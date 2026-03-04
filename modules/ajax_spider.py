"""
Ajax Spider — headless Chromium crawler for JavaScript-heavy SPAs.
Uses Playwright if available; gracefully disabled if not installed.

Captures:
- All pages navigated to (multi-tab concurrent crawling)
- All form inputs (rendered by JS, not just HTML)
- XHR / fetch network requests → additional InputSurface objects
- Links discovered after JS execution
- WebSocket endpoints (ws:// / wss://)

Multi-tab: 3 concurrent Playwright instances via producer-consumer queue.
Each tab runs its own sync_playwright() (thread-safe per Playwright Python docs).

To install: pip install playwright && playwright install chromium
"""
from __future__ import annotations

import json
import queue as _queue
import re
import threading
import time
from typing import Optional
from urllib.parse import parse_qs, urlparse

try:
    from .crawler import InputSurface, SiteMap
    from .scope import ScopeManager
except ImportError:
    pass   # Allow standalone testing

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ── Reusable JS snippets ──────────────────────────────────────────────────────

_JS_FORMS = """() => {
    return Array.from(document.querySelectorAll('form')).map(f => ({
        action: f.action || window.location.href,
        method: (f.method || 'get').toUpperCase(),
        inputs: Array.from(f.querySelectorAll(
            'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]),' +
            ' select, textarea'
        )).map(i => ({
            name:  i.name  || i.id || '',
            type:  i.type  || 'text',
            value: i.value || ''
        })).filter(i => i.name)
    }));
}"""

_JS_LINKS = """() =>
    Array.from(document.querySelectorAll('a[href], [onclick], [ng-click], [v-on]'))
        .map(el => el.href || '')
        .filter(h => h.startsWith('http'))
"""

# ── Sprint 3: Session refresh + Smart form fill ───────────────────────────────

_LOGIN_PATH_RE = re.compile(
    r"/(login|signin|sign[_\-]in|auth(?:enticate)?|sso|session/new|account/login"
    r"|user/login|users/sign_in|wp-login\.php)",
    re.IGNORECASE,
)

# (compiled pattern, test value) — matched against field name/id
_SMART_FILL: list = [
    (re.compile(r"e?mail",                         re.I), "test@example.com"),
    (re.compile(r"user(?:name)?|login|acct|handle", re.I), "testuser"),
    (re.compile(r"pass(?:word)?|pwd|secret",        re.I), "Test@1234"),
    (re.compile(r"phone|tel(?:ephone)?|mobile|cell",re.I), "5555555555"),
    (re.compile(r"(?:full.?|first.?|last.?)?name",  re.I), "Test User"),
    (re.compile(r"\bsearch\b|query|\bq\b",          re.I), "test"),
    (re.compile(r"\bage\b|\byear\b",                re.I), "25"),
    (re.compile(r"zip|postal",                      re.I), "12345"),
    (re.compile(r"url|website|link|href|site",      re.I), "https://example.com"),
    (re.compile(r"message|body|comment|description|note|content", re.I), "test message"),
    (re.compile(r"address|street|addr",             re.I), "123 Test St"),
    (re.compile(r"\bcity\b",                        re.I), "Testville"),
    (re.compile(r"state|province|region",           re.I), "CA"),
    (re.compile(r"country",                         re.I), "US"),
    (re.compile(r"number|num|count|qty|quantity|amount", re.I), "1"),
    (re.compile(r"date|birthday|dob",               re.I), "2000-01-01"),
    (re.compile(r"title|subject|topic|heading",     re.I), "Test"),
    (re.compile(r"company|org(?:anization)?|firm",  re.I), "TestCorp"),
]

_SMART_TYPE_DEFAULTS: dict = {
    "number":   "1",
    "email":    "test@example.com",
    "tel":      "5555555555",
    "url":      "https://example.com",
    "date":     "2000-01-01",
    "color":    "#000000",
    "range":    "50",
    "search":   "test",
}


class AjaxSpider:
    """
    Headless Chromium spider. Handles JS rendering, SPAs, dynamic forms,
    captures XHR/fetch network traffic, and WebSocket endpoints.

    Uses a producer-consumer queue with `max_tabs` concurrent Playwright
    instances for faster crawling. Falls back gracefully if Playwright
    is not installed.
    """

    def __init__(
        self,
        target:       str,
        scope:        "ScopeManager",
        max_pages:    int = 50,
        max_depth:    int = 3,
        page_timeout: int = 15_000,   # ms for page navigation
        idle_wait:    int = 1_500,    # ms to wait for JS after navigation
        headless:     bool = True,
        cookies:      list[dict] | None = None,  # [{name, value, domain, path}]
        headers:      dict       | None = None,
        stop_event:   threading.Event | None = None,
        callback      = None,         # called with (url, status) on each page
        max_tabs:     int = 3,        # concurrent browser instances (1-5)
        # Sprint 3 additions
        auth_config:  dict | None = None,  # {login_url, username, password, user_field, pass_field}
        smart_fill:   bool = True,         # submit forms with smart test values
    ):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright is not installed.\n"
                "Install: pip install playwright && playwright install chromium"
            )
        self.target       = target
        self.scope        = scope
        self.max_pages    = max_pages
        self.max_depth    = max_depth
        self.page_timeout = page_timeout
        self.idle_wait    = idle_wait
        self.headless     = headless
        self.cookies      = cookies or []
        self.headers      = headers or {}
        self.stop_event   = stop_event or threading.Event()
        self.callback     = callback
        self.max_tabs     = max(1, min(max_tabs, 5))
        self.auth_config  = auth_config or {}
        self.smart_fill   = smart_fill

        self.sitemap         = SiteMap()
        self._visited: set[str] = set()
        self._network_reqs: list[dict] = []
        self._ws_endpoints: list[dict] = []

        # Thread-safety locks
        self._net_lock     = threading.Lock()
        self._sitemap_lock = threading.Lock()
        self._visited_lock = threading.Lock()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def crawl(self) -> "SiteMap":
        """Launch multi-tab Playwright workers, crawl target, return SiteMap."""
        # Producer-consumer: master feeds work_q, workers put results in result_q
        work_q:   _queue.Queue = _queue.Queue()
        result_q: _queue.Queue = _queue.Queue()

        # Seed queue with the start URL
        start_url = self.target.split("#")[0]
        with self._visited_lock:
            self._visited.add(start_url)
        work_q.put((start_url, 0))
        pending = 1  # number of URLs currently in flight / queued

        stop_tabs = threading.Event()

        # Spawn N tab workers
        workers = []
        for tab_id in range(self.max_tabs):
            t = threading.Thread(
                target=self._tab_worker,
                args=(work_q, result_q, stop_tabs, tab_id),
                daemon=True,
                name=f"ajax-tab-{tab_id}",
            )
            t.start()
            workers.append(t)

        # Master loop: route results → feed new URLs back into work_q
        while pending > 0 and not self.stop_event.is_set():
            try:
                result = result_q.get(timeout=3)
            except _queue.Empty:
                continue

            pending -= 1
            new_urls = result.get("new_urls", [])

            with self._visited_lock:
                for href, depth in new_urls:
                    if (href not in self._visited
                            and len(self._visited) < self.max_pages
                            and depth <= self.max_depth):
                        self._visited.add(href)
                        work_q.put((href, depth))
                        pending += 1

        # Signal all workers to stop and wait
        stop_tabs.set()
        for t in workers:
            t.join(timeout=10)

        # Post-process: convert network captures to surfaces + add WS pages
        self._extract_network_surfaces()
        self._add_network_and_ws_pages()

        return self.sitemap

    # ─────────────────────────────────────────────────────────────────────────
    # Tab worker (each runs its own Playwright instance)
    # ─────────────────────────────────────────────────────────────────────────

    def _tab_worker(
        self,
        work_q:   _queue.Queue,
        result_q: _queue.Queue,
        stop_tabs: threading.Event,
        tab_id:   int,
    ):
        """Each tab owns its own sync_playwright() context (thread-safe)."""
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=self.headless)
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=self.headers,
                    user_agent="Mozilla/5.0 (DAST-AjaxSpider/2.0)",
                )
                if self.cookies:
                    ctx.add_cookies(self.cookies)

                page = ctx.new_page()

                # ── Network capture ───────────────────────────────────────
                def _on_request(req):
                    try:
                        if self.scope.in_scope(req.url):
                            with self._net_lock:
                                self._network_reqs.append({
                                    "url":       req.url,
                                    "method":    req.method,
                                    "headers":   dict(req.headers),
                                    "post_data": req.post_data or "",
                                })
                    except Exception:
                        pass

                # ── WebSocket capture ─────────────────────────────────────
                def _on_websocket(ws):
                    try:
                        ws_url = ws.url
                        with self._net_lock:
                            self._ws_endpoints.append({
                                "url":          ws_url,
                                "source":       "websocket",
                                "status":       101,
                                "content_type": "websocket",
                                "title":        "[WebSocket]",
                            })
                    except Exception:
                        pass

                page.on("request", _on_request)
                page.on("websocket", _on_websocket)

                # ── Work loop ─────────────────────────────────────────────
                while not self.stop_event.is_set() and not stop_tabs.is_set():
                    try:
                        url, depth = work_q.get(timeout=1)
                    except _queue.Empty:
                        continue

                    new_urls = self._navigate(page, url, depth)
                    result_q.put({"new_urls": new_urls})

                try:
                    page.close()
                    browser.close()
                except Exception:
                    pass

        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Sprint 3.1 — Session refresh helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _is_login_page(self, url: str, resp, page) -> bool:
        """Return True when we appear to have been redirected to a login page."""
        if _LOGIN_PATH_RE.search(url):
            return True
        if resp and resp.status in (401, 403):
            return True
        try:
            title = page.title().lower()
            if any(w in title for w in ("login", "sign in", "sign-in", "log in",
                                        "authenticate", "authentication")):
                return True
        except Exception:
            pass
        return False

    def _reauth(self, page) -> bool:
        """Navigate to the login URL, fill credentials, submit.  Returns True on success."""
        cfg = self.auth_config
        login_url = cfg.get("login_url", "")
        username  = cfg.get("username", "")
        password  = cfg.get("password", "")
        if not (login_url and username and password):
            return False

        try:
            page.goto(login_url, timeout=self.page_timeout, wait_until="networkidle")
            page.wait_for_timeout(800)

            # ── Fill username ──────────────────────────────────────────────
            user_field = cfg.get("user_field", "")
            user_selectors = (
                [f'[name="{user_field}"]', f'#{user_field}'] if user_field else []
            ) + [
                '[name="username"]', '[name="email"]', '[name="user"]',
                '[name="login"]', '[id="username"]', '[id="email"]',
                '[type="email"]',
                'input[placeholder*="user" i]', 'input[placeholder*="email" i]',
                'input[placeholder*="login" i]',
            ]
            user_filled = False
            for sel in user_selectors:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible() and el.is_enabled():
                        el.fill(username)
                        user_filled = True
                        break
                except Exception:
                    pass

            # ── Fill password ──────────────────────────────────────────────
            pass_field = cfg.get("pass_field", "")
            pass_selectors = (
                [f'[name="{pass_field}"]', f'#{pass_field}'] if pass_field else []
            ) + [
                '[name="password"]', '[name="pass"]', '[name="pwd"]',
                '[id="password"]', '[type="password"]',
                'input[placeholder*="pass" i]', 'input[placeholder*="secret" i]',
            ]
            pass_filled = False
            for sel in pass_selectors:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible() and el.is_enabled():
                        el.fill(password)
                        pass_filled = True
                        break
                except Exception:
                    pass

            if not (user_filled and pass_filled):
                return False

            # ── Submit ────────────────────────────────────────────────────
            submitted = False
            for sel in ['[type="submit"]', 'button[type="submit"]',
                        'button:not([type="button"]):not([type="reset"])']:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible():
                        el.click()
                        submitted = True
                        break
                except Exception:
                    pass
            if not submitted:
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass

            try:
                page.wait_for_load_state("networkidle", timeout=6_000)
            except Exception:
                pass
            page.wait_for_timeout(500)
            return True

        except Exception:
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Sprint 3.2 — Smart form submission
    # ─────────────────────────────────────────────────────────────────────────

    def _smart_value(self, name: str, itype: str) -> str:
        """Return a context-appropriate test value for a form field."""
        for pattern, val in _SMART_FILL:
            if pattern.search(name):
                return val
        return _SMART_TYPE_DEFAULTS.get(itype, "test")

    def _fill_and_submit_forms(self, page, url: str, depth: int) -> list:
        """
        Fill every form on `url` with smart test values and submit.
        Returns list of (newly_discovered_url, depth+1) from submission redirects.
        """
        new_urls: list = []
        try:
            forms = page.evaluate(_JS_FORMS)
        except Exception:
            return new_urls

        for form_idx, form in enumerate(forms[:4]):   # cap at 4 forms per page
            if self.stop_event.is_set():
                break
            inputs = form.get("inputs", [])
            if not inputs:
                continue

            try:
                # Re-navigate for every form after the first (fresh DOM state)
                if form_idx > 0:
                    page.goto(url, timeout=self.page_timeout, wait_until="networkidle")
                    page.wait_for_timeout(500)

                # Fill each input via smart value
                for inp in inputs:
                    name  = inp.get("name", "")
                    itype = inp.get("type", "text")
                    if not name:
                        continue
                    val = self._smart_value(name, itype)
                    for sel in [f'[name="{name}"]', f'#{name}']:
                        try:
                            el = page.query_selector(sel)
                            if el and el.is_visible() and el.is_enabled():
                                if itype in ("checkbox", "radio"):
                                    el.check()
                                elif itype in ("select", "select-one"):
                                    opts = page.eval_on_selector(
                                        sel,
                                        "el => Array.from(el.options).map(o=>o.value).filter(v=>v)"
                                    )
                                    if opts:
                                        el.select_option(opts[0])
                                else:
                                    el.fill(val)
                                break
                        except Exception:
                            pass

                pre_url = page.url.split("#")[0]

                # Click submit — try scoped selectors first, then global
                submitted = False
                for sel in [
                    '[type="submit"]', 'button[type="submit"]',
                    'button:not([type="button"]):not([type="reset"])',
                    'input[type="image"]',
                ]:
                    try:
                        el = page.query_selector(sel)
                        if el and el.is_visible():
                            el.click()
                            submitted = True
                            break
                    except Exception:
                        pass
                if not submitted:
                    try:
                        page.keyboard.press("Enter")
                        submitted = True
                    except Exception:
                        pass
                if not submitted:
                    continue

                try:
                    page.wait_for_load_state("networkidle", timeout=4_000)
                except Exception:
                    pass
                page.wait_for_timeout(400)

                post_url = page.url.split("#")[0]
                if post_url != pre_url and self.scope.in_scope(post_url):
                    with self._visited_lock:
                        already = post_url in self._visited
                    if not already:
                        try:
                            title = page.title()
                        except Exception:
                            title = ""
                        with self._sitemap_lock:
                            self.sitemap.add_page(
                                post_url, 200, "", {}, f"[Form-Submit] {title}"
                            )
                        new_urls.append((post_url, depth + 1))
                        if self.callback:
                            self.callback(post_url, 200)

            except Exception:
                pass

        # Leave page at the original URL so the tab can continue cleanly
        if forms:
            try:
                page.goto(url, timeout=self.page_timeout, wait_until="networkidle")
                page.wait_for_timeout(800)
            except Exception:
                pass

        return new_urls

    # ─────────────────────────────────────────────────────────────────────────
    # Single page navigation (called by each tab worker)
    # ─────────────────────────────────────────────────────────────────────────

    def _navigate(self, page, url: str, depth: int) -> list:
        """Navigate `page` to `url`, extract data, return list of (href, depth+1)."""
        new_urls = []
        try:
            resp = page.goto(
                url,
                timeout=self.page_timeout,
                wait_until="networkidle",
            )
            page.wait_for_timeout(self.idle_wait)

            # ── Sprint 3.1: Session expiry detection → re-authenticate ────
            final_url = page.url.split("#")[0]
            if self.auth_config and self._is_login_page(final_url, resp, page):
                if self._reauth(page):
                    # Retry original URL with fresh session
                    resp = page.goto(url, timeout=self.page_timeout,
                                     wait_until="networkidle")
                    page.wait_for_timeout(self.idle_wait)

            status = resp.status if resp else 0
            ct     = (resp.headers.get("content-type", "") if resp else "")
            title  = ""
            try:
                title = page.title()
            except Exception:
                pass

            with self._sitemap_lock:
                self.sitemap.add_page(url, status, ct, {}, f"[Ajax] {title}")

            if self.callback:
                self.callback(url, status)

            # ── URL query params ──────────────────────────────────────────
            parsed = urlparse(url)
            if parsed.query:
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for param, vals in parse_qs(parsed.query).items():
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=clean, method="GET", param=param,
                            param_type="query",
                            original_value=vals[0] if vals else "",
                        ))

            # ── Forms via JS evaluation ───────────────────────────────────
            if depth < self.max_depth:
                try:
                    forms = page.evaluate(_JS_FORMS)
                    for form in forms:
                        action = form.get("action", url)
                        method = form.get("method", "GET").upper()
                        for inp in form.get("inputs", []):
                            if inp.get("name"):
                                with self._sitemap_lock:
                                    self.sitemap.add_surface(InputSurface(
                                        url=action, method=method,
                                        param=inp["name"],
                                        param_type="form",
                                        original_value=inp.get("value", ""),
                                        content_type="application/x-www-form-urlencoded",
                                    ))
                except Exception:
                    pass

            # ── Links for BFS queue ───────────────────────────────────────
            if depth < self.max_depth:
                try:
                    hrefs = page.evaluate(_JS_LINKS)
                    with self._visited_lock:
                        visited_snap = set(self._visited)
                    for href in hrefs:
                        href = href.split("#")[0]
                        if href not in visited_snap and self.scope.in_scope(href):
                            new_urls.append((href, depth + 1))
                except Exception:
                    pass

            # ── Sprint 3.2: Smart form submission ─────────────────────────
            if self.smart_fill and depth < self.max_depth:
                form_urls = self._fill_and_submit_forms(page, url, depth)
                new_urls.extend(form_urls)

        except PlaywrightTimeout:
            with self._sitemap_lock:
                self.sitemap.add_page(url, 0, "timeout", {}, "[Ajax] Timeout")
        except Exception:
            pass

        return new_urls

    # ─────────────────────────────────────────────────────────────────────────
    # Post-processing
    # ─────────────────────────────────────────────────────────────────────────

    def _add_network_and_ws_pages(self):
        """Add captured XHR and WebSocket URLs as sitemap pages."""
        seen_pages = set(self.sitemap.pages.keys())

        with self._net_lock:
            for nr in self._network_reqs:
                nurl = nr["url"].split("#")[0]
                if nurl not in seen_pages and self.scope.in_scope(nurl):
                    with self._sitemap_lock:
                        self.sitemap.add_page(nurl, 0, "xhr/network", {}, "[Ajax-net]")
                    seen_pages.add(nurl)

            for ws in self._ws_endpoints:
                ws_url = ws["url"]
                if ws_url not in seen_pages:
                    with self._sitemap_lock:
                        self.sitemap.add_page(ws_url, 101, "websocket", {}, "[WebSocket]")
                    seen_pages.add(ws_url)

    def _extract_network_surfaces(self):
        """Convert captured XHR/fetch requests into InputSurface objects."""
        seen: set[tuple] = set()

        for req in self._network_reqs:
            url    = req["url"]
            method = req["method"]
            key    = (url, method)
            if key in seen:
                continue
            seen.add(key)

            # Query params from URL
            parsed = urlparse(url)
            if parsed.query:
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for param, vals in parse_qs(parsed.query).items():
                    with self._sitemap_lock:
                        self.sitemap.add_surface(InputSurface(
                            url=clean, method=method, param=param,
                            param_type="query",
                            original_value=vals[0] if vals else "",
                        ))

            # POST body
            post_data = req.get("post_data", "")
            if not post_data:
                continue

            ct = req.get("headers", {}).get("content-type", "")

            if "application/json" in ct:
                try:
                    body = json.loads(post_data)
                    if isinstance(body, dict):
                        for k, v in list(body.items())[:20]:
                            with self._sitemap_lock:
                                self.sitemap.add_surface(InputSurface(
                                    url=url, method=method, param=k,
                                    param_type="json",
                                    original_value=str(v),
                                    content_type="application/json",
                                ))
                except Exception:
                    pass

            elif "form" in ct or "urlencoded" in ct:
                for pair in post_data.split("&"):
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        if k:
                            with self._sitemap_lock:
                                self.sitemap.add_surface(InputSurface(
                                    url=url, method=method, param=k,
                                    param_type="form", original_value=v,
                                    content_type="application/x-www-form-urlencoded",
                                ))
