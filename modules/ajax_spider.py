"""
Ajax Spider — headless Chromium crawler for JavaScript-heavy SPAs.
Uses Playwright if available; gracefully disabled if not installed.

Captures:
- All pages navigated to
- All form inputs (rendered by JS, not just HTML)
- XHR / fetch network requests → additional InputSurface objects
- Links discovered after JS execution

To install: pip install playwright && playwright install chromium
"""
from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
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


class AjaxSpider:
    """
    Headless Chromium spider. Handles JS rendering, SPAs, dynamic forms,
    and captures all XHR/fetch network traffic.

    Falls back gracefully if Playwright is not installed.
    """

    def __init__(
        self,
        target:     str,
        scope:      "ScopeManager",
        max_pages:  int = 50,
        max_depth:  int = 3,
        page_timeout: int = 15_000,   # ms for page navigation
        idle_wait:  int = 1_500,      # ms to wait for JS after navigation
        headless:   bool = True,
        cookies:    list[dict] | None = None,    # [{name, value, domain, path}]
        headers:    dict        | None = None,
        stop_event: threading.Event | None = None,
        callback = None,   # called with (url, status) on each page
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
        self.sitemap      = SiteMap()
        self._visited:    set[str] = set()
        self._network_reqs: list[dict] = []
        self._net_lock    = threading.Lock()

    def crawl(self) -> "SiteMap":
        """Launch Playwright, crawl target, return populated SiteMap."""
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.headless)
            ctx = browser.new_context(
                ignore_https_errors = True,
                extra_http_headers  = self.headers,
                user_agent          = "Mozilla/5.0 (DAST-AjaxSpider/2.0)",
            )

            # Inject auth cookies
            if self.cookies:
                ctx.add_cookies(self.cookies)

            page = ctx.new_page()

            # Capture all outbound requests for API surface discovery
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

            page.on("request", _on_request)

            # BFS crawl
            queue: deque[tuple[str, int]] = deque([(self.target, 0)])

            while queue and not self.stop_event.is_set():
                url, depth = queue.popleft()
                url = url.split("#")[0]

                if url in self._visited:
                    continue
                if not self.scope.in_scope(url):
                    continue
                if len(self._visited) >= self.max_pages:
                    break
                if depth > self.max_depth:
                    continue

                self._visited.add(url)

                try:
                    resp = page.goto(
                        url,
                        timeout    = self.page_timeout,
                        wait_until = "networkidle",
                    )
                    # Give JS more time to settle
                    page.wait_for_timeout(self.idle_wait)

                    status = resp.status if resp else 0
                    ct     = (resp.headers.get("content-type", "") if resp else "")
                    title  = ""
                    try:
                        title = page.title()
                    except Exception:
                        pass

                    self.sitemap.add_page(url, status, ct, {}, f"[Ajax] {title}")

                    if self.callback:
                        self.callback(url, status)

                    # ── URL query params ───────────────────────────────────────
                    parsed = urlparse(url)
                    if parsed.query:
                        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        for param, vals in parse_qs(parsed.query).items():
                            self.sitemap.add_surface(InputSurface(
                                url=clean, method="GET", param=param,
                                param_type="query",
                                original_value=vals[0] if vals else "",
                            ))

                    # ── Forms via JS evaluation ────────────────────────────────
                    try:
                        forms = page.evaluate("""() => {
                            return Array.from(document.querySelectorAll('form')).map(f => ({
                                action: f.action || window.location.href,
                                method: (f.method || 'get').toUpperCase(),
                                inputs: Array.from(f.querySelectorAll(
                                    'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]), select, textarea'
                                )).map(i => ({
                                    name:  i.name  || i.id || '',
                                    type:  i.type  || 'text',
                                    value: i.value || ''
                                })).filter(i => i.name)
                            }));
                        }""")
                        for form in forms:
                            action = form.get("action", url)
                            method = form.get("method", "GET").upper()
                            for inp in form.get("inputs", []):
                                self.sitemap.add_surface(InputSurface(
                                    url=action, method=method, param=inp["name"],
                                    param_type="form",
                                    original_value=inp.get("value", ""),
                                    content_type="application/x-www-form-urlencoded",
                                ))
                    except Exception:
                        pass

                    # ── Links for BFS queue ────────────────────────────────────
                    if depth < self.max_depth:
                        try:
                            hrefs = page.evaluate("""() =>
                                Array.from(document.querySelectorAll('a[href], [onclick], [ng-click], [v-on]'))
                                    .map(el => el.href || '')
                                    .filter(h => h.startsWith('http'))
                            """)
                            for href in hrefs:
                                href = href.split("#")[0]
                                if href not in self._visited and self.scope.in_scope(href):
                                    queue.append((href, depth + 1))
                        except Exception:
                            pass

                except PlaywrightTimeout:
                    self.sitemap.add_page(url, 0, "timeout", {}, "[Ajax] Timeout")
                except Exception:
                    pass

            # Process all captured network traffic
            self._extract_network_surfaces()

            page.close()
            browser.close()

        return self.sitemap

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
                            self.sitemap.add_surface(InputSurface(
                                url=url, method=method, param=k,
                                param_type="form", original_value=v,
                                content_type="application/x-www-form-urlencoded",
                            ))
