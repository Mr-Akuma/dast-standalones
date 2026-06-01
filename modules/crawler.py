"""
Web Crawler — BFS discovery of all endpoints, forms, and input parameters.
Returns a structured SiteMap used by the fuzzer to enumerate attack surface.
"""
from __future__ import annotations
import re
import threading
import time
from collections import deque
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse, urlencode

import requests
import requests.exceptions
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .scope import ScopeManager
from .event_bus import safe_publish, CRAWL_URL_FOUND


# ── Logout / session-expiry detection patterns ───────────────────────────────

_LOGIN_URL_PATTERNS: list[str] = [
    "/login", "/signin", "/sign-in", "/sign_in",
    "/auth/", "/authenticate", "/session/new",
    "/account/login", "/user/login", "/users/sign_in",
    "/sso/", "/oauth/", "/saml/", "/cas/login",
]

_LOGOUT_BODY_PATTERNS = re.compile(
    r'type=["\']password["\']'
    r'|please\s+log\s*in'
    r'|session\s+expired'
    r'|log\s+in\s+to\s+continue'
    r'|you\s+have\s+been\s+logged\s+out'
    r'|login\s+required'
    r'|sign\s+in\s+to\s+continue'
    r'|authentication\s+required',
    re.IGNORECASE,
)

# ── HTML Parser ────────────────────────────────────────────────────────────────

class _PageParser(HTMLParser):
    """Extract links, forms, scripts, and input parameters from a page."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url   = base_url
        self.links:     list[str] = []
        self.forms:     list[dict] = []
        self.scripts:   list[str] = []
        self.meta_redirects: list[str] = []
        self._cur_form: Optional[dict] = None
        self._in_meta_content: bool = False

    def handle_starttag(self, tag: str, attrs: list):
        a = dict(attrs)
        tag = tag.lower()

        if tag == "a" and "href" in a:
            self.links.append(a["href"])

        # Image map areas
        elif tag == "area" and "href" in a:
            self.links.append(a["href"])

        # data-href / data-url attributes on any element
        elif a.get("data-href"):
            self.links.append(a["data-href"])
        elif a.get("data-url"):
            self.links.append(a["data-url"])

        # Canonical / alternate link tags
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if rel in ("canonical", "alternate", "next", "prev", "previous") and a.get("href"):
                self.links.append(a["href"])

        # Meta refresh redirects
        elif tag == "meta":
            heq = a.get("http-equiv", "").lower()
            if heq == "refresh":
                content = a.get("content", "")
                m = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.I)
                if m:
                    self.meta_redirects.append(m.group(1))

        elif tag == "form":
            self._cur_form = {
                "action": a.get("action", self.base_url),
                "method": a.get("method", "get").lower(),
                "inputs": {},
                "url":    self.base_url,
            }

        elif tag == "input" and self._cur_form is not None:
            name  = a.get("name", "")
            itype = a.get("type", "text").lower()
            val   = a.get("value", "")
            if name and itype not in ("submit", "button", "image", "reset"):
                self._cur_form["inputs"][name] = {"type": itype, "value": val}

        elif tag == "select" and self._cur_form is not None:
            name = a.get("name", "")
            if name:
                self._cur_form["inputs"][name] = {"type": "select", "value": "1"}

        elif tag == "textarea" and self._cur_form is not None:
            name = a.get("name", "")
            if name:
                self._cur_form["inputs"][name] = {"type": "textarea", "value": "test"}

        elif tag == "button":
            # button[formaction] overrides the enclosing form's action
            formaction = a.get("formaction", "")
            if formaction and self._cur_form is not None:
                self.links.append(formaction)
            if self._cur_form is not None and a.get("type", "").lower() == "submit":
                name = a.get("name", "")
                if name:
                    self._cur_form["inputs"][name] = {"type": "submit", "value": a.get("value", "")}

        elif tag == "script":
            src = a.get("src", "")
            if src:
                self.scripts.append(src)

    def handle_endtag(self, tag: str):
        if tag.lower() == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


# ── Input Surface ──────────────────────────────────────────────────────────────

class InputSurface:
    """Represents a single fuzzable endpoint + parameter combination."""
    __slots__ = ("url", "method", "param", "param_type", "original_value",
                 "headers", "body_template", "content_type", "_context_vtypes")

    def __init__(self, url: str, method: str, param: str, param_type: str,
                 original_value: str = "", headers: dict | None = None,
                 body_template: str = "", content_type: str = ""):
        self.url            = url
        self.method         = method.upper()
        self.param          = param
        # Supported param_type values:
        #   "query"         → URL_QUERY_STRING
        #   "form"          → BODY_PARAMETER
        #   "json"          → JSON_PARAMETER
        #   "header"        → HTTP_HEADER
        #   "path"          → URL_PATH_FOLDER
        #   "path_filename" → URL_PATH_FILENAME  (last path segment / filename)
        #   "request_line"  → REQUEST_LINE       (extra path token after endpoint)
        #   "cookie"        → COOKIE
        #   "xml"           → XML_PARAMETER
        #   "multipart"     → MULTIPART_PARAMETER
        self.param_type     = param_type
        self.original_value = original_value
        self.headers        = headers or {}
        self.body_template  = body_template
        self.content_type   = content_type

    def __repr__(self):
        return f"<InputSurface {self.method} {self.url} [{self.param_type}:{self.param}]>"


# ── Site Map ───────────────────────────────────────────────────────────────────

class SiteMap:
    """Stores all discovered pages and input surfaces."""

    def __init__(self):
        self._lock    = threading.Lock()
        self.pages:   dict[str, dict] = {}      # url → page info
        self.surfaces: list[InputSurface] = []  # all fuzzable surfaces
        self.tech:    dict = {}                  # fingerprint results
        self._surface_keys: set = set()          # O(1) dedup — mirrors surfaces list

    def add_page(self, url: str, status: int, content_type: str, headers: dict, title: str = ""):
        with self._lock:
            self.pages[url] = {
                "url":          url,
                "status":       status,
                "content_type": content_type,
                "title":        title,
                "headers":      headers,
            }

    def add_surface(self, surface: InputSurface):
        with self._lock:
            key = (surface.url, surface.method, surface.param, surface.param_type)
            if key in self._surface_keys:
                return
            self._surface_keys.add(key)
            self.surfaces.append(surface)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "pages":    list(self.pages.values()),
                "surfaces": [
                    {"url": s.url, "method": s.method, "param": s.param,
                     "type": s.param_type, "value": s.original_value}
                    for s in self.surfaces
                ],
                "tech":     self.tech,
                "stats": {
                    "pages":    len(self.pages),
                    "surfaces": len(self.surfaces),
                },
            }


# ── Crawler ────────────────────────────────────────────────────────────────────

class Crawler:
    """
    BFS web crawler. Discovers all in-scope pages, forms, and parameters.
    Uses a shared requests.Session (which may carry auth cookies).
    """

    # Headers that are always worth fuzzing
    FUZZ_HEADERS = [
        "User-Agent", "Referer", "X-Forwarded-For",
        "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
        "X-Custom-IP-Authorization",
    ]

    def __init__(
        self,
        target: str,
        scope: ScopeManager,
        session: requests.Session,
        max_pages: int = 200,
        max_depth: int = 5,
        timeout:   int = 10,
        delay:     float = 0.1,
        callback = None,           # called with (url, status) on each page
        auth_callback = None,      # called with () on detected logout — triggers re-auth
        login_patterns = None,     # override default login URL patterns
    ):
        self.target    = target
        self.scope     = scope
        self.session   = session
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout   = timeout
        self.delay     = delay
        self.callback  = callback
        self.sitemap   = SiteMap()
        self._visited: set[str] = set()
        self._stop     = False
        self.auth_callback   = auth_callback
        self._login_patterns = login_patterns or _LOGIN_URL_PATTERNS
        self._reauth_attempted: set[str] = set()

    def stop(self):
        self._stop = True

    def _detect_logout(self, resp, original_url: str) -> bool:
        """Return True if response indicates session expiry / forced logout."""
        if self.auth_callback is None:
            return False
        orig_lower = original_url.lower()
        if any(p in orig_lower for p in self._login_patterns):
            return False
        final_url = getattr(resp, "url", original_url) or original_url
        if final_url.rstrip("/") != original_url.rstrip("/"):
            if any(p in final_url.lower() for p in self._login_patterns):
                return True
        try:
            if _LOGOUT_BODY_PATTERNS.search(resp.text[:4000]):
                return True
        except Exception:
            pass
        return False

    def _fetch(self, url: str) -> requests.Response:
        """Fetch a URL, retrying with Connection: close on first failure.

        Some embedded devices / appliances reject HTTP/1.1 keep-alive but
        respond normally when given Connection: close.  Raw IPs running
        non-standard stacks (cameras, routers, IoT devices) hit this path.
        """
        headers = {"Accept": "text/html,application/json,*/*"}
        try:
            return self.session.get(
                url, timeout=self.timeout,
                allow_redirects=True,
                headers=headers,
            )
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ChunkedEncodingError):
            # Retry with Connection: close — helps with HTTP/1.1-unfriendly servers
            headers["Connection"] = "close"
            headers["User-Agent"] = "Mozilla/5.0 (compatible; DAST/2.0)"
            return self.session.get(
                url, timeout=self.timeout,
                allow_redirects=True,
                headers=headers,
            )

    def crawl(self) -> SiteMap:
        """BFS crawl from target. Returns populated SiteMap."""
        queue: deque[tuple[str, int]] = deque([(self.target, 0)])

        # Seed with common paths
        for path in [
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
            "/swagger/v1/swagger.json", "/v1/api-docs", "/api/swagger.json",
            "/.git/config", "/.env", "/.env.local", "/.env.production",
            "/admin", "/login", "/dashboard", "/console",
            "/wp-admin", "/phpmyadmin", "/graphql", "/gql",
            "/actuator", "/actuator/env", "/actuator/health",
            "/_ah/admin", "/jmx-console", "/manager/html",
            "/api/health", "/health", "/status", "/metrics",
            "/api/users", "/api/user", "/api/me", "/api/profile",
        ]:
            try:
                queue.append((self.scope.normalise(path), 0))
            except Exception:
                pass

        while queue and not self._stop:
            url, depth = queue.popleft()
            url = url.split("#")[0]   # strip fragment

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
                resp = self._fetch(url)
            except Exception:
                continue

            # ── Logout / session-expiry detection ─────────────────────────
            if self._detect_logout(resp, url):
                if url not in self._reauth_attempted:
                    self._reauth_attempted.add(url)
                    try:
                        self.auth_callback()
                    except Exception:
                        pass
                    queue.appendleft((url, depth))  # re-queue at front
                continue  # skip processing this login-page response

            if self.delay:
                time.sleep(self.delay)

            ct     = resp.headers.get("content-type", "")
            status = resp.status_code

            # Extract title
            title = ""
            m = re.search(r"<title[^>]*>([^<]{1,120})</title>", resp.text, re.I)
            if m:
                title = m.group(1).strip()

            self.sitemap.add_page(url, status, ct, dict(resp.headers), title)
            safe_publish(CRAWL_URL_FOUND, {"url": url, "status_code": status, "content_type": ct})

            if self.callback:
                self.callback(url, status)

            # ── Extract URL parameters as input surfaces ──────────────────
            parsed = urlparse(url)
            if parsed.query:
                for param, vals in parse_qs(parsed.query).items():
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    self.sitemap.add_surface(InputSurface(
                        url=clean_url, method="GET", param=param,
                        param_type="query", original_value=vals[0] if vals else "",
                    ))

            # ── Add header injection surfaces for every page ──────────────
            for hdr in self.FUZZ_HEADERS:
                self.sitemap.add_surface(InputSurface(
                    url=url, method="GET", param=hdr,
                    param_type="header", original_value="",
                ))

            # ── URL_PATH_FILENAME surfaces ────────────────────────────────
            # Emit when the last path segment looks like a filename (has an
            # extension) or a bare resource name (no query string).
            # e.g. /api/report.pdf → param_type="path_filename", param="report"
            _pf_path = parsed.path
            _pf_last = _pf_path.rsplit("/", 1)[-1]
            if _pf_last and not parsed.query:
                _pf_dot = _pf_last.rfind(".")
                _pf_stem = _pf_last[:_pf_dot] if _pf_dot != -1 else _pf_last
                if _pf_stem:
                    self.sitemap.add_surface(InputSurface(
                        url=url, method="GET", param=_pf_stem,
                        param_type="path_filename", original_value=_pf_stem,
                    ))

            # ── REQUEST_LINE surfaces ─────────────────────────────────────
            # One surface per non-static page: injects an extra path token
            # after the last segment (tests path-traversal, routing bypass,
            # spring-actuator-style path override).
            # param name is the base path so findings are deduplicated cleanly.
            _rl_path = parsed.path.rstrip("/") or "/"
            self.sitemap.add_surface(InputSurface(
                url=url, method="GET", param=_rl_path,
                param_type="request_line", original_value="",
            ))

            # ── Parse HTML ────────────────────────────────────────────────
            if "text/html" not in ct:
                continue

            parser = _PageParser(url)
            try:
                parser.feed(resp.text)
            except Exception:
                continue

            # Add form surfaces
            for form in parser.forms:
                action     = urljoin(url, form["action"]) if form["action"] else url
                method_str = form["method"].upper()
                for fname, finfo in form["inputs"].items():
                    self.sitemap.add_surface(InputSurface(
                        url=action, method=method_str, param=fname,
                        param_type="form", original_value=finfo.get("value", ""),
                        body_template=urlencode({k: v.get("value","") for k,v in form["inputs"].items()}),
                        content_type="application/x-www-form-urlencoded",
                    ))

            # ── Cookie surfaces from Set-Cookie headers ───────────────────
            for hdr_name, hdr_val in resp.headers.items():
                if hdr_name.lower() == "set-cookie":
                    # Extract cookie name from "name=value; Path=/" pattern
                    cookie_part = hdr_val.split(";")[0].strip()
                    if "=" in cookie_part:
                        cname = cookie_part.split("=", 1)[0].strip()
                        cval  = cookie_part.split("=", 1)[1].strip()
                        if cname and not cname.lower().startswith("__secure"):
                            self.sitemap.add_surface(InputSurface(
                                url=url, method="GET", param=cname,
                                param_type="cookie", original_value=cval[:200],
                            ))

            # Queue discovered links
            if depth < self.max_depth:
                for href in parser.links:
                    abs_url = urljoin(url, href).split("#")[0]
                    if abs_url not in self._visited and self.scope.in_scope(abs_url):
                        queue.append((abs_url, depth + 1))

                # Meta refresh redirects
                for redir in parser.meta_redirects:
                    abs_url = urljoin(url, redir).split("#")[0]
                    if abs_url not in self._visited and self.scope.in_scope(abs_url):
                        queue.append((abs_url, depth + 1))

            # ── JSON API discovery from JS files ──────────────────────────
            for src in parser.scripts[:12]:  # raised from 5 → 12
                js_url = urljoin(url, src)
                if not self.scope.in_scope(js_url):
                    continue
                try:
                    js_resp = self._fetch(js_url)
                    self._extract_api_paths_from_js(js_resp.text, url, queue)
                except Exception:
                    pass

            # ── JSON API responses: mine embedded paths ───────────────────
            if "application/json" in ct and depth == 0:
                try:
                    self._extract_api_paths_from_js(resp.text[:50_000], url, queue)
                except Exception:
                    pass

        return self.sitemap

    def _extract_api_paths_from_js(self, js_text: str, base_url: str, queue: deque | None = None):
        """Find API endpoints hardcoded in JS files and queue them for crawling."""
        patterns = [
            # Static path strings: "/api/users", '/v1/orders'
            (r'["\'](/(?:api|v\d+|rest|gql|graphql|internal|private|admin)[a-zA-Z0-9/_.-]{2,100})["\']', 1),
            # fetch() with URL string
            (r'fetch\s*\(\s*["\']([^"\'?#\s]{4,120})["\']', 1),
            # fetch() with options object: fetch(url, {method: 'POST'})
            (r'fetch\s*\(\s*["\']([^"\'?#\s]{4,120})["\'],\s*\{', 1),
            # axios.METHOD(url)
            (r'axios\s*\.\s*(?:get|post|put|patch|delete|head)\s*\(\s*["\']([^"\'?#\s]{4,120})["\']', 1),
            # axios({url: ...})
            (r'axios\s*\(\s*\{[^}]{0,200}url\s*:\s*["\']([^"\'?#\s]{4,120})["\']', 1),
            # $.ajax({url: ...}) / $.get / $.post
            (r'\$\s*\.\s*(?:ajax|get|post|getJSON|put)\s*\(\s*["\']([^"\'?#\s]{4,120})["\']', 1),
            # XMLHttpRequest: xhr.open("GET", "/api/...")
            (r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\'?#\s]{4,120})["\']', 1),
            # Angular HttpClient: this.http.get('/api/...')
            (r'(?:this\.)?(?:http|_http|httpClient)\s*\.\s*(?:get|post|put|patch|delete)\s*(?:<[^>]*>)?\s*\(\s*["\']([^"\'?#\s]{4,120})["\']', 1),
            # SWR / React Query hooks
            (r'use(?:SWR|Query|InfiniteQuery)\s*\(\s*["\']([^"\'?#\s]{4,120})["\']', 1),
            # URL variable assignments: apiUrl = "/api/v1/users"
            (r'(?:api|endpoint|base|backend|server)(?:Url|URL|Uri|Path|Host|_url|_path)?\s*[:=]\s*["\']([^"\'?#\s]{4,120})["\']', 1),
        ]
        seen: set[str] = set()
        for pat, grp in patterns:
            for m in re.finditer(pat, js_text, re.I):
                try:
                    path = m.group(grp)
                except IndexError:
                    continue
                if not path or len(path) < 4:
                    continue
                if path.startswith("/") or path.startswith("http"):
                    try:
                        abs_url = self.scope.normalise(path, base_url)
                    except Exception:
                        continue
                    if abs_url in seen:
                        continue
                    seen.add(abs_url)
                    if self.scope.in_scope(abs_url) and abs_url not in self._visited:
                        if queue is not None:
                            queue.append((abs_url, 1))
