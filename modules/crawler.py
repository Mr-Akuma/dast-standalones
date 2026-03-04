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


# ── HTML Parser ────────────────────────────────────────────────────────────────

class _PageParser(HTMLParser):
    """Extract links, forms, scripts, and input parameters from a page."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url   = base_url
        self.links:     list[str] = []
        self.forms:     list[dict] = []
        self.scripts:   list[str] = []
        self._cur_form: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs: list):
        a = dict(attrs)
        tag = tag.lower()

        if tag == "a" and "href" in a:
            self.links.append(a["href"])

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

        elif tag == "button" and self._cur_form is not None:
            if a.get("type", "").lower() == "submit":
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
                 "headers", "body_template", "content_type")

    def __init__(self, url: str, method: str, param: str, param_type: str,
                 original_value: str = "", headers: dict | None = None,
                 body_template: str = "", content_type: str = ""):
        self.url            = url
        self.method         = method.upper()
        self.param          = param
        self.param_type     = param_type    # "query", "form", "json", "header", "path", "cookie"
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
            # Avoid duplicates
            key = (surface.url, surface.method, surface.param, surface.param_type)
            for s in self.surfaces:
                if (s.url, s.method, s.param, s.param_type) == key:
                    return
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

    def stop(self):
        self._stop = True

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
        for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
                     "/api", "/api/v1", "/api/v2", "/swagger.json", "/openapi.json",
                     "/api-docs", "/.git/config", "/.env", "/admin", "/login",
                     "/wp-admin", "/phpmyadmin", "/graphql"]:
            queue.append((self.scope.normalise(path), 0))

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

            # Queue discovered links
            if depth < self.max_depth:
                for href in parser.links:
                    abs_url = urljoin(url, href).split("#")[0]
                    if abs_url not in self._visited and self.scope.in_scope(abs_url):
                        queue.append((abs_url, depth + 1))

            # ── JSON API discovery from JS files ──────────────────────────
            for src in parser.scripts[:5]:  # limit JS analysis to first 5
                js_url = urljoin(url, src)
                if not self.scope.in_scope(js_url):
                    continue
                try:
                    js_resp = self._fetch(js_url)
                    self._extract_api_paths_from_js(js_resp.text, url)
                except Exception:
                    pass

        return self.sitemap

    def _extract_api_paths_from_js(self, js_text: str, base_url: str):
        """Find API endpoints hardcoded in JS files."""
        # Match patterns like: "/api/users", '/v1/orders', fetch("/endpoint")
        patterns = [
            r'["\'](/api/[a-z0-9/_-]{2,60})["\']',
            r'["\'](/v\d+/[a-z0-9/_-]{2,60})["\']',
            r'fetch\(["\']([^"\']{3,80})["\']',
            r'axios\.(get|post|put|delete|patch)\(["\']([^"\']{3,80})["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, js_text, re.I):
                path = m.group(1) if "axios" not in pat else m.group(2)
                if path.startswith("/") or path.startswith("http"):
                    abs_url = self.scope.normalise(path, base_url)
                    if self.scope.in_scope(abs_url) and abs_url not in self._visited:
                        self.sitemap.add_page(abs_url, 0, "discovered", {}, "JS-discovered")
                        # Add as GET surface with no params (will be picked up on next crawl pass)
                        self._visited.discard(abs_url)  # allow crawling
