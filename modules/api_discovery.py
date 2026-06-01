"""
API Route Discovery -- extracts API endpoints from JavaScript source files.
Parses fetch(), XMLHttpRequest, axios, $.ajax patterns to find hidden routes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests


@dataclass
class DiscoveredRoute:
    """An API route discovered from JavaScript analysis."""

    url: str
    method: str  # GET, POST, etc.
    source_file: str  # JS file it was found in
    pattern_type: str  # "fetch", "xhr", "axios", "jquery", "url_literal"
    confidence: str  # "high", "medium", "low"


# ---------------------------------------------------------------------------
# Compiled patterns (module-level for reuse)
# ---------------------------------------------------------------------------

# fetch("url") or fetch('url') with optional method
_FETCH_CALL_RE = re.compile(
    r"""fetch\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
_FETCH_METHOD_RE = re.compile(
    r"""fetch\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[^}]*?method\s*:\s*["'](\w+)["']""",
    re.IGNORECASE | re.DOTALL,
)

# XMLHttpRequest .open("METHOD", "url")
_XHR_RE = re.compile(
    r"""\.open\(\s*["'](\w+)["']\s*,\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)

# axios.get/post/put/delete/patch("url")
_AXIOS_METHOD_RE = re.compile(
    r"""axios\.(get|post|put|delete|patch|options|head)\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)

# axios({ url: "...", method: "..." })
_AXIOS_OBJ_RE = re.compile(
    r"""axios\(\s*\{[^}]*?url\s*:\s*["'`]([^"'`]+)["'`][^}]*?method\s*:\s*["'](\w+)["']""",
    re.IGNORECASE | re.DOTALL,
)
_AXIOS_OBJ_RE2 = re.compile(
    r"""axios\(\s*\{[^}]*?method\s*:\s*["'](\w+)["'][^}]*?url\s*:\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE | re.DOTALL,
)

# $.ajax({ url: "..." }), $.get("url"), $.post("url")
_JQUERY_AJAX_RE = re.compile(
    r"""\$\.ajax\(\s*\{[^}]*?url\s*:\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE | re.DOTALL,
)
_JQUERY_AJAX_METHOD_RE = re.compile(
    r"""\$\.ajax\(\s*\{[^}]*?url\s*:\s*["'`]([^"'`]+)["'`][^}]*?method\s*:\s*["'](\w+)["'][^}]*\}""",
    re.IGNORECASE | re.DOTALL,
)
_JQUERY_AJAX_METHOD_RE2 = re.compile(
    r"""\$\.ajax\(\s*\{[^}]*?method\s*:\s*["'](\w+)["'][^}]*?url\s*:\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE | re.DOTALL,
)
_JQUERY_GET_RE = re.compile(
    r"""\$\.(get|post|getJSON)\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)

# Generic /api/... URL literals inside strings
_URL_LITERAL_RE = re.compile(
    r"""["'`](/(?:api|v[1-9]\d*|rest|graphql|ws)/[a-zA-Z0-9/_\-\.]+)["'`]""",
)

# Inline script tag extraction
_SCRIPT_INLINE_RE = re.compile(
    r"<script[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)["']""",
    re.IGNORECASE,
)

# API path indicators
_API_PATH_SEGMENTS = ("/api", "/v1", "/v2", "/v3", "/rest", "/graphql", "/ws", "/webhook", "/rpc")
_API_EXTENSIONS = (".json", ".xml")


class ApiRouteDiscoverer:
    """Discovers API routes by analyzing JavaScript files."""

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        timeout: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self._seen: set[tuple[str, str]] = set()       # (url, method) route dedup
        self._fetched_js: set[str] = set()             # JS URLs already fetched

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_from_js_urls(self, js_urls: list[str]) -> list[DiscoveredRoute]:
        """Fetch JS files and extract routes. Each URL is fetched at most once."""
        routes: list[DiscoveredRoute] = []
        for url in js_urls:
            if url in self._fetched_js:
                continue
            self._fetched_js.add(url)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                resp.raise_for_status()
                routes.extend(self.discover_from_js_content(resp.text, url))
            except requests.RequestException:
                continue
        return routes

    def discover_from_js_content(self, content: str, source_url: str) -> list[DiscoveredRoute]:
        """Extract routes from JS source code."""
        raw: list[tuple[str, str, str, str]] = []  # (path, method, confidence, pattern_type)

        for path, method, conf in self._extract_fetch_routes(content):
            raw.append((path, method, conf, "fetch"))
        for path, method, conf in self._extract_xhr_routes(content):
            raw.append((path, method, conf, "xhr"))
        for path, method, conf in self._extract_axios_routes(content):
            raw.append((path, method, conf, "axios"))
        for path, method, conf in self._extract_jquery_routes(content):
            raw.append((path, method, conf, "jquery"))
        for path, method, conf in self._extract_url_literals(content):
            raw.append((path, method, conf, "url_literal"))

        routes: list[DiscoveredRoute] = []
        for path, method, confidence, pattern_type in raw:
            resolved = self._resolve_url(path, source_url)
            if resolved is None:
                continue
            method_upper = method.upper()
            key = (resolved, method_upper)
            if key in self._seen:
                continue
            self._seen.add(key)
            routes.append(
                DiscoveredRoute(
                    url=resolved,
                    method=method_upper,
                    source_file=source_url,
                    pattern_type=pattern_type,
                    confidence=confidence,
                )
            )
        return routes

    def discover_from_page_body(self, page_body: str, page_url: str) -> list[DiscoveredRoute]:
        """Extract inline JS and API routes from HTML page body.

        Returns discovered routes from inline scripts. Also populates
        external JS src URLs which can later be fetched with
        discover_from_js_urls.
        """
        routes: list[DiscoveredRoute] = []

        # Process inline <script> blocks
        for m in _SCRIPT_INLINE_RE.finditer(page_body):
            script_content = m.group(1).strip()
            if script_content:
                routes.extend(self.discover_from_js_content(script_content, page_url))

        # Collect external script src URLs and fetch them
        js_urls: list[str] = []
        for m in _SCRIPT_SRC_RE.finditer(page_body):
            src = m.group(1)
            resolved = self._resolve_url(src, page_url)
            if resolved:
                js_urls.append(resolved)

        if js_urls:
            routes.extend(self.discover_from_js_urls(js_urls))

        return routes

    # ------------------------------------------------------------------
    # Pattern extractors - return list[(path, method, confidence)]
    # ------------------------------------------------------------------

    def _extract_fetch_routes(self, content: str) -> list[tuple[str, str, str]]:
        """Extract routes from fetch() calls."""
        results: list[tuple[str, str, str]] = []

        # First pass: fetch with explicit method
        seen_urls: set[str] = set()
        for m in _FETCH_METHOD_RE.finditer(content):
            url, method = m.group(1), m.group(2)
            seen_urls.add(url)
            confidence = "high" if self._is_api_path(url) else "medium"
            results.append((url, method, confidence))

        # Second pass: fetch without method (defaults to GET)
        for m in _FETCH_CALL_RE.finditer(content):
            url = m.group(1)
            if url not in seen_urls:
                confidence = "high" if self._is_api_path(url) else "medium"
                results.append((url, "GET", confidence))

        return results

    def _extract_xhr_routes(self, content: str) -> list[tuple[str, str, str]]:
        """Extract routes from XMLHttpRequest.open() calls."""
        results: list[tuple[str, str, str]] = []
        for m in _XHR_RE.finditer(content):
            method, url = m.group(1), m.group(2)
            confidence = "high" if self._is_api_path(url) else "medium"
            results.append((url, method, confidence))
        return results

    def _extract_axios_routes(self, content: str) -> list[tuple[str, str, str]]:
        """Extract routes from axios.get/post/put/delete calls."""
        results: list[tuple[str, str, str]] = []

        # axios.method("url")
        for m in _AXIOS_METHOD_RE.finditer(content):
            method, url = m.group(1), m.group(2)
            confidence = "high" if self._is_api_path(url) else "medium"
            results.append((url, method, confidence))

        # axios({ url: "...", method: "..." }) - both orderings
        for m in _AXIOS_OBJ_RE.finditer(content):
            url, method = m.group(1), m.group(2)
            confidence = "high" if self._is_api_path(url) else "medium"
            results.append((url, method, confidence))

        for m in _AXIOS_OBJ_RE2.finditer(content):
            method, url = m.group(1), m.group(2)
            confidence = "high" if self._is_api_path(url) else "medium"
            results.append((url, method, confidence))

        return results

    def _extract_jquery_routes(self, content: str) -> list[tuple[str, str, str]]:
        """Extract routes from $.ajax, $.get, $.post calls."""
        results: list[tuple[str, str, str]] = []

        # $.ajax with method specified (both orderings)
        ajax_with_method: set[str] = set()
        for m in _JQUERY_AJAX_METHOD_RE.finditer(content):
            url, method = m.group(1), m.group(2)
            ajax_with_method.add(url)
            confidence = "high" if self._is_api_path(url) else "medium"
            results.append((url, method, confidence))

        for m in _JQUERY_AJAX_METHOD_RE2.finditer(content):
            method, url = m.group(1), m.group(2)
            if url not in ajax_with_method:
                ajax_with_method.add(url)
                confidence = "high" if self._is_api_path(url) else "medium"
                results.append((url, method, confidence))

        # $.ajax without explicit method (defaults to GET)
        for m in _JQUERY_AJAX_RE.finditer(content):
            url = m.group(1)
            if url not in ajax_with_method:
                confidence = "high" if self._is_api_path(url) else "medium"
                results.append((url, "GET", confidence))

        # $.get, $.post, $.getJSON
        for m in _JQUERY_GET_RE.finditer(content):
            shorthand, url = m.group(1).lower(), m.group(2)
            method = "POST" if shorthand == "post" else "GET"
            confidence = "high" if self._is_api_path(url) else "medium"
            results.append((url, method, confidence))

        return results

    def _extract_url_literals(self, content: str) -> list[tuple[str, str, str]]:
        """Extract /api/... URL patterns from string literals."""
        results: list[tuple[str, str, str]] = []
        for m in _URL_LITERAL_RE.finditer(content):
            url = m.group(1)
            results.append((url, "GET", "low"))
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_url(self, path: str, source_url: str) -> Optional[str]:
        """Resolve relative path to full URL. Skip data: and blob: URLs."""
        if not path:
            return None

        # Skip non-HTTP schemes
        lower = path.lower()
        if lower.startswith(("data:", "blob:", "javascript:", "mailto:")):
            return None

        # Already absolute
        if lower.startswith(("http://", "https://")):
            return path

        # Resolve against base_url (not source_url) for consistency
        return urljoin(self.base_url + "/", path)

    def _is_api_path(self, path: str) -> bool:
        """Check if path looks like an API endpoint."""
        lower = path.lower()
        for segment in _API_PATH_SEGMENTS:
            if segment in lower:
                return True
        for ext in _API_EXTENSIONS:
            if lower.endswith(ext):
                return True
        return False


def extract_sourcemap_endpoints(sourcemap_data) -> list[str]:
    """Extract API endpoint paths from a JavaScript source map.

    Source maps contain original source file paths and content, which often
    reveal internal API routes, service names, and endpoint patterns not
    visible in the compiled bundle.

    Args:
        sourcemap_data: Either a JSON string or already-parsed dict of the .map file

    Returns:
        List of discovered endpoint paths and service names
    """
    import json, re

    if isinstance(sourcemap_data, str):
        try:
            sourcemap_data = json.loads(sourcemap_data)
        except Exception:
            return []

    if not isinstance(sourcemap_data, dict):
        return []

    endpoints = set()

    # Source file names often reveal service/module structure
    sources = sourcemap_data.get('sources', [])
    for src in sources:
        if isinstance(src, str):
            # Extract path components that look like API routes
            # e.g. "src/services/api/users.js" -> "/api/users"
            parts = src.replace('\\', '/').split('/')
            for i, part in enumerate(parts):
                if part in ('api', 'services', 'routes', 'endpoints', 'controllers'):
                    # Build path from this component forward
                    api_path = '/' + '/'.join(parts[i:]).replace('.js', '').replace('.ts', '')
                    if len(api_path) > 3:
                        endpoints.add(api_path)

    # Also scan sourcesContent if available
    sources_content = sourcemap_data.get('sourcesContent', [])
    for content in sources_content:
        if isinstance(content, str) and len(content) > 0:
            # Re-use webpack extraction on original source content
            try:
                from .source_discovery import extract_webpack_endpoints
                found = extract_webpack_endpoints(content[:5000])  # Limit per source
                endpoints.update(found)
            except Exception:
                pass

    return sorted(endpoints)
