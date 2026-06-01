"""
BrowserSession — requests.Session-compatible wrapper backed by Playwright's
Chromium APIRequestContext.  All traffic goes through the real Chromium
network stack, so the scanner presents a genuine browser TLS fingerprint and
headers (sec-ch-ua, Accept-Language, etc.) instead of python-requests.

Drop-in replacement for PassiveInterceptSession: also runs the passive
scanner on every response so no findings are missed.
"""
from __future__ import annotations

import json as _json
import logging
import threading
import time
from datetime import timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlparse, urlunparse

log = logging.getLogger("dast.browser_session")

if TYPE_CHECKING:
    from .passive import PassiveScanner


# ── Playwright availability guard ─────────────────────────────────────────────
try:
    from playwright.sync_api import sync_playwright as _sync_playwright
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False


class BrowserResponse:
    """requests.Response-compatible wrapper around a Playwright APIResponse."""

    def __init__(self, pw_resp, url: str, elapsed: float = 0.0):
        self.status_code: int  = pw_resp.status
        self.url: str          = url
        self.headers: dict     = dict(pw_resp.headers)
        self.content: bytes    = pw_resp.body()
        self.encoding: str     = "utf-8"
        self.elapsed           = timedelta(seconds=elapsed)

        try:
            self.text: str = self.content.decode(self.encoding, errors="replace")
        except Exception:
            self.text = ""

    def json(self):
        return _json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            from requests.exceptions import HTTPError
            raise HTTPError(f"HTTP {self.status_code}", response=self)

    @property
    def ok(self) -> bool:
        return self.status_code < 400


class _CookieCompat:
    """Minimal cookie jar that satisfies `{c.name: c.value for c in session.cookies}`."""

    def __init__(self):
        self._jar: dict[str, str] = {}

    def __iter__(self):
        for name, value in self._jar.items():
            yield _CookieEntry(name, value)

    def __setitem__(self, name: str, value: str):
        self._jar[name] = value

    def __getitem__(self, name: str) -> str:
        return self._jar[name]

    def update(self, d: dict):
        self._jar.update(d)


class _CookieEntry:
    __slots__ = ("name", "value")

    def __init__(self, name: str, value: str):
        self.name  = name
        self.value = value


class BrowserSession:
    """
    requests.Session-compatible HTTP client using Playwright's Chromium
    APIRequestContext.  Requests are made via the browser's network stack —
    no python-requests involved.

    Also mirrors PassiveInterceptSession: every response is analysed by the
    global passive scanner so header/cookie findings are not lost.
    """

    def __init__(self, scanner: PassiveScanner | None = None):
        if not _PLAYWRIGHT_OK:
            raise RuntimeError(
                "Playwright is not installed.  Install it with:\n"
                "  pip install playwright && playwright install chromium"
            )

        from .passive import passive_scanner as _default_scanner
        self._scanner   = scanner or _default_scanner
        self._lock      = threading.Lock()
        self._headers_lock = threading.Lock()
        self._pw        = None
        self._browser   = None
        self._context   = None
        self._request   = None   # Playwright APIRequestContext
        self._started   = False

        # Public attributes that callers read/write (mirrors requests.Session)
        self.headers  = {}
        self.cookies  = _CookieCompat()
        self.verify   = False

        # Passive-scan dedup
        self._passive_seen: set[tuple[str, str, str]] = set()
        self._passive_lock = threading.Lock()
        self._passive_findings: list = []

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def _ensure_started(self):
        if self._started:
            return
        with self._lock:
            if self._started:
                return
            log.info("[BrowserSession] Launching headless Chromium…")
            self._pw      = _sync_playwright().start()
            self._browser = self._pw.chromium.launch(
                headless=True,
                args=["--ignore-certificate-errors", "--no-sandbox",
                      "--disable-dev-shm-usage"],
            )
            self._context = self._browser.new_context(
                ignore_https_errors=True,
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
            self._request = self._context.request
            self._started = True
            log.info("[BrowserSession] Chromium ready")

    def close(self):
        with self._lock:
            if not self._started:
                return
            try:
                self._browser.close()
            except Exception:
                pass
            try:
                self._pw.stop()
            except Exception:
                pass
            self._started = False
            log.info("[BrowserSession] Chromium closed")

    def mount(self, prefix, adapter):
        pass  # no-op: Playwright handles retries at the context level

    # ── request methods ───────────────────────────────────────────────────────

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def request(self, method: str, url: str, *,
                headers: dict | None = None,
                params: dict | None = None,
                data=None,
                json=None,
                timeout=None,
                allow_redirects: bool = True,
                verify=None,
                **_ignored) -> BrowserResponse:

        self._ensure_started()

        # Snapshot session headers under lock to avoid dict-size-change races
        with self._headers_lock:
            merged_headers = {**self.headers, **(headers or {})}

        # Append query params to URL
        if params:
            parsed = urlparse(url)
            qs     = urlencode(params)
            url    = urlunparse(parsed._replace(
                query=(parsed.query + "&" + qs) if parsed.query else qs
            ))

        # Build Playwright fetch options (ignore_https_errors is context-level only)
        opts: dict = {
            "headers":       merged_headers,
            "max_redirects": 10 if allow_redirects else 0,
        }

        if timeout is not None:
            opts["timeout"] = int(timeout * 1000)  # seconds → ms

        if json is not None:
            merged_headers.setdefault("Content-Type", "application/json")
            opts["headers"] = merged_headers
            opts["data"]    = _json.dumps(json)
        elif data is not None:
            if isinstance(data, dict):
                opts["form"] = data
            else:
                opts["data"] = data

        t0 = time.monotonic()
        try:
            pw_resp = self._request.fetch(url, method=method.upper(), **opts)
        except Exception as exc:
            log.debug("[BrowserSession] %s %s → %s", method, url, exc)
            raise

        resp = BrowserResponse(pw_resp, url, elapsed=time.monotonic() - t0)

        # Sync cookies only when the response actually sets them
        if "set-cookie" in resp.headers:
            try:
                for c in self._context.cookies():
                    self.cookies[c["name"]] = c["value"]
            except Exception:
                log.debug("[BrowserSession] cookie sync failed", exc_info=True)

        self._run_passive(url, resp, merged_headers)
        return resp

    # ── passive scan integration ───────────────────────────────────────────────

    def _run_passive(self, url: str, resp: BrowserResponse, req_headers: dict):
        try:
            body = resp.text[:8000]
            results = self._scanner.scan(
                url=url,
                status_code=resp.status_code,
                resp_headers=resp.headers,
                resp_body=body,
                cookies={c.name: c.value for c in self.cookies},
                request_headers=req_headers,
            )
            if not results:
                return
            path = urlparse(url).path
            with self._passive_lock:
                for f in results:
                    key = (path, f.category, f.finding)
                    if key not in self._passive_seen:
                        self._passive_seen.add(key)
                        self._passive_findings.append(f)
        except Exception:
            pass  # never let passive scanning interrupt the caller

    @property
    def findings(self) -> list:
        with self._passive_lock:
            return list(self._passive_findings)
