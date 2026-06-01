"""
Session Record & Replay — Burp-style HTTP traffic capture and playback.

Record mode:  Wraps a requests.Session to capture every HTTP exchange.
              Saves to Burp XML or native JSON format.

Replay mode:  Loads a saved session (Burp XML or JSON) and reconstructs
              InputSurface objects + SiteMap for scanning/fuzzing.

Usage (headless CLI):
    Record:  python3 main.py --headless --target http://app --record-session traffic.json
    Replay:  python3 main.py --headless --target http://app --replay-session traffic.json
    Burp:    python3 main.py --headless --target http://app --replay-session burp_export.xml
"""
from __future__ import annotations

import base64
import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode

import requests


# Max response body size to capture per entry (64KB)
_MAX_BODY_SIZE = 65536

# Cookie names that likely carry session/auth state
_SESSION_COOKIE_RE = re.compile(
    r"\b(session|auth|token|sid|jwt|access|refresh|credential|id_token|bearer)\b", re.I
)


class HttpExchange:
    """Single captured HTTP request/response pair."""
    __slots__ = (
        "timestamp", "method", "url", "request_headers", "request_body",
        "status_code", "response_headers", "response_body", "elapsed_ms",
    )

    def __init__(
        self,
        method: str,
        url: str,
        request_headers: dict,
        request_body: str,
        status_code: int,
        response_headers: dict,
        response_body: str,
        elapsed_ms: float = 0,
        timestamp: str = "",
    ):
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.method = method.upper()
        self.url = url
        self.request_headers = request_headers
        self.request_body = request_body
        self.status_code = status_code
        self.response_headers = response_headers
        self.response_body = response_body[:_MAX_BODY_SIZE]
        self.elapsed_ms = elapsed_ms

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "elapsed_ms": self.elapsed_ms,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HttpExchange":
        return cls(
            method=d.get("method", "GET"),
            url=d.get("url", ""),
            request_headers=d.get("request_headers", {}),
            request_body=d.get("request_body", ""),
            status_code=d.get("status_code", 0),
            response_headers=d.get("response_headers", {}),
            response_body=d.get("response_body", ""),
            elapsed_ms=d.get("elapsed_ms", 0),
            timestamp=d.get("timestamp", ""),
        )

    def to_raw_request(self) -> str:
        """Reconstruct raw HTTP request text."""
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = [f"{self.method} {path} HTTP/1.1"]
        if "Host" not in self.request_headers and "host" not in self.request_headers:
            lines.append(f"Host: {parsed.netloc}")
        for k, v in self.request_headers.items():
            lines.append(f"{k}: {v}")
        raw = "\r\n".join(lines) + "\r\n\r\n"
        if self.request_body:
            raw += self.request_body
        return raw

    def to_raw_response(self) -> str:
        """Reconstruct raw HTTP response text."""
        lines = [f"HTTP/1.1 {self.status_code} OK"]
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {v}")
        raw = "\r\n".join(lines) + "\r\n\r\n"
        raw += self.response_body
        return raw


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION RECORDER — wraps requests.Session to capture all traffic
# ═══════════════════════════════════════════════════════════════════════════════

class SessionRecorder:
    """
    Wraps any requests.Session (including PassiveInterceptSession) to record
    all HTTP exchanges for later export or replay.
    """

    def __init__(self, session: requests.Session):
        self.session = session
        self.exchanges: list[HttpExchange] = []
        self._lock = threading.Lock()
        self._original_request = session.request
        # Monkey-patch the session's request method
        session.request = self._intercepting_request

    def _intercepting_request(self, method, url, **kwargs):
        """Intercept every request, record exchange, pass through."""
        # Capture request details
        req_headers = dict(self.session.headers)
        req_headers.update(kwargs.get("headers", {}) or {})
        req_body = ""
        if kwargs.get("data"):
            d = kwargs["data"]
            req_body = d if isinstance(d, str) else urlencode(d) if isinstance(d, dict) else str(d)
        elif kwargs.get("json"):
            req_body = json.dumps(kwargs["json"])

        # Execute the actual request
        start = time.time()
        resp = self._original_request(method, url, **kwargs)
        elapsed = (time.time() - start) * 1000

        # Capture response
        resp_body = ""
        try:
            resp_body = resp.text[:_MAX_BODY_SIZE]
        except Exception:
            pass

        exchange = HttpExchange(
            method=method,
            url=resp.url or url,
            request_headers=req_headers,
            request_body=req_body,
            status_code=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp_body,
            elapsed_ms=elapsed,
        )

        with self._lock:
            self.exchanges.append(exchange)

        return resp

    def stop(self):
        """Restore the original request method."""
        self.session.request = self._original_request

    # ── Export: Native JSON ────────────────────────────────────────────────────

    def save_json(self, path: str) -> int:
        """Save all recorded exchanges to JSON. Returns count saved."""
        with self._lock:
            data = {
                "format": "dast-session-log",
                "version": "1.0",
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "count": len(self.exchanges),
                "exchanges": [e.to_dict() for e in self.exchanges],
            }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return data["count"]

    # ── Export: Burp XML ──────────────────────────────────────────────────────

    def save_burp_xml(self, path: str) -> int:
        """Save all recorded exchanges in Burp Suite XML format. Returns count."""
        with self._lock:
            exchanges = list(self.exchanges)

        root = ET.Element("items", burpVersion="2024.0", exportTime=datetime.now().isoformat())
        for i, ex in enumerate(exchanges):
            item = ET.SubElement(root, "item")

            ET.SubElement(item, "time").text = ex.timestamp
            ET.SubElement(item, "url").text = ex.url
            parsed = urlparse(ex.url)
            ET.SubElement(item, "host", ip="").text = parsed.hostname or ""
            ET.SubElement(item, "port").text = str(parsed.port or (443 if parsed.scheme == "https" else 80))
            ET.SubElement(item, "protocol").text = parsed.scheme or "https"
            ET.SubElement(item, "method").text = ex.method
            ET.SubElement(item, "path").text = parsed.path or "/"
            ET.SubElement(item, "extension").text = (parsed.path.rsplit(".", 1)[-1]
                                                     if "." in (parsed.path or "") else "")
            # Base64 encode request and response
            req_elem = ET.SubElement(item, "request", base64="true")
            req_elem.text = base64.b64encode(ex.to_raw_request().encode("utf-8", errors="replace")).decode()
            ET.SubElement(item, "status").text = str(ex.status_code)
            ET.SubElement(item, "responselength").text = str(len(ex.response_body))
            ET.SubElement(item, "mimetype").text = ex.response_headers.get("Content-Type", "")
            resp_elem = ET.SubElement(item, "response", base64="true")
            resp_elem.text = base64.b64encode(ex.to_raw_response().encode("utf-8", errors="replace")).decode()
            ET.SubElement(item, "comment").text = ""

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(path, encoding="unicode", xml_declaration=True)
        return len(exchanges)


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION LOADER — import Burp XML or native JSON
# ═══════════════════════════════════════════════════════════════════════════════

def load_session(path: str) -> list[HttpExchange]:
    """
    Load a session log file. Auto-detects format (Burp XML or native JSON).
    Returns list of HttpExchange objects.
    """
    with open(path, "r", errors="replace") as f:
        head = f.read(256)

    if head.lstrip().startswith("<?xml") or head.lstrip().startswith("<items"):
        return _load_burp_xml(path)
    else:
        return _load_json(path)


def _load_json(path: str) -> list[HttpExchange]:
    """Load native JSON session log."""
    with open(path, "r") as f:
        data = json.load(f)
    exchanges = []
    for entry in data.get("exchanges", []):
        exchanges.append(HttpExchange.from_dict(entry))
    return exchanges


def _load_burp_xml(path: str) -> list[HttpExchange]:
    """Load Burp Suite XML export."""
    tree = ET.parse(path)
    root = tree.getroot()
    exchanges = []

    for item in root.findall("item"):
        url = (item.findtext("url") or "").strip()
        method = (item.findtext("method") or "GET").strip()
        status = int(item.findtext("status") or "0")
        timestamp = (item.findtext("time") or "")

        # Decode request
        req_elem = item.find("request")
        req_raw = ""
        if req_elem is not None and req_elem.text:
            if req_elem.get("base64") == "true":
                try:
                    req_raw = base64.b64decode(req_elem.text).decode("utf-8", errors="replace")
                except Exception:
                    req_raw = req_elem.text
            else:
                req_raw = req_elem.text

        # Decode response
        resp_elem = item.find("response")
        resp_raw = ""
        if resp_elem is not None and resp_elem.text:
            if resp_elem.get("base64") == "true":
                try:
                    resp_raw = base64.b64decode(resp_elem.text).decode("utf-8", errors="replace")
                except Exception:
                    resp_raw = resp_elem.text
            else:
                resp_raw = resp_elem.text

        # Parse request headers and body
        req_headers, req_body = _parse_raw_http(req_raw, is_request=True)
        resp_headers, resp_body = _parse_raw_http(resp_raw, is_request=False)

        exchanges.append(HttpExchange(
            method=method,
            url=url,
            request_headers=req_headers,
            request_body=req_body,
            status_code=status,
            response_headers=resp_headers,
            response_body=resp_body[:_MAX_BODY_SIZE],
            timestamp=timestamp,
        ))

    return exchanges


def _parse_raw_http(raw: str, is_request: bool = True) -> tuple[dict, str]:
    """Parse raw HTTP message into (headers_dict, body_str)."""
    if not raw:
        return {}, ""
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) == 1:
        parts = raw.split("\n\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    headers = {}
    lines = header_block.split("\r\n") if "\r\n" in header_block else header_block.split("\n")
    # Skip first line (request line or status line)
    for line in lines[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k] = v

    return headers, body


def _extract_auth_from_exchanges(exchanges: list) -> dict:
    """Scan recorded exchanges for session cookies and Bearer tokens.

    Reads response Set-Cookie headers (auth-named cookies only) and request
    Authorization: Bearer headers. Last value wins — assumes final exchange
    reflects the post-login authenticated state.
    """
    cookies: dict[str, str] = {}
    authorization: Optional[str] = None
    for ex in exchanges:
        set_cookie = (ex.response_headers.get("Set-Cookie", "")
                      or ex.response_headers.get("set-cookie", ""))
        if set_cookie:
            for cookie_str in set_cookie.split("\n"):
                name_val = cookie_str.strip().split(";")[0].strip()
                if "=" in name_val:
                    name, val = name_val.split("=", 1)
                    if _SESSION_COOKIE_RE.search(name.strip()):
                        cookies[name.strip()] = val.strip()
        auth_hdr = (ex.request_headers.get("Authorization", "")
                    or ex.request_headers.get("authorization", ""))
        if auth_hdr and auth_hdr.lower().startswith("bearer "):
            authorization = auth_hdr
    return {"cookies": cookies, "authorization": authorization}


# ═══════════════════════════════════════════════════════════════════════════════
# REPLAY → SITEMAP — convert exchanges into fuzzable surfaces
# ═══════════════════════════════════════════════════════════════════════════════

def replay_to_sitemap(exchanges: list[HttpExchange], scope=None,
                      inject_session: Optional[requests.Session] = None):
    """
    Convert loaded exchanges into a SiteMap with pages and InputSurfaces.
    Optionally filter by scope.

    Returns: SiteMap
    """
    from .crawler import SiteMap, InputSurface

    sitemap = SiteMap()

    for ex in exchanges:
        # Skip non-HTTP or out-of-scope
        if scope and not scope.in_scope(ex.url):
            continue

        # Add as page
        ct = ex.response_headers.get("Content-Type", "")
        sitemap.add_page(ex.url, ex.status_code, ct, ex.response_headers)

        parsed = urlparse(ex.url)

        # Extract query parameters as surfaces
        if parsed.query:
            for param, values in parse_qs(parsed.query).items():
                sitemap.add_surface(InputSurface(
                    url=ex.url,
                    method=ex.method,
                    param=param,
                    param_type="query",
                    original_value=values[0] if values else "",
                ))

        # Extract form/JSON body parameters
        if ex.request_body and ex.method in ("POST", "PUT", "PATCH"):
            content_type = (ex.request_headers.get("Content-Type", "") or
                            ex.request_headers.get("content-type", ""))

            if "json" in content_type:
                # JSON body
                try:
                    body_data = json.loads(ex.request_body)
                    if isinstance(body_data, dict):
                        for param, val in body_data.items():
                            sitemap.add_surface(InputSurface(
                                url=ex.url,
                                method=ex.method,
                                param=param,
                                param_type="json",
                                original_value=str(val),
                                body_template=ex.request_body,
                                content_type=content_type,
                            ))
                except (json.JSONDecodeError, ValueError):
                    pass
            else:
                # URL-encoded form body
                try:
                    for param, values in parse_qs(ex.request_body).items():
                        sitemap.add_surface(InputSurface(
                            url=ex.url,
                            method=ex.method,
                            param=param,
                            param_type="form",
                            original_value=values[0] if values else "",
                            body_template=ex.request_body,
                            content_type=content_type or "application/x-www-form-urlencoded",
                        ))
                except Exception:
                    pass

        # Extract cookie parameters
        cookie_header = ex.request_headers.get("Cookie", "") or ex.request_headers.get("cookie", "")
        if cookie_header:
            for part in cookie_header.split(";"):
                if "=" in part:
                    name, val = part.strip().split("=", 1)
                    sitemap.add_surface(InputSurface(
                        url=ex.url,
                        method=ex.method,
                        param=name.strip(),
                        param_type="cookie",
                        original_value=val.strip(),
                    ))

    if inject_session is not None:
        auth = _extract_auth_from_exchanges(exchanges)
        for name, value in auth["cookies"].items():
            inject_session.cookies.set(name, value)
        if auth["authorization"]:
            inject_session.headers["Authorization"] = auth["authorization"]

    return sitemap
