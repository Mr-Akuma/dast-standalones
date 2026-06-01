"""
Payload Injection Engine — Burp Intruder / ZAP Active Scan equivalent.

Structured payload injection with:
  1. Request templating from raw HTTP or TrafficExchange objects
  2. Automatic injection point discovery (query, form, header, cookie, path, JSON, XML)
  3. Context-aware encoding per injection point type
  4. Position markers (§value§) for targeted injection
  5. One-at-a-time parameter replacement (sniper mode)
  6. Battering ram mode (all positions at once)
  7. Response analysis using existing DETECTORS from fuzzer.py

Attack modes (Burp-compatible):
  - SNIPER:        One position at a time, one payload at a time
  - BATTERING_RAM: Same payload in all positions simultaneously
  - PITCHFORK:     Different payload list per position (parallel iteration)
  - CLUSTER_BOMB:  All combinations of payload lists across positions

Usage:
    from modules.payload_injector import PayloadInjector, RequestTemplate

    # From a captured traffic exchange:
    template = RequestTemplate.from_traffic_exchange(exchange)

    # Or from raw HTTP:
    template = RequestTemplate.from_raw_http(raw_request, base_url)

    # Or manual:
    template = RequestTemplate(method="GET", url="https://target.com/search",
                               query_params={"q": "test"})

    injector = PayloadInjector(session=session, scope=scope)
    findings = injector.run(template, attack_mode="sniper",
                            vuln_types=["sqli_error", "xss_reflected"])
"""
from __future__ import annotations

import html
import json
import re
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional
from urllib.parse import (
    parse_qs, urlencode, urlparse, urlunparse, quote, unquote,
)

import requests
import requests.exceptions

from .fuzzer import PAYLOADS, DETECTORS, FuzzResult
from .scope import ScopeManager
from .evidence import EvidenceStore, evidence_store as _global_store


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

POSITION_MARKER = "§"  # Burp-style position marker

_MAX_PAYLOADS_PER_POINT = 12   # Max payloads per injection point per vuln type
_MAX_INJECTION_POINTS = 50     # Don't fuzz more than 50 positions per request


# ═══════════════════════════════════════════════════════════════════════════════
# ENCODING CONTEXTS
# ═══════════════════════════════════════════════════════════════════════════════

class EncodingContext(Enum):
    """Encoding context determines how payloads are transformed before injection."""
    URL_QUERY    = "url_query"      # URL-encode for query string
    URL_PATH     = "url_path"       # URL-encode for path segment
    FORM_BODY    = "form_body"      # URL-encode for application/x-www-form-urlencoded
    HTML_BODY    = "html_body"      # HTML-entity-encode
    JSON_VALUE   = "json_value"     # JSON-escape (quotes, backslash, control chars)
    XML_VALUE    = "xml_value"      # XML-escape (&, <, >, ", ')
    HEADER_VALUE = "header_value"   # Strip CR/LF (prevent header injection by encoding)
    COOKIE_VALUE = "cookie_value"   # URL-encode for cookie value
    MULTIPART    = "multipart"      # Raw (multipart boundary handles separation)
    RAW          = "raw"            # No encoding — payload as-is


def encode_payload(payload: str, context: EncodingContext) -> str:
    """Apply context-appropriate encoding to a payload string."""
    if context == EncodingContext.RAW or context == EncodingContext.MULTIPART:
        return payload

    if context == EncodingContext.URL_QUERY:
        return quote(payload, safe="")

    if context == EncodingContext.URL_PATH:
        return quote(payload, safe="/")

    if context == EncodingContext.FORM_BODY:
        return quote(payload, safe="")

    if context == EncodingContext.HTML_BODY:
        return html.escape(payload)

    if context == EncodingContext.JSON_VALUE:
        # json.dumps adds surrounding quotes — strip them
        return json.dumps(payload)[1:-1]

    if context == EncodingContext.XML_VALUE:
        return (payload
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;"))

    if context == EncodingContext.HEADER_VALUE:
        # Strip CR/LF to prevent header injection
        return payload.replace("\r", "").replace("\n", "")

    if context == EncodingContext.COOKIE_VALUE:
        return quote(payload, safe="")

    return payload


# ═══════════════════════════════════════════════════════════════════════════════
# INJECTION POINT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class InjectionPoint:
    """A single injectable position within a request."""
    location:  str                # "query", "form", "header", "cookie", "path", "json", "xml"
    name:      str                # Parameter/header/cookie name, or path segment index
    value:     str                # Original value at this position
    context:   EncodingContext    # Encoding to apply
    index:     int = 0           # For positional (path segments, JSON arrays)
    json_path: str = ""          # Dot-notation path for nested JSON (e.g. "user.name")

    @property
    def display(self) -> str:
        if self.json_path:
            return f"{self.location}:{self.json_path}"
        return f"{self.location}:{self.name}"


# ═══════════════════════════════════════════════════════════════════════════════
# REQUEST TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RequestTemplate:
    """
    A parsed HTTP request with discovered injection points.
    Immutable template — injection creates modified copies.
    """
    method:        str = "GET"
    url:           str = ""
    path:          str = ""
    query_params:  dict = field(default_factory=dict)   # {name: value}
    headers:       dict = field(default_factory=dict)    # {name: value}
    cookies:       dict = field(default_factory=dict)    # {name: value}
    body:          str = ""
    body_type:     str = ""     # "form", "json", "xml", "multipart", "raw"
    form_params:   dict = field(default_factory=dict)    # parsed form body
    json_body:     object = None  # parsed JSON body
    injection_points: list = field(default_factory=list)  # list[InjectionPoint]

    @classmethod
    def from_traffic_exchange(cls, exchange) -> "RequestTemplate":
        """Create a template from a TrafficExchange object."""
        parsed = urlparse(exchange.url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        # Flatten single-value lists
        query_flat = {k: v[0] if len(v) == 1 else v[0] for k, v in query.items()}

        tpl = cls(
            method=exchange.method.upper(),
            url=exchange.url,
            path=parsed.path,
            query_params=query_flat,
            headers=dict(exchange.request_headers),
            body=exchange.request_body or "",
        )

        # Parse cookies from headers
        cookie_hdr = tpl.headers.get("Cookie", tpl.headers.get("cookie", ""))
        if cookie_hdr:
            for pair in cookie_hdr.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    tpl.cookies[k.strip()] = v.strip()

        # Detect body type and parse
        ct = tpl.headers.get("Content-Type", tpl.headers.get("content-type", ""))
        tpl._detect_body_type(ct)

        # Discover injection points
        tpl._discover_injection_points()
        return tpl

    @classmethod
    def from_raw_http(cls, raw: str, base_url: str = "") -> "RequestTemplate":
        """Parse a raw HTTP request string into a template."""
        lines = raw.strip().split("\n")
        if not lines:
            return cls()

        # Request line
        parts = lines[0].strip().split(" ", 2)
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        # Build full URL
        if path.startswith("http"):
            url = path
        elif base_url:
            url = base_url.rstrip("/") + path
        else:
            url = path

        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query_flat = {k: v[0] if len(v) == 1 else v[0] for k, v in query.items()}

        # Headers
        headers = {}
        body_start = len(lines)
        for i, line in enumerate(lines[1:], 1):
            stripped = line.strip()
            if not stripped:
                body_start = i + 1
                break
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                headers[k.strip()] = v.strip()

        # Body
        body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""

        tpl = cls(
            method=method,
            url=url,
            path=parsed.path,
            query_params=query_flat,
            headers=headers,
            body=body,
        )

        # Parse cookies
        cookie_hdr = headers.get("Cookie", headers.get("cookie", ""))
        if cookie_hdr:
            for pair in cookie_hdr.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    tpl.cookies[k.strip()] = v.strip()

        ct = headers.get("Content-Type", headers.get("content-type", ""))
        tpl._detect_body_type(ct)
        tpl._discover_injection_points()
        return tpl

    @classmethod
    def from_url(cls, method: str, url: str, headers: dict | None = None,
                 body: str = "", content_type: str = "") -> "RequestTemplate":
        """Create a template from URL components."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query_flat = {k: v[0] if len(v) == 1 else v[0] for k, v in query.items()}

        tpl = cls(
            method=method.upper(),
            url=url,
            path=parsed.path,
            query_params=query_flat,
            headers=dict(headers or {}),
            body=body,
        )
        # Parse cookies from headers
        cookie_hdr = tpl.headers.get("Cookie", tpl.headers.get("cookie", ""))
        if cookie_hdr:
            for pair in cookie_hdr.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    tpl.cookies[k.strip()] = v.strip()

        tpl._detect_body_type(content_type or tpl.headers.get("Content-Type", ""))
        tpl._discover_injection_points()
        return tpl

    def _detect_body_type(self, content_type: str):
        """Detect body type from content-type header and parse accordingly."""
        ct = content_type.lower()
        if "json" in ct:
            self.body_type = "json"
            try:
                self.json_body = json.loads(self.body)
            except (json.JSONDecodeError, TypeError):
                self.json_body = None
        elif "xml" in ct or "soap" in ct:
            self.body_type = "xml"
        elif "multipart" in ct:
            self.body_type = "multipart"
        elif "x-www-form-urlencoded" in ct or (self.body and "=" in self.body):
            self.body_type = "form"
            pairs = parse_qs(self.body, keep_blank_values=True)
            self.form_params = {k: v[0] if len(v) == 1 else v[0] for k, v in pairs.items()}
        elif self.body:
            self.body_type = "raw"

    def _discover_injection_points(self):
        """Auto-discover all injectable positions in the request."""
        points: list[InjectionPoint] = []

        # 1. Query parameters
        for name, value in self.query_params.items():
            points.append(InjectionPoint(
                location="query", name=name, value=str(value),
                context=EncodingContext.URL_QUERY,
            ))

        # 2. Form body parameters
        for name, value in self.form_params.items():
            points.append(InjectionPoint(
                location="form", name=name, value=str(value),
                context=EncodingContext.FORM_BODY,
            ))

        # 3. JSON body — flatten to dot-notation paths
        if self.json_body is not None:
            self._discover_json_points(self.json_body, "", points)

        # 4. XML body — find attribute values and text nodes
        if self.body_type == "xml" and self.body:
            self._discover_xml_points(points)

        # 5. Headers (skip Host, Content-Length, Content-Type)
        skip_headers = {"host", "content-length", "content-type", "accept",
                        "accept-encoding", "accept-language", "connection",
                        "user-agent", "cookie"}
        for name, value in self.headers.items():
            if name.lower() not in skip_headers:
                points.append(InjectionPoint(
                    location="header", name=name, value=value,
                    context=EncodingContext.HEADER_VALUE,
                ))

        # 6. Cookies
        for name, value in self.cookies.items():
            points.append(InjectionPoint(
                location="cookie", name=name, value=value,
                context=EncodingContext.COOKIE_VALUE,
            ))

        # 7. Path segments (non-empty segments that look like parameters)
        segments = [s for s in self.path.split("/") if s]
        for i, seg in enumerate(segments):
            # Only inject into segments that look like values (not static paths)
            if re.match(r"^\d+$", seg) or len(seg) > 20 or re.match(r"^[a-f0-9-]{8,}$", seg):
                points.append(InjectionPoint(
                    location="path", name=f"segment_{i}", value=seg,
                    context=EncodingContext.URL_PATH, index=i,
                ))

        # 8. Position markers — find §value§ patterns
        for match in re.finditer(r"§([^§]+)§", self.url + self.body):
            marker_value = match.group(1)
            points.append(InjectionPoint(
                location="marker", name=f"marker_{len(points)}", value=marker_value,
                context=EncodingContext.RAW,
            ))

        self.injection_points = points[:_MAX_INJECTION_POINTS]

    def _discover_json_points(self, obj, prefix: str, points: list):
        """Recursively discover injection points in JSON body."""
        if isinstance(obj, dict):
            for key, val in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                if isinstance(val, (dict, list)):
                    self._discover_json_points(val, path, points)
                else:
                    points.append(InjectionPoint(
                        location="json", name=key, value=str(val),
                        context=EncodingContext.JSON_VALUE,
                        json_path=path,
                    ))
        elif isinstance(obj, list):
            for i, val in enumerate(obj):
                path = f"{prefix}[{i}]"
                if isinstance(val, (dict, list)):
                    self._discover_json_points(val, path, points)
                else:
                    points.append(InjectionPoint(
                        location="json", name=f"[{i}]", value=str(val),
                        context=EncodingContext.JSON_VALUE,
                        json_path=path, index=i,
                    ))

    def _discover_xml_points(self, points: list):
        """Discover injection points in XML body via regex (no lxml dependency)."""
        # Tag text content: <tag>value</tag>
        for match in re.finditer(r"<(\w+)(?:\s[^>]*)?>([^<]+)</\1>", self.body):
            tag = match.group(1)
            val = match.group(2).strip()
            if val:
                points.append(InjectionPoint(
                    location="xml", name=tag, value=val,
                    context=EncodingContext.XML_VALUE,
                ))
        # Attribute values: attr="value"
        for match in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', self.body):
            attr = match.group(1)
            val = match.group(2)
            if attr.lower() not in ("xmlns", "version", "encoding"):
                points.append(InjectionPoint(
                    location="xml_attr", name=attr, value=val,
                    context=EncodingContext.XML_VALUE,
                ))


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK MODES
# ═══════════════════════════════════════════════════════════════════════════════

class AttackMode(Enum):
    SNIPER        = "sniper"         # One position at a time, iterate payloads
    BATTERING_RAM = "battering_ram"  # Same payload in ALL positions
    PITCHFORK     = "pitchfork"      # Parallel payload lists per position
    CLUSTER_BOMB  = "cluster_bomb"   # All combinations across positions


# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOAD INJECTOR ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class PayloadInjector:
    """
    Systematic payload injection engine — Burp Intruder equivalent.

    Takes a RequestTemplate, discovers injection points, and methodically
    injects payloads with context-aware encoding, analyzing each response
    for vulnerability signatures.
    """

    def __init__(
        self,
        session:       requests.Session,
        scope:         ScopeManager,
        ev_store:      EvidenceStore | None = None,
        timeout:       int = 10,
        rate_limit:    float = 0.05,
        max_payloads:  int = _MAX_PAYLOADS_PER_POINT,
        on_finding:    Callable | None = None,
        stop_event:    threading.Event | None = None,
        encode:        bool = True,     # Apply context-aware encoding
        follow_redirects: bool = False,
    ):
        self.session     = session
        self.scope       = scope
        self.ev_store    = ev_store or _global_store
        self.timeout     = timeout
        self.rate_limit  = rate_limit
        self.max_payloads = max_payloads
        self.on_finding  = on_finding
        self.stop_event  = stop_event or threading.Event()
        self.encode      = encode
        self.follow_redirects = follow_redirects
        self._lock       = threading.Lock()
        self.results:    list[FuzzResult] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def run(
        self,
        template:    RequestTemplate,
        attack_mode: str = "sniper",
        vuln_types:  list[str] | None = None,
        payloads:    list[str] | None = None,
        payload_map: dict[int, list[str]] | None = None,
    ) -> list[FuzzResult]:
        """
        Execute payload injection against a request template.

        Args:
            template:    Parsed request template with injection points
            attack_mode: "sniper", "battering_ram", "pitchfork", "cluster_bomb"
            vuln_types:  List of vuln types to test (uses PAYLOADS dict). If None, auto-detect.
            payloads:    Custom payload list (overrides vuln_types). Used for all points.
            payload_map: Per-position payload lists {point_index: [payloads]}. For pitchfork/cluster.

        Returns:
            List of FuzzResult findings.
        """
        if not template.injection_points:
            return []

        mode = AttackMode(attack_mode.lower().replace("-", "_").replace(" ", "_"))

        if mode == AttackMode.SNIPER:
            self._attack_sniper(template, vuln_types, payloads)
        elif mode == AttackMode.BATTERING_RAM:
            self._attack_battering_ram(template, vuln_types, payloads)
        elif mode == AttackMode.PITCHFORK:
            self._attack_pitchfork(template, payload_map or {})
        elif mode == AttackMode.CLUSTER_BOMB:
            self._attack_cluster_bomb(template, payload_map or {})

        return self.results

    def inject_single(
        self,
        template:  RequestTemplate,
        point:     InjectionPoint,
        payload:   str,
        vuln_type: str = "",
    ) -> requests.Response | None:
        """Inject a single payload into a single point. Returns the response."""
        encoded = encode_payload(payload, point.context) if self.encode else payload
        return self._send_injected(template, point, encoded, vuln_type, payload)

    # ── Attack mode implementations ───────────────────────────────────────────

    def _attack_sniper(self, template, vuln_types, custom_payloads):
        """Sniper: one position at a time, iterate payloads through it."""
        for point in template.injection_points:
            if self.stop_event.is_set():
                return

            payload_list = self._resolve_payloads(point, vuln_types, custom_payloads)
            vuln_type = self._infer_vuln_type(point, vuln_types)

            # Get baseline for comparison
            baseline = self._send_baseline(template)

            for payload in payload_list[:self.max_payloads]:
                if self.stop_event.is_set():
                    return
                time.sleep(self.rate_limit)
                encoded = encode_payload(payload, point.context) if self.encode else payload
                self._send_injected(template, point, encoded, vuln_type, payload, baseline)

    def _attack_battering_ram(self, template, vuln_types, custom_payloads):
        """Battering ram: same payload in ALL positions simultaneously."""
        if not template.injection_points:
            return

        first_point = template.injection_points[0]
        payload_list = self._resolve_payloads(first_point, vuln_types, custom_payloads)
        vuln_type = self._infer_vuln_type(first_point, vuln_types)
        baseline = self._send_baseline(template)

        for payload in payload_list[:self.max_payloads]:
            if self.stop_event.is_set():
                return
            time.sleep(self.rate_limit)
            self._send_all_injected(template, payload, vuln_type, baseline)

    def _attack_pitchfork(self, template, payload_map):
        """Pitchfork: parallel iteration of per-position payload lists."""
        points = template.injection_points
        if not points or not payload_map:
            return
        baseline = self._send_baseline(template)

        # Find the shortest list length
        max_iter = min(len(plist) for plist in payload_map.values()) if payload_map else 0

        for i in range(min(max_iter, self.max_payloads)):
            if self.stop_event.is_set():
                return
            time.sleep(self.rate_limit)
            # Build request with each point getting payload_map[idx][i]
            req_data = self._build_base_request(template)
            for idx, point in enumerate(points):
                if idx in payload_map and i < len(payload_map[idx]):
                    payload = payload_map[idx][i]
                    encoded = encode_payload(payload, point.context) if self.encode else payload
                    self._apply_injection(req_data, point, encoded)

            resp = self._send_request(req_data)
            if resp:
                self._analyze_response(resp, template, "pitchfork", "", baseline)

    def _attack_cluster_bomb(self, template, payload_map):
        """Cluster bomb: all combinations across positions."""
        points = template.injection_points
        if not points or not payload_map:
            return
        baseline = self._send_baseline(template)

        # Generate combinations (limit to prevent explosion)
        import itertools
        lists = [payload_map.get(i, [""])[:6] for i in range(len(points))]
        combinations = list(itertools.islice(itertools.product(*lists), 500))

        for combo in combinations:
            if self.stop_event.is_set():
                return
            time.sleep(self.rate_limit)
            req_data = self._build_base_request(template)
            for point, payload in zip(points, combo):
                encoded = encode_payload(payload, point.context) if self.encode else payload
                self._apply_injection(req_data, point, encoded)
            resp = self._send_request(req_data)
            if resp:
                self._analyze_response(resp, template, "cluster_bomb", "", baseline)

    # ── Request building & sending ────────────────────────────────────────────

    def _build_base_request(self, template: RequestTemplate) -> dict:
        """Build a mutable request dict from template."""
        return {
            "method":  template.method,
            "url":     template.url,
            "path":    template.path,
            "query":   dict(template.query_params),
            "headers": dict(template.headers),
            "cookies": dict(template.cookies),
            "body":    template.body,
            "body_type": template.body_type,
            "form_params": dict(template.form_params),
            "json_body": deepcopy(template.json_body) if template.json_body else None,
        }

    def _apply_injection(self, req_data: dict, point: InjectionPoint, encoded_payload: str):
        """Apply an encoded payload to a specific injection point in the request dict."""
        if point.location == "query":
            req_data["query"][point.name] = encoded_payload
            # Rebuild URL with new query
            parsed = urlparse(req_data["url"])
            new_qs = urlencode(req_data["query"])
            req_data["url"] = urlunparse(parsed._replace(query=new_qs))

        elif point.location == "form":
            req_data["form_params"][point.name] = encoded_payload
            req_data["body"] = urlencode(req_data["form_params"])

        elif point.location == "json":
            if req_data["json_body"] is not None:
                self._set_json_path(req_data["json_body"], point.json_path, encoded_payload)
                req_data["body"] = json.dumps(req_data["json_body"])

        elif point.location in ("xml", "xml_attr"):
            # Replace original value in XML body
            req_data["body"] = req_data["body"].replace(point.value, encoded_payload, 1)

        elif point.location == "header":
            req_data["headers"][point.name] = encoded_payload

        elif point.location == "cookie":
            req_data["cookies"][point.name] = encoded_payload

        elif point.location == "path":
            segments = req_data["path"].split("/")
            non_empty = [s for s in segments if s]
            if point.index < len(non_empty):
                non_empty[point.index] = encoded_payload
                req_data["path"] = "/" + "/".join(non_empty)
                # Rebuild URL
                parsed = urlparse(req_data["url"])
                req_data["url"] = urlunparse(parsed._replace(path=req_data["path"]))

        elif point.location == "path_filename":
            # Replace the filename stem of the last URL path segment, preserving extension.
            # e.g.  /api/report.pdf  →  /api/<payload>.pdf
            from urllib.parse import urlparse as _urlparse, urlunparse as _urlunparse, quote as _quote
            _p = _urlparse(req_data["url"])
            _path = _p.path
            _last_slash = _path.rfind("/")
            _filename = _path[_last_slash + 1:]
            _dot = _filename.rfind(".")
            if _dot != -1:
                _new_filename = _quote(encoded_payload, safe="") + _filename[_dot:]
            else:
                _new_filename = _quote(encoded_payload, safe="")
            req_data["url"] = _urlunparse(_p._replace(path=_path[:_last_slash + 1] + _new_filename))

        elif point.location == "request_line":
            # Append payload as an extra path token after the last URL segment.
            # e.g.  GET /api/users  →  GET /api/users/<payload>
            from urllib.parse import urlparse as _urlparse, urlunparse as _urlunparse, quote as _quote
            _p = _urlparse(req_data["url"])
            _new_path = _p.path.rstrip("/") + "/" + _quote(encoded_payload, safe="")
            req_data["url"] = _urlunparse(_p._replace(path=_new_path))

        elif point.location == "marker":
            marker = f"{POSITION_MARKER}{point.value}{POSITION_MARKER}"
            req_data["url"] = req_data["url"].replace(marker, encoded_payload)
            req_data["body"] = req_data["body"].replace(marker, encoded_payload)

    def _set_json_path(self, obj, path: str, value: str):
        """Set a value at a dot-notation JSON path."""
        parts = re.split(r"\.|(?=\[)", path)
        current = obj
        for i, part in enumerate(parts[:-1]):
            m = re.match(r"\[(\d+)\]", part)
            if m:
                current = current[int(m.group(1))]
            else:
                current = current[part]
        last = parts[-1]
        m = re.match(r"\[(\d+)\]", last)
        if m:
            current[int(m.group(1))] = value
        else:
            current[last] = value

    def _send_injected(
        self,
        template:  RequestTemplate,
        point:     InjectionPoint,
        encoded:   str,
        vuln_type: str,
        raw_payload: str,
        baseline:  requests.Response | None = None,
    ) -> requests.Response | None:
        """Send a request with one injection point modified."""
        req_data = self._build_base_request(template)
        self._apply_injection(req_data, point, encoded)
        resp = self._send_request(req_data)
        if resp:
            self._analyze_response(
                resp, template, vuln_type, raw_payload, baseline,
                point=point,
            )
        return resp

    def _send_all_injected(
        self,
        template: RequestTemplate,
        payload:  str,
        vuln_type: str,
        baseline: requests.Response | None,
    ):
        """Send a request with ALL injection points set to the same payload."""
        req_data = self._build_base_request(template)
        for point in template.injection_points:
            encoded = encode_payload(payload, point.context) if self.encode else payload
            self._apply_injection(req_data, point, encoded)
        resp = self._send_request(req_data)
        if resp:
            self._analyze_response(resp, template, vuln_type, payload, baseline)

    def _send_baseline(self, template: RequestTemplate) -> requests.Response | None:
        """Send the original (unmodified) request for baseline comparison."""
        req_data = self._build_base_request(template)
        return self._send_request(req_data)

    def _send_request(self, req_data: dict) -> requests.Response | None:
        """Execute an HTTP request from a request data dict."""
        url = req_data["url"]
        if not self.scope.in_scope(url):
            return None
        try:
            headers = dict(req_data["headers"])
            headers.setdefault("User-Agent", "Mozilla/5.0 (DAST-PayloadInjector/2.0)")

            # Rebuild cookies into header
            if req_data["cookies"]:
                cookie_str = "; ".join(f"{k}={v}" for k, v in req_data["cookies"].items())
                headers["Cookie"] = cookie_str

            kwargs = {
                "timeout": self.timeout,
                "verify": False,
                "allow_redirects": self.follow_redirects,
                "headers": headers,
            }
            body = req_data.get("body", "")
            if body and req_data["method"] in ("POST", "PUT", "PATCH", "DELETE"):
                if req_data["body_type"] == "json":
                    kwargs["data"] = body.encode("utf-8")
                    headers.setdefault("Content-Type", "application/json")
                elif req_data["body_type"] == "xml":
                    kwargs["data"] = body.encode("utf-8")
                    headers.setdefault("Content-Type", "application/xml")
                elif req_data["body_type"] == "form":
                    kwargs["data"] = body
                    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                else:
                    kwargs["data"] = body.encode("utf-8")

            return self.session.request(req_data["method"], url, **kwargs)
        except (requests.exceptions.RequestException, Exception):
            return None

    # ── Response analysis ─────────────────────────────────────────────────────

    def _analyze_response(
        self,
        resp:      requests.Response,
        template:  RequestTemplate,
        vuln_type: str,
        payload:   str,
        baseline:  requests.Response | None,
        point:     InjectionPoint | None = None,
    ):
        """Analyze a response for vulnerability signatures using DETECTORS."""
        body = resp.text[:8000] if resp.text else ""

        # Check against all relevant detectors
        types_to_check = [vuln_type] if vuln_type and vuln_type in DETECTORS else list(DETECTORS.keys())

        for vtype in types_to_check:
            patterns = DETECTORS.get(vtype, [])
            for pattern, description in patterns:
                if re.search(pattern, body, re.I):
                    # Skip CSRF protection indicators (false positive)
                    if "PROTECTED" in description:
                        continue

                    finding = FuzzResult(
                        url=template.url,
                        method=template.method,
                        param=point.name if point else "multiple",
                        param_type=point.location if point else "mixed",
                        vuln_type=vtype,
                        payload=payload,
                        finding=f"{description} [{template.url}]",
                        severity=self._severity(vtype),
                        evidence_id=None,
                    )
                    with self._lock:
                        self.results.append(finding)
                    if self.on_finding:
                        try:
                            self.on_finding(finding)
                        except Exception:
                            pass
                    return  # One finding per response is enough

        # Check for reflection (XSS indicator)
        if payload and payload in body:
            if any(c in payload for c in "<>\"'"):
                finding = FuzzResult(
                    url=template.url,
                    method=template.method,
                    param=point.name if point else "multiple",
                    param_type=point.location if point else "mixed",
                    vuln_type="xss_reflected",
                    payload=payload,
                    finding=f"Payload reflected unencoded in response [{template.url}]",
                    severity="high",
                    evidence_id=None,
                )
                with self._lock:
                    self.results.append(finding)
                if self.on_finding:
                    try:
                        self.on_finding(finding)
                    except Exception:
                        pass

        # Time-based detection (if response is notably slow)
        if baseline and resp.elapsed.total_seconds() > baseline.elapsed.total_seconds() + 2.5:
            if vuln_type in ("sqli_blind_time", "cmdi", "ssti"):
                finding = FuzzResult(
                    url=template.url,
                    method=template.method,
                    param=point.name if point else "multiple",
                    param_type=point.location if point else "mixed",
                    vuln_type=vuln_type,
                    payload=payload,
                    finding=f"Time-based detection — {resp.elapsed.total_seconds():.1f}s delay [{template.url}]",
                    severity="high",
                    evidence_id=None,
                )
                with self._lock:
                    self.results.append(finding)
                if self.on_finding:
                    try:
                        self.on_finding(finding)
                    except Exception:
                        pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_payloads(self, point: InjectionPoint, vuln_types, custom_payloads) -> list[str]:
        """Get the payload list for a given injection point."""
        if custom_payloads:
            return custom_payloads

        # Auto-detect vuln types based on injection point location
        types = vuln_types or self._auto_vuln_types(point)
        all_payloads = []
        for vt in types:
            all_payloads.extend(PAYLOADS.get(vt, []))
        return all_payloads

    def _infer_vuln_type(self, point: InjectionPoint, vuln_types) -> str:
        """Infer the primary vuln type for detection matching."""
        if vuln_types:
            return vuln_types[0]
        types = self._auto_vuln_types(point)
        return types[0] if types else "xss_reflected"

    def _auto_vuln_types(self, point: InjectionPoint) -> list[str]:
        """Auto-determine vuln types based on injection point characteristics and name semantics."""
        from .fuzzer import Fuzzer
        location_map = {
            "query": "query", "form": "form", "header": "header",
            "cookie": "cookie", "path": "path", "json": "json",
            "xml": "json", "xml_attr": "json", "marker": "query",
        }
        pt = location_map.get(point.location, "query")
        location_types = Fuzzer.PARAM_TYPE_MAP.get(pt, ["sqli_error", "xss_reflected"])

        # Context-aware: prioritize by parameter name semantics
        name_types = Fuzzer.name_based_vuln_types(point.name)
        if name_types:
            seen = set(name_types)
            return name_types + [vt for vt in location_types if vt not in seen]
        return location_types

    @staticmethod
    def _severity(vuln_type: str) -> str:
        """Look up severity for a vuln type."""
        from .fuzzer import Fuzzer
        return Fuzzer.SEV_MAP.get(vuln_type, "medium")


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def quick_inject(
    url: str,
    session: requests.Session,
    scope: ScopeManager,
    vuln_types: list[str] | None = None,
    attack_mode: str = "sniper",
    **kwargs,
) -> list[FuzzResult]:
    """One-liner convenience for payload injection against a URL."""
    template = RequestTemplate.from_url("GET", url)
    injector = PayloadInjector(session=session, scope=scope, **kwargs)
    return injector.run(template, attack_mode=attack_mode, vuln_types=vuln_types)
