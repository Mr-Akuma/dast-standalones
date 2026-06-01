"""
Audit Insertion Point system — Python port of Burp Suite's Montoya API.

    api/montoya/scanner/audit/insertionpoint/
        AuditInsertionPointType  (enum)
        AuditInsertionPoint      (injection builder)

Provides enum-driven payload injection across every HTTP location, including
the two that were previously missing from this tool:
  - URL_PATH_FILENAME  — injects into the filename segment of the URL path
  - REQUEST_LINE       — injects an extra path token (path-traversal style)
"""
from __future__ import annotations

import enum
import json
import re
import urllib.parse
from typing import Optional


# ── Enum ──────────────────────────────────────────────────────────────────────

class AuditInsertionPointType(enum.Enum):
    """
    Mirrors Burp Suite's AuditInsertionPointType enum.

    Value strings are the legacy param_type strings used by InputSurface,
    preserving full backward compatibility with all existing crawler/fuzzer code.
    """
    URL_QUERY_STRING    = "query"           # ?param=<payload>
    BODY_PARAMETER      = "form"            # POST form-encoded param
    COOKIE              = "cookie"          # Cookie: name=<payload>
    HTTP_HEADER         = "header"          # HeaderName: <payload>
    URL_PATH_FOLDER     = "path"            # /seg1/<payload>/seg2
    URL_PATH_FILENAME   = "path_filename"   # /path/<payload>.ext  ← was missing
    REQUEST_LINE        = "request_line"    # /path/<payload>  (extra path token)
    JSON_PARAMETER      = "json"            # {"param":"<payload>"}
    XML_PARAMETER       = "xml"             # <param><payload></param>
    MULTIPART_PARAMETER = "multipart"       # multipart/form-data field
    AMF_PARAMETER       = "amf"             # Adobe AMF (rare)

    # ── Convenience helpers ───────────────────────────────────────────────────

    @classmethod
    def from_string(cls, s: str) -> "AuditInsertionPointType":
        """Coerce a legacy param_type string into the matching enum member."""
        _MAP: dict[str, AuditInsertionPointType] = {
            "query":         cls.URL_QUERY_STRING,
            "form":          cls.BODY_PARAMETER,
            "cookie":        cls.COOKIE,
            "header":        cls.HTTP_HEADER,
            "path":          cls.URL_PATH_FOLDER,
            "path_filename": cls.URL_PATH_FILENAME,
            "request_line":  cls.REQUEST_LINE,
            "json":          cls.JSON_PARAMETER,
            "xml":           cls.XML_PARAMETER,
            "multipart":     cls.MULTIPART_PARAMETER,
            "amf":           cls.AMF_PARAMETER,
        }
        return _MAP.get(s.lower(), cls.URL_QUERY_STRING)

    @property
    def label(self) -> str:
        """Human-readable label for reports and logs."""
        return self.name.replace("_", " ").title()


# ── Injection builder ─────────────────────────────────────────────────────────

class AuditInsertionPoint:
    """
    Single injectable location within an HTTP request.

    Mirrors the Burp Suite Montoya AuditInsertionPoint interface:

        type            AuditInsertionPointType enum
        name            parameter / header / segment name
        base_value      original value at this position
        build_http_request(payload) → (url, headers, body)

    Usage::

        ip = AuditInsertionPoint(
            point_type=AuditInsertionPointType.URL_PATH_FILENAME,
            name="report",
            url="https://example.com/api/report.pdf",
            method="GET",
        )
        url, hdrs, body = ip.build_http_request("../../../etc/passwd")
        # → ("https://example.com/api/%2E%2E%2F%2E%2E%2Fetc%2Fpasswd.pdf", {...}, None)
    """

    def __init__(
        self,
        point_type:     AuditInsertionPointType,
        name:           str,
        base_value:     str = "",
        url:            str = "",
        method:         str = "GET",
        headers:        Optional[dict] = None,
        body_template:  str = "",
        content_type:   str = "",
    ):
        self.type           = point_type
        self.name           = name
        self.base_value     = base_value
        self.url            = url
        self.method         = method.upper()
        self.headers        = headers or {}
        self.body_template  = body_template
        self.content_type   = content_type

    def __repr__(self) -> str:
        return (
            f"<AuditInsertionPoint {self.type.name} "
            f"[{self.method} {self.url} | {self.name!r}]>"
        )

    # ── Core interface ────────────────────────────────────────────────────────

    def build_http_request(
        self, payload: str
    ) -> tuple[str, dict, Optional[str]]:
        """
        Inject *payload* at this insertion point.

        Returns:
            (url, headers, body)  — pass all three to requests.request().
            body is None when the insertion point is URL/header-based.
        """
        return (
            self._inject_url(payload),
            self._inject_headers(payload),
            self._inject_body(payload),
        )

    # ── Per-type injection logic ──────────────────────────────────────────────

    def _inject_url(self, payload: str) -> str:
        t = self.type
        p = urllib.parse.urlparse(self.url)

        # ── URL_QUERY_STRING ──────────────────────────────────────────────────
        if t == AuditInsertionPointType.URL_QUERY_STRING:
            params = urllib.parse.parse_qs(p.query, keep_blank_values=True)
            params[self.name] = [payload]
            new_query = urllib.parse.urlencode(
                {k: v[0] for k, v in params.items()}
            )
            return urllib.parse.urlunparse(p._replace(query=new_query))

        # ── URL_PATH_FOLDER ───────────────────────────────────────────────────
        if t == AuditInsertionPointType.URL_PATH_FOLDER:
            segments = p.path.split("/")
            # Match both crawled segment values ("123") and OpenAPI-style
            # placeholders ("{userId}") so proof replays work for API-spec surfaces.
            placeholder = f"{{{self.name}}}"
            for i, seg in enumerate(segments):
                if seg == self.name or seg == placeholder:
                    segments[i] = urllib.parse.quote(payload, safe="")
                    break
            else:
                # Segment not found — append as a new path token
                segments.append(urllib.parse.quote(payload, safe=""))
            return urllib.parse.urlunparse(p._replace(path="/".join(segments)))

        # ── URL_PATH_FILENAME ─────────────────────────────────────────────────
        #
        # Injects the payload into the *filename* of the last path segment,
        # preserving any file extension so the server routes the request
        # through the same handler.
        #
        # Examples:
        #   /api/report.pdf      → /api/<payload>.pdf
        #   /users/profile.json  → /users/<payload>.json
        #   /download/file.php   → /download/<payload>.php
        #   /users/123           → /users/<payload>          (no extension)
        if t == AuditInsertionPointType.URL_PATH_FILENAME:
            path      = p.path
            last_slash = path.rfind("/")
            filename   = path[last_slash + 1:]
            dot        = filename.rfind(".")
            if dot != -1:
                ext         = filename[dot:]                     # e.g. ".pdf"
                new_filename = urllib.parse.quote(payload, safe="") + ext
            else:
                new_filename = urllib.parse.quote(payload, safe="")
            new_path = path[: last_slash + 1] + new_filename
            return urllib.parse.urlunparse(p._replace(path=new_path))

        # ── REQUEST_LINE ──────────────────────────────────────────────────────
        #
        # Injects the payload as an extra path token appended to the URL.
        # This exercises path-traversal, path-override, and spring-actuator
        # style bugs where the server's routing layer is confused by extra
        # path segments that appear after a legitimate endpoint name.
        #
        # Examples:
        #   GET /api/users HTTP/1.1  → GET /api/users/<payload> HTTP/1.1
        #   GET /profile    HTTP/1.1 → GET /profile/<payload>   HTTP/1.1
        if t == AuditInsertionPointType.REQUEST_LINE:
            path     = p.path.rstrip("/")
            new_path = path + "/" + urllib.parse.quote(payload, safe="")
            return urllib.parse.urlunparse(p._replace(path=new_path))

        return self.url

    def _inject_headers(self, payload: str) -> dict:
        h: dict = {"User-Agent": "Mozilla/5.0 (compatible; DAST-Scanner/1.0)"}
        h.update(self.headers)
        if self.content_type:
            h.setdefault("Content-Type", self.content_type)

        t = self.type

        if t == AuditInsertionPointType.HTTP_HEADER:
            h[self.name] = payload

        elif t == AuditInsertionPointType.COOKIE:
            existing = h.get("Cookie", "")
            parts    = [c.strip() for c in existing.split(";") if c.strip()]
            new_parts: list[str] = []
            replaced = False
            for part in parts:
                k, _, _ = part.partition("=")
                if k.strip() == self.name:
                    new_parts.append(f"{self.name}={payload}")
                    replaced = True
                else:
                    new_parts.append(part)
            if not replaced:
                new_parts.append(f"{self.name}={payload}")
            h["Cookie"] = "; ".join(new_parts)

        return h

    def _inject_body(self, payload: str) -> Optional[str]:
        if self.method in ("GET", "HEAD"):
            return None

        t = self.type

        if t == AuditInsertionPointType.BODY_PARAMETER:
            base = {
                k: v[0]
                for k, v in urllib.parse.parse_qs(
                    self.body_template, keep_blank_values=True
                ).items()
            }
            base[self.name] = payload
            return urllib.parse.urlencode(base)

        if t == AuditInsertionPointType.JSON_PARAMETER:
            try:
                data = json.loads(self.body_template) if self.body_template else {}
            except (json.JSONDecodeError, ValueError):
                data = {}
            data[self.name] = payload
            return json.dumps(data)

        if t == AuditInsertionPointType.XML_PARAMETER:
            pattern = re.compile(
                rf"(<{re.escape(self.name)}[^>]*>)[^<]*(</\s*{re.escape(self.name)}\s*>)",
                re.IGNORECASE,
            )
            if self.body_template and pattern.search(self.body_template):
                return pattern.sub(
                    rf"\g<1>{_xml_escape(payload)}\2",
                    self.body_template,
                )
            return self.body_template or None

        if t == AuditInsertionPointType.MULTIPART_PARAMETER:
            pattern = re.compile(
                rf'(name="{re.escape(self.name)}"[^\r\n]*\r?\n\r?\n)[^\r\n-]*',
                re.IGNORECASE,
            )
            if self.body_template and pattern.search(self.body_template):
                return pattern.sub(rf"\g<1>{payload}", self.body_template)
            return self.body_template or None

        return None


# ── XML helper ────────────────────────────────────────────────────────────────

def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&apos;")
    )


# ── Convenience factory ───────────────────────────────────────────────────────

def from_input_surface(surface) -> AuditInsertionPoint:
    """
    Build an AuditInsertionPoint from a crawler InputSurface.
    Coerces the legacy string param_type to the correct enum member.
    """
    pt = AuditInsertionPointType.from_string(surface.param_type)
    return AuditInsertionPoint(
        point_type    = pt,
        name          = surface.param,
        base_value    = surface.original_value,
        url           = surface.url,
        method        = surface.method,
        headers       = surface.headers,
        body_template = surface.body_template,
        content_type  = surface.content_type,
    )
