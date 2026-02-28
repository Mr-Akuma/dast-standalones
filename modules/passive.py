"""
Passive Scanner — analyzes HTTP responses for security misconfigurations
without sending ANY attack payloads. Pure response analysis, zero API key needed.

Checks:
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- Cookie flag issues (HttpOnly, Secure, SameSite)
- Server/framework version disclosure
- Stack traces / debug info in response body
- CORS misconfigurations
- Clickjacking exposure
- Information leakage (comments, emails, API keys in HTML)
"""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict
from typing import Optional


# ── Finding dataclass ──────────────────────────────────────────────────────────

@dataclass
class PassiveFinding:
    url:         str
    category:    str      # "security_header", "cookie", "info_disclosure", "cors", "clickjacking"
    finding:     str      # human-readable description
    severity:    str      # "High", "Medium", "Low", "Info"
    evidence:    str      # what was found in the response
    remediation: str      # how to fix it
    cwe:         str = "" # CWE reference

    def to_dict(self) -> dict:
        return asdict(self)


# ── Security header rules ──────────────────────────────────────────────────────

_REQUIRED_HEADERS: dict[str, tuple[str, str, str, str]] = {
    # header_name: (severity, finding, remediation, cwe)
    "strict-transport-security": (
        "High",
        "Missing HTTP Strict Transport Security (HSTS) — SSL stripping possible",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "CWE-319",
    ),
    "content-security-policy": (
        "Medium",
        "Missing Content-Security-Policy — XSS exploitation easier",
        "Define CSP: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "CWE-693",
    ),
    "x-frame-options": (
        "Medium",
        "Missing X-Frame-Options — page can be embedded in iframes (clickjacking)",
        "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN",
        "CWE-1021",
    ),
    "x-content-type-options": (
        "Low",
        "Missing X-Content-Type-Options — MIME sniffing attacks possible",
        "Add: X-Content-Type-Options: nosniff",
        "CWE-430",
    ),
    "referrer-policy": (
        "Low",
        "Missing Referrer-Policy — sensitive URLs may leak in Referer header",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "CWE-200",
    ),
    "permissions-policy": (
        "Info",
        "Missing Permissions-Policy — browser features not restricted",
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "CWE-693",
    ),
    "cache-control": (
        "Info",
        "Missing Cache-Control — sensitive pages may be cached by browsers/proxies",
        "Add: Cache-Control: no-store, no-cache for authenticated pages",
        "CWE-525",
    ),
}

# ── Version disclosure patterns ────────────────────────────────────────────────

_SERVER_PATTERNS = [
    (re.compile(r"Apache/[\d.]+", re.I),          "Apache version disclosed in Server header"),
    (re.compile(r"nginx/[\d.]+", re.I),            "Nginx version disclosed in Server header"),
    (re.compile(r"Microsoft-IIS/[\d.]+", re.I),    "IIS version disclosed in Server header"),
    (re.compile(r"Tomcat/[\d.]+", re.I),           "Apache Tomcat version disclosed"),
    (re.compile(r"PHP/[\d.]+", re.I),              "PHP version disclosed"),
    (re.compile(r"OpenSSL/[\d.]+", re.I),          "OpenSSL version disclosed"),
    (re.compile(r"mod_ssl/[\d.]+", re.I),          "mod_ssl version disclosed"),
    (re.compile(r"(JBoss|WebLogic|WebSphere)/[\d.]+", re.I), "Java app server version disclosed"),
    (re.compile(r"Express", re.I),                 "Node.js Express framework disclosed"),
    (re.compile(r"Werkzeug/[\d.]+", re.I),         "Python Werkzeug/Flask version disclosed"),
    (re.compile(r"gunicorn/[\d.]+", re.I),         "Gunicorn version disclosed"),
    (re.compile(r"uvicorn/[\d.]+", re.I),          "Uvicorn version disclosed"),
]

# ── Stack trace / debug patterns ──────────────────────────────────────────────

_ERROR_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)",    re.I), "Python traceback exposed in response", "High", "CWE-209"),
    (re.compile(r"Fatal error:|Warning:.*on line \d+",     re.I), "PHP error/warning exposed",            "High", "CWE-209"),
    (re.compile(r"java\.lang\.\w+Exception",               re.I), "Java exception exposed",               "High", "CWE-209"),
    (re.compile(r"at \w+\.\w+\([\w.]+:\d+\)",             re.I), "Java stack trace in response",         "High", "CWE-209"),
    (re.compile(r"ORA-\d{4,}",                             re.I), "Oracle DB error exposed",              "High", "CWE-209"),
    (re.compile(r"SQLSTATE\[",                             re.I), "SQL error code exposed",               "High", "CWE-209"),
    (re.compile(r"mysql_fetch_array|pg_query|mysqli_",     re.I), "PHP database function in response",    "High", "CWE-209"),
    (re.compile(r"Microsoft SQL Server.*Error",            re.I), "MSSQL error exposed",                  "High", "CWE-209"),
    (re.compile(r"syntax error.*near|unclosed quotation",  re.I), "SQL syntax error in response",         "High", "CWE-209"),
    (re.compile(r"DEBUG\s*=\s*True",                       re.I), "Django DEBUG=True in response",        "High", "CWE-215"),
    (re.compile(r"<b>Notice</b>:|<b>Warning</b>:",         re.I), "PHP notice/warning in HTML",           "Medium", "CWE-209"),
    (re.compile(r"app\.config\[|SECRET_KEY\s*=",           re.I), "Secret key in response body",          "High", "CWE-312"),
]

# ── Sensitive info patterns ────────────────────────────────────────────────────

_INFO_PATTERNS = [
    (re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I),
     "Email address found in response", "Info", "CWE-200"),
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?[\w@#$!%^&*]{6,}", re.I),
     "Possible plaintext password in response", "High", "CWE-312"),
    (re.compile(r"(?:api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*['\"]?[a-zA-Z0-9]{16,}", re.I),
     "Possible API key in response body", "High", "CWE-312"),
    (re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", re.I),
     "Private key found in response", "Critical", "CWE-312"),
    (re.compile(r"(?:AWS|AMAZON).*(?:ACCESS|SECRET).*KEY", re.I),
     "AWS credential string in response", "Critical", "CWE-312"),
    (re.compile(r"<!--[\s\S]{10,200}-->",),
     "HTML comment in response — may contain sensitive info", "Info", "CWE-200"),
    (re.compile(r"\/\*[\s\S]{20,}?\*\/"),
     "JS/CSS block comment — may contain sensitive info", "Info", "CWE-200"),
    (re.compile(r"(?:todo|fixme|hack|xxx|bug|issue)\s*:?\s*\w+", re.I),
     "Developer comment (TODO/FIXME) in source", "Info", "CWE-200"),
    (re.compile(r"\b(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+"),
     "Internal IP address in response", "Low", "CWE-200"),
]


# ── Main scanner class ─────────────────────────────────────────────────────────

class PassiveScanner:
    """
    Stateless passive scanner. Call scan() on each HTTP response.
    Returns list of PassiveFinding — zero network requests made.
    """

    def scan(
        self,
        url:             str,
        status_code:     int,
        resp_headers:    dict,
        resp_body:       str,
        cookies:         dict,
        request_headers: dict | None = None,
    ) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        h = {k.lower(): v for k, v in resp_headers.items()}

        findings += self._check_security_headers(url, h)
        findings += self._check_server_disclosure(url, h)
        findings += self._check_cookies(url, h, resp_headers)
        findings += self._check_body_errors(url, resp_body)
        findings += self._check_body_info(url, resp_body)
        findings += self._check_cors(url, h, request_headers or {})
        findings += self._check_clickjacking(url, h)
        return findings

    # ── Security headers ────────────────────────────────────────────────────

    def _check_security_headers(self, url: str, h: dict) -> list[PassiveFinding]:
        findings = []
        for header, (severity, msg, fix, cwe) in _REQUIRED_HEADERS.items():
            if header not in h:
                findings.append(PassiveFinding(
                    url=url, category="security_header",
                    finding=msg, severity=severity,
                    evidence=f"Header '{header}' absent",
                    remediation=fix, cwe=cwe,
                ))
        return findings

    # ── Server version disclosure ────────────────────────────────────────────

    def _check_server_disclosure(self, url: str, h: dict) -> list[PassiveFinding]:
        findings = []
        for hdr_name in ("server", "x-powered-by", "x-aspnet-version",
                         "x-aspnetmvc-version", "x-generator"):
            val = h.get(hdr_name, "")
            if not val:
                continue
            for pat, msg in _SERVER_PATTERNS:
                if pat.search(val):
                    findings.append(PassiveFinding(
                        url=url, category="info_disclosure",
                        finding=msg,
                        severity="Low",
                        evidence=f"{hdr_name}: {val}",
                        remediation="Remove or genericize server/version headers in web server config",
                        cwe="CWE-200",
                    ))
                    break
            else:
                # Any non-empty Server header is info leak
                if hdr_name == "server" and val.strip():
                    findings.append(PassiveFinding(
                        url=url, category="info_disclosure",
                        finding=f"Server header reveals technology: {val}",
                        severity="Info",
                        evidence=f"Server: {val}",
                        remediation="Set a generic Server header or remove it entirely",
                        cwe="CWE-200",
                    ))
        return findings

    # ── Cookie flags ─────────────────────────────────────────────────────────

    def _check_cookies(self, url: str, h_lower: dict, h_orig: dict) -> list[PassiveFinding]:
        findings = []
        is_https = url.startswith("https://")

        # Collect all Set-Cookie header values
        set_cookie_headers = []
        for k, v in h_orig.items():
            if k.lower() == "set-cookie":
                if isinstance(v, list):
                    set_cookie_headers.extend(v)
                else:
                    set_cookie_headers.append(v)

        for sc in set_cookie_headers:
            sc_lower = sc.lower()
            # Extract cookie name
            name_part = sc.split(";")[0].split("=")[0].strip()

            if "httponly" not in sc_lower:
                findings.append(PassiveFinding(
                    url=url, category="cookie",
                    finding=f"Cookie '{name_part}' missing HttpOnly flag — accessible via JavaScript",
                    severity="Medium",
                    evidence=sc[:120],
                    remediation="Add HttpOnly to all session/auth cookies to prevent XSS theft",
                    cwe="CWE-1004",
                ))

            if is_https and "secure" not in sc_lower:
                findings.append(PassiveFinding(
                    url=url, category="cookie",
                    finding=f"Cookie '{name_part}' missing Secure flag — sent over plain HTTP",
                    severity="Medium",
                    evidence=sc[:120],
                    remediation="Add Secure flag to prevent cookie transmission over HTTP",
                    cwe="CWE-614",
                ))

            if "samesite" not in sc_lower:
                findings.append(PassiveFinding(
                    url=url, category="cookie",
                    finding=f"Cookie '{name_part}' missing SameSite attribute — CSRF risk",
                    severity="Low",
                    evidence=sc[:120],
                    remediation="Add SameSite=Strict or SameSite=Lax",
                    cwe="CWE-352",
                ))
        return findings

    # ── Error/debug info in body ──────────────────────────────────────────────

    def _check_body_errors(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        sample = body[:8000]
        for pat, msg, severity, cwe in _ERROR_PATTERNS:
            m = pat.search(sample)
            if m:
                start  = max(0, m.start() - 50)
                end    = min(len(sample), m.end() + 150)
                snippet = sample[start:end].strip()
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=snippet[:300],
                    remediation="Disable debug mode; never expose stack traces in production",
                    cwe=cwe,
                ))
        return findings

    # ── Sensitive info patterns ───────────────────────────────────────────────

    def _check_body_info(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        sample = body[:8000]
        seen = set()
        for pat, msg, severity, cwe in _INFO_PATTERNS:
            m = pat.search(sample)
            if m and msg not in seen:
                seen.add(msg)
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=m.group(0)[:120],
                    remediation="Remove sensitive data from client-facing responses",
                    cwe=cwe,
                ))
        return findings

    # ── CORS misconfiguration ─────────────────────────────────────────────────

    def _check_cors(self, url: str, h: dict, req_headers: dict) -> list[PassiveFinding]:
        findings = []
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower()
        acam = h.get("access-control-allow-methods", "")

        if acao == "*":
            findings.append(PassiveFinding(
                url=url, category="cors",
                finding="CORS wildcard (*) allows any origin to read response",
                severity="Medium",
                evidence=f"Access-Control-Allow-Origin: *",
                remediation="Restrict to specific trusted origins: Access-Control-Allow-Origin: https://yourdomain.com",
                cwe="CWE-942",
            ))

        if acao not in ("", "*") and acac == "true":
            findings.append(PassiveFinding(
                url=url, category="cors",
                finding="CORS credentials=true with reflected origin — potential account takeover",
                severity="High",
                evidence=f"ACAO: {acao}  |  ACAC: {acac}",
                remediation="Never set Access-Control-Allow-Credentials: true with dynamic origin reflection",
                cwe="CWE-942",
            ))

        # Check for dangerous methods
        if "DELETE" in acam or "PUT" in acam:
            findings.append(PassiveFinding(
                url=url, category="cors",
                finding=f"CORS allows dangerous HTTP methods: {acam}",
                severity="Medium",
                evidence=f"Access-Control-Allow-Methods: {acam}",
                remediation="Restrict CORS methods to only what's required (GET, POST)",
                cwe="CWE-942",
            ))
        return findings

    # ── Clickjacking ──────────────────────────────────────────────────────────

    def _check_clickjacking(self, url: str, h: dict) -> list[PassiveFinding]:
        findings = []
        xfo = h.get("x-frame-options", "")
        csp = h.get("content-security-policy", "")

        if not xfo and "frame-ancestors" not in csp:
            findings.append(PassiveFinding(
                url=url, category="clickjacking",
                finding="Page embeddable in iframes — clickjacking not prevented",
                severity="Medium",
                evidence="No X-Frame-Options and no CSP frame-ancestors directive",
                remediation="Add X-Frame-Options: DENY  or  Content-Security-Policy: frame-ancestors 'none'",
                cwe="CWE-1021",
            ))
        return findings


# Global instance
passive_scanner = PassiveScanner()
