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
import math
import re
from dataclasses import dataclass, asdict, field
from typing import Optional
from urllib.parse import urlparse, parse_qs

# ── Nuclei-mined extension modules ──────────────────────────────────────────
from modules.nuclei_tokens    import run_checks as _nuclei_tokens_check
from modules.nuclei_exposures import run_checks as _nuclei_exposures_check
from modules.nuclei_misconfig import run_checks as _nuclei_misconfig_check
from modules.nuclei_dast      import run_checks as _nuclei_dast_check
from modules.js_library_scanner import scan_js_libraries as _js_lib_check

_NUCLEI_MODULES = [
    _nuclei_tokens_check,
    _nuclei_exposures_check,
    _nuclei_misconfig_check,
    _nuclei_dast_check,
]


# ── Finding dataclass ──────────────────────────────────────────────────────────

@dataclass
class PassiveFinding:
    url:         str
    category:    str      # "security_header", "cookie", "info_disclosure", "cors", "clickjacking"
    finding:     str      # human-readable description
    severity:    str      # "High", "Medium", "Low", "Info"
    evidence:    str      # what was found in the response
    remediation: str      # how to fix it
    cwe:         str = ""
    owasp:       str = ""
    param:       str = ""
    status_code: int = 0
    method:      str = "GET"
    request_headers:  dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    resp_body:   str = ""

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
    (re.compile(r"\b(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+\b"),
     "RFC 1918 private IP address in response body", "Low", "CWE-200"),
    (re.compile(r"\b127\.\d+\.\d+\.\d+\b"),
     "Localhost IP address (127.x.x.x) in response body", "Low", "CWE-200"),
    (re.compile(r"\b169\.254\.\d+\.\d+\b"),
     "Link-local IP address (169.254.x.x) in response body", "Low", "CWE-200"),
    (re.compile(r"(?:^|[\s\"',;])(?:::1|fc00:|fd[0-9a-f]{2}:)[0-9a-f:]*", re.I),
     "IPv6 private/loopback address in response body", "Low", "CWE-200"),
]

# Headers commonly leaking internal IPs
_PRIVATE_IP_HEADER_RE = re.compile(
    r"\b(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"127\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+)\b"
)
_PRIVATE_IP_HEADERS = {
    "x-forwarded-for", "x-real-ip", "via", "x-originating-ip",
    "x-remote-addr", "x-host", "x-backend-server", "x-upstream",
    "location", "content-location", "x-forwarded-server",
}

# ── PII detection patterns ───────────────────────────────────────────────────

_PII_PATTERNS = [
    (re.compile(r"\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"),
     "Possible Visa card number in response", "High", "CWE-359"),
    (re.compile(r"\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"),
     "Possible Mastercard number in response", "High", "CWE-359"),
    (re.compile(r"\b3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}\b"),
     "Possible Amex card number in response", "High", "CWE-359"),
    (re.compile(r"\b6(?:011|5[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"),
     "Possible Discover card number in response", "High", "CWE-359"),
    (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b"),
     "Possible IBAN in response", "High", "CWE-359"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "Possible US SSN in response", "Critical", "CWE-359"),
]

# ── Hash disclosure patterns (structured only — no bare hex) ─────────────────

_HASH_PATTERNS = [
    (re.compile(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}"),
     "bcrypt password hash disclosed", "High", "CWE-916"),
    (re.compile(r"\$(?:1|5|6)\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{22,86}"),
     "Unix crypt hash disclosed", "High", "CWE-916"),
    (re.compile(r"\$apr1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}"),
     "Apache APR1 hash disclosed", "High", "CWE-916"),
]

# ── Dangerous JS function patterns ───────────────────────────────────────────

_DANGEROUS_JS_PATTERNS = [
    (re.compile(r"\beval\s*\("),
     "Dangerous eval() call in JavaScript", "Medium", "CWE-95"),
    (re.compile(r"\.innerHTML\s*="),
     "innerHTML assignment — potential DOM XSS sink", "Medium", "CWE-79"),
    (re.compile(r"\bdocument\.write\s*\("),
     "document.write() call — potential DOM XSS sink", "Medium", "CWE-79"),
    (re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]"),
     "setTimeout/setInterval with string argument — eval-like", "Medium", "CWE-95"),
    (re.compile(r"\.outerHTML\s*="),
     "outerHTML assignment — potential DOM XSS sink", "Medium", "CWE-79"),
    (re.compile(r"\bdocument\.writeln\s*\("),
     "document.writeln() call — potential DOM XSS sink", "Medium", "CWE-79"),
    # ── Clipboard API Abuse / Pastejacking (M10) ─────────────────────────
    (re.compile(r"\.clipboardData\s*\.\s*setData\s*\("),
     "Clipboard API abuse — clipboardData.setData() in script (pastejacking risk)", "Low", "CWE-693"),
    (re.compile(r"\bnavigator\s*\.\s*clipboard\s*\.\s*writeText\s*\("),
     "Clipboard API abuse — navigator.clipboard.writeText() in script", "Low", "CWE-693"),
    (re.compile(r"""addEventListener\s*\(\s*['"](?:copy|cut|paste)['"]\s*,"""),
     "Clipboard API abuse — copy/cut/paste event listener registered (pastejacking risk)", "Low", "CWE-693"),
    (re.compile(r"\.clipboardData\s*\.\s*getData\s*\("),
     "Clipboard API abuse — clipboardData.getData() intercepts paste events", "Low", "CWE-693"),
    # ── CSS Injection sinks — style attribute / element manipulation (M7) ─
    (re.compile(r"\.style\s*\.\s*cssText\s*="),
     "CSS injection sink — element.style.cssText assignment in script", "Medium", "CWE-79"),
    (re.compile(r"\.setAttribute\s*\(\s*['\"]style['\"]"),
     "CSS injection sink — setAttribute('style', ...) in script", "Medium", "CWE-79"),
    (re.compile(r"\bCSSStyleSheet\s*\(\s*\)|\.insertRule\s*\("),
     "CSS injection sink — dynamic stylesheet rule insertion in script", "Medium", "CWE-79"),
    (re.compile(r"document\.styleSheets.*\.addRule\s*\("),
     "CSS injection sink — addRule() dynamic CSS injection in script", "Medium", "CWE-79"),
]

# ── DOM XSS source→sink analysis ─────────────────────────────────────────────

_SCRIPT_BLOCK_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)

# Sources: user-controllable inputs that can be manipulated by an attacker
_DOM_XSS_SOURCES = [
    (re.compile(r"\blocation\s*\.\s*hash\b"),             "location.hash"),
    (re.compile(r"\blocation\s*\.\s*search\b"),           "location.search"),
    (re.compile(r"\blocation\s*\.\s*href\b"),             "location.href"),
    (re.compile(r"\blocation\s*\.\s*pathname\b"),         "location.pathname"),
    (re.compile(r"\bdocument\s*\.\s*URL\b"),              "document.URL"),
    (re.compile(r"\bdocument\s*\.\s*documentURI\b"),      "document.documentURI"),
    (re.compile(r"\bdocument\s*\.\s*referrer\b"),         "document.referrer"),
    (re.compile(r"\bdocument\s*\.\s*cookie\b"),           "document.cookie"),
    (re.compile(r"\bwindow\s*\.\s*name\b"),               "window.name"),
    (re.compile(r"\bpostMessage\b"),                       "postMessage"),
    (re.compile(r"\blocalStorage\s*\.\s*getItem\b"),      "localStorage.getItem"),
    (re.compile(r"\bsessionStorage\s*\.\s*getItem\b"),    "sessionStorage.getItem"),
    (re.compile(r"\bURLSearchParams\b"),                   "URLSearchParams"),
    (re.compile(r"\blocation\s*\.\s*toString\s*\(\)"),    "location.toString()"),
    (re.compile(r"\bhistory\s*\.\s*(?:push|replace)State\b"), "history.pushState/replaceState"),
]

# Sinks: dangerous functions/properties that can execute or render attacker content
# (pattern, label, severity_when_source_present, severity_sink_only)
_DOM_XSS_SINKS = [
    # Code execution sinks — High severity
    (re.compile(r"\beval\s*\("),                           "eval()",              "High",   "Medium"),
    (re.compile(r"\bFunction\s*\("),                       "Function()",          "High",   "Medium"),
    (re.compile(r"\bsetTimeout\s*\(\s*[^,\)]*(?:location|document|window|hash|search|href|name|referrer|cookie|localStorage|sessionStorage|URLSearchParams)"), "setTimeout(tainted)", "High", "Low"),
    (re.compile(r"\bsetInterval\s*\(\s*[^,\)]*(?:location|document|window|hash|search|href|name|referrer|cookie|localStorage|sessionStorage|URLSearchParams)"), "setInterval(tainted)", "High", "Low"),
    # HTML injection sinks — High/Medium severity
    (re.compile(r"\.innerHTML\s*="),                       "innerHTML",           "High",   "Low"),
    (re.compile(r"\.outerHTML\s*="),                       "outerHTML",           "High",   "Low"),
    (re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("),  "document.write()",    "High",   "Medium"),
    (re.compile(r"\.insertAdjacentHTML\s*\("),             "insertAdjacentHTML()", "High",  "Low"),
    # Navigation sinks — Medium severity
    (re.compile(r"\blocation\s*\.\s*assign\s*\("),        "location.assign()",   "Medium", "Low"),
    (re.compile(r"\blocation\s*\.\s*replace\s*\("),       "location.replace()",  "Medium", "Low"),
    (re.compile(r"\blocation\s*\.\s*href\s*="),           "location.href=",      "Medium", "Low"),
    (re.compile(r"\bwindow\s*\.\s*open\s*\("),            "window.open()",       "Medium", "Low"),
    # jQuery sinks — Medium severity
    (re.compile(r"\$\s*\(\s*[^)]*\)\s*\.\s*html\s*\("),  "$.html()",            "Medium", "Low"),
    (re.compile(r"\$\s*\(\s*[^)]*\)\s*\.\s*append\s*\("),"$.append()",          "Medium", "Low"),
    (re.compile(r"\$\s*\(\s*[^)]*\)\s*\.\s*prepend\s*\("), "$.prepend()",       "Medium", "Low"),
    (re.compile(r"\$\s*\(\s*[^)]*\)\s*\.\s*after\s*\("), "$.after()",           "Medium", "Low"),
    (re.compile(r"\$\s*\(\s*[^)]*\)\s*\.\s*before\s*\("), "$.before()",         "Medium", "Low"),
    # Framework sinks
    (re.compile(r"\bv-html\b"),                            "Vue v-html",         "Medium", "Low"),
    (re.compile(r"\bdangerouslySetInnerHTML\b"),           "React dangerouslySetInnerHTML", "Medium", "Low"),
    (re.compile(r"\bng-bind-html\b"),                      "Angular ng-bind-html", "Medium", "Low"),
    (re.compile(r"\bbypassSecurityTrust"),                  "Angular bypassSecurityTrust", "High", "Medium"),
]

# Direct source→sink assignment patterns (highest confidence)
_DOM_XSS_DIRECT_FLOWS = [
    re.compile(r"\.innerHTML\s*=\s*[^;]*(?:location|document\.URL|document\.referrer|window\.name|document\.cookie|localStorage|sessionStorage|URLSearchParams)", re.I),
    re.compile(r"\.outerHTML\s*=\s*[^;]*(?:location|document\.URL|document\.referrer|window\.name)", re.I),
    re.compile(r"\bdocument\.write(?:ln)?\s*\([^)]*(?:location|document\.URL|document\.referrer|window\.name|document\.cookie)", re.I),
    re.compile(r"\beval\s*\([^)]*(?:location|document\.URL|document\.referrer|window\.name|document\.cookie|localStorage|sessionStorage)", re.I),
    re.compile(r"\bFunction\s*\([^)]*(?:location|document\.URL|document\.referrer|window\.name)", re.I),
    re.compile(r"\blocation\s*\.\s*href\s*=\s*[^;]*(?:location\.hash|location\.search|document\.URL|document\.referrer|window\.name)", re.I),
    re.compile(r"\$\s*\([^)]*\)\s*\.\s*(?:html|append|prepend)\s*\([^)]*(?:location|document\.URL|document\.referrer|window\.name)", re.I),
]

# ── Directory browsing signatures ────────────────────────────────────────────

_DIRECTORY_BROWSING_PATTERNS = [
    (re.compile(r"<title>Index of /", re.I),
     "Apache-style directory listing enabled", "Medium", "CWE-548"),
    (re.compile(r"<title>Directory listing for /", re.I),
     "Python-style directory listing enabled", "Medium", "CWE-548"),
    (re.compile(r"\[To Parent Directory\]", re.I),
     "IIS directory listing enabled", "Medium", "CWE-548"),
    (re.compile(r'<a href="\?C=[NMSD];O=[AD]">', re.I),
     "Nginx/Apache autoindex directory listing", "Medium", "CWE-548"),
]

# ── Path disclosure patterns ─────────────────────────────────────────────────

_PATH_DISCLOSURE_PATTERNS = [
    (re.compile(r"(?:/home/\w+|/var/www|/opt/\w+|/usr/local|/srv/\w+)/\S{3,}"),
     "Unix file path disclosed in response", "Low", "CWE-200"),
    (re.compile(r"[A-Z]:\\(?:Users|Windows|inetpub|Program Files|wwwroot)\\\S{3,}", re.I),
     "Windows file path disclosed in response", "Low", "CWE-200"),
]

# ── Disclosure headers (PRESENCE indicates info leak) ────────────────────────

_DISCLOSURE_HEADERS: dict[str, tuple[str, str, str]] = {
    # header: (severity, finding, cwe)
    "x-chromelogger-data":   ("Medium", "X-ChromeLogger-Data header exposes server debug data", "CWE-200"),
    "x-chromephp-data":      ("Medium", "X-ChromePhp-Data header exposes server debug data", "CWE-200"),
    "x-backend-server":      ("Low",    "X-Backend-Server header reveals internal hostname", "CWE-200"),
    "x-debug-token":         ("Medium", "Symfony X-Debug-Token header exposes profiler token", "CWE-200"),
    "x-debug-token-link":    ("Medium", "Symfony X-Debug-Token-Link exposes profiler URL", "CWE-200"),
    "x-sourcefiles":         ("Medium", "X-SourceFiles header reveals local filesystem paths", "CWE-200"),
    "x-litespeed-tag":       ("Info",   "X-LiteSpeed-Tag header reveals cache internals", "CWE-200"),
    "x-turbo-charged-by":    ("Info",   "X-Turbo-Charged-By header reveals LiteSpeed usage", "CWE-200"),
}

# ── Cache / proxy topology headers (PRESENCE reveals infrastructure) ──────────

_CACHE_TOPOLOGY_HEADERS: dict[str, tuple[str, str, str]] = {
    "via":              ("Info",  "Via header reveals proxy/gateway topology", "CWE-200"),
    "x-varnish":        ("Info",  "X-Varnish header reveals Varnish cache infrastructure", "CWE-200"),
    "x-cache-hits":     ("Info",  "X-Cache-Hits header reveals caching behavior", "CWE-200"),
    "x-served-by":      ("Info",  "X-Served-By header reveals backend server identity", "CWE-200"),
    "x-timer":          ("Info",  "X-Timer header reveals Fastly/CDN timing internals", "CWE-200"),
    "x-amz-cf-id":      ("Info",  "X-Amz-Cf-Id reveals AWS CloudFront distribution", "CWE-200"),
    "x-amz-cf-pop":     ("Info",  "X-Amz-Cf-Pop reveals AWS CloudFront edge location", "CWE-200"),
    "x-azure-ref":      ("Info",  "X-Azure-Ref reveals Azure Front Door request ID", "CWE-200"),
    "x-request-id":     ("Info",  "X-Request-Id header reveals internal request tracing", "CWE-200"),
    "x-correlation-id":  ("Info", "X-Correlation-Id reveals internal request correlation", "CWE-200"),
}

# ── Sensitive URL parameter names (ZAP 10024) ────────────────────────────────

_SENSITIVE_URL_PARAMS = re.compile(
    r"[?&](password|passwd|pwd|secret|token|session[_-]?id|api[_-]?key|"
    r"apikey|access[_-]?key|auth|authorization|private[_-]?key|"
    r"client[_-]?secret|refresh[_-]?token|ssn|credit[_-]?card|"
    r"card[_-]?number|cvv|pin)\s*=\s*[^&\s]+", re.I,
)

# ── Sensitive Referrer parameter detection (ZAP 10025) ────────────────────────

_SENSITIVE_REFERRER_PARAMS = _SENSITIVE_URL_PARAMS  # Same pattern set

# Catches OAuth tokens in URL fragments (#access_token=...) inside Referer headers.
# _SENSITIVE_REFERRER_PARAMS uses [?&] and misses #-prefixed fragments — separate pattern needed.
_OAUTH_FRAGMENT_RE = re.compile(
    r"#(?:access_token|id_token|token)=[a-zA-Z0-9._~+/=-]{10,}", re.I
)

# ── Timestamp disclosure (ZAP 10096) — Unix epoch in body ─────────────────────

_TIMESTAMP_IN_BODY = re.compile(
    r'(?:timestamp|created[_-]?at|updated[_-]?at|expires?|date|time|'
    r'last[_-]?modified|issued[_-]?at|iat|exp|nbf|auth[_-]?time)'
    r'\s*["\']?\s*[:=]\s*["\']?(\d{10})(?:\d{0,3})["\']?',
    re.I,
)

# ── SQL keywords in HTML comments (ZAP suspicious comments) ───────────────────

_SQL_IN_COMMENTS = re.compile(
    r'<!--[^>]*?\b(SELECT\s+.{5,}?FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|'
    r'DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|'
    r'WHERE\s+\w+\s*=|ORDER\s+BY|GROUP\s+BY|UNION\s+SELECT)\b[^>]*?-->',
    re.I | re.DOTALL,
)

# ── Username enumeration signal patterns (ZAP 40023 equivalent) ──────────────
# These messages reveal whether an account exists, enabling enumeration attacks.
# Grouped: (compiled_regex, finding_description, severity)

_USERNAME_ENUM_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # --- Explicit "user not found" / "account doesn't exist" messages ---
    (re.compile(
        r"\b(?:user(?:name)?|account|email|login|member|identity)\s+"
        r"(?:does\s*n[o']t|doesn['\u2019]t|not|never)\s+"
        r"(?:exist|found|registered|recognized|known|match)",
        re.I),
     "Response reveals account does not exist (username enumeration)", "Medium"),
    (re.compile(
        r"\b(?:no|invalid|unknown|unregistered|unrecognized)\s+"
        r"(?:such\s+)?(?:user(?:name)?|account|email|member|login)\b",
        re.I),
     "Response reveals invalid username (username enumeration)", "Medium"),

    # --- "Incorrect password" (implies the username IS valid) ---
    (re.compile(
        r"\b(?:incorrect|invalid|wrong)\s+password\b", re.I),
     "Response says 'incorrect password' — confirms username exists", "Medium"),
    (re.compile(
        r"\bpassword\s+(?:is\s+)?(?:incorrect|invalid|wrong|does\s*n[o']t\s+match)\b",
        re.I),
     "Response says password doesn't match — confirms username exists", "Medium"),

    # --- "Password reset sent" vs "email not found" differential ---
    (re.compile(
        r"\b(?:reset|recovery)\s+(?:link|email|instructions)\s+"
        r"(?:has\s+been\s+)?sent\b",
        re.I),
     "Password reset confirms account exists (should use generic message)", "Low"),

    # --- Account status leak ---
    (re.compile(
        r"\b(?:account|user)\s+(?:is\s+)?(?:locked|disabled|suspended|deactivated|banned|blocked)\b",
        re.I),
     "Response reveals account status (locked/disabled) — confirms existence", "Medium"),

    # --- Registration "already taken" ---
    (re.compile(
        r"\b(?:user(?:name)?|email|account)\s+"
        r"(?:is\s+)?(?:already|previously)\s+"
        r"(?:taken|registered|exists|in\s+use)\b",
        re.I),
     "Registration reveals existing account (username enumeration)", "Medium"),
    (re.compile(
        r"\b(?:already\s+(?:have|has)\s+an?\s+account|already\s+registered)\b",
        re.I),
     "Registration reveals existing account (username enumeration)", "Medium"),

    # --- Timing hint in response body ---
    (re.compile(
        r"\b(?:login|auth(?:entication)?)\s+(?:attempt\s+)?(?:failed|failure)\s+"
        r"(?:for|with)\s+(?:user|account|email)\b",
        re.I),
     "Login failure message references specific user context", "Low"),
]

# ── Site isolation headers (ABSENCE is a security gap) ───────────────────────

_SITE_ISOLATION_HEADERS: dict[str, tuple[str, str, str, str]] = {
    # header: (severity, finding, remediation, cwe)
    "cross-origin-resource-policy": (
        "Info",
        "Missing Cross-Origin-Resource-Policy — resources loadable cross-origin (Spectre risk)",
        "Add: Cross-Origin-Resource-Policy: same-origin",
        "CWE-16",
    ),
    "cross-origin-embedder-policy": (
        "Info",
        "Missing Cross-Origin-Embedder-Policy — no cross-origin isolation",
        "Add: Cross-Origin-Embedder-Policy: require-corp",
        "CWE-16",
    ),
    "cross-origin-opener-policy": (
        "Info",
        "Missing Cross-Origin-Opener-Policy — cross-origin window refs not isolated",
        "Add: Cross-Origin-Opener-Policy: same-origin",
        "CWE-16",
    ),
}

# ── Polyfill CDN known-bad domains ───────────────────────────────────────────

_POLYFILL_BAD_DOMAINS = {
    "polyfill.io", "cdn.polyfill.io", "bootcss.com", "bootcdn.net",
    "staticfile.net", "staticfile.org", "unionadjs.com", "xhsbpza.com",
    "union.macoms.la", "newcrbpc.com",
}

# ── CSRF token field names (common patterns) ────────────────────────────────

_CSRF_TOKEN_NAMES = re.compile(
    r"csrf|xsrf|token|authenticity.token|__RequestVerificationToken|antiforgery",
    re.I,
)

# ── ViewState patterns ───────────────────────────────────────────────────────

_VIEWSTATE_RE = re.compile(
    r'<input[^>]+name=["\']?__VIEWSTATE["\']?[^>]+value=["\']([^"\']+)["\']',
    re.I,
)
_VIEWSTATE_MAC_RE = re.compile(
    r'<input[^>]+name=["\']?__VIEWSTATEGENERATOR["\']?',
    re.I,
)

# ── Service-specific API key patterns ──────────────────────────────────────────

_SERVICE_API_KEY_PATTERNS = [
    (re.compile(r"\bsk_live_[a-zA-Z0-9]{24,}\b"),
     "Stripe live secret key (sk_live_) in response", "Critical", "CWE-312"),
    (re.compile(r"\bsk_test_[a-zA-Z0-9]{24,}\b"),
     "Stripe test secret key (sk_test_) in response", "High", "CWE-312"),
    (re.compile(r"\brk_live_[a-zA-Z0-9]{24,}\b"),
     "Stripe restricted live key (rk_live_) in response", "Critical", "CWE-312"),
    (re.compile(r"\bAC[a-f0-9]{32}\b"),
     "Twilio Account SID (AC...) in response", "High", "CWE-312"),
    (re.compile(r"\bSK[a-f0-9]{32}\b"),
     "Twilio API key SID (SK...) in response", "High", "CWE-312"),
    (re.compile(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b"),
     "SendGrid API key (SG.xxx.xxx) in response", "Critical", "CWE-312"),
    (re.compile(r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}\b"),
     "Slack bot token (xoxb-) in response", "Critical", "CWE-312"),
    (re.compile(r"\bxoxs-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}\b"),
     "Slack user session token (xoxs-) in response", "Critical", "CWE-312"),
    (re.compile(r"\bxoxa-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}\b"),
     "Slack app-level token (xoxa-) in response", "Critical", "CWE-312"),
    (re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
     "Slack incoming webhook URL in response", "High", "CWE-312"),
    (re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
     "GitHub Personal Access Token (ghp_) in response", "Critical", "CWE-312"),
    (re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{82}\b"),
     "GitHub fine-grained PAT in response", "Critical", "CWE-312"),
    (re.compile(r"\bgho_[a-zA-Z0-9]{36}\b"),
     "GitHub OAuth access token (gho_) in response", "Critical", "CWE-312"),
    (re.compile(r"\bghs_[a-zA-Z0-9]{36}\b"),
     "GitHub Actions token (ghs_) in response", "Critical", "CWE-312"),
    (re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
     "AWS IAM Access Key ID (AKIA...) in response", "Critical", "CWE-312"),
    (re.compile(r"\bASIA[A-Z0-9]{16}\b"),
     "AWS STS temporary Access Key ID (ASIA...) in response", "High", "CWE-312"),
    (re.compile(r"\bAIza[a-zA-Z0-9_-]{35}\b"),
     "Google API Key (AIza...) in response", "High", "CWE-312"),
    (re.compile(r"GOCSPX-[a-zA-Z0-9_-]{28}"),
     "Google OAuth Client Secret (GOCSPX-) in response", "Critical", "CWE-312"),
    (re.compile(r"\bglpat-[a-zA-Z0-9_-]{20,}\b"),
     "GitLab Personal Access Token (glpat-) in response", "Critical", "CWE-312"),
    (re.compile(r"\bkey-[a-f0-9]{32}\b"),
     "Mailgun API key (key-...) in response", "High", "CWE-312"),
    (re.compile(r"\b[a-f0-9]{32}-us[0-9]{1,2}\b"),
     "Mailchimp API key in response", "High", "CWE-312"),
    (re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"),
     "Shopify Admin API token (shpat_) in response", "Critical", "CWE-312"),
    (re.compile(r"\bshpss_[a-fA-F0-9]{32}\b"),
     "Shopify shared secret (shpss_) in response", "Critical", "CWE-312"),
    (re.compile(r"\b\d{9,10}:[a-zA-Z0-9_-]{35}\b"),
     "Telegram Bot API token in response", "High", "CWE-312"),
    (re.compile(r"\bnpm_[a-zA-Z0-9]{36}\b"),
     "npm access token (npm_) in response", "High", "CWE-312"),
    (re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{40,}\b"),
     "Anthropic API key (sk-ant-) in response", "Critical", "CWE-312"),
    (re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{48,}\b"),
     "OpenAI API key (sk-...) in response", "Critical", "CWE-312"),
    (re.compile(r"\bhf_[a-zA-Z0-9]{34}\b"),
     "HuggingFace API token (hf_) in response", "High", "CWE-312"),
]

# ── JWT passive patterns ──────────────────────────────────────────────────────

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

_JWT_SENSITIVE_CLAIMS = [
    (re.compile(r'"password"\s*:'),    "JWT payload contains password claim",   "Critical", "CWE-522"),
    (re.compile(r'"ssn"\s*:'),         "JWT payload contains SSN claim",        "Critical", "CWE-359"),
    (re.compile(r'"credit_card"\s*:'), "JWT payload contains credit card claim", "Critical", "CWE-312"),
    (re.compile(r'"secret"\s*:'),      "JWT payload contains secret claim",     "High",     "CWE-312"),
    (re.compile(r'"admin"\s*:\s*true', re.I), "JWT payload grants admin=true",  "High",     "CWE-285"),
]

# ── CSP policy analysis patterns ──────────────────────────────────────────────

_CSP_DIRECTIVE_CHECKS = [
    (re.compile(r"script-src\b[^;]*'unsafe-inline'", re.I),
     "CSP script-src contains 'unsafe-inline' — XSS protections bypassed", "High", "CWE-693"),
    (re.compile(r"script-src\b[^;]*'unsafe-eval'", re.I),
     "CSP script-src contains 'unsafe-eval' — eval()-based XSS possible", "High", "CWE-693"),
    (re.compile(r"script-src\b[^;]*(?:\s|;)\*(?:\s|;|$)", re.I),
     "CSP script-src allows wildcard (*) — any external script executable", "High", "CWE-693"),
    (re.compile(r"script-src\b[^;]*\bdata:", re.I),
     "CSP script-src allows data: URIs — trivial XSS bypass", "High", "CWE-693"),
    (re.compile(r"script-src\b[^;]*\bhttp:", re.I),
     "CSP script-src allows http: scheme — MitM can inject scripts", "High", "CWE-693"),
    (re.compile(r"default-src\b[^;]*(?:\s|;)\*(?:\s|;|$)", re.I),
     "CSP default-src is wildcard (*) — no resource restriction", "Medium", "CWE-693"),
    (re.compile(r"\breport-uri\b", re.I),
     "CSP uses deprecated report-uri — migrate to report-to", "Info", "CWE-693"),
]

# ── Source map patterns ───────────────────────────────────────────────────────

_SOURCE_MAP_JS = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\n]+\.map)", re.I)
_SOURCE_MAP_CSS = re.compile(r"/\*[#@]\s*sourceMappingURL\s*=\s*([^\s*]+\.map)", re.I)
_SOURCE_MAP_INLINE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*data:application/json", re.I)

# ── Cloud metadata patterns ──────────────────────────────────────────────────

_CLOUD_METADATA_PATTERNS = [
    (re.compile(r"169\.254\.169\.254"),
     "Cloud IMDS IP (169.254.169.254) in response — possible SSRF", "High", "CWE-918"),
    (re.compile(r"metadata\.google\.internal", re.I),
     "GCP metadata endpoint hostname in response", "High", "CWE-918"),
    (re.compile(r"/latest/meta-data/", re.I),
     "AWS IMDS path /latest/meta-data/ in response — active SSRF indicator", "Critical", "CWE-918"),
    (re.compile(r'"AccessKeyId"\s*:\s*"ASIA[A-Z0-9]{16}"'),
     "AWS STS credentials in response — SSRF exploitation", "Critical", "CWE-918"),
    (re.compile(r"100\.100\.100\.200"),
     "Alibaba Cloud metadata IP in response", "High", "CWE-918"),
    (re.compile(r"/var/run/secrets/kubernetes\.io/serviceaccount", re.I),
     "Kubernetes service account path in response", "Critical", "CWE-918"),
]

# ── JSONP callback patterns ──────────────────────────────────────────────────

_JSONP_RESPONSE_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\(\s*[\[{]", re.MULTILINE)
_JSONP_CALLBACK_PARAMS = re.compile(
    r"[?&](?:callback|cb|jsonp|jsonpcallback)\s*=\s*([^&#\s]+)", re.I,
)

# ── Prototype pollution sink patterns ────────────────────────────────────────

_PROTO_POLLUTION_PATTERNS = [
    (re.compile(r"""\[['"]__proto__['"]\]\s*="""),
     "Prototype pollution sink: ['__proto__'] assignment in JS", "High", "CWE-1321"),
    (re.compile(r"\.constructor\.prototype\s*="),
     "Prototype pollution sink: .constructor.prototype assignment", "High", "CWE-1321"),
    (re.compile(r"_\.(?:merge|defaultsDeep|defaults)\s*\(", re.I),
     "Lodash merge/defaultsDeep — prototype pollution if unpatched", "Medium", "CWE-1321"),
    (re.compile(r"\$\.extend\s*\(\s*true\s*,"),
     "jQuery.extend(true,...) deep merge — prototype pollution sink", "Medium", "CWE-1321"),
    (re.compile(r"""['"]__proto__['"]\s*:"""),
     "__proto__ key in object literal — prototype pollution source", "High", "CWE-1321"),
]

# ── GraphQL passive patterns ─────────────────────────────────────────────────

_GRAPHQL_PASSIVE_PATTERNS = [
    (re.compile(r'"__schema"\s*:\s*\{'),
     "GraphQL introspection response — full schema exposed", "Medium", "CWE-200"),
    (re.compile(r'"message"\s*:\s*"[^"]*Did you mean [\'"]?\w+[\'"]?\?', re.I),
     "GraphQL field suggestion in error — schema enumerable via typos", "Low", "CWE-200"),
    (re.compile(r"(?:graphiql|graphql-playground|apollo-sandbox)", re.I),
     "GraphQL IDE reference in response — disable in production", "Medium", "CWE-200"),
]

# ── Deserialization patterns (multi-language) ────────────────────────────────

_DESER_PATTERNS = [
    (re.compile(r'(?:^|[\s,])O:\d+:"[A-Za-z_]\w*":\d+:\{'),
     "PHP serialized object in response", "High", "CWE-502"),
    (re.compile(r"!ruby/object:", re.I),
     "Ruby YAML object instantiation marker in response", "High", "CWE-502"),
    (re.compile(r"!!python/object(?:/apply|/new)?:", re.I),
     "Python YAML object instantiation marker in response", "High", "CWE-502"),
    (re.compile(r"!!java\.(?:util|lang|io)\.\w+", re.I),
     "Java YAML object instantiation marker (SnakeYAML) in response", "High", "CWE-502"),
    (re.compile(r"_\$\$ND_FUNC\$\$_function\s*\("),
     "Node.js node-serialize RCE pattern in response", "Critical", "CWE-502"),
]

# ── Build artifact / dev mode patterns ───────────────────────────────────────

_BUILD_ARTIFACT_PATTERNS = [
    (re.compile(r"webpack-dev-server|webpack\.HotModuleReplacementPlugin|__webpack_hmr", re.I),
     "Webpack HMR in response — development build deployed", "High", "CWE-215"),
    (re.compile(r"process\.env\.(?:REACT_APP_|NEXT_PUBLIC_|VUE_APP_|VITE_)[A-Z_]+", re.I),
     "Client-side env variable reference in JavaScript bundle", "Medium", "CWE-312"),
    (re.compile(r"process\.env\.[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z_]*\s*[=:]", re.I),
     "Sensitive env variable name in client-side JavaScript", "High", "CWE-312"),
    (re.compile(r"@vite/client|vite:(?:legacy|preload)", re.I),
     "Vite development client artifact in response", "High", "CWE-215"),
]

# ── Framework debug mode patterns ────────────────────────────────────────────

_FRAMEWORK_DEBUG_PATTERNS = [
    (re.compile(r'"buildId"\s*:\s*"development"', re.I),
     "Next.js development buildId — dev build in production", "High", "CWE-215"),
    (re.compile(r"__NUXT_DEVTOOLS__", re.I),
     "Nuxt.js DevTools enabled in response", "High", "CWE-215"),
    (re.compile(r"Angular is running in development mode", re.I),
     "Angular running in development mode", "Medium", "CWE-215"),
    (re.compile(r'djdt-\w+|id="djDebug"', re.I),
     "Django Debug Toolbar artifacts in response", "High", "CWE-215"),
    (re.compile(r"Whoops[^<]*Laravel", re.I),
     "Laravel Whoops error page — APP_DEBUG=true", "High", "CWE-215"),
    (re.compile(r'(?:href|src)\s*=\s*["\']?/actuator(?:/\w+)?', re.I),
     "Spring Boot Actuator endpoint referenced", "High", "CWE-215"),
    (re.compile(r"swagger-ui-bundle\.js|redoc\.standalone\.js", re.I),
     "API documentation UI (Swagger/ReDoc) exposed in production", "Medium", "CWE-200"),
    (re.compile(r"\[Vue warn\]:", re.I),
     "Vue.js development warning in response", "Medium", "CWE-215"),
]

# ── Session fixation indicators ──────────────────────────────────────────────

_LOGIN_URL_RE = re.compile(r"/(?:login|signin|sign-in|auth|authenticate|sso)", re.I)
_SESSION_COOKIE_NAMES = re.compile(
    r"^(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session|sid|sessionid)$", re.I,
)
_SESSION_IN_URL_RE = re.compile(
    r"[?&](?:PHPSESSID|JSESSIONID|sessionid|session_id|sid)\s*=\s*[a-zA-Z0-9+/=%]{16,}", re.I,
)

# ── Insecure WebSocket patterns ──────────────────────────────────────────────

_INSECURE_WS_PATTERNS = [
    (re.compile(r"(?:new\s+WebSocket|WebSocket\s*\()\s*\(?\s*[\"']ws://", re.I),
     "Insecure WebSocket (ws://) connection on HTTPS page", "High", "CWE-319"),
    (re.compile(r'(?:wsUrl|websocketUrl|ws_url|socket_url)\s*[=:]\s*["\']ws://', re.I),
     "Insecure WebSocket URL in JavaScript configuration", "High", "CWE-319"),
]

# ── Modern security headers (absence = gap) ─────────────────────────────────

_MODERN_HEADERS: dict[str, tuple[str, str, str, str]] = {
    "permissions-policy": (
        "Low",
        "Missing Permissions-Policy header — browser features not restricted",
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "CWE-16",
    ),
    "x-dns-prefetch-control": (
        "Info",
        "Missing X-DNS-Prefetch-Control — DNS prefetching not controlled",
        "Add: X-DNS-Prefetch-Control: off",
        "CWE-16",
    ),
    "x-download-options": (
        "Info",
        "Missing X-Download-Options — IE can open downloads in site context",
        "Add: X-Download-Options: noopen",
        "CWE-16",
    ),
    "x-permitted-cross-domain-policies": (
        "Info",
        "Missing X-Permitted-Cross-Domain-Policies — Flash/PDF cross-domain not restricted",
        "Add: X-Permitted-Cross-Domain-Policies: none",
        "CWE-16",
    ),
}

# ── OAuth misconfiguration patterns ──────────────────────────────────────────

_OAUTH_PATTERNS = [
    (re.compile(r"[?&#](?:access_token|token)\s*=\s*[a-zA-Z0-9._~+/-]{20,}", re.I),
     "OAuth access token exposed in URL — leaks via Referer/logs", "High", "CWE-598"),
    (re.compile(r"response_type\s*=\s*token(?:[&\s]|$)", re.I),
     "OAuth implicit flow (response_type=token) — deprecated, use PKCE", "High", "CWE-287"),
    (re.compile(r'"refresh_token"\s*:\s*"[a-zA-Z0-9._~+/-]{20,}"', re.I),
     "OAuth refresh token in response — ensure HTTPS-only", "Medium", "CWE-319"),
]


# ── False-positive suppression constants ─────────────────────────────────────

_TEST_EMAIL_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "test.com", "test.org",
    "localhost", "noreply.com", "placeholder.com", "sentry.io",
    "users.noreply.github.com",
})

_TEST_CARD_NUMBERS = frozenset({
    "4111111111111111", "4012888888881881", "4222222222222",
    "5555555555554444", "5105105105105100",
    "378282246310005", "371449635398431",
    "6011111111111117", "6011000990139424",
    "3530111333300000", "3566002020360505",
})


def _luhn_valid(number: str) -> bool:
    """Luhn algorithm — returns True for valid credit card numbers."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        total += d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
    return total % 10 == 0


def _iter_set_cookie(h: dict) -> list[str]:
    """Extract all Set-Cookie header values from a headers dict."""
    result = []
    for k, v in h.items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                result.extend(v)
            else:
                result.append(v)
    return result


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

        # For header-level findings (CSP, HSTS, cookies, CORS, etc.) normalise
        # the URL to scheme+host so they group per-domain, not per-path.
        try:
            from urllib.parse import urlparse as _up
            _p = _up(url)
            base_url = f"{_p.scheme}://{_p.netloc}" if _p.netloc else url
        except Exception:
            base_url = url

        # ── Binary content-type gate — skip non-text responses entirely ──────
        _ct = h.get("content-type", "")
        if any(t in _ct for t in ("image/", "video/", "audio/", "font/", "octet-stream")):
            return findings

        # ── Decode response body if encoded ─────────────────────────────────
        # Edge case 1: gzip Content-Encoding that wasn't auto-decompressed
        _ce = h.get("content-encoding", "").lower()
        if "gzip" in _ce and resp_body and resp_body[:2] == "\x1f\x8b":
            try:
                import gzip as _gzip
                resp_body = _gzip.decompress(resp_body.encode("latin-1")).decode("utf-8", errors="replace")
            except Exception:
                pass  # fall back to original resp_body
        # Edge case 2: entire body is a Base64-encoded blob
        import re as _re, base64 as _b64
        if resp_body and len(resp_body) > 32:
            _stripped = resp_body.strip()
            if _re.match(r'^[A-Za-z0-9+/\r\n]{32,}={0,2}$', _stripped):
                _no_ws = _stripped.replace('\n', '').replace('\r', '').replace(' ', '')
                if len(_no_ws) % 4 == 0:
                    try:
                        _decoded = _b64.b64decode(_no_ws).decode("utf-8", errors="replace")
                        # Only use decoded version if it looks like text (not binary noise)
                        if _decoded.isprintable() or '<' in _decoded or '{' in _decoded:
                            resp_body = _decoded
                    except Exception:
                        pass  # fall back to original

        findings += self._check_security_headers(url, h, status_code)
        findings += self._check_server_disclosure(url, h)
        findings += self._check_cookies(url, h, resp_headers)
        findings += self._check_body_errors(url, resp_body, status_code)
        findings += self._check_body_info(url, resp_body)
        findings += self._check_cors(url, h, request_headers or {})
        findings += self._check_clickjacking(url, h)
        # ── New checks (ZAP parity) ──
        findings += self._check_content_type(url, h)
        findings += self._check_charset_mismatch(url, h, resp_body)
        findings += self._check_disclosure_headers(url, h)
        findings += self._check_site_isolation(url, h)
        findings += self._check_pii(url, resp_body)
        findings += self._check_hashes(url, resp_body)
        findings += self._check_dangerous_js(url, resp_body)
        findings += self._check_dom_xss(url, resp_body, h)
        findings += self._check_directory_browsing(url, resp_body)
        findings += self._check_path_disclosure(url, resp_body)
        findings += self._check_mixed_content(url, resp_body)
        findings += self._check_csrf_tokens(url, resp_body)
        findings += self._check_sri(url, resp_body)
        findings += self._check_reverse_tabnabbing(url, resp_body)
        findings += self._check_insecure_form_action(url, resp_body)
        findings += self._check_cross_domain_scripts(url, resp_body)
        findings += self._check_open_redirect(url, status_code, h, resp_body)
        findings += self._check_viewstate(url, resp_body)
        findings += self._check_java_serialization(url, resp_body)
        findings += self._check_polyfill_cdn(url, resp_body)
        findings += self._check_big_redirect(url, status_code, resp_body, h)
        # ── Advanced checks (Burp/Nuclei parity) ──
        findings += self._check_service_api_keys(url, resp_body)
        findings += self._check_jwt_passive(url, resp_body)
        findings += self._check_csp_policy(url, h)
        findings += self._check_source_maps(url, resp_body, h)
        findings += self._check_cloud_metadata(url, resp_body)
        findings += self._check_jsonp(url, resp_body)
        findings += self._check_proto_pollution(url, resp_body)
        findings += self._check_graphql_passive(url, resp_body)
        findings += self._check_deserialization_multi(url, resp_body)
        findings += self._check_build_artifacts(url, resp_body)
        findings += self._check_framework_debug(url, resp_body)
        findings += self._check_modern_headers(url, h)
        findings += self._check_tech_fingerprints(url, resp_body)
        findings += self._check_session_fixation(url, h)
        findings += self._check_insecure_websocket(url, resp_body)
        findings += self._check_oauth_indicators(url, resp_body, h)
        # ── Info disclosure in responses (ZAP parity — 5 new checks) ──
        findings += self._check_sensitive_url_params(url)
        findings += self._check_referrer_leak(url, h, request_headers or {})
        findings += self._check_timestamp_disclosure(url, resp_body)
        findings += self._check_cache_topology(url, h)
        findings += self._check_private_ip_headers(url, h)
        findings += self._check_username_enumeration(url, resp_body)
        findings += self._check_sql_in_comments(url, resp_body)
        # ── ZAP parity: 15 additional passive rules ──
        findings += self._check_cache_control(url, h)
        findings += self._check_cookie_loose_scope(url, resp_headers)
        findings += self._check_suspicious_comments(url, resp_body)
        findings += self._check_banner_info_leak(url, resp_body)
        findings += self._check_insecure_auth(url, h)
        findings += self._check_session_id_in_url(url)
        findings += self._check_source_code_in_response(url, resp_body)
        findings += self._check_content_cacheability(url, h, status_code)
        findings += self._check_x_chromelogger(url, h)
        findings += self._check_servlet_param_pollution(url)
        findings += self._check_base64_disclosure(url, resp_body)
        findings += self._check_user_controllable_html(url, resp_body)
        findings += self._check_cookie_poisoning(url, resp_headers)
        # ── Burp Suite parity: 30 additional passive checks ──
        findings += self._check_password_autocomplete(url, resp_body)
        findings += self._check_cleartext_password_form(url, resp_body)
        findings += self._check_file_upload_form(url, resp_body)
        findings += self._check_input_reflection(url, resp_body)
        findings += self._check_request_smuggling_indicators(url, h)
        findings += self._check_stack_traces_extended(url, resp_body, status_code)
        findings += self._check_verbose_db_errors(url, resp_body)
        findings += self._check_xxe_indicators(url, resp_body)
        findings += self._check_robots_sensitive(url, resp_body)
        findings += self._check_aspnet_tracing(url, resp_body)
        findings += self._check_hsts_preload(url, h)
        findings += self._check_duplicate_cookies(url, h)
        findings += self._check_samesite_none_insecure(url, h)
        findings += self._check_cross_domain_form(url, resp_body)
        findings += self._check_hidden_form_fields(url, resp_body)
        findings += self._check_login_form_detected(url, resp_body)
        findings += self._check_captcha_absence(url, resp_body)
        findings += self._check_sensitive_html_comments(url, resp_body)
        findings += self._check_cors_preflight_cache(url, h)
        findings += self._check_xss_protection_disabled(url, h)
        findings += self._check_etag_inode_leak(url, h)
        findings += self._check_insecure_redirect_chain(url, h, status_code)
        findings += self._check_wsdl_exposure(url, resp_body)
        findings += self._check_webmanifest_exposure(url, resp_body)
        findings += self._check_strict_transport_gaps(url, h)
        findings += self._check_cookie_without_expiry(url, h)
        findings += self._check_multiple_csp(url, h)
        findings += self._check_csp_unsafe(url, h)
        findings += self._check_wildcard_csp(url, h)
        findings += self._check_html_base_tag(url, resp_body)
        findings += self._check_open_api_spec(url, resp_body)
        findings += self._check_graphql_introspection(url, resp_body)
        findings += self._check_sourcemap_url(url, resp_body, h)
        findings += self._check_acao_null(url, h)
        findings += self._check_csp_report_only(url, h)
        # ── ZAP full-parity rules (12 additional passive checks) ──
        findings += self._check_user_controllable_charset(url, resp_body, h)
        findings += self._check_heartbleed(url, h)
        findings += self._check_relative_path_confusion(url, resp_body)
        findings += self._check_username_hash_found(url, resp_body)
        findings += self._check_get_for_post(url, resp_body)
        findings += self._check_format_string_error(url, resp_body)
        findings += self._check_saml_indicators(url, resp_body, h)
        findings += self._check_backup_file_ref(url, resp_body)
        findings += self._check_browser_storage_disclosure(url, resp_body)
        findings += self._check_insecure_component_version(url, resp_body, h)
        findings += self._check_https_available_via_http(url, h)
        findings += self._check_apache_range_dos(url, h)
        # ── ZAP Client Side Integration passive rules ──
        findings += self._check_postmessage_origin(url, resp_body)
        findings += self._check_dom_clobbering(url, resp_body)
        findings += self._check_js_prototype_pollution_sink(url, resp_body)
        # ── Behavioral / identity checks ──
        findings += self._check_referer_dependent_response(url, resp_body, request_headers or {})
        findings += self._check_spoofable_client_ip(url, resp_body, request_headers or {}, h)
        findings += self._check_jwks_endpoint_disclosed(url, resp_body, h)
        findings += self._check_jwt_private_key_disclosed(url, resp_body)
        findings += self._check_useragent_dependent_response(url, resp_body, request_headers or {})
        # ── JS library vulnerability scanner (Retire.js equivalent) ──
        try:
            for d in _js_lib_check(url, resp_body, resp_headers, cookies):
                findings.append(PassiveFinding(
                    url=d["url"], category=d["category"],
                    finding=d["finding"], severity=d["severity"],
                    evidence=d.get("evidence", ""),
                    remediation=d.get("remediation", ""),
                    cwe=d.get("cwe", ""),
                ))
        except Exception:
            pass
        # ── Nuclei-mined extension checks (~93 additional patterns) ──
        for nuclei_check in _NUCLEI_MODULES:
            try:
                if nuclei_check is _nuclei_misconfig_check:
                    raw = nuclei_check(url, resp_body, resp_headers, cookies,
                                       status_code=status_code)
                else:
                    raw = nuclei_check(url, resp_body, resp_headers, cookies)
                for d in raw:
                    findings.append(PassiveFinding(
                        url=d["url"], category=d["category"],
                        finding=d["finding"], severity=d["severity"],
                        evidence=d.get("evidence", ""),
                        remediation=d.get("remediation", ""),
                        cwe=d.get("cwe", ""),
                    ))
            except Exception:
                pass  # never let an extension module crash the core scanner
        # ── Stamp HTTP evidence onto every finding (enables per-finding req/resp display) ──
        _resp_h_clean = {k: v for k, v in resp_headers.items()
                         if not k.lower().startswith("set-cookie")} if resp_headers else {}
        _req_h_clean  = dict(request_headers) if request_headers else {}
        for _f in findings:
            if not _f.status_code:
                _f.status_code = status_code
            if not _f.request_headers:
                _f.request_headers = _req_h_clean
            if not _f.response_headers:
                _f.response_headers = _resp_h_clean
            if not _f.resp_body:
                _f.resp_body = resp_body[:4000] if resp_body else ""

        # ── Deduplicate: keep highest-severity finding per (cwe, url, param) ──
        _SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "": 0}
        _seen_keys: dict = {}
        for _f in findings:
            _fd = _f.to_dict() if hasattr(_f, "to_dict") else _f
            _key = (_fd.get("cwe", ""), _fd.get("url", _fd.get("location", "")), _fd.get("evidence", "")[:40])
            _existing = _seen_keys.get(_key)
            if _existing is None:
                _seen_keys[_key] = _f
            else:
                _ed = _existing.to_dict() if hasattr(_existing, "to_dict") else _existing
                if _SEV_RANK.get(_fd.get("severity", "").lower(), 0) > _SEV_RANK.get(_ed.get("severity", "").lower(), 0):
                    _seen_keys[_key] = _f
        findings = list(_seen_keys.values())
        return findings

    # ── Security headers ────────────────────────────────────────────────────

    def _check_security_headers(self, url: str, h: dict, status_code: int = 200) -> list[PassiveFinding]:
        findings = []
        # Only flag missing security headers on successful responses
        if status_code >= 400:
            return findings
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

        # Session-like cookie names — flag at High severity instead of Medium
        _SESSION_NAMES = re.compile(
            r"^(sess(ion)?id?|phpsessid|jsessionid|aspsessionid|sid|token|"
            r"auth[_-]?token|access[_-]?token|refresh[_-]?token|csrf[_-]?token|"
            r"jwt|api[_-]?key|__session|_session|connect\.sid|laravel_session|"
            r"rack\.session|_rails_session|express[_.]sid)$", re.I)

        for sc in set_cookie_headers:
            # Parse attributes from the portion AFTER the first semicolon
            # to avoid matching flag names inside the cookie name/value
            parts = sc.split(";")
            name_part = parts[0].split("=")[0].strip()
            attrs_lower = ";".join(parts[1:]).lower() if len(parts) > 1 else ""
            is_session = bool(_SESSION_NAMES.match(name_part))
            base_sev = "High" if is_session else "Medium"

            has_secure   = bool(re.search(r"\bsecure\b", attrs_lower))
            has_httponly  = bool(re.search(r"\bhttponly\b", attrs_lower))
            has_samesite = "samesite" in attrs_lower

            if not has_httponly:
                findings.append(PassiveFinding(
                    url=url, category="cookie",
                    finding=f"Cookie '{name_part}' missing HttpOnly flag — accessible via JavaScript",
                    severity=base_sev,
                    evidence=sc[:120],
                    remediation="Add HttpOnly to all session/auth cookies to prevent XSS theft",
                    cwe="CWE-1004",
                ))

            if is_https and not has_secure:
                findings.append(PassiveFinding(
                    url=url, category="cookie",
                    finding=f"Cookie '{name_part}' missing Secure flag — sent over plain HTTP",
                    severity=base_sev,
                    evidence=sc[:120],
                    remediation="Add Secure flag to prevent cookie transmission over HTTP",
                    cwe="CWE-614",
                ))

            if not has_samesite:
                findings.append(PassiveFinding(
                    url=url, category="cookie",
                    finding=f"Cookie '{name_part}' missing SameSite attribute — CSRF risk",
                    severity="Low",
                    evidence=sc[:120],
                    remediation="Add SameSite=Strict or SameSite=Lax",
                    cwe="CWE-352",
                ))

            # SameSite=None without Secure — explicit bad config (browser will reject)
            if has_samesite:
                ss_m = re.search(r"samesite\s*=\s*(\w+)", attrs_lower)
                if ss_m and ss_m.group(1) == "none" and not has_secure:
                    findings.append(PassiveFinding(
                        url=url, category="cookie",
                        finding=f"Cookie '{name_part}' has SameSite=None without Secure — browsers reject this",
                        severity="High",
                        evidence=sc[:120],
                        remediation="Cookies with SameSite=None MUST also have the Secure flag",
                        cwe="CWE-614",
                    ))

            # __Secure- prefix validation (RFC 6265bis)
            if name_part.startswith("__Secure-") and not has_secure:
                findings.append(PassiveFinding(
                    url=url, category="cookie",
                    finding=f"Cookie '{name_part}' uses __Secure- prefix but lacks Secure flag",
                    severity="High",
                    evidence=sc[:120],
                    remediation="__Secure- prefixed cookies MUST have the Secure attribute (RFC 6265bis)",
                    cwe="CWE-614",
                ))

            # __Host- prefix validation (RFC 6265bis — strictest)
            if name_part.startswith("__Host-"):
                host_issues = []
                if not has_secure:
                    host_issues.append("missing Secure")
                if re.search(r"domain\s*=", attrs_lower):
                    host_issues.append("must not have Domain attribute")
                if not re.search(r"path\s*=\s*/\s*(;|$)", attrs_lower):
                    host_issues.append("must have Path=/")
                if host_issues:
                    findings.append(PassiveFinding(
                        url=url, category="cookie",
                        finding=f"Cookie '{name_part}' __Host- prefix violation: {'; '.join(host_issues)}",
                        severity="High",
                        evidence=sc[:120],
                        remediation="__Host- cookies MUST have Secure, MUST NOT have Domain, MUST have Path=/ (RFC 6265bis)",
                        cwe="CWE-614",
                    ))

            # Loose scoping — cookie domain broader than request hostname
            domain_m = re.search(r"domain\s*=\s*([^;\s]+)", attrs_lower)
            if domain_m:
                from urllib.parse import urlparse
                cookie_domain = domain_m.group(1).strip().lstrip(".")
                page_host = urlparse(url).hostname or ""
                # If cookie domain is a parent of the page host, it's loosely scoped
                if cookie_domain and page_host and cookie_domain != page_host:
                    if page_host.endswith("." + cookie_domain):
                        findings.append(PassiveFinding(
                            url=url, category="cookie",
                            finding=f"Cookie '{name_part}' loosely scoped to .{cookie_domain} — shared across subdomains",
                            severity="Info",
                            evidence=f"domain={cookie_domain}, page={page_host}",
                            remediation="Scope cookies to the most specific domain needed",
                            cwe="CWE-287",
                        ))
        return findings

    # ── Error/debug info in body ──────────────────────────────────────────────

    def _check_body_errors(self, url: str, body: str, status_code: int = 200) -> list[PassiveFinding]:
        findings = []
        # Error patterns on 4xx/5xx responses are expected behavior — skip
        if status_code >= 400:
            return findings
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
                # Skip emails from test/example domains
                if msg == "Email address found in response":
                    matched = m.group(0)
                    domain = matched.rsplit("@", 1)[-1].lower()
                    if domain in _TEST_EMAIL_DOMAINS:
                        continue
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
        # Clickjacking only relevant for HTML pages
        ct = (h.get("content-type") or "").lower()
        if "text/html" not in ct:
            return findings
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

    # ══════════════════════════════════════════════════════════════════════════
    # NEW CHECKS — ZAP parity (35 rules)
    # ══════════════════════════════════════════════════════════════════════════

    # ── Content-Type missing ───────────────────────────────────────────────

    def _check_content_type(self, url: str, h: dict) -> list[PassiveFinding]:
        if "content-type" not in h:
            return [PassiveFinding(
                url=url, category="security_header",
                finding="Content-Type header missing — MIME sniffing and encoding attacks possible",
                severity="Medium",
                evidence="No Content-Type header in response",
                remediation="Always set Content-Type with explicit charset: Content-Type: text/html; charset=UTF-8",
                cwe="CWE-173",
            )]
        return []

    # ── Charset mismatch ──────────────────────────────────────────────────

    def _check_charset_mismatch(self, url: str, h: dict, body: str) -> list[PassiveFinding]:
        ct = h.get("content-type", "")
        if "charset=" not in ct.lower():
            return []

        # Extract charset from Content-Type header
        header_charset = ""
        for part in ct.split(";"):
            if "charset=" in part.lower():
                header_charset = part.split("=", 1)[1].strip().strip('"').lower()
                break

        if not header_charset:
            return []

        # Extract charset from HTML meta tag
        m = re.search(r'<meta[^>]+charset=["\']?([a-zA-Z0-9_-]+)', body[:2000], re.I)
        if not m:
            m = re.search(r'<meta[^>]+content=["\'][^"\']*charset=([a-zA-Z0-9_-]+)', body[:2000], re.I)
        if not m:
            return []

        meta_charset = m.group(1).strip().lower()
        # Normalize common aliases
        aliases = {"utf8": "utf-8", "ascii": "us-ascii", "latin1": "iso-8859-1", "latin-1": "iso-8859-1"}
        header_charset = aliases.get(header_charset, header_charset)
        meta_charset = aliases.get(meta_charset, meta_charset)

        if header_charset != meta_charset:
            return [PassiveFinding(
                url=url, category="security_header",
                finding="Charset mismatch between Content-Type header and HTML meta — encoding attacks possible",
                severity="Medium",
                evidence=f"Header charset: {header_charset}, Meta charset: {meta_charset}",
                remediation="Ensure Content-Type charset and HTML meta charset are identical",
                cwe="CWE-436",
            )]
        return []

    # ── Disclosure headers (presence = info leak) ─────────────────────────

    def _check_disclosure_headers(self, url: str, h: dict) -> list[PassiveFinding]:
        findings = []
        for hdr, (severity, msg, cwe) in _DISCLOSURE_HEADERS.items():
            val = h.get(hdr, "")
            if val:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=f"{hdr}: {val[:200]}",
                    remediation=f"Remove the {hdr} header in production",
                    cwe=cwe,
                ))
        return findings

    # ── Site isolation (CORP/COEP/COOP) ───────────────────────────────────

    def _check_site_isolation(self, url: str, h: dict) -> list[PassiveFinding]:
        findings = []
        for hdr, (severity, msg, fix, cwe) in _SITE_ISOLATION_HEADERS.items():
            if hdr not in h:
                findings.append(PassiveFinding(
                    url=url, category="security_header",
                    finding=msg,
                    severity=severity,
                    evidence=f"Header '{hdr}' absent",
                    remediation=fix,
                    cwe=cwe,
                ))
        return findings

    # ── PII disclosure ────────────────────────────────────────────────────

    def _check_pii(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        sample = body[:8000]
        seen = set()
        _CARD_MSGS = {"Possible Visa card number in response",
                      "Possible Mastercard number in response",
                      "Possible Amex card number in response",
                      "Possible Discover card number in response"}
        for pat, msg, severity, cwe in _PII_PATTERNS:
            m = pat.search(sample)
            if m and msg not in seen:
                # Only flag Luhn-valid card numbers — filters test/fake cards
                if msg in _CARD_MSGS:
                    raw = m.group(0).replace(" ", "").replace("-", "")
                    if not _luhn_valid(raw) or raw in _TEST_CARD_NUMBERS:
                        continue
                seen.add(msg)
                findings.append(PassiveFinding(
                    url=url, category="pii_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=re.sub(r"\d", "*", m.group(0)),  # mask digits
                    remediation="Never expose PII in responses — mask or remove sensitive data",
                    cwe=cwe,
                ))
        return findings

    # ── Hash disclosure ───────────────────────────────────────────────────

    def _check_hashes(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        sample = body[:8000]
        # Skip responses that are likely static assets or have no real body
        if len(sample.strip()) < 20:
            return findings
        seen = set()
        for pat, msg, severity, cwe in _HASH_PATTERNS:
            m = pat.search(sample)
            if m and msg not in seen:
                # Skip if the match also appears in the URL path (cache buster, commit hash)
                matched = m.group(0)
                if matched in url:
                    continue
                seen.add(msg)
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=matched[:60] + "...",
                    remediation="Never expose password hashes in responses",
                    cwe=cwe,
                ))
        return findings

    # ── Dangerous JS functions ────────────────────────────────────────────

    def _check_dangerous_js(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        sample = body[:16000]
        seen = set()
        for pat, msg, severity, cwe in _DANGEROUS_JS_PATTERNS:
            m = pat.search(sample)
            if m and msg not in seen:
                seen.add(msg)
                start = max(0, m.start() - 20)
                end = min(len(sample), m.end() + 40)
                findings.append(PassiveFinding(
                    url=url, category="dangerous_js",
                    finding=msg,
                    severity=severity,
                    evidence=sample[start:end].strip()[:120],
                    remediation="Avoid eval(), innerHTML, document.write() — use safer DOM APIs",
                    cwe=cwe,
                ))
        return findings

    # ── DOM XSS source→sink analysis ──────────────────────────────────────

    def _check_dom_xss(self, url: str, body: str, h: dict | None = None) -> list[PassiveFinding]:
        """
        Static analysis for DOM-based XSS: extract inline <script> blocks
        and check for user-controllable sources flowing into dangerous sinks.

        Three detection tiers:
          1. DIRECT FLOW — regex matches source→sink in single expression (High confidence)
          2. CO-OCCURRENCE — source + sink in same <script> block (Medium confidence)
          3. EVENT HANDLER — on* attributes containing sources (High confidence)
        """
        findings: list[PassiveFinding] = []
        # DOM XSS checks only relevant for HTML pages
        if h is not None:
            ct = (h.get("content-type") or "").lower()
            if "text/html" not in ct:
                return findings
        seen_flows: set[tuple[str, str]] = set()  # (source_label, sink_label)
        sample = body[:32000]  # analyze more of the page for JS

        # ── Tier 1: Direct source→sink assignment patterns ────────────
        for flow_re in _DOM_XSS_DIRECT_FLOWS:
            m = flow_re.search(sample)
            if m:
                snippet = m.group(0)[:120]
                # Identify which source and sink
                source_label = "user-controllable source"
                for spat, slabel in _DOM_XSS_SOURCES:
                    if spat.search(snippet):
                        source_label = slabel
                        break
                sink_label = "dangerous sink"
                for spat, slabel, _, _ in _DOM_XSS_SINKS:
                    if spat.search(snippet):
                        sink_label = slabel
                        break

                flow_key = (source_label, sink_label)
                if flow_key not in seen_flows:
                    seen_flows.add(flow_key)
                    findings.append(PassiveFinding(
                        url=url, category="dom_xss",
                        finding=(
                            f"DOM XSS — direct source→sink flow: "
                            f"{source_label} → {sink_label}"
                        ),
                        severity="High",
                        evidence=snippet.strip(),
                        remediation=(
                            "Never pass user-controllable input directly to DOM "
                            "manipulation sinks. Use textContent instead of innerHTML, "
                            "sanitize with DOMPurify, or use framework-safe bindings."
                        ),
                        cwe="CWE-79",
                    ))

        # ── Tier 2: Co-occurrence in same <script> block ──────────────
        for block_match in _SCRIPT_BLOCK_RE.finditer(sample):
            block = block_match.group(1)
            if len(block) < 10:
                continue

            # Find all sources in this block
            block_sources = []
            for spat, slabel in _DOM_XSS_SOURCES:
                if spat.search(block):
                    block_sources.append(slabel)

            if not block_sources:
                continue

            # Find all sinks in this block
            for spat, slabel, sev_with_source, _ in _DOM_XSS_SINKS:
                sm = spat.search(block)
                if sm:
                    for src_label in block_sources:
                        flow_key = (src_label, slabel)
                        if flow_key in seen_flows:
                            continue
                        seen_flows.add(flow_key)

                        # Extract evidence around the sink
                        start = max(0, sm.start() - 30)
                        end = min(len(block), sm.end() + 50)
                        snippet = block[start:end].strip()[:120]

                        findings.append(PassiveFinding(
                            url=url, category="dom_xss",
                            finding=(
                                f"DOM XSS risk — {src_label} and {slabel} "
                                f"in same script block"
                            ),
                            severity=sev_with_source,
                            evidence=snippet,
                            remediation=(
                                "Review script block for data flow from "
                                f"{src_label} into {slabel}. Sanitize input "
                                "with DOMPurify or use safe DOM APIs."
                            ),
                            cwe="CWE-79",
                        ))

        # ── Tier 3: Event handler attributes containing sources ───────
        event_handler_re = re.compile(
            r"""\bon\w+\s*=\s*["']([^"']{5,300})["']""", re.I
        )
        for em in event_handler_re.finditer(sample):
            handler = em.group(1)
            for spat, slabel in _DOM_XSS_SOURCES:
                if spat.search(handler):
                    flow_key = (slabel, "event_handler_attr")
                    if flow_key not in seen_flows:
                        seen_flows.add(flow_key)
                        findings.append(PassiveFinding(
                            url=url, category="dom_xss",
                            finding=(
                                f"DOM XSS — event handler references {slabel}"
                            ),
                            severity="High",
                            evidence=em.group(0)[:120],
                            remediation=(
                                "Do not reference user-controllable sources in "
                                "inline event handlers. Use addEventListener with "
                                "proper input validation."
                            ),
                            cwe="CWE-79",
                        ))
                    break  # one source per handler is enough

        return findings

    # ── Directory browsing ────────────────────────────────────────────────

    def _check_directory_browsing(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        sample = body[:4000]
        for pat, msg, severity, cwe in _DIRECTORY_BROWSING_PATTERNS:
            if pat.search(sample):
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=msg,
                    remediation="Disable directory listing in web server config (Options -Indexes / autoindex off)",
                    cwe=cwe,
                ))
                break  # one match is enough
        return findings

    # ── Path disclosure ───────────────────────────────────────────────────

    def _check_path_disclosure(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        sample = body[:8000]
        seen = set()
        for pat, msg, severity, cwe in _PATH_DISCLOSURE_PATTERNS:
            m = pat.search(sample)
            if m and msg not in seen:
                seen.add(msg)
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=m.group(0)[:120],
                    remediation="Do not expose internal filesystem paths in responses",
                    cwe=cwe,
                ))
        return findings

    # ── Mixed content (HTTP resources on HTTPS page) ──────────────────────

    def _check_mixed_content(self, url: str, body: str) -> list[PassiveFinding]:
        if not url.startswith("https://"):
            return []
        findings = []
        # Find http:// in src, href, action attributes
        mixed = re.findall(
            r'(?:src|href|action)\s*=\s*["\']?(http://[^"\'>\s]+)',
            body[:16000], re.I,
        )
        if mixed:
            unique = list(dict.fromkeys(mixed[:5]))  # first 5 unique
            findings.append(PassiveFinding(
                url=url, category="mixed_content",
                finding="Mixed content — HTTPS page loads HTTP resources (MitM risk)",
                severity="Medium",
                evidence="; ".join(unique)[:300],
                remediation="Load all resources over HTTPS or use protocol-relative URLs",
                cwe="CWE-311",
            ))
        return findings

    # ── CSRF token absence ────────────────────────────────────────────────

    def _check_csrf_tokens(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        # Find POST forms
        forms = re.finditer(
            r'<form\b[^>]*method\s*=\s*["\']?post[^>]*>(.*?)</form>',
            body[:32000], re.I | re.DOTALL,
        )
        for form_match in forms:
            form_html = form_match.group(1)
            # Check for CSRF token field
            if not _CSRF_TOKEN_NAMES.search(form_html):
                # Extract action for evidence
                action_m = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)', form_match.group(0), re.I)
                action = action_m.group(1) if action_m else "(self)"
                findings.append(PassiveFinding(
                    url=url, category="csrf",
                    finding="POST form missing anti-CSRF token — Cross-Site Request Forgery possible",
                    severity="Medium",
                    evidence=f"Form action={action}, no CSRF/token hidden field found",
                    remediation="Add a hidden anti-CSRF token field to all state-changing forms",
                    cwe="CWE-352",
                ))
                break  # one finding per page is enough
        return findings

    # ── Sub-Resource Integrity (SRI) missing ──────────────────────────────

    def _check_sri(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        # Find external script tags (CDN/third-party)
        scripts = re.finditer(
            r'<script\b([^>]*)src\s*=\s*["\']?(https?://[^"\'>\s]+)',
            body[:32000], re.I,
        )
        for m in scripts:
            attrs, src = m.group(1) + m.group(0), m.group(2)
            # Skip same-origin scripts
            from urllib.parse import urlparse
            src_host = urlparse(src).hostname or ""
            page_host = urlparse(url).hostname or ""
            if src_host == page_host:
                continue
            if "integrity=" not in attrs.lower():
                findings.append(PassiveFinding(
                    url=url, category="sri",
                    finding="External script loaded without Sub-Resource Integrity (SRI) attribute",
                    severity="Medium",
                    evidence=f"Script src={src[:120]} — no integrity= attribute",
                    remediation="Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" to external script tags",
                    cwe="CWE-353",
                ))
                break  # one finding per page
        return findings

    # ── Reverse tabnabbing ────────────────────────────────────────────────

    def _check_reverse_tabnabbing(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        # Find target=_blank links without rel=noopener
        links = re.finditer(
            r'<a\b([^>]*target\s*=\s*["\']?_blank[^>]*)>',
            body[:32000], re.I,
        )
        for m in links:
            attrs = m.group(1).lower()
            if "noopener" not in attrs and "noreferrer" not in attrs:
                href_m = re.search(r'href\s*=\s*["\']?([^"\'>\s]+)', m.group(0), re.I)
                href = href_m.group(1) if href_m else "(unknown)"
                findings.append(PassiveFinding(
                    url=url, category="tabnabbing",
                    finding="Link with target=_blank missing rel=noopener — reverse tabnabbing possible",
                    severity="Medium",
                    evidence=f"href={href[:100]}, target=_blank without rel=noopener/noreferrer",
                    remediation="Add rel=\"noopener noreferrer\" to all target=_blank links",
                    cwe="CWE-1022",
                ))
                break  # one per page
        return findings

    # ── Insecure form action (HTTPS page → HTTP action) ───────────────────

    def _check_insecure_form_action(self, url: str, body: str) -> list[PassiveFinding]:
        if not url.startswith("https://"):
            return []
        findings = []
        actions = re.findall(
            r'<form\b[^>]*action\s*=\s*["\']?(http://[^"\'>\s]+)',
            body[:16000], re.I,
        )
        for action in actions[:3]:
            findings.append(PassiveFinding(
                url=url, category="mixed_content",
                finding="HTTPS page submits form to HTTP action — credentials may be intercepted",
                severity="High",
                evidence=f"Form action={action[:120]} on HTTPS page",
                remediation="Ensure form actions use HTTPS on secure pages",
                cwe="CWE-319",
            ))
            break  # one per page
        return findings

    # ── Cross-domain script inclusion ─────────────────────────────────────

    def _check_cross_domain_scripts(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        from urllib.parse import urlparse
        page_host = urlparse(url).hostname or ""
        scripts = re.findall(
            r'<script\b[^>]*src\s*=\s*["\']?(https?://[^"\'>\s]+)',
            body[:32000], re.I,
        )
        external = []
        for src in scripts:
            src_host = urlparse(src).hostname or ""
            if src_host and src_host != page_host:
                external.append(src_host)
        if external:
            unique = list(dict.fromkeys(external))[:5]
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding=f"Cross-domain JavaScript inclusion from {len(set(external))} external domain(s)",
                severity="Low",
                evidence=f"External script domains: {', '.join(unique)}"[:300],
                remediation="Review external script dependencies; use SRI for third-party scripts",
                cwe="CWE-829",
            ))
        return findings

    # ── Open redirect (passive — reflected Location header) ───────────────

    def _check_open_redirect(self, url: str, status_code: int, h: dict,
                             body: str = "") -> list[PassiveFinding]:
        findings = []
        from urllib.parse import urlparse, parse_qs
        url_parsed = urlparse(url)

        # 1) Location header reflection on 3xx responses
        if status_code in (301, 302, 303, 307, 308):
            location = h.get("location", "")
            if location and url_parsed.query:
                for _param, vals in parse_qs(url_parsed.query).items():
                    for val in vals:
                        if val and len(val) > 3 and val in location:
                            findings.append(PassiveFinding(
                                url=url, category="open_redirect",
                                finding="Possible open redirect — user input reflected in Location header",
                                severity="Medium",
                                evidence=f"Location: {location[:200]} (param value '{val[:50]}' reflected)",
                                remediation="Validate redirect targets against a whitelist of allowed domains",
                                cwe="CWE-601",
                            ))
                            return findings

        # 2) Meta refresh redirect to external domain
        if body:
            import re as _re
            meta_refresh = _re.search(
                r'<meta[^>]*http-equiv\s*=\s*["\']?refresh[^>]*content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*["\']?(https?://[^\s"\'>;]+)',
                body[:8000], _re.I
            )
            if meta_refresh:
                refresh_url = meta_refresh.group(1)
                refresh_host = urlparse(refresh_url).hostname or ""
                page_host = url_parsed.hostname or ""
                if refresh_host and refresh_host != page_host and not refresh_host.endswith("." + page_host):
                    findings.append(PassiveFinding(
                        url=url, category="open_redirect",
                        finding="Meta refresh redirects to external domain",
                        severity="Medium",
                        evidence=f"<meta refresh> URL: {refresh_url[:200]}",
                        remediation="Avoid meta refresh redirects to user-controlled or external URLs",
                        cwe="CWE-601",
                    ))

            # 3) JavaScript-based redirect reflecting query params
            if url_parsed.query:
                js_redirect_patterns = [
                    r'window\.location\s*=\s*["\'][^"\']*',
                    r'document\.location\s*=\s*["\'][^"\']*',
                    r'window\.location\.href\s*=\s*["\'][^"\']*',
                    r'window\.location\.replace\s*\(["\'][^"\']*',
                    r'window\.location\.assign\s*\(["\'][^"\']*',
                ]
                for _param, vals in parse_qs(url_parsed.query).items():
                    for val in vals:
                        if val and len(val) > 3:
                            for pat in js_redirect_patterns:
                                match = _re.search(pat + _re.escape(val), body[:8000], _re.I)
                                if match:
                                    findings.append(PassiveFinding(
                                        url=url, category="open_redirect",
                                        finding="JavaScript redirect reflects user input from query parameter",
                                        severity="Medium",
                                        evidence=f"JS: {match.group(0)[:200]} (param value '{val[:50]}' reflected)",
                                        remediation="Validate redirect targets in JS against an allowlist",
                                        cwe="CWE-601",
                                    ))
                                    return findings

        return findings

    # ── ViewState analysis ────────────────────────────────────────────────

    def _check_viewstate(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        m = _VIEWSTATE_RE.search(body[:32000])
        if not m:
            return []
        vs_value = m.group(1)
        # Check if ViewState is unprotected (no MAC)
        has_mac = _VIEWSTATE_MAC_RE.search(body[:32000])
        if not has_mac:
            findings.append(PassiveFinding(
                url=url, category="viewstate",
                finding="ASP.NET ViewState without MAC — tampering and deserialization attacks possible",
                severity="High",
                evidence=f"__VIEWSTATE present ({len(vs_value)} chars), no __VIEWSTATEGENERATOR found",
                remediation="Enable ViewState MAC validation: <pages enableViewStateMac=\"true\" />",
                cwe="CWE-642",
            ))
        else:
            findings.append(PassiveFinding(
                url=url, category="viewstate",
                finding="ASP.NET ViewState detected — verify encryption is enabled",
                severity="Info",
                evidence=f"__VIEWSTATE={vs_value[:80]}...",
                remediation="Ensure ViewState encryption is enabled for sensitive pages",
                cwe="CWE-642",
            ))
        return findings

    # ── Java serialization ────────────────────────────────────────────────

    def _check_java_serialization(self, url: str, body: str) -> list[PassiveFinding]:
        # Check for base64-encoded Java serialization magic bytes: rO0AB
        if "rO0AB" in body[:8000]:
            return [PassiveFinding(
                url=url, category="info_disclosure",
                finding="Java serialization object detected — deserialization attacks possible",
                severity="High",
                evidence="Base64-encoded Java serialization magic bytes (rO0AB) found",
                remediation="Avoid Java serialization; use safe formats (JSON). If required, use look-ahead deserialization filters",
                cwe="CWE-502",
            )]
        return []

    # ── Polyfill CDN (malicious supply chain) ─────────────────────────────

    def _check_polyfill_cdn(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        scripts = re.findall(
            r'(?:src|href)\s*=\s*["\']?https?://([^/"\'>\s]+)',
            body[:32000], re.I,
        )
        for domain in scripts:
            domain_lower = domain.lower()
            for bad in _POLYFILL_BAD_DOMAINS:
                if domain_lower == bad or domain_lower.endswith("." + bad):
                    findings.append(PassiveFinding(
                        url=url, category="supply_chain",
                        finding=f"Script loaded from known-malicious domain: {domain}",
                        severity="High",
                        evidence=f"Resource loaded from {domain} — known supply-chain attack domain",
                        remediation="Replace polyfill.io with cdnjs.cloudflare.com/polyfill or self-host polyfills",
                        cwe="CWE-829",
                    ))
                    return findings  # one is enough
        return findings

    # ── Big redirect (large response body on redirect) ────────────────────

    def _check_big_redirect(self, url: str, status_code: int, body: str, h: dict) -> list[PassiveFinding]:
        if status_code not in (301, 302, 303, 307, 308):
            return []
        if len(body) > 512:
            return [PassiveFinding(
                url=url, category="info_disclosure",
                finding="Large redirect response — may leak sensitive information in body",
                severity="Low",
                evidence=f"Status {status_code} redirect with {len(body)} byte body (expected minimal)",
                remediation="Redirect responses should have minimal or empty bodies",
                cwe="CWE-200",
            )]
        return []

    # ══════════════════════════════════════════════════════════════════════════
    # Advanced checks — Burp Suite / Nuclei / modern pattern parity
    # ══════════════════════════════════════════════════════════════════════════

    # ── Service-specific API key detection ───────────────────────────────────

    def _check_service_api_keys(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        scan_body = body[:32000]
        for pat, desc, sev, cwe in _SERVICE_API_KEY_PATTERNS:
            m = pat.search(scan_body)
            if m:
                matched = m.group(0)
                masked = matched[:8] + "..." + matched[-4:] if len(matched) > 16 else matched[:8] + "..."
                findings.append(PassiveFinding(
                    url=url, category="secret_disclosure",
                    finding=desc, severity=sev,
                    evidence=f"Matched: {masked}",
                    remediation="Rotate the exposed credential immediately and remove from response",
                    cwe=cwe,
                ))
        return findings

    # ── JWT passive analysis ─────────────────────────────────────────────────

    def _check_jwt_passive(self, url: str, body: str) -> list[PassiveFinding]:
        import base64, json as _json
        findings = []
        tokens = _JWT_RE.findall(body[:32000])
        for token in tokens[:3]:
            parts = token.split(".")
            if len(parts) < 2:
                continue
            # Decode header
            try:
                hdr_b = parts[0] + "=" * (4 - len(parts[0]) % 4)
                hdr = _json.loads(base64.urlsafe_b64decode(hdr_b))
            except Exception:
                continue
            alg = str(hdr.get("alg", "")).lower()
            if alg == "none":
                findings.append(PassiveFinding(
                    url=url, category="jwt",
                    finding="JWT with alg:none — signature verification bypass",
                    severity="Critical",
                    evidence=f"JWT header: alg={hdr.get('alg')}",
                    remediation="Reject JWTs with alg:none; always verify signatures",
                    cwe="CWE-347",
                ))
            elif alg in ("hs256", "hs384", "hs512"):
                findings.append(PassiveFinding(
                    url=url, category="jwt",
                    finding=f"JWT uses symmetric algorithm ({hdr.get('alg')}) — verify secret strength",
                    severity="Medium",
                    evidence=f"JWT header: alg={hdr.get('alg')}",
                    remediation="Use asymmetric algorithms (RS256/ES256) or ensure strong HMAC secrets",
                    cwe="CWE-326",
                ))
            # Decode payload for sensitive claims
            try:
                pay_b = parts[1] + "=" * (4 - len(parts[1]) % 4)
                pay_str = base64.urlsafe_b64decode(pay_b).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for cpat, cdesc, csev, ccwe in _JWT_SENSITIVE_CLAIMS:
                if cpat.search(pay_str):
                    findings.append(PassiveFinding(
                        url=url, category="jwt",
                        finding=cdesc, severity=csev,
                        evidence=f"Sensitive claim found in JWT payload",
                        remediation="Do not store sensitive data in JWT payload; use server-side session storage",
                        cwe=ccwe,
                    ))
            # Check expiration
            try:
                import time as _time
                pay_obj = _json.loads(pay_str)
                exp = pay_obj.get("exp")
                if exp and isinstance(exp, (int, float)) and exp < _time.time():
                    findings.append(PassiveFinding(
                        url=url, category="jwt",
                        finding="Expired JWT returned in response",
                        severity="Info",
                        evidence=f"JWT exp={exp} is in the past",
                        remediation="Do not return expired JWTs; issue fresh tokens",
                        cwe="CWE-613",
                    ))
            except Exception:
                pass
            break  # one JWT per page is enough
        return findings

    # ── CSP policy quality analysis ──────────────────────────────────────────

    def _check_csp_policy(self, url: str, h: dict) -> list[PassiveFinding]:
        # CSP checks only relevant for HTML pages
        ct = (h.get("content-type") or "").lower()
        if "text/html" not in ct:
            return []
        csp = h.get("content-security-policy", "")
        if not csp:
            return []  # absence already caught by _check_security_headers
        findings = []
        for pat, desc, sev, cwe in _CSP_DIRECTIVE_CHECKS:
            if pat.search(csp):
                findings.append(PassiveFinding(
                    url=url, category="csp_policy",
                    finding=desc, severity=sev,
                    evidence=f"CSP: {csp[:200]}",
                    remediation="Tighten CSP directives; remove unsafe-inline/unsafe-eval/wildcards",
                    cwe=cwe,
                ))
        # Missing frame-ancestors (clickjacking via CSP)
        if "frame-ancestors" not in csp.lower():
            findings.append(PassiveFinding(
                url=url, category="csp_policy",
                finding="CSP missing frame-ancestors directive — clickjacking not prevented via CSP",
                severity="Medium",
                evidence=f"CSP: {csp[:200]}",
                remediation="Add: frame-ancestors 'self'",
                cwe="CWE-1021",
            ))
        # Missing base-uri
        if "base-uri" not in csp.lower():
            findings.append(PassiveFinding(
                url=url, category="csp_policy",
                finding="CSP missing base-uri — base tag injection allows relative URL hijack",
                severity="Medium",
                evidence=f"CSP: {csp[:200]}",
                remediation="Add: base-uri 'self'",
                cwe="CWE-693",
            ))
        return findings

    # ── Source map disclosure ─────────────────────────────────────────────────

    def _check_source_maps(self, url: str, body: str, h: dict) -> list[PassiveFinding]:
        findings = []
        # Header check
        for hdr_name in ("sourcemap", "x-sourcemap"):
            if hdr_name in h:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"SourceMap header present — source code map accessible",
                    severity="Medium",
                    evidence=f"{hdr_name}: {h[hdr_name][:200]}",
                    remediation="Remove SourceMap headers in production; restrict .map file access",
                    cwe="CWE-540",
                ))
        # Inline source map (full source embedded)
        if _SOURCE_MAP_INLINE.search(body[:32000]):
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="Inline source map embedded — full source code in response",
                severity="High",
                evidence="sourceMappingURL=data:application/json found",
                remediation="Remove inline source maps in production builds",
                cwe="CWE-540",
            ))
        else:
            # External .map reference
            for pat in (_SOURCE_MAP_JS, _SOURCE_MAP_CSS):
                m = pat.search(body[:32000])
                if m:
                    findings.append(PassiveFinding(
                        url=url, category="info_disclosure",
                        finding="Source map file referenced — source code may be accessible",
                        severity="Medium",
                        evidence=f"sourceMappingURL={m.group(1)[:100]}",
                        remediation="Remove sourceMappingURL in production; restrict .map access",
                        cwe="CWE-540",
                    ))
                    break
        return findings

    # ── Cloud metadata URLs ──────────────────────────────────────────────────

    def _check_cloud_metadata(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        for pat, desc, sev, cwe in _CLOUD_METADATA_PATTERNS:
            if pat.search(body):
                findings.append(PassiveFinding(
                    url=url, category="ssrf",
                    finding=desc, severity=sev,
                    evidence=f"Pattern: {pat.pattern[:60]}",
                    remediation="Block access to cloud metadata endpoints; validate URL inputs server-side",
                    cwe=cwe,
                ))
        return findings

    # ── JSONP callback detection ─────────────────────────────────────────────

    def _check_jsonp(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        # Check if response looks like JSONP
        if _JSONP_RESPONSE_RE.search(body[:2000]):
            # Check if URL has a callback parameter
            cb_m = _JSONP_CALLBACK_PARAMS.search(url)
            if cb_m:
                cb_val = cb_m.group(1)
                if cb_val in body[:2000]:
                    findings.append(PassiveFinding(
                        url=url, category="jsonp",
                        finding="JSONP endpoint — callback parameter reflected in response",
                        severity="High",
                        evidence=f"callback={cb_val} reflected in JSONP response",
                        remediation="Migrate from JSONP to CORS; validate/whitelist callback values",
                        cwe="CWE-79",
                    ))
            else:
                findings.append(PassiveFinding(
                    url=url, category="jsonp",
                    finding="JSONP-style response detected — potential data theft via script injection",
                    severity="Medium",
                    evidence="Response starts with function call wrapping JSON",
                    remediation="Migrate from JSONP to CORS; restrict callback origins",
                    cwe="CWE-79",
                ))
        return findings

    # ── Prototype pollution sinks ────────────────────────────────────────────

    def _check_proto_pollution(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        scan = body[:32000]
        for pat, desc, sev, cwe in _PROTO_POLLUTION_PATTERNS:
            if pat.search(scan):
                findings.append(PassiveFinding(
                    url=url, category="prototype_pollution",
                    finding=desc, severity=sev,
                    evidence=f"Pattern: {pat.pattern[:60]}",
                    remediation="Use Object.create(null), freeze prototypes, or input validation",
                    cwe=cwe,
                ))
        return findings

    # ── GraphQL passive detection ────────────────────────────────────────────

    def _check_graphql_passive(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        for pat, desc, sev, cwe in _GRAPHQL_PASSIVE_PATTERNS:
            if pat.search(body[:16000]):
                findings.append(PassiveFinding(
                    url=url, category="graphql",
                    finding=desc, severity=sev,
                    evidence=f"Pattern: {pat.pattern[:60]}",
                    remediation="Disable GraphQL introspection in production; remove IDE endpoints",
                    cwe=cwe,
                ))
        return findings

    # ── Multi-language deserialization ────────────────────────────────────────

    def _check_deserialization_multi(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        for pat, desc, sev, cwe in _DESER_PATTERNS:
            if pat.search(body[:16000]):
                findings.append(PassiveFinding(
                    url=url, category="deserialization",
                    finding=desc, severity=sev,
                    evidence=f"Pattern: {pat.pattern[:60]}",
                    remediation="Avoid native serialization; use safe formats (JSON). Add deserialization filters",
                    cwe=cwe,
                ))
        return findings

    # ── Build artifacts / dev mode ───────────────────────────────────────────

    def _check_build_artifacts(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        for pat, desc, sev, cwe in _BUILD_ARTIFACT_PATTERNS:
            if pat.search(body[:32000]):
                findings.append(PassiveFinding(
                    url=url, category="build_artifact",
                    finding=desc, severity=sev,
                    evidence=f"Pattern: {pat.pattern[:60]}",
                    remediation="Use production builds; strip dev artifacts before deployment",
                    cwe=cwe,
                ))
        return findings

    # ── Framework debug mode ─────────────────────────────────────────────────

    def _check_framework_debug(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        for pat, desc, sev, cwe in _FRAMEWORK_DEBUG_PATTERNS:
            if pat.search(body[:16000]):
                findings.append(PassiveFinding(
                    url=url, category="debug_mode",
                    finding=desc, severity=sev,
                    evidence=f"Pattern: {pat.pattern[:60]}",
                    remediation="Disable debug mode in production; use production build configurations",
                    cwe=cwe,
                ))
        return findings

    # ── Modern security headers ──────────────────────────────────────────────

    def _check_modern_headers(self, url: str, h: dict) -> list[PassiveFinding]:
        findings = []
        for hdr, (sev, finding, remediation, cwe) in _MODERN_HEADERS.items():
            if hdr not in h:
                findings.append(PassiveFinding(
                    url=url, category="security_header",
                    finding=finding, severity=sev,
                    evidence=f"Response missing {hdr} header",
                    remediation=remediation, cwe=cwe,
                ))
        return findings

    # ── Technology fingerprints ──────────────────────────────────────────────

    def _check_tech_fingerprints(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        for pat, desc, sev, cwe in _FRAMEWORK_DEBUG_PATTERNS + _BUILD_ARTIFACT_PATTERNS:
            pass  # already covered above
        # Dedicated technology checks
        scan = body[:16000]
        for pat, desc, sev, cwe in [
            (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([\d.]+)', re.I),
             "WordPress version disclosed in generator meta tag", "Low", "CWE-200"),
            (re.compile(r'xml-rpc server accepts POST requests only', re.I),
             "WordPress XML-RPC accessible — brute-force amplification risk", "High", "CWE-284"),
            (re.compile(r'(?i)APP_KEY\s*=\s*base64:[A-Za-z0-9+/=]{44}'),
             "Laravel APP_KEY exposed — session forgery possible", "Critical", "CWE-312"),
            (re.compile(r'(?i)DB_(?:PASSWORD|CONNECTION)\s*=\s*\S+'),
             "Laravel .env database configuration exposed", "Critical", "CWE-312"),
            (re.compile(r'"activeProfiles"\s*:\s*\[', re.I),
             "Spring Boot Actuator /env exposed — environment variables disclosed", "Critical", "CWE-200"),
            (re.compile(r'::\s*Spring Boot\s*::\s*\(v[\d.]+\)', re.I),
             "Spring Boot version disclosed in response", "Info", "CWE-200"),
            (re.compile(r'(?i)SECRET_KEY\s*=\s*["\'][a-z0-9!@#$%^&*()\-_+]{40,}["\']'),
             "Django SECRET_KEY exposed in response", "Critical", "CWE-312"),
            (re.compile(r'(?i)secret_key_base\s*[=:]\s*["\']?[a-f0-9]{128}'),
             "Rails secret_key_base exposed — session forgery possible", "Critical", "CWE-312"),
            (re.compile(r'(?i)RAILS_MASTER_KEY\s*=\s*[a-f0-9]{32}'),
             "Rails master.key exposed", "Critical", "CWE-312"),
            (re.compile(r'(?i)validationKey\s*=\s*["\'][A-Fa-f0-9]{48,}["\']'),
             "ASP.NET machineKey validationKey exposed — RCE possible", "Critical", "CWE-312"),
            (re.compile(r'(?i)<title>phpinfo\(\)</title>'),
             "PHP phpinfo() page accessible", "Critical", "CWE-200"),
            (re.compile(r'"openapi"\s*:\s*"[23]\.\d+\.\d+"'),
             "OpenAPI/Swagger specification exposed publicly", "Low", "CWE-200"),
        ]:
            if pat.search(scan):
                findings.append(PassiveFinding(
                    url=url, category="tech_fingerprint",
                    finding=desc, severity=sev,
                    evidence=f"Pattern: {pat.pattern[:60]}",
                    remediation="Remove debug/config info from production; restrict admin endpoints",
                    cwe=cwe,
                ))
        return findings

    # ── Session fixation indicators ──────────────────────────────────────────

    def _check_session_fixation(self, url: str, h: dict) -> list[PassiveFinding]:
        findings = []
        # Session ID in URL
        if _SESSION_IN_URL_RE.search(url):
            findings.append(PassiveFinding(
                url=url, category="session",
                finding="Session ID transmitted in URL — session fixation and leakage via Referer",
                severity="High",
                evidence=f"URL contains session parameter: {url[:200]}",
                remediation="Transmit session IDs only via cookies; never in URL parameters",
                cwe="CWE-384",
            ))
        # Pre-auth session cookie on login pages
        if _LOGIN_URL_RE.search(url):
            for key in ("set-cookie",):
                cookie_val = h.get(key, "")
                if cookie_val:
                    for sc in cookie_val.split("\n"):
                        name = sc.split("=", 1)[0].strip()
                        if _SESSION_COOKIE_NAMES.match(name):
                            sc_lower = sc.lower()
                            if "httponly" not in sc_lower or "secure" not in sc_lower:
                                findings.append(PassiveFinding(
                                    url=url, category="session",
                                    finding=f"Session cookie '{name}' set on login page without full security flags",
                                    severity="Medium",
                                    evidence=f"Set-Cookie: {sc[:100]}",
                                    remediation="Ensure session cookies have HttpOnly, Secure, and SameSite flags",
                                    cwe="CWE-384",
                                ))
                                break
        return findings

    # ── Insecure WebSocket (ws:// on HTTPS) ──────────────────────────────────

    def _check_insecure_websocket(self, url: str, body: str) -> list[PassiveFinding]:
        if not url.startswith("https://"):
            return []
        findings = []
        for pat, desc, sev, cwe in _INSECURE_WS_PATTERNS:
            if pat.search(body[:16000]):
                findings.append(PassiveFinding(
                    url=url, category="mixed_content",
                    finding=desc, severity=sev,
                    evidence=f"ws:// WebSocket on HTTPS page",
                    remediation="Upgrade WebSocket connections to wss:// (secure WebSocket)",
                    cwe=cwe,
                ))
                break
        return findings

    # ── OAuth misconfiguration indicators ────────────────────────────────────

    def _check_oauth_indicators(self, url: str, body: str, h: dict) -> list[PassiveFinding]:
        findings = []
        # Check URL and body for OAuth token leakage
        check_text = url + " " + body[:8000]
        for pat, desc, sev, cwe in _OAUTH_PATTERNS:
            if pat.search(check_text):
                findings.append(PassiveFinding(
                    url=url, category="oauth",
                    finding=desc, severity=sev,
                    evidence=f"Pattern: {pat.pattern[:60]}",
                    remediation="Use PKCE flow; transmit tokens in body/headers, never in URLs",
                    cwe=cwe,
                ))
        return findings

    # ── Sensitive parameters in URL (ZAP 10024) ──────────────────────────────

    def _check_sensitive_url_params(self, url: str) -> list[PassiveFinding]:
        findings = []
        for m in _SENSITIVE_URL_PARAMS.finditer(url):
            param_match = m.group(0)
            param_name = param_match.split("=")[0].lstrip("?&").strip()
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding=f"Sensitive parameter '{param_name}' transmitted in URL — visible in logs/Referer",
                severity="Medium",
                evidence=f"URL contains: {param_match[:80]}",
                remediation="Transmit sensitive values via POST body or headers, never in URL query strings",
                cwe="CWE-598",
            ))
        return findings

    # ── Sensitive data in Referrer header (ZAP 10025) ─────────────────────────

    def _check_referrer_leak(self, url: str, h: dict, req_headers: dict) -> list[PassiveFinding]:
        findings = []
        referer = req_headers.get("referer", req_headers.get("Referer", ""))
        if not referer:
            return findings
        for m in _SENSITIVE_REFERRER_PARAMS.finditer(referer):
            param_match = m.group(0)
            param_name = param_match.split("=")[0].lstrip("?&").strip()
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding=f"Referrer header leaks sensitive parameter '{param_name}' to this page",
                severity="Medium",
                evidence=f"Referer: {referer[:120]}",
                remediation="Set Referrer-Policy: strict-origin-when-cross-origin; avoid sensitive data in URLs",
                cwe="CWE-200",
            ))
        # OAuth implicit-flow tokens in URL fragment leak to third-party resources via Referer
        if _OAUTH_FRAGMENT_RE.search(referer):
            findings.append(PassiveFinding(
                url=url, category="oauth",
                finding="OAuth token in URL fragment leaking via Referer header to this resource",
                severity="High",
                evidence=f"Referer contains fragment token: {referer[:120]}",
                remediation=(
                    "Set Referrer-Policy: no-referrer on OAuth callback pages; "
                    "use Authorization Code + PKCE instead of implicit flow"
                ),
                cwe="CWE-598",
            ))
        return findings

    # ── Timestamp disclosure (ZAP 10096) ──────────────────────────────────────

    def _check_timestamp_disclosure(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        m = _TIMESTAMP_IN_BODY.search(body[:16000])
        if m:
            ts_val = m.group(1)
            # Only flag plausible timestamps (2000-01-01 to 2040-01-01)
            try:
                ts_int = int(ts_val)
                if 946684800 <= ts_int <= 2208988800:
                    findings.append(PassiveFinding(
                        url=url, category="info_disclosure",
                        finding="Unix timestamp disclosed — reveals server date/time information",
                        severity="Info",
                        evidence=f"Timestamp found: {m.group(0)[:100]}",
                        remediation="Avoid exposing server timestamps; use relative times or opaque tokens",
                        cwe="CWE-200",
                    ))
            except (ValueError, OverflowError):
                pass
        return findings

    # ── Cache / proxy topology headers ────────────────────────────────────────

    def _check_cache_topology(self, url: str, h: dict) -> list[PassiveFinding]:
        findings = []
        for hdr, (severity, msg, cwe) in _CACHE_TOPOLOGY_HEADERS.items():
            val = h.get(hdr, "")
            if val:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=f"{hdr}: {val[:120]}",
                    remediation="Strip infrastructure headers at the edge/reverse proxy before reaching clients",
                    cwe=cwe,
                ))
        return findings

    # ── Private IP disclosure in headers ─────────────────────────────────────

    def _check_private_ip_headers(self, url: str, h: dict) -> list[PassiveFinding]:
        """Detect private/internal IP addresses leaked in response headers."""
        findings = []
        seen = set()
        for hdr_name in _PRIVATE_IP_HEADERS:
            val = h.get(hdr_name, "")
            if not val:
                continue
            m = _PRIVATE_IP_HEADER_RE.search(val)
            if m and m.group(0) not in seen:
                seen.add(m.group(0))
                findings.append(PassiveFinding(
                    url=url, category="private_ip_disclosure",
                    finding=f"Private IP address leaked in {hdr_name} header",
                    severity="Low",
                    evidence=f"{hdr_name}: {val[:120]}",
                    remediation="Configure reverse proxy to strip or rewrite internal "
                                "IP addresses from response headers before reaching clients",
                    cwe="CWE-200",
                ))
        return findings

    # ── Username enumeration signals (ZAP 40023) ────────────────────────────────

    def _check_username_enumeration(self, url: str, body: str) -> list[PassiveFinding]:
        """Detect response messages that reveal whether a username/account exists."""
        findings = []
        # Only check pages that look like auth-related responses
        url_lower = url.lower()
        auth_url = any(kw in url_lower for kw in (
            "login", "signin", "sign-in", "auth", "account", "register",
            "signup", "sign-up", "password", "forgot", "reset", "recover",
        ))
        # Also check if body contains form-related auth context
        body_sample = body[:12000]
        auth_body = bool(re.search(
            r"(?:type=[\"']password|name=[\"'](?:user|email|login|pass))",
            body_sample, re.I
        ))

        if not (auth_url or auth_body):
            return findings

        # Suppress if the page uses a GENERIC safe error message
        # (e.g., "Invalid username or password" — this is the correct pattern)
        _generic_safe = re.compile(
            r"\b(?:invalid|incorrect|wrong)\s+"
            r"(?:user(?:name)?|email|login|credentials?)\s+"
            r"(?:or|and|/)\s+password\b", re.I
        )
        has_generic_safe = bool(_generic_safe.search(body_sample))

        seen = set()
        for pat, desc, severity in _USERNAME_ENUM_PATTERNS:
            # If page has generic "invalid username or password", skip
            # password-specific AND username-specific patterns (they'd be FPs)
            if has_generic_safe and ("password" in desc.lower() or "username" in desc.lower()):
                continue
            m = pat.search(body_sample)
            if m and desc not in seen:
                seen.add(desc)
                findings.append(PassiveFinding(
                    url=url, category="username_enumeration",
                    finding=desc,
                    severity=severity,
                    evidence=m.group(0)[:120],
                    remediation="Use generic error messages like 'Invalid username or password' "
                                "for all authentication failures. Do not reveal whether the "
                                "username exists separately from the password check.",
                    cwe="CWE-204",
                ))
        return findings

    # ── SQL keywords in HTML comments (ZAP suspicious comments) ───────────────

    def _check_sql_in_comments(self, url: str, body: str) -> list[PassiveFinding]:
        findings = []
        m = _SQL_IN_COMMENTS.search(body[:16000])
        if m:
            keyword = m.group(1)[:40]
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="HTML comment contains SQL statement — possible query leakage",
                severity="Medium",
                evidence=f"Comment contains: {keyword}",
                remediation="Remove SQL and debug information from HTML comments in production",
                cwe="CWE-200",
            ))
        return findings

    # ── ZAP parity: 15 additional passive rules ──────────────────────────────

    def _check_cache_control(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10015 — Missing or weak Cache-Control on potentially sensitive pages."""
        findings = []
        cc = h.get("cache-control", "")
        pragma = h.get("pragma", "")
        # Only flag if URL looks sensitive (auth, account, admin, api)
        sensitive_patterns = ("/login", "/auth", "/account", "/admin", "/api/",
                              "/user", "/profile", "/settings", "/dashboard")
        is_sensitive = any(p in url.lower() for p in sensitive_patterns)
        if is_sensitive and "no-store" not in cc and "no-cache" not in pragma:
            findings.append(PassiveFinding(
                url=url, category="cache_control",
                finding="Sensitive page lacks Cache-Control: no-store directive",
                severity="Low",
                evidence=f"Cache-Control: {cc or '(missing)'}",
                remediation="Add 'Cache-Control: no-store' to responses containing sensitive data",
                cwe="CWE-525",
            ))
        return findings

    def _check_cookie_loose_scope(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 90033 — Cookie domain is broader than the current host."""
        findings = []
        hostname = urlparse(url).hostname or ""
        for sc in _iter_set_cookie(h):
            domain_match = re.search(r"domain=([^;\s]+)", sc, re.IGNORECASE)
            if domain_match:
                cookie_domain = domain_match.group(1).strip().lstrip(".")
                if cookie_domain and hostname.endswith(cookie_domain) and cookie_domain != hostname:
                    name = sc.split("=")[0].strip()
                    findings.append(PassiveFinding(
                        url=url, category="cookie_security",
                        finding=f"Cookie '{name}' has loosely scoped domain (broader than host)",
                        severity="Info",
                        evidence=f"Domain={cookie_domain} vs Host={hostname}",
                        remediation="Scope cookies to the narrowest domain necessary",
                        cwe="CWE-565",
                    ))
        return findings

    def _check_suspicious_comments(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10027 — Suspicious comments: TODO, FIXME, HACK, BUG, XXX, WORKAROUND."""
        findings = []
        if not body:
            return findings
        # Only check HTML content
        comment_patterns = re.findall(
            r"<!--[\s\S]*?(?:TODO|FIXME|HACK|BUG|XXX|WORKAROUND|DEBUG|LATER|TEMP)\b[\s\S]*?-->",
            body[:16000], re.IGNORECASE,
        )
        if comment_patterns:
            sample = comment_patterns[0][:120]
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding=f"HTML contains suspicious developer comment ({len(comment_patterns)} found)",
                severity="Info",
                evidence=sample,
                remediation="Remove developer comments (TODO, FIXME, HACK, BUG) from production HTML",
                cwe="CWE-615",
            ))
        return findings

    def _check_banner_info_leak(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10009 — In-page banner information leak (server version strings in body)."""
        findings = []
        if not body:
            return findings
        banner_patterns = [
            (r"Apache/([\d.]+)", "Apache"),
            (r"nginx/([\d.]+)", "nginx"),
            (r"Microsoft-IIS/([\d.]+)", "IIS"),
            (r"PHP/([\d.]+)", "PHP"),
            (r"OpenSSL/([\d.a-z]+)", "OpenSSL"),
            (r"Tomcat/([\d.]+)", "Tomcat"),
            (r"Jetty\(?([\d.v]+)", "Jetty"),
        ]
        for pattern, name in banner_patterns:
            m = re.search(pattern, body[:16000])
            if m:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Server banner in page body reveals {name} version",
                    severity="Low",
                    evidence=f"{name}/{m.group(1)}",
                    remediation="Remove server version banners from page content",
                    cwe="CWE-200",
                ))
                break  # One finding per page
        return findings

    def _check_insecure_auth(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10105 — Basic/Digest authentication over plain HTTP."""
        findings = []
        www_auth = h.get("www-authenticate", "")
        if www_auth and url.startswith("http://"):
            scheme = www_auth.split()[0] if www_auth.split() else ""
            findings.append(PassiveFinding(
                url=url, category="auth_security",
                finding=f"{scheme} authentication credentials sent over unencrypted HTTP",
                severity="High",
                evidence=f"WWW-Authenticate: {www_auth[:80]}",
                remediation="Use HTTPS for all pages requiring authentication",
                cwe="CWE-319",
            ))
        return findings

    def _check_session_id_in_url(self, url: str) -> list[PassiveFinding]:
        """ZAP 3 — Session ID exposed in URL (URL rewriting)."""
        findings = []
        session_patterns = [
            (r"[?&;](?:JSESSIONID|jsessionid)=([a-fA-F0-9]{16,})", "JSESSIONID"),
            (r"[?&;](?:PHPSESSID|phpsessid)=([a-zA-Z0-9]{16,})", "PHPSESSID"),
            (r"[?&;](?:ASP\.NET_SessionId|asp\.net_sessionid)=([a-zA-Z0-9]{16,})", "ASP.NET_SessionId"),
            (r"[?&;](?:sid|SID|session_id|sessionid)=([a-zA-Z0-9]{16,})", "session_id"),
            (r";jsessionid=([a-fA-F0-9]{16,})", "JSESSIONID (path param)"),
        ]
        for pattern, name in session_patterns:
            if re.search(pattern, url):
                findings.append(PassiveFinding(
                    url=url, category="session_security",
                    finding=f"Session ID ({name}) exposed in URL — vulnerable to session fixation and leakage",
                    severity="Medium",
                    evidence=url[:200],
                    remediation="Use cookies for session management instead of URL rewriting",
                    cwe="CWE-598",
                ))
                break
        return findings

    def _check_permissions_policy(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10063 — Missing Permissions-Policy (Feature-Policy) header."""
        findings = []
        pp = h.get("permissions-policy", "")
        fp = h.get("feature-policy", "")
        ct = h.get("content-type", "")
        if "text/html" in ct and not pp and not fp:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="Permissions-Policy header not set — browser features unrestricted",
                severity="Low",
                evidence="Missing Permissions-Policy and Feature-Policy headers",
                remediation="Set Permissions-Policy to restrict camera, microphone, geolocation, etc.",
                cwe="CWE-693",
            ))
        return findings

    def _check_source_code_in_response(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10099 — Source code (PHP, JSP, ASP) leaked in response."""
        findings = []
        if not body:
            return findings
        code_patterns = [
            (r"<\?php\s", "PHP"),
            (r"<%@?\s*(?:page|import|taglib)", "JSP"),
            (r"<%\s*(?:Response|Request|Session|Server)\.", "ASP"),
            (r"<\?=\s*\$", "PHP short tag"),
        ]
        for pattern, lang in code_patterns:
            if re.search(pattern, body[:32000]):
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Server-side {lang} source code leaked in response",
                    severity="High",
                    evidence=f"Response contains {lang} code tags",
                    remediation=f"Ensure {lang} is processed server-side and never sent raw to clients",
                    cwe="CWE-540",
                ))
                break
        return findings

    def _check_content_cacheability(self, url: str, h: dict, status_code: int) -> list[PassiveFinding]:
        """ZAP 10049 — Authenticated/sensitive responses that are cacheable."""
        findings = []
        cc = h.get("cache-control", "")
        auth_header = h.get("authorization", "")
        has_set_cookie = "set-cookie" in h
        # If response sets auth cookies or has auth context, it shouldn't be public-cacheable
        if (has_set_cookie or auth_header) and "public" in cc:
            findings.append(PassiveFinding(
                url=url, category="cache_control",
                finding="Authenticated response marked as publicly cacheable",
                severity="Medium",
                evidence=f"Cache-Control: {cc[:80]}; has auth context",
                remediation="Use 'Cache-Control: no-store, private' for authenticated responses",
                cwe="CWE-524",
            ))
        return findings

    def _check_x_chromelogger(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10052 — X-ChromeLogger-Data or X-ChromePhp-Data header leaks debug info."""
        findings = []
        for header_name in ("x-chromelogger-data", "x-chromephp-data"):
            val = h.get(header_name, "")
            if val:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Debug header '{header_name}' leaks server-side debugging data",
                    severity="Medium",
                    evidence=f"{header_name}: {val[:80]}",
                    remediation="Remove ChromeLogger/ChromePHP debug headers in production",
                    cwe="CWE-200",
                ))
        return findings

    def _check_servlet_param_pollution(self, url: str) -> list[PassiveFinding]:
        """ZAP 10026 — HTTP Parameter Pollution (duplicate parameters in URL)."""
        findings = []
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            dupes = [k for k, v in params.items() if len(v) > 1]
            if dupes:
                findings.append(PassiveFinding(
                    url=url, category="input_validation",
                    finding=f"Duplicate HTTP parameters detected: {', '.join(dupes[:5])}",
                    severity="Info",
                    evidence=f"Parameters with multiple values: {dupes[:5]}",
                    remediation="Ensure application handles duplicate parameters consistently",
                    cwe="CWE-235",
                ))
        return findings

    def _check_base64_disclosure(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10094 — Base64-encoded strings that decode to sensitive content."""
        findings = []
        if not body:
            return findings
        import base64
        # Find base64 strings (min 32 chars to reduce noise)
        b64_matches = re.findall(r'[A-Za-z0-9+/]{32,}={0,2}', body[:16000])
        for match in b64_matches[:5]:  # Check first 5 only
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                # Check if decoded content looks sensitive
                sensitive_kw = ("password", "secret", "token", "apikey", "api_key",
                                "private_key", "BEGIN RSA", "BEGIN PRIVATE")
                for kw in sensitive_kw:
                    if kw.lower() in decoded.lower():
                        findings.append(PassiveFinding(
                            url=url, category="info_disclosure",
                            finding=f"Base64-encoded string decodes to sensitive content (contains '{kw}')",
                            severity="Medium",
                            evidence=f"Decoded sample: {decoded[:80]}",
                            remediation="Remove base64-encoded sensitive data from responses",
                            cwe="CWE-200",
                        ))
                        return findings  # One finding per page
            except Exception:
                continue
        return findings

    def _check_user_controllable_html(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10031 — URL parameters reflected in HTML element attributes."""
        findings = []
        if not body:
            return findings
        parsed = urlparse(url)
        if not parsed.query:
            return findings
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name, values in list(params.items())[:10]:
            for val in values:
                if len(val) < 4:
                    continue
                # Check if param value appears in an HTML attribute
                patterns = [
                    rf'<[^>]+\s(?:href|src|action|formaction|data|value)=["\'][^"\']*{re.escape(val)}',
                    rf'<[^>]+\son\w+=["\'][^"\']*{re.escape(val)}',
                ]
                for pattern in patterns:
                    if re.search(pattern, body[:16000], re.IGNORECASE):
                        findings.append(PassiveFinding(
                            url=url, category="xss",
                            finding=f"URL parameter '{param_name}' value reflected in HTML attribute",
                            severity="Info",
                            evidence=f"Parameter value '{val[:40]}' found in HTML attribute context",
                            remediation="Encode user input when reflecting in HTML attributes",
                            cwe="CWE-79",
                        ))
                        return findings  # One finding per page
        return findings

    def _check_cookie_poisoning(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10029 — User-supplied input appears in Set-Cookie header value."""
        findings = []
        parsed = urlparse(url)
        if not parsed.query:
            return findings
        params = parse_qs(parsed.query, keep_blank_values=True)
        for sc in _iter_set_cookie(h):
            cookie_val = sc.split("=", 1)[1].split(";")[0] if "=" in sc else ""
            if len(cookie_val) < 4:
                continue
            for param_name, values in params.items():
                for val in values:
                    if len(val) >= 4 and val in cookie_val:
                        name = sc.split("=")[0].strip()
                        findings.append(PassiveFinding(
                            url=url, category="cookie_security",
                            finding=f"URL parameter '{param_name}' reflected in Set-Cookie '{name}' — cookie poisoning risk",
                            severity="Medium",
                            evidence=f"Param value '{val[:40]}' found in cookie value",
                            remediation="Do not reflect user input into Set-Cookie values without validation",
                            cwe="CWE-20",
                        ))
                        return findings
        return findings

    # ── Burp Suite parity: 30 additional passive checks ──────────────────────

    def _check_password_autocomplete(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp 500600 — Password field with autocomplete enabled."""
        findings = []
        if not body:
            return findings
        pw_inputs = re.findall(
            r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>', body[:32000], re.I
        )
        for tag in pw_inputs:
            if 'autocomplete' not in tag.lower() or re.search(r'autocomplete\s*=\s*["\']on["\']', tag, re.I):
                findings.append(PassiveFinding(
                    url=url, category="form_security",
                    finding="Password field has autocomplete enabled — credentials may be cached",
                    severity="Low",
                    evidence=tag[:120],
                    remediation="Add autocomplete='off' or autocomplete='new-password' to password inputs",
                    cwe="CWE-525",
                ))
                break
        return findings

    def _check_cleartext_password_form(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp 300100 — Form submitting password over unencrypted HTTP."""
        findings = []
        if not body:
            return findings
        forms = re.findall(r'<form[^>]*>[\s\S]*?</form>', body[:64000], re.I)
        for form in forms:
            if not re.search(r'type\s*=\s*["\']password["\']', form, re.I):
                continue
            action = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form, re.I)
            if action:
                act = action.group(1)
                if act.startswith("http://"):
                    findings.append(PassiveFinding(
                        url=url, category="form_security",
                        finding="Password form submits credentials over unencrypted HTTP",
                        severity="High",
                        evidence=f"action='{act[:100]}'",
                        remediation="Change form action to HTTPS",
                        cwe="CWE-319",
                    ))
                    break
            elif url.startswith("http://"):
                findings.append(PassiveFinding(
                    url=url, category="form_security",
                    finding="Password form on HTTP page — credentials sent in cleartext",
                    severity="High",
                    evidence="Page served over HTTP with password input",
                    remediation="Serve login pages over HTTPS only",
                    cwe="CWE-319",
                ))
                break
        return findings

    def _check_file_upload_form(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp informational — File upload functionality detected."""
        findings = []
        if not body:
            return findings
        if re.search(r'<input[^>]*type\s*=\s*["\']file["\'][^>]*>', body[:32000], re.I):
            findings.append(PassiveFinding(
                url=url, category="attack_surface",
                finding="File upload form detected — test for unrestricted upload",
                severity="Info",
                evidence="<input type='file'> found",
                remediation="Validate file type, size, and content; store uploads outside webroot",
                cwe="CWE-434",
            ))
        return findings

    def _check_input_reflection(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp 134110 — URL parameter value reflected in response body."""
        findings = []
        if not body:
            return findings
        parsed = urlparse(url)
        if not parsed.query:
            return findings
        params = parse_qs(parsed.query, keep_blank_values=True)
        body_lower = body[:32000].lower()
        for name, values in params.items():
            for val in values:
                if len(val) >= 6 and val.lower() in body_lower:
                    findings.append(PassiveFinding(
                        url=url, category="xss_indicator",
                        finding=f"URL parameter '{name}' value reflected in response body",
                        severity="Info",
                        evidence=f"'{val[:60]}' found in body",
                        remediation="Investigate for reflected XSS — ensure output encoding is applied",
                        cwe="CWE-79",
                    ))
                    return findings
        return findings

    def _check_request_smuggling_indicators(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — HTTP request smuggling indicators in response headers."""
        findings = []
        te = h.get("transfer-encoding", "")
        cl = h.get("content-length", "")
        if te and cl:
            findings.append(PassiveFinding(
                url=url, category="protocol_issue",
                finding="Response contains both Transfer-Encoding and Content-Length headers",
                severity="Medium",
                evidence=f"TE: {te[:60]}, CL: {cl}",
                remediation="Server should not send both TE and CL — potential request smuggling vector",
                cwe="CWE-444",
            ))
        if te and "," in te:
            findings.append(PassiveFinding(
                url=url, category="protocol_issue",
                finding="Multiple Transfer-Encoding values in response — smuggling risk",
                severity="Medium",
                evidence=f"Transfer-Encoding: {te[:80]}",
                remediation="Use a single Transfer-Encoding value",
                cwe="CWE-444",
            ))
        return findings

    def _check_stack_traces_extended(self, url: str, body: str, status_code: int = 200) -> list[PassiveFinding]:
        """Extended stack trace detection beyond _ERROR_PATTERNS — .NET, Node, Ruby, Go."""
        findings = []
        if not body:
            return findings
        # Stack traces on error pages are expected — only flag on 200
        if status_code != 200:
            return findings
        sample = body[:16000]
        traces = [
            (r"at System\.\w+\.\w+\(", ".NET CLR stack trace exposed", "CWE-209"),
            (r"System\.Web\.Http\w*Exception", ".NET Web exception exposed", "CWE-209"),
            (r"Server Error in '/' Application", "ASP.NET detailed error page exposed", "CWE-209"),
            (r"\bat\s+Object\.<anonymous>\s*\(", "Node.js stack trace exposed", "CWE-209"),
            (r"\bat\s+Module\._compile\s*\(", "Node.js module stack trace exposed", "CWE-209"),
            (r"(?:from|at)\s+[\w/]+\.rb:\d+:in\s+`", "Ruby stack trace exposed", "CWE-209"),
            (r"goroutine \d+ \[running\]:", "Go goroutine stack trace exposed", "CWE-209"),
            (r"panic:\s+runtime error:", "Go panic stack trace exposed", "CWE-209"),
            (r"ActionView::Template::Error", "Ruby on Rails template error exposed", "CWE-209"),
            (r"Illuminate\\[A-Z]\w+\\[A-Z]\w+Exception", "Laravel exception exposed", "CWE-209"),
            (r"raise \w+Error\(", "Python exception raise in response", "CWE-209"),
            (r"ExceptionHandler.*StackTrace", ".NET exception handler trace exposed", "CWE-209"),
        ]
        for pat, msg, cwe in traces:
            if re.search(pat, sample):
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg, severity="High",
                    evidence=re.search(pat, sample).group(0)[:120],
                    remediation="Disable detailed error pages in production; use custom error handlers",
                    cwe=cwe,
                ))
                break
        return findings

    def _check_verbose_db_errors(self, url: str, body: str) -> list[PassiveFinding]:
        """Extended database error messages beyond _ERROR_PATTERNS."""
        findings = []
        if not body:
            return findings
        sample = body[:16000]
        db_errs = [
            (r"ERROR:\s+(?:relation|column|syntax error at)", "PostgreSQL verbose error exposed", "CWE-209"),
            (r"You have an error in your SQL syntax.*MySQL", "MySQL verbose syntax error exposed", "CWE-209"),
            (r"Unclosed quotation mark after.*nvarchar", "MSSQL verbose error exposed", "CWE-209"),
            (r"PLS-\d{4,}:", "Oracle PL/SQL error code exposed", "CWE-209"),
            (r"SQLite3::SQLException", "SQLite error exposed", "CWE-209"),
            (r"com\.mongodb\.\w+Exception", "MongoDB Java driver error exposed", "CWE-209"),
            (r"MongoError:|MongoServerError:", "MongoDB error exposed in response", "CWE-209"),
            (r"redis\.exceptions\.\w+Error", "Redis error exposed in response", "CWE-209"),
        ]
        for pat, msg, cwe in db_errs:
            if re.search(pat, sample, re.I):
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg, severity="High",
                    evidence=re.search(pat, sample, re.I).group(0)[:120],
                    remediation="Suppress detailed database error messages in production",
                    cwe=cwe,
                ))
                break
        return findings

    def _check_xxe_indicators(self, url: str, body: str) -> list[PassiveFinding]:
        """Passive XXE indicators — DTD declarations or entity references in response."""
        findings = []
        if not body:
            return findings
        sample = body[:16000]
        if re.search(r'<!DOCTYPE[^>]*\[[\s\S]*?<!ENTITY', sample, re.I):
            findings.append(PassiveFinding(
                url=url, category="xml_security",
                finding="Response contains XML DTD with ENTITY declaration — XXE risk",
                severity="High",
                evidence="DOCTYPE with ENTITY found in response",
                remediation="Disable DTD processing and external entity resolution in XML parsers",
                cwe="CWE-611",
            ))
        elif re.search(r'<!DOCTYPE[^>]*SYSTEM\s+["\']', sample, re.I):
            findings.append(PassiveFinding(
                url=url, category="xml_security",
                finding="Response references external SYSTEM DTD — potential XXE vector",
                severity="Medium",
                evidence="DOCTYPE SYSTEM reference found",
                remediation="Disable external DTD loading in XML parser configuration",
                cwe="CWE-611",
            ))
        return findings

    def _check_robots_sensitive(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — robots.txt reveals sensitive paths."""
        findings = []
        if not url.rstrip("/").endswith("/robots.txt"):
            return findings
        if not body:
            return findings
        sensitive = [
            r"/admin", r"/backup", r"/config", r"/database", r"/debug",
            r"/deploy", r"/internal", r"/private", r"/secret", r"/staging",
            r"/test", r"/tmp", r"\.git", r"\.env", r"\.sql", r"/api/",
            r"/console", r"/phpmyadmin", r"/wp-admin", r"/cpanel",
        ]
        found = []
        for line in body.splitlines():
            line_l = line.lower().strip()
            if not line_l.startswith(("disallow:", "allow:")):
                continue
            path = line_l.split(":", 1)[1].strip()
            for s in sensitive:
                if re.search(s, path, re.I):
                    found.append(path)
                    break
        if found:
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding=f"robots.txt reveals {len(found)} sensitive path(s)",
                severity="Info",
                evidence="; ".join(found[:5]),
                remediation="Review robots.txt — Disallow doesn't protect paths, it just advertises them",
                cwe="CWE-200",
            ))
        return findings

    def _check_aspnet_tracing(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — ASP.NET tracing/debugging endpoints exposed."""
        findings = []
        if not body:
            return findings
        sample = body[:16000]
        indicators = [
            (r"trace\.axd", "ASP.NET trace.axd tracing endpoint exposed"),
            (r"elmah\.axd", "ASP.NET ELMAH error log endpoint exposed"),
            (r"<customErrors\s+mode\s*=\s*[\"']Off[\"']", "ASP.NET customErrors disabled — verbose errors exposed"),
            (r"<compilation[^>]*debug\s*=\s*[\"']true[\"']", "ASP.NET compilation debug mode enabled"),
            (r"__VIEWSTATEGENERATOR", "ASP.NET ViewState generator ID exposed"),
        ]
        for pat, msg in indicators:
            if re.search(pat, sample, re.I):
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg, severity="Medium",
                    evidence=re.search(pat, sample, re.I).group(0)[:80],
                    remediation="Disable ASP.NET tracing and debug mode in production web.config",
                    cwe="CWE-215",
                ))
        return findings

    def _check_hsts_preload(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — HSTS header present but missing preload or includeSubDomains."""
        findings = []
        hsts = h.get("strict-transport-security", "")
        if not hsts:
            return findings
        hsts_l = hsts.lower()
        if "includesubdomains" not in hsts_l:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="HSTS header missing includeSubDomains — subdomains unprotected",
                severity="Low",
                evidence=f"Strict-Transport-Security: {hsts[:80]}",
                remediation="Add includeSubDomains to HSTS header",
                cwe="CWE-319",
            ))
        if "preload" not in hsts_l:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="HSTS header missing preload directive",
                severity="Info",
                evidence=f"Strict-Transport-Security: {hsts[:80]}",
                remediation="Add preload directive and submit to hstspreload.org",
                cwe="CWE-319",
            ))
        ma = re.search(r"max-age\s*=\s*(\d+)", hsts_l)
        if ma and int(ma.group(1)) < 15768000:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="HSTS max-age too low — should be at least 6 months",
                severity="Low",
                evidence=f"max-age={ma.group(1)} (< 15768000)",
                remediation="Set HSTS max-age to at least 31536000 (1 year)",
                cwe="CWE-319",
            ))
        return findings

    def _check_duplicate_cookies(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — Same cookie name set multiple times in response."""
        findings = []
        sc = h.get("set-cookie", "")
        if not sc:
            return findings
        cookies = [c.strip() for c in sc.split("\n") if c.strip()]
        if len(cookies) < 2:
            return findings
        names = []
        for c in cookies:
            name = c.split("=")[0].strip().lower()
            names.append(name)
        seen = {}
        for n in names:
            seen[n] = seen.get(n, 0) + 1
        dupes = [n for n, c in seen.items() if c > 1]
        if dupes:
            findings.append(PassiveFinding(
                url=url, category="cookie_security",
                finding=f"Cookie set multiple times: {', '.join(dupes[:3])} — inconsistent behavior risk",
                severity="Low",
                evidence=f"Duplicate Set-Cookie names: {', '.join(dupes[:3])}",
                remediation="Set each cookie name only once per response",
                cwe="CWE-436",
            ))
        return findings

    def _check_samesite_none_insecure(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — Cookie with SameSite=None but without Secure flag."""
        findings = []
        sc = h.get("set-cookie", "")
        if not sc:
            return findings
        for cookie in sc.split("\n"):
            cookie_l = cookie.lower()
            if "samesite=none" in cookie_l and "secure" not in cookie_l:
                name = cookie.split("=")[0].strip()
                findings.append(PassiveFinding(
                    url=url, category="cookie_security",
                    finding=f"Cookie '{name}' has SameSite=None without Secure flag",
                    severity="Medium",
                    evidence=cookie[:100],
                    remediation="Cookies with SameSite=None must also have the Secure flag",
                    cwe="CWE-614",
                ))
                break
        return findings

    def _check_cross_domain_form(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — Form submits data to a different domain."""
        findings = []
        if not body:
            return findings
        parsed = urlparse(url)
        our_domain = parsed.netloc.lower()
        forms = re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\'][^>]*>', body[:32000], re.I)
        for action in forms:
            if action.startswith(("http://", "https://")):
                action_domain = urlparse(action).netloc.lower()
                if action_domain and action_domain != our_domain:
                    findings.append(PassiveFinding(
                        url=url, category="form_security",
                        finding=f"Form submits to external domain: {action_domain}",
                        severity="Medium",
                        evidence=f"action='{action[:100]}'",
                        remediation="Verify cross-domain form submissions are intentional — possible data exfiltration",
                        cwe="CWE-352",
                    ))
                    break
        return findings

    def _check_hidden_form_fields(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — Hidden form fields with sensitive names (debug, admin, role, price)."""
        findings = []
        if not body:
            return findings
        hidden = re.findall(
            r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
            body[:32000], re.I,
        )
        hidden += re.findall(
            r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*type\s*=\s*["\']hidden["\'][^>]*>',
            body[:32000], re.I,
        )
        sensitive_names = re.compile(
            r"(?:debug|admin|role|is_?admin|price|discount|privilege|access_?level|"
            r"user_?type|permission|secret|token|internal)", re.I
        )
        flagged = set()
        for name in hidden:
            if sensitive_names.search(name) and name.lower() not in flagged:
                flagged.add(name.lower())
        if flagged:
            findings.append(PassiveFinding(
                url=url, category="attack_surface",
                finding=f"Hidden field(s) with sensitive names: {', '.join(sorted(flagged)[:4])}",
                severity="Low",
                evidence=f"Names: {', '.join(sorted(flagged)[:4])}",
                remediation="Validate hidden field values server-side — they are user-controllable",
                cwe="CWE-472",
            ))
        return findings

    def _check_login_form_detected(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp informational — Login/authentication form detected."""
        findings = []
        if not body:
            return findings
        if re.search(r'type\s*=\s*["\']password["\']', body[:32000], re.I):
            login_signals = re.search(
                r'(?:login|log.in|sign.in|auth|credential|username|email.*password)',
                body[:32000], re.I,
            )
            if login_signals:
                findings.append(PassiveFinding(
                    url=url, category="attack_surface",
                    finding="Login/authentication form detected on this page",
                    severity="Info",
                    evidence="Password input with login-related content found",
                    remediation="Ensure login form has rate limiting, CAPTCHA, and account lockout",
                    cwe="CWE-307",
                ))
        return findings

    def _check_captcha_absence(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — Login form without CAPTCHA or rate-limit indication."""
        findings = []
        if not body:
            return findings
        sample = body[:32000]
        has_pw = re.search(r'type\s*=\s*["\']password["\']', sample, re.I)
        if not has_pw:
            return findings
        has_captcha = re.search(
            r'(?:captcha|recaptcha|hcaptcha|turnstile|g-recaptcha|cf-turnstile|arkose)',
            sample, re.I,
        )
        if not has_captcha:
            findings.append(PassiveFinding(
                url=url, category="form_security",
                finding="Login form without CAPTCHA — brute force may be feasible",
                severity="Low",
                evidence="Password field found, no CAPTCHA elements detected",
                remediation="Add CAPTCHA or implement rate limiting and account lockout",
                cwe="CWE-307",
            ))
        return findings

    def _check_sensitive_html_comments(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp 615 — HTML comments containing passwords, secrets, credentials."""
        findings = []
        if not body:
            return findings
        comments = re.findall(r'<!--([\s\S]*?)-->', body[:32000])
        sensitive = re.compile(
            r"(?:password|secret|credential|api.?key|token|private.?key|"
            r"connection.?string|db_?pass|mysql|postgres|mongodb://)", re.I
        )
        for comment in comments[:20]:
            if sensitive.search(comment):
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding="HTML comment contains potentially sensitive content",
                    severity="Medium",
                    evidence=f"<!--{comment[:100]}-->",
                    remediation="Remove comments containing credentials or sensitive information",
                    cwe="CWE-615",
                ))
                break
        return findings

    def _check_cors_preflight_cache(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — Access-Control-Max-Age set excessively high."""
        findings = []
        max_age = h.get("access-control-max-age", "")
        if not max_age:
            return findings
        try:
            val = int(max_age.strip())
            if val > 86400:
                findings.append(PassiveFinding(
                    url=url, category="cors",
                    finding=f"CORS preflight cache too long ({val}s) — stale policy risk",
                    severity="Low",
                    evidence=f"Access-Control-Max-Age: {val} (> 86400s / 24h)",
                    remediation="Set Access-Control-Max-Age to 86400 or less",
                    cwe="CWE-346",
                ))
        except ValueError:
            pass
        return findings

    def _check_xss_protection_disabled(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — X-XSS-Protection explicitly disabled with value 0."""
        findings = []
        xss = h.get("x-xss-protection", "")
        if xss.strip() == "0":
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="X-XSS-Protection explicitly disabled (set to 0)",
                severity="Low",
                evidence="X-XSS-Protection: 0",
                remediation="Remove the header or set to '1; mode=block' if CSP is not in use",
                cwe="CWE-79",
            ))
        return findings

    def _check_etag_inode_leak(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — Apache ETag leaking inode number."""
        findings = []
        etag = h.get("etag", "")
        if not etag:
            return findings
        m = re.match(r'"([0-9a-f]+)-([0-9a-f]+)-([0-9a-f]+)"', etag, re.I)
        if m:
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="ETag header leaks inode number (Apache default format)",
                severity="Low",
                evidence=f"ETag: {etag}",
                remediation="Configure Apache: FileETag MTime Size (remove inode component)",
                cwe="CWE-200",
            ))
        return findings

    def _check_insecure_redirect_chain(self, url: str, h: dict, status_code: int) -> list[PassiveFinding]:
        """Burp — HTTP redirect to HTTP (not upgrading to HTTPS)."""
        findings = []
        if status_code not in (301, 302, 303, 307, 308):
            return findings
        location = h.get("location", "")
        if url.startswith("http://") and location.startswith("http://"):
            findings.append(PassiveFinding(
                url=url, category="protocol_issue",
                finding="HTTP redirect stays on HTTP — not upgrading to HTTPS",
                severity="Medium",
                evidence=f"Location: {location[:100]}",
                remediation="Redirect HTTP traffic to HTTPS",
                cwe="CWE-319",
            ))
        return findings

    def _check_wsdl_exposure(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — WSDL/WADL service descriptor exposed."""
        findings = []
        if not body:
            return findings
        sample = body[:16000]
        if re.search(r'<(?:wsdl:)?definitions\b', sample, re.I):
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="WSDL service descriptor exposed — reveals internal API structure",
                severity="Medium",
                evidence="WSDL definitions element found in response",
                remediation="Restrict access to WSDL files — do not expose on public endpoints",
                cwe="CWE-200",
            ))
        elif re.search(r'<(?:wadl:)?application\b.*xmlns.*wadl', sample, re.I):
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="WADL service descriptor exposed — reveals REST API structure",
                severity="Medium",
                evidence="WADL application element found in response",
                remediation="Restrict access to WADL files",
                cwe="CWE-200",
            ))
        return findings

    def _check_webmanifest_exposure(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp informational — Web manifest may reveal app internals."""
        findings = []
        if not (url.endswith("manifest.json") or url.endswith(".webmanifest")):
            return findings
        if not body:
            return findings
        if re.search(r'"start_url"|"name"|"scope"', body[:8000]):
            scope = re.search(r'"scope"\s*:\s*"([^"]+)"', body)
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="Web app manifest exposed — reveals application structure and scope",
                severity="Info",
                evidence=f"scope: {scope.group(1)[:60]}" if scope else "manifest.json found",
                remediation="Ensure manifest does not expose sensitive internal paths",
                cwe="CWE-200",
            ))
        return findings

    def _check_strict_transport_gaps(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — HTTPS response missing HSTS (different from _REQUIRED_HEADERS which checks all pages)."""
        findings = []
        if not url.startswith("https://"):
            return findings
        if "strict-transport-security" not in h:
            ct = h.get("content-type", "")
            if "text/html" in ct:
                findings.append(PassiveFinding(
                    url=url, category="security_header",
                    finding="HTTPS page missing HSTS header — downgrade attack possible",
                    severity="Medium",
                    evidence="HTTPS response without Strict-Transport-Security",
                    remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    cwe="CWE-319",
                ))
        return findings

    def _check_cookie_without_expiry(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — Persistent-looking cookie without Expires/Max-Age (session-scoped)."""
        findings = []
        sc = h.get("set-cookie", "")
        if not sc:
            return findings
        for cookie in sc.split("\n"):
            cookie_l = cookie.lower()
            name = cookie.split("=")[0].strip()
            is_session_like = re.search(r"(?:sess|token|auth|jwt|sid|login)", name, re.I)
            has_expiry = "expires=" in cookie_l or "max-age=" in cookie_l
            if is_session_like and not has_expiry:
                findings.append(PassiveFinding(
                    url=url, category="cookie_security",
                    finding=f"Session cookie '{name}' has no explicit expiry — persists until browser close",
                    severity="Info",
                    evidence=cookie[:100],
                    remediation="Set explicit Max-Age or Expires for session cookies for predictable lifecycle",
                    cwe="CWE-613",
                ))
                break
        return findings

    def _check_multiple_csp(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — Multiple Content-Security-Policy headers (intersection may weaken policy)."""
        findings = []
        csp = h.get("content-security-policy", "")
        if not csp:
            return findings
        # Multiple CSP headers get concatenated with commas in some libraries
        if csp.count("default-src") > 1 or csp.count("script-src") > 1:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="Multiple CSP policies detected — browser intersects them, possibly weakening protection",
                severity="Low",
                evidence=f"CSP contains {csp.count('default-src')} default-src directives",
                remediation="Consolidate into a single Content-Security-Policy header",
                cwe="CWE-693",
            ))
        return findings

    def _check_csp_unsafe(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp 1020 — CSP with unsafe-inline or unsafe-eval weakens XSS protection."""
        findings = []
        csp = h.get("content-security-policy", "")
        if not csp:
            return findings
        if "'unsafe-inline'" in csp and "script-src" in csp:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="CSP allows unsafe-inline in script-src — XSS protection weakened",
                severity="Medium",
                evidence="script-src contains 'unsafe-inline'",
                remediation="Replace unsafe-inline with nonce or hash-based CSP",
                cwe="CWE-79",
            ))
        if "'unsafe-eval'" in csp:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="CSP allows unsafe-eval — eval() and similar functions permitted",
                severity="Medium",
                evidence="CSP contains 'unsafe-eval'",
                remediation="Remove unsafe-eval and refactor code to avoid eval()",
                cwe="CWE-79",
            ))
        return findings

    def _check_wildcard_csp(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — CSP with wildcard source effectively disables protection."""
        findings = []
        csp = h.get("content-security-policy", "")
        if not csp:
            return findings
        directives = re.findall(r'((?:script|object|base-uri|frame)-src)\s+[^;]*\*', csp)
        if directives:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding=f"CSP uses wildcard (*) in {', '.join(list(set(directives))[:3])} — protection bypassed",
                severity="Medium",
                evidence=f"Wildcard in: {', '.join(list(set(directives))[:3])}",
                remediation="Replace wildcard with explicit allowed origins",
                cwe="CWE-693",
            ))
        return findings

    def _check_html_base_tag(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — <base> tag can hijack relative URLs if attacker-controlled."""
        findings = []
        if not body:
            return findings
        base = re.search(r'<base\s+[^>]*href\s*=\s*["\']([^"\']+)["\']', body[:8000], re.I)
        if base:
            parsed = urlparse(url)
            base_parsed = urlparse(base.group(1))
            if base_parsed.netloc and base_parsed.netloc.lower() != parsed.netloc.lower():
                findings.append(PassiveFinding(
                    url=url, category="html_security",
                    finding=f"HTML <base> tag points to external domain: {base_parsed.netloc}",
                    severity="High",
                    evidence=f"<base href='{base.group(1)[:80]}'>",
                    remediation="Ensure <base> href points to the same origin or remove it",
                    cwe="CWE-79",
                ))
        return findings

    def _check_open_api_spec(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — OpenAPI/Swagger specification exposed."""
        findings = []
        if not body:
            return findings
        sample = body[:8000]
        if re.search(r'"(?:openapi|swagger)"\s*:\s*"[23]\.\d', sample):
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="OpenAPI/Swagger specification exposed — reveals full API structure",
                severity="Medium",
                evidence="OpenAPI/Swagger JSON spec detected",
                remediation="Restrict access to API specs in production",
                cwe="CWE-200",
            ))
        elif re.search(r'(?:openapi|swagger):\s*["\']?[23]\.\d', sample):
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="OpenAPI/Swagger YAML specification exposed",
                severity="Medium",
                evidence="OpenAPI/Swagger YAML spec detected",
                remediation="Restrict access to API specs in production",
                cwe="CWE-200",
            ))
        return findings

    def _check_graphql_introspection(self, url: str, body: str) -> list[PassiveFinding]:
        """Burp — GraphQL introspection enabled (schema visible)."""
        findings = []
        if not body:
            return findings
        if '"__schema"' in body[:16000] and '"types"' in body[:16000]:
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="GraphQL introspection enabled — full schema exposed",
                severity="Medium",
                evidence="__schema and types found in response",
                remediation="Disable GraphQL introspection in production",
                cwe="CWE-200",
            ))
        return findings

    def _check_sourcemap_url(self, url: str, body: str, h: dict) -> list[PassiveFinding]:
        """Burp — SourceMappingURL or X-SourceMap header pointing to .map file."""
        findings = []
        sm_header = h.get("sourcemap", h.get("x-sourcemap", ""))
        if sm_header:
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="SourceMap header exposes source map file URL",
                severity="Low",
                evidence=f"SourceMap: {sm_header[:80]}",
                remediation="Remove SourceMap headers in production",
                cwe="CWE-540",
            ))
        if body and re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)', body[-2000:]):
            m = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)', body[-2000:])
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="JavaScript source map reference found — original source recoverable",
                severity="Low",
                evidence=f"sourceMappingURL={m.group(1)[:60]}",
                remediation="Remove sourceMappingURL comments in production builds",
                cwe="CWE-540",
            ))
        return findings

    def _check_acao_null(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — Access-Control-Allow-Origin set to null (bypassable)."""
        findings = []
        acao = h.get("access-control-allow-origin", "")
        if acao.strip().lower() == "null":
            findings.append(PassiveFinding(
                url=url, category="cors",
                finding="CORS Access-Control-Allow-Origin set to 'null' — bypassable via sandboxed iframe",
                severity="Medium",
                evidence="Access-Control-Allow-Origin: null",
                remediation="Use specific origin values instead of 'null'",
                cwe="CWE-346",
            ))
        return findings

    def _check_csp_report_only(self, url: str, h: dict) -> list[PassiveFinding]:
        """Burp — CSP in report-only mode does not enforce protections."""
        findings = []
        if "content-security-policy-report-only" in h and "content-security-policy" not in h:
            findings.append(PassiveFinding(
                url=url, category="security_header",
                finding="CSP is report-only with no enforcing policy — XSS protection not active",
                severity="Medium",
                evidence="Content-Security-Policy-Report-Only present, no enforcing CSP",
                remediation="Deploy an enforcing Content-Security-Policy header alongside report-only",
                cwe="CWE-693",
            ))
        return findings

    # ── ZAP full-parity rules (12 additional passive checks) ─────────────────

    def _check_user_controllable_charset(self, url: str, body: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10030 — URL parameter value reflected in charset declaration."""
        findings: list[PassiveFinding] = []
        if not body:
            return findings
        parsed = urlparse(url)
        if not parsed.query:
            return findings
        params = parse_qs(parsed.query, keep_blank_values=True)
        meta_charset = re.search(r'<meta[^>]+charset=["\']?([^"\';\s>]+)', body, re.IGNORECASE)
        ct_meta = re.search(r'<meta[^>]+content=["\'][^"\']*charset=([^"\';\s>]+)', body, re.IGNORECASE)
        charset_val = (meta_charset.group(1) if meta_charset else None) or (ct_meta.group(1) if ct_meta else None)
        if not charset_val:
            return findings
        for param_name, values in params.items():
            for val in values:
                if len(val) >= 3 and val.lower() in charset_val.lower():
                    findings.append(PassiveFinding(
                        url=url, category="info_disclosure",
                        finding=f"User-controllable charset — param '{param_name}' reflected in charset declaration",
                        severity="Medium",
                        evidence=f"Charset '{charset_val}' contains param value '{val[:30]}'",
                        remediation="Hard-code the charset declaration; never derive it from user input",
                        cwe="CWE-16",
                    ))
                    return findings
        return findings

    def _check_heartbleed(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10034 — OpenSSL HeartBleed (CVE-2014-0160) version in Server header."""
        server = h.get("server", "")
        if not server:
            return []
        # Vulnerable: OpenSSL 1.0.1 through 1.0.1f
        m = re.search(r'OpenSSL[/\s]+(1\.0\.1[a-f]?)(?:\b|$)', server, re.IGNORECASE)
        if m:
            return [PassiveFinding(
                url=url, category="info_disclosure",
                finding="HeartBleed — Server header indicates vulnerable OpenSSL version",
                severity="Critical",
                evidence=f"Server: {server.strip()} (CVE-2014-0160 affects OpenSSL 1.0.1–1.0.1f)",
                remediation="Upgrade OpenSSL to 1.0.1g or later. Revoke and reissue TLS certificates.",
                cwe="CWE-119",
            )]
        return []

    def _check_relative_path_confusion(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10051 — Relative path confusion in base href or form actions."""
        findings: list[PassiveFinding] = []
        if not body:
            return findings
        parsed = urlparse(url)
        path_depth = len([p for p in parsed.path.split("/") if p])
        # Check for missing or relative <base href> when URL has deep path
        base_tag = re.search(r'<base[^>]+href=["\']?([^"\'>\s]+)', body, re.IGNORECASE)
        if path_depth >= 2:
            if not base_tag:
                # No base tag on deep URL — relative paths may resolve incorrectly
                has_relative = re.search(r'(?:href|src|action)=["\'](?!https?://|//|#|mailto:|javascript:)([^"\'>\s]+)', body, re.IGNORECASE)
                if has_relative:
                    findings.append(PassiveFinding(
                        url=url, category="misconfiguration",
                        finding="Relative path confusion — deep URL path with relative resource references, no <base> tag",
                        severity="Low",
                        evidence=f"URL depth: {path_depth}, relative ref found: {has_relative.group(0)[:60]}",
                        remediation="Add <base href='/'>  or use absolute paths for all resource references",
                        cwe="CWE-20",
                    ))
            elif base_tag and not base_tag.group(1).startswith(("http", "/")):
                findings.append(PassiveFinding(
                    url=url, category="misconfiguration",
                    finding="Relative path confusion — <base href> uses relative path",
                    severity="Medium",
                    evidence=f"<base href='{base_tag.group(1)[:60]}'>",
                    remediation="Use an absolute URL for <base href>",
                    cwe="CWE-20",
                ))
        return findings

    def _check_username_hash_found(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10057 — Potential username/password hash patterns in response body."""
        if not body:
            return []
        # Look for standalone hex strings of hash lengths (MD5=32, SHA1=40, SHA256=64)
        # Only flag if they appear in structured data contexts (JSON, HTML values)
        hash_re = re.compile(r'(?:["\'=:\s])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?:["\',\s]|$)', re.IGNORECASE)
        m = hash_re.search(body[:8000])
        if m:
            hlen = len(m.group(1))
            algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(hlen, "hash")
            return [PassiveFinding(
                url=url, category="info_disclosure",
                finding=f"Potential {algo} hash found in response — may be credential hash",
                severity="Info",
                evidence=f"Hash value: {m.group(1)[:20]}... (length {hlen})",
                remediation="Ensure password hashes are never returned in API/HTML responses",
                cwe="CWE-200",
            )]
        return []

    def _check_get_for_post(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10058 — Sensitive HTML form using GET method exposes data in URL."""
        findings: list[PassiveFinding] = []
        if not body:
            return findings
        def _form_is_get(form_tag: str) -> bool:
            """
            True only when the form will actually submit as GET.
            - Explicit method="get" → always True
            - No method attribute + has action URL → True (HTML default is GET)
            - No method attribute + no action → False (JS-controlled form;
              React/Next.js/Vue forms handle submission via onSubmit/fetch and
              the method attribute is irrelevant — flagging these is a false positive)
            """
            tag_lower = form_tag.lower()
            if re.search(r'method=["\']?get["\']?', tag_lower):
                return True
            if 'method=' not in tag_lower:
                # Only flag if there's a real action URL (traditional HTML form)
                has_action = bool(re.search(r'action=["\'][^"\']+["\']', tag_lower))
                return has_action
            return False

        # Scan every form in the page body
        for form_match in re.finditer(r'(<form([^>]*)>)(.*?)</form>', body, re.IGNORECASE | re.DOTALL):
            form_tag   = form_match.group(1)
            form_attrs = form_match.group(2)
            form_body  = form_match.group(3)

            if not _form_is_get(form_tag):
                continue

            # Only flag forms that have a password input that would actually be submitted:
            # - must be type="password"
            # - must have a non-empty name= attribute (nameless fields are never sent)
            # - must not be disabled
            for input_match in re.finditer(r'<input([^>]+)>', form_body, re.IGNORECASE):
                attrs = input_match.group(1)
                is_password = re.search(r'type=["\']?password["\']?', attrs, re.IGNORECASE)
                if not is_password:
                    continue
                has_name = re.search(r'\bname=["\']([^"\'>\s]+)["\']?', attrs, re.IGNORECASE)
                is_disabled = re.search(r'\bdisabled\b', attrs, re.IGNORECASE)
                if has_name and not is_disabled:
                    findings.append(PassiveFinding(
                        url=url, category="security_header",
                        finding="Sensitive form uses GET method — password field exposed in URL",
                        severity="High",
                        evidence=f"{form_tag[:100]} contains <input type=password name={has_name.group(1)}>",
                        remediation="Use method='POST' for all forms with password fields",
                        cwe="CWE-319",
                    ))
                    break
            if findings:
                break

        return findings[:1]  # one finding per page is enough

    def _check_format_string_error(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10067 — Format string error patterns in response body."""
        if not body:
            return []
        # Raw format string artifacts that leaked into output
        patterns = [
            (r'%[0-9]*[sduoxXeEfgGp]', "printf-style format specifier"),
            (r'%%[nNpP]', "%%n/%%p format string RCE indicator"),
            (r'\{[0-9]+\}.*\{[0-9]+\}', "Python/Java positional format literal"),
        ]
        for pat, desc in patterns:
            m = re.search(pat, body[:4000])
            if m:
                # Context check — exclude CSS/JS template literals
                ctx = body[max(0, m.start()-20):m.end()+20]
                if any(skip in ctx for skip in ["content:", "font-", "rgb(", "var(", "calc("]):
                    continue
                return [PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Format string error — {desc} visible in response",
                    severity="Medium",
                    evidence=f"Pattern found: '{m.group(0)[:40]}' in context: '{ctx[:80]}'",
                    remediation="Never pass user input as format string argument. Use parameterized logging.",
                    cwe="CWE-134",
                )]
        return []

    def _check_saml_indicators(self, url: str, body: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10070 — SAML assertion/response detected in HTTP traffic."""
        findings: list[PassiveFinding] = []
        saml_patterns = [
            (r'SAMLResponse', "SAMLResponse parameter in URL/form"),
            (r'SAMLRequest', "SAMLRequest parameter in URL/form"),
            (r'<saml[p2]?:Assertion', "SAML Assertion XML element"),
            (r'<saml[p2]?:Response', "SAML Response XML element"),
            (r'urn:oasis:names:tc:SAML', "SAML namespace URI"),
        ]
        for pat, desc in saml_patterns:
            if re.search(pat, body[:16000], re.IGNORECASE):
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"SAML usage detected — {desc}",
                    severity="Info",
                    evidence=f"SAML indicator '{pat}' found in response",
                    remediation="Ensure SAML assertions are signed and encrypted. Validate XML signatures strictly.",
                    cwe="CWE-287",
                ))
                return findings  # one finding per page
        # Check RelayState in URL
        if "relaystate" in url.lower():
            findings.append(PassiveFinding(
                url=url, category="info_disclosure",
                finding="SAML usage detected — RelayState parameter in URL",
                severity="Info",
                evidence="RelayState parameter found in request URL",
                remediation="Validate RelayState against allowed values to prevent open redirect via SAML flow.",
                cwe="CWE-287",
            ))
        return findings

    def _check_backup_file_ref(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 10095 — References to backup files (.bak, .orig, .old, ~) in response."""
        if not body:
            return []
        backup_re = re.compile(
            r'(?:href|src|action|data-src)=["\']([^"\'>\s]+\.(?:bak|orig|old|backup|save|tmp|swp|copy)|\~[^"\'>\s]+)["\']',
            re.IGNORECASE,
        )
        m = backup_re.search(body[:16000])
        if m:
            return [PassiveFinding(
                url=url, category="info_disclosure",
                finding=f"Backup file reference found in page — source/config may be exposed",
                severity="Medium",
                evidence=f"Reference: {m.group(0)[:80]}",
                remediation="Remove all backup and temporary file references. Add backup extensions to server deny rules.",
                cwe="CWE-530",
            )]
        return []

    def _check_browser_storage_disclosure(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP 120000 — Sensitive data written to localStorage/sessionStorage."""
        if not body:
            return []
        _SENSITIVE_KEYS = re.compile(
            r'(?:local|session)Storage\.setItem\s*\(\s*["\']'
            r'(?:token|jwt|auth|password|passwd|secret|api[_-]?key|access[_-]?key|'
            r'session[_-]?id|bearer|credential|private[_-]?key)',
            re.IGNORECASE,
        )
        jwt_storage = re.compile(
            r'(?:local|session)Storage\.setItem\s*\([^)]*eyJ[A-Za-z0-9_-]+\.',
            re.IGNORECASE,
        )
        m = _SENSITIVE_KEYS.search(body[:16000]) or jwt_storage.search(body[:16000])
        if m:
            return [PassiveFinding(
                url=url, category="info_disclosure",
                finding="Sensitive data written to browser storage (localStorage/sessionStorage)",
                severity="Medium",
                evidence=f"Storage call: {m.group(0)[:80]}",
                remediation="Do not store tokens, passwords, or credentials in localStorage/sessionStorage. Use httpOnly cookies.",
                cwe="CWE-922",
            )]
        return []

    def _check_insecure_component_version(self, url: str, body: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10046 — Known-vulnerable library/framework version detected."""
        findings: list[PassiveFinding] = []
        # jQuery vulnerable versions (< 3.5.0 for XSS, <1.12.4 for many issues)
        jq = re.search(r'jquery[/-](\d+\.\d+\.\d+)', body[:32000], re.IGNORECASE)
        if jq:
            parts = [int(x) for x in jq.group(1).split(".")]
            if parts < [3, 5, 0]:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Known-vulnerable jQuery version {jq.group(1)} detected",
                    severity="High",
                    evidence=f"jQuery {jq.group(1)} — multiple XSS/prototype pollution CVEs below 3.5.0",
                    remediation="Upgrade jQuery to 3.5.0 or later",
                    cwe="CWE-1035",
                ))
        # Bootstrap vulnerable versions (< 4.6.2)
        bs = re.search(r'bootstrap[/-](\d+\.\d+\.\d+)', body[:32000], re.IGNORECASE)
        if bs:
            parts = [int(x) for x in bs.group(1).split(".")]
            if parts < [4, 6, 2]:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Known-vulnerable Bootstrap version {bs.group(1)} detected",
                    severity="Medium",
                    evidence=f"Bootstrap {bs.group(1)} — XSS CVEs below 4.6.2",
                    remediation="Upgrade Bootstrap to 4.6.2 or later",
                    cwe="CWE-1035",
                ))
        # AngularJS 1.x vulnerable (< 1.8.0 for XSS sandbox escapes)
        ng = re.search(r'angular(?:js)?[/-](\d+\.\d+\.\d+)', body[:32000], re.IGNORECASE)
        if ng:
            parts = [int(x) for x in ng.group(1).split(".")]
            if parts[0] == 1 and parts < [1, 8, 0]:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Known-vulnerable AngularJS version {ng.group(1)} detected",
                    severity="High",
                    evidence=f"AngularJS {ng.group(1)} — sandbox escape XSS CVEs below 1.8.0",
                    remediation="Upgrade AngularJS or migrate to Angular 2+",
                    cwe="CWE-1035",
                ))
        # Apache version check in headers
        server = h.get("server", "")
        apache_ver = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
        if apache_ver:
            parts = [int(x) for x in apache_ver.group(1).split(".")]
            if parts < [2, 4, 51]:
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Potentially vulnerable Apache version {apache_ver.group(1)} in Server header",
                    severity="High",
                    evidence=f"Server: {server.strip()}",
                    remediation="Upgrade Apache to latest stable version",
                    cwe="CWE-1035",
                ))
        return findings[:2]  # cap at 2 findings per page

    def _check_https_available_via_http(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10047 — HTTP URL with HSTS or upgrade headers indicates HTTPS is available."""
        parsed = urlparse(url)
        if parsed.scheme != "http":
            return []
        # HSTS on HTTP means server wants HTTPS but is also serving HTTP
        if h.get("strict-transport-security"):
            return [PassiveFinding(
                url=url, category="misconfiguration",
                finding="HTTPS available but content served over HTTP — HSTS header present on HTTP response",
                severity="Low",
                evidence=f"HSTS header '{h['strict-transport-security'][:80]}' on HTTP URL",
                remediation="Redirect all HTTP traffic to HTTPS (301). Do not serve content over HTTP.",
                cwe="CWE-319",
            )]
        # Upgrade-Insecure-Requests hint
        if "upgrade-insecure-requests" in h or h.get("content-security-policy", "").find("upgrade-insecure-requests") != -1:
            return [PassiveFinding(
                url=url, category="misconfiguration",
                finding="HTTPS upgrade policy present on HTTP response",
                severity="Low",
                evidence="upgrade-insecure-requests directive found on HTTP URL",
                remediation="Serve all content over HTTPS and set up HTTP→HTTPS redirect",
                cwe="CWE-319",
            )]
        return []

    def _check_apache_range_dos(self, url: str, h: dict) -> list[PassiveFinding]:
        """ZAP 10053 — Apache Range header DoS (CVE-2011-3192) via vulnerable version."""
        server = h.get("server", "")
        if not server:
            return []
        m = re.search(r'Apache/(\d+\.\d+(?:\.\d+)?)', server, re.IGNORECASE)
        if not m:
            return []
        try:
            parts = [int(x) for x in m.group(1).split(".")]
            # Vulnerable: Apache 1.x and Apache 2.0.x, 2.2.x before 2.2.21
            vulnerable = (
                parts[0] == 1 or
                (parts[0] == 2 and parts[1] == 0) or
                (parts[0] == 2 and parts[1] == 2 and (len(parts) < 3 or parts[2] < 21))
            )
            if vulnerable:
                return [PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=f"Apache {m.group(1)} may be vulnerable to Range header DoS (CVE-2011-3192)",
                    severity="High",
                    evidence=f"Server: {server.strip()} — CVE-2011-3192 affects Apache 2.0.x and 2.2.x < 2.2.21",
                    remediation="Upgrade Apache to 2.2.21+ or 2.4.x. Apply mod_headers to drop Range requests.",
                    cwe="CWE-400",
                )]
        except (ValueError, IndexError):
            pass
        return []

    # ── ZAP Client Side Integration passive rules ────────────────────────────

    def _check_postmessage_origin(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP Client Side — postMessage listener without origin validation."""
        if not body:
            return []
        # Find addEventListener('message' or 'onmessage' handlers
        listener = re.search(r'addEventListener\s*\(\s*["\']message["\']', body, re.IGNORECASE)
        on_message = re.search(r'\.onmessage\s*=', body)
        if not (listener or on_message):
            return []
        # Check if origin is validated
        has_origin_check = bool(re.search(
            r'event\.origin\s*[!=]=|e\.origin\s*[!=]=|message\.origin|allowedOrigins|trustedOrigins',
            body, re.IGNORECASE,
        ))
        if has_origin_check:
            return []
        evidence = (listener or on_message).group(0)
        return [PassiveFinding(
            url=url, category="xss",
            finding="postMessage listener without origin validation — cross-origin message injection risk",
            severity="Medium",
            evidence=f"Handler: '{evidence[:80]}' with no event.origin check found",
            remediation="Always validate event.origin against an allowlist before processing postMessage data.",
            cwe="CWE-346",
        )]

    def _check_dom_clobbering(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP Client Side — HTML id/name attributes that may clobber global JS variables."""
        if not body:
            return []
        # Look for id= or name= on form/input/anchor that shadow JS globals
        _CLOBBER_TARGETS = re.compile(
            r'<(?:a|form|input|img|object|embed)[^>]+(?:id|name)=["\']'
            r'(window|document|location|history|navigator|top|parent|self|frames|'
            r'alert|eval|fetch|XMLHttpRequest|prototype|constructor)["\']',
            re.IGNORECASE,
        )
        m = _CLOBBER_TARGETS.search(body[:16000])
        if m:
            return [PassiveFinding(
                url=url, category="xss",
                finding=f"DOM Clobbering — HTML element id/name '{m.group(1)}' shadows JS global",
                severity="Medium",
                evidence=f"Element: {m.group(0)[:80]}",
                remediation="Avoid using id/name attributes that match JavaScript global variable names.",
                cwe="CWE-79",
            )]
        return []

    def _check_js_prototype_pollution_sink(self, url: str, body: str) -> list[PassiveFinding]:
        """ZAP Client Side — merge/assign operations that may be prototype pollution sinks."""
        if not body:
            return []
        # Detect dangerous merge patterns that can propagate user-controlled keys
        _POLLUTION_SINKS = [
            (r'Object\.assign\s*\(\s*(?:\{\}|target|\w+)\s*,\s*(?:req|request|body|params|query|input|data|json)', "Object.assign with user input"),
            (r'_\.merge\s*\(', "Lodash _.merge (prototype pollution vector)"),
            (r'\$\.extend\s*\(\s*true', "jQuery $.extend(true, ...) deep merge"),
            (r'deepmerge\s*\(', "deepmerge library call"),
            (r'Object\.setPrototypeOf\s*\(', "Object.setPrototypeOf call"),
            (r'__proto__\s*[=:]', "__proto__ assignment"),
            (r'\[["\'`]constructor["\'`]\]\s*\[["\'`]prototype["\'`]\]', "constructor.prototype assignment"),
        ]
        for pat, desc in _POLLUTION_SINKS:
            m = re.search(pat, body[:16000], re.IGNORECASE)
            if m:
                return [PassiveFinding(
                    url=url, category="xss",
                    finding=f"Prototype pollution sink — {desc}",
                    severity="Medium",
                    evidence=f"Pattern: {m.group(0)[:80]}",
                    remediation="Use Object.create(null) for safe merge targets. Validate keys against allowlist before merging.",
                    cwe="CWE-1321",
                )]
        return []


# Global instance
    # ── Behavioral / identity passive checks ─────────────────────────────────

    def _check_referer_dependent_response(
        self, url: str, body: str, req_headers: dict
    ) -> list[PassiveFinding]:
        """
        Detect responses that differ based on the Referer header.
        A response that returns meaningful content only when a specific Referer
        is present may bypass direct-browsing protections.
        Fires when Referer was provided and response is non-empty with auth-sensitive patterns.
        """
        referer = req_headers.get("referer", req_headers.get("Referer", ""))
        if not referer or not body:
            return []
        # Heuristic: non-trivial response body AND referer-specific auth/session patterns
        sensitive = re.search(
            r'(?i)(session|token|credential|csrf|auth|admin|dashboard|account)', body
        )
        if sensitive and len(body) > 500:
            return [PassiveFinding(
                url=url, category="behavioral",
                finding="Referer-dependent response — server returns sensitive content only with specific Referer header",
                severity="Low",
                evidence=f"Referer: {referer[:120]} | Body contains '{sensitive.group()}'",
                remediation="Validate access control server-side, not via Referer. Referer header is spoofable.",
                cwe="CWE-807",
            )]
        return []

    def _check_spoofable_client_ip(
        self, url: str, body: str, req_headers: dict, resp_headers: dict
    ) -> list[PassiveFinding]:
        """
        Detect when X-Forwarded-For or similar IP-override headers are reflected or
        influence the response — indicates server trusts client-supplied IP headers.
        """
        spoof_headers = {
            "x-forwarded-for", "x-real-ip", "x-originating-ip",
            "x-remote-addr", "x-client-ip", "cf-connecting-ip",
            "true-client-ip", "forwarded",
        }
        present = [h for h in req_headers if h.lower() in spoof_headers]
        if not present:
            return []
        # Check if any spoofed IP value appears reflected in the response body
        findings = []
        for hdr in present:
            val = req_headers[hdr]
            if val and val in body:
                findings.append(PassiveFinding(
                    url=url, category="behavioral",
                    finding=f"Spoofable client IP — {hdr} value reflected in response body",
                    severity="Medium",
                    evidence=f"Header: {hdr}: {val[:60]} | Reflected in response body",
                    remediation="Never trust X-Forwarded-For for access control. Use network-level IP if needed.",
                    cwe="CWE-348",
                ))
                break
        return findings

    def _check_jwks_endpoint_disclosed(
        self, url: str, body: str, resp_headers: dict
    ) -> list[PassiveFinding]:
        """
        Detect exposed JWKS (JSON Web Key Set) endpoints.
        /.well-known/jwks.json or similar paths exposing public key material
        may enable algorithm confusion attacks if combined with JWT weaknesses.
        """
        # Match URL patterns for JWKS endpoints
        jwks_path = re.search(r'(?i)(jwks\.json|\.well-known/jwks|/oauth/jwks|/auth/jwks)', url)
        # Or body contains a JWKS structure
        jwks_body = re.search(r'"keys"\s*:\s*\[', body) if body else None

        if not (jwks_path or jwks_body):
            return []

        ct = resp_headers.get("content-type", "")
        if jwks_body and "json" not in ct and not jwks_path:
            return []

        return [PassiveFinding(
            url=url, category="info_disclosure",
            finding="JWKS endpoint disclosed — JSON Web Key Set exposed publicly",
            severity="Info",
            evidence=f"URL: {url} | {'JWKS structure in body' if jwks_body else 'JWKS path pattern matched'}",
            remediation="Ensure JWKS endpoint only exposes public keys. Verify it's intentionally public. "
                        "Monitor for private key material accidentally included.",
            cwe="CWE-200",
        )]

    def _check_jwt_private_key_disclosed(
        self, url: str, body: str
    ) -> list[PassiveFinding]:
        """
        Detect JWT private key material in HTTP responses.
        PEM-encoded private keys in responses indicate a critical secret exposure.
        """
        if not body:
            return []
        # PEM private key patterns
        pem_patterns = [
            r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
            r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
            r'"private_key"\s*:\s*"-----BEGIN',
            r'"privateKey"\s*:\s*"-----BEGIN',
        ]
        for pattern in pem_patterns:
            m = re.search(pattern, body)
            if m:
                return [PassiveFinding(
                    url=url, category="info_disclosure",
                    finding="JWT private key disclosed — PEM private key found in HTTP response",
                    severity="Critical",
                    evidence=f"Pattern matched: {m.group()[:80]}",
                    remediation="Immediately rotate all affected keys. Audit what data was encrypted/signed with "
                                "the exposed key. Remove private key material from all HTTP responses.",
                    cwe="CWE-321",
                )]
        return []

    def _check_useragent_dependent_response(
        self, url: str, body: str, req_headers: dict
    ) -> list[PassiveFinding]:
        """
        Detect when the User-Agent header influences response content in a
        security-relevant way (e.g. skipping auth checks for known bots/scanners,
        or returning different content for specific UAs).
        Port of Burp's UserAgentDependentResponse passive check.
        """
        ua = req_headers.get("user-agent", req_headers.get("User-Agent", ""))
        if not ua or not body:
            return []
        # Flag if a scanner/bot UA is used and response reveals admin/internal content
        bot_ua = re.search(
            r'(?i)(googlebot|bingbot|slurp|wget|python-requests|go-http|curl/|scanner|nuclei|burp)',
            ua
        )
        if not bot_ua:
            return []
        sensitive = re.search(
            r'(?i)(admin|internal|debug|config|env\b|secret|credential|password)', body
        )
        if sensitive:
            return [PassiveFinding(
                url=url, category="behavioral",
                finding=f"User-Agent-dependent response — server returns sensitive content to bot/scanner UA '{bot_ua.group()}'",
                severity="Medium",
                evidence=f"UA: {ua[:80]} | Body contains '{sensitive.group()}'",
                remediation="Apply consistent access controls regardless of User-Agent. "
                            "Never use UA as a security gate.",
                cwe="CWE-807",
            )]
        return []


passive_scanner = PassiveScanner()


# ── Intercept Session — passive rules on EVERY HTTP response ─────────────────

import threading
from urllib.parse import urlparse
import requests


class PassiveInterceptSession(requests.Session):
    """Drop-in requests.Session replacement that runs passive rules on every response.

    Use this instead of raw requests.Session so every HTTP response — from
    crawl, fuzz, forced browse, or any other module — is automatically
    analyzed by the passive scanner.  Findings are deduplicated and stored
    in a thread-safe list.

    Also feeds all traffic into a TrafficLog for full visibility (ZAP parity).
    """

    def __init__(self, scanner: PassiveScanner | None = None, traffic_log=None, **kwargs):
        super().__init__(**kwargs)
        self._scanner = scanner or passive_scanner
        self._findings: list[PassiveFinding] = []
        self._seen: set[tuple[str, str, str]] = set()   # (path, category, finding)
        self._lock = threading.Lock()
        self._traffic_log = traffic_log  # modules.traffic.TrafficLog or None

    # -- override the single gateway all verbs route through --
    def request(self, method, url, **kwargs):
        import time as _time
        _start = _time.time()
        resp = super().request(method, url, **kwargs)
        _elapsed = (_time.time() - _start) * 1000  # ms
        try:
            self._passive_scan(url, resp)
        except Exception:
            pass  # never interfere with the caller
        try:
            self._log_traffic(method, url, resp, _elapsed, kwargs)
        except Exception:
            pass  # never interfere
        return resp

    def _passive_scan(self, url: str, resp) -> None:
        body = ""
        try:
            body = resp.text[:8000]
        except Exception:
            pass

        results = self._scanner.scan(
            url=url,
            status_code=resp.status_code,
            resp_headers=dict(resp.headers),
            resp_body=body,
            cookies={c.name: c.value for c in self.cookies},
            request_headers=dict(self.headers),
        )

        if not results:
            return

        path = urlparse(url).path
        with self._lock:
            for f in results:
                key = (path, f.category, f.finding)
                if key not in self._seen:
                    self._seen.add(key)
                    self._findings.append(f)

    def _log_traffic(self, method, url, resp, elapsed_ms, kwargs) -> None:
        """Feed exchange into TrafficLog for full traffic visibility."""
        if not self._traffic_log:
            return

        # Extract request body from kwargs
        req_body = ""
        if "data" in kwargs and kwargs["data"]:
            req_body = str(kwargs["data"])[:16384]
        elif "json" in kwargs and kwargs["json"]:
            import json as _json
            req_body = _json.dumps(kwargs["json"])[:16384]

        content_type = resp.headers.get("Content-Type", "")
        content_length = int(resp.headers.get("Content-Length", 0))

        resp_body = ""
        try:
            resp_body = resp.text[:32768]
        except Exception:
            pass

        self._traffic_log.record(
            method=method,
            url=url,
            status_code=resp.status_code,
            request_headers=dict(self.headers),
            request_body=req_body,
            response_headers=dict(resp.headers),
            response_body=resp_body,
            content_type=content_type,
            content_length=content_length,
            elapsed_ms=elapsed_ms,
            source="session",
        )

    # -- public API --
    def get_findings(self) -> list[PassiveFinding]:
        """Return all deduplicated passive findings collected so far."""
        with self._lock:
            return list(self._findings)

    def get_findings_dicts(self) -> list[dict]:
        """Return findings as dicts (ready for JSON serialization)."""
        with self._lock:
            return [f.to_dict() for f in self._findings]

    def clear_findings(self) -> None:
        """Reset collected findings."""
        with self._lock:
            self._findings.clear()
            self._seen.clear()


# ── Response Variation Analyzer ────────────────────────────────────────────────
#
# Port of Burp Suite's Montoya API:
#   api/montoya/http/message/responses/analysis/
#       ResponseVariationsAnalyzer   → ResponseVariationAnalyzer
#       ResponseKeywordsAnalyzer     → ResponseKeywordsAnalyzer
#
# Unlike PassiveScanner (which inspects a single response for static patterns),
# these classes compare a PROBED response against a BASELINE population to
# detect blind injections — SQLi, SSRF, SSTI — without relying on error strings.
# ──────────────────────────────────────────────────────────────────────────────


# ── Header names that change on every request — excluded from variation scoring

_NOISE_HEADERS: frozenset[str] = frozenset([
    "date", "age", "etag", "last-modified", "expires",
    "x-request-id", "x-trace-id", "x-correlation-id", "x-request-start",
    "cf-ray", "x-amz-request-id", "x-amzn-requestid", "x-amzn-trace-id",
    "nel", "report-to",
])


@dataclass
class ResponseVariation:
    """
    Structural diff between a probed response and a baseline population.

    All fields are populated by ResponseVariationAnalyzer.compare().
    Consumers should test has_significant_variation first, then read
    significant_variations for a human-readable list of what changed.
    """
    # Body length
    body_delta_bytes:       float           # probed_len − baseline_mean
    body_length_ratio:      float           # probed_len / baseline_mean
    body_threshold:         float           # dynamic significance threshold
    baseline_mean_len:      float
    baseline_std_len:       float

    # Status code
    status_changed:         bool
    baseline_status:        int
    probed_status:          int

    # Timing
    timing_delta_ms:        float           # probed − baseline_mean (ms)
    baseline_mean_timing_ms: float

    # Header changes (noise-filtered)
    new_headers:            list[str] = field(default_factory=list)
    missing_headers:        list[str] = field(default_factory=list)
    changed_headers:        list[str] = field(default_factory=list)

    # Content-type
    content_type_changed:   bool = False

    # Input reflection
    reflection_found:       bool = False

    # Human-readable list of significant differences
    significant_variations: list[str] = field(default_factory=list)

    @property
    def has_significant_variation(self) -> bool:
        """True when at least one attribute differs beyond its significance threshold."""
        return len(self.significant_variations) > 0

    def summary(self) -> str:
        """One-line human-readable description for findings and logs."""
        if not self.significant_variations:
            return "no significant variation detected"
        return "; ".join(self.significant_variations)


class ResponseVariationAnalyzer:
    """
    Structural comparison of HTTP responses for blind injection detection.

    Port of Burp Suite's ResponseVariationsAnalyzer.

    Collects a population of baseline responses to model natural page variance,
    then compares a probed (attack) response against that baseline across five
    independent attributes: body length, status code, response timing, HTTP
    headers, and Content-Type.  None of these require error strings in the body.

    Body-length significance uses the same statistical model as the fuzzer's
    boolean-blind SQLi detector: threshold = max(3σ, 5% of mean, 20 bytes).
    This eliminates false positives from dynamic pages (ad banners, CSRF tokens,
    timestamps) while catching genuine data-conditional length changes.

    Usage::

        analyzer = ResponseVariationAnalyzer(timing_threshold_ms=3000.0)
        for resp, t in baseline_samples:
            analyzer.add_baseline(resp, elapsed_ms=t)

        variation = analyzer.compare(attack_resp, elapsed_ms=4800.0,
                                     injected_input="' OR 1=1--")
        if variation.has_significant_variation:
            report(f"Blind injection candidate: {variation.summary()}")
    """

    def __init__(self, timing_threshold_ms: float = 3000.0):
        """
        Args:
            timing_threshold_ms: Minimum timing delta (ms) above baseline mean
                                  to flag as significant.  Default 3000 ms matches
                                  the SLEEP(3) / pg_sleep(3) convention.
        """
        self._baselines: list[dict] = []
        self._timing_threshold_ms = timing_threshold_ms

    # ── Baseline collection ───────────────────────────────────────────────────

    def add_baseline(self, resp, elapsed_ms: float = 0.0) -> None:
        """
        Record one baseline response.

        Call at least 3 times before compare() for statistically meaningful
        results.  5 baselines (matching the fuzzer's boolean-blind model) are
        recommended.

        Args:
            resp:        requests.Response (or duck-typed with .status_code,
                         .text, .headers)
            elapsed_ms:  round-trip time in milliseconds for this response
        """
        self._baselines.append({
            "status":       resp.status_code,
            "body_len":     len(resp.text),
            "headers":      {k.lower(): v for k, v in resp.headers.items()},
            "content_type": resp.headers.get("Content-Type", ""),
            "elapsed_ms":   elapsed_ms,
        })

    def baseline_count(self) -> int:
        return len(self._baselines)

    def reset(self) -> None:
        """Clear all recorded baselines."""
        self._baselines.clear()

    # ── Comparison ────────────────────────────────────────────────────────────

    def compare(
        self,
        probed_resp,
        elapsed_ms:     float = 0.0,
        injected_input: str   = "",
    ) -> ResponseVariation:
        """
        Compare *probed_resp* against the collected baseline population.

        Args:
            probed_resp:     The response to the attack/probe request.
            elapsed_ms:      Round-trip time in milliseconds for the probe.
            injected_input:  The payload that was injected (used for reflection
                             detection; safe to omit).

        Returns:
            ResponseVariation with has_significant_variation=True when the
            probed response diverges meaningfully from baseline.

        Raises:
            ValueError: if no baselines have been recorded.
        """
        if not self._baselines:
            raise ValueError(
                "No baselines recorded — call add_baseline() at least once before compare()"
            )

        # ── Body-length statistics ────────────────────────────────────────────
        b_lengths = [b["body_len"] for b in self._baselines]
        mean_len  = sum(b_lengths) / len(b_lengths)
        variance  = sum((x - mean_len) ** 2 for x in b_lengths) / len(b_lengths)
        std_len   = math.sqrt(variance) if variance > 0 else 0.0
        # Significance threshold: 3σ, 5% of mean, or 20 bytes (whichever is largest).
        # The 20-byte floor prevents flagging on tiny pages where 5% is noise-level.
        body_threshold = max(3.0 * std_len, mean_len * 0.05, 20.0)

        probed_len  = len(probed_resp.text)
        body_delta  = probed_len - mean_len

        # ── Timing statistics ─────────────────────────────────────────────────
        b_timings       = [b["elapsed_ms"] for b in self._baselines]
        mean_timing     = sum(b_timings) / len(b_timings) if b_timings else 0.0
        timing_delta    = elapsed_ms - mean_timing

        # ── Status code ───────────────────────────────────────────────────────
        b_statuses      = [b["status"] for b in self._baselines]
        # Use the mode (most common) for stable comparison; mean can be fractional
        baseline_status = max(set(b_statuses), key=b_statuses.count)
        status_changed  = probed_resp.status_code != baseline_status

        # ── Header analysis ───────────────────────────────────────────────────
        # Union of all header names seen in baseline (robust against per-request variability)
        baseline_header_names: set[str] = set()
        for b in self._baselines:
            baseline_header_names.update(b["headers"].keys())

        probed_headers = {k.lower(): v for k, v in probed_resp.headers.items()}

        raw_new     = [h for h in probed_headers if h not in baseline_header_names]
        raw_missing = [h for h in baseline_header_names if h not in probed_headers]

        # Changed header values: present in both, different values
        baseline_last = self._baselines[-1]["headers"]
        changed = [
            h for h in probed_headers
            if h in baseline_last and probed_headers[h] != baseline_last[h]
            and h not in _NOISE_HEADERS
        ]

        # Filter noise headers out of new/missing
        new_headers     = [h for h in raw_new     if h not in _NOISE_HEADERS]
        missing_headers = [h for h in raw_missing if h not in _NOISE_HEADERS]

        # ── Content-Type ──────────────────────────────────────────────────────
        baseline_ct = self._baselines[0]["content_type"].split(";")[0].strip().lower()
        probed_ct   = probed_resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        ct_changed  = baseline_ct != probed_ct

        # ── Input reflection ──────────────────────────────────────────────────
        reflection = bool(
            injected_input
            and len(injected_input) >= 4
            and injected_input in probed_resp.text
        )

        # ── Significance scoring ──────────────────────────────────────────────
        significant: list[str] = []

        if abs(body_delta) > body_threshold:
            significant.append(
                f"body_length delta={body_delta:+.0f}B "
                f"(threshold={body_threshold:.0f}B, "
                f"baseline mean={mean_len:.0f}B σ={std_len:.1f}B)"
            )

        if status_changed:
            significant.append(
                f"status_code {baseline_status}→{probed_resp.status_code}"
            )

        if timing_delta > self._timing_threshold_ms:
            significant.append(
                f"timing delta={timing_delta:+.0f}ms "
                f"(baseline mean={mean_timing:.0f}ms, "
                f"threshold={self._timing_threshold_ms:.0f}ms)"
            )

        if ct_changed:
            significant.append(f"content_type {baseline_ct!r}→{probed_ct!r}")

        if new_headers:
            significant.append(f"new_headers={new_headers}")

        if missing_headers:
            significant.append(f"missing_headers={missing_headers}")

        return ResponseVariation(
            body_delta_bytes        = body_delta,
            body_length_ratio       = probed_len / max(mean_len, 1.0),
            body_threshold          = body_threshold,
            baseline_mean_len       = mean_len,
            baseline_std_len        = std_len,
            status_changed          = status_changed,
            baseline_status         = baseline_status,
            probed_status           = probed_resp.status_code,
            timing_delta_ms         = timing_delta,
            baseline_mean_timing_ms = mean_timing,
            new_headers             = new_headers,
            missing_headers         = missing_headers,
            changed_headers         = changed,
            content_type_changed    = ct_changed,
            reflection_found        = reflection,
            significant_variations  = significant,
        )


# ── Response Keywords Analyzer ────────────────────────────────────────────────

@dataclass
class KeywordMatch:
    """A single keyword hit returned by ResponseKeywordsAnalyzer."""
    category:   str   # "ssti_result", "blind_sqli", "reflection", "error_trace", "oob_indicator"
    keyword:    str   # the matched pattern or literal string
    evidence:   str   # up to 120 chars of surrounding context
    confidence: str   # "high", "medium", "low"


class ResponseKeywordsAnalyzer:
    """
    Port of Burp Suite's ResponseKeywordsAnalyzer.

    Inspects a response body and headers for keywords that confirm blind
    injection WITHOUT requiring full error messages.  Designed to be used
    alongside ResponseVariationAnalyzer: the variation analyzer detects THAT
    something changed; this class identifies WHAT changed.

    Key detection categories
    ────────────────────────
    ssti_result   — Template expression evaluated server-side (e.g. 7*7 → 49)
    reflection    — Injected input reflected verbatim in response
    error_trace   — Partial stack trace or exception class leaked in body
    blind_sqli    — Structural keyword that appears under true/false condition
    oob_indicator — Out-of-band callback confirmation keyword in body

    Usage::

        analyzer = ResponseKeywordsAnalyzer()
        matches = analyzer.analyze(
            probed_body=resp.text,
            probed_headers=dict(resp.headers),
            injected_input="{{7*7}}",
        )
        for m in matches:
            print(m.category, m.evidence)
    """

    # ── SSTI confirmation patterns ────────────────────────────────────────────
    # When {{7*7}}, ${7*7}, #{7*7} or <%=7*7%> is injected, the server-side
    # template engine evaluates the expression.  We look for the numeric result
    # in the response body regardless of the surrounding context.

    _SSTI_CONFIRMATIONS: list[tuple[re.Pattern, str]] = [
        # Standard math probes
        (re.compile(r'\b49\b'),         "{{7*7}} evaluated to 49 — SSTI confirmed"),
        (re.compile(r'\b7777777\b'),    "{{7*'7'}} evaluated to 7777777 — Python/Jinja2 SSTI"),
        (re.compile(r'\b(True|False)\b'), "Python boolean expression evaluated — SSTI possible"),
        # Twig / Smarty
        (re.compile(r'\bpasswd\b'),     "File read via SSTI expression (e.g. /etc/passwd)"),
        # FreeMarker
        (re.compile(r'Execute:\s*\d+'), "FreeMarker command execution output pattern"),
    ]

    # ── Partial error trace patterns ──────────────────────────────────────────
    # Short fragments that indicate an exception without a full stack trace.
    # Ordered from most specific (high confidence) to most generic (medium).

    _ERROR_TRACE_PATTERNS: list[tuple[re.Pattern, str, str]] = [
        # (pattern, label, confidence)
        (re.compile(r'at\s+[\w.$]+\([\w.]+\.(?:java|kt):\d+\)', re.I),
         "Java exception stack frame", "high"),
        (re.compile(r'File "[^"]+\.py", line \d+', re.I),
         "Python traceback fragment", "high"),
        (re.compile(r'in\s+<module>\s*$', re.M),
         "Python module-level exception context", "medium"),
        (re.compile(r'System\.Exception|NullReferenceException|ArgumentException', re.I),
         ".NET exception class name", "high"),
        (re.compile(r'PDOException|mysqli_error|ORA-\d{5}', re.I),
         "Database exception class/code", "high"),
        (re.compile(r'TemplateNotFound|UndefinedError|TemplateSyntaxError', re.I),
         "Template engine exception (potential SSTI probe site)", "high"),
        (re.compile(r'\bSyntaxError\b.*\bexpected\b', re.I),
         "Parser syntax error (injection may have broken expression)", "medium"),
        (re.compile(r'parse error.*line\s+\d+', re.I),
         "Parse error with line number", "medium"),
        (re.compile(r'eval\(\).*argument', re.I),
         "eval() argument error (code injection)", "high"),
    ]

    # ── Blind SQLi structural keywords ───────────────────────────────────────
    # Words that typically appear in the *true* branch response (logged-in
    # user data, admin panel links) but disappear in the *false* branch.
    # Used in differential mode: check if keyword is in probed but not baseline.

    _BLIND_SQLI_POSITIVE_KEYWORDS: frozenset[str] = frozenset([
        "welcome", "dashboard", "logout", "profile", "account",
        "admin", "administrator", "settings", "your account",
        "signed in", "logged in", "hello,", "hi,",
    ])

    # ── OOB callback confirmation keywords ───────────────────────────────────
    # These appear in DNS/HTTP callback responses from SSRF/XXE/Log4Shell OOB.

    _OOB_KEYWORDS: frozenset[str] = frozenset([
        "request received", "connection from", "callback received",
        "burpcollaborator", "oastify", "interact.sh",
        "canarytokens", "requestbin", "pipedream",
    ])

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(
        self,
        probed_body:    str,
        probed_headers: dict,
        injected_input: str = "",
        baseline_body:  str = "",
    ) -> list[KeywordMatch]:
        """
        Scan *probed_body* + *probed_headers* for blind injection indicators.

        Args:
            probed_body:    Response body of the attack request.
            probed_headers: Response headers (case-insensitive dict).
            injected_input: The payload that was injected (used for reflection
                            and SSTI result detection; safe to omit).
            baseline_body:  If provided, differential keyword matching is
                            enabled — keywords are flagged only when present
                            in probed but absent in baseline (or vice versa).

        Returns:
            List of KeywordMatch, empty when nothing is found.
        """
        matches: list[KeywordMatch] = []
        body_lower = probed_body.lower()

        # 1. SSTI evaluation result detection
        matches.extend(self._check_ssti_results(probed_body, injected_input))

        # 2. Partial error / exception trace detection
        matches.extend(self._check_error_traces(probed_body))

        # 3. Input reflection
        if injected_input and len(injected_input) >= 4:
            matches.extend(self._check_reflection(probed_body, injected_input))

        # 4. Blind SQLi structural keywords (differential)
        if baseline_body:
            matches.extend(
                self._check_blind_sqli_keywords(probed_body, baseline_body)
            )

        # 5. OOB callback indicators in body
        for kw in self._OOB_KEYWORDS:
            if kw in body_lower:
                ctx = self._context(probed_body, kw)
                matches.append(KeywordMatch(
                    category   = "oob_indicator",
                    keyword    = kw,
                    evidence   = ctx,
                    confidence = "high",
                ))

        return matches

    def analyze_pair(
        self,
        true_body:      str,
        false_body:     str,
        injected_true:  str = "",
        injected_false: str = "",
    ) -> list[KeywordMatch]:
        """
        Differential analysis for boolean-blind injection.

        Compares a TRUE-condition response body against a FALSE-condition body
        and returns keywords that distinguish them.  This is the keyword
        counterpart to ResponseVariationAnalyzer's length/status comparison.

        Returns keyword matches from true_body that are absent in false_body
        and vice versa.
        """
        matches: list[KeywordMatch] = []

        true_lower  = true_body.lower()
        false_lower = false_body.lower()

        for kw in self._BLIND_SQLI_POSITIVE_KEYWORDS:
            in_true  = kw in true_lower
            in_false = kw in false_lower
            if in_true and not in_false:
                matches.append(KeywordMatch(
                    category   = "blind_sqli",
                    keyword    = kw,
                    evidence   = f"keyword {kw!r} present in TRUE response, absent in FALSE response",
                    confidence = "medium",
                ))
            elif in_false and not in_true:
                matches.append(KeywordMatch(
                    category   = "blind_sqli",
                    keyword    = kw,
                    evidence   = f"keyword {kw!r} present in FALSE response, absent in TRUE response",
                    confidence = "medium",
                ))

        return matches

    # ── Internal detectors ────────────────────────────────────────────────────

    def _check_ssti_results(
        self, body: str, injected_input: str
    ) -> list[KeywordMatch]:
        matches: list[KeywordMatch] = []
        # Only run SSTI result checks when the injection looks like a template expression
        _SSTI_PROBE_HINTS = re.compile(
            r"\{\{|\$\{|#\{|<%=|\{%|@\{|\*\{", re.I
        )
        if injected_input and not _SSTI_PROBE_HINTS.search(injected_input):
            return matches

        for pattern, label in self._SSTI_CONFIRMATIONS:
            m = pattern.search(body)
            if m:
                ctx = self._context(body, m.group(0))
                matches.append(KeywordMatch(
                    category   = "ssti_result",
                    keyword    = m.group(0),
                    evidence   = f"{label}: {ctx}",
                    confidence = "high",
                ))
        return matches

    def _check_error_traces(self, body: str) -> list[KeywordMatch]:
        matches: list[KeywordMatch] = []
        for pattern, label, confidence in self._ERROR_TRACE_PATTERNS:
            m = pattern.search(body)
            if m:
                ctx = self._context(body, m.group(0))
                matches.append(KeywordMatch(
                    category   = "error_trace",
                    keyword    = m.group(0)[:60],
                    evidence   = f"{label}: {ctx}",
                    confidence = confidence,
                ))
        return matches

    def _check_reflection(self, body: str, injected_input: str) -> list[KeywordMatch]:
        if injected_input not in body:
            return []
        ctx = self._context(body, injected_input)
        return [KeywordMatch(
            category   = "reflection",
            keyword    = injected_input[:80],
            evidence   = ctx,
            confidence = "medium",
        )]

    def _check_blind_sqli_keywords(
        self, probed_body: str, baseline_body: str
    ) -> list[KeywordMatch]:
        matches: list[KeywordMatch] = []
        p_lower = probed_body.lower()
        b_lower = baseline_body.lower()
        for kw in self._BLIND_SQLI_POSITIVE_KEYWORDS:
            in_probed   = kw in p_lower
            in_baseline = kw in b_lower
            if in_probed and not in_baseline:
                matches.append(KeywordMatch(
                    category   = "blind_sqli",
                    keyword    = kw,
                    evidence   = f"keyword {kw!r} appeared in probed response but was absent in baseline",
                    confidence = "medium",
                ))
        return matches

    @staticmethod
    def _context(body: str, token: str, window: int = 60) -> str:
        """Return up to 120 chars of context around *token* in *body*."""
        idx = body.find(token)
        if idx == -1:
            idx = body.lower().find(token.lower())
        if idx == -1:
            return token[:120]
        start = max(0, idx - window)
        end   = min(len(body), idx + len(token) + window)
        snippet = body[start:end].strip()
        return snippet[:120]
