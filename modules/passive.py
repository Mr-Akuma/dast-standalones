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
        # ── New checks (ZAP parity) ──
        findings += self._check_content_type(url, h)
        findings += self._check_charset_mismatch(url, h, resp_body)
        findings += self._check_disclosure_headers(url, h)
        findings += self._check_site_isolation(url, h)
        findings += self._check_pii(url, resp_body)
        findings += self._check_hashes(url, resp_body)
        findings += self._check_dangerous_js(url, resp_body)
        findings += self._check_dom_xss(url, resp_body)
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
        for pat, msg, severity, cwe in _PII_PATTERNS:
            m = pat.search(sample)
            if m and msg not in seen:
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
        seen = set()
        for pat, msg, severity, cwe in _HASH_PATTERNS:
            m = pat.search(sample)
            if m and msg not in seen:
                seen.add(msg)
                findings.append(PassiveFinding(
                    url=url, category="info_disclosure",
                    finding=msg,
                    severity=severity,
                    evidence=m.group(0)[:60] + "...",
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

    def _check_dom_xss(self, url: str, body: str) -> list[PassiveFinding]:
        """
        Static analysis for DOM-based XSS: extract inline <script> blocks
        and check for user-controllable sources flowing into dangerous sinks.

        Three detection tiers:
          1. DIRECT FLOW — regex matches source→sink in single expression (High confidence)
          2. CO-OCCURRENCE — source + sink in same <script> block (Medium confidence)
          3. EVENT HANDLER — on* attributes containing sources (High confidence)
        """
        findings: list[PassiveFinding] = []
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
                        severity="Medium",
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


# Global instance
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
    """

    def __init__(self, scanner: PassiveScanner | None = None, **kwargs):
        super().__init__(**kwargs)
        self._scanner = scanner or passive_scanner
        self._findings: list[PassiveFinding] = []
        self._seen: set[tuple[str, str, str]] = set()   # (path, category, finding)
        self._lock = threading.Lock()

    # -- override the single gateway all verbs route through --
    def request(self, method, url, **kwargs):
        resp = super().request(method, url, **kwargs)
        try:
            self._passive_scan(url, resp)
        except Exception:
            pass  # never interfere with the caller
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
