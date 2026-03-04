"""
Nuclei-mined misconfiguration and technology fingerprint detection.

Detects server misconfigs, framework/runtime debug modes, Spring Boot
actuator deep patterns, and new technology fingerprints. All patterns are
sourced from nuclei community templates and adapted for passive scanning.

This module complements passive.py -- it does NOT duplicate any checks
already present there (X-Powered-By, Server version, missing security
headers, Django/Laravel/Spring/Angular debug basics, Swagger, WordPress,
mixed content, etc.).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Pre-compiled regexes (compiled once at import time for performance)
# ---------------------------------------------------------------------------

_RE_POSTMESSAGE_WILDCARD = re.compile(
    r"\.postMessage\([^,]+,\s*['\"]?\*['\"]?\)"
)
_RE_INTERNAL_IP = re.compile(
    r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"
)
_RE_NGINX_STUB_STATUS = re.compile(
    r"Active connections:\s*\d+\s+server accepts handled requests"
)
_RE_APACHE_STATUS_TITLE = re.compile(r"<title>Apache Status</title>", re.IGNORECASE)
_RE_BIGIP_COOKIE = re.compile(r"BIGipServer[a-z_.~0-9A-Z-]*=")
_RE_BOA_SERVER = re.compile(r"Boa/\d+")
_RE_AKAMAI_CACHE = re.compile(r"TCP_(?:HIT|MISS).*akamai", re.IGNORECASE)
_RE_BAMBOO = re.compile(r"atlassian bamboo", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helper to build a finding dict
# ---------------------------------------------------------------------------

def _finding(
    url: str,
    category: str,
    finding: str,
    severity: str,
    evidence: str,
    remediation: str,
    cwe: str,
) -> dict:
    return {
        "url": url,
        "category": category,
        "finding": finding,
        "severity": severity,
        "evidence": evidence[:500],  # cap evidence length
        "remediation": remediation,
        "cwe": cwe,
    }


# ---------------------------------------------------------------------------
# GROUP 1 -- Server Misconfigurations
# ---------------------------------------------------------------------------

def _check_postmessage_wildcard(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """1. postMessage wildcard origin -- CWE-346."""
    m = _RE_POSTMESSAGE_WILDCARD.search(b)
    if m:
        findings.append(_finding(
            url,
            "misconfiguration",
            "postMessage called with wildcard (*) origin -- any window can receive the message",
            "Medium",
            m.group(0),
            "Replace '*' with the specific trusted origin in postMessage calls",
            "CWE-346",
        ))


def _check_internal_ip_location(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """2. Internal IP leaked in Location header -- CWE-200."""
    location = h.get("location", "")
    m = _RE_INTERNAL_IP.search(location)
    if m:
        findings.append(_finding(
            url,
            "info_disclosure",
            "Location header redirects to internal/private IP address",
            "Low",
            f"Location: {location[:200]}",
            "Configure reverse proxy to rewrite internal IPs in redirect headers",
            "CWE-200",
        ))


def _check_x_backend_server(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """3. X-Backend-Server header disclosure -- CWE-200."""
    backend = h.get("x-backend-server", "")
    if backend:
        findings.append(_finding(
            url,
            "info_disclosure",
            "X-Backend-Server header exposes internal infrastructure details",
            "Low",
            f"X-Backend-Server: {backend[:200]}",
            "Remove X-Backend-Server header from responses via reverse proxy configuration",
            "CWE-200",
        ))


def _check_webdav_enabled(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """4. WebDAV enabled -- CWE-16."""
    body_match = "<D:multistatus" in b or "<d:multistatus" in b
    header_match = any("DAV:" in v for v in h.values())
    if body_match or header_match:
        evidence_parts = []
        if body_match:
            evidence_parts.append("WebDAV multistatus response detected in body")
        if header_match:
            evidence_parts.append("DAV: header present")
        findings.append(_finding(
            url,
            "misconfiguration",
            "WebDAV is enabled -- may allow unauthorized file manipulation",
            "Medium",
            "; ".join(evidence_parts),
            "Disable WebDAV if not required. If needed, restrict access with authentication and IP allowlists",
            "CWE-16",
        ))


def _check_https_to_http_redirect(
    url: str, b: str, h: dict, findings: list[dict], status_code: int | None = None
) -> None:
    """5. HTTPS page redirecting to HTTP -- CWE-319."""
    location = h.get("location", "")
    if not location:
        return
    parsed_url = urlparse(url)
    is_https = parsed_url.scheme == "https"
    redirects_to_http = location.startswith("http://")
    # status_code may not be available; rely on Location header presence
    if is_https and redirects_to_http:
        findings.append(_finding(
            url,
            "misconfiguration",
            "HTTPS page redirects to HTTP -- SSL/TLS protection is stripped",
            "Medium",
            f"Location: {location[:200]}",
            "Ensure all redirects stay on HTTPS. Update server config to redirect http->https only",
            "CWE-319",
        ))


def _check_nginx_stub_status(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """6. Nginx stub_status exposed -- CWE-200."""
    m = _RE_NGINX_STUB_STATUS.search(b)
    if m:
        findings.append(_finding(
            url,
            "info_disclosure",
            "Nginx stub_status page is publicly accessible -- exposes connection metrics",
            "Low",
            m.group(0)[:200],
            "Restrict /nginx_status to internal networks via allow/deny directives",
            "CWE-200",
        ))


def _check_apache_server_status(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """7. Apache server-status exposed -- CWE-200."""
    if _RE_APACHE_STATUS_TITLE.search(b) or "Apache Server Status for" in b:
        evidence = "Apache server-status page detected"
        if "Apache Server Status for" in b:
            idx = b.index("Apache Server Status for")
            evidence = b[idx : idx + 80]
        findings.append(_finding(
            url,
            "info_disclosure",
            "Apache server-status page is publicly accessible -- exposes request details and server metrics",
            "Low",
            evidence,
            "Restrict /server-status to internal networks via <Location> and Require directives",
            "CWE-200",
        ))


# ---------------------------------------------------------------------------
# GROUP 2 -- Framework/Runtime Debug Patterns (NOT in passive.py)
# ---------------------------------------------------------------------------

def _check_symfony_debug(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """8. Symfony debug mode (profiler bar) -- CWE-215."""
    indicators = ["_profiler", "Symfony Exception", "sf-toolbar"]
    matched = [ind for ind in indicators if ind in b]
    if matched:
        findings.append(_finding(
            url,
            "debug_mode",
            "Symfony debug/profiler mode is active in production -- exposes internals and stack traces",
            "High",
            f"Matched indicators: {', '.join(matched)}",
            "Set APP_ENV=prod and APP_DEBUG=false in Symfony configuration",
            "CWE-215",
        ))


def _check_flask_werkzeug_debugger(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """9. Flask Werkzeug debugger -- CWE-215 (RCE risk)."""
    has_debugger = "Werkzeug Debugger" in b
    has_console_traceback = "traceback = " in b and "console" in b
    if has_debugger or has_console_traceback:
        evidence = "Werkzeug Debugger" if has_debugger else "traceback/console pattern"
        findings.append(_finding(
            url,
            "debug_mode",
            "Flask Werkzeug interactive debugger is exposed -- allows Remote Code Execution (RCE)",
            "Critical",
            evidence,
            "IMMEDIATELY disable debug mode: set FLASK_DEBUG=0 or app.debug=False. Never expose Werkzeug debugger in production",
            "CWE-215",
        ))


def _check_flask_debug_toolbar(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """10. Flask debug toolbar -- CWE-215."""
    if "flDebugToolbar" in b or "flDebugToolbarHandle" in b:
        matched = "flDebugToolbar" if "flDebugToolbar" in b else "flDebugToolbarHandle"
        findings.append(_finding(
            url,
            "debug_mode",
            "Flask Debug Toolbar is active in production -- exposes SQL queries, config, and request data",
            "High",
            f"Detected: {matched}",
            "Remove or disable flask-debugtoolbar in production (DEBUG_TB_ENABLED=False)",
            "CWE-215",
        ))


def _check_php_debugbar(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """11. PHP DebugBar -- CWE-215."""
    if "phpdebugbar" in b or "PhpDebugBar" in b:
        matched = "phpdebugbar" if "phpdebugbar" in b else "PhpDebugBar"
        findings.append(_finding(
            url,
            "debug_mode",
            "PHP DebugBar is active in production -- exposes database queries, routes, and session data",
            "High",
            f"Detected: {matched}",
            "Disable PHP DebugBar in production by setting 'debugbar.enabled' to false or removing the package",
            "CWE-215",
        ))


def _check_thinkphp_error(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """12. ThinkPHP error -- CWE-215."""
    if "ThinkPHP" in b and ("Error" in b or "Exception" in b):
        findings.append(_finding(
            url,
            "debug_mode",
            "ThinkPHP error/exception page is exposed -- leaks framework internals and stack trace",
            "Medium",
            "ThinkPHP error/exception page detected",
            "Set app_debug=false and app_trace=false in ThinkPHP production configuration",
            "CWE-215",
        ))


def _check_typo3_debug(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """13. TYPO3 debug output -- CWE-215."""
    has_exception = "TYPO3 Exception" in b
    has_tx_marker = "tx_" in b and "TYPO3" in b
    if has_exception or has_tx_marker:
        evidence = "TYPO3 Exception" if has_exception else "TYPO3 tx_ debug markers"
        findings.append(_finding(
            url,
            "debug_mode",
            "TYPO3 debug output or exception page is exposed -- leaks CMS internals",
            "Medium",
            evidence,
            "Set displayErrors=0 in TYPO3 LocalConfiguration.php and disable debug mode",
            "CWE-215",
        ))


# ---------------------------------------------------------------------------
# GROUP 3 -- Spring Boot Actuator Deep Detection
# ---------------------------------------------------------------------------

def _check_actuator_env(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """14. /actuator/env exposed -- CWE-200."""
    markers = ['"spring.datasource"', '"spring.mail"', '"java.runtime"']
    matched = [m for m in markers if m in b]
    if matched:
        findings.append(_finding(
            url,
            "actuator",
            "Spring Boot /actuator/env is exposed -- leaks environment variables, database credentials, and secrets",
            "Critical",
            f"Matched properties: {', '.join(matched)}",
            "Restrict actuator endpoints with Spring Security: management.endpoints.web.exposure.exclude=env",
            "CWE-200",
        ))


def _check_actuator_heapdump(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """15. /actuator/heapdump marker -- CWE-200."""
    content_type = h.get("content-type", "")
    if "application/octet-stream" in content_type and "heapdump" in url.lower():
        findings.append(_finding(
            url,
            "actuator",
            "Spring Boot /actuator/heapdump is accessible -- full JVM heap dump exposes secrets, credentials, and PII",
            "Critical",
            f"Content-Type: {content_type}; URL contains 'heapdump'",
            "Disable heapdump endpoint: management.endpoint.heapdump.enabled=false and restrict actuator with Spring Security",
            "CWE-200",
        ))


def _check_actuator_beans(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """16. /actuator/beans exposed -- CWE-200."""
    if '"beans":' in b and '"scope":' in b and '"type":' in b:
        findings.append(_finding(
            url,
            "actuator",
            "Spring Boot /actuator/beans is exposed -- reveals all application beans and their dependencies",
            "Medium",
            'Response contains "beans", "scope", and "type" JSON keys',
            "Restrict actuator endpoints: management.endpoints.web.exposure.exclude=beans",
            "CWE-200",
        ))


def _check_actuator_loggers(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """17. /actuator/loggers exposed -- CWE-200."""
    if '"configuredLevel"' in b and '"effectiveLevel"' in b:
        findings.append(_finding(
            url,
            "actuator",
            "Spring Boot /actuator/loggers is exposed -- attackers can change log levels to exfiltrate data or cause DoS",
            "Medium",
            'Response contains "configuredLevel" and "effectiveLevel" JSON keys',
            "Restrict actuator endpoints: management.endpoints.web.exposure.exclude=loggers",
            "CWE-200",
        ))


# ---------------------------------------------------------------------------
# GROUP 4 -- New Technology Fingerprints
# ---------------------------------------------------------------------------

def _check_adonisjs(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """18. AdonisJS framework -- CWE-200."""
    xpb = h.get("x-powered-by", "")
    if "AdonisJs" in xpb:
        findings.append(_finding(
            url,
            "tech_fingerprint",
            "AdonisJS framework detected via X-Powered-By header",
            "Info",
            f"X-Powered-By: {xpb[:200]}",
            "Remove X-Powered-By header or set a generic value",
            "CWE-200",
        ))


def _check_f5_bigip_cookie(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """19. F5 BIG-IP persistence cookie -- CWE-200."""
    set_cookie = h.get("set-cookie", "")
    if _RE_BIGIP_COOKIE.search(set_cookie):
        findings.append(_finding(
            url,
            "tech_fingerprint",
            "F5 BIG-IP load balancer detected via persistence cookie -- may leak internal pool/server info",
            "Info",
            f"Set-Cookie contains BIGipServer pattern",
            "Encrypt BIG-IP persistence cookies (cookie encryption profile) or use cookie rewrite",
            "CWE-200",
        ))


def _check_boa_web_server(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """20. Boa Web Server (IoT) -- CWE-200."""
    server = h.get("server", "")
    if _RE_BOA_SERVER.search(server):
        findings.append(_finding(
            url,
            "tech_fingerprint",
            "Boa Web Server detected (common in IoT/embedded devices) -- often unpatched and vulnerable",
            "Info",
            f"Server: {server[:200]}",
            "Replace Boa with a maintained web server or restrict access to management interfaces",
            "CWE-200",
        ))


def _check_backdrop_cms(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """21. Backdrop CMS -- CWE-200."""
    x_gen = h.get("x-generator", "")
    if "Backdrop CMS" in x_gen:
        findings.append(_finding(
            url,
            "tech_fingerprint",
            "Backdrop CMS detected via X-Generator header",
            "Info",
            f"X-Generator: {x_gen[:200]}",
            "Remove X-Generator header to reduce technology fingerprinting surface",
            "CWE-200",
        ))


def _check_akamai_cdn(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """22. Akamai CDN -- CWE-200."""
    x_cache = h.get("x-cache", "")
    if _RE_AKAMAI_CACHE.search(x_cache):
        findings.append(_finding(
            url,
            "tech_fingerprint",
            "Akamai CDN detected via X-Cache header",
            "Info",
            f"X-Cache: {x_cache[:200]}",
            "Suppress X-Cache header if CDN vendor disclosure is not desired",
            "CWE-200",
        ))


def _check_bamboo_ci(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """23. Atlassian Bamboo CI/CD -- CWE-200."""
    if _RE_BAMBOO.search(b):
        m = _RE_BAMBOO.search(b)
        findings.append(_finding(
            url,
            "tech_fingerprint",
            "Atlassian Bamboo CI/CD server detected -- CI/CD interfaces should not be publicly accessible",
            "Info",
            m.group(0) if m else "Atlassian Bamboo reference detected",
            "Restrict Bamboo access to internal networks and require authentication",
            "CWE-200",
        ))


def _check_blazor_wasm(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """24. Blazor WebAssembly -- CWE-200."""
    if "dotnet.wasm" in b or "_framework/blazor" in b:
        matched = "dotnet.wasm" if "dotnet.wasm" in b else "_framework/blazor"
        findings.append(_finding(
            url,
            "tech_fingerprint",
            "Blazor WebAssembly (.NET) application detected",
            "Info",
            f"Detected: {matched}",
            "Ensure Blazor WASM app does not embed secrets in client-side assemblies",
            "CWE-200",
        ))


def _check_apostrophe_cms(url: str, b: str, h: dict, findings: list[dict]) -> None:
    """25. ApostropheCMS -- CWE-200."""
    if "window.apos" in b or "/modules/apostrophe-" in b:
        matched = "window.apos" if "window.apos" in b else "/modules/apostrophe-"
        findings.append(_finding(
            url,
            "tech_fingerprint",
            "ApostropheCMS detected",
            "Info",
            f"Detected: {matched}",
            "Keep ApostropheCMS updated and restrict admin routes to authenticated users",
            "CWE-200",
        ))


# ---------------------------------------------------------------------------
# Ordered list of all check functions
# ---------------------------------------------------------------------------

_ALL_CHECKS = [
    # Group 1 -- Server Misconfigurations
    _check_postmessage_wildcard,
    _check_internal_ip_location,
    _check_x_backend_server,
    _check_webdav_enabled,
    _check_https_to_http_redirect,
    _check_nginx_stub_status,
    _check_apache_server_status,
    # Group 2 -- Framework/Runtime Debug Patterns
    _check_symfony_debug,
    _check_flask_werkzeug_debugger,
    _check_flask_debug_toolbar,
    _check_php_debugbar,
    _check_thinkphp_error,
    _check_typo3_debug,
    # Group 3 -- Spring Boot Actuator Deep Detection
    _check_actuator_env,
    _check_actuator_heapdump,
    _check_actuator_beans,
    _check_actuator_loggers,
    # Group 4 -- New Technology Fingerprints
    _check_adonisjs,
    _check_f5_bigip_cookie,
    _check_boa_web_server,
    _check_backdrop_cms,
    _check_akamai_cdn,
    _check_bamboo_ci,
    _check_blazor_wasm,
    _check_apostrophe_cms,
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_checks(
    url: str,
    body: str,
    headers: dict,
    cookies: dict,
    status_code: int | None = None,
) -> list[dict]:
    """
    Scan a single HTTP response for misconfigurations and technology fingerprints.

    Args:
        url:         The request URL.
        body:        The response body (HTML/JSON/text).
        headers:     Response headers as a dict (any casing).
        cookies:     Response cookies (reserved for future cookie-level checks).
        status_code: HTTP status code (optional, used for redirect detection).

    Returns:
        List of finding dicts, each with keys:
        url, category, finding, severity, evidence, remediation, cwe.
    """
    findings: list[dict] = []

    # Normalize: lowercase header keys, cap body scan to 32 KB
    b = body[:32_000] if body else ""
    h = {k.lower(): v for k, v in headers.items()} if headers else {}

    for check_fn in _ALL_CHECKS:
        try:
            check_fn(url, b, h, findings)
        except Exception:
            # Never let a single check crash the entire scan
            pass

    return findings
