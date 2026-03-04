"""
Nuclei-mined DAST response analysis patterns.

Detects extended SQL injection errors (databases beyond the MySQL/PostgreSQL/Oracle/MSSQL
set already handled in passive.py), SSRF internal service banners, LFI/file-read content
disclosure, and miscellaneous vulnerability response indicators.

All patterns are compiled at module load time for performance.  The public entry
point is ``run_checks()`` which returns a list of finding dicts compatible with
the rest of the scanner pipeline.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Type alias for pattern tuples: (compiled regex, description, severity, CWE)
# ---------------------------------------------------------------------------
PatternEntry = Tuple[re.Pattern[str], str, str, str]

# ===================================================================
# GROUP 1 -- Extended SQL Error Detection
# (databases NOT already covered by passive.py _ERROR_PATTERNS)
# ===================================================================

_EXTENDED_SQL_ERRORS: List[PatternEntry] = [
    # SQLite
    (
        re.compile(r"SQLITE_ERROR|sqlite3\.OperationalError:|SQLite error \d+:", re.I),
        "SQLite database error disclosed in response",
        "Medium",
        "CWE-89",
    ),
    # IBM DB2
    (
        re.compile(r"CLI Driver.*DB2|DB2 SQL error", re.I),
        "IBM DB2 database error disclosed in response",
        "Medium",
        "CWE-89",
    ),
    # HSQLDB / H2
    (
        re.compile(
            r"Unexpected end of command in statement \[|org\.h2\.jdbc",
            re.I,
        ),
        "HSQLDB/H2 database error disclosed in response",
        "Medium",
        "CWE-89",
    ),
    # Sybase
    (
        re.compile(r"Sybase message:|SybSQLException", re.I),
        "Sybase database error disclosed in response",
        "Medium",
        "CWE-89",
    ),
    # MongoDB (NoSQL injection indicator)
    (
        re.compile(r"MongoError:|E11000 duplicate key", re.I),
        "MongoDB error disclosed in response (possible NoSQL injection)",
        "Medium",
        "CWE-89",
    ),
    # MariaDB (distinct from generic MySQL pattern in passive.py)
    (
        re.compile(
            r"check the manual that corresponds to your MariaDB server version",
            re.I,
        ),
        "MariaDB SQL error disclosed in response",
        "Medium",
        "CWE-89",
    ),
    # ODBC generic
    (
        re.compile(r"ODBC Driver \d+ for SQL Server|\[Microsoft\]\[ODBC", re.I),
        "ODBC driver error disclosed in response",
        "Medium",
        "CWE-89",
    ),
    # ColdFusion / Macromedia JDBC
    (
        re.compile(r"\[Macromedia\]\[SQLServer JDBC Driver\]", re.I),
        "ColdFusion SQL Server JDBC error disclosed in response",
        "Medium",
        "CWE-89",
    ),
]

# ===================================================================
# GROUP 2 -- SSRF Internal Service Banner Detection
# ===================================================================

_SSRF_BANNERS: List[PatternEntry] = [
    # SSH banner
    (
        re.compile(r"SSH-\d\.\d-OpenSSH_\d"),
        "SSH service banner in response body (SSRF to internal SSH)",
        "High",
        "CWE-918",
    ),
    # Redis
    (
        re.compile(r"DENIED Redis|CONFIG REWRITE|NOAUTH Authentication", re.I),
        "Redis service response in body (SSRF to internal Redis)",
        "High",
        "CWE-918",
    ),
    # MySQL banner
    (
        re.compile(r"\d\.\d\.\d.*mysql_native_password"),
        "MySQL service banner in response body (SSRF to internal MySQL)",
        "High",
        "CWE-918",
    ),
    # SMTP banner
    (
        re.compile(r"220 .* (?:ESMTP|SMTP)"),
        "SMTP service banner in response body (SSRF to internal mail server)",
        "Medium",
        "CWE-918",
    ),
    # FTP banner
    (
        re.compile(r"220 .* FTP|230 Login successful", re.I),
        "FTP service banner in response body (SSRF to internal FTP)",
        "Medium",
        "CWE-918",
    ),
]

# ===================================================================
# GROUP 3 -- LFI / File Read Disclosure
# ===================================================================

_LFI_CONTENT: List[PatternEntry] = [
    # /etc/passwd
    (
        re.compile(r"root:.*:0:0:"),
        "Unix /etc/passwd content in response (LFI/file read)",
        "Critical",
        "CWE-22",
    ),
    # /etc/shadow
    (
        re.compile(r"root:\$\d\$"),
        "Unix /etc/shadow content in response (LFI/file read)",
        "Critical",
        "CWE-22",
    ),
    # Windows win.ini -- requires both markers present
    (
        re.compile(r"for 16-bit app support.*\[fonts\]|\[fonts\].*for 16-bit app support", re.I | re.DOTALL),
        "Windows win.ini content in response (LFI/file read)",
        "High",
        "CWE-22",
    ),
    # phpinfo() page -- title tag OR version + config combo
    (
        re.compile(
            r"<title>phpinfo\(\)</title>|PHP Version \d+\.\d+.*Configuration File|Configuration File.*PHP Version \d+\.\d+",
            re.I | re.DOTALL,
        ),
        "PHP phpinfo() page content in response (information disclosure)",
        "Medium",
        "CWE-200",
    ),
]

# ===================================================================
# GROUP 4 -- Response-Based Vulnerability Indicators
# ===================================================================

_VULN_INDICATORS: List[PatternEntry] = [
    # XXE -- system file content appearing in an XML-ish response
    (
        re.compile(r"root:x:0:0"),
        "Possible XXE exploitation (/etc/passwd content in response)",
        "High",
        "CWE-611",
    ),
    # Server-Side Includes (SSI)
    (
        re.compile(r"<!--#exec cmd=|<!--#include virtual="),
        "Server-Side Include (SSI) directive in response body",
        "High",
        "CWE-97",
    ),
    # LDAP error disclosure
    (
        re.compile(r"javax\.naming\.|LDAP.*error|Invalid DN syntax", re.I),
        "LDAP error information disclosed in response",
        "Medium",
        "CWE-90",
    ),
    # XPath error disclosure
    (
        re.compile(r"XPath(?:Exception|Error)|Invalid XPath expression|XPathEvalError", re.I),
        "XPath error information disclosed in response",
        "Medium",
        "CWE-643",
    ),
]

# ===================================================================
# Header-only pattern: CRLF injection via Set-Cookie
# Not part of body scanning, handled separately in run_checks().
# ===================================================================

_CRLF_COOKIE_RE = re.compile(r"crlfinjection", re.I)

# ===================================================================
# Category mapping for each pattern group
# ===================================================================

_CATEGORY_MAP: Dict[int, str] = {
    id(_EXTENDED_SQL_ERRORS): "sql_error_extended",
    id(_SSRF_BANNERS): "ssrf_service_banner",
    id(_LFI_CONTENT): "lfi_disclosure",
    id(_VULN_INDICATORS): "vuln_indicator",
}

# Remediation text keyed by category
_REMEDIATION: Dict[str, str] = {
    "sql_error_extended": (
        "Suppress verbose database error messages in production. "
        "Use parameterized queries to prevent SQL/NoSQL injection."
    ),
    "ssrf_service_banner": (
        "Restrict outbound requests from the application server. "
        "Validate and allowlist user-supplied URLs. Block access to "
        "internal network ranges (RFC 1918, link-local)."
    ),
    "lfi_disclosure": (
        "Sanitize file path inputs. Never pass user-controlled data to "
        "filesystem operations without strict allowlist validation. "
        "Restrict file access to the application root."
    ),
    "vuln_indicator": (
        "Investigate the underlying vulnerability indicated by the response "
        "pattern. Apply input validation, output encoding, and principle "
        "of least privilege as appropriate."
    ),
    "crlf_injection": (
        "Strip CR (\\r) and LF (\\n) characters from user input before "
        "including it in HTTP headers. Use framework-provided header-setting "
        "APIs that encode values automatically."
    ),
}


# -------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------


def run_checks(
    url: str,
    body: str,
    headers: dict,
    cookies: dict,
) -> List[dict]:
    """Scan response for DAST-relevant patterns.

    Parameters
    ----------
    url:
        The request URL that produced this response.
    body:
        The response body text (will be truncated to 32 000 chars internally).
    headers:
        Response headers as ``{name: value}`` (case-insensitive lookup is the
        caller's responsibility; values may be strings or lists).
    cookies:
        Parsed cookies from the response (``{name: value}``).

    Returns
    -------
    list[dict]
        Each dict contains: url, category, finding, severity, evidence, remediation, cwe.
    """
    findings: List[dict] = []

    # Truncate body to a reasonable size to avoid regex backtracking on
    # extremely large responses.
    b = body[:32_000] if body else ""

    # -- Body-based pattern groups --
    pattern_groups: List[List[PatternEntry]] = [
        _EXTENDED_SQL_ERRORS,
        _SSRF_BANNERS,
        _LFI_CONTENT,
        _VULN_INDICATORS,
    ]

    for group in pattern_groups:
        category = _CATEGORY_MAP[id(group)]
        remediation = _REMEDIATION[category]
        for pat, desc, severity, cwe in group:
            m = pat.search(b)
            if m:
                snippet = m.group(0)
                # Truncate matched evidence to avoid dumping huge blobs
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                findings.append(
                    {
                        "url": url,
                        "category": category,
                        "finding": desc,
                        "severity": severity,
                        "evidence": f"Pattern matched: {snippet!r}",
                        "remediation": remediation,
                        "cwe": cwe,
                    }
                )

    # -- Header-based check: CRLF injection via Set-Cookie --
    _check_crlf_injection(url, headers, findings)

    return findings


def _check_crlf_injection(
    url: str,
    headers: dict,
    findings: List[dict],
) -> None:
    """Detect CRLF injection evidence in Set-Cookie response headers."""
    set_cookie_values: list = []

    for name, value in headers.items():
        if name.lower() == "set-cookie":
            if isinstance(value, list):
                set_cookie_values.extend(value)
            else:
                set_cookie_values.append(value)

    for cookie_val in set_cookie_values:
        if _CRLF_COOKIE_RE.search(str(cookie_val)):
            findings.append(
                {
                    "url": url,
                    "category": "crlf_injection",
                    "finding": "CRLF injection evidence in Set-Cookie header",
                    "severity": "Low",
                    "evidence": f"Set-Cookie value contains CRLF marker: {str(cookie_val)[:120]!r}",
                    "remediation": _REMEDIATION["crlf_injection"],
                    "cwe": "CWE-113",
                }
            )
