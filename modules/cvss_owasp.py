"""
CVSS v3.1 Scoring & OWASP Top 10 (2021) Category Mapping for DAST Findings.

Enriches findings with:
  - cvss_score: CVSS v3.1 base score (0.0-10.0)
  - cvss_vector: CVSS v3.1 vector string
  - cvss_severity: textual severity from CVSS score
  - owasp_category: OWASP Top 10 2021 category ID (A01-A10)
  - owasp_name: Full OWASP category name

Lookup order:
  1. CWE ID (most precise)
  2. vuln_type string (fallback when CWE is absent)
"""
from __future__ import annotations


# ═══════════════════════════════════════════════════════════════════════════════
# OWASP Top 10 — 2021
# ═══════════════════════════════════════════════════════════════════════════════

OWASP_CATEGORIES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}


# ═══════════════════════════════════════════════════════════════════════════════
# CWE → CVSS v3.1 base score + vector
# Standard mappings for 50+ common web-application CWEs.
# Scores reflect typical worst-case for a confirmed exploitable instance.
# ═══════════════════════════════════════════════════════════════════════════════

CWE_CVSS: dict[int, tuple[float, str]] = {
    # ── Injection ──────────────────────────────────────────────────────────
    89:   (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # SQL Injection
    564:  (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Hibernate Injection
    78:   (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # OS Command Injection
    77:   (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Command Injection
    94:   (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Code Injection
    917:  (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Expression Language Injection
    1336: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # SSTI
    90:   (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"),      # LDAP Injection
    91:   (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"),      # XML Injection
    643:  (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"),      # XPath Injection
    652:  (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"),      # XQuery Injection

    # ── XSS ────────────────────────────────────────────────────────────────
    79:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS (generic)
    80:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS Basic
    81:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS Error Message
    82:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS Script Tag
    83:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS Attribute
    84:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS URI
    85:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS Double-Encoding
    86:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS Through HTTP Headers
    87:   (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS Alt Syntax

    # ── Path Traversal / File Inclusion ────────────────────────────────────
    22:   (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Path Traversal
    23:   (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Relative Path Traversal
    36:   (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Absolute Path Traversal
    98:   (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Remote File Inclusion
    829:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Local File Inclusion

    # ── SSRF ───────────────────────────────────────────────────────────────
    918:  (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),      # SSRF

    # ── XXE ────────────────────────────────────────────────────────────────
    611:  (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),      # XXE
    827:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # XML Entity Expansion

    # ── Authentication / Session ──────────────────────────────────────────
    287:  (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Improper Authentication
    306:  (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Missing Auth for Critical Func
    798:  (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Hardcoded Credentials
    384:  (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),      # Session Fixation
    613:  (5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),      # Insufficient Session Expiration
    614:  (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),      # Sensitive Cookie w/o Secure
    1004: (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),      # Sensitive Cookie w/o HttpOnly
    307:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Brute Force

    # ── Access Control ────────────────────────────────────────────────────
    284:  (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),      # Improper Access Control
    639:  (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),      # IDOR
    862:  (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),      # Missing AuthZ
    863:  (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),      # Incorrect AuthZ
    269:  (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),      # Improper Privilege Mgmt
    285:  (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),      # Improper Authorization

    # ── CSRF ───────────────────────────────────────────────────────────────
    352:  (8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),      # CSRF

    # ── Deserialization ───────────────────────────────────────────────────
    502:  (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Deserialization of Untrusted Data

    # ── Open Redirect ─────────────────────────────────────────────────────
    601:  (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # Open Redirect

    # ── Cryptographic ─────────────────────────────────────────────────────
    327:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Broken Crypto Algorithm
    328:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Reversible One-Way Hash
    326:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Inadequate Encryption
    295:  (7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),      # Improper Cert Validation
    319:  (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Cleartext Transmission

    # ── Information Disclosure ────────────────────────────────────────────
    200:  (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),      # Info Exposure
    209:  (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),      # Error Message Info Exposure
    532:  (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),      # Info Exposure Through Logs
    548:  (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),      # Info Exposure Through Dir Listing

    # ── Security Misconfiguration ─────────────────────────────────────────
    16:   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),      # Configuration
    693:  (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),      # Protection Mechanism Failure
    1021: (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),      # Missing X-Frame-Options (Clickjacking)
    942:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Permissive CORS
    444:  (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),      # HTTP Request Smuggling

    # ── HTTP response manipulation ────────────────────────────────────────
    113:  (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # HTTP Response Splitting

    # ── Prototype Pollution ───────────────────────────────────────────────
    1321: (7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),      # Prototype Pollution

    # ── Vulnerable Components ─────────────────────────────────────────────
    1035: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Using Known-Vulnerable Components

    # ── Logging / Monitoring ──────────────────────────────────────────────
    778:  (3.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N"),      # Insufficient Logging
    223:  (3.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N"),      # Omission of Security-Relevant Info

    # ── DoS / Resource ────────────────────────────────────────────────────
    400:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),      # Uncontrolled Resource Consumption
    770:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),      # Allocation w/o Limits

    # ── JWT-specific ──────────────────────────────────────────────────────
    345:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Insufficient Verification of Data Authenticity (JWT alg:none, etc)
    347:  (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Improper Verification of Crypto Signature
}


# ═══════════════════════════════════════════════════════════════════════════════
# CWE → OWASP Top 10 2021 category
# ═══════════════════════════════════════════════════════════════════════════════

CWE_TO_OWASP: dict[int, str] = {
    # A01: Broken Access Control
    284: "A01", 285: "A01", 269: "A01", 639: "A01", 862: "A01", 863: "A01",
    352: "A01", 601: "A01", 1021: "A01",

    # A02: Cryptographic Failures
    326: "A02", 327: "A02", 328: "A02", 295: "A02", 319: "A02", 614: "A02",
    311: "A02", 312: "A02", 798: "A02",

    # A03: Injection
    79: "A03", 80: "A03", 81: "A03", 82: "A03", 83: "A03", 84: "A03",
    85: "A03", 86: "A03", 87: "A03",
    89: "A03", 564: "A03",
    78: "A03", 77: "A03", 94: "A03", 917: "A03", 1336: "A03",
    90: "A03", 91: "A03", 643: "A03", 652: "A03",
    611: "A03", 827: "A03",
    113: "A03",

    # A04: Insecure Design
    209: "A04", 532: "A04", 200: "A04", 548: "A04",

    # A05: Security Misconfiguration
    16: "A05", 693: "A05", 942: "A05", 1004: "A05",

    # A06: Vulnerable and Outdated Components
    1035: "A06", 1104: "A06",

    # A07: Identification and Authentication Failures
    287: "A07", 306: "A07", 384: "A07", 613: "A07", 307: "A07",
    345: "A07", 347: "A07",

    # A08: Software and Data Integrity Failures
    502: "A08", 829: "A08",

    # A09: Security Logging and Monitoring Failures
    778: "A09", 223: "A09",

    # A10: SSRF
    918: "A10",
}


# ═══════════════════════════════════════════════════════════════════════════════
# vuln_type string → (CWE-ID, fallback CVSS score, fallback CVSS vector, OWASP)
# Used when finding has no CWE field.
# ═══════════════════════════════════════════════════════════════════════════════

VULN_TYPE_MAP: dict[str, tuple[int, float, str, str]] = {
    # ── Injection ─────────────────────────────────────────────────────────
    "sqli":                     (89,   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03"),
    "sqli_blind":               (89,   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03"),
    "sqli_error":               (89,   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03"),
    "cmdi":                     (78,   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03"),
    "cmdi_blind":               (78,   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03"),
    "ssti":                     (1336, 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03"),
    "ssti_blind":               (1336, 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03"),
    "ldap_injection":           (90,   8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "A03"),

    # ── XSS ───────────────────────────────────────────────────────────────
    "xss_reflected":            (79,   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "A03"),
    "xss_stored":               (79,   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "A03"),
    "xss_dom":                  (79,   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "A03"),
    "xss":                      (79,   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "A03"),

    # ── File Inclusion / Path Traversal ───────────────────────────────────
    "lfi":                      (22,   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A03"),
    "lfi_blind":                (22,   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A03"),
    "path_traversal":           (22,   7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A03"),
    "rfi":                      (98,   9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03"),

    # ── SSRF ──────────────────────────────────────────────────────────────
    "ssrf":                     (918,  9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A10"),
    "ssrf_blind":               (918,  9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A10"),

    # ── XXE ───────────────────────────────────────────────────────────────
    "xxe":                      (611,  9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A03"),
    "xxe_blind":                (611,  9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A03"),

    # ── Deserialization ───────────────────────────────────────────────────
    "deserialization":          (502,  9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A08"),

    # ── Open Redirect ─────────────────────────────────────────────────────
    "open_redirect":            (601,  6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "A01"),

    # ── CSRF ──────────────────────────────────────────────────────────────
    "csrf":                     (352,  8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "A01"),

    # ── Access Control ────────────────────────────────────────────────────
    "broken_access_control":    (284,  8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A01"),
    "missing_authentication":   (306,  9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A07"),
    "privilege_escalation":     (269,  8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A01"),
    "horizontal_privilege_escalation": (639, 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A01"),
    "cross_user_idor":          (639,  8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A01"),
    "idor":                     (639,  8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A01"),

    # ── CORS ──────────────────────────────────────────────────────────────
    "cors_critical":            (942,  7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A05"),
    "cors_medium":              (942,  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05"),
    "cors_preflight":           (942,  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05"),
    "cors_cache_poison":        (942,  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05"),
    "cors_subdomain_wildcard":  (942,  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05"),

    # ── JWT ───────────────────────────────────────────────────────────────
    "jwt_alg_none":             (345,  7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A07"),
    "jwt_weak_secret":          (347,  7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A07"),
    "jwt_kid_injection":        (345,  7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A07"),
    "jwt_alg_confusion":        (345,  7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A07"),
    "jwt_sig_strip":            (345,  7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A07"),
    "jwt_jku_injection":        (345,  7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A07"),
    "jwt_expired_accept":       (613,  5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", "A07"),
    "jwt_claim_tamper":         (345,  7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A07"),

    # ── Session ───────────────────────────────────────────────────────────
    "weak_session_token":       (384,  8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A07"),
    "predictable_session_token": (384, 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A07"),

    # ── HTTP Smuggling ────────────────────────────────────────────────────
    "http_smuggling":           (444,  9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A05"),

    # ── Host Header / Method Tamper ───────────────────────────────────────
    "host_header":              (16,   5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05"),
    "method_tamper":            (16,   5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05"),

    # ── Prototype Pollution ───────────────────────────────────────────────
    "prototype_pollution":      (1321, 7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", "A03"),

    # ── Exceptional Conditions / Info Disclosure ──────────────────────────
    "exceptional_conditions":   (209,  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A04"),
    "info_disclosure":          (200,  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A04"),

    # ── Security Headers (low severity) ──────────────────────────────────
    "missing_csp":              (693,  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05"),
    "missing_x_frame":          (1021, 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "A05"),
    "missing_hsts":             (319,  5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "A02"),

    # ── Vulnerable Components ─────────────────────────────────────────────
    "vulnerable_component":     (1035, 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A06"),
    "outdated_library":         (1035, 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A06"),
}


# ═══════════════════════════════════════════════════════════════════════════════
# CVSS score → textual severity
# ═══════════════════════════════════════════════════════════════════════════════

def _cvss_severity(score: float) -> str:
    """Map a CVSS v3.1 base score to a textual severity label."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "Info"


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def enrich_finding(finding: dict, fetch_epss_score: bool = False) -> dict:
    """
    Add CVSS and OWASP data to a single finding dict (in-place + returned).

    Lookup priority:
      1. CWE field (e.g. "CWE-89") -> CWE_CVSS / CWE_TO_OWASP tables
      2. vuln_type field (e.g. "sqli") -> VULN_TYPE_MAP fallback

    Added keys:
      - cvss_score      (float)  e.g. 9.8
      - cvss_vector     (str)    e.g. "CVSS:3.1/AV:N/AC:L/..."
      - cvss_severity   (str)    e.g. "Critical"
      - owasp_category  (str)    e.g. "A03"
      - owasp_name      (str)    e.g. "Injection"
    """
    score: float | None = None
    vector: str | None = None
    owasp_id: str | None = None

    # ── Try CWE-based lookup first ────────────────────────────────────────
    cwe_raw = finding.get("cwe", "")
    cwe_num: int | None = None
    if cwe_raw and isinstance(cwe_raw, str) and cwe_raw.upper().startswith("CWE-"):
        try:
            cwe_num = int(cwe_raw.split("-", 1)[1])
        except (ValueError, IndexError):
            pass

    if cwe_num is not None:
        if cwe_num in CWE_CVSS:
            score, vector = CWE_CVSS[cwe_num]
        if cwe_num in CWE_TO_OWASP:
            owasp_id = CWE_TO_OWASP[cwe_num]

    # ── Fallback: vuln_type string ────────────────────────────────────────
    vuln_type = finding.get("vuln_type", "")
    if vuln_type and vuln_type in VULN_TYPE_MAP:
        vt_cwe, vt_score, vt_vector, vt_owasp = VULN_TYPE_MAP[vuln_type]
        if score is None:
            score = vt_score
            vector = vt_vector
        if owasp_id is None:
            owasp_id = vt_owasp
        # Also backfill CWE if missing
        if not cwe_raw:
            finding["cwe"] = f"CWE-{vt_cwe}"

    # ── Apply enrichments ─────────────────────────────────────────────────
    if score is not None:
        finding["cvss_score"] = score
        finding["cvss_vector"] = vector
        finding["cvss_severity"] = _cvss_severity(score)

    if owasp_id is not None:
        finding["owasp_category"] = owasp_id
        finding["owasp_name"] = OWASP_CATEGORIES.get(owasp_id, "Unknown")

    # ── EPSS enrichment (optional — makes an HTTP call) ────────────────
    if fetch_epss_score:
        cve = finding.get("cwe", "")  # CWE field may contain CVE in some scanners
        # Also check dedicated cve field
        cve_id = finding.get("cve") or (cve if cve.upper().startswith("CVE-") else None)
        if cve_id:
            epss = fetch_epss(cve_id)
            if epss is not None:
                finding["epss_score"] = epss
                existing_cvss = finding.get("cvss_score")
                if existing_cvss is not None:
                    finding["blended_risk_score"] = blend_risk_score(existing_cvss, epss)

    return finding


def enrich_all(findings: list[dict], fetch_epss_score: bool = False) -> list[dict]:
    """Enrich a list of findings with CVSS scores and OWASP categories."""
    for f in findings:
        enrich_finding(f, fetch_epss_score=fetch_epss_score)
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# EPSS (Exploit Prediction Scoring System) Integration
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_epss(cve_id: str, timeout: int = 5) -> float | None:
    """Fetch EPSS (Exploit Prediction Scoring System) score for a CVE.

    Returns float 0.0-1.0 representing exploit probability in the next 30 days.
    Returns None if CVE not found, API unreachable, or any error.

    Source: api.first.org/data/v1/epss -- free, no authentication required.
    EPSS outperforms CVSS-only by +48.9% MRR (AI-Driven Hybrid SAST-DAST study, 2026).
    """
    import urllib.request
    import json

    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return None

    url = f"https://api.first.org/data/v1/epss?cve={cve_id.upper()}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DAST-Scanner/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        items = data.get("data", [])
        if not items:
            return None
        return float(items[0].get("epss", 0))
    except Exception:
        return None


def blend_risk_score(cvss: float, epss: float | None) -> float:
    """Blend CVSS and EPSS into a composite risk score (0.0-10.0).

    Formula: 0.6 * EPSS_normalized + 0.4 * (CVSS / 10)
    Then scale back to 0-10 range.

    If EPSS unavailable, returns CVSS unchanged.
    """
    if epss is None:
        return cvss
    epss_normalized = max(0.0, min(1.0, epss))
    cvss_normalized = max(0.0, min(10.0, cvss)) / 10.0
    blended = (0.6 * epss_normalized + 0.4 * cvss_normalized) * 10.0
    return round(blended, 1)
