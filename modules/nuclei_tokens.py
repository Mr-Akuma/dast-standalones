"""
Nuclei-mined token and credential detection patterns.
Extends PassiveScanner with 26 new service-specific credential checks.

These patterns are derived from nuclei security templates and cover
infrastructure tokens, payment processors, cloud provider credentials,
encryption keys, and connection strings that passive.py does not handle.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Pattern list: (compiled_regex, description, severity, cwe)
# ---------------------------------------------------------------------------
_NUCLEI_TOKEN_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # ---- HashiCorp / Terraform ----
    (re.compile(r"\bhvs\.[a-z0-9_-]{90,100}\b"),
     "HashiCorp Vault service token (hvs.) exposed in response",
     "Critical", "CWE-522"),

    (re.compile(r"\bhvb\.[a-z0-9_-]{138,212}\b"),
     "HashiCorp Vault batch token (hvb.) exposed in response",
     "Critical", "CWE-522"),

    (re.compile(r"\b[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,70}\b"),
     "Terraform Cloud API token (atlasv1) exposed in response",
     "High", "CWE-522"),

    # ---- Databricks ----
    (re.compile(r"\bdapi[a-h0-9]{32}\b"),
     "Databricks Personal Access Token (dapi) exposed in response",
     "High", "CWE-522"),

    # ---- Dynatrace ----
    (re.compile(r"\bdt0[a-zA-Z]\d{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b"),
     "Dynatrace API token (dt0) exposed in response",
     "High", "CWE-522"),

    # ---- Doppler ----
    (re.compile(r"\bdp\.st\.[a-zA-Z0-9_-]{40,50}\b"),
     "Doppler service token (dp.st.) exposed in response",
     "High", "CWE-522"),

    # ---- Braintree / PayPal ----
    (re.compile(r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"),
     "Braintree/PayPal production access token exposed in response",
     "Critical", "CWE-522"),

    # ---- Square ----
    (re.compile(r"\bsq0csp-[a-zA-Z0-9_-]{43}\b"),
     "Square OAuth client secret (sq0csp-) exposed in response",
     "Critical", "CWE-522"),

    (re.compile(r"\bsq0atp-[a-zA-Z0-9_-]{22}\b"),
     "Square access token (sq0atp-) exposed in response",
     "Critical", "CWE-522"),

    # ---- Grafana ----
    (re.compile(r"\bglsa_[a-zA-Z0-9_]{32}_[a-f0-9]{8}\b"),
     "Grafana service account token (glsa_) exposed in response",
     "High", "CWE-522"),

    (re.compile(r"\bglc_[a-zA-Z0-9_+/]{32,}={0,2}\b"),
     "Grafana Cloud token (glc_) exposed in response",
     "High", "CWE-522"),

    # ---- DigitalOcean ----
    (re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
     "DigitalOcean Personal Access Token (dop_v1_) exposed in response",
     "High", "CWE-522"),

    (re.compile(r"\bdoo_v1_[a-f0-9]{64}\b"),
     "DigitalOcean OAuth token (doo_v1_) exposed in response",
     "High", "CWE-522"),

    (re.compile(r"\bdor_v1_[a-f0-9]{64}\b"),
     "DigitalOcean refresh token (dor_v1_) exposed in response",
     "High", "CWE-522"),

    # ---- Elastic Cloud ----
    (re.compile(r"\bessu_[a-zA-Z0-9_-]{30,40}\b"),
     "Elastic Cloud API key (essu_) exposed in response",
     "High", "CWE-522"),

    # ---- Docker Hub ----
    (re.compile(r"\bdckr_pat_[a-zA-Z0-9_-]{27}\b"),
     "Docker Hub Personal Access Token (dckr_pat_) exposed in response",
     "High", "CWE-522"),

    # ---- Mapbox ----
    # Uses a dot-separated structure (sk.<account>.<token>) to distinguish
    # from Stripe sk_live_ / sk_test_ prefixes.
    (re.compile(r"\bsk\.[a-zA-Z0-9]{60,}\b"),
     "Mapbox secret token (sk.*) exposed in response",
     "High", "CWE-522"),

    # ---- Typeform ----
    (re.compile(r"\btfp_[a-zA-Z0-9_]{40,60}\b"),
     "Typeform Personal Access Token (tfp_) exposed in response",
     "High", "CWE-522"),

    # ---- Firebase FCM ----
    (re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"),
     "Firebase FCM legacy server key (AAAA...) exposed in response",
     "Medium", "CWE-200"),

    # ---- Azure Application Insights ----
    (re.compile(
        r"""instrumentationKey['":\s]+"""
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE,
    ),
     "Azure App Insights instrumentation key exposed in response",
     "Medium", "CWE-200"),

    # ---- Google OAuth access token ----
    (re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),
     "Google OAuth access token (ya29.) exposed in response",
     "High", "CWE-522"),

    # ==================================================================
    # Config / credential file patterns
    # ==================================================================

    # ---- WireGuard ----
    (re.compile(r"PrivateKey\s*=\s*[A-Za-z0-9+/]{43}="),
     "WireGuard private key exposed in response",
     "High", "CWE-321"),

    (re.compile(r"PresharedKey\s*=\s*[A-Za-z0-9+/]{43}="),
     "WireGuard preshared key exposed in response",
     "High", "CWE-321"),

    # ---- Age encryption ----
    (re.compile(r"\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b"),
     "Age encryption secret key (AGE-SECRET-KEY-1) exposed in response",
     "High", "CWE-321"),

    # ---- Azure Storage connection string ----
    (re.compile(
        r"(?:AccountName|SharedAccessKeyName)\s*=\s*[^;]{1,80}\s*;\s*"
        r"(?:AccountKey|SharedAccessKey)\s*=\s*[^;]{1,100}",
        re.IGNORECASE,
    ),
     "Azure Storage connection string with key exposed in response",
     "Critical", "CWE-522"),

    # ---- JDBC with password ----
    (re.compile(r"""jdbc:[a-z]+://[^\s'"]{5,}\?[^\s'"]*password=[^\s&'"]+"""),
     "JDBC connection string with embedded password exposed in response",
     "High", "CWE-522"),
]


def run_checks(
    url: str, body: str, headers: dict, cookies: dict
) -> list[dict]:
    """Scan response body for leaked tokens/credentials.

    Returns a list of finding dicts compatible with PassiveScanner output.
    """
    findings: list[dict] = []
    scan_body = body[:32000]  # limit scan area for performance

    for pat, desc, sev, cwe in _NUCLEI_TOKEN_PATTERNS:
        m = pat.search(scan_body)
        if m:
            matched = m.group(0)
            if len(matched) > 16:
                masked = matched[:8] + "..." + matched[-4:]
            else:
                masked = matched[:8] + "..."
            findings.append({
                "url": url,
                "category": "nuclei_token_disclosure",
                "finding": desc,
                "severity": sev,
                "evidence": f"Matched: {masked}",
                "remediation": (
                    "Rotate the exposed credential immediately "
                    "and remove from response"
                ),
                "cwe": cwe,
            })
    return findings


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"Loaded {len(_NUCLEI_TOKEN_PATTERNS)} nuclei token patterns.")
    print("All patterns compile OK.\n")

    # Synthetic test tokens (NOT real credentials)
    _test_vectors: list[tuple[str, str]] = [
        ("hvs." + "a" * 95, "HashiCorp Vault service token"),
        ("hvb." + "b" * 150, "HashiCorp Vault batch token"),
        ("abcdefghijklmn.atlasv1." + "x" * 65, "Terraform Cloud API token"),
        ("dapi" + "0a1b2c3d" * 4, "Databricks PAT"),
        ("dt0a12." + "A" * 24 + "." + "B" * 64, "Dynatrace API token"),
        ("dp.st." + "a" * 45, "Doppler service token"),
        ("access_token$production$" + "a" * 16 + "$" + "b" * 32,
         "Braintree/PayPal access token"),
        ("sq0csp-" + "a" * 43, "Square OAuth secret"),
        ("sq0atp-" + "a" * 22, "Square access token"),
        ("glsa_" + "a" * 32 + "_" + "b" * 8, "Grafana SA token"),
        ("glc_" + "a" * 40, "Grafana Cloud token"),
        ("dop_v1_" + "a" * 64, "DigitalOcean PAT"),
        ("doo_v1_" + "a" * 64, "DigitalOcean OAuth"),
        ("dor_v1_" + "a" * 64, "DigitalOcean refresh"),
        ("essu_" + "a" * 35, "Elastic Cloud API key"),
        ("dckr_pat_" + "a" * 27, "Docker Hub PAT"),
        ("sk." + "a" * 70, "Mapbox secret token"),
        ("tfp_" + "a" * 50, "Typeform PAT"),
        ("AAAAabcdefg:" + "A" * 140, "Firebase FCM server key"),
        ('instrumentationKey: "01234567-89ab-cdef-0123-456789abcdef"',
         "Azure App Insights key"),
        ("ya29." + "A" * 30, "Google OAuth access token"),
        ("PrivateKey = " + "A" * 43 + "=", "WireGuard private key"),
        ("PresharedKey = " + "B" * 43 + "=", "WireGuard preshared key"),
        ("AGE-SECRET-KEY-1" + "A" * 58, "Age encryption key"),
        ("AccountName=myaccount;AccountKey=" + "x" * 40,
         "Azure Storage connection string"),
        ("jdbc:mysql://db.example.com:3306/app?user=root&password=s3cret",
         "JDBC with password"),
    ]

    passed = 0
    failed = 0
    for token, label in _test_vectors:
        hits = run_checks("https://test.example.com", token, {}, {})
        if hits:
            print(f"  PASS  {label}")
            passed += 1
        else:
            print(f"  FAIL  {label} -- no match")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed out of "
          f"{len(_test_vectors)} test vectors.")
    if failed == 0:
        print("All tests passed.")
    else:
        raise SystemExit(f"{failed} test(s) failed!")
