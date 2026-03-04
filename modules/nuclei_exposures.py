"""
Nuclei-mined exposure detection patterns.
Detects config files, credential stores, log files, and API specs in response bodies.

These checks complement passive.py without duplicating its existing detections
(private keys, source maps, .git/HEAD, stack traces, SQL errors, internal IPs, emails).
"""
from __future__ import annotations

import re

# ── Pre-compiled regexes ─────────────────────────────────────────────────────

_RE_GIT_CRED_URL = re.compile(r"url\s*=\s*https?://[^@:]+:[^@]+@")
_RE_DOCKER_COMPOSE_VERSION = re.compile(r"^version:\s*['\"]?\d", re.MULTILINE)
_RE_SQL_DUMP = re.compile(
    r"(?:DROP|CREATE)\s+TABLE|INSERT\s+INTO\s+\w+\s*\(", re.IGNORECASE | re.MULTILINE
)
_RE_SWAGGER_JSON = re.compile(r'"swagger"\s*:\s*"')
_RE_OPENAPI_JSON = re.compile(r'"openapi"\s*:\s*"')
_RE_ASYNCAPI = re.compile(r'"asyncapi"\s*:\s*"[0-9.]+"', re.IGNORECASE)


# ── Public API ───────────────────────────────────────────────────────────────

def run_checks(
    url: str,
    body: str,
    headers: dict,
    cookies: dict,
) -> list[dict]:
    """
    Scan an HTTP response for exposed files, configs, logs, and API specs.

    Returns a list of finding dicts, each containing:
        url, category, finding, severity, evidence, remediation, cwe
    """
    findings: list[dict] = []
    # Limit body size to avoid runaway regex on huge responses
    b = body[:32_000]
    ct = headers.get("content-type", headers.get("Content-Type", "")).lower()

    _check_config_credential_files(url, b, findings)
    _check_log_files(url, b, ct, findings)
    _check_infrastructure(url, b, findings)
    _check_api_specs(url, b, findings)

    return findings


# ── Helpers ──────────────────────────────────────────────────────────────────

def _finding(
    url: str,
    category: str,
    finding: str,
    severity: str,
    evidence: str,
    remediation: str,
    cwe: str,
) -> dict:
    """Build a normalised finding dict."""
    return {
        "url": url,
        "category": category,
        "finding": finding,
        "severity": severity,
        "evidence": evidence[:512],
        "remediation": remediation,
        "cwe": cwe,
    }


# ── GROUP 1: Config / Credential Files Exposed ──────────────────────────────

def _check_config_credential_files(url: str, b: str, findings: list[dict]) -> None:
    # 1. htpasswd file hashes
    if ":{SHA}" in b or ":$apr1$" in b or ":$2y$" in b:
        matched = next(
            (tok for tok in (":{SHA}", ":$apr1$", ":$2y$") if tok in b), ""
        )
        findings.append(_finding(
            url,
            "config_exposure",
            "Exposed htpasswd file containing password hashes",
            "High",
            f"Body contains htpasswd hash pattern: {matched}",
            "Remove htpasswd files from web-accessible paths and restrict access via server configuration.",
            "CWE-522",
        ))

    # 2. SSH authorized_keys
    if "ssh-ed25519" in b or "ssh-rsa AAAA" in b or "ecdsa-sha2-nistp" in b:
        matched = next(
            (tok for tok in ("ssh-ed25519", "ssh-rsa AAAA", "ecdsa-sha2-nistp") if tok in b), ""
        )
        findings.append(_finding(
            url,
            "config_exposure",
            "Exposed SSH authorized_keys file",
            "Medium",
            f"Body contains SSH public key pattern: {matched}",
            "Remove SSH key files from web-accessible paths. Restrict access to .ssh directories.",
            "CWE-200",
        ))

    # 3. Git config with embedded credentials
    m = _RE_GIT_CRED_URL.search(b)
    if m:
        findings.append(_finding(
            url,
            "credential_exposure",
            "Git config file contains embedded credentials in remote URL",
            "Medium",
            f"Body contains credential URL: {m.group()[:120]}",
            "Remove credentials from git remote URLs. Use SSH keys or credential helpers instead.",
            "CWE-522",
        ))

    # 4. Dockercfg / Docker config.json auth (requires BOTH conditions)
    if '"auth":' in b and '"email":' in b:
        findings.append(_finding(
            url,
            "credential_exposure",
            "Exposed Docker config.json or .dockercfg with registry authentication",
            "High",
            'Body contains Docker auth fields: "auth:" and "email:"',
            "Remove Docker config files from web-accessible paths. Use credential stores instead of plaintext configs.",
            "CWE-522",
        ))

    # 5. S3 config with keys (requires ALL three conditions)
    if "access_key" in b and "secret_key" in b and "bucket_location" in b:
        findings.append(_finding(
            url,
            "credential_exposure",
            "Exposed S3 configuration containing access keys",
            "High",
            "Body contains S3 config fields: access_key, secret_key, bucket_location",
            "Remove S3 config files from web-accessible paths. Use IAM roles instead of static credentials.",
            "CWE-522",
        ))

    # 6. Firebase JS config (requires ALL three conditions)
    if "apiKey:" in b and "authDomain:" in b and "storageBucket:" in b:
        findings.append(_finding(
            url,
            "config_exposure",
            "Exposed Firebase JavaScript configuration",
            "Medium",
            "Body contains Firebase config fields: apiKey, authDomain, storageBucket",
            "Restrict Firebase API keys with HTTP referrer restrictions. Enable Firebase App Check.",
            "CWE-200",
        ))

    # 7. Docker-compose config (requires regex match AND keyword)
    if _RE_DOCKER_COMPOSE_VERSION.search(b) and "services:" in b:
        findings.append(_finding(
            url,
            "config_exposure",
            "Exposed docker-compose configuration file",
            "Medium",
            "Body contains docker-compose structure: version + services block",
            "Remove docker-compose files from web-accessible paths. They may reveal internal service architecture.",
            "CWE-200",
        ))

    # 8. PuTTY PPK private key (requires BOTH conditions)
    if "PuTTY-User-Key-File" in b and "Encryption:" in b:
        findings.append(_finding(
            url,
            "credential_exposure",
            "Exposed PuTTY PPK private key file",
            "High",
            "Body contains PuTTY private key markers: PuTTY-User-Key-File and Encryption",
            "Remove private key files from web-accessible paths immediately. Rotate the exposed key pair.",
            "CWE-321",
        ))

    # 9. OpenSSH / PKCS8 / PGP private keys
    _priv_key_markers = (
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "BEGIN PGP PRIVATE KEY BLOCK",
    )
    for marker in _priv_key_markers:
        if marker in b:
            findings.append(_finding(
                url,
                "credential_exposure",
                f"Exposed private key file ({marker})",
                "High",
                f"Body contains private key header: {marker}",
                "Remove private key files from web-accessible paths immediately. Rotate the exposed key.",
                "CWE-321",
            ))
            break  # one finding per response is sufficient


# ── GROUP 2: Log Files Exposed ───────────────────────────────────────────────

def _check_log_files(url: str, b: str, ct: str, findings: list[dict]) -> None:
    # 10. Laravel application log (requires content-type check)
    if "text/plain" in ct:
        if "local.ERROR" in b or "InvalidArgumentException" in b:
            matched = "local.ERROR" if "local.ERROR" in b else "InvalidArgumentException"
            findings.append(_finding(
                url,
                "log_exposure",
                "Exposed Laravel application log file",
                "High",
                f"Body contains Laravel log pattern: {matched} (content-type: text/plain)",
                "Remove log files from web-accessible paths. Configure log storage outside the web root.",
                "CWE-532",
            ))

    # 11. NPM debug log (requires BOTH conditions)
    if "verbose cli" in b and "verbose stack" in b:
        findings.append(_finding(
            url,
            "log_exposure",
            "Exposed NPM debug log file",
            "Low",
            "Body contains NPM debug log patterns: 'verbose cli' and 'verbose stack'",
            "Remove npm-debug.log files from web-accessible paths. Add them to .gitignore.",
            "CWE-532",
        ))

    # 12. Rails / Django production log
    if "Started GET" in b or "Connecting to database specified by database.yml" in b:
        matched = (
            "Started GET" if "Started GET" in b
            else "Connecting to database specified by database.yml"
        )
        findings.append(_finding(
            url,
            "log_exposure",
            "Exposed Rails/Django production log file",
            "Info",
            f"Body contains production log pattern: {matched}",
            "Remove production log files from web-accessible paths. Store logs outside the web root.",
            "CWE-532",
        ))


# ── GROUP 3: Infrastructure Exposure ─────────────────────────────────────────

def _check_infrastructure(url: str, b: str, findings: list[dict]) -> None:
    # 13. Prometheus metrics endpoint
    _prom_markers = (
        "cpu_seconds_total",
        "process_virtual_memory_bytes",
        "http_request_duration_seconds",
    )
    for marker in _prom_markers:
        if marker in b:
            findings.append(_finding(
                url,
                "infrastructure_exposure",
                "Exposed Prometheus metrics endpoint",
                "Medium",
                f"Body contains Prometheus metric: {marker}",
                "Restrict access to /metrics endpoints. Use authentication or network-level access controls.",
                "CWE-200",
            ))
            break

    # 14. Grafana metrics (requires BOTH conditions)
    if "grafana_build_info" in b and "# TYPE grafana_" in b:
        findings.append(_finding(
            url,
            "infrastructure_exposure",
            "Exposed Grafana internal metrics",
            "Low",
            "Body contains Grafana metric patterns: grafana_build_info and # TYPE grafana_",
            "Restrict access to Grafana metrics endpoints. Disable public metric exposure.",
            "CWE-200",
        ))

    # 15. SQL dump content
    m = _RE_SQL_DUMP.search(b)
    if m:
        findings.append(_finding(
            url,
            "infrastructure_exposure",
            "Exposed SQL dump file containing database structure or data",
            "Medium",
            f"Body contains SQL dump statement: {m.group()[:120]}",
            "Remove SQL dump files from web-accessible paths. Store database backups securely off-server.",
            "CWE-200",
        ))


# ── GROUP 4: API Specification Exposure ──────────────────────────────────────

def _check_api_specs(url: str, b: str, findings: list[dict]) -> None:
    # 16. Swagger / OpenAPI spec
    if (
        _RE_SWAGGER_JSON.search(b)
        or _RE_OPENAPI_JSON.search(b)
        or 'id="swagger-ui"' in b
    ):
        findings.append(_finding(
            url,
            "api_spec_exposure",
            "Exposed Swagger/OpenAPI specification or UI",
            "Info",
            "Body contains Swagger/OpenAPI spec markers",
            "Restrict access to API documentation in production. Use authentication for spec endpoints.",
            "CWE-200",
        ))

    # 17. WADL API descriptor
    if "http://wadl.dev.java.net/2009/02" in b:
        findings.append(_finding(
            url,
            "api_spec_exposure",
            "Exposed WADL API descriptor",
            "Info",
            "Body contains WADL namespace: http://wadl.dev.java.net/2009/02",
            "Restrict access to WADL descriptors in production environments.",
            "CWE-200",
        ))

    # 18. AsyncAPI spec
    if _RE_ASYNCAPI.search(b):
        findings.append(_finding(
            url,
            "api_spec_exposure",
            "Exposed AsyncAPI specification",
            "Info",
            "Body contains AsyncAPI version declaration",
            "Restrict access to AsyncAPI specifications in production environments.",
            "CWE-200",
        ))

    # 19. Postman collection (requires ALL three conditions)
    if '"info":' in b and '"item":[' in b and '"_postman_id"' in b:
        findings.append(_finding(
            url,
            "api_spec_exposure",
            "Exposed Postman API collection",
            "Low",
            'Body contains Postman collection markers: "info", "item", "_postman_id"',
            "Remove Postman collections from web-accessible paths. They may contain authentication tokens and internal endpoints.",
            "CWE-200",
        ))

    # 20. WSDL service definition
    if "<wsdl:definitions" in b or '<definitions xmlns="http://schemas.xmlsoap.org' in b:
        matched = (
            "<wsdl:definitions" if "<wsdl:definitions" in b
            else '<definitions xmlns="http://schemas.xmlsoap.org'
        )
        findings.append(_finding(
            url,
            "api_spec_exposure",
            "Exposed WSDL web service definition",
            "Info",
            f"Body contains WSDL marker: {matched}",
            "Restrict access to WSDL endpoints in production. Disable automatic WSDL generation.",
            "CWE-200",
        ))
