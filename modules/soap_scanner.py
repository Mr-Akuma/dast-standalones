"""
SOAP Scanner — active vulnerability testing for SOAP/WSDL web services.
Equivalent to ZAP's SOAP Support add-on + active scan rules.

Parses WSDL 1.1 documents, enumerates operations, and tests each
parameter for SQLi, XXE, XSS, and authentication bypass.
"""
from __future__ import annotations

import logging
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SOAPOperation:
    """Represents a single SOAP operation parsed from a WSDL document."""

    name: str
    endpoint: str
    soap_action: str
    namespace: str
    input_params: list[str]
    output_params: list[str]

    def to_input_surface(self, base_url: str = ""):
        """
        Convert this SOAP operation into a fuzzer-ready InputSurface.

        The surface targets the first input parameter (or a generic 'param' if
        the operation has no declared params).  The body_template contains a
        minimal SOAP 1.1 envelope with a placeholder that the fuzzer replaces.

        Args:
            base_url: Override the endpoint host (e.g. "https://prod.example.com").
                      If empty, uses self.endpoint as-is.
        """
        from .crawler import InputSurface

        url = base_url.rstrip("/") + "/" if base_url else self.endpoint
        if base_url and self.endpoint:
            from urllib.parse import urlparse
            parsed = urlparse(self.endpoint)
            base_parsed = urlparse(base_url.rstrip("/"))
            url = base_parsed.scheme + "://" + base_parsed.netloc + parsed.path

        param = self.input_params[0] if self.input_params else "param"
        ns    = self.namespace or "http://tempuri.org/"

        body_template = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:tns="{ns}">'
            "<soap:Body>"
            f"<tns:{self.name}>"
            f"<tns:{param}>{{FUZZ}}</tns:{param}>"
            f"</tns:{self.name}>"
            "</soap:Body>"
            "</soap:Envelope>"
        )

        headers = {}
        if self.soap_action:
            headers["SOAPAction"] = f'"{self.soap_action}"'

        return InputSurface(
            url=url,
            method="POST",
            param=param,
            param_type="xml",
            original_value="test",
            headers=headers,
            body_template=body_template,
            content_type="text/xml; charset=utf-8",
        )


@dataclass
class SOAPFinding:
    """A vulnerability finding from SOAP service testing."""

    url: str
    operation_name: str
    param_name: str
    test_type: str
    finding: str
    severity: str
    evidence: str
    cwe: str
    agent_id: str = "soap_scanner"
    icon: str = "\U0001f9fc"  # soap emoji

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SOAPScanner:
    """Active SOAP/WSDL vulnerability scanner."""

    _WSDL_NS = {
        "wsdl": "http://schemas.xmlsoap.org/wsdl/",
        "soap": "http://schemas.xmlsoap.org/wsdl/soap/",
        "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
        "xsd": "http://www.w3.org/2001/XMLSchema",
    }

    # SQL error signatures that indicate injectable parameters
    _SQL_ERROR_PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"ORA-\d{5}",
            r"MySQL",
            r"syntax error",
            r"SQLSTATE",
            r"Unclosed quotation mark",
            r"microsoft OLE DB",
            r"ODBC SQL Server Driver",
            r"PostgreSQL.*ERROR",
            r"SQLite3?::SQLException",
            r"java\.sql\.SQLException",
            r"com\.mysql\.jdbc",
            r"DB2 SQL error",
            r"quoted string not properly terminated",
        ]
    ]

    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # WSDL parsing
    # ------------------------------------------------------------------

    def parse_wsdl(
        self, wsdl_url: str, session: requests.Session
    ) -> list[SOAPOperation]:
        """Fetch and parse a WSDL 1.1 document, returning discovered operations."""
        try:
            resp = session.get(wsdl_url, timeout=self.timeout)
            resp.raise_for_status()
            root = ET.fromstring(resp.content)
        except Exception as exc:
            logger.debug("WSDL parse error for %s: %s", wsdl_url, exc)
            return []

        ns = self._WSDL_NS
        target_namespace = root.attrib.get("targetNamespace", "")

        # ---- resolve endpoint from service/port/soap:address -----------
        endpoint = ""
        for port in root.findall(".//wsdl:service/wsdl:port", ns):
            addr = port.find("soap:address", ns)
            if addr is None:
                addr = port.find("soap12:address", ns)
            if addr is not None:
                endpoint = addr.attrib.get("location", "")
                break

        if not endpoint:
            logger.debug("No endpoint found in WSDL %s", wsdl_url)
            return []

        # ---- build message-name → param-list map ----------------------
        messages: dict[str, list[str]] = {}
        for msg_el in root.findall("wsdl:message", ns):
            msg_name = msg_el.attrib.get("name", "")
            parts = [
                p.attrib.get("name", "")
                for p in msg_el.findall("wsdl:part", ns)
                if p.attrib.get("name")
            ]
            if msg_name:
                messages[msg_name] = parts

        # ---- extract operations from portType -------------------------
        operations: list[SOAPOperation] = []
        for port_type in root.findall("wsdl:portType", ns):
            for op_el in port_type.findall("wsdl:operation", ns):
                op_name = op_el.attrib.get("name", "")
                if not op_name:
                    continue

                # input params
                input_el = op_el.find("wsdl:input", ns)
                input_params: list[str] = []
                if input_el is not None:
                    msg_ref = input_el.attrib.get("message", "")
                    msg_local = msg_ref.split(":")[-1] if ":" in msg_ref else msg_ref
                    input_params = messages.get(msg_local, [])

                # output params
                output_el = op_el.find("wsdl:output", ns)
                output_params: list[str] = []
                if output_el is not None:
                    msg_ref = output_el.attrib.get("message", "")
                    msg_local = msg_ref.split(":")[-1] if ":" in msg_ref else msg_ref
                    output_params = messages.get(msg_local, [])

                # resolve soapAction from binding
                soap_action = self._resolve_soap_action(root, op_name, ns)

                operations.append(
                    SOAPOperation(
                        name=op_name,
                        endpoint=endpoint,
                        soap_action=soap_action,
                        namespace=target_namespace,
                        input_params=input_params,
                        output_params=output_params,
                    )
                )

        return operations

    @staticmethod
    def _resolve_soap_action(
        root: ET.Element, operation_name: str, ns: dict[str, str]
    ) -> str:
        """Look up the soapAction for a given operation name from bindings."""
        for binding in root.findall("wsdl:binding", ns):
            for op_el in binding.findall("wsdl:operation", ns):
                if op_el.attrib.get("name") == operation_name:
                    soap_op = op_el.find("soap:operation", ns)
                    if soap_op is None:
                        soap_op = op_el.find("soap12:operation", ns)
                    if soap_op is not None:
                        return soap_op.attrib.get("soapAction", "")
        return ""

    # ------------------------------------------------------------------
    # SOAP envelope helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_envelope(
        namespace: str,
        operation_name: str,
        param_name: str,
        param_value: str,
    ) -> str:
        """Build a minimal SOAP 1.1 envelope XML string."""
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{namespace}">\n'
            "  <soap:Body>\n"
            f"    <tns:{operation_name}>\n"
            f"      <tns:{param_name}>{param_value}</tns:{param_name}>\n"
            f"    </tns:{operation_name}>\n"
            "  </soap:Body>\n"
            "</soap:Envelope>"
        )

    def _send_soap(
        self,
        session: requests.Session,
        operation: SOAPOperation,
        param_name: str,
        payload: str,
    ) -> tuple[Optional[requests.Response], float]:
        """Send a SOAP request and return (response, elapsed_ms)."""
        envelope = self._build_envelope(
            operation.namespace, operation.name, param_name, payload
        )
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{operation.soap_action}"',
        }
        try:
            start = time.monotonic()
            resp = session.post(
                operation.endpoint,
                data=envelope.encode("utf-8"),
                headers=headers,
                timeout=self.timeout,
            )
            elapsed_ms = (time.monotonic() - start) * 1000.0
            return resp, elapsed_ms
        except Exception as exc:
            logger.debug(
                "SOAP request failed for %s/%s: %s",
                operation.name,
                param_name,
                exc,
            )
            return None, 0.0

    # ------------------------------------------------------------------
    # Active test methods
    # ------------------------------------------------------------------

    def test_sqli(
        self, session: requests.Session, operation: SOAPOperation
    ) -> list[SOAPFinding]:
        """Test each parameter for SQL injection."""
        findings: list[SOAPFinding] = []
        payloads = ["' OR '1'='1", "' OR 1=1--", "1; DROP TABLE--"]

        for param in operation.input_params:
            for payload in payloads:
                resp, _ = self._send_soap(session, operation, param, payload)
                if resp is None:
                    continue
                body = resp.text
                for pattern in self._SQL_ERROR_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        findings.append(
                            SOAPFinding(
                                url=operation.endpoint,
                                operation_name=operation.name,
                                param_name=param,
                                test_type="SQL Injection",
                                finding=(
                                    f"SQL error detected in parameter '{param}' "
                                    f"of operation '{operation.name}'"
                                ),
                                severity="High",
                                evidence=match.group(0)[:200],
                                cwe="CWE-89",
                            )
                        )
                        break  # one finding per param per payload is enough
        return findings

    def test_xxe(
        self, session: requests.Session, operation: SOAPOperation
    ) -> list[SOAPFinding]:
        """Test each parameter for XML External Entity injection."""
        findings: list[SOAPFinding] = []
        xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe "xxe_test_marker">]>'
            "<root>&xxe;</root>"
        )

        for param in operation.input_params:
            resp, _ = self._send_soap(session, operation, param, xxe_payload)
            if resp is None:
                continue
            if "xxe_test_marker" in resp.text:
                findings.append(
                    SOAPFinding(
                        url=operation.endpoint,
                        operation_name=operation.name,
                        param_name=param,
                        test_type="XXE Injection",
                        finding=(
                            f"XXE entity resolved in parameter '{param}' "
                            f"of operation '{operation.name}'"
                        ),
                        severity="Critical",
                        evidence="xxe_test_marker reflected in response",
                        cwe="CWE-611",
                    )
                )
        return findings

    def test_auth_bypass(
        self, session: requests.Session, operation: SOAPOperation
    ) -> list[SOAPFinding]:
        """Test for authentication bypass by sending unauthenticated requests."""
        findings: list[SOAPFinding] = []

        # Build a bare envelope with a dummy param value (no WS-Security)
        param_name = operation.input_params[0] if operation.input_params else "test"
        envelope = self._build_envelope(
            operation.namespace, operation.name, param_name, "auth_bypass_probe"
        )
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{operation.soap_action}"',
        }

        try:
            # Use a clean session without any stored auth state
            clean_session = requests.Session()
            resp = clean_session.post(
                operation.endpoint,
                data=envelope.encode("utf-8"),
                headers=headers,
                timeout=self.timeout,
            )
        except Exception:
            return findings

        if resp.status_code == 200:
            body_lower = resp.text.lower()
            if "fault" not in body_lower and "unauthorized" not in body_lower:
                findings.append(
                    SOAPFinding(
                        url=operation.endpoint,
                        operation_name=operation.name,
                        param_name="(no auth)",
                        test_type="Authentication Bypass",
                        finding=(
                            f"Operation '{operation.name}' returned 200 OK "
                            "without authentication credentials"
                        ),
                        severity="High",
                        evidence=f"HTTP 200 with no Fault element (length={len(resp.text)})",
                        cwe="CWE-287",
                    )
                )
        return findings

    def test_xss(
        self, session: requests.Session, operation: SOAPOperation
    ) -> list[SOAPFinding]:
        """Test each parameter for reflected cross-site scripting."""
        findings: list[SOAPFinding] = []
        payloads = [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
        ]

        for param in operation.input_params:
            for payload in payloads:
                resp, _ = self._send_soap(session, operation, param, payload)
                if resp is None:
                    continue
                if payload in resp.text:
                    findings.append(
                        SOAPFinding(
                            url=operation.endpoint,
                            operation_name=operation.name,
                            param_name=param,
                            test_type="Cross-Site Scripting",
                            finding=(
                                f"XSS payload reflected in parameter '{param}' "
                                f"of operation '{operation.name}'"
                            ),
                            severity="Medium",
                            evidence=payload[:120],
                            cwe="CWE-79",
                        )
                    )
                    break  # one finding per param is sufficient
        return findings

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan(
        self, session: requests.Session, wsdl_url: str
    ) -> list[SOAPFinding]:
        """Run all active SOAP vulnerability tests against a WSDL endpoint."""
        operations = self.parse_wsdl(wsdl_url, session)
        if not operations:
            logger.debug("No operations found in %s — skipping SOAP scan", wsdl_url)
            return []

        all_findings: list[SOAPFinding] = []
        seen: set[tuple[str, str, str, str]] = set()

        for op in operations:
            for test_fn in (
                self.test_sqli,
                self.test_xxe,
                self.test_auth_bypass,
                self.test_xss,
            ):
                for finding in test_fn(session, op):
                    key = (
                        finding.operation_name,
                        finding.param_name,
                        finding.test_type,
                        finding.cwe,
                    )
                    if key not in seen:
                        seen.add(key)
                        all_findings.append(finding)

        return all_findings
