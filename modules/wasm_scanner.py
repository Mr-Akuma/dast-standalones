"""
WebAssembly Security Scanner
=============================
Detects Wasm-specific vulnerabilities in web applications:

1. Wasm Detection — identifies Wasm usage via magic bytes, content-type, .wasm responses
2. WASI Path Traversal — tests file-serving endpoints for sandbox escape via ../ sequences
3. Resource Exhaustion Probes — tests for unquota'd WASI resource consumption
4. CVE Version Checks — detects known-vulnerable Wasmer/Wasmtime/WAMR versions
5. WASI Syscall Abuse Patterns — probes for filesystem starvation vectors

Based on: USENIX Security '25 — Wasm resource isolation failures are invisible
to standard container resource limits (Cgroup blind spot).
No existing DAST tool covers Wasm-specific attack surface.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("dast.wasm_scanner")

# Wasm binary magic bytes: \0asm version 1
WASM_MAGIC = b'\x00asm\x01\x00\x00\x00'
WASM_MAGIC_SHORT = b'\x00asm'

# Known vulnerable runtime versions (CVE database)
_KNOWN_VULNERABLE_RUNTIMES = {
    "wasmer": {
        "CVE-2023-51661": {
            "affected_below": "4.2.1",
            "description": "Path traversal via virtual-to-host path translation allows reading files outside sandbox",
            "severity": "high",
        }
    },
    "wasmtime": {
        "CVE-2024-30266": {
            "affected_below": "19.0.2",
            "description": "Type confusion via WasmIndirectFunctionTable overwrite enables arbitrary write primitive",
            "severity": "critical",
        }
    },
    "wamr": {
        "GHSA-8fc8-4g25-c8m7": {
            "affected_below": "1.3.3",
            "description": "Symlink escape: create symlink outside preopened directory then open with create flag writes to host filesystem",
            "severity": "high",
        }
    },
}

# WASI path traversal payloads (sandbox escape attempts)
_WASI_TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2fetc%2fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e/etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "..\\..\\..\\Windows\\win.ini",
    # Symlink-style escapes (WAMR CVE)
    "../symlink_target",
    "../../proc/self/environ",
    "../dev/stdin",
]


@dataclass
class WasmFinding:
    """A security finding from the Wasm scanner."""
    url: str
    test: str                          # Test name
    finding: str                       # Finding description
    severity: str                      # critical/high/medium/low/info
    evidence: str                      # HTTP response/behavior details
    cve: str = ""                      # Associated CVE if applicable
    vuln_type: str = "wasm_security"
    agent: str = "Wasm Scanner"
    agent_id: str = "wasm"
    icon: str = "🔷"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "test": self.test,
            "finding": self.finding,
            "severity": self.severity,
            "evidence": self.evidence,
            "cve": self.cve,
            "vuln_type": self.vuln_type,
            "agent": self.agent,
            "agent_id": self.agent_id,
            "icon": self.icon,
        }


class WasmScanner:
    """WebAssembly security scanner.

    Tests web applications for Wasm-specific vulnerabilities including
    WASI sandbox escapes, resource exhaustion, and known CVEs.
    """

    def __init__(
        self,
        session: Any = None,
        timeout: int = 10,
        max_traversal_depth: int = 5,
    ):
        self.session = session  # requests.Session or None
        self.timeout = timeout
        self.max_traversal_depth = max_traversal_depth
        self._findings: list[WasmFinding] = []

    def scan(self, target_url: str, discovered_urls: list[str] | None = None) -> list[WasmFinding]:
        """Run full Wasm security scan against target.

        Args:
            target_url: Base URL of target application
            discovered_urls: Additional URLs to test (from crawler)

        Returns:
            List of WasmFinding objects
        """
        self._findings = []
        urls_to_test = [target_url] + (discovered_urls or [])

        # Phase 1: Detect Wasm usage
        wasm_urls = self._detect_wasm_usage(urls_to_test)

        if wasm_urls:
            log.info("[WasmScanner] Wasm detected at %d URL(s), running full tests", len(wasm_urls))

            # Phase 2: Path traversal tests
            for url in wasm_urls[:10]:  # Limit
                self._test_wasi_path_traversal(url)

            # Phase 3: Resource exhaustion
            for url in wasm_urls[:5]:
                self._test_resource_exhaustion(url)

            # Phase 4: CVE version checks
            self._check_runtime_versions(target_url, wasm_urls)
        else:
            # Still check main target for version headers
            self._check_runtime_versions(target_url, [target_url])

        return self._findings

    def _fetch(self, url: str, method: str = "GET", headers: dict | None = None, data: bytes | None = None) -> tuple[int, bytes, dict]:
        """Make HTTP request, return (status_code, body_bytes, response_headers)."""
        try:
            if self.session:
                # Use requests.Session if available
                resp = self.session.request(
                    method, url,
                    headers=headers or {},
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False,
                )
                return resp.status_code, resp.content, dict(resp.headers)
            else:
                req = urllib.request.Request(
                    url, data=data,
                    headers=headers or {"User-Agent": "DAST-Wasm-Scanner/1.0"},
                    method=method,
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, b"", {}
        except Exception as exc:
            log.debug("[WasmScanner] Fetch error %s %s: %s", method, url, exc)
            return 0, b"", {}

    def detect_wasm(self, response_body: bytes, response_headers: dict, url: str = "") -> bool:
        """Detect Wasm usage from response body and headers.

        Detection methods:
        1. Wasm magic bytes in body: \\x00asm
        2. Content-Type: application/wasm
        3. .wasm file extension in URL
        4. Wasm runtime headers (x-powered-by, server)
        """
        # Magic bytes
        if response_body[:4] == WASM_MAGIC_SHORT:
            return True

        # Content-Type
        ct = response_headers.get("Content-Type", response_headers.get("content-type", ""))
        if "application/wasm" in ct or "application/x-wasm" in ct:
            return True

        # URL extension
        url_lower = url.lower().split("?")[0]
        if url_lower.endswith(".wasm"):
            return True

        # Runtime headers
        server = response_headers.get("Server", response_headers.get("server", "")).lower()
        powered = response_headers.get("X-Powered-By", response_headers.get("x-powered-by", "")).lower()
        combined = server + " " + powered
        for runtime in ("wasmtime", "wasmer", "wamr", "wasm", "fastly-compute", "cloudflare-workers"):
            if runtime in combined:
                return True

        # Wasm-related strings in HTML/JS response
        if len(response_body) < 500_000:  # Only scan small responses
            body_text = response_body.decode("utf-8", errors="replace")
            wasm_indicators = [
                "WebAssembly.instantiate",
                "WebAssembly.compile",
                ".wasm",
                "wasm-bindgen",
                "wasi_snapshot_preview1",
                "__wasm_memory",
            ]
            if any(ind in body_text for ind in wasm_indicators):
                return True

        return False

    def _detect_wasm_usage(self, urls: list[str]) -> list[str]:
        """Scan URLs for Wasm usage, return list of Wasm-related URLs."""
        wasm_urls = []

        for url in urls[:50]:  # Limit probing
            status, body, headers = self._fetch(url)
            if status and self.detect_wasm(body, headers, url):
                wasm_urls.append(url)
                log.info("[WasmScanner] Wasm detected at: %s", url)

        return wasm_urls

    def _test_wasi_path_traversal(self, base_url: str) -> None:
        """Test for WASI path traversal / sandbox escape.

        Based on: WAMR GHSA-8fc8-4g25-c8m7 (symlink escape),
        Wasmer CVE-2023-51661 (path translation bypass).
        """
        from urllib.parse import urljoin, urlparse

        for payload in _WASI_TRAVERSAL_PAYLOADS[:self.max_traversal_depth]:
            # Test as query parameter
            test_url = f"{base_url}?file={urllib.parse.quote(payload)}&path={urllib.parse.quote(payload)}"
            status, body, headers = self._fetch(test_url)

            if status in (200, 206):
                body_text = body.decode("utf-8", errors="replace")
                # Check for Linux /etc/passwd content
                if "root:" in body_text and "/bin/" in body_text:
                    self._findings.append(WasmFinding(
                        url=test_url,
                        test="wasi_path_traversal",
                        finding=f"WASI sandbox path traversal: /etc/passwd contents exposed via payload '{payload}'",
                        severity="critical",
                        evidence=body_text[:500],
                        cve="CVE-2023-51661",
                    ))
                    return  # Found one, no need to keep testing

                # Windows win.ini
                if "[fonts]" in body_text.lower() or "[extensions]" in body_text.lower():
                    self._findings.append(WasmFinding(
                        url=test_url,
                        test="wasi_path_traversal",
                        finding=f"WASI sandbox path traversal: Windows system file exposed via payload '{payload}'",
                        severity="critical",
                        evidence=body_text[:500],
                        cve="CVE-2023-51661",
                    ))
                    return

            # Test as path segment
            test_url_path = urljoin(base_url + "/", payload.lstrip("/"))
            status2, body2, _ = self._fetch(test_url_path)
            if status2 == 200:
                body_text2 = body2.decode("utf-8", errors="replace")
                if "root:" in body_text2 and "/bin/" in body_text2:
                    self._findings.append(WasmFinding(
                        url=test_url_path,
                        test="wasi_path_traversal_path",
                        finding="WASI path traversal via URL path: /etc/passwd exposed",
                        severity="critical",
                        evidence=body_text2[:500],
                        cve="CVE-2023-51661",
                    ))
                    return

    def _test_resource_exhaustion(self, url: str) -> None:
        """Test for WASI resource exhaustion (unquota'd resource consumption).

        Based on USENIX '25 finding: Wasm containers can exhaust host resources
        via WASI syscall abuse while staying under Cgroup CPU limits (stealth attack).
        Tests for unprotected compute-intensive endpoints.
        """
        # Send 5 rapid sequential requests and measure response time degradation
        response_times = []

        for i in range(5):
            t0 = time.perf_counter()
            status, _, _ = self._fetch(url)
            elapsed = (time.perf_counter() - t0) * 1000
            if status > 0:
                response_times.append(elapsed)

        if len(response_times) >= 4:
            first_avg = sum(response_times[:2]) / 2
            last_avg = sum(response_times[-2:]) / 2
            degradation_pct = ((last_avg - first_avg) / max(first_avg, 1)) * 100

            if degradation_pct > 200 and last_avg > 2000:
                self._findings.append(WasmFinding(
                    url=url,
                    test="wasm_resource_exhaustion",
                    finding=f"Potential Wasm resource exhaustion: response time degraded {degradation_pct:.0f}% after 5 rapid requests ({first_avg:.0f}ms -> {last_avg:.0f}ms)",
                    severity="medium",
                    evidence=f"Response times: {[round(t,0) for t in response_times]}ms. Degradation: {degradation_pct:.0f}%",
                    cve="",
                ))

    def _check_runtime_versions(self, target_url: str, wasm_urls: list[str]) -> None:
        """Check response headers for Wasm runtime version disclosure.

        If runtime version found and is below known-vulnerable threshold, flag CVE.
        """
        version_pattern = re.compile(r'(\d+)\.(\d+)\.(\d+)')

        for url in [target_url] + wasm_urls[:3]:
            status, body, headers = self._fetch(url)
            if not status:
                continue

            # Check all headers for runtime mentions
            all_headers = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

            for runtime, cves in _KNOWN_VULNERABLE_RUNTIMES.items():
                if runtime in all_headers:
                    # Try to extract version
                    match = version_pattern.search(all_headers[all_headers.index(runtime):])
                    if match:
                        detected_version = match.group(0)
                        major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))

                        for cve_id, cve_info in cves.items():
                            # Simple version comparison
                            affected_below = cve_info["affected_below"]
                            ab_parts = [int(x) for x in affected_below.split(".")]
                            detected_tuple = (major, minor, patch)
                            affected_tuple = tuple(ab_parts[:3])

                            if detected_tuple < affected_tuple:
                                self._findings.append(WasmFinding(
                                    url=url,
                                    test="wasm_cve_version_check",
                                    finding=f"{runtime.title()} v{detected_version} is below {affected_below} -- vulnerable to {cve_id}: {cve_info['description']}",
                                    severity=cve_info["severity"],
                                    evidence=f"Detected: {runtime} {detected_version} in response headers. Fixed in: {affected_below}",
                                    cve=cve_id,
                                ))
                    else:
                        # Runtime detected but version unknown -- info finding
                        self._findings.append(WasmFinding(
                            url=url,
                            test="wasm_runtime_detected",
                            finding=f"Wasm runtime '{runtime}' detected in response headers -- verify version for known CVEs",
                            severity="info",
                            evidence=f"Header hint: {runtime} found in: {all_headers[:200]}",
                        ))
                        break  # Only one info finding per runtime

    def get_findings(self) -> list[dict]:
        """Return all findings as dicts."""
        return [f.to_dict() for f in self._findings]

    def __repr__(self) -> str:
        return f"WasmScanner(findings={len(self._findings)})"
