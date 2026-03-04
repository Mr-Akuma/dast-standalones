"""
WebSocket Security Scanner — comprehensive WS endpoint testing.

Tests performed:
  1.  Endpoint discovery      — probe common WS paths + sitemap-discovered URLs
  2.  Cross-Site WS Hijacking — connect with evil Origin to test CSWSH
  3.  Auth bypass             — connect without credentials
  4.  SQL/NoSQL injection     — payloads through WS message frames
  5.  XSS injection           — script payloads via WS frames
  6.  Message flooding        — rapid burst to detect missing rate limits
  7.  Large frame abuse       — oversized payloads for buffer handling
  8.  Info disclosure         — malformed frames triggering verbose errors
  9.  Insecure transport      — ws:// when HTTPS is available
  10. Command injection       — OS command payloads through WS frames

Uses websocket-client (sync) — already available in project dependencies.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlparse, urljoin

try:
    import websocket as ws_client
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False


# ── Well-known WebSocket paths ───────────────────────────────────────────────

WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/", "/sockjs/",
    "/cable", "/hub", "/signalr", "/realtime", "/live",
    "/stream", "/feed", "/events", "/api/ws", "/api/websocket",
    "/api/stream", "/graphql",  # GraphQL subscriptions over WS
    "/ws/v1", "/ws/v2",
]

# ── Injection payloads ───────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "1' AND SLEEP(3)--",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "{{7*7}}",
]

CMDI_PAYLOADS = [
    "; id",
    "| cat /etc/passwd",
    "$(whoami)",
    "`uname -a`",
]

# ── Info disclosure patterns ─────────────────────────────────────────────────

INFO_LEAK_PATTERNS = [
    (re.compile(r"at\s+[\w.]+\([\w/\\]+\.(?:js|ts|py|java|go|rb):\d+", re.I), "stack_trace"),
    (re.compile(r"(?:\/home\/|\/var\/|\/usr\/|C:\\\\|\/app\/|\/src\/)\S+", re.I), "file_path"),
    (re.compile(r"\b(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b"), "internal_ip"),
    (re.compile(r'"debug"\s*:\s*true', re.I), "debug_mode"),
    (re.compile(r"(?:postgres|mysql|mongo|redis|sqlite)://", re.I), "connection_string"),
    (re.compile(r"(?:password|passwd|secret|token|api_?key)\s*[:=]\s*[\"']?\w+", re.I), "credential_leak"),
]


# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class WebSocketScanner:
    """
    Comprehensive WebSocket security scanner.

    Usage:
        scanner = WebSocketScanner(target, stop_event=evt)
        findings = scanner.scan()
    """

    def __init__(
        self,
        target:     str,
        stop_event  = None,
        on_finding: Callable | None = None,
        timeout:    int = 5,
        rate_limit: float = 0.05,
    ):
        self.target     = target.rstrip("/")
        self.stop_event = stop_event
        self.on_finding = on_finding
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self._alive_urls: list[str] = []

        # Derive ws:// / wss:// base from http target
        parsed = urlparse(self.target)
        self._scheme = "wss" if parsed.scheme == "https" else "ws"
        self._http_scheme = parsed.scheme
        self._origin = f"{parsed.scheme}://{parsed.netloc}"
        self._ws_base = f"{self._scheme}://{parsed.netloc}"

    def _stopped(self) -> bool:
        return self.stop_event is not None and self.stop_event.is_set()

    # ── Finding builder ──────────────────────────────────────────────────────

    def _finding(
        self,
        url: str, vuln_type: str, finding: str, severity: str,
        proof: str, payload: str, method: str = "WEBSOCKET",
        param: str = "frame", param_type: str = "websocket",
        resp_time_ms: float = 0.0, status_code: int = 101,
    ) -> dict:
        f = {
            "id":          f"ws_{uuid.uuid4().hex[:10]}",
            "url":         url,
            "method":      method,
            "param":       param,
            "param_type":  param_type,
            "vuln_type":   vuln_type,
            "finding":     finding,
            "severity":    severity,
            "proof":       (proof or "")[:500],
            "payload":     (payload or "")[:200],
            "resp_time_ms": resp_time_ms,
            "status_code": status_code,
            "ts":          datetime.now(timezone.utc).isoformat(),
        }
        if self.on_finding:
            try:
                self.on_finding(f)
            except Exception:
                pass
        return f

    # ── WS connection helper ─────────────────────────────────────────────────

    def _ws_connect(self, url: str, origin: str | None = None,
                    headers: dict | None = None, skip_auth: bool = False) -> "ws_client.WebSocket | None":
        """Try to establish a WebSocket connection. Returns WebSocket or None."""
        if not WS_AVAILABLE:
            return None
        try:
            ws = ws_client.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
            h = []
            if origin:
                h.append(f"Origin: {origin}")
            if headers:
                for k, v in headers.items():
                    h.append(f"{k}: {v}")
            ws.connect(url, header=h or None, timeout=self.timeout)
            return ws
        except Exception:
            return None

    def _ws_send_recv(self, ws, message: str, recv_timeout: float = 3.0) -> str | None:
        """Send a message and try to receive a response."""
        try:
            ws.settimeout(recv_timeout)
            ws.send(message)
            time.sleep(self.rate_limit)
            return ws.recv()
        except Exception:
            return None

    def _ws_close(self, ws):
        try:
            ws.close()
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ══════════════════════════════════════════════════════════════════════════

    def scan(self, extra_urls: list[str] | None = None) -> list[dict]:
        """
        Run full WebSocket security scan. Returns list of finding dicts.

        Args:
            extra_urls: Additional WS URLs (e.g., from Playwright crawling)
        """
        if not WS_AVAILABLE:
            return []

        findings: list[dict] = []

        # Phase 0: Discover alive WebSocket endpoints
        self._alive_urls = self._discover_endpoints(extra_urls or [])
        if not self._alive_urls:
            return findings

        for url in self._alive_urls:
            if self._stopped():
                break

            # Test 1: Cross-Site WebSocket Hijacking
            findings += self._test_cswsh(url)

            # Test 2: Auth bypass
            findings += self._test_auth_bypass(url)

            # Test 3: SQL/NoSQL injection
            findings += self._test_injection(url)

            # Test 4: XSS injection
            findings += self._test_xss(url)

            # Test 5: Message flooding / rate limiting
            findings += self._test_flooding(url)

            # Test 6: Large frame abuse
            findings += self._test_large_frame(url)

            # Test 7: Info disclosure
            findings += self._test_info_disclosure(url)

            # Test 8: Insecure transport
            findings += self._test_insecure_transport(url)

            # Test 9: Command injection
            findings += self._test_command_injection(url)

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # ENDPOINT DISCOVERY
    # ══════════════════════════════════════════════════════════════════════════

    def _discover_endpoints(self, extra_urls: list[str]) -> list[str]:
        alive = []

        # Build candidate list from known paths
        candidates = set()
        for path in WS_PATHS:
            candidates.add(f"{self._ws_base}{path}")

        # Add extra URLs (from crawling), converting http→ws scheme
        for u in extra_urls:
            parsed = urlparse(u)
            if parsed.scheme in ("ws", "wss"):
                candidates.add(u)
            elif any(kw in u.lower() for kw in ("websocket", "/ws", "socket", "cable", "signalr")):
                ws_scheme = "wss" if parsed.scheme == "https" else "ws"
                candidates.add(f"{ws_scheme}://{parsed.netloc}{parsed.path}")

        for url in candidates:
            if self._stopped():
                break
            ws = self._ws_connect(url, origin=self._origin)
            if ws:
                alive.append(url)
                self._ws_close(ws)

        return alive

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 1: CROSS-SITE WEBSOCKET HIJACKING (CSWSH)
    # ══════════════════════════════════════════════════════════════════════════

    def _test_cswsh(self, url: str) -> list[dict]:
        findings = []
        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]

        for origin in evil_origins:
            if self._stopped():
                break
            ws = self._ws_connect(url, origin=origin)
            if ws:
                # Connection accepted with evil origin — CSWSH vulnerability
                # Try to send a message to confirm it's fully functional
                resp = self._ws_send_recv(ws, '{"type":"ping"}')
                self._ws_close(ws)

                findings.append(self._finding(
                    url=url, vuln_type="ws_cswsh",
                    finding=f"Cross-Site WebSocket Hijacking — connection accepted with Origin: {origin} [{url}]",
                    severity="high",
                    proof=f"WS connection established with Origin: {origin}, response: {(resp or 'none')[:200]}",
                    payload=f"Origin: {origin}",
                ))
                break  # One finding is enough

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 2: AUTH BYPASS
    # ══════════════════════════════════════════════════════════════════════════

    def _test_auth_bypass(self, url: str) -> list[dict]:
        findings = []

        # Connect without any auth headers/cookies
        ws = self._ws_connect(url, skip_auth=True)
        if ws:
            # Try to send a query to confirm data access
            test_msgs = [
                '{"type":"subscribe","channel":"*"}',
                '{"action":"list"}',
                '{"query":"users"}',
            ]
            for msg in test_msgs:
                resp = self._ws_send_recv(ws, msg)
                if resp and len(resp) > 10:
                    # Got a substantive response without auth
                    body = resp[:300]
                    if "error" not in body.lower() and "unauthorized" not in body.lower():
                        findings.append(self._finding(
                            url=url, vuln_type="ws_auth_bypass",
                            finding=f"WebSocket accepts unauthenticated connections with data access [{url}]",
                            severity="high",
                            proof=f"Response without auth: {body}",
                            payload=msg,
                        ))
                        break
            self._ws_close(ws)

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 3: SQL/NoSQL INJECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _test_injection(self, url: str) -> list[dict]:
        findings = []

        ws = self._ws_connect(url, origin=self._origin)
        if not ws:
            return findings

        # SQL injection through JSON message frames
        for payload in SQLI_PAYLOADS:
            if self._stopped():
                break
            messages = [
                json.dumps({"query": payload}),
                json.dumps({"data": {"id": payload}}),
                json.dumps({"message": payload}),
            ]
            for msg in messages:
                t0 = time.time()
                resp = self._ws_send_recv(ws, msg)
                elapsed = time.time() - t0
                if not resp:
                    continue

                body = resp.lower()
                sql_errors = ["syntax error", "sql", "mysql", "postgres", "sqlite",
                              "ora-", "odbc", "unclosed quotation", "unterminated"]
                if any(e in body for e in sql_errors):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_sqli",
                        finding=f"SQL injection via WebSocket message frame [{url}]",
                        severity="high",
                        proof=resp[:300],
                        payload=payload,
                        resp_time_ms=elapsed * 1000,
                    ))
                    self._ws_close(ws)
                    return findings

                # Time-based detection
                if "SLEEP" in payload and elapsed > 2.5:
                    findings.append(self._finding(
                        url=url, vuln_type="ws_sqli",
                        finding=f"Blind SQL injection (time-based) via WebSocket frame [{url}]",
                        severity="high",
                        proof=f"SLEEP payload caused {elapsed:.1f}s delay",
                        payload=payload,
                        resp_time_ms=elapsed * 1000,
                    ))
                    self._ws_close(ws)
                    return findings

        # NoSQL injection
        for payload in NOSQL_PAYLOADS:
            if self._stopped():
                break
            msg = json.dumps({"filter": payload})
            resp = self._ws_send_recv(ws, msg)
            if resp:
                nosql_errors = ["$gt", "$where", "MongoError", "mongo"]
                if any(e in resp for e in nosql_errors):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_nosqli",
                        finding=f"NoSQL injection via WebSocket message frame [{url}]",
                        severity="high",
                        proof=resp[:300],
                        payload=payload,
                    ))
                    break

        self._ws_close(ws)
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 4: XSS INJECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _test_xss(self, url: str) -> list[dict]:
        findings = []

        ws = self._ws_connect(url, origin=self._origin)
        if not ws:
            return findings

        for payload in XSS_PAYLOADS:
            if self._stopped():
                break
            msg = json.dumps({"message": payload})
            resp = self._ws_send_recv(ws, msg)
            if resp and payload in resp:
                # Payload reflected unescaped
                findings.append(self._finding(
                    url=url, vuln_type="ws_xss",
                    finding=f"XSS payload reflected unescaped in WebSocket response [{url}]",
                    severity="high",
                    proof=resp[:300],
                    payload=payload,
                ))
                break

        self._ws_close(ws)
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 5: MESSAGE FLOODING / RATE LIMITING
    # ══════════════════════════════════════════════════════════════════════════

    def _test_flooding(self, url: str) -> list[dict]:
        findings = []

        ws = self._ws_connect(url, origin=self._origin)
        if not ws:
            return findings

        # Send 100 rapid messages
        msg = '{"type":"ping"}'
        success_count = 0
        t0 = time.time()

        try:
            ws.settimeout(1)
            for i in range(100):
                if self._stopped():
                    break
                try:
                    ws.send(msg)
                    success_count += 1
                except Exception:
                    break

            elapsed = time.time() - t0

            if success_count >= 90:
                findings.append(self._finding(
                    url=url, vuln_type="ws_no_rate_limit",
                    finding=f"WebSocket lacks rate limiting — {success_count}/100 rapid messages accepted in {elapsed:.1f}s [{url}]",
                    severity="medium",
                    proof=f"{success_count} messages sent in {elapsed:.1f}s without throttling or disconnect",
                    payload=f"{msg} x{success_count}",
                    resp_time_ms=elapsed * 1000,
                ))
        except Exception:
            pass

        self._ws_close(ws)
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 6: LARGE FRAME ABUSE
    # ══════════════════════════════════════════════════════════════════════════

    def _test_large_frame(self, url: str) -> list[dict]:
        findings = []

        ws = self._ws_connect(url, origin=self._origin)
        if not ws:
            return findings

        # Send 1MB payload
        large_payload = "A" * (1024 * 1024)
        msg = json.dumps({"data": large_payload})

        try:
            t0 = time.time()
            ws.send(msg)
            elapsed = time.time() - t0

            # Try to receive response
            ws.settimeout(3)
            try:
                resp = ws.recv()
                # If server accepted and processed 1MB without error
                if resp and "error" not in resp.lower():
                    findings.append(self._finding(
                        url=url, vuln_type="ws_large_frame",
                        finding=f"WebSocket accepts oversized frames (1MB) without rejection [{url}]",
                        severity="medium",
                        proof=f"1MB payload accepted in {elapsed:.1f}s, response: {(resp or '')[:200]}",
                        payload="1MB payload (1048576 bytes)",
                        resp_time_ms=elapsed * 1000,
                    ))
            except Exception:
                # Timeout or disconnect is actually the correct behavior
                pass
        except Exception:
            pass

        self._ws_close(ws)
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 7: INFORMATION DISCLOSURE
    # ══════════════════════════════════════════════════════════════════════════

    def _test_info_disclosure(self, url: str) -> list[dict]:
        findings = []

        ws = self._ws_connect(url, origin=self._origin)
        if not ws:
            return findings

        # Send malformed messages to trigger verbose errors
        malformed = [
            "{invalid json",
            '{"type": null, "data": undefined}',
            "",
            "\x00\x01\x02\x03",
            '{"__proto__": {"admin": true}}',
            "A" * 10000,
        ]

        for payload in malformed:
            if self._stopped():
                break
            resp = self._ws_send_recv(ws, payload)
            if not resp:
                continue

            for pattern, leak_type in INFO_LEAK_PATTERNS:
                matches = pattern.findall(resp)
                if matches:
                    findings.append(self._finding(
                        url=url, vuln_type="ws_info_disclosure",
                        finding=f"WebSocket error exposes {leak_type}: {matches[0][:80]} [{url}]",
                        severity="medium" if leak_type in ("stack_trace", "credential_leak", "connection_string") else "low",
                        proof=resp[:400],
                        payload=payload[:100],
                    ))
                    break

        self._ws_close(ws)
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 8: INSECURE TRANSPORT
    # ══════════════════════════════════════════════════════════════════════════

    def _test_insecure_transport(self, url: str) -> list[dict]:
        findings = []

        parsed = urlparse(url)
        if parsed.scheme == "ws" and self._http_scheme == "https":
            # Site uses HTTPS but WebSocket is unencrypted
            findings.append(self._finding(
                url=url, vuln_type="ws_insecure_transport",
                finding=f"WebSocket uses unencrypted ws:// while site uses HTTPS [{url}]",
                severity="high",
                proof=f"Site scheme: {self._http_scheme}, WS scheme: {parsed.scheme}",
                payload=url,
            ))
        elif parsed.scheme == "ws":
            # Check if wss:// is available for the same path
            wss_url = url.replace("ws://", "wss://", 1)
            ws = self._ws_connect(wss_url, origin=self._origin)
            if ws:
                self._ws_close(ws)
                findings.append(self._finding(
                    url=url, vuln_type="ws_insecure_transport",
                    finding=f"WebSocket uses ws:// but wss:// is available on same path [{url}]",
                    severity="medium",
                    proof=f"Both ws:// and wss:// endpoints respond — unencrypted transport unnecessary",
                    payload=url,
                ))

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 9: COMMAND INJECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _test_command_injection(self, url: str) -> list[dict]:
        findings = []

        ws = self._ws_connect(url, origin=self._origin)
        if not ws:
            return findings

        for payload in CMDI_PAYLOADS:
            if self._stopped():
                break
            messages = [
                json.dumps({"command": payload}),
                json.dumps({"cmd": payload}),
                json.dumps({"exec": payload}),
            ]
            for msg in messages:
                resp = self._ws_send_recv(ws, msg)
                if not resp:
                    continue

                # Check for command execution indicators
                cmdi_indicators = ["uid=", "root:", "/bin/", "Linux", "Darwin",
                                   "Windows", "SYSTEM", "x86_64", "amd64"]
                if any(indicator in resp for indicator in cmdi_indicators):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_cmdi",
                        finding=f"Command injection via WebSocket message frame [{url}]",
                        severity="critical",
                        proof=resp[:300],
                        payload=payload,
                    ))
                    self._ws_close(ws)
                    return findings

        self._ws_close(ws)
        return findings


# ── Convenience function ─────────────────────────────────────────────────────

def scan_websocket(target: str, stop_event=None, on_finding=None,
                   timeout: int = 5, extra_urls: list | None = None) -> list[dict]:
    """One-liner: scan a target for WebSocket vulnerabilities."""
    scanner = WebSocketScanner(
        target=target, stop_event=stop_event,
        on_finding=on_finding, timeout=timeout,
    )
    return scanner.scan(extra_urls=extra_urls)
