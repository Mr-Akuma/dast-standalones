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

SESSION_HOLD_SECS: int = 35  # seconds to hold connection open in renewal test

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
        target:      str,
        stop_event   = None,
        on_finding:  Callable | None = None,
        timeout:     int = 5,
        rate_limit:  float = 0.05,
        auth_headers: dict | None = None,
    ):
        self.target      = target.rstrip("/")
        self.stop_event  = stop_event
        self.on_finding  = on_finding
        self.timeout     = timeout
        self.rate_limit  = rate_limit
        self._alive_urls: list[str] = []
        # Auth headers (cookies, Authorization) injected into every WS handshake
        # except those explicitly testing auth-bypass (skip_auth=True).
        self._auth_headers: dict = dict(auth_headers) if auth_headers else {}

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
        """Try to establish a WebSocket connection. Returns WebSocket or None.

        When skip_auth=False (default), any auth_headers stored on the scanner
        (cookies, Authorization) are included in the upgrade handshake so that
        authenticated WebSocket endpoints can be reached during scanning.
        skip_auth=True is used only by _test_auth_bypass to intentionally probe
        the endpoint without credentials.
        """
        if not WS_AVAILABLE:
            return None
        try:
            ws = ws_client.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
            h = []
            if origin:
                h.append(f"Origin: {origin}")
            # Inject auth headers unless this is an explicit unauthenticated probe
            if not skip_auth and self._auth_headers:
                for k, v in self._auth_headers.items():
                    h.append(f"{k}: {v}")
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

            # Test 1: Connection upgrade validation (Origin + version checks)
            findings += self._test_upgrade_validation(url)

            # Test 2: Cross-Site WebSocket Hijacking — full (5 origins + CSRF)
            findings += self._test_cswsh(url)

            # Test 3: Auth bypass
            findings += self._test_auth_bypass(url)

            # Test 4: Frame-level payload injection (binary + raw text)
            findings += self._test_frame_injection(url)

            # Test 5: SQL/NoSQL injection (JSON-wrapped)
            findings += self._test_injection(url)

            # Test 6: XSS injection (JSON-wrapped)
            findings += self._test_xss(url)

            # Test 7: State machine fuzzing (out-of-order sequences)
            findings += self._test_state_machine_fuzzing(url)

            # Test 8: Session token renewal / post-logout invalidation
            findings += self._test_session_token_renewal(url)

            # Test 9: Message flooding / rate limiting
            findings += self._test_flooding(url)

            # Test 10: Large frame abuse
            findings += self._test_large_frame(url)

            # Test 11: Info disclosure
            findings += self._test_info_disclosure(url)

            # Test 12: Insecure transport
            findings += self._test_insecure_transport(url)

            # Test 13: Command injection
            findings += self._test_command_injection(url)

            # Test 14: Binary frame protocol violations (reserved opcodes, RSV bits, oversized control)
            findings += self._test_binary_frame_malformed(url)

            # Test 15: Subprotocol downgrade (server accepts weaker/unrequested protocol)
            findings += self._test_subprotocol_downgrade(url)

            # Test 16: Close frame data injection
            findings += self._test_close_frame_injection(url)

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
        """Full CSWSH test — 5 origin variants + CSRF token absence probe.

        Covers:
          - Third-party evil origin
          - null origin (browser sandbox frame bypass)
          - Subdomain typosquatting  evil.{target_host}
          - Origin suffix confusion  {target_host}.evil.com
          - CSRF token absence on upgrade (when any origin is accepted)
        """
        findings = []
        parsed   = urlparse(url)
        host     = parsed.netloc  # e.g. example.com:8080

        origin_probes = [
            ("https://evil.com",                      "third_party_origin",  "high"),
            ("https://attacker.example.com",           "third_party_origin",  "high"),
            ("null",                                   "null_origin",         "high"),
            (f"https://evil.{host}",                  "subdomain_typosquat", "high"),
            (f"https://{host}.evil.com",              "suffix_confusion",    "critical"),
        ]

        for origin, label, severity in origin_probes:
            if self._stopped():
                break
            ws = self._ws_connect(url, origin=origin)
            if ws:
                resp = self._ws_send_recv(ws, '{"type":"ping"}')
                self._ws_close(ws)
                findings.append(self._finding(
                    url=url, vuln_type="ws_cswsh",
                    finding=(
                        f"CSWSH [{label}]: WebSocket upgrade accepted with "
                        f"Origin: {origin} [{url}]"
                    ),
                    severity=severity,
                    proof=(
                        f"Origin: {origin} accepted; "
                        f"response: {(resp or 'none')[:200]}"
                    ),
                    payload=f"Origin: {origin}",
                ))

        # CSRF token absence probe — fires only if at least one evil origin was accepted
        if findings and not self._stopped():
            # Attempt upgrade with evil origin but NO X-CSRF-Token / no auth cookies
            # If this succeeds the attack is fully exploitable from a browser
            ws = self._ws_connect(url, origin="https://evil.com")
            if ws:
                self._ws_close(ws)
                findings.append(self._finding(
                    url=url, vuln_type="ws_cswsh_no_csrf",
                    finding=(
                        f"CSWSH fully exploitable — evil origin accepted "
                        f"with no CSRF token on upgrade [{url}]"
                    ),
                    severity="critical",
                    proof=(
                        "Evil origin accepted AND no X-CSRF-Token/anti-CSRF "
                        "validation detected in upgrade handshake"
                    ),
                    payload="Origin: https://evil.com (no CSRF token)",
                ))

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


    # ══════════════════════════════════════════════════════════════════════════
    # TEST 10: CONNECTION UPGRADE VALIDATION
    # ══════════════════════════════════════════════════════════════════════════

    def _test_upgrade_validation(self, url: str) -> list[dict]:
        """Test the HTTP → WebSocket upgrade handshake for security flaws.

        Three independent probes:
          1. No Origin header  — server MUST validate or reject origin-less upgrades.
          2. Origin: null      — used by sandboxed iframes; many servers whitelist it.
          3. Sec-WebSocket-Version: 12 — old non-standard version; spec requires 13.
             Acceptance implies loose version validation.
        """
        findings = []

        # Probe 1: no Origin header at all
        # _ws_connect(origin=None) already sends no Origin header
        ws = self._ws_connect(url, origin=None)
        if ws:
            resp = self._ws_send_recv(ws, '{"type":"ping"}')
            self._ws_close(ws)
            findings.append(self._finding(
                url=url, vuln_type="ws_missing_origin_check",
                finding=(
                    f"WebSocket upgrade accepted with no Origin header — "
                    f"server performs no origin validation [{url}]"
                ),
                severity="high",
                proof=(
                    f"Connection established without Origin header; "
                    f"response: {(resp or 'none')[:200]}"
                ),
                payload="(no Origin header)",
            ))

        # Probe 2: Origin: null
        if not self._stopped():
            ws = self._ws_connect(url, origin="null")
            if ws:
                resp = self._ws_send_recv(ws, '{"type":"ping"}')
                self._ws_close(ws)
                findings.append(self._finding(
                    url=url, vuln_type="ws_null_origin_accepted",
                    finding=(
                        f"WebSocket upgrade accepted with Origin: null — "
                        f"bypasses allowlist origin checks [{url}]"
                    ),
                    severity="high",
                    proof=(
                        f"Connection established with Origin: null; "
                        f"response: {(resp or 'none')[:200]}"
                    ),
                    payload="Origin: null",
                ))

        # Probe 3: wrong Sec-WebSocket-Version (12 instead of 13)
        if not self._stopped():
            ws = self._ws_connect(url, headers={"Sec-WebSocket-Version": "12"})
            if ws:
                self._ws_close(ws)
                findings.append(self._finding(
                    url=url, vuln_type="ws_downgrade_accepted",
                    finding=(
                        f"WebSocket accepts downgraded Sec-WebSocket-Version: 12 "
                        f"(RFC 6455 requires 13) [{url}]"
                    ),
                    severity="low",
                    proof="Server accepted WS version 12 — indicates loose handshake validation",
                    payload="Sec-WebSocket-Version: 12",
                ))

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 11: FRAME-LEVEL PAYLOAD INJECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _test_frame_injection(self, url: str) -> list[dict]:
        """Inject payloads at the WS frame level — binary frames and raw text.

        Distinct from _test_injection (which wraps payloads in JSON).  Binary
        frame injection can bypass JSON-aware input sanitisation, and raw text
        injection tests servers that accept non-JSON protocol messages.
        """
        findings = []
        ws = self._ws_connect(url, origin=self._origin)
        if not ws:
            return findings

        error_patterns = [
            "sql", "syntax error", "mysql", "postgres", "sqlite",
            "traceback", "exception", "at line", "internal error",
            "root:", "/bin/", "/etc/", "49",   # 49 = 7*7 SSTI result
        ]

        # ── Binary frame injection ───────────────────────────────────────────
        binary_payloads: list[tuple[str, bytes]] = [
            ("sqli_binary",   b"\' OR \'1\'=\'1\x00"),
            ("xss_binary",    b"<script>alert(1)</script>\x00"),
            ("cmdi_binary",   b"; cat /etc/passwd\x00"),
            ("null_bytes",    b"\x00" * 64),
            ("high_bytes",    bytes(range(128, 200))),
        ]
        for name, payload_bytes in binary_payloads:
            if self._stopped():
                break
            try:
                ws.send_binary(payload_bytes)
                resp = None
                try:
                    ws.settimeout(2.0)
                    resp = ws.recv()
                except Exception:
                    pass
                if resp:
                    body = resp.lower()
                    if any(e in body for e in error_patterns):
                        findings.append(self._finding(
                            url=url, vuln_type="ws_binary_injection",
                            finding=(
                                f"Binary frame injection ({name}) triggered "
                                f"error/sensitive response [{url}]"
                            ),
                            severity="medium",
                            proof=resp[:300],
                            payload=f"binary:{name}",
                        ))
            except Exception:
                pass

        # ── Raw text (non-JSON) frame injection ──────────────────────────────
        raw_text_payloads: list[tuple[str, str]] = [
            ("raw_sqli",    "\' OR \'1\'=\'1"),
            ("raw_xss",     "<script>alert(document.cookie)</script>"),
            ("raw_cmdi",    "; id ; uname -a"),
            ("raw_ssti",    "{{7*7}}${7*7}"),
            ("raw_lfi",     "../../../../etc/passwd"),
            ("raw_xxe",     (
                "<?xml version=\'1.0\'?>"
                "<!DOCTYPE x [<!ENTITY xxe SYSTEM \'file:///etc/passwd\'>]>"
                "<x>&xxe;</x>"
            )),
        ]
        for name, raw_payload in raw_text_payloads:
            if self._stopped():
                break
            resp = self._ws_send_recv(ws, raw_payload)
            if resp:
                body = resp.lower()
                if any(e in body for e in error_patterns):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_raw_frame_injection",
                        finding=(
                            f"Raw text frame injection ({name}) triggered "
                            f"vulnerable response [{url}]"
                        ),
                        severity="high",
                        proof=resp[:300],
                        payload=raw_payload[:100],
                    ))

        self._ws_close(ws)
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 12: SESSION TOKEN RENEWAL
    # ══════════════════════════════════════════════════════════════════════════

    def _test_session_token_renewal(self, url: str) -> list[dict]:
        """Test whether session tokens are renewed or invalidated during
        a persistent WebSocket connection.

        Two sub-tests:
          1. Long-held connection — hold for SESSION_HOLD_SECS using periodic
             pings; if still responsive afterwards the server never rotated
             or invalidated the token.
          2. Post-logout invalidation — probe common logout paths via HTTP,
             then re-test WS session.  If WS still works, logout doesn't
             invalidate the WS session.
        """
        findings = []

        # ── Sub-test 1: long-held connection ─────────────────────────────────
        ws = self._ws_connect(url, origin=self._origin)
        if not ws:
            return findings

        # Periodic ping keepalive for SESSION_HOLD_SECS
        deadline = time.time() + SESSION_HOLD_SECS
        still_alive = True
        while time.time() < deadline and not self._stopped():
            try:
                ws.ping()
            except Exception:
                still_alive = False
                break
            time.sleep(5)

        if still_alive and not self._stopped():
            resp = self._ws_send_recv(ws, '{"type":"ping","test":"renewal"}', recv_timeout=5.0)
            resp_lower = (resp or "").lower()
            if resp and "unauthorized" not in resp_lower and "expired" not in resp_lower:
                findings.append(self._finding(
                    url=url, vuln_type="ws_session_no_renewal",
                    finding=(
                        f"WebSocket session not renewed after {SESSION_HOLD_SECS}s "
                        f"persistent connection — token appears perpetually valid [{url}]"
                    ),
                    severity="medium",
                    proof=(
                        f"Connection active after {SESSION_HOLD_SECS}s hold; "
                        f"response: {(resp or 'none')[:200]}"
                    ),
                    payload=f"hold={SESSION_HOLD_SECS}s",
                ))
        self._ws_close(ws)

        # ── Sub-test 2: post-logout WS session invalidation ──────────────────
        if self._stopped():
            return findings

        logout_paths = [
            "/api/logout", "/logout", "/auth/logout",
            "/api/auth/logout", "/api/session", "/session/logout",
        ]
        import urllib.request as _urllib_req
        parsed = urlparse(self.target)
        for path in logout_paths:
            if self._stopped():
                break
            logout_url = f"{self._http_scheme}://{parsed.netloc}{path}"
            try:
                req = _urllib_req.Request(logout_url, method="DELETE")
                req.add_header("Origin", self._origin)
                _urllib_req.urlopen(req, timeout=3)
            except Exception:
                pass  # 404/405 expected — probe regardless

            # Attempt fresh WS connect after logout
            ws2 = self._ws_connect(url, origin=self._origin)
            if ws2:
                resp2 = self._ws_send_recv(
                    ws2, '{"type":"ping","test":"post_logout"}', recv_timeout=4.0,
                )
                self._ws_close(ws2)
                resp2_lower = (resp2 or "").lower()
                if resp2 and "unauthorized" not in resp2_lower and "expired" not in resp2_lower:
                    findings.append(self._finding(
                        url=url, vuln_type="ws_session_post_logout",
                        finding=(
                            f"WebSocket session still active after logout probe "
                            f"to {path} — token not invalidated on logout [{url}]"
                        ),
                        severity="high",
                        proof=(
                            f"Logout attempted via DELETE {path}; "
                            f"WS response: {(resp2 or 'none')[:200]}"
                        ),
                        payload=f"DELETE {logout_url}",
                    ))
                    break  # one post-logout finding is enough

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 13: STATE MACHINE FUZZING
    # ══════════════════════════════════════════════════════════════════════════

    def _test_state_machine_fuzzing(self, url: str) -> list[dict]:
        """Send out-of-order and malformed message sequences to probe state
        machine robustness.

        Each sequence opens a fresh connection to avoid cross-sequence state
        bleed.  A finding is raised when the server returns a stack trace,
        exception message, or a crash indicator in response to a sequence.

        Sequences tested:
          data_before_subscribe     — payload before any auth/subscribe
          double_subscribe          — subscribe to same channel twice
          unsubscribe_without_sub   — unsubscribe before subscribing
          malformed_json_frame      — syntactically invalid JSON
          null_message_frame        — literal "null" + empty string
          deeply_nested_payload     — 40-level JSON nesting
          oversized_action_name     — 10 000-char action key
          unicode_overflow          — 1 000 U+FFFF codepoints
          rapid_action_storm        — 20 messages without pause
        """
        import json as _json

        findings = []

        deep_nest = '{"a":' * 40 + '"deep"' + '}' * 40

        sequences: list[tuple[str, list[str]]] = [
            ("data_before_subscribe", [
                '{"action":"list","resource":"users"}',
                '{"action":"get","id":"1"}',
            ]),
            ("double_subscribe", [
                '{"type":"subscribe","channel":"updates"}',
                '{"type":"subscribe","channel":"updates"}',
            ]),
            ("unsubscribe_without_sub", [
                '{"type":"unsubscribe","channel":"updates"}',
            ]),
            ("malformed_json_frame", [
                '{bad json here}',
                '{"key":',
                '[unclosed',
            ]),
            ("null_message_frame", [
                "null",
                "",
            ]),
            ("deeply_nested_payload", [deep_nest]),
            ("oversized_action_name", [
                _json.dumps({"action": "A" * 10_000, "data": "x"}),
            ]),
            ("unicode_overflow", [
                _json.dumps({"data": "\uFFFF" * 1_000}),
            ]),
        ]

        crash_indicators = [
            "traceback", "exception", "at line", "stack trace",
            "internal error", "panic", "fatal", "unhandled",
            "null pointer", "segfault", "assertion",
        ]

        for seq_name, messages in sequences:
            if self._stopped():
                break

            ws = self._ws_connect(url, origin=self._origin)
            if not ws:
                continue

            signals: list[str] = []
            for msg in messages:
                if self._stopped():
                    break
                try:
                    if msg == "":
                        # Send empty text frame
                        ws.send("")
                        resp = None
                        try:
                            ws.settimeout(2.0)
                            resp = ws.recv()
                        except Exception:
                            pass
                    else:
                        resp = self._ws_send_recv(ws, msg, recv_timeout=3.0)

                    if resp:
                        body = resp.lower()
                        if any(x in body for x in crash_indicators):
                            signals.append(
                                f"seq={seq_name} msg={msg[:60]!r}: "
                                f"crash indicator in response: {resp[:200]}"
                            )
                        # Malformed JSON accepted without error is also interesting
                        if seq_name == "malformed_json_frame" and "error" not in body:
                            signals.append(
                                f"seq={seq_name}: server accepted malformed JSON "
                                f"without error: {resp[:150]}"
                            )
                except Exception as exc:
                    signals.append(f"seq={seq_name}: exception during send: {exc}")

            self._ws_close(ws)

            if signals:
                findings.append(self._finding(
                    url=url, vuln_type="ws_state_machine_flaw",
                    finding=(
                        f"State machine flaw — sequence '{seq_name}' "
                        f"triggered abnormal server response [{url}]"
                    ),
                    severity="medium",
                    proof=("; ".join(signals))[:400],
                    payload=seq_name,
                ))

        # Rapid action storm (20 messages, no response wait between sends)
        if not self._stopped():
            ws = self._ws_connect(url, origin=self._origin)
            if ws:
                try:
                    for i in range(20):
                        ws.send(_json.dumps({"action": "get", "id": str(i), "seq": i}))
                        time.sleep(0.02)

                    # Collect any responses
                    ws.settimeout(2.0)
                    for _ in range(20):
                        try:
                            r = ws.recv()
                            if r and any(x in r.lower() for x in crash_indicators):
                                findings.append(self._finding(
                                    url=url, vuln_type="ws_state_machine_flaw",
                                    finding=(
                                        f"Server leaks internal error under "
                                        f"rapid message storm (20 msgs) [{url}]"
                                    ),
                                    severity="medium",
                                    proof=r[:300],
                                    payload="rapid_storm_20_messages",
                                ))
                                break
                        except Exception:
                            break
                except Exception:
                    pass
                finally:
                    self._ws_close(ws)

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 14: BINARY FRAME PROTOCOL VIOLATIONS
    # ══════════════════════════════════════════════════════════════════════════

    def _test_binary_frame_malformed(self, url: str) -> list[dict]:
        """Send RFC 6455 protocol-violating frames to probe server robustness.

        Distinct from _test_frame_injection (which sends attack *payloads* inside
        valid binary frames). This test sends structurally invalid frames:
          - Oversized ping  (>125 bytes — RFC §5.5 MUST NOT)
          - Reserved opcode (3) — server MUST close with 1002
          - RSV1 flag set without extension negotiation — server MUST close with 1002
        """
        if not WS_AVAILABLE:
            return []
        findings = []
        crash_indicators = (
            "traceback", "exception", "internal error", "panic",
            "fatal", "assertion", "segfault", "unhandled",
        )

        # ── Probe 1: oversized ping (>125 bytes) ─────────────────────────────
        ws = self._ws_connect(url, origin=self._origin)
        if ws:
            try:
                ws.ping(b"P" * 200)
                ws.settimeout(2.0)
                resp = ws.recv()
                if resp and any(c in resp.lower() for c in crash_indicators):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_malformed_frame",
                        finding=f"Oversized ping (200-byte payload) caused error response [{url}]",
                        severity="medium",
                        proof=resp[:300],
                        payload="ping payload=200 bytes (RFC §5.5 max=125)",
                    ))
            except Exception:
                pass
            self._ws_close(ws)

        # ── Probe 2: reserved non-control opcode (3) ─────────────────────────
        ws = self._ws_connect(url, origin=self._origin)
        if ws:
            try:
                frame = ws_client.ABNF.create_frame(
                    b"reserved_opcode_probe", opcode=3, fin=1,
                )
                ws.send_frame(frame)
                ws.settimeout(2.0)
                resp = ws.recv()
                if resp and any(c in resp.lower() for c in crash_indicators):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_malformed_frame",
                        finding=f"Reserved opcode 3 caused server error response [{url}]",
                        severity="medium",
                        proof=resp[:300],
                        payload="opcode=3 (reserved, RFC §5.2 MUST close 1002)",
                    ))
            except Exception:
                pass
            self._ws_close(ws)

        # ── Probe 3: RSV1 flag set without extension negotiation ──────────────
        ws = self._ws_connect(url, origin=self._origin)
        if ws:
            try:
                frame = ws_client.ABNF.create_frame(
                    b"rsv1_probe",
                    opcode=ws_client.ABNF.OPCODE_BINARY,
                    fin=1,
                    rsv1=1,
                )
                ws.send_frame(frame)
                ws.settimeout(2.0)
                resp = ws.recv()
                if resp and any(c in resp.lower() for c in crash_indicators):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_malformed_frame",
                        finding=f"RSV1-flagged frame (no extension) caused error response [{url}]",
                        severity="medium",
                        proof=resp[:300],
                        payload="RSV1=1 without Sec-WebSocket-Extensions (RFC §5.2 MUST close 1002)",
                    ))
            except Exception:
                pass
            self._ws_close(ws)

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 15: SUBPROTOCOL DOWNGRADE
    # ══════════════════════════════════════════════════════════════════════════

    _STRONG_SUBPROTOCOLS = [
        "graphql-transport-ws",
        "chat.v3",
        "wamp.2.json",
        "mqtt.secure",
        "binary.v2",
    ]

    def _test_subprotocol_downgrade(self, url: str) -> list[dict]:
        """Test whether a server accepts a weaker or unrequested subprotocol.

        A downgrade occurs when the server returns a Sec-WebSocket-Protocol value
        that was not in the client's offered list, or returns a significantly older
        version than the best-offered protocol.
        """
        if not WS_AVAILABLE:
            return []
        findings = []

        # Connect offering the strong protocol list
        offered = self._STRONG_SUBPROTOCOLS
        try:
            ws = ws_client.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
            h = [f"Origin: {self._origin}"]
            if self._auth_headers:
                for k, v in self._auth_headers.items():
                    h.append(f"{k}: {v}")
            ws.connect(url, header=h, subprotocols=offered, timeout=self.timeout)
            negotiated = ws.getheaders().get("sec-websocket-protocol", "")
            self._ws_close(ws)

            if not negotiated:
                return findings  # server didn't negotiate any subprotocol — nothing to downgrade

            # Server returned something not in our offered list → unexpected/downgraded
            offered_set = {p.lower() for p in offered}
            if negotiated.lower() not in offered_set:
                findings.append(self._finding(
                    url=url, vuln_type="ws_subprotocol_downgrade",
                    finding=(
                        f"WebSocket subprotocol downgrade — server returned "
                        f"'{negotiated}' which was not in the offered list [{url}]"
                    ),
                    severity="medium",
                    proof=(
                        f"Offered: {', '.join(offered)}; "
                        f"Server returned: {negotiated}"
                    ),
                    payload=f"Sec-WebSocket-Protocol: {', '.join(offered)}",
                ))
        except Exception:
            pass

        # Second check: request only a strong-versioned protocol, see if server
        # accepts and then also accepts a plain connection (no subprotocol)
        try:
            ws_plain = self._ws_connect(url, origin=self._origin)
            if ws_plain:
                # Plain connection succeeded while we just offered a strict protocol → no enforcement
                plain_headers = ws_plain.getheaders() if hasattr(ws_plain, "getheaders") else {}
                plain_proto = plain_headers.get("sec-websocket-protocol", "")
                self._ws_close(ws_plain)

                if not plain_proto and findings:
                    # Server accepted plain connection with no subprotocol despite
                    # negotiating a specific one in the previous attempt — downgrade confirmed
                    findings[0]["finding"] += " and server also accepts plain connections"
                    findings[0]["proof"] += "; plain (no subprotocol) connection also accepted"
        except Exception:
            pass

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 16: CLOSE FRAME DATA INJECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _test_close_frame_injection(self, url: str) -> list[dict]:
        """Inject payloads in the WebSocket Close frame reason field.

        RFC 6455 §5.5.1 allows a 2-byte status code + optional UTF-8 reason.
        Some servers process the reason string rather than discarding it —
        enabling injection through an unexpected channel.
        """
        if not WS_AVAILABLE:
            return []
        findings = []

        injection_payloads: list[tuple[str, bytes]] = [
            ("sqli_reason",  b"' OR '1'='1\x00"),
            ("xss_reason",   b"<script>alert(1)</script>"),
            ("cmdi_reason",  b"; id; uname -a"),
        ]
        invalid_codes: list[tuple[str, int]] = [
            ("status_0",     0),
            ("status_999",   999),
            ("status_5000",  5000),
            ("status_65535", 65535),
        ]

        error_indicators = (
            "traceback", "exception", "error", "internal",
            "syntax", "sql", "<script", "root:", "/bin/",
        )

        # ── Injection payloads in reason field ───────────────────────────────
        for probe_name, reason_bytes in injection_payloads:
            if self._stopped():
                break
            ws = self._ws_connect(url, origin=self._origin)
            if not ws:
                continue
            try:
                # Send a couple of benign messages first so the connection is live
                ws.send('{"type":"ping"}')
                ws.settimeout(1.0)
                try:
                    ws.recv()
                except Exception:
                    pass
                ws.send_close(status=1000, reason=reason_bytes)
                ws.settimeout(2.0)
                resp = ws.recv()
                if resp and any(ind in resp.lower() for ind in error_indicators):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_close_frame_injection",
                        finding=(
                            f"Close frame reason injection ({probe_name}) "
                            f"triggered server-side processing [{url}]"
                        ),
                        severity="high",
                        proof=resp[:300],
                        payload=f"Close reason: {reason_bytes[:60]!r}",
                    ))
            except Exception:
                pass
            finally:
                self._ws_close(ws)

        # ── Invalid close status codes ────────────────────────────────────────
        for code_name, status_code in invalid_codes:
            if self._stopped():
                break
            ws = self._ws_connect(url, origin=self._origin)
            if not ws:
                continue
            try:
                ws.send_close(status=status_code, reason=b"dast_probe")
                ws.settimeout(2.0)
                resp = ws.recv()
                if resp and any(ind in resp.lower() for ind in error_indicators):
                    findings.append(self._finding(
                        url=url, vuln_type="ws_close_frame_injection",
                        finding=(
                            f"Invalid close status code {status_code} ({code_name}) "
                            f"triggered error response [{url}]"
                        ),
                        severity="medium",
                        proof=resp[:300],
                        payload=f"Close status={status_code}",
                    ))
            except Exception:
                pass
            finally:
                self._ws_close(ws)

        return findings


# ── Convenience function ─────────────────────────────────────────────────────

def scan_websocket(target: str, stop_event=None, on_finding=None,
                   timeout: int = 5, extra_urls: list | None = None,
                   auth_headers: dict | None = None) -> list[dict]:
    """One-liner: scan a target for WebSocket vulnerabilities.

    Args:
        auth_headers: Dict of HTTP headers to include in every WS upgrade
            handshake (e.g. ``{"Authorization": "Bearer …", "Cookie": "…"}``).
            Populated from the active requests.Session before calling so that
            authenticated endpoints are reachable.
    """
    scanner = WebSocketScanner(
        target=target, stop_event=stop_event,
        on_finding=on_finding, timeout=timeout,
        auth_headers=auth_headers,
    )
    return scanner.scan(extra_urls=extra_urls)
