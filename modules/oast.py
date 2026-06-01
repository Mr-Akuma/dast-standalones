"""
OAST (Out-of-Band Application Security Testing) Server.
Detects blind injection vulnerabilities: blind SQLi, SSRF, XXE, CMDi, blind XSS.

Uses stdlib http.server — zero external dependencies.
Starts a local HTTP/DNS-less callback server on a random port.
Generates unique tokens per test, correlates callbacks to originating tests.

Usage:
    oast = get_or_start_oast()
    url  = oast.make_url("ssrf", "http://target/page", "redirect_param")
    # inject url into target parameter
    # check oast.poll(token) for callbacks
    oast.stop()
"""
from __future__ import annotations

import enum
import os
import random
import socket
import struct
import threading
import uuid
import time
from dataclasses import dataclass, asdict, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from urllib.parse import urlparse


# ── Callback dataclass ────────────────────────────────────────────────────────

@dataclass
class OASTCallback:
    token:      str
    timestamp:  float
    source_ip:  str
    method:     str
    path:       str
    headers:    dict
    body:       str
    vuln_type:  str    # what we were testing when we injected
    target_url: str    # the app URL being tested
    parameter:  str    # the fuzzed parameter
    ts_iso:     str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── HTTP handler ──────────────────────────────────────────────────────────────

class _OASTHandler(BaseHTTPRequestHandler):
    """Silent HTTP handler — records all incoming requests without logging."""

    # Class-level shared state (single server per process)
    _callbacks:  list[OASTCallback] = []
    _token_map:  dict[str, dict]    = {}   # token → {vuln_type, target_url, parameter}
    _lock:       threading.Lock     = threading.Lock()

    def do_GET(self):     self._handle()
    def do_POST(self):    self._handle()
    def do_PUT(self):     self._handle()
    def do_HEAD(self):    self._handle()
    def do_OPTIONS(self): self._handle()
    def do_DELETE(self):  self._handle()

    def _handle(self):
        try:
            path  = self.path
            # Token is the first path segment: /token123/anything
            parts = path.strip("/").split("/")
            token = parts[0] if parts else ""

            # Read body if present
            body = ""
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length > 0:
                    body = self.rfile.read(min(length, 8192)).decode("utf-8", errors="replace")
            except Exception:
                pass

            # Lookup test metadata
            vuln_type = target_url = parameter = "unknown"
            with self.__class__._lock:
                meta = self.__class__._token_map.get(token, {})
                vuln_type  = meta.get("vuln_type",  "unknown")
                target_url = meta.get("target_url", "")
                parameter  = meta.get("parameter",  "")

                self.__class__._callbacks.append(OASTCallback(
                    token      = token,
                    timestamp  = time.time(),
                    source_ip  = self.client_address[0],
                    method     = self.command,
                    path       = path,
                    headers    = dict(self.headers),
                    body       = body,
                    vuln_type  = vuln_type,
                    target_url = target_url,
                    parameter  = parameter,
                    ts_iso     = __import__("datetime").datetime.utcnow().isoformat(),
                ))

            # Silent 200
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
        except Exception:
            pass

    def log_message(self, fmt, *args):
        pass  # Suppress all default access logs


# ── DNS OAST Server ──────────────────────────────────────────────────────────

class DNSOASTServer:
    """
    Minimal DNS callback server for out-of-band DNS interaction testing.

    Listens on a random UDP port (5300-5399) to avoid needing root for port 53.
    Generates unique tokens per test injection. Records DNS queries for later correlation.

    Usage: server.make_fqdn(token) -> "{token}.oast-dns.local"
    Note: Only works for DNS rebinding / blind DNS tests pointing to localhost:RANDOM_PORT
    For real external DNS callbacks, configure an external DNS resolver.
    """

    def __init__(self) -> None:
        self.port: int | None = None
        self._sock: socket.socket | None = None
        self._callbacks: list[dict] = []
        self._lock = threading.Lock()
        self._running = False

        # Try to bind a UDP socket on a random port in 5300-5399
        ports = list(range(5300, 5400))
        random.shuffle(ports)
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", p))
                self._sock = s
                self.port = p
                break
            except OSError:
                try:
                    s.close()
                except Exception:
                    pass

    def start(self) -> None:
        """Start the DNS listener in a daemon thread."""
        if self._sock is None or self.port is None:
            return
        self._running = True
        t = threading.Thread(target=self._dns_listener, daemon=True, name="oast-dns")
        t.start()

    def _dns_listener(self) -> None:
        """Read UDP datagrams and parse minimal DNS queries."""
        assert self._sock is not None
        self._sock.settimeout(1.0)
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                # Parse minimal DNS query
                if len(data) < 12:
                    continue

                tx_id = data[0:2]

                # Parse QNAME starting at byte 12
                pos = 12
                labels: list[str] = []
                while pos < len(data):
                    length = data[pos]
                    if length == 0:
                        pos += 1
                        break
                    pos += 1
                    if pos + length > len(data):
                        break
                    labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
                    pos += length

                fqdn = ".".join(labels)
                token = labels[0] if labels else ""

                with self._lock:
                    self._callbacks.append({
                        "token": token,
                        "source_ip": addr[0],
                        "qname": fqdn,
                        "timestamp": time.time(),
                    })

                # Send minimal NXDOMAIN response
                # Copy TX ID, set QR=1 (0x8000), RCODE=3 (NXDOMAIN)
                flags = 0x8003  # QR=1, RCODE=3
                # Header: TX_ID, FLAGS, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
                resp = tx_id + struct.pack("!HHHHH", flags, 1, 0, 0, 0)
                # Echo back the question section
                resp += data[12:pos]
                # QTYPE and QCLASS from original (2+2 bytes after QNAME)
                if pos + 4 <= len(data):
                    resp += data[pos:pos + 4]
                else:
                    resp += struct.pack("!HH", 1, 1)  # A record, IN class

                self._sock.sendto(resp, addr)
            except Exception:
                pass

    @staticmethod
    def make_fqdn(token: str) -> str:
        """Return the FQDN to inject into payloads."""
        return f"{token}.oast-dns.local"

    def poll(self, token: str) -> list[dict]:
        """Return callbacks matching the given token."""
        with self._lock:
            return [cb for cb in self._callbacks if cb["token"] == token]

    def stop(self) -> None:
        """Close the UDP socket and stop the listener."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ── SMTP OAST Server ─────────────────────────────────────────────────────────

class SMTPOASTServer:
    """
    Minimal SMTP callback server for out-of-band email injection testing.

    Listens on a random TCP port (2525-2599). Records MAIL FROM, RCPT TO, and body.
    Useful for detecting blind email injection / SMTP injection vulnerabilities.
    """

    def __init__(self) -> None:
        self.port: int | None = None
        self._sock: socket.socket | None = None
        self._callbacks: list[dict] = []
        self._lock = threading.Lock()
        self._running = False

        # Try to bind a TCP socket on a random port in 2525-2599
        ports = list(range(2525, 2600))
        random.shuffle(ports)
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", p))
                s.listen(5)
                self._sock = s
                self.port = p
                break
            except OSError:
                try:
                    s.close()
                except Exception:
                    pass

    def start(self) -> None:
        """Start the SMTP listener in a daemon thread."""
        if self._sock is None or self.port is None:
            return
        self._running = True
        t = threading.Thread(target=self._smtp_listener, daemon=True, name="oast-smtp")
        t.start()

    def _smtp_listener(self) -> None:
        """Accept TCP connections and handle basic SMTP exchange."""
        assert self._sock is not None
        self._sock.settimeout(1.0)
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # Handle each connection in a separate daemon thread
            t = threading.Thread(
                target=self._handle_smtp, args=(conn, addr), daemon=True,
                name="oast-smtp-conn",
            )
            t.start()

    def _handle_smtp(self, conn: socket.socket, addr: tuple) -> None:
        """Handle a single SMTP conversation."""
        try:
            conn.settimeout(10.0)
            conn.sendall(b"220 oast-smtp.local SMTP Ready\r\n")

            mail_from = ""
            rcpt_to = ""
            body = ""

            while True:
                raw = conn.recv(4096)
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").strip()
                upper = line.upper()

                if upper.startswith("HELO") or upper.startswith("EHLO"):
                    conn.sendall(b"250 OK\r\n")
                elif upper.startswith("MAIL FROM"):
                    mail_from = line.split(":", 1)[1].strip() if ":" in line else line
                    conn.sendall(b"250 OK\r\n")
                elif upper.startswith("RCPT TO"):
                    rcpt_to = line.split(":", 1)[1].strip() if ":" in line else line
                    conn.sendall(b"250 OK\r\n")
                elif upper.startswith("DATA"):
                    conn.sendall(b"354 Start input\r\n")
                    # Read body until \r\n.\r\n
                    body_parts: list[str] = []
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        body_parts.append(chunk.decode("utf-8", errors="replace"))
                        # Check for end-of-data marker
                        joined = "".join(body_parts)
                        if "\r\n.\r\n" in joined:
                            body = joined.split("\r\n.\r\n")[0]
                            break
                    body = body[:2000]
                    conn.sendall(b"250 OK\r\n")
                elif upper.startswith("QUIT"):
                    conn.sendall(b"221 Bye\r\n")
                    break
                elif upper.startswith("RSET"):
                    conn.sendall(b"250 OK\r\n")
                elif upper.startswith("NOOP"):
                    conn.sendall(b"250 OK\r\n")
                else:
                    conn.sendall(b"500 Unrecognized command\r\n")

            # Extract token from RCPT TO: {token}@oast-smtp.local
            token = ""
            clean_rcpt = rcpt_to.strip("<>").strip()
            if "@" in clean_rcpt:
                token = clean_rcpt.split("@")[0]

            if token or mail_from or rcpt_to:
                with self._lock:
                    self._callbacks.append({
                        "token": token,
                        "source_ip": addr[0],
                        "mail_from": mail_from,
                        "rcpt_to": rcpt_to,
                        "body": body,
                        "timestamp": time.time(),
                    })
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def make_addr(self, token: str) -> str | None:
        """Return the email address to inject into payloads, or None if not bound."""
        if self.port is None:
            return None
        return f"{token}@oast-smtp.local:{self.port}"

    def poll(self, token: str) -> list[dict]:
        """Return callbacks matching the given token."""
        with self._lock:
            return [cb for cb in self._callbacks if cb["token"] == token]

    def stop(self) -> None:
        """Close the server socket and stop the listener."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ── OAST Server ───────────────────────────────────────────────────────────────

class OASTServer:
    """
    Local OAST listener. Generates unique injection URLs.

    Note: For external target testing, the machine running this must be
    reachable from the target server. For localhost/local-network targets
    (e.g. DVWA, Juice Shop, lab VMs) this works as-is.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 0, public_base_url: str = ""):
        self.host    = host
        self.port    = port   # 0 = OS picks a random available port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.started = False
        self.listen_ip: str = "127.0.0.1"  # set after start
        self.public_base_url: str = ""
        self._dns_server: DNSOASTServer | None = None
        self._smtp_server: SMTPOASTServer | None = None
        configured_base = public_base_url or os.environ.get("DAST_OAST_PUBLIC_BASE_URL", "")
        if configured_base:
            self.set_public_base_url(configured_base)

    def set_public_base_url(self, base_url: str) -> None:
        """Set an externally reachable HTTP callback base URL."""
        base = (base_url or "").strip().rstrip("/")
        if not base:
            self.public_base_url = ""
            return
        parsed = urlparse(base)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("public_base_url must be an absolute http(s) URL")
        self.public_base_url = base

    @property
    def domain(self) -> str:
        """Best-effort host value for legacy scanner code that expects .domain."""
        if self.public_base_url:
            return urlparse(self.public_base_url).netloc
        return f"{self.listen_ip}:{self.port}"

    def callback_url_for_token(self, token: str, host_override: str = "") -> str:
        if self.public_base_url:
            return f"{self.public_base_url}/{token}"
        host = host_override or self.listen_ip
        return f"http://{host}:{self.port}/{token}"

    def start(self) -> int:
        """Start listener. Returns the actual port bound."""
        # Reset shared state
        _OASTHandler._callbacks = []
        _OASTHandler._token_map = {}

        self._server = HTTPServer((self.host, self.port), _OASTHandler)
        self.port    = self._server.server_address[1]   # actual port if 0 was given

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="oast-listener",
        )
        self._thread.start()
        self.started   = True
        self.listen_ip = "127.0.0.1"
        return self.port

    def stop(self):
        if self._server:
            self._server.shutdown()
        if self._dns_server:
            self._dns_server.stop()
            self._dns_server = None
        if self._smtp_server:
            self._smtp_server.stop()
            self._smtp_server = None
        self.started = False

    def make_url(
        self,
        vuln_type:     str,
        target_url:    str,
        parameter:     str,
        host_override: str = "",
    ) -> str:
        """
        Generate a unique OAST callback URL for injection.
        Inject this URL as a payload value — if the server fetches it, it's SSRF/blind/etc.
        """
        if not self.started:
            raise RuntimeError("OAST server not started — call start() first")

        token = uuid.uuid4().hex[:20]
        with _OASTHandler._lock:
            _OASTHandler._token_map[token] = {
                "vuln_type":  vuln_type,
                "target_url": target_url,
                "parameter":  parameter,
            }

        return self.callback_url_for_token(token, host_override=host_override)

    def get_callbacks(self, since: float = 0.0) -> list[OASTCallback]:
        """Return all callbacks received after `since` timestamp."""
        with _OASTHandler._lock:
            return [c for c in _OASTHandler._callbacks if c.timestamp >= since]

    def poll_token(self, token: str, wait: float = 5.0) -> Optional[OASTCallback]:
        """Wait up to `wait` seconds for a callback matching this token."""
        deadline = time.time() + wait
        while time.time() < deadline:
            with _OASTHandler._lock:
                for cb in _OASTHandler._callbacks:
                    if cb.token == token:
                        return cb
            time.sleep(0.2)
        return None

    def all_callbacks(self) -> list[dict]:
        with _OASTHandler._lock:
            return [c.to_dict() for c in _OASTHandler._callbacks]

    def clear(self):
        with _OASTHandler._lock:
            _OASTHandler._callbacks.clear()
            _OASTHandler._token_map.clear()

    def start_dns_smtp(self) -> None:
        """Start DNS and SMTP callback servers alongside HTTP."""
        if self._dns_server is None:
            self._dns_server = DNSOASTServer()
            self._dns_server.start()
        if self._smtp_server is None:
            self._smtp_server = SMTPOASTServer()
            self._smtp_server.start()

    def dns_url(self, token: str) -> str | None:
        """Return a DNS injection FQDN, or None if DNS server not started."""
        if self._dns_server is None or self._dns_server.port is None:
            return None
        return DNSOASTServer.make_fqdn(token)

    def smtp_addr(self, token: str) -> str | None:
        """Return an SMTP injection address, or None if SMTP server not started."""
        if self._smtp_server is None:
            return None
        return self._smtp_server.make_addr(token)

    def status(self) -> dict:
        return {
            "started":         self.started,
            "port":            self.port,
            "listen_ip":       self.listen_ip,
            "public_base_url": self.public_base_url,
            "callbacks_total": len(_OASTHandler._callbacks),
            "tokens_active":   len(_OASTHandler._token_map),
            "dns_port":        self._dns_server.port if self._dns_server else None,
            "smtp_port":       self._smtp_server.port if self._smtp_server else None,
        }


# ── Global singleton ──────────────────────────────────────────────────────────

_global_oast: Optional[OASTServer] = None
_oast_lock = threading.Lock()


def get_or_start_oast(host_override: str = "", public_base_url: str = "") -> OASTServer:
    """Return the global OAST server, starting it if needed."""
    global _global_oast
    host_override = host_override or os.environ.get("DAST_OAST_HOST", "")
    public_base_url = public_base_url or os.environ.get("DAST_OAST_PUBLIC_BASE_URL", "")
    with _oast_lock:
        if _global_oast is None or not _global_oast.started:
            _global_oast = OASTServer(public_base_url=public_base_url)
            _global_oast.start()
            _global_oast.start_dns_smtp()
            if host_override:
                _global_oast.listen_ip = host_override
            if public_base_url:
                _global_oast.set_public_base_url(public_base_url)
        elif public_base_url:
            _global_oast.set_public_base_url(public_base_url)
        if host_override:
            _global_oast.listen_ip = host_override
    return _global_oast


# ── Collaborator / OOB Interaction Tracking ───────────────────────────────────
#
# Port of Burp Suite's Montoya API:
#   git/api/montoya/collaborator/
#       InteractionType       → InteractionType  (enum)
#       DnsDetails            → DnsDetails       (dataclass)
#       HttpDetails           → HttpDetails      (dataclass)
#       SmtpDetails           → SmtpDetails      (dataclass)
#       Interaction           → Interaction      (dataclass)
#       CollaboratorPayload   → CollaboratorPayload (dataclass)
#       CollaboratorClient    → CollaboratorClient  (class)
#
# Extends the existing HTTP/DNS/SMTP OAST servers with a unified per-payload
# ID system, typed interaction objects, cross-channel polling, and
# interaction → finding correlation.
# ─────────────────────────────────────────────────────────────────────────────


class InteractionType(enum.Enum):
    """
    Mirrors Burp Suite's InteractionType enum.

    DNS  — A DNS lookup was received for the payload subdomain.
           Triggered by blind SSRF, XXE, Log4Shell, JNDI injection, etc.
    HTTP — An HTTP request was received at the OAST HTTP listener.
           Triggered by SSRF, open redirect, blind injection with HTTP fetch.
    SMTP — An SMTP connection was received at the OAST SMTP listener.
           Triggered by blind email injection, XXE mail exfil, SSRF to port 25.
    """
    DNS  = "dns"
    HTTP = "http"
    SMTP = "smtp"


@dataclass
class DnsDetails:
    """Details of a DNS-type OOB interaction."""
    qname:      str   # fully-qualified domain name queried
    source_ip:  str   # IP that sent the query


@dataclass
class HttpDetails:
    """Details of an HTTP-type OOB interaction."""
    method:   str
    path:     str
    headers:  dict = field(default_factory=dict)
    body:     str  = ""


@dataclass
class SmtpDetails:
    """Details of an SMTP-type OOB interaction."""
    mail_from: str = ""
    rcpt_to:   str = ""
    body:      str = ""


@dataclass
class Interaction:
    """
    Mirrors Burp Suite's Interaction class.

    Represents one OOB callback received from the target application after
    a payload was injected.  Exactly one detail field is populated based on
    the interaction type.

    The injection context fields (vuln_type, target_url, parameter) are
    copied from the CollaboratorPayload that triggered the callback so that
    callers never need to cross-reference.
    """
    interaction_id: str              # payload token that produced this callback
    type:           InteractionType
    timestamp_ms:   float            # Unix epoch * 1000
    source_ip:      str

    # Exactly one is populated:
    dns_details:    Optional[DnsDetails]  = None
    http_details:   Optional[HttpDetails] = None
    smtp_details:   Optional[SmtpDetails] = None

    # Injection context (copied from CollaboratorPayload at creation time)
    vuln_type:   str = ""
    target_url:  str = ""
    parameter:   str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class CollaboratorPayload:
    """
    Mirrors Burp Suite's CollaboratorPayload class.

    All three injection vectors (HTTP URL, DNS hostname, SMTP address) share
    the same payload_id so any callback — regardless of channel — can be
    correlated back to the exact injection point that triggered it.

    Attributes
    ----------
    payload_id  The unique token embedded in every injection vector.
    http_url    Full URL to inject as a value (SSRF, redirect, fetch, etc.)
    dns_host    Hostname to inject (blind XXE, Log4Shell JNDI, DNS rebind)
    smtp_addr   Email address to inject (SMTP injection, XXE mail exfil)
    """
    payload_id:  str
    http_url:    str
    dns_host:    str
    smtp_addr:   str
    vuln_type:   str
    target_url:  str
    parameter:   str
    created_at:  float = field(default_factory=time.time)


# Severity map for correlate_to_finding()
_VULN_SEVERITY: dict[str, str] = {
    "ssrf":              "critical",
    "blind_ssrf":        "critical",
    "blind_xxe":         "critical",
    "xxe":               "critical",
    "log4shell":         "critical",
    "cmdi":              "critical",
    "rfi":               "critical",
    "sqli_bool_true":    "high",
    "sqli_blind_time":   "high",
    "xss_blind":         "high",
    "header_injection":  "medium",
}


class CollaboratorClient:
    """
    Mirrors Burp Suite's CollaboratorClient.

    Wraps OASTServer to provide a per-payload unique ID system that spans all
    three OOB channels (HTTP / DNS / SMTP), typed Interaction objects, unified
    cross-channel polling, and interaction → finding correlation.

    Design
    ------
    - Every call to generate_payload() mints one token (24 hex chars).
    - The same token is embedded in the HTTP URL, DNS hostname, and SMTP address
      so callbacks from any channel map to the same injection.
    - get_interactions() aggregates callbacks from all three channels.
    - correlate_to_finding() converts confirmed interactions into a finding dict
      compatible with the scanner's results list.

    Usage::

        oast   = get_or_start_oast()
        client = CollaboratorClient(oast)

        # For each injection point:
        payload = client.generate_payload("ssrf", "https://target/api", "url_param")
        inject(payload.http_url)          # in URL-fetch parameters
        inject(payload.dns_host)          # in hostname parameters / JNDI
        inject(payload.smtp_addr)         # in email / To: fields

        # After sending payloads, poll for OOB callbacks:
        interactions = client.poll_payload(payload.payload_id, wait=10.0)
        finding = client.correlate_to_finding(payload.payload_id)
        if finding:
            results.append(finding)

        # Or poll every registered payload at once:
        all_hits = client.poll_all_payloads(wait=30.0)
    """

    def __init__(self, oast_server: OASTServer) -> None:
        self._server   = oast_server
        self._payloads: dict[str, CollaboratorPayload] = {}
        self._lock     = threading.Lock()

    # ── Payload generation ────────────────────────────────────────────────────

    def generate_payload(
        self,
        vuln_type:  str,
        target_url: str,
        parameter:  str,
    ) -> CollaboratorPayload:
        """
        Mint a new unique payload that covers all three OOB channels.

        Args:
            vuln_type:  Vulnerability class (e.g. "ssrf", "log4shell", "blind_xxe").
            target_url: URL of the endpoint under test (for finding context).
            parameter:  Name of the injected parameter (for finding context).

        Returns:
            CollaboratorPayload with .http_url, .dns_host, .smtp_addr.
            All three embed the same payload_id.
        """
        if not self._server.started:
            raise RuntimeError(
                "OASTServer not started — call start() or get_or_start_oast() first"
            )

        token = uuid.uuid4().hex[:24]

        # Register with the HTTP handler so metadata is available when callbacks arrive
        with _OASTHandler._lock:
            _OASTHandler._token_map[token] = {
                "vuln_type":  vuln_type,
                "target_url": target_url,
                "parameter":  parameter,
            }

        http_url  = self._server.callback_url_for_token(token)
        dns_host  = DNSOASTServer.make_fqdn(token)
        smtp_addr = (
            self._server._smtp_server.make_addr(token)
            if self._server._smtp_server
            else f"{token}@oast-smtp.local"
        )

        payload = CollaboratorPayload(
            payload_id  = token,
            http_url    = http_url,
            dns_host    = dns_host,
            smtp_addr   = smtp_addr,
            vuln_type   = vuln_type,
            target_url  = target_url,
            parameter   = parameter,
        )

        with self._lock:
            self._payloads[token] = payload

        return payload

    # ── Interaction retrieval ─────────────────────────────────────────────────

    def get_interactions(self, payload_id: str) -> list[Interaction]:
        """
        Return all OOB interactions received so far for *payload_id*.

        Aggregates all three channels (HTTP, DNS, SMTP) and returns typed
        Interaction objects sorted by ascending timestamp.
        """
        with self._lock:
            meta = self._payloads.get(payload_id)
        ctx = {
            "vuln_type":  meta.vuln_type  if meta else "",
            "target_url": meta.target_url if meta else "",
            "parameter":  meta.parameter  if meta else "",
        }

        interactions: list[Interaction] = []

        # HTTP channel
        with _OASTHandler._lock:
            for cb in _OASTHandler._callbacks:
                if cb.token == payload_id:
                    interactions.append(Interaction(
                        interaction_id = payload_id,
                        type           = InteractionType.HTTP,
                        timestamp_ms   = cb.timestamp * 1000,
                        source_ip      = cb.source_ip,
                        http_details   = HttpDetails(
                            method  = cb.method,
                            path    = cb.path,
                            headers = cb.headers,
                            body    = cb.body,
                        ),
                        **ctx,
                    ))

        # DNS channel
        if self._server._dns_server:
            for cb in self._server._dns_server.poll(payload_id):
                interactions.append(Interaction(
                    interaction_id = payload_id,
                    type           = InteractionType.DNS,
                    timestamp_ms   = cb["timestamp"] * 1000,
                    source_ip      = cb["source_ip"],
                    dns_details    = DnsDetails(
                        qname     = cb["qname"],
                        source_ip = cb["source_ip"],
                    ),
                    **ctx,
                ))

        # SMTP channel
        if self._server._smtp_server:
            for cb in self._server._smtp_server.poll(payload_id):
                interactions.append(Interaction(
                    interaction_id = payload_id,
                    type           = InteractionType.SMTP,
                    timestamp_ms   = cb["timestamp"] * 1000,
                    source_ip      = cb["source_ip"],
                    smtp_details   = SmtpDetails(
                        mail_from = cb.get("mail_from", ""),
                        rcpt_to   = cb.get("rcpt_to",   ""),
                        body      = cb.get("body",      ""),
                    ),
                    **ctx,
                ))

        interactions.sort(key=lambda i: i.timestamp_ms)
        return interactions

    def poll_payload(
        self,
        payload_id: str,
        wait:       float = 5.0,
        interval:   float = 0.3,
    ) -> list[Interaction]:
        """
        Block until at least one interaction arrives for *payload_id* or timeout.

        Args:
            payload_id: Token from generate_payload().
            wait:       Maximum seconds to wait.
            interval:   Poll interval in seconds.

        Returns:
            All interactions received (empty list on timeout).
        """
        deadline = time.time() + wait
        while time.time() < deadline:
            found = self.get_interactions(payload_id)
            if found:
                return found
            time.sleep(interval)
        return []

    def poll_all_payloads(
        self,
        wait:     float = 5.0,
        interval: float = 0.5,
    ) -> dict[str, list[Interaction]]:
        """
        Poll every registered payload and return those with at least one interaction.

        Returns:
            Mapping of payload_id → list[Interaction] for payloads that got callbacks.
            Empty dict on timeout.
        """
        deadline = time.time() + wait
        results:  dict[str, list[Interaction]] = {}

        while time.time() < deadline:
            with self._lock:
                ids = list(self._payloads.keys())
            for pid in ids:
                hits = self.get_interactions(pid)
                if hits:
                    results[pid] = hits
            if results:
                return results
            time.sleep(interval)

        # Final sweep after timeout
        with self._lock:
            ids = list(self._payloads.keys())
        for pid in ids:
            hits = self.get_interactions(pid)
            if hits:
                results[pid] = hits
        return results

    # ── Finding correlation ───────────────────────────────────────────────────

    def correlate_to_finding(self, payload_id: str) -> Optional[dict]:
        """
        If interactions exist for *payload_id*, build a finding dict.

        The returned dict is compatible with scanner.py's finding format
        (url, category, finding, severity, evidence, remediation, cwe).
        Returns None when no interactions have been received yet.
        """
        interactions = self.get_interactions(payload_id)
        if not interactions:
            return None

        with self._lock:
            payload = self._payloads.get(payload_id)
        if not payload:
            return None

        channels   = sorted({i.type.value for i in interactions})
        first      = interactions[0]
        ch_display = ", ".join(c.upper() for c in channels)

        return {
            "url":         payload.target_url,
            "category":    "blind_injection",
            "vuln_type":   payload.vuln_type,
            "parameter":   payload.parameter,
            "finding":     (
                f"OOB interaction confirmed via {ch_display} — "
                f"blind {payload.vuln_type.replace('_', ' ').upper()} "
                f"[param={payload.parameter!r}]"
            ),
            "severity":    _VULN_SEVERITY.get(payload.vuln_type, "high"),
            "evidence":    (
                f"First callback from {first.source_ip} "
                f"({first.type.value.upper()}, "
                f"{int(first.timestamp_ms / 1000)} Unix). "
                f"Total interactions: {len(interactions)} "
                f"across channel(s): {ch_display}."
            ),
            "remediation": (
                "An OOB callback confirms the server made an outbound request "
                "using attacker-controlled data.  Investigate and remediate the "
                "injection vector immediately."
            ),
            "cwe":          _FINDING_CWE.get(payload.vuln_type, "CWE-918"),
            "interactions": [i.to_dict() for i in interactions],
        }

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def active_payload_count(self) -> int:
        """Number of payloads currently tracked by this client."""
        with self._lock:
            return len(self._payloads)

    def clear_payloads(self) -> None:
        """Discard all tracked payloads without stopping the OOB servers."""
        with self._lock:
            self._payloads.clear()


# CWE map for correlate_to_finding()
_FINDING_CWE: dict[str, str] = {
    "ssrf":           "CWE-918",
    "blind_ssrf":     "CWE-918",
    "blind_xxe":      "CWE-611",
    "xxe":            "CWE-611",
    "log4shell":      "CWE-917",
    "cmdi":           "CWE-78",
    "rfi":            "CWE-98",
    "xss_blind":      "CWE-79",
    "sqli_bool_true": "CWE-89",
    "sqli_blind_time":"CWE-89",
}
