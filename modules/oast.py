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

import threading
import uuid
import time
from dataclasses import dataclass, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional


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


# ── OAST Server ───────────────────────────────────────────────────────────────

class OASTServer:
    """
    Local OAST listener. Generates unique injection URLs.

    Note: For external target testing, the machine running this must be
    reachable from the target server. For localhost/local-network targets
    (e.g. DVWA, Juice Shop, lab VMs) this works as-is.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self.host    = host
        self.port    = port   # 0 = OS picks a random available port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.started = False
        self.listen_ip: str = "127.0.0.1"  # set after start

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
        host  = host_override or self.listen_ip

        with _OASTHandler._lock:
            _OASTHandler._token_map[token] = {
                "vuln_type":  vuln_type,
                "target_url": target_url,
                "parameter":  parameter,
            }

        return f"http://{host}:{self.port}/{token}"

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

    def status(self) -> dict:
        return {
            "started":         self.started,
            "port":            self.port,
            "listen_ip":       self.listen_ip,
            "callbacks_total": len(_OASTHandler._callbacks),
            "tokens_active":   len(_OASTHandler._token_map),
        }


# ── Global singleton ──────────────────────────────────────────────────────────

_global_oast: Optional[OASTServer] = None
_oast_lock = threading.Lock()


def get_or_start_oast(host_override: str = "") -> OASTServer:
    """Return the global OAST server, starting it if needed."""
    global _global_oast
    with _oast_lock:
        if _global_oast is None or not _global_oast.started:
            _global_oast = OASTServer()
            _global_oast.start()
            if host_override:
                _global_oast.listen_ip = host_override
    return _global_oast
