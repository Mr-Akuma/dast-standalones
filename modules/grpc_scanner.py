"""
gRPC Security Scanner -- comprehensive gRPC endpoint security testing.

Tests performed:
  1.  Service Discovery       -- reflection API enumeration to extract full schema
  2.  Protobuf Payload Fuzzing -- type-aware mutations: SQLi, XXE, overflow, nesting
  3.  mTLS Certificate Tests  -- plaintext, no-cert, self-signed, expired, wrong SNI
  4.  Metadata Injection      -- HTTP/2 header attacks: auth bypass, CRLF, IDOR, SSRF
  5.  Stream Type Security    -- unbounded streams, missing backpressure, RST_STREAM

No compiled protobuf stubs required.  Uses:
  - grpcio + grpcio-reflection for reflection API and channel management
  - Raw protobuf wire encoding helpers (implemented here) for schemaless fuzzing
  - httpx (http2=True) as fallback transport when grpcio is unavailable

Zero hard dependencies beyond the Python standard library; grpcio and httpx are
optional and detected at import time.
"""
from __future__ import annotations

import logging
import os
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Callable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional dependency detection
# ---------------------------------------------------------------------------

try:
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
    GRPCIO_AVAILABLE = True
    GRPCIO_IMPORT_ERROR = None
except Exception as exc:
    # grpc/protobuf can fail with binary compatibility errors on newer Python
    # builds. Treat it like a missing optional dependency and use fallbacks.
    grpc = None  # type: ignore[assignment]
    reflection_pb2 = None  # type: ignore[assignment]
    reflection_pb2_grpc = None  # type: ignore[assignment]
    GRPCIO_AVAILABLE = False
    GRPCIO_IMPORT_ERROR = str(exc)

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    HTTPX_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)

# ── Module-level constants ────────────────────────────────────────────────────

GRPC_COMMON_PORTS = [50051, 50052, 9090, 8080, 8443, 443, 9000, 6565]

GRPC_STATUS_CODES = {
    0: "OK",
    1: "CANCELLED",
    2: "UNKNOWN",
    3: "INVALID_ARGUMENT",
    4: "DEADLINE_EXCEEDED",
    5: "NOT_FOUND",
    7: "PERMISSION_DENIED",
    8: "RESOURCE_EXHAUSTED",
    12: "UNIMPLEMENTED",
    13: "INTERNAL",
    14: "UNAVAILABLE",
    16: "UNAUTHENTICATED",
}

# Metadata payloads: (header_name, header_value, attack_label)
METADATA_ATTACKS: list[tuple[str, str, str]] = [
    # Auth bypass
    ("authorization",      "Bearer ' OR '1'='1'--",           "sql_in_auth_header"),
    ("authorization",      "Bearer <script>alert(1)</script>", "xss_in_auth_header"),
    ("x-api-key",          "' UNION SELECT 1,2,3--",          "sqli_api_key"),
    # Privilege escalation via metadata
    ("x-user-id",          "1",                               "idor_via_metadata"),
    ("x-user-role",        "admin",                           "privilege_via_metadata"),
    ("x-admin",            "true",                            "admin_flag_metadata"),
    ("x-forwarded-for",    "127.0.0.1",                       "ssrf_via_metadata"),
    ("x-original-url",     "/admin",                          "path_override_metadata"),
    # CRLF injection in metadata key (header injection)
    ("x-test\r\nx-injected", "injected",                      "crlf_metadata"),
    # Timeout/DoS
    ("grpc-timeout",       "0",                               "zero_timeout_bypass"),
    ("grpc-timeout",       "999999999S",                      "timeout_overflow"),
]

# Well-known gRPC service paths to probe when reflection is unavailable
WELL_KNOWN_SERVICES = [
    "grpc.health.v1.Health/Check",
    "grpc.health.v1.Health/Watch",
    "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
]


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class GrpcFinding:
    """Single security finding from a gRPC scan."""
    host:        str
    port:        int
    service:     str
    method:      str
    test:        str            # test name
    finding:     str            # human-readable description
    severity:    str            # critical / high / medium / low
    vuln_type:   str            # grpc_reflection_exposed, grpc_injection, ...
    proof:       str            # grpc-status + response snippet
    grpc_status: int = -1
    payload_name: str = ""
    stream_type: str = ""       # unary / server_stream / client_stream / bidi

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GrpcMethod:
    """Descriptor for a single gRPC method discovered via reflection."""
    service:       str
    method:        str
    full_name:     str          # service/method
    stream_type:   str          # unary / server_stream / client_stream / bidi
    request_type:  str
    response_type: str


# ── Wire-protocol helpers (no external deps) ─────────────────────────────────

def _encode_varint(n: int) -> bytes:
    """Encode an unsigned integer as LEB128 varint (protobuf standard)."""
    buf = bytearray()
    # Mask to unsigned 64-bit for safety
    n = n & 0xFFFFFFFFFFFFFFFF
    while n > 0x7F:
        buf.append((n & 0x7F) | 0x80)
        n >>= 7
    buf.append(n & 0x7F)
    return bytes(buf)


def _encode_signed_varint(n: int) -> bytes:
    """Encode a signed integer as a two's-complement 64-bit varint.

    Negative values are encoded as their 64-bit unsigned equivalent, which
    produces a 10-byte varint -- this is how protobuf encodes int64/int32.
    """
    if n >= 0:
        return _encode_varint(n)
    # Two's complement: -1 => 0xFFFFFFFFFFFFFFFF
    return _encode_varint(n & 0xFFFFFFFFFFFFFFFF)


def _pb_field(num: int, wire: int, value: bytes) -> bytes:
    """Build a raw protobuf field.

    Wire types:
      0 = varint
      1 = 64-bit fixed
      2 = length-delimited
      5 = 32-bit fixed
    """
    tag = (num << 3) | wire
    return _encode_varint(tag) + value


def _pb_string(field_num: int, s: str) -> bytes:
    """Encode a string as a protobuf length-delimited field."""
    encoded = s.encode("utf-8")
    return _pb_field(field_num, 2, _encode_varint(len(encoded)) + encoded)


def _pb_varint(field_num: int, n: int) -> bytes:
    """Encode an integer as a protobuf varint field."""
    return _pb_field(field_num, 0, _encode_signed_varint(n))


def _pb_nested(field_num: int, inner: bytes) -> bytes:
    """Encode nested message bytes as a length-delimited field."""
    return _pb_field(field_num, 2, _encode_varint(len(inner)) + inner)


def _grpc_frame(body: bytes, compressed: bool = False) -> bytes:
    """Build the 5-byte gRPC length-prefixed frame.

    Format: [compressed_flag: 1 byte] [message_length: 4 bytes big-endian] [body]
    """
    flag = 1 if compressed else 0
    return struct.pack(">BI", flag, len(body)) + body


def _make_fuzz_payloads() -> list[tuple[str, bytes]]:
    """Generate the 8 protobuf-encoded fuzz payloads.

    Each payload targets a different class of server vulnerability.
    Returns a list of (name, raw_protobuf_bytes) tuples.
    """
    payloads: list[tuple[str, bytes]] = []

    # 1. Empty message -- triggers default handling; may crash if server
    #    assumes at least one field is always present.
    payloads.append(("empty_message", b""))

    # 2. Max varint -- field 1 = 2^63-1 as INT64.  Tests integer overflow
    #    handling and whether the server safely bounds large values.
    payloads.append(("max_varint", _pb_varint(1, (2**63) - 1)))

    # 3. Negative varint -- field 1 = -1.  Encoded as 10-byte two's complement.
    #    Servers that cast to unsigned or use as array index may crash.
    payloads.append(("negative_varint", _pb_varint(1, -1)))

    # 4. SQL injection in strings -- field 1 and field 2 carry SQLi payloads.
    #    Tests whether string fields flow unescaped into SQL queries.
    sqli = (
        _pb_string(1, "' OR '1'='1")
        + _pb_string(2, "1; DROP TABLE users--")
    )
    payloads.append(("sqli_strings", sqli))

    # 5. XXE / path traversal / SSTI -- field 1 carries traversal and template
    #    injection strings.  Detects file-read, template engine eval, or XML
    #    entity expansion when protobuf strings are forwarded to other parsers.
    xxe = (
        _pb_string(1, "../../../../etc/passwd")
        + _pb_string(2, "${7*7}")
        + _pb_string(3, "{{7*7}}")
    )
    payloads.append(("xxe_traversal_ssti", xxe))

    # 6. Oversized message -- field 1 = 100 000 'A' characters.  Tests whether
    #    the server enforces max message size or blindly allocates memory.
    payloads.append(("oversized_100k", _pb_string(1, "A" * 100_000)))

    # 7. Deeply nested message -- 50 levels of nesting on field 1.  Protobuf
    #    parsers that use recursion may stack-overflow.
    inner = _pb_string(1, "deep")
    for _ in range(50):
        inner = _pb_nested(1, inner)
    payloads.append(("deeply_nested_50", inner))

    # 8. Malformed varint -- 10 bytes of 0xFF is an invalid varint (overflow).
    #    Low-level protobuf decoders must reject this; if they don't, they may
    #    enter infinite loops or return garbage data.
    payloads.append(("malformed_varint", b"\xff" * 10))

    return payloads


# ── Certificate generation helpers ────────────────────────────────────────────

def _generate_self_signed_cert(
    cn: str = "evil.example.com",
    expired: bool = False,
) -> tuple[bytes, bytes]:
    """Generate a self-signed X.509 certificate and private key in PEM format.

    Args:
        cn: Common Name for the certificate subject.
        expired: If True, set notAfter to yesterday so the cert is already expired.

    Returns:
        (cert_pem, key_pem) as bytes.

    Requires the ``cryptography`` library.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=30)
        not_after = now - timedelta(days=1)
    else:
        not_before = now
        not_after = now + timedelta(days=1)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ── GrpcScanner ───────────────────────────────────────────────────────────────

class GrpcScanner:
    """Comprehensive gRPC security scanner.

    Runs five test groups against a target gRPC server:

      1. Service discovery via reflection API
      2. Protobuf payload fuzzing (type-aware, 8 mutation strategies)
      3. mTLS certificate validation testing
      4. Metadata (HTTP/2 header) injection
      5. Stream-type security testing

    Supports both grpcio (preferred) and httpx (http2) as transport backends.
    All grpcio calls degrade gracefully when the library is absent.
    """

    def __init__(
        self,
        host: str,
        port: int = 50051,
        stop_event: Optional[threading.Event] = None,
        timeout: int = 10,
        proto_file: Optional[str] = None,
        use_tls: bool = False,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        ca_cert: Optional[str] = None,
        on_finding: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
        auth_metadata: Optional[List[Tuple[str, str]]] = None,
    ):
        self.host = host
        self.port = port
        self.stop_event = stop_event or threading.Event()
        self.timeout = timeout
        self.proto_file = proto_file
        self.use_tls = use_tls
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_cert = ca_cert
        self.on_finding = on_finding
        self.on_progress = on_progress
        # Application-level auth forwarded as gRPC metadata on every call.
        # Typically [("authorization", "Bearer <token>")] extracted from the
        # HTTP auth session.  Prepended before any per-call attack metadata so
        # injection tests still fire even on auth-gated services.
        self.auth_metadata: List[Tuple[str, str]] = list(auth_metadata) if auth_metadata else []

        self.target = f"{host}:{port}"
        self.findings: list[GrpcFinding] = []
        self.methods: list[GrpcMethod] = []

        self._scan_id = uuid.uuid4().hex[:12]

    # -- Public API ---------------------------------------------------------

    def scan(self) -> list[GrpcFinding]:
        """Execute all five test groups and return accumulated findings.

        Each test group is wrapped in its own try/except so a failure in one
        never prevents the others from running.  The ``stop_event`` is checked
        between every group, allowing graceful cancellation.
        """
        groups = [
            ("service_discovery",   self._test_service_discovery),
            ("payload_fuzzing",     self._test_payload_fuzzing),
            ("mtls_validation",     self._test_mtls_validation),
            ("metadata_injection",  self._test_metadata_injection),
            ("stream_security",     self._test_stream_security),
        ]

        for name, fn in groups:
            if self.stop_event.is_set():
                logger.info("Stop event set -- aborting scan early")
                break
            self._progress(name, f"Starting {name} against {self.target}")
            try:
                fn()
            except Exception:
                logger.exception("Test group %s failed with unhandled exception", name)

        return self.findings

    # -- Helpers ------------------------------------------------------------

    def _stopped(self) -> bool:
        return self.stop_event.is_set()

    def _progress(self, step: str, detail: str) -> None:
        if self.on_progress:
            try:
                self.on_progress(step, detail)
            except Exception:
                pass

    def _add_finding(self, f: GrpcFinding) -> None:
        self.findings.append(f)
        if self.on_finding:
            try:
                self.on_finding(f)
            except Exception:
                pass

    def _make_finding(self, **kwargs) -> GrpcFinding:
        """Convenience builder that pre-fills host/port."""
        kwargs.setdefault("host", self.host)
        kwargs.setdefault("port", self.port)
        return GrpcFinding(**kwargs)

    def _get_channel(self, *, use_tls: bool | None = None) -> "grpc.Channel":
        """Create a grpcio channel with the configured TLS / mTLS settings.

        This is a thin wrapper so every test group gets a consistently
        configured channel without duplicating credential setup.
        """
        if not GRPCIO_AVAILABLE:
            raise RuntimeError("grpcio is not installed")

        if use_tls is None:
            use_tls = self.use_tls

        if use_tls:
            root_certs = None
            private_key = None
            cert_chain = None

            if self.ca_cert and os.path.isfile(self.ca_cert):
                with open(self.ca_cert, "rb") as fh:
                    root_certs = fh.read()
            if self.client_key and os.path.isfile(self.client_key):
                with open(self.client_key, "rb") as fh:
                    private_key = fh.read()
            if self.client_cert and os.path.isfile(self.client_cert):
                with open(self.client_cert, "rb") as fh:
                    cert_chain = fh.read()

            creds = grpc.ssl_channel_credentials(
                root_certificates=root_certs,
                private_key=private_key,
                certificate_chain=cert_chain,
            )
            return grpc.secure_channel(
                self.target,
                creds,
                options=[("grpc.max_receive_message_length", 10 * 1024 * 1024)],
            )
        else:
            return grpc.insecure_channel(
                self.target,
                options=[("grpc.max_receive_message_length", 10 * 1024 * 1024)],
            )

    def _raw_unary_call(
        self,
        path: str,
        body: bytes,
        metadata: Optional[list[tuple[str, str]]] = None,
        *,
        timeout: Optional[int] = None,
    ) -> tuple[int, str, bytes]:
        """Issue a raw unary gRPC call and return (status_code, details, response_bytes).

        Tries grpcio first; falls back to httpx HTTP/2 POST if grpcio is
        unavailable.  The ``path`` must be the full ``/package.Service/Method``
        path.

        ``self.auth_metadata`` (e.g. Bearer token) is always prepended so that
        calls reach auth-gated services.  Per-call ``metadata`` (used by attack
        tests) is appended after, keeping injection payloads clearly separated.
        """
        timeout = timeout or self.timeout

        # Merge auth metadata + per-call metadata; auth always comes first.
        merged_metadata: list[tuple[str, str]] = list(self.auth_metadata)
        if metadata:
            merged_metadata.extend(metadata)
        effective_metadata = merged_metadata or None

        if GRPCIO_AVAILABLE:
            return self._raw_unary_grpcio(path, body, effective_metadata, timeout)
        elif HTTPX_AVAILABLE:
            return self._raw_unary_httpx(path, body, effective_metadata, timeout)
        else:
            raise RuntimeError("Neither grpcio nor httpx is available")

    def _raw_unary_grpcio(
        self,
        path: str,
        body: bytes,
        metadata: Optional[list[tuple[str, str]]],
        timeout: int,
    ) -> tuple[int, str, bytes]:
        """Execute a raw unary call via grpcio's generic channel interface."""
        try:
            channel = self._get_channel()
            # Use the low-level unary-unary callable on the channel directly.
            method = channel.unary_unary(
                path,
                request_serializer=lambda x: x,       # already raw bytes
                response_deserializer=lambda x: x,     # return raw bytes
            )
            response = method(
                body,
                timeout=timeout,
                metadata=metadata or [],
            )
            channel.close()
            return (0, "OK", response)
        except grpc.RpcError as exc:
            code = exc.code().value[0] if hasattr(exc, "code") else -1
            details = exc.details() if hasattr(exc, "details") else str(exc)
            return (code, details, b"")
        except Exception as exc:
            return (-1, str(exc), b"")

    def _raw_unary_httpx(
        self,
        path: str,
        body: bytes,
        metadata: Optional[list[tuple[str, str]]],
        timeout: int,
    ) -> tuple[int, str, bytes]:
        """Execute a raw unary gRPC call over HTTP/2 using httpx.

        gRPC over HTTP/2 is a POST to the method path with content-type
        ``application/grpc`` and the body wrapped in a 5-byte length-prefixed
        frame.
        """
        scheme = "https" if self.use_tls else "http"
        url = f"{scheme}://{self.target}{path}"

        headers = {
            "content-type": "application/grpc",
            "te": "trailers",
        }
        if metadata:
            for key, value in metadata:
                # Skip keys that would collide with HTTP/2 pseudo-headers
                if not key.startswith(":"):
                    headers[key] = value

        framed = _grpc_frame(body)

        try:
            with httpx.Client(http2=True, verify=self.use_tls, timeout=timeout) as client:
                resp = client.post(url, content=framed, headers=headers)

            # Extract grpc-status from trailers (httpx exposes trailing headers
            # in the headers dict for HTTP/2).
            grpc_status = int(resp.headers.get("grpc-status", -1))
            grpc_message = resp.headers.get("grpc-message", "")

            # Strip the 5-byte frame header from the response body if present.
            resp_body = resp.content
            if len(resp_body) >= 5:
                resp_body = resp_body[5:]

            return (grpc_status, grpc_message, resp_body)
        except Exception as exc:
            return (-1, str(exc), b"")

    # ======================================================================
    # TEST GROUP 1 -- Service Discovery via Reflection
    # ======================================================================

    def _test_service_discovery(self) -> None:
        """Enumerate services and methods through the gRPC server reflection API.

        The reflection API is a bidirectional stream at
        ``grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo``.
        If the server has reflection enabled, we can dump every service name,
        method signature, and message type -- a goldmine for attackers.

        Attack rationale:
            Reflection should be disabled in production.  Exposing it leaks the
            entire API surface, enabling targeted fuzzing and business-logic
            abuse without needing .proto files.
        """
        self._progress("service_discovery", "Attempting reflection API enumeration")

        if GRPCIO_AVAILABLE:
            discovered = self._discover_via_reflection()
        else:
            discovered = False

        if not discovered:
            self._progress("service_discovery", "Reflection unavailable, probing well-known paths")
            self._probe_well_known_services()

    def _discover_via_reflection(self) -> bool:
        """Use grpc.reflection to enumerate all services.

        Returns True if reflection was accessible, False otherwise.
        """
        try:
            channel = self._get_channel()
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)

            # Step 1: List all services
            list_req = reflection_pb2.ServerReflectionRequest(
                list_services="",
            )

            responses = stub.ServerReflectionInfo(
                iter([list_req]), timeout=self.timeout,
                metadata=self.auth_metadata or None,
            )

            service_names: list[str] = []
            for resp in responses:
                if resp.HasField("list_services_response"):
                    for svc in resp.list_services_response.service:
                        service_names.append(svc.name)

            channel.close()

            if not service_names:
                return False

            # Finding: reflection is exposed
            self._add_finding(self._make_finding(
                service="*",
                method="ServerReflectionInfo",
                test="reflection_enumeration",
                finding=(
                    f"gRPC reflection API is enabled and exposes "
                    f"{len(service_names)} service(s): {', '.join(service_names[:10])}"
                ),
                severity="medium",
                vuln_type="grpc_reflection_exposed",
                proof=f"services={service_names}",
            ))

            # Step 2: For each service, fetch its FileDescriptorProto
            self._progress("service_discovery", f"Fetching descriptors for {len(service_names)} services")
            self._fetch_service_descriptors(service_names)

            return True

        except Exception as exc:
            logger.debug("Reflection discovery failed: %s", exc)
            return False

    def _fetch_service_descriptors(self, service_names: list[str]) -> None:
        """Fetch FileDescriptorProtos for each service and parse method info.

        We send ``FileContainingSymbol`` requests through a fresh reflection
        stream.  The response contains serialised ``FileDescriptorProto``
        bytes which we parse with minimal hand-rolled logic (we only need
        service/method names and streaming flags, not full proto parsing).
        """
        try:
            channel = self._get_channel()
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)

            requests_list = [
                reflection_pb2.ServerReflectionRequest(
                    file_containing_symbol=svc_name,
                )
                for svc_name in service_names
                if svc_name != "grpc.reflection.v1alpha.ServerReflection"
            ]

            if not requests_list:
                channel.close()
                return

            responses = stub.ServerReflectionInfo(
                iter(requests_list), timeout=self.timeout,
                metadata=self.auth_metadata or None,
            )

            for resp in responses:
                if self._stopped():
                    break
                if resp.HasField("file_descriptor_response"):
                    for fd_bytes in resp.file_descriptor_response.file_descriptor_proto:
                        self._parse_file_descriptor(fd_bytes)

            channel.close()
        except Exception as exc:
            logger.debug("Descriptor fetch failed: %s", exc)

    def _parse_file_descriptor(self, raw: bytes) -> None:
        """Minimalist FileDescriptorProto parser.

        We only extract service definitions (tag 6) and within each service
        the method descriptors (tag 2).  Full proto parsing is overkill --
        we just need names and streaming flags.

        FileDescriptorProto layout (relevant fields):
          - field 2: package name (string)
          - field 6: ServiceDescriptorProto (repeated message)
            - field 1: service name (string)
            - field 2: MethodDescriptorProto (repeated message)
              - field 1: method name (string)
              - field 2: input type (string)
              - field 3: output type (string)
              - field 5: client_streaming (bool/varint)
              - field 6: server_streaming (bool/varint)
        """
        try:
            fields = self._parse_proto_fields(raw)
        except Exception:
            return

        # Extract package name
        package = ""
        for fnum, _wire, val in fields:
            if fnum == 2 and isinstance(val, bytes):
                package = val.decode("utf-8", errors="replace")
                break

        # Extract service descriptors (field 6)
        for fnum, _wire, val in fields:
            if fnum == 6 and isinstance(val, bytes):
                self._parse_service_descriptor(package, val)

    def _parse_service_descriptor(self, package: str, raw: bytes) -> None:
        """Parse a ServiceDescriptorProto message."""
        try:
            fields = self._parse_proto_fields(raw)
        except Exception:
            return

        svc_name = ""
        for fnum, _wire, val in fields:
            if fnum == 1 and isinstance(val, bytes):
                svc_name = val.decode("utf-8", errors="replace")
                break

        full_svc = f"{package}.{svc_name}" if package else svc_name

        # Parse methods (field 2)
        for fnum, _wire, val in fields:
            if fnum == 2 and isinstance(val, bytes):
                self._parse_method_descriptor(full_svc, val)

    def _parse_method_descriptor(self, service: str, raw: bytes) -> None:
        """Parse a MethodDescriptorProto and register a GrpcMethod."""
        try:
            fields = self._parse_proto_fields(raw)
        except Exception:
            return

        method_name = ""
        input_type = ""
        output_type = ""
        client_streaming = False
        server_streaming = False

        for fnum, _wire, val in fields:
            if fnum == 1 and isinstance(val, bytes):
                method_name = val.decode("utf-8", errors="replace")
            elif fnum == 2 and isinstance(val, bytes):
                input_type = val.decode("utf-8", errors="replace")
            elif fnum == 3 and isinstance(val, bytes):
                output_type = val.decode("utf-8", errors="replace")
            elif fnum == 5 and isinstance(val, int):
                client_streaming = bool(val)
            elif fnum == 6 and isinstance(val, int):
                server_streaming = bool(val)

        if client_streaming and server_streaming:
            stream_type = "bidi"
        elif server_streaming:
            stream_type = "server_stream"
        elif client_streaming:
            stream_type = "client_stream"
        else:
            stream_type = "unary"

        gm = GrpcMethod(
            service=service,
            method=method_name,
            full_name=f"{service}/{method_name}",
            stream_type=stream_type,
            request_type=input_type,
            response_type=output_type,
        )
        self.methods.append(gm)
        logger.debug("Discovered method: %s (%s)", gm.full_name, stream_type)

    @staticmethod
    def _parse_proto_fields(raw: bytes) -> list[tuple[int, int, object]]:
        """Minimal protobuf field parser.

        Returns a list of (field_number, wire_type, value) tuples.
        Wire type 0 (varint) -> int, wire type 2 (length-delimited) -> bytes,
        wire types 1/5 -> bytes (fixed-width).
        """
        result: list[tuple[int, int, object]] = []
        pos = 0
        length = len(raw)

        while pos < length:
            # Decode tag varint
            tag = 0
            shift = 0
            while pos < length:
                b = raw[pos]
                pos += 1
                tag |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break

            wire_type = tag & 0x07
            field_num = tag >> 3

            if wire_type == 0:
                # Varint
                val = 0
                shift = 0
                while pos < length:
                    b = raw[pos]
                    pos += 1
                    val |= (b & 0x7F) << shift
                    shift += 7
                    if not (b & 0x80):
                        break
                result.append((field_num, wire_type, val))

            elif wire_type == 2:
                # Length-delimited
                size = 0
                shift = 0
                while pos < length:
                    b = raw[pos]
                    pos += 1
                    size |= (b & 0x7F) << shift
                    shift += 7
                    if not (b & 0x80):
                        break
                data = raw[pos:pos + size]
                pos += size
                result.append((field_num, wire_type, data))

            elif wire_type == 1:
                # 64-bit fixed
                result.append((field_num, wire_type, raw[pos:pos + 8]))
                pos += 8

            elif wire_type == 5:
                # 32-bit fixed
                result.append((field_num, wire_type, raw[pos:pos + 4]))
                pos += 4

            else:
                # Unknown wire type -- bail to avoid infinite loop
                break

        return result

    def _probe_well_known_services(self) -> None:
        """Probe well-known gRPC service paths when reflection is unavailable.

        Sends an empty unary request to common endpoints (health check, etc.)
        and infers service existence from the response status.
        """
        for path in WELL_KNOWN_SERVICES:
            if self._stopped():
                break
            full_path = f"/{path}"
            try:
                status, details, _body = self._raw_unary_call(full_path, b"")
                if status in (0, 3, 12, 16):
                    # OK / INVALID_ARGUMENT / UNIMPLEMENTED / UNAUTHENTICATED
                    # all indicate the service exists on the server.
                    parts = path.rsplit("/", 1)
                    svc = parts[0] if len(parts) == 2 else path
                    method_name = parts[1] if len(parts) == 2 else "Unknown"
                    gm = GrpcMethod(
                        service=svc,
                        method=method_name,
                        full_name=path,
                        stream_type="unary",
                        request_type="unknown",
                        response_type="unknown",
                    )
                    self.methods.append(gm)
            except Exception:
                pass

    # ======================================================================
    # TEST GROUP 2 -- Protobuf Payload Fuzzing
    # ======================================================================

    def _test_payload_fuzzing(self) -> None:
        """Send type-aware fuzz payloads to every discovered method.

        Attack rationale:
            gRPC services often trust that incoming protobuf messages are
            well-formed because "protobuf handles validation."  In reality,
            hand-crafted payloads can bypass schema validation entirely:

            - Empty messages expose null-pointer dereferences
            - Max/negative varints trigger integer overflow
            - SQL/path-traversal strings test for injection when proto fields
              flow into SQL queries or file operations
            - Oversized messages test max-message-size enforcement
            - Deeply nested messages cause stack overflow in recursive parsers
            - Malformed varints crash low-level decoders
        """
        self._progress("payload_fuzzing", f"Fuzzing {len(self.methods)} methods with 8 payload mutations")

        payloads = _make_fuzz_payloads()

        for gm in self.methods:
            if self._stopped():
                break

            path = f"/{gm.full_name}"

            # Establish a baseline response for comparison
            baseline_status, baseline_details, _ = self._raw_unary_call(path, b"")

            for payload_name, payload_bytes in payloads:
                if self._stopped():
                    break

                try:
                    status, details, resp_body = self._raw_unary_call(path, payload_bytes)
                except Exception as exc:
                    logger.debug("Fuzz call failed for %s/%s: %s", gm.full_name, payload_name, exc)
                    continue

                self._analyze_fuzz_response(
                    gm, payload_name, status, details, resp_body,
                    baseline_status, baseline_details,
                )

    def _analyze_fuzz_response(
        self,
        gm: GrpcMethod,
        payload_name: str,
        status: int,
        details: str,
        resp_body: bytes,
        baseline_status: int,
        baseline_details: str,
    ) -> None:
        """Analyse a fuzz response for signs of vulnerability.

        We look for:
          - grpc-status 2 (UNKNOWN) -- server crash / panic
          - grpc-status 13 (INTERNAL) -- unhandled server error
          - Stack traces or verbose errors in the details string
          - Unexpected success (status 0) on injection payloads
          - Oversized message acceptance (no RESOURCE_EXHAUSTED)
        """
        proof = f"grpc-status={status}, details={details[:300]}"

        # Server panic / crash -- status UNKNOWN (2)
        if status == 2:
            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="payload_fuzz",
                finding=(
                    f"Server returned UNKNOWN (panic/crash) for payload '{payload_name}' "
                    f"on {gm.full_name}"
                ),
                severity="high",
                vuln_type="grpc_panic",
                proof=proof,
                grpc_status=status,
                payload_name=payload_name,
                stream_type=gm.stream_type,
            ))

        # Internal server error -- status 13
        if status == 13:
            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="payload_fuzz",
                finding=(
                    f"Server returned INTERNAL error for payload '{payload_name}' "
                    f"on {gm.full_name}"
                ),
                severity="high",
                vuln_type="grpc_panic",
                proof=proof,
                grpc_status=status,
                payload_name=payload_name,
                stream_type=gm.stream_type,
            ))

        # Stack trace or verbose error in details
        if details and _contains_stack_trace(details):
            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="payload_fuzz",
                finding=(
                    f"Server leaked stack trace / internal error details for "
                    f"payload '{payload_name}' on {gm.full_name}"
                ),
                severity="medium",
                vuln_type="grpc_panic",
                proof=proof,
                grpc_status=status,
                payload_name=payload_name,
                stream_type=gm.stream_type,
            ))

        # Injection: SQL / traversal payloads returned OK unexpectedly
        if payload_name in ("sqli_strings", "xxe_traversal_ssti"):
            if status == 0 and baseline_status != 0:
                # The injection payload succeeded where the baseline failed --
                # strong signal that input reached a backend interpreter.
                self._add_finding(self._make_finding(
                    service=gm.service,
                    method=gm.method,
                    test="payload_fuzz",
                    finding=(
                        f"Injection payload '{payload_name}' returned OK on "
                        f"{gm.full_name} (baseline returned status {baseline_status})"
                    ),
                    severity="critical" if "sqli" in payload_name else "high",
                    vuln_type="grpc_injection",
                    proof=proof,
                    grpc_status=status,
                    payload_name=payload_name,
                    stream_type=gm.stream_type,
                ))

        # Oversized message accepted without RESOURCE_EXHAUSTED (8)
        if payload_name == "oversized_100k":
            if status not in (8, 3, 14):  # not RESOURCE_EXHAUSTED / INVALID / UNAVAILABLE
                self._add_finding(self._make_finding(
                    service=gm.service,
                    method=gm.method,
                    test="payload_fuzz",
                    finding=(
                        f"Server accepted 100KB oversized message on {gm.full_name} "
                        f"without rejecting it (status={status})"
                    ),
                    severity="medium",
                    vuln_type="grpc_oversized_message_accepted",
                    proof=proof,
                    grpc_status=status,
                    payload_name=payload_name,
                    stream_type=gm.stream_type,
                ))

    # ======================================================================
    # TEST GROUP 3 -- mTLS Certificate Validation
    # ======================================================================

    def _test_mtls_validation(self) -> None:
        """Test certificate validation and TLS enforcement.

        Attack rationale:
            mTLS is the primary authentication mechanism for many gRPC services
            (especially in service meshes).  Misconfigurations are common:

            - Server accepts plaintext when TLS should be required
            - Server accepts any client cert (no CA validation)
            - Server accepts expired certificates
            - Server does not validate SNI hostname

            Each of these allows an attacker to impersonate a legitimate client.
        """
        self._progress("mtls_validation", "Testing 5 TLS/mTLS certificate scenarios")

        # Use the first discovered method for probing, or a well-known path
        probe_path = self._get_probe_path()

        # Scenario 1: Plaintext connection (should fail if TLS required)
        self._test_plaintext_connection(probe_path)

        if self._stopped():
            return

        # Scenario 2: TLS without client cert (should fail if mTLS required)
        self._test_tls_no_client_cert(probe_path)

        if self._stopped():
            return

        # Scenario 3: Self-signed client cert
        self._test_self_signed_cert(probe_path)

        if self._stopped():
            return

        # Scenario 4: Expired client cert
        self._test_expired_cert(probe_path)

        if self._stopped():
            return

        # Scenario 5: Wrong hostname in SNI
        self._test_wrong_sni(probe_path)

    def _get_probe_path(self) -> str:
        """Return a method path to use for mTLS probing."""
        if self.methods:
            return f"/{self.methods[0].full_name}"
        return "/grpc.health.v1.Health/Check"

    def _test_plaintext_connection(self, path: str) -> None:
        """Scenario 1: Connect over plaintext -- should fail if TLS is expected."""
        self._progress("mtls_validation", "Testing plaintext connection acceptance")

        if not GRPCIO_AVAILABLE:
            # Use httpx without TLS
            try:
                url = f"http://{self.target}{path}"
                with httpx.Client(http2=True, timeout=self.timeout) as client:
                    resp = client.post(
                        url,
                        content=_grpc_frame(b""),
                        headers={"content-type": "application/grpc", "te": "trailers"},
                    )
                grpc_status = int(resp.headers.get("grpc-status", -1))
                if grpc_status != -1:
                    # Server responded to plaintext
                    if self.use_tls:
                        self._add_finding(self._make_finding(
                            service="*", method="*",
                            test="mtls_plaintext",
                            finding="Server accepts plaintext gRPC when TLS is expected",
                            severity="high",
                            vuln_type="grpc_plaintext_accepted",
                            proof=f"Plaintext HTTP/2 returned grpc-status={grpc_status}",
                        ))
            except Exception:
                pass
            return

        try:
            channel = grpc.insecure_channel(
                self.target,
                options=[("grpc.max_receive_message_length", 1024 * 1024)],
            )
            method = channel.unary_unary(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            try:
                method(b"", timeout=self.timeout)
                # If we get here, the server accepted plaintext
                if self.use_tls:
                    self._add_finding(self._make_finding(
                        service="*", method="*",
                        test="mtls_plaintext",
                        finding="Server accepts plaintext gRPC when TLS is expected",
                        severity="high",
                        vuln_type="grpc_plaintext_accepted",
                        proof="Plaintext insecure_channel call succeeded",
                    ))
            except grpc.RpcError as exc:
                code = exc.code().value[0] if hasattr(exc, "code") else -1
                # Certain status codes still prove the server responded
                if self.use_tls and code in (0, 3, 5, 12, 16):
                    self._add_finding(self._make_finding(
                        service="*", method="*",
                        test="mtls_plaintext",
                        finding=(
                            f"Server responded to plaintext gRPC with status "
                            f"{GRPC_STATUS_CODES.get(code, code)} when TLS is expected"
                        ),
                        severity="high",
                        vuln_type="grpc_plaintext_accepted",
                        proof=f"grpc-status={code}, details={exc.details() if hasattr(exc, 'details') else ''}",
                    ))
            finally:
                channel.close()
        except Exception:
            pass

    def _test_tls_no_client_cert(self, path: str) -> None:
        """Scenario 2: TLS without client certificate -- should fail if mTLS enforced."""
        self._progress("mtls_validation", "Testing TLS without client certificate")

        if not GRPCIO_AVAILABLE:
            return

        if not self.use_tls:
            return

        try:
            # Connect with TLS but no client cert
            root_certs = None
            if self.ca_cert and os.path.isfile(self.ca_cert):
                with open(self.ca_cert, "rb") as fh:
                    root_certs = fh.read()

            creds = grpc.ssl_channel_credentials(
                root_certificates=root_certs,
                private_key=None,       # no client key
                certificate_chain=None,  # no client cert
            )
            channel = grpc.secure_channel(self.target, creds)
            method = channel.unary_unary(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            try:
                method(b"", timeout=self.timeout)
                # Server accepted connection without client cert
                if self.client_cert:
                    # If the scanner was configured with a client cert, it means
                    # mTLS was expected but not enforced.
                    self._add_finding(self._make_finding(
                        service="*", method="*",
                        test="mtls_no_client_cert",
                        finding="Server accepts TLS connections without client certificate (mTLS not enforced)",
                        severity="high",
                        vuln_type="grpc_mtls_not_enforced",
                        proof="TLS connection without client cert succeeded with status OK",
                    ))
            except grpc.RpcError as exc:
                code = exc.code().value[0] if hasattr(exc, "code") else -1
                if self.client_cert and code in (0, 3, 5, 12):
                    self._add_finding(self._make_finding(
                        service="*", method="*",
                        test="mtls_no_client_cert",
                        finding="Server accepts TLS connections without client certificate (mTLS not enforced)",
                        severity="high",
                        vuln_type="grpc_mtls_not_enforced",
                        proof=f"grpc-status={code}",
                    ))
            finally:
                channel.close()
        except Exception:
            pass

    def _test_self_signed_cert(self, path: str) -> None:
        """Scenario 3: Connect with a self-signed client certificate.

        If the server accepts our self-signed cert, it means client cert
        validation is missing or CA pinning is not enforced.
        """
        self._progress("mtls_validation", "Testing self-signed client certificate acceptance")

        if not GRPCIO_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE:
            logger.debug("Skipping self-signed cert test (missing deps)")
            return

        if not self.use_tls:
            return

        try:
            cert_pem, key_pem = _generate_self_signed_cert(cn="evil.attacker.com")

            root_certs = None
            if self.ca_cert and os.path.isfile(self.ca_cert):
                with open(self.ca_cert, "rb") as fh:
                    root_certs = fh.read()

            creds = grpc.ssl_channel_credentials(
                root_certificates=root_certs,
                private_key=key_pem,
                certificate_chain=cert_pem,
            )
            channel = grpc.secure_channel(self.target, creds)
            method = channel.unary_unary(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            try:
                method(b"", timeout=self.timeout)
                self._add_finding(self._make_finding(
                    service="*", method="*",
                    test="mtls_self_signed",
                    finding="Server accepts self-signed client certificate -- CA validation missing",
                    severity="critical",
                    vuln_type="grpc_cert_validation_bypass",
                    proof="Self-signed cert with CN=evil.attacker.com accepted",
                ))
            except grpc.RpcError as exc:
                code = exc.code().value[0] if hasattr(exc, "code") else -1
                if code in (0, 3, 5, 12):
                    self._add_finding(self._make_finding(
                        service="*", method="*",
                        test="mtls_self_signed",
                        finding="Server accepts self-signed client certificate -- CA validation missing",
                        severity="critical",
                        vuln_type="grpc_cert_validation_bypass",
                        proof=f"Self-signed cert accepted, grpc-status={code}",
                    ))
            finally:
                channel.close()
        except Exception as exc:
            logger.debug("Self-signed cert test failed: %s", exc)

    def _test_expired_cert(self, path: str) -> None:
        """Scenario 4: Connect with an expired client certificate.

        Servers that don't check notAfter will accept stale credentials,
        allowing access with compromised but "expired" certificates.
        """
        self._progress("mtls_validation", "Testing expired client certificate acceptance")

        if not GRPCIO_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE:
            logger.debug("Skipping expired cert test (missing deps)")
            return

        if not self.use_tls:
            return

        try:
            cert_pem, key_pem = _generate_self_signed_cert(
                cn="expired.attacker.com", expired=True,
            )

            root_certs = None
            if self.ca_cert and os.path.isfile(self.ca_cert):
                with open(self.ca_cert, "rb") as fh:
                    root_certs = fh.read()

            creds = grpc.ssl_channel_credentials(
                root_certificates=root_certs,
                private_key=key_pem,
                certificate_chain=cert_pem,
            )
            channel = grpc.secure_channel(self.target, creds)
            method = channel.unary_unary(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            try:
                method(b"", timeout=self.timeout)
                self._add_finding(self._make_finding(
                    service="*", method="*",
                    test="mtls_expired_cert",
                    finding="Server accepts expired client certificate -- cert expiry not validated",
                    severity="critical",
                    vuln_type="grpc_cert_validation_bypass",
                    proof="Expired cert (notAfter=yesterday) with CN=expired.attacker.com accepted",
                ))
            except grpc.RpcError as exc:
                code = exc.code().value[0] if hasattr(exc, "code") else -1
                if code in (0, 3, 5, 12):
                    self._add_finding(self._make_finding(
                        service="*", method="*",
                        test="mtls_expired_cert",
                        finding="Server accepts expired client certificate -- cert expiry not validated",
                        severity="critical",
                        vuln_type="grpc_cert_validation_bypass",
                        proof=f"Expired cert accepted, grpc-status={code}",
                    ))
            finally:
                channel.close()
        except Exception as exc:
            logger.debug("Expired cert test failed: %s", exc)

    def _test_wrong_sni(self, path: str) -> None:
        """Scenario 5: Connect with a mismatched SNI hostname.

        If the server doesn't validate that the SNI hostname matches the
        expected service identity, an attacker on the network can redirect
        traffic.
        """
        self._progress("mtls_validation", "Testing wrong SNI hostname acceptance")

        if not GRPCIO_AVAILABLE:
            return
        if not self.use_tls:
            return

        try:
            root_certs = None
            if self.ca_cert and os.path.isfile(self.ca_cert):
                with open(self.ca_cert, "rb") as fh:
                    root_certs = fh.read()

            private_key = None
            cert_chain = None
            if self.client_key and os.path.isfile(self.client_key):
                with open(self.client_key, "rb") as fh:
                    private_key = fh.read()
            if self.client_cert and os.path.isfile(self.client_cert):
                with open(self.client_cert, "rb") as fh:
                    cert_chain = fh.read()

            creds = grpc.ssl_channel_credentials(
                root_certificates=root_certs,
                private_key=private_key,
                certificate_chain=cert_chain,
            )

            # Override the target name to a wrong hostname
            wrong_host = "wrong.hostname.invalid"
            channel = grpc.secure_channel(
                self.target,
                creds,
                options=[
                    ("grpc.ssl_target_name_override", wrong_host),
                    ("grpc.max_receive_message_length", 1024 * 1024),
                ],
            )
            method = channel.unary_unary(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            try:
                method(b"", timeout=self.timeout)
                self._add_finding(self._make_finding(
                    service="*", method="*",
                    test="mtls_wrong_sni",
                    finding="Server accepted connection with mismatched SNI hostname",
                    severity="medium",
                    vuln_type="grpc_cert_validation_bypass",
                    proof=f"SNI override to '{wrong_host}' accepted",
                ))
            except grpc.RpcError as exc:
                code = exc.code().value[0] if hasattr(exc, "code") else -1
                if code in (0, 3, 5, 12):
                    self._add_finding(self._make_finding(
                        service="*", method="*",
                        test="mtls_wrong_sni",
                        finding="Server accepted connection with mismatched SNI hostname",
                        severity="medium",
                        vuln_type="grpc_cert_validation_bypass",
                        proof=f"SNI override to '{wrong_host}' accepted, grpc-status={code}",
                    ))
            finally:
                channel.close()
        except Exception as exc:
            logger.debug("Wrong SNI test failed: %s", exc)

    # ======================================================================
    # TEST GROUP 4 -- Metadata Injection
    # ======================================================================

    def _test_metadata_injection(self) -> None:
        """Send attack payloads via gRPC metadata (HTTP/2 headers).

        Attack rationale:
            gRPC metadata maps directly to HTTP/2 headers.  Many applications
            trust metadata values without sanitisation because they assume the
            transport layer is safe.  Common vulnerabilities:

            - SQL injection in authorization tokens parsed server-side
            - Privilege escalation via trusted x-user-id / x-user-role headers
              that an API gateway was supposed to set
            - SSRF via x-forwarded-for trusted by upstream proxies
            - CRLF injection to create extra headers (HTTP response splitting)
            - Timeout manipulation to bypass rate limiting or cause DoS
        """
        self._progress("metadata_injection", f"Testing {len(METADATA_ATTACKS)} metadata attacks")

        # Collect methods to test; fall back to well-known health check
        methods_to_test = self.methods or [
            GrpcMethod(
                service="grpc.health.v1.Health",
                method="Check",
                full_name="grpc.health.v1.Health/Check",
                stream_type="unary",
                request_type="unknown",
                response_type="unknown",
            )
        ]

        for gm in methods_to_test:
            if self._stopped():
                break

            path = f"/{gm.full_name}"

            # Establish baseline: empty body, no attack metadata
            baseline_status, baseline_details, baseline_body = self._raw_unary_call(
                path, b"",
            )

            for meta_key, meta_value, attack_label in METADATA_ATTACKS:
                if self._stopped():
                    break

                try:
                    metadata = [(meta_key, meta_value)]
                    status, details, resp_body = self._raw_unary_call(
                        path, b"", metadata=metadata,
                    )
                except Exception as exc:
                    logger.debug("Metadata attack %s failed on %s: %s", attack_label, gm.full_name, exc)
                    continue

                self._analyze_metadata_response(
                    gm, attack_label, meta_key, meta_value,
                    status, details, resp_body,
                    baseline_status, baseline_details, baseline_body,
                )

    def _analyze_metadata_response(
        self,
        gm: GrpcMethod,
        attack_label: str,
        meta_key: str,
        meta_value: str,
        status: int,
        details: str,
        resp_body: bytes,
        baseline_status: int,
        baseline_details: str,
        baseline_body: bytes,
    ) -> None:
        """Analyse metadata injection response for signs of vulnerability.

        Key signals:
          - Status OK (0) when baseline was not OK -- the metadata changed
            server behaviour (likely accepted as trusted input)
          - Different response body compared to baseline -- the metadata
            influenced output (e.g. IDOR returned different data)
          - Stack trace in details -- the metadata caused an error path that
            leaks internal information
          - CRLF injection success -- server processed the injected header
        """
        proof = (
            f"attack={attack_label}, header={meta_key}: {meta_value[:80]}, "
            f"grpc-status={status}, details={details[:200]}"
        )

        # Signal 1: Success where baseline failed
        if status == 0 and baseline_status != 0:
            severity = "high" if attack_label in (
                "sql_in_auth_header", "sqli_api_key", "privilege_via_metadata",
                "admin_flag_metadata", "ssrf_via_metadata",
            ) else "medium"

            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="metadata_injection",
                finding=(
                    f"Metadata attack '{attack_label}' changed server response "
                    f"from {GRPC_STATUS_CODES.get(baseline_status, baseline_status)} "
                    f"to OK on {gm.full_name}"
                ),
                severity=severity,
                vuln_type="grpc_metadata_injection",
                proof=proof,
                grpc_status=status,
                payload_name=attack_label,
                stream_type=gm.stream_type,
            ))

        # Signal 2: Different response body (potential IDOR / data leak)
        if resp_body and resp_body != baseline_body and status == 0:
            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="metadata_injection",
                finding=(
                    f"Metadata '{meta_key}' produced different response body "
                    f"on {gm.full_name} -- possible IDOR or data exposure"
                ),
                severity="high",
                vuln_type="grpc_metadata_injection",
                proof=proof,
                grpc_status=status,
                payload_name=attack_label,
                stream_type=gm.stream_type,
            ))

        # Signal 3: Stack trace / internal error leak
        if details and _contains_stack_trace(details):
            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="metadata_injection",
                finding=(
                    f"Metadata attack '{attack_label}' triggered stack trace / "
                    f"verbose error on {gm.full_name}"
                ),
                severity="medium",
                vuln_type="grpc_metadata_injection",
                proof=proof,
                grpc_status=status,
                payload_name=attack_label,
                stream_type=gm.stream_type,
            ))

        # Signal 4: Server crash (UNKNOWN / INTERNAL)
        if status in (2, 13) and baseline_status not in (2, 13):
            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="metadata_injection",
                finding=(
                    f"Metadata attack '{attack_label}' caused server error "
                    f"({GRPC_STATUS_CODES.get(status, status)}) on {gm.full_name}"
                ),
                severity="high",
                vuln_type="grpc_metadata_injection",
                proof=proof,
                grpc_status=status,
                payload_name=attack_label,
                stream_type=gm.stream_type,
            ))

    # ======================================================================
    # TEST GROUP 5 -- Stream Type Security
    # ======================================================================

    def _test_stream_security(self) -> None:
        """Test stream-related security issues for each discovered method.

        Attack rationale:
            gRPC's streaming modes (server, client, bidi) introduce resource
            management challenges that many servers handle poorly:

            - Server-streaming: an endpoint that never sends EOF can hold
              connections open indefinitely, exhausting client-side resources
              or acting as a slow-loris DoS vector
            - Client-streaming: without backpressure or message limits, an
              attacker can flood the server with messages, exhausting memory
            - Bidi: combines both attack surfaces
            - RST_STREAM amplification: rapidly opening and cancelling streams
              forces the server to allocate and tear down resources, potentially
              causing CPU/memory spikes disproportionate to attacker effort
        """
        self._progress("stream_security", f"Testing stream security on {len(self.methods)} methods")

        if not GRPCIO_AVAILABLE:
            self._progress("stream_security", "Skipping stream tests (grpcio unavailable)")
            return

        for gm in self.methods:
            if self._stopped():
                break

            if gm.stream_type == "unary":
                self._test_unary_cancellation(gm)
            elif gm.stream_type == "server_stream":
                self._test_server_stream(gm)
            elif gm.stream_type == "client_stream":
                self._test_client_stream(gm)
            elif gm.stream_type == "bidi":
                self._test_bidi_stream(gm)

        # RST_STREAM amplification test (run on any available method)
        if self.methods and not self._stopped():
            self._test_stream_reset_amplification(self.methods[0])

    def _test_unary_cancellation(self, gm: GrpcMethod) -> None:
        """Test unary method cancellation behaviour.

        Send a request then immediately cancel.  The server should handle
        cancellation gracefully without resource leaks.
        """
        path = f"/{gm.full_name}"
        try:
            channel = self._get_channel()
            method = channel.unary_unary(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            future = method.future(b"", timeout=self.timeout)
            future.cancel()
            channel.close()
        except Exception:
            pass

    def _test_server_stream(self, gm: GrpcMethod) -> None:
        """Test server-streaming endpoint for unbounded response streams.

        Connect and read messages until we hit 10,000 or the timeout.
        If the server sends > 10,000 messages without EOF, it lacks proper
        response limits.
        """
        self._progress("stream_security", f"Testing server stream bounds on {gm.full_name}")

        path = f"/{gm.full_name}"
        message_count = 0
        max_messages = 10_000

        try:
            channel = self._get_channel()
            method = channel.unary_stream(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            responses = method(b"", timeout=self.timeout)

            start = time.monotonic()
            for _resp in responses:
                message_count += 1
                if message_count >= max_messages:
                    break
                if time.monotonic() - start > self.timeout:
                    break
                if self._stopped():
                    break

            channel.close()

            if message_count >= max_messages:
                self._add_finding(self._make_finding(
                    service=gm.service,
                    method=gm.method,
                    test="stream_security",
                    finding=(
                        f"Server-streaming method {gm.full_name} sent {message_count}+ "
                        f"messages without EOF -- no response limit enforced"
                    ),
                    severity="medium",
                    vuln_type="grpc_unbounded_stream",
                    proof=f"Received {message_count} messages before aborting",
                    stream_type="server_stream",
                ))

        except grpc.RpcError:
            pass
        except Exception as exc:
            logger.debug("Server stream test failed for %s: %s", gm.full_name, exc)

    def _test_client_stream(self, gm: GrpcMethod) -> None:
        """Test client-streaming endpoint for missing backpressure.

        Open a client stream and send 10,000 empty messages as fast as
        possible.  If the server accepts all without pushback, it lacks
        message-count limits and is vulnerable to memory exhaustion.
        """
        self._progress("stream_security", f"Testing client stream limits on {gm.full_name}")

        path = f"/{gm.full_name}"
        send_count = 10_000

        def message_generator():
            for i in range(send_count):
                if self._stopped():
                    return
                yield b""

        try:
            channel = self._get_channel()
            method = channel.stream_unary(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response = method(message_generator(), timeout=self.timeout)

            # If we got here, the server accepted all 10k messages
            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="stream_security",
                finding=(
                    f"Client-streaming method {gm.full_name} accepted {send_count} "
                    f"rapid messages without backpressure or rejection"
                ),
                severity="medium",
                vuln_type="grpc_no_client_stream_limit",
                proof=f"Sent {send_count} empty messages, server accepted all",
                stream_type="client_stream",
            ))

            channel.close()

        except grpc.RpcError as exc:
            code = exc.code().value[0] if hasattr(exc, "code") else -1
            # RESOURCE_EXHAUSTED (8) means the server properly enforced limits
            if code != 8:
                logger.debug("Client stream test ended with status %s for %s", code, gm.full_name)
        except Exception as exc:
            logger.debug("Client stream test failed for %s: %s", gm.full_name, exc)

    def _test_bidi_stream(self, gm: GrpcMethod) -> None:
        """Test bidirectional streaming for flow-control issues.

        Send 100 messages rapidly and check whether the server buffers them
        all without applying flow control or message limits.
        """
        self._progress("stream_security", f"Testing bidi stream on {gm.full_name}")

        path = f"/{gm.full_name}"
        send_count = 100

        def message_generator():
            for i in range(send_count):
                if self._stopped():
                    return
                yield b""

        try:
            channel = self._get_channel()
            method = channel.stream_stream(
                path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            responses = method(message_generator(), timeout=self.timeout)

            recv_count = 0
            start = time.monotonic()
            for _resp in responses:
                recv_count += 1
                if recv_count >= 10_000:
                    break
                if time.monotonic() - start > self.timeout:
                    break
                if self._stopped():
                    break

            channel.close()

            if recv_count >= 10_000:
                self._add_finding(self._make_finding(
                    service=gm.service,
                    method=gm.method,
                    test="stream_security",
                    finding=(
                        f"Bidi method {gm.full_name} buffered all messages without "
                        f"flow control -- received {recv_count}+ responses"
                    ),
                    severity="medium",
                    vuln_type="grpc_unbounded_stream",
                    proof=f"Sent {send_count}, received {recv_count}+ messages",
                    stream_type="bidi",
                ))

        except grpc.RpcError:
            pass
        except Exception as exc:
            logger.debug("Bidi stream test failed for %s: %s", gm.full_name, exc)

    def _test_stream_reset_amplification(self, gm: GrpcMethod) -> None:
        """Test RST_STREAM amplification vulnerability.

        Rapidly open a stream, send the initial message, then immediately
        cancel (RST_STREAM).  Repeat 50 times.  If the server allocates
        significant resources on each open (goroutine, thread, DB connection)
        and doesn't handle cancellation cheaply, this causes disproportionate
        server work relative to attacker effort.

        This is the gRPC equivalent of a SYN flood at the application layer.
        """
        self._progress("stream_security", f"Testing RST_STREAM amplification on {gm.full_name}")

        path = f"/{gm.full_name}"
        reset_count = 50
        errors = 0

        for i in range(reset_count):
            if self._stopped():
                break
            try:
                channel = self._get_channel()
                method = channel.unary_unary(
                    path,
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x,
                )
                future = method.future(b"", timeout=2)
                # Immediately cancel to force RST_STREAM
                future.cancel()
                channel.close()
            except grpc.RpcError:
                errors += 1
            except Exception:
                errors += 1

        # If a significant portion of the rapid resets caused errors,
        # the server may be struggling with the load
        if errors > reset_count * 0.5:
            self._add_finding(self._make_finding(
                service=gm.service,
                method=gm.method,
                test="stream_reset",
                finding=(
                    f"Rapid RST_STREAM on {gm.full_name} caused {errors}/{reset_count} "
                    f"errors -- server may be vulnerable to stream reset amplification"
                ),
                severity="low",
                vuln_type="grpc_stream_reset_amplification",
                proof=f"{errors}/{reset_count} rapid cancellations caused errors",
                stream_type=gm.stream_type,
            ))


# ── Module-level utilities ────────────────────────────────────────────────────

def _contains_stack_trace(text: str) -> bool:
    """Detect stack traces, file paths, or verbose error internals in a string.

    These patterns indicate the server is leaking implementation details
    that aid an attacker in mapping the code base.
    """
    indicators = [
        "Traceback",
        "at ",
        "panic:",
        "goroutine ",
        "Exception in thread",
        "NullPointerException",
        "SIGSEGV",
        "stack trace",
        ".go:",
        ".py:",
        ".java:",
        ".js:",
        ".rs:",
        "/src/",
        "/app/",
        "runtime error",
    ]
    text_lower = text.lower()
    return any(ind.lower() in text_lower for ind in indicators)
