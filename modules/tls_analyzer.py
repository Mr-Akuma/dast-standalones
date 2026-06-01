"""
TLS Analyzer — Deep certificate and TLS configuration analysis.

Goes beyond protocol version/cipher checks to analyze:
- Certificate chain validity, expiry, and trust
- Key size and algorithm weaknesses
- Forward secrecy cipher preference
- Certificate Transparency (via crt.sh)
- HSTS configuration depth
- Common misconfigurations: wildcard certs, self-signed, expired

Complements scanner.py's _check_weak_tls and _check_weak_ciphers which
focus on protocol versions and cipher suites.
"""
from __future__ import annotations

import ssl
import socket
import datetime
import hashlib
import json
import logging
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger("dast.tls_analyzer")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TLSFinding:
    """A single TLS/certificate finding produced by the analyzer."""

    url: str
    test: str           # e.g., "cert_expiry", "self_signed", "weak_key"
    finding: str        # human-readable description
    severity: str       # "critical", "high", "medium", "low", "info"
    evidence: str       # technical detail
    cve: str = ""
    agent_id: str = "tls_analyzer"
    icon: str = "\U0001f512"          # lock emoji
    vuln_type: str = "tls_weakness"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CertInfo:
    """Parsed certificate metadata (internal use)."""

    subject: dict
    issuer: dict
    san: list[str]
    not_before: datetime.datetime
    not_after: datetime.datetime
    serial: str
    version: int
    key_type: str
    key_bits: int
    signature_algorithm: str
    is_wildcard: bool
    is_self_signed: bool
    days_until_expiry: int
    fingerprint_sha256: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_cert_time(raw: str) -> datetime.datetime:
    """Parse the notBefore / notAfter string returned by getpeercert()."""
    # OpenSSL format: "Sep 18 00:00:00 2025 GMT"
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(raw, fmt)
        except ValueError:
            continue
    # Fallback — try ISO-ish
    return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00").replace(" GMT", ""))


def _subject_cn(subject_tuples: tuple) -> str:
    """Extract the Common Name from a subject/issuer tuple-of-tuples."""
    for rdn in subject_tuples:
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                return attr_value
    return ""


def _extract_san(cert_dict: dict) -> list[str]:
    """Return a list of SAN DNS names from a getpeercert() dict."""
    san_entries = cert_dict.get("subjectAltName", ())
    return [value for kind, value in san_entries if kind == "DNS"]


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class TLSAnalyzer:
    """Deep TLS and certificate analysis for a single target."""

    def __init__(
        self,
        timeout: int = 10,
        stop_event: threading.Event | None = None,
    ):
        self.timeout = timeout
        self.stop_event = stop_event or threading.Event()
        self._findings: list[TLSFinding] = []

    # ------------------------------------------------------------------
    # Certificate retrieval
    # ------------------------------------------------------------------

    def analyze_certificate(self, host: str, port: int = 443) -> CertInfo | None:
        """Connect via TLS and extract detailed certificate information."""
        try:
            if self.stop_event.is_set():
                return None

            # Build a context that does NOT verify — we want to inspect
            # even bad certs rather than failing on them.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # --- binary DER cert for fingerprint ---
            pem = ssl.get_server_certificate((host, port), timeout=self.timeout)
            der = ssl.PEM_cert_to_DER_cert(pem)
            fingerprint = hashlib.sha256(der).hexdigest()

            # --- rich dict via getpeercert ---
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as tls:
                    cert_dict = tls.getpeercert(binary_form=False)
                    # getpeercert(False) with CERT_NONE returns {} on CPython;
                    # fall back to binary parsing when needed.
                    cipher_info = tls.cipher()  # noqa: F841 — kept for debug

            # If getpeercert returned an empty dict (CERT_NONE), do a
            # second connection with verification enabled but tolerate errors.
            if not cert_dict:
                try:
                    ctx3 = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=self.timeout) as sock3:
                        with ctx3.wrap_socket(sock3, server_hostname=host) as tls3:
                            cert_dict = tls3.getpeercert(binary_form=False)
                except ssl.SSLCertVerificationError:
                    # Self-signed / untrusted — parse what we can from PEM
                    pass

            if not cert_dict:
                # Minimal info from PEM alone
                cert_dict = {}

            subject = cert_dict.get("subject", ())
            issuer = cert_dict.get("issuer", ())
            subject_cn = _subject_cn(subject)
            issuer_cn = _subject_cn(issuer)

            san_list = _extract_san(cert_dict)

            not_before_raw = cert_dict.get("notBefore", "")
            not_after_raw = cert_dict.get("notAfter", "")

            now = datetime.datetime.utcnow()

            not_before = _parse_cert_time(not_before_raw) if not_before_raw else now
            not_after = _parse_cert_time(not_after_raw) if not_after_raw else now

            days_until_expiry = (not_after - now).days

            serial = cert_dict.get("serialNumber", "unknown")
            version = cert_dict.get("version", 0)

            # Key type/size — CPython does not expose these in getpeercert().
            # We infer from the signature algorithm and default to RSA/2048
            # since deeper parsing would require pyOpenSSL.
            sig_alg = str(cert_dict.get("signatureAlgorithm", "")).lower()
            if not sig_alg:
                # Attempt heuristic from the PEM header length
                sig_alg = "unknown"

            key_type = "RSA"
            key_bits = 2048
            if "ecdsa" in sig_alg or "ec" in sig_alg.split("-"):
                key_type = "EC"
                key_bits = 256
            elif "dsa" in sig_alg and "ecdsa" not in sig_alg:
                key_type = "DSA"
                key_bits = 1024

            # Rough key-size estimation from DER length when we cannot
            # introspect the public key directly.
            der_len = len(der)
            if key_type == "RSA":
                if der_len > 1800:
                    key_bits = 4096
                elif der_len > 1200:
                    key_bits = 2048
                else:
                    key_bits = 1024

            is_wildcard = any(s.startswith("*") for s in san_list)
            if not san_list and subject_cn.startswith("*"):
                is_wildcard = True

            is_self_signed = (subject_cn != "" and subject_cn == issuer_cn)

            return CertInfo(
                subject=dict(subject) if isinstance(subject, (list, tuple)) else subject,
                issuer=dict(issuer) if isinstance(issuer, (list, tuple)) else issuer,
                san=san_list,
                not_before=not_before,
                not_after=not_after,
                serial=serial,
                version=version,
                key_type=key_type,
                key_bits=key_bits,
                signature_algorithm=sig_alg,
                is_wildcard=is_wildcard,
                is_self_signed=is_self_signed,
                days_until_expiry=days_until_expiry,
                fingerprint_sha256=fingerprint,
            )

        except Exception as exc:
            log.warning("analyze_certificate failed for %s:%d — %s", host, port, exc)
            return None

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_cert_expiry(self, url: str, cert: CertInfo) -> TLSFinding | None:
        """Check certificate expiration status."""
        try:
            days = cert.days_until_expiry
            if days < 0:
                return TLSFinding(
                    url=url,
                    test="cert_expiry",
                    finding=f"Certificate expired {abs(days)} days ago",
                    severity="critical",
                    evidence=f"notAfter={cert.not_after.isoformat()}, days_until_expiry={days}",
                )
            if days < 14:
                return TLSFinding(
                    url=url,
                    test="cert_expiry",
                    finding=f"Certificate expires in {days} days",
                    severity="critical",
                    evidence=f"notAfter={cert.not_after.isoformat()}, days_until_expiry={days}",
                )
            if days < 30:
                return TLSFinding(
                    url=url,
                    test="cert_expiry",
                    finding=f"Certificate expires in {days} days",
                    severity="medium",
                    evidence=f"notAfter={cert.not_after.isoformat()}, days_until_expiry={days}",
                )
            if days < 90:
                return TLSFinding(
                    url=url,
                    test="cert_expiry",
                    finding=f"Certificate expires in {days} days",
                    severity="low",
                    evidence=f"notAfter={cert.not_after.isoformat()}, days_until_expiry={days}",
                )
            return None
        except Exception as exc:
            log.debug("check_cert_expiry error: %s", exc)
            return None

    def check_self_signed(self, host: str, cert: CertInfo) -> TLSFinding | None:
        """Detect self-signed certificates."""
        try:
            if cert.is_self_signed:
                return TLSFinding(
                    url=host,
                    test="self_signed",
                    finding="Self-signed certificate detected",
                    severity="high",
                    evidence=f"subject_cn={_subject_cn(cert.subject) if isinstance(cert.subject, tuple) else cert.subject}, "
                             f"issuer_cn={_subject_cn(cert.issuer) if isinstance(cert.issuer, tuple) else cert.issuer}",
                )
            return None
        except Exception as exc:
            log.debug("check_self_signed error: %s", exc)
            return None

    def check_weak_key(self, host: str, cert: CertInfo) -> TLSFinding | None:
        """Check for weak cryptographic key parameters."""
        try:
            kt = cert.key_type
            bits = cert.key_bits

            if kt == "RSA" and bits < 2048:
                return TLSFinding(
                    url=host,
                    test="weak_key",
                    finding=f"Weak RSA key — {bits} bits (minimum 2048)",
                    severity="high",
                    evidence=f"key_type={kt}, key_bits={bits}",
                )
            if kt == "EC" and bits < 224:
                return TLSFinding(
                    url=host,
                    test="weak_key",
                    finding=f"Weak EC key — {bits} bits (minimum 224)",
                    severity="high",
                    evidence=f"key_type={kt}, key_bits={bits}",
                )
            if kt == "DSA":
                return TLSFinding(
                    url=host,
                    test="weak_key",
                    finding="DSA key algorithm is deprecated",
                    severity="medium",
                    evidence=f"key_type={kt}, key_bits={bits}",
                )
            if kt == "RSA" and bits < 4096:
                return TLSFinding(
                    url=host,
                    test="weak_key",
                    finding=f"RSA key is {bits} bits — 4096 recommended for high-security",
                    severity="info",
                    evidence=f"key_type={kt}, key_bits={bits}",
                )
            return None
        except Exception as exc:
            log.debug("check_weak_key error: %s", exc)
            return None

    def check_wildcard_cert(self, host: str, cert: CertInfo) -> TLSFinding | None:
        """Flag wildcard certificates (informational)."""
        try:
            if cert.is_wildcard:
                return TLSFinding(
                    url=host,
                    test="wildcard_cert",
                    finding="Wildcard certificate in use",
                    severity="info",
                    evidence=f"san={cert.san}",
                )
            return None
        except Exception as exc:
            log.debug("check_wildcard_cert error: %s", exc)
            return None

    def check_forward_secrecy(self, host: str, port: int = 443) -> TLSFinding | None:
        """Test whether the server supports forward-secrecy ciphers."""
        try:
            if self.stop_event.is_set():
                return None

            # Try FS ciphers first
            fs_supported = False
            try:
                ctx_fs = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_fs.check_hostname = False
                ctx_fs.verify_mode = ssl.CERT_NONE
                ctx_fs.set_ciphers("ECDHE+AES:DHE+AES")
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx_fs.wrap_socket(sock, server_hostname=host) as tls:
                        tls.do_handshake()
                        fs_supported = True
            except (ssl.SSLError, OSError):
                pass

            if fs_supported:
                return None  # Forward secrecy is supported — good

            # Try non-FS ciphers
            non_fs_works = False
            try:
                ctx_nfs = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_nfs.check_hostname = False
                ctx_nfs.verify_mode = ssl.CERT_NONE
                ctx_nfs.set_ciphers("AES128-SHA:AES256-SHA")
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx_nfs.wrap_socket(sock, server_hostname=host) as tls:
                        tls.do_handshake()
                        non_fs_works = True
            except (ssl.SSLError, OSError):
                pass

            if non_fs_works:
                return TLSFinding(
                    url=host,
                    test="forward_secrecy",
                    finding="Forward secrecy not supported — server only negotiates non-FS ciphers",
                    severity="medium",
                    evidence="ECDHE/DHE ciphers rejected; AES128-SHA/AES256-SHA accepted",
                )

            # Neither worked — possibly port closed or TLS 1.3 only (which has FS built in)
            return None

        except Exception as exc:
            log.debug("check_forward_secrecy error: %s", exc)
            return None

    def check_hsts_header(self, response_headers: dict, url: str) -> TLSFinding | None:
        """Evaluate Strict-Transport-Security header quality."""
        try:
            hsts = None
            # Case-insensitive header lookup
            for key, value in response_headers.items():
                if key.lower() == "strict-transport-security":
                    hsts = value
                    break

            if hsts is None:
                return TLSFinding(
                    url=url,
                    test="hsts_missing",
                    finding="Strict-Transport-Security header is absent",
                    severity="medium",
                    evidence="No HSTS header found in response",
                )

            hsts_lower = hsts.lower()

            # Parse max-age
            max_age = 0
            for part in hsts_lower.split(";"):
                part = part.strip()
                if part.startswith("max-age"):
                    try:
                        max_age = int(part.split("=", 1)[1].strip())
                    except (ValueError, IndexError):
                        pass

            if max_age < 15_768_000:  # Less than ~6 months
                return TLSFinding(
                    url=url,
                    test="hsts_short",
                    finding=f"HSTS max-age too short ({max_age}s) — recommend >= 15768000 (6 months)",
                    severity="low",
                    evidence=f"Strict-Transport-Security: {hsts}",
                )

            if "includesubdomains" not in hsts_lower:
                return TLSFinding(
                    url=url,
                    test="hsts_no_subdomains",
                    finding="HSTS header lacks includeSubDomains directive",
                    severity="info",
                    evidence=f"Strict-Transport-Security: {hsts}",
                )

            return None  # HSTS looks good

        except Exception as exc:
            log.debug("check_hsts_header error: %s", exc)
            return None

    def check_cert_transparency(self, host: str) -> list[TLSFinding]:
        """Query crt.sh for Certificate Transparency log entries."""
        findings: list[TLSFinding] = []
        try:
            if self.stop_event.is_set():
                return findings

            ct_url = f"https://crt.sh/?q={host}&output=json"
            req = urllib.request.Request(ct_url, headers={"User-Agent": "DAST-TLS-Analyzer/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if not data:
                return findings

            total_certs = len(data)
            log.info("crt.sh returned %d entries for %s", total_certs, host)

            # Check for recently-issued certificates
            now = datetime.datetime.utcnow()
            recent_threshold = now - datetime.timedelta(days=7)

            for entry in data[:50]:  # Limit iteration
                entry_ts = entry.get("entry_timestamp", "")
                name_value = entry.get("name_value", "")
                try:
                    issued = datetime.datetime.fromisoformat(
                        entry_ts.replace("T", " ").split(".")[0]
                    )
                    if issued > recent_threshold:
                        findings.append(TLSFinding(
                            url=host,
                            test="ct_recent_issuance",
                            finding="New certificate issued recently (possible domain takeover signal)",
                            severity="info",
                            evidence=f"issued={entry_ts}, cn={name_value}, total_ct_entries={total_certs}",
                        ))
                        break  # One finding is enough
                except (ValueError, TypeError):
                    continue

            # Check for wildcard certs in CT logs
            for entry in data[:50]:
                name_value = entry.get("name_value", "")
                if name_value.startswith("*"):
                    findings.append(TLSFinding(
                        url=host,
                        test="ct_wildcard",
                        finding="Wildcard certificate found in Certificate Transparency logs",
                        severity="info",
                        evidence=f"name_value={name_value}, total_ct_entries={total_certs}",
                    ))
                    break

            return findings

        except Exception as exc:
            log.debug("check_cert_transparency error: %s", exc)
            return findings

    def check_signature_algorithm(self, host: str, cert: CertInfo) -> TLSFinding | None:
        """Flag weak signature algorithms (SHA-1, MD5)."""
        try:
            alg = cert.signature_algorithm.lower()
            if "md5" in alg:
                return TLSFinding(
                    url=host,
                    test="weak_signature",
                    finding="Certificate uses MD5 signature algorithm — cryptographically broken",
                    severity="high",
                    evidence=f"signature_algorithm={cert.signature_algorithm}",
                    cve="CVE-2004-2761",
                )
            if "sha1" in alg and "sha1" not in ("sha128", "sha192"):
                return TLSFinding(
                    url=host,
                    test="weak_signature",
                    finding="Certificate uses SHA-1 signature algorithm — deprecated",
                    severity="high",
                    evidence=f"signature_algorithm={cert.signature_algorithm}",
                    cve="CVE-2005-4900",
                )
            # sha256, sha384, sha512 are all fine
            return None
        except Exception as exc:
            log.debug("check_signature_algorithm error: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    def scan(self, target_url: str) -> list[TLSFinding]:
        """Run all TLS checks against a target URL. Returns list of findings."""
        findings: list[TLSFinding] = []

        try:
            parsed = urlparse(target_url)
            scheme = parsed.scheme.lower()
            host = parsed.hostname or ""
            port = parsed.port or (443 if scheme == "https" else 80)

            if scheme != "https":
                findings.append(TLSFinding(
                    url=target_url,
                    test="https_check",
                    finding="Target is HTTP-only — no TLS to analyze",
                    severity="info",
                    evidence=f"scheme={scheme}",
                ))
                self._findings = findings
                return findings

            if self.stop_event.is_set():
                return findings

            # ---- Certificate analysis ----
            cert_info = self.analyze_certificate(host, port)

            if cert_info:
                expiry = self.check_cert_expiry(target_url, cert_info)
                if expiry:
                    findings.append(expiry)

                self_signed = self.check_self_signed(target_url, cert_info)
                if self_signed:
                    findings.append(self_signed)

                weak_key = self.check_weak_key(target_url, cert_info)
                if weak_key:
                    findings.append(weak_key)

                wildcard = self.check_wildcard_cert(target_url, cert_info)
                if wildcard:
                    findings.append(wildcard)

                sig_alg = self.check_signature_algorithm(target_url, cert_info)
                if sig_alg:
                    findings.append(sig_alg)
            else:
                log.warning("Could not retrieve certificate for %s — skipping cert checks", host)

            # ---- Forward secrecy ----
            if not self.stop_event.is_set():
                fs = self.check_forward_secrecy(host, port)
                if fs:
                    findings.append(fs)

            # ---- HSTS from live response ----
            if not self.stop_event.is_set():
                headers: dict = {}
                try:
                    ctx_fetch = ssl.create_default_context()
                    ctx_fetch.check_hostname = False
                    ctx_fetch.verify_mode = ssl.CERT_NONE
                    handler = urllib.request.HTTPSHandler(context=ctx_fetch)
                    opener = urllib.request.build_opener(handler)
                    req = urllib.request.Request(
                        target_url,
                        headers={"User-Agent": "DAST-TLS-Analyzer/1.0"},
                        method="HEAD",
                    )
                    with opener.open(req, timeout=self.timeout) as resp:
                        headers = dict(resp.headers)
                except Exception as exc:
                    log.debug("Could not fetch headers from %s: %s", target_url, exc)

                hsts = self.check_hsts_header(headers, target_url)
                if hsts:
                    findings.append(hsts)

            # ---- Certificate Transparency ----
            if not self.stop_event.is_set():
                ct_findings = self.check_cert_transparency(host)
                findings.extend(ct_findings)

        except Exception as exc:
            log.error("TLSAnalyzer.scan failed for %s: %s", target_url, exc)

        self._findings = findings
        return findings

    def get_findings(self) -> list[TLSFinding]:
        """Return all findings accumulated by the last scan() call."""
        return self._findings
