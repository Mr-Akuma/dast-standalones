"""
Crypto Scanner — OWASP A02:2021 Cryptographic Failures

Covers gaps not addressed by tls_analyzer.py (cert/TLS), scanner.py (protocol/cipher),
or passive.py (HSTS/cookie Secure/mixed-content):

  1. http_cleartext_endpoint   — target reachable over plain HTTP without redirect
  2. sensitive_url_param       — password/token/key in crawled URL query strings
  3. ecb_mode_cookie           — ECB block-repeat pattern in base64-encoded cookies
  4. password_in_response      — plaintext password fields in API/JSON responses
  5. http_basic_auth           — WWW-Authenticate: Basic header
  6. cleartext_token_encoding  — base64(JSON) session cookie (unencrypted "token")
  7. tls_fallback_scsv_absent  — server accepts TLS 1.1 (POODLE mitigation absent)
  8. sensitive_get_param       — sensitive param name + substantial value in GET URL
"""
from __future__ import annotations

import base64
import json
import logging
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass  # SiteMap type hint only — avoid circular import

log = logging.getLogger("dast.crypto_scanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SENSITIVE_PARAM_NAMES = frozenset({
    "password", "passwd", "pwd", "token", "api_key", "apikey", "secret",
    "auth", "access_token", "session", "key", "private_key", "credential",
    "credentials", "pass", "passphrase", "authorization", "client_secret",
    "refresh_token", "id_token",
})

_SENSITIVE_RESPONSE_KEYS = re.compile(
    r'"(?:password|passwd|secret|private_key|client_secret|passphrase)"\s*:\s*"([^"]{4,})"',
    re.I,
)

_MASKED_VALUES = frozenset({"", "***", "****", "*****", "null", "undefined", "redacted"})

_FINDING_AGENT = "Crypto Scanner"


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class CryptoScanner:
    """
    OWASP A02 Cryptographic Failures — active and passive checks.

    Usage::

        scanner = CryptoScanner(target="https://example.com", session=requests_session)
        findings = scanner.scan(sitemap)
    """

    def __init__(
        self,
        target: str,
        session=None,
        timeout: int = 10,
        stop_event: threading.Event | None = None,
    ):
        self.target = target.rstrip("/")
        self.session = session
        self.timeout = timeout
        self.stop_event = stop_event or threading.Event()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def scan(self, sitemap=None) -> list[dict]:
        """Run all crypto checks. Returns list of finding dicts."""
        findings: list[dict] = []

        parsed = urllib.parse.urlparse(self.target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_https = parsed.scheme == "https"

        # ── 1. HTTP cleartext endpoint ──────────────────────────────────
        if not self.stop_event.is_set():
            f = self._check_http_cleartext(self.target)
            if f:
                findings.append(f)

        # ── 2. Sensitive params in crawled URLs ─────────────────────────
        if not self.stop_event.is_set() and sitemap is not None:
            findings.extend(self._check_sensitive_url_params(sitemap))

        # ── 3. TLS_FALLBACK_SCSV (only meaningful for HTTPS targets) ───
        if not self.stop_event.is_set() and is_https and host:
            f = self._check_tls_fallback_scsv(host, port)
            if f:
                findings.append(f)

        # ── 4-8. Per-page passive checks ────────────────────────────────
        if not self.stop_event.is_set() and sitemap is not None:
            findings.extend(self._passive_page_checks(sitemap))

        return findings

    # ------------------------------------------------------------------
    # Check 1: HTTP cleartext endpoint
    # ------------------------------------------------------------------

    def _check_http_cleartext(self, url: str) -> dict | None:
        """Active probe: can the target be reached over plain HTTP?"""
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme != "https":
                return None  # already HTTP — not our job here

            http_url = url.replace("https://", "http://", 1)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                http_url,
                headers={"User-Agent": "DAST-CryptoScanner/1.0"},
                method="HEAD",
            )
            # Do NOT follow redirects automatically — we want to see the raw response
            opener = urllib.request.build_opener(NoRedirectHandler())
            try:
                with opener.open(req, timeout=5) as resp:
                    status = resp.status
                    location = resp.headers.get("Location", "")
                    if status in (200, 204, 206):
                        return _finding(
                            type_="cleartext_endpoint",
                            severity="high",
                            finding="Target accessible over plain HTTP without HTTPS redirect",
                            url=http_url,
                            evidence=f"HTTP {status} returned with no Location redirect",
                            cwe="CWE-319",
                            remediation=(
                                "Return HTTP 301 redirect to HTTPS for all plain-HTTP requests. "
                                "Deploy HSTS to prevent future plaintext connections."
                            ),
                        )
                    if status in (301, 302, 307, 308):
                        if location.startswith("https://"):
                            return None  # Proper redirect to HTTPS
                        # Redirect to another HTTP URL — still a problem
                        return _finding(
                            type_="cleartext_redirect_loop",
                            severity="medium",
                            finding="HTTP redirect does not point to HTTPS",
                            url=http_url,
                            evidence=f"HTTP {status} Location: {location[:120]}",
                            cwe="CWE-319",
                            remediation="Ensure HTTP redirects target https:// URLs.",
                        )
            except urllib.error.HTTPError as e:
                # 4xx/5xx on HTTP is fine — server exists but rejects
                pass
            except urllib.error.URLError:
                # Connection refused / timeout — HTTP port not open
                pass
        except Exception as exc:
            log.debug("_check_http_cleartext error: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Check 2: Sensitive params in crawled URLs
    # ------------------------------------------------------------------

    def _check_sensitive_url_params(self, sitemap) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        try:
            pages = sitemap.pages if hasattr(sitemap, "pages") else {}
            urls = list(pages.keys()) if isinstance(pages, dict) else list(pages)

            for url in urls[:500]:  # cap to avoid huge sitemaps
                if self.stop_event.is_set():
                    break
                try:
                    qs = urllib.parse.urlparse(url).query
                    if not qs:
                        continue
                    params = urllib.parse.parse_qs(qs, keep_blank_values=False)
                    for name, values in params.items():
                        if name.lower() in _SENSITIVE_PARAM_NAMES:
                            val = (values[0] if values else "").strip()
                            if val and val.lower() not in _MASKED_VALUES:
                                dedup_key = f"{name.lower()}:{url[:80]}"
                                if dedup_key in seen:
                                    continue
                                seen.add(dedup_key)
                                findings.append(_finding(
                                    type_="sensitive_url_param",
                                    severity="high",
                                    finding=f"Sensitive parameter '{name}' passed in URL query string",
                                    url=url,
                                    evidence=f"param={name}, url={url[:120]}",
                                    cwe="CWE-598",
                                    remediation=(
                                        "Move sensitive parameters to POST body or HTTP headers. "
                                        "URL query parameters are logged by servers, proxies, and browsers."
                                    ),
                                ))
                except Exception:
                    continue
        except Exception as exc:
            log.debug("_check_sensitive_url_params error: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Check 3: ECB mode cookie detection
    # ------------------------------------------------------------------

    def _check_ecb_cookie(self, url: str, cookies: dict) -> list[dict]:
        """Detect block-cipher ECB mode via repeating 16-byte blocks in cookie values."""
        findings = []
        try:
            for name, value in (cookies or {}).items():
                if not value or len(value) < 44:  # at least 32 bytes base64 = 44 chars
                    continue
                # Skip JWTs (three dot-separated segments)
                if value.count(".") == 2:
                    continue
                try:
                    # Add padding and decode
                    padded = value + "=" * (4 - len(value) % 4)
                    decoded = base64.b64decode(padded)
                    if len(decoded) < 32:
                        continue
                    # Check for repeating 16-byte blocks (ECB signature)
                    blocks: dict[bytes, int] = {}
                    for i in range(0, len(decoded) - 15, 16):
                        block = decoded[i:i + 16]
                        blocks[block] = blocks.get(block, 0) + 1
                    if any(count >= 2 for count in blocks.values()):
                        findings.append(_finding(
                            type_="ecb_mode_cookie",
                            severity="high",
                            finding=f"Cookie '{name}' shows repeating 16-byte blocks — likely AES-ECB mode",
                            url=url,
                            evidence=(
                                f"cookie={name}, decoded_len={len(decoded)}, "
                                f"repeating_blocks={sum(1 for c in blocks.values() if c >= 2)}"
                            ),
                            cwe="CWE-327",
                            remediation=(
                                "Replace AES-ECB with AES-GCM or AES-CBC with a random IV. "
                                "ECB mode leaks plaintext patterns through ciphertext structure."
                            ),
                        ))
                        break  # one finding per cookie
                except Exception:
                    continue
        except Exception as exc:
            log.debug("_check_ecb_cookie error: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Check 4: Password in API response
    # ------------------------------------------------------------------

    def _check_password_in_response(
        self, url: str, body: str, content_type: str
    ) -> list[dict]:
        findings = []
        try:
            if not body:
                return findings

            body_slice = body[:32000]

            # Try JSON parse first
            if "json" in content_type.lower():
                try:
                    data = json.loads(body_slice)
                    hits = _find_sensitive_json_values(data, depth=0)
                    for key, val in hits[:3]:
                        findings.append(_finding(
                            type_="password_in_response",
                            severity="critical",
                            finding=f"API response contains plaintext sensitive field '{key}'",
                            url=url,
                            evidence=f"field={key}, value_length={len(str(val))}",
                            cwe="CWE-312",
                            remediation=(
                                "Never return password/secret fields in API responses. "
                                "Omit the field entirely or return a masked placeholder."
                            ),
                        ))
                    if hits:
                        return findings
                except (json.JSONDecodeError, ValueError):
                    pass

            # Fallback: regex scan
            for m in _SENSITIVE_RESPONSE_KEYS.finditer(body_slice):
                val = m.group(1)
                if val.lower() not in _MASKED_VALUES:
                    findings.append(_finding(
                        type_="password_in_response",
                        severity="critical",
                        finding="Response body contains plaintext sensitive field",
                        url=url,
                        evidence=f"match={m.group(0)[:60]}",
                        cwe="CWE-312",
                        remediation=(
                            "Never return password/secret fields in API responses."
                        ),
                    ))
                    break  # one per page
        except Exception as exc:
            log.debug("_check_password_in_response error: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Check 5: HTTP Basic Auth
    # ------------------------------------------------------------------

    def _check_http_basic_auth(self, url: str, resp_headers: dict) -> dict | None:
        try:
            www_auth = ""
            for k, v in resp_headers.items():
                if k.lower() == "www-authenticate":
                    www_auth = v
                    break
            if www_auth and "basic" in www_auth.lower():
                is_http = url.startswith("http://")
                return _finding(
                    type_="http_basic_auth",
                    severity="high" if is_http else "medium",
                    finding=(
                        "Server uses HTTP Basic Authentication — credentials base64-encoded"
                        + (" over plain HTTP" if is_http else ", consider stronger auth")
                    ),
                    url=url,
                    evidence=f"WWW-Authenticate: {www_auth[:120]}",
                    cwe="CWE-523",
                    remediation=(
                        "Replace HTTP Basic Auth with token-based auth (OAuth2/JWT). "
                        "At minimum, enforce HTTPS. Basic auth credentials are trivially decoded."
                    ),
                )
        except Exception as exc:
            log.debug("_check_http_basic_auth error: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Check 6: Cleartext token encoding (base64 JSON in cookie)
    # ------------------------------------------------------------------

    def _check_cleartext_token_encoding(self, url: str, cookies: dict) -> list[dict]:
        findings = []
        try:
            for name, value in (cookies or {}).items():
                if not value or len(value) < 20:
                    continue
                # Skip JWTs
                if value.count(".") == 2:
                    continue
                try:
                    padded = value + "=" * (4 - len(value) % 4)
                    decoded = base64.b64decode(padded)
                    try:
                        decoded_str = decoded.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    # Must parse as a JSON object (dict) to be interesting
                    parsed = json.loads(decoded_str)
                    if not isinstance(parsed, dict):
                        continue
                    keys = list(parsed.keys())
                    findings.append(_finding(
                        type_="cleartext_token_encoding",
                        severity="high",
                        finding=(
                            f"Cookie '{name}' is base64-encoded JSON — not encrypted, "
                            "data is readable by anyone with access to the cookie"
                        ),
                        url=url,
                        evidence=f"cookie={name}, decoded_keys={keys[:8]}",
                        cwe="CWE-312",
                        remediation=(
                            "Encrypt session tokens with AES-GCM or use an opaque server-side session ID. "
                            "Base64 encoding is NOT encryption."
                        ),
                    ))
                except (ValueError, json.JSONDecodeError, UnicodeDecodeError, Exception):
                    continue
        except Exception as exc:
            log.debug("_check_cleartext_token_encoding error: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Check 7: TLS_FALLBACK_SCSV
    # ------------------------------------------------------------------

    def _check_tls_fallback_scsv(self, host: str, port: int) -> dict | None:
        """
        Check if server accepts TLS 1.1. If it does, TLS_FALLBACK_SCSV may not
        be enforced, leaving the door open for POODLE-style downgrade attacks.
        """
        try:
            if not hasattr(ssl, "TLSVersion"):
                return None  # Python too old to test this

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            except (AttributeError, ssl.SSLError):
                return None

            try:
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        tls.do_handshake()
                        ver = tls.version()
                # Connection succeeded — server still accepts TLS 1.1
                return _finding(
                    type_="tls_fallback_scsv_absent",
                    severity="medium",
                    finding=f"Server accepts TLS 1.1 — downgrade attack (POODLE) mitigation incomplete",
                    url=f"https://{host}:{port}",
                    evidence=f"TLS handshake succeeded with maximum_version=TLS 1.1 (negotiated {ver})",
                    cwe="CWE-757",
                    remediation=(
                        "Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2+ only. "
                        "Ensure TLS_FALLBACK_SCSV (RFC 7507) is supported by your TLS library."
                    ),
                )
            except (ssl.SSLError, OSError):
                # TLS 1.1 was rejected — server properly refuses downgrade
                return None

        except Exception as exc:
            log.debug("_check_tls_fallback_scsv error: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Check 8: Sensitive GET parameters (value-aware)
    # ------------------------------------------------------------------

    def _check_sensitive_get_params(self, url: str) -> dict | None:
        """Flag URLs where a sensitive param name carries a substantial value."""
        try:
            qs = urllib.parse.urlparse(url).query
            if not qs:
                return None
            params = urllib.parse.parse_qs(qs, keep_blank_values=False)
            for name, values in params.items():
                if name.lower() not in _SENSITIVE_PARAM_NAMES:
                    continue
                val = (values[0] if values else "").strip()
                if not val or val.lower() in _MASKED_VALUES:
                    continue
                # Value must look like a real credential (not a placeholder like "example")
                if len(val) < 8:
                    continue
                return _finding(
                    type_="sensitive_get_param",
                    severity="high",
                    finding=f"Sensitive parameter '{name}' with substantial value found in GET URL",
                    url=url,
                    evidence=f"param={name}, value_len={len(val)}, url={url[:120]}",
                    cwe="CWE-598",
                    remediation=(
                        "Transmit credentials via POST body or Authorization header. "
                        "GET parameters appear in server logs, proxy logs, and browser history."
                    ),
                )
        except Exception as exc:
            log.debug("_check_sensitive_get_params error: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Per-page passive runner
    # ------------------------------------------------------------------

    def _passive_page_checks(self, sitemap) -> list[dict]:
        """Run per-page passive checks over all pages in the sitemap."""
        findings: list[dict] = []
        try:
            pages = sitemap.pages if hasattr(sitemap, "pages") else {}
            if isinstance(pages, dict):
                page_items = list(pages.items())
            else:
                page_items = [(u, None) for u in pages]

            for url, page_data in page_items[:200]:  # cap
                if self.stop_event.is_set():
                    break

                # Extract body, headers, cookies from page_data if available
                body = ""
                headers: dict = {}
                cookies: dict = {}
                content_type = ""

                if page_data and hasattr(page_data, "body"):
                    body = page_data.body or ""
                if page_data and hasattr(page_data, "headers"):
                    headers = page_data.headers or {}
                if page_data and hasattr(page_data, "cookies"):
                    cookies = page_data.cookies or {}
                content_type = headers.get("content-type", headers.get("Content-Type", ""))

                # Basic Auth header
                f = self._check_http_basic_auth(url, headers)
                if f:
                    findings.append(f)

                # ECB mode cookie
                findings.extend(self._check_ecb_cookie(url, cookies))

                # Cleartext token encoding
                findings.extend(self._check_cleartext_token_encoding(url, cookies))

                # Password in response body
                if body:
                    findings.extend(
                        self._check_password_in_response(url, body, content_type)
                    )

                # Sensitive GET params in this URL
                f = self._check_sensitive_get_params(url)
                if f:
                    findings.append(f)

        except Exception as exc:
            log.debug("_passive_page_checks error: %s", exc)
        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    *,
    type_: str,
    severity: str,
    finding: str,
    url: str,
    evidence: str,
    cwe: str,
    remediation: str,
) -> dict:
    return {
        "agent":       _FINDING_AGENT,
        "type":        type_,
        "severity":    severity,
        "finding":     finding,
        "url":         url,
        "evidence":    evidence,
        "cwe":         cwe,
        "remediation": remediation,
    }


def _find_sensitive_json_values(obj, depth: int = 0) -> list[tuple[str, object]]:
    """Recursively walk a JSON structure and return (key, value) for sensitive keys."""
    _SENSITIVE_KEYS = {"password", "passwd", "secret", "private_key", "client_secret", "passphrase"}
    hits = []
    if depth > 6:
        return hits
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in _SENSITIVE_KEYS:
                if isinstance(v, str) and len(v) >= 4 and v.lower() not in _MASKED_VALUES:
                    hits.append((k, v))
            else:
                hits.extend(_find_sensitive_json_values(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj[:20]:
            hits.extend(_find_sensitive_json_values(item, depth + 1))
    return hits


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """URL opener that does NOT follow redirects."""

    def http_error_301(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_307(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_308(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


if __name__ == "__main__":
    # Standalone smoke test
    cs = CryptoScanner(target="https://httpbin.org", timeout=5)
    results = cs.scan(sitemap=None)
    print(f"CryptoScanner OK — {len(results)} findings")
