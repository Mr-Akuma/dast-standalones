"""OAuth, OIDC, and WebAuthn configuration checks."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse


class OAuthOIDCAnalyzer:
    def analyze_metadata(
        self,
        issuer: str,
        metadata: dict | None = None,
        callback_url: str = "",
        webauthn_js: str = "",
    ) -> list[dict]:
        metadata = metadata or {}
        findings: list[dict] = []

        def add(vuln_type: str, severity: str, finding: str, proof: str) -> None:
            findings.append({
                "agent": "OAuth/OIDC/WebAuthn Analyzer",
                "vuln_type": vuln_type,
                "type": vuln_type,
                "severity": severity,
                "finding": finding,
                "url": issuer or metadata.get("issuer", ""),
                "proof": proof,
                "cwe": self._cwe(vuln_type),
                "owasp": "WSTG-ATHN",
            })

        response_types = {str(v).lower() for v in metadata.get("response_types_supported", [])}
        grant_types = {str(v).lower() for v in metadata.get("grant_types_supported", [])}
        if any("token" in rt for rt in response_types) or "implicit" in grant_types:
            add(
                "oauth_implicit_flow_enabled",
                "medium",
                "OAuth/OIDC implicit flow is enabled",
                f"response_types={sorted(response_types)} grant_types={sorted(grant_types)}",
            )

        pkce_methods = {str(v).upper() for v in metadata.get("code_challenge_methods_supported", [])}
        if pkce_methods and "S256" not in pkce_methods:
            add("oauth_pkce_plain_only", "high", "PKCE does not advertise S256", str(sorted(pkce_methods)))
        elif not pkce_methods and metadata.get("authorization_endpoint"):
            add("oauth_pkce_not_advertised", "medium", "PKCE support is not advertised", "missing code_challenge_methods_supported")

        algs = {str(v).lower() for v in metadata.get("id_token_signing_alg_values_supported", [])}
        if "none" in algs:
            add("oidc_none_alg_supported", "critical", "OIDC metadata allows unsigned ID tokens", "alg=none")

        redirect_uris = metadata.get("redirect_uris") or metadata.get("redirect_uris_supported") or []
        if any("*" in str(uri) for uri in redirect_uris):
            add("oauth_wildcard_redirect_uri", "high", "OAuth redirect URI allows wildcard matching", str(redirect_uris))

        if callback_url:
            qs = parse_qs(urlparse(callback_url).query)
            if "code" in qs and "state" not in qs:
                add("oauth_missing_state", "high", "OAuth callback contains code without state", callback_url)
            if ("id_token" in qs or "token" in qs) and "nonce" not in qs:
                add("oidc_missing_nonce", "medium", "OIDC callback token lacks nonce", callback_url)

        findings.extend(self.analyze_webauthn(issuer, webauthn_js))
        return findings

    def analyze_webauthn(self, url: str, js: str = "") -> list[dict]:
        if not js:
            return []
        findings: list[dict] = []

        def add(vuln_type: str, severity: str, finding: str, proof: str) -> None:
            findings.append({
                "agent": "OAuth/OIDC/WebAuthn Analyzer",
                "vuln_type": vuln_type,
                "type": vuln_type,
                "severity": severity,
                "finding": finding,
                "url": url,
                "proof": proof,
                "cwe": self._cwe(vuln_type),
                "owasp": "ASVS-V2",
            })

        if "navigator.credentials" in js and re.search(r"userVerification\s*:\s*['\"]discouraged['\"]", js, re.I):
            add(
                "webauthn_user_verification_discouraged",
                "medium",
                "WebAuthn appears to discourage user verification",
                "userVerification: discouraged",
            )
        if "navigator.credentials" in js and "rpId" not in js:
            add("webauthn_missing_rpid", "low", "WebAuthn options do not show an explicit rpId", "rpId not found")
        return findings

    def scan_metadata_url(self, session, issuer: str, timeout: int = 8) -> list[dict]:
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        resp = session.get(url, timeout=timeout)
        try:
            metadata = resp.json()
        except Exception:
            metadata = {}
        return self.analyze_metadata(issuer=issuer, metadata=metadata)

    @staticmethod
    def _cwe(vuln_type: str) -> str:
        return {
            "oauth_implicit_flow_enabled": "CWE-319",
            "oauth_pkce_plain_only": "CWE-347",
            "oauth_pkce_not_advertised": "CWE-347",
            "oidc_none_alg_supported": "CWE-347",
            "oauth_wildcard_redirect_uri": "CWE-601",
            "oauth_missing_state": "CWE-352",
            "oidc_missing_nonce": "CWE-345",
            "webauthn_user_verification_discouraged": "CWE-287",
            "webauthn_missing_rpid": "CWE-346",
        }.get(vuln_type, "CWE-287")
