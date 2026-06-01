"""Browser-side security analysis for HTML/JS responses."""
from __future__ import annotations

import re
from typing import Mapping


class BrowserSecurityAnalyzer:
    def analyze(self, url: str, html: str = "", headers: Mapping[str, str] | None = None) -> list[dict]:
        headers_l = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        body = html or ""
        findings: list[dict] = []

        def add(vuln_type: str, severity: str, finding: str, proof: str, payload: str = "") -> None:
            findings.append({
                "agent": "Browser Security Analyzer",
                "vuln_type": vuln_type,
                "type": vuln_type,
                "severity": severity,
                "finding": finding,
                "url": url,
                "proof": proof[:500],
                "payload": payload,
                "cwe": self._cwe(vuln_type),
                "owasp": "WSTG-CLNT",
            })

        if re.search(r"postMessage[\s\S]{0,300},\s*['\"]\*['\"]", body, re.I):
            add(
                "postmessage_wildcard_target",
                "medium",
                "postMessage sends data to wildcard origin",
                "postMessage(..., '*')",
            )

        if re.search(r"addEventListener\s*\(\s*['\"]message['\"]", body, re.I) and not re.search(
            r"\.origin\s*(?:===|!==|==|!=|\.startsWith|\.endsWith|\.includes)", body
        ):
            add(
                "postmessage_missing_origin_check",
                "medium",
                "message event handler does not appear to validate event.origin",
                "message listener without origin comparison",
            )

        if re.search(
            r"(localStorage|sessionStorage)\s*\.\s*(setItem|getItem)\s*\([^)]*(token|secret|jwt|apiKey|apikey|password)",
            body,
            re.I | re.S,
        ):
            add(
                "browser_storage_secret",
                "high",
                "Client-side storage appears to contain sensitive authentication material",
                "localStorage/sessionStorage token-like key",
            )

        csp = headers_l.get("content-security-policy", "")
        if not csp:
            add("weak_csp", "medium", "Content-Security-Policy header is missing", "missing CSP")
        elif "'unsafe-inline'" in csp or re.search(r"(^|;)\s*script-src[^;]*\*", csp, re.I):
            add("weak_csp", "medium", "Content-Security-Policy allows weak script execution", csp)

        if "serviceWorker.register" in body and not re.search(r"scope\s*:", body):
            add(
                "service_worker_broad_scope",
                "low",
                "Service worker is registered without an explicit constrained scope",
                "navigator.serviceWorker.register",
            )

        if not (
            headers_l.get("cross-origin-opener-policy")
            and headers_l.get("cross-origin-embedder-policy")
            and headers_l.get("cross-origin-resource-policy")
        ):
            add(
                "missing_cross_origin_isolation",
                "low",
                "COOP/COEP/CORP headers are incomplete, increasing XS-Leak exposure",
                "missing one or more cross-origin isolation headers",
            )

        return findings

    @staticmethod
    def _cwe(vuln_type: str) -> str:
        return {
            "postmessage_wildcard_target": "CWE-346",
            "postmessage_missing_origin_check": "CWE-346",
            "browser_storage_secret": "CWE-922",
            "weak_csp": "CWE-693",
            "service_worker_broad_scope": "CWE-668",
            "missing_cross_origin_isolation": "CWE-1021",
        }.get(vuln_type, "CWE-693")
