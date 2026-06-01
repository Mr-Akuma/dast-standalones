"""
scan_brain.py — Central decision engine for the autonomous DAST scanner.

Observes scan progress (fingerprinting results, HTTP responses, discovered
findings) and makes tactical decisions mid-scan: which payload sets to use,
how aggressively to test, whether to back off when a WAF is blocking, and
which findings can be chained together for higher-impact exploits.

Policies:
    passive-only  — no active payloads; observe and fingerprint only.
    standard      — balanced intensity with WAF-aware backoff.
    aggressive    — maximum coverage; ignore WAF throttling signals.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static extension sets used by endpoint-priority decisions
# ---------------------------------------------------------------------------
_STATIC_EXTENSIONS: set[str] = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
}

# Common WAF response headers (lowercase keys for comparison)
_WAF_HEADER_SIGNATURES: dict[str, str] = {
    "x-sucuri-id":          "Sucuri",
    "x-sucuri-cache":       "Sucuri",
    "server":               None,       # checked for specific values below
    "x-cdn":                None,
    "cf-ray":               "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-aws-waf-rule":      "AWS WAF",
    "x-datadome":           "DataDome",
    "x-distil-cs":          "Distil/Imperva",
}

_WAF_SERVER_VALUES: dict[str, str] = {
    "cloudflare":    "Cloudflare",
    "akamaighost":   "Akamai",
    "bigip":         "F5 BIG-IP",
    "barracuda":     "Barracuda",
    "imperva":       "Imperva",
    "incapsula":     "Imperva",
    "sucuri":        "Sucuri",
    "ddos-guard":    "DDoS-Guard",
    "aws-waf":       "AWS WAF",
}

# DB-specific payload set names keyed by common fingerprint identifiers
_DB_PAYLOAD_MAP: dict[str, str] = {
    "mysql":      "mysql_sqli",
    "mariadb":    "mysql_sqli",
    "postgresql":  "postgres_sqli",
    "postgres":    "postgres_sqli",
    "mssql":       "mssql_sqli",
    "sqlserver":   "mssql_sqli",
    "oracle":      "oracle_sqli",
    "sqlite":      "sqlite_sqli",
    "mongodb":     "nosql_injection",
    "couchdb":     "nosql_injection",
}

# Tech-specific payload set names keyed by language / framework
_TECH_PAYLOAD_MAP: dict[str, list[str]] = {
    "php":        ["php_ssti", "php_rce", "php_lfi"],
    "python":     ["python_ssti", "python_rce"],
    "java":       ["java_deserialization", "java_ssti", "java_sqli"],
    "node":       ["node_ssti", "node_prototype_pollution"],
    "asp.net":    ["aspnet_viewstate", "mssql_sqli"],
    "ruby":       ["ruby_ssti", "ruby_rce"],
}


class ScanBrain:
    """Central tactical decision-maker for autonomous DAST scanning."""

    # --------------------------------------------------------------------- #
    # Initialisation
    # --------------------------------------------------------------------- #
    def __init__(
        self,
        fingerprint_results: dict | None = None,
        policy: str = "standard",
    ) -> None:
        if policy not in ("passive-only", "standard", "aggressive"):
            raise ValueError(
                f"Unknown policy '{policy}'. "
                "Must be one of: passive-only, standard, aggressive"
            )

        self.policy: str = policy
        self.decisions: list[dict] = []
        self.tech_stack: dict = {}
        self.waf_detected: str | None = None
        self.scan_phase: str = "init"
        self.findings_count: dict[str, int] = {}
        self.blocked_count: int = 0
        self.total_requests: int = 0

        # Internal tracking
        self._response_times: list[float] = []
        self._status_history: dict[str, list[int]] = {}  # url -> [status …]
        self._consecutive_blocks: int = 0

        if fingerprint_results:
            self.observe_fingerprint(fingerprint_results)

        logger.info("ScanBrain initialised (policy=%s)", self.policy)

    # --------------------------------------------------------------------- #
    # Observation methods
    # --------------------------------------------------------------------- #
    def observe_fingerprint(self, fingerprint: dict) -> None:
        """Ingest technology-stack information from the fingerprinting phase.

        Expected keys (all optional):
            server, language, framework, database, os, waf, headers, cms
        """
        self.tech_stack = fingerprint
        self.scan_phase = "fingerprinted"

        # Detect WAF from fingerprint data
        waf_value = fingerprint.get("waf")
        if waf_value:
            self.waf_detected = waf_value

        self._log_decision(
            category="fingerprint",
            decision="tech_stack_updated",
            reason=f"Ingested fingerprint: {fingerprint}",
        )
        logger.info("Fingerprint ingested: %s", fingerprint)

    def observe_response(
        self,
        url: str,
        status: int,
        resp_time: float,
        headers: dict,
    ) -> None:
        """Track an HTTP response and look for WAF / throttling signals."""
        self.total_requests += 1
        self._response_times.append(resp_time)
        self._status_history.setdefault(url, []).append(status)

        # --- WAF detection via headers ---
        lower_headers: dict[str, str] = {
            k.lower(): v for k, v in headers.items()
        }

        if not self.waf_detected:
            self.waf_detected = self._detect_waf_from_headers(lower_headers)
            if self.waf_detected:
                self._log_decision(
                    category="waf",
                    decision="waf_identified",
                    reason=f"Detected WAF: {self.waf_detected} from response headers",
                )
                logger.warning("WAF detected: %s", self.waf_detected)

        # --- Block / throttle tracking ---
        is_blocked = False
        if status == 403 and self._has_waf_headers(lower_headers):
            is_blocked = True
        elif status == 429:
            is_blocked = True
        elif status == 503 and "retry-after" in lower_headers:
            is_blocked = True

        if is_blocked:
            self.blocked_count += 1
            self._consecutive_blocks += 1
            if self._consecutive_blocks % 5 == 0:
                self._log_decision(
                    category="waf",
                    decision="block_streak",
                    reason=(
                        f"{self._consecutive_blocks} consecutive blocks "
                        f"(total {self.blocked_count}). url={url} status={status}"
                    ),
                )
        else:
            self._consecutive_blocks = 0

    def observe_finding(self, finding: dict) -> None:
        """Record a discovered vulnerability and update internal tallies.

        Expected keys: vuln_type (str), severity (str), url (str).
        """
        vuln_type: str = finding.get("vuln_type", "unknown")
        self.findings_count[vuln_type] = self.findings_count.get(vuln_type, 0) + 1

        self._log_decision(
            category="finding",
            decision="finding_recorded",
            reason=(
                f"New {vuln_type} finding "
                f"(total for type: {self.findings_count[vuln_type]}). "
                f"url={finding.get('url', 'N/A')}"
            ),
        )

        # If we crossed a threshold that enables chaining, note it.
        chains = self.should_chain_findings()
        if chains:
            self._log_decision(
                category="chaining",
                decision="chain_opportunities_detected",
                reason=f"{len(chains)} chain(s) possible after latest finding",
            )

    # --------------------------------------------------------------------- #
    # Decision methods
    # --------------------------------------------------------------------- #
    def decide_payload_strategy(
        self,
        param_name: str,
        param_type: str,
    ) -> dict[str, Any]:
        """Return a payload strategy for a specific parameter.

        Returns:
            dict with keys: payload_sets, intensity, skip, reason
        """
        # --- Passive-only policy: always skip ---
        if self.policy == "passive-only":
            strategy = {
                "payload_sets": [],
                "intensity": 0,
                "skip": True,
                "reason": "Policy is passive-only; active payloads disabled",
            }
            self._log_decision("payload", "skip_passive", strategy["reason"])
            return strategy

        payload_sets: list[str] = []
        intensity: int = 3  # default mid-range
        skip: bool = False
        reasons: list[str] = []

        # --- Parameter-type heuristics ---
        param_type_lower = param_type.lower() if param_type else ""
        param_name_lower = param_name.lower() if param_name else ""

        if param_type_lower == "url" or "url" in param_name_lower:
            payload_sets.append("ssrf")
            payload_sets.append("open_redirect")
            reasons.append("param_type=url -> SSRF/redirect payloads")

        if param_type_lower == "filename" or any(
            kw in param_name_lower for kw in ("file", "path", "doc", "template")
        ):
            payload_sets.append("lfi")
            payload_sets.append("path_traversal")
            reasons.append("param relates to filenames -> LFI payloads")

        if param_type_lower == "id" or re.search(r"_?id$", param_name_lower):
            payload_sets.append("idor")
            payload_sets.append("bola")
            reasons.append("param looks like an identifier -> IDOR payloads")

        # --- Tech-stack-aware payloads ---
        db = (self.tech_stack.get("database") or "").lower()
        for db_key, pset in _DB_PAYLOAD_MAP.items():
            if db_key in db:
                payload_sets.append(pset)
                reasons.append(f"Detected DB {db} -> {pset}")
                break
        else:
            # No specific DB detected; include generic SQLi
            payload_sets.append("generic_sqli")

        lang = (self.tech_stack.get("language") or "").lower()
        framework = (self.tech_stack.get("framework") or "").lower()
        for tech_key, psets in _TECH_PAYLOAD_MAP.items():
            if tech_key in lang or tech_key in framework:
                payload_sets.extend(psets)
                reasons.append(f"Tech {tech_key} -> {psets}")

        # Always include generic XSS
        payload_sets.append("xss_reflected")
        payload_sets.append("xss_stored")

        # --- WAF-aware adjustments ---
        if self.waf_detected and self.blocked_count > 10:
            if self.policy == "aggressive":
                intensity = 5
                payload_sets.append("waf_bypass")
                reasons.append(
                    f"WAF ({self.waf_detected}) active with {self.blocked_count} "
                    "blocks, but aggressive policy keeps high intensity"
                )
            else:
                intensity = max(1, intensity - 2)
                # Replace direct payloads with evasion variants
                payload_sets = [
                    f"{p}_evasion" if not p.endswith("_evasion") else p
                    for p in payload_sets
                ]
                payload_sets.append("waf_bypass")
                reasons.append(
                    f"WAF ({self.waf_detected}) blocking "
                    f"({self.blocked_count} blocks) -> evasion payloads, "
                    f"intensity lowered to {intensity}"
                )
        elif self.policy == "aggressive":
            intensity = 5
            reasons.append("Aggressive policy -> maximum intensity")

        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for p in payload_sets:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        payload_sets = deduped

        reason_str = "; ".join(reasons) if reasons else "Default strategy applied"
        strategy = {
            "payload_sets": payload_sets,
            "intensity": intensity,
            "skip": skip,
            "reason": reason_str,
        }

        self._log_decision(
            "payload",
            f"strategy for {param_name} ({param_type})",
            reason_str,
        )
        return strategy

    def decide_endpoint_priority(
        self,
        url: str,
        method: str,
        findings_so_far: int,
    ) -> dict[str, Any]:
        """Decide how important an endpoint is and whether to skip it.

        Returns:
            dict with keys: priority (1-10), skip (bool), reason (str)
        """
        priority: int = 5  # baseline
        skip: bool = False
        reasons: list[str] = []

        # --- Static resource check ---
        path_lower = url.lower().split("?")[0]
        for ext in _STATIC_EXTENSIONS:
            if path_lower.endswith(ext):
                skip = True
                reasons.append(f"Static resource ({ext})")
                break

        # --- Consistent-403 check ---
        history = self._status_history.get(url, [])
        if len(history) >= 3 and all(s == 403 for s in history[-3:]):
            priority = max(1, priority - 3)
            reasons.append(
                "Last 3 responses were 403 -> lowered priority"
            )

        # --- Findings amplification ---
        if findings_so_far > 0:
            bonus = min(findings_so_far * 2, 5)
            priority = min(10, priority + bonus)
            reasons.append(
                f"{findings_so_far} finding(s) already -> priority +{bonus}"
            )

        # --- Method bonus ---
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            priority = min(10, priority + 1)
            reasons.append(f"Write method ({method.upper()}) -> priority +1")

        # --- Passive policy: lower priority for all active tests ---
        if self.policy == "passive-only":
            priority = 1
            skip = True
            reasons.append("Passive-only policy -> skip active testing")

        reason_str = "; ".join(reasons) if reasons else "Default priority"
        result = {"priority": priority, "skip": skip, "reason": reason_str}

        self._log_decision(
            "endpoint",
            f"priority={priority} skip={skip} for {method} {url}",
            reason_str,
        )
        return result

    def decide_concurrency(self) -> dict[str, Any]:
        """Decide concurrency and inter-request delay based on server behaviour.

        Returns:
            dict with keys: max_concurrent (int), delay_ms (int), reason (str)
        """
        max_concurrent: int = 10
        delay_ms: int = 0
        reasons: list[str] = []

        # Baseline adjustments per policy
        if self.policy == "passive-only":
            max_concurrent = 5
            delay_ms = 200
            reasons.append("Passive-only: conservative concurrency")
        elif self.policy == "aggressive":
            max_concurrent = 20
            delay_ms = 0
            reasons.append("Aggressive: high concurrency baseline")

        # --- WAF / block-rate adjustments (standard + passive) ---
        if self.policy != "aggressive":
            if self.blocked_count > 50:
                max_concurrent = max(1, max_concurrent // 4)
                delay_ms = max(delay_ms, 2000)
                reasons.append(
                    f"Heavy blocking ({self.blocked_count}) -> "
                    f"concurrent={max_concurrent}, delay={delay_ms}ms"
                )
            elif self.blocked_count > 20:
                max_concurrent = max(2, max_concurrent // 2)
                delay_ms = max(delay_ms, 1000)
                reasons.append(
                    f"Moderate blocking ({self.blocked_count}) -> "
                    f"concurrent={max_concurrent}, delay={delay_ms}ms"
                )
            elif self.blocked_count > 10:
                max_concurrent = max(3, max_concurrent - 3)
                delay_ms = max(delay_ms, 500)
                reasons.append(
                    f"Light blocking ({self.blocked_count}) -> "
                    f"concurrent={max_concurrent}, delay={delay_ms}ms"
                )

        # --- Slow server detection ---
        if self._response_times:
            avg_time = sum(self._response_times[-50:]) / len(self._response_times[-50:])
            if avg_time > 5.0:
                max_concurrent = max(1, max_concurrent // 2)
                delay_ms = max(delay_ms, 500)
                reasons.append(
                    f"Slow avg response ({avg_time:.1f}s) -> reduced concurrency"
                )
            elif avg_time > 2.0:
                max_concurrent = max(2, max_concurrent - 2)
                reasons.append(
                    f"Moderate avg response ({avg_time:.1f}s) -> slight reduction"
                )

        reason_str = "; ".join(reasons) if reasons else "Default concurrency settings"
        result = {
            "max_concurrent": max_concurrent,
            "delay_ms": delay_ms,
            "reason": reason_str,
        }

        self._log_decision("concurrency", f"max={max_concurrent} delay={delay_ms}ms", reason_str)
        return result

    def should_chain_findings(self) -> list[dict[str, str]]:
        """Examine current findings and return chaining opportunities.

        Returns:
            List of dicts with keys: type, trigger, action
        """
        chains: list[dict[str, str]] = []

        # SSRF -> cloud metadata pivot
        if self.findings_count.get("ssrf", 0) > 0:
            chains.append({
                "type": "ssrf_to_metadata",
                "trigger": "ssrf finding exists",
                "action": "run metadata probe (169.254.169.254, Azure IMDS, GCP metadata)",
            })

        # LFI -> credential harvesting
        if self.findings_count.get("lfi", 0) > 0:
            chains.append({
                "type": "lfi_to_credentials",
                "trigger": "lfi finding exists",
                "action": "attempt reading /etc/passwd, .env, web.config, wp-config.php",
            })

        # SQLi -> data exfiltration probe
        if any(
            self.findings_count.get(k, 0) > 0
            for k in (
                "sqli", "generic_sqli", "mysql_sqli", "postgres_sqli",
                "mssql_sqli", "oracle_sqli", "sqlite_sqli",
            )
        ):
            chains.append({
                "type": "sqli_to_data_exfil",
                "trigger": "sqli finding exists",
                "action": "enumerate database schema and attempt UNION-based extraction",
            })

        # XSS + session info -> session hijack scenario
        xss_total = sum(
            self.findings_count.get(k, 0)
            for k in ("xss_reflected", "xss_stored", "xss", "dom_xss")
        )
        if xss_total > 0 and self.findings_count.get("session_fixation", 0) > 0:
            chains.append({
                "type": "xss_session_hijack",
                "trigger": "xss + session fixation findings exist",
                "action": "craft session-stealing XSS payload and validate cookie scope",
            })

        # IDOR + auth bypass -> privilege escalation
        if (
            self.findings_count.get("idor", 0) > 0
            and self.findings_count.get("auth_bypass", 0) > 0
        ):
            chains.append({
                "type": "idor_privesc",
                "trigger": "idor + auth_bypass findings exist",
                "action": "attempt cross-tenant data access with escalated context",
            })

        # Open redirect + SSRF -> internal network pivot
        if (
            self.findings_count.get("open_redirect", 0) > 0
            and self.findings_count.get("ssrf", 0) > 0
        ):
            chains.append({
                "type": "redirect_ssrf_chain",
                "trigger": "open_redirect + ssrf findings exist",
                "action": "use open redirect as SSRF trampoline to internal services",
            })

        # File upload + RCE indicators
        if self.findings_count.get("file_upload", 0) > 0:
            chains.append({
                "type": "upload_to_rce",
                "trigger": "file_upload finding exists",
                "action": "upload webshell variants and probe for execution",
            })

        if chains:
            self._log_decision(
                "chaining",
                f"{len(chains)} chain(s) identified",
                "; ".join(c["type"] for c in chains),
            )

        return chains

    # --------------------------------------------------------------------- #
    # Reasoning log
    # --------------------------------------------------------------------- #
    def get_reasoning_log(self) -> list[dict]:
        """Return the full decision/reasoning log."""
        return list(self.decisions)

    # --------------------------------------------------------------------- #
    # Private helpers
    # --------------------------------------------------------------------- #
    def _log_decision(
        self,
        category: str,
        decision: str,
        reason: str,
    ) -> None:
        """Append a timestamped entry to the reasoning log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": category,
            "decision": decision,
            "reason": reason,
        }
        self.decisions.append(entry)
        logger.debug("[%s] %s — %s", category, decision, reason)

    def _detect_waf_from_headers(
        self,
        lower_headers: dict[str, str],
    ) -> str | None:
        """Inspect response headers and return WAF name if recognised."""
        for header_key, waf_name in _WAF_HEADER_SIGNATURES.items():
            if header_key in lower_headers:
                if waf_name is not None:
                    return waf_name
                # For 'server' and 'x-cdn', match against known values
                value = lower_headers[header_key].lower()
                for pattern, name in _WAF_SERVER_VALUES.items():
                    if pattern in value:
                        return name
        return None

    def _has_waf_headers(self, lower_headers: dict[str, str]) -> bool:
        """Return True if the response headers suggest a WAF-generated block."""
        # Any recognised WAF header counts
        for header_key, waf_name in _WAF_HEADER_SIGNATURES.items():
            if header_key in lower_headers:
                if waf_name is not None:
                    return True
                value = lower_headers[header_key].lower()
                for pattern in _WAF_SERVER_VALUES:
                    if pattern in value:
                        return True
        return False
