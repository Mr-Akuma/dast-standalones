"""
Finding correlation engine for DAST scanner.

Links related vulnerabilities across endpoints to identify root causes
and systemic issues rather than treating each finding in isolation.
"""

from __future__ import annotations

import re
import uuid
import hashlib
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional
from urllib.parse import urlparse


@dataclass
class CorrelationGroup:
    correlation_id: str
    root_cause: str
    category: str  # same_param_pattern | same_vuln_type | same_root_cause | escalation_chain | shared_library
    finding_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0
    severity_impact: str = ""  # "amplified" if systemic issue makes individual findings worse
    description: str = ""


# Severity ordering for comparison and ranking
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class FindingCorrelator:
    """Correlates DAST findings to surface root causes and systemic issues."""

    # Escalation chain definitions: (vuln_a, vuln_b) -> (chain_name, description)
    ESCALATION_CHAINS = {
        ("xss", "missing_httponly"): (
            "session_hijack",
            "XSS combined with missing HttpOnly cookie flag enables session hijacking",
        ),
        ("sqli", "admin_endpoint"): (
            "full_compromise",
            "SQL injection on admin endpoint enables full application compromise",
        ),
        ("ssrf", "cloud_metadata"): (
            "iam_escalation",
            "SSRF with cloud metadata access enables IAM credential theft and privilege escalation",
        ),
        ("idor", "pii_exposure"): (
            "mass_data_breach",
            "IDOR combined with PII exposure enables mass user data exfiltration",
        ),
        ("auth_bypass", "sqli"): (
            "unauth_data_access",
            "Authentication bypass chained with SQL injection gives unauthenticated database access",
        ),
        ("xss", "csrf"): (
            "account_takeover",
            "XSS can be used to bypass CSRF protections, enabling account takeover",
        ),
    }

    def __init__(self):
        self._url_id_pattern = re.compile(r'/(\d+)(?=/|$)')
        self._url_uuid_pattern = re.compile(
            r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
            re.IGNORECASE,
        )
        self._error_msg_pattern = re.compile(
            r'(?:error|exception|traceback|warning|failure)[:\s]+"?([^"<>\n]{10,120})',
            re.IGNORECASE,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, findings: list[dict]) -> list[CorrelationGroup]:
        """Run all correlation strategies and merge results.

        Args:
            findings: List of finding dicts with keys:
                url, method, vuln_type, parameter, severity, evidence, finding_id

        Returns:
            Deduplicated list of CorrelationGroup objects.
        """
        if len(findings) < 2:
            return []

        groups: list[CorrelationGroup] = []
        groups.extend(self._correlate_by_param(findings))
        groups.extend(self._correlate_by_vuln_type(findings))
        groups.extend(self._correlate_by_path_pattern(findings))
        groups.extend(self._correlate_by_response_similarity(findings))
        groups.extend(self._correlate_escalation(findings))

        return self._deduplicate_groups(groups)

    def get_root_causes(self, groups: list[CorrelationGroup]) -> list[dict]:
        """Deduplicate and rank root causes by affected endpoints x severity.

        Returns list of dicts sorted by impact (descending):
            root_cause, affected_endpoints, severity, remediation_hint
        """
        cause_map: dict[str, dict] = {}

        for g in groups:
            key = g.root_cause
            if key not in cause_map:
                cause_map[key] = {
                    "root_cause": g.root_cause,
                    "affected_endpoints": len(g.finding_ids),
                    "severity": g.severity_impact or "normal",
                    "remediation_hint": self._remediation_for(g.category, g.root_cause),
                    "_score": 0.0,
                }
            else:
                cause_map[key]["affected_endpoints"] += len(g.finding_ids)

        for entry in cause_map.values():
            sev_weight = 2.0 if entry["severity"] == "amplified" else 1.0
            entry["_score"] = entry["affected_endpoints"] * sev_weight

        ranked = sorted(cause_map.values(), key=lambda x: x["_score"], reverse=True)
        for r in ranked:
            del r["_score"]
        return ranked

    def get_systemic_issues(self, groups: list[CorrelationGroup]) -> list[dict]:
        """Filter for groups with 3+ findings — systemic, not endpoint-specific.

        Returns list of dicts with severity_impact set to 'amplified'.
        """
        systemic = []
        for g in groups:
            if len(g.finding_ids) >= 3:
                systemic.append({
                    "correlation_id": g.correlation_id,
                    "root_cause": g.root_cause,
                    "category": g.category,
                    "finding_count": len(g.finding_ids),
                    "confidence": g.confidence,
                    "severity_impact": "amplified",
                    "description": g.description,
                })
        return sorted(systemic, key=lambda x: x["finding_count"], reverse=True)

    # ------------------------------------------------------------------
    # Correlation strategies
    # ------------------------------------------------------------------

    def _correlate_by_param(self, findings: list[dict]) -> list[CorrelationGroup]:
        """Same parameter name with same vuln_type across different endpoints.

        Indicates shared input handling — e.g. a common sanitization function
        that is broken across the board.
        """
        # Key: (parameter, vuln_type) -> list of findings
        buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for f in findings:
            param = (f.get("parameter") or "").strip().lower()
            vtype = (f.get("vuln_type") or "").strip().lower()
            if param and vtype:
                buckets[(param, vtype)].append(f)

        groups = []
        for (param, vtype), bucket in buckets.items():
            urls = {f.get("url", "") for f in bucket}
            if len(urls) < 2:
                continue
            finding_ids = [f["finding_id"] for f in bucket]
            groups.append(CorrelationGroup(
                correlation_id=str(uuid.uuid4()),
                root_cause=f"Missing input sanitization for parameter '{param}' across {len(urls)} endpoints",
                category="same_param_pattern",
                finding_ids=finding_ids,
                confidence=0.8,
                severity_impact="amplified" if len(urls) >= 3 else "normal",
                description=(
                    f"Parameter '{param}' is vulnerable to {vtype} in {len(urls)} "
                    f"different endpoints, suggesting a shared input handling flaw."
                ),
            ))
        return groups

    def _correlate_by_vuln_type(self, findings: list[dict]) -> list[CorrelationGroup]:
        """Same vuln_type in >3 endpoints — systemic issue, not a one-off."""
        buckets: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            vtype = (f.get("vuln_type") or "").strip().lower()
            if vtype:
                buckets[vtype].append(f)

        groups = []
        for vtype, bucket in buckets.items():
            urls = {f.get("url", "") for f in bucket}
            if len(urls) <= 3:
                continue
            finding_ids = [f["finding_id"] for f in bucket]
            max_sev = max(
                (_SEVERITY_ORDER.get(f.get("severity", "info").lower(), 0) for f in bucket),
                default=0,
            )
            sev_label = {v: k for k, v in _SEVERITY_ORDER.items()}.get(max_sev, "info")
            groups.append(CorrelationGroup(
                correlation_id=str(uuid.uuid4()),
                root_cause=f"Systemic {vtype} vulnerability across {len(urls)} endpoints",
                category="same_vuln_type",
                finding_ids=finding_ids,
                confidence=0.7,
                severity_impact="amplified",
                description=(
                    f"{vtype.upper()} found in {len(urls)} endpoints (max severity: {sev_label}). "
                    f"This pattern indicates a systemic issue such as a shared vulnerable "
                    f"middleware or missing security control at the framework level."
                ),
            ))
        return groups

    def _correlate_by_path_pattern(self, findings: list[dict]) -> list[CorrelationGroup]:
        """Findings sharing a URL path pattern — same controller likely vulnerable.

        E.g. /api/v1/users/:id and /api/v1/orders/:id both have SQLi →
        the v1 API layer is missing parameterized queries.
        """
        buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for f in findings:
            url = f.get("url", "")
            vtype = (f.get("vuln_type") or "").strip().lower()
            pattern = self._normalize_url_pattern(url)
            if pattern and vtype:
                buckets[(pattern, vtype)].append(f)

        groups = []
        for (pattern, vtype), bucket in buckets.items():
            raw_urls = {f.get("url", "") for f in bucket}
            if len(raw_urls) < 2:
                continue
            finding_ids = [f["finding_id"] for f in bucket]
            groups.append(CorrelationGroup(
                correlation_id=str(uuid.uuid4()),
                root_cause=f"Shared vulnerable controller pattern '{pattern}'",
                category="same_root_cause",
                finding_ids=finding_ids,
                confidence=0.75,
                severity_impact="amplified" if len(raw_urls) >= 3 else "normal",
                description=(
                    f"URL pattern '{pattern}' has {vtype} across {len(raw_urls)} "
                    f"concrete URLs, suggesting a shared controller or route handler is vulnerable."
                ),
            ))
        return groups

    def _correlate_by_response_similarity(self, findings: list[dict]) -> list[CorrelationGroup]:
        """Findings with similar error messages — same backend handler.

        Extracts error signatures from evidence and groups by fingerprint.
        """
        sig_buckets: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            sig = self._extract_error_signature(f)
            if sig:
                sig_buckets[sig].append(f)

        groups = []
        for sig, bucket in sig_buckets.items():
            if len(bucket) < 2:
                continue
            finding_ids = [f["finding_id"] for f in bucket]
            groups.append(CorrelationGroup(
                correlation_id=str(uuid.uuid4()),
                root_cause=f"Shared backend handler producing error signature '{sig[:60]}'",
                category="same_root_cause",
                finding_ids=finding_ids,
                confidence=0.65,
                severity_impact="normal",
                description=(
                    f"{len(bucket)} findings share the same error response signature, "
                    f"indicating they hit the same backend handler or error path."
                ),
            ))
        return groups

    def _correlate_escalation(self, findings: list[dict]) -> list[CorrelationGroup]:
        """Detect exploit chains where combining two finding types escalates impact.

        E.g. XSS + missing HttpOnly → session hijack potential.
        """
        # Build a set of vuln_types present and map to findings
        type_map: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            vtype = (f.get("vuln_type") or "").strip().lower()
            if vtype:
                type_map[vtype].append(f)

        groups = []
        for (type_a, type_b), (chain_name, chain_desc) in self.ESCALATION_CHAINS.items():
            if type_a in type_map and type_b in type_map:
                combined_ids = (
                    [f["finding_id"] for f in type_map[type_a]]
                    + [f["finding_id"] for f in type_map[type_b]]
                )
                groups.append(CorrelationGroup(
                    correlation_id=str(uuid.uuid4()),
                    root_cause=f"Escalation chain: {chain_name}",
                    category="escalation_chain",
                    finding_ids=combined_ids,
                    confidence=0.85,
                    severity_impact="amplified",
                    description=chain_desc,
                ))
        return groups

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _normalize_url_pattern(self, url: str) -> str:
        """Replace numeric IDs and UUIDs with :id placeholder for pattern matching.

        '/api/v1/users/42/orders/abc-def-123' → '/api/v1/users/:id/orders/:id'
        """
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            path = parsed.path
        except Exception:
            path = url

        # Replace UUIDs first (longer pattern), then numeric segments
        path = self._url_uuid_pattern.sub('/:id', path)
        path = self._url_id_pattern.sub('/:id', path)

        # Collapse trailing slash
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        return path

    def _extract_error_signature(self, finding: dict) -> str | None:
        """Extract error message fingerprint from finding evidence.

        Looks for error/exception patterns in the evidence string and
        returns a short hash-based signature for grouping.
        """
        evidence = finding.get("evidence") or ""
        if not evidence:
            return None

        match = self._error_msg_pattern.search(evidence)
        if not match:
            return None

        raw_msg = match.group(1).strip()
        # Normalize: collapse whitespace, lowercase, strip variable parts like IDs
        normalized = re.sub(r'\s+', ' ', raw_msg.lower())
        normalized = re.sub(r'\b\d+\b', 'N', normalized)
        normalized = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'UUID',
            normalized,
        )

        sig = hashlib.sha256(normalized.encode()).hexdigest()[:16]
        return sig

    def _deduplicate_groups(self, groups: list[CorrelationGroup]) -> list[CorrelationGroup]:
        """Remove groups whose finding_ids are a strict subset of another group
        in the same category with higher confidence."""
        if not groups:
            return []

        # Sort by confidence descending so we keep higher-confidence groups
        groups.sort(key=lambda g: g.confidence, reverse=True)
        result = []
        seen_sets: list[tuple[str, frozenset[str]]] = []

        for g in groups:
            fid_set = frozenset(g.finding_ids)
            is_subset = False
            for cat, existing_set in seen_sets:
                if cat == g.category and fid_set <= existing_set:
                    is_subset = True
                    break
            if not is_subset:
                result.append(g)
                seen_sets.append((g.category, fid_set))

        return result

    @staticmethod
    def _remediation_for(category: str, root_cause: str) -> str:
        """Generate a remediation hint based on correlation category."""
        hints = {
            "same_param_pattern": (
                "Implement centralized input validation/sanitization for the affected "
                "parameter. Consider a shared validation middleware or decorator."
            ),
            "same_vuln_type": (
                "Address this vulnerability class at the framework or middleware level "
                "rather than patching individual endpoints. Review security controls "
                "for systematic gaps."
            ),
            "same_root_cause": (
                "The shared controller or handler needs a fix applied once — all "
                "affected endpoints will be remediated together."
            ),
            "escalation_chain": (
                "Prioritize fixing the most impactful link in the chain first. "
                "Breaking any single link prevents the full escalation."
            ),
            "shared_library": (
                "Update or patch the shared library/dependency. All consumers "
                "will benefit from a single fix."
            ),
        }
        return hints.get(category, "Review and remediate the identified root cause.")


# ------------------------------------------------------------------
# Cross-Layer Confirmation Gate (module-level)
# ------------------------------------------------------------------

_SEVERITY_DOWNGRADE = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
}


def enrich_signal_count(finding: dict) -> int:
    """Compute independent signal count for a single finding.

    Resolution order:
    1. Explicit ``signal_count`` field on the finding.
    2. Count of ``confirming_agents`` list + 1 (the original agent).
    3. Count of ``confirmed_by`` list + 1.
    4. 1 if ``agent_id`` is present (single agent produced it).
    5. Default to 1.
    """
    # 1. Already set explicitly
    explicit = finding.get("signal_count")
    if explicit is not None:
        return int(explicit)

    # 2. confirming_agents list (each entry is an independent confirmation)
    confirming = finding.get("confirming_agents")
    if confirming is not None and isinstance(confirming, list):
        base = 1 if finding.get("agent_id") else 0
        return base + len(confirming)

    # 3. confirmed_by list
    confirmed_by = finding.get("confirmed_by")
    if confirmed_by is not None and isinstance(confirmed_by, list):
        base = 1 if finding.get("agent_id") else 0
        return base + len(confirmed_by)

    # 4. Single agent produced it
    if finding.get("agent_id"):
        return 1

    # 5. Fallback
    return 1


def confidence_gate(findings: list[dict], min_signals: int = 2) -> list[dict]:
    """Apply cross-layer confirmation gate to findings.

    Findings confirmed by fewer than *min_signals* independent methods/agents
    get their severity downgraded one level.  This approximates the 46-57% FP
    reduction achieved by multi-layer signal correlation in hybrid SAST-DAST
    systems.

    Source: AI-Driven Hybrid SAST-DAST-SCA-IAST Framework (preprints.org, 2026).

    Args:
        findings: List of finding dicts.
        min_signals: Minimum independent signals required to retain severity
            (default 2).

    Returns:
        New list of finding dicts with ``signal_count`` added; single-signal
        findings have severity downgraded one level and
        ``confidence_gated=True`` added.
    """
    gated: list[dict] = []

    for finding in findings:
        out = dict(finding)  # shallow copy — do not mutate originals
        signals = enrich_signal_count(finding)
        out["signal_count"] = signals

        if signals < min_signals:
            current_sev = (out.get("severity") or "info").lower()
            out["severity"] = _SEVERITY_DOWNGRADE.get(current_sev, current_sev)
            out["confidence_gated"] = True

        gated.append(out)

    return gated
