"""DAST assurance coverage registry.

This module is intentionally data-first: every scanner capability can declare
what it covers, how risky it is, and which standards it maps to. The app can
then report gaps without guessing from filenames.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class CoverageCheck:
    check_id: str
    name: str
    capability: str
    vuln_types: tuple[str, ...]
    references: tuple[str, ...]
    mode: str = "passive"
    auth_required: bool = False
    dangerous: bool = False
    proof: str = "heuristic"
    owner_module: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CoverageRegistry:
    def __init__(self, checks: Iterable[CoverageCheck] = ()):
        self._checks: dict[str, CoverageCheck] = {}
        for check in checks:
            self.register(check)

    def register(self, check: CoverageCheck) -> None:
        if not check.check_id:
            raise ValueError("check_id is required")
        if check.check_id in self._checks:
            raise ValueError(f"duplicate coverage check_id: {check.check_id}")
        self._checks[check.check_id] = check

    def get(self, check_id: str) -> CoverageCheck:
        return self._checks[check_id]

    def list_checks(self) -> list[CoverageCheck]:
        return sorted(self._checks.values(), key=lambda c: c.check_id)

    def gap_report(self, executed_check_ids: Iterable[str] = ()) -> dict:
        executed = {str(cid) for cid in executed_check_ids if cid}
        checks = self.list_checks()
        covered = [c for c in checks if c.check_id in executed]
        missing = [c for c in checks if c.check_id not in executed]
        by_capability: dict[str, dict] = {}
        for check in checks:
            bucket = by_capability.setdefault(
                check.capability,
                {"total": 0, "covered": 0, "missing": 0, "check_ids": []},
            )
            bucket["total"] += 1
            bucket["check_ids"].append(check.check_id)
            if check.check_id in executed:
                bucket["covered"] += 1
            else:
                bucket["missing"] += 1
        return {
            "total_checks": len(checks),
            "covered_count": len(covered),
            "missing_count": len(missing),
            "coverage_pct": round((len(covered) / len(checks) * 100), 2) if checks else 100.0,
            "covered": [c.to_dict() for c in covered],
            "missing": [c.to_dict() for c in missing],
            "by_capability": by_capability,
        }


def default_registry() -> CoverageRegistry:
    checks = [
        CoverageCheck(
            "COV-REGISTRY-001",
            "Coverage registry and gap dashboard",
            "assurance",
            ("coverage_gap",),
            ("OWASP WSTG reporting", "OWASP ASVS verification coverage"),
            proof="declared-check-map",
            owner_module="coverage_registry",
        ),
        CoverageCheck(
            "AUTH-JOURNEY-001",
            "Authenticated journey replay and cross-role comparison",
            "authenticated_journeys",
            ("cross_role_data_exposure", "workflow_bypass", "idor"),
            ("OWASP WSTG-ATHZ", "OWASP API1:2023 BOLA", "OWASP API5:2023 BFLA"),
            mode="active",
            auth_required=True,
            proof="role-response-diff",
            owner_module="auth_journey",
        ),
        CoverageCheck(
            "API-DATA-DIFF-001",
            "API response vs UI field exposure diff",
            "api_security",
            ("excessive_data_exposure",),
            ("OWASP API3:2023 Broken Object Property Level Authorization", "OWASP WSTG API Testing"),
            proof="ui-api-field-diff",
            owner_module="api_exposure_diff",
        ),
        CoverageCheck(
            "OAUTH-OIDC-001",
            "OAuth/OIDC metadata and callback checks",
            "identity_protocols",
            ("oauth_implicit_flow_enabled", "oauth_missing_state", "oidc_none_alg_supported"),
            ("OWASP WSTG-ATHN", "OWASP ASVS V2 Authentication"),
            owner_module="oauth_oidc_scanner",
        ),
        CoverageCheck(
            "WEBAUTHN-001",
            "WebAuthn browser configuration checks",
            "identity_protocols",
            ("webauthn_user_verification_discouraged",),
            ("OWASP ASVS V2 Authentication", "W3C WebAuthn security considerations"),
            owner_module="oauth_oidc_scanner",
        ),
        CoverageCheck(
            "BROWSER-CLIENT-001",
            "Browser-side security checks",
            "browser_security",
            ("postmessage_wildcard_target", "browser_storage_secret", "weak_csp"),
            ("OWASP WSTG-CLNT", "OWASP ASVS V14 Configuration"),
            owner_module="browser_security",
        ),
        CoverageCheck(
            "FP-LAB-001",
            "Golden vulnerable fixture and false-positive scoring lab",
            "quality",
            ("false_positive_regression",),
            ("OWASP WSTG reporting", "DAST regression testing"),
            proof="golden-fixture-score",
            owner_module="false_positive_lab",
        ),
        CoverageCheck(
            "RESUME-STATE-001",
            "Resumable scan state and surface queue checkpoints",
            "scan_reliability",
            ("scan_resume_gap",),
            ("OWASP WSTG testing workflow",),
            proof="queue-checkpoint",
            owner_module="resumable_scan",
        ),
        CoverageCheck(
            "EVIDENCE-REPLAY-001",
            "Replayable evidence bundle with curl and response diff",
            "evidence",
            ("evidence_replay",),
            ("OWASP WSTG reporting", "OWASP ASVS V1 Architecture"),
            proof="baseline-attack-diff",
            owner_module="evidence_replay",
        ),
        CoverageCheck(
            "API-RESOURCE-001",
            "Unrestricted resource consumption heuristics",
            "api_security",
            ("resource_exhaustion", "rate_limit_missing"),
            ("OWASP API4:2023 Unrestricted Resource Consumption",),
            mode="active",
            owner_module="api_tester",
        ),
        CoverageCheck(
            "BUS-FLOW-001",
            "Sensitive business flow abuse checks",
            "business_logic",
            ("coupon_stacking", "workflow_bypass", "state_confusion"),
            ("OWASP API6:2023 Unrestricted Access to Sensitive Business Flows",),
            mode="active",
            owner_module="biz_logic",
        ),
    ]
    return CoverageRegistry(checks)
