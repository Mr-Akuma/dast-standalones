"""Golden fixture scoring for DAST false-positive/false-negative tracking."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class GoldenFinding:
    vuln_type: str
    url_contains: str
    severity: str = "medium"

    def matches(self, finding: dict) -> bool:
        return (
            (finding.get("vuln_type") or finding.get("type") or "") == self.vuln_type
            and self.url_contains in (finding.get("url") or finding.get("target") or "")
        )


class FalsePositiveLab:
    def __init__(self):
        self.fixtures = {
            "basic-web": [
                GoldenFinding("xss_reflected", "/search", "high"),
                GoldenFinding("sqli_error", "/item", "high"),
                GoldenFinding("weak_csp", "/", "medium"),
            ],
            "api-auth": [
                GoldenFinding("excessive_data_exposure", "/api/profile", "high"),
                GoldenFinding("cross_role_data_exposure", "/api/profile", "high"),
                GoldenFinding("oauth_missing_state", "/callback", "high"),
            ],
        }

    def list_fixtures(self) -> dict:
        return {
            name: {
                "expected_count": len(items),
                "expected": [item.__dict__ for item in items],
            }
            for name, items in self.fixtures.items()
        }

    def score(self, fixture_name: str, findings: Iterable[dict]) -> dict:
        expected = self.fixtures.get(fixture_name)
        if expected is None:
            raise KeyError(f"unknown fixture: {fixture_name}")
        findings_list = list(findings)
        matched_expected: set[int] = set()
        matched_findings: set[int] = set()
        for f_idx, finding in enumerate(findings_list):
            for e_idx, golden in enumerate(expected):
                if e_idx not in matched_expected and golden.matches(finding):
                    matched_expected.add(e_idx)
                    matched_findings.add(f_idx)
                    break
        false_positives = [f for idx, f in enumerate(findings_list) if idx not in matched_findings]
        false_negatives = [g.__dict__ for idx, g in enumerate(expected) if idx not in matched_expected]
        tp = len(matched_findings)
        fp = len(false_positives)
        fn = len(false_negatives)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        return {
            "fixture": fixture_name,
            "expected_count": len(expected),
            "observed_count": len(findings_list),
            "true_positive_count": tp,
            "false_positive_count": fp,
            "false_negative_count": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positives": false_positives[:50],
            "false_negatives": false_negatives,
        }
