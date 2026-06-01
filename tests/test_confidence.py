"""Tests for AuditIssueConfidence — Burp Suite 3-tier confidence model."""
import pytest
from modules.confidence import (
    AuditIssueConfidence,
    ConfidenceScorer,
    infer_confidence,
    score_to_burp_confidence,
)
from modules.scanner import ScanFinding


# ── AuditIssueConfidence enum ─────────────────────────────────────────────────

class TestAuditIssueConfidenceEnum:
    def test_three_members(self):
        members = list(AuditIssueConfidence)
        assert len(members) == 3

    def test_values(self):
        assert AuditIssueConfidence.CERTAIN.value   == "Certain"
        assert AuditIssueConfidence.FIRM.value       == "Firm"
        assert AuditIssueConfidence.TENTATIVE.value  == "Tentative"

    def test_lookup_by_value(self):
        assert AuditIssueConfidence("Certain")   is AuditIssueConfidence.CERTAIN
        assert AuditIssueConfidence("Firm")       is AuditIssueConfidence.FIRM
        assert AuditIssueConfidence("Tentative")  is AuditIssueConfidence.TENTATIVE


# ── score_to_burp_confidence ──────────────────────────────────────────────────

class TestScoreToBurpConfidence:
    def test_oast_score_is_certain(self):
        assert score_to_burp_confidence(0.95) is AuditIssueConfidence.CERTAIN

    def test_proof_confirmed_score_is_certain(self):
        assert score_to_burp_confidence(0.90) is AuditIssueConfidence.CERTAIN

    def test_boundary_certain(self):
        assert score_to_burp_confidence(0.85) is AuditIssueConfidence.CERTAIN

    def test_error_based_score_is_firm(self):
        assert score_to_burp_confidence(0.80) is AuditIssueConfidence.FIRM

    def test_time_based_score_is_firm(self):
        assert score_to_burp_confidence(0.70) is AuditIssueConfidence.FIRM

    def test_boolean_blind_score_is_firm(self):
        assert score_to_burp_confidence(0.65) is AuditIssueConfidence.FIRM

    def test_boundary_firm_lower(self):
        # 0.65 is the lowest FIRM score
        assert score_to_burp_confidence(0.65) is AuditIssueConfidence.FIRM

    def test_pattern_match_score_is_tentative(self):
        assert score_to_burp_confidence(0.50) is AuditIssueConfidence.TENTATIVE

    def test_passive_score_is_tentative(self):
        assert score_to_burp_confidence(0.40) is AuditIssueConfidence.TENTATIVE

    def test_zero_is_tentative(self):
        assert score_to_burp_confidence(0.0) is AuditIssueConfidence.TENTATIVE

    def test_one_is_certain(self):
        assert score_to_burp_confidence(1.0) is AuditIssueConfidence.CERTAIN


# ── infer_confidence ──────────────────────────────────────────────────────────

class TestInferConfidence:
    def test_confirmed_in_finding_is_certain(self):
        result = infer_confidence("sqli_error", "SQLi CONFIRMED — DB version extracted", "proof")
        assert result is AuditIssueConfidence.CERTAIN

    def test_oast_vuln_type_is_certain(self):
        result = infer_confidence("oast_ssrf", "OOB callback received", "")
        assert result is AuditIssueConfidence.CERTAIN

    def test_callback_in_finding_is_certain(self):
        result = infer_confidence("ssrf", "DNS callback observed from target", "")
        assert result is AuditIssueConfidence.CERTAIN

    def test_proof_non_empty_is_firm(self):
        result = infer_confidence("xss_reflected", "XSS payload reflected", "payload echoed")
        assert result is AuditIssueConfidence.FIRM

    def test_error_in_vuln_type_is_firm(self):
        result = infer_confidence("sqli_error", "MySQL syntax error detected", "")
        assert result is AuditIssueConfidence.FIRM

    def test_time_in_vuln_type_is_firm(self):
        result = infer_confidence("sqli_time_based", "Timing anomaly detected", "")
        assert result is AuditIssueConfidence.FIRM

    def test_blind_in_vuln_type_is_firm(self):
        result = infer_confidence("sqli_blind", "Boolean differential detected", "")
        assert result is AuditIssueConfidence.FIRM

    def test_no_signals_is_tentative(self):
        result = infer_confidence("xss_reflected", "Possible XSS pattern found", "")
        assert result is AuditIssueConfidence.TENTATIVE

    def test_passive_check_is_tentative(self):
        result = infer_confidence("missing_hsts", "HSTS header not present", "")
        assert result is AuditIssueConfidence.TENTATIVE


# ── ConfidenceScorer.score_and_annotate emits audit_confidence ────────────────

class TestScoreAndAnnotate:
    def test_oast_finding_annotated_certain(self):
        scorer = ConfidenceScorer()
        finding = {
            "vuln_type": "oast_ssrf",
            "finding": "OAST callback received",
            "proof": "DNS interaction logged",
        }
        result = scorer.score_and_annotate(finding)
        assert "audit_confidence" in result
        assert result["audit_confidence"] == "Certain"

    def test_passive_finding_annotated_tentative(self):
        scorer = ConfidenceScorer()
        finding = {
            "vuln_type": "missing_hsts",
            "finding": "HSTS header missing",
            "proof": "",
            "source_phase": "passive",
        }
        result = scorer.score_and_annotate(finding)
        assert result["audit_confidence"] in ("Tentative", "Firm")  # passive weight is 0.40

    def test_annotate_preserves_existing_keys(self):
        scorer = ConfidenceScorer()
        finding = {"vuln_type": "sqli_error", "finding": "Error", "proof": "stacktrace", "url": "http://x.com"}
        result = scorer.score_and_annotate(finding)
        assert result["url"] == "http://x.com"
        assert "confidence_score" in result
        assert "confidence_level" in result
        assert "audit_confidence" in result


# ── ScanFinding.confidence_level field ───────────────────────────────────────

class TestScanFindingConfidenceField:
    def _make_sf(self, **kwargs):
        defaults = dict(
            id="sf_test", url="http://x.com", method="GET",
            param="q", param_type="query", vuln_type="sqli_error",
            owasp_category="A03:2025 Injection", cwe="CWE-89",
            finding="SQLi detected", severity="high",
            proof="", payload="' OR 1=1--", evidence_id=None,
            remediation="Use parameterised queries.",
        )
        defaults.update(kwargs)
        return ScanFinding(**defaults)

    def test_default_confidence_is_tentative(self):
        sf = self._make_sf()
        assert sf.confidence_level is AuditIssueConfidence.TENTATIVE

    def test_explicit_certain_stored(self):
        sf = self._make_sf(confidence_level=AuditIssueConfidence.CERTAIN)
        assert sf.confidence_level is AuditIssueConfidence.CERTAIN

    def test_to_dict_emits_string_value(self):
        sf = self._make_sf(confidence_level=AuditIssueConfidence.FIRM)
        d = sf.to_dict()
        assert d["confidence_level"] == "Firm"

    def test_to_dict_certain_serializes_correctly(self):
        sf = self._make_sf(confidence_level=AuditIssueConfidence.CERTAIN)
        assert sf.to_dict()["confidence_level"] == "Certain"

    def test_to_dict_tentative_serializes_correctly(self):
        sf = self._make_sf(confidence_level=AuditIssueConfidence.TENTATIVE)
        assert sf.to_dict()["confidence_level"] == "Tentative"
