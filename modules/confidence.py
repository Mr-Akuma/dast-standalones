"""Central confidence scoring module.

Combines multiple signals (proof validation, anomaly scoring, detection method,
feedback history) into a single confidence score and level for each finding.

Also provides AuditIssueConfidence — a Python port of Burp Suite's
api/montoya/scanner/audit/issues/AuditIssueConfidence.java — the canonical
3-tier confidence enum attached to every ScanFinding.
"""
from __future__ import annotations

import enum
import logging
from urllib.parse import urlparse

log = logging.getLogger(__name__)


# ── Burp-compatible 3-tier confidence enum ────────────────────────────────────

class AuditIssueConfidence(enum.Enum):
    """
    Mirrors Burp Suite's AuditIssueConfidence enum.

    CERTAIN   — Confirmed exploit.  OAST callback received, or ProofValidator
                successfully replayed and confirmed the vulnerability.
    FIRM      — Strong technical evidence but not a live exploit.  DB error
                in response, statistically significant timing delta, or
                boolean-blind differential confirms the injection channel.
    TENTATIVE — Heuristic or indirect signal.  Pattern match in response,
                passive header/config check, or a single anomalous response
                that hasn't been confirmed.
    """
    CERTAIN   = "Certain"
    FIRM      = "Firm"
    TENTATIVE = "Tentative"

# Detection method confidence weights (some methods are more reliable)
DETECTION_WEIGHTS: dict[str, float] = {
    "oast_callback":    0.95,  # Out-of-band confirmation
    "proof_confirmed":  0.90,  # ProofValidator confirmed
    "error_based":      0.80,  # DB error in response
    "time_based":       0.70,  # Timing-based (can be noisy)
    "boolean_blind":    0.65,  # Differential analysis
    "pattern_match":    0.50,  # Regex pattern match (most FP-prone)
    "passive":          0.40,  # Passive detection (header/config check)
    "default":          0.50,
}

CONFIDENCE_LEVELS = {
    (0.85, 1.01): "Critical",       # Near-certain
    (0.70, 0.85): "High",           # Very likely real
    (0.50, 0.70): "Medium",         # Probable
    (0.30, 0.50): "Low",            # Possible
    (0.00, 0.30): "Informational",  # Needs investigation
}

# Detection method → AuditIssueConfidence tier
_METHOD_TO_CONFIDENCE: dict[str, AuditIssueConfidence] = {
    "oast_callback":   AuditIssueConfidence.CERTAIN,
    "proof_confirmed": AuditIssueConfidence.CERTAIN,
    "error_based":     AuditIssueConfidence.FIRM,
    "time_based":      AuditIssueConfidence.FIRM,
    "boolean_blind":   AuditIssueConfidence.FIRM,
    "pattern_match":   AuditIssueConfidence.TENTATIVE,
    "passive":         AuditIssueConfidence.TENTATIVE,
}


def score_to_burp_confidence(score: float) -> AuditIssueConfidence:
    """Map a 0.0–1.0 confidence score to the Burp 3-tier enum.

    Thresholds align with DETECTION_WEIGHTS:
        ≥ 0.85  → CERTAIN   (oast_callback / proof_confirmed territory)
        ≥ 0.65  → FIRM      (error_based / time_based / boolean_blind)
        < 0.65  → TENTATIVE (pattern_match / passive)
    """
    if score >= 0.85:
        return AuditIssueConfidence.CERTAIN
    if score >= 0.65:
        return AuditIssueConfidence.FIRM
    return AuditIssueConfidence.TENTATIVE


def infer_confidence(vuln_type: str, finding: str, proof: str) -> AuditIssueConfidence:
    """Lightweight heuristic inference — used by ScanFinding construction.

    Prefer explicit ``score_to_burp_confidence`` when a numeric score is
    available.  This function is for call sites that only have the raw strings.
    """
    vt  = vuln_type.lower()
    txt = finding.lower()

    # CERTAIN: active confirmation in finding text or vuln type
    if ("confirmed" in txt
            or "oast" in vt
            or "callback" in txt
            or "oast_callback" in vt):
        return AuditIssueConfidence.CERTAIN

    # FIRM: proof non-empty, or detection method implies technical evidence
    if (proof
            or "error" in vt
            or "time" in vt
            or "bool" in vt
            or "blind" in vt):
        return AuditIssueConfidence.FIRM

    return AuditIssueConfidence.TENTATIVE


class ConfidenceScorer:
    """Assigns confidence score and level to findings.

    Signals considered:
        1. proof_status   - Does the finding have proof_validator confirmation?
        2. anomaly_score  - How anomalous was the response vs baseline? (0.0-1.0)
        3. detection_method - How was it detected? (pattern match, blind, OAST, etc.)
        4. feedback_history - Has this pattern been marked FP before?
    """

    def __init__(self, anomaly_scorer=None, feedback_store=None):
        """
        Args:
            anomaly_scorer: AnomalyScorer instance (optional).
            feedback_store: FeedbackStore instance (optional).
        """
        self._anomaly = anomaly_scorer
        self._feedback = feedback_store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, finding: dict) -> tuple[float, str]:
        """Score a finding's confidence.

        Returns:
            (confidence_score: float 0.0-1.0, confidence_level: str)
        """
        # 1. Base score from detection method
        method = self._classify_detection_method(finding)
        base_score = DETECTION_WEIGHTS.get(method, DETECTION_WEIGHTS["default"])

        # 2. Boost from proof validation
        if finding.get("proof"):
            base_score = max(base_score, DETECTION_WEIGHTS["proof_confirmed"])

        # 3. Boost/penalize from anomaly score
        if self._anomaly:
            anomaly = self._anomaly.score_finding(finding)
            # Anomaly > 0.5 boosts by up to 0.15; low anomaly penalizes pattern_match
            if anomaly > 0.5:
                base_score = min(1.0, base_score + (anomaly - 0.5) * 0.3)
            elif anomaly < 0.1 and method == "pattern_match":
                base_score = max(0.0, base_score - 0.1)

        # 4. Penalize from FP feedback history
        if self._feedback:
            fp_key = self._make_feedback_key(finding)
            fp_rate = self._feedback.get_fp_rate(fp_key)
            # If >50% FP rate for this pattern, significantly penalize
            base_score = base_score * (1.0 - fp_rate * 0.5)

        # Clamp to [0.0, 1.0]
        score = max(0.0, min(1.0, base_score))
        level = self._score_to_level(score)

        return score, level

    def score_and_annotate(self, finding: dict) -> dict:
        """Score finding and add confidence_score + confidence_level fields.

        Adds three keys:
            confidence_score  — float 0.0–1.0
            confidence_level  — internal level string ("Critical", "High", …)
            audit_confidence  — Burp-compatible tier string ("Certain", "Firm",
                                "Tentative")

        Returns the modified finding dict.
        """
        score, level = self.score(finding)
        finding["confidence_score"] = round(score, 3)
        finding["confidence_level"] = level
        finding["audit_confidence"]  = score_to_burp_confidence(score).value
        return finding

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify_detection_method(self, finding: dict) -> str:
        """Classify how this finding was detected."""
        vuln = finding.get("vuln_type", "")
        source = finding.get("source_phase", "")

        if "blind" in vuln and "time" in vuln:
            return "time_based"
        if "blind" in vuln or "bool" in vuln:
            return "boolean_blind"
        if "oast" in vuln.lower() or "callback" in str(finding.get("finding", "")).lower():
            return "oast_callback"
        if finding.get("proof"):
            return "proof_confirmed"
        if "error" in vuln:
            return "error_based"
        if source == "passive":
            return "passive"
        return "pattern_match"

    @staticmethod
    def _score_to_level(score: float) -> str:
        """Map a numeric score to a human-readable confidence level."""
        for (lo, hi), level in CONFIDENCE_LEVELS.items():
            if lo <= score < hi:
                return level
        return "Informational"

    @staticmethod
    def _make_feedback_key(finding: dict) -> str:
        """Create a dedup-style key for feedback lookup."""
        url = finding.get("url", "")
        param = finding.get("param", finding.get("parameter", ""))
        vuln = finding.get("vuln_type", finding.get("category", ""))
        # Normalize URL to path only (strip query params for grouping)
        path = urlparse(url).path
        return f"{path}|{param}|{vuln}"
