from __future__ import annotations
import logging
from typing import Any

log = logging.getLogger(__name__)


class AnomalyScorer:
    """
    Scores response anomaly relative to per-endpoint baseline.
    Higher score = more anomalous = higher confidence the finding is real.
    """

    def __init__(self, baseline=None):
        """
        Args:
            baseline: EndpointBaseline instance (from modules.baseline)
                     If None, all scores are 0.0 (no baseline available).
        """
        self._baseline = baseline

    def score(self, url: str, status_code: int, content_length: int,
              response_time_ms: float, sigma: float = 2.0) -> float:
        """
        Score how anomalous this response is.

        Returns:
            float 0.0-1.0 where:
            - 0.0 = within normal range (or no baseline)
            - 0.5 = mildly anomalous (1-2 sigma deviation)
            - 0.8 = highly anomalous (3-4 sigma deviation)
            - 1.0 = extreme anomaly (>6 sigma deviation)
        """
        if self._baseline is None:
            return 0.0

        is_anomaly, deviation_score = self._baseline.is_anomalous(
            url, status_code, content_length, response_time_ms, sigma)
        return deviation_score

    def score_finding(self, finding: dict) -> float:
        """
        Score a finding dict. Extracts url, status_code, content_length, response_time
        from finding fields. Finding may have keys like:
        - 'url', 'status_code', 'resp_time_ms', 'content_length'
        - or nested in different formats

        Returns float 0.0-1.0
        """
        url = finding.get("url", "")
        status = finding.get("status_code", 200)
        content_len = finding.get("content_length", 0)
        resp_time = finding.get("resp_time_ms", 0.0)

        return self.score(url, status, content_len, resp_time)

    def classify_anomaly(self, score: float) -> str:
        """
        Classify anomaly score into human-readable level.
        Returns: 'none', 'low', 'medium', 'high', 'extreme'
        """
        if score < 0.1:
            return "none"
        if score < 0.3:
            return "low"
        if score < 0.6:
            return "medium"
        if score < 0.8:
            return "high"
        return "extreme"
