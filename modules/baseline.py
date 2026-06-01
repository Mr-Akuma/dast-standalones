"""Endpoint baseline capture for false-positive reduction.

Records per-endpoint response characteristics during the passive crawl phase
(before fuzzing). The anomaly scorer uses this data to detect anomalous
responses after payload injection.
"""
from __future__ import annotations

import math
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class EndpointStats:
    """Statistics for a single endpoint."""

    url: str
    status_codes: list[int] = field(default_factory=list)
    content_lengths: list[int] = field(default_factory=list)
    response_times: list[float] = field(default_factory=list)  # milliseconds

    @property
    def sample_count(self) -> int:
        return len(self.response_times)

    def status_code_mode(self) -> int:
        """Most common status code. Returns 0 if no samples."""
        if not self.status_codes:
            return 0
        return Counter(self.status_codes).most_common(1)[0][0]

    def content_length_mean(self) -> float:
        if not self.content_lengths:
            return 0.0
        return sum(self.content_lengths) / len(self.content_lengths)

    def content_length_stddev(self) -> float:
        if len(self.content_lengths) < 2:
            return 0.0
        mean = self.content_length_mean()
        variance = sum((x - mean) ** 2 for x in self.content_lengths) / len(self.content_lengths)
        return math.sqrt(variance)

    def response_time_mean(self) -> float:
        if not self.response_times:
            return 0.0
        return sum(self.response_times) / len(self.response_times)

    def response_time_stddev(self) -> float:
        if len(self.response_times) < 2:
            return 0.0
        mean = self.response_time_mean()
        variance = sum((x - mean) ** 2 for x in self.response_times) / len(self.response_times)
        return math.sqrt(variance)

    def response_time_p95(self) -> float:
        """95th percentile response time."""
        if not self.response_times:
            return 0.0
        sorted_times = sorted(self.response_times)
        idx = int(0.95 * len(sorted_times))
        idx = min(idx, len(sorted_times) - 1)
        return sorted_times[idx]

    def is_anomalous(
        self,
        status_code: int,
        content_length: int,
        response_time: float,
        sigma: float = 2.0,
    ) -> tuple[bool, float]:
        """Check if a response deviates from baseline.

        Returns:
            (is_anomaly, deviation_score) where deviation_score is 0.0-1.0.
        """
        if self.sample_count < 2:
            return False, 0.0

        z_scores: list[float] = []

        # Content length z-score
        cl_std = self.content_length_stddev()
        if cl_std > 0:
            cl_z = abs(content_length - self.content_length_mean()) / cl_std
        else:
            cl_z = 0.0 if content_length == self.content_length_mean() else float(sigma + 1)
        z_scores.append(cl_z)

        # Response time z-score
        rt_std = self.response_time_stddev()
        if rt_std > 0:
            rt_z = abs(response_time - self.response_time_mean()) / rt_std
        else:
            rt_z = 0.0 if response_time == self.response_time_mean() else float(sigma + 1)
        z_scores.append(rt_z)

        # Status code check: mode mismatch counts as anomalous signal
        status_anomaly = status_code != self.status_code_mode()

        max_z = max(z_scores)
        deviation_score = min(max_z / 6.0, 1.0)
        is_anomaly = max_z > sigma or status_anomaly

        return is_anomaly, deviation_score


class EndpointBaseline:
    """Collects and stores baseline response characteristics per endpoint."""

    def __init__(self) -> None:
        self._endpoints: dict[str, EndpointStats] = {}
        self._locked: bool = False

    def record(
        self,
        url: str,
        status_code: int,
        content_length: int,
        response_time_ms: float,
    ) -> None:
        """Record a response observation during crawl. No-op if locked."""
        if self._locked:
            return
        if url not in self._endpoints:
            self._endpoints[url] = EndpointStats(url=url)
        stats = self._endpoints[url]
        stats.status_codes.append(status_code)
        stats.content_lengths.append(content_length)
        stats.response_times.append(response_time_ms)

    def lock(self) -> None:
        """Lock baseline -- called after crawl phase ends, before fuzzing."""
        self._locked = True
        total = sum(s.sample_count for s in self._endpoints.values())
        log.info(
            "Baseline locked: %d endpoints, %d total samples",
            len(self._endpoints),
            total,
        )

    def get_stats(self, url: str) -> EndpointStats | None:
        """Get baseline stats for a URL."""
        return self._endpoints.get(url)

    def is_anomalous(
        self,
        url: str,
        status_code: int,
        content_length: int,
        response_time_ms: float,
        sigma: float = 2.0,
    ) -> tuple[bool, float]:
        """Check if a response deviates >sigma from baseline.

        Returns:
            (is_anomaly, deviation_score) where deviation_score is 0.0-1.0.
            If no baseline exists for the URL, returns (False, 0.0).
        """
        stats = self._endpoints.get(url)
        if stats is None:
            return False, 0.0
        return stats.is_anomalous(status_code, content_length, response_time_ms, sigma)

    def summary(self) -> dict:
        """Return summary: {total_endpoints, total_samples, locked}."""
        return {
            "total_endpoints": len(self._endpoints),
            "total_samples": sum(s.sample_count for s in self._endpoints.values()),
            "locked": self._locked,
        }

    def export(self) -> dict:
        """Export all baseline data as JSON-serializable dict for persistence."""
        return {
            "locked": self._locked,
            "endpoints": {
                url: {
                    "url": s.url,
                    "status_codes": s.status_codes,
                    "content_lengths": s.content_lengths,
                    "response_times": s.response_times,
                }
                for url, s in self._endpoints.items()
            },
        }

    @classmethod
    def from_export(cls, data: dict) -> EndpointBaseline:
        """Reconstruct from exported dict."""
        baseline = cls()
        baseline._locked = data.get("locked", False)
        for url, ep in data.get("endpoints", {}).items():
            stats = EndpointStats(
                url=ep["url"],
                status_codes=ep.get("status_codes", []),
                content_lengths=ep.get("content_lengths", []),
                response_times=ep.get("response_times", []),
            )
            baseline._endpoints[url] = stats
        return baseline
