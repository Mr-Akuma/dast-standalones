from __future__ import annotations
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)


@dataclass
class FeedbackEntry:
    """A single FP/TP marking."""
    key: str              # dedup-style key: path|param|vuln_type
    is_fp: bool           # True = false positive, False = true positive
    timestamp: float      # Unix timestamp
    analyst: str = ""     # Who marked it
    notes: str = ""       # Optional notes
    finding_summary: str = ""  # Brief finding text for context


class FeedbackStore:
    """
    Persists analyst FP/TP feedback to JSON file.
    Computes FP rates per finding pattern for confidence scoring.
    """

    def __init__(self, path: str = ".dast-feedback.json"):
        self._path = path
        self._entries: list[FeedbackEntry] = []
        self._fp_cache: dict[str, float] = {}  # key -> FP rate (cached)
        self._load()

    @staticmethod
    def make_key(finding: dict) -> str:
        """Create feedback key from finding dict."""
        url = finding.get("url", "")
        path = urlparse(url).path.rstrip("/") or "/"
        param = finding.get("param", finding.get("parameter", ""))
        vuln = finding.get("vuln_type", finding.get("category", ""))
        return f"{path}|{param}|{vuln}"

    def mark_fp(self, finding: dict, analyst: str = "", notes: str = "") -> None:
        """Mark a finding as false positive."""
        entry = FeedbackEntry(
            key=self.make_key(finding),
            is_fp=True,
            timestamp=time.time(),
            analyst=analyst,
            notes=notes,
            finding_summary=str(finding.get("finding", ""))[:200],
        )
        self._entries.append(entry)
        self._fp_cache.clear()  # Invalidate cache
        self._save()

    def mark_tp(self, finding: dict, analyst: str = "", notes: str = "") -> None:
        """Mark a finding as true positive."""
        entry = FeedbackEntry(
            key=self.make_key(finding),
            is_fp=False,
            timestamp=time.time(),
            analyst=analyst,
            notes=notes,
            finding_summary=str(finding.get("finding", ""))[:200],
        )
        self._entries.append(entry)
        self._fp_cache.clear()
        self._save()

    def get_fp_rate(self, key: str) -> float:
        """
        Get FP rate for a pattern key (0.0-1.0).
        If no feedback exists, returns 0.0 (no penalty).
        Also checks broader patterns (same vuln_type across all endpoints).
        """
        if key in self._fp_cache:
            return self._fp_cache[key]

        # Exact match
        exact = [e for e in self._entries if e.key == key]
        if exact:
            fp_count = sum(1 for e in exact if e.is_fp)
            rate = fp_count / len(exact)
            self._fp_cache[key] = rate
            return rate

        # Broader match: same vuln_type across all endpoints
        parts = key.split("|")
        if len(parts) == 3:
            vuln_type = parts[2]
            broader = [e for e in self._entries if e.key.endswith(f"|{vuln_type}")]
            if len(broader) >= 3:  # Only use if enough data
                fp_count = sum(1 for e in broader if e.is_fp)
                rate = fp_count / len(broader) * 0.5  # Half weight for broader match
                self._fp_cache[key] = rate
                return rate

        self._fp_cache[key] = 0.0
        return 0.0

    def get_stats(self) -> dict:
        """Return feedback statistics."""
        total = len(self._entries)
        fps = sum(1 for e in self._entries if e.is_fp)
        tps = total - fps
        return {"total_feedback": total, "false_positives": fps, "true_positives": tps}

    def get_entries_for_key(self, key: str) -> list[FeedbackEntry]:
        """Get all feedback entries for a pattern key."""
        return [e for e in self._entries if e.key == key]

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            data = [
                {
                    "key": e.key, "is_fp": e.is_fp, "timestamp": e.timestamp,
                    "analyst": e.analyst, "notes": e.notes,
                    "finding_summary": e.finding_summary,
                }
                for e in self._entries
            ]
            with open(self._path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.warning("[Feedback] Save failed: %s", e)

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path) as f:
                data = json.load(f)
            for d in data:
                self._entries.append(FeedbackEntry(
                    key=d["key"], is_fp=d["is_fp"], timestamp=d.get("timestamp", 0),
                    analyst=d.get("analyst", ""), notes=d.get("notes", ""),
                    finding_summary=d.get("finding_summary", ""),
                ))
            log.info("[Feedback] Loaded %d entries from %s", len(self._entries), self._path)
        except Exception as e:
            log.warning("[Feedback] Load failed: %s", e)

    def clear(self) -> None:
        self._entries.clear()
        self._fp_cache.clear()
