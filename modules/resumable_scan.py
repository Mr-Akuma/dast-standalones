"""Persistent resumable scan queue state."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


class ResumableScanStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else Path.home() / ".dast" / "resume_state.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def start_scan(self, scan_id: str, target: str, surfaces: Iterable[str]) -> dict:
        unique = list(dict.fromkeys(str(s) for s in surfaces if str(s)))
        state = {
            "scan_id": scan_id,
            "target": target,
            "created_at": self._now(),
            "updated_at": self._now(),
            "pending": unique,
            "done": [],
            "skipped": [],
            "coverage": {"total": len(unique), "done": 0, "skipped": 0, "pending": len(unique)},
        }
        data = self._read_all()
        data[scan_id] = state
        self._write_all(data)
        return state

    def load(self, scan_id: str) -> dict:
        return self._read_all().get(scan_id, {})

    def mark_done(self, scan_id: str, surface: str) -> dict:
        return self._move(scan_id, surface, "done")

    def mark_skipped(self, scan_id: str, surface: str, reason: str = "") -> dict:
        state = self._move(scan_id, surface, "skipped")
        if reason:
            state.setdefault("skip_reasons", {})[surface] = reason
            self._save_state(state)
        return state

    def next_batch(self, scan_id: str, limit: int = 25) -> list[str]:
        state = self.load(scan_id)
        return list(state.get("pending", []))[: max(0, int(limit))]

    def _move(self, scan_id: str, surface: str, bucket: str) -> dict:
        state = self.load(scan_id)
        if not state:
            raise KeyError(f"unknown scan_id: {scan_id}")
        surface = str(surface)
        if surface in state.get("pending", []):
            state["pending"].remove(surface)
        if surface not in state.setdefault(bucket, []):
            state[bucket].append(surface)
        state["updated_at"] = self._now()
        self._refresh_coverage(state)
        self._save_state(state)
        return state

    def _save_state(self, state: dict) -> None:
        self._refresh_coverage(state)
        data = self._read_all()
        data[state["scan_id"]] = state
        self._write_all(data)

    @staticmethod
    def _refresh_coverage(state: dict) -> None:
        total = len(state.get("pending", [])) + len(state.get("done", [])) + len(state.get("skipped", []))
        state["coverage"] = {
            "total": total,
            "done": len(state.get("done", [])),
            "skipped": len(state.get("skipped", [])),
            "pending": len(state.get("pending", [])),
        }

    def _read_all(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _write_all(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
