"""
Evidence Store — captures full HTTP request/response pairs for every finding.
Each finding references an evidence_id for audit/report purposes.

Persistence: records are written to both the in-memory dict (for fast get()
calls during an active scan) AND to Tier 1 SQLite via db_manager on record().
"""
from __future__ import annotations
import logging
import threading
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

log = logging.getLogger("dast.evidence")


@dataclass
class HttpEvidence:
    id: str
    url: str
    method: str
    req_headers: dict
    req_body: str
    status_code: int
    resp_headers: dict
    resp_body: str          # first 10000 chars
    resp_time_ms: float
    ts: str
    vuln_type: str          # "sqli", "xss", "lfi", etc.
    payload: str            # the specific payload that triggered the finding
    parameter: str          # which parameter was fuzzed
    source: str = "active"  # "active" | "passive" | "proxy"
    scan_id: str = ""       # links evidence to a specific scan session
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceStore:
    def __init__(self):
        self._lock    = threading.Lock()
        self._store: dict[str, HttpEvidence] = {}

    def record(
        self,
        url: str,
        method: str,
        req_headers: dict,
        req_body: str,
        status_code: int,
        resp_headers: dict,
        resp_body: str,
        resp_time_ms: float,
        vuln_type: str,
        payload: str,
        parameter: str,
        source: str = "active",
        scan_id: str = "",
        notes: str = "",
    ) -> str:
        eid = f"ev_{uuid.uuid4().hex[:10]}"
        ev  = HttpEvidence(
            id            = eid,
            url           = url,
            method        = method,
            req_headers   = req_headers,
            req_body      = req_body,
            status_code   = status_code,
            resp_headers  = resp_headers,
            resp_body     = resp_body[:10000],
            resp_time_ms  = round(resp_time_ms, 1),
            ts            = datetime.now(timezone.utc).isoformat(),
            vuln_type     = vuln_type,
            payload       = payload,
            parameter     = parameter,
            source        = source,
            scan_id       = scan_id,
            notes         = notes,
        )
        with self._lock:
            self._store[eid] = ev
        # ── Tier 1 persistence ────────────────────────────────────────────
        try:
            from modules.db_manager import db as _db
            _db.store_evidence(
                evidence_id = eid,
                scan_id     = scan_id or "",
                finding_id  = None,  # linked later when finding is written
                data        = {
                    "ts":          ev.ts,
                    "url":         url,
                    "method":      method,
                    "request":     {"headers": req_headers, "body": req_body},
                    "status_code": status_code,
                    "response":    {"headers": resp_headers, "body": resp_body[:32768]},
                    "resp_time_ms": resp_time_ms,
                    "vuln_type":   vuln_type,
                    "payload":     payload,
                    "parameter":   parameter,
                },
            )
        except Exception as _e:
            log.debug("[Evidence] DB write skipped: %s", _e)
        return eid

    def get(self, eid: str) -> Optional[HttpEvidence]:
        """Return from in-memory cache first; fall back to SQLite."""
        ev = self._store.get(eid)
        if ev:
            return ev
        # Fallback: read from Tier 1 SQLite
        try:
            from modules.db_manager import db as _db
            row = _db.get_evidence(eid)
            if row:
                return HttpEvidence(
                    id           = row["evidence_id"],
                    url          = row.get("url", ""),
                    method       = row.get("method", "GET"),
                    req_headers  = row.get("req_headers") or {},
                    req_body     = row.get("req_body", ""),
                    status_code  = row.get("status_code", 0),
                    resp_headers = row.get("resp_headers") or {},
                    resp_body    = row.get("resp_body", ""),
                    resp_time_ms = row.get("resp_time_ms", 0.0),
                    ts           = row.get("ts", ""),
                    vuln_type    = row.get("vuln_type", ""),
                    payload      = row.get("payload", ""),
                    parameter    = row.get("parameter", ""),
                    scan_id      = row.get("scan_id", ""),
                )
        except Exception:
            pass
        return None

    def all(self) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in self._store.values()]

    def clear(self):
        with self._lock:
            self._store.clear()


# Global store instance
evidence_store = EvidenceStore()
