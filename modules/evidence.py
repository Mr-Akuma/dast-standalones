"""
Evidence Store — captures full HTTP request/response pairs for every finding.
Each finding references an evidence_id for audit/report purposes.
"""
from __future__ import annotations
import threading
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class HttpEvidence:
    id: str
    url: str
    method: str
    req_headers: dict
    req_body: str
    status_code: int
    resp_headers: dict
    resp_body: str          # first 4096 chars
    resp_time_ms: float
    ts: str
    vuln_type: str          # "sqli", "xss", "lfi", etc.
    payload: str            # the specific payload that triggered the finding
    parameter: str          # which parameter was fuzzed
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
            resp_body     = resp_body[:4096],
            resp_time_ms  = round(resp_time_ms, 1),
            ts            = datetime.now(timezone.utc).isoformat(),
            vuln_type     = vuln_type,
            payload       = payload,
            parameter     = parameter,
            notes         = notes,
        )
        with self._lock:
            self._store[eid] = ev
        return eid

    def get(self, eid: str) -> Optional[HttpEvidence]:
        return self._store.get(eid)

    def all(self) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in self._store.values()]

    def clear(self):
        with self._lock:
            self._store.clear()


# Global store instance
evidence_store = EvidenceStore()
