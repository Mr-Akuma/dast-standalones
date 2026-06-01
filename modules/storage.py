"""
Finding Storage Layer — Postgres → SQLite → In-Memory Fallback
==============================================================
Persists scan findings and scan metadata for cross-scan trending,
false positive management, and historical analysis.

Fallback chain (automatic, no configuration needed):
  1. Postgres  — full feature set, cross-process sharing
  2. SQLite    — single-process persistence, no server needed
  3. In-memory — non-persistent, functionally equivalent for the scan

Usage::

    from modules.storage import FindingStore

    store = FindingStore()               # auto-selects backend
    scan_id = store.create_scan("https://target.com")
    store.add_finding(scan_id, finding_dict)
    findings = store.get_findings(scan_id)
    trending = store.get_trending(days=30)
    store.mark_false_positive(finding_id)

All methods are thread-safe. Postgres connections use a pool (default 5).
SQLite uses WAL mode for concurrent reads.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

# Auto-load .env from project root (or any parent dir) if python-dotenv is installed.
# This means REDIS_URL / POSTGRES_DSN are picked up without any manual export.
try:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(usecwd=True), override=False)
except ImportError:
    pass

log = logging.getLogger("dast.storage")

# ── Schema DDL ────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id       TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    completed_at  TEXT,
    status        TEXT NOT NULL DEFAULT 'running',
    finding_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    scan_id           TEXT NOT NULL REFERENCES scans(scan_id),
    url               TEXT,
    method            TEXT,
    param             TEXT,
    vuln_type         TEXT,
    severity          TEXT,
    finding           TEXT,
    proof             TEXT,
    payload           TEXT,
    ts                TEXT,
    agent_id          TEXT,
    dedup_hash        TEXT,
    is_fp             INTEGER NOT NULL DEFAULT 0,
    resp_time_ms      REAL    NOT NULL DEFAULT 0.0,
    baseline_time_ms  REAL    NOT NULL DEFAULT 0.0,
    time_delta_ms     REAL    NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_dedup     ON findings(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_scans_target       ON scans(target);
"""

# Postgres-compatible DDL (TEXT → VARCHAR, INTEGER → BOOLEAN)
_DDL_PG = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id       UUID PRIMARY KEY,
    target        TEXT NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL,
    completed_at  TIMESTAMPTZ,
    status        TEXT NOT NULL DEFAULT 'running',
    finding_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id                UUID PRIMARY KEY,
    scan_id           UUID NOT NULL REFERENCES scans(scan_id),
    url               TEXT,
    method            TEXT,
    param             TEXT,
    vuln_type         TEXT,
    severity          TEXT,
    finding           TEXT,
    proof             TEXT,
    payload           TEXT,
    ts                TIMESTAMPTZ,
    agent_id          TEXT,
    dedup_hash        TEXT,
    is_fp             BOOLEAN NOT NULL DEFAULT FALSE,
    resp_time_ms      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    baseline_time_ms  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    time_delta_ms     DOUBLE PRECISION NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_dedup     ON findings(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_scans_target       ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_started      ON scans(started_at);
"""


def _dedup_hash(f: dict) -> str:
    """SHA-256 of target+vuln_type+param+first-100-chars-of-finding."""
    key = "|".join([
        (f.get("target") or ""),
        (f.get("vuln_type") or f.get("phase") or ""),
        (f.get("param") or ""),
        (f.get("finding") or "")[:100],
    ])
    return hashlib.sha256(key.encode()).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Backend implementations
# ══════════════════════════════════════════════════════════════════════════════

class _SQLiteBackend:
    """SQLite backend — single-file, no server, WAL for concurrent reads."""

    def __init__(self, path: str = "dast_findings.db"):
        self._path = path
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self):
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self):
        with self._lock:
            conn = self._connect()
            conn.executescript(_DDL)
            conn.commit()
            conn.close()

    def create_scan(self, target: str) -> str:
        scan_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO scans(scan_id,target,started_at,status) VALUES(?,?,?,'running')",
                (scan_id, target, ts),
            )
            conn.commit(); conn.close()
        return scan_id

    def complete_scan(self, scan_id: str, status: str = "complete"):
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE scans SET completed_at=?, status=?, "
                "finding_count=(SELECT COUNT(*) FROM findings WHERE scan_id=?) "
                "WHERE scan_id=?",
                (ts, status, scan_id, scan_id),
            )
            conn.commit(); conn.close()

    def add_finding(self, scan_id: str, f: dict) -> str | dict:
        fid  = str(uuid.uuid4())
        dhash = _dedup_hash(f)
        with self._lock:
            conn = self._connect()
            # Historical FP suppression: skip if same hash is a known FP
            fp_row = conn.execute(
                "SELECT id FROM findings WHERE dedup_hash=? AND is_fp=1 LIMIT 1", (dhash,)
            ).fetchone()
            if fp_row:
                conn.close()
                log.debug("[FindingStore] Suppressed known FP: dedup_hash=%s", dhash)
                return {"suppressed": True, "reason": "known_false_positive", "dedup_hash": dhash}
            # Cross-scan deduplication: skip if same hash seen before
            row = conn.execute(
                "SELECT id FROM findings WHERE dedup_hash=? LIMIT 1", (dhash,)
            ).fetchone()
            if row:
                conn.close()
                return row["id"]  # return existing id — not a new insert
            conn.execute(
                """INSERT INTO findings
                   (id,scan_id,url,method,param,vuln_type,severity,
                    finding,proof,payload,ts,agent_id,dedup_hash,
                    resp_time_ms,baseline_time_ms,time_delta_ms)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    fid, scan_id,
                    f.get("url") or f.get("target", ""),
                    f.get("method", "GET"),
                    f.get("param", ""),
                    f.get("vuln_type") or f.get("phase", ""),
                    f.get("severity", "medium"),
                    f.get("finding", ""),
                    (f.get("proof") or "")[:2000],
                    (f.get("payload") or "")[:500],
                    f.get("ts") or datetime.now(timezone.utc).isoformat(),
                    f.get("agent_id", ""),
                    dhash,
                    float(f.get("resp_time_ms") or 0.0),
                    float(f.get("baseline_time_ms") or 0.0),
                    float(f.get("time_delta_ms") or 0.0),
                ),
            )
            conn.commit(); conn.close()
        return fid

    def list_suppressed_fps(self, scan_id: str | None = None) -> dict:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT dedup_hash, COUNT(*) as count FROM findings WHERE is_fp=1 GROUP BY dedup_hash"
            ).fetchall()
            patterns = [r["dedup_hash"] for r in rows]
            result: dict[str, Any] = {
                "suppressed_count": len(patterns),
                "patterns": patterns,
            }
            if scan_id is not None:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM findings WHERE scan_id=? AND is_fp=1",
                    (scan_id,),
                ).fetchone()
                result["scan_suppressed_count"] = row["cnt"] if row else 0
            conn.close()
        return result

    def get_findings(self, scan_id: str) -> list[dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id=? AND is_fp=0 ORDER BY ts",
                (scan_id,),
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def get_trending(self, days: int = 30) -> list[dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                """SELECT vuln_type, severity, COUNT(*) as count
                   FROM findings f
                   JOIN scans s ON f.scan_id=s.scan_id
                   WHERE s.started_at >= ? AND f.is_fp=0
                   GROUP BY vuln_type, severity
                   ORDER BY count DESC""",
                (cutoff,),
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def mark_false_positive(self, finding_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "UPDATE findings SET is_fp=1 WHERE id=?", (finding_id,)
            )
            conn.commit(); conn.close()
        return cur.rowcount > 0

    def list_false_positives(self) -> list[dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM findings WHERE is_fp=1 ORDER BY ts DESC"
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> dict | None:
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id=?", (scan_id,)
            ).fetchone()
            conn.close()
        return dict(row) if row else None

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def get_dedup_hashes(self) -> dict:
        """Return all dedup hashes from DB for cache warming.
        Returns {"seen": {hash: id}, "fp": [hash, ...]}
        """
        with self._lock:
            conn = self._connect()
            seen_rows = conn.execute(
                "SELECT dedup_hash, id FROM findings WHERE is_fp=0 AND dedup_hash IS NOT NULL"
            ).fetchall()
            fp_rows = conn.execute(
                "SELECT DISTINCT dedup_hash FROM findings WHERE is_fp=1 AND dedup_hash IS NOT NULL"
            ).fetchall()
            conn.close()
        return {
            "seen": {r["dedup_hash"]: r["id"] for r in seen_rows},
            "fp":   [r["dedup_hash"] for r in fp_rows],
        }


class _PostgresBackend:
    """Postgres backend using psycopg2 with a simple connection pool."""

    def __init__(self, dsn: str, pool_size: int = 5):
        import psycopg2  # type: ignore
        from psycopg2 import pool as pg_pool  # type: ignore
        self._pool = pg_pool.ThreadedConnectionPool(1, pool_size, dsn)
        self._init_schema()

    def _get_conn(self):
        return self._pool.getconn()

    def _put_conn(self, conn):
        self._pool.putconn(conn)

    def _init_schema(self):
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                # Run each statement separately (executescript not available in psycopg2)
                for stmt in _DDL_PG.split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        cur.execute(stmt)
            conn.commit()
        finally:
            self._put_conn(conn)

    def create_scan(self, target: str) -> str:
        scan_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc)
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO scans(scan_id,target,started_at,status) VALUES(%s,%s,%s,'running')",
                    (scan_id, target, ts),
                )
            conn.commit()
        finally:
            self._put_conn(conn)
        return scan_id

    def complete_scan(self, scan_id: str, status: str = "complete"):
        ts = datetime.now(timezone.utc)
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE scans SET completed_at=%s, status=%s, "
                    "finding_count=(SELECT COUNT(*) FROM findings WHERE scan_id=%s) "
                    "WHERE scan_id=%s",
                    (ts, status, scan_id, scan_id),
                )
            conn.commit()
        finally:
            self._put_conn(conn)

    def add_finding(self, scan_id: str, f: dict) -> str | dict:
        fid   = str(uuid.uuid4())
        dhash = _dedup_hash(f)
        conn  = self._get_conn()
        try:
            with conn.cursor() as cur:
                # Historical FP suppression: skip if same hash is a known FP
                cur.execute(
                    "SELECT id FROM findings WHERE dedup_hash=%s AND is_fp=TRUE LIMIT 1", (dhash,)
                )
                fp_row = cur.fetchone()
                if fp_row:
                    log.debug("[FindingStore] Suppressed known FP: dedup_hash=%s", dhash)
                    return {"suppressed": True, "reason": "known_false_positive", "dedup_hash": dhash}
                cur.execute(
                    "SELECT id FROM findings WHERE dedup_hash=%s LIMIT 1", (dhash,)
                )
                row = cur.fetchone()
                if row:
                    return row[0]
                cur.execute(
                    """INSERT INTO findings
                       (id,scan_id,url,method,param,vuln_type,severity,
                        finding,proof,payload,ts,agent_id,dedup_hash,
                        resp_time_ms,baseline_time_ms,time_delta_ms)
                       VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        fid, scan_id,
                        f.get("url") or f.get("target", ""),
                        f.get("method", "GET"),
                        f.get("param", ""),
                        f.get("vuln_type") or f.get("phase", ""),
                        f.get("severity", "medium"),
                        f.get("finding", ""),
                        (f.get("proof") or "")[:2000],
                        (f.get("payload") or "")[:500],
                        f.get("ts") or datetime.now(timezone.utc),
                        f.get("agent_id", ""),
                        dhash,
                        float(f.get("resp_time_ms") or 0.0),
                        float(f.get("baseline_time_ms") or 0.0),
                        float(f.get("time_delta_ms") or 0.0),
                    ),
                )
            conn.commit()
        finally:
            self._put_conn(conn)
        return fid

    def list_suppressed_fps(self, scan_id: str | None = None) -> dict:
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT dedup_hash, COUNT(*) as count FROM findings WHERE is_fp=TRUE GROUP BY dedup_hash"
                )
                rows = cur.fetchall()
                patterns = [r[0] for r in rows]
                result: dict[str, Any] = {
                    "suppressed_count": len(patterns),
                    "patterns": patterns,
                }
                if scan_id is not None:
                    cur.execute(
                        "SELECT COUNT(*) FROM findings WHERE scan_id=%s AND is_fp=TRUE",
                        (scan_id,),
                    )
                    row = cur.fetchone()
                    result["scan_suppressed_count"] = row[0] if row else 0
        finally:
            self._put_conn(conn)
        return result

    def get_findings(self, scan_id: str) -> list[dict]:
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM findings WHERE scan_id=%s AND is_fp=FALSE ORDER BY ts",
                    (scan_id,),
                )
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            self._put_conn(conn)

    def get_trending(self, days: int = 30) -> list[dict]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT vuln_type, severity, COUNT(*) as count
                       FROM findings f
                       JOIN scans s ON f.scan_id=s.scan_id
                       WHERE s.started_at >= %s AND f.is_fp=FALSE
                       GROUP BY vuln_type, severity
                       ORDER BY count DESC""",
                    (cutoff,),
                )
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            self._put_conn(conn)

    def mark_false_positive(self, finding_id: str) -> bool:
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE findings SET is_fp=TRUE WHERE id=%s", (finding_id,)
                )
                affected = cur.rowcount
            conn.commit()
            return affected > 0
        finally:
            self._put_conn(conn)

    def list_false_positives(self) -> list[dict]:
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM findings WHERE is_fp=TRUE ORDER BY ts DESC"
                )
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            self._put_conn(conn)

    def get_scan(self, scan_id: str) -> dict | None:
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM scans WHERE scan_id=%s", (scan_id,))
                row = cur.fetchone()
                if not row:
                    return None
                cols = [d[0] for d in cur.description]
                return dict(zip(cols, row))
        finally:
            self._put_conn(conn)

    def list_scans(self, limit: int = 50) -> list[dict]:
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM scans ORDER BY started_at DESC LIMIT %s", (limit,)
                )
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            self._put_conn(conn)

    def get_dedup_hashes(self) -> dict:
        """Return all dedup hashes from DB for cache warming.
        Returns {"seen": {hash: id}, "fp": [hash, ...]}
        """
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT dedup_hash, id FROM findings WHERE is_fp=FALSE AND dedup_hash IS NOT NULL"
                )
                seen = {row[0]: str(row[1]) for row in cur.fetchall()}
                cur.execute(
                    "SELECT DISTINCT dedup_hash FROM findings WHERE is_fp=TRUE AND dedup_hash IS NOT NULL"
                )
                fp = [row[0] for row in cur.fetchall()]
            return {"seen": seen, "fp": fp}
        finally:
            self._put_conn(conn)


class _InMemoryBackend:
    """Non-persistent in-memory fallback. Loses data on restart."""

    def __init__(self):
        self._lock   = threading.Lock()
        self._scans:    dict[str, dict] = {}
        self._findings: list[dict]      = []
        self._dedup:    set[str]        = set()

    def create_scan(self, target: str) -> str:
        scan_id = str(uuid.uuid4())
        with self._lock:
            self._scans[scan_id] = {
                "scan_id": scan_id, "target": target,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": None, "status": "running", "finding_count": 0,
            }
        return scan_id

    def complete_scan(self, scan_id: str, status: str = "complete"):
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
                self._scans[scan_id]["status"]       = status
                self._scans[scan_id]["finding_count"] = sum(
                    1 for f in self._findings if f.get("scan_id") == scan_id
                )

    def add_finding(self, scan_id: str, f: dict) -> str | dict:
        fid   = str(uuid.uuid4())
        dhash = _dedup_hash(f)
        with self._lock:
            # Historical FP suppression: skip if same hash is a known FP
            fp_match = any(
                x.get("dedup_hash") == dhash and x.get("is_fp")
                for x in self._findings
            )
            if fp_match:
                log.debug("[FindingStore] Suppressed known FP: dedup_hash=%s", dhash)
                return {"suppressed": True, "reason": "known_false_positive", "dedup_hash": dhash}
            if dhash in self._dedup:
                existing = next(
                    (x["id"] for x in self._findings if x.get("dedup_hash") == dhash), fid
                )
                return existing
            self._dedup.add(dhash)
            self._findings.append({**f, "id": fid, "scan_id": scan_id,
                                    "dedup_hash": dhash, "is_fp": False})
        return fid

    def list_suppressed_fps(self, scan_id: str | None = None) -> dict:
        with self._lock:
            fp_hashes = list({
                f.get("dedup_hash") for f in self._findings if f.get("is_fp")
            })
            result: dict[str, Any] = {
                "suppressed_count": len(fp_hashes),
                "patterns": fp_hashes,
            }
            if scan_id is not None:
                result["scan_suppressed_count"] = sum(
                    1 for f in self._findings
                    if f.get("scan_id") == scan_id and f.get("is_fp")
                )
        return result

    def get_findings(self, scan_id: str) -> list[dict]:
        with self._lock:
            return [f for f in self._findings
                    if f.get("scan_id") == scan_id and not f.get("is_fp")]

    def get_trending(self, days: int = 30) -> list[dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            counts: dict[tuple, int] = {}
            for f in self._findings:
                if f.get("is_fp"):
                    continue
                scan = self._scans.get(f.get("scan_id", ""))
                if scan and (scan.get("started_at") or "") >= cutoff:
                    key = (f.get("vuln_type", ""), f.get("severity", ""))
                    counts[key] = counts.get(key, 0) + 1
        return [
            {"vuln_type": k[0], "severity": k[1], "count": v}
            for k, v in sorted(counts.items(), key=lambda x: -x[1])
        ]

    def mark_false_positive(self, finding_id: str) -> bool:
        with self._lock:
            for f in self._findings:
                if f.get("id") == finding_id:
                    f["is_fp"] = True
                    return True
        return False

    def list_false_positives(self) -> list[dict]:
        with self._lock:
            return [f for f in self._findings if f.get("is_fp")]

    def get_scan(self, scan_id: str) -> dict | None:
        with self._lock:
            return self._scans.get(scan_id)

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self._lock:
            scans = sorted(self._scans.values(),
                           key=lambda s: s.get("started_at", ""), reverse=True)
            return scans[:limit]

    def get_dedup_hashes(self) -> dict:
        """Return all dedup hashes from memory for cache warming."""
        with self._lock:
            seen = {
                f["dedup_hash"]: f["id"]
                for f in self._findings
                if not f.get("is_fp") and f.get("dedup_hash")
            }
            fp = list({
                f["dedup_hash"]
                for f in self._findings
                if f.get("is_fp") and f.get("dedup_hash")
            })
        return {"seen": seen, "fp": fp}


# ══════════════════════════════════════════════════════════════════════════════
# Public facade
# ══════════════════════════════════════════════════════════════════════════════

class FindingStore:
    """Persistent finding store. Auto-selects backend.

    Args:
        postgres_dsn:  Postgres DSN string (e.g. "postgresql://user:pass@host/db").
                       If None or connection fails, falls back to SQLite.
        sqlite_path:   SQLite file path. Defaults to "dast_findings.db".
                       If SQLite unavailable (unlikely), falls back to in-memory.
        pool_size:     Postgres connection pool size (default 5).
        redis_url:     Redis URL for dedup cache (e.g. "redis://localhost:6379/0").
                       Also read from REDIS_URL env var. If unavailable, all SQL
                       dedup paths continue working unchanged.
        warm_cache:    If True (default), pre-load existing DB hashes into Redis
                       on startup so dedup is instant from the first finding.
    """

    def __init__(
        self,
        postgres_dsn: str | None = None,
        sqlite_path:  str = "dast_findings.db",
        pool_size:    int = 5,
        redis_url:    str | None = None,
        warm_cache:   bool = True,
    ):
        from modules.dedup import DedupCache

        self._backend: _PostgresBackend | _SQLiteBackend | _InMemoryBackend
        self.backend_name: str

        if postgres_dsn:
            try:
                self._backend    = _PostgresBackend(postgres_dsn, pool_size)
                self.backend_name = "postgres"
                log.info("[FindingStore] Using Postgres backend")
            except Exception as exc:
                log.warning("[FindingStore] Postgres unavailable (%s) — falling back to SQLite", exc)
                self._backend    = _SQLiteBackend(sqlite_path)
                self.backend_name = "sqlite"
                log.info("[FindingStore] Using SQLite backend (%s)", sqlite_path)
        else:
            try:
                self._backend    = _SQLiteBackend(sqlite_path)
                self.backend_name = "sqlite"
                log.info("[FindingStore] Using SQLite backend (%s)", sqlite_path)
            except Exception as exc:
                log.warning("[FindingStore] SQLite unavailable (%s) — using in-memory", exc)
                self._backend    = _InMemoryBackend()
                self.backend_name = "memory"
                log.info("[FindingStore] Using in-memory backend (non-persistent)")

        # ── Redis dedup cache (optional, graceful fallback) ───────────────────
        _redis_url = redis_url or os.getenv("REDIS_URL")
        self._cache = DedupCache(_redis_url) if _redis_url else DedupCache.__new__(DedupCache)
        if not _redis_url:
            # No URL provided — create a no-op cache (available=False)
            self._cache._available = False
            self._cache._r = None

        if self._cache.available and warm_cache:
            self.warm_dedup_cache()

    # ── Dedup cache public API ────────────────────────────────────────────────

    def warm_dedup_cache(self) -> None:
        """Pre-load all existing DB dedup hashes into Redis. Called automatically
        on __init__ when Redis is available. Safe to call again after bulk imports."""
        if not self._cache.available:
            return
        data = self._backend.get_dedup_hashes()
        self._cache.warm(data["seen"], data["fp"])

    def cache_stats(self) -> dict:
        """Return Redis cache statistics (seen_count, fp_count, available)."""
        return self._cache.stats()

    # ── Core methods (add_finding and mark_false_positive intercept Redis) ────

    def add_finding(self, scan_id: str, finding: dict) -> str | dict:
        """Persist one finding. Returns finding id (UUID) or suppression dict.
        Deduplicates automatically — checks Redis first, falls back to SQL."""
        dhash = _dedup_hash(finding)

        if self._cache.available:
            # Fast path 1: known false positive
            if self._cache.is_fp(dhash):
                log.debug("[FindingStore] Redis: suppressed known FP %s", dhash)
                return {"suppressed": True, "reason": "known_false_positive", "dedup_hash": dhash}
            # Fast path 2: already seen (duplicate)
            existing_id = self._cache.get_seen_id(dhash)
            if existing_id:
                log.debug("[FindingStore] Redis: dedup hit for %s", dhash)
                return existing_id

        # Cache miss or Redis unavailable — hit the DB
        result = self._backend.add_finding(scan_id, finding)

        # Update cache with DB result so future checks skip SQL
        if self._cache.available:
            if isinstance(result, dict) and result.get("suppressed"):
                self._cache.mark_fp(dhash)
            elif isinstance(result, str):
                self._cache.mark_seen(dhash, result)

        return result

    def mark_false_positive(self, finding_id: str) -> bool:
        """Mark a finding as a false positive. Returns True if found.
        Also invalidates the Redis dedup cache entry so future matches are suppressed."""
        # Resolve hash before marking (reverse lookup from Redis or skip)
        dhash = self._cache.get_hash_for_id(finding_id) if self._cache.available else None

        result = self._backend.mark_false_positive(finding_id)

        if result and dhash and self._cache.available:
            self._cache.mark_fp(dhash)

        return result

    # ── Delegate remaining methods to backend ─────────────────────────────────

    def create_scan(self, target: str) -> str:
        """Create a new scan record. Returns scan_id (UUID string)."""
        return self._backend.create_scan(target)

    def complete_scan(self, scan_id: str, status: str = "complete") -> None:
        """Mark a scan as complete (or 'stopped', 'error')."""
        self._backend.complete_scan(scan_id, status)

    def list_suppressed_fps(self, scan_id: str | None = None) -> dict:
        """Return known FP dedup_hashes and suppression counts."""
        return self._backend.list_suppressed_fps(scan_id)

    def get_findings(self, scan_id: str) -> list[dict]:
        """Return all non-FP findings for a scan."""
        return self._backend.get_findings(scan_id)

    def get_trending(self, days: int = 30) -> list[dict]:
        """Return vuln_type/severity counts across all scans in the past N days."""
        return self._backend.get_trending(days)

    def list_false_positives(self) -> list[dict]:
        """Return all findings marked as false positives."""
        return self._backend.list_false_positives()

    def get_scan(self, scan_id: str) -> dict | None:
        """Return scan metadata dict or None."""
        return self._backend.get_scan(scan_id)

    def list_scans(self, limit: int = 50) -> list[dict]:
        """Return recent scans, newest first."""
        return self._backend.list_scans(limit)

    def __repr__(self) -> str:
        return f"FindingStore(backend={self.backend_name!r}, cache={self._cache.stats()})"


# ── Singleton ─────────────────────────────────────────────────────────────────

_store_instance: FindingStore | None = None
_store_lock = threading.Lock()


def get_store(
    postgres_dsn: str | None = None,
    redis_url:    str | None = None,
    **kwargs,
) -> FindingStore:
    """Return the process-wide singleton FindingStore.

    Redis URL is also auto-detected from REDIS_URL environment variable.
    """
    global _store_instance
    if _store_instance is None:
        with _store_lock:
            if _store_instance is None:
                _store_instance = FindingStore(
                    postgres_dsn=postgres_dsn,
                    redis_url=redis_url,
                    **kwargs,
                )
    return _store_instance
