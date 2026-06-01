"""
DAST Multi-Database Manager
============================
Three-tier storage architecture:

  Tier 1 — PostgreSQL (prod) or SQLite (dev/local)
            Selected via DATABASE_URL env var.
            PostgreSQL: set DATABASE_URL=postgresql://user:pass@host:5432/dbname
            SQLite fallback: ~/.dast/dast_master.db (when DATABASE_URL unset)
            scans / findings / evidence / scan_metrics / schedules / kv

  Tier 2 — Redis (optional, performance) set REDIS_URL to enable
            Dedup hash cache, agent context (TTL), rate limiting.
            Graceful fallback to SQL / in-memory when Redis unavailable.

  Tier 3 — JSON File Store              ~/.dast/data/
            Scan profiles, baseline snapshots, custom wordlists.
            Human-readable, diffable, zero DB overhead.

Usage:
    from modules.db_manager import db
    db.start_scan(scan_id, target)
    db.write_finding(scan_id, finding_dict)
    db.record_metric(scan_id, phase, pages=10, payloads=100)
    db.complete_scan(scan_id, status="completed")
    history = db.get_scan_history(limit=20)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("dast.db")

# ── Paths ──────────────────────────────────────────────────────────────────────

_BASE_DIR  = Path.home() / ".dast"
_DB_PATH   = _BASE_DIR / "dast_master.db"
_DATA_DIR  = _BASE_DIR / "data"
_PROFILES_DIR = _DATA_DIR / "profiles"
_BASELINES_DIR = _DATA_DIR / "baselines"

# ── SQLite schema ──────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

-- ── Tier 1a: Master scan records ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    status          TEXT DEFAULT 'running',   -- running|completed|stopped|failed
    profile         TEXT DEFAULT 'default',
    finding_count   INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    pages_crawled   INTEGER DEFAULT 0,
    payloads_sent   INTEGER DEFAULT 0,
    surfaces_found  INTEGER DEFAULT 0,
    duration_sec    REAL,
    summary         TEXT,                     -- human-readable "2 critical, 5 high"
    engine_meta     TEXT                      -- JSON: crawler config, auth mode, etc.
);

-- ── Tier 1b: Individual findings (one row per finding) ────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    agent           TEXT,
    phase           TEXT,
    icon            TEXT,
    vuln_type       TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    finding         TEXT NOT NULL,
    target          TEXT,
    url             TEXT,
    param           TEXT,
    payload         TEXT,
    evidence_id     TEXT,
    owasp           TEXT,
    cwe             TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    remediation     TEXT,
    dedup_hash      TEXT,
    is_false_positive INTEGER DEFAULT 0,
    proof           TEXT,
    proof_data      TEXT,
    extra           TEXT                      -- JSON: any extra fields
);

CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type    ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_dedup   ON findings(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_findings_fp      ON findings(is_false_positive);

-- ── Tier 1c: Evidence (HTTP request/response pairs) ───────────────────────────
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id     TEXT PRIMARY KEY,
    scan_id         TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id      TEXT REFERENCES findings(finding_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    url             TEXT,
    method          TEXT,
    req_headers     TEXT,
    req_body        TEXT,
    status_code     INTEGER,
    resp_headers    TEXT,
    resp_body       TEXT,                     -- truncated to 32 KB
    resp_time_ms    REAL,
    vuln_type       TEXT,
    payload         TEXT,
    parameter       TEXT
);

CREATE INDEX IF NOT EXISTS idx_evidence_scan    ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

-- ── Tier 1d: Time-series scan metrics (one row per phase checkpoint) ──────────
CREATE TABLE IF NOT EXISTS scan_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    phase           TEXT,
    pages_crawled   INTEGER DEFAULT 0,
    surfaces_found  INTEGER DEFAULT 0,
    payloads_sent   INTEGER DEFAULT 0,
    findings_count  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    elapsed_sec     REAL
);

CREATE INDEX IF NOT EXISTS idx_metrics_scan ON scan_metrics(scan_id);
CREATE INDEX IF NOT EXISTS idx_metrics_ts   ON scan_metrics(ts);

-- ── Tier 1e: KV store (config, cached data, preferences) ─────────────────────
CREATE TABLE IF NOT EXISTS kv (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    expires_at  TEXT                          -- NULL = never expires
);

-- ── Tier 1f: Scheduled scans ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schedules (
    id               TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    label            TEXT,
    interval_minutes INTEGER NOT NULL,
    profile          TEXT DEFAULT 'default',
    enabled          INTEGER DEFAULT 1,
    last_run         TEXT,
    next_run         TEXT,
    created_at       TEXT
);

-- ── Tier 1g: Dedup cache (SQLite fallback when Redis unavailable) ─────────────
CREATE TABLE IF NOT EXISTS dedup_cache (
    dedup_hash  TEXT PRIMARY KEY,
    finding_id  TEXT,
    scan_id     TEXT,
    first_seen  TEXT NOT NULL,
    is_fp       INTEGER DEFAULT 0            -- 1 = confirmed false positive
);

-- ── Tier 1h: Raw requests — every HTTP request sent (payload + full response) ──
-- Stores ALL payloads fired during fuzzing, intruder, crawler, and manual replay.
-- Enables replay: pick any row and re-fire it via /api/replay/<request_id>.
CREATE TABLE IF NOT EXISTS raw_requests (
    request_id      TEXT PRIMARY KEY,
    scan_id         TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'fuzzer',  -- fuzzer|intruder|crawler|replay|manual
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    req_headers     TEXT,                    -- JSON object
    req_body        TEXT,
    payload         TEXT,                    -- the injected value
    parameter       TEXT,                    -- which param was fuzzed
    vuln_type       TEXT,                    -- sqli|xss|lfi|...
    status_code     INTEGER,
    resp_headers    TEXT,                    -- JSON object
    resp_body       TEXT,                    -- truncated to 8 KB
    resp_time_ms    REAL,
    content_length  INTEGER,
    is_baseline     INTEGER DEFAULT 0,       -- 1 = no payload, baseline request
    is_finding      INTEGER DEFAULT 0,       -- 1 = triggered a confirmed finding
    finding_id      TEXT,                    -- populated when is_finding=1
    grep_matches    TEXT,                    -- JSON array of matched strings
    baseline_diff   INTEGER DEFAULT 0        -- resp length delta vs baseline
);

CREATE INDEX IF NOT EXISTS idx_rawreq_scan     ON raw_requests(scan_id);
CREATE INDEX IF NOT EXISTS idx_rawreq_url      ON raw_requests(url);
CREATE INDEX IF NOT EXISTS idx_rawreq_source   ON raw_requests(source);
CREATE INDEX IF NOT EXISTS idx_rawreq_finding  ON raw_requests(is_finding);
CREATE INDEX IF NOT EXISTS idx_rawreq_vuln     ON raw_requests(vuln_type);
CREATE INDEX IF NOT EXISTS idx_rawreq_status   ON raw_requests(status_code);

-- ── Tier 1i: Payload library — list metadata ─────────────────────────────────
CREATE TABLE IF NOT EXISTS payload_library (
    name        TEXT PRIMARY KEY,
    category    TEXT NOT NULL DEFAULT 'custom',
    description TEXT,
    count       INTEGER DEFAULT 0,           -- maintained by triggers below
    source      TEXT DEFAULT 'builtin',      -- builtin|custom|imported
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_paylib_category ON payload_library(category);
CREATE INDEX IF NOT EXISTS idx_paylib_source   ON payload_library(source);

-- ── Tier 1j: Individual payloads (one row per payload string) ─────────────────
-- Replaces JSON-blob storage: every payload queryable by SQL, sortable by
-- effectiveness (hit_count), filterable by category/source/tag.
CREATE TABLE IF NOT EXISTS payloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    list_name   TEXT NOT NULL REFERENCES payload_library(name) ON DELETE CASCADE,
    payload     TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'custom',
    tags        TEXT NOT NULL DEFAULT '[]',  -- JSON array of tag strings
    hit_count   INTEGER NOT NULL DEFAULT 0,  -- incremented when payload triggers a finding
    last_used   TEXT,
    created_at  TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'builtin'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payloads_uniq     ON payloads(list_name, payload);
CREATE INDEX IF NOT EXISTS        idx_payloads_list     ON payloads(list_name);
CREATE INDEX IF NOT EXISTS        idx_payloads_category ON payloads(category);
CREATE INDEX IF NOT EXISTS        idx_payloads_hits     ON payloads(hit_count DESC);
CREATE INDEX IF NOT EXISTS        idx_payloads_source   ON payloads(source);

-- FTS5 virtual table for sub-millisecond full-text search across all payloads
CREATE VIRTUAL TABLE IF NOT EXISTS payloads_fts USING fts5(
    payload, tags,
    content=payloads,
    content_rowid=id,
    tokenize='unicode61'
);

-- Triggers: keep FTS index in sync automatically
CREATE TRIGGER IF NOT EXISTS payloads_ai AFTER INSERT ON payloads BEGIN
    INSERT INTO payloads_fts(rowid, payload, tags)
    VALUES (new.id, new.payload, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS payloads_ad AFTER DELETE ON payloads BEGIN
    INSERT INTO payloads_fts(payloads_fts, rowid, payload, tags)
    VALUES ('delete', old.id, old.payload, old.tags);
END;

CREATE TRIGGER IF NOT EXISTS payloads_au AFTER UPDATE OF payload, tags ON payloads BEGIN
    INSERT INTO payloads_fts(payloads_fts, rowid, payload, tags)
    VALUES ('delete', old.id, old.payload, old.tags);
    INSERT INTO payloads_fts(rowid, payload, tags)
    VALUES (new.id, new.payload, new.tags);
END;

-- Triggers: keep payload_library.count accurate
CREATE TRIGGER IF NOT EXISTS payload_count_ai AFTER INSERT ON payloads BEGIN
    UPDATE payload_library SET count = count + 1, updated_at = datetime('now')
    WHERE name = new.list_name;
END;

CREATE TRIGGER IF NOT EXISTS payload_count_ad AFTER DELETE ON payloads BEGIN
    UPDATE payload_library SET count = count - 1, updated_at = datetime('now')
    WHERE name = old.list_name;
END;

-- ── Gap 1: Finding lifecycle / triage state ───────────────────────────────────
CREATE TABLE IF NOT EXISTS finding_comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    author      TEXT NOT NULL DEFAULT 'system',
    body        TEXT NOT NULL,
    ts          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fc_finding ON finding_comments(finding_id);

-- ── Gap 3: Scan coverage tracking ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tested_endpoints (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    method       TEXT NOT NULL DEFAULT 'GET',
    phases       TEXT NOT NULL DEFAULT '[]',
    first_tested TEXT NOT NULL,
    last_tested  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_te_uniq ON tested_endpoints(scan_id, url, method);
CREATE INDEX IF NOT EXISTS idx_te_scan ON tested_endpoints(scan_id);

-- ── Gap 4: Audit trail ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  TEXT,
    actor    TEXT NOT NULL DEFAULT 'system',
    ip       TEXT,
    action   TEXT NOT NULL,
    detail   TEXT,
    ts       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_scan   ON scan_audit_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON scan_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON scan_audit_log(ts);
"""

_MIGRATE_SQL = [
    # Add columns that older versions of the scans table may be missing
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS profile TEXT DEFAULT 'default'",
    # raw_requests and payload_library are new — their CREATE IF NOT EXISTS handles it
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS critical_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS high_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS medium_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS low_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS info_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS pages_crawled INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS payloads_sent INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS surfaces_found INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS duration_sec REAL",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS engine_meta TEXT",
    # Gap 1 — finding lifecycle columns (try/except in _ensure_init handles duplicates)
    "ALTER TABLE findings ADD COLUMN status TEXT DEFAULT 'open'",
    "ALTER TABLE findings ADD COLUMN assignee TEXT",
    "ALTER TABLE findings ADD COLUMN notes TEXT",
    "ALTER TABLE findings ADD COLUMN resolved_at TEXT",
    "ALTER TABLE findings ADD COLUMN retested_at TEXT",
    "ALTER TABLE findings ADD COLUMN retest_status TEXT",
    # storage.py schema includes these timing columns; add them to pre-existing DBs
    "ALTER TABLE findings ADD COLUMN resp_time_ms REAL DEFAULT 0.0",
    "ALTER TABLE findings ADD COLUMN baseline_time_ms REAL DEFAULT 0.0",
    "ALTER TABLE findings ADD COLUMN time_delta_ms REAL DEFAULT 0.0",
]


# ── PostgreSQL schema (used when DATABASE_URL is set) ─────────────────────────

_PG_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    status          TEXT DEFAULT 'running',
    profile         TEXT DEFAULT 'default',
    finding_count   INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    pages_crawled   INTEGER DEFAULT 0,
    payloads_sent   INTEGER DEFAULT 0,
    surfaces_found  INTEGER DEFAULT 0,
    duration_sec    DOUBLE PRECISION,
    summary         TEXT,
    engine_meta     TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    agent           TEXT,
    phase           TEXT,
    icon            TEXT,
    vuln_type       TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    finding         TEXT NOT NULL,
    target          TEXT,
    url             TEXT,
    param           TEXT,
    payload         TEXT,
    evidence_id     TEXT,
    owasp           TEXT,
    cwe             TEXT,
    cvss_score      DOUBLE PRECISION,
    cvss_vector     TEXT,
    remediation     TEXT,
    dedup_hash      TEXT,
    is_false_positive INTEGER DEFAULT 0,
    proof           TEXT,
    proof_data      TEXT,
    extra           TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type    ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_dedup   ON findings(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_findings_fp      ON findings(is_false_positive);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id     TEXT PRIMARY KEY,
    scan_id         TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id      TEXT REFERENCES findings(finding_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    url             TEXT,
    method          TEXT,
    req_headers     TEXT,
    req_body        TEXT,
    status_code     INTEGER,
    resp_headers    TEXT,
    resp_body       TEXT,
    resp_time_ms    DOUBLE PRECISION,
    vuln_type       TEXT,
    payload         TEXT,
    parameter       TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_scan    ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE TABLE IF NOT EXISTS scan_metrics (
    id              SERIAL PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    phase           TEXT,
    pages_crawled   INTEGER DEFAULT 0,
    surfaces_found  INTEGER DEFAULT 0,
    payloads_sent   INTEGER DEFAULT 0,
    findings_count  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    elapsed_sec     DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_metrics_scan ON scan_metrics(scan_id);
CREATE INDEX IF NOT EXISTS idx_metrics_ts   ON scan_metrics(ts);
CREATE TABLE IF NOT EXISTS kv (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    expires_at  TEXT
);
CREATE TABLE IF NOT EXISTS schedules (
    id               TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    label            TEXT,
    interval_minutes INTEGER NOT NULL,
    profile          TEXT DEFAULT 'default',
    enabled          INTEGER DEFAULT 1,
    last_run         TEXT,
    next_run         TEXT,
    created_at       TEXT
);
CREATE TABLE IF NOT EXISTS dedup_cache (
    dedup_hash  TEXT PRIMARY KEY,
    finding_id  TEXT,
    scan_id     TEXT,
    first_seen  TEXT NOT NULL,
    is_fp       INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS raw_requests (
    request_id      TEXT PRIMARY KEY,
    scan_id         TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
    ts              TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'fuzzer',
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    req_headers     TEXT,
    req_body        TEXT,
    payload         TEXT,
    parameter       TEXT,
    vuln_type       TEXT,
    status_code     INTEGER,
    resp_headers    TEXT,
    resp_body       TEXT,
    resp_time_ms    DOUBLE PRECISION,
    content_length  INTEGER,
    is_baseline     INTEGER DEFAULT 0,
    is_finding      INTEGER DEFAULT 0,
    finding_id      TEXT,
    grep_matches    TEXT,
    baseline_diff   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rawreq_scan     ON raw_requests(scan_id);
CREATE INDEX IF NOT EXISTS idx_rawreq_url      ON raw_requests(url);
CREATE INDEX IF NOT EXISTS idx_rawreq_source   ON raw_requests(source);
CREATE INDEX IF NOT EXISTS idx_rawreq_finding  ON raw_requests(is_finding);
CREATE INDEX IF NOT EXISTS idx_rawreq_vuln     ON raw_requests(vuln_type);
CREATE INDEX IF NOT EXISTS idx_rawreq_status   ON raw_requests(status_code);
CREATE TABLE IF NOT EXISTS payload_library (
    name        TEXT PRIMARY KEY,
    category    TEXT NOT NULL DEFAULT 'custom',
    description TEXT,
    count       INTEGER DEFAULT 0,
    source      TEXT DEFAULT 'builtin',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_paylib_category ON payload_library(category);
CREATE INDEX IF NOT EXISTS idx_paylib_source   ON payload_library(source);
CREATE TABLE IF NOT EXISTS payloads (
    id          SERIAL PRIMARY KEY,
    list_name   TEXT NOT NULL REFERENCES payload_library(name) ON DELETE CASCADE,
    payload     TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'custom',
    tags        TEXT NOT NULL DEFAULT '[]',
    hit_count   INTEGER NOT NULL DEFAULT 0,
    last_used   TEXT,
    created_at  TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'builtin',
    UNIQUE (list_name, payload)
);
CREATE INDEX IF NOT EXISTS idx_payloads_list     ON payloads(list_name);
CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);
CREATE INDEX IF NOT EXISTS idx_payloads_hits     ON payloads(hit_count DESC);
CREATE INDEX IF NOT EXISTS idx_payloads_source   ON payloads(source);
CREATE OR REPLACE FUNCTION _dast_payload_count() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE payload_library SET count = count + 1, updated_at = NOW()::TEXT WHERE name = NEW.list_name;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE payload_library SET count = GREATEST(count - 1, 0), updated_at = NOW()::TEXT WHERE name = OLD.list_name;
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS payload_count_ai ON payloads;
CREATE TRIGGER payload_count_ai AFTER INSERT ON payloads FOR EACH ROW EXECUTE FUNCTION _dast_payload_count();
DROP TRIGGER IF EXISTS payload_count_ad ON payloads;
CREATE TRIGGER payload_count_ad AFTER DELETE ON payloads FOR EACH ROW EXECUTE FUNCTION _dast_payload_count();
CREATE TABLE IF NOT EXISTS finding_comments (
    id          SERIAL PRIMARY KEY,
    finding_id  TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    author      TEXT NOT NULL DEFAULT 'system',
    body        TEXT NOT NULL,
    ts          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fc_finding ON finding_comments(finding_id);
CREATE TABLE IF NOT EXISTS tested_endpoints (
    id           SERIAL PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    method       TEXT NOT NULL DEFAULT 'GET',
    phases       TEXT NOT NULL DEFAULT '[]',
    first_tested TEXT NOT NULL,
    last_tested  TEXT NOT NULL,
    UNIQUE (scan_id, url, method)
);
CREATE INDEX IF NOT EXISTS idx_te_scan ON tested_endpoints(scan_id);
CREATE TABLE IF NOT EXISTS scan_audit_log (
    id       SERIAL PRIMARY KEY,
    scan_id  TEXT,
    actor    TEXT NOT NULL DEFAULT 'system',
    ip       TEXT,
    action   TEXT NOT NULL,
    detail   TEXT,
    ts       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_scan   ON scan_audit_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON scan_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON scan_audit_log(ts);
"""

_PG_MIGRATE_SQL = [
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS profile TEXT DEFAULT 'default'",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS critical_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS high_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS medium_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS low_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS info_count INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS pages_crawled INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS payloads_sent INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS surfaces_found INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS duration_sec DOUBLE PRECISION",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS engine_meta TEXT",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'open'",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS assignee TEXT",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS notes TEXT",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolved_at TEXT",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS retested_at TEXT",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS retest_status TEXT",
]



# ══════════════════════════════════════════════════════════════════════════════
# Tier 1b: PostgreSQL Store
# ══════════════════════════════════════════════════════════════════════════════

class _PostgresStore:
    """PostgreSQL backend — prod-grade, connection-pooled, thread-safe."""

    _PK_MAP: Dict[str, str] = {
        "scans": "scan_id",
        "findings": "finding_id",
        "evidence": "evidence_id",
        "kv": "key",
        "schedules": "id",
        "dedup_cache": "dedup_hash",
        "raw_requests": "request_id",
        "payload_library": "name",
    }

    def __init__(self, url: str):
        import psycopg2.pool
        min_c = int(os.getenv("DB_POOL_MIN", "2"))
        max_c = int(os.getenv("DB_POOL_MAX", "20"))
        self._pool = psycopg2.pool.ThreadedConnectionPool(min_c, max_c, dsn=url)
        self._init_schema()
        log.info("[DB:Postgres] Connected — pool %d-%d  url=%s",
                 min_c, max_c, re.sub(r':[^@/]+@', ':***@', url))

    def _init_schema(self) -> None:
        con = self._pool.getconn()
        try:
            con.autocommit = False
            cur = con.cursor()
            for stmt in _PG_SCHEMA_SQL.split(";"):
                stmt = stmt.strip()
                if stmt:
                    try:
                        cur.execute(stmt)
                    except Exception as e:
                        log.debug("[DB:Postgres] schema stmt skipped: %s", e)
                        con.rollback()
            for stmt in _PG_MIGRATE_SQL:
                try:
                    cur.execute(stmt)
                except Exception:
                    con.rollback()
            con.commit()
            cur.close()
        finally:
            self._pool.putconn(con)

    def _translate(self, sql: str) -> str:
        """Translate SQLite-style SQL to PostgreSQL."""
        sql = sql.replace("?", "%s")
        up = sql.upper()
        if "INSERT OR IGNORE" in up:
            sql = re.sub(r'(?i)INSERT\s+OR\s+IGNORE\s+INTO', 'INSERT INTO', sql)
            if "ON CONFLICT" not in sql.upper():
                sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
            return sql
        if "INSERT OR REPLACE" in up:
            m = re.search(r'(?i)INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*\(([^)]+)\)', sql)
            if m:
                table = m.group(1).lower()
                pk = self._PK_MAP.get(table)
                cols = [c.strip() for c in m.group(2).split(",")]
                non_pk = [c for c in cols if c.lower() != (pk or "").lower()]
                sql = re.sub(r'(?i)INSERT\s+OR\s+REPLACE\s+INTO', 'INSERT INTO', sql)
                sql = sql.rstrip().rstrip(";")
                if pk and non_pk:
                    upd = ", ".join(f"{c}=EXCLUDED.{c}" for c in non_pk)
                    sql += f" ON CONFLICT ({pk}) DO UPDATE SET {upd}"
                elif pk:
                    sql += f" ON CONFLICT ({pk}) DO NOTHING"
        return sql

    def _getconn(self):
        con = self._pool.getconn()
        con.autocommit = True
        return con

    def _putconn(self, con) -> None:
        self._pool.putconn(con)

    def execute(self, sql: str, params=()):
        import psycopg2.extras
        sql = self._translate(sql)
        con = self._getconn()
        try:
            cur = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute(sql, params if params else None)
            return cur
        finally:
            self._putconn(con)

    def executemany(self, sql: str, params_seq) -> None:
        from psycopg2.extras import execute_batch
        sql = self._translate(sql)
        con = self._getconn()
        try:
            cur = con.cursor()
            execute_batch(cur, sql, list(params_seq), page_size=100)
            cur.close()
        finally:
            self._putconn(con)

    def commit(self) -> None:
        pass  # autocommit=True — each statement is its own transaction

    def fetchall(self, sql: str, params=()) -> list:
        import psycopg2.extras
        sql = self._translate(sql)
        con = self._getconn()
        try:
            cur = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute(sql, params if params else None)
            return cur.fetchall()
        finally:
            self._putconn(con)

    def fetchone(self, sql: str, params=()):
        import psycopg2.extras
        sql = self._translate(sql)
        con = self._getconn()
        try:
            cur = con.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute(sql, params if params else None)
            return cur.fetchone()
        finally:
            self._putconn(con)

    def exec_commit(self, sql: str, params=()) -> None:
        self.execute(sql, params)

    def insert_returning_id(self, sql: str, params=()) -> Optional[int]:
        """Execute an INSERT and return the generated id via RETURNING id."""
        sql = self._translate(sql)
        sql = sql.rstrip().rstrip(";")
        if "RETURNING" not in sql.upper():
            sql += " RETURNING id"
        con = self._getconn()
        try:
            cur = con.cursor()
            cur.execute(sql, params if params else None)
            row = cur.fetchone()
            return row[0] if row else None
        finally:
            self._putconn(con)


# ══════════════════════════════════════════════════════════════════════════════
# Tier 1: SQLite Store
# ══════════════════════════════════════════════════════════════════════════════

class _SqliteStore:
    """Thread-safe SQLite wrapper using WAL mode + per-thread connections."""

    def __init__(self, path: Path):
        self._path = path
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._initialized = False

    def _ensure_init(self):
        if not self._initialized:
            with self._init_lock:
                if not self._initialized:
                    self._path.parent.mkdir(parents=True, exist_ok=True)
                    con = sqlite3.connect(str(self._path), timeout=30.0)
                    try:
                        con.executescript(_SCHEMA_SQL)
                        # Run migrations (ignore errors — column may already exist)
                        for stmt in _MIGRATE_SQL:
                            try:
                                con.execute(stmt)
                            except Exception:
                                pass
                        con.commit()
                        self._initialized = True
                    finally:
                        con.close()

    def _conn(self) -> sqlite3.Connection:
        self._ensure_init()
        if not getattr(self._local, "con", None):
            con = sqlite3.connect(str(self._path), check_same_thread=False, timeout=30.0)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA busy_timeout=30000")
            con.execute("PRAGMA synchronous=NORMAL")
            con.execute("PRAGMA foreign_keys=ON")
            self._local.con = con
        return self._local.con

    def reset_after_fork(self) -> None:
        """Close and discard any SQLite connection inherited from the parent process."""
        con = getattr(self._local, "con", None)
        if con is not None:
            try:
                con.close()
            except Exception:
                pass
            self._local.con = None

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        return self._conn().execute(sql, params)

    def executemany(self, sql: str, params_seq) -> None:
        self._conn().executemany(sql, params_seq)

    def commit(self) -> None:
        self._conn().commit()

    def fetchall(self, sql: str, params=()) -> list:
        return self._conn().execute(sql, params).fetchall()

    def fetchone(self, sql: str, params=()) -> Optional[sqlite3.Row]:
        return self._conn().execute(sql, params).fetchone()

    def exec_commit(self, sql: str, params=()) -> None:
        con = self._conn()
        try:
            con.execute(sql, params)
            con.commit()
        except Exception:
            try:
                con.rollback()
            except Exception:
                pass
            raise


# ══════════════════════════════════════════════════════════════════════════════
# Tier 2: Redis Store (optional)
# ══════════════════════════════════════════════════════════════════════════════

class _RedisStore:
    """Optional Redis layer — gracefully disabled if redis-py not installed or server down."""

    _DEDUP_KEY   = "dast:dedup"        # HASH: dedup_hash → finding_id
    _FP_KEY      = "dast:fp"           # SET:  confirmed false positive hashes
    _CONTEXT_PFX = "dast:ctx:"         # HASH per scan: agent → context string
    _RATE_PFX    = "dast:rate:"        # STRING counters for rate limiting

    def __init__(self, url: str | None = None):
        self._url     = url
        self._client  = None
        self._ok      = False
        if self._url:
            self._connect()
        else:
            log.debug("[DB:Redis] Disabled; set REDIS_URL to enable Redis cache")

    def _connect(self):
        try:
            import redis as _r
            client = _r.from_url(
                self._url, decode_responses=True,
                socket_timeout=0.5, socket_connect_timeout=1.0,
            )
            client.ping()
            self._client = client
            self._ok     = True
            log.info("[DB:Redis] Connected at %s", self._url)
        except Exception as e:
            log.warning("[DB:Redis] Unavailable (%s) - using SQLite fallback", e)
            self._ok = False

    @property
    def available(self) -> bool:
        return self._ok

    def _safe(self, fn):
        if not self._ok:
            return None
        try:
            return fn()
        except Exception as e:
            log.debug("[DB:Redis] Error: %s", e)
            self._ok = False  # disable on error; restart will re-enable
            return None

    # ── Dedup ──────────────────────────────────────────────────────────────────
    def is_duplicate(self, dedup_hash: str) -> bool:
        result = self._safe(lambda: self._client.hexists(self._DEDUP_KEY, dedup_hash))
        return bool(result)

    def mark_seen(self, dedup_hash: str, finding_id: str, scan_id: str) -> None:
        self._safe(lambda: self._client.hset(self._DEDUP_KEY, dedup_hash, finding_id))

    def is_false_positive(self, dedup_hash: str) -> bool:
        result = self._safe(lambda: self._client.sismember(self._FP_KEY, dedup_hash))
        return bool(result)

    def mark_false_positive(self, dedup_hash: str) -> None:
        self._safe(lambda: self._client.sadd(self._FP_KEY, dedup_hash))

    # ── Agent context (TTL 2h) ─────────────────────────────────────────────────
    def set_context(self, scan_id: str, key: str, value: str) -> None:
        hkey = f"{self._CONTEXT_PFX}{scan_id}"
        self._safe(lambda: (
            self._client.hset(hkey, key, value),
            self._client.expire(hkey, 7200),
        ))

    def get_context(self, scan_id: str, key: str) -> Optional[str]:
        hkey = f"{self._CONTEXT_PFX}{scan_id}"
        return self._safe(lambda: self._client.hget(hkey, key))

    def get_all_context(self, scan_id: str) -> dict:
        hkey = f"{self._CONTEXT_PFX}{scan_id}"
        result = self._safe(lambda: self._client.hgetall(hkey))
        return result or {}

    def clear_context(self, scan_id: str) -> None:
        hkey = f"{self._CONTEXT_PFX}{scan_id}"
        self._safe(lambda: self._client.delete(hkey))

    # ── Rate limiting ──────────────────────────────────────────────────────────
    def rate_check(self, key: str, limit: int, window_sec: int) -> bool:
        rkey = f"{self._RATE_PFX}{key}"
        def _fn():
            pipe = self._client.pipeline()
            pipe.incr(rkey)
            pipe.expire(rkey, window_sec)
            count, _ = pipe.execute()
            return int(count) <= limit
        result = self._safe(_fn)
        return True if result is None else result


# ══════════════════════════════════════════════════════════════════════════════
# Tier 3: JSON File Store
# ══════════════════════════════════════════════════════════════════════════════

class _JsonFileStore:
    """Lightweight JSON file store for profiles, baselines, and config."""

    def __init__(self, base_dir: Path):
        self._base = base_dir
        base_dir.mkdir(parents=True, exist_ok=True)
        (_PROFILES_DIR).mkdir(parents=True, exist_ok=True)
        (_BASELINES_DIR).mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, namespace: str, key: str) -> Path:
        safe = key.replace("/", "_").replace(":", "_").replace(" ", "_")
        return self._base / namespace / f"{safe}.json"

    def write(self, namespace: str, key: str, data: Any) -> None:
        p = self._path(namespace, key)
        p.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            p.write_text(json.dumps(data, indent=2, default=str))

    def read(self, namespace: str, key: str, default=None) -> Any:
        p = self._path(namespace, key)
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text())
        except Exception:
            return default

    def delete(self, namespace: str, key: str) -> None:
        p = self._path(namespace, key)
        with self._lock:
            p.unlink(missing_ok=True)

    def list_keys(self, namespace: str) -> list:
        d = self._base / namespace
        if not d.exists():
            return []
        return [p.stem for p in d.glob("*.json")]

    # ── Convenience helpers ────────────────────────────────────────────────────
    def save_baseline(self, scan_id: str, baseline_data: dict) -> None:
        self.write("baselines", scan_id, baseline_data)

    def load_baseline(self, scan_id: str) -> Optional[dict]:
        return self.read("baselines", scan_id)

    def save_profile(self, name: str, profile: dict) -> None:
        self.write("profiles", name, profile)

    def load_profile(self, name: str) -> Optional[dict]:
        return self.read("profiles", name)

    def list_profiles(self) -> list:
        return self.list_keys("profiles")


# ══════════════════════════════════════════════════════════════════════════════
# DASTDatabase — unified façade
# ══════════════════════════════════════════════════════════════════════════════

class DASTDatabase:
    """
    Unified multi-DB façade.

    All public methods are thread-safe. Redis is optional — every operation
    degrades gracefully to SQLite or in-memory when Redis is unavailable.
    """

    def __init__(self, redis_url: str | None = None):
        db_url = os.getenv("DATABASE_URL", "")
        if db_url:
            self.sql = _PostgresStore(db_url)
            self._is_postgres = True
        else:
            self.sql = _SqliteStore(_DB_PATH)
            self._is_postgres = False
        configured_redis_url = redis_url or os.getenv("REDIS_URL", "").strip() or None
        self.redis  = _RedisStore(configured_redis_url)
        self.files  = _JsonFileStore(_DATA_DIR)
        self._metric_buf: list  = []
        self._metric_lock       = threading.RLock()
        self._metric_flush_at   = time.monotonic() + 10
        # Per-scan start times for duration tracking
        self._scan_start: Dict[str, float] = {}

    # ── Dedup helpers (Redis → SQLite fallback) ────────────────────────────────

    def _dedup_hash(self, finding: dict) -> str:
        key = "|".join([
            (finding.get("agent")   or ""),
            (finding.get("vuln_type") or finding.get("type") or ""),
            (finding.get("finding") or ""),
            (finding.get("url")     or finding.get("target") or ""),
            (finding.get("param")   or ""),
        ])
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def is_duplicate(self, dedup_hash: str) -> bool:
        if self.redis.available:
            return self.redis.is_duplicate(dedup_hash)
        row = self.sql.fetchone(
            "SELECT 1 FROM dedup_cache WHERE dedup_hash=? AND is_fp=0", (dedup_hash,)
        )
        return row is not None

    def _mark_seen(self, dedup_hash: str, finding_id: str, scan_id: str) -> None:
        if self.redis.available:
            self.redis.mark_seen(dedup_hash, finding_id, scan_id)
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.sql.exec_commit(
                "INSERT OR IGNORE INTO dedup_cache VALUES (?,?,?,?,0)",
                (dedup_hash, finding_id, scan_id, now),
            )
        except Exception:
            pass

    # ── Scan lifecycle ─────────────────────────────────────────────────────────

    def start_scan(self, scan_id: str, target: str, profile: str = "default",
                   engine_meta: Optional[dict] = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._scan_start[scan_id] = time.monotonic()
        try:
            self.sql.exec_commit(
                "INSERT OR REPLACE INTO scans "
                "(scan_id,target,started_at,status,profile,engine_meta) VALUES (?,?,?,?,?,?)",
                (scan_id, target, now, "running", profile,
                 json.dumps(engine_meta) if engine_meta else None),
            )
        except Exception as e:
            log.error("[DB] start_scan error: %s", e)
        # Clear Redis context for this scan
        self.redis.clear_context(scan_id)
        # Clear SQLite dedup_cache so previous scans don't suppress new findings
        try:
            self.sql.exec_commit("DELETE FROM dedup_cache")
        except Exception:
            pass
        log.info("[DB] Scan started: %s → %s", scan_id, target)

    def update_scan_counts(self, scan_id: str, **counts) -> None:
        allowed = {"finding_count","critical_count","high_count","medium_count",
                   "low_count","info_count","pages_crawled","payloads_sent","surfaces_found"}
        sets = [(f"{k}=?", v) for k, v in counts.items() if k in allowed]
        if not sets:
            return
        sql = "UPDATE scans SET " + ", ".join(s for s, _ in sets) + " WHERE scan_id=?"
        params = [v for _, v in sets] + [scan_id]
        try:
            self.sql.exec_commit(sql, params)
        except Exception:
            pass

    def complete_scan(self, scan_id: str, status: str = "completed",
                      summary: Optional[str] = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        elapsed = None
        if scan_id in self._scan_start:
            elapsed = time.monotonic() - self._scan_start.pop(scan_id)
        import time as _time
        for attempt in range(6):
            try:
                self.sql.exec_commit(
                    "UPDATE scans SET completed_at=?, status=?, duration_sec=?, summary=? "
                    "WHERE scan_id=?",
                    (now, status, elapsed, summary, scan_id),
                )
                self._flush_metrics()
                break
            except Exception as e:
                if attempt < 5 and "locked" in str(e).lower():
                    _time.sleep(0.5 * (attempt + 1))
                    continue
                log.error("[DB] complete_scan error: %s", e)
                break
        log.info("[DB] Scan %s → %s (%.1fs)", scan_id, status, elapsed or 0)

    # ── Finding persistence (real-time writes) ─────────────────────────────────

    def _refresh_scan_summary(self, scan_id: str) -> None:
        row = self.sql.fetchone(
            """SELECT critical_count,high_count,medium_count,low_count,info_count
               FROM scans WHERE scan_id=?""",
            (scan_id,),
        )
        if not row:
            return
        counts = {
            "critical": int(row[0] or 0),
            "high":     int(row[1] or 0),
            "medium":   int(row[2] or 0),
            "low":      int(row[3] or 0),
            "info":     int(row[4] or 0),
        }
        summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
        self.sql.exec_commit(
            "UPDATE scans SET finding_count=?, summary=? WHERE scan_id=?",
            (sum(counts.values()), summary, scan_id),
        )

    def write_finding(self, scan_id: str, finding: dict,
                      check_duplicate: bool = True) -> Optional[str]:
        """
        Persist one finding to SQLite. Returns the finding_id (new or existing).
        Skips if a dedup match is found in Redis or SQLite.
        """
        dh = self._dedup_hash(finding)
        if check_duplicate and self.is_duplicate(dh):
            return None

        finding_id = finding.get("finding_id") or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Extract known fields; everything else goes into extra JSON
        _known = {"agent","phase","icon","vuln_type","type","severity","finding","target",
                  "url","param","payload","evidence_id","owasp","cwe","cvss_score",
                  "cvss_vector","remediation","proof","proof_data","ts"}
        extra = {k: v for k, v in finding.items() if k not in _known and k != "finding_id"}

        sev = (finding.get("severity") or "info").lower()
        try:
            self.sql.exec_commit(
                """INSERT OR IGNORE INTO findings
                   (finding_id,scan_id,ts,agent,phase,icon,vuln_type,severity,finding,
                    target,url,param,payload,evidence_id,owasp,cwe,cvss_score,cvss_vector,
                    remediation,dedup_hash,proof,proof_data,extra)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    finding_id, scan_id,
                    finding.get("ts") or now,
                    finding.get("agent"),
                    finding.get("phase"),
                    finding.get("icon"),
                    finding.get("vuln_type") or finding.get("type"),
                    sev,
                    finding.get("finding"),
                    finding.get("target"),
                    finding.get("url"),
                    finding.get("param"),
                    finding.get("payload"),
                    finding.get("evidence_id"),
                    finding.get("owasp"),
                    finding.get("cwe"),
                    finding.get("cvss_score"),
                    finding.get("cvss_vector"),
                    finding.get("remediation"),
                    dh,
                    finding.get("proof"),
                    finding.get("proof_data"),
                    json.dumps(extra) if extra else None,
                ),
            )
            self._mark_seen(dh, finding_id, scan_id)
            # Increment severity counter on the scan row
            col_map = {"critical":"critical_count","high":"high_count","medium":"medium_count",
                       "low":"low_count","info":"info_count"}
            col = col_map.get(sev, "info_count")
            self.sql.exec_commit(
                f"UPDATE scans SET finding_count=finding_count+1, {col}={col}+1 WHERE scan_id=?",
                (scan_id,),
            )
            self._refresh_scan_summary(scan_id)
            # Credit the payload that triggered this finding
            payload_str = finding.get("payload", "")
            if payload_str:
                try:
                    self.bump_hit_count(payload_str)
                except Exception:
                    pass
        except Exception as e:
            log.debug("[DB] write_finding error: %s", e)
        return finding_id

    def mark_false_positive(self, finding_id: str) -> None:
        try:
            row = self.sql.fetchone("SELECT dedup_hash FROM findings WHERE finding_id=?", (finding_id,))
            if row:
                dh = row[0]
                self.sql.exec_commit(
                    "UPDATE findings SET is_false_positive=1 WHERE finding_id=?", (finding_id,))
                self.sql.exec_commit(
                    "UPDATE dedup_cache SET is_fp=1 WHERE dedup_hash=?", (dh,))
                if self.redis.available:
                    self.redis.mark_false_positive(dh)
        except Exception as e:
            log.debug("[DB] mark_fp error: %s", e)

    # ── Finding lifecycle / triage (Gap 1) ────────────────────────────────────

    _VALID_STATUSES = frozenset({"open", "triaged", "accepted_risk", "fixed", "wontfix"})

    def update_finding_status(self, finding_id: str, status: Optional[str] = None,
                               assignee: Optional[str] = None,
                               notes: Optional[str] = None) -> bool:
        """Update triage state of a finding. Returns True on success."""
        if status and status not in self._VALID_STATUSES:
            return False
        sets, params = [], []
        if status:
            sets.append("status=?"); params.append(status)
            if status in ("fixed", "wontfix", "accepted_risk"):
                sets.append("resolved_at=?")
                params.append(datetime.now(timezone.utc).isoformat())
        if assignee is not None:
            sets.append("assignee=?"); params.append(assignee)
        if notes is not None:
            sets.append("notes=?"); params.append(notes)
        if not sets:
            return False
        params.append(finding_id)
        try:
            self.sql.exec_commit(
                f"UPDATE findings SET {', '.join(sets)} WHERE finding_id=?", params)
            return True
        except Exception as e:
            log.debug("[DB] update_finding_status error: %s", e)
            return False

    def add_finding_comment(self, finding_id: str, body: str,
                            author: str = "user") -> Optional[int]:
        """Append a comment to a finding. Returns the new comment id."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            if self._is_postgres:
                return self.sql.insert_returning_id(
                    "INSERT INTO finding_comments (finding_id,author,body,ts) "
                    "VALUES (%s,%s,%s,%s) RETURNING id",
                    (finding_id, author, body, now),
                )
            cur = self.sql.execute(
                "INSERT INTO finding_comments (finding_id,author,body,ts) VALUES (?,?,?,?)",
                (finding_id, author, body, now),
            )
            self.sql.commit()
            return cur.lastrowid
        except Exception as e:
            log.debug("[DB] add_finding_comment error: %s", e)
            return None

    def get_finding_comments(self, finding_id: str) -> List[dict]:
        rows = self.sql.fetchall(
            "SELECT id,finding_id,author,body,ts FROM finding_comments "
            "WHERE finding_id=? ORDER BY ts ASC", (finding_id,))
        return [dict(r) for r in rows]

    def record_retest(self, finding_id: str, retest_status: str) -> None:
        """Record re-verification result: still_vulnerable | fixed | inconclusive."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.sql.exec_commit(
                "UPDATE findings SET retested_at=?, retest_status=? WHERE finding_id=?",
                (now, retest_status, finding_id))
            if retest_status == "fixed":
                self.update_finding_status(finding_id, status="fixed")
        except Exception as e:
            log.debug("[DB] record_retest error: %s", e)

    # ── Scan coverage tracking (Gap 3) ────────────────────────────────────────

    def mark_endpoint_tested(self, scan_id: str, url: str,
                              method: str = "GET", phase: str = "") -> None:
        """Record that an endpoint was tested during a scan."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            row = self.sql.fetchone(
                "SELECT id, phases FROM tested_endpoints WHERE scan_id=? AND url=? AND method=?",
                (scan_id, url, method))
            if row:
                existing = json.loads(row[1] if row[1] else "[]")
                if phase and phase not in existing:
                    existing.append(phase)
                self.sql.exec_commit(
                    "UPDATE tested_endpoints SET phases=?, last_tested=? "
                    "WHERE scan_id=? AND url=? AND method=?",
                    (json.dumps(existing), now, scan_id, url, method))
            else:
                phases = json.dumps([phase] if phase else [])
                self.sql.exec_commit(
                    "INSERT OR IGNORE INTO tested_endpoints "
                    "(scan_id,url,method,phases,first_tested,last_tested) VALUES (?,?,?,?,?,?)",
                    (scan_id, url, method, phases, now, now))
        except Exception as e:
            log.debug("[DB] mark_endpoint_tested error: %s", e)

    def get_coverage(self, scan_id: str) -> dict:
        """Return coverage stats for a scan."""
        try:
            tested = self.sql.fetchone(
                "SELECT COUNT(*) FROM tested_endpoints WHERE scan_id=?", (scan_id,))
            findings_urls = self.sql.fetchone(
                "SELECT COUNT(DISTINCT url) FROM findings WHERE scan_id=?", (scan_id,))
            by_phase = self.sql.fetchall(
                "SELECT method, COUNT(*) as c FROM tested_endpoints "
                "WHERE scan_id=? GROUP BY method", (scan_id,))
            return {
                "scan_id": scan_id,
                "tested_endpoints": tested[0] if tested else 0,
                "unique_finding_urls": findings_urls[0] if findings_urls else 0,
                "by_method": {r[0]: r[1] for r in by_phase},
            }
        except Exception as e:
            log.debug("[DB] get_coverage error: %s", e)
            return {"scan_id": scan_id, "tested_endpoints": 0, "unique_finding_urls": 0}

    # ── Audit trail (Gap 4) ───────────────────────────────────────────────────

    def log_audit(self, action: str, scan_id: Optional[str] = None,
                  actor: str = "system", ip: Optional[str] = None,
                  detail: Optional[str] = None) -> None:
        """Append an immutable audit event."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.sql.exec_commit(
                "INSERT INTO scan_audit_log (scan_id,actor,ip,action,detail,ts) "
                "VALUES (?,?,?,?,?,?)",
                (scan_id, actor, ip, action, detail, now))
        except Exception as e:
            log.debug("[DB] log_audit error: %s", e)

    def get_audit_log(self, scan_id: Optional[str] = None,
                      limit: int = 200) -> List[dict]:
        if scan_id:
            rows = self.sql.fetchall(
                "SELECT id,scan_id,actor,ip,action,detail,ts FROM scan_audit_log "
                "WHERE scan_id=? ORDER BY ts DESC LIMIT ?", (scan_id, limit))
        else:
            rows = self.sql.fetchall(
                "SELECT id,scan_id,actor,ip,action,detail,ts FROM scan_audit_log "
                "ORDER BY ts DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    # ── Evidence (HTTP request/response pairs) ─────────────────────────────────

    def store_evidence(self, evidence_id: str, scan_id: str, finding_id: Optional[str],
                       data: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.sql.exec_commit(
                """INSERT OR IGNORE INTO evidence
                   (evidence_id,scan_id,finding_id,ts,url,method,req_headers,req_body,
                    status_code,resp_headers,resp_body,resp_time_ms,vuln_type,payload,parameter)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_id, scan_id, finding_id, data.get("ts", now),
                    data.get("url"), data.get("method"),
                    json.dumps(data.get("request", {}).get("headers", {})),
                    data.get("request", {}).get("body", ""),
                    data.get("status_code"),
                    json.dumps(data.get("response", {}).get("headers", {})),
                    (data.get("response", {}).get("body") or "")[:32768],
                    data.get("resp_time_ms"),
                    data.get("vuln_type"),
                    data.get("payload"),
                    data.get("parameter"),
                ),
            )
        except Exception as e:
            log.debug("[DB] store_evidence error: %s", e)

    def get_evidence(self, evidence_id: str) -> Optional[dict]:
        row = self.sql.fetchone(
            "SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)
        )
        if not row:
            return None
        d = dict(row)
        for k in ("req_headers", "resp_headers"):
            try:
                d[k] = json.loads(d.get(k) or "{}")
            except Exception:
                d[k] = {}
        return d

    # ── Time-series metrics ────────────────────────────────────────────────────

    def record_metric(self, scan_id: str, phase: str, **values) -> None:
        now = datetime.now(timezone.utc).isoformat()
        row = (
            scan_id, now, phase,
            values.get("pages_crawled", 0),
            values.get("surfaces_found", 0),
            values.get("payloads_sent", 0),
            values.get("findings_count", 0),
            values.get("critical_count", 0),
            values.get("high_count", 0),
            values.get("medium_count", 0),
            values.get("low_count", 0),
            values.get("info_count", 0),
            values.get("elapsed_sec"),
        )
        with self._metric_lock:
            self._metric_buf.append(row)
            if time.monotonic() >= self._metric_flush_at:
                self._flush_metrics()

    def _flush_metrics(self) -> None:
        with self._metric_lock:
            if not self._metric_buf:
                return
            buf, self._metric_buf = self._metric_buf, []
            self._metric_flush_at = time.monotonic() + 10
        try:
            self.sql.executemany(
                """INSERT INTO scan_metrics
                   (scan_id,ts,phase,pages_crawled,surfaces_found,payloads_sent,
                    findings_count,critical_count,high_count,medium_count,low_count,
                    info_count,elapsed_sec)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                buf,
            )
            self.sql.commit()
        except Exception as e:
            log.debug("[DB] flush_metrics error: %s", e)

    def get_scan_metrics(self, scan_id: str) -> List[dict]:
        rows = self.sql.fetchall(
            "SELECT * FROM scan_metrics WHERE scan_id=? ORDER BY ts ASC", (scan_id,)
        )
        return [dict(r) for r in rows]

    # ── Scan history ───────────────────────────────────────────────────────────

    def get_scan_history(self, limit: int = 20) -> List[dict]:
        rows = self.sql.fetchall(
            """SELECT scan_id,target,started_at,completed_at,status,profile,
                      finding_count,critical_count,high_count,medium_count,
                      low_count,info_count,pages_crawled,payloads_sent,duration_sec,summary,engine_meta
               FROM scans ORDER BY started_at DESC LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> Optional[dict]:
        row = self.sql.fetchone("SELECT * FROM scans WHERE scan_id=?", (scan_id,))
        return dict(row) if row else None

    def get_findings(self, scan_id: Optional[str] = None,
                     severity: Optional[str] = None,
                     is_fp: bool = False,
                     limit: int = 5000) -> List[dict]:
        clauses = ["is_false_positive=?"]
        params:  list = [int(is_fp)]
        if scan_id:
            clauses.append("scan_id=?")
            params.append(scan_id)
        if severity:
            clauses.append("severity=?")
            params.append(severity.lower())
        where = " AND ".join(clauses)
        rows = self.sql.fetchall(
            f"SELECT * FROM findings WHERE {where} "
            f"ORDER BY ts DESC LIMIT ?",
            params + [limit],
        )
        return [dict(r) for r in rows]

    def _deleted_scan_ids(self) -> set[str]:
        deleted = self.kv_get("deleted_scan_ids", [])
        if isinstance(deleted, list):
            return {str(scan_id) for scan_id in deleted if scan_id}
        return set()

    def _remember_deleted_scan(self, scan_id: str) -> None:
        if not scan_id:
            return
        deleted = list(self._deleted_scan_ids())
        if scan_id not in deleted:
            deleted.append(scan_id)
        self.kv_set("deleted_scan_ids", deleted[-5000:])

    def _delete_legacy_scan(self, scan_id: str) -> None:
        candidates = [
            Path.home() / ".dast" / "scans.db",
            Path(__file__).parent.parent / "dast_findings.db",
        ]
        for path in candidates:
            try:
                if not path.exists() or path.resolve() == _DB_PATH.resolve():
                    continue
                old = sqlite3.connect(str(path))
                try:
                    for stmt in (
                        "DELETE FROM findings WHERE scan_id=?",
                        "DELETE FROM scans WHERE scan_id=?",
                        "DELETE FROM scans WHERE id=?",
                    ):
                        try:
                            old.execute(stmt, (scan_id,))
                        except Exception:
                            pass
                    old.commit()
                finally:
                    old.close()
            except Exception:
                pass

    def _legacy_migration_key(self, path: Path) -> str:
        try:
            source = str(path.resolve()).lower()
        except Exception:
            source = str(path).lower()
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:24]
        return f"legacy_migrated:{digest}"

    def _legacy_migration_done(self, path: Path) -> bool:
        marker = self.kv_get(self._legacy_migration_key(path), None)
        return bool(marker)

    def _remember_legacy_migrated(self, path: Path, migrated: int) -> None:
        try:
            source = str(path.resolve())
        except Exception:
            source = str(path)
        self.kv_set(self._legacy_migration_key(path), {
            "path": source,
            "migrated": migrated,
            "at": datetime.now(timezone.utc).isoformat(),
            "version": 1,
        })

    def delete_scan(self, scan_id: str) -> bool:
        try:
            self._remember_deleted_scan(scan_id)
            # Use a dedicated fresh connection for delete to avoid any
            # stale transaction state on the thread-local connection.
            con = sqlite3.connect(str(self.sql._path), check_same_thread=False, timeout=30.0)
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA busy_timeout=30000")
            con.execute("PRAGMA foreign_keys=ON")
            try:
                for table in (
                    "findings", "evidence", "scan_metrics", "tested_endpoints",
                    "scan_audit_log", "raw_requests", "dedup_cache",
                ):
                    try:
                        con.execute(f"DELETE FROM {table} WHERE scan_id=?", (scan_id,))
                    except Exception:
                        pass
                con.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
                con.commit()
            except Exception as e:
                log.error("delete_scan(%s) failed: %s", scan_id, e, exc_info=True)
                try:
                    con.rollback()
                except Exception:
                    pass
                return False
            finally:
                try:
                    con.close()
                except Exception:
                    pass
            self._delete_legacy_scan(scan_id)
            return True
        except Exception as e:
            log.error("delete_scan(%s) outer failed: %s", scan_id, e, exc_info=True)
            return False

    # ── Agent context (Redis → in-memory fallback) ────────────────────────────

    _ctx_mem: Dict[str, Dict[str, str]] = {}  # fallback when Redis down

    def set_context(self, scan_id: str, key: str, value: str) -> None:
        if self.redis.available:
            self.redis.set_context(scan_id, key, value)
        else:
            self._ctx_mem.setdefault(scan_id, {})[key] = value

    def get_context(self, scan_id: str, key: str) -> Optional[str]:
        if self.redis.available:
            return self.redis.get_context(scan_id, key)
        return self._ctx_mem.get(scan_id, {}).get(key)

    def get_all_context(self, scan_id: str) -> dict:
        if self.redis.available:
            return self.redis.get_all_context(scan_id)
        return dict(self._ctx_mem.get(scan_id, {}))

    def clear_context(self, scan_id: str) -> None:
        self.redis.clear_context(scan_id)
        self._ctx_mem.pop(scan_id, None)

    # ── KV Store ──────────────────────────────────────────────────────────────

    def kv_set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        expires = None
        if ttl_seconds:
            from datetime import timedelta
            expires = (datetime.now(timezone.utc) +
                       timedelta(seconds=ttl_seconds)).isoformat()
        try:
            self.sql.exec_commit(
                "INSERT OR REPLACE INTO kv VALUES (?,?,?)",
                (key, json.dumps(value, default=str), expires),
            )
        except Exception:
            pass

    def kv_get(self, key: str, default=None) -> Any:
        row = self.sql.fetchone("SELECT value,expires_at FROM kv WHERE key=?", (key,))
        if not row:
            return default
        if row[1]:
            try:
                exp = datetime.fromisoformat(row[1])
                if datetime.now(timezone.utc) > exp:
                    self.sql.exec_commit("DELETE FROM kv WHERE key=?", (key,))
                    return default
            except Exception:
                pass
        try:
            return json.loads(row[0])
        except Exception:
            return default

    # ── Schedules (proxy to SQL) ──────────────────────────────────────────────

    def get_schedules(self) -> List[dict]:
        rows = self.sql.fetchall(
            "SELECT * FROM schedules ORDER BY created_at DESC"
        )
        return [dict(r) for r in rows]

    def save_schedule(self, sched_id, target, label, interval_minutes,
                      profile, next_run) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.sql.exec_commit(
            "INSERT OR REPLACE INTO schedules VALUES (?,?,?,?,?,1,NULL,?,?)",
            (sched_id, target, label, interval_minutes, profile, next_run, now),
        )

    def delete_schedule(self, sched_id: str) -> None:
        self.sql.exec_commit("DELETE FROM schedules WHERE id=?", (sched_id,))

    def update_schedule(self, sched_id: str, **kwargs) -> None:
        allowed = {"enabled", "last_run", "next_run"}
        for k, v in kwargs.items():
            if k in allowed:
                self.sql.exec_commit(
                    f"UPDATE schedules SET {k}=? WHERE id=?", (v, sched_id)
                )

    # ── Cross-scan analytics ──────────────────────────────────────────────────

    def get_vuln_trend(self, vuln_type: str, limit: int = 10) -> List[dict]:
        """How often a vuln type appeared across recent scans."""
        rows = self.sql.fetchall(
            """SELECT s.scan_id, s.target, s.started_at,
                      COUNT(f.finding_id) as count
               FROM scans s
               LEFT JOIN findings f ON s.scan_id=f.scan_id AND f.vuln_type=?
               GROUP BY s.scan_id
               ORDER BY s.started_at DESC LIMIT ?""",
            (vuln_type, limit),
        )
        return [dict(r) for r in rows]

    def compare_scans(self, scan_id_a: str, scan_id_b: str) -> dict:
        """
        Diff two scans: new findings in B, resolved findings (in A but not B),
        and findings present in both.
        """
        def _hashes(sid):
            rows = self.sql.fetchall(
                "SELECT dedup_hash, finding, severity FROM findings "
                "WHERE scan_id=? AND is_false_positive=0", (sid,)
            )
            return {r[0]: {"finding": r[1], "severity": r[2]} for r in rows}

        hashes_a = _hashes(scan_id_a)
        hashes_b = _hashes(scan_id_b)
        new_in_b      = {h: v for h, v in hashes_b.items() if h not in hashes_a}
        resolved      = {h: v for h, v in hashes_a.items() if h not in hashes_b}
        persisted     = {h: v for h, v in hashes_b.items() if h in hashes_a}
        return {
            "scan_a": scan_id_a,
            "scan_b": scan_id_b,
            "new_findings":      list(new_in_b.values()),
            "resolved_findings": list(resolved.values()),
            "persisted_findings": list(persisted.values()),
            "new_count":      len(new_in_b),
            "resolved_count": len(resolved),
            "persisted_count": len(persisted),
        }

    def get_top_vulns(self, limit: int = 10) -> List[dict]:
        """Most common vuln types across ALL scans."""
        rows = self.sql.fetchall(
            """SELECT vuln_type, severity, COUNT(*) as total
               FROM findings WHERE is_false_positive=0
               GROUP BY vuln_type
               ORDER BY total DESC LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in rows]

    def get_targets_summary(self) -> List[dict]:
        """Per-target finding summary across all scans."""
        rows = self.sql.fetchall(
            """SELECT target,
                      COUNT(DISTINCT scan_id)  as scan_count,
                      SUM(finding_count)        as total_findings,
                      SUM(critical_count)       as total_critical,
                      SUM(high_count)           as total_high,
                      MAX(started_at)           as last_scan
               FROM scans
               GROUP BY target
               ORDER BY last_scan DESC""",
        )
        return [dict(r) for r in rows]

    # ── Migration: import old scans.db data ───────────────────────────────────

    def migrate_legacy(self, legacy_path: Optional[Path] = None) -> int:
        """
        Import all historical scans into the master DB.
        Handles two source formats:
          A. Old blob format: scans(id, target, started, finished, findings JSON, summary)
          B. Normalised format: scans(scan_id, target, started_at, ...) + findings(id, scan_id, ...)
        Returns number of scans migrated.
        """
        if legacy_path is None:
            # Try both known locations
            candidates = [
                Path.home() / ".dast" / "scans.db",
                Path(__file__).parent.parent / "dast_findings.db",
            ]
        else:
            candidates = [legacy_path]

        total = 0
        deleted_scan_ids = self._deleted_scan_ids()
        force = bool(legacy_path) or os.getenv("DAST_FORCE_LEGACY_MIGRATION", "").lower() in {"1", "true", "yes"}
        for path in candidates:
            if not path.exists() or path.resolve() == _DB_PATH.resolve():
                continue
            if not force and self._legacy_migration_done(path):
                continue
            migrated = self._migrate_one(path, deleted_scan_ids)
            total += migrated
            if not force:
                self._remember_legacy_migrated(path, migrated)
        return total

    def _migrate_one(self, path: Path, deleted_scan_ids: Optional[set[str]] = None) -> int:
        migrated = 0
        deleted_scan_ids = deleted_scan_ids or set()
        try:
            old = sqlite3.connect(str(path))
            old.row_factory = sqlite3.Row
            # Detect schema format
            cols = {r[1] for r in old.execute("PRAGMA table_info(scans)").fetchall()}
            is_blob_format = "findings" in cols and "id" in cols
            is_norm_format = "scan_id" in cols and "started_at" in cols

            if is_norm_format:
                # Format B: normalised scans + separate findings table
                scans = old.execute(
                    "SELECT scan_id,target,started_at,completed_at,status,finding_count "
                    "FROM scans ORDER BY started_at"
                ).fetchall()
                for s in scans:
                    scan_id = s["scan_id"]
                    if scan_id in deleted_scan_ids:
                        continue
                    if self.get_scan(scan_id):
                        continue
                    self.sql.exec_commit(
                        "INSERT OR IGNORE INTO scans (scan_id,target,started_at,completed_at,status,finding_count) "
                        "VALUES (?,?,?,?,?,?)",
                        (scan_id, s["target"], s["started_at"], s["completed_at"],
                         s["status"] or "completed", s["finding_count"] or 0),
                    )
                    # Migrate individual findings rows
                    try:
                        frows = old.execute(
                            "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
                        ).fetchall()
                        for f in frows:
                            fd = dict(f)
                            self.write_finding(scan_id, {
                                "finding":   fd.get("finding"),
                                "severity":  fd.get("severity", "info"),
                                "vuln_type": fd.get("vuln_type"),
                                "url":       fd.get("url"),
                                "param":     fd.get("param"),
                                "payload":   fd.get("payload"),
                                "ts":        fd.get("ts"),
                                "agent":     fd.get("agent_id"),
                                "proof":     fd.get("proof"),
                            }, check_duplicate=False)
                    except Exception:
                        pass
                    migrated += 1

            elif is_blob_format:
                # Format A: single JSON blob per scan
                scans = old.execute(
                    "SELECT id,target,started,finished,findings,summary FROM scans"
                ).fetchall()
                for s in scans:
                    scan_id = s["id"]
                    if scan_id in deleted_scan_ids:
                        continue
                    if self.get_scan(scan_id):
                        continue
                    self.start_scan(scan_id, s["target"])
                    try:
                        findings = json.loads(s["findings"] or "[]")
                    except Exception:
                        findings = []
                    for f in findings:
                        self.write_finding(scan_id, f, check_duplicate=False)
                    self.complete_scan(scan_id, "completed", s["summary"])
                    self.sql.exec_commit(
                        "UPDATE scans SET started_at=?,completed_at=? WHERE scan_id=?",
                        (s["started"], s["finished"], scan_id),
                    )
                    migrated += 1

            old.close()
            log.info("[DB] Migrated %d scans from %s", migrated, path)
        except Exception as e:
            log.warning("[DB] Migration error for %s: %s", path, e)
        return migrated

    # ══════════════════════════════════════════════════════════════════════════
    # Raw Requests — every HTTP request sent (fuzzer, intruder, crawler, replay)
    # ══════════════════════════════════════════════════════════════════════════

    def store_raw_request(self, scan_id: str, source: str, url: str, method: str = "GET",
                          req_headers: Optional[dict] = None, req_body: str = "",
                          payload: str = "", parameter: str = "",
                          vuln_type: str = "", status_code: int = 0,
                          resp_headers: Optional[dict] = None, resp_body: str = "",
                          resp_time_ms: float = 0.0, content_length: int = 0,
                          is_baseline: bool = False, is_finding: bool = False,
                          finding_id: Optional[str] = None,
                          grep_matches: Optional[list] = None,
                          baseline_diff: int = 0) -> str:
        """Persist a single HTTP request+response pair. Returns request_id."""
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.sql.exec_commit(
                """INSERT OR IGNORE INTO raw_requests
                   (request_id,scan_id,ts,source,url,method,req_headers,req_body,
                    payload,parameter,vuln_type,status_code,resp_headers,resp_body,
                    resp_time_ms,content_length,is_baseline,is_finding,finding_id,
                    grep_matches,baseline_diff)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    request_id, scan_id, now, source, url, method,
                    json.dumps(req_headers or {}),
                    req_body[:4096] if req_body else "",
                    payload, parameter, vuln_type, status_code,
                    json.dumps(resp_headers or {}),
                    resp_body[:8192] if resp_body else "",
                    round(resp_time_ms, 2), content_length,
                    int(is_baseline), int(is_finding), finding_id,
                    json.dumps(grep_matches or []), baseline_diff,
                ),
            )
        except Exception as e:
            log.debug("[DB] store_raw_request error: %s", e)
        return request_id

    def bulk_store_raw_requests(self, rows: list) -> None:
        """Bulk insert raw requests (e.g., full Intruder attack result set)."""
        if not rows:
            return
        now = datetime.now(timezone.utc).isoformat()
        params = []
        for r in rows:
            params.append((
                f"req_{uuid.uuid4().hex[:12]}",
                r.get("scan_id", ""),
                r.get("ts", now),
                r.get("source", "intruder"),
                r.get("url", ""),
                r.get("method", "GET"),
                json.dumps(r.get("req_headers") or {}),
                (r.get("req_body") or "")[:4096],
                r.get("payload", ""),
                r.get("parameter", ""),
                r.get("vuln_type", ""),
                r.get("status_code", 0),
                json.dumps(r.get("resp_headers") or {}),
                (r.get("resp_body") or "")[:8192],
                round(float(r.get("resp_time_ms") or 0), 2),
                r.get("content_length", 0),
                int(r.get("is_baseline", False)),
                int(r.get("is_finding", False)),
                r.get("finding_id"),
                json.dumps(r.get("grep_matches") or []),
                r.get("baseline_diff", 0),
            ))
        try:
            self.sql.executemany(
                """INSERT OR IGNORE INTO raw_requests
                   (request_id,scan_id,ts,source,url,method,req_headers,req_body,
                    payload,parameter,vuln_type,status_code,resp_headers,resp_body,
                    resp_time_ms,content_length,is_baseline,is_finding,finding_id,
                    grep_matches,baseline_diff)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                params,
            )
            self.sql.commit()
        except Exception as e:
            log.debug("[DB] bulk_store_raw_requests error: %s", e)

    def get_raw_requests(self, scan_id: Optional[str] = None,
                         source: Optional[str] = None,
                         vuln_type: Optional[str] = None,
                         is_finding: Optional[bool] = None,
                         status_code: Optional[int] = None,
                         url_contains: Optional[str] = None,
                         limit: int = 500,
                         offset: int = 0) -> List[dict]:
        """Query raw requests with flexible filters."""
        clauses, params = [], []
        if scan_id:
            clauses.append("scan_id=?"); params.append(scan_id)
        if source:
            clauses.append("source=?"); params.append(source)
        if vuln_type:
            clauses.append("vuln_type=?"); params.append(vuln_type)
        if is_finding is not None:
            clauses.append("is_finding=?"); params.append(int(is_finding))
        if status_code is not None:
            clauses.append("status_code=?"); params.append(status_code)
        if url_contains:
            clauses.append("url LIKE ?"); params.append(f"%{url_contains}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.sql.fetchall(
            f"SELECT * FROM raw_requests {where} ORDER BY ts DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        result = []
        for r in rows:
            d = dict(r)
            for k in ("req_headers", "resp_headers", "grep_matches"):
                try:
                    d[k] = json.loads(d.get(k) or "{}" if k != "grep_matches" else "[]")
                except Exception:
                    d[k] = {} if k != "grep_matches" else []
            result.append(d)
        return result

    def get_raw_request(self, request_id: str) -> Optional[dict]:
        row = self.sql.fetchone("SELECT * FROM raw_requests WHERE request_id=?", (request_id,))
        if not row:
            return None
        d = dict(row)
        for k in ("req_headers", "resp_headers", "grep_matches"):
            try:
                d[k] = json.loads(d.get(k) or "{}" if k != "grep_matches" else "[]")
            except Exception:
                d[k] = {} if k != "grep_matches" else []
        return d

    def replay_request(self, request_id: str, override_payload: Optional[str] = None,
                       override_headers: Optional[dict] = None,
                       scan_id: Optional[str] = None) -> Optional[dict]:
        """
        Re-fire a stored raw request. Optionally substitute a new payload or headers.
        Returns a new raw_request dict (stored as source='replay') with the live response.
        """
        import requests as _req_lib
        import urllib3
        urllib3.disable_warnings()

        stored = self.get_raw_request(request_id)
        if not stored:
            return {"error": f"request_id {request_id} not found"}

        url     = stored["url"]
        method  = stored.get("method", "GET")
        headers = dict(stored.get("req_headers") or {})
        body    = stored.get("req_body", "")
        payload = stored.get("payload", "")

        # Apply overrides
        if override_payload is not None:
            # Substitute the original payload with the new one in the URL and body
            if payload and payload in url:
                url = url.replace(payload, override_payload, 1)
            if payload and payload in (body or ""):
                body = body.replace(payload, override_payload, 1)
            payload = override_payload
        if override_headers:
            headers.update(override_headers)

        # Remove headers that break requests
        for h in ("Content-Length", "Transfer-Encoding", "Host"):
            headers.pop(h, None)
            headers.pop(h.lower(), None)

        try:
            import time as _time
            t0   = _time.monotonic()
            resp = _req_lib.request(
                method, url,
                headers=headers,
                data=body if method not in ("GET", "HEAD") else None,
                timeout=15,
                verify=False,
                allow_redirects=False,
            )
            elapsed = (_time.monotonic() - t0) * 1000
            resp_body    = resp.text[:8192] if resp.text else ""
            resp_headers = dict(resp.headers)
            sid = scan_id or stored.get("scan_id", "")
            new_id = self.store_raw_request(
                scan_id      = sid,
                source       = "replay",
                url          = url,
                method       = method,
                req_headers  = headers,
                req_body     = body,
                payload      = payload,
                parameter    = stored.get("parameter", ""),
                vuln_type    = stored.get("vuln_type", ""),
                status_code  = resp.status_code,
                resp_headers = resp_headers,
                resp_body    = resp_body,
                resp_time_ms = elapsed,
                content_length = len(resp.content),
            )
            return {
                "request_id":   new_id,
                "replayed_from": request_id,
                "url":          url,
                "method":       method,
                "payload":      payload,
                "status_code":  resp.status_code,
                "resp_time_ms": round(elapsed, 2),
                "content_length": len(resp.content),
                "resp_body":    resp_body,
                "resp_headers": resp_headers,
            }
        except Exception as e:
            log.debug("[DB] replay_request error: %s", e)
            return {"error": str(e)}

    def get_raw_request_stats(self, scan_id: Optional[str] = None) -> dict:
        """Summary stats for raw_requests."""
        where = "WHERE scan_id=?" if scan_id else ""
        params = [scan_id] if scan_id else []
        stats = {}
        for col, label in [("COUNT(*)", "total"), ("SUM(is_finding)", "findings"),
                            ("SUM(is_baseline)", "baselines"), ("AVG(resp_time_ms)", "avg_resp_ms")]:
            try:
                r = self.sql.fetchone(f"SELECT {col} FROM raw_requests {where}", params)
                stats[label] = round(r[0] or 0, 2) if r else 0
            except Exception:
                stats[label] = 0
        for src in ("fuzzer", "intruder", "crawler", "replay", "manual"):
            try:
                r = self.sql.fetchone(f"SELECT COUNT(*) FROM raw_requests {where}{'AND' if where else 'WHERE'} source=?",
                                      params + [src])
                stats[f"source_{src}"] = r[0] if r else 0
            except Exception:
                stats[f"source_{src}"] = 0
        # Most fuzzed vuln type
        try:
            r = self.sql.fetchone(
                f"SELECT vuln_type, COUNT(*) as c FROM raw_requests {where} GROUP BY vuln_type ORDER BY c DESC LIMIT 1",
                params)
            stats["top_vuln_type"] = r[0] if r else ""
        except Exception:
            stats["top_vuln_type"] = ""
        return stats

    # ══════════════════════════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════════════════════════
    # Payload Library — normalized (one row per payload, FTS search)
    # ══════════════════════════════════════════════════════════════════════════

    def _ensure_list(self, name: str, category: str = "custom",
                     description: str = "", source: str = "custom") -> None:
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.sql.exec_commit(
                "INSERT OR IGNORE INTO payload_library (name,category,description,count,source,created_at,updated_at) "
                "VALUES (?,?,?,0,?,?,?)",
                (name, category, description, source, now, now),
            )
        except Exception:
            pass

    # ── List-level operations ───────────────────────────────────────────────────

    def upsert_payload_list(self, name: str, payloads: list,
                            category: str = "custom", description: str = "",
                            source: str = "custom") -> None:
        """Replace a payload list with new payloads (deletes existing rows, inserts new)."""
        now = datetime.now(timezone.utc).isoformat()
        self._ensure_list(name, category, description, source)
        # Delete existing payloads for this list
        try:
            self.sql.exec_commit("DELETE FROM payloads WHERE list_name=?", (name,))
        except Exception:
            pass
        # Bulk insert new payloads
        rows = [(name, p, category, now, source) for p in payloads if p and str(p).strip()]
        try:
            self.sql.executemany(
                "INSERT OR IGNORE INTO payloads (list_name,payload,category,created_at,source) "
                "VALUES (?,?,?,?,?)",
                rows,
            )
            self.sql.commit()
        except Exception as e:
            log.debug("[DB] upsert_payload_list insert error: %s", e)

    def get_payload_list(self, name: str) -> Optional[list]:
        """Return all payload strings for a named list."""
        row = self.sql.fetchone("SELECT name FROM payload_library WHERE name=?", (name,))
        if not row:
            return None
        rows = self.sql.fetchall(
            "SELECT payload FROM payloads WHERE list_name=? ORDER BY hit_count DESC, id ASC",
            (name,),
        )
        return [r[0] for r in rows]

    def list_payload_libraries(self, category: Optional[str] = None) -> List[dict]:
        if category:
            rows = self.sql.fetchall(
                "SELECT name,category,description,count,source,created_at,updated_at "
                "FROM payload_library WHERE category=? ORDER BY category,name",
                (category,),
            )
        else:
            rows = self.sql.fetchall(
                "SELECT name,category,description,count,source,created_at,updated_at "
                "FROM payload_library ORDER BY category,name",
            )
        return [dict(r) for r in rows]

    def append_payloads(self, name: str, new_payloads: list,
                        source: str = "custom") -> int:
        """Append payloads to an existing list (deduped at DB level). Returns new count."""
        self._ensure_list(name)
        now = datetime.now(timezone.utc).isoformat()
        rows = [(name, str(p).strip(), now, source) for p in new_payloads if p and str(p).strip()]
        try:
            self.sql.executemany(
                "INSERT OR IGNORE INTO payloads (list_name,payload,created_at,source) VALUES (?,?,?,?)",
                rows,
            )
            self.sql.commit()
        except Exception as e:
            log.debug("[DB] append_payloads error: %s", e)
        row = self.sql.fetchone("SELECT COUNT(*) FROM payloads WHERE list_name=?", (name,))
        return row[0] if row else 0

    def delete_payload_list(self, name: str) -> bool:
        try:
            # CASCADE deletes all payloads rows via FK
            self.sql.exec_commit("DELETE FROM payload_library WHERE name=?", (name,))
            return True
        except Exception:
            return False

    # ── Individual payload CRUD ─────────────────────────────────────────────────

    def add_payload(self, list_name: str, payload: str,
                    tags: Optional[list] = None, source: str = "custom") -> Optional[int]:
        """Add a single payload to a list. Returns the new row id, or None if duplicate."""
        self._ensure_list(list_name, source=source)
        now = datetime.now(timezone.utc).isoformat()
        try:
            if self._is_postgres:
                return self.sql.insert_returning_id(
                    "INSERT INTO payloads (list_name,payload,category,tags,created_at,source) "
                    "SELECT %s,%s,category,%s,%s,%s FROM payload_library WHERE name=%s "
                    "ON CONFLICT (list_name, payload) DO NOTHING RETURNING id",
                    (list_name, payload.strip(), json.dumps(tags or []), now, source, list_name),
                )
            cur = self.sql.execute(
                "INSERT OR IGNORE INTO payloads (list_name,payload,category,tags,created_at,source) "
                "SELECT ?,?,category,?,?,? FROM payload_library WHERE name=?",
                (list_name, payload.strip(), json.dumps(tags or []), now, source, list_name),
            )
            self.sql.commit()
            return cur.lastrowid if cur.rowcount else None
        except Exception as e:
            log.debug("[DB] add_payload error: %s", e)
            return None

    def update_payload(self, payload_id: int, payload: Optional[str] = None,
                       tags: Optional[list] = None, list_name: Optional[str] = None) -> bool:
        """Edit a payload's text, tags, or move it to another list."""
        sets, params = [], []
        if payload is not None:
            sets.append("payload=?"); params.append(payload.strip())
        if tags is not None:
            sets.append("tags=?"); params.append(json.dumps(tags))
        if list_name is not None:
            sets.append("list_name=?"); params.append(list_name)
        if not sets:
            return False
        params.append(payload_id)
        try:
            self.sql.exec_commit(
                f"UPDATE payloads SET {', '.join(sets)} WHERE id=?", params)
            return True
        except Exception:
            return False

    def delete_payload(self, payload_id: int) -> bool:
        try:
            self.sql.exec_commit("DELETE FROM payloads WHERE id=?", (payload_id,))
            return True
        except Exception:
            return False

    def get_payload(self, payload_id: int) -> Optional[dict]:
        row = self.sql.fetchone("SELECT * FROM payloads WHERE id=?", (payload_id,))
        if not row:
            return None
        d = dict(row)
        try:
            d["tags"] = json.loads(d.get("tags") or "[]")
        except Exception:
            d["tags"] = []
        return d

    def bump_hit_count(self, payload_text: str, list_name: Optional[str] = None) -> None:
        """Increment hit_count for a payload when it triggers a confirmed finding."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            if list_name:
                self.sql.exec_commit(
                    "UPDATE payloads SET hit_count=hit_count+1, last_used=? "
                    "WHERE list_name=? AND payload=?",
                    (now, list_name, payload_text),
                )
            else:
                self.sql.exec_commit(
                    "UPDATE payloads SET hit_count=hit_count+1, last_used=? WHERE payload=?",
                    (now, payload_text),
                )
        except Exception:
            pass

    # ── Query + search ──────────────────────────────────────────────────────────

    def search_payloads(self, q: str, category: Optional[str] = None,
                        list_name: Optional[str] = None,
                        source: Optional[str] = None,
                        sort: str = "hit_count",
                        limit: int = 100, offset: int = 0) -> List[dict]:
        """
        Full-text + LIKE search across all payloads.
        sort: hit_count (most effective first) | id (insertion order) | payload (alpha)
        """
        q = q.strip() if q else ""
        clauses, params = [], []

        if list_name:
            clauses.append("p.list_name=?"); params.append(list_name)
        if category:
            clauses.append("p.category=?"); params.append(category)
        if source:
            clauses.append("p.source=?"); params.append(source)

        if q:
            # Try FTS5 first; fall back to LIKE if FTS unavailable
            try:
                fts_rows = self.sql.fetchall(
                    "SELECT rowid FROM payloads_fts WHERE payloads_fts MATCH ? LIMIT 2000",
                    (q,),
                )
                ids = [r[0] for r in fts_rows]
                if ids:
                    id_placeholders = ",".join("?" * len(ids))
                    clauses.append(f"p.id IN ({id_placeholders})")
                    params.extend(ids)
                else:
                    return []
            except Exception:
                # FTS not available or no match — fall back to LIKE
                clauses.append("p.payload LIKE ?")
                params.append(f"%{q}%")

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        order_col = {"hit_count": "p.hit_count DESC, p.id ASC",
                     "id": "p.id ASC",
                     "payload": "p.payload ASC"}.get(sort, "p.hit_count DESC")
        rows = self.sql.fetchall(
            f"SELECT p.id, p.list_name, p.payload, p.category, p.tags, "
            f"       p.hit_count, p.last_used, p.created_at, p.source "
            f"FROM payloads p {where} ORDER BY {order_col} LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["tags"] = json.loads(d.get("tags") or "[]")
            except Exception:
                d["tags"] = []
            result.append(d)
        return result

    def get_payloads_page(self, list_name: str, sort: str = "hit_count",
                          limit: int = 50, offset: int = 0) -> List[dict]:
        """Paginated fetch of all payloads in a list."""
        return self.search_payloads("", list_name=list_name, sort=sort,
                                    limit=limit, offset=offset)

    def import_payloads(self, list_name: str, text: str, category: str = "custom",
                        source: str = "imported") -> int:
        """
        Import newline-separated payloads from a text string.
        Handles Burp Suite copy-paste, SecLists format, plain newlines.
        Returns count of new payloads added.
        """
        self._ensure_list(list_name, category=category, source=source)
        lines = []
        for raw in text.splitlines():
            p = raw.strip()
            # Strip BOM, comments, empty lines
            if not p or p.startswith("#") or p.startswith("//"):
                continue
            p = p.lstrip("﻿")
            lines.append(p)
        if not lines:
            return 0
        return self.append_payloads(list_name, lines, source=source)

    def get_payload_stats(self, list_name: Optional[str] = None) -> dict:
        """Aggregate stats about the payload library."""
        where = "WHERE list_name=?" if list_name else ""
        params = [list_name] if list_name else []
        stats: dict = {}
        try:
            r = self.sql.fetchone(f"SELECT COUNT(*) FROM payloads {where}", params)
            stats["total"] = r[0] if r else 0
            r = self.sql.fetchone(f"SELECT COUNT(*) FROM payloads {where}{'AND' if where else 'WHERE'} hit_count>0", params + [])
            stats["effective"] = r[0] if r else 0
            r = self.sql.fetchone(f"SELECT SUM(hit_count) FROM payloads {where}", params)
            stats["total_hits"] = r[0] or 0 if r else 0
            rows = self.sql.fetchall(
                f"SELECT category, COUNT(*) as c FROM payloads {where} GROUP BY category ORDER BY c DESC",
                params,
            )
            stats["by_category"] = {r[0]: r[1] for r in rows}
            rows = self.sql.fetchall(
                f"SELECT payload, hit_count FROM payloads {where} ORDER BY hit_count DESC LIMIT 5",
                params,
            )
            stats["top_effective"] = [{"payload": r[0], "hits": r[1]} for r in rows if r[1] > 0]
        except Exception as e:
            log.debug("[DB] get_payload_stats error: %s", e)
        return stats

    # ── Seed built-in payloads (migrates from old JSON-blob schema) ────────────

    def _migrate_payload_library_schema(self) -> None:
        """
        One-time migration: drop the old JSON-blob `payloads` column from payload_library.
        Postgres: ALTER TABLE DROP COLUMN IF EXISTS.
        SQLite: recreate the table (no DROP COLUMN before 3.35).
        """
        try:
            if self._is_postgres:
                row = self.sql.fetchone(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='payload_library' AND column_name='payloads'"
                )
                if not row:
                    return
                self.sql.exec_commit("ALTER TABLE payload_library DROP COLUMN IF EXISTS payloads")
                log.info("[DB:Postgres] Migrated payload_library: removed legacy JSON-blob column")
                return
            # SQLite path
            con = self.sql._conn()
            cols = {r[1] for r in con.execute("PRAGMA table_info(payload_library)").fetchall()}
            if "payloads" not in cols:
                return
            con.execute("PRAGMA foreign_keys = OFF")
            con.executescript("""
                CREATE TABLE IF NOT EXISTS _pl_new (
                    name        TEXT PRIMARY KEY,
                    category    TEXT NOT NULL DEFAULT 'custom',
                    description TEXT,
                    count       INTEGER DEFAULT 0,
                    source      TEXT DEFAULT 'builtin',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );
                INSERT OR IGNORE INTO _pl_new (name,category,description,count,source,created_at,updated_at)
                    SELECT name,category,COALESCE(description,''),0,source,created_at,updated_at
                    FROM payload_library;
                DROP TABLE payload_library;
            """)
            con.execute("ALTER TABLE _pl_new RENAME TO payload_library")
            con.execute("CREATE INDEX IF NOT EXISTS idx_paylib_category ON payload_library(category)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_paylib_source ON payload_library(source)")
            con.execute("PRAGMA foreign_keys = ON")
            con.commit()
            log.info("[DB] Migrated payload_library: removed legacy JSON-blob payloads column")
        except Exception as e:
            log.warning("[DB] payload_library migration error: %s", e)

    def seed_builtin_payloads(self) -> int:
        """
        Seed payload_library + payloads tables from built-in fuzzer PAYLOADS dict.
        Runs one-time schema migration first (drops old JSON-blob column).
        Skips lists that already exist in the new normalized schema.
        Returns count of lists seeded.
        """
        self._migrate_payload_library_schema()
        try:
            from modules.fuzzer import PAYLOADS as _fp
        except Exception:
            return 0
        cat_map = {
            "sqli": "sqli", "xss": "xss", "lfi": "lfi", "cmdi": "cmdi",
            "ssti": "ssti", "ssrf": "ssrf", "xxe": "xxe", "csrf": "csrf",
            "cors": "cors", "idor": "idor", "open_redirect": "openredirect",
            "header": "header", "smuggling": "smuggling",
        }
        seeded = 0
        for name, payloads in _fp.items():
            if not payloads:
                continue
            existing = self.sql.fetchone(
                "SELECT COUNT(*) FROM payloads WHERE list_name=?", (name,))
            if existing and existing[0] > 0:
                continue  # already normalized
            cat = "custom"
            for kw, c in cat_map.items():
                if kw in name:
                    cat = c; break
            self.upsert_payload_list(
                name, list(payloads), category=cat,
                description=f"Built-in {name} payloads ({len(payloads)} items)",
                source="builtin",
            )
            seeded += 1
        log.info("[DB] Seeded/migrated %d payload lists into normalized schema", seeded)
        return seeded

    def get_db_stats(self) -> dict:
        """Summary of what the DB currently holds."""
        stats = {}
        for table in ("scans", "findings", "evidence", "scan_metrics",
                      "dedup_cache", "raw_requests", "payload_library",
                      "finding_comments", "tested_endpoints", "scan_audit_log"):
            try:
                row = self.sql.fetchone(f"SELECT COUNT(*) FROM {table}")
                stats[table] = row[0] if row else 0
            except Exception:
                stats[table] = -1
        # Raw request breakdown by source
        for src in ("fuzzer", "intruder", "crawler", "replay"):
            try:
                r = self.sql.fetchone(f"SELECT COUNT(*) FROM raw_requests WHERE source=?", (src,))
                stats[f"raw_{src}"] = r[0] if r else 0
            except Exception:
                stats[f"raw_{src}"] = 0
        stats["redis_available"] = self.redis.available
        if self._is_postgres:
            stats["db_backend"] = "postgresql"
        else:
            stats["db_path"]    = str(_DB_PATH)
            stats["db_size_mb"] = round(_DB_PATH.stat().st_size / 1_048_576, 2) if _DB_PATH.exists() else 0
        return stats


# ── Singleton instance ─────────────────────────────────────────────────────────
db = DASTDatabase()
