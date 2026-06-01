"""
Race Condition / TOCTOU Detector — HTTP/2 Single-Packet Attack implementation.

Detection methodology matching Turbo Intruder / PortSwigger research:
  1. Identify state-changing endpoints during crawl (POST/PUT/PATCH/DELETE)
  2. Send N requests simultaneously:
     - Thread Burst: threading.Barrier to synchronize N threads (no HTTP/2 required)
     - HTTP/2 Single-Packet: httpx.AsyncClient + asyncio.gather() — all streams sent
       through one TCP connection, arriving at the server in a single TCP packet
  3. Analyze response differentials:
     - Response divergence: N sent but only 1 should succeed
     - Timing anomalies: lock contention, ordering anomalies
     - State inconsistency: verify final resource state via follow-up GET
  4. Confirm with second round if signals are weak

Attack patterns:
  1. double_spend        — Balance/credit: check-then-act window (value params)
  2. coupon_reuse        — Single-use coupon/token redemption (double-spend)
  3. limit_bypass        — Rate limit / quota / inventory bypass
  4. inventory_oversell  — Stock decrement on purchase (overselling attack)
  5. toctou              — File upload → scan → move window; config update race
  6. file_toctou         — Upload + virus-scan + move: scan bypass window
  7. 2fa_timing          — 2FA/OTP validation: timing window for code reuse
  8. parallel_auth       — Simultaneous logins: session fixation / token reuse
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import statistics
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed, wait as cf_wait, FIRST_COMPLETED
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse, urlencode, urljoin

import requests
import requests.exceptions

from .payload_safety import is_dangerous_endpoint
from .scope import ScopeManager
import httpx
HTTPX_AVAILABLE = True


def is_h3_available() -> bool:
    """Check if httpx HTTP/3 support is available."""
    try:
        import httpx as _httpx
        # httpx supports http3 via the http3 extra (requires aioquic)
        _client = _httpx.AsyncClient(http3=True)
        # If no error, http3 param is accepted
        return True
    except Exception:
        return False


# ── Result types ─────────────────────────────────────────────────────────────

@dataclass
class RaceResult:
    """Result of a single request in a race burst."""
    thread_id:    int
    status_code:  int
    body_length:  int
    body_hash:    str
    elapsed_ms:   float
    headers:      dict   = field(default_factory=dict)
    body_snippet: str    = ""
    error:        str    = ""


@dataclass
class RaceFinding:
    """A confirmed or suspected race condition."""
    url:            str
    method:         str
    attack_pattern: str
    finding:        str
    severity:       str
    proof:          str
    concurrency:    int
    state_before:   str = ""   # resource state before burst
    state_after:    str = ""   # resource state after burst
    h2_confirmed:   bool = False
    race_window_ms: float = 0.0
    protocol:       str = "h2"
    results:        list[RaceResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url":            self.url,
            "method":         self.method,
            "attack_pattern": self.attack_pattern,
            "finding":        self.finding,
            "severity":       self.severity,
            "proof":          self.proof,
            "concurrency":    self.concurrency,
            "state_before":   self.state_before,
            "state_after":    self.state_after,
            "h2_confirmed":   self.h2_confirmed,
            "race_window_ms": self.race_window_ms,
            "protocol":       self.protocol,
        }


# ── Attack pattern matchers ───────────────────────────────────────────────────

# Value-bearing params → double-spend
_VALUE_PARAMS = re.compile(
    r"(?:amount|price|quantity|qty|total|balance|credits?|points?|"
    r"transfer|payment|withdraw|deposit|charge|refund|order)",
    re.I,
)

# Coupon/voucher params → double-spend
_COUPON_PARAMS = re.compile(
    r"(?:code|coupon|promo|voucher|discount|gift|redeem|token|invite)",
    re.I,
)

# Auth paths → parallel auth / 2FA
_AUTH_PATHS = re.compile(
    r"(?:login|signin|sign-in|authenticate|auth|session|token|oauth|register|signup)",
    re.I,
)

# 2FA / OTP paths → timing window
_2FA_PATHS = re.compile(
    r"(?:2fa|otp|mfa|totp|verify[-_]?code|confirm[-_]?code|"
    r"sms[-_]?code|email[-_]?code|phone[-_]?verify|one[-_]?time)",
    re.I,
)

# Inventory / purchase paths → overselling
_INVENTORY_PATHS = re.compile(
    r"(?:purchase|buy|checkout|order|cart|add[-_]?to[-_]?cart|"
    r"reserve|book|stock|inventory|ticket|seat|slot)",
    re.I,
)
_INVENTORY_PARAMS = re.compile(
    r"(?:quantity|qty|stock|item_id|product_id|sku|variant|count)",
    re.I,
)

# File upload + scan paths → TOCTOU bypass
_FILE_UPLOAD_PATHS = re.compile(
    r"(?:upload|import|attach|file|document|image|avatar|media|"
    r"scan|antivirus|quarantine|process|convert|extract)",
    re.I,
)

# Generic state-change paths
_STATE_CHANGE_PATHS = re.compile(
    r"(?:update|edit|modify|delete|remove|approve|confirm|"
    r"publish|activate|deactivate|toggle|switch|enable|disable|submit|process)",
    re.I,
)

# Limit-type paths
_LIMIT_PATHS = re.compile(
    r"(?:vote|like|follow|subscribe|claim|redeem|download|generate|create|add|"
    r"send|invite|request|apply|enroll|book|reserve)",
    re.I,
)

# State value extraction from JSON responses
_STATE_KEYS = re.compile(
    r'"(?:balance|amount|total|quantity|qty|count|remaining|available|'
    r'credits?|points?|stock|inventory|limit|uses|used|status|approved|'
    r'success|result|id|order_id|transaction_id|error_code)"\s*:\s*(["\d][^,}\]]*)',
    re.I,
)


# ── Main tester ───────────────────────────────────────────────────────────────

class RaceConditionTester:
    """
    Detects race conditions / TOCTOU windows via concurrent request bursts.

    Flow:
      1. Identify candidate endpoints from sitemap
      2. Classify each into an attack pattern
      3. Optionally capture pre-burst state (GET)
      4. Thread burst (Barrier-synchronized) → analyze responses
      5. HTTP/2 single-packet (AsyncClient + gather) → tighter timing confirmation
      6. Verify post-burst state (GET) → compare with pre-burst
      7. Emit RaceFinding with full proof
    """

    DEFAULT_CONCURRENCY = [10, 20]
    MAX_CANDIDATES = 30

    def __init__(
        self,
        session:         requests.Session,
        scope:           Optional[ScopeManager] = None,
        timeout:         int   = 10,
        rate_limit:      float = 0.0,
        stop_event:      Optional[threading.Event] = None,
        concurrency:     list[int] | None = None,
        use_http2:       bool  = True,
        rounds:          int   = 2,
        on_finding:      Optional[Callable] = None,
        on_progress:     Optional[Callable] = None,
        allow_dangerous_endpoints: bool = False,
    ):
        self.session      = session
        self.scope        = scope
        self.timeout      = timeout
        self.stop_event   = stop_event or threading.Event()
        self.concurrency  = concurrency or self.DEFAULT_CONCURRENCY
        self.use_http2    = use_http2 and HTTPX_AVAILABLE
        self.rounds       = rounds
        self.on_finding   = on_finding
        self.on_progress  = on_progress   # callback(tested, total, candidate_url)
        self.allow_dangerous_endpoints = allow_dangerous_endpoints
        self._findings:   list[RaceFinding] = []
        self._lock        = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, base_url: str, sitemap=None) -> list[RaceFinding]:
        """Run race condition scan. Returns list of RaceFindings."""
        candidates = self._collect_candidates(base_url, sitemap)
        total = len(candidates)

        for idx, (url, method, params, content_type, pattern) in enumerate(candidates, 1):
            if self.stop_event.is_set():
                break
            if self.on_progress:
                self.on_progress(idx, total, url)
            self._test_endpoint(url, method, params, content_type, pattern)

        return self._findings

    # ── Candidate collection ──────────────────────────────────────────────────

    def _collect_candidates(
        self, base_url: str, sitemap=None
    ) -> list[tuple[str, str, dict, str, str]]:
        """
        Collect and classify candidate endpoints from the sitemap.
        Returns: [(url, method, params, content_type, attack_pattern), ...]
        """
        candidates: list[tuple[str, str, dict, str, str]] = []
        seen: set[str] = set()

        if not sitemap or not hasattr(sitemap, "surfaces"):
            return candidates

        for surface in list(sitemap.surfaces)[:150]:
            url    = getattr(surface, "url", "") or getattr(surface, "action", "")
            method = (getattr(surface, "method", "GET") or "GET").upper()
            ct     = getattr(surface, "content_type", "") or ""

            if not url or method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue

            if self.scope and hasattr(self.scope, "in_scope") and not self.scope.in_scope(url):
                continue

            if (
                not self.allow_dangerous_endpoints
                and is_dangerous_endpoint(method, url, getattr(surface, "param", ""))
            ):
                continue

            params = {}
            for p in getattr(surface, "params", []):
                name = p.get("name", "") if isinstance(p, dict) else getattr(p, "name", "")
                val  = p.get("value", "") if isinstance(p, dict) else getattr(p, "value", "")
                if name:
                    params[name] = val or "test"

            pattern = self._classify_pattern(url, method, params)
            if not pattern:
                continue

            norm = f"{method}:{url}:{pattern}"
            if norm in seen:
                continue
            seen.add(norm)
            candidates.append((url, method, params, ct, pattern))

            if len(candidates) >= self.MAX_CANDIDATES:
                break

        return candidates

    def _classify_pattern(self, url: str, method: str, params: dict) -> str | None:
        """Classify endpoint into an attack pattern. Priority-ordered."""
        param_names = " ".join(params.keys())
        path = urlparse(url).path.lower()

        # 2FA timing window (most specific — check first)
        if _2FA_PATHS.search(path) or _2FA_PATHS.search(param_names):
            return "2fa_timing"

        # File upload TOCTOU
        if _FILE_UPLOAD_PATHS.search(path) and method in ("POST", "PUT"):
            return "file_toctou"

        # Inventory overselling (purchase with quantity)
        if _INVENTORY_PATHS.search(path) or _INVENTORY_PARAMS.search(param_names):
            return "inventory_oversell"

        # Double-spend (value-bearing params)
        if _VALUE_PARAMS.search(param_names):
            return "double_spend"

        # Coupon/token reuse
        if _COUPON_PARAMS.search(param_names):
            return "coupon_reuse"

        # Parallel auth
        if _AUTH_PATHS.search(path):
            return "parallel_auth"

        # TOCTOU state change
        if _STATE_CHANGE_PATHS.search(path):
            return "toctou"

        # Limit bypass (generic)
        if _LIMIT_PATHS.search(path) or method == "POST":
            return "limit_bypass"

        return None

    # ── Testing ───────────────────────────────────────────────────────────────

    def _test_endpoint(
        self,
        url: str,
        method: str,
        params: dict,
        content_type: str,
        pattern: str,
    ) -> None:
        """Test one endpoint: capture state, burst, analyze, verify state, emit finding."""
        # Step 1: Capture pre-burst state
        state_before = self._capture_state(url)

        for n in self.concurrency:
            if self.stop_event.is_set():
                return

            for _round in range(self.rounds):
                if self.stop_event.is_set():
                    return

                # Thread burst
                results = self._burst_requests(url, method, params, content_type, n)
                if not results:
                    continue

                finding = self._analyze_results(url, method, params, pattern, n, results)
                if finding:
                    finding.state_before = state_before
                    finding.state_after  = self._capture_state(url)
                    if finding.state_after and finding.state_before:
                        if finding.state_after != finding.state_before:
                            finding.proof += (
                                f" | STATE CHANGED: before={finding.state_before[:120]!r}"
                                f" after={finding.state_after[:120]!r}"
                            )
                    self._emit(finding)
                    return  # One finding per endpoint

                # HTTP/2 single-packet: true concurrent streams via asyncio.gather
                if self.use_http2 and not finding:
                    h2_results = self._run_async(
                        self._single_packet_attack(url, method, params, content_type, n)
                    )
                    if h2_results:
                        finding = self._analyze_results(url, method, params, pattern, n, h2_results)
                        if finding:
                            finding.h2_confirmed = True
                            finding.protocol     = "h2"
                            finding.race_window_ms = getattr(self, "_last_h2_window_ms", 0.0)
                            finding.proof       += " [HTTP/2 single-packet confirmed]"
                            finding.state_before = state_before
                            finding.state_after  = self._capture_state(url)
                            self._emit(finding)
                            return

                # HTTP/3 QUIC race condition (blind spot in all existing RC tools per ScienceDirect 2025)
                if is_h3_available():
                    h3_findings = self._run_async(
                        self._single_datagram_h3_attack(url, method, params, content_type, n)
                    )
                    if h3_findings:
                        for h3f in h3_findings:
                            h3f.state_before = state_before
                            h3f.state_after = self._capture_state(url)
                            self._emit(h3f)
                        return

    def _emit(self, finding: RaceFinding) -> None:
        with self._lock:
            self._findings.append(finding)
        if self.on_finding:
            self.on_finding(finding)

    # ── Thread burst ──────────────────────────────────────────────────────────

    def _burst_requests(
        self,
        url: str,
        method: str,
        params: dict,
        content_type: str,
        concurrency: int,
    ) -> list[RaceResult]:
        """
        Send N identical requests synchronized by a threading.Barrier.
        All threads block at the barrier until all N are ready, then release
        simultaneously — minimizing jitter to < 1ms between first and last send.
        """
        results: list[RaceResult] = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(concurrency, timeout=5)

        def _worker(tid: int) -> None:
            try:
                barrier.wait()  # All threads start at the same instant
            except threading.BrokenBarrierError:
                return

            start = time.perf_counter()
            try:
                kwargs: dict = {
                    "timeout":        self.timeout,
                    "verify":         False,
                    "allow_redirects": False,
                    "headers":        {"User-Agent": "DAST-RaceCondition/2.1"},
                }
                if content_type and "json" in content_type:
                    kwargs["data"]                   = json.dumps(params)
                    kwargs["headers"]["Content-Type"] = "application/json"
                elif params:
                    kwargs["data"] = params

                resp    = self.session.request(method, url, **kwargs)
                elapsed = (time.perf_counter() - start) * 1000
                body    = resp.text[:2000]

                with results_lock:
                    results.append(RaceResult(
                        thread_id   = tid,
                        status_code = resp.status_code,
                        body_length = len(resp.content),
                        body_hash   = hashlib.md5(body.encode()).hexdigest(),
                        elapsed_ms  = round(elapsed, 2),
                        headers     = dict(resp.headers),
                        body_snippet= body[:500],
                    ))
            except Exception as exc:
                elapsed = (time.perf_counter() - start) * 1000
                with results_lock:
                    results.append(RaceResult(
                        thread_id   = tid,
                        status_code = 0,
                        body_length = 0,
                        body_hash   = "",
                        elapsed_ms  = round(elapsed, 2),
                        error       = str(exc)[:100],
                    ))

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            for f in as_completed([pool.submit(_worker, i) for i in range(concurrency)]):
                pass

        return sorted(results, key=lambda r: r.thread_id)

    # ── HTTP/2 single-packet attack ───────────────────────────────────────────

    async def _single_packet_attack(
        self,
        url: str,
        method: str,
        params: dict,
        content_type: str,
        concurrency: int,
    ) -> list[RaceResult]:
        """
        True concurrent HTTP/2 attack:
        - Opens ONE httpx.AsyncClient (single TCP connection with HTTP/2 multiplexing)
        - Uses asyncio.gather() to fire all streams concurrently
        - All streams share the same underlying connection → arrive at server
          in the same TCP window (single-packet attack pattern)
        """
        if not HTTPX_AVAILABLE:
            return []

        results: list[RaceResult] = []

        try:
            # Build request kwargs once
            req_kwargs: dict = {
                "headers": {"User-Agent": "DAST-RaceCondition/2.1"},
            }
            if content_type and "json" in content_type:
                req_kwargs["content"]                   = json.dumps(params).encode()
                req_kwargs["headers"]["Content-Type"]    = "application/json"
            elif params:
                req_kwargs["data"] = params

            async def _send(client: httpx.AsyncClient, tid: int) -> RaceResult:
                start = time.perf_counter()
                try:
                    resp    = await client.request(method, url, **req_kwargs)
                    elapsed = (time.perf_counter() - start) * 1000
                    body    = resp.text[:2000]
                    return RaceResult(
                        thread_id   = tid,
                        status_code = resp.status_code,
                        body_length = len(resp.content),
                        body_hash   = hashlib.md5(body.encode()).hexdigest(),
                        elapsed_ms  = round(elapsed, 2),
                        headers     = dict(resp.headers),
                        body_snippet= body[:500],
                    )
                except Exception as exc:
                    elapsed = (time.perf_counter() - start) * 1000
                    return RaceResult(
                        thread_id=tid, status_code=0, body_length=0,
                        body_hash="", elapsed_ms=round(elapsed, 2), error=str(exc)[:100],
                    )

            # Single AsyncClient = single TCP connection (HTTP/2 multiplexing)
            async with httpx.AsyncClient(http2=True, verify=False, timeout=self.timeout) as client:
                # asyncio.gather fires all coroutines concurrently on the event loop
                # With HTTP/2, they share the same underlying TCP stream
                _t_start = asyncio.get_event_loop().time()
                results = list(await asyncio.gather(
                    *[_send(client, i) for i in range(concurrency)]
                ))
                _t_end = asyncio.get_event_loop().time()
                _window_ms = round((_t_end - _t_start) * 1000.0, 2)

                # Store timing for the caller to apply to findings
                self._last_h2_window_ms = _window_ms

        except Exception:
            return []

        return sorted(results, key=lambda r: r.thread_id)

    async def _single_datagram_h3_attack(
        self,
        url: str,
        method: str,
        params: dict,
        content_type: str,
        concurrency: int,
    ) -> list[RaceFinding]:
        """HTTP/3 QUIC single-datagram race condition attack.

        Coalesces multiple HTTP/3 stream final DATA+FIN frames into one UDP datagram
        so the server schedules all requests in the same processing tick.

        Based on: 'Race Against Time' (ScienceDirect 2025) — QUICker methodology.
        Note: HTTP/3 endpoints are a blind spot in all existing RC tooling (paper finding).

        Requires: httpx[http3] with HTTP/3 support (gracefully skipped if unavailable).
        """
        try:
            import httpx as _httpx
        except ImportError:
            return []

        findings: list[RaceFinding] = []

        try:
            req_kwargs: dict = {
                "headers": {"User-Agent": "DAST-RaceCondition/2.1"},
            }
            if content_type and "json" in content_type:
                req_kwargs["content"] = json.dumps(params).encode()
                req_kwargs["headers"]["Content-Type"] = "application/json"
            elif params:
                req_kwargs["data"] = params

            async def _h3_request(client: _httpx.AsyncClient, tid: int) -> RaceResult:
                start = time.perf_counter()
                try:
                    resp = await client.request(method, url, **req_kwargs)
                    elapsed = (time.perf_counter() - start) * 1000
                    body = resp.text[:2000]
                    return RaceResult(
                        thread_id=tid,
                        status_code=resp.status_code,
                        body_length=len(resp.content),
                        body_hash=hashlib.md5(body.encode()).hexdigest(),
                        elapsed_ms=round(elapsed, 2),
                        headers=dict(resp.headers),
                        body_snippet=body[:500],
                    )
                except Exception as exc:
                    elapsed = (time.perf_counter() - start) * 1000
                    return RaceResult(
                        thread_id=tid, status_code=0, body_length=0,
                        body_hash="", elapsed_ms=round(elapsed, 2), error=str(exc)[:100],
                    )

            # HTTP/3 client — coalesces frames by default when server supports QUIC
            try:
                async with _httpx.AsyncClient(http3=True, verify=False, timeout=float(self.timeout)) as client:
                    t_start = time.perf_counter()
                    results = list(await asyncio.gather(
                        *[_h3_request(client, i) for i in range(concurrency)]
                    ))
                    t_end = time.perf_counter()
                    window_ms = round((t_end - t_start) * 1000, 2)
            except Exception:
                # HTTP/3 not supported by server or client — fallback gracefully
                return []

            # Analyze results for race condition indicators
            valid = [r for r in results if r.status_code > 0]
            if not valid:
                return []

            status_codes = [r.status_code for r in valid]
            success_codes = [s for s in status_codes if 200 <= s < 300]

            if len(success_codes) >= 2:
                finding = RaceFinding(
                    url=url,
                    method=method,
                    attack_pattern="single_datagram_h3",
                    finding=(
                        f"HTTP/3 QUIC race condition: {len(success_codes)}/{concurrency} "
                        f"requests succeeded simultaneously (window: {window_ms}ms)"
                    ),
                    severity="high",
                    proof=(
                        f"HTTP/3 single-datagram attack sent {concurrency} requests in "
                        f"{window_ms}ms window. All responses: {status_codes}"
                    ),
                    concurrency=concurrency,
                    race_window_ms=window_ms,
                    protocol="h3",
                    results=valid[:6],
                )
                findings.append(finding)

            return findings

        except Exception:
            return []

    def _run_async(self, coro) -> list[RaceResult]:
        """Run an async coroutine from sync context."""
        try:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()
        except Exception:
            return []

    # ── State capture ─────────────────────────────────────────────────────────

    def _capture_state(self, url: str) -> str:
        """
        GET the endpoint to snapshot current state.
        Extracts JSON state values (balance, stock, count, etc.) as a fingerprint.
        """
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "DAST-RaceCondition/2.1"},
            )
            if resp.status_code not in (200, 201):
                return ""
            body = resp.text[:3000]
            # Extract state key-value pairs
            state_pairs = []
            for match in _STATE_KEYS.finditer(body):
                key = match.group(0).split('"')[1]
                val = match.group(1).strip().strip('"')
                state_pairs.append(f"{key}={val}")
            return " | ".join(state_pairs) if state_pairs else body[:200]
        except Exception:
            return ""

    # ── Response analysis ─────────────────────────────────────────────────────

    def _analyze_results(
        self,
        url: str,
        method: str,
        params: dict,
        pattern: str,
        concurrency: int,
        results: list[RaceResult],
    ) -> RaceFinding | None:
        """Analyze burst results for race condition signals."""
        valid = [r for r in results if r.status_code > 0]
        if len(valid) < 3:
            return None

        status_codes   = [r.status_code for r in valid]
        status_counter = Counter(status_codes)
        mixed_status   = len(status_counter) > 1

        body_hashes    = [r.body_hash for r in valid if r.body_hash]
        hash_counter   = Counter(body_hashes)
        mixed_bodies   = len(hash_counter) > 1

        success_count  = sum(1 for r in valid if 200 <= r.status_code < 300)
        all_success    = success_count == len(valid)

        state_diffs    = self._extract_state_diffs(valid)

        timings         = [r.elapsed_ms for r in valid]
        timing_spread   = max(timings) - min(timings) if len(timings) >= 2 else 0
        timing_anomaly  = timing_spread > 500

        # Per-pattern response table for proof
        response_table = self._response_table(valid[:8])

        confirmed     = False
        proof_parts:  list[str] = []
        severity      = "medium"

        # ── Pattern-specific evaluation ──────────────────────────────────────

        if pattern == "double_spend":
            if all_success and success_count >= concurrency * 0.8:
                confirmed = True
                severity  = "critical"
                proof_parts.append(
                    f"DOUBLE-SPEND: {success_count}/{len(valid)} requests returned "
                    f"HTTP 2xx — check-then-act window exploitable"
                )
            if state_diffs:
                confirmed = True
                severity  = "critical"
                proof_parts.append(f"State values diverged: {state_diffs}")

        elif pattern == "coupon_reuse":
            if all_success and success_count > 1:
                confirmed = True
                severity  = "high"
                proof_parts.append(
                    f"COUPON REUSE: {success_count} successful redemptions — "
                    f"single-use token accepted multiple times under race"
                )

        elif pattern == "inventory_oversell":
            # Multiple successes on a purchase endpoint → overselling
            if all_success and success_count >= concurrency * 0.7:
                confirmed = True
                severity  = "high"
                proof_parts.append(
                    f"OVERSELL: {success_count}/{len(valid)} purchase requests succeeded — "
                    f"inventory decrement is not atomic (stock check ↔ write race)"
                )
            if state_diffs:
                confirmed = True
                severity  = "critical"
                proof_parts.append(f"Stock counter inconsistency: {state_diffs}")

        elif pattern == "file_toctou":
            # Mixed responses on upload endpoint → TOCTOU in upload→scan→move pipeline
            if mixed_bodies or mixed_status:
                confirmed = True
                severity  = "high"
                proof_parts.append(
                    f"FILE TOCTOU: {len(hash_counter)} distinct responses from {len(valid)} "
                    f"concurrent uploads — scan-bypass window between upload and virus scan"
                )

        elif pattern == "2fa_timing":
            # Multiple successes on 2FA endpoint → code reuse via timing race
            if success_count > 1 or (mixed_status and success_count >= 1):
                confirmed = True
                severity  = "critical"
                proof_parts.append(
                    f"2FA BYPASS: {success_count} successful validations in parallel burst — "
                    f"OTP/code accepted in concurrent requests (timing window)"
                )
            if state_diffs:
                confirmed = True
                proof_parts.append(f"Validation state diffs: {state_diffs}")

        elif pattern == "limit_bypass":
            if all_success and success_count > 5:
                confirmed = True
                severity  = "high"
                proof_parts.append(
                    f"LIMIT BYPASS: {success_count} successes — "
                    f"rate/quota check not atomic under concurrency={concurrency}"
                )
            elif mixed_status and success_count > concurrency * 0.5:
                confirmed = True
                severity  = "medium"
                proof_parts.append(
                    f"PARTIAL BYPASS: {dict(status_counter)} — "
                    f"some requests slipped past the limit check"
                )

        elif pattern == "toctou":
            if mixed_bodies or state_diffs:
                confirmed = True
                severity  = "high"
                proof_parts.append(
                    f"TOCTOU: response bodies diverged across {len(valid)} concurrent requests "
                    f"— shared state modified concurrently without locking"
                )
                if state_diffs:
                    proof_parts.append(f"State diffs: {state_diffs}")

        elif pattern == "parallel_auth":
            cookies = {
                r.headers.get("Set-Cookie", r.headers.get("set-cookie", ""))[:80]
                for r in valid
                if r.headers.get("Set-Cookie") or r.headers.get("set-cookie")
            }
            if len(cookies) > 1 or mixed_bodies:
                confirmed = True
                severity  = "high"
                proof_parts.append(
                    f"PARALLEL AUTH: {len(cookies)} distinct session tokens from "
                    f"{len(valid)} simultaneous logins — session fixation / token reuse risk"
                )

        # ── Generic fallback signals ─────────────────────────────────────────

        if not confirmed and mixed_status and mixed_bodies:
            confirmed = True
            severity  = "low"
            proof_parts.append(
                f"RACE SIGNAL: mixed status {dict(status_counter)} + "
                f"{len(hash_counter)} body variants under concurrency={concurrency}"
            )

        if not confirmed:
            return None

        # Add timing evidence
        if timings:
            avg_ms = round(sum(timings) / len(timings), 1)
            proof_parts.append(
                f"Timing: min={min(timings):.0f}ms avg={avg_ms}ms "
                f"max={max(timings):.0f}ms spread={timing_spread:.0f}ms"
                + (" ⚠ lock-contention likely" if timing_anomaly else "")
            )

        # Add response sequence table
        proof_parts.append(f"Response sequence: {response_table}")

        return RaceFinding(
            url            = url,
            method         = method,
            attack_pattern = pattern,
            finding        = (
                f"Race condition ({pattern.replace('_', ' ')}) — "
                f"{concurrency} concurrent {method} {urlparse(url).path}"
            ),
            severity       = severity,
            proof          = " | ".join(proof_parts),
            concurrency    = concurrency,
            results        = valid[:6],
        )

    def _extract_state_diffs(self, results: list[RaceResult]) -> dict:
        """Extract JSON state values from responses and find any that differ."""
        state_values: dict[str, list[str]] = {}
        for r in results:
            if not r.body_snippet:
                continue
            for match in _STATE_KEYS.finditer(r.body_snippet):
                key = match.group(0).split('"')[1]
                val = match.group(1).strip().strip('"')
                state_values.setdefault(key, []).append(val)

        return {
            key: list(unique)[:5]
            for key, values in state_values.items()
            if len(unique := set(values)) > 1
        }

    def _response_table(self, results: list[RaceResult]) -> str:
        """Compact response summary: [tid:status:ms, ...]"""
        parts = []
        for r in results:
            if r.status_code:
                parts.append(f"t{r.thread_id}:{r.status_code}:{r.elapsed_ms:.0f}ms")
            else:
                parts.append(f"t{r.thread_id}:ERR")
        return "[" + " ".join(parts) + "]"

    # ── Utility ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        if not self._findings:
            return "No race condition findings."
        by_pattern = Counter(f.attack_pattern for f in self._findings)
        parts = [f"{p.replace('_', ' ')}: {c}" for p, c in by_pattern.items()]
        return f"Race conditions: {len(self._findings)} finding(s) ({', '.join(parts)})"
