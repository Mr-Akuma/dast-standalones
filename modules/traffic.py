"""
Traffic Visibility Module — full request/response capture and analysis.

Captures EVERY HTTP exchange from all sources:
  - requests.Session (crawl, fuzz, forced browse, passive scan)
  - Playwright browser (AJAX spider, SPA traffic)
  - Manual imports (session replay)

Improvement over ZAP: transparent in-process capture, zero proxy config,
no CA cert installation, automatic stats and analysis.

Usage:
    --traffic-log traffic.json   Export full traffic capture for audit
"""
from __future__ import annotations

import json
import threading
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

_MAX_BODY_STORE = 32_768      # 32KB max stored per response body
_MAX_REQ_BODY_STORE = 16_384  # 16KB max stored per request body
_BINARY_TYPES = frozenset({
    "image/", "audio/", "video/", "font/", "application/octet-stream",
    "application/pdf", "application/zip", "application/gzip",
    "application/wasm",
})


def _is_binary(content_type: str) -> bool:
    """Check if a content-type is binary (don't store body)."""
    ct = content_type.lower()
    return any(ct.startswith(bt) for bt in _BINARY_TYPES)


# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC EXCHANGE — single request/response pair
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TrafficExchange:
    """One HTTP request/response pair with full metadata."""
    # Request
    method:           str = ""
    url:              str = ""
    request_headers:  dict = field(default_factory=dict)
    request_body:     str = ""      # truncated, never binary

    # Response
    status_code:      int = 0
    response_headers: dict = field(default_factory=dict)
    response_body:    str = ""      # truncated, never binary
    content_type:     str = ""
    content_length:   int = 0

    # Metadata
    elapsed_ms:       float = 0.0   # response time in milliseconds
    source:           str = ""      # "session", "browser", "replay", "manual"
    timestamp:        float = 0.0   # time.time()

    def to_dict(self) -> dict:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC LOG — thread-safe collection of all exchanges
# ═══════════════════════════════════════════════════════════════════════════════

class TrafficLog:
    """
    Central traffic capture — sees every HTTP exchange from all scanner sources.

    Thread-safe, O(1) append, no blocking I/O during capture.
    """

    def __init__(self):
        self._exchanges: list[TrafficExchange] = []
        self._lock = threading.Lock()
        self._total_bytes: int = 0

    def record(
        self,
        method: str,
        url: str,
        status_code: int,
        request_headers: Optional[dict] = None,
        request_body: Optional[str] = None,
        response_headers: Optional[dict] = None,
        response_body: Optional[str] = None,
        content_type: str = "",
        content_length: int = 0,
        elapsed_ms: float = 0.0,
        source: str = "session",
    ) -> None:
        """Record a single HTTP exchange. Non-blocking, exception-safe."""
        try:
            # Truncate bodies, skip binary
            resp_body = ""
            if response_body and not _is_binary(content_type):
                resp_body = response_body[:_MAX_BODY_STORE]

            req_body = ""
            if request_body:
                req_body = request_body[:_MAX_REQ_BODY_STORE]

            exchange = TrafficExchange(
                method=method.upper(),
                url=url,
                request_headers=dict(request_headers or {}),
                request_body=req_body,
                status_code=status_code,
                response_headers=dict(response_headers or {}),
                response_body=resp_body,
                content_type=content_type,
                content_length=content_length,
                elapsed_ms=elapsed_ms,
                source=source,
                timestamp=time.time(),
            )

            with self._lock:
                self._exchanges.append(exchange)
                self._total_bytes += content_length
        except Exception:
            pass  # Never interfere with scanner

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._exchanges)

    def summary(self) -> dict:
        """
        Traffic analysis summary:
        - Total requests, total bytes
        - Status code distribution
        - Content-type breakdown
        - Source breakdown (session vs browser)
        - Response time stats (avg, p50, p95, max)
        - Top 10 slowest URLs
        """
        with self._lock:
            exchanges = list(self._exchanges)

        if not exchanges:
            return {"total_requests": 0}

        status_counts = Counter()
        content_types = Counter()
        sources = Counter()
        times = []
        host_counts = Counter()

        for ex in exchanges:
            status_counts[ex.status_code] += 1
            ct = ex.content_type.split(";")[0].strip() if ex.content_type else "unknown"
            content_types[ct] += 1
            sources[ex.source] += 1
            if ex.elapsed_ms > 0:
                times.append(ex.elapsed_ms)
            host = urlparse(ex.url).hostname or "unknown"
            host_counts[host] += 1

        times.sort()
        time_stats = {}
        if times:
            time_stats = {
                "avg_ms": round(sum(times) / len(times), 1),
                "p50_ms": round(times[len(times) // 2], 1),
                "p95_ms": round(times[int(len(times) * 0.95)], 1),
                "max_ms": round(times[-1], 1),
            }

        # Top 10 slowest
        slowest = sorted(exchanges, key=lambda e: e.elapsed_ms, reverse=True)[:10]
        top_slow = [
            {"url": e.url, "elapsed_ms": round(e.elapsed_ms, 1), "status": e.status_code}
            for e in slowest if e.elapsed_ms > 0
        ]

        return {
            "total_requests": len(exchanges),
            "total_bytes": self._total_bytes,
            "status_codes": dict(status_counts.most_common()),
            "content_types": dict(content_types.most_common(15)),
            "sources": dict(sources.most_common()),
            "hosts": dict(host_counts.most_common(10)),
            "response_times": time_stats,
            "slowest_urls": top_slow[:5],
        }

    def print_summary(self) -> None:
        """Print a human-readable traffic summary."""
        s = self.summary()
        if s["total_requests"] == 0:
            print("[DAST] Traffic: No exchanges captured")
            return

        print(f"[DAST] ─── Traffic Visibility ───────────────────────────────")
        print(f"[DAST]  Total exchanges : {s['total_requests']:,}")
        print(f"[DAST]  Total bytes     : {s['total_bytes']:,}")

        # Sources
        for src, cnt in s.get("sources", {}).items():
            print(f"[DAST]  Source [{src:8}]: {cnt:,} requests")

        # Status codes
        status_line = ", ".join(f"{code}:{cnt}" for code, cnt in
                                sorted(s.get("status_codes", {}).items()))
        print(f"[DAST]  Status codes    : {status_line}")

        # Timing
        ts = s.get("response_times", {})
        if ts:
            print(f"[DAST]  Response time   : avg={ts['avg_ms']}ms  "
                  f"p50={ts['p50_ms']}ms  p95={ts['p95_ms']}ms  max={ts['max_ms']}ms")

        print(f"[DAST] ─────────────────────────────────────────────────────")

    def export(self, path: str) -> int:
        """Export all exchanges to JSON file. Returns count."""
        with self._lock:
            data = [e.to_dict() for e in self._exchanges]
        with open(path, "w") as f:
            json.dump({"exchanges": data, "summary": self.summary()}, f, indent=2)
        return len(data)

    def get_exchanges(self) -> list[TrafficExchange]:
        """Return a copy of all exchanges."""
        with self._lock:
            return list(self._exchanges)
