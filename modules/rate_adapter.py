"""Adaptive rate limiter for DAST scanning.

Detects throttling (429, 503, elevated latency) and adjusts concurrency
and delay automatically to avoid being blocked while maximising scan speed.
"""

from __future__ import annotations

import random
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class RateState:
    """Snapshot of the current rate-limiter state."""

    max_concurrent: int = 10
    delay_ms: int = 0
    current_rps: float = 0.0
    throttle_level: str = "none"  # none | light | moderate | heavy
    backoff_until: float | None = None


_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
    "Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


class RateAdapter:
    """Adaptive rate controller that reacts to server-side throttling."""

    def __init__(
        self,
        initial_concurrent: int = 10,
        initial_delay_ms: int = 0,
        min_concurrent: int = 1,
        max_concurrent: int = 50,
    ) -> None:
        self._min_concurrent = min_concurrent
        self._max_concurrent = max_concurrent

        self._response_times: deque[float] = deque(maxlen=100)
        self._status_codes: deque[int] = deque(maxlen=100)
        self._block_count: int = 0

        self._state = RateState(
            max_concurrent=initial_concurrent,
            delay_ms=initial_delay_ms,
        )

        self._last_adjustment: float = 0.0
        self._adjustment_cooldown: float = 5.0

        self._ua_index: int = 0
        self._request_timestamps: deque[float] = deque(maxlen=100)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, status_code: int, response_time_ms: float) -> None:
        """Record a response and trigger adjustment if warranted."""
        now = time.monotonic()
        self._response_times.append(response_time_ms)
        self._status_codes.append(status_code)
        self._request_timestamps.append(now)

        if status_code in (429, 503):
            self._block_count += 1
        else:
            self._block_count = 0

        if self._should_adjust():
            self._adjust()

    def get_rate(self) -> RateState:
        """Return a copy of the current rate state."""
        self._state.current_rps = self._calculate_rps()
        return RateState(
            max_concurrent=self._state.max_concurrent,
            delay_ms=self._state.delay_ms,
            current_rps=self._state.current_rps,
            throttle_level=self._state.throttle_level,
            backoff_until=self._state.backoff_until,
        )

    def get_delay(self) -> float:
        """Return seconds to wait before the next request.

        Respects backoff_until if an active heavy-backoff is in effect.
        """
        now = time.time()
        base = self._state.delay_ms / 1000.0

        if self._state.backoff_until and now < self._state.backoff_until:
            remaining = self._state.backoff_until - now
            base = max(base, remaining)

        return self.add_jitter(base) if base > 0 else 0.0

    def add_jitter(self, base_delay: float) -> float:
        """Add 10-30% random jitter to *base_delay* (seconds)."""
        if base_delay <= 0:
            return 0.0
        jitter_factor = 1.0 + random.uniform(0.10, 0.30)
        return base_delay * jitter_factor

    def get_user_agent(self) -> str:
        """Rotate through realistic browser UA strings when throttled."""
        ua = _USER_AGENTS[self._ua_index % len(_USER_AGENTS)]
        if self._state.throttle_level != "none":
            self._ua_index += 1
        return ua

    def stats(self) -> dict:
        """Return a human-friendly stats dictionary."""
        times = list(self._response_times)
        avg_rt = sum(times) / len(times) if times else 0.0
        p95_rt = self._percentile(times, 95) if times else 0.0

        codes = list(self._status_codes)
        block_codes = sum(1 for c in codes if c in (429, 503))
        block_rate = block_codes / len(codes) if codes else 0.0

        return {
            "avg_response_time_ms": round(avg_rt, 1),
            "p95_response_time_ms": round(p95_rt, 1),
            "block_rate": round(block_rate, 3),
            "throttle_level": self._state.throttle_level,
            "concurrent": self._state.max_concurrent,
            "delay_ms": self._state.delay_ms,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _should_adjust(self) -> bool:
        """Return True when we have enough data and the cooldown elapsed."""
        if len(self._response_times) < 5:
            return False
        now = time.monotonic()
        if now - self._last_adjustment < self._adjustment_cooldown:
            return False
        return True

    def _adjust(self) -> None:
        """Core rate-adjustment logic — throttle or recover."""
        self._last_adjustment = time.monotonic()
        recent_codes = list(self._status_codes)[-10:]
        wider_codes = list(self._status_codes)[-20:]

        # --- Heavy: 3+ consecutive blocks → exponential backoff ----------
        if self._block_count >= 3:
            self._state.throttle_level = "heavy"
            self._state.max_concurrent = self._min_concurrent
            self._state.delay_ms = min(self._state.delay_ms * 2 or 2000, 10_000)
            self._state.backoff_until = time.time() + self._state.delay_ms / 1000.0
            return

        # --- Heavy: any 503 in last 10 -----------------------------------
        if 503 in recent_codes:
            self._state.throttle_level = "heavy"
            self._state.max_concurrent = self._min_concurrent
            self._state.delay_ms = max(self._state.delay_ms, 2000)
            self._state.backoff_until = time.time() + self._state.delay_ms / 1000.0
            return

        # --- Moderate: any 429 in last 10 --------------------------------
        if 429 in recent_codes:
            self._state.throttle_level = "moderate"
            self._state.max_concurrent = max(
                self._min_concurrent, self._state.max_concurrent // 2
            )
            self._state.delay_ms = max(self._state.delay_ms, 500)
            self._state.backoff_until = None
            return

        # --- Light: P95 response time > 5 s ------------------------------
        times = list(self._response_times)
        p95 = self._percentile(times, 95)
        if p95 > 5000:
            self._state.throttle_level = "light"
            reduced = int(self._state.max_concurrent * 0.75)
            self._state.max_concurrent = max(self._min_concurrent, reduced)
            self._state.backoff_until = None
            return

        # --- Recovery: no blocks in last 20 AND avg < 1 s ----------------
        has_blocks = any(c in (429, 503) for c in wider_codes)
        avg_rt = sum(times) / len(times) if times else 0.0

        if not has_blocks and avg_rt < 1000 and len(wider_codes) >= 20:
            self._state.throttle_level = "none"
            increased = int(self._state.max_concurrent * 1.25)
            self._state.max_concurrent = min(self._max_concurrent, max(increased, self._state.max_concurrent + 1))
            reduced_delay = int(self._state.delay_ms * 0.75)
            self._state.delay_ms = max(0, reduced_delay)
            self._state.backoff_until = None
            return

        # No change needed
        if not has_blocks:
            self._state.throttle_level = "none"
            self._state.backoff_until = None

    def _calculate_rps(self) -> float:
        """Estimate current requests per second from recent timestamps."""
        if len(self._request_timestamps) < 2:
            return 0.0
        stamps = list(self._request_timestamps)
        elapsed = stamps[-1] - stamps[0]
        if elapsed <= 0:
            return 0.0
        return (len(stamps) - 1) / elapsed

    @staticmethod
    def _percentile(values: list[float], pct: int) -> float:
        """Return the *pct*-th percentile of *values* (nearest-rank)."""
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        idx = max(0, int(len(sorted_vals) * pct / 100) - 1)
        return sorted_vals[idx]
