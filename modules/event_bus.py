"""
Event Bus — Lightweight Pub/Sub for DAST Scan Orchestration
============================================================
Enables decoupled communication between scan components without
modifying their direct interfaces.

Usage::

    from modules.event_bus import get_global_bus, FINDING_DISCOVERED

    bus = get_global_bus()

    # Subscribe: storage layer listens for new findings
    bus.subscribe(FINDING_DISCOVERED, my_storage_handler)

    # Publish: fuzzer emits a finding
    bus.publish(FINDING_DISCOVERED, {"finding": "XSS", "severity": "high"})

Handlers run in background daemon threads so `publish()` is non-blocking.
The scan thread never waits for storage, notifications, or other side effects.

Thread-safety: subscribe/unsubscribe use a lock; publish snapshots handlers
before iterating so subscribe/unsubscribe during dispatch is safe.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable

log = logging.getLogger("dast.event_bus")

# ── DAST event type constants ─────────────────────────────────────────────────

SCAN_STARTED        = "scan.started"
SCAN_COMPLETE       = "scan.complete"
SCAN_STOPPED        = "scan.stopped"
SCAN_ERROR          = "scan.error"
PHASE_STARTED       = "phase.started"
PHASE_COMPLETE      = "phase.complete"
AGENT_DONE          = "agent.done"
FINDING_DISCOVERED  = "finding.discovered"
FINDING_DEDUPLICATED = "finding.deduplicated"   # fired when dedup drops a finding
EXTERNAL_TOOL_DONE  = "external_tool.done"
CRAWL_URL_FOUND     = "crawl.url_found"
AUTH_REFRESHED      = "auth.refreshed"
AUTH_FAILED         = "auth.failed"

# Ordered list for documentation / introspection
ALL_EVENT_TYPES: list[str] = [
    SCAN_STARTED, SCAN_COMPLETE, SCAN_STOPPED, SCAN_ERROR,
    PHASE_STARTED, PHASE_COMPLETE,
    AGENT_DONE,
    FINDING_DISCOVERED, FINDING_DEDUPLICATED,
    EXTERNAL_TOOL_DONE, CRAWL_URL_FOUND,
    AUTH_REFRESHED, AUTH_FAILED,
]

# Type alias
Handler = Callable[[str, Any], None]


# ══════════════════════════════════════════════════════════════════════════════
# EventBus
# ══════════════════════════════════════════════════════════════════════════════

class EventBus:
    """Thread-safe, non-blocking publish/subscribe event bus.

    Handlers are invoked in background daemon threads so the publisher
    never blocks waiting for handlers to complete.  Handler exceptions
    are caught and logged without killing the scan.
    """

    def __init__(self, name: str = "default"):
        self.name       = name
        self._lock      = threading.Lock()
        self._handlers: dict[str, list[Handler]] = {}
        self._stats: dict[str, int] = {}  # event_type → publish count

    # ── Subscribe / unsubscribe ───────────────────────────────────────────────

    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Register `handler` to be called when `event_type` is published.

        Args:
            event_type: One of the DAST_EVENTS constants or a custom string.
            handler:    Callable(event_type: str, payload: Any) → None.
        """
        with self._lock:
            self._handlers.setdefault(event_type, [])
            if handler not in self._handlers[event_type]:
                self._handlers[event_type].append(handler)
                log.debug("[EventBus:%s] Subscribed %s → %s",
                          self.name, event_type, getattr(handler, "__name__", repr(handler)))

    def subscribe_many(self, event_types: list[str], handler: Handler) -> None:
        """Subscribe a single handler to multiple event types."""
        for et in event_types:
            self.subscribe(et, handler)

    def unsubscribe(self, event_type: str, handler: Handler) -> None:
        """Remove `handler` from `event_type`. No-op if not subscribed."""
        with self._lock:
            handlers = self._handlers.get(event_type, [])
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def unsubscribe_all(self, event_type: str | None = None) -> None:
        """Remove all handlers for `event_type`, or all handlers entirely."""
        with self._lock:
            if event_type:
                self._handlers.pop(event_type, None)
            else:
                self._handlers.clear()

    # ── Publish ───────────────────────────────────────────────────────────────

    def publish(self, event_type: str, payload: Any = None) -> int:
        """Fire `event_type` to all registered handlers asynchronously.

        Returns:
            Number of handlers notified.
        """
        with self._lock:
            handlers = list(self._handlers.get(event_type, []))
            self._stats[event_type] = self._stats.get(event_type, 0) + 1

        for handler in handlers:
            t = threading.Thread(
                target=self._invoke,
                args=(event_type, payload, handler),
                daemon=True,
                name=f"dast-event-{event_type}",
            )
            t.start()

        return len(handlers)

    def publish_sync(self, event_type: str, payload: Any = None) -> int:
        """Fire `event_type` synchronously (blocks until all handlers done).

        Use sparingly — prefer `publish()` for non-blocking dispatch.
        """
        with self._lock:
            handlers = list(self._handlers.get(event_type, []))
            self._stats[event_type] = self._stats.get(event_type, 0) + 1

        for handler in handlers:
            self._invoke(event_type, payload, handler)
        return len(handlers)

    @staticmethod
    def _invoke(event_type: str, payload: Any, handler: Handler) -> None:
        try:
            handler(event_type, payload)
        except Exception as exc:
            log.error("[EventBus] Handler %s raised on %s: %s",
                      getattr(handler, "__name__", repr(handler)), event_type, exc)

    # ── Introspection ─────────────────────────────────────────────────────────

    def stats(self) -> dict[str, int]:
        """Return {event_type: publish_count} for all events published."""
        with self._lock:
            return dict(self._stats)

    def handler_count(self, event_type: str) -> int:
        """Return number of handlers registered for event_type."""
        with self._lock:
            return len(self._handlers.get(event_type, []))

    def registered_events(self) -> list[str]:
        """Return list of event types that have at least one subscriber."""
        with self._lock:
            return [et for et, h in self._handlers.items() if h]

    def __repr__(self) -> str:
        return (
            f"EventBus(name={self.name!r}, "
            f"events={len(self._handlers)}, "
            f"total_published={sum(self._stats.values())})"
        )


# ── Singleton global bus ──────────────────────────────────────────────────────

_global_bus: EventBus | None = None
_bus_lock = threading.Lock()


def get_global_bus() -> EventBus:
    """Return the process-wide singleton EventBus."""
    global _global_bus
    if _global_bus is None:
        with _bus_lock:
            if _global_bus is None:
                _global_bus = EventBus(name="global")
    return _global_bus


def reset_global_bus() -> None:
    """Reset the global bus (useful for testing)."""
    global _global_bus
    with _bus_lock:
        _global_bus = None


def safe_publish(event_type: str, payload: Any = None) -> None:
    """Publish an event without raising — logs failures at DEBUG level."""
    try:
        get_global_bus().publish(event_type, payload)
    except Exception as exc:
        log.debug("[EventBus] safe_publish failed for %s: %s", event_type, exc)
