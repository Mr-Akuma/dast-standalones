from __future__ import annotations
import json
import logging
import os
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)


class FindingDeduplicator:
    """
    Deduplicates findings by (normalized_url_path, parameter, vuln_type).
    Keeps the finding instance with the highest confidence_score.
    Supports cross-run dedup via file persistence.
    """

    def __init__(self, persistence_path: str | None = None):
        """
        Args:
            persistence_path: JSON file path for cross-run dedup state.
                            If None, dedup is in-memory only (single run).
        """
        self._seen: dict[str, dict] = {}  # key -> best finding
        self._persistence_path = persistence_path
        if persistence_path:
            self._load()

    @staticmethod
    def _make_key(finding: dict) -> str:
        """Create dedup key from (normalized_path, param, vuln_type, finding_name)."""
        url = finding.get("url", "")
        path = urlparse(url).path.rstrip("/") or "/"
        param = finding.get("param", finding.get("parameter", ""))
        vuln = finding.get("vuln_type", finding.get("category", ""))
        # Include finding name to prevent collision when vuln_type is generic (e.g. "BChecks")
        name = finding.get("finding", "")[:80]
        return f"{path}|{param}|{vuln}|{name}"

    def is_duplicate(self, finding: dict) -> bool:
        """Check if this finding is a duplicate of an existing one."""
        key = self._make_key(finding)
        return key in self._seen

    def add(self, finding: dict) -> bool:
        """
        Add finding. Returns True if it's new or higher-confidence than existing.
        Returns False if it's a lower-confidence duplicate.
        """
        key = self._make_key(finding)
        new_confidence = finding.get("confidence_score", 0.5)

        if key in self._seen:
            existing_confidence = self._seen[key].get("confidence_score", 0.5)
            if new_confidence > existing_confidence:
                self._seen[key] = finding
                return True
            return False

        self._seen[key] = finding
        return True

    def deduplicate(self, findings: list[dict]) -> list[dict]:
        """
        Deduplicate a list of findings. Returns filtered list with only
        unique or highest-confidence instances.
        """
        result = []
        for f in findings:
            if self.add(f):
                result.append(f)
        return result

    def get_unique_count(self) -> int:
        return len(self._seen)

    def summary(self) -> dict:
        return {
            "unique_findings": len(self._seen),
            "persistence": self._persistence_path or "in-memory",
        }

    def save(self) -> None:
        """Persist dedup state to disk."""
        if not self._persistence_path:
            return
        try:
            os.makedirs(os.path.dirname(self._persistence_path) or ".", exist_ok=True)
            # Store only the dedup keys and their confidence scores (not full findings)
            state = {}
            for key, finding in self._seen.items():
                state[key] = {
                    "confidence_score": finding.get("confidence_score", 0.5),
                    "vuln_type": finding.get("vuln_type", ""),
                    "url": finding.get("url", ""),
                    "severity": finding.get("severity", ""),
                    "finding": finding.get("finding", "")[:200],  # truncate for storage
                }
            with open(self._persistence_path, "w") as f:
                json.dump(state, f, indent=2)
            log.info("[Dedup] Saved %d unique findings to %s", len(state), self._persistence_path)
        except Exception as e:
            log.warning("[Dedup] Failed to save: %s", e)

    def _load(self) -> None:
        """Load previous dedup state from disk."""
        if not self._persistence_path or not os.path.exists(self._persistence_path):
            return
        try:
            with open(self._persistence_path) as f:
                state = json.load(f)
            for key, data in state.items():
                self._seen[key] = data
            log.info("[Dedup] Loaded %d previous findings from %s", len(state), self._persistence_path)
        except Exception as e:
            log.warning("[Dedup] Failed to load: %s", e)

    def clear(self) -> None:
        """Reset dedup state."""
        self._seen.clear()


class DedupCache:
    """Redis-backed dedup cache — eliminates SQL round-trips for duplicate checks.

    During a scan, every finding triggers 2 SQL queries just to check "seen before?".
    This class answers those checks from Redis (O(1) in-memory) instead.

    Data layout in Redis:
        dast:seen        — Redis hash:  dedup_hash  → finding_id
        dast:id_to_hash  — Redis hash:  finding_id  → dedup_hash  (reverse for FP marking)
        dast:fp          — Redis set:   dedup_hash  (false positive hashes)

    Falls back silently if Redis is unavailable — no behavior change in callers.

    Usage::

        cache = DedupCache("redis://localhost:6379/0")
        if cache.available:
            cache.warm(seen_map, fp_list)   # pre-load from DB on startup

        # In add_finding():
        if cache.is_fp(dhash):   return suppressed_dict
        if existing := cache.get_seen_id(dhash):   return existing
        result = db.insert(...)
        cache.mark_seen(dhash, result)

        # In mark_false_positive():
        dhash = cache.get_hash_for_id(finding_id)
        db.mark_fp(finding_id)
        cache.mark_fp(dhash)
    """

    _SEEN_KEY    = "dast:seen"        # hash: dedup_hash → finding_id
    _ID_KEY      = "dast:id_to_hash"  # hash: finding_id → dedup_hash
    _FP_KEY      = "dast:fp"          # set:  dedup_hash (false positives)

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self._available = False
        self._r = None
        try:
            import redis as _redis
            client = _redis.from_url(redis_url, decode_responses=True, socket_timeout=1.0)
            client.ping()
            self._r = client
            self._available = True
            log.info("[DedupCache] Connected to Redis at %s", redis_url)
        except Exception as exc:
            log.info("[DedupCache] Redis unavailable (%s) — SQL fallback active", exc)

    @property
    def available(self) -> bool:
        return self._available

    def is_fp(self, dhash: str) -> bool:
        """True if this hash is a known false positive."""
        if not self._available:
            return False
        try:
            return bool(self._r.sismember(self._FP_KEY, dhash))
        except Exception:
            return False

    def get_seen_id(self, dhash: str) -> str | None:
        """Return existing finding_id if this hash was seen before, else None."""
        if not self._available:
            return None
        try:
            return self._r.hget(self._SEEN_KEY, dhash)
        except Exception:
            return None

    def get_hash_for_id(self, finding_id: str) -> str | None:
        """Reverse lookup: finding_id → dedup_hash (for FP marking)."""
        if not self._available:
            return None
        try:
            return self._r.hget(self._ID_KEY, finding_id)
        except Exception:
            return None

    def mark_seen(self, dhash: str, finding_id: str) -> None:
        """Record hash → finding_id after a successful DB insert."""
        if not self._available:
            return
        try:
            pipe = self._r.pipeline()
            pipe.hset(self._SEEN_KEY, dhash, finding_id)
            pipe.hset(self._ID_KEY, finding_id, dhash)
            pipe.execute()
        except Exception:
            pass

    def mark_fp(self, dhash: str) -> None:
        """Mark a hash as false positive — suppresses future findings with this hash."""
        if not self._available:
            return
        try:
            pipe = self._r.pipeline()
            pipe.sadd(self._FP_KEY, dhash)
            pipe.hdel(self._SEEN_KEY, dhash)
            pipe.execute()
        except Exception:
            pass

    def warm(self, seen: dict[str, str], fp_hashes: list[str]) -> None:
        """Pre-load existing DB hashes into Redis. Call once on startup.

        Args:
            seen:      {dedup_hash: finding_id} for all non-FP findings in DB
            fp_hashes: list of dedup_hash for all known FP findings in DB
        """
        if not self._available:
            return
        try:
            pipe = self._r.pipeline()
            if seen:
                pipe.hset(self._SEEN_KEY, mapping=seen)
                # Also build reverse id→hash mapping
                reverse = {v: k for k, v in seen.items()}
                pipe.hset(self._ID_KEY, mapping=reverse)
            for h in fp_hashes:
                pipe.sadd(self._FP_KEY, h)
            pipe.execute()
            log.info("[DedupCache] Warmed: %d seen hashes, %d FP hashes", len(seen), len(fp_hashes))
        except Exception as exc:
            log.warning("[DedupCache] Warm failed: %s", exc)

    def stats(self) -> dict:
        """Return cache hit statistics."""
        if not self._available:
            return {"available": False}
        try:
            return {
                "available": True,
                "seen_count": self._r.hlen(self._SEEN_KEY),
                "fp_count":   self._r.scard(self._FP_KEY),
            }
        except Exception:
            return {"available": False}

    def flush(self) -> None:
        """Clear all cache keys. Used in testing."""
        if not self._available:
            return
        try:
            self._r.delete(self._SEEN_KEY, self._ID_KEY, self._FP_KEY)
        except Exception:
            pass
