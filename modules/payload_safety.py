"""
Payload safety filter for DAST scanner.

Ensures no destructive payloads are ever sent, even when the scanner
is operating autonomously. All payloads pass through compiled regex
deny-lists before transmission.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Blocked pattern registry — compiled once at import time
# ---------------------------------------------------------------------------

_SQL_DESTRUCTIVE = [
    r"\bDROP\b",
    r"\bDELETE\s+FROM\b",
    r"\bTRUNCATE\b",
    r"\bALTER\b",
    r"\bINSERT\s+INTO\b",
    r"\bUPDATE\b.+\bSET\b",
    r"\bCREATE\b",
    r"\bGRANT\b",
    r"\bREVOKE\b",
    r"\bEXEC\s+xp_",
    r"\bSHUTDOWN\b",
    r"\bsp_configure\b",
]

_OS_COMMANDS = [
    r"\brm\s+-rf\b",
    r"\brm\s+-f\b",
    r"\bdel\s+/f\b",
    r"\bformat\b",
    r"\bfdisk\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bkill\s+-9\b",
    r"\bpkill\b",
    r"\bsystem\s*\(",
    r"\bshell_exec\s*\(",
    r"\bpassthru\s*\(",
    r"wget.*\|.*sh",
    r"curl.*\|.*bash",
]

_FILE_OPS = [
    r">\s*/dev/",
    r">>\s*/etc/",
    r"\bchmod\s+777\b",
    r"\bchown\b",
    r"\bmv\s+/etc\b",
    r"\bcp\s+/dev/null\b",
]

_NETWORK = [
    r"\bnc\s+-e\b",
    r"\bncat\s+-e\b",
    r"bash\s+-i\s+>&",
    r"/dev/tcp/",
    r"python.*socket.*connect",
]

_DATA_EXFIL = [
    r"\bLOAD_FILE\b",
    r"\bINTO\s+OUTFILE\b",
    r"\bINTO\s+DUMPFILE\b",
    r"\bCOPY\b.*\bTO\b.*\bPROGRAM\b",
]

BLOCKED_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        _SQL_DESTRUCTIVE
        + _OS_COMMANDS
        + _FILE_OPS
        + _NETWORK
        + _DATA_EXFIL
    )
]

# Category labels aligned with the pattern lists for rejection messages
_CATEGORY_RANGES: list[tuple[int, int, str]] = [
    (0, len(_SQL_DESTRUCTIVE), "Destructive SQL"),
    (
        len(_SQL_DESTRUCTIVE),
        len(_SQL_DESTRUCTIVE) + len(_OS_COMMANDS),
        "Dangerous OS command",
    ),
    (
        len(_SQL_DESTRUCTIVE) + len(_OS_COMMANDS),
        len(_SQL_DESTRUCTIVE) + len(_OS_COMMANDS) + len(_FILE_OPS),
        "Dangerous file operation",
    ),
    (
        len(_SQL_DESTRUCTIVE) + len(_OS_COMMANDS) + len(_FILE_OPS),
        len(_SQL_DESTRUCTIVE)
        + len(_OS_COMMANDS)
        + len(_FILE_OPS)
        + len(_NETWORK),
        "Reverse-shell / network abuse",
    ),
    (
        len(_SQL_DESTRUCTIVE)
        + len(_OS_COMMANDS)
        + len(_FILE_OPS)
        + len(_NETWORK),
        len(BLOCKED_PATTERNS),
        "Data exfiltration",
    ),
]

# Strict-mode extras
_UNION_COLUMNS_RE = re.compile(
    r"\bUNION\s+SELECT\s+((?:(?:NULL|[\w.'\"]+)\s*,\s*){3,})",
    re.IGNORECASE,
)
_SLEEP_RE = re.compile(
    r"\bSLEEP\s*\(\s*(\d+)\s*\)", re.IGNORECASE
)
_WAITFOR_RE = re.compile(
    r"\bWAITFOR\s+DELAY\s+['\"]00:00:(\d+)", re.IGNORECASE
)

# Passive-only extras
_PASSIVE_BLOCK = re.compile(
    r"(?:\bSELECT\b|\bUNION\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b"
    r"|<\s*script|[;|`$()])",
    re.IGNORECASE,
)

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_ALWAYS_DANGEROUS_ENDPOINT_TOKENS = {
    "logout",
    "logoff",
    "signout",
    "signoff",
}
_DANGEROUS_ENDPOINT_TOKENS = {
    "2fa",
    "admin",
    "amount",
    "billing",
    "cancel",
    "charge",
    "checkout",
    "close",
    "deactivate",
    "delete",
    "destroy",
    "disable",
    "invoice",
    "mfa",
    "order",
    "password",
    "pay",
    "payment",
    "payments",
    "payout",
    "permission",
    "purchase",
    "refund",
    "remove",
    "reset",
    "role",
    "subscription",
    "transfer",
    "update",
    "withdraw",
}


def _endpoint_tokens(url: str, param_name: str = "") -> set[str]:
    parsed = urlparse(url or "")
    haystack = " ".join(
        part for part in (parsed.path, parsed.query, param_name or "") if part
    ).lower()
    return {tok for tok in re.split(r"[^a-z0-9]+", haystack) if tok}


def is_dangerous_endpoint(method: str, url: str, param_name: str = "") -> bool:
    """Return True when active fuzzing could trigger state-changing behavior.

    Scope exclusions catch obvious paths such as /logout and /delete. This helper
    adds a broader production safety layer for business-risk endpoints such as
    payments, refunds, transfers, password resets, and account deactivation.
    """
    method_u = (method or "GET").upper()
    tokens = _endpoint_tokens(url, param_name)

    if tokens & _ALWAYS_DANGEROUS_ENDPOINT_TOKENS:
        return True
    if method_u == "DELETE":
        return True
    if method_u in _STATE_CHANGING_METHODS and tokens & _DANGEROUS_ENDPOINT_TOKENS:
        return True
    return False


def is_dangerous_surface(surface) -> bool:
    """Return True if a crawler/API surface should be skipped for active probes."""
    return is_dangerous_endpoint(
        getattr(surface, "method", "GET"),
        getattr(surface, "url", "") or getattr(surface, "action", ""),
        getattr(surface, "param", "") or getattr(surface, "name", ""),
    )


def filter_dangerous_surfaces(surfaces: list, allow_dangerous_endpoints: bool = False) -> list:
    """Return surfaces safe for active probing under the current endpoint policy."""
    if allow_dangerous_endpoints:
        return list(surfaces or [])
    return [surface for surface in (surfaces or []) if not is_dangerous_surface(surface)]


# ---------------------------------------------------------------------------
# PayloadSafetyFilter
# ---------------------------------------------------------------------------


class PayloadSafetyFilter:
    """Filter payloads against a deny-list of destructive patterns."""

    VALID_POLICIES = ("standard", "strict", "passive-only")

    def __init__(self, policy: str = "standard") -> None:
        if policy not in self.VALID_POLICIES:
            raise ValueError(
                f"Unknown policy '{policy}'. "
                f"Choose from {self.VALID_POLICIES}"
            )
        self.policy = policy
        self._total_checked = 0
        self._total_blocked = 0
        self._total_passed = 0
        self._block_reasons: Counter = Counter()

    # -- core checks -------------------------------------------------------

    def _check_blocked_patterns(self, payload: str) -> str | None:
        """Return category string if payload matches a blocked pattern."""
        for idx, pat in enumerate(BLOCKED_PATTERNS):
            if pat.search(payload):
                for start, end, label in _CATEGORY_RANGES:
                    if start <= idx < end:
                        return label
                return "Blocked pattern"
        return None

    def _check_strict(self, payload: str) -> str | None:
        """Extra checks for strict mode."""
        m = _UNION_COLUMNS_RE.search(payload)
        if m:
            cols = m.group(1).count(",") + 1
            if cols > 3:
                return f"UNION SELECT with {cols} columns (max 3)"

        m = _SLEEP_RE.search(payload)
        if m and int(m.group(1)) > 10:
            return f"SLEEP({m.group(1)}) exceeds 10 s limit"

        m = _WAITFOR_RE.search(payload)
        if m and int(m.group(1)) > 10:
            return f"WAITFOR DELAY of {m.group(1)} s exceeds 10 s limit"

        if len(payload) > 2000:
            return f"Payload length {len(payload)} exceeds 2000 char limit"

        return None

    def _check_passive(self, payload: str) -> str | None:
        """Extra checks for passive-only mode."""
        if _PASSIVE_BLOCK.search(payload):
            return "Active payload blocked in passive-only mode"
        return None

    # -- public API ---------------------------------------------------------

    def is_safe(self, payload: str) -> bool:
        """Return True if the payload passes all filters for the policy."""
        self._total_checked += 1

        reason = self._check_blocked_patterns(payload)

        if reason is None and self.policy == "strict":
            reason = self._check_strict(payload)

        if reason is None and self.policy == "passive-only":
            reason = self._check_passive(payload)

        if reason is not None:
            self._total_blocked += 1
            self._block_reasons[reason] += 1
            return False

        self._total_passed += 1
        return True

    def filter_payloads(self, payloads: list[str]) -> list[str]:
        """Return only the payloads that pass safety checks."""
        return [p for p in payloads if self.is_safe(p)]

    def sanitize(self, payload: str) -> str | None:
        """Try to strip destructive parts. Return None if unsalvageable."""
        if self.policy == "passive-only":
            return None  # can't meaningfully strip active content

        sanitized = payload
        for pat in BLOCKED_PATTERNS:
            sanitized = pat.sub("", sanitized)

        # Collapse leftover whitespace
        sanitized = re.sub(r"\s{2,}", " ", sanitized).strip()

        if not sanitized or sanitized == payload:
            # Nothing left, or nothing was removed (but blocked elsewhere)
            if not self.is_safe(sanitized):
                return None

        # Re-validate
        if self.is_safe(sanitized):
            return sanitized
        return None

    def explain_rejection(self, payload: str) -> str:
        """Human-readable explanation of why a payload was blocked."""
        reasons: list[str] = []

        cat = self._check_blocked_patterns(payload)
        if cat:
            reasons.append(f"Matched deny-list category: {cat}")

        if self.policy == "strict":
            strict_reason = self._check_strict(payload)
            if strict_reason:
                reasons.append(f"Strict policy: {strict_reason}")

        if self.policy == "passive-only":
            passive_reason = self._check_passive(payload)
            if passive_reason:
                reasons.append(passive_reason)

        if not reasons:
            return "Payload is not blocked."

        return "; ".join(reasons)

    def get_stats(self) -> dict:
        """Return filtering statistics."""
        return {
            "total_checked": self._total_checked,
            "total_blocked": self._total_blocked,
            "total_passed": self._total_passed,
            "block_reasons": dict(self._block_reasons),
        }


# ---------------------------------------------------------------------------
# ScopeEnforcer
# ---------------------------------------------------------------------------


class ScopeEnforcer:
    """Ensure the scanner stays within allowed domains and rate budgets."""

    def __init__(
        self,
        allowed_domains: list[str],
        policy: str = "standard",
        max_requests_per_endpoint: int = 100,
    ) -> None:
        self.allowed_domains = [d.lower().strip() for d in allowed_domains]
        self.policy = policy
        self.max_requests_per_endpoint = max_requests_per_endpoint
        self._request_counts: Counter = Counter()
        self._out_of_scope_attempts = 0

    @staticmethod
    def _normalize_endpoint(url: str) -> str:
        """Strip query/fragment to get the canonical endpoint."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    def _extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()

    def is_in_scope(self, url: str) -> bool:
        """Check whether a URL falls within the allowed domains."""
        domain = self._extract_domain(url)
        if not domain:
            return False
        for allowed in self.allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True
        return False

    def can_request(self, url: str) -> bool:
        """Check scope AND per-endpoint budget."""
        if not self.is_in_scope(url):
            self._out_of_scope_attempts += 1
            return False
        endpoint = self._normalize_endpoint(url)
        return self._request_counts[endpoint] < self.max_requests_per_endpoint

    def record_request(self, url: str) -> None:
        """Increment the request counter for the endpoint."""
        endpoint = self._normalize_endpoint(url)
        self._request_counts[endpoint] += 1

    def get_stats(self) -> dict:
        """Return scope-enforcement statistics."""
        return {
            "request_counts": dict(self._request_counts),
            "out_of_scope_attempts": self._out_of_scope_attempts,
            "total_requests": sum(self._request_counts.values()),
        }
