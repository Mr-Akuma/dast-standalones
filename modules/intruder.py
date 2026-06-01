"""
Intruder -- Burp Suite-style flexible HTTP fuzzer.

Attack modes:
  SNIPER       -- One payload set. Iterates each payload into each position independently.
  BATTERING_RAM -- One payload set. Same payload inserted into ALL positions simultaneously.
  PITCHFORK    -- Multiple payload sets. Iterates in lockstep (zip).
  CLUSTER_BOMB -- Multiple payload sets. Full cartesian product (itertools.product).

Position syntax: \xa7marker\xa7 in request template (same as Burp Suite).

Example:
    intruder = Intruder()
    intruder.set_template("/search?q=\xa7FUZZ\xa7&page=\xa7PAGE\xa7")
    intruder.add_payload_set("FUZZ", ["' OR 1=1--", "admin", "<script>alert(1)</script>"])
    intruder.add_payload_set("PAGE", ["1", "2", "999"])
    intruder.set_grep_match(["error", "admin", "root:"])
    results = intruder.run(base_url="http://target.com", method="GET", session=session)
"""
from __future__ import annotations

import base64
import html
import itertools
import re
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests


# ---------------------------------------------------------------------------
# Enums & data classes
# ---------------------------------------------------------------------------

class AttackMode(Enum):
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


@dataclass
class PayloadSet:
    """A named set of payloads mapped to a \xa7NAME\xa7 marker."""
    name: str
    payloads: list[str]
    position_index: int = 0


@dataclass
class IntruderResult:
    """Single result from an Intruder request."""
    request_url: str
    request_method: str
    request_body: str
    response_status: int
    response_length: int
    response_body: str
    latency_ms: float
    payload_values: dict[str, str]
    grep_matches: list[str] = field(default_factory=list)
    baseline_length_diff: int = 0

    def to_dict(self) -> dict:
        return {
            "request_url": self.request_url,
            "request_method": self.request_method,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_length": self.response_length,
            "response_body": self.response_body,
            "latency_ms": self.latency_ms,
            "payload_values": dict(self.payload_values),
            "grep_matches": list(self.grep_matches),
            "baseline_length_diff": self.baseline_length_diff,
        }


# ---------------------------------------------------------------------------
# Position marker regex  --  \xa7NAME\xa7
# ---------------------------------------------------------------------------
_POSITION_RE = re.compile(r"\xa7([A-Za-z0-9_]+)\xa7")


# ---------------------------------------------------------------------------
# Intruder
# ---------------------------------------------------------------------------

class Intruder:
    """Burp Suite Intruder-style flexible HTTP fuzzer."""

    # Built-in payload wordlists (small defaults)
    SQLI_PAYLOADS: list[str] = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "admin'--",
    ]
    XSS_PAYLOADS: list[str] = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'\"><svg onload=alert(1)>",
    ]
    LFI_PAYLOADS: list[str] = [
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "/etc/passwd%00",
        "..%2F..%2Fetc%2Fpasswd",
    ]
    FUZZ_CHARS: list[str] = [
        "'", '"', "<", ">", ";", "|", "&", "`", "$(", "${", "{{", "}}",
    ]

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        attack_mode: AttackMode = AttackMode.SNIPER,
        timeout: int = 10,
        concurrency: int = 5,
        stop_event: threading.Event | None = None,
        follow_redirects: bool = True,
        max_results: int = 1000,
    ):
        self.attack_mode = attack_mode
        self.timeout = timeout
        self.concurrency = concurrency
        self.stop_event = stop_event or threading.Event()
        self.follow_redirects = follow_redirects
        self.max_results = max_results

        self._template: str = ""
        self._payload_sets: dict[str, PayloadSet] = {}
        self._grep_match_patterns: list[str] = []
        self._grep_extract_patterns: list[str] = []
        self._baseline_length: int | None = None

        # §2.8 Payload processing state
        self._payload_encoding: str | None = None   # "url" | "base64" | "hex" | "html"
        self._payload_prefix: str = ""
        self._payload_suffix: str = ""
        self._match_replace: list[tuple[re.Pattern, str]] = []  # (compiled_re, replacement)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_template(self, template: str) -> None:
        """Set the request template with \xa7MARKER\xa7 syntax."""
        self._template = template

    def add_payload_set(self, name: str, payloads: list[str]) -> None:
        """Register a payload list for a marker name."""
        positions = self._get_positions(self._template)
        idx = positions.index(name) if name in positions else len(self._payload_sets)
        self._payload_sets[name] = PayloadSet(
            name=name,
            payloads=list(payloads),
            position_index=idx,
        )

    def set_grep_match(self, patterns: list[str]) -> None:
        """Regex patterns to search in response body."""
        self._grep_match_patterns = list(patterns)

    def set_grep_extract(self, patterns: list[str]) -> None:
        """Regex patterns to extract values from response body."""
        self._grep_extract_patterns = list(patterns)

    # §2.7 — Additional payload source methods -------------------------

    def add_payload_file(self, name: str, filepath: str) -> None:
        """Read payloads from a file (one per line); blank lines are skipped."""
        lines = [
            ln.strip()
            for ln in Path(filepath).read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip()
        ]
        self.add_payload_set(name, lines)

    def add_number_payloads(self, name: str, start: int, end: int, step: int = 1) -> None:
        """Generate sequential integer payloads from start to end (inclusive)."""
        payloads = [str(n) for n in range(start, end + 1, step)]
        self.add_payload_set(name, payloads)

    def add_null_payloads(self, name: str, count: int) -> None:
        """Generate `count` empty-string payloads (useful for baseline comparison)."""
        self.add_payload_set(name, [""] * max(1, count))

    def add_brute_force_payloads(
        self,
        name: str,
        charset: str,
        min_len: int,
        max_len: int,
        cap: int = 10_000,
    ) -> None:
        """Generate all permutations of `charset` for lengths min_len..max_len.

        Capped at `cap` entries to prevent memory exhaustion on large charsets.
        """
        payloads: list[str] = []
        for length in range(max(1, min_len), max_len + 1):
            for combo in itertools.islice(itertools.product(charset, repeat=length), cap - len(payloads)):
                payloads.append("".join(combo))
            if len(payloads) >= cap:
                break
        self.add_payload_set(name, payloads[:cap])

    # §2.8 — Payload processing configuration -------------------------

    def set_payload_encoding(self, encoding: str) -> None:
        """Apply an encoding to every payload before injection.

        Accepted values: "url", "base64", "hex", "html".
        """
        if encoding not in ("url", "base64", "hex", "html"):
            raise ValueError(f"Unknown encoding {encoding!r}; use url/base64/hex/html")
        self._payload_encoding = encoding

    def set_prefix(self, prefix: str) -> None:
        """Prepend `prefix` to every payload value."""
        self._payload_prefix = prefix

    def set_suffix(self, suffix: str) -> None:
        """Append `suffix` to every payload value."""
        self._payload_suffix = suffix

    def add_match_replace(self, pattern: str, replacement: str) -> None:
        """Add a regex match/replace transform applied to each payload in order."""
        self._match_replace.append((re.compile(pattern), replacement))

    def _prepare_payload(self, value: str) -> str:
        """Apply all §2.8 transforms to a payload value.

        Order: match/replace → encoding → prefix/suffix.
        """
        # 1. Match/replace transforms (in registration order)
        for pat, repl in self._match_replace:
            value = pat.sub(repl, value)

        # 2. Encoding
        if self._payload_encoding == "url":
            value = quote(value, safe="")
        elif self._payload_encoding == "base64":
            value = base64.b64encode(value.encode()).decode()
        elif self._payload_encoding == "hex":
            value = value.encode().hex()
        elif self._payload_encoding == "html":
            value = html.escape(value)

        # 3. Prefix / suffix
        return self._payload_prefix + value + self._payload_suffix

    # ------------------------------------------------------------------
    # Template helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_positions(template: str) -> list[str]:
        """Extract marker names from \xa7MARKER\xa7 syntax, in order."""
        return _POSITION_RE.findall(template)

    def _apply_payloads(self, template: str, payload_map: dict[str, str]) -> str:
        """Replace \xa7MARKER\xa7 with payload values.

        Applies §2.8 transforms via _prepare_payload() before substitution.
        If the marker appears in a query-string context (after '?') and no
        explicit encoding is set, the value is URL-encoded automatically.
        """
        result = template
        for name, value in payload_map.items():
            # Apply §2.8 processing (match/replace, encoding, prefix/suffix)
            processed = self._prepare_payload(value)
            marker = f"\xa7{name}\xa7"
            # Auto URL-encode in query-string context when no explicit encoding set
            q_pos = result.find("?")
            m_pos = result.find(marker)
            if q_pos != -1 and m_pos > q_pos and self._payload_encoding is None:
                processed = quote(processed, safe="")
            result = result.replace(marker, processed)
        return result

    # ------------------------------------------------------------------
    # Payload sequence generation
    # ------------------------------------------------------------------

    def _build_payload_sequences(
        self,
        mode: AttackMode,
    ) -> list[dict[str, str]]:
        """Generate list of {marker: payload} dicts for the given attack mode."""
        positions = self._get_positions(self._template)
        if not positions:
            return []

        sequences: list[dict[str, str]] = []

        if mode == AttackMode.SNIPER:
            # One payload set (the first registered, or each set maps to its
            # own position). For each position, iterate the payloads that
            # belong to it (falling back to the first set if only one exists).
            sets_list = list(self._payload_sets.values())
            if not sets_list:
                return []
            for pos_name in positions:
                pset = self._payload_sets.get(pos_name, sets_list[0])
                for payload in pset.payloads:
                    mapping: dict[str, str] = {}
                    for p in positions:
                        if p == pos_name:
                            mapping[p] = payload
                        else:
                            # Keep original marker as empty string placeholder
                            mapping[p] = ""
                    sequences.append(mapping)

        elif mode == AttackMode.BATTERING_RAM:
            sets_list = list(self._payload_sets.values())
            if not sets_list:
                return []
            primary = sets_list[0]
            for payload in primary.payloads:
                sequences.append({p: payload for p in positions})

        elif mode == AttackMode.PITCHFORK:
            ordered_sets = []
            for pos_name in positions:
                if pos_name in self._payload_sets:
                    ordered_sets.append(self._payload_sets[pos_name].payloads)
                else:
                    ordered_sets.append([""])
            for combo in zip(*ordered_sets):
                sequences.append(dict(zip(positions, combo)))

        elif mode == AttackMode.CLUSTER_BOMB:
            ordered_sets = []
            for pos_name in positions:
                if pos_name in self._payload_sets:
                    ordered_sets.append(self._payload_sets[pos_name].payloads)
                else:
                    ordered_sets.append([""])
            for combo in itertools.product(*ordered_sets):
                sequences.append(dict(zip(positions, combo)))

        return sequences

    # ------------------------------------------------------------------
    # HTTP execution
    # ------------------------------------------------------------------

    def _send_request(
        self,
        url: str,
        method: str,
        body: str,
        headers: dict[str, str],
        session: requests.Session | None,
        payload_map: dict[str, str],
    ) -> IntruderResult:
        """Send one HTTP request, measure latency, check grep patterns."""
        sender = session or requests
        kwargs: dict = {
            "url": url,
            "headers": headers,
            "timeout": self.timeout,
            "allow_redirects": self.follow_redirects,
        }
        if body:
            kwargs["data"] = body

        t0 = time.perf_counter()
        try:
            resp = sender.request(method, **kwargs)  # type: ignore[arg-type]
            latency = (time.perf_counter() - t0) * 1000.0
            resp_body = resp.text
            resp_status = resp.status_code
            resp_length = len(resp_body)
        except requests.RequestException:
            latency = (time.perf_counter() - t0) * 1000.0
            resp_body = ""
            resp_status = 0
            resp_length = 0

        # Grep matching
        grep_hits: list[str] = []
        for pattern in self._grep_match_patterns:
            try:
                if re.search(pattern, resp_body, re.IGNORECASE):
                    grep_hits.append(pattern)
            except re.error:
                # Treat as literal substring match on bad regex
                if pattern.lower() in resp_body.lower():
                    grep_hits.append(pattern)

        # Grep extraction (stored as additional grep_matches entries)
        for pattern in self._grep_extract_patterns:
            try:
                matches = re.findall(pattern, resp_body, re.IGNORECASE)
                for m in matches:
                    grep_hits.append(f"extract:{pattern}={m}")
            except re.error:
                pass

        baseline_diff = 0
        if self._baseline_length is not None:
            baseline_diff = resp_length - self._baseline_length

        return IntruderResult(
            request_url=url,
            request_method=method,
            request_body=body,
            response_status=resp_status,
            response_length=resp_length,
            response_body=resp_body,
            latency_ms=round(latency, 2),
            payload_values=dict(payload_map),
            grep_matches=grep_hits,
            baseline_length_diff=baseline_diff,
        )

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def run(
        self,
        base_url: str,
        method: str = "GET",
        body_template: str = "",
        headers: dict[str, str] | None = None,
        session: requests.Session | None = None,
    ) -> list[IntruderResult]:
        """Execute the attack. Returns results sorted by response_length desc."""
        headers = dict(headers) if headers else {}
        sequences = self._build_payload_sequences(self.attack_mode)
        if not sequences:
            return []

        # Optionally capture baseline (template with empty payloads)
        self._baseline_length = None

        results: list[IntruderResult] = []
        lock = threading.Lock()
        semaphore = threading.Semaphore(self.concurrency)

        def _worker(payload_map: dict[str, str]) -> None:
            if self.stop_event.is_set():
                return

            # Build URL
            rendered_path = self._apply_payloads(self._template, payload_map)
            if rendered_path.startswith(("http://", "https://")):
                url = rendered_path
            else:
                url = base_url.rstrip("/") + "/" + rendered_path.lstrip("/")

            # Build body
            body = self._apply_payloads(body_template, payload_map) if body_template else ""

            # Build headers (apply payloads to header values too)
            req_headers = {}
            for k, v in headers.items():
                req_headers[k] = self._apply_payloads(v, payload_map)

            try:
                result = self._send_request(
                    url=url,
                    method=method,
                    body=body,
                    headers=req_headers,
                    session=session,
                    payload_map=payload_map,
                )
                with lock:
                    if len(results) < self.max_results:
                        results.append(result)
            finally:
                semaphore.release()

        threads: list[threading.Thread] = []
        for payload_map in sequences:
            if self.stop_event.is_set():
                break
            if len(results) >= self.max_results:
                break

            semaphore.acquire()
            t = threading.Thread(target=_worker, args=(payload_map,), daemon=True)
            t.start()
            threads.append(t)

        # Wait for all threads to complete
        for t in threads:
            t.join(timeout=self.timeout + 5)

        # Sort by response_length descending (anomalies float to top)
        results.sort(key=lambda r: r.response_length, reverse=True)
        return results

    # ------------------------------------------------------------------
    # Result filtering
    # ------------------------------------------------------------------

    @staticmethod
    def filter_results(
        results: list[IntruderResult],
        status_codes: list[int] | None = None,
        min_length_diff: int | None = None,
        grep_match_only: bool = False,
    ) -> list[IntruderResult]:
        """Filter results by status code, length diff, or grep matches."""
        filtered = results
        if status_codes is not None:
            filtered = [r for r in filtered if r.response_status in status_codes]
        if min_length_diff is not None:
            filtered = [r for r in filtered if abs(r.baseline_length_diff) >= min_length_diff]
        if grep_match_only:
            filtered = [r for r in filtered if r.grep_matches]
        return filtered
