"""
BCheck Engine — BChecks DSL parser and executor for DAST standalone.

Parses and executes Burp BChecks (.bcheck) files, integrating findings into
the standard DAST scan pipeline.

Supported triggers:
    given host then           — sends requests to the target host
    given request then        — replays/modifies each crawled URL
    given response then       — passively inspects each crawled response
    given path then           — probes specific paths on the host

Supported constructs:
    metadata:                 — language, name, description, author, tags
    define:                   — variable = template string
    run for each:             — variable = val1, val2, ...
    send request called NAME: — HTTP request with method/path/appending_path/headers
    send request:             — anonymous HTTP request
    if COND then/end if       — condition blocks (nested supported)
    report issue [and continue]: — finding with severity/confidence/detail/remediation
    {random_str(N)}           — random alphanumeric string of length N
    {to_lower(X)}             — lowercase transform
    {VAR.response.body/headers/status_code} — named response accessors

Not supported (skipped with warning):
    generate_collaborator_address() — requires Burp Collaborator (OAST)
    http/dns/any interactions  — OAST-based conditions
    given insertion point then — parameter injection (future work)
    given query or body insertion point then
"""
from __future__ import annotations

import logging
import os
import random
import re
import string
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests

log = logging.getLogger("bcheck_engine")

# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class BCheckRequest:
    name: str = ""           # named reference, "" = anonymous ("latest")
    method: str = "GET"
    path: str = ""           # full path override (replaces URL path)
    appending_path: str = "" # appended to existing URL path
    headers: dict = field(default_factory=dict)
    body: str = ""


@dataclass
class BCheckIssue:
    severity: str = "info"
    confidence: str = "tentative"
    detail: str = ""
    remediation: str = ""
    continue_after: bool = False


@dataclass
class BCheckBlock:
    """One if/end if conditional block."""
    raw_condition: str = ""
    send_requests: list = field(default_factory=list)   # BCheckRequest
    issue: Optional[BCheckIssue] = None
    nested_blocks: list = field(default_factory=list)   # BCheckBlock


@dataclass
class BCheckSpec:
    name: str
    description: str = ""
    author: str = ""
    tags: list = field(default_factory=list)
    language: str = "v1-beta"
    defines: dict = field(default_factory=dict)
    run_for_each: dict = field(default_factory=dict)   # var -> [val1, val2, ...]
    trigger: str = "response"   # host | request | response | path
    top_requests: list = field(default_factory=list)   # BCheckRequest before first if
    blocks: list = field(default_factory=list)         # BCheckBlock
    oast_required: bool = False
    file_path: str = ""


# ─── Parser ───────────────────────────────────────────────────────────────────

class BCheckParser:
    """Parses a .bcheck file into a BCheckSpec."""

    _TRIGGER_MAP = {
        "host": "host",
        "request": "request",
        "response": "response",
        "path": "path",
        "insertion point": "insertion_point",
        "query or body insertion point": "insertion_point",
    }

    def parse(self, file_path: str) -> Optional[BCheckSpec]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            log.warning("BCheck: cannot read %s: %s", file_path, exc)
            return None

        # Normalize: expand tabs to 4 spaces
        lines = [ln.expandtabs(4) for ln in raw.splitlines()]
        return self._parse_lines(lines, file_path)

    def _parse_lines(self, lines: list[str], file_path: str) -> Optional[BCheckSpec]:
        i = 0
        n = len(lines)

        meta: dict[str, Any] = {}
        defines: dict[str, str] = {}
        run_for_each: dict[str, list[str]] = {}
        trigger = "response"
        top_requests: list[BCheckRequest] = []
        blocks: list[BCheckBlock] = []
        oast_required = False

        section = None  # metadata | define | run_for_each | trigger_body

        while i < n:
            raw_line = lines[i]
            stripped = raw_line.strip()

            # Skip blank lines and comments
            if not stripped or stripped.startswith("#"):
                i += 1
                continue

            lower = stripped.lower()

            # Section headers (at approx column 0, indent < 4)
            if len(raw_line) - len(raw_line.lstrip()) < 4:
                if lower == "metadata:":
                    section = "metadata"
                    i += 1
                    continue
                if lower == "define:":
                    section = "define"
                    i += 1
                    continue
                if lower in ("run for each:", "run for each"):
                    section = "run_for_each"
                    i += 1
                    continue
                # given X then
                m = re.match(r"given\s+(.+?)\s+then\s*$", stripped, re.I)
                if m:
                    trigger_phrase = m.group(1).strip().lower()
                    trigger = self._TRIGGER_MAP.get(trigger_phrase, trigger_phrase)
                    section = "trigger_body"
                    i += 1
                    # Parse trigger body
                    top_requests, blocks, oast_req, i = self._parse_body(lines, i, n)
                    if oast_req:
                        oast_required = True
                    continue

            # Content within current section
            if section == "metadata":
                kv = re.match(r"(\w+)\s*:\s*(.*)", stripped)
                if kv:
                    key, val = kv.group(1).lower(), kv.group(2).strip().strip('"')
                    if key == "tags":
                        meta["tags"] = [t.strip().strip('"') for t in val.split(",")]
                    else:
                        meta[key] = val

            elif section == "define":
                # var = `template` or var = "value"
                kv = re.match(r"(\w+)\s*=\s*(.*)", stripped)
                if kv:
                    var, val = kv.group(1), kv.group(2).strip()
                    val = val.strip("`").strip('"')
                    if "generate_collaborator_address" in val:
                        oast_required = True
                    defines[var] = val

            elif section == "run_for_each":
                # var = val1, val2, ... (may span multiple lines)
                kv = re.match(r"(\w+)\s*=\s*(.*)", stripped)
                if kv:
                    var = kv.group(1)
                    vals_raw = kv.group(2)
                    # Collect continuation lines
                    j = i + 1
                    while j < n:
                        next_s = lines[j].strip()
                        if not next_s or next_s.startswith("#"):
                            j += 1
                            continue
                        # If next line looks like another section or given statement, stop
                        if re.match(r"(\w+)\s*:", next_s) and not next_s.startswith('"'):
                            break
                        if re.match(r"given\s+", next_s, re.I):
                            break
                        # It's a continuation value line
                        vals_raw += "," + next_s
                        j += 1
                    i = j - 1  # will be incremented at bottom
                    vals = [v.strip().strip("`").strip('"') for v in vals_raw.split(",") if v.strip()]
                    if any("generate_collaborator_address" in v for v in vals):
                        oast_required = True
                    run_for_each[var] = vals

            i += 1

        if "name" not in meta:
            log.debug("BCheck: no name in %s, skipping", file_path)
            return None

        return BCheckSpec(
            name=meta.get("name", ""),
            description=meta.get("description", ""),
            author=meta.get("author", ""),
            tags=meta.get("tags", []),
            language=meta.get("language", "v1-beta"),
            defines=defines,
            run_for_each=run_for_each,
            trigger=trigger,
            top_requests=top_requests,
            blocks=blocks,
            oast_required=oast_required,
            file_path=file_path,
        )

    def _parse_body(self, lines: list[str], i: int, n: int) -> tuple[list, list, bool, int]:
        """Parse trigger body into top_requests and blocks. Returns (top_requests, blocks, oast_required, next_i)."""
        top_requests: list[BCheckRequest] = []
        blocks: list[BCheckBlock] = []
        oast_required = False

        while i < n:
            raw_line = lines[i]
            stripped = raw_line.strip()

            if not stripped or stripped.startswith("#"):
                i += 1
                continue

            lower = stripped.lower()

            # New top-level section — end of trigger body
            if len(raw_line) - len(raw_line.lstrip()) < 4 and re.match(r"(metadata|define|run for each|given)\s*", lower):
                break

            if lower.startswith("send request"):
                req, i = self._parse_send_request(lines, i, n)
                if req:
                    if "generate_collaborator_address" in (req.path + req.appending_path + req.body):
                        oast_required = True
                    top_requests.append(req)

            elif lower.startswith("if ") or lower == "if":
                block, i, oast_req = self._parse_if_block(lines, i, n)
                if oast_req:
                    oast_required = True
                if block:
                    blocks.append(block)

            else:
                i += 1

        return top_requests, blocks, oast_required, i

    def _parse_send_request(self, lines: list[str], i: int, n: int) -> tuple[Optional[BCheckRequest], int]:
        """Parse a send request block. Returns (BCheckRequest, next_i)."""
        stripped = lines[i].strip().lower()
        # Extract name
        m = re.match(r"send request called\s+(\w+)\s*:", stripped)
        name = m.group(1) if m else ""
        req = BCheckRequest(name=name)

        i += 1
        while i < n:
            raw_line = lines[i]
            s = raw_line.strip()
            if not s or s.startswith("#"):
                i += 1
                continue
            sl = s.lower()

            # Request properties
            if sl.startswith("method:"):
                req.method = s.split(":", 1)[1].strip().strip('"').upper()
                i += 1
            elif sl.startswith("path:"):
                req.path = s.split(":", 1)[1].strip().strip('"').strip("`")
                i += 1
            elif sl.startswith("appending path:"):
                req.appending_path = s.split(":", 1)[1].strip().strip("`").strip('"')
                i += 1
            elif sl.startswith("body:"):
                req.body = s.split(":", 1)[1].strip().strip('"')
                i += 1
            elif sl.startswith("headers:"):
                # Parse header block: lines of "Header-Name": "value"
                i += 1
                while i < n:
                    hs = lines[i].strip()
                    if not hs or hs.startswith("#"):
                        i += 1
                        continue
                    hm = re.match(r'"([^"]+)"\s*:\s*"([^"]*)"', hs)
                    if hm:
                        req.headers[hm.group(1)] = hm.group(2)
                        i += 1
                    else:
                        break  # end of headers block
            else:
                # End of request block
                break

        return req, i

    def _parse_if_block(self, lines: list[str], i: int, n: int) -> tuple[Optional[BCheckBlock], int, bool]:
        """Parse if COND then ... end if block. Returns (BCheckBlock, next_i, oast_required)."""
        stripped = lines[i].strip()
        oast_required = False

        # Collect full condition (may span multiple lines until `then`)
        cond_parts = [stripped]
        i += 1
        while i < n:
            s = lines[i].strip()
            if not s or s.startswith("#"):
                i += 1
                continue
            # Condition ends at `then` keyword at end of a line
            cond_parts.append(s)
            if cond_parts and re.search(r"\bthen\s*$", " ".join(cond_parts), re.I):
                i += 1
                break
            # If line is clearly not a continuation (new keyword), stop
            sl = s.lower()
            if sl.startswith(("send ", "report ", "end if", "if ")):
                break
            i += 1

        raw_cond = " ".join(cond_parts)
        # Strip leading `if ` and trailing `then`
        raw_cond = re.sub(r"^\s*if\s+", "", raw_cond, flags=re.I)
        raw_cond = re.sub(r"\s+then\s*$", "", raw_cond, flags=re.I)

        if "generate_collaborator_address" in raw_cond:
            oast_required = True
        if re.search(r"\b(http|dns|any)\s+interactions\b", raw_cond, re.I):
            oast_required = True

        block = BCheckBlock(raw_condition=raw_cond.strip())

        # Parse block body
        while i < n:
            raw_line = lines[i]
            s = raw_line.strip()
            if not s or s.startswith("#"):
                i += 1
                continue
            sl = s.lower()

            if sl == "end if" or sl == "end if ":
                i += 1
                break

            if sl.startswith("send request"):
                req, i = self._parse_send_request(lines, i, n)
                if req:
                    if "generate_collaborator_address" in (req.path + req.appending_path):
                        oast_required = True
                    block.send_requests.append(req)

            elif sl.startswith("report issue and continue"):
                issue, i = self._parse_report_issue(lines, i, n, continue_after=True)
                block.issue = issue

            elif sl.startswith("report issue"):
                issue, i = self._parse_report_issue(lines, i, n, continue_after=False)
                block.issue = issue

            elif sl.startswith("if "):
                nested, i, oast_req = self._parse_if_block(lines, i, n)
                if oast_req:
                    oast_required = True
                if nested:
                    block.nested_blocks.append(nested)

            else:
                i += 1

        return block, i, oast_required

    def _parse_report_issue(self, lines: list[str], i: int, n: int, continue_after: bool = False) -> tuple[BCheckIssue, int]:
        """Parse report issue block."""
        issue = BCheckIssue(continue_after=continue_after)
        i += 1
        while i < n:
            s = lines[i].strip()
            if not s or s.startswith("#"):
                i += 1
                continue
            sl = s.lower()

            if sl.startswith("severity:"):
                issue.severity = s.split(":", 1)[1].strip().strip('"').lower()
                i += 1
            elif sl.startswith("confidence:"):
                issue.confidence = s.split(":", 1)[1].strip().strip('"').lower()
                i += 1
            elif sl.startswith("detail:"):
                issue.detail = s.split(":", 1)[1].strip().strip('"').strip("`")
                i += 1
            elif sl.startswith("remediation:"):
                issue.remediation = s.split(":", 1)[1].strip().strip('"').strip("`")
                i += 1
            else:
                break

        return issue, i


# ─── Template resolution ───────────────────────────────────────────────────────

def _random_str(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _resolve(template: str, ctx: dict[str, str]) -> str:
    """Resolve {VAR} references and built-in functions in a template string."""
    if not template:
        return template

    # Handle {to_lower(X)} — resolve X first, then lowercase
    def _to_lower_sub(m: re.Match) -> str:
        inner = m.group(1)
        resolved_inner = _resolve(inner, ctx)
        return resolved_inner.lower()

    result = re.sub(r"\{to_lower\(([^)]+)\)\}", _to_lower_sub, template)

    # Replace {VAR} with context values
    def _var_sub(m: re.Match) -> str:
        key = m.group(1).strip()
        return ctx.get(key, m.group(0))  # leave unresolved if not in ctx

    result = re.sub(r"\{([^{}]+)\}", _var_sub, result)
    return result


# ─── Condition evaluator ──────────────────────────────────────────────────────

def _eval_condition(raw: str, ctx: dict[str, str]) -> bool:
    """
    Evaluate a BChecks condition string against the current context.
    Handles: string containment, regex match, equality, not(), and/or, parenthesized groups.
    Returns False (not a finding) for OAST conditions.
    """
    raw = raw.strip()
    if not raw:
        return False

    # OAST conditions — always skip (no Collaborator)
    if re.search(r"\b(http|dns|any)\s+interactions\b", raw, re.I):
        return False

    # not(COND)
    m = re.match(r"not\s*\(\s*(.+)\s*\)\s*$", raw, re.I)
    if m:
        return not _eval_condition(m.group(1), ctx)

    # Split on top-level `and` / `or` (not inside parentheses)
    parts_and, parts_or = _split_top_level(raw)
    if parts_and:
        return all(_eval_condition(p, ctx) for p in parts_and)
    if parts_or:
        return any(_eval_condition(p, ctx) for p in parts_or)

    # Parenthesized group — evaluate inner
    m = re.match(r"^\s*\(\s*(.+)\s*\)\s*$", raw, re.I | re.S)
    if m:
        return _eval_condition(m.group(1), ctx)

    # {VAR} in {VAR2} — variable-reference containment (e.g. {answer} in {base.response})
    m = re.match(r'\{([^}]+)\}\s+in\s+\{([^}]+)\}', raw, re.I)
    if m:
        var1, var2 = m.group(1), m.group(2)
        pattern = ctx.get(var1, "")
        haystack = _resolve("{" + var2 + "}", ctx)
        return bool(pattern) and pattern.lower() in haystack.lower()

    # "pattern" in {VAR} or {VAR} in {VAR2}
    m = re.match(r'"([^"]*)"(?i)\s+in\s+\{([^}]+)\}', raw, re.I)
    if m:
        pattern, var = m.group(1), m.group(2)
        haystack = _resolve("{" + var + "}", ctx)
        return pattern.lower() in haystack.lower()

    m = re.match(r'`([^`]*)`\s+in\s+\{([^}]+)\}', raw, re.I)
    if m:
        pattern, var = m.group(1), m.group(2)
        resolved_pattern = _resolve(pattern, ctx)
        haystack = _resolve("{" + var + "}", ctx)
        return resolved_pattern.lower() in haystack.lower()

    # {VAR} matches "REGEX"
    m = re.match(r'\{([^}]+)\}\s+matches\s+"([^"]*)"', raw, re.I)
    if m:
        var, pattern = m.group(1), m.group(2)
        haystack = _resolve("{" + var + "}", ctx)
        try:
            return bool(re.search(pattern, haystack, re.I))
        except re.error:
            return False

    # {VAR} is "VALUE"
    m = re.match(r'\{([^}]+)\}\s+is\s+"([^"]*)"', raw, re.I)
    if m:
        var, value = m.group(1), m.group(2)
        actual = _resolve("{" + var + "}", ctx)
        return actual == value

    # {VAR} is not "VALUE"
    m = re.match(r'\{([^}]+)\}\s+is\s+not\s+"([^"]*)"', raw, re.I)
    if m:
        var, value = m.group(1), m.group(2)
        actual = _resolve("{" + var + "}", ctx)
        return actual != value

    log.debug("BCheck: unrecognized condition: %r", raw[:120])
    return False


def _split_top_level(raw: str) -> tuple[list[str], list[str]]:
    """
    Split on top-level `and` or `or` (not inside parentheses/quotes).
    Returns (and_parts, or_parts). One will be non-empty only if split found.
    """
    depth = 0
    in_quote = False
    quote_char = None
    i = 0
    n = len(raw)

    and_splits: list[int] = []
    or_splits: list[int] = []

    while i < n:
        ch = raw[i]
        if in_quote:
            if ch == quote_char and (i == 0 or raw[i-1] != "\\"):
                in_quote = False
        elif ch in ('"', "'", "`"):
            in_quote = True
            quote_char = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and not in_quote:
            if raw[i:i+5].lower() == " and ":
                and_splits.append(i)
                i += 5
                continue
            if raw[i:i+4].lower() == " or ":
                or_splits.append(i)
                i += 4
                continue
        i += 1

    if and_splits:
        parts = []
        prev = 0
        for pos in and_splits:
            parts.append(raw[prev:pos].strip())
            prev = pos + 5
        parts.append(raw[prev:].strip())
        return parts, []

    if or_splits:
        parts = []
        prev = 0
        for pos in or_splits:
            parts.append(raw[prev:pos].strip())
            prev = pos + 4
        parts.append(raw[prev:].strip())
        return [], parts

    return [], []


# ─── Engine ───────────────────────────────────────────────────────────────────

class BCheckEngine:
    """
    Loads all .bcheck files from bchecks/ and executes them against a target.

    Usage:
        engine = BCheckEngine(bchecks_dir="/path/to/bchecks", session=requests_session)
        findings = engine.run(sitemap=sitemap, target="https://example.com")
    """

    def __init__(
        self,
        bchecks_dir: str | Path,
        session: Optional[requests.Session] = None,
        timeout: int = 10,
        stop_event: Any = None,
    ):
        self._timeout = timeout
        self._session = session or requests.Session()
        self._session.verify = False
        self._stop_event = stop_event
        self._specs: list[BCheckSpec] = []

        bchecks_dir = Path(bchecks_dir)
        parser = BCheckParser()
        loaded = skipped = 0

        for bcheck_file in sorted(bchecks_dir.rglob("*.bcheck")):
            spec = parser.parse(str(bcheck_file))
            if spec is None:
                skipped += 1
                continue
            if spec.oast_required:
                log.info("BCheck: skipping OAST check (no Collaborator): %s", spec.name)
                skipped += 1
                continue
            if spec.trigger in ("insertion_point",):
                log.debug("BCheck: skipping insertion-point check (not yet integrated): %s", spec.name)
                skipped += 1
                continue
            self._specs.append(spec)
            loaded += 1

        log.info("BCheckEngine: loaded %d checks, skipped %d", loaded, skipped)

    @property
    def check_count(self) -> int:
        return len(self._specs)

    def run(self, sitemap: Any, target: str) -> list[dict]:
        """
        Run all loaded checks against the target.

        Args:
            sitemap: SiteMap object with .pages dict (url -> page_info)
            target:  Base target URL (e.g. "https://example.com")

        Returns:
            List of finding dicts compatible with the DAST finding schema.
        """
        findings: list[dict] = []
        urls = list(sitemap.pages.keys()) if sitemap and hasattr(sitemap, "pages") else [target]

        # Group checks by trigger type
        response_checks = [s for s in self._specs if s.trigger == "response"]
        host_checks     = [s for s in self._specs if s.trigger == "host"]
        request_checks  = [s for s in self._specs if s.trigger == "request"]
        path_checks     = [s for s in self._specs if s.trigger == "path"]

        log.info("BCheck: running %d passive, %d host, %d request, %d path checks on %d URLs",
                 len(response_checks), len(host_checks), len(request_checks), len(path_checks), len(urls))

        # 1. Passive: given response then — fetch each URL, run all passive checks
        if response_checks:
            for url in urls:
                if self._stopped():
                    break
                resp_ctx = self._fetch(url)
                if resp_ctx is None:
                    continue
                for spec in response_checks:
                    if self._stopped():
                        break
                    results = self._execute(spec, url, base_ctx=resp_ctx)
                    findings.extend(results)

        # 2. Host checks — run once per host (deduplicated)
        if host_checks:
            seen_hosts: set[str] = set()
            for url in [target] + urls:
                parsed = urlparse(url)
                host_base = f"{parsed.scheme}://{parsed.netloc}"
                if host_base in seen_hosts:
                    continue
                seen_hosts.add(host_base)
                for spec in host_checks:
                    if self._stopped():
                        break
                    results = self._execute(spec, host_base, base_ctx={})
                    findings.extend(results)

        # 3. Request checks — run per crawled URL
        if request_checks:
            for url in urls:
                if self._stopped():
                    break
                for spec in request_checks:
                    if self._stopped():
                        break
                    results = self._execute(spec, url, base_ctx={})
                    findings.extend(results)

        # 4. Path checks — run per path entry against host
        if path_checks:
            parsed = urlparse(target)
            host_base = f"{parsed.scheme}://{parsed.netloc}"
            for spec in path_checks:
                if self._stopped():
                    break
                results = self._execute(spec, host_base, base_ctx={})
                findings.extend(results)

        log.info("BCheck: %d total findings", len(findings))
        return findings

    # ── Execution ─────────────────────────────────────────────────────────────

    def _execute(self, spec: BCheckSpec, base_url: str, base_ctx: dict) -> list[dict]:
        """Execute a single BCheckSpec against base_url. Returns list of finding dicts."""
        findings: list[dict] = []

        # Build iteration combinations from run_for_each
        iterations = self._build_iterations(spec)

        for iter_ctx in iterations:
            ctx = dict(base_ctx)
            # Add defines (resolving templates)
            for var, template in spec.defines.items():
                # Handle random_str() at execution time
                def resolve_random(t: str) -> str:
                    return re.sub(r"\{random_str\((\d+)\)\}", lambda m: _random_str(int(m.group(1))), t)
                ctx[var] = resolve_random(template)
            ctx.update(iter_ctx)

            # Execute top-level requests
            for req in spec.top_requests:
                resp_ctx, ok = self._send_request(req, base_url, ctx)
                if ok:
                    ctx.update(resp_ctx)

            # Evaluate conditional blocks
            for block in spec.blocks:
                try:
                    block_findings = self._eval_block(block, base_url, spec, ctx)
                    findings.extend(block_findings)
                except Exception as exc:
                    log.debug("BCheck %s: block error: %s", spec.name, exc)

        return findings

    def _build_iterations(self, spec: BCheckSpec) -> list[dict]:
        """Build list of context dicts for each run_for_each combination."""
        if not spec.run_for_each:
            return [{}]

        # Cartesian product of all run_for_each variables
        import itertools
        vars_list = list(spec.run_for_each.keys())
        vals_list = [spec.run_for_each[v] for v in vars_list]

        iterations = []
        for combo in itertools.product(*vals_list):
            ctx = {vars_list[k]: combo[k] for k in range(len(vars_list))}
            iterations.append(ctx)
        return iterations

    def _eval_block(self, block: BCheckBlock, base_url: str, spec: BCheckSpec, ctx: dict) -> list[dict]:
        """Evaluate one if block, returning any findings."""
        findings: list[dict] = []

        if not _eval_condition(block.raw_condition, ctx):
            return findings

        # Execute inner send requests
        for req in block.send_requests:
            resp_ctx, ok = self._send_request(req, base_url, ctx)
            if ok:
                ctx.update(resp_ctx)

        # Report issue if present
        if block.issue:
            finding = self._make_finding(block.issue, base_url, spec, ctx)
            findings.append(finding)
            if not block.issue.continue_after:
                return findings

        # Evaluate nested blocks
        for nested in block.nested_blocks:
            try:
                nested_findings = self._eval_block(nested, base_url, spec, ctx)
                findings.extend(nested_findings)
            except Exception as exc:
                log.debug("BCheck %s: nested block error: %s", spec.name, exc)

        return findings

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> Optional[dict]:
        """Fetch a URL and return a context dict with response.* keys (including base.*)."""
        try:
            resp = self._session.get(url, timeout=self._timeout, allow_redirects=True)
            return self._resp_to_ctx("latest", resp, include_base=True)
        except Exception as exc:
            log.debug("BCheck: fetch failed for %s: %s", url, exc)
            return None

    def _send_request(self, req: BCheckRequest, base_url: str, ctx: dict) -> tuple[dict, bool]:
        """Send an HTTP request and return (context_update, success)."""
        try:
            # Build URL
            if req.path:
                resolved_path = _resolve(req.path, ctx)
                url = urljoin(base_url.rstrip("/") + "/", resolved_path.lstrip("/"))
            elif req.appending_path:
                resolved_append = _resolve(req.appending_path, ctx)
                url = base_url.rstrip("/") + resolved_append
            else:
                url = base_url

            method = req.method.upper()
            resolved_headers = {k: _resolve(v, ctx) for k, v in req.headers.items()} if req.headers else {}
            resp = self._session.request(
                method, url,
                headers=resolved_headers,
                data=_resolve(req.body, ctx) if req.body else None,
                timeout=self._timeout,
                allow_redirects=True,
            )
            name = req.name if req.name else "latest"
            ctx_update = self._resp_to_ctx(name, resp)
            # Always update "latest" too
            if name != "latest":
                ctx_update.update(self._resp_to_ctx("latest", resp))
            return ctx_update, True

        except Exception as exc:
            log.debug("BCheck: request failed (%s %s): %s", req.method, req.path, exc)
            return {}, False

    @staticmethod
    def _resp_to_ctx(name: str, resp: requests.Response, include_base: bool = False) -> dict:
        """Convert an HTTP response to BChecks context variables.

        Args:
            name: Response name (e.g. "latest", "checkRequest")
            resp: HTTP response
            include_base: If True, also set base.response.* keys (only for initial fetch)
        """
        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = resp.text[:65536]  # cap at 64KB to avoid memory issues
        full = headers_str + "\r\n\r\n" + body
        ctx = {
            f"{name}.response": full,
            f"{name}.response.body": body,
            f"{name}.response.headers": headers_str,
            f"{name}.response.status_code": str(resp.status_code),
            "latest.response": full,
            "latest.response.body": body,
            "latest.response.headers": headers_str,
            "latest.response.status_code": str(resp.status_code),
        }
        if include_base:
            ctx["base.response"] = full
            ctx["base.response.body"] = body
            ctx["base.response.headers"] = headers_str
            ctx["base.response.status_code"] = str(resp.status_code)
        return ctx

    @staticmethod
    def _make_finding(issue: BCheckIssue, url: str, spec: BCheckSpec, ctx: dict) -> dict:
        """Convert a BCheckIssue into a DAST finding dict."""
        severity_map = {
            "high": "High", "medium": "Medium", "low": "Low",
            "info": "Info", "information": "Info",
        }
        confidence_map = {
            "certain": "Certain", "firm": "Firm", "tentative": "Tentative",
        }
        detail = _resolve(issue.detail, ctx)
        remediation = _resolve(issue.remediation, ctx)
        return {
            "url": url,
            "category": "BChecks",
            "finding": spec.name,
            "severity": severity_map.get(issue.severity.lower(), "Info"),
            "confidence": confidence_map.get(issue.confidence.lower(), "Tentative"),
            "evidence": detail[:500] if detail else spec.description,
            "remediation": remediation,
            "cwe": "",
            "tags": ", ".join(spec.tags),
            "check_author": spec.author,
        }

    def _stopped(self) -> bool:
        return self._stop_event is not None and self._stop_event.is_set()
