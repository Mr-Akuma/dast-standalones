"""
YAML BChecks Engine — YAML-defined custom scan rules for DAST standalone.

Loads `.yaml` rule files from the `bchecks/` directory and runs them as
additional scan checks.  Provides the extensibility of Burp BChecks without
requiring knowledge of the Burp DSL syntax — rules are plain YAML.

YAML Rule format:

    name: "Sensitive file exposure"
    trigger: host                   # host | request
    request:
      path: "/.env"                 # relative path to probe (host trigger)
      method: GET                   # default: GET
      headers: {}                   # optional extra headers
    detection:
      status_code: 200              # optional — exact status match
      body_contains: "DB_PASSWORD"  # optional — substring in response body
      body_regex: "APP_KEY=base64:" # optional — regex search in response body
    issue:
      name: "Sensitive File Exposed"
      severity: high                # critical | high | medium | low | info
      confidence: certain           # certain | firm | tentative
      detail: "The .env file is publicly readable."
      remediation: "Block .env access at the web server level."

Trigger modes:
    host     — sends one request per rule to the target host (new path probe)
    request  — replays each discovered URL from the sitemap (passive-style active)

All three detection conditions are optional; a finding is emitted if ANY
enabled condition matches.  If no conditions are specified the rule matches
every response (useful for informational rules).
"""
from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _yaml = None        # type: ignore
    _HAS_YAML = False

log = logging.getLogger("yaml_bcheck")

# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class YAMLRule:
    """Parsed YAML BCheck rule."""
    name:         str   = ""
    trigger:      str   = "host"       # host | request
    # request fields
    path:         str   = "/"
    method:       str   = "GET"
    headers:      dict  = field(default_factory=dict)
    body:         str   = ""
    # detection conditions (all optional — any match → finding)
    status_code:  Optional[int]   = None
    body_contains: Optional[str]  = None
    body_regex:   Optional[str]   = None
    # issue metadata
    issue_name:   str   = ""
    severity:     str   = "info"
    confidence:   str   = "tentative"
    detail:       str   = ""
    remediation:  str   = ""

    def matches(self, resp: requests.Response) -> bool:
        """Return True if this rule's detection conditions match the response."""
        # No conditions specified → always match (informational)
        if self.status_code is None and self.body_contains is None and self.body_regex is None:
            return True
        hit = False
        if self.status_code is not None:
            hit = hit or (resp.status_code == self.status_code)
        if self.body_contains is not None:
            hit = hit or (self.body_contains in (resp.text or ""))
        if self.body_regex is not None:
            try:
                hit = hit or bool(re.search(self.body_regex, resp.text or ""))
            except re.error:
                pass
        return hit


def _parse_rule(data: dict) -> Optional[YAMLRule]:
    """Parse a raw YAML dict into a YAMLRule.  Returns None on validation error."""
    try:
        issue  = data.get("issue", {})
        req    = data.get("request", {})
        det    = data.get("detection", {})
        return YAMLRule(
            name          = str(data.get("name", "Unnamed YAML Rule")),
            trigger       = str(data.get("trigger", "host")).lower(),
            path          = str(req.get("path", "/")),
            method        = str(req.get("method", "GET")).upper(),
            headers       = req.get("headers") or {},
            body          = str(req.get("body", "")),
            status_code   = int(det["status_code"]) if "status_code" in det else None,
            body_contains = str(det["body_contains"]) if "body_contains" in det else None,
            body_regex    = str(det["body_regex"])    if "body_regex"    in det else None,
            issue_name    = str(issue.get("name",         data.get("name", "Unnamed Issue"))),
            severity      = str(issue.get("severity",     "info")).lower(),
            confidence    = str(issue.get("confidence",   "tentative")).lower(),
            detail        = str(issue.get("detail",       "")),
            remediation   = str(issue.get("remediation",  "")),
        )
    except Exception as exc:
        log.warning("YAML BCheck parse error in rule %r: %s", data.get("name", "?"), exc)
        return None


# ── Engine ─────────────────────────────────────────────────────────────────────

class YAMLRuleEngine:
    """
    Loads and runs YAML BCheck rules.

    Interface mirrors BCheckEngine so it can be wired into app.py alongside it.
    """

    def __init__(
        self,
        bchecks_dir: str,
        session:     requests.Session,
        timeout:     int  = 10,
        stop_event:  Optional[threading.Event] = None,
    ):
        self._session    = session
        self._timeout    = timeout
        self._stop       = stop_event or threading.Event()
        self._rules: list[YAMLRule] = []
        self._load(bchecks_dir)

    # ── Loading ────────────────────────────────────────────────────────────────

    def _load(self, bchecks_dir: str) -> None:
        if not _HAS_YAML:
            log.warning("PyYAML not installed — YAML BChecks disabled")
            return
        root = Path(bchecks_dir)
        if not root.is_dir():
            return
        for yaml_path in sorted(root.rglob("*.yaml")):
            try:
                with yaml_path.open("r", encoding="utf-8") as fh:
                    data = _yaml.safe_load(fh)
                if not isinstance(data, dict):
                    continue
                rule = _parse_rule(data)
                if rule:
                    self._rules.append(rule)
                    log.debug("YAML BCheck loaded: %s", rule.name)
            except Exception as exc:
                log.warning("Failed to load YAML BCheck %s: %s", yaml_path, exc)

    @property
    def check_count(self) -> int:
        return len(self._rules)

    # ── Running ────────────────────────────────────────────────────────────────

    def run(self, sitemap: Any, target: str) -> list[dict]:
        findings: list[dict] = []
        parsed_target = urlparse(target)
        base_url      = f"{parsed_target.scheme}://{parsed_target.netloc}"

        for rule in self._rules:
            if self._stop.is_set():
                break
            if rule.trigger == "host":
                findings.extend(self._run_host_rule(rule, base_url))
            elif rule.trigger == "request":
                findings.extend(self._run_request_rule(rule, sitemap))
        return findings

    def _run_host_rule(self, rule: YAMLRule, base_url: str) -> list[dict]:
        url = urljoin(base_url, rule.path)
        try:
            resp = self._session.request(
                method  = rule.method,
                url     = url,
                headers = rule.headers,
                data    = rule.body or None,
                timeout = self._timeout,
                verify  = False,
                allow_redirects = True,
            )
            if rule.matches(resp):
                return [self._make_finding(rule, url, resp)]
        except Exception as exc:
            log.debug("YAML BCheck %r host probe error: %s", rule.name, exc)
        return []

    def _run_request_rule(self, rule: YAMLRule, sitemap: Any) -> list[dict]:
        results = []
        pages = getattr(sitemap, "pages", {})
        # pages is a dict url→info
        urls = list(pages.keys()) if isinstance(pages, dict) else []
        for url in urls:
            if self._stop.is_set():
                break
            try:
                resp = self._session.request(
                    method  = rule.method,
                    url     = url,
                    headers = rule.headers,
                    data    = rule.body or None,
                    timeout = self._timeout,
                    verify  = False,
                    allow_redirects = True,
                )
                if rule.matches(resp):
                    results.append(self._make_finding(rule, url, resp))
            except Exception as exc:
                log.debug("YAML BCheck %r request probe error for %s: %s", rule.name, url, exc)
        return results

    @staticmethod
    def _make_finding(rule: YAMLRule, url: str, resp: requests.Response) -> dict:
        return {
            "issue_name":   rule.issue_name or rule.name,
            "severity":     rule.severity,
            "confidence":   rule.confidence,
            "detail":       rule.detail,
            "remediation":  rule.remediation,
            "url":          url,
            "status_code":  resp.status_code,
            "agent":        "YAMLBChecks",
        }
