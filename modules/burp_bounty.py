"""
BurpBounty profile engine for DAST.

Loads all .bb JSON profiles from BurpBountyData/profiles/ and provides:
  - Active scanning: inject payloads per InsertionPointType, grep responses
  - Passive scanning: grep request/response without injection

Profile format: BurpBountyPro v3.0.0 .bb JSON
"""
from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore

log = logging.getLogger("dast.burp_bounty")


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class BurpBountyGrepRule:
    """Parsed grep rule from a .bb profile Grep array entry."""
    enabled: bool
    logic: str       # "AND" or "OR"
    match_type: str  # "Simple String" or "Regex"
    position: str    # "" | "Not in Headers" | "In Headers"
    pattern: str


@dataclass
class BurpBountyProfile:
    """Parsed BurpBounty .bb scan profile."""
    profile_name: str
    scanner: int           # 1=active, 2=passive-req, 3=passive-resp
    payloads: list         # list[str] (enabled only)
    grep_rules: list       # list[BurpBountyGrepRule]
    tags: list             # list[str]
    insertion_point_types: list  # list[int]
    is_header_value: bool
    new_headers: list      # list[str] for custom header injection
    is_time: bool
    timeout1: float        # seconds
    timeout2: float
    negative_ct: bool
    content_types: list    # list[str] to exclude (when negative_ct=True)
    issue_name: str
    issue_severity: str
    issue_confidence: str
    steps: list            # list[dict] raw step objects
    enabled: bool = True


@dataclass
class BurpBountyFinding:
    """Finding produced by the BurpBounty engine."""
    url: str
    profile_name: str
    issue_name: str
    severity: str
    confidence: str
    evidence: str
    payload: str
    matched_grep: str
    tags: list
    cwe: str = "CWE-0"
    agent_id: str = "burp_bounty"
    icon: str = "🎯"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "profile_name": self.profile_name,
            "issue_name": self.issue_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "payload": self.payload,
            "matched_grep": self.matched_grep,
            "tags": self.tags,
            "cwe": self.cwe,
            "agent_id": self.agent_id,
            "icon": self.icon,
        }


# ── Parse helpers ─────────────────────────────────────────────────────────────

def _parse_payloads(raw: list) -> list:
    """
    Parse ["true,value", "false,value", ...] → list of enabled payload strings.
    Splits on first comma only to preserve commas in payload values.
    """
    result = []
    for item in raw:
        try:
            parts = str(item).split(",", 1)
            if len(parts) == 2 and parts[0].strip().lower() == "true":
                result.append(parts[1])
        except Exception:
            continue
    return result


def _parse_grep_rules(raw: list) -> list:
    """
    Parse ["enabled,logic,type,position,pattern", ...] → list[BurpBountyGrepRule].
    Uses maxsplit=4 to preserve commas in regex patterns.
    """
    result = []
    for item in raw:
        try:
            parts = str(item).split(",", 4)
            # Pad to 5 parts
            while len(parts) < 5:
                parts.append("")
            enabled = parts[0].strip().lower() == "true"
            if not enabled:
                continue
            logic = parts[1].strip().upper() if parts[1].strip() else "AND"
            match_type = parts[2].strip() if parts[2].strip() else "Simple String"
            position = parts[3].strip()
            pattern = parts[4].strip()
            if not pattern:
                continue
            result.append(BurpBountyGrepRule(
                enabled=True,
                logic=logic,
                match_type=match_type,
                position=position,
                pattern=pattern,
            ))
        except Exception:
            continue
    return result


def _to_float(v) -> float:
    """Convert timeout string to float, 0.0 on failure."""
    try:
        return float(v) if v else 0.0
    except (TypeError, ValueError):
        return 0.0


def load_profiles(directory: str) -> list:
    """
    Load all .bb files from directory → list[BurpBountyProfile].
    Gracefully skips malformed files.
    """
    profiles = []
    bb_dir = Path(directory)
    if not bb_dir.exists():
        log.warning("BurpBounty profiles directory not found: %s", directory)
        return profiles

    for bb_file in sorted(bb_dir.glob("*.bb")):
        try:
            raw = json.loads(bb_file.read_text(encoding="utf-8"))
            if not isinstance(raw, list) or not raw:
                continue
            d = raw[0]

            ct_raw = d.get("ContentType", "")
            content_types = [x.strip() for x in ct_raw.split(",") if x.strip()] if ct_raw else []

            profile = BurpBountyProfile(
                profile_name=d.get("ProfileName", bb_file.stem),
                scanner=int(d.get("Scanner", 1)),
                payloads=_parse_payloads(d.get("Payloads", [])),
                grep_rules=_parse_grep_rules(d.get("Grep", [])),
                tags=d.get("Tags", []),
                insertion_point_types=d.get("InsertionPointType", []),
                is_header_value=bool(d.get("isHeaderValue", False)),
                new_headers=d.get("NewHeaders", []),
                is_time=bool(d.get("isTime", False)),
                timeout1=_to_float(d.get("TimeOut1", "")),
                timeout2=_to_float(d.get("TimeOut2", "")),
                negative_ct=bool(d.get("NegativeCT", False)),
                content_types=content_types,
                issue_name=d.get("IssueName", d.get("ProfileName", bb_file.stem)),
                issue_severity=d.get("IssueSeverity", "Information"),
                issue_confidence=d.get("IssueConfidence", "Tentative"),
                steps=d.get("steps", []),
                enabled=bool(d.get("Enabled", True)),
            )
            profiles.append(profile)
        except Exception as exc:
            log.warning("Failed to parse BurpBounty profile %s: %s", bb_file.name, exc)

    log.info("Loaded %d BurpBounty profiles from %s", len(profiles), directory)
    return profiles


# ── Grep evaluator ────────────────────────────────────────────────────────────

def _eval_grep_rules(rules: list, text: str, case_sensitive: bool = False) -> tuple:
    """
    Evaluate list[BurpBountyGrepRule] against text.
    Returns (matched: bool, evidence: str).

    First rule is the base AND condition.
    Subsequent OR rules: any match satisfies.
    Subsequent AND rules: all must match.
    """
    if not rules:
        return False, ""

    result = None
    evidence = ""

    for rule in rules:
        if rule.match_type == "Regex":
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                m = re.search(rule.pattern, text, flags)
                matched = bool(m)
            except re.error:
                matched = False
        else:
            # Simple String
            if case_sensitive:
                matched = rule.pattern in text
            else:
                matched = rule.pattern.lower() in text.lower()

        if result is None:
            result = matched
            if matched:
                evidence = rule.pattern
        elif rule.logic == "OR":
            if matched and not evidence:
                evidence = rule.pattern
            result = result or matched
        else:
            # AND
            result = result and matched
            if matched and not evidence:
                evidence = rule.pattern

    return (bool(result) if result is not None else False, evidence)


# ── Variable substitution ─────────────────────────────────────────────────────

def _substitute_vars(text: str, oast_url: str = "", nonce: str = "",
                     current_url: str = "") -> str:
    """Replace BurpBounty dynamic variables: {BC}, {RANDOM}, {CURRENT_URL}, etc."""
    if not nonce:
        nonce = uuid.uuid4().hex[:8]
    parsed = urlparse(current_url) if current_url else None
    host = parsed.netloc if parsed else ""
    port = str(parsed.port) if parsed and parsed.port else ""

    text = text.replace("{BC}", oast_url or "oast.local")
    text = text.replace("{RANDOM}", nonce)
    text = text.replace("{CURRENT_URL}", current_url or "")
    text = text.replace("{CURRENT_HOST}", host)
    text = text.replace("{CURRENT_PORT}", port)
    return text


# ── Injection helpers ─────────────────────────────────────────────────────────

def _inject_query_params(url: str, payload: str) -> list:
    """Inject payload into each query param. Returns list of modified URL strings."""
    variants = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        new_query = urlencode({"bb_test": payload})
        variants.append(urlunparse(parsed._replace(query=new_query)))
    else:
        for param_name in params:
            modified = {k: v[:] for k, v in params.items()}
            modified[param_name] = [payload]
            new_query = urlencode(modified, doseq=True)
            variants.append(urlunparse(parsed._replace(query=new_query)))

    return variants


def _inject_post_body(body: str, payload: str) -> list:
    """Inject payload into each POST body field. Returns list of modified body strings."""
    variants = []

    # Try JSON body
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for key in data:
                if isinstance(data[key], str):
                    modified = dict(data)
                    modified[key] = payload
                    variants.append(json.dumps(modified))
            if variants:
                return variants
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    # Try form-urlencoded
    if "=" in body:
        try:
            params = parse_qs(body, keep_blank_values=True)
            if params:
                for param_name in params:
                    modified = {k: v[:] for k, v in params.items()}
                    modified[param_name] = [payload]
                    variants.append(urlencode(modified, doseq=True))
                if variants:
                    return variants
        except Exception:
            pass

    # Raw body — append
    return [body + payload]


def _inject_headers(profile: BurpBountyProfile, payload: str,
                    base_headers: dict) -> list:
    """
    Build list of header dicts with payload injected.
    Handles NewHeaders[] custom injection and standard header value injection.
    """
    variants = []

    if profile.is_header_value and profile.new_headers:
        for header_name in profile.new_headers:
            h = dict(base_headers)
            h[header_name] = payload
            variants.append(h)
    elif 6 in profile.insertion_point_types:
        for header_name in base_headers:
            if header_name.lower() in ("host", "content-length", "transfer-encoding"):
                continue
            h = dict(base_headers)
            h[header_name] = payload
            variants.append(h)

    return variants


def _should_skip_for_content_type(profile: BurpBountyProfile,
                                   response_content_type: str) -> bool:
    """Return True if profile's NegativeCT excludes this content type."""
    if not profile.negative_ct or not profile.content_types:
        return False
    resp_ct_lower = response_content_type.lower()
    for ct in profile.content_types:
        if ct.lower() in resp_ct_lower:
            return True
    return False


# ── Active profile runner ─────────────────────────────────────────────────────

def run_active_profile(session, url: str, profile: BurpBountyProfile,
                       oast_url: str = "") -> list:
    """
    Run a single active BurpBountyProfile against url.
    Returns list[BurpBountyFinding].
    """
    findings = []
    seen: set = set()

    try:
        nonce = uuid.uuid4().hex[:8]

        # Multi-step profiles use steps[]; single-step use synthetic step
        if profile.steps:
            steps_to_run = profile.steps
        else:
            steps_to_run = [{"Payloads": [f"true,{p}" for p in profile.payloads],
                             "Grep": []}]

        base_headers: dict = {"User-Agent": "Mozilla/5.0 (DAST-BurpBounty-Scanner)"}
        session_cookies: dict = {}

        for step in steps_to_run:
            raw_step_payloads = step.get("Payloads", [])
            step_payloads = _parse_payloads(raw_step_payloads) if raw_step_payloads else profile.payloads

            raw_step_grep = step.get("Grep", [])
            step_grep_rules = _parse_grep_rules(raw_step_grep) if raw_step_grep else profile.grep_rules

            if not step_payloads:
                continue

            for payload in step_payloads:
                final_payload = _substitute_vars(payload, oast_url, nonce, url)

                ipts = profile.insertion_point_types
                injection_jobs = []  # list of (req_url, method, headers, body)

                # Query param injection: types 1, 64, 65
                if any(t in ipts for t in (1, 64, 65)) or not ipts:
                    for mod_url in _inject_query_params(url, final_payload):
                        injection_jobs.append((mod_url, "GET", dict(base_headers), ""))

                # POST body injection: types 2, 64, 65
                if any(t in ipts for t in (2, 64, 65)):
                    for mod_body in _inject_post_body("", final_payload):
                        injection_jobs.append((url, "POST", dict(base_headers), mod_body))

                # Cookie injection: type 5
                if 5 in ipts:
                    h = dict(base_headers)
                    h["Cookie"] = f"bb_test={final_payload}"
                    injection_jobs.append((url, "GET", h, ""))

                # Header injection: types 6, 18 or is_header_value=True
                if 6 in ipts or 18 in ipts or profile.is_header_value:
                    for h in _inject_headers(profile, final_payload, base_headers):
                        injection_jobs.append((url, "GET", h, ""))

                # URL path injection: type 0
                if 0 in ipts:
                    parsed = urlparse(url)
                    new_path = parsed.path.rstrip("/") + "/" + quote(final_payload, safe="")
                    mod_url = urlunparse(parsed._replace(path=new_path))
                    injection_jobs.append((mod_url, "GET", dict(base_headers), ""))

                for (req_url, method, headers, body) in injection_jobs:
                    try:
                        if session_cookies:
                            existing = headers.get("Cookie", "")
                            extra = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
                            headers["Cookie"] = f"{existing}; {extra}".strip("; ")

                        start = time.monotonic()
                        if method == "POST":
                            ct = "application/json" if body.startswith("{") else "application/x-www-form-urlencoded"
                            headers["Content-Type"] = ct
                            resp = session.post(req_url, data=body, headers=headers,
                                                timeout=15, allow_redirects=True)
                        else:
                            resp = session.get(req_url, headers=headers,
                                               timeout=15, allow_redirects=True)
                        elapsed = time.monotonic() - start

                        if step.get("reuseCookie"):
                            session_cookies.update(dict(resp.cookies))

                        resp_ct = resp.headers.get("content-type", "")
                        if _should_skip_for_content_type(profile, resp_ct):
                            continue

                        finding = None

                        if profile.is_time and profile.timeout1 > 0:
                            if elapsed >= profile.timeout1:
                                finding = BurpBountyFinding(
                                    url=req_url,
                                    profile_name=profile.profile_name,
                                    issue_name=profile.issue_name,
                                    severity=profile.issue_severity,
                                    confidence=profile.issue_confidence,
                                    evidence=f"Response time {elapsed:.1f}s >= threshold {profile.timeout1}s",
                                    payload=final_payload,
                                    matched_grep=f"time_based:{elapsed:.1f}s",
                                    tags=profile.tags,
                                )
                        elif step_grep_rules:
                            matched, evidence = _eval_grep_rules(step_grep_rules, resp.text)
                            if matched:
                                finding = BurpBountyFinding(
                                    url=req_url,
                                    profile_name=profile.profile_name,
                                    issue_name=profile.issue_name,
                                    severity=profile.issue_severity,
                                    confidence=profile.issue_confidence,
                                    evidence=f"Grep matched: {evidence}",
                                    payload=final_payload,
                                    matched_grep=evidence,
                                    tags=profile.tags,
                                )
                        elif oast_url and "{BC}" in payload:
                            # OAST profile — payload injected, callback via OOB
                            finding = BurpBountyFinding(
                                url=req_url,
                                profile_name=profile.profile_name,
                                issue_name=profile.issue_name,
                                severity=profile.issue_severity,
                                confidence="Tentative",
                                evidence=f"OAST payload injected: {final_payload[:80]}",
                                payload=final_payload,
                                matched_grep="oast_injected",
                                tags=profile.tags,
                            )

                        if finding:
                            dedup_key = (finding.url, finding.profile_name, finding.matched_grep)
                            if dedup_key not in seen:
                                seen.add(dedup_key)
                                findings.append(finding)

                    except Exception as req_exc:
                        log.debug("BurpBounty request error [%s / %s]: %s",
                                  req_url, profile.profile_name, req_exc)

    except Exception as exc:
        log.warning("run_active_profile error for %s: %s", profile.profile_name, exc)

    return findings


# ── Passive profile runner ────────────────────────────────────────────────────

def run_passive_profile(url: str, body: str, headers_dict: dict,
                        profile: BurpBountyProfile) -> list:
    """
    Run a single passive profile (scanner=2 or 3) against response data.
    No HTTP requests — grep only.
    Returns list[BurpBountyFinding].
    """
    findings = []
    try:
        resp_ct = (headers_dict.get("content-type")
                   or headers_dict.get("Content-Type") or "")
        if _should_skip_for_content_type(profile, resp_ct):
            return findings

        if not profile.grep_rules:
            return findings

        if profile.scanner == 2:
            # Passive request: grep URL + request representation
            text = url + "\n" + str(headers_dict)
        else:
            # Passive response: grep body + response headers
            text = body + "\n" + str(headers_dict)

        matched, evidence = _eval_grep_rules(profile.grep_rules, text)
        if matched:
            findings.append(BurpBountyFinding(
                url=url,
                profile_name=profile.profile_name,
                issue_name=profile.issue_name,
                severity=profile.issue_severity,
                confidence=profile.issue_confidence,
                evidence=f"Grep matched: {evidence}",
                payload="",
                matched_grep=evidence,
                tags=profile.tags,
            ))
    except Exception as exc:
        log.debug("run_passive_profile error for %s: %s", profile.profile_name, exc)
    return findings


# ── BurpBountyEngine ──────────────────────────────────────────────────────────

class BurpBountyEngine:
    """
    Loads all BurpBounty .bb profiles and orchestrates active + passive scanning.

    Usage:
        engine = BurpBountyEngine()          # loads profiles from BurpBountyData/profiles/
        findings = engine.run_active(session, "https://target.com/", tags_filter=["SQLi"])
        passive_findings = engine.run_passive(url, response_body, response_headers)
    """

    def __init__(self, profiles_dir: str = ""):
        if not profiles_dir:
            # Search common locations for BurpBountyData/profiles/
            candidates = [
                # Project root
                Path(__file__).parent.parent / "BurpBountyData" / "profiles",
                # Downloads (common install location)
                Path.home() / "Downloads" / "BurpBountyPro_v3.0.0" / "BurpBountyData" / "profiles",
                Path.home() / "Downloads" / "BurpBountyData" / "profiles",
            ]
            # Also glob Downloads for any BurpBountyPro_* directory
            try:
                for p in sorted((Path.home() / "Downloads").glob("BurpBountyPro_*")):
                    candidates.append(p / "BurpBountyData" / "profiles")
            except Exception:
                pass

            profiles_dir = str(Path(__file__).parent.parent / "BurpBountyData" / "profiles")
            for candidate in candidates:
                if candidate.exists():
                    profiles_dir = str(candidate)
                    break
        self.profiles_dir = profiles_dir
        self.profiles: list = []
        self._load()

    def _load(self) -> None:
        self.profiles = load_profiles(self.profiles_dir)

    def list_profiles(self) -> list:
        """Return metadata list for all loaded profiles."""
        return [
            {
                "profile_name": p.profile_name,
                "scanner": p.scanner,
                "tags": p.tags,
                "issue_name": p.issue_name,
                "issue_severity": p.issue_severity,
                "enabled": p.enabled,
            }
            for p in self.profiles
        ]

    def run_active(self, session, url: str,
                   tags_filter: list = None,
                   oast_url: str = "") -> list:
        """
        Run all enabled active profiles (scanner=1) against url.
        tags_filter: optional list of tag strings (case-insensitive); None = run all.
        Returns list[BurpBountyFinding].
        """
        findings = []
        for profile in self.profiles:
            if not profile.enabled or profile.scanner != 1:
                continue
            if tags_filter:
                profile_tags_lower = [t.lower() for t in profile.tags]
                if not any(f.lower() in profile_tags_lower for f in tags_filter):
                    continue
            findings += run_active_profile(session, url, profile, oast_url)
        return findings

    def run_passive(self, url: str, body: str, headers_dict: dict) -> list:
        """
        Run all enabled passive profiles (scanner=2/3) against response data.
        Returns list[BurpBountyFinding].
        """
        findings = []
        for profile in self.profiles:
            if not profile.enabled or profile.scanner not in (2, 3):
                continue
            findings += run_passive_profile(url, body, headers_dict, profile)
        return findings
