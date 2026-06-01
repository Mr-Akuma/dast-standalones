"""User-Agent Behavioral Diffing Scanner.

Inspired by PortSwigger's Identity Crisis extension. Detects when web
applications behave differently based on User-Agent header values.

Technique:
  1. Establish a response baseline by sending 3+ requests with the original UA.
  2. Replay the same request with categorized UA strings (desktop, mobile,
     crawlers, attack payloads).
  3. Compare each response against the baseline using SequenceMatcher after
     stripping naturally-varying headers (Date, ETag, Cache-Control, Expires).
  4. Report anomalous responses as findings — these indicate hidden attack
     surfaces, bot-detection bypass, UA-based auth differences, or reflected
     UA → XSS.

Security value:
  - Bot detection bypass: Googlebot UA may expose hidden content
  - Mobile vs desktop: different endpoints or skipped security checks
  - Reflected UA → XSS: unsanitised User-Agent in response body
  - WAF fingerprinting: different UAs trigger/bypass WAF rules differently
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, List, Optional

import requests

log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# USER-AGENT STRING CATEGORIES
# ═══════════════════════════════════════════════════════════════════════════════

_UA_DESKTOP = {
    "IE 6":      "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
    "IE 7":      "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
    "IE 8":      "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
    "IE 9":      "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "IE 10":     "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)",
    "IE 11":     "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "Firefox":   "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Chrome":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Edge":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Opera":     "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.12.388 Version/12.16",
    "Safari":    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

_UA_MOBILE = {
    "Android Chrome":  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "iPhone Safari":   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "iPad Safari":     "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Nokia":           "Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/12.0.024; Profile/MIDP-2.1 Configuration/CLDC-1.1) AppleWebKit/525 (KHTML, like Gecko) BrowserNG/7.1.12344",
    "Samsung":         "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
}

_UA_BOTS = {
    "Googlebot":       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot Mobile":"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Bingbot":         "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Yahoo Slurp":     "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Baiduspider":     "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "YandexBot":       "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "DuckDuckBot":     "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "curl":            "curl/8.4.0",
    "wget":            "Wget/1.21.4",
    "Python requests": "python-requests/2.31.0",
}

_UA_NON_BROWSER = {
    "Windows Media Player": "Windows-Media-Player/12.0.19041.3636",
    "PlayStation":          "Mozilla/5.0 (PlayStation; PlayStation 5/2.26) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15",
    "Smart TV":             "Mozilla/5.0 (SMART-TV; Linux; Tizen 7.0) AppleWebKit/537.36 (KHTML, like Gecko) Version/7.0 TV Safari/537.36",
    "Roku":                 "Roku4640X/DVP-7.70 (297.70E04154A)",
    "Alexa":                "Mozilla/5.0 (compatible; alexa site audit/2.0; +http://www.alexa.com/help/webmasters)",
}

_UA_ATTACK = {
    "XSS script tag":       '<script>alert("XSS")</script>',
    "XSS img onerror":      '<img src=x onerror=alert(1)>',
    "XSS svg onload":       '<svg/onload=alert(1)>',
    "SQLi single quote":    "' OR '1'='1",
    "SQLi UNION":           "' UNION SELECT NULL--",
    "SQLi comment":         "admin'--",
    "Path traversal unix":  "../../../../etc/passwd",
    "Path traversal win":   "..\\..\\..\\..\\windows\\system32\\config\\sam",
    "Path traversal null":  "....//....//etc/passwd%00",
    "SSTI Jinja2":          "{{7*7}}",
    "SSTI Twig":            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
    "CRLF injection":       "test\r\nX-Injected: true",
    "Log4Shell probe":      "${jndi:ldap://test.example.com/a}",
    "Empty UA":             "",
}

# Headers that vary naturally and should be stripped before comparison
_NOISY_HEADERS = frozenset({
    "date", "expires", "etag", "cache-control", "age", "x-request-id",
    "x-trace-id", "x-amzn-requestid", "x-correlation-id", "cf-ray",
    "set-cookie", "last-modified", "content-length",
})

# Vulnerability type constants
_VT_BEHAVIORAL_DIFF = "ua_behavioral_diff"
_VT_REFLECTED_XSS   = "ua_reflected_xss"
_VT_ATTACK_DIFF     = "ua_attack_diff"
_VT_BOT_DIFF        = "ua_bot_diff"

# Similarity threshold — below this, the response is considered anomalous
_SIMILARITY_THRESHOLD = 0.92

# Number of baseline requests to establish normal response pattern
_BASELINE_REQUESTS = 3

# Maximum endpoints to test (avoid excessive scan time)
_MAX_ENDPOINTS = 50


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING DATACLASS (mirrors ScanFinding from scanner.py, avoids circular import)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class UADiffFinding:
    """Finding from UA behavioral diffing — converts to ScanFinding-compatible dict."""
    id:             str
    url:            str
    method:         str
    param:          str    = "User-Agent"
    param_type:     str    = "header"
    vuln_type:      str    = _VT_BEHAVIORAL_DIFF
    owasp_category: str    = "A05:2021 Security Misconfiguration"
    cwe:            str    = "CWE-16"
    finding:        str    = ""
    severity:       str    = "Info"
    proof:          str    = ""
    payload:        str    = ""
    evidence_id:    Optional[str] = None
    remediation:    str    = "Ensure consistent application behavior regardless of User-Agent header. Do not serve different security controls based on User-Agent."
    chain_id:       Optional[str] = None
    chain_desc:     Optional[str] = None
    resp_time_ms:   float  = 0.0
    status_code:    int    = 0
    ts:             str    = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "url":            self.url,
            "method":         self.method,
            "param":          self.param,
            "param_type":     self.param_type,
            "vuln_type":      self.vuln_type,
            "owasp_category": self.owasp_category,
            "cwe":            self.cwe,
            "finding":        self.finding,
            "severity":       self.severity,
            "proof":          self.proof[:500] if self.proof else "",
            "payload":        self.payload,
            "evidence_id":    self.evidence_id,
            "remediation":    self.remediation,
            "chain_id":       self.chain_id,
            "chain_desc":     self.chain_desc,
            "resp_time_ms":   self.resp_time_ms,
            "status_code":    self.status_code,
            "ts":             self.ts,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# UA DIFF SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class UADiffScanner:
    """Detects behavioral differences in web application responses based on User-Agent header.

    Establishes a response baseline, then replays requests with varied UA strings
    across categories (desktop, mobile, bot, attack). Anomalous responses are
    reported as findings.
    """

    def __init__(
        self,
        session:    requests.Session,
        stop_event: Any = None,
        timeout:    int = 10,
        max_endpoints: int = _MAX_ENDPOINTS,
        similarity_threshold: float = _SIMILARITY_THRESHOLD,
    ):
        self.session = session
        self.stop_event = stop_event
        self.timeout = timeout
        self.max_endpoints = max_endpoints
        self.similarity_threshold = similarity_threshold

        # Combine all UA categories
        self._ua_strings: dict[str, dict[str, str]] = {
            "Desktop":     _UA_DESKTOP,
            "Mobile":      _UA_MOBILE,
            "Bot/Crawler": _UA_BOTS,
            "Non-Browser": _UA_NON_BROWSER,
            "Attack":      _UA_ATTACK,
        }

    def _stopped(self) -> bool:
        return self.stop_event is not None and self.stop_event.is_set()

    # ── Response normalization ────────────────────────────────────────────

    @staticmethod
    def _normalize_response(resp: requests.Response) -> str:
        """Normalize response for comparison: strip noisy headers, build comparable text."""
        parts = []

        # Status line
        parts.append(f"HTTP {resp.status_code}")

        # Headers (filtered)
        for name, value in sorted(resp.headers.items()):
            if name.lower() not in _NOISY_HEADERS:
                parts.append(f"{name}: {value}")

        # Body
        parts.append("")
        parts.append(resp.text[:15_000])  # Cap body at 15KB for comparison

        return "\n".join(parts)

    # ── Baseline establishment ────────────────────────────────────────────

    def _establish_baseline(self, url: str, method: str = "GET") -> tuple[list[str], int | None]:
        """Send N requests with the session's current UA and return (normalized_responses, status_code)."""
        baselines = []
        baseline_status: int | None = None
        for _ in range(_BASELINE_REQUESTS):
            if self._stopped():
                break
            try:
                resp = self.session.request(
                    method, url, timeout=self.timeout,
                    allow_redirects=True, verify=False,
                )
                baselines.append(self._normalize_response(resp))
                if baseline_status is None:
                    baseline_status = resp.status_code
            except requests.RequestException as e:
                log.debug("[UADiff] Baseline request failed for %s: %s", url, e)
        return baselines, baseline_status

    @staticmethod
    def _baseline_similarity(baselines: list[str]) -> float:
        """Compute minimum pairwise similarity among baseline responses."""
        if len(baselines) < 2:
            return 1.0
        min_sim = 1.0
        for i in range(len(baselines)):
            for j in range(i + 1, len(baselines)):
                sim = SequenceMatcher(None, baselines[i], baselines[j]).ratio()
                min_sim = min(min_sim, sim)
        return min_sim

    # ── Single UA test ────────────────────────────────────────────────────

    def _test_ua(
        self,
        url: str,
        method: str,
        ua_name: str,
        ua_string: str,
        baselines: list[str],
        baseline_min_sim: float,
        baseline_status: int | None = None,
    ) -> Optional[UADiffFinding]:
        """Test a single UA string against the baseline. Returns a finding if anomalous."""
        try:
            headers = {"User-Agent": ua_string}
            start = time.time()
            resp = self.session.request(
                method, url, timeout=self.timeout,
                headers=headers, allow_redirects=True, verify=False,
            )
            elapsed_ms = (time.time() - start) * 1000
        except requests.RequestException as e:
            log.debug("[UADiff] Request failed for UA %r on %s: %s", ua_name, url, e)
            return None

        normalized = self._normalize_response(resp)

        # Compare against all baselines, take the highest similarity
        max_sim = 0.0
        for bl in baselines:
            sim = SequenceMatcher(None, bl, normalized).ratio()
            max_sim = max(max_sim, sim)

        # Adjust threshold based on baseline variance
        effective_threshold = min(self.similarity_threshold, baseline_min_sim - 0.02)
        effective_threshold = max(effective_threshold, 0.80)  # Floor

        if max_sim >= effective_threshold:
            return None  # Response is within normal range

        # ── Determine severity and vuln_type based on category ────────
        severity = "Info"
        vuln_type = _VT_BEHAVIORAL_DIFF
        cwe = "CWE-16"
        owasp = "A05:2021 Security Misconfiguration"

        # Check if UA string is reflected in response (potential XSS)
        if ua_string and ua_string in resp.text:
            severity = "Medium"
            vuln_type = _VT_REFLECTED_XSS
            cwe = "CWE-79"
            owasp = "A03:2021 Injection"

        # Attack payloads getting different responses = interesting
        if ua_name.startswith(("XSS", "SQLi", "Path traversal", "SSTI", "CRLF", "Log4Shell")):
            if severity == "Info":
                severity = "Low"
            vuln_type = _VT_ATTACK_DIFF

        # Bot UA getting different content = hidden surface
        if ua_name in _UA_BOTS:
            vuln_type = _VT_BOT_DIFF

        # Status code change is more significant
        if baseline_status and resp.status_code != baseline_status:
            if severity == "Info":
                severity = "Low"

        # Build proof
        proof_lines = [
            f"UA tested: {ua_name}",
            f"UA string: {ua_string[:200]}",
            f"Similarity to baseline: {max_sim:.3f} (threshold: {effective_threshold:.3f})",
            f"Baseline status: {baseline_status}, Test status: {resp.status_code}",
            f"Baseline min similarity: {baseline_min_sim:.3f}",
        ]
        if ua_string and ua_string in resp.text:
            proof_lines.append("WARNING: User-Agent value reflected in response body")

        return UADiffFinding(
            id=f"ua-diff-{uuid.uuid4().hex[:12]}",
            url=url,
            method=method,
            vuln_type=vuln_type,
            owasp_category=owasp,
            cwe=cwe,
            finding=f"Behavioral difference detected with {ua_name} User-Agent (similarity: {max_sim:.2f})",
            severity=severity,
            proof="\n".join(proof_lines),
            payload=ua_string[:500],
            resp_time_ms=elapsed_ms,
            status_code=resp.status_code,
        )

    # ── Main scan method ──────────────────────────────────────────────────

    def scan(self, sitemap: Any) -> list[dict]:
        """Run UA behavioral diffing against discovered endpoints.

        Args:
            sitemap: SiteMap object with .pages dict (url → page info).

        Returns:
            List of finding dicts (ScanFinding-compatible).
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        findings: list[dict] = []

        if sitemap is None or not hasattr(sitemap, "pages"):
            log.warning("[UADiff] No sitemap provided, skipping UA diff scan")
            return findings

        # Collect unique URLs to test (sample if too many)
        urls = list(sitemap.pages.keys())[:self.max_endpoints]
        total_uas = sum(len(v) for v in self._ua_strings.values())
        log.info("[UADiff] Testing %d endpoints with %d UA strings across %d categories",
                 len(urls), total_uas, len(self._ua_strings))

        for url in urls:
            if self._stopped():
                break

            # Establish baseline (sequential — must complete before UA testing)
            baselines, baseline_status = self._establish_baseline(url)
            if len(baselines) < 2:
                log.debug("[UADiff] Insufficient baseline for %s, skipping", url)
                continue

            baseline_min_sim = self._baseline_similarity(baselines)

            # If baseline responses are already highly variable, skip this endpoint
            if baseline_min_sim < 0.85:
                log.debug("[UADiff] Baseline too variable for %s (min_sim=%.3f), skipping",
                         url, baseline_min_sim)
                continue

            # Build flat list of (category, ua_name, ua_string) for parallel execution
            ua_jobs = [
                (category, ua_name, ua_string)
                for category, ua_dict in self._ua_strings.items()
                for ua_name, ua_string in ua_dict.items()
            ]

            # Parallel UA testing for this endpoint
            with ThreadPoolExecutor(max_workers=8) as pool:
                future_to_meta = {
                    pool.submit(
                        self._test_ua, url, "GET", ua_name, ua_string,
                        baselines, baseline_min_sim, baseline_status,
                    ): (category, ua_name)
                    for category, ua_name, ua_string in ua_jobs
                }
                for future in as_completed(future_to_meta):
                    if self._stopped():
                        break
                    category, ua_name = future_to_meta[future]
                    try:
                        finding = future.result()
                    except Exception:
                        continue
                    if finding:
                        fd = finding.to_dict()
                        fd["source_phase"] = "ua_diff"
                        fd["ua_category"] = category
                        findings.append(fd)
                        log.info("[UADiff] Finding: %s on %s (category=%s)",
                                ua_name, url, category)

            # Explicit cleanup of baseline data
            del baselines

        log.info("[UADiff] Scan complete: %d findings across %d endpoints", len(findings), len(urls))
        return findings
