"""
cache_poisoning.py — Advanced cache poisoning scanner.

Tests techniques NOT covered by scanner.py's _check_web_cache_poisoning:

  • Fat GET (GET with body — some CDNs ignore body in cache key)
  • Cookie-based cache key confusion
  • Host header port confusion
  • X-HTTP-Method-Override cache pollution
  • Poison persistence verification (clean request after poison probe)

scanner.py already covers: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL,
X-Forwarded-Scheme. This module adds the remaining techniques.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import requests

log = logging.getLogger(__name__)


class CachePoisoningScanner:
    """
    Advanced cache poisoning scanner — focuses on techniques distinct from
    the basic header-reflection tests in scanner.py.

    Usage:
        scanner = CachePoisoningScanner(target="https://app.example.com", session=sess)
        findings = scanner.scan(urls=list(sitemap.pages.keys()))
    """

    def __init__(
        self,
        target:     str,
        session:    requests.Session | None = None,
        stop_event: Any = None,
        timeout:    int = 10,
        rate_limit: float = 0.15,
    ):
        self.target     = target.rstrip("/")
        self.session    = session or self._default_session()
        self.stop_event = stop_event
        self.timeout    = timeout
        self.rate_limit = rate_limit

    @staticmethod
    def _default_session() -> requests.Session:
        import urllib3
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify = False
        s.headers["User-Agent"] = "Mozilla/5.0 (DAST-CachePoison/1.0)"
        return s

    def _stopped(self) -> bool:
        return self.stop_event is not None and self.stop_event.is_set()

    def _req(self, method: str, url: str,
             headers: dict | None = None,
             data: bytes | None = None) -> requests.Response | None:
        try:
            time.sleep(self.rate_limit)
            return self.session.request(
                method, url,
                headers=headers or {},
                data=data,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
        except Exception:
            return None

    def _finding(self, url: str, vuln_type: str, finding: str,
                 severity: str, proof: str = "", technique: str = "") -> dict:
        return {
            "id":          f"cpois_{uuid.uuid4().hex[:10]}",
            "url":         url,
            "method":      "GET",
            "param":       technique,
            "param_type":  "header",
            "vuln_type":   vuln_type,
            "finding":     finding,
            "severity":    severity,
            "proof":       proof[:600],
            "category":    "Cache Poisoning",
            "agent":       "Cache Poisoning Scanner",
            "cwe":         "CWE-444",
            "remediation": (
                "Include all security-relevant headers in cache key (Vary header). "
                "Ignore unrecognized headers. Validate Host header against an allowlist."
            ),
        }

    # ── Baseline ──────────────────────────────────────────────────────────────

    def _baseline(self, url: str) -> requests.Response | None:
        """Clean baseline request with no extra headers."""
        return self._req("GET", url)

    # ── Fat GET ───────────────────────────────────────────────────────────────

    def _test_fat_get(self, url: str, baseline: requests.Response) -> list[dict]:
        """
        GET request with a non-empty body. Some CDNs cache based on URL only
        and ignore the request body, so a poisoned body can persist in cache.
        Detection: response differs from baseline OR body content is reflected.
        """
        findings = []
        canary = f"dast-fat-get-{uuid.uuid4().hex[:8]}"
        body   = f"injected={canary}".encode()

        resp = self._req(
            "GET", url,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Content-Length": str(len(body))},
            data=body,
        )
        if resp is None:
            return findings

        # Check 1: canary reflected in response (body injection)
        if canary in resp.text:
            findings.append(self._finding(
                url=url,
                vuln_type="cache_poisoning_fat_get",
                finding=(
                    f"Fat GET body reflected in response — CDN or reverse proxy "
                    f"may merge GET body into response, poisoning the cache entry for {url}."
                ),
                severity="High",
                proof=f"Canary '{canary}' reflected | HTTP {resp.status_code}",
                technique="fat-GET-body",
            ))
            log.info("[CachePoison] Fat GET body reflected at %s", url)

        # Check 2: response meaningfully differs from baseline (different body length)
        elif abs(len(resp.text) - len(baseline.text)) > 50:
            # Verify poison persists with a clean follow-up request
            clean = self._req("GET", url)
            if clean and abs(len(clean.text) - len(baseline.text)) > 50:
                findings.append(self._finding(
                    url=url,
                    vuln_type="cache_poisoning_fat_get",
                    finding=(
                        f"Fat GET cache poisoning — GET with body altered response, "
                        f"and poisoned response persisted in a subsequent clean GET to {url}."
                    ),
                    severity="High",
                    proof=(
                        f"Baseline len={len(baseline.text)} | "
                        f"Poison len={len(resp.text)} | "
                        f"Clean-follow len={len(clean.text)}"
                    ),
                    technique="fat-GET-persist",
                ))
                log.warning("[CachePoison] Fat GET cache poisoning PERSISTED at %s", url)

        return findings

    # ── Cookie cache key confusion ─────────────────────────────────────────────

    def _test_cookie_confusion(self, url: str, baseline: requests.Response) -> list[dict]:
        """
        Inject a unique cookie value. If a subsequent clean request (no cookie)
        returns the cookie value in its response, the cache did not key on the
        cookie — an attacker with different cookie could poison responses for
        unauthenticated users.
        """
        findings = []
        canary_val = uuid.uuid4().hex

        poisoned = self._req(
            "GET", url,
            headers={"Cookie": f"dast_cache_probe={canary_val}"},
        )
        if poisoned is None:
            return findings

        # If response reflected our cookie value, test if it persists without cookie
        if canary_val in poisoned.text:
            time.sleep(0.5)  # brief wait for cache propagation
            clean = self._req("GET", url)  # no Cookie header
            if clean and canary_val in clean.text:
                findings.append(self._finding(
                    url=url,
                    vuln_type="cache_poisoning_cookie_confusion",
                    finding=(
                        f"Cookie-based cache poisoning — injected cookie value '{canary_val[:8]}...' "
                        f"was reflected in response and persisted in cache (clean request retrieved it). "
                        f"Cache does not key on cookies; attacker can poison responses for all users."
                    ),
                    severity="High",
                    proof=(
                        f"Cookie value in poisoned response: True | "
                        f"Cookie value in clean follow-up: True | HTTP {clean.status_code}"
                    ),
                    technique="cookie-cache-key-confusion",
                ))
                log.warning("[CachePoison] Cookie cache poisoning PERSISTED at %s", url)

        return findings

    # ── Host header port confusion ─────────────────────────────────────────────

    def _test_host_port_confusion(self, url: str, baseline: requests.Response) -> list[dict]:
        """
        Inject Host header with non-standard port. If server reflects the Host
        in Location/Content-Location/Link headers or body, cache may store the
        poisoned host, redirecting victims to attacker-controlled port.
        """
        findings = []
        from urllib.parse import urlparse
        parsed     = urlparse(url)
        evil_host  = f"{parsed.hostname}:9999"

        resp = self._req("GET", url, headers={"Host": evil_host})
        if resp is None:
            return findings

        all_text = resp.text + str(resp.headers)
        if ":9999" in all_text and ":9999" not in str(baseline.headers):
            findings.append(self._finding(
                url=url,
                vuln_type="cache_poisoning_host_port",
                finding=(
                    f"Host header port confusion — injecting Host: {evil_host} caused "
                    f"the port ':9999' to appear in the response. "
                    f"Caching this response could redirect victims to a non-standard port."
                ),
                severity="Medium",
                proof=f"':9999' found in response | HTTP {resp.status_code} | Location: {resp.headers.get('Location', '')}",
                technique="Host-port-confusion",
            ))
            log.info("[CachePoison] Host port confusion at %s", url)

        return findings

    # ── X-HTTP-Method-Override ─────────────────────────────────────────────────

    def _test_method_override(self, url: str, baseline: requests.Response) -> list[dict]:
        """
        Some frameworks honour X-HTTP-Method-Override on GET requests.
        If a DELETE/POST is honoured and that response is cached, subsequent
        GETs from all users would get the cached mutation response.
        """
        findings = []
        for override in ("DELETE", "PUT", "PATCH"):
            if self._stopped():
                break
            resp = self._req("GET", url, headers={"X-HTTP-Method-Override": override})
            if resp is None:
                continue

            # Flag if response differs significantly from baseline (status or size)
            status_diff = resp.status_code != baseline.status_code
            size_diff   = abs(len(resp.text) - len(baseline.text)) > 100

            if status_diff or size_diff:
                findings.append(self._finding(
                    url=url,
                    vuln_type="cache_poisoning_method_override",
                    finding=(
                        f"X-HTTP-Method-Override cache pollution — injecting "
                        f"X-HTTP-Method-Override: {override} changed the response "
                        f"(status: {baseline.status_code}→{resp.status_code}, "
                        f"size diff: {len(resp.text)-len(baseline.text)} bytes). "
                        f"If cached, all users requesting {url} would receive this mutated response."
                    ),
                    severity="High",
                    proof=(
                        f"Header: X-HTTP-Method-Override: {override} | "
                        f"Baseline status={baseline.status_code} size={len(baseline.text)} | "
                        f"Override status={resp.status_code} size={len(resp.text)}"
                    ),
                    technique=f"X-HTTP-Method-Override:{override}",
                ))
                log.info("[CachePoison] Method override changed response at %s (override=%s)", url, override)
                break  # one finding per URL is enough

        return findings

    # ── Main scan ─────────────────────────────────────────────────────────────

    def scan(self, urls: list[str] | None = None) -> list[dict]:
        """
        Run advanced cache poisoning scan. Returns list of finding dicts.
        Tests Fat GET, Cookie confusion, Host port confusion, Method override.
        """
        findings: list[dict] = []
        test_urls = (urls or [])[:10]  # cap: 10 URLs × 4 techniques × 2 requests = ~80 req

        for url in test_urls:
            if self._stopped():
                break

            baseline = self._baseline(url)
            if baseline is None or baseline.status_code in (404, 410):
                continue

            findings += self._test_fat_get(url, baseline)
            if self._stopped():
                break
            findings += self._test_cookie_confusion(url, baseline)
            if self._stopped():
                break
            findings += self._test_host_port_confusion(url, baseline)
            if self._stopped():
                break
            findings += self._test_method_override(url, baseline)

        log.info("[CachePoison] Complete: %d findings across %d URLs", len(findings), len(test_urls))
        return findings
