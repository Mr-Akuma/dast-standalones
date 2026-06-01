"""
shadow_api.py — Shadow API / Version Detection scanner.

Implements OWASP API9:2023 — Improper Inventory Management.

Tests:
  • Dead API versions: /v1/ still live when app uses /v3/
  • Date-based dead versions: /2022/endpoint still live when /2024/ is current
  • Shadow endpoints: discovered via version prefix injection
  • Internal/admin API paths accidentally exposed in production
  • API documentation paths exposed (swagger, openapi, redoc)
  • Deprecation/Sunset response headers revealing version lifecycle
  • Environment/stage headers leaking deployment context
  • Non-GET HTTP methods accepted on endpoints (undocumented method expansion)
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from urllib.parse import urlparse, urlunparse

import requests

log = logging.getLogger(__name__)

# ── Version prefix patterns ───────────────────────────────────────────────────
_VERSION_RE = re.compile(
    r"(/(?:api/)?)(v\d+)(/|$)",
    re.IGNORECASE,
)

_DATE_VERSION_RE = re.compile(
    r"/(20(?:2[0-6]|1\d))/",  # matches /2010/ through /2026/
    re.IGNORECASE,
)

_VERSION_PREFIXES = [
    "/v1", "/v2", "/v3", "/v4", "/v5", "/v6", "/v7", "/v8", "/v9",
    "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
    "/api/v6", "/api/v7", "/api/v8", "/api/v9",
    "/api/1", "/api/2", "/api/3",
]

# ── Internal / admin path patterns ───────────────────────────────────────────
_INTERNAL_PATHS = [
    "/internal",
    "/internal/api",
    "/admin/api",
    "/management",
    "/management/api",
    "/debug",
    "/debug/api",
    "/_internal",
    "/_debug",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/metrics",
    "/healthz",
    "/__admin",
]

# ── Documentation paths ───────────────────────────────────────────────────────
_DOC_PATHS = [
    "/swagger",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/redoc",
    "/.well-known/openapi",
    "/v2/api-docs",
    "/v3/api-docs",
]

# ── Deprecation / version lifecycle headers ───────────────────────────────────
_DEPRECATION_HEADERS = frozenset([
    "deprecation",
    "sunset",
    "x-api-version",
    "api-version",
    "x-api-deprecated",
])

# ── Environment / stage leak headers ─────────────────────────────────────────
_ENV_RESPONSE_HEADERS = frozenset([
    "x-environment",
    "x-stage",
    "x-forwarded-host",
    "x-original-host",
    "x-backend",
    "server-environment",
])

# ── Extra HTTP methods to probe ───────────────────────────────────────────────
_EXTRA_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS"]

# ── Static asset extensions to skip for version/method probing ───────────────
_STATIC_EXTS = frozenset([
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
])

# Response bodies that indicate "not found" even at 200 status
_NOT_FOUND_HINTS = frozenset([
    "not found", "404", "no such endpoint", "unknown route",
    "route not found", "cannot get", "cannot post",
])


class ShadowAPIScanner:
    """
    Shadow API and version enumeration scanner.

    Usage:
        scanner = ShadowAPIScanner(target="https://api.example.com", session=sess)
        findings = scanner.scan(discovered_urls=list(sitemap.pages.keys()))
    """

    def __init__(
        self,
        target:     str,
        session:    requests.Session | None = None,
        stop_event=None,
        timeout:    int = 10,
        rate_limit: float = 0.1,
        extra_urls: list[str] | None = None,
    ):
        self.target     = target.rstrip("/")
        self.session    = session or self._default_session()
        self.stop_event = stop_event
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self.extra_urls     = extra_urls or []
        self._cached_spec: dict | None = None
        parsed              = urlparse(self.target)
        self._base          = f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _default_session() -> requests.Session:
        import urllib3
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify = False
        s.headers["User-Agent"] = "Mozilla/5.0 (DAST-ShadowAPI/1.0)"
        return s

    def _stopped(self) -> bool:
        return self.stop_event is not None and self.stop_event.is_set()

    def _get(self, url: str) -> requests.Response | None:
        try:
            time.sleep(self.rate_limit)
            return self.session.get(
                url, timeout=self.timeout,
                allow_redirects=False, verify=False,
            )
        except Exception:
            return None

    def _request(self, method: str, url: str) -> requests.Response | None:
        try:
            time.sleep(self.rate_limit)
            return self.session.request(
                method, url, timeout=self.timeout,
                allow_redirects=False, verify=False,
            )
        except Exception:
            return None

    def _get_root(self) -> requests.Response | None:
        """GET target root with trailing-slash fallback."""
        resp = self._get(self.target + "/")
        return resp if resp is not None else self._get(self.target)

    def _is_static(self, path: str) -> bool:
        return any(path.lower().endswith(ext) for ext in _STATIC_EXTS)

    def _is_real_response(self, resp: requests.Response) -> bool:
        """Heuristic: does the response look like a real endpoint vs a 404 page?"""
        if resp.status_code in (404, 410, 405):
            return False
        body_lower = resp.text[:500].lower()
        if any(h in body_lower for h in _NOT_FOUND_HINTS):
            return False
        return True

    def _finding(self, url: str, vuln_type: str, finding: str,
                 severity: str, proof: str = "", evidence: str = "") -> dict:
        return {
            "id":          f"shadow_{uuid.uuid4().hex[:10]}",
            "url":         url,
            "method":      "GET",
            "param":       "",
            "param_type":  "path",
            "vuln_type":   vuln_type,
            "finding":     finding,
            "severity":    severity,
            "proof":       proof[:500],
            "evidence":    evidence[:500],
            "category":    "API Security",
            "agent":       "Shadow API Scanner",
            "cwe":         "CWE-1059",
            "remediation": "Decommission old API versions. Audit all endpoints against OpenAPI spec. Block internal paths at gateway.",
        }

    def _probe_path_list(
        self,
        paths: list[str],
        vuln_type: str,
        log_label: str,
        make_finding,  # (url, path, resp) -> (finding_str, severity, proof, evidence)
    ) -> list[dict]:
        """Probe a list of absolute paths against self._base; emit findings for accessible ones."""
        findings: list[dict] = []
        for path in paths:
            if self._stopped():
                break
            url  = self._base + path
            resp = self._get(url)
            if resp is None:
                continue
            if self._is_real_response(resp) and resp.status_code not in (401, 403):
                finding_str, severity, proof, evidence = make_finding(url, path, resp)
                findings.append(self._finding(
                    url=url, vuln_type=vuln_type,
                    finding=finding_str, severity=severity,
                    proof=proof, evidence=evidence,
                ))
                log.info("[ShadowAPI] %s: %s (%d)", log_label, url, resp.status_code)
        return findings

    # ── Old version enumeration ───────────────────────────────────────────────

    def _enumerate_versions(self, discovered_urls: list[str]) -> list[dict]:
        """
        For each URL with a version segment (numeric or date-based), test all
        other version prefixes. Flag any that return real responses.
        """
        findings: list[dict] = []
        tested: set[str] = set()

        for url in discovered_urls[:200]:
            if self._stopped():
                break
            parsed = urlparse(url)
            path   = parsed.path

            m = _VERSION_RE.search(path)
            if m:
                prefix      = m.group(1)   # e.g. "/api/"
                current_ver = m.group(2)   # e.g. "v3"
                suffix      = path[m.end():]

                try:
                    current_num = int(current_ver.lstrip("vV"))
                except ValueError:
                    current_num = None

                if current_num is not None:
                    current_resp = None  # lazy-fetch once if any old version responds
                    for v in range(1, 10):
                        if v == current_num or self._stopped():
                            continue
                        old_path = f"{prefix}v{v}/{suffix}".replace("//", "/")
                        old_url  = urlunparse(parsed._replace(path=old_path))
                        if old_url in tested:
                            continue
                        tested.add(old_url)

                        resp = self._get(old_url)
                        if resp is None:
                            continue

                        if self._is_real_response(resp):
                            if current_resp is None:
                                current_resp = self._get(url)
                            diff_body = (
                                current_resp is not None
                                and resp.text[:200] != current_resp.text[:200]
                            )
                            findings.append(self._finding(
                                url=old_url,
                                vuln_type="shadow_api_old_version",
                                finding=(
                                    f"Dead API version active — {old_url} returns HTTP {resp.status_code}. "
                                    f"Current version is {current_ver}, old v{v} still responds. "
                                    f"Old versions may lack security patches or access controls."
                                ),
                                severity="High",
                                proof=f"HTTP {resp.status_code} | body[:100]={resp.text[:100]}",
                                evidence=(
                                    f"Current ({url}) status={current_resp.status_code if current_resp else '?'} | "
                                    f"Old (v{v}) status={resp.status_code} | "
                                    f"Bodies differ: {diff_body}"
                                ),
                            ))
                            log.info("[ShadowAPI] Old version live: %s (%d)", old_url, resp.status_code)

            dm = _DATE_VERSION_RE.search(path)
            if dm and not self._stopped():
                current_year = int(dm.group(1))
                before_date  = path[:dm.start()]
                after_date   = path[dm.end() - 1:]  # keep leading slash of next segment

                for year in range(max(2010, current_year - 3), min(2027, current_year + 3)):
                    if year == current_year or self._stopped():
                        continue
                    alt_path = f"{before_date}/{year}{after_date}".replace("//", "/")
                    alt_url  = urlunparse(parsed._replace(path=alt_path))
                    if alt_url in tested:
                        continue
                    tested.add(alt_url)

                    resp = self._get(alt_url)
                    if resp is None:
                        continue

                    if self._is_real_response(resp):
                        findings.append(self._finding(
                            url=alt_url,
                            vuln_type="shadow_api_date_version",
                            finding=(
                                f"Dead date-based API version active — {alt_url} returns HTTP {resp.status_code}. "
                                f"Current year-based path is /{current_year}/, old /{year}/ still responds. "
                                f"Stale date-versioned endpoints may lack current security controls."
                            ),
                            severity="Medium",
                            proof=f"HTTP {resp.status_code} | body[:100]={resp.text[:100]}",
                            evidence=f"Date version variant: current=/{current_year}/ probed=/{year}/",
                        ))
                        log.info("[ShadowAPI] Date version live: %s (%d)", alt_url, resp.status_code)

        return findings

    # ── Shadow endpoint detection ─────────────────────────────────────────────

    def _find_shadow_endpoints(self, discovered_urls: list[str]) -> list[dict]:
        """
        Probe version prefix variants for paths discovered from the sitemap.
        Tests all non-static paths regardless of whether they contain /api/.
        """
        findings: list[dict] = []
        tested: set[str] = set()
        discovered_set = set(discovered_urls)  # built once; reused in inner loop

        for url in discovered_urls[:100]:
            if self._stopped():
                break
            parsed = urlparse(url)
            path   = parsed.path

            # Skip static assets — version prefixes on .css/.js are meaningless
            if self._is_static(path):
                continue

            for vprefix in _VERSION_PREFIXES:
                if self._stopped():
                    break
                # Skip if path already starts with this prefix (avoids double-prefixing)
                if path.startswith(vprefix + "/") or path == vprefix:
                    continue
                candidate_path = vprefix + path
                candidate = urlunparse(parsed._replace(path=candidate_path))
                if candidate in tested or candidate in discovered_set:
                    continue
                tested.add(candidate)

                resp = self._get(candidate)
                if resp is None:
                    continue

                if self._is_real_response(resp):
                    findings.append(self._finding(
                        url=candidate,
                        vuln_type="shadow_api_endpoint",
                        finding=(
                            f"Shadow API endpoint — {candidate} responds (HTTP {resp.status_code}) "
                            f"but was not in the crawled sitemap or OpenAPI spec. "
                            f"May be an undocumented or forgotten endpoint."
                        ),
                        severity="Medium",
                        proof=f"HTTP {resp.status_code} | body[:100]={resp.text[:100]}",
                        evidence=f"Discovered via version prefix injection: {vprefix} + {path}",
                    ))
                    log.info("[ShadowAPI] Shadow endpoint: %s (%d)", candidate, resp.status_code)

        return findings

    # ── Internal / admin path probing ─────────────────────────────────────────

    def _probe_internal_paths(self) -> list[dict]:
        def _fn(url, path, resp):
            sev = "Critical" if resp.status_code == 200 else "High"
            return (
                f"Internal API path exposed — {url} returned HTTP {resp.status_code}. "
                f"Internal management, debug, or admin paths should not be reachable from the internet.",
                sev,
                f"HTTP {resp.status_code} | body[:150]={resp.text[:150]}",
                f"Path: {path}",
            )
        return self._probe_path_list(_INTERNAL_PATHS, "internal_api_exposed", "Internal path exposed", _fn)

    # ── Documentation path probing ────────────────────────────────────────────

    def _probe_doc_paths(self) -> list[dict]:
        findings: list[dict] = []
        for path in _DOC_PATHS:
            if self._stopped():
                break
            url  = self._base + path
            resp = self._get(url)
            if resp is None:
                continue
            if not (self._is_real_response(resp) and resp.status_code not in (401, 403)):
                continue
            if self._cached_spec is None:
                try:
                    candidate = resp.json()
                    if isinstance(candidate, dict) and "paths" in candidate:
                        self._cached_spec = candidate
                except Exception:
                    pass
            findings.append(self._finding(
                url=url, vuln_type="api_docs_exposed",
                finding=(
                    f"API documentation exposed — {url} returned HTTP {resp.status_code}. "
                    f"Publicly accessible API docs reveal endpoint inventory, parameters, "
                    f"and authentication requirements to attackers."
                ),
                severity="Medium",
                proof=f"HTTP {resp.status_code} | body[:150]={resp.text[:150]}",
                evidence=f"Documentation path: {path}",
            ))
            log.info("[ShadowAPI] API docs exposed: %s (%d)", url, resp.status_code)
        return findings

    # ── Root header detection (deprecation + environment) ────────────────────

    def _check_root_headers(self) -> list[dict]:
        """
        Single GET to the target root; checks both deprecation/version headers
        and environment/stage leak headers in one request.
        """
        findings: list[dict] = []

        resp = self._get_root()
        if resp is None:
            return findings

        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header in _DEPRECATION_HEADERS:
            value = resp_headers_lower.get(header)
            if value:
                findings.append(self._finding(
                    url=self.target,
                    vuln_type="api_deprecation_header",
                    finding=(
                        f"API version lifecycle header detected — response includes '{header}: {value}'. "
                        f"Deprecation and Sunset headers reveal API version inventory and decommission timelines."
                    ),
                    severity="Info",
                    proof=f"{header}: {value}",
                    evidence=f"Header '{header}' found in response to GET {self.target}",
                ))
                log.info("[ShadowAPI] Version header: %s=%s", header, value)

        for header in _ENV_RESPONSE_HEADERS:
            value = resp_headers_lower.get(header)
            if value:
                findings.append(self._finding(
                    url=self.target,
                    vuln_type="environment_header_leaked",
                    finding=(
                        f"Environment context header leaked — response includes '{header}: {value}'. "
                        f"Headers revealing deployment environment, stage, or backend host "
                        f"aid attackers in targeting environment-specific vulnerabilities."
                    ),
                    severity="Medium",
                    proof=f"{header}: {value}",
                    evidence=f"Header '{header}' found in response to GET {self.target}",
                ))
                log.info("[ShadowAPI] Env header: %s=%s", header, value)

        return findings

    # ── HTTP method variation ─────────────────────────────────────────────────

    def _probe_methods(self, urls: list[str]) -> list[dict]:
        """
        Test PUT, DELETE, PATCH, OPTIONS on discovered URLs.
        Flags endpoints that unexpectedly accept non-GET methods.
        """
        findings: list[dict] = []

        for url in dict.fromkeys(urls[:50]):  # deduplicate, preserve order
            if self._stopped():
                break
            parsed = urlparse(url)
            if self._is_static(parsed.path):
                continue

            for method in _EXTRA_METHODS:
                if self._stopped():
                    break

                resp = self._request(method, url)
                if resp is None:
                    continue

                if not (200 <= resp.status_code < 400):
                    continue

                findings.append(self._finding(
                    url=url,
                    vuln_type="shadow_api_method_allowed",
                    finding=(
                        f"Unexpected HTTP method accepted — {method} {url} returned HTTP {resp.status_code}. "
                        f"Undocumented method acceptance may expose create/update/delete operations "
                        f"that are not in the API inventory."
                    ),
                    severity="Medium",
                    proof=f"HTTP {resp.status_code} on {method} | body[:100]={resp.text[:100]}",
                    evidence=f"Method: {method} | URL: {url}",
                ))
                log.info("[ShadowAPI] Method allowed: %s %s (%d)", method, url, resp.status_code)

        return findings

    def _diff_openapi_spec(self, discovered_urls: list[str]) -> list[dict]:
        """Compare crawled paths against OpenAPI spec to find undocumented endpoints."""
        findings: list[dict] = []
        spec: dict | None = self._cached_spec  # populated by _probe_doc_paths()

        if spec is None:
            for doc_path in _DOC_PATHS:
                resp = self._get(self._base + doc_path)
                if resp is None or not self._is_real_response(resp):
                    continue
                ct = resp.headers.get("Content-Type", "")
                try:
                    if "yaml" in ct or doc_path.endswith((".yaml", ".yml")):
                        try:
                            import yaml
                            spec = yaml.safe_load(resp.text)
                        except Exception:
                            spec = None
                    if spec is None:
                        spec = resp.json()
                    if isinstance(spec, dict) and "paths" in spec:
                        break
                except Exception:
                    spec = None

        if not spec or not isinstance(spec.get("paths"), dict):
            return findings

        spec_paths: set[str] = set(spec["paths"].keys())
        crawled_paths: set[str] = {urlparse(u).path for u in discovered_urls if u}

        for path in crawled_paths - spec_paths:
            if not path or path == "/":
                continue
            findings.append(self._finding(
                url=self._base + path,
                vuln_type="undocumented_endpoint",
                finding=f"Undocumented endpoint not in OpenAPI spec: {path}",
                severity="Medium",
                proof=f"Path {path!r} found via crawl but absent from OpenAPI spec",
            ))

        for path in spec_paths - crawled_paths:
            findings.append(self._finding(
                url=self._base + path,
                vuln_type="shadow_api_spec_only",
                finding=f"Spec-declared endpoint not crawled: {path}",
                severity="Info",
                proof=f"Path {path!r} declared in OpenAPI spec but not observed in crawl",
            ))

        if findings:
            log.info("[ShadowAPI] Spec diff: %d findings", len(findings))
        return findings

    # ── Main scan ─────────────────────────────────────────────────────────────

    def scan(self, discovered_urls: list[str] | None = None) -> list[dict]:
        """
        Run full shadow API / version detection scan. Returns list of finding dicts.
        """
        urls     = list(dict.fromkeys((discovered_urls or []) + self.extra_urls))
        findings: list[dict] = []

        findings += self._enumerate_versions(urls)
        if not self._stopped():
            findings += self._find_shadow_endpoints(urls)
        if not self._stopped():
            findings += self._probe_internal_paths()
        if not self._stopped():
            findings += self._probe_doc_paths()
        if not self._stopped():
            findings += self._check_root_headers()
        if not self._stopped():
            findings += self._probe_methods(urls)
        if not self._stopped():
            findings += self._diff_openapi_spec(urls)

        log.info("[ShadowAPI] Complete: %d findings across %d URLs", len(findings), len(urls))
        return findings
