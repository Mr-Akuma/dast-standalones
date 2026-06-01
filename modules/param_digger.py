"""
Param Digger — brute-force discovery of hidden/undocumented URL and body parameters.
Equivalent to ZAP's Param Digger add-on and James Kettle's param-miner technique.

Probes each candidate parameter name and detects responses that differ from the baseline,
indicating the server is actually processing that parameter.
"""
from __future__ import annotations
import time
import random
import string
import hashlib
from dataclasses import dataclass, asdict
from typing import Optional
import requests


@dataclass
class ParamDiggerResult:
    """A single discovered hidden parameter."""

    url: str
    param_name: str
    method: str
    injected_value: str
    baseline_status: int
    found_status: int
    length_diff: int
    reflected: bool
    evidence: str

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Wordlist — 350+ common parameter names grouped by category
# ---------------------------------------------------------------------------

WORDLIST: list[str] = [
    # Debug / admin
    "debug", "test", "admin", "backdoor", "hidden", "dev", "development",
    "staging", "preview", "beta", "internal", "testing", "qa", "sandbox",
    "maintenance", "diagnostic", "diag", "console", "panel", "dashboard",
    "manage", "manager", "root", "superuser", "su", "devmode", "testmode",
    "debugmode", "show_errors", "display_errors",

    # Auth / session
    "token", "auth", "apikey", "api_key", "key", "secret", "password",
    "passwd", "access_token", "bearer", "jwt", "session", "sessionid",
    "session_id", "csrf", "csrf_token", "xsrf", "nonce", "oauth",
    "oauth_token", "refresh_token", "client_id", "client_secret",
    "api_secret", "app_key", "app_id", "app_secret", "credentials",
    "login", "username", "user", "email", "phone",

    # Navigation / redirect
    "redirect", "next", "return", "returnurl", "return_url", "continue",
    "url", "callback", "goto", "forward", "to", "from", "origin",
    "redirect_uri", "redirect_url", "target_url", "dest_url", "back",
    "backurl", "back_url", "redir", "returnto", "return_to", "hop",
    "relay", "relay_state", "state", "ref_url", "referer", "referrer",

    # ID / entity
    "id", "uid", "user_id", "userid", "account_id", "customer_id",
    "order_id", "product_id", "item_id", "object_id", "entity_id",
    "ref", "reference", "uuid", "guid", "oid", "pid", "cid", "tid",
    "parent_id", "group_id", "org_id", "organization_id", "team_id",
    "project_id", "workspace_id", "tenant_id", "record_id", "doc_id",
    "document_id", "invoice_id", "transaction_id", "payment_id",

    # Format / output
    "format", "output", "type", "content_type", "encoding", "lang",
    "language", "locale", "timezone", "tz", "accept", "charset",
    "mime", "render", "renderer", "template_engine", "pretty",
    "indent", "minify", "compress", "gzip", "deflate", "raw",

    # File / path
    "file", "filename", "path", "filepath", "dir", "directory",
    "include", "page", "template", "view", "layout", "action",
    "module", "controller", "handler", "route", "component",
    "partial", "fragment", "section", "resource", "asset",
    "upload", "download", "attachment", "document", "image",
    "photo", "media", "video", "audio", "css", "js", "script",

    # Pagination
    "page", "limit", "offset", "per_page", "count", "size", "start",
    "end", "cursor", "page_size", "pagesize", "pagenumber",
    "page_number", "skip", "take", "first", "last", "after", "before",
    "max", "min", "num", "number", "total", "index", "position",

    # Sorting
    "sort", "order", "orderby", "order_by", "sortby", "sort_by",
    "direction", "asc", "desc", "sort_order", "sort_field",
    "sort_column", "sort_dir", "group", "groupby", "group_by",
    "aggregate", "distinct", "unique",

    # Search
    "q", "query", "search", "keyword", "term", "filter", "where",
    "condition", "find", "lookup", "match", "pattern", "regex",
    "contains", "like", "starts_with", "ends_with", "prefix",
    "suffix", "fulltext", "fts", "autocomplete", "suggest",

    # Feature flags
    "feature", "flag", "mode", "toggle", "enable", "disable",
    "version", "v", "variant", "experiment", "ab", "abtest",
    "ab_test", "canary", "rollout", "percentage", "bucket",
    "release", "channel", "tier", "plan", "subscription",

    # Cache / CDN
    "cache", "nocache", "refresh", "force", "bust", "purge",
    "no_cache", "cache_bust", "cache_control", "ttl", "expires",
    "max_age", "stale", "revalidate", "etag", "if_none_match",
    "if_modified_since", "cdn", "edge", "invalidate",

    # Debug tools
    "verbose", "logging", "log", "trace", "traceback", "profiling",
    "profile", "benchmark", "timing", "metrics", "stats",
    "statistics", "monitor", "inspect", "introspect", "dump",
    "stacktrace", "stack_trace", "explain", "analyze", "audit",
    "loglevel", "log_level", "debug_mode",

    # SSRF targets
    "target", "host", "server", "endpoint", "service", "uri",
    "src", "source", "dest", "destination", "proxy", "upstream",
    "backend", "remote", "external", "internal_url", "fetch",
    "load", "read", "open", "connect", "socket", "webhook",
    "webhook_url", "ping", "healthcheck",

    # Injection sinks
    "name", "value", "data", "body", "content", "payload", "input",
    "msg", "message", "text", "comment", "description", "title",
    "subject", "note", "notes", "label", "tag", "tags", "category",
    "categories", "metadata", "meta", "annotation", "remark",
    "feedback", "review", "rating", "score",

    # Web cache / proxy headers as params
    "x_forwarded_host", "x_original_url", "x_rewrite_url",
    "forwarded", "x_forwarded_for", "x_real_ip", "x_host",
    "x_forwarded_proto", "x_forwarded_scheme", "x_forwarded_port",

    # Misc
    "returncode", "status", "code", "result", "response", "error",
    "warning", "info", "success", "fail", "ok", "reason", "detail",
    "details", "context", "scope", "domain", "namespace", "prefix",
    "config", "configuration", "setting", "settings", "option",
    "options", "param", "parameter", "args", "arguments", "extra",
    "custom", "override", "fallback", "default", "backup",
    "timeout", "retry", "retries", "delay", "interval", "wait",
    "async", "sync", "blocking", "nonblocking", "background",
    "priority", "weight", "rank", "level", "depth", "width",
    "height", "color", "colour", "theme", "style", "class",
    "role", "permission", "permissions", "access", "acl", "allow",
    "deny", "block", "whitelist", "blacklist", "ip", "range",
    "country", "region", "city", "zip", "postal", "address",
    "lat", "lng", "latitude", "longitude", "geo", "location",
    "coordinates", "map", "place", "venue", "event", "date",
    "time", "datetime", "timestamp", "created", "updated",
    "modified", "deleted", "active", "inactive", "enabled",
    "disabled", "visible", "public", "private", "draft",
    "published", "archived", "expired", "pending", "approved",
    "rejected", "verified", "confirmed", "cancelled", "completed",
]


# ---------------------------------------------------------------------------
# Header wordlist — 50 most useful custom headers for probing
# ---------------------------------------------------------------------------

_HEADER_WORDLIST: list[str] = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Custom-Header",
    "X-Debug",
    "X-Admin",
    "X-Internal",
    "X-API-Key",
    "X-Auth-Token",
    "X-Session-ID",
    "X-Request-ID",
    "X-Correlation-ID",
    "X-Environment",
    "X-Version",
    "X-Feature-Flag",
    "X-Forwarded-Proto",
    "X-Forwarded-Port",
    "X-Forwarded-Scheme",
    "X-Original-Host",
    "X-Client-IP",
    "X-Cluster-Client-IP",
    "X-ProxyUser-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Azure-ClientIP",
    "X-Originating-IP",
    "X-Backend",
    "X-Upstream",
    "X-Proxy",
    "X-Middleware",
    "X-Gateway",
    "X-Token",
    "X-Secret",
    "X-CSRF-Token",
    "X-XSRF-Token",
    "X-Requested-With",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-Tenant-ID",
    "X-Workspace-ID",
    "X-Org-ID",
    "X-User-ID",
    "X-Role",
    "X-Permission",
    "X-Cache-Control",
    "X-No-Cache",
]


class ParamDigger:
    """Brute-force discovery of hidden / undocumented parameters."""

    def __init__(
        self,
        delay: float = 0.1,
        timeout: int = 10,
        diff_threshold: int = 50,
    ) -> None:
        self.delay = delay
        self.timeout = timeout
        self.diff_threshold = diff_threshold

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _random_nonce() -> str:
        """Return an 8-char random alphanumeric string for cache busting."""
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    @staticmethod
    def _fingerprint(resp: requests.Response) -> tuple[int, int]:
        """Quick fingerprint: (status_code, body_length)."""
        return (resp.status_code, len(resp.text))

    def _is_different(
        self,
        baseline_fp: tuple[int, int],
        probe_fp: tuple[int, int],
        probe_text: str,
        baseline_text: str,
    ) -> bool:
        """Return True when a probe response deviates meaningfully from baseline."""
        if baseline_fp[0] != probe_fp[0]:
            return True
        if abs(probe_fp[1] - baseline_fp[1]) > self.diff_threshold:
            return True
        return False

    # ------------------------------------------------------------------
    # Probe methods
    # ------------------------------------------------------------------

    def _probe_url_params(
        self,
        session: requests.Session,
        url: str,
        wordlist: list[str],
        method: str = "GET",
    ) -> list[ParamDiggerResult]:
        """Probe URL query parameters (GET or any method with query string)."""
        results: list[ParamDiggerResult] = []

        # Baseline request with cache-bust only
        baseline_nonce = self._random_nonce()
        try:
            baseline_resp = session.request(
                method,
                url,
                params={"_cache_bust": baseline_nonce},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            return results

        baseline_fp = self._fingerprint(baseline_resp)
        baseline_text = baseline_resp.text

        for word in wordlist:
            nonce = self._random_nonce()
            cache_nonce = self._random_nonce()
            try:
                probe_resp = session.request(
                    method,
                    url,
                    params={word: nonce, "_cache_bust": cache_nonce},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue

            probe_fp = self._fingerprint(probe_resp)
            probe_text = probe_resp.text

            if self._is_different(baseline_fp, probe_fp, probe_text, baseline_text):
                reflected = nonce in probe_text
                length_diff = probe_fp[1] - baseline_fp[1]
                evidence_parts: list[str] = []
                if baseline_fp[0] != probe_fp[0]:
                    evidence_parts.append(
                        f"status changed {baseline_fp[0]}->{probe_fp[0]}"
                    )
                if abs(length_diff) > self.diff_threshold:
                    evidence_parts.append(f"length diff {length_diff}")
                if reflected:
                    evidence_parts.append("value reflected in response")

                results.append(
                    ParamDiggerResult(
                        url=url,
                        param_name=word,
                        method=method,
                        injected_value=nonce,
                        baseline_status=baseline_fp[0],
                        found_status=probe_fp[0],
                        length_diff=length_diff,
                        reflected=reflected,
                        evidence="; ".join(evidence_parts),
                    )
                )

            if self.delay > 0:
                time.sleep(self.delay)

        return results

    def _probe_body_params(
        self,
        session: requests.Session,
        url: str,
        wordlist: list[str],
        method: str = "POST",
    ) -> list[ParamDiggerResult]:
        """Probe body parameters (form-encoded POST / PUT / PATCH)."""
        results: list[ParamDiggerResult] = []

        # Baseline with cache-bust only
        baseline_nonce = self._random_nonce()
        try:
            baseline_resp = session.request(
                method,
                url,
                data={"_cache_bust": baseline_nonce},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            return results

        baseline_fp = self._fingerprint(baseline_resp)
        baseline_text = baseline_resp.text

        for word in wordlist:
            nonce = self._random_nonce()
            cache_nonce = self._random_nonce()
            try:
                probe_resp = session.request(
                    method,
                    url,
                    data={word: nonce, "_cache_bust": cache_nonce},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue

            probe_fp = self._fingerprint(probe_resp)
            probe_text = probe_resp.text

            if self._is_different(baseline_fp, probe_fp, probe_text, baseline_text):
                reflected = nonce in probe_text
                length_diff = probe_fp[1] - baseline_fp[1]
                evidence_parts: list[str] = []
                if baseline_fp[0] != probe_fp[0]:
                    evidence_parts.append(
                        f"status changed {baseline_fp[0]}->{probe_fp[0]}"
                    )
                if abs(length_diff) > self.diff_threshold:
                    evidence_parts.append(f"length diff {length_diff}")
                if reflected:
                    evidence_parts.append("value reflected in response")

                results.append(
                    ParamDiggerResult(
                        url=url,
                        param_name=word,
                        method=method,
                        injected_value=nonce,
                        baseline_status=baseline_fp[0],
                        found_status=probe_fp[0],
                        length_diff=length_diff,
                        reflected=reflected,
                        evidence="; ".join(evidence_parts),
                    )
                )

            if self.delay > 0:
                time.sleep(self.delay)

        return results

    def _probe_header_params(
        self,
        session: requests.Session,
        url: str,
        wordlist: list[str] | None = None,
    ) -> list[ParamDiggerResult]:
        """Probe custom HTTP headers for hidden behavior."""
        results: list[ParamDiggerResult] = []
        header_words = wordlist if wordlist is not None else _HEADER_WORDLIST

        # Baseline (plain GET, cache-bust via query)
        baseline_nonce = self._random_nonce()
        try:
            baseline_resp = session.get(
                url,
                params={"_cache_bust": baseline_nonce},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            return results

        baseline_fp = self._fingerprint(baseline_resp)
        baseline_text = baseline_resp.text

        for header_name in header_words:
            nonce = self._random_nonce()
            cache_nonce = self._random_nonce()
            try:
                probe_resp = session.get(
                    url,
                    params={"_cache_bust": cache_nonce},
                    headers={header_name: nonce},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue

            probe_fp = self._fingerprint(probe_resp)
            probe_text = probe_resp.text

            if self._is_different(baseline_fp, probe_fp, probe_text, baseline_text):
                reflected = nonce in probe_text
                length_diff = probe_fp[1] - baseline_fp[1]
                evidence_parts: list[str] = []
                if baseline_fp[0] != probe_fp[0]:
                    evidence_parts.append(
                        f"status changed {baseline_fp[0]}->{probe_fp[0]}"
                    )
                if abs(length_diff) > self.diff_threshold:
                    evidence_parts.append(f"length diff {length_diff}")
                if reflected:
                    evidence_parts.append("value reflected in response")

                results.append(
                    ParamDiggerResult(
                        url=url,
                        param_name=header_name,
                        method="HEADER",
                        injected_value=nonce,
                        baseline_status=baseline_fp[0],
                        found_status=probe_fp[0],
                        length_diff=length_diff,
                        reflected=reflected,
                        evidence="; ".join(evidence_parts),
                    )
                )

            if self.delay > 0:
                time.sleep(self.delay)

        return results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        session: requests.Session,
        url: str,
        methods: list[str] | None = None,
    ) -> list[ParamDiggerResult]:
        """
        Run parameter discovery against *url*.

        Parameters
        ----------
        session : requests.Session
            Pre-configured session (cookies, auth, headers).
        url : str
            Target URL to probe.
        methods : list[str] | None
            Probe methods to run.  Accepted values: ``'url'``, ``'body'``,
            ``'header'``.  Defaults to ``['url', 'body']``.

        Returns
        -------
        list[ParamDiggerResult]
            De-duplicated list of discovered parameters.
        """
        if methods is None:
            methods = ["url", "body"]

        all_results: list[ParamDiggerResult] = []

        for probe_method in methods:
            if probe_method == "url":
                all_results.extend(
                    self._probe_url_params(session, url, WORDLIST, method="GET")
                )
            elif probe_method == "body":
                all_results.extend(
                    self._probe_body_params(session, url, WORDLIST, method="POST")
                )
            elif probe_method == "header":
                all_results.extend(self._probe_header_params(session, url))

            if self.delay > 0:
                time.sleep(self.delay)

        # De-duplicate by (url, param_name, method)
        seen: set[tuple[str, str, str]] = set()
        deduped: list[ParamDiggerResult] = []
        for r in all_results:
            key = (r.url, r.param_name, r.method)
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        return deduped
