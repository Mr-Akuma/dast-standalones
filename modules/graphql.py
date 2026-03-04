"""
GraphQL Security Scanner — comprehensive GraphQL endpoint testing.

Tests performed:
  1.  Introspection          — full schema dump via __schema
  2.  Partial introspection   — __type enumeration when introspection disabled
  3.  Field suggestion leak   — "Did you mean" schema enumeration
  4.  Depth bomb              — deeply nested queries (5/7/10/15 levels)
  5.  Batch query abuse       — array of 20 queries
  6.  Alias-based DoS         — 100+ aliases in single query
  7.  Directive overloading   — 50+ @skip/@include directives
  8.  Circular fragment abuse — recursive fragment definitions
  9.  SQL/NoSQL injection     — payloads through GraphQL arguments
  10. CSRF via GET            — mutations executable via GET method
  11. Info disclosure         — verbose errors, stack traces, debug info
  12. GET-based queries       — query via URL parameters (cache poisoning)

Zero hard dependencies beyond requests (already required by parent project).
"""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urljoin, urlencode

import requests
import requests.exceptions


# ── Well-known GraphQL paths ─────────────────────────────────────────────────

GQL_PATHS = [
    "/graphql", "/api/graphql", "/gql", "/graph", "/api/graph",
    "/graphiql", "/v1/graphql", "/v2/graphql", "/api/query",
    "/query", "/api/gql", "/playground",
]

# ── Introspection queries ────────────────────────────────────────────────────

FULL_INTROSPECTION = {
    "query": """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind ofType { name kind } } }
      }
    }
    directives { name locations args { name } }
  }
}"""
}

PARTIAL_INTROSPECTION = {
    "query": "{ __schema { queryType { name } types { name kind } } }"
}

# Common type names for blind enumeration when introspection disabled
COMMON_TYPE_NAMES = [
    "Query", "Mutation", "Subscription", "User", "Admin", "Account",
    "Post", "Comment", "Order", "Product", "Payment", "Token",
    "Session", "Role", "Permission", "File", "Upload", "Message",
    "Notification", "Setting", "Config", "Log", "Event", "Node",
]

# ── Injection payloads ───────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL,NULL--",
    "1' AND SLEEP(3)--",
    "admin'--",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "sleep(3000)"}',
]

# ── Info disclosure patterns ─────────────────────────────────────────────────

INFO_LEAK_PATTERNS = [
    (re.compile(r"at\s+[\w.]+\([\w/\\]+\.(?:js|ts|py|java|go|rb):\d+", re.I), "stack_trace"),
    (re.compile(r"(?:\/home\/|\/var\/|\/usr\/|C:\\\\|\/app\/|\/src\/)\S+", re.I), "file_path"),
    (re.compile(r"\b(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b"), "internal_ip"),
    (re.compile(r'"debug"\s*:\s*true', re.I), "debug_mode"),
    (re.compile(r"(?:postgres|mysql|mongo|redis|sqlite)://", re.I), "connection_string"),
    (re.compile(r"(?:password|passwd|secret|token|api_?key)\s*[:=]\s*[\"']?\w+", re.I), "credential_leak"),
]


# ══════════════════════════════════════════════════════════════════════════════
# GRAPHQL SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class GraphQLScanner:
    """
    Comprehensive GraphQL security scanner.

    Usage:
        scanner = GraphQLScanner(target, session=sess, stop_event=evt)
        findings = scanner.scan()
    """

    def __init__(
        self,
        target:     str,
        session:    requests.Session | None = None,
        stop_event  = None,
        on_finding: Callable | None = None,
        timeout:    int = 10,
        rate_limit: float = 0.05,
    ):
        self.target     = target.rstrip("/")
        self.session    = session or self._default_session()
        self.stop_event = stop_event
        self.on_finding = on_finding
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self._schema    = None           # parsed introspection result
        self._alive_urls: list[str] = [] # confirmed GraphQL endpoints

    @staticmethod
    def _default_session() -> requests.Session:
        import urllib3
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify = False
        s.headers["User-Agent"] = "Mozilla/5.0 (DAST-GraphQL/2.0)"
        return s

    def _stopped(self) -> bool:
        return self.stop_event is not None and self.stop_event.is_set()

    # ── HTTP helpers ─────────────────────────────────────────────────────────

    def _gql_post(self, url: str, payload: dict, headers: dict | None = None) -> requests.Response | None:
        h = {"Content-Type": "application/json"}
        if headers:
            h.update(headers)
        try:
            time.sleep(self.rate_limit)
            return self.session.post(url, json=payload, headers=h, timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _gql_post_raw(self, url: str, body: str, headers: dict | None = None) -> requests.Response | None:
        h = {"Content-Type": "application/json"}
        if headers:
            h.update(headers)
        try:
            time.sleep(self.rate_limit)
            return self.session.post(url, data=body.encode(), headers=h, timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _gql_get(self, url: str, query: str) -> requests.Response | None:
        try:
            time.sleep(self.rate_limit)
            params = urlencode({"query": query})
            return self.session.get(f"{url}?{params}", timeout=self.timeout, verify=False)
        except Exception:
            return None

    # ── Finding builder ──────────────────────────────────────────────────────

    def _finding(
        self,
        url: str, vuln_type: str, finding: str, severity: str,
        proof: str, payload: str, method: str = "POST",
        param: str = "query", param_type: str = "json",
        resp_time_ms: float = 0.0, status_code: int = 0,
    ) -> dict:
        f = {
            "id":          f"gql_{uuid.uuid4().hex[:10]}",
            "url":         url,
            "method":      method,
            "param":       param,
            "param_type":  param_type,
            "vuln_type":   vuln_type,
            "finding":     finding,
            "severity":    severity,
            "proof":       (proof or "")[:500],
            "payload":     (payload or "")[:200],
            "resp_time_ms": resp_time_ms,
            "status_code": status_code,
            "ts":          datetime.now(timezone.utc).isoformat(),
        }
        if self.on_finding:
            try:
                self.on_finding(f)
            except Exception:
                pass
        return f

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ══════════════════════════════════════════════════════════════════════════

    def scan(self, extra_urls: list[str] | None = None) -> list[dict]:
        """
        Run full GraphQL security scan. Returns list of finding dicts.

        Args:
            extra_urls: Additional URLs to probe (e.g., from crawling/sitemap)
        """
        findings: list[dict] = []

        # Phase 0: Discover alive GraphQL endpoints
        self._alive_urls = self._discover_endpoints(extra_urls or [])
        if not self._alive_urls:
            return findings

        for url in self._alive_urls:
            if self._stopped():
                break

            # Phase 1: Introspection
            findings += self._test_introspection(url)

            # Phase 2: Partial introspection / __type enumeration
            findings += self._test_type_enumeration(url)

            # Phase 3: Field suggestion leakage
            findings += self._test_field_suggestion(url)

            # Phase 4: Depth bomb
            findings += self._test_depth_bomb(url)

            # Phase 5: Batch abuse
            findings += self._test_batch_abuse(url)

            # Phase 6: Alias-based DoS
            findings += self._test_alias_dos(url)

            # Phase 7: Directive overloading
            findings += self._test_directive_overload(url)

            # Phase 8: Circular fragment abuse
            findings += self._test_fragment_abuse(url)

            # Phase 9: Injection (SQL/NoSQL) through arguments
            findings += self._test_injection(url)

            # Phase 10: CSRF via GET
            findings += self._test_csrf_get(url)

            # Phase 11: Information disclosure via errors
            findings += self._test_info_disclosure(url)

            # Phase 12: GET-based query execution
            findings += self._test_get_queries(url)

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # ENDPOINT DISCOVERY
    # ══════════════════════════════════════════════════════════════════════════

    def _discover_endpoints(self, extra_urls: list[str]) -> list[str]:
        alive = []
        probe = {"query": "{ __typename }"}

        # Build candidate list
        candidates = set()
        for path in GQL_PATHS:
            candidates.add(urljoin(self.target + "/", path.lstrip("/")))
        for u in extra_urls:
            if any(kw in u.lower() for kw in ("graphql", "gql", "/query", "graphiql")):
                candidates.add(u)

        for url in candidates:
            if self._stopped():
                break
            resp = self._gql_post(url, probe)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        alive.append(url)
                except Exception:
                    pass
        return alive

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 1: INTROSPECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _test_introspection(self, url: str) -> list[dict]:
        findings = []
        resp = self._gql_post(url, FULL_INTROSPECTION)
        if not resp or resp.status_code != 200:
            return findings

        try:
            data = resp.json()
            schema = (data.get("data") or {}).get("__schema")
            if not schema:
                return findings

            self._schema = schema
            types = [t["name"] for t in (schema.get("types") or [])
                     if t.get("name") and not t["name"].startswith("__")]
            mutations = schema.get("mutationType")
            query_type = schema.get("queryType")

            type_count = len(types)
            mut_name = mutations.get("name") if mutations else "none"
            q_name = query_type.get("name") if query_type else "none"

            findings.append(self._finding(
                url=url, vuln_type="graphql_introspection",
                finding=f"GraphQL introspection enabled — {type_count} types, query={q_name}, mutation={mut_name} [{url}]",
                severity="medium",
                proof=f"Types: {', '.join(types[:20])}{'...' if type_count > 20 else ''}",
                payload=FULL_INTROSPECTION["query"][:100],
                status_code=resp.status_code,
            ))
        except Exception:
            pass
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 2: __TYPE ENUMERATION (when introspection disabled)
    # ══════════════════════════════════════════════════════════════════════════

    def _test_type_enumeration(self, url: str) -> list[dict]:
        if self._schema:
            return []  # Introspection works — no need to enumerate

        findings = []
        found_types = []

        for type_name in COMMON_TYPE_NAMES:
            if self._stopped():
                break
            q = {"query": f'{{ __type(name: "{type_name}") {{ name kind fields {{ name }} }} }}'}
            resp = self._gql_post(url, q)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    t = (data.get("data") or {}).get("__type")
                    if t and t.get("name"):
                        found_types.append(t["name"])
                except Exception:
                    pass

        if found_types:
            findings.append(self._finding(
                url=url, vuln_type="graphql_type_enumeration",
                finding=f"GraphQL __type enumeration exposes {len(found_types)} types despite disabled introspection [{url}]",
                severity="medium",
                proof=f"Discovered types: {', '.join(found_types[:15])}",
                payload='{ __type(name: "User") { name fields { name } } }',
                status_code=200,
            ))
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 3: FIELD SUGGESTION LEAKAGE
    # ══════════════════════════════════════════════════════════════════════════

    def _test_field_suggestion(self, url: str) -> list[dict]:
        findings = []
        probe_fields = ["usernme", "passwrd", "emial", "adminAcces", "secrt"]

        for field_name in probe_fields:
            if self._stopped():
                break
            q = {"query": f"{{ {field_name} }}"}
            resp = self._gql_post(url, q)
            if resp and "Did you mean" in (resp.text or ""):
                suggestions = re.findall(r'"Did you mean[^"]*"', resp.text)
                findings.append(self._finding(
                    url=url, vuln_type="graphql_field_suggestion",
                    finding=f"GraphQL field suggestion enabled — schema enumerable via error messages [{url}]",
                    severity="low",
                    proof=resp.text[:300],
                    payload=f'{{ {field_name} }}',
                    status_code=resp.status_code,
                ))
                break  # One finding is enough
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 4: DEPTH BOMB
    # ══════════════════════════════════════════════════════════════════════════

    def _test_depth_bomb(self, url: str) -> list[dict]:
        findings = []

        # Build nested queries at various depths
        depths = [7, 10, 15]
        for depth in depths:
            if self._stopped():
                break
            nested = "{ __typename }"
            for _ in range(depth):
                nested = f"{{ a: __typename b: __typename c: __typename {nested.replace('{', 'sub {')} }}"

            # Simpler reliable depth bomb using a known pattern
            chain = "id"
            for _ in range(depth):
                chain = f"... on __Type {{ name fields {{ name type {{ {chain} }} }} }}"
            depth_query = {"query": f"{{ __schema {{ types {{ {chain} }} }} }}"}

            t0 = time.time()
            resp = self._gql_post(url, depth_query)
            elapsed = time.time() - t0

            if resp and elapsed > 3.0:
                findings.append(self._finding(
                    url=url, vuln_type="graphql_depth_bomb",
                    finding=f"GraphQL depth bomb — {elapsed:.1f}s response at depth {depth} [{url}]",
                    severity="medium",
                    proof=f"Response time: {elapsed:.1f}s at depth {depth}",
                    payload=f"Nested query depth={depth}",
                    resp_time_ms=elapsed * 1000,
                    status_code=resp.status_code if resp else 0,
                ))
                break  # Found the issue, no need to go deeper

            # Also test with a simpler depth pattern using repeated nesting
            simple_q = "{ __typename " * depth + "}" * depth
            t0 = time.time()
            resp2 = self._gql_post(url, {"query": simple_q})
            elapsed2 = time.time() - t0
            if resp2 and elapsed2 > 3.0:
                findings.append(self._finding(
                    url=url, vuln_type="graphql_depth_bomb",
                    finding=f"GraphQL depth bomb — {elapsed2:.1f}s on nested __typename depth {depth} [{url}]",
                    severity="medium",
                    proof=f"Response time: {elapsed2:.1f}s",
                    payload=f"Nested __typename depth={depth}",
                    resp_time_ms=elapsed2 * 1000,
                    status_code=resp2.status_code if resp2 else 0,
                ))
                break

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 5: BATCH QUERY ABUSE
    # ══════════════════════════════════════════════════════════════════════════

    def _test_batch_abuse(self, url: str) -> list[dict]:
        findings = []
        batch = [{"query": "{ __typename }"} for _ in range(20)]

        resp = self._gql_post_raw(url, json.dumps(batch))
        if resp and resp.status_code == 200:
            try:
                result = resp.json()
                if isinstance(result, list) and len(result) >= 15:
                    findings.append(self._finding(
                        url=url, vuln_type="graphql_batch_abuse",
                        finding=f"GraphQL batch queries accepted — {len(result)} responses for 20 queries [{url}]",
                        severity="medium",
                        proof=f"Batch of 20 queries returned {len(result)} results",
                        payload="[{query: ...} x20]",
                        status_code=resp.status_code,
                    ))
            except Exception:
                pass
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 6: ALIAS-BASED DoS
    # ══════════════════════════════════════════════════════════════════════════

    def _test_alias_dos(self, url: str) -> list[dict]:
        findings = []

        # Build query with 100 aliases
        aliases = " ".join(f"a{i}: __typename" for i in range(100))
        q = {"query": f"{{ {aliases} }}"}

        t0 = time.time()
        resp = self._gql_post(url, q)
        elapsed = time.time() - t0

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                result_count = len(data.get("data", {}))
                if result_count >= 90:
                    sev = "high" if elapsed > 2.0 else "medium"
                    findings.append(self._finding(
                        url=url, vuln_type="graphql_alias_dos",
                        finding=f"GraphQL alias-based DoS — {result_count} aliases processed in {elapsed:.1f}s [{url}]",
                        severity=sev,
                        proof=f"{result_count}/100 aliases processed, {elapsed:.1f}s response time",
                        payload=f"{{ a0: __typename a1: __typename ... a99: __typename }}",
                        resp_time_ms=elapsed * 1000,
                        status_code=resp.status_code,
                    ))
            except Exception:
                pass
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 7: DIRECTIVE OVERLOADING
    # ══════════════════════════════════════════════════════════════════════════

    def _test_directive_overload(self, url: str) -> list[dict]:
        findings = []

        # 50 @skip(if:false) directives on a single field
        directives = " @skip(if:false)" * 50
        q = {"query": f"{{ __typename{directives} }}"}

        t0 = time.time()
        resp = self._gql_post(url, q)
        elapsed = time.time() - t0

        if resp and resp.status_code == 200 and elapsed > 2.0:
            findings.append(self._finding(
                url=url, vuln_type="graphql_directive_overload",
                finding=f"GraphQL directive overloading — 50 directives processed in {elapsed:.1f}s [{url}]",
                severity="medium",
                proof=f"50 @skip directives: {elapsed:.1f}s response",
                payload="{ __typename @skip(if:false) x50 }",
                resp_time_ms=elapsed * 1000,
                status_code=resp.status_code,
            ))
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 8: CIRCULAR FRAGMENT ABUSE
    # ══════════════════════════════════════════════════════════════════════════

    def _test_fragment_abuse(self, url: str) -> list[dict]:
        findings = []

        # Circular fragment reference (should be rejected by compliant servers)
        circular = {
            "query": """
                query { ...A }
                fragment A on Query { ...B }
                fragment B on Query { ...A }
            """
        }

        # Deeply nested fragment
        deep_frag = {
            "query": """
                query { ...F1 }
                fragment F1 on Query { __typename ...F2 }
                fragment F2 on Query { __typename ...F3 }
                fragment F3 on Query { __typename ...F4 }
                fragment F4 on Query { __typename ...F5 }
                fragment F5 on Query { __typename ...F6 }
                fragment F6 on Query { __typename ...F7 }
                fragment F7 on Query { __typename ...F8 }
                fragment F8 on Query { __typename ...F9 }
                fragment F9 on Query { __typename ...F10 }
                fragment F10 on Query { __typename }
            """
        }

        # Test circular
        t0 = time.time()
        resp = self._gql_post(url, circular)
        elapsed = time.time() - t0

        if resp and resp.status_code == 200:
            body = resp.text or ""
            if "error" not in body.lower() and elapsed > 2.0:
                findings.append(self._finding(
                    url=url, vuln_type="graphql_fragment_abuse",
                    finding=f"GraphQL circular fragment accepted — possible infinite recursion [{url}]",
                    severity="high",
                    proof=f"Circular fragments processed in {elapsed:.1f}s without error",
                    payload="fragment A on Query { ...B } fragment B on Query { ...A }",
                    resp_time_ms=elapsed * 1000,
                    status_code=resp.status_code,
                ))

        # Test deep fragments
        t0 = time.time()
        resp2 = self._gql_post(url, deep_frag)
        elapsed2 = time.time() - t0

        if resp2 and resp2.status_code == 200 and elapsed2 > 3.0:
            findings.append(self._finding(
                url=url, vuln_type="graphql_fragment_abuse",
                finding=f"GraphQL deep fragment chain (10 levels) — {elapsed2:.1f}s response [{url}]",
                severity="medium",
                proof=f"10-level fragment chain: {elapsed2:.1f}s",
                payload="fragment F1->F2->...->F10",
                resp_time_ms=elapsed2 * 1000,
                status_code=resp2.status_code,
            ))
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 9: INJECTION (SQL / NoSQL) VIA ARGUMENTS
    # ══════════════════════════════════════════════════════════════════════════

    def _test_injection(self, url: str) -> list[dict]:
        findings = []

        # Use schema if available to find string arguments
        arg_queries = self._build_injection_queries()
        if not arg_queries:
            # Fallback: common query patterns
            arg_queries = [
                ('user(id: "{PAYLOAD}")', "user", "id"),
                ('users(filter: "{PAYLOAD}")', "users", "filter"),
                ('search(query: "{PAYLOAD}")', "search", "query"),
                ('login(username: "{PAYLOAD}", password: "test")', "login", "username"),
                ('node(id: "{PAYLOAD}")', "node", "id"),
            ]

        for query_tpl, field_name, arg_name in arg_queries[:8]:  # Limit to 8 queries
            if self._stopped():
                break

            for payload in SQLI_PAYLOADS[:3]:
                if self._stopped():
                    break
                q = {"query": "{ " + query_tpl.replace("{PAYLOAD}", payload) + " { __typename } }"}

                t0 = time.time()
                resp = self._gql_post(url, q)
                elapsed = time.time() - t0

                if not resp:
                    continue

                body = resp.text or ""
                # Check for SQL error indicators
                sql_errors = ["syntax error", "sql", "mysql", "postgres", "sqlite",
                              "ORA-", "ODBC", "unclosed quotation", "unterminated"]
                if any(e.lower() in body.lower() for e in sql_errors):
                    findings.append(self._finding(
                        url=url, vuln_type="graphql_sqli",
                        finding=f"SQL injection via GraphQL argument {field_name}.{arg_name} [{url}]",
                        severity="high",
                        proof=body[:300],
                        payload=payload,
                        resp_time_ms=elapsed * 1000,
                        status_code=resp.status_code,
                    ))
                    break

                # Time-based detection
                if "SLEEP" in payload and elapsed > 2.5:
                    findings.append(self._finding(
                        url=url, vuln_type="graphql_sqli",
                        finding=f"Blind SQL injection (time-based) via GraphQL {field_name}.{arg_name} [{url}]",
                        severity="high",
                        proof=f"SLEEP payload caused {elapsed:.1f}s delay",
                        payload=payload,
                        resp_time_ms=elapsed * 1000,
                        status_code=resp.status_code,
                    ))
                    break

            # NoSQL injection
            for payload in NOSQL_PAYLOADS[:2]:
                if self._stopped():
                    break
                q = {"query": "{ " + query_tpl.replace("{PAYLOAD}", payload) + " { __typename } }"}
                resp = self._gql_post(url, q)
                if resp and resp.status_code == 200:
                    body = resp.text or ""
                    if "data" in body and '"null"' not in body:
                        nosql_errors = ["$gt", "$where", "MongoError", "mongo"]
                        if any(e in body for e in nosql_errors):
                            findings.append(self._finding(
                                url=url, vuln_type="graphql_nosqli",
                                finding=f"NoSQL injection via GraphQL argument {field_name}.{arg_name} [{url}]",
                                severity="high",
                                proof=body[:300],
                                payload=payload,
                                status_code=resp.status_code,
                            ))
                            break

        return findings

    def _build_injection_queries(self) -> list[tuple]:
        """Extract query fields with string arguments from introspection schema."""
        if not self._schema:
            return []
        queries = []
        query_type_name = (self._schema.get("queryType") or {}).get("name", "Query")
        for t in (self._schema.get("types") or []):
            if t.get("name") != query_type_name:
                continue
            for f in (t.get("fields") or []):
                for arg in (f.get("args") or []):
                    arg_type = arg.get("type", {})
                    type_name = arg_type.get("name") or (arg_type.get("ofType") or {}).get("name", "")
                    if type_name in ("String", "ID"):
                        tpl = f'{f["name"]}({arg["name"]}: "{{PAYLOAD}}")'
                        queries.append((tpl, f["name"], arg["name"]))
        return queries

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 10: CSRF VIA GET
    # ══════════════════════════════════════════════════════════════════════════

    def _test_csrf_get(self, url: str) -> list[dict]:
        findings = []

        # Check if mutations work via GET (CSRF vector)
        # Use a safe read-only mutation test — __typename via GET
        resp = self._gql_get(url, "{ __typename }")
        if not resp or resp.status_code != 200:
            return findings

        try:
            data = resp.json()
            if "data" not in data:
                return findings
        except Exception:
            return findings

        # GET queries work — now test if mutations are accepted via GET
        if self._schema and self._schema.get("mutationType"):
            mut_type_name = self._schema["mutationType"]["name"]
            for t in (self._schema.get("types") or []):
                if t.get("name") == mut_type_name:
                    mut_fields = [f["name"] for f in (t.get("fields") or [])[:3]]
                    if mut_fields:
                        # Test if mutation via GET is accepted (just check parsing, don't execute)
                        test_q = f"mutation {{ __typename }}"
                        resp2 = self._gql_get(url, test_q)
                        if resp2 and resp2.status_code == 200:
                            body = resp2.text or ""
                            if "data" in body and "error" not in body.lower():
                                findings.append(self._finding(
                                    url=url, vuln_type="graphql_csrf",
                                    finding=f"GraphQL mutations accepted via GET — CSRF possible for {', '.join(mut_fields)} [{url}]",
                                    severity="high",
                                    proof=f"mutation {{ __typename }} accepted via GET",
                                    payload="GET ?query=mutation{...}",
                                    method="GET",
                                    status_code=resp2.status_code,
                                ))
                    break

        # Even without mutations, GET queries can be a cache poisoning vector
        findings.append(self._finding(
            url=url, vuln_type="graphql_get_query",
            finding=f"GraphQL accepts queries via GET method — potential cache poisoning [{url}]",
            severity="low",
            proof="GET ?query={{ __typename }} returned valid data",
            payload="GET ?query={__typename}",
            method="GET",
            status_code=resp.status_code,
        ))
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 11: INFORMATION DISCLOSURE
    # ══════════════════════════════════════════════════════════════════════════

    def _test_info_disclosure(self, url: str) -> list[dict]:
        findings = []

        # Send intentionally malformed queries to trigger verbose errors
        malformed = [
            {"query": "{ "},                              # incomplete
            {"query": "{ __nonExistentField }"},          # invalid field
            {"query": "mutation { __typename("},          # syntax error
            {"query": "{ a" * 100 + "}" * 100},           # stress parser
            {"variables": {"a": "b"}},                     # missing query
        ]

        for payload in malformed:
            if self._stopped():
                break
            resp = self._gql_post(url, payload)
            if not resp:
                continue

            body = resp.text or ""
            for pattern, leak_type in INFO_LEAK_PATTERNS:
                matches = pattern.findall(body)
                if matches:
                    findings.append(self._finding(
                        url=url, vuln_type="graphql_info_disclosure",
                        finding=f"GraphQL error exposes {leak_type}: {matches[0][:80]} [{url}]",
                        severity="medium" if leak_type in ("stack_trace", "credential_leak", "connection_string") else "low",
                        proof=body[:400],
                        payload=json.dumps(payload)[:100],
                        status_code=resp.status_code,
                    ))
                    break  # One disclosure per payload is enough
        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TEST 12: GET-BASED QUERIES (handled in CSRF test above)
    # ══════════════════════════════════════════════════════════════════════════

    def _test_get_queries(self, url: str) -> list[dict]:
        # This is covered by _test_csrf_get — no duplicate
        return []


# ── Convenience function ─────────────────────────────────────────────────────

def scan_graphql(target: str, session=None, stop_event=None, on_finding=None,
                 timeout: int = 10, extra_urls: list | None = None) -> list[dict]:
    """One-liner: scan a target for GraphQL vulnerabilities."""
    scanner = GraphQLScanner(
        target=target, session=session, stop_event=stop_event,
        on_finding=on_finding, timeout=timeout,
    )
    return scanner.scan(extra_urls=extra_urls)
