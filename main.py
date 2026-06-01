"""
DAST Standalone — entry point.

UI Mode (default):
    python3 main.py
    python3 main.py --port 8080

Headless CLI Mode (no browser needed, no API key needed):
    python3 main.py --headless --target http://example.com
    python3 main.py --headless --target http://example.com --output report.json
    python3 main.py --headless --target http://example.com --openapi http://api/swagger.json
    python3 main.py --headless --target http://example.com --force-browse --no-fuzz
"""
from __future__ import annotations
import sys
import os
import json
import argparse

# macOS: prevent SIGABRT when gunicorn forks workers after Objective-C runtime
# initialization has begun in another thread (e.g. NSCharacterSet via urllib3).
os.environ.setdefault("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES")

# Allow running from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_headless(args):
    """Full standalone scan — no Flask, no browser, no API key."""
    import threading, time, requests
    from urllib.parse import urlparse

    # Silence urllib3 SSL warnings
    import urllib3; urllib3.disable_warnings()

    from modules.scope        import ScopeManager
    from modules.evidence     import evidence_store
    from modules.fingerprint  import fingerprint, fingerprint_summary
    from modules.crawler      import Crawler
    from modules.passive      import passive_scanner, PassiveInterceptSession
    from modules.forcedbrowse import ForcedBrowser, load_wordlist, load_multiple_wordlists
    from modules.traffic      import TrafficLog

    # ── Load YAML scan config (if provided) ─────────────────────────────────
    yaml_hooks = {}
    if getattr(args, 'scan_config', None):
        from modules.automation import load_scan_config, merge_config_into_args
        try:
            config, yaml_hooks = load_scan_config(args.scan_config)
            merge_config_into_args(args, config)
            print(f"[DAST] Loaded scan config: {args.scan_config}")
        except (ValueError, ImportError) as e:
            print(f"[DAST] ⚠ Scan config error: {e}", file=sys.stderr)
            return 1

    raw_pattern_packs = getattr(args, "pattern_pack", None) or []
    pattern_packs = [raw_pattern_packs] if isinstance(raw_pattern_packs, str) else list(raw_pattern_packs)
    env_pattern_packs = os.environ.get("DAST_PATTERN_PACKS") or os.environ.get("DAST_PATTERN_PACK", "")
    if env_pattern_packs:
        pattern_packs.extend(
            part.strip()
            for chunk in env_pattern_packs.split(os.pathsep)
            for part in chunk.split(",")
            if part.strip()
        )
    if pattern_packs:
        try:
            from modules.industry_patterns import load_pattern_packs
            loaded = load_pattern_packs(pattern_packs)
            print(f"[DAST] Loaded {loaded} external DAST pattern pack(s)")
        except Exception as e:
            print(f"[DAST] Pattern pack error: {e}", file=sys.stderr)
            return 1

    from modules.fuzzer import Fuzzer

    target = args.target.strip()
    print(f"\n[DAST] ═══════════════════════════════════════════════════════")
    print(f"[DAST]  Target  : {target}")
    print(f"[DAST]  Mode    : Headless / Standalone (no API key needed)")
    print(f"[DAST] ═══════════════════════════════════════════════════════\n")

    # ── Resolve hook commands (CLI args override YAML) ────────────────────────
    pre_scan_hook = getattr(args, 'pre_scan_hook', None) or yaml_hooks.get('pre_scan')
    post_scan_hook = getattr(args, 'post_scan_hook', None) or yaml_hooks.get('post_scan')
    on_finding_hook = getattr(args, 'on_finding_hook', None) or yaml_hooks.get('on_finding')

    scope       = ScopeManager(target)
    traffic_log = TrafficLog()
    session     = PassiveInterceptSession(traffic_log=traffic_log)
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 (DAST-Headless/2.0)"

    findings: list[dict] = []
    stop     = threading.Event()
    recorder = None

    # ── Pre-scan hook ────────────────────────────────────────────────────────
    if pre_scan_hook:
        from modules.automation import run_hook
        print(f"[DAST] Running pre-scan hook: {pre_scan_hook}")
        run_hook(pre_scan_hook, "pre_scan", data={"target": target})

    # ── Session recording (Burp-style traffic capture) ───────────────────────
    if args.record_session:
        from modules.session_replay import SessionRecorder
        recorder = SessionRecorder(session)
        print(f"[DAST] Recording session traffic → {args.record_session}")

    # ── Authenticated scanning (browser-based login) ─────────────────────────
    auth = None  # Will hold AuthHandler if any auth method is used

    if args.login_url:
        from modules.auth import AuthHandler
        print(f"[DAST] Phase 0: Authenticating via browser login...")
        print(f"[DAST]  Login URL: {args.login_url}")
        print(f"[DAST]  Username : {args.login_user}")

        auth = AuthHandler(timeout=args.timeout)
        result = auth.browser_login(
            login_url=args.login_url,
            username=args.login_user or "",
            password=args.login_pass or "",
            user_selector=args.user_field,
            pass_selector=args.pass_field,
            submit_selector=args.submit_field,
        )

        if result.get("method") == "fallback":
            # Playwright not installed — try requests-based login
            print(f"[DAST] ⚠ {result['message']}")
            print(f"[DAST] Attempting requests-based form login...")
            result = auth.form_login(args.login_url, args.login_user or "", args.login_pass or "")

        if result["success"]:
            print(f"[DAST] ✓ Login successful — {len(result['cookies'])} cookies captured")
            auth.transfer_cookies_to(session)
            # Store credentials for re-auth on 401
            auth.store_credentials("browser",
                login_url=args.login_url,
                username=args.login_user or "",
                password=args.login_pass or "",
                user_selector=args.user_field,
                pass_selector=args.pass_field,
                submit_selector=args.submit_field,
            )
        else:
            print(f"[DAST] ⚠ Login result: {result['message']}")
            print(f"[DAST] Continuing scan without authentication...\n")
            auth = None

    # ── Token-based API authentication (POST JSON → bearer token) ────────────
    elif args.token_url:
        from modules.auth import AuthHandler
        print(f"[DAST] Phase 0: Token authentication...")
        print(f"[DAST]  Token URL: {args.token_url}")
        print(f"[DAST]  Username : {args.login_user or '(from --login-user)'}")

        auth = AuthHandler(timeout=args.timeout)
        result = auth.token_login(
            url=args.token_url,
            username=args.login_user or "",
            password=args.login_pass or "",
            user_field=args.token_field,
            pass_field=args.token_pass_field,
            token_path=args.token_path,
        )

        if result["success"]:
            print(f"[DAST] ✓ Bearer token captured — {result['token']}")
            auth.transfer_cookies_to(session)
            if "Authorization" in auth.session.headers:
                session.headers["Authorization"] = auth.session.headers["Authorization"]
            # Store credentials for re-auth on 401
            auth.store_credentials("token",
                url=args.token_url,
                username=args.login_user or "",
                password=args.login_pass or "",
                user_field=args.token_field,
                pass_field=args.token_pass_field,
                token_path=args.token_path,
            )
        else:
            print(f"[DAST] ⚠ Token auth: {result['message']}")
            print(f"[DAST] Continuing scan without authentication...\n")
            auth = None

    # ── Multi-step scripted authentication ────────────────────────────────
    elif getattr(args, 'auth_script', None):
        from modules.auth import AuthHandler
        print(f"[DAST] Phase 0: Multi-step scripted authentication...")
        print(f"[DAST]  Script: {args.auth_script}")

        auth = AuthHandler(timeout=args.timeout)
        extra_vars = {"target": target}
        if args.login_user:
            extra_vars["username"] = args.login_user
        if args.login_pass:
            extra_vars["password"] = args.login_pass

        result = auth.script_login(args.auth_script, extra_vars=extra_vars)

        if result["success"]:
            print(f"[DAST] ✓ Auth script completed — {result['steps_completed']} steps, "
                  f"{len(result['cookies'])} cookies")
            auth.transfer_cookies_to(session)
            if "Authorization" in auth.session.headers:
                session.headers["Authorization"] = auth.session.headers["Authorization"]
            # Store for re-auth
            auth.store_credentials("script",
                script_path=args.auth_script,
                extra_vars=extra_vars,
            )
        else:
            print(f"[DAST] ⚠ Auth script: {result['message']}")
            print(f"[DAST] Continuing scan without authentication...\n")
            auth = None

    # ── Enable automatic re-authentication on 401 ─────────────────────────
    reauth_session = None
    if auth and auth.authenticated:
        from modules.auth import ReAuthSession, ProactiveReAuthSession
        reauth_session = ReAuthSession(session, auth)
        print(f"[DAST] ✓ Re-authentication enabled (auto-refresh on 401)")
        # Proactive refresh — only when credentials can be replayed (not static cookies)
        _replayable = {"token", "form", "browser", "script"}
        if getattr(auth, "_stored_auth", None) or getattr(auth, "auth_type", "") in _replayable:
            try:
                proactive_reauth = ProactiveReAuthSession(
                    session, auth, refresh_interval=300, refresh_every_n=100,
                )
                print(f"[DAST] ✓ Proactive session refresh enabled (every 5m or 100 requests)\n")
            except Exception as exc:
                print(f"[DAST] ⚠ Proactive refresh setup failed: {exc}\n")
        else:
            print(f"[DAST] ℹ Proactive refresh skipped — static session ({auth.auth_type}), cookies valid until expiry\n")

    # ── OpenAPI import (if requested) ──────────────────────────────────────────
    openapi_surfaces = []
    if args.openapi:
        print(f"[DAST] Importing OpenAPI spec: {args.openapi}")
        try:
            from modules.openapi import import_openapi
            openapi_surfaces = import_openapi(args.openapi, base_url=target)
            print(f"[DAST] → {len(openapi_surfaces)} surfaces from spec")
        except Exception as e:
            print(f"[DAST] ⚠ OpenAPI import failed: {e}")

    # ── Crawl ─────────────────────────────────────────────────────────────────
    if not args.no_crawl:
        print("[DAST] Phase 1: Crawling...")
        crawler = Crawler(
            target=target, scope=scope, session=session,
            max_pages=args.max_pages, max_depth=args.depth,
            timeout=args.timeout, delay=0.05,
            callback=lambda u, s: print(f"  [{s}] {u}"),
        )
        sitemap = crawler.crawl()
        print(f"[DAST] → {len(sitemap.pages)} pages, {len(sitemap.surfaces)} surfaces\n")
    else:
        from modules.crawler import SiteMap
        sitemap = SiteMap()

    # Merge OpenAPI surfaces
    for s in openapi_surfaces:
        sitemap.add_surface(s)

    # ── AJAX Spider (Playwright-based SPA crawling) ──────────────────────────
    if getattr(args, 'ajax_spider', False):
        try:
            from modules.ajax_spider import AjaxSpider
            print("[DAST] Phase 1b: AJAX spider (Playwright headless browser)...")
            # Pass auth cookies and headers to browser context
            ajax_cookies = []
            ajax_headers = dict(session.headers)
            if auth and auth.authenticated:
                parsed = urlparse(target)
                for c in session.cookies:
                    ajax_cookies.append({
                        "name": c.name, "value": c.value,
                        "domain": c.domain or parsed.hostname,
                        "path": c.path or "/",
                    })
            spider = AjaxSpider(
                target=target, scope=scope,
                max_pages=min(args.max_pages, 50),
                max_depth=min(args.depth, 3),
                cookies=ajax_cookies,
                headers=ajax_headers,
                stop_event=stop,
                callback=lambda u, s: print(f"  [JS] [{s}] {u}"),
                traffic_log=traffic_log,
                passive_scanner_instance=passive_scanner,
            )
            ajax_sitemap = spider.crawl()
            # Merge — SiteMap.add_page/add_surface already deduplicates
            pre_pages = len(sitemap.pages)
            pre_surfaces = len(sitemap.surfaces)
            for url, info in ajax_sitemap.pages.items():
                sitemap.add_page(url, info["status"], info["content_type"], info["headers"])
            for s in ajax_sitemap.surfaces:
                sitemap.add_surface(s)
            new_pages = len(sitemap.pages) - pre_pages
            new_surfaces = len(sitemap.surfaces) - pre_surfaces
            # Merge browser passive findings
            browser_findings = spider.get_browser_findings()
            if browser_findings:
                findings.extend(browser_findings)
                print(f"[DAST] → AJAX spider: +{new_pages} new pages, +{new_surfaces} new surfaces, "
                      f"{len(browser_findings)} passive findings from browser traffic\n")
            else:
                print(f"[DAST] → AJAX spider: +{new_pages} new pages, +{new_surfaces} new surfaces\n")
        except RuntimeError as e:
            print(f"[DAST] ⚠ AJAX spider skipped: {e}\n")
        except Exception as e:
            print(f"[DAST] ⚠ AJAX spider failed: {e}\n")

    # ── Replay session (Burp XML or JSON) ─────────────────────────────────────
    if args.replay_session:
        from modules.session_replay import load_session, replay_to_sitemap
        print(f"[DAST] Loading session log: {args.replay_session}")
        try:
            exchanges = load_session(args.replay_session)
            replay_map = replay_to_sitemap(exchanges, scope=scope, inject_session=session)
            # Merge replayed pages and surfaces into main sitemap
            for url, info in replay_map.pages.items():
                sitemap.add_page(url, info["status"], info["content_type"], info["headers"])
            for s in replay_map.surfaces:
                sitemap.add_surface(s)
            print(f"[DAST] → {len(exchanges)} exchanges loaded, "
                  f"{len(replay_map.pages)} pages, {len(replay_map.surfaces)} surfaces\n")
        except Exception as e:
            print(f"[DAST] ⚠ Session replay failed: {e}\n")

    # ── Passive scan (ALL pages — ZAP parity) ──────────────────────────────
    all_pages = list(sitemap.pages.keys())
    print(f"[DAST] Phase 2: Passive scanning {len(all_pages)} pages (headers, cookies, info leaks)...")
    p_count = 0
    for page_url in all_pages:
        try:
            r  = session.get(page_url, timeout=args.timeout)
            pf = passive_scanner.scan(
                url=page_url, status_code=r.status_code,
                resp_headers=dict(r.headers), resp_body=r.text[:8000],
                cookies={c.name: c.value for c in session.cookies},
            )
            for f in pf:
                findings.append({**f.to_dict(), "phase": "passive"})
                p_count += 1
        except Exception:
            pass
    print(f"[DAST] → {p_count} passive findings\n")

    # ── Session token randomness analysis ───────────────────────────────────
    token_findings = []
    if not args.no_token_analysis:
        from modules.token_analysis import analyze_tokens
        print("[DAST] Phase 2b: Session token randomness analysis...")
        try:
            token_findings = analyze_tokens(
                url=target, session=session, timeout=args.timeout,
                callback=lambda f: print(
                    f"  [{f['severity'].upper()}] {f['vuln_type']} — {f['finding'][:80]}"
                ),
            )
            if token_findings:
                print(f"[DAST] → {len(token_findings)} token analysis findings\n")
            else:
                print("[DAST] → No session token issues detected (or no session cookies found)\n")
        except Exception as e:
            print(f"[DAST] ⚠ Token analysis failed: {e}\n")

    # ── Fingerprint ───────────────────────────────────────────────────────────
    print("[DAST] Phase 3: Fingerprinting technology stack...")
    try:
        r  = session.get(target, timeout=args.timeout)
        fp = fingerprint(target, r.status_code, dict(r.headers), r.text[:8000],
                         {c.name: c.value for c in session.cookies})
        print(f"[DAST] → {fingerprint_summary(fp)}\n")
    except Exception as e:
        print(f"[DAST] ⚠ Fingerprint failed: {e}\n")
        fp = {}

    # ── Forced browse (optional) ───────────────────────────────────────────────
    browse_results = []
    if args.force_browse:
        # Determine wordlist selection
        fb_kwargs = {}
        if args.wordlist_categories:
            merged = load_multiple_wordlists(*args.wordlist_categories)
            print(f"[DAST] Phase 4: Forced browse ({len(merged):,} paths from: {', '.join(args.wordlist_categories)})...")
            fb_kwargs["extra_wordlist"] = merged
            fb_kwargs["wordlist_name"] = ""  # skip default loading
        elif args.wordlist:
            if os.path.isfile(args.wordlist):
                fb_kwargs["wordlist_path"] = args.wordlist
                wl = load_wordlist(args.wordlist)
                print(f"[DAST] Phase 4: Forced browse ({len(wl):,} paths from {args.wordlist})...")
            else:
                fb_kwargs["wordlist_name"] = args.wordlist
                wl = load_wordlist(args.wordlist)
                print(f"[DAST] Phase 4: Forced browse ({len(wl):,} paths from '{args.wordlist}')...")
        else:
            wl = load_wordlist("common")
            print(f"[DAST] Phase 4: Forced browse ({len(wl):,} paths, full wordlist)...")

        fb = ForcedBrowser(
            base_url=target, session=session, stop_event=stop,
            callback=lambda r: print(f"  [{r.status_code}] {r.url}  {r.note}"),
            **fb_kwargs,
        )
        browse_results = [r.to_dict() for r in fb.run()]
        print(f"[DAST] → {len(browse_results)} interesting paths\n")

    # ── Start OAST callback server for blind vulnerability detection ─────────
    oast_server = None
    try:
        from modules.oast import get_or_start_oast
        oast_server = get_or_start_oast(
            host_override=getattr(args, "oast_host", "") or "",
            public_base_url=getattr(args, "oast_public_base_url", "") or "",
        )
        print(f"[DAST] OAST callback listener started on port {oast_server.port}")
        if getattr(oast_server, "public_base_url", ""):
            print(f"[DAST] OAST public callback base: {oast_server.public_base_url}")
    except Exception as e:
        print(f"[DAST] ⚠ OAST server failed to start: {e} (blind detection disabled)")

    # ── LLM provider for adaptive fuzzing (env vars: ANTHROPIC_API_KEY, OPENAI_API_KEY)
    _llm_provider = None
    _llm_keys = {}
    if os.environ.get("ANTHROPIC_API_KEY"):
        _llm_keys["anthropic"] = os.environ["ANTHROPIC_API_KEY"]
    if os.environ.get("OPENAI_API_KEY"):
        _llm_keys["openai"] = os.environ["OPENAI_API_KEY"]
    if _llm_keys:
        try:
            from modules.llm_provider import LLMProvider
            _llm_provider = LLMProvider(api_keys=_llm_keys)
            print(f"[DAST] ✓ LLM adaptive fuzzer enabled ({_llm_provider.active_backend()})")
        except Exception as e:
            print(f"[DAST] ⚠ LLM provider setup failed: {e}")

    # ── Active fuzz ────────────────────────────────────────────────────────────
    fuzz_findings = []
    if not args.no_fuzz and sitemap.surfaces:
        print(f"[DAST] Phase 5: Active fuzzing ({len(sitemap.surfaces)} surfaces)...")
        fuzzer = Fuzzer(scope=scope, session=session, timeout=args.timeout,
                        rate_limit=0.05, stop_event=stop, oast=oast_server,
                        llm_provider=_llm_provider,
                        allow_dangerous_endpoints=getattr(args, "allow_dangerous_endpoints", False))
        results = fuzzer.fuzz_all(sitemap.surfaces)
        for r in results:
            fuzz_findings.append(r.__dict__)
            sev = r.severity.upper()
            print(f"  [{sev}] {r.vuln_type} — {r.url} [{r.param}]")
        print(f"[DAST] → {len(fuzz_findings)} active findings\n")

    # ── GraphQL scanning ──────────────────────────────────────────────────────
    gql_findings = []
    if not getattr(args, 'no_graphql', False):
        from modules.graphql import scan_graphql
        # Auto-detect GraphQL endpoints from crawl results + common paths
        gql_urls = set()
        for page_url in sitemap.pages:
            if any(seg in page_url.lower() for seg in ("/graphql", "/gql", "/query")):
                gql_urls.add(page_url)
        # Always probe common GraphQL paths
        for path in ["/graphql", "/api/graphql", "/gql", "/graphql/v1", "/api/gql"]:
            gql_urls.add(target.rstrip("/") + path)

        if gql_urls:
            print(f"[DAST] Phase 5b: GraphQL scanning ({len(gql_urls)} endpoints)...")
            try:
                gql_findings = scan_graphql(
                    target=target, session=session, stop_event=stop,
                    timeout=args.timeout, extra_urls=list(gql_urls),
                    on_finding=lambda f: print(
                        f"  [{f.get('severity','?').upper()}] {f.get('vuln_type','')} — {f.get('finding','')[:80]}"
                    ),
                )
                print(f"[DAST] → {len(gql_findings)} GraphQL findings\n")
            except Exception as e:
                print(f"[DAST] ⚠ GraphQL scan failed: {e}\n")

    # ── WebSocket scanning ─────────────────────────────────────────────────────
    ws_findings = []
    if not getattr(args, 'no_websocket', False):
        from modules.websocket import scan_websocket
        # Auto-detect WebSocket endpoints from crawl, AJAX spider network reqs
        ws_urls = set()
        for page_url in sitemap.pages:
            if page_url.startswith(("ws://", "wss://")):
                ws_urls.add(page_url)
        # Probe common WebSocket paths
        ws_base = target.replace("http://", "ws://").replace("https://", "wss://").rstrip("/")
        for path in ["/ws", "/websocket", "/socket", "/ws/v1", "/realtime"]:
            ws_urls.add(ws_base + path)

        if ws_urls:
            print(f"[DAST] Phase 5c: WebSocket scanning ({len(ws_urls)} endpoints)...")
            try:
                # Extract auth headers from the active session so that
                # authenticated WS endpoints are reachable during the scan.
                _ws_auth: dict = {}
                _auth_val = session.headers.get("Authorization", "")
                if _auth_val:
                    _ws_auth["Authorization"] = _auth_val
                _ws_cookie = "; ".join(
                    f"{c.name}={c.value}" for c in session.cookies
                )
                if _ws_cookie:
                    _ws_auth["Cookie"] = _ws_cookie

                ws_findings = scan_websocket(
                    target=target, stop_event=stop,
                    timeout=args.timeout, extra_urls=list(ws_urls),
                    auth_headers=_ws_auth or None,
                    on_finding=lambda f: print(
                        f"  [{f.get('severity','?').upper()}] {f.get('vuln_type','')} — {f.get('finding','')[:80]}"
                    ),
                )
                print(f"[DAST] → {len(ws_findings)} WebSocket findings\n")
            except Exception as e:
                print(f"[DAST] ⚠ WebSocket scan failed: {e}\n")

    # ── Per-user access control comparison ────────────────────────────────────
    ac_findings = []
    if args.users_file:
        from modules.auth import MultiUserScanner
        print(f"[DAST] Phase 6: Multi-user access control testing...")
        try:
            mu_scanner = MultiUserScanner.from_config(
                args.users_file, timeout=args.timeout,
                filter_users=args.users,
            )
            # Always include unauthenticated baseline
            has_unauth = any(u.role.lower() == "none" for u in mu_scanner.users)
            if not has_unauth:
                mu_scanner.add_unauth_baseline()

            # Authenticate all users
            auth_results = mu_scanner.authenticate_all()
            for ar in auth_results:
                status = "✓" if ar["success"] else "✗"
                print(f"  [{status}] {ar['user']} (role={ar['role']}): {ar['message']}")

            # Compare access across all discovered pages
            test_urls = list(sitemap.pages.keys())
            print(f"[DAST] Testing {len(test_urls)} URLs across {len(mu_scanner.users)} user contexts...")
            ac_findings = mu_scanner.compare_access(
                test_urls, timeout=args.timeout,
                callback=lambda f: print(
                    f"  [{f['severity'].upper()}] {f['vuln_type']} — {f['url']} "
                    f"[{f['user']} vs {f['ref_user']}]"
                ),
            )
            print(f"[DAST] → {len(ac_findings)} access control findings\n")
        except Exception as e:
            print(f"[DAST] ⚠ Multi-user scanning failed: {e}\n")

    # ── Advanced scanner — JWT, session security, CORS, OAuth, CSRF ─────────────
    advanced_findings: list[dict] = []
    if not getattr(args, 'no_fuzz', False):
        try:
            from modules.scanner import VulnerabilityScanner as Scanner
            print("[DAST] Phase 6a: Advanced security checks (JWT, session, CORS, OAuth, CSRF)...")
            adv_scanner = Scanner(
                target=target, scope=scope, session=session, timeout=args.timeout,
                allow_dangerous_endpoints=getattr(args, "allow_dangerous_endpoints", False),
                on_finding=lambda f: print(
                    f"  [{f.get('severity','?').upper()}] {f.get('vuln_type','')} — "
                    f"{f.get('finding','')[:80]}"
                ),
            )
            adv_results = adv_scanner.scan(sitemap)
            for r in adv_results:
                d = r if isinstance(r, dict) else (r.__dict__ if hasattr(r, '__dict__') else {})
                advanced_findings.append(d)
            print(f"[DAST] → {len(advanced_findings)} advanced findings\n")
        except Exception as e:
            print(f"[DAST] ⚠ Advanced scanner failed: {e}\n")

    # ── HTTP/2 smuggling ───────────────────────────────────────────────────────
    smuggle_findings: list[dict] = []
    if not getattr(args, 'no_fuzz', False):
        try:
            from modules.http2_smuggler import HTTP2Smuggler as Http2Smuggler
            print("[DAST] Phase 6b: HTTP/2 request smuggling...")
            smuggler = Http2Smuggler(
                target=target, session=session, timeout=args.timeout, stop_event=stop,
                on_finding=lambda f: print(
                    f"  [{f.get('severity','?').upper()}] {f.get('vuln_type','')} — "
                    f"{f.get('finding','')[:80]}"
                ),
            )
            smuggle_results = smuggler.scan(list(sitemap.pages.keys()))
            for r in smuggle_results:
                d = r if isinstance(r, dict) else (r.__dict__ if hasattr(r, '__dict__') else {})
                smuggle_findings.append(d)
            print(f"[DAST] → {len(smuggle_findings)} HTTP/2 smuggling findings\n")
        except Exception as e:
            print(f"[DAST] ⚠ HTTP/2 smuggler failed: {e}\n")

    # ── Race condition testing ─────────────────────────────────────────────────
    race_findings: list[dict] = []
    if not getattr(args, 'no_fuzz', False) and sitemap.surfaces:
        try:
            from modules.race_condition import RaceConditionTester as RaceConditionScanner
            race_surfaces = [
                s for s in sitemap.surfaces
                if s.method in ("POST", "PUT", "PATCH", "DELETE")
            ][:20]  # cap to 20 endpoints for headless budget
            if race_surfaces:
                print(f"[DAST] Phase 6c: Race condition testing ({len(race_surfaces)} endpoints)...")
                race_scanner = RaceConditionScanner(
                    session=session, timeout=args.timeout, stop_event=stop,
                    allow_dangerous_endpoints=getattr(args, "allow_dangerous_endpoints", False),
                    on_finding=lambda f: print(
                        f"  [{f.get('severity','?').upper()}] {f.get('vuln_type','')} — "
                        f"{f.get('finding','')[:80]}"
                    ),
                )
                race_results = race_scanner.scan(target, sitemap=sitemap)
                for r in race_results:
                    d = r if isinstance(r, dict) else (r.__dict__ if hasattr(r, '__dict__') else {})
                    race_findings.append(d)
                print(f"[DAST] → {len(race_findings)} race condition findings\n")
        except Exception as e:
            print(f"[DAST] ⚠ Race condition scanner failed: {e}\n")

    # ── DOM XSS active scanning ────────────────────────────────────────────────
    dom_xss_findings: list[dict] = []
    if not getattr(args, 'no_fuzz', False) and sitemap.surfaces:
        try:
            from modules.dom_xss_active import DomXssActiveScanner
            print(f"[DAST] Phase 6d: DOM XSS active scanning ({len(sitemap.surfaces)} surfaces)...")
            dom_scanner = DomXssActiveScanner(
                session=session, scope=scope,
                on_finding=lambda f: print(
                    f"  [{f.get('severity','?').upper()}] {f.get('vuln_type','')} — "
                    f"{f.get('finding','')[:80]}"
                ),
            )
            dom_results = dom_scanner.scan(target, sitemap=sitemap)
            for r in dom_results:
                d = r if isinstance(r, dict) else (r.__dict__ if hasattr(r, '__dict__') else {})
                dom_xss_findings.append(d)
            print(f"[DAST] → {len(dom_xss_findings)} DOM XSS findings\n")
        except Exception as e:
            print(f"[DAST] ⚠ DOM XSS scanner failed: {e}\n")

    # ── Cache poisoning ────────────────────────────────────────────────────────
    cache_findings: list[dict] = []
    if not getattr(args, 'no_fuzz', False):
        try:
            from modules.cache_poisoning import CachePoisoningScanner
            print(f"[DAST] Phase 6e: Cache poisoning ({len(sitemap.pages)} pages)...")
            cache_scanner = CachePoisoningScanner(
                target=target, session=session, stop_event=stop,
            )
            cache_results = cache_scanner.scan(list(sitemap.pages.keys()))
            for r in cache_results:
                d = r if isinstance(r, dict) else (r.__dict__ if hasattr(r, '__dict__') else {})
                cache_findings.append(d)
            print(f"[DAST] → {len(cache_findings)} cache poisoning findings\n")
        except Exception as e:
            print(f"[DAST] ⚠ Cache poisoning scanner failed: {e}\n")

    # ── Merge intercepted passive findings (from ALL phases) ────────────────────
    intercepted = session.get_findings_dicts()
    if intercepted:
        # Deduplicate against findings already captured in the dedicated passive phase
        existing_keys = set()
        for f in findings:
            existing_keys.add((f.get("url", ""), f.get("category", ""), f.get("finding", "")))
        new_intercepts = 0
        for f in intercepted:
            key = (f.get("url", ""), f.get("category", ""), f.get("finding", ""))
            if key not in existing_keys:
                findings.append({**f, "phase": "passive_intercept"})
                existing_keys.add(key)
                new_intercepts += 1
        if new_intercepts:
            print(f"[DAST] → {new_intercepts} additional passive findings from intercepted responses\n")

    # ── Summary ────────────────────────────────────────────────────────────────
    all_findings = (
        findings + fuzz_findings + gql_findings + ws_findings + ac_findings
        + token_findings + advanced_findings + smuggle_findings
        + race_findings + dom_xss_findings + cache_findings
    )
    from modules.finding_postprocessor import postprocess_findings
    all_findings, postprocess_summary = postprocess_findings(all_findings)
    if postprocess_summary.get("duplicates_removed"):
        print(
            "[DAST] Post-processing removed "
            f"{postprocess_summary['duplicates_removed']} duplicate/noisier findings"
        )

    # ── Apply policy overrides (per-rule IGNORE/INFO/WARN/FAIL) ──────────────
    from modules.reporting import PolicyEngine, SuppressionFile, SarifReport, calculate_exit_code

    if args.policy:
        policy = PolicyEngine(args.policy)
        before_policy_count = len(all_findings)
        all_findings = policy.apply(all_findings)
        ignored = before_policy_count - len(all_findings)
        if ignored:
            print(f"[DAST] Policy applied — {ignored} findings ignored by policy")

    # ── Apply false positive suppression ─────────────────────────────────────
    if args.suppress:
        suppression = SuppressionFile(args.suppress)
        all_findings, suppressed_count = suppression.filter(all_findings)
        if suppressed_count:
            print(f"[DAST] Suppression applied — {suppressed_count} false positives filtered")

    # ── Generate suppression template (if requested) ─────────────────────────
    if args.generate_suppress:
        count = SuppressionFile.generate(all_findings, args.generate_suppress)
        print(f"[DAST] Suppression template generated → {args.generate_suppress} ({count} entries)")

    severity_counts = {}
    for f in all_findings:
        s = f.get("severity", "Info")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    print("[DAST] ═══════════════════════════════════════════════════════")
    print(f"[DAST]  SCAN COMPLETE — {len(all_findings)} total findings")
    for sev, cnt in sorted(severity_counts.items()):
        print(f"[DAST]    {sev:10}: {cnt}")
    print("[DAST] ═══════════════════════════════════════════════════════\n")

    # ── Per-finding hook ─────────────────────────────────────────────────────
    if on_finding_hook:
        from modules.automation import run_hook
        print(f"[DAST] Running on-finding hook for {len(all_findings)} findings...")
        for finding in all_findings:
            run_hook(on_finding_hook, "on_finding", data=finding)

    # ── Output — JSON report ─────────────────────────────────────────────────
    report = {
        "target":        target,
        "fingerprint":   fp,
        "pages":         len(sitemap.pages),
        "surfaces":      len(sitemap.surfaces),
        "findings":      all_findings,
        "browse":        browse_results,
        "severity_summary": severity_counts,
        "post_processing": postprocess_summary,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[DAST] Report saved → {args.output}")
    else:
        print(json.dumps(report, indent=2))

    # ── Output — SARIF report (for GitHub/GitLab CI) ─────────────────────────
    if args.output_sarif:
        sarif = SarifReport()
        sarif.save(all_findings, target, args.output_sarif)
        print(f"[DAST] SARIF report saved → {args.output_sarif}")

    # ── Save recorded session (if recording) ──────────────────────────────────
    if recorder:
        recorder.stop()
        out_path = args.record_session
        if out_path.endswith(".xml"):
            count = recorder.save_burp_xml(out_path)
            fmt = "Burp XML"
        else:
            count = recorder.save_json(out_path)
            fmt = "JSON"
        print(f"[DAST] Session log saved → {out_path} ({count} exchanges, {fmt})")
        print(f"[DAST] ⚠ Session log may contain auth tokens/cookies — store securely")

    # ── Traffic visibility summary ─────────────────────────────────────────
    traffic_log.print_summary()

    # ── Export traffic log (if requested) ──────────────────────────────────
    traffic_log_path = getattr(args, 'traffic_log', None)
    if traffic_log_path:
        count = traffic_log.export(traffic_log_path)
        print(f"[DAST] Traffic log saved → {traffic_log_path} ({count} exchanges)")

    # ── Post-scan hook ───────────────────────────────────────────────────────
    if post_scan_hook:
        from modules.automation import run_hook
        print(f"[DAST] Running post-scan hook: {post_scan_hook}")
        run_hook(post_scan_hook, "post_scan", data={
            "target": target,
            "finding_count": len(all_findings),
            "severity_summary": severity_counts,
        })

    # ── CI exit code ─────────────────────────────────────────────────────────
    exit_code = calculate_exit_code(all_findings, fail_on=args.fail_on)
    if exit_code == 0:
        print(f"[DAST] CI: PASS (no findings at or above '{args.fail_on}' severity)")
    elif exit_code == 1:
        print(f"[DAST] CI: FAIL (findings at or above '{args.fail_on}' severity)")
    elif exit_code == 2:
        print(f"[DAST] CI: WARN (findings below '{args.fail_on}' but Medium+ present)")
    return exit_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DAST Standalone — Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Server mode
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5002)),
                        help="Port for UI server (default: 5002)")

    # Headless mode
    parser.add_argument("--headless", action="store_true",
                        help="Run headless scan (no UI server, no API key)")
    parser.add_argument("--target",    help="Target URL for headless scan")
    parser.add_argument("--output",    help="Output file path (JSON). Default: stdout")
    parser.add_argument("--openapi",   help="OpenAPI/Swagger spec URL or file path")
    parser.add_argument("--max-pages", type=int, default=200, dest="max_pages",
                        help="Max pages to crawl (default: 200)")
    parser.add_argument("--depth",     type=int, default=5,
                        help="Crawl depth (default: 5)")
    parser.add_argument("--timeout",   type=int, default=10,
                        help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--force-browse", action="store_true", dest="force_browse",
                        help="Run forced browse (wordlist directory discovery)")
    parser.add_argument("--wordlist",  dest="wordlist",
                        help="Wordlist category or file path for forced browse "
                             "(e.g. 'common', 'admin', 'api', 'cms', or /path/to/file.txt)")
    parser.add_argument("--wordlist-category", dest="wordlist_categories", action="append",
                        help="Load specific wordlist categories (can repeat: "
                             "--wordlist-category admin --wordlist-category api)")
    parser.add_argument("--list-wordlists", action="store_true", dest="list_wordlists",
                        help="List available wordlist categories and exit")
    parser.add_argument("--no-fuzz",   action="store_true", dest="no_fuzz",
                        help="Skip active fuzzing (passive + crawl only)")
    parser.add_argument("--allow-dangerous-endpoints", action="store_true",
                        dest="allow_dangerous_endpoints",
                        help="Allow active fuzzing of payment/account-changing endpoints")
    parser.add_argument("--no-crawl",  action="store_true", dest="no_crawl",
                        help="Skip crawling (use with --openapi)")
    parser.add_argument("--no-token-analysis", action="store_true", dest="no_token_analysis",
                        help="Skip session token randomness analysis")
    parser.add_argument("--ajax-spider", action="store_true", dest="ajax_spider",
                        help="Run AJAX spider (Playwright-based SPA crawling)")
    parser.add_argument("--no-graphql", action="store_true", dest="no_graphql",
                        help="Skip GraphQL scanning")
    parser.add_argument("--no-websocket", action="store_true", dest="no_websocket",
                        help="Skip WebSocket scanning")
    parser.add_argument("--pattern-pack", dest="pattern_pack", action="append",
                        help="Load an external JSON DAST pattern pack (repeatable)")
    parser.add_argument("--oast-public-base-url", dest="oast_public_base_url",
                        help="Externally reachable OAST HTTP callback base URL")
    parser.add_argument("--oast-host", dest="oast_host",
                        help="Host/IP to place in local OAST callback URLs")

    # Per-user multi-role authenticated scanning
    parser.add_argument("--users-file", dest="users_file",
                        help="JSON config with multiple users/roles for access control testing")
    parser.add_argument("-U", "--user", dest="users", action="append",
                        help="User name from --users-file to scan as (repeatable, default: all)")

    # Authenticated scanning (browser-based login)
    parser.add_argument("--login-url",  dest="login_url",
                        help="Login page URL for authenticated scanning")
    parser.add_argument("--login-user", dest="login_user",
                        help="Username/email for login")
    parser.add_argument("--login-pass", dest="login_pass",
                        help="Password for login")
    parser.add_argument("--user-field", dest="user_field",
                        help="CSS selector for username field (default: auto-detect)")
    parser.add_argument("--pass-field", dest="pass_field",
                        help="CSS selector for password field (default: auto-detect)")
    parser.add_argument("--submit-field", dest="submit_field",
                        help="CSS selector for submit button (default: auto-detect)")

    # Token-based API authentication (POST JSON → capture bearer token)
    parser.add_argument("--token-url",  dest="token_url",
                        help="API login endpoint for bearer token auth (POST JSON)")
    parser.add_argument("--token-field", dest="token_field", default="username",
                        help="JSON key for username in token request (default: username)")
    parser.add_argument("--token-pass-field", dest="token_pass_field", default="password",
                        help="JSON key for password in token request (default: password)")
    parser.add_argument("--token-path", dest="token_path",
                        help="Dot-path to token in response JSON (e.g. data.access_token). "
                             "Default: auto-detect")

    # Multi-step scripted authentication
    parser.add_argument("--auth-script", dest="auth_script",
                        help="JSON auth script for multi-step login flows (OAuth, MFA, SSO)")

    # Session record & replay (Burp-style)
    parser.add_argument("--record-session", dest="record_session",
                        help="Record all HTTP traffic to file (JSON or .xml for Burp format)")
    parser.add_argument("--replay-session", dest="replay_session",
                        help="Replay a saved session log (Burp XML or JSON) for scanning")

    # CI/CD reporting options
    parser.add_argument("--output-sarif", dest="output_sarif",
                        help="Export SARIF v2.1.0 report (for GitHub/GitLab CI)")
    parser.add_argument("--policy", dest="policy",
                        help="Policy JSON for per-rule severity overrides (IGNORE/INFO/WARN/FAIL)")
    parser.add_argument("--suppress", dest="suppress",
                        help="Suppression JSON for false positive filtering by fingerprint")
    parser.add_argument("--generate-suppress", dest="generate_suppress",
                        help="Generate suppression template from findings to this file path")
    parser.add_argument("--fail-on", dest="fail_on", default="high",
                        choices=["low", "medium", "high", "critical"],
                        help="CI failure threshold (default: high). Exit 1 if findings at/above this level")

    # Automation — YAML config and hooks
    parser.add_argument("--scan-config", dest="scan_config",
                        help="YAML scan configuration file (declarative scan plan)")
    parser.add_argument("--pre-scan-hook", dest="pre_scan_hook",
                        help="Shell command to run before scan starts")
    parser.add_argument("--post-scan-hook", dest="post_scan_hook",
                        help="Shell command to run after scan completes")
    parser.add_argument("--on-finding-hook", dest="on_finding_hook",
                        help="Shell command to run for each finding (JSON on stdin)")

    # Traffic visibility
    parser.add_argument("--traffic-log", dest="traffic_log",
                        help="Export full traffic capture (all HTTP exchanges) to JSON file")

    args = parser.parse_args()

    if args.list_wordlists:
        from modules.forcedbrowse import available_wordlists, WORDLIST_CATEGORIES
        avail = available_wordlists()
        print("[DAST] Available wordlist categories:")
        for name in sorted(WORDLIST_CATEGORIES.keys()):
            count = avail.get(name, 0)
            marker = " ★" if name == "common" else ""
            if count:
                print(f"  {name:15} {count:>6,} paths{marker}")
            else:
                print(f"  {name:15}   (not found)")
        print(f"\nUsage: --wordlist <category>  or  --wordlist /path/to/custom.txt")
        print(f"       --wordlist-category admin --wordlist-category api  (merge multiple)")
        sys.exit(0)

    if args.headless:
        if not args.target:
            print("[ERROR] --target is required with --headless", file=sys.stderr)
            sys.exit(1)
        sys.exit(run_headless(args))
    else:
        from app import app
        port = args.port
        app.config["PORT"] = port
        # Use gunicorn in production, fall back to Werkzeug dev server only locally
        use_gunicorn = os.environ.get("USE_GUNICORN", "1") != "0"
        if use_gunicorn:
            try:
                from gunicorn.app.base import BaseApplication
                class _StandaloneApp(BaseApplication):
                    def __init__(self, application, options=None):
                        self.options = options or {}
                        self.application = application
                        super().__init__()
                    def load_config(self):
                        for k, v in self.options.items():
                            self.cfg.set(k.lower(), v)
                    def load(self):
                        return self.application
                def _post_worker_init(worker):
                    """Post-fork worker init: disable proxy detection + reset SQLite."""
                    # macOS 26.4: SCDynamicStoreCopyProxiesWithOptions crashes in worker
                    # threads after fork. Disable proxy detection entirely in the worker.
                    import os as _os
                    _os.environ["no_proxy"] = "*"
                    _os.environ["NO_PROXY"] = "*"
                    # Patch urllib so _scproxy.getproxies() is never called
                    try:
                        import urllib.request as _ur
                        _ur.getproxies = lambda: {}
                    except Exception:
                        pass
                    try:
                        import urllib.request as _ur
                        if hasattr(_ur, "proxy_bypass_macosx_sysconf"):
                            _ur.proxy_bypass_macosx_sysconf = lambda host: True
                    except Exception:
                        pass
                    # Patch requests so it never calls get_proxy_settings
                    try:
                        import requests.utils as _ru
                        _ru.get_environ_proxies = lambda url, no_proxy=None: {}
                    except Exception:
                        pass
                    try:
                        import requests as _rq
                        _orig_send = _rq.adapters.HTTPAdapter.send
                        def _send_no_proxy(self, request, *args, **kwargs):
                            kwargs.setdefault("proxies", {})
                            return _orig_send(self, request, *args, **kwargs)
                        _rq.adapters.HTTPAdapter.send = _send_no_proxy
                    except Exception:
                        pass
                    # Close any SQLite connections inherited from master via fork
                    try:
                        from modules.db_manager import _db
                        if hasattr(_db, "sql") and hasattr(_db.sql, "reset_after_fork"):
                            _db.sql.reset_after_fork()
                    except Exception:
                        pass

                # Pre-warm macOS proxy detection in the master process so
                # NSMutableDictionary and SCDynamicStore are fully initialised
                # before any fork().  Without this, the child's first call to
                # get_proxy_settings() triggers ObjC +initialize on the child
                # side of fork and crashes with SIGKILL (namespace OBJC).
                # OBJC_DISABLE_INITIALIZE_FORK_SAFETY is not honoured on macOS 26+.
                try:
                    import urllib.request as _ur
                    _ur.getproxies()
                except Exception:
                    pass
                try:
                    import urllib3 as _u3
                    _u3.ProxyManager  # force import
                except Exception:
                    pass
                try:
                    import requests as _rq
                    _rq.utils.get_environ_proxies("http://localhost")
                except Exception:
                    pass

                workers = int(os.environ.get("WEB_CONCURRENCY", "1"))
                print(f"[DAST] Starting with gunicorn on http://0.0.0.0:{port} ({workers} worker(s))")
                _StandaloneApp(app, {
                    "bind":              f"0.0.0.0:{port}",
                    "workers":           workers,
                    "worker_class":      "gthread",
                    "threads":           4,
                    "timeout":           120,
                    "graceful_timeout":  30,
                    "accesslog":         "-",
                    "errorlog":          "-",
                    "post_worker_init":  _post_worker_init,
                }).run()
            except ImportError:
                print("[DAST] gunicorn not installed — falling back to Werkzeug (not for production)")
                app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
        else:
            print(f"[DAST] Starting on http://localhost:{port} (Werkzeug dev server)")
            app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
