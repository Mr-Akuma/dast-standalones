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
    from modules.fuzzer       import Fuzzer
    from modules.passive      import passive_scanner, PassiveInterceptSession
    from modules.forcedbrowse import ForcedBrowser, load_wordlist, load_multiple_wordlists

    target = args.target.strip()
    print(f"\n[DAST] ═══════════════════════════════════════════════════════")
    print(f"[DAST]  Target  : {target}")
    print(f"[DAST]  Mode    : Headless / Standalone (no API key needed)")
    print(f"[DAST] ═══════════════════════════════════════════════════════\n")

    scope    = ScopeManager(target)
    session  = PassiveInterceptSession()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 (DAST-Headless/2.0)"

    findings: list[dict] = []
    stop     = threading.Event()
    recorder = None

    # ── Session recording (Burp-style traffic capture) ───────────────────────
    if args.record_session:
        from modules.session_replay import SessionRecorder
        recorder = SessionRecorder(session)
        print(f"[DAST] Recording session traffic → {args.record_session}")

    # ── Authenticated scanning (browser-based login) ─────────────────────────
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
            # Transfer auth cookies/headers to the scan session
            auth.transfer_cookies_to(session)
        else:
            print(f"[DAST] ⚠ Login result: {result['message']}")
            print(f"[DAST] Continuing scan without authentication...\n")

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
            # Also transfer the Authorization header directly
            if "Authorization" in auth.session.headers:
                session.headers["Authorization"] = auth.session.headers["Authorization"]
        else:
            print(f"[DAST] ⚠ Token auth: {result['message']}")
            print(f"[DAST] Continuing scan without authentication...\n")

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

    # ── Replay session (Burp XML or JSON) ─────────────────────────────────────
    if args.replay_session:
        from modules.session_replay import load_session, replay_to_sitemap
        print(f"[DAST] Loading session log: {args.replay_session}")
        try:
            exchanges = load_session(args.replay_session)
            replay_map = replay_to_sitemap(exchanges, scope=scope)
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
        oast_server = get_or_start_oast()
        print(f"[DAST] OAST callback listener started on port {oast_server.port}")
    except Exception as e:
        print(f"[DAST] ⚠ OAST server failed to start: {e} (blind detection disabled)")

    # ── Active fuzz ────────────────────────────────────────────────────────────
    fuzz_findings = []
    if not args.no_fuzz and sitemap.surfaces:
        print(f"[DAST] Phase 5: Active fuzzing ({len(sitemap.surfaces)} surfaces)...")
        fuzzer = Fuzzer(scope=scope, session=session, timeout=args.timeout,
                        rate_limit=0.05, stop_event=stop, oast=oast_server)
        results = fuzzer.fuzz_all(sitemap.surfaces)
        for r in results:
            fuzz_findings.append(r.__dict__)
            sev = r.severity.upper()
            print(f"  [{sev}] {r.vuln_type} — {r.url} [{r.param}]")
        print(f"[DAST] → {len(fuzz_findings)} active findings\n")

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
    all_findings = findings + fuzz_findings + ac_findings + token_findings
    severity_counts = {}
    for f in all_findings:
        s = f.get("severity", "Info")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    print("[DAST] ═══════════════════════════════════════════════════════")
    print(f"[DAST]  SCAN COMPLETE — {len(all_findings)} total findings")
    for sev, cnt in sorted(severity_counts.items()):
        print(f"[DAST]    {sev:10}: {cnt}")
    print("[DAST] ═══════════════════════════════════════════════════════\n")

    # ── Output ─────────────────────────────────────────────────────────────────
    report = {
        "target":        target,
        "fingerprint":   fp,
        "pages":         len(sitemap.pages),
        "surfaces":      len(sitemap.surfaces),
        "findings":      all_findings,
        "browse":        browse_results,
        "severity_summary": severity_counts,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[DAST] Report saved → {args.output}")
    else:
        print(json.dumps(report, indent=2))

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

    return 0 if not any(
        f.get("severity") in ("High", "Critical") for f in all_findings
    ) else 1


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
    parser.add_argument("--no-crawl",  action="store_true", dest="no_crawl",
                        help="Skip crawling (use with --openapi)")
    parser.add_argument("--no-token-analysis", action="store_true", dest="no_token_analysis",
                        help="Skip session token randomness analysis")

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

    # Session record & replay (Burp-style)
    parser.add_argument("--record-session", dest="record_session",
                        help="Record all HTTP traffic to file (JSON or .xml for Burp format)")
    parser.add_argument("--replay-session", dest="replay_session",
                        help="Replay a saved session log (Burp XML or JSON) for scanning")

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
        print(f"[DAST] Starting on http://localhost:{port}")
        print(f"[DAST] Headless mode: python3 main.py --headless --target http://TARGET")
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
