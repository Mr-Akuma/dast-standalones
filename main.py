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
    from modules.passive      import passive_scanner
    from modules.forcedbrowse import ForcedBrowser

    target = args.target.strip()
    print(f"\n[DAST] ═══════════════════════════════════════════════════════")
    print(f"[DAST]  Target  : {target}")
    print(f"[DAST]  Mode    : Headless / Standalone (no API key needed)")
    print(f"[DAST] ═══════════════════════════════════════════════════════\n")

    scope    = ScopeManager(target)
    session  = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 (DAST-Headless/2.0)"

    findings: list[dict] = []
    stop     = threading.Event()

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

    # ── Passive scan ──────────────────────────────────────────────────────────
    print("[DAST] Phase 2: Passive scanning (headers, cookies, info leaks)...")
    p_count = 0
    for page_url in list(sitemap.pages.keys())[:50]:
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
        print("[DAST] Phase 4: Forced browse (hidden path discovery)...")
        fb_results = []
        fb = ForcedBrowser(
            base_url=target, session=session, stop_event=stop,
            callback=lambda r: print(f"  [{r.status_code}] {r.url}  {r.note}"),
        )
        browse_results = [r.to_dict() for r in fb.run()]
        print(f"[DAST] → {len(browse_results)} interesting paths\n")

    # ── Active fuzz ────────────────────────────────────────────────────────────
    fuzz_findings = []
    if not args.no_fuzz and sitemap.surfaces:
        print(f"[DAST] Phase 5: Active fuzzing ({len(sitemap.surfaces)} surfaces)...")
        fuzzer = Fuzzer(scope=scope, session=session, timeout=args.timeout,
                        rate_limit=0.05, stop_event=stop)
        results = fuzzer.fuzz_all(sitemap.surfaces)
        for r in results:
            fuzz_findings.append(r.__dict__)
            sev = r.severity.upper()
            print(f"  [{sev}] {r.vuln_type} — {r.url} [{r.param}]")
        print(f"[DAST] → {len(fuzz_findings)} active findings\n")

    # ── Summary ────────────────────────────────────────────────────────────────
    all_findings = findings + fuzz_findings
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
    parser.add_argument("--no-fuzz",   action="store_true", dest="no_fuzz",
                        help="Skip active fuzzing (passive + crawl only)")
    parser.add_argument("--no-crawl",  action="store_true", dest="no_crawl",
                        help="Skip crawling (use with --openapi)")

    args = parser.parse_args()

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
