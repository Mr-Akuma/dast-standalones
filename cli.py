#!/usr/bin/env python3
"""
DAST Scanner — CLI-first interface.

Usage:
    dast scan --target https://staging.example.com
    dast scan --config dast.yml
    dast scan --target https://example.com --fail-on critical --output-sarif report.sarif
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Allow running from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ═══════════════════════════════════════════════════════════════════════════════
# SEVERITY → EXIT CODE MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _evaluate_exit_code(output_path: str | None, report: dict | None, fail_on: str) -> int:
    """
    Read findings from output JSON or in-memory report and return exit code.

    Exit codes:
        0 = clean (nothing at or above threshold)
        1 = critical findings present
        2 = high findings present (but no critical)
    """
    findings = []

    # Prefer in-memory report, fall back to reading the file
    if report and "findings" in report:
        findings = report["findings"]
    elif output_path and os.path.isfile(output_path):
        try:
            with open(output_path, "r") as f:
                data = json.load(f)
            findings = data.get("findings", [])
        except (json.JSONDecodeError, OSError):
            pass

    if not findings:
        return 0

    threshold = _SEVERITY_RANK.get(fail_on, 3)
    has_critical = False
    has_high = False
    has_above_threshold = False

    for f in findings:
        sev = f.get("severity", "info").lower()
        rank = _SEVERITY_RANK.get(sev, 0)
        if rank >= threshold:
            has_above_threshold = True
        if sev == "critical":
            has_critical = True
        if sev == "high":
            has_high = True

    if not has_above_threshold:
        return 0
    if has_critical:
        return 1
    if has_high:
        return 2
    # Medium or low triggered threshold — still a failure, use exit 1
    return 1


# ═══════════════════════════════════════════════════════════════════════════════
# ARGPARSE SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dast",
        description="DAST Scanner — CLI-first security scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command")

    # ── scan subcommand ────────────────────────────────────────────────────
    scan = sub.add_parser("scan", help="Run a DAST scan against a target")

    # Target & config
    scan.add_argument("--target", help="Target URL to scan")
    scan.add_argument("--config", dest="config", help="YAML config file")

    # Output
    scan.add_argument("--output", help="JSON output path")
    scan.add_argument("--output-sarif", dest="output_sarif", help="SARIF output path")

    # Scan tuning
    scan.add_argument("--depth", type=int, default=3, help="Crawl depth (default: 3)")
    scan.add_argument("--max-pages", type=int, default=100, dest="max_pages",
                       help="Max pages to crawl (default: 100)")
    scan.add_argument("--openapi", help="OpenAPI spec file or URL")
    scan.add_argument("--no-fuzz", action="store_true", dest="no_fuzz",
                       help="Skip active fuzzing")
    scan.add_argument("--no-crawl", action="store_true", dest="no_crawl",
                       help="Skip crawling")

    # Thresholds
    scan.add_argument("--fail-on", dest="fail_on", default="high",
                       choices=["critical", "high", "medium", "low"],
                       help="Severity threshold for non-zero exit (default: high)")

    # Auth
    scan.add_argument("--auth-type", dest="auth_type",
                       choices=["bearer", "basic", "cookie", "form"],
                       help="Authentication type")
    scan.add_argument("--auth-token", dest="auth_token", help="Bearer token")
    scan.add_argument("--auth-user", dest="auth_user", help="Username for basic/form auth")
    scan.add_argument("--auth-pass", dest="auth_pass", help="Password for basic/form auth")
    scan.add_argument("--login-url", dest="login_url", help="Login URL for form auth")

    # Scope
    scan.add_argument("--scope", dest="scope", action="append", default=[],
                       help="Restrict scan scope (repeatable)")

    # HTML report
    scan.add_argument("--output-html", dest="output_html",
                       help="HTML report output path")

    # Jira integration
    scan.add_argument("--jira-webhook", dest="jira_webhook",
                       help="Jira webhook URL for ticket creation")
    scan.add_argument("--jira-url", dest="jira_url",
                       help="Jira Cloud base URL (e.g. https://company.atlassian.net)")
    scan.add_argument("--jira-user", dest="jira_user",
                       help="Jira username/email for API auth")
    scan.add_argument("--jira-token", dest="jira_token",
                       help="Jira API token (or set JIRA_API_TOKEN env var)")
    scan.add_argument("--jira-project", dest="jira_project", default="SEC",
                       help="Jira project key (default: SEC)")

    # Verbosity
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    return parser


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG → FLAT ARGS NAMESPACE BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def _build_headless_namespace(cli_args: argparse.Namespace) -> argparse.Namespace:
    """
    Build the flat argparse.Namespace that main.py's run_headless() expects.

    Merges: YAML config (if any) < CLI args (CLI wins).
    """
    # Start with defaults that run_headless expects
    ns = argparse.Namespace(
        headless=True,
        target=None,
        output=None,
        output_sarif=None,
        openapi=None,
        max_pages=100,
        depth=3,
        timeout=10,
        no_fuzz=False,
        no_crawl=False,
        no_token_analysis=False,
        no_graphql=False,
        no_websocket=False,
        ajax_spider=False,
        force_browse=False,
        wordlist=None,
        wordlist_categories=None,
        login_url=None,
        login_user=None,
        login_pass=None,
        user_field=None,
        pass_field=None,
        submit_field=None,
        token_url=None,
        token_field="username",
        token_pass_field="password",
        token_path=None,
        auth_script=None,
        users_file=None,
        users=None,
        record_session=None,
        replay_session=None,
        traffic_log=None,
        policy=None,
        suppress=None,
        generate_suppress=None,
        fail_on="high",
        scan_config=None,
        pre_scan_hook=None,
        post_scan_hook=None,
        on_finding_hook=None,
    )

    # ── Layer 1: YAML config (if provided) ─────────────────────────────────
    if cli_args.config:
        from modules.automation import load_nested_config
        nested = load_nested_config(cli_args.config)
        for key, value in nested.items():
            setattr(ns, key, value)

    # ── Layer 2: CLI args override everything ──────────────────────────────
    if cli_args.target:
        ns.target = cli_args.target
    if cli_args.output:
        ns.output = cli_args.output
    if cli_args.output_sarif:
        ns.output_sarif = cli_args.output_sarif
    if cli_args.openapi:
        ns.openapi = cli_args.openapi
    if cli_args.depth != 3:  # non-default
        ns.depth = cli_args.depth
    if cli_args.max_pages != 100:  # non-default
        ns.max_pages = cli_args.max_pages
    if cli_args.no_fuzz:
        ns.no_fuzz = True
    if cli_args.no_crawl:
        ns.no_crawl = True
    if cli_args.fail_on != "high":  # non-default
        ns.fail_on = cli_args.fail_on
    if cli_args.verbose:
        ns.verbose = True

    # Auth mapping: CLI's simplified auth → run_headless flat args
    if cli_args.auth_type == "bearer" and cli_args.auth_token:
        # Token-based: set token_url to target (handled by session header)
        # For bearer, we inject directly — run_headless checks token_url
        ns.token_url = None  # no token endpoint needed
        ns.login_url = None
        # We'll handle bearer injection separately
        ns._bearer_token = cli_args.auth_token
    elif cli_args.auth_type == "form":
        ns.login_url = cli_args.login_url
        ns.login_user = cli_args.auth_user
        ns.login_pass = cli_args.auth_pass
    elif cli_args.auth_type == "basic":
        ns.login_user = cli_args.auth_user
        ns.login_pass = cli_args.auth_pass

    # Scope
    if cli_args.scope:
        ns.scope = cli_args.scope

    # Validate: target is required
    if not ns.target:
        print("[DAST CLI] ERROR: --target is required (or set target: in config YAML)",
              file=sys.stderr)
        sys.exit(3)

    return ns


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = build_parser()
    cli_args = parser.parse_args()

    if not cli_args.command:
        parser.print_help()
        return 0

    if cli_args.command == "scan":
        return _cmd_scan(cli_args)

    parser.print_help()
    return 0


def _cmd_scan(cli_args: argparse.Namespace) -> int:
    """Execute the scan subcommand."""
    try:
        ns = _build_headless_namespace(cli_args)
    except Exception as e:
        print(f"[DAST CLI] Config error: {e}", file=sys.stderr)
        return 3

    # Import and run
    try:
        from main import run_headless

        # If bearer token was set via --auth-token, we need to inject it
        bearer = getattr(ns, "_bearer_token", None)
        if bearer:
            # Monkey-patch: run_headless will create a session — we set an env var
            # that downstream code can pick up, or we handle post-init.
            # Simplest: use the existing token mechanism by setting headers
            os.environ["DAST_BEARER_TOKEN"] = bearer
            delattr(ns, "_bearer_token")

        rc = run_headless(ns)

        # Evaluate exit code based on findings severity
        exit_code = _evaluate_exit_code(ns.output, None, ns.fail_on)

        # Load findings for post-scan integrations
        findings = []
        if ns.output and os.path.isfile(ns.output):
            try:
                with open(ns.output, "r") as f:
                    data = json.load(f)
                findings = data.get("findings", [])
            except (json.JSONDecodeError, OSError):
                pass

        # HTML report generation
        if getattr(cli_args, "output_html", None) and findings:
            try:
                from modules.reporting import HtmlReport
                HtmlReport().save(findings, ns.target, cli_args.output_html)
                print(f"[DAST CLI] HTML report written to {cli_args.output_html}")
            except Exception as e:
                print(f"[DAST CLI] HTML report error: {e}", file=sys.stderr)

        # Jira ticket creation
        jira_webhook = getattr(cli_args, "jira_webhook", None)
        jira_url = getattr(cli_args, "jira_url", None)
        if (jira_webhook or jira_url) and findings:
            try:
                from modules.reporting import JiraWebhook

                jira_token = (
                    getattr(cli_args, "jira_token", None)
                    or os.environ.get("JIRA_API_TOKEN")
                )
                jira_user = getattr(cli_args, "jira_user", None)
                jira_project = getattr(cli_args, "jira_project", "SEC")

                jira = JiraWebhook(
                    webhook_url=jira_webhook,
                    jira_url=jira_url,
                    jira_user=jira_user,
                    jira_token=jira_token,
                    project_key=jira_project,
                )
                results = jira.create_tickets(findings, ns.target)
                ok = sum(1 for r in results if "error" not in r)
                err = len(results) - ok
                print(f"[DAST CLI] Jira: {ok} ticket(s) created, {err} failed")
            except Exception as e:
                print(f"[DAST CLI] Jira integration error: {e}", file=sys.stderr)

        # If run_headless already returned non-zero, respect it
        if rc != 0 and exit_code == 0:
            return rc

        return exit_code

    except KeyboardInterrupt:
        print("\n[DAST CLI] Scan interrupted by user", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"[DAST CLI] Scan error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
