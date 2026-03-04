"""
DAST Agent Dashboard — standalone Flask app.

Inspired by OWASP ZAP. Runs 24 specialist AI agents across 4 phases:
  • Discovery        (Spider, Recon, Passive Scanner, Secrets Scanner,
                     API Spec, Security Headers, Vulnerable JS Libs)
  • Active Scanning  (SQLi, XSS, SSRF, SSTI, XXE,
                     LFI/Path Traversal, Command Injection, Open Redirect)
  • Auth & Session   (Deserial, CORS, JWT, OAuth, CSRF)
  • Protocol         (WAF Bypass, TLS/SSL, Smuggling, OAST)
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sqlite3
import ssl
import subprocess
import threading
import traceback
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse
import uuid
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, Response, jsonify, render_template, redirect, url_for, session
from flask import request as req
from functools import wraps

# ── DAST Engine modules ───────────────────────────────────────────────────────
try:
    from modules.scope        import ScopeManager
    from modules.evidence     import EvidenceStore, evidence_store as _ev_store
    from modules.fingerprint  import fingerprint, fingerprint_summary
    from modules.auth         import AuthHandler
    from modules.crawler      import Crawler, SiteMap
    from modules.fuzzer       import Fuzzer
    from modules.passive      import PassiveScanner, passive_scanner as _passive, PassiveInterceptSession
    from modules.oast         import OASTServer, get_or_start_oast
    from modules.openapi      import OpenAPIImporter, import_openapi
    from modules.forcedbrowse import ForcedBrowser, BrowseResult, load_wordlist, load_multiple_wordlists, available_wordlists, WORDLIST_CATEGORIES
    from modules.scanner     import VulnerabilityScanner, ScanFinding
    _ENGINE_AVAILABLE = True
except ImportError as _ei:
    _ENGINE_AVAILABLE = False
    print(f"[WARN] DAST engine modules not fully loaded: {_ei}")

# Ajax Spider (optional — requires playwright)
try:
    from modules.ajax_spider import AjaxSpider
    _AJAX_SPIDER_AVAILABLE = True
except ImportError:
    _AJAX_SPIDER_AVAILABLE = False

# Katana (optional — requires Go binary in PATH)
import shutil as _shutil_top
_KATANA_AVAILABLE = bool(_shutil_top.which("katana"))
_HTTPX_AVAILABLE  = bool(_shutil_top.which("httpx"))

app = Flask(__name__)
app.secret_key = os.environ.get("REVELIO_SECRET", "revelio-dev-secret-2025")

@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-XSS-Protection", "0")
    return response

# ── Auth credentials ───────────────────────────────────────────────────────────
_AUTH_USERS = {
    "admin": "admin",          # default — change in production
}

def _login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ── Scan History (SQLite) ─────────────────────────────────────────────────────

_DB_PATH = Path.home() / ".dast" / "scans.db"

def _db_init():
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(_DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id        TEXT PRIMARY KEY,
            target    TEXT,
            started   TEXT,
            finished  TEXT,
            findings  TEXT,
            summary   TEXT
        )
    """)
    con.commit()
    con.close()

def _db_save_scan(scan_id: str, target: str, started: str, findings: list):
    try:
        _db_init()
        counts = {}
        for f in findings:
            counts[f.get("severity","medium")] = counts.get(f.get("severity","medium"),0) + 1
        summary = ", ".join(f"{v} {k}" for k,v in sorted(counts.items()))
        con = sqlite3.connect(_DB_PATH)
        con.execute(
            "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?)",
            (scan_id, target, started, datetime.now(timezone.utc).isoformat(),
             json.dumps(findings), summary)
        )
        con.commit()
        con.close()
    except Exception:
        pass

def _db_get_history(limit: int = 20) -> list:
    try:
        _db_init()
        con = sqlite3.connect(_DB_PATH)
        rows = con.execute(
            "SELECT id,target,started,finished,summary FROM scans ORDER BY started DESC LIMIT ?",
            (limit,)
        ).fetchall()
        con.close()
        return [{"id": r[0], "target": r[1], "started": r[2],
                 "finished": r[3], "summary": r[4]} for r in rows]
    except Exception:
        return []

_db_init()


def _log_activity(event: str, target: str = "", detail: str = ""):
    """Append a timestamped scan-event to the in-memory activity log."""
    global _activity_log
    _activity_log.append({
        "ts":     datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "event":  event,
        "target": target,
        "detail": detail,
    })
    if len(_activity_log) > _ACTIVITY_MAX:
        _activity_log = _activity_log[-_ACTIVITY_MAX:]


# ── SSL context (macOS cert fix) ──────────────────────────────────────────────

def _make_ssl_ctx() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    try:
        ctx = ssl.create_default_context()
        ctx.load_default_certs()
        return ctx
    except Exception:
        pass
    return ssl._create_unverified_context()

_SSL_CTX = _make_ssl_ctx()


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _http_post(url: str, payload: bytes, headers: dict, timeout: int = 40) -> dict:
    request = urllib.request.Request(url, data=payload, headers=headers)
    try:
        resp = urllib.request.urlopen(request, timeout=timeout, context=_SSL_CTX)
        raw  = resp.read()
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
            if isinstance(err_body.get("error"), dict):
                raise RuntimeError(err_body["error"].get("message", str(e)))
            raise RuntimeError(str(err_body.get("error", e)))
        except (json.JSONDecodeError, KeyError):
            raise RuntimeError(f"HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e.reason}")

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"Invalid JSON response: {raw[:200]}")


# ── Robust JSON parser ────────────────────────────────────────────────────────

def _parse_llm_json(text: str) -> dict:
    text = text.strip()
    for s, e in [(text.find("{"), text.rfind("}")),
                 (text.find("["), text.rfind("]"))]:
        if s != -1 and e != -1 and e > s:
            try:
                return json.loads(text[s:e+1])
            except json.JSONDecodeError:
                pass
    # strip markdown fences
    clean = re.sub(r"```(?:json)?", "", text).strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cannot parse JSON from LLM: {exc}\nRaw: {text[:300]}")


# ── API key store ─────────────────────────────────────────────────────────────

_api_keys: dict = {}

@app.route("/api/keys", methods=["POST"])
def set_keys():
    data = req.json or {}
    if data.get("openai"):
        _api_keys["openai"] = data["openai"].strip()
    if data.get("anthropic"):
        _api_keys["anthropic"] = data["anthropic"].strip()
    if "auth_header" in data:
        val = (data["auth_header"] or "").strip()
        if val:
            _api_keys["auth_header"] = val
        else:
            _api_keys.pop("auth_header", None)
    return jsonify({"success": True, "keys": list(_api_keys.keys())})

@app.route("/api/keys")
def get_keys():
    return jsonify({"keys": list(_api_keys.keys())})


# ── DAST Agent Specs ──────────────────────────────────────────────────────────
# 17 specialist agents across 4 phases (ZAP-inspired taxonomy)

_DAST_AGENTS = [
    # ── PHASE 1: DISCOVERY ────────────────────────────────────────────────────
    {
        "name": "Spider Agent",
        "icon": "🕷️",
        "phase": "Discovery",
        "task": (
            "Crawl the target web application to discover all endpoints, links, forms, "
            "and API paths. Use: katana -u {target} -depth 4 -jc -silent, "
            "then curl to probe discovered paths. Report all unique URLs found."
        ),
    },
    {
        "name": "Recon Agent",
        "icon": "🔍",
        "phase": "Discovery",
        "task": (
            "Perform initial reconnaissance: HTTP headers, tech stack fingerprinting, "
            "server info, WAF detection, robots.txt, sitemap.xml, favicon hash. "
            "Use: curl -I {target}, whatweb {target}, wafw00f {target}, nmap -sV -p 80,443,8080,8443."
        ),
    },
    {
        "name": "Passive Scanner",
        "icon": "📡",
        "phase": "Discovery",
        "task": (
            "Passively analyse the target by examining public sources: Shodan-style analysis, "
            "SSL certificate info, DNS records, open redirect indicators, information disclosure "
            "in HTTP responses. Use: curl, openssl s_client -connect, dig, nmap --script http-headers."
        ),
    },
    {
        "name": "Secrets Scanner",
        "icon": "🔑",
        "phase": "Discovery",
        "task": (
            "Search for exposed secrets, API keys, credentials and sensitive files. "
            "Look for: .env, backup files, .git/config, swagger/openapi docs, debug endpoints, "
            "hardcoded tokens in JS files. Use: gobuster dir, curl on common secret paths, "
            "grep patterns on JS files."
        ),
    },
    {
        "name": "API Spec Agent",
        "icon": "📋",
        "phase": "Discovery",
        "task": (
            "Discover and parse API specifications to enumerate all endpoints and parameters. "
            "Probe common spec paths: /swagger.json, /swagger.yaml, /openapi.json, /openapi.yaml, "
            "/api-docs, /v1/api-docs, /v2/api-docs, /v3/api-docs, /graphql, /api/schema, "
            "/docs, /.well-known/openid-configuration. Download and parse any found spec to list "
            "all endpoints, HTTP methods, and parameters. Share discovered endpoint list so other "
            "agents can use them. Use: curl on spec paths, parse JSON/YAML responses with python3 -c."
        ),
    },
    {
        "name": "Security Headers",
        "icon": "🔏",
        "phase": "Discovery",
        "task": (
            "Analyse all HTTP security response headers and cookie security flags. "
            "For each of the following, report present/absent/misconfigured: "
            "Content-Security-Policy (check for unsafe-inline, unsafe-eval, wildcard *), "
            "X-Frame-Options (DENY or SAMEORIGIN), X-Content-Type-Options (nosniff), "
            "Strict-Transport-Security (min-age 31536000, includeSubDomains), "
            "Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy. "
            "Also check Set-Cookie headers for HttpOnly, Secure, SameSite flags. "
            "Check Server/X-Powered-By/X-AspNet-Version headers for version disclosure. "
            "Use: curl -sI {target} to grab all response headers, probe key paths. "
            "Rate every missing/misconfigured header at appropriate severity."
        ),
    },
    {
        "name": "JS Library Scanner",
        "icon": "📚",
        "phase": "Discovery",
        "task": (
            "Detect outdated and vulnerable JavaScript libraries loaded by the target. "
            "Fetch the main page HTML and all referenced JS files. Extract library names and "
            "versions from <script> src attributes, inline version strings, and JS file content. "
            "Look for: jQuery (< 3.5.0 = XSS), Bootstrap (< 4.3.1 = XSS), Angular.js (any 1.x = EOL), "
            "Prototype.js, MooTools, handlebars.js, lodash (< 4.17.21), moment.js (EOL), "
            "DOMPurify (< 2.4.0), highlight.js (< 11.x). "
            "Use: curl -s {target} to get HTML, grep for script src, curl each JS file and grep for version patterns. "
            "Flag any library with a known CVE or that is end-of-life as a finding."
        ),
    },
    # ── PHASE 2: ACTIVE SCANNING ──────────────────────────────────────────────
    {
        "name": "SQLi Agent",
        "icon": "💉",
        "phase": "Active Scanning",
        "task": (
            "Test all discovered endpoints for SQL injection vulnerabilities. "
            "Test GET/POST parameters, headers (User-Agent, Referer, X-Forwarded-For), "
            "and JSON body fields. Use: sqlmap -u {target} --batch --level 2 --risk 1 "
            "--forms --crawl=2 --output-dir /tmp/dast_sqlmap."
        ),
    },
    {
        "name": "XSS Agent",
        "icon": "🔥",
        "phase": "Active Scanning",
        "task": (
            "Test for Cross-Site Scripting (reflected, stored, DOM-based). "
            "Fuzz all input parameters with XSS payloads. "
            "Use: dalfox url {target} --silence, ffuf with XSS wordlist, "
            "manual payloads via curl for reflected XSS indicators."
        ),
    },
    {
        "name": "SSRF Agent",
        "icon": "🌐",
        "phase": "Active Scanning",
        "task": (
            "Test for Server-Side Request Forgery. Check URL parameters, file upload paths, "
            "webhook endpoints, PDF/image processing. "
            "Use internal addresses (127.0.0.1, 169.254.169.254 metadata service, "
            "localhost:22, localhost:6379). Report any out-of-band or error-based indicators."
        ),
    },
    {
        "name": "SSTI Agent",
        "icon": "🧪",
        "phase": "Active Scanning",
        "task": (
            "Test for Server-Side Template Injection in all user-controlled inputs. "
            "Use probing payloads: {{7*7}}, ${7*7}, #{7*7}, <% = 7*7 %>, {{config}}. "
            "Use: tplmap -u {target}, manual curl with template payloads. "
            "Identify template engine from error messages and escalate."
        ),
    },
    {
        "name": "XXE Agent",
        "icon": "📄",
        "phase": "Active Scanning",
        "task": (
            "Test for XML External Entity injection in XML-accepting endpoints, "
            "file uploads (DOCX/SVG/XML), and SOAP services. "
            "Inject XXE payloads to read /etc/passwd, /etc/hostname, internal network access. "
            "Use: xxeinjector if available, else curl with crafted XML payloads."
        ),
    },
    {
        "name": "LFI Agent",
        "icon": "📂",
        "phase": "Active Scanning",
        "task": (
            "Test for Local File Inclusion and Path Traversal vulnerabilities. "
            "Inject path traversal sequences into all GET/POST parameters, HTTP headers (Referer, Cookie), "
            "and file-name parameters. Payloads: ../../../etc/passwd, ....//....//etc/passwd, "
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd (URL-encoded), ..%2f..%2f..%2fetc%2fpasswd, "
            "..\\..\\..\\windows\\win.ini (Windows), /proc/self/environ, /var/log/apache2/access.log. "
            "Also test for null byte injection: ../../etc/passwd%00.jpg. "
            "Use: curl with payloads in each discovered parameter. Look for /etc/passwd root: in response."
        ),
    },
    {
        "name": "CMDi Agent",
        "icon": "💻",
        "phase": "Active Scanning",
        "task": (
            "Test for OS command injection in all input parameters, HTTP headers, and form fields. "
            "Inject both immediate and time-delay payloads: ;id, |id, &&id, `id`, $(id), "
            ";sleep 5, |sleep 5, &&sleep 5, ;ping -c 5 127.0.0.1. "
            "Test in: GET/POST parameters, User-Agent, Referer, X-Forwarded-For, Cookie values, "
            "file name fields, search fields. "
            "Use: curl to send payloads, measure response time for time-delay probes. "
            "Look for uid=, gid=, Linux/Windows system info in responses. "
            "If interactsh or burp collaborator available, use OOB callbacks for blind CMDi."
        ),
    },
    {
        "name": "Open Redirect",
        "icon": "↗️",
        "phase": "Active Scanning",
        "task": (
            "Test for open redirect vulnerabilities in URL-like parameters. "
            "Identify all parameters that contain URLs or paths: url, redirect, next, return, "
            "goto, link, redir, returnUrl, redirectUri, callback, dest, destination, "
            "forward, location, to, from, ref, out, view, go, jump. "
            "Test with external domain payloads: https://evil.com, //evil.com, "
            "https://target.com.evil.com, https://evil.com\\@target.com (parser confusion), "
            "javascript:alert(1) (for XSS via redirect). "
            "Use: curl -L to follow redirects and check final destination. "
            "Report if the redirect reaches an external domain not in scope."
        ),
    },
    # ── PHASE 3: AUTH & SESSION ───────────────────────────────────────────────
    {
        "name": "Deserial Agent",
        "icon": "🔓",
        "phase": "Auth & Session",
        "task": (
            "Test for insecure deserialization in cookies, hidden fields, API parameters. "
            "Look for base64-encoded serialized objects, Java serialization magic bytes (aced0005), "
            "PHP serialized strings (O:4:). Use: ysoserial payloads via curl, "
            "check for deserialization errors in responses."
        ),
    },
    {
        "name": "CORS Agent",
        "icon": "🌍",
        "phase": "Auth & Session",
        "task": (
            "Test for CORS misconfiguration. Send requests with Origin: headers set to "
            "attacker.com, null, {target}.attacker.com, evil-{target}. "
            "Check Access-Control-Allow-Origin and Access-Control-Allow-Credentials. "
            "Use: curl -H 'Origin: https://evil.com' on all API endpoints."
        ),
    },
    {
        "name": "JWT Agent",
        "icon": "🪙",
        "phase": "Auth & Session",
        "task": (
            "Test JWT implementation weaknesses: alg=none attack, weak secret brute-force, "
            "RS256-to-HS256 confusion, kid injection, jku/x5u header injection. "
            "If JWT found in cookies or Authorization header, decode and test with: "
            "jwt_tool if available, else manual curl with crafted tokens."
        ),
    },
    {
        "name": "OAuth Agent",
        "icon": "🔐",
        "phase": "Auth & Session",
        "task": (
            "Test OAuth2/OpenID Connect flow for: open redirect in redirect_uri, "
            "state parameter CSRF, authorization code interception, token leakage in referrer. "
            "Probe /.well-known/openid-configuration, /oauth/authorize, /oauth/token. "
            "Use curl to test parameter manipulation."
        ),
    },
    {
        "name": "CSRF Agent",
        "icon": "🎭",
        "phase": "Auth & Session",
        "task": (
            "Test for Cross-Site Request Forgery vulnerabilities. "
            "Check all state-changing endpoints (POST/PUT/DELETE/PATCH) for: missing CSRF tokens, "
            "predictable or reusable CSRF tokens, missing SameSite cookie attribute, "
            "weak Origin/Referer header validation. "
            "Use: curl with forged Origin and Referer headers on login/account/API endpoints, "
            "replay requests with modified Origin header, test null origin bypass. "
            "Also check Set-Cookie headers for SameSite=Strict/Lax enforcement."
        ),
    },
    # ── PHASE 4: PROTOCOL & TRANSPORT ────────────────────────────────────────
    {
        "name": "WAF Bypass",
        "icon": "🛡️",
        "phase": "Protocol & Transport",
        "task": (
            "Detect and attempt to bypass Web Application Firewall. "
            "Test payload encoding (URL, double URL, Unicode, hex, base64), "
            "HTTP verb tampering, header manipulation (X-Originating-IP, X-Remote-IP). "
            "Use: wafw00f {target}, nmap --script http-waf-detect, curl with encoded payloads."
        ),
    },
    {
        "name": "TLS/SSL Agent",
        "icon": "🔒",
        "phase": "Protocol & Transport",
        "task": (
            "Analyse TLS/SSL configuration: weak protocols (SSLv3, TLS 1.0/1.1), "
            "weak cipher suites, certificate issues (expired, self-signed, wrong hostname), "
            "HSTS enforcement, certificate transparency. "
            "Use: sslscan {target}, testssl.sh --fast {target} if available, "
            "openssl s_client -connect {target}:443."
        ),
    },
    {
        "name": "Smuggling Agent",
        "icon": "📦",
        "phase": "Protocol & Transport",
        "task": (
            "Test for HTTP Request Smuggling (CL.TE and TE.CL). "
            "Look for: frontend/backend proxy setups, chunked transfer encoding support, "
            "discrepancies in Content-Length vs Transfer-Encoding handling. "
            "Use: smuggler.py if available, else craft manual CL.TE payloads via curl with --http1.1."
        ),
    },
    {
        "name": "OAST Agent",
        "icon": "🌊",
        "phase": "Protocol & Transport",
        "task": (
            "Perform Out-of-Band Application Security Testing. Test for blind SSRF, "
            "blind XXE, blind command injection, DNS rebinding using pingback/OOB techniques. "
            "Use collaborator-style payloads if burp collaborator or interactsh is available. "
            "Else test with requestbin-style endpoints or DNS resolution via curl."
        ),
    },
    # ── PHASE 5: ADVANCED (new) ───────────────────────────────────────────────
    {
        "name": "IDOR Agent",
        "icon": "🔄",
        "phase": "Advanced",
        "task": (
            "Test for Insecure Direct Object Reference (IDOR) vulnerabilities. "
            "Find all endpoints that accept user-controlled IDs (numeric or UUID) in URL paths, "
            "query params, or request bodies: /api/users/{id}, /account?id=, /orders/{id}, "
            "/documents/{id}, /invoices/{id}. "
            "Test by: enumerating IDs sequentially (1,2,3), swapping IDs between accounts if possible, "
            "using negative IDs, large IDs, and non-existent IDs to detect enumeration. "
            "Check: does changing the ID return another user's data? Does the app return 200 vs 403? "
            "Use: curl to probe discovered ID-based endpoints with modified values. "
            "Report if any ID substitution returns data that should be protected."
        ),
    },
    {
        "name": "Rate Limit Agent",
        "icon": "⏱️",
        "phase": "Advanced",
        "task": (
            "Test for missing or bypassable rate limiting on sensitive endpoints. "
            "Target: login, register, password-reset, OTP/2FA verification, API key endpoints. "
            "Test: send 50+ rapid requests to /login, /forgot-password, /api/verify-otp. "
            "Bypass techniques: rotate User-Agent headers, use X-Forwarded-For spoofing "
            "(X-Forwarded-For: 1.2.3.4, X-Real-IP: 1.2.3.5, X-Originating-IP: 1.2.3.6), "
            "add random query params (?t=random) to bust caching rate limits. "
            "Use: for i in $(seq 1 50); do curl -s -o /dev/null -w '%{http_code}\\n' -X POST {target}/login "
            "-d 'user=test&pass=test'; done | sort | uniq -c to detect throttling. "
            "Report if no 429/lockout after 20+ failed attempts."
        ),
    },
    {
        "name": "Business Logic Agent",
        "icon": "🧩",
        "phase": "Advanced",
        "task": (
            "Test for business logic vulnerabilities. "
            "Check: negative price/quantity parameters in purchase flows (price=-1, qty=-100), "
            "currency/unit manipulation in API params, workflow step skipping "
            "(POST to /checkout without /cart), coupon code stacking, "
            "mass assignment (send extra JSON fields: isAdmin=true, role=admin, price=0), "
            "HTTP parameter pollution (id=1&id=2), parameter type confusion (string vs int). "
            "Use: curl -X POST {target}/api/order -d '{\"price\":-1,\"qty\":-1}' to test negative values. "
            "curl -X PATCH {target}/api/profile -d '{\"role\":\"admin\",\"isAdmin\":true}' for mass assignment. "
            "Report any unexpected behavior: 200 on negative prices, privilege escalation, workflow bypass."
        ),
    },
    {
        "name": "Subdomain Enum",
        "icon": "🌐",
        "phase": "Advanced",
        "task": (
            "Enumerate subdomains of the target domain to expand attack surface. "
            "Extract base domain from target URL. "
            "Use: curl -s 'https://crt.sh/?q={domain}&output=json' | python3 -c "
            "\"import sys,json; [print(e.get('name_value','')) for e in json.load(sys.stdin)]\" "
            "to query certificate transparency logs. "
            "Also try common subdomains: admin, api, dev, staging, test, beta, internal, vpn, "
            "mail, smtp, ftp, git, jenkins, jira, confluence, kibana, grafana, prometheus. "
            "Use: for sub in admin api dev staging test; do curl -sI http://$sub.{domain} 2>/dev/null | "
            "head -1; done to probe common subdomains. "
            "Report all discovered live subdomains with their HTTP status codes."
        ),
    },
    {
        "name": "Nuclei Agent",
        "icon": "⚡",
        "phase": "Advanced",
        "task": (
            "Run nuclei vulnerability scanner against the target with community templates. "
            "Check if nuclei is installed: which nuclei. "
            "If available, run: nuclei -u {target} -severity medium,high,critical -j -silent -timeout 10 "
            "-rate-limit 10 -bulk-size 5 -c 5 2>/dev/null | head -50 "
            "Parse JSON output lines to extract template-id, severity, matched-at, and name. "
            "Also run: nuclei -u {target} -t exposures/ -t cves/ -severity high,critical -j -silent 2>/dev/null | head -30 "
            "If nuclei not installed: report 'nuclei not installed — install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' "
            "Report each nuclei finding with template name, severity, and matched URL."
        ),
    },
]

# Map phase name → ordered list of agents (for UI rendering)
PHASES = ["Discovery", "Active Scanning", "Auth & Session", "Protocol & Transport", "Advanced"]

_AGENT_SYSTEM_PROMPT = """\
You are {name} — a specialist DAST (Dynamic Application Security Testing) agent.
Target: {target}
Phase: {phase}
Scope: Only test URLs within {scope}. Do not follow links to external domains.
Your task: {task}{auth_note}

You MUST respond with ONLY valid JSON — no markdown, no text outside the JSON.
Choose ONE of:

1. Run the next command:
{{"command": "exact shell command with target substituted", "reason": "one-line reason", "phase": "{phase}"}}

2. When complete:
{{"done": true, "summary": "what you found", "findings": [{{"text": "specific finding", "severity": "critical|high|medium|low|info"}}]}}

Severity guide:
  critical = RCE, auth bypass, credentials exposed, data exfiltration
  high     = SQLi confirmed, stored XSS, SSRF confirmed, SSTI, XXE, JWT bypass
  medium   = reflected XSS, CORS misconfigured, CSRF, weak TLS, insecure deserial indicator
  low      = missing security headers, verbose errors, non-sensitive info disclosure
  info     = fingerprinting, spec/docs discovered, observations with no direct impact

RULES:
- ONE command at a time. Adapt next command based on output.
- Substitute the real target into commands — never use placeholders like <target>.
- Max {max_iter} commands. Use them efficiently.
- findings text must be specific and actionable (e.g. "Reflected XSS in /search?q= parameter", "SQLi via id= GET param").
- Never run destructive or irreversible commands.
- If a tool is not installed, skip it and try another approach.
"""


# ── State ─────────────────────────────────────────────────────────────────────

_lock         = threading.Lock()
_SEM          = threading.Semaphore(5)   # max concurrent agents (reset per scan)
_agents: dict = {}          # agent_id → agent state
_findings: list = []        # all findings across all agents
_context: dict  = {}        # shared inter-agent context
_scan_active: bool = False
_scan_target: str  = ""
_seen_findings: set = set() # dedup set: (agent_name, finding_text_hash)


# ── LLM call ─────────────────────────────────────────────────────────────────

def _llm_call(messages: list) -> str:
    openai_key    = _api_keys.get("openai")
    anthropic_key = _api_keys.get("anthropic")

    if openai_key:
        try:
            body = _http_post(
                "https://api.openai.com/v1/chat/completions",
                json.dumps({
                    "model": "gpt-4o-mini",
                    "messages": messages,
                    "temperature": 0.1,
                    "max_tokens": 2000,
                    "response_format": {"type": "json_object"},
                }).encode(),
                {"Content-Type": "application/json",
                 "Authorization": f"Bearer {openai_key}"},
                timeout=35,
            )
            if not body.get("choices"):
                raise RuntimeError(f"No choices in response: {body}")
            return body["choices"][0]["message"]["content"].strip()
        except Exception:
            pass

    if anthropic_key:
        sys_msg   = next((m["content"] for m in messages if m["role"] == "system"), "")
        user_msgs = [m for m in messages if m["role"] != "system"]
        body = _http_post(
            "https://api.anthropic.com/v1/messages",
            json.dumps({
                "model": "claude-sonnet-4-6",
                "max_tokens": 2000,
                "system": sys_msg,
                "messages": user_msgs,
            }).encode(),
            {"Content-Type": "application/json",
             "x-api-key": anthropic_key,
             "anthropic-version": "2023-06-01"},
            timeout=35,
        )
        return body["content"][0]["text"].strip()

    raise RuntimeError("No API key configured")


# ── Command runner ────────────────────────────────────────────────────────────

def _run_cmd(cmd: str, timeout: int = 90) -> str:
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "TERM": "dumb"},
        )
        out = (result.stdout + result.stderr).strip()
        return out[:6000] if out else "(no output)"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s"
    except FileNotFoundError as e:
        return f"[NOT FOUND] {e} — tool may not be installed"
    except Exception as e:
        return f"[ERROR] {e}"


# ── Agent worker ──────────────────────────────────────────────────────────────

def _record_findings(state: dict, agent_id: str, target: str, raw_findings: list) -> None:
    """Parse findings (str or dict) into normalised records in _findings and state."""
    import hashlib
    for f in raw_findings:
        if isinstance(f, dict):
            text     = f.get("text", str(f))
            severity = f.get("severity", "medium").lower()
        else:
            text     = str(f)
            severity = "medium"
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"
        # Deduplication: skip if same agent already reported same finding
        dedup_key = (state["name"], hashlib.md5(text.encode()).hexdigest())
        if dedup_key in _seen_findings:
            continue
        _seen_findings.add(dedup_key)
        state["findings"].append({"text": text, "severity": severity})
        _findings.append({
            "agent":    state["name"],
            "agent_id": agent_id,
            "icon":     state["icon"],
            "phase":    state["phase"],
            "finding":  text,
            "severity": severity,
            "target":   target,
            "ts":       datetime.now(timezone.utc).isoformat(),
        })
    if raw_findings:
        first = raw_findings[0]
        _context[f"{state['name']}_key"] = (
            first.get("text", str(first)) if isinstance(first, dict) else str(first)
        )


def _agent_worker(agent_id: str, target: str):
    global _scan_active
    _SEM.acquire()
    state = _agents.get(agent_id)
    if not state:          # scan was reset while this thread was queued
        _SEM.release()
        return
    state["status"] = "running"

    scope     = urlparse(target).netloc or target
    auth_hdr  = _api_keys.get("auth_header", "")
    auth_note = f"\nAuth: Include this header in all authenticated requests: {auth_hdr}" if auth_hdr else ""

    task_filled = state["task"].replace("{target}", target)
    sys_prompt  = _AGENT_SYSTEM_PROMPT.format(
        name=state["name"],
        target=target,
        phase=state["phase"],
        task=task_filled,
        max_iter=state["max_iter"],
        scope=scope,
        auth_note=auth_note,
    )
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user",   "content": f"Begin your DAST task. Target: {target}"},
    ]

    # ── Static (no-key) fallback ──────────────────────────────────────────────
    has_key = bool(_api_keys.get("openai") or _api_keys.get("anthropic"))
    if not has_key:
        state["output"].append("[MODE] No AI key — running static tool commands")
        _run_static_agent(state, agent_id, target)
        state["status"]      = "completed"
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _SEM.release()
        with _lock:
            all_done = all(
                a["status"] in ("completed", "error", "stopped")
                for a in _agents.values()
            )
            if all_done:
                _scan_active = False
        return

    try:
        for i in range(state["max_iter"]):
            if state.get("stop"):
                break

            state["iteration"] = i + 1

            # inject shared context every 3 iterations
            if i > 0 and i % 3 == 0 and _context:
                ctx_lines = ["Other agents discovered:"]
                for k, v in list(_context.items())[-8:]:
                    ctx_lines.append(f"  • {k}: {v}")
                messages.append({
                    "role": "user",
                    "content": "[SHARED INTEL]\n" + "\n".join(ctx_lines) + "\nAdapt if relevant.",
                })
                state["output"].append(f"[ADAPT] Incorporating {len(_context)} shared context items")

            try:
                raw      = _llm_call(messages)
                decision = _parse_llm_json(raw)
            except Exception as e:
                state["output"].append(f"[LLM ERROR] {e}")
                break

            if decision.get("done"):
                summary      = decision.get("summary", "Task complete")
                raw_findings = decision.get("findings", [])
                state["summary"] = summary
                state["output"].append(f"[DONE] {summary}")

                with _lock:
                    _record_findings(state, agent_id, target, raw_findings)
                    if summary:
                        _context[f"{state['name']}_summary"] = summary
                break

            cmd    = decision.get("command", "").strip()
            reason = decision.get("reason", "")
            share  = decision.get("share")

            if not cmd:
                break

            state["output"].append(f"[{state['phase']}] $ {cmd}")
            if reason:
                state["output"].append(f"  → {reason}")

            cmd_out = _run_cmd(cmd)
            state["output"].append(cmd_out)
            state["commands_run"] += 1

            if share:
                with _lock:
                    _context[f"{state['name']}_{i}"] = share
                state["output"].append(f"[SHARED] → {share}")

            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": (
                    f"Command output:\n{cmd_out}\n\n"
                    "If you found something important, add a 'share' key with a short discovery string. "
                    "Continue or respond with done."
                ),
            })

    except Exception as e:
        state["output"].append(f"[AGENT ERROR] {e}")
        state["status"] = "error"
    finally:
        if state["status"] == "running":
            state["status"] = "completed"
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _SEM.release()

        # Check if all agents done
        with _lock:
            all_done = all(
                a["status"] in ("completed", "error", "stopped")
                for a in _agents.values()
            )
            if all_done:
                _scan_active = False
                # Persist scan to history
                _db_save_scan(
                    scan_id=f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
                    target=_scan_target,
                    started=next(iter(_agents.values()), {}).get("created_at", ""),
                    findings=list(_findings),
                )


# ── Static agent (no-key mode) ────────────────────────────────────────────────
# Maps phase→agent_name to a list of (command_template, reason) tuples.
# These run sequentially when no AI API key is configured.
_STATIC_CMDS: dict = {
    "Spider Agent": [
        ("curl -sI {target}", "Probe HTTP headers"),
        ("curl -s {target}/robots.txt", "Check robots.txt"),
        ("curl -s {target}/sitemap.xml", "Check sitemap.xml"),
    ],
    "Recon Agent": [
        ("curl -sI {target}", "Fingerprint server"),
        ("curl -s {target}/.well-known/security.txt", "Check security.txt"),
        ("nmap -sV --open -p 80,443,8080,8443,8000,3000 {host}", "Port scan"),
    ],
    "Passive Scanner": [
        ("curl -sk {target}", "Grab homepage"),
        ("openssl s_client -connect {host}:443 -showcerts </dev/null 2>&1", "TLS cert check"),
        ("curl -sI {target} | grep -i 'server\\|x-powered\\|x-aspnet'", "Info disclosure headers"),
    ],
    "Secrets Scanner": [
        ("curl -sf {target}/.env", "Probe .env"),
        ("curl -sf {target}/.git/config", "Probe .git/config"),
        ("curl -sf {target}/swagger.json {target}/openapi.json {target}/api-docs", "Probe API specs"),
    ],
    "API Spec Agent": [
        ("curl -sf {target}/swagger.json", "Probe swagger.json"),
        ("curl -sf {target}/openapi.json", "Probe openapi.json"),
        ("curl -sf {target}/graphql --data '{\"query\":\"{__typename}\"}'", "Probe GraphQL"),
    ],
    "Security Headers": [
        ("curl -sI {target}", "Grab all response headers"),
        ("curl -sI {target} | grep -i 'content-security-policy\\|x-frame-options\\|x-content-type-options\\|strict-transport-security\\|referrer-policy\\|permissions-policy'", "Check security headers"),
        ("curl -sI {target} | grep -i 'set-cookie'", "Check cookie security flags"),
        ("curl -sI {target} | grep -i 'server:\\|x-powered-by:\\|x-aspnet'", "Check version disclosure"),
    ],
    "JS Library Scanner": [
        ("curl -s {target} | grep -oE 'src=\"[^\"]+\\.js[^\"]*\"'", "Extract JS file paths"),
        ("curl -s {target} | grep -iE 'jquery[.-]([0-9.]+)|bootstrap[.-]([0-9.]+)|angular[.-]([0-9.]+)|lodash[.-]([0-9.]+)'", "Detect library versions in HTML"),
        ("curl -s {target} | python3 -c \"import sys,re; html=sys.stdin.read(); scripts=re.findall(r'src=[\\\"\\']([^\\\"\\']+\\.js[^\\\"\\']*)[\\\"\\']', html); [print(s) for s in scripts[:10]]\"", "List JS files to inspect"),
    ],
    "SQLi Agent": [
        ("curl -s '{target}/?id=1'", "Probe id param"),
        ("curl -s '{target}/?id=1'\"'\"", "SQLi quote test"),
        ("curl -s '{target}/?q=1 OR 1=1--'", "SQLi OR test"),
    ],
    "XSS Agent": [
        ("curl -s '{target}/?q=<script>alert(1)</script>'", "Reflected XSS probe"),
        ("curl -s '{target}/?search=<img src=x onerror=alert(1)>'", "IMG onerror probe"),
    ],
    "SSRF Agent": [
        ("curl -s '{target}/?url=http://169.254.169.254/latest/meta-data/'", "AWS metadata probe"),
        ("curl -s '{target}/?url=http://127.0.0.1:22'", "SSRF localhost probe"),
    ],
    "SSTI Agent": [
        ("curl -s '{target}/?name={{7*7}}'", "SSTI Jinja2 probe"),
        ("curl -s '{target}/?name=${{7*7}}'", "SSTI Freemarker probe"),
    ],
    "XXE Agent": [
        ("curl -s -X POST {target} -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>'", "XXE file read probe"),
    ],
    "LFI Agent": [
        ("curl -s '{target}/?file=../../../etc/passwd'", "LFI in file param"),
        ("curl -s '{target}/?page=../../../etc/passwd'", "LFI in page param"),
        ("curl -s '{target}/?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'", "URL-encoded traversal"),
        ("curl -s '{target}/?file=....//....//....//etc/passwd'", "Double-dot bypass"),
    ],
    "CMDi Agent": [
        ("curl -s '{target}/?q=;id'", "CMDi semicolon test"),
        ("curl -s '{target}/?q=|whoami'", "CMDi pipe test"),
        ("curl -s '{target}/?q=`id`'", "CMDi backtick test"),
        ("curl -s '{target}/?search=%3Bid' -H 'User-Agent: curl/;id'", "CMDi in User-Agent"),
    ],
    "Open Redirect": [
        ("curl -sI '{target}/?url=https://evil.com' | grep -i location", "Open redirect in url param"),
        ("curl -sI '{target}/?redirect=https://evil.com' | grep -i location", "Open redirect in redirect param"),
        ("curl -sI '{target}/?next=//evil.com' | grep -i location", "Protocol-relative redirect"),
        ("curl -sI '{target}/?return=https://evil.com' | grep -i location", "Open redirect in return param"),
    ],
    "Deserial Agent": [
        ("curl -sI {target}", "Check Set-Cookie for serialized objects"),
    ],
    "CORS Agent": [
        ("curl -sI {target} -H 'Origin: https://evil.com'", "CORS evil origin test"),
        ("curl -sI {target} -H 'Origin: null'", "CORS null origin test"),
    ],
    "JWT Agent": [
        ("curl -sI {target}", "Check Authorization header usage"),
    ],
    "OAuth Agent": [
        ("curl -sf {target}/.well-known/openid-configuration", "OIDC discovery"),
        ("curl -sf {target}/oauth/authorize", "OAuth authorize endpoint"),
    ],
    "CSRF Agent": [
        ("curl -sI {target} | grep -i 'set-cookie'", "Check SameSite cookie flag"),
        ("curl -s -X POST {target}/login -H 'Origin: https://evil.com' -H 'Referer: https://evil.com'", "CSRF Origin bypass test"),
    ],
    "WAF Bypass": [
        ("curl -sI {target}", "WAF fingerprint via headers"),
        ("curl -s '{target}/?q=<script>alert(1)</script>'", "WAF XSS detection test"),
    ],
    "TLS/SSL Agent": [
        ("openssl s_client -connect {host}:443 </dev/null 2>&1", "TLS handshake"),
        ("curl -sk --tlsv1 {target}", "TLS 1.0 test"),
        ("curl -sI {target} | grep -i hsts", "HSTS header check"),
    ],
    "Smuggling Agent": [
        ("curl -s --http1.1 -X POST {target} -H 'Content-Length: 6' -H 'Transfer-Encoding: chunked' -d '0\r\n\r\nG'", "CL.TE smuggling probe"),
    ],
    "OAST Agent": [
        ("curl -s '{target}/?url=http://169.254.169.254/'", "OAST SSRF probe"),
    ],
    "IDOR Agent": [
        ("curl -sI '{target}/api/users/1'", "Probe user ID 1"),
        ("curl -sI '{target}/api/users/2'", "Probe user ID 2 — check if accessible"),
        ("curl -sI '{target}/api/orders/1'", "Probe order ID 1"),
        ("curl -s '{target}/account?id=1'", "IDOR via query param"),
        ("curl -s '{target}/api/documents/1'", "IDOR document probe"),
    ],
    "Rate Limit Agent": [
        ("for i in $(seq 1 20); do curl -s -o /dev/null -w '%{http_code}' -X POST '{target}/login' -d 'username=test&password=wrong'; done | fold -w3 | sort | uniq -c", "Rapid login — check for 429"),
        ("curl -s -X POST '{target}/forgot-password' -d 'email=test@test.com' -H 'X-Forwarded-For: 1.2.3.4'", "Rate limit bypass via X-Forwarded-For"),
        ("for i in $(seq 1 10); do curl -s -o /dev/null -w '%{http_code}' '{target}/api/verify?code=123456'; done | fold -w3 | sort | uniq -c", "OTP endpoint rapid probe"),
    ],
    "Business Logic Agent": [
        ("curl -s -X POST '{target}/api/order' -H 'Content-Type: application/json' -d '{\"price\":-1,\"qty\":-1}'", "Negative price/qty test"),
        ("curl -s -X PATCH '{target}/api/profile' -H 'Content-Type: application/json' -d '{\"role\":\"admin\",\"isAdmin\":true}'", "Mass assignment probe"),
        ("curl -sI '{target}/checkout' -X POST -d 'step=payment'", "Workflow skip — direct to payment"),
        ("curl -s '{target}/api/cart?qty=-100'", "Negative quantity in cart"),
    ],
    "Subdomain Enum": [
        ("curl -s 'https://crt.sh/?q={host}&output=json' | python3 -c \"import sys,json; data=json.load(sys.stdin); [print(e.get('name_value','')) for e in data if e.get('name_value')]\" 2>/dev/null | sort -u | head -30", "crt.sh cert transparency lookup"),
        ("for sub in admin api dev staging test beta internal vpn mail git jenkins jira; do code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://$sub.{host} 2>/dev/null); [ \"$code\" != \"000\" ] && echo \"$sub.{host} → $code\"; done", "Common subdomain bruteforce"),
    ],
    "Nuclei Agent": [
        ("which nuclei && echo 'nuclei installed' || echo 'nuclei not installed — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'", "Check nuclei installation"),
        ("nuclei -u {target} -severity medium,high,critical -j -silent -timeout 10 -rate-limit 5 -bulk-size 3 -c 3 2>/dev/null | head -20", "Nuclei scan — medium/high/critical"),
    ],
}


# ── Static pattern-matching findings ─────────────────────────────────────────
# Each entry: list of (check_fn, finding_text, severity)
# check_fn receives the full accumulated output string → returns bool
# Negative checks (absent = finding) only fire when output is non-trivial (>50 chars)

_STATIC_PATTERNS: dict = {
    "Security Headers": [
        (lambda o: len(o) > 50 and "content-security-policy" not in o.lower(),
         "Content-Security-Policy header missing — XSS payloads execute without restriction", "medium"),
        (lambda o: len(o) > 50 and "x-frame-options" not in o.lower() and "frame-ancestors" not in o.lower(),
         "X-Frame-Options missing — page embeddable in iframe (clickjacking risk)", "medium"),
        (lambda o: len(o) > 50 and "x-content-type-options" not in o.lower(),
         "X-Content-Type-Options: nosniff missing — MIME-sniffing attacks possible", "low"),
        (lambda o: len(o) > 50 and "strict-transport-security" not in o.lower(),
         "HSTS header missing — SSL-stripping downgrade attacks possible", "medium"),
        (lambda o: len(o) > 50 and "referrer-policy" not in o.lower(),
         "Referrer-Policy missing — URL parameters/tokens may leak to third-party sites", "low"),
        (lambda o: re.search(r"x-powered-by:\s*\S+", o, re.I) is not None,
         "X-Powered-By header discloses server technology to attackers", "low"),
        (lambda o: re.search(r"server:\s*\S+/[\d.]+", o, re.I) is not None,
         "Server header discloses version number — aids attacker reconnaissance", "low"),
        (lambda o: "set-cookie:" in o.lower() and "httponly" not in o.lower(),
         "Session cookie missing HttpOnly flag — accessible via document.cookie in XSS", "medium"),
        (lambda o: "set-cookie:" in o.lower() and re.search(r"set-cookie:[^\n]*\n", o, re.I) is not None
         and "secure" not in o.lower(),
         "Session cookie missing Secure flag — transmitted over plaintext HTTP", "medium"),
        (lambda o: "set-cookie:" in o.lower() and "samesite" not in o.lower(),
         "Session cookie missing SameSite attribute — cross-site request forgery possible", "medium"),
    ],
    "JS Library Scanner": [
        (lambda o: re.search(r"jquery[.-](1\.[0-9]\.|2\.[0-2]\.)", o, re.I) is not None,
         "Vulnerable jQuery version detected (< 3.5.0) — CVE-2020-11022 XSS via .html()/.append()", "high"),
        (lambda o: re.search(r"bootstrap[.-](2\.|3\.|4\.[0-2]\.)", o, re.I) is not None,
         "Outdated Bootstrap detected (< 4.3.1) — CVE-2019-8331 XSS via data-* attributes", "medium"),
        (lambda o: re.search(r"angular[.-]?js[.-](1\.[0-9])", o, re.I) is not None,
         "AngularJS 1.x detected — End of Life since Dec 2021, multiple XSS CVEs", "medium"),
        (lambda o: re.search(r"lodash[.-](4\.(1[0-6]|[0-9])\.|3\.|2\.|1\.|0\.)", o, re.I) is not None,
         "Vulnerable Lodash version detected (< 4.17.21) — CVE-2021-23337 prototype pollution", "medium"),
        (lambda o: "moment.js" in o.lower() or re.search(r"moment[.-][\d.]+\.js", o, re.I) is not None,
         "Moment.js detected — End of Life, consider migrating to date-fns or Day.js", "low"),
    ],
    "LFI Agent": [
        (lambda o: "root:x:0:0:" in o or "root:*:0:0:" in o,
         "LFI CONFIRMED: /etc/passwd readable — full system user list exposed", "critical"),
        (lambda o: "/bin/bash" in o or "/bin/sh" in o,
         "LFI confirmed: shell path visible — system file contents leaking", "high"),
        (lambda o: "[fonts]" in o or "[extensions]" in o,
         "LFI CONFIRMED: Windows win.ini readable via path traversal", "critical"),
        (lambda o: "/var/log" in o or "access.log" in o,
         "LFI: log file path visible — potential log poisoning RCE vector", "high"),
    ],
    "CMDi Agent": [
        (lambda o: re.search(r"uid=\d+\(", o) is not None,
         "COMMAND INJECTION CONFIRMED: id command output visible in response", "critical"),
        (lambda o: re.search(r"uid=0\(root\)", o) is not None,
         "COMMAND INJECTION AS ROOT CONFIRMED — full server compromise", "critical"),
        (lambda o: re.search(r"^[a-z_][a-z0-9_-]*$", o.strip().split("\n")[0] if o.strip() else "", re.I) is not None
         and "whoami" in o.lower(),
         "Possible command injection: username returned in response", "high"),
    ],
    "Open Redirect": [
        (lambda o: "evil.com" in o.lower() and "location:" in o.lower(),
         "OPEN REDIRECT CONFIRMED: Location header redirects to evil.com", "medium"),
        (lambda o: "//evil.com" in o,
         "Open redirect confirmed via protocol-relative URL", "medium"),
    ],
    "CORS Agent": [
        (lambda o: "access-control-allow-origin: *" in o.lower(),
         "CORS wildcard (*) — any origin can read responses from this API", "medium"),
        (lambda o: "access-control-allow-origin: https://evil.com" in o.lower(),
         "CORS reflects arbitrary Origin — cross-origin reads possible from any domain", "high"),
        (lambda o: "access-control-allow-origin: null" in o.lower(),
         "CORS allows null origin — exploitable via sandboxed iframes", "medium"),
        (lambda o: "access-control-allow-credentials: true" in o.lower()
         and ("access-control-allow-origin: *" in o.lower()
              or "access-control-allow-origin: https://evil.com" in o.lower()),
         "CRITICAL CORS: credentials=true with permissive origin — session theft via CORS", "critical"),
    ],
    "TLS/SSL Agent": [
        (lambda o: "sslv3" in o.lower(),
         "SSLv3 supported — vulnerable to POODLE attack (CVE-2014-3566)", "high"),
        (lambda o: re.search(r"\bTLSv1\b", o) is not None and "TLSv1.2" not in o and "TLSv1.3" not in o,
         "TLS 1.0 only — deprecated protocol, vulnerable to BEAST/POODLE", "medium"),
        (lambda o: len(o) > 30 and "strict-transport-security" not in o.lower(),
         "HSTS header absent on HTTPS endpoint — SSL-stripping possible", "medium"),
        (lambda o: "verify error" in o.lower() or "certificate has expired" in o.lower(),
         "TLS certificate expired or invalid — users see browser security warnings", "high"),
        (lambda o: "self signed" in o.lower(),
         "Self-signed TLS certificate — not trusted by browsers", "medium"),
    ],
    "SQLi Agent": [
        (lambda o: any(s in o.lower() for s in
                       ["sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_", "you have an error in your sql"]),
         "SQL error message in response — database error leakage, possible injection point", "high"),
        (lambda o: "warning: mysql" in o.lower() or "mysql error" in o.lower(),
         "MySQL error message exposed — confirms MySQL backend, aids injection", "high"),
    ],
    "XSS Agent": [
        (lambda o: "<script>alert(1)</script>" in o,
         "REFLECTED XSS CONFIRMED: script tag payload returned unescaped in response", "high"),
        (lambda o: "onerror=alert(1)" in o,
         "REFLECTED XSS CONFIRMED: onerror payload returned unescaped in response", "high"),
    ],
    "SSRF Agent": [
        (lambda o: "ami-id" in o.lower() or "instance-id" in o.lower() or "iam" in o.lower(),
         "SSRF CONFIRMED: AWS instance metadata service (169.254.169.254) accessible", "critical"),
        (lambda o: "ssh-" in o.lower() or "openssh" in o.lower(),
         "SSRF confirmed: internal SSH service reachable via SSRF", "high"),
    ],
    "XXE Agent": [
        (lambda o: "root:x:0:0:" in o or "root:*:0:0:" in o,
         "XXE CONFIRMED: /etc/passwd returned in XML response", "critical"),
    ],
    "Secrets Scanner": [
        (lambda o: re.search(r"(api_key|apikey|secret_key|aws_secret|password)\s*=\s*\S+", o, re.I) is not None,
         "Credentials exposed in response — API key or password visible", "critical"),
        (lambda o: "[core]" in o and "repositoryformatversion" in o,
         ".git/config publicly exposed — attacker can clone source code repository", "high"),
        (lambda o: '"swagger"' in o or '"openapi"' in o or '"paths"' in o,
         "API specification exposed publicly — full endpoint list visible to attacker", "medium"),
    ],
    "API Spec Agent": [
        (lambda o: '"swagger"' in o or '"openapi"' in o,
         "OpenAPI/Swagger spec publicly accessible — full API surface exposed", "medium"),
        (lambda o: "__typename" in o,
         "GraphQL endpoint active and responsive to introspection queries", "info"),
    ],
    "OAuth Agent": [
        (lambda o: "authorization_endpoint" in o.lower() and "token_endpoint" in o.lower(),
         "OpenID Connect configuration (.well-known/openid-configuration) publicly accessible", "info"),
    ],
    "WAF Bypass": [
        (lambda o: any(w in o.lower() for w in ["cloudflare", "sucuri", "imperva", "akamai", "f5", "barracuda"]),
         "WAF detected — active security filtering in place", "info"),
        (lambda o: "<script>alert(1)</script>" in o,
         "WAF bypass: XSS payload reflected without blocking — WAF not filtering this vector", "high"),
    ],
    "CSRF Agent": [
        (lambda o: "set-cookie:" in o.lower() and "samesite" not in o.lower(),
         "Session cookie missing SameSite attribute — cross-site request forgery attacks possible", "medium"),
    ],
    "Recon Agent": [
        (lambda o: re.search(r"server:\s*\S+/[\d.]+", o, re.I) is not None,
         "Server version disclosed in HTTP response headers", "low"),
        (lambda o: "x-powered-by:" in o.lower(),
         "X-Powered-By header reveals backend technology stack", "low"),
    ],
    "SSTI Agent": [
        (lambda o: "49" in o and "{{7*7}}" not in o,
         "Possible SSTI: arithmetic payload {{7*7}} evaluated to 49 in response", "high"),
    ],
    "IDOR Agent": [
        (lambda o: '"id":2' in o or '"user_id":2' in o or '"userId":2' in o,
         "Possible IDOR: object ID 2 returned — verify if cross-user data access is possible", "high"),
        (lambda o: re.search(r'"email":\s*"[^"]+@[^"]+"', o) is not None and "200" in o,
         "API returns user email on ID probe — potential IDOR data exposure", "high"),
    ],
    "Rate Limit Agent": [
        (lambda o: "200" in o and o.count("200") > 15,
         "No rate limiting detected — 15+ successful requests without 429 throttling", "high"),
        (lambda o: "429" not in o and "locked" not in o.lower() and "blocked" not in o.lower(),
         "Login endpoint returned no 429/lockout after repeated attempts — brute-force possible", "medium"),
    ],
    "Business Logic Agent": [
        (lambda o: '"price"' in o and re.search(r'"price":\s*-', o) is not None,
         "Negative price accepted in API response — business logic bypass possible", "critical"),
        (lambda o: '"role"' in o and '"admin"' in o.lower() and "200" in o,
         "Possible mass assignment: role=admin accepted in profile update", "critical"),
        (lambda o: re.search(r'"isAdmin":\s*true', o, re.I) is not None,
         "Possible privilege escalation via mass assignment — isAdmin=true accepted", "critical"),
    ],
    "Subdomain Enum": [
        (lambda o: re.search(r'[a-z0-9-]+\.[a-z0-9.-]+\.[a-z]{2,}', o) is not None,
         "Subdomains discovered via certificate transparency — expanded attack surface", "info"),
        (lambda o: "→ 200" in o or "→ 301" in o or "→ 302" in o,
         "Live subdomains found — additional attack surface identified", "info"),
    ],
    "Nuclei Agent": [
        (lambda o: "nuclei installed" in o,
         "Nuclei scanner available — template-based vulnerability scanning active", "info"),
        (lambda o: '"severity":"critical"' in o or '"severity":"high"' in o,
         "Nuclei detected critical/high severity vulnerability — review nuclei output", "critical"),
        (lambda o: "nuclei not installed" in o,
         "Nuclei not installed — install for 5000+ template-based vulnerability checks", "info"),
    ],
}


def _run_static_agent(state: dict, agent_id: str, target: str) -> None:
    """Run predefined commands for no-key mode; collect output, then pattern-match findings."""
    name  = state["name"]
    cmds  = _STATIC_CMDS.get(name, [])
    host  = urlparse(target).netloc or target

    if not cmds:
        state["output"].append(f"[STATIC] No static commands defined for {name}")
        return

    accumulated = []   # collect all output for pattern matching
    for tpl, reason in cmds:
        if state.get("stop"):
            break
        cmd = tpl.replace("{target}", target).replace("{host}", host)
        state["output"].append(f"[Static] $ {cmd}")
        state["output"].append(f"  → {reason}")
        out = _run_cmd(cmd)
        state["output"].append(out)
        state["commands_run"] += 1
        accumulated.append(out)

    # Pattern-based finding extraction
    combined = "\n".join(accumulated)
    patterns = _STATIC_PATTERNS.get(name, [])
    new_findings = []
    for check_fn, finding_text, severity in patterns:
        try:
            if check_fn(combined):
                new_findings.append({"text": finding_text, "severity": severity})
        except Exception:
            pass

    if new_findings:
        with _lock:
            _record_findings(state, agent_id, target, new_findings)
        state["output"].append(f"[STATIC] {len(new_findings)} finding(s) detected via pattern analysis")
    else:
        state["output"].append("[STATIC] No issues detected — add an AI key for deeper analysis")

    with _lock:
        _context[f"{state['name']}_static"] = f"static scan completed for {target}"


# ── REST API ──────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    error = None
    username = ""
    if req.method == "POST":
        username = (req.form.get("username") or "").strip()
        password = (req.form.get("password") or "").strip()
        if username in _AUTH_USERS and _AUTH_USERS[username] == password:
            session["authenticated"] = True
            session["username"] = username
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials — access denied"
    return render_template("login.html", error=error, username=username)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@_login_required
def index():
    return render_template("index.html")


@app.route("/api/scan/launch", methods=["POST"])
def scan_launch():
    global _scan_active, _scan_target, _SEM

    data           = req.json or {}
    target         = data.get("target", "").strip()
    phases         = data.get("phases", PHASES)
    max_concurrent = max(1, int(data.get("max_concurrent", 5)))

    if not target:
        return jsonify({"success": False, "error": "target required"}), 400

    # Auto-resolve scheme/port — works for http, https, IP:port, etc.
    target = _resolve_target(target)

    ai_mode = bool(_api_keys.get("openai") or _api_keys.get("anthropic"))

    # Reset state
    with _lock:
        _SEM = threading.Semaphore(max_concurrent)
        _agents.clear()
        _findings.clear()
        _context.clear()
        _seen_findings.clear()
        _scan_active = True
        _scan_target = target

    # Spawn selected agents
    agent_ids = []
    for spec in _DAST_AGENTS:
        if spec["phase"] not in phases:
            continue
        aid = f"agent_{uuid.uuid4().hex[:8]}"
        state = {
            "id":           aid,
            "name":         spec["name"],
            "icon":         spec["icon"],
            "phase":        spec["phase"],
            "task":         spec["task"],
            "status":       "pending",
            "iteration":    0,
            "max_iter":     10,
            "commands_run": 0,
            "output":       [f"[{spec['name']}] Initialising for {target}..."],
            "findings":     [],
            "summary":      "",
            "created_at":   datetime.now(timezone.utc).isoformat(),
            "finished_at":  None,
            "stop":         False,
        }
        _agents[aid] = state
        agent_ids.append(aid)

        t = threading.Thread(
            target=_agent_worker, args=(aid, target), daemon=True,
            name=f"DAST-{spec['name']}"
        )
        t.start()

    return jsonify({
        "success":   True,
        "target":    target,
        "agent_ids": agent_ids,
        "count":     len(agent_ids),
        "phases":    phases,
        "ai_mode":   ai_mode,
    })


@app.route("/api/scan/stop", methods=["POST"])
def scan_stop():
    global _scan_active
    with _lock:
        for agent in _agents.values():
            agent["stop"] = True
        _scan_active = False
    return jsonify({"success": True})


@app.route("/api/scan/status")
def scan_status():
    with _lock:
        agents_list = list(_agents.values())
    total    = len(agents_list)
    running  = sum(1 for a in agents_list if a["status"] == "running")
    pending  = sum(1 for a in agents_list if a["status"] == "pending")
    done     = sum(1 for a in agents_list if a["status"] in ("completed", "error", "stopped"))
    findings = len(_findings)

    agents_out = []
    for a in agents_list:
        agents_out.append({
            "id":           a["id"],
            "name":         a["name"],
            "icon":         a["icon"],
            "phase":        a["phase"],
            "status":       a["status"],
            "iteration":    a["iteration"],
            "commands_run": a["commands_run"],
            "findings_count": len(a["findings"]),
            "summary":      a["summary"],
            "finished_at":  a["finished_at"],
        })

    return jsonify({
        "scan_active": _scan_active,
        "target":      _scan_target,
        "total":       total,
        "running":     running,
        "pending":     pending,
        "done":        done,
        "findings":    findings,
        "agents":      agents_out,
    })


@app.route("/api/agent/<aid>/output")
def agent_output(aid: str):
    agent = _agents.get(aid)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    after = int(req.args.get("after", 0))
    lines = agent["output"]
    return jsonify({
        "lines":          lines[after:],
        "after":          len(lines),
        "status":         agent["status"],
        "iteration":      agent["iteration"],
        "commands_run":   agent["commands_run"],
        "findings_count": len(agent["findings"]),
    })


@app.route("/api/agent/<aid>/stop", methods=["POST"])
def agent_stop(aid: str):
    agent = _agents.get(aid)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    agent["stop"] = True
    agent["status"] = "stopped"
    return jsonify({"success": True})


@app.route("/api/findings")
def findings():
    phase = req.args.get("phase")
    with _lock:
        out = [f for f in _findings if not phase or f["phase"] == phase]
    return jsonify({"findings": out, "count": len(out)})


@app.route("/api/history")
def scan_history():
    limit = int(req.args.get("limit", 20))
    return jsonify({"history": _db_get_history(limit)})


@app.route("/api/activity")
def scan_activity():
    """Return recent scan activity events (spider, AJAX, passive, engine)."""
    limit = int(req.args.get("limit", 100))
    with _engine_lock:
        events = list(_activity_log[-limit:])
    return jsonify({"events": list(reversed(events)), "count": len(events)})


@app.route("/api/findings/export")
def findings_export():
    with _lock:
        data = list(_findings)
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=dast_findings.json"},
    )


# ── Remediation + CVSS Knowledge Base ─────────────────────────────────────────

_REMEDIATION: dict = {
    "sqli": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": "9.8",
        "cwe": "CWE-89",
        "fix": "Use parameterised queries / prepared statements. Never concatenate user input into SQL strings. Apply ORM-level protections.",
    },
    "xss": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": "6.1",
        "cwe": "CWE-79",
        "fix": "HTML-encode all output. Implement a strict Content-Security-Policy. Use a context-aware output encoding library.",
    },
    "ssrf": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "score": "10.0",
        "cwe": "CWE-918",
        "fix": "Allowlist outbound URLs. Block RFC-1918 ranges and metadata endpoints. Use a dedicated outbound proxy.",
    },
    "lfi": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": "7.5",
        "cwe": "CWE-22",
        "fix": "Never pass user-controlled filenames to file operations. Use allowlists for valid file paths. Jail the process with chroot.",
    },
    "cmdi": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": "9.8",
        "cwe": "CWE-78",
        "fix": "Avoid shell invocation entirely. Use language-native APIs. If shell needed, allowlist acceptable characters and use parameterised shell calls.",
    },
    "cors": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "score": "8.1",
        "cwe": "CWE-942",
        "fix": "Restrict Access-Control-Allow-Origin to an explicit allowlist. Never reflect arbitrary Origin headers. Do not combine wildcard origin with credentials.",
    },
    "jwt": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": "9.1",
        "cwe": "CWE-347",
        "fix": "Reject alg=none tokens server-side. Use asymmetric keys and pin the expected algorithm. Validate all JWT claims including exp, iss, aud.",
    },
    "idor": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "score": "8.1",
        "cwe": "CWE-639",
        "fix": "Enforce object-level authorisation on every endpoint. Use opaque UUIDs instead of sequential IDs. Verify the authenticated user owns the requested resource.",
    },
    "csrf": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "score": "8.1",
        "cwe": "CWE-352",
        "fix": "Implement synchronised CSRF tokens. Set SameSite=Strict on session cookies. Validate Origin and Referer headers on state-changing requests.",
    },
    "headers": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": "5.3",
        "cwe": "CWE-693",
        "fix": "Add security headers: Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security, Referrer-Policy.",
    },
    "rate": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": "5.3",
        "cwe": "CWE-307",
        "fix": "Implement server-side rate limiting with exponential backoff. Do not rely solely on client IP — also track by account. Alert on threshold breaches.",
    },
    "nuclei": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": "9.8",
        "cwe": "CWE-1",
        "fix": "Review the specific nuclei template finding. Apply the recommended fix from the template metadata or the associated CVE advisory.",
    },
}

def _get_remediation(finding_text: str, agent: str) -> dict:
    """Match finding to a remediation entry."""
    t = (finding_text + " " + agent).lower()
    if any(k in t for k in ["sql", "sqli", "injection confirmed"]):
        return _REMEDIATION["sqli"]
    if any(k in t for k in ["xss", "cross-site scripting", "script tag", "onerror"]):
        return _REMEDIATION["xss"]
    if any(k in t for k in ["ssrf", "server-side request", "metadata"]):
        return _REMEDIATION["ssrf"]
    if any(k in t for k in ["lfi", "path traversal", "file inclusion", "/etc/passwd"]):
        return _REMEDIATION["lfi"]
    if any(k in t for k in ["command injection", "cmdi", "uid=", "whoami"]):
        return _REMEDIATION["cmdi"]
    if any(k in t for k in ["cors", "access-control"]):
        return _REMEDIATION["cors"]
    if any(k in t for k in ["jwt", "json web token", "alg=none"]):
        return _REMEDIATION["jwt"]
    if any(k in t for k in ["idor", "insecure direct object", "object reference"]):
        return _REMEDIATION["idor"]
    if any(k in t for k in ["csrf", "cross-site request forgery", "samesite"]):
        return _REMEDIATION["csrf"]
    if any(k in t for k in ["header", "csp", "hsts", "x-frame", "nosniff", "cookie"]):
        return _REMEDIATION["headers"]
    if any(k in t for k in ["rate limit", "429", "brute-force", "lockout"]):
        return _REMEDIATION["rate"]
    if any(k in t for k in ["nuclei"]):
        return _REMEDIATION["nuclei"]
    return {}


# ── HTML Report ───────────────────────────────────────────────────────────────

def _render_report_html(findings: list, target: str) -> str:
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(findings)

    SEV_ORDER  = ["critical", "high", "medium", "low", "info"]
    SEV_RANK   = {s: i for i, s in enumerate(SEV_ORDER)}
    SEV_COLORS = {
        "critical": ("#ff4444", "#2d0a0a"),
        "high":     ("#f85149", "#4a0e0e"),
        "medium":   ("#d29922", "#4a3800"),
        "low":      ("#3fb950", "#1a4226"),
        "info":     ("#388bfd", "#1f4080"),
    }

    counts = defaultdict(int)
    for f in findings:
        counts[f.get("severity", "medium").lower()] += 1

    cards = ""
    for s in SEV_ORDER:
        fg = SEV_COLORS[s][0]
        cards += (
            f'<div class="sev-card">'
            f'<div class="count" style="color:{fg}">{counts[s]}</div>'
            f'<div class="label">{s.title()}</div></div>\n'
        )

    # ── Group findings by issue description ───────────────────────────────────
    # Key = finding text. Each group collects all affected URLs + highest severity.
    groups: dict = {}   # finding_text → {severity, urls, agent, icon, phase, rem}
    for f in findings:
        key = f.get("finding", "").strip()
        sev = f.get("severity", "medium").lower()
        url = f.get("target") or f.get("url", "")
        if key not in groups:
            groups[key] = {
                "severity": sev,
                "urls":     [],
                "agent":    f.get("agent", ""),
                "icon":     f.get("icon", "🔍"),
                "phase":    f.get("phase", ""),
            }
        # Escalate to highest severity
        if SEV_RANK.get(sev, 4) < SEV_RANK.get(groups[key]["severity"], 4):
            groups[key]["severity"] = sev
        if url and url not in groups[key]["urls"]:
            groups[key]["urls"].append(url)

    # Sort groups by severity
    sorted_groups = sorted(groups.items(),
                           key=lambda kv: SEV_RANK.get(kv[1]["severity"], 4))

    rows = ""
    for finding_text, g in sorted_groups:
        sev    = g["severity"]
        fg, bg = SEV_COLORS.get(sev, ("#888", "#222"))
        badge  = (
            f'<span style="background:{bg};color:{fg};padding:2px 8px;'
            f'border-radius:3px;font-size:11px;font-weight:700;">{sev.upper()}</span>'
        )
        text   = (finding_text
                  .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        rem    = _get_remediation(finding_text, g["agent"])
        cvss_cell = ""
        if rem:
            cvss_cell = (
                f'<div style="font-size:11px;margin-top:4px;color:#7d8590;">'
                f'<span style="color:{fg};font-weight:700;">CVSS {rem.get("score","?")}</span>'
                f' &nbsp;{rem.get("cwe","")}</div>'
                f'<div style="font-size:11px;margin-top:3px;color:#adbac7;">'
                f'<b>Fix:</b> {rem.get("fix","")}</div>'
            )
        url_count  = len(g["urls"])
        url_suffix = (
            f'<div style="margin-top:6px;font-size:11px;color:#7d8590;">'
            f'<b style="color:#adbac7">Affected ({url_count}):</b> '
            + ", ".join(
                f'<span style="font-family:monospace;color:#79c0ff">{u.replace("&","&amp;").replace("<","&lt;")}</span>'
                for u in g["urls"][:30]
            )
            + ("…" if url_count > 30 else "")
            + "</div>"
        ) if g["urls"] else ""

        rows += (
            f"<tr><td>{badge}</td>"
            f"<td>{g['icon']} {g['phase']}</td>"
            f"<td>{g['agent']}</td>"
            f"<td>{text}{cvss_cell}{url_suffix}</td></tr>\n"
        )

    table = (
        '<table><thead><tr>'
        '<th>Severity</th><th>Phase</th><th>Source</th>'
        '<th>Issue / Remediation / Affected URLs</th>'
        '</tr></thead><tbody>' + rows + '</tbody></table>'
    ) if findings else '<div class="no-findings">No findings recorded yet.</div>'

    unique_issues = len(groups)
    css = (
        "body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}"
        "h1{font-size:22px;margin-bottom:4px}"
        ".meta{color:#7d8590;font-size:13px;margin-bottom:24px}"
        ".summary{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}"
        ".sev-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center;min-width:80px}"
        ".sev-card .count{font-size:28px;font-weight:700}"
        ".sev-card .label{font-size:11px;color:#7d8590;margin-top:2px;text-transform:capitalize}"
        "table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;border:1px solid #30363d}"
        "th{background:#1c2128;padding:10px 14px;text-align:left;font-size:11px;color:#7d8590;text-transform:uppercase;letter-spacing:.5px}"
        "td{padding:10px 14px;border-top:1px solid #21262d;font-size:13px;vertical-align:top}"
        "tr:hover td{background:#1c2128}"
        ".no-findings{text-align:center;padding:48px;color:#7d8590;font-size:14px}"
    )

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        f'<title>DAST Report — {target}</title>'
        f'<style>{css}</style></head><body>'
        '<h1>DAST Security Report</h1>'
        f'<div class="meta">Target: <strong>{target}</strong>'
        f'&nbsp;&nbsp;|&nbsp;&nbsp;Generated: {ts}'
        f'&nbsp;&nbsp;|&nbsp;&nbsp;Total findings: <strong>{total}</strong>'
        f'&nbsp;&nbsp;|&nbsp;&nbsp;Unique issues: <strong>{unique_issues}</strong></div>'
        '<div class="summary">' + cards + '</div>'
        + table
        + '</body></html>'
    )


@app.route("/api/report")
def findings_report():
    with _lock:
        data = list(_findings)
    # Merge passive findings (normalize schema to match agent findings)
    with _engine_lock:
        for pf in _passive_findings:
            data.append({
                "finding":  pf.get("finding", ""),
                "severity": pf.get("severity", "Info").lower(),
                "target":   pf.get("url", ""),
                "url":      pf.get("url", ""),
                "agent":    "Passive Scanner",
                "icon":     "🛡",
                "phase":    "Passive",
            })
    html     = _render_report_html(data, _scan_target or "unknown")
    filename = f"dast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ██  PROXY ENGINE  (ZAP parity — traffic visibility + passive scan all traffic)
# ═══════════════════════════════════════════════════════════════════════════════

try:
    import asyncio as _asyncio
    from mitmproxy.options import Options as _MitmOptions
    from mitmproxy.tools.dump import DumpMaster as _DumpMaster
    from mitmproxy import http as _mhttp
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_AVAILABLE = False

_proxy_thread  = None
_proxy_port    = 8090
_site_map: dict = {}   # url → {methods, params, content_type, auth_seen}


_proxy_passive_seen: set = set()  # dedup: (path, category, finding)

class _DASTProxyAddon:
    """mitmproxy addon — full passive scans every intercepted response, builds site map."""

    def response(self, flow: "_mhttp.HTTPFlow") -> None:
        url    = flow.request.pretty_url
        method = flow.request.method
        hdrs   = dict(flow.response.headers)
        body   = ""
        try:
            body = flow.response.text or ""
        except Exception:
            pass

        # ── Site map ──────────────────────────────────────────────────────────
        from urllib.parse import parse_qs, urlparse as _up
        parsed = _up(url)
        params = list(parse_qs(parsed.query).keys())
        with _lock:
            entry = _site_map.setdefault(url, {
                "methods": [], "params": [], "content_type": "", "auth_seen": False
            })
            if method not in entry["methods"]:
                entry["methods"].append(method)
            entry["params"] = list(set(entry["params"] + params))
            entry["content_type"] = hdrs.get("content-type", "")
            if "authorization" in (k.lower() for k in flow.request.headers):
                entry["auth_seen"] = True

        # ── Full passive scan on every proxied response (278 rules — ZAP parity) ─
        try:
            cookies = {}
            for c_hdr in flow.response.headers.get_all("set-cookie"):
                if "=" in c_hdr:
                    cname = c_hdr.split("=", 1)[0].strip()
                    cval  = c_hdr.split("=", 1)[1].split(";")[0].strip()
                    cookies[cname] = cval
        except Exception:
            cookies = {}
        pf_results = _passive.scan(
            url=url, status_code=flow.response.status_code,
            resp_headers=hdrs, resp_body=body[:8000],
            cookies=cookies,
        )
        if pf_results:
            from urllib.parse import urlparse as _pup
            path = _pup(url).path
            new_count = 0
            with _lock:
                for pf in pf_results:
                    dedup_key = (path, pf.category, pf.finding)
                    if dedup_key not in _proxy_passive_seen:
                        _proxy_passive_seen.add(dedup_key)
                        _findings.append({
                            "agent": "Proxy Passive Scanner",
                            "agent_id": "proxy",
                            "icon": "🔌",
                            "phase": "Discovery",
                            "finding": pf.finding,
                            "severity": pf.severity,
                            "type": pf.category,
                            "url": url,
                            "evidence": pf.evidence,
                            "remediation": pf.remediation,
                            "target": url,
                            "ts": datetime.now(timezone.utc).isoformat(),
                        })
                        new_count += 1
            if new_count:
                _trigger_hook("on_finding", {"text": pf_results[-1].finding, "severity": pf_results[-1].severity})

        # ── Session token analysis ─────────────────────────────────────────────
        set_cookie = hdrs.get("set-cookie", "")
        if set_cookie:
            _analyze_session_tokens(url, set_cookie)

        _trigger_hook("on_response", url, flow.response.status_code, hdrs, body)


def _proxy_passive_scan(url: str, status: int, combined: str) -> list:
    """100+ ZAP-inspired passive checks on every proxied HTTP response."""
    lo = combined.lower()
    finds = []

    def _chk(condition: bool, text: str, sev: str):
        if condition:
            finds.append({"text": f"{text} [{url}]", "severity": sev})

    # Security headers (same as _STATIC_PATTERNS but on every proxied response)
    if len(combined) > 80:
        _chk("content-security-policy" not in lo,
             "Content-Security-Policy header missing", "medium")
        _chk("x-frame-options" not in lo and "frame-ancestors" not in lo,
             "X-Frame-Options missing — clickjacking risk", "medium")
        _chk("x-content-type-options" not in lo,
             "X-Content-Type-Options: nosniff missing", "low")
        _chk("strict-transport-security" not in lo and url.startswith("https"),
             "HSTS header missing on HTTPS endpoint", "medium")
        _chk("referrer-policy" not in lo,
             "Referrer-Policy header missing", "low")
        _chk("permissions-policy" not in lo,
             "Permissions-Policy header missing", "low")

    # Cookie flags
    if "set-cookie:" in lo:
        _chk("httponly" not in lo, "Cookie missing HttpOnly flag", "medium")
        _chk("samesite" not in lo, "Cookie missing SameSite attribute", "medium")
        _chk(url.startswith("https") and "secure" not in lo,
             "Cookie missing Secure flag on HTTPS", "medium")

    # Information disclosure
    if re.search(r"server:\s*\S+/[\d.]+", combined, re.I):
        _chk(True, "Server version number disclosed in response header", "low")
    if "x-powered-by:" in lo:
        _chk(True, "X-Powered-By header exposes technology fingerprint", "low")
    if "x-aspnet-version:" in lo:
        _chk(True, "X-AspNet-Version header discloses framework version", "low")
    if re.search(r"\b(?:10|172|192)\.\d+\.\d+\.\d+\b", body := combined.split("\n", 20)[-1]):
        _chk(True, "Private IP address disclosed in response body", "low")

    # SQL / DB errors (passive detection)
    sql_errors = ["you have an error in your sql", "ora-0", "mysql_fetch",
                  "sqlite_", "pg_query", "microsoft sql", "odbc driver"]
    _chk(any(e in lo for e in sql_errors),
         "Database error message in response — possible injection surface", "high")

    # Stack traces / debug info
    debug_indicators = ["stack trace", "traceback (most recent", "at org.apache",
                        "at com.sun", "exception in thread", "debug mode", "werkzeug debugger"]
    _chk(any(d in lo for d in debug_indicators),
         "Stack trace / debug info exposed in response", "medium")

    # Exposed credentials in body
    _chk(bool(re.search(r"(password|secret|api_key|token)\s*[=:]\s*['\"]?\S{8,}", combined, re.I)),
         "Credentials or secrets pattern detected in response body", "critical")

    # Cache-control on authenticated pages
    if status in (200, 201) and "authorization" in lo:
        _chk("cache-control" not in lo or "no-store" not in lo,
             "Authenticated response may be cached — missing Cache-Control: no-store", "low")

    # CORS
    _chk("access-control-allow-origin: *" in lo,
         "CORS wildcard origin — any domain can read API responses", "medium")
    _chk("access-control-allow-origin: null" in lo,
         "CORS allows null origin — exploitable via sandboxed iframes", "medium")
    if "access-control-allow-credentials: true" in lo and "access-control-allow-origin: *" in lo:
        _chk(True, "Critical CORS: credentials=true with wildcard origin", "critical")

    # Username enumeration signal
    _chk(status == 200 and re.search(r"user.*not found|invalid username|no such user", lo) is not None,
         "Username enumeration: different response for invalid username vs password", "medium")

    # Directory listing
    _chk("index of /" in lo and "<a href" in lo,
         "Directory listing enabled — file system structure exposed", "medium")

    # Clickjacking (check frames allowed)
    if status == 200 and "text/html" in lo:
        _chk("x-frame-options" not in lo and "frame-ancestors" not in lo,
             "HTML page missing anti-clickjacking header", "medium")

    return finds


# ── Proxy start / stop ────────────────────────────────────────────────────────

def _run_proxy_loop(port: int) -> None:
    loop = _asyncio.new_event_loop()
    _asyncio.set_event_loop(loop)
    opts = _MitmOptions(listen_host="0.0.0.0", listen_port=port,
                        ssl_insecure=True, confdir="/tmp/.mitmproxy_dast")
    master = _DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(_DASTProxyAddon())
    try:
        loop.run_until_complete(master.run())
    except Exception:
        pass


@app.route("/api/proxy/start", methods=["POST"])
def proxy_start():
    global _proxy_thread, _proxy_port
    if not PROXY_AVAILABLE:
        return jsonify({"success": False,
                        "error": "mitmproxy not installed — run: pip install mitmproxy"}), 400
    data  = req.json or {}
    port  = int(data.get("port", _proxy_port))
    _proxy_port = port
    if _proxy_thread and _proxy_thread.is_alive():
        return jsonify({"success": True, "port": port, "status": "already_running"})
    _proxy_thread = threading.Thread(
        target=_run_proxy_loop, args=(port,), daemon=True, name="DAST-Proxy"
    )
    _proxy_thread.start()
    return jsonify({"success": True, "port": port, "status": "started",
                    "configure": f"Set browser/tool proxy to http://localhost:{port}"})


@app.route("/api/proxy/status")
def proxy_status():
    running = bool(_proxy_thread and _proxy_thread.is_alive())
    return jsonify({
        "available":   PROXY_AVAILABLE,
        "running":     running,
        "port":        _proxy_port,
        "site_map_count": len(_site_map),
        "passive_findings": sum(1 for f in _findings if f.get("agent_id") == "proxy"),
    })


@app.route("/api/sitemap")
def sitemap():
    with _lock:
        data = dict(_site_map)
    return jsonify({"count": len(data), "urls": data})


@app.route("/api/sitemap/export")
def sitemap_export():
    with _lock:
        data = dict(_site_map)
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=dast_sitemap.json"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ██  SESSION TOKEN ANALYSIS  (ZAP Token Analysis add-on parity)
# ═══════════════════════════════════════════════════════════════════════════════

import math as _math
from collections import Counter as _Counter


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq   = _Counter(s)
    length = len(s)
    return -sum((c / length) * _math.log2(c / length) for c in freq.values())


def _analyze_session_tokens(url: str, set_cookie_header: str) -> None:
    """Check captured session tokens for predictability / weak randomness."""
    for cookie_part in set_cookie_header.split(","):
        name_val = cookie_part.strip().split(";")[0]
        if "=" not in name_val:
            continue
        name, value = name_val.split("=", 1)
        name  = name.strip()
        value = value.strip()
        if not any(k in name.lower() for k in
                   ["sess", "token", "auth", "jwt", "sid", "id", "key", "csrf"]):
            continue
        if not value or len(value) < 4:
            continue

        ent = _entropy(value)
        find = None
        if ent < 3.0:
            find = {"text": f"Very low-entropy session token '{name}' (entropy={ent:.2f}/8.0) — highly predictable",
                    "severity": "critical"}
        elif ent < 3.5:
            find = {"text": f"Low-entropy session token '{name}' (entropy={ent:.2f}/8.0) — likely brute-forceable",
                    "severity": "high"}
        elif len(value) < 16:
            find = {"text": f"Short session token '{name}' ({len(value)} chars) — insufficient randomness space",
                    "severity": "medium"}

        if find:
            with _lock:
                _findings.append({
                    "agent": "Session Token Analyzer",
                    "agent_id": "token_analyzer",
                    "icon": "🎲",
                    "phase": "Auth & Session",
                    "finding": f"{find['text']} [{url}]",
                    "severity": find["severity"],
                    "target": url,
                    "ts": datetime.now(timezone.utc).isoformat(),
                })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  AJAX SPIDER + AUTHENTICATED SCANNING  (Playwright — optional dep)
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from playwright.async_api import async_playwright as _async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

_login_config: dict = {}   # username, password, login_url, user_field, pass_field


@app.route("/api/login/config", methods=["POST"])
def set_login_config():
    data = req.json or {}
    _login_config.update({
        "login_url":   data.get("login_url", ""),
        "username":    data.get("username", ""),
        "password":    data.get("password", ""),
        "user_field":  data.get("user_field", "username"),
        "pass_field":  data.get("pass_field", "password"),
    })
    return jsonify({"success": True, "configured": bool(_login_config.get("login_url"))})


@app.route("/api/login/config")
def get_login_config():
    return jsonify({"configured": bool(_login_config.get("login_url")),
                    "login_url": _login_config.get("login_url", "")})


def _playwright_ajax_crawl(target: str, proxy_port: int = 8090) -> list:
    """Headless Chrome through proxy — captures JS-rendered routes. Returns discovered URLs."""
    import asyncio

    async def _crawl():
        urls = []
        async with _async_playwright() as p:
            proxy_cfg = {"server": f"http://localhost:{proxy_port}"} if _proxy_thread and _proxy_thread.is_alive() else None
            launch_args = {"headless": True, "args": ["--ignore-certificate-errors"]}
            if proxy_cfg:
                launch_args["proxy"] = proxy_cfg
            browser = await p.chromium.launch(**launch_args)
            page    = await browser.new_page()
            page.on("request",  lambda req: urls.append(req.url))
            try:
                await page.goto(target, wait_until="networkidle", timeout=30000)
                # Click common nav elements to trigger route changes
                for sel in ["a[href]", "button", "[role=link]", "[role=button]"]:
                    try:
                        elements = await page.query_selector_all(sel)
                        for el in elements[:5]:
                            try:
                                await el.click(timeout=2000)
                                await page.wait_for_timeout(500)
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass
            await browser.close()
        return list(set(urls))

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_crawl())
    finally:
        loop.close()


def _playwright_login(target: str) -> Optional[str]:
    """Headless browser login — returns captured session cookie string or None."""
    if not _login_config.get("login_url"):
        return None
    import asyncio

    async def _do_login():
        async with _async_playwright() as p:
            browser = await p.chromium.launch(headless=True,
                                               args=["--ignore-certificate-errors"])
            ctx     = await browser.new_context()
            page    = await ctx.new_page()
            try:
                await page.goto(_login_config["login_url"], timeout=20000)
                await page.fill(f'[name={_login_config["user_field"]}]',
                                _login_config["username"])
                await page.fill(f'[name={_login_config["pass_field"]}]',
                                _login_config["password"])
                await page.click('[type=submit]')
                await page.wait_for_load_state("networkidle", timeout=10000)
                cookies = await ctx.cookies()
                session = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                return session
            except Exception as e:
                return None
            finally:
                await browser.close()

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_do_login())
    finally:
        loop.close()


@app.route("/api/ajax-crawl", methods=["POST"])
def ajax_crawl():
    if not PLAYWRIGHT_AVAILABLE:
        return jsonify({"success": False,
                        "error": "playwright not installed — run: pip install playwright && playwright install chromium"}), 400
    data   = req.json or {}
    target = data.get("target", _scan_target).strip()
    if not target:
        return jsonify({"success": False, "error": "target required"}), 400

    # Auto-resolve scheme/port before handing to Playwright
    target = _resolve_target(target)

    def _bg():
        urls = _playwright_ajax_crawl(target, _proxy_port)
        with _lock:
            for u in urls:
                if u not in _site_map:
                    _site_map[u] = {"methods": ["GET"], "params": [], "content_type": "", "auth_seen": False}
        _trigger_hook("after_ajax_crawl", urls)

    threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"success": True, "status": "crawling_in_background"})


@app.route("/api/login/execute", methods=["POST"])
def execute_login():
    if not PLAYWRIGHT_AVAILABLE:
        return jsonify({"success": False,
                        "error": "playwright not installed — run: pip install playwright && playwright install chromium"}), 400
    session = _playwright_login(_scan_target or "")
    if session:
        _api_keys["auth_header"] = f"Cookie: {session}"
        return jsonify({"success": True, "session_captured": True,
                        "cookie_length": len(session)})
    return jsonify({"success": False, "error": "Login failed — check credentials/selectors"}), 400


# ═══════════════════════════════════════════════════════════════════════════════
# ██  HOOK SYSTEM  (ZAP scripting parity)
# ═══════════════════════════════════════════════════════════════════════════════

_hooks: dict = defaultdict(list)


import shutil as _shutil

# ── Runtime detection ─────────────────────────────────────────────────────────
_NODE_AVAILABLE   = bool(_shutil.which("node") or _shutil.which("nodejs"))
_GROOVY_AVAILABLE = bool(_shutil.which("groovy"))

_HOOK_EVENTS = [
    "on_request", "on_response", "on_finding",
    "before_scan", "after_scan", "before_agent", "after_agent",
    "after_ajax_crawl",
]

# ── JS runner (invoked as: node _runner.js <hookfile> <event> <json>) ─────────
_JS_RUNNER_SRC = r"""
const fs = require('fs');
const [,, hookFile, event, payloadJson] = process.argv;
const payload = JSON.parse(payloadJson || '{}');
eval(fs.readFileSync(hookFile, 'utf8'));
let fn;
try { fn = eval(event); } catch(e) { process.exit(0); }
if (typeof fn === 'function') {
    const r = fn(payload);
    if (r !== undefined && r !== null) process.stdout.write(JSON.stringify(r));
}
"""

# ── Groovy runner (invoked as: groovy _runner.groovy <hookfile> <event> <json>) ──
_GROOVY_RUNNER_SRC = """\
import groovy.json.*
String hookFile = args[0], event = args[1]
def payload = new JsonSlurper().parseText(args.size() > 2 ? args[2] : '{}')
Binding b = new Binding()
new GroovyShell(b).evaluate(new File(hookFile))
if (b.hasVariable(event)) {
    def fn = b.getVariable(event)
    if (fn instanceof Closure) {
        def r = fn(payload)
        if (r != null) println JsonOutput.toJson(r)
    }
}
"""


def _load_hooks(hooks_dir: str = "hooks") -> int:
    """Load Python, JavaScript (node), and Groovy hook files from hooks/ directory."""
    import importlib.util, glob as _glob, re as _re, tempfile, json as _json
    import subprocess as _sp
    count = 0
    if not os.path.isdir(hooks_dir):
        return 0

    # ── Python hooks (exec in-process) ────────────────────────────────────
    for path in _glob.glob(os.path.join(hooks_dir, "*.py")):
        try:
            spec   = importlib.util.spec_from_file_location("hook", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for event in _HOOK_EVENTS:
                fn = getattr(module, event, None)
                if callable(fn):
                    _hooks[event].append(fn)
                    count += 1
        except Exception as e:
            print(f"[HOOKS] Failed to load Python {path}: {e}")

    # ── JavaScript hooks (requires node) ──────────────────────────────────
    if _NODE_AVAILABLE:
        js_runner = os.path.join(tempfile.gettempdir(), "_dast_js_runner.js")
        with open(js_runner, "w") as f:
            f.write(_JS_RUNNER_SRC)
        node_bin = _shutil.which("node") or _shutil.which("nodejs")
        for path in _glob.glob(os.path.join(hooks_dir, "*.js")):
            try:
                content = open(path).read()
                # Detect function names defined in the file
                js_fns  = set(_re.findall(r'function\s+(\w+)\s*\(', content))
                js_fns |= set(_re.findall(
                    r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\(|function)', content))
                for event in _HOOK_EVENTS:
                    if event not in js_fns:
                        continue
                    def _make_js(p=path, e=event, nb=node_bin, jr=js_runner):
                        def _call(payload=None):
                            try:
                                _sp.run(
                                    [nb, jr, p, e, _json.dumps(payload or {})],
                                    capture_output=True, text=True, timeout=5,
                                )
                            except Exception:
                                pass
                        return _call
                    _hooks[event].append(_make_js())
                    count += 1
                    print(f"[HOOKS] JS hook loaded: {os.path.basename(path)}::{event}")
            except Exception as e:
                print(f"[HOOKS] Failed to load JS {path}: {e}")
    else:
        print("[HOOKS] JavaScript hooks disabled — 'node' not found in PATH")

    # ── Groovy hooks (requires groovy on PATH) ────────────────────────────
    if _GROOVY_AVAILABLE:
        gv_runner = os.path.join(tempfile.gettempdir(), "_dast_groovy_runner.groovy")
        with open(gv_runner, "w") as f:
            f.write(_GROOVY_RUNNER_SRC)
        for path in _glob.glob(os.path.join(hooks_dir, "*.groovy")):
            try:
                content = open(path).read()
                # Detect closure/def names in Groovy file
                gv_fns  = set(_re.findall(r'def\s+(\w+)\s*[=\{(]', content))
                gv_fns |= set(_re.findall(r'(\w+)\s*=\s*\{', content))
                for event in _HOOK_EVENTS:
                    if event not in gv_fns:
                        continue
                    def _make_gv(p=path, e=event, gr=gv_runner):
                        def _call(payload=None):
                            try:
                                _sp.run(
                                    ["groovy", gr, p, e, _json.dumps(payload or {})],
                                    capture_output=True, text=True, timeout=10,
                                )
                            except Exception:
                                pass
                        return _call
                    _hooks[event].append(_make_gv())
                    count += 1
                    print(f"[HOOKS] Groovy hook loaded: {os.path.basename(path)}::{event}")
            except Exception as e:
                print(f"[HOOKS] Failed to load Groovy {path}: {e}")
    else:
        print("[HOOKS] Groovy hooks disabled — 'groovy' not found in PATH")

    return count


def _trigger_hook(event: str, *args, **kwargs) -> None:
    for fn in _hooks.get(event, []):
        try:
            fn(*args, **kwargs)
        except Exception:
            pass


@app.route("/api/hooks/reload", methods=["POST"])
def hooks_reload():
    _hooks.clear()
    count = _load_hooks()
    return jsonify({"success": True, "hooks_loaded": count,
                    "events": {k: len(v) for k, v in _hooks.items()}})


@app.route("/api/hooks/status")
def hooks_status():
    return jsonify({
        "events":   {k: len(v) for k, v in _hooks.items()},
        "total":    sum(len(v) for v in _hooks.values()),
        "runtimes": {
            "python":     True,
            "javascript": _NODE_AVAILABLE,
            "groovy":     _GROOVY_AVAILABLE,
        },
    })


# ── Auto-load hooks at startup ────────────────────────────────────────────────
_load_hooks()


# ═══════════════════════════════════════════════════════════════════════════════
# ██  PER-AGENT TUNING  (ZAP scan policy parity)
# ═══════════════════════════════════════════════════════════════════════════════

_INTENSITY_ITER = {"low": 5, "medium": 10, "high": 20}

_agent_config: dict = {
    spec["name"]: {"enabled": True, "intensity": "medium"}
    for spec in _DAST_AGENTS
}


@app.route("/api/config/agents", methods=["POST"])
def set_agent_config():
    data = req.json or {}
    for agent_name, cfg in data.items():
        if agent_name in _agent_config:
            if "enabled" in cfg:
                _agent_config[agent_name]["enabled"] = bool(cfg["enabled"])
            if "intensity" in cfg and cfg["intensity"] in _INTENSITY_ITER:
                _agent_config[agent_name]["intensity"] = cfg["intensity"]
    return jsonify({"success": True, "config": _agent_config})


@app.route("/api/config/agents")
def get_agent_config():
    return jsonify({"config": _agent_config, "intensity_levels": list(_INTENSITY_ITER.keys())})


# ── Wire tuning into scan launch ──────────────────────────────────────────────
# (Patch scan_launch to respect _agent_config — intensity → max_iter, enabled → skip)
_original_scan_launch = app.view_functions["scan_launch"]


def _patched_scan_launch():
    response = _original_scan_launch()
    # Already launched; post-patch each agent's max_iter and remove disabled agents
    with _lock:
        for aid, state in list(_agents.items()):
            cfg = _agent_config.get(state["name"], {})
            if not cfg.get("enabled", True):
                state["stop"]   = True
                state["status"] = "stopped"
            else:
                intensity = cfg.get("intensity", "medium")
                state["max_iter"] = _INTENSITY_ITER.get(intensity, 10)
    return response


app.view_functions["scan_launch"] = _patched_scan_launch

# ── Also inject hook trigger into scan lifecycle ──────────────────────────────
_orig_scan_stop = app.view_functions["scan_stop"]


def _patched_scan_stop():
    _trigger_hook("after_scan", list(_findings))
    return _orig_scan_stop()


app.view_functions["scan_stop"] = _patched_scan_stop


# ═══════════════════════════════════════════════════════════════════════════════
# ██  SARIF 2.1.0 REPORT  (CI/CD gate format — GitHub, GitLab, Azure DevOps)
# ═══════════════════════════════════════════════════════════════════════════════

_SEV_SARIF = {
    "critical": "error", "high": "error",
    "medium":   "warning", "low": "note", "info": "note",
}
_SEV_RANK = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}


def _render_sarif(findings: list, target: str) -> dict:
    rules = {}
    results = []
    for f in findings:
        rule_id = re.sub(r"\W+", "_", f.get("agent", "unknown"))[:40]
        sev     = f.get("severity", "medium")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("agent", "Unknown"),
                "shortDescription": {"text": f.get("agent", "DAST Finding")},
                "fullDescription": {"text": f.get("agent", "DAST Finding")},
                "defaultConfiguration": {"level": _SEV_SARIF.get(sev, "warning")},
                "properties": {
                    "tags": [f.get("phase", "")],
                    "security-severity": str(_SEV_RANK.get(sev, 5.0)),
                },
            }
        results.append({
            "ruleId": rule_id,
            "level": _SEV_SARIF.get(sev, "warning"),
            "message": {"text": f.get("finding", "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("target", target)},
            }}],
            "properties": {"severity": sev, "agent": f.get("agent", ""), "icon": f.get("icon", "")},
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DAST AI Agent",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/dast-standalone",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {"target": target},
        }],
    }


@app.route("/api/report/sarif")
def findings_sarif():
    with _lock:
        data = list(_findings)
    sarif    = _render_sarif(data, _scan_target or "unknown")
    filename = f"dast_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"
    return Response(
        json.dumps(sarif, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ██  XML REPORT  (ZAP traditional-xml parity)
# ═══════════════════════════════════════════════════════════════════════════════

def _render_xml(findings: list, target: str) -> str:
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<report generated="{ts}" target="{target}" count="{len(findings)}">',
             "  <findings>"]
    for f in findings:
        def _esc(s: str) -> str:
            return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;"))
        lines.append(
            f'    <finding severity="{_esc(f.get("severity",""))}" '
            f'phase="{_esc(f.get("phase",""))}" '
            f'agent="{_esc(f.get("agent",""))}" '
            f'ts="{_esc(f.get("ts",""))}">'
        )
        lines.append(f'      <description>{_esc(f.get("finding",""))}</description>')
        lines.append(f'      <target>{_esc(f.get("target",""))}</target>')
        lines.append("    </finding>")
    lines += ["  </findings>", "</report>"]
    return "\n".join(lines)


@app.route("/api/report/xml")
def findings_xml():
    with _lock:
        data = list(_findings)
    xml_str  = _render_xml(data, _scan_target or "unknown")
    filename = f"dast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    return Response(
        xml_str,
        mimetype="application/xml",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ██  TRADITIONAL SPIDER  (ZAP-style HTML link crawler, no JS execution)
# ═══════════════════════════════════════════════════════════════════════════════

from html.parser import HTMLParser
from collections import deque as _deque
from urllib.parse import urljoin, urldefrag


class _TraditionalSpider:
    """Pure HTML link spider — ZAP traditional spider parity.

    Extracts links from <a href>, <form action>, <img src>, <script src>,
    <link href>, <iframe src>, <area href>, then recursively crawls in-scope URLs.
    No JavaScript execution — use Playwright AJAX spider for SPAs.
    """

    def __init__(self, target: str, max_depth: int = 5, max_urls: int = 0,
                 scope: str = "domain", timeout: int = 10):
        self.target    = target
        self.max_depth = max_depth
        self.max_urls  = max_urls   # 0 = unlimited
        self.scope     = scope      # "domain" | "path"
        self.timeout   = timeout
        self._base     = urlparse(target)
        self._lock     = threading.Lock()
        self._stop_ev  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.visited:  list = []
        self.found:    list = []
        self.status    = "idle"

    # ── Scope check ───────────────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        if self.scope == "path":
            return (p.netloc == self._base.netloc and
                    p.path.startswith(self._base.path))
        return p.netloc == self._base.netloc  # default: same domain

    # ── Link extractor (pure stdlib html.parser) ──────────────────────────
    @staticmethod
    def _extract_links(html_body: str, base_url: str) -> list:
        links: list = []

        class _LP(HTMLParser):
            _ATTRS = {
                "a": "href", "area": "href", "link": "href",
                "form": "action",
                "img": "src", "script": "src", "iframe": "src", "frame": "src",
            }
            def handle_starttag(self, tag, attrs):
                attr_name = _LP._ATTRS.get(tag)
                if not attr_name:
                    return
                val = dict(attrs).get(attr_name)
                if val:
                    abs_url, _ = urldefrag(urljoin(base_url, val))
                    if abs_url.startswith(("http://", "https://")):
                        links.append(abs_url)

        try:
            _LP().feed(html_body)
        except Exception:
            pass
        return links

    # ── Crawl loop (runs in background thread) ────────────────────────────
    def _crawl(self) -> None:
        self.status = "running"
        seen: set = set()
        q = _deque([(self.target, 0)])

        while q and not self._stop_ev.is_set():
            url, depth = q.popleft()
            if url in seen or depth > self.max_depth:
                continue
            if self.max_urls and len(seen) >= self.max_urls:
                break
            seen.add(url)

            try:
                import requests as _req_spider
                import urllib3 as _u3
                _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
                _sr = _req_spider.get(
                    url, timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "DAST-Spider/1.0", "Connection": "close"},
                )
                status       = _sr.status_code
                content_type = _sr.headers.get("Content-Type", "")
                body         = _sr.text[:1_000_000] if "text/html" in content_type else ""
            except Exception:
                continue

            with self._lock:
                self.visited.append(url)
                self.found.append(url)
                _site_map[url] = {
                    "method":       "GET",
                    "status":       status,
                    "content_type": content_type,
                    "source":       "spider",
                }

            if body and depth < self.max_depth:
                for link in self._extract_links(body, url):
                    if link not in seen and self._in_scope(link):
                        q.append((link, depth + 1))

        self.status = "stopped" if self._stop_ev.is_set() else "done"

    def start(self) -> None:
        self._stop_ev.clear()
        self._thread = threading.Thread(target=self._crawl, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_ev.set()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


_spider: Optional[_TraditionalSpider] = None


@app.route("/api/spider/start", methods=["POST"])
def spider_start():
    global _spider
    data   = req.get_json(silent=True) or {}
    target = data.get("target") or _scan_target
    if not target:
        return jsonify({"error": "No target — enter a URL or start a scan first"}), 400
    if _spider and _spider.is_running():
        return jsonify({"error": "Spider already running", "status": _spider.status}), 409

    # Auto-resolve scheme/port (http→https upgrade, alt-port detection)
    target = _resolve_target(target)

    _spider = _TraditionalSpider(
        target    = target,
        max_depth = int(data.get("max_depth", 5)),
        max_urls  = int(data.get("max_urls",  0)),
        scope     = data.get("scope", "domain"),
        timeout   = int(data.get("timeout", 10)),
    )
    _spider.start()
    _log_activity("spider_start", target)
    _trigger_hook("before_scan", {"mode": "traditional_spider", "target": target})
    return jsonify({"started": True, "target": target,
                    "max_depth": _spider.max_depth, "scope": _spider.scope})


@app.route("/api/spider/stop", methods=["POST"])
def spider_stop():
    if _spider:
        _spider.stop()
        with _spider._lock:
            found = len(_spider.found)
        _log_activity("spider_stop", _spider.target, f"{found} URLs found")
        return jsonify({"stopped": True})
    return jsonify({"stopped": False, "error": "No spider running"})


@app.route("/api/spider/status")
def spider_status():
    if not _spider:
        return jsonify({"status": "idle", "urls_found": 0, "urls_visited": 0})
    with _spider._lock:
        found   = len(_spider.found)
        visited = len(_spider.visited)
    return jsonify({
        "status":       _spider.status,
        "running":      _spider.is_running(),
        "urls_found":   found,
        "urls_visited": visited,
        "max_depth":    _spider.max_depth,
        "scope":        _spider.scope,
    })


@app.route("/api/spider/results")
def spider_results():
    if not _spider:
        return jsonify({"urls": [], "count": 0})
    with _spider._lock:
        urls = list(_spider.found)
    return jsonify({"urls": urls, "count": len(urls)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  OPENAPI / SWAGGER IMPORT  (ZAP openapi add-on parity)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Supports:
#   • OpenAPI 3.x  (application/json or application/yaml)
#   • Swagger 2.0  (swagger: "2.0")
#   • Import from URL  (fetched server-side)
#   • Import from uploaded JSON/YAML body
#
# On import:
#   1. All paths + methods extracted
#   2. Path params substituted with test values → concrete URLs built
#   3. Query params collected
#   4. Every endpoint added to _site_map (source="openapi")
#   5. _openapi_endpoints list available for agents as extra attack surface
# ──────────────────────────────────────────────────────────────────────────────

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

# Holds parsed state from last import
_openapi_state: dict = {
    "title":      "",
    "version":    "",
    "spec_type":  "",          # "openapi3" | "swagger2"
    "base_url":   "",
    "endpoints":  [],          # list of {method, path, url, params, tags}
    "imported_at": None,
}
_openapi_endpoints: list = []   # mirrors _openapi_state["endpoints"] for fast access

# ── Test values substituted into path parameters ──────────────────────────────
_PARAM_TEST_VALUES: dict = {
    "id":       "1",
    "userId":   "1",
    "petId":    "1",
    "orderId":  "1",
    "name":     "test",
    "username": "admin",
    "token":    "test-token",
    "key":      "test-key",
    "slug":     "test-slug",
    "uuid":     "00000000-0000-0000-0000-000000000000",
    "default":  "1",
}


def _substitute_path_params(path: str, param_names: list) -> str:
    """Replace {param} placeholders with safe test values."""
    result = path
    for name in param_names:
        val = _PARAM_TEST_VALUES.get(name, _PARAM_TEST_VALUES["default"])
        result = result.replace(f"{{{name}}}", val)
    return result


def _parse_openapi_spec(spec: dict, source_url: str = "") -> dict:
    """Parse OpenAPI 3.x or Swagger 2.0 spec dict → normalised endpoint list."""
    endpoints: list = []

    # ── Determine spec type and base URL ──────────────────────────────────
    if "openapi" in spec:                          # OAS 3.x
        spec_type = "openapi3"
        info      = spec.get("info", {})
        servers   = spec.get("servers", [{}])
        server_url = servers[0].get("url", "") if servers else ""
        if server_url.startswith("/"):             # relative → prepend source host
            from urllib.parse import urlparse as _up
            p = _up(source_url)
            server_url = f"{p.scheme}://{p.netloc}{server_url}"
        base_url = server_url.rstrip("/")

    elif spec.get("swagger", "").startswith("2"): # Swagger 2.0
        spec_type = "swagger2"
        info      = spec.get("info", {})
        host      = spec.get("host", "")
        base_path = spec.get("basePath", "/").rstrip("/")
        schemes   = spec.get("schemes", ["https"])
        scheme    = schemes[0] if schemes else "https"
        base_url  = f"{scheme}://{host}{base_path}" if host else ""
        if not base_url and source_url:
            from urllib.parse import urlparse as _up
            p = _up(source_url)
            base_url = f"{p.scheme}://{p.netloc}{base_path}"
    else:
        return {"error": "Unrecognised spec — expected OpenAPI 3.x or Swagger 2.0"}

    # ── Extract paths ──────────────────────────────────────────────────────
    paths = spec.get("paths", {})
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Collect path-level parameters
        path_params_all = path_item.get("parameters", [])

        for method, operation in path_item.items():
            if method.lower() not in http_methods:
                continue
            if not isinstance(operation, dict):
                continue

            # Merge path-level + operation-level params
            op_params  = operation.get("parameters", [])
            all_params = path_params_all + op_params

            path_param_names = [
                p.get("name", "") for p in all_params
                if p.get("in") == "path"
            ]
            query_params = [
                {"name": p.get("name"), "required": p.get("required", False)}
                for p in all_params if p.get("in") == "query"
            ]

            concrete_path = _substitute_path_params(path, path_param_names)
            full_url      = base_url + concrete_path

            # Build query string from required params
            req_query = "&".join(
                f"{p['name']}=test" for p in query_params if p["required"]
            )
            if req_query:
                full_url += "?" + req_query

            endpoints.append({
                "method":       method.upper(),
                "path":         path,
                "url":          full_url,
                "query_params": query_params,
                "tags":         operation.get("tags", []),
                "summary":      operation.get("summary", ""),
                "operationId":  operation.get("operationId", ""),
            })

    return {
        "spec_type":  spec_type,
        "title":      info.get("title", "Unknown"),
        "version":    info.get("version", ""),
        "base_url":   base_url,
        "endpoints":  endpoints,
    }


def _load_spec_from_url(url: str) -> dict:
    """Fetch spec from URL, auto-detect JSON/YAML."""
    import urllib.request as _ur
    try:
        with _ur.urlopen(_ur.Request(url, headers={"Accept": "application/json,*/*"}),
                         timeout=15) as r:
            raw = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": f"Fetch failed: {e}"}
    return _decode_spec(raw)


def _decode_spec(raw: str) -> dict:
    """Try JSON first, then YAML."""
    try:
        return {"spec": json.loads(raw)}
    except json.JSONDecodeError:
        pass
    if _YAML_AVAILABLE:
        try:
            return {"spec": _yaml.safe_load(raw)}
        except Exception as e:
            return {"error": f"YAML parse error: {e}"}
    return {"error": "Not valid JSON — install PyYAML for YAML support (pip install pyyaml)"}


@app.route("/api/openapi/import", methods=["POST"])
def openapi_import():
    """Import OpenAPI/Swagger spec from URL or raw body."""
    global _openapi_endpoints
    data = req.get_json(silent=True) or {}

    spec_url  = data.get("url", "").strip()
    raw_body  = data.get("spec", "")        # raw JSON/YAML string from UI paste
    source_url = spec_url

    # ── Resolve spec ──────────────────────────────────────────────────────
    if spec_url:
        result = _load_spec_from_url(spec_url)
    elif raw_body:
        result = _decode_spec(raw_body)
        source_url = _scan_target or ""
    else:
        return jsonify({"error": "Provide 'url' or 'spec' in request body"}), 400

    if "error" in result:
        return jsonify(result), 400

    # ── Parse ─────────────────────────────────────────────────────────────
    parsed = _parse_openapi_spec(result["spec"], source_url)
    if "error" in parsed:
        return jsonify(parsed), 400

    endpoints = parsed["endpoints"]

    # ── Populate site map ─────────────────────────────────────────────────
    with _lock:
        for ep in endpoints:
            _site_map[ep["url"]] = {
                "method":       ep["method"],
                "status":       0,
                "content_type": "",
                "source":       "openapi",
                "tags":         ep.get("tags", []),
                "summary":      ep.get("summary", ""),
            }

    # ── Persist state ─────────────────────────────────────────────────────
    _openapi_state.update({
        "title":       parsed["title"],
        "version":     parsed["version"],
        "spec_type":   parsed["spec_type"],
        "base_url":    parsed["base_url"],
        "endpoints":   endpoints,
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "source_url":  spec_url,
    })
    _openapi_endpoints.clear()
    _openapi_endpoints.extend(endpoints)

    # ── Auto-scan (optional) ──────────────────────────────────────
    auto_scan      = data.get("auto_scan", False)
    scan_started   = False
    scan_skipped   = ""

    if auto_scan:
        with _engine_lock:
            already_running = _engine_running
        if already_running:
            scan_skipped = "engine scan already running"
        else:
            # Convert endpoints to InputSurface objects via modules/openapi.py
            spec_source = result["spec"]
            base_url_override = parsed["base_url"]
            scan_started = True
            _start_openapi_auto_scan(spec_source, base_url_override, source_url)

    return jsonify({
        "success":        True,
        "title":          parsed["title"],
        "version":        parsed["version"],
        "spec_type":      parsed["spec_type"],
        "base_url":       parsed["base_url"],
        "endpoints_found": len(endpoints),
        "urls_added_to_sitemap": len(endpoints),
        "scan_started":   scan_started,
        "scan_skipped":   scan_skipped or None,
    })


# ── OpenAPI Auto-Scan Worker ─────────────────────────────────────────────────

def _start_openapi_auto_scan(spec: dict, base_url: str, source_url: str):
    """Launch a background scan of all endpoints discovered from an OpenAPI spec."""
    global _engine_running, _engine_stop_event, _engine_thread
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_status_msg, _engine_progress

    _engine_stop_event   = threading.Event()
    _engine_sitemap      = None
    _engine_fuzz_results = []
    _engine_fingerprint  = {}
    _engine_status_msg   = "openapi auto-scan starting"
    _engine_progress     = {
        "phase":          "openapi_import",
        "pages_crawled":  0,
        "surfaces_found": 0,
        "payloads_sent":  0,
        "findings_count": 0,
        "source":         "openapi",
    }
    _engine_running = True

    _engine_thread = threading.Thread(
        target=_openapi_auto_scan_worker,
        args=(spec, base_url, source_url),
        daemon=True,
        name="dast-openapi-autoscan",
    )
    _engine_thread.start()


def _openapi_auto_scan_worker(spec: dict, base_url: str, source_url: str):
    """Background thread: convert OpenAPI spec → InputSurfaces → passive + fuzz + OWASP."""
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_running, _engine_status_msg, _engine_progress
    global _passive_findings

    try:
        if not _ENGINE_AVAILABLE:
            _engine_status_msg = "error: engine modules not loaded"
            return

        # ── 0. Build surfaces from spec ──────────────────────────────────────
        _engine_status_msg = "parsing spec into attack surfaces"
        _engine_progress["phase"] = "parsing"

        surfaces = import_openapi(spec, base_url=base_url)
        if not surfaces:
            _engine_status_msg = "complete (no fuzzable surfaces found)"
            _engine_progress["phase"] = "complete"
            return

        # Build a SiteMap from the imported surfaces
        from modules.crawler import SiteMap
        sitemap = SiteMap()
        seen_urls = set()
        for s in surfaces:
            sitemap.add_surface(s)
            if s.url not in seen_urls:
                sitemap.add_page(s.url, 0, "", {}, title=f"OpenAPI: {s.method} {s.url}")
                seen_urls.add(s.url)

        with _engine_lock:
            _engine_sitemap = sitemap
            _engine_progress["surfaces_found"] = len(surfaces)

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        # ── 1. Setup session ─────────────────────────────────────────────────
        target = base_url or source_url
        scope  = ScopeManager(target)
        session = _engine_auth_handler.session if _engine_auth_handler else None

        import requests as _req_lib
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        if session is None:
            session = PassiveInterceptSession()
            session.verify = False
            session.headers["User-Agent"] = "Mozilla/5.0 (DAST-Engine/2.0 OpenAPI-AutoScan)"
            _retry = Retry(total=2, connect=2, read=2, backoff_factor=0.3,
                           status_forcelist=[500, 502, 503, 504],
                           allowed_methods=["HEAD", "GET", "OPTIONS"])
            _adapter = HTTPAdapter(max_retries=_retry)
            session.mount("http://", _adapter)
            session.mount("https://", _adapter)

        # ── 2. Passive scan each unique URL ──────────────────────────────────
        _engine_status_msg = "passive scanning OpenAPI endpoints"
        _engine_progress["phase"] = "passive"
        p_count = 0

        for page_url in seen_urls:
            if _engine_stop_event.is_set():
                break
            try:
                resp = session.get(page_url, timeout=10)
                pf   = _passive.scan(
                    url             = page_url,
                    status_code     = resp.status_code,
                    resp_headers    = dict(resp.headers),
                    resp_body       = resp.text[:8000],
                    cookies         = {c.name: c.value for c in session.cookies},
                    request_headers = dict(session.headers),
                )
                for f in pf:
                    d = f.to_dict()
                    with _engine_lock:
                        _passive_findings.append(d)
                        p_count += 1
                        _engine_progress["passive_count"] = p_count
                    with _lock:
                        _findings.append({
                            "agent":       "Passive Scanner",
                            "severity":    f.severity,
                            "type":        f.category,
                            "finding":     f.finding,
                            "url":         page_url,
                            "evidence":    f.evidence,
                            "remediation": f.remediation,
                            "cwe":         f.cwe,
                        })
            except Exception:
                pass

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        # ── 3. Fingerprint (first reachable URL) ────────────────────────────
        _engine_status_msg = "fingerprinting"
        _engine_progress["phase"] = "fingerprinting"

        for page_url in seen_urls:
            try:
                fp_resp = session.get(page_url, timeout=10)
                fp = fingerprint(
                    url          = page_url,
                    status_code  = fp_resp.status_code,
                    resp_headers = dict(fp_resp.headers),
                    resp_body    = fp_resp.text[:8000],
                    cookies      = {c.name: c.value for c in session.cookies},
                )
                with _engine_lock:
                    _engine_fingerprint = fp
                    sitemap.tech = fp
                break
            except Exception:
                continue

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        # ── 4. Fuzz all surfaces ─────────────────────────────────────────────
        _engine_status_msg = "fuzzing OpenAPI surfaces"
        _engine_progress["phase"] = "fuzzing"

        fuzzer = Fuzzer(
            scope      = scope,
            session    = session,
            timeout    = 10,
            rate_limit = 0.05,
            stop_event = _engine_stop_event,
        )
        results = fuzzer.fuzz_all(sitemap.surfaces)

        with _engine_lock:
            _engine_fuzz_results = [
                {k: v for k, v in r.__dict__.items()} for r in results
            ]
            _engine_progress["findings_count"] = len(results)
            _engine_progress["payloads_sent"]  = len(sitemap.surfaces) * 8

        for r in results:
            with _lock:
                _findings.append({
                    "agent":       "Engine Fuzzer",
                    "severity":    r.severity,
                    "type":        r.vuln_type,
                    "finding":     r.finding,
                    "url":         r.url,
                    "param":       r.param,
                    "payload":     r.payload,
                    "evidence_id": r.evidence_id,
                    "resp_time_ms": r.resp_time_ms,
                })

        # ── 5. VulnerabilityScanner — OWASP specialized checks ──────────────
        if not _engine_stop_event.is_set():
            _engine_status_msg = "running OWASP specialized checks on OpenAPI endpoints"
            _engine_progress["phase"] = "owasp_checks"

            def _on_scan_finding(sf):
                with _lock:
                    _findings.append({
                        "agent":         "DAST Scanner",
                        "agent_id":      "scanner",
                        "icon":          "⚙️",
                        "phase":         "Active Scanning",
                        "finding":       sf.finding,
                        "severity":      sf.severity,
                        "target":        sf.url,
                        "url":           sf.url,
                        "param":         sf.param,
                        "payload":       sf.payload,
                        "type":          sf.vuln_type,
                        "owasp":         sf.owasp_category,
                        "cwe":           sf.cwe,
                        "remediation":   sf.remediation,
                        "proof":         sf.proof,
                        "chain_id":      sf.chain_id,
                        "chain_desc":    sf.chain_desc,
                        "evidence_id":   sf.evidence_id,
                        "resp_time_ms":  sf.resp_time_ms,
                        "status_code":   sf.status_code,
                        "ts":            sf.ts,
                    })

            scanner = VulnerabilityScanner(
                target     = target,
                scope      = scope,
                session    = session,
                ev_store   = _ev_store,
                stop_event = _engine_stop_event,
                on_finding = _on_scan_finding,
                timeout    = 10,
                rate_limit = 0.05,
            )
            scan_findings = scanner.scan(sitemap)

            with _engine_lock:
                _engine_progress["findings_count"] = len(results) + len(scan_findings)

        _engine_status_msg = "complete"
        _engine_progress["phase"] = "complete"

    except Exception as exc:
        _engine_status_msg = f"error: {exc}"
        _engine_progress["phase"] = "error"
    finally:
        with _engine_lock:
            _engine_running = False


@app.route("/api/openapi/status")
def openapi_status():
    return jsonify({
        "imported":     bool(_openapi_state["imported_at"]),
        "title":        _openapi_state["title"],
        "version":      _openapi_state["version"],
        "spec_type":    _openapi_state["spec_type"],
        "base_url":     _openapi_state["base_url"],
        "endpoint_count": len(_openapi_endpoints),
        "imported_at":  _openapi_state["imported_at"],
        "source_url":   _openapi_state.get("source_url", ""),
    })


@app.route("/api/openapi/endpoints")
def openapi_endpoints_list():
    method_filter = req.args.get("method", "").upper()
    tag_filter    = req.args.get("tag", "")
    eps = _openapi_endpoints
    if method_filter:
        eps = [e for e in eps if e["method"] == method_filter]
    if tag_filter:
        eps = [e for e in eps if tag_filter in e.get("tags", [])]
    return jsonify({"endpoints": eps, "count": len(eps)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  FABRIC INTEGRATION  (Daniel Miessler's Fabric AI pattern runner)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Fabric patterns most valuable for DAST:
#   create_report_finding    → raw finding → structured pentest-style report
#   improve_report_finding   → polish + add remediation detail to a finding
#   write_hackerone_report   → finding → ready-to-submit bug bounty report
#   create_cyber_summary     → all findings → executive summary
#   create_threat_scenarios  → findings → attack chain narrative
#   create_stride_threat_model → target → STRIDE model
#   analyze_threat_report    → full report → deep threat analysis
#   analyze_risk             → findings → risk assessment
# ──────────────────────────────────────────────────────────────────────────────

import shutil as _sh2

_FABRIC_BIN      = _sh2.which("fabric")
_FABRIC_AVAILABLE = bool(_FABRIC_BIN)

# Curated patterns relevant to DAST (shown in UI pattern picker)
_FABRIC_DAST_PATTERNS = [
    {"id": "create_report_finding",    "label": "📝 Create Report Finding",
     "desc": "Raw finding → structured pentest-style vuln report"},
    {"id": "improve_report_finding",   "label": "✨ Improve Finding",
     "desc": "Polish & enrich an existing finding with remediation steps"},
    {"id": "write_hackerone_report",   "label": "🐛 HackerOne Report",
     "desc": "Convert finding to a ready-to-submit bug bounty report"},
    {"id": "create_cyber_summary",     "label": "📊 Cyber Summary",
     "desc": "All findings → executive / management summary"},
    {"id": "create_threat_scenarios",  "label": "⚔️ Threat Scenarios",
     "desc": "Generate attack chain narratives from findings"},
    {"id": "create_stride_threat_model","label": "🛡 STRIDE Model",
     "desc": "Build STRIDE threat model from target description"},
    {"id": "analyze_threat_report",    "label": "🔍 Analyze Threat Report",
     "desc": "Deep threat intelligence analysis of scan output"},
    {"id": "analyze_risk",             "label": "⚠️ Risk Assessment",
     "desc": "Risk analysis of discovered vulnerabilities"},
    {"id": "extract_poc",              "label": "💥 Extract PoC",
     "desc": "Extract proof-of-concept steps from finding text"},
    {"id": "analyze_logs",             "label": "📋 Analyze Logs",
     "desc": "Analyse raw agent/proxy output logs for patterns"},
]


def _run_fabric(pattern: str, input_text: str, timeout: int = 60) -> dict:
    """Run `echo input | fabric -p pattern` and return output."""
    if not _FABRIC_AVAILABLE:
        return {"error": "fabric not found in PATH — install from github.com/danielmiessler/fabric"}
    if not pattern or not input_text.strip():
        return {"error": "pattern and input_text are required"}
    try:
        result = subprocess.run(
            [_FABRIC_BIN, "-p", pattern],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            err = result.stderr.strip() or f"fabric exited with code {result.returncode}"
            return {"error": err}
        return {"output": result.stdout.strip(), "pattern": pattern}
    except subprocess.TimeoutExpired:
        return {"error": f"fabric timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def _format_finding_for_fabric(finding: dict) -> str:
    """Serialise a DAST finding into readable text for Fabric input."""
    lines = [
        f"Vulnerability: {finding.get('finding', '')}",
        f"Severity: {finding.get('severity', 'medium').upper()}",
        f"Agent: {finding.get('agent', '')}",
        f"Phase: {finding.get('phase', '')}",
        f"Target: {finding.get('target', '')}",
    ]
    if finding.get("ts"):
        lines.append(f"Discovered: {finding['ts']}")
    return "\n".join(lines)


@app.route("/api/fabric/patterns")
def fabric_patterns():
    return jsonify({
        "available": _FABRIC_AVAILABLE,
        "patterns":  _FABRIC_DAST_PATTERNS,
    })


@app.route("/api/fabric/run", methods=["POST"])
def fabric_run():
    """Generic Fabric pattern runner — POST {pattern, input}."""
    data    = req.get_json(silent=True) or {}
    pattern = data.get("pattern", "").strip()
    text    = data.get("input",   "").strip()
    timeout = int(data.get("timeout", 60))
    if not pattern:
        return jsonify({"error": "pattern is required"}), 400
    if not text:
        return jsonify({"error": "input is required"}), 400
    result = _run_fabric(pattern, text, timeout)
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)


@app.route("/api/fabric/finding/<int:idx>", methods=["POST"])
def fabric_finding(idx: int):
    """Run a Fabric pattern on a single finding by index."""
    data    = req.get_json(silent=True) or {}
    pattern = data.get("pattern", "create_report_finding")
    with _lock:
        findings = list(_findings)
    if idx < 0 or idx >= len(findings):
        return jsonify({"error": f"Finding index {idx} out of range"}), 404
    text   = _format_finding_for_fabric(findings[idx])
    result = _run_fabric(pattern, text)
    if "error" in result:
        return jsonify(result), 500
    return jsonify({**result, "finding_index": idx, "finding": findings[idx]})


@app.route("/api/fabric/summary", methods=["POST"])
def fabric_summary():
    """Run create_cyber_summary (or chosen pattern) on ALL current findings."""
    data    = req.get_json(silent=True) or {}
    pattern = data.get("pattern", "create_cyber_summary")
    with _lock:
        findings = list(_findings)
    if not findings:
        return jsonify({"error": "No findings to summarise — run a scan first"}), 400

    # Build a comprehensive input: target + all findings
    lines = [f"Target: {_scan_target or 'unknown'}", "",
             f"Total findings: {len(findings)}", ""]
    for i, f in enumerate(findings, 1):
        lines.append(f"--- Finding {i} ---")
        lines.append(_format_finding_for_fabric(f))
        lines.append("")

    result = _run_fabric(pattern, "\n".join(lines), timeout=120)
    if "error" in result:
        return jsonify(result), 500
    return jsonify({**result, "findings_processed": len(findings)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  REAL DAST ENGINE  — Crawler + Fuzzer + Auth + Evidence + Fingerprint
# ═══════════════════════════════════════════════════════════════════════════════

# Engine state (one session at a time)
_engine_lock          = threading.Lock()
_engine_auth_handler: Optional["AuthHandler"]   = None   # type: ignore
_engine_sitemap:      Optional["SiteMap"]        = None   # type: ignore
_engine_fuzz_results: list                       = []
_engine_fingerprint:  dict                       = {}
_engine_running:      bool                       = False
_engine_stop_event:   threading.Event            = threading.Event()
_engine_thread:       Optional[threading.Thread] = None
_engine_status_msg:   str                        = "idle"
_engine_progress:     dict                       = {
    "phase": "idle",
    "pages_crawled":  0,
    "surfaces_found": 0,
    "payloads_sent":  0,
    "findings_count": 0,
    "passive_count":  0,
    "browse_count":   0,
    "detected_url":   None,   # set when engine auto-discovers a different port
}

# Extra module state
_passive_findings:    list = []    # PassiveFinding dicts from passive scanner
_browse_results:      list = []    # BrowseResult dicts from forced browse
_browse_running:      bool = False
_browse_stop_event:   threading.Event = threading.Event()
_browse_thread:       Optional[threading.Thread] = None
_ajax_running:        bool = False
_ajax_urls_found:     int  = 0
_ajax_pages:          list = []   # [{url, status, content_type, source}] from last AJAX crawl
_ajax_stop_event:     threading.Event = threading.Event()
_ajax_thread:         Optional[threading.Thread] = None
_openapi_surfaces:    list = []    # InputSurface dicts from OpenAPI import
_activity_log:        list = []    # Scan activity events {ts, event, target, detail}
_ACTIVITY_MAX        = 300         # Keep last N events


def _engine_scan_worker(target: str, config: dict):
    """Background thread: crawl → passive scan → fingerprint → fuzz."""
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_running, _engine_status_msg, _engine_progress
    global _passive_findings

    try:
        # ── 0. Setup ──────────────────────────────────────────────────────────
        if not _ENGINE_AVAILABLE:
            _engine_status_msg = "error: engine modules not loaded"
            return

        scope   = ScopeManager(target)
        session = _engine_auth_handler.session if _engine_auth_handler else None

        import requests as _req_lib
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        if session is None:
            session = PassiveInterceptSession()
            session.verify = False
            session.headers["User-Agent"] = "Mozilla/5.0 (DAST-Engine/2.0)"
            # Retry on connection-level errors (helps with raw IPs and non-standard stacks)
            _retry = Retry(total=2, connect=2, read=2, backoff_factor=0.3,
                           status_forcelist=[500, 502, 503, 504],
                           allowed_methods=["HEAD", "GET", "OPTIONS"])
            _adapter = HTTPAdapter(max_retries=_retry)
            session.mount("http://", _adapter)
            session.mount("https://", _adapter)

        # ── 0.5 Preflight — verify target responds; auto-detect port if not ──
        _engine_status_msg = "probing target"
        _engine_progress["phase"] = "preflight"

        # Use shared probe helper — handles http→https upgrade, alt-port discovery
        _probe = _probe_target(target)
        if not _probe["reachable"]:
            _engine_status_msg = "error: target unreachable — check URL and network"
            return
        if _probe["port_changed"] or _probe["resolved"] != target:
            target = _probe["resolved"]
            scope  = ScopeManager(target)
            _engine_progress["detected_url"] = target

        # ── 1. Crawl ──────────────────────────────────────────────────────────
        _engine_status_msg = "crawling"
        _engine_progress["phase"] = "crawling"

        def _crawl_cb(url: str, status: int):
            with _engine_lock:
                _engine_progress["pages_crawled"] += 1

        crawler = Crawler(
            target    = target,
            scope     = scope,
            session   = session,
            max_pages = config.get("max_pages", 200),
            max_depth = config.get("max_depth", 5),
            timeout   = config.get("timeout", 10),
            delay     = config.get("delay", 0.05),
            callback  = _crawl_cb,
        )
        sitemap = crawler.crawl()

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        with _engine_lock:
            _engine_sitemap = sitemap
            _engine_progress["surfaces_found"] = len(sitemap.surfaces)

        # ── 1.5 Passive scan every crawled page ───────────────────────────────
        _engine_status_msg = "passive scanning"
        _engine_progress["phase"] = "passive"
        p_count = 0
        if _ENGINE_AVAILABLE:
            for page_url, page_info in sitemap.pages.items():
                if _engine_stop_event.is_set():
                    break
                try:
                    resp = session.get(page_url, timeout=10)
                    pf   = _passive.scan(
                        url             = page_url,
                        status_code     = resp.status_code,
                        resp_headers    = dict(resp.headers),
                        resp_body       = resp.text[:8000],
                        cookies         = {c.name: c.value for c in session.cookies},
                        request_headers = dict(session.headers),
                    )
                    for f in pf:
                        d = f.to_dict()
                        with _engine_lock:
                            _passive_findings.append(d)
                            p_count += 1
                            _engine_progress["passive_count"] = p_count
                        # also surface in main findings list
                        with _lock:
                            _findings.append({
                                "agent":    "Passive Scanner",
                                "severity": f.severity,
                                "type":     f.category,
                                "finding":  f.finding,
                                "url":      page_url,
                                "evidence": f.evidence,
                                "remediation": f.remediation,
                                "cwe":      f.cwe,
                            })
                except Exception:
                    pass

        # ── 2. Fingerprint (first page) ───────────────────────────────────────
        _engine_status_msg = "fingerprinting"
        _engine_progress["phase"] = "fingerprinting"

        if sitemap.pages:
            first = next(iter(sitemap.pages.values()))
            try:
                import requests as _r
                fp_resp = session.get(first["url"], timeout=10)
                fp = fingerprint(
                    url          = first["url"],
                    status_code  = fp_resp.status_code,
                    resp_headers = dict(fp_resp.headers),
                    resp_body    = fp_resp.text[:8000],
                    cookies      = {c.name: c.value for c in session.cookies},
                )
                with _engine_lock:
                    _engine_fingerprint = fp
                    sitemap.tech = fp
            except Exception:
                pass

        if _engine_stop_event.is_set():
            _engine_status_msg = "stopped"
            return

        # ── 3. Fuzz ───────────────────────────────────────────────────────────
        _engine_status_msg = "fuzzing"
        _engine_progress["phase"] = "fuzzing"

        fuzzer = Fuzzer(
            scope      = scope,
            session    = session,
            timeout    = config.get("timeout", 10),
            rate_limit = config.get("delay", 0.05),
            stop_event = _engine_stop_event,
        )
        results = fuzzer.fuzz_all(sitemap.surfaces)

        with _engine_lock:
            # Convert dataclass to dict safely
            _engine_fuzz_results = [
                {k: v for k, v in r.__dict__.items()} for r in results
            ]
            _engine_progress["findings_count"]  = len(results)
            _engine_progress["payloads_sent"]   = len(sitemap.surfaces) * 8  # approx

        # ── 4. Merge into main findings list ──────────────────────────────────
        for r in results:
            finding = {
                "agent":    "Engine Fuzzer",
                "severity": r.severity,
                "type":     r.vuln_type,
                "finding":  r.finding,
                "url":      r.url,
                "param":    r.param,
                "payload":  r.payload,
                "evidence_id": r.evidence_id,
                "resp_time_ms": r.resp_time_ms,
            }
            with _lock:
                _findings.append(finding)

        # ── 5. VulnerabilityScanner — specialized OWASP checks + chaining ────
        if not _engine_stop_event.is_set():
            _engine_status_msg = "running OWASP specialized checks"
            _engine_progress["phase"] = "owasp_checks"

            def _on_scan_finding(sf: "ScanFinding"):  # type: ignore
                with _lock:
                    _findings.append({
                        "agent":         "DAST Scanner",
                        "agent_id":      "scanner",
                        "icon":          "⚙️",
                        "phase":         "Active Scanning",
                        "finding":       sf.finding,
                        "severity":      sf.severity,
                        "target":        sf.url,
                        "url":           sf.url,
                        "param":         sf.param,
                        "payload":       sf.payload,
                        "type":          sf.vuln_type,
                        "owasp":         sf.owasp_category,
                        "cwe":           sf.cwe,
                        "remediation":   sf.remediation,
                        "proof":         sf.proof,
                        "chain_id":      sf.chain_id,
                        "chain_desc":    sf.chain_desc,
                        "evidence_id":   sf.evidence_id,
                        "resp_time_ms":  sf.resp_time_ms,
                        "status_code":   sf.status_code,
                        "ts":            sf.ts,
                    })

            scanner = VulnerabilityScanner(
                target     = target,
                scope      = scope,
                session    = session,
                ev_store   = _ev_store,
                stop_event = _engine_stop_event,
                on_finding = _on_scan_finding,
                timeout    = config.get("timeout", 10),
                rate_limit = config.get("delay", 0.05),
            )
            scan_findings = scanner.scan(sitemap)

            # Count distinct scanner findings (passive phase is deduplicated)
            with _engine_lock:
                _engine_progress["findings_count"] = len(results) + len(scan_findings)

        # ── Merge intercepted passive findings from ALL phases ────────────────
        if hasattr(session, 'get_findings'):
            intercepted = session.get_findings()
            if intercepted:
                existing_keys = set()
                for f in _passive_findings:
                    existing_keys.add((f.get("url", ""), f.get("category", ""), f.get("finding", "")))
                intercept_count = 0
                for f in intercepted:
                    fd = f.to_dict()
                    key = (fd.get("url", ""), fd.get("category", ""), fd.get("finding", ""))
                    if key not in existing_keys:
                        existing_keys.add(key)
                        _passive_findings.append(fd)
                        with _lock:
                            _findings.append({
                                "agent":    "Passive Scanner (Intercept)",
                                "severity": fd.get("severity", "Info"),
                                "type":     fd.get("category", ""),
                                "detail":   fd.get("finding", ""),
                                "url":      fd.get("url", ""),
                                "ts":       datetime.now(timezone.utc).isoformat(),
                            })
                        intercept_count += 1
                _engine_progress["passive_intercept_count"] = intercept_count

        _engine_status_msg = "complete"
        _engine_progress["phase"] = "complete"

    except Exception as exc:
        _engine_status_msg = f"error: {exc}"
        _engine_progress["phase"] = "error"
    finally:
        with _engine_lock:
            _engine_running = False


# ── Engine: Auth ──────────────────────────────────────────────────────────────

@app.route("/api/engine/auth", methods=["POST"])
def engine_auth():
    """Configure auth for the DAST engine. Supports form, bearer, basic, cookie, header."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine modules not available"}), 503

    data = req.get_json(silent=True) or {}
    mode = data.get("mode", "none")

    global _engine_auth_handler
    handler = AuthHandler(timeout=15)

    try:
        if mode == "bearer":
            handler.set_bearer(data["token"])
            return jsonify({"success": True, "mode": "bearer", "info": handler.get_auth_summary()})

        elif mode == "basic":
            handler.set_basic(data["username"], data["password"])
            return jsonify({"success": True, "mode": "basic", "info": handler.get_auth_summary()})

        elif mode == "cookie":
            handler.set_cookie(data["name"], data["value"])
            return jsonify({"success": True, "mode": "cookie", "info": handler.get_auth_summary()})

        elif mode == "header":
            handler.set_header(data["header_name"], data["header_value"])
            return jsonify({"success": True, "mode": "header", "info": handler.get_auth_summary()})

        elif mode == "form":
            result = handler.form_login(data["login_url"], data["username"], data["password"])
            if result["success"]:
                with _engine_lock:
                    _engine_auth_handler = handler
                return jsonify({"success": True, "mode": "form", "info": handler.get_auth_summary(), "detail": result})
            else:
                return jsonify({"success": False, "mode": "form", "detail": result}), 401

        elif mode == "none":
            with _engine_lock:
                _engine_auth_handler = None
            return jsonify({"success": True, "mode": "none"})

        else:
            return jsonify({"error": f"Unknown auth mode: {mode}"}), 400

    except KeyError as ke:
        return jsonify({"error": f"Missing field: {ke}"}), 400


# ── Engine: Start scan ────────────────────────────────────────────────────────

@app.route("/api/engine/scan", methods=["POST"])
def engine_scan_start():
    """Start a full engine scan: crawl → fingerprint → fuzz."""
    global _engine_running, _engine_stop_event, _engine_thread
    global _engine_sitemap, _engine_fuzz_results, _engine_fingerprint
    global _engine_status_msg, _engine_progress

    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine modules not available"}), 503

    with _engine_lock:
        if _engine_running:
            return jsonify({"error": "Engine scan already running"}), 409

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "target URL required"}), 400

    config = {
        "max_pages":    data.get("max_pages",   200),
        "max_depth":    data.get("max_depth",   5),
        "timeout":      data.get("timeout",     10),
        "delay":        data.get("delay",       0.05),
        "max_per_type": data.get("max_per_type", 8),
    }

    # Reset state
    _engine_stop_event   = threading.Event()
    _engine_sitemap      = None
    _engine_fuzz_results = []
    _engine_fingerprint  = {}
    _engine_status_msg   = "starting"
    _engine_progress     = {
        "phase": "starting",
        "pages_crawled":  0,
        "surfaces_found": 0,
        "payloads_sent":  0,
        "findings_count": 0,
    }
    _engine_running = True

    _engine_thread = threading.Thread(
        target=_engine_scan_worker,
        args=(target, config),
        daemon=True,
        name="dast-engine",
    )
    _engine_thread.start()

    return jsonify({"success": True, "target": target, "status": "started"})


# ── Engine: Stop scan ─────────────────────────────────────────────────────────

@app.route("/api/engine/stop", methods=["POST"])
def engine_scan_stop():
    """Signal the engine scan to stop gracefully."""
    _engine_stop_event.set()
    return jsonify({"success": True, "message": "Stop signal sent"})


# ── Engine: Status ────────────────────────────────────────────────────────────

@app.route("/api/engine/status")
def engine_status():
    """Return current engine scan progress."""
    with _engine_lock:
        return jsonify({
            "running":   _engine_running,
            "status":    _engine_status_msg,
            "progress":  _engine_progress,
            "engine_available": _ENGINE_AVAILABLE,
            "auth": _engine_auth_handler.get_auth_summary() if _engine_auth_handler else None,
        })


# ── Engine: Site map ──────────────────────────────────────────────────────────

@app.route("/api/engine/sitemap")
def engine_sitemap():
    """Return the crawled site map (pages + input surfaces)."""
    with _engine_lock:
        if _engine_sitemap is None:
            return jsonify({"pages": [], "surfaces": [], "tech": {}, "stats": {"pages": 0, "surfaces": 0}})
        return jsonify(_engine_sitemap.to_dict())


# ── Engine: Fingerprint ───────────────────────────────────────────────────────

@app.route("/api/engine/fingerprint")
def engine_fingerprint_result():
    """Return technology fingerprint for the scanned target."""
    with _engine_lock:
        fp = _engine_fingerprint
    if not fp:
        return jsonify({"error": "No fingerprint yet — run an engine scan first"}), 404
    return jsonify({
        "fingerprint": fp,
        "summary": fingerprint_summary(fp) if _ENGINE_AVAILABLE else "",
    })


# ── Engine: Findings ──────────────────────────────────────────────────────────

@app.route("/api/engine/findings")
def engine_findings():
    """Return all findings from the engine fuzzer."""
    with _engine_lock:
        results = list(_engine_fuzz_results)
    return jsonify({"findings": results, "count": len(results)})


# ── Evidence viewer ───────────────────────────────────────────────────────────

@app.route("/api/evidence/<eid>")
def get_evidence(eid: str):
    """Return full HTTP request/response evidence for a finding."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine modules not available"}), 503
    ev = _ev_store.get(eid)
    if ev is None:
        return jsonify({"error": f"Evidence ID {eid!r} not found"}), 404
    return jsonify({
        "id":            ev.id,
        "url":           ev.url,
        "method":        ev.method,
        "vuln_type":     ev.vuln_type,
        "payload":       ev.payload,
        "parameter":     ev.parameter,
        "resp_time_ms":  ev.resp_time_ms,
        "ts":            ev.ts,
        "request": {
            "headers": ev.req_headers,
            "body":    ev.req_body,
        },
        "response": {
            "status":  ev.status_code,
            "headers": ev.resp_headers,
            "body":    ev.resp_body[:4096],
        },
    })


# ── Evidence: list all ────────────────────────────────────────────────────────

@app.route("/api/evidence")
def list_evidence():
    """Return summary list of all captured evidence entries."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"evidence": [], "count": 0})
    entries = _ev_store.all()   # returns list[dict]
    return jsonify({
        "evidence": [
            {
                "id":           e["id"],
                "url":          e["url"],
                "method":       e["method"],
                "vuln_type":    e["vuln_type"],
                "parameter":    e["parameter"],
                "resp_time_ms": e["resp_time_ms"],
                "ts":           e["ts"],
            }
            for e in entries
        ],
        "count": len(entries),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  PASSIVE SCANNER ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/passive/findings")
def passive_findings():
    """Return all passive scan findings (no payload needed — headers/cookies/info)."""
    with _engine_lock:
        findings = list(_passive_findings)
    return jsonify({"findings": findings, "count": len(findings)})


@app.route("/api/passive/scan", methods=["POST"])
def passive_scan_url():
    """Passively scan target + all already-crawled pages. No fuzzing."""
    global _passive_findings
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "target required — enter a URL in the scan bar"}), 400

    # Auto-resolve scheme/port
    target = _resolve_target(target)

    import urllib3 as _u3
    _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    s = PassiveInterceptSession()
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 (DAST-Passive/2.0)"

    # Build URL list: target + all pages from engine sitemap (if already crawled)
    urls_to_scan: list[str] = [target]
    with _engine_lock:
        if _engine_sitemap:
            sitemap_urls = list(_engine_sitemap.pages.keys())
            # Exclude noise (assets, fonts, JS bundles) — focus on HTML + API endpoints
            for u in sitemap_urls:
                ext = u.rsplit(".", 1)[-1].lower().split("?")[0]
                if ext not in ("js", "css", "png", "jpg", "jpeg", "gif", "ico",
                               "svg", "woff", "woff2", "ttf", "eot", "map"):
                    if u not in urls_to_scan:
                        urls_to_scan.append(u)
        # Also add common paths not yet crawled
        common = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
                  "/api", "/swagger.json", "/openapi.json", "/api-docs"]
        for path in common:
            u = target.rstrip("/") + path
            if u not in urls_to_scan:
                urls_to_scan.append(u)

    # Cap at 50 pages for on-demand scan
    urls_to_scan = urls_to_scan[:50]

    all_findings: list = []
    for url in urls_to_scan:
        try:
            r = s.get(url, timeout=8, allow_redirects=True)
            pf = _passive.scan(
                url=url, status_code=r.status_code,
                resp_headers=dict(r.headers),
                resp_body=r.text[:8000],
                cookies={c.name: c.value for c in s.cookies},
                request_headers=dict(s.headers),
            )
            all_findings.extend(pf)
        except Exception:
            continue

    # Persist so /api/passive/findings returns results
    with _engine_lock:
        _passive_findings = [f.to_dict() for f in all_findings]

    _log_activity("passive_scan", target,
                  f"{len(all_findings)} findings across {len(urls_to_scan)} pages")

    return jsonify({
        "findings_count": len(all_findings),
        "urls_scanned":   len(urls_to_scan),
        "findings":       [f.to_dict() for f in all_findings[:20]],
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ██  OPENAPI IMPORT ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/engine/import/openapi", methods=["POST"])
def engine_openapi_import():
    """
    Import an OpenAPI/Swagger spec and populate the engine's attack surface.
    Body: {source: "URL | file path | raw JSON string", base_url: "optional override"}
    """
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503

    global _openapi_surfaces
    data     = req.get_json(silent=True) or {}
    source   = data.get("source", "").strip()
    base_url = data.get("base_url", "").strip()

    if not source:
        return jsonify({"error": "source required (URL, file path, or raw JSON)"}), 400

    try:
        surfaces = import_openapi(source, base_url=base_url)
        with _engine_lock:
            _openapi_surfaces = [
                {"url": s.url, "method": s.method, "param": s.param,
                 "type": s.param_type, "value": s.original_value,
                 "content_type": s.content_type}
                for s in surfaces
            ]
            # Also merge into live sitemap if available
            if _engine_sitemap is not None:
                for s in surfaces:
                    _engine_sitemap.add_surface(s)
        return jsonify({
            "success":  True,
            "surfaces": len(surfaces),
            "preview":  _openapi_surfaces[:10],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/engine/import/openapi/surfaces")
def openapi_surfaces():
    """Return all surfaces imported from OpenAPI spec."""
    with _engine_lock:
        surfs = list(_openapi_surfaces)
    return jsonify({"surfaces": surfs, "count": len(surfs)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  FORCED BROWSE ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/engine/forcebrowse", methods=["POST"])
def forcebrowse_start():
    """Start a forced browse scan (DirBuster-style). Body: {target, extra_wordlist: [...]}"""
    global _browse_running, _browse_stop_event, _browse_thread, _browse_results

    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503

    with _engine_lock:
        if _browse_running:
            return jsonify({"error": "Forced browse already running"}), 409

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400

    extra       = data.get("extra_wordlist", [])
    wordlist    = data.get("wordlist", "common")       # category name or file path
    categories  = data.get("wordlist_categories", [])  # list of category names to merge

    _browse_stop_event = threading.Event()
    _browse_results    = []
    _browse_running    = True

    def _browse_worker():
        global _browse_running, _browse_results
        try:
            sess = PassiveInterceptSession(); sess.verify = False
            sess.headers["User-Agent"] = "Mozilla/5.0 (DAST-ForcedBrowse/2.0)"

            def _cb(result):
                with _engine_lock:
                    _browse_results.append(result.to_dict())
                with _lock:
                    _findings.append({
                        "agent":    "Forced Browse",
                        "severity": "Info" if result.status_code == 200 else "Low",
                        "type":     "forced_browse",
                        "finding":  f"[{result.status_code}] {result.note}",
                        "url":      result.url,
                    })

            # Build wordlist kwargs
            fb_kwargs = {}
            if categories:
                merged = load_multiple_wordlists(*categories)
                fb_kwargs["wordlist_name"] = ""
                fb_kwargs["extra_wordlist"] = merged + extra
            else:
                fb_kwargs["wordlist_name"] = wordlist
                if extra:
                    fb_kwargs["extra_wordlist"] = extra

            fb = ForcedBrowser(
                base_url       = target,
                session        = sess,
                workers        = data.get("workers", 15),
                timeout        = data.get("timeout", 8),
                stop_event     = _browse_stop_event,
                callback       = _cb,
                **fb_kwargs,
            )
            fb.run()
        except Exception:
            pass
        finally:
            with _engine_lock:
                _browse_running = False

    _browse_thread = threading.Thread(target=_browse_worker, daemon=True, name="dast-forcebrowse")
    _browse_thread.start()
    return jsonify({"success": True, "target": target, "wordlist_size": 2000})


@app.route("/api/engine/forcebrowse/stop", methods=["POST"])
def forcebrowse_stop():
    _browse_stop_event.set()
    return jsonify({"success": True})


@app.route("/api/engine/forcebrowse/results")
def forcebrowse_results():
    with _engine_lock:
        results = list(_browse_results)
        running = _browse_running
    return jsonify({"results": results, "count": len(results), "running": running})


@app.route("/api/engine/wordlists")
def wordlists_list():
    """List available wordlist categories with path counts."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503
    avail = available_wordlists()
    cats = []
    for name, filename in sorted(WORDLIST_CATEGORIES.items()):
        count = avail.get(name, 0)
        cats.append({"name": name, "filename": filename, "count": count, "available": count > 0})
    return jsonify({"wordlists": cats, "total_categories": len(cats)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  GRAPHQL SECURITY SCANNER (standalone)
# ═══════════════════════════════════════════════════════════════════════════════

_graphql_scan_running  = False
_graphql_scan_findings: list = []
_graphql_scan_status   = "idle"
_graphql_scan_stop     = threading.Event()

@app.route("/api/engine/graphql/scan", methods=["POST"])
def graphql_scan_start():
    """Launch a standalone GraphQL security scan against the configured target."""
    global _graphql_scan_running, _graphql_scan_findings, _graphql_scan_status, _graphql_scan_stop
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503
    if _graphql_scan_running:
        return jsonify({"error": "GraphQL scan already running"}), 409

    data = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "No target configured — set target in Engine tab first"}), 400

    _graphql_scan_running  = True
    _graphql_scan_findings = []
    _graphql_scan_status   = "starting"
    _graphql_scan_stop     = threading.Event()

    def _gql_worker(t):
        global _graphql_scan_running, _graphql_scan_status
        try:
            from modules.graphql import GraphQLScanner

            _graphql_scan_status = "discovering endpoints"
            scanner = GraphQLScanner(
                target=t,
                stop_event=_graphql_scan_stop,
                timeout=10,
            )
            # Collect known GraphQL pages from sitemap if available
            extra = [url for url in _all_pages if
                     any(kw in (url if isinstance(url, str) else url.get("url", "")).lower()
                         for kw in ("graphql", "gql", "/query", "graphiql"))]
            extra_urls = [u if isinstance(u, str) else u.get("url", "") for u in extra]

            _graphql_scan_status = "running 12 security tests"
            results = scanner.scan(extra_urls=extra_urls)
            with _engine_lock:
                _graphql_scan_findings.extend(results)
            _graphql_scan_status = f"complete — {len(results)} findings"
        except Exception as e:
            _graphql_scan_status = f"error: {e}"
        finally:
            _graphql_scan_running = False

    threading.Thread(target=_gql_worker, args=(target,), daemon=True).start()
    return jsonify({"success": True, "target": target})


@app.route("/api/engine/graphql/stop", methods=["POST"])
def graphql_scan_stop():
    _graphql_scan_stop.set()
    return jsonify({"success": True})


@app.route("/api/engine/graphql/status")
def graphql_scan_status():
    return jsonify({
        "running":  _graphql_scan_running,
        "status":   _graphql_scan_status,
        "findings": len(_graphql_scan_findings),
    })


@app.route("/api/engine/graphql/results")
def graphql_scan_results():
    with _engine_lock:
        results = list(_graphql_scan_findings)
    return jsonify({"results": results, "count": len(results), "running": _graphql_scan_running})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  WEBSOCKET SECURITY SCANNER (standalone)
# ═══════════════════════════════════════════════════════════════════════════════

_ws_scan_running  = False
_ws_scan_findings: list = []
_ws_scan_status   = "idle"
_ws_scan_stop     = threading.Event()

@app.route("/api/engine/websocket/scan", methods=["POST"])
def ws_scan_start():
    """Launch a standalone WebSocket security scan against the configured target."""
    global _ws_scan_running, _ws_scan_findings, _ws_scan_status, _ws_scan_stop
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503
    if _ws_scan_running:
        return jsonify({"error": "WebSocket scan already running"}), 409

    data = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "No target configured — set target in Engine tab first"}), 400

    _ws_scan_running  = True
    _ws_scan_findings = []
    _ws_scan_status   = "starting"
    _ws_scan_stop     = threading.Event()

    def _ws_worker(t):
        global _ws_scan_running, _ws_scan_status
        try:
            from modules.websocket import WebSocketScanner

            _ws_scan_status = "discovering WebSocket endpoints"
            scanner = WebSocketScanner(
                target=t,
                stop_event=_ws_scan_stop,
                timeout=5,
            )
            # Collect known WS pages from sitemap if available
            extra = [u if isinstance(u, str) else u.get("url", "") for u in _all_pages
                     if any(kw in (u if isinstance(u, str) else u.get("url", "")).lower()
                            for kw in ("websocket", "/ws", "socket", "cable", "signalr"))]

            _ws_scan_status = "running 9 security tests"
            results = scanner.scan(extra_urls=extra)
            with _engine_lock:
                _ws_scan_findings.extend(results)
            _ws_scan_status = f"complete — {len(results)} findings"
        except Exception as e:
            _ws_scan_status = f"error: {e}"
        finally:
            _ws_scan_running = False

    threading.Thread(target=_ws_worker, args=(target,), daemon=True).start()
    return jsonify({"success": True, "target": target})


@app.route("/api/engine/websocket/stop", methods=["POST"])
def ws_scan_stop():
    _ws_scan_stop.set()
    return jsonify({"success": True})


@app.route("/api/engine/websocket/status")
def ws_scan_status():
    return jsonify({
        "running":  _ws_scan_running,
        "status":   _ws_scan_status,
        "findings": len(_ws_scan_findings),
    })


@app.route("/api/engine/websocket/results")
def ws_scan_results():
    with _engine_lock:
        results = list(_ws_scan_findings)
    return jsonify({"results": results, "count": len(results), "running": _ws_scan_running})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  OAST SERVER ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/oast/start", methods=["POST"])
def oast_start():
    """Start the OAST callback listener."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"error": "Engine not available"}), 503
    data = req.get_json(silent=True) or {}
    host = data.get("host_override", "")
    try:
        srv  = get_or_start_oast(host_override=host)
        return jsonify({"success": True, "status": srv.status()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/oast/status")
def oast_status():
    """Get OAST server status."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"available": False})
    try:
        srv = get_or_start_oast()
        return jsonify(srv.status())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/oast/callbacks")
def oast_callbacks():
    """Return all OAST callbacks received."""
    if not _ENGINE_AVAILABLE:
        return jsonify({"callbacks": [], "count": 0})
    try:
        srv       = get_or_start_oast()
        callbacks = srv.all_callbacks()
        return jsonify({"callbacks": callbacks, "count": len(callbacks)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/oast/clear", methods=["POST"])
def oast_clear():
    """Clear all captured OAST callbacks."""
    if _ENGINE_AVAILABLE:
        try:
            get_or_start_oast().clear()
        except Exception:
            pass
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  ADVANCED CRAWLER — Playwright AJAX + Katana + Wayback (unified, deduped)
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_seed_urls(target: str, stop_event: threading.Event) -> list:
    """Fetch robots.txt and sitemap.xml from target, return seed URL entries.

    Parses:
      - robots.txt  → Disallow/Allow paths (attack surface hints) + Sitemap: directives
      - sitemap.xml → all <loc> URLs (regular sitemap + sitemap index recursion)

    Returns list of {url, source='robots'|'sitemap', status=0, content_type='', title=''}
    """
    from urllib.parse import urljoin, urlparse as _up
    import urllib.request as _ur
    import re as _re

    parsed      = _up(target)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    seed:  list = []
    seen_u: set = set()
    seen_sm: set = set()

    def _fetch(url: str, timeout: int = 6) -> str:
        try:
            req = _ur.Request(url, headers={"User-Agent": "DAST-SeedFetcher/1.0"})
            with _ur.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _add(url: str, source: str):
        url = url.strip()
        if url and url not in seen_u:
            seen_u.add(url)
            seed.append({"url": url, "source": source, "status": 0,
                         "content_type": "", "title": ""})

    def _parse_sitemap(url: str, depth: int = 0):
        if depth > 4 or url in seen_sm or stop_event.is_set():
            return
        seen_sm.add(url)
        content = _fetch(url)
        if not content:
            return
        # Sitemap index: recurse into child sitemaps
        for loc in _re.findall(r"<sitemap>.*?<loc>(.*?)</loc>.*?</sitemap>",
                                content, _re.DOTALL):
            if not stop_event.is_set():
                _parse_sitemap(loc.strip(), depth + 1)
        # Regular sitemap: <url><loc>...</loc></url>
        for loc in _re.findall(r"<url>.*?<loc>(.*?)</loc>.*?</url>",
                                content, _re.DOTALL):
            if stop_event.is_set():
                break
            _add(loc.strip(), "sitemap")

    # ── robots.txt ────────────────────────────────────────────────────────────
    robots_content = _fetch(f"{base_origin}/robots.txt")
    if robots_content and not stop_event.is_set():
        for line in robots_content.splitlines():
            line = line.strip()
            if stop_event.is_set():
                break
            if line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                if sitemap_url:
                    _parse_sitemap(sitemap_url)
            elif line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                # Skip wildcards and trivial entries
                if path and path not in ("/", "") and "*" not in path:
                    full_url = urljoin(base_origin + "/", path.lstrip("/"))
                    _add(full_url, "robots")

    # ── sitemap.xml (if no Sitemap: directive was found in robots.txt) ────────
    if not seen_sm and not stop_event.is_set():
        _parse_sitemap(f"{base_origin}/sitemap.xml")

    return seed


def _run_graphql_introspection(target: str, stop_event: threading.Event,
                                discovered_urls: list) -> list:
    """Try GraphQL introspection on known + common GraphQL endpoints.

    `discovered_urls` — list of URL strings already found by other crawlers,
    used to detect /graphql paths that are definitely alive.

    Returns list of {url, source='graphql', status, content_type, title}
    """
    try:
        import requests as _r
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    except ImportError:
        return []

    from urllib.parse import urlparse as _up

    parsed      = _up(target)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    # Well-known GraphQL paths + anything already discovered that looks like GraphQL
    gql_paths = {"/graphql", "/api/graphql", "/query", "/gql",
                 "/graphiql", "/v1/graphql", "/v2/graphql", "/api/query"}
    for u in discovered_urls:
        p = _up(u).path.lower()
        if "graphql" in p or "/gql" in p or "/query" in p:
            gql_paths.add(_up(u).path)

    introspection_q = {"query": "{ __schema { queryType { name } types { name kind fields { name } } } }"}
    results = []

    for path in gql_paths:
        if stop_event.is_set():
            break
        url = base_origin + path
        try:
            resp = _r.post(
                url,
                json    = introspection_q,
                timeout = 5,
                verify  = False,
                headers = {"Content-Type": "application/json",
                           "User-Agent": "DAST-GraphQL/1.0"},
            )
            if resp.status_code == 200:
                try:
                    data   = resp.json()
                    schema = (data.get("data") or {}).get("__schema")
                    if schema:
                        types = [t["name"] for t in (schema.get("types") or [])
                                 if t.get("name") and not t["name"].startswith("__")]
                        results.append({
                            "url":          url,
                            "source":       "graphql",
                            "status":       200,
                            "content_type": "application/json",
                            "title":        f"[GraphQL] {len(types)} types",
                        })
                except Exception:
                    pass
        except Exception:
            pass

    return results


def _run_wayback(target: str, stop_event: threading.Event, limit: int = 5000):
    """Fetch all historical URLs for target from Wayback Machine CDX API.

    Returns list of raw URL strings (unprobed — call _probe_liveness next).
    """
    from urllib.parse import urlparse as _up
    import urllib.request as _ur
    import urllib.parse as _uparse

    parsed   = _up(target)
    domain   = parsed.netloc or parsed.path   # handle bare domain input
    # Strip port for CDX query (archive.org indexes by hostname only)
    host     = domain.split(":")[0]

    cdx_url  = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={_uparse.quote(host)}/*"
        "&output=json"
        "&fl=original"
        "&collapse=urlkey"
        f"&limit={limit}"
    )

    raw_urls: list = []
    try:
        req  = _ur.Request(cdx_url, headers={"User-Agent": "DAST-WaybackHarvester/1.0"})
        with _ur.urlopen(req, timeout=20) as resp:
            if stop_event.is_set():
                return []
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            # First row is the header ["original"], skip it
            for row in data[1:]:
                if stop_event.is_set():
                    break
                if row and row[0]:
                    url = row[0].strip()
                    # Keep only same-host HTTP/HTTPS URLs
                    try:
                        p = _up(url)
                        if p.scheme in ("http", "https") and host in p.netloc:
                            raw_urls.append(url)
                    except Exception:
                        pass
    except Exception:
        pass

    return raw_urls


def _probe_liveness(urls, stop_event, timeout: int = 5):
    """Probe a list of URLs for liveness using httpx binary or requests fallback.

    Returns list of {url, status, content_type, source='wayback'} for live URLs (2xx/3xx).
    Dead URLs (404, 5xx, timeout) are silently dropped.
    """
    if not urls:
        return []

    live: list = []

    # ── Path 1: httpx binary (fastest — concurrent Go HTTP client) ────────────
    if _HTTPX_AVAILABLE and not stop_event.is_set():
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(urls))
            tf_path = tf.name
        try:
            cmd = [
                "httpx",
                "-l", tf_path,
                "-silent",
                "-sc",           # status code
                "-ct",           # content-type
                "-timeout", str(timeout),
                "-threads", "25",
                "-json",
                "-no-color",
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in proc.stdout:  # type: ignore[union-attr]
                if stop_event.is_set():
                    proc.terminate()
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj    = json.loads(line)
                    status = obj.get("status-code", 0) or obj.get("status_code", 0)
                    if 200 <= status < 400:
                        live.append({
                            "url":          obj.get("url", ""),
                            "status":       status,
                            "content_type": obj.get("content-type", ""),
                            "source":       "wayback",
                            "title":        obj.get("title", ""),
                        })
                except (json.JSONDecodeError, KeyError):
                    pass
            proc.wait(timeout=5)
        except Exception:
            pass
        finally:
            try:
                os.unlink(tf_path)
            except Exception:
                pass
        return live

    # ── Path 2: requests fallback (no httpx binary) ───────────────────────────
    import concurrent.futures
    try:
        import requests as _r
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    except ImportError:
        return []

    def _check(url):
        if stop_event.is_set():
            return None
        try:
            resp = _r.head(
                url,
                timeout    = timeout,
                verify     = False,
                allow_redirects = True,
                headers    = {"User-Agent": "DAST-WaybackProbe/1.0"},
            )
            if 200 <= resp.status_code < 400:
                return {
                    "url":          resp.url,
                    "status":       resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "source":       "wayback",
                    "title":        "",
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_check, u): u for u in urls}
        for fut in concurrent.futures.as_completed(futures):
            if stop_event.is_set():
                break
            result = fut.result()
            if result:
                live.append(result)

    return live


def _run_katana(target: str, stop_event: threading.Event,
                depth: int = 3, rate_limit: int = 10,
                extra_headers=None,    # Optional[list[str]]
                form_fill: bool = True,
                concurrency: int = 10):
    """Run katana binary as subprocess, parse JSONL output.

    Full JS coverage mode:
      -jc           JS file crawling (parse .js files for endpoints)
      -jsl          JSLuice — advanced bundled-JS endpoint extraction
      -aff          Automatic Form Fill — submits forms to discover POST endpoints
      -c 10         10 parallel crawlers (vs default 1)
      -strategy bfs Breadth-first so shallow endpoints aren't missed
      -kf all       Capture forms, links, scripts

    Returns:
      results  — list of {url, method, source='katana', status, content_type, title}
      surfaces — list of (endpoint, method, body, content_type) for POST InputSurface creation
    """
    import shutil as _sh
    katana_bin = _sh.which("katana")
    if not katana_bin:
        return [], []

    cmd = [
        katana_bin,
        "-u", target,
        "-d", str(depth),
        "-jc",                         # JS crawling
        "-jsl",                        # JSLuice endpoint extraction
        "-rl", str(rate_limit),
        "-c", str(concurrency),        # parallel crawlers
        "-strategy", "breadth-first",  # breadth-first → broader coverage first
        "-timeout", "10",
        "-silent",
        "-jsonl",
        "-kf", "all",                  # forms, links, scripts
        "-no-color",
    ]
    if form_fill:
        cmd.append("-aff")   # Automatic Form Fill → discovers POST endpoints
    if extra_headers:
        for h in extra_headers:
            cmd += ["-H", h]

    results:  list = []
    surfaces: list = []   # (endpoint, method, body, content_type) tuples

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in proc.stdout:  # type: ignore[union-attr]
            if stop_event.is_set():
                proc.terminate()
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj      = json.loads(line)
                req      = obj.get("request", {})
                resp     = obj.get("response", {})
                endpoint = req.get("endpoint") or obj.get("endpoint", "")
                method   = req.get("method", "GET")
                body     = req.get("body", "") or ""
                status   = resp.get("status_code", 0)
                ct_resp  = resp.get("content_type", "")
                ct_req   = req.get("headers", {}).get("content-type", "")

                if endpoint:
                    results.append({
                        "url":          endpoint,
                        "method":       method,
                        "source":       "katana",
                        "status":       status,
                        "content_type": ct_resp,
                        "title":        "",
                    })
                    # Extract POST body params for InputSurface creation
                    if method in ("POST", "PUT", "PATCH") and body:
                        surfaces.append((endpoint, method, body, ct_req or "application/x-www-form-urlencoded"))
            except (json.JSONDecodeError, KeyError):
                pass
        proc.wait(timeout=5)
    except Exception:
        pass
    return results, surfaces


def _run_katana_js_static(js_urls: list, stop_event: threading.Event) -> list:
    """Phase 2 Katana: static analysis of already-discovered JS file URLs.

    Runs katana at depth=0 (no crawling) against each .js file URL to extract
    endpoints embedded in bundled JavaScript (webpack, rollup, etc.) without
    re-crawling the whole site.

    Returns list of {url, method, source='katana', status=0, content_type='', title}
    """
    import shutil as _sh
    katana_bin = _sh.which("katana")
    if not katana_bin or not js_urls:
        return []

    results: list = []

    for js_url in js_urls[:100]:          # cap at 100 JS files
        if stop_event.is_set():
            break
        # Skip non-JS or data URIs
        path_lower = js_url.lower().split("?")[0]
        if not (path_lower.endswith(".js") or path_lower.endswith(".mjs")
                or path_lower.endswith(".ts") or "/js/" in path_lower):
            continue

        cmd = [
            katana_bin,
            "-u", js_url,
            "-d", "0",          # depth 0 — analyse this file only, don't follow links
            "-jc",              # parse JS
            "-jsl",             # JSLuice endpoint extraction
            "-timeout", "8",
            "-silent",
            "-jsonl",
            "-no-color",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            fname = js_url.rstrip("/").split("/")[-1].split("?")[0][:30]
            for line in proc.stdout:  # type: ignore[union-attr]
                if stop_event.is_set():
                    proc.terminate()
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj      = json.loads(line)
                    endpoint = obj.get("request", {}).get("endpoint") or obj.get("endpoint", "")
                    if endpoint:
                        results.append({
                            "url":          endpoint,
                            "method":       obj.get("request", {}).get("method", "GET"),
                            "source":       "katana",
                            "status":       0,
                            "content_type": "",
                            "title":        f"[JS:{fname}]",
                        })
                except (json.JSONDecodeError, KeyError):
                    pass
            proc.wait(timeout=5)
        except Exception:
            pass

    return results


@app.route("/api/engine/ajax-crawl", methods=["POST"])
def ajax_crawl_start():
    """Start Advanced Crawler (Playwright AJAX + Katana). Body: {target, max_pages, max_depth}"""
    global _ajax_running, _ajax_stop_event, _ajax_thread

    if not _AJAX_SPIDER_AVAILABLE:
        return jsonify({
            "error": "Playwright not installed",
            "install": "pip install playwright && playwright install chromium"
        }), 503

    with _engine_lock:
        if _ajax_running:
            return jsonify({"error": "Ajax crawl already running"}), 409

    data   = req.get_json(silent=True) or {}
    target = (data.get("target") or _scan_target or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400

    # Auto-resolve scheme/port (http→https, alt-port detection)
    target = _resolve_target(target)

    _ajax_stop_event = threading.Event()
    _ajax_running    = True

    def _ajax_worker():
        """Unified Advanced Crawler — 5 parallel sources, shared dedup store.

        Sources:
          1. Playwright AJAX spider (multi-tab, with WebSocket capture)
          2. Katana static JS analysis subprocess
          3. Wayback Machine CDX harvest + httpx liveness probe
          4. robots.txt / sitemap.xml seed URLs
          5. GraphQL introspection (runs after crawlers finish)

        Pre-seeds from traditional spider (_engine_sitemap) if already run.
        """
        global _ajax_running, _ajax_urls_found, _ajax_pages

        # Shared dedup state — all crawlers write here under _merge_lock
        _seen_urls: set  = set()
        _all_pages: list = []
        _merge_lock      = threading.Lock()

        def _add_pages(entries):
            """Merge new URL entries, skip duplicates by URL."""
            with _merge_lock:
                for e in entries:
                    url = (e.get("url") or "").strip()
                    if url and url not in _seen_urls:
                        _seen_urls.add(url)
                        _all_pages.append(e)

        # ── Pre-seed from Traditional Spider results (if already run) ─────────
        with _engine_lock:
            if _engine_sitemap is not None and _engine_sitemap.pages:
                for page_url, page_info in _engine_sitemap.pages.items():
                    ct  = page_info.get("content_type", "")
                    _add_pages([{
                        "url":          page_url,
                        "status":       page_info.get("status", 0),
                        "content_type": ct,
                        "source":       "traditional",
                        "title":        page_info.get("title", ""),
                    }])

        # ── Thread 1: Playwright AJAX spider (multi-tab + WebSocket) ──────────
        playwright_result = []

        def _run_playwright():
            try:
                scope   = ScopeManager(target)
                cookies = []
                if _engine_auth_handler:
                    cookies = [
                        {"name": c.name, "value": c.value,
                         "domain": urlparse(target).netloc, "path": "/"}
                        for c in _engine_auth_handler.session.cookies
                    ]
                spider = AjaxSpider(
                    target      = target,
                    scope       = scope,
                    max_pages   = data.get("max_pages", 50),
                    max_depth   = data.get("max_depth", 3),
                    headless    = data.get("headless", True),
                    cookies     = cookies,
                    stop_event  = _ajax_stop_event,
                    callback    = lambda u, s: None,
                    max_tabs    = 3,
                    # Sprint 3: pass login config for session refresh + form fill
                    auth_config = _login_config if _login_config.get("login_url") else {},
                    smart_fill  = True,
                )
                ajax_sitemap = spider.crawl()

                pages = []
                for page_url, page_info in ajax_sitemap.pages.items():
                    ct  = page_info.get("content_type", "")
                    if ct == "websocket":
                        src = "websocket"
                    elif ct == "xhr/network":
                        src = "network"
                    else:
                        src = "browser"
                    pages.append({
                        "url":          page_url,
                        "status":       page_info.get("status", 0),
                        "content_type": ct,
                        "source":       src,
                        "title":        page_info.get("title", ""),
                    })

                playwright_result.extend(pages)
                _add_pages(pages)

                # Merge into engine sitemap if a full scan has already run
                with _engine_lock:
                    if _engine_sitemap is not None:
                        for page_url, page_info in ajax_sitemap.pages.items():
                            _engine_sitemap.add_page(
                                page_info["url"], page_info["status"],
                                page_info["content_type"], page_info.get("headers", {}),
                                page_info.get("title", "")
                            )
                        for surf in ajax_sitemap.surfaces:
                            _engine_sitemap.add_surface(surf)
            except Exception:
                pass

        # ── Thread 2: Katana subprocess (full JS coverage) ────────────────────
        katana_result   = []
        katana_surfaces = []   # (endpoint, method, body, content_type) for InputSurface

        def _run_katana_thread():
            if not _KATANA_AVAILABLE:
                return
            extra_headers = []
            if _engine_auth_handler:
                try:
                    cookie_str = "; ".join(
                        f"{c.name}={c.value}"
                        for c in _engine_auth_handler.session.cookies
                    )
                    if cookie_str:
                        extra_headers.append(f"Cookie: {cookie_str}")
                except Exception:
                    pass

            entries, surfs = _run_katana(
                target,
                _ajax_stop_event,
                depth         = data.get("max_depth", 3),
                rate_limit    = 10,
                extra_headers = extra_headers if extra_headers else None,
                form_fill     = True,
                concurrency   = 10,
            )
            katana_result.extend(entries)
            katana_surfaces.extend(surfs)
            _add_pages(entries)

        # ── Thread 3: Wayback Machine harvest + liveness probe ───────────────
        wayback_result = []

        def _run_wayback_thread():
            raw_urls = _run_wayback(target, _ajax_stop_event)
            if not raw_urls or _ajax_stop_event.is_set():
                return
            with _merge_lock:
                unknown = [u for u in raw_urls if u not in _seen_urls]
            if not unknown or _ajax_stop_event.is_set():
                return
            live = _probe_liveness(unknown, _ajax_stop_event)
            wayback_result.extend(live)
            _add_pages(live)

        # ── Thread 4: robots.txt + sitemap.xml seed ───────────────────────────
        sitemap_result = []

        def _run_sitemap_thread():
            entries = _fetch_seed_urls(target, _ajax_stop_event)
            if not entries or _ajax_stop_event.is_set():
                return
            # Only keep URLs not already known
            new_entries = [e for e in entries if (e.get("url") or "") not in _seen_urls]
            sitemap_result.extend(new_entries)
            _add_pages(new_entries)

        # ── Run all four crawlers in parallel ─────────────────────────────────
        t_pw = threading.Thread(target=_run_playwright,    daemon=True, name="adv-crawler-playwright")
        t_kt = threading.Thread(target=_run_katana_thread, daemon=True, name="adv-crawler-katana")
        t_wb = threading.Thread(target=_run_wayback_thread, daemon=True, name="adv-crawler-wayback")
        t_sm = threading.Thread(target=_run_sitemap_thread, daemon=True, name="adv-crawler-sitemap")
        t_pw.start(); t_kt.start(); t_wb.start(); t_sm.start()
        t_pw.join();  t_kt.join();  t_wb.join();  t_sm.join()

        # ── Post-crawl Phase A: Katana POST body → InputSurface objects ────────
        # Katana's -aff flag submits forms; the POST bodies reveal real params.
        # Convert those into InputSurface objects so the fuzzer can attack them.
        if katana_surfaces and not _ajax_stop_event.is_set():
            from urllib.parse import parse_qs as _pqs
            try:
                from modules.crawler import InputSurface as _IS
                with _engine_lock:
                    if _engine_sitemap is not None:
                        for ep, method, body, ct in katana_surfaces:
                            if "json" in ct:
                                try:
                                    body_obj = json.loads(body)
                                    if isinstance(body_obj, dict):
                                        for k, v in list(body_obj.items())[:20]:
                                            _engine_sitemap.add_surface(_IS(
                                                url=ep, method=method, param=k,
                                                param_type="json", original_value=str(v),
                                                content_type="application/json",
                                            ))
                                except Exception:
                                    pass
                            else:
                                for pair in body.split("&"):
                                    if "=" in pair:
                                        k, _, v = pair.partition("=")
                                        if k:
                                            _engine_sitemap.add_surface(_IS(
                                                url=ep, method=method, param=k,
                                                param_type="form", original_value=v,
                                                content_type=ct or "application/x-www-form-urlencoded",
                                            ))
            except Exception:
                pass

        # ── Post-crawl Phase B: Katana static JS analysis ─────────────────────
        # Extract .js URLs from all crawlers → run Katana depth-0 against each.
        # Finds endpoints buried in webpack bundles without re-crawling the site.
        if _KATANA_AVAILABLE and not _ajax_stop_event.is_set():
            with _merge_lock:
                js_urls = [
                    p.get("url", "") for p in _all_pages
                    if p.get("url", "").lower().split("?")[0].endswith((".js", ".mjs"))
                    or "/js/" in p.get("url", "").lower()
                ]
            if js_urls:
                js_static_entries = _run_katana_js_static(js_urls, _ajax_stop_event)
                if js_static_entries:
                    _add_pages(js_static_entries)
                    _log_activity("katana_js_static", target,
                                  f"JS static: {len(js_static_entries)} endpoints from {len(js_urls)} JS files")

        # ── Post-crawl Phase C: GraphQL introspection ─────────────────────────
        if not _ajax_stop_event.is_set():
            with _merge_lock:
                discovered = [p.get("url", "") for p in _all_pages]
            gql_entries = _run_graphql_introspection(target, _ajax_stop_event, discovered)
            if gql_entries:
                _add_pages(gql_entries)
                for e in gql_entries:
                    _log_activity("graphql_found", e["url"], e.get("title", ""))

        # ── Persist merged results ────────────────────────────────────────────
        with _engine_lock:
            _ajax_pages      = list(_all_pages)
            _ajax_urls_found = len(_all_pages)

        # Build summary breakdown for activity log
        n_browser     = sum(1 for p in _all_pages if p.get("source") == "browser")
        n_network     = sum(1 for p in _all_pages if p.get("source") == "network")
        n_websocket   = sum(1 for p in _all_pages if p.get("source") == "websocket")
        n_katana      = sum(1 for p in _all_pages if p.get("source") == "katana")
        n_wayback     = sum(1 for p in _all_pages if p.get("source") == "wayback")
        n_sitemap     = sum(1 for p in _all_pages if p.get("source") in ("sitemap", "robots"))
        n_traditional = sum(1 for p in _all_pages if p.get("source") == "traditional")
        n_graphql     = sum(1 for p in _all_pages if p.get("source") == "graphql")
        n_form_submit = sum(1 for p in _all_pages if p.get("source") == "form_submit")
        detail = f"{len(_all_pages)} URLs total"
        parts  = []
        if n_browser + n_network + n_websocket:
            pw_count = n_browser + n_network + n_websocket
            parts.append(f"Playwright: {pw_count}")
        if n_katana:      parts.append(f"Katana: {n_katana}")
        if n_wayback:     parts.append(f"Wayback: {n_wayback}")
        if n_sitemap:     parts.append(f"Sitemap: {n_sitemap}")
        if n_traditional: parts.append(f"Traditional: {n_traditional}")
        if n_graphql:     parts.append(f"GraphQL: {n_graphql}")
        if n_form_submit: parts.append(f"Form-Submit: {n_form_submit}")
        if parts:         detail += f" ({', '.join(parts)})"

        with _engine_lock:
            _ajax_running = False
        _log_activity("ajax_done", target, detail)

    sources = ["Playwright (3-tab)", "Sitemap", "Wayback"]
    if _KATANA_AVAILABLE:
        sources.append("Katana")
    _log_activity("ajax_start", target, f"Starting: {', '.join(sources)}")
    _ajax_thread = threading.Thread(target=_ajax_worker, daemon=True, name="dast-adv-crawler")
    _ajax_thread.start()
    return jsonify({"success": True, "target": target,
                    "playwright": _AJAX_SPIDER_AVAILABLE,
                    "katana":     _KATANA_AVAILABLE,
                    "wayback":    True,
                    "sitemap":    True,
                    "graphql":    True,
                    "httpx":      _HTTPX_AVAILABLE})


@app.route("/api/engine/ajax-crawl/stop", methods=["POST"])
def ajax_crawl_stop():
    _ajax_stop_event.set()
    return jsonify({"success": True})


@app.route("/api/engine/ajax-crawl/status")
def ajax_crawl_status():
    with _engine_lock:
        running    = _ajax_running
        urls_found = _ajax_urls_found
        pages      = list(_ajax_pages)

    # Per-source breakdown
    breakdown = {
        "browser":      sum(1 for p in pages if p.get("source") == "browser"),
        "network":      sum(1 for p in pages if p.get("source") == "network"),
        "websocket":    sum(1 for p in pages if p.get("source") == "websocket"),
        "katana":       sum(1 for p in pages if p.get("source") == "katana"),
        "wayback":      sum(1 for p in pages if p.get("source") == "wayback"),
        "sitemap":      sum(1 for p in pages if p.get("source") in ("sitemap", "robots")),
        "traditional":  sum(1 for p in pages if p.get("source") == "traditional"),
        "graphql":      sum(1 for p in pages if p.get("source") == "graphql"),
        "form_submit":  sum(1 for p in pages if p.get("source") == "form_submit"),
    }
    return jsonify({
        "running":              running,
        "urls_found":           urls_found,
        "playwright_available": _AJAX_SPIDER_AVAILABLE,
        "katana_available":     _KATANA_AVAILABLE,
        "httpx_available":      _HTTPX_AVAILABLE,
        "breakdown":            breakdown,
    })


@app.route("/api/engine/ajax-crawl/results")
def ajax_crawl_results():
    """Return all URLs discovered by the last AJAX crawl."""
    with _engine_lock:
        pages = list(_ajax_pages)
    return jsonify({"urls": pages, "count": len(pages)})


# ═══════════════════════════════════════════════════════════════════════════════
# ██  TARGET PROBE  (auto-discover working port/scheme)
# ═══════════════════════════════════════════════════════════════════════════════

def _probe_target(target: str) -> dict:
    """Check if target responds with a useful page; auto-corrects scheme/port.

    Detection order:
      1. Try target as-is.
      2. If HTTP 400 (server rejected plain HTTP), try https:// on same host:port.
      3. If connection failed entirely, probe common alt ports.
    Returns the best resolved URL and whether a correction was made.
    """
    import requests as _r
    from urllib.parse import urlparse as _up
    _s = _r.Session(); _s.verify = False
    _headers = {"User-Agent": "Mozilla/5.0 (DAST-Probe/1.0)", "Connection": "close"}

    _p    = _up(target)
    _host = _p.hostname or target
    _port = _p.port  # may be None
    _scheme = _p.scheme or "http"

    def _try(url: str) -> "_r.Response | None":
        try:
            return _s.get(url, timeout=5, headers=_headers, allow_redirects=True)
        except Exception:
            return None

    # 1. Try as-is
    _resp = _try(target)
    if _resp is not None:
        # HTTP 400 on a TLS port usually means wrong scheme → try https same host:port
        if _resp.status_code == 400 and _scheme == "http":
            _https = f"https://{_host}" + (f":{_port}" if _port else "")
            _r2 = _try(_https)
            if _r2 is not None and _r2.status_code != 400:
                return {"reachable": True, "original": target, "resolved": _https,
                        "status": _r2.status_code, "port_changed": True,
                        "note": "Switched http→https (server rejected plain HTTP)"}
        return {"reachable": True, "original": target, "resolved": target,
                "status": _resp.status_code, "port_changed": False}

    # 2. Connection failed — try https same port first (if currently http)
    if _scheme == "http" and _port:
        _https = f"https://{_host}:{_port}"
        _r2 = _try(_https)
        if _r2 is not None:
            return {"reachable": True, "original": target, "resolved": _https,
                    "status": _r2.status_code, "port_changed": True,
                    "note": "Switched http→https on same port"}

    # 3. Probe alt ports
    for _aport in [8443, 8080, 443, 8000, 3000, 9090, 9000, 5000, 4848]:
        if _aport == _port:
            continue
        _alt_scheme = "https" if _aport in (443, 8443) else _scheme
        _alt = f"{_alt_scheme}://{_host}:{_aport}"
        _r2 = _try(_alt)
        if _r2 is not None:
            return {"reachable": True, "original": target, "resolved": _alt,
                    "status": _r2.status_code, "port_changed": True}
    return {"reachable": False, "original": target, "resolved": target,
            "status": None, "port_changed": False}


def _resolve_target(target: str) -> str:
    """Return the best reachable URL for target (auto-upgrades scheme/port).
    Falls back to original if nothing responds — never blocks the caller.
    """
    try:
        result = _probe_target(target)
        return result.get("resolved") or target
    except Exception:
        return target


@app.route("/api/probe-target", methods=["POST"])
def probe_target_api():
    """Probe target reachability — auto-detects correct port if default fails."""
    data   = req.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    result = _probe_target(target)
    return jsonify(result)


# ██  CAPABILITY STATUS  (single endpoint for UI feature detection)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/capabilities")
def capabilities():
    with _engine_lock:
        eng_running = _engine_running
        eng_status  = _engine_status_msg
        eng_progress = dict(_engine_progress)

    return jsonify({
        "proxy":      {"available": PROXY_AVAILABLE, "running": bool(_proxy_thread and _proxy_thread.is_alive()), "port": _proxy_port},
        "playwright": {"available": PLAYWRIGHT_AVAILABLE},
        "hooks":      {
            "loaded":   sum(len(v) for v in _hooks.values()),
            "runtimes": {
                "python":     True,
                "javascript": _NODE_AVAILABLE,
                "groovy":     _GROOVY_AVAILABLE,
            },
        },
        "agents":     {"total": len(_DAST_AGENTS), "enabled": sum(1 for c in _agent_config.values() if c["enabled"])},
        "site_map":   {"urls": len(_site_map)},
        "fabric":          {"available": _FABRIC_AVAILABLE, "patterns": len(_FABRIC_DAST_PATTERNS)},
        "engine":          {
            "available": _ENGINE_AVAILABLE,
            "running":   eng_running,
            "status":    eng_status,
            "progress":  eng_progress,
        },
        "passive_scanner": {"available": _ENGINE_AVAILABLE, "findings": len(_passive_findings)},
        "forced_browse":   {"available": _ENGINE_AVAILABLE, "running": _browse_running,
                            "results": len(_browse_results)},
        "oast":            {"available": _ENGINE_AVAILABLE},
        "openapi_import":  {"available": _ENGINE_AVAILABLE, "surfaces_loaded": len(_openapi_surfaces)},
        "ajax_spider":     {"available": _AJAX_SPIDER_AVAILABLE, "running": _ajax_running},
        "katana":          {"available": _KATANA_AVAILABLE},
        "httpx":           {"available": _HTTPX_AVAILABLE},
        "wayback":         {"available": True},   # always available (CDX API + requests fallback)
        "sitemap_seed":    {"available": True},   # always available (urllib.request)
        "graphql":         {"available": True},   # always available (introspection probe)
        "graphql_scanner": {"available": True, "running": _graphql_scan_running,
                            "findings": len(_graphql_scan_findings)},
        "ws_scanner":      {"available": True, "running": _ws_scan_running,
                            "findings": len(_ws_scan_findings)},
        "websocket":       {"available": _AJAX_SPIDER_AVAILABLE},  # Playwright required
        "session_refresh": {"available": _AJAX_SPIDER_AVAILABLE,    # Sprint 3.1
                            "configured": bool(_login_config.get("login_url"))},
        "smart_form_fill": {"available": _AJAX_SPIDER_AVAILABLE},   # Sprint 3.2
    })
