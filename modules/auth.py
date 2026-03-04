"""
Authentication Module — handles form-based login, browser-based login (Playwright),
Bearer token, Basic auth, and cookie injection.
Maintains session for authenticated scanning.
"""
from __future__ import annotations
import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests


class _FormParser(HTMLParser):
    """Extract login form fields from HTML."""
    def __init__(self):
        super().__init__()
        self.forms:  list[dict] = []
        self._cur:   Optional[dict] = None
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list):
        a = dict(attrs)
        if tag == "form":
            self._cur = {
                "action":  a.get("action", ""),
                "method":  a.get("method", "post").lower(),
                "inputs":  {},
            }
            self._in_form = True
        elif tag == "input" and self._in_form and self._cur is not None:
            name  = a.get("name", "")
            itype = a.get("type", "text").lower()
            value = a.get("value", "")
            if name:
                self._cur["inputs"][name] = {"type": itype, "value": value}
        elif tag == "button" and self._in_form and self._cur is not None:
            name = a.get("name", "")
            if name:
                self._cur["inputs"][name] = {"type": "submit", "value": a.get("value", "")}

    def handle_endtag(self, tag: str):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur     = None
            self._in_form = False


# Heuristics to identify which field is username/email and which is password
_USER_FIELD_HINTS  = re.compile(r"user|email|login|name|account|mail", re.I)
_PASS_FIELD_HINTS  = re.compile(r"pass|pwd|secret|credential", re.I)
_CSRF_FIELD_HINTS  = re.compile(r"csrf|_token|token|nonce|authenticity", re.I)


class AuthHandler:
    """
    Handles authentication for DAST scanning.
    After calling authenticate(), the internal session carries auth cookies/headers.
    Pass this session to the crawler and fuzzer.
    """

    def __init__(self, timeout: int = 15):
        self.session       = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; DAST-Scanner/1.0)"
        )
        self.timeout       = timeout
        self.auth_type:    Optional[str] = None   # "form", "bearer", "basic", "cookie"
        self.authenticated = False
        self.auth_info:    dict = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def set_bearer(self, token: str):
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.auth_type     = "bearer"
        self.authenticated = True
        self.auth_info     = {"type": "bearer", "token": token[:20] + "..."}

    def set_basic(self, username: str, password: str):
        self.session.auth  = (username, password)
        self.auth_type     = "basic"
        self.authenticated = True
        self.auth_info     = {"type": "basic", "username": username}

    def set_cookie(self, name: str, value: str):
        self.session.cookies.set(name, value)
        self.auth_type     = "cookie"
        self.authenticated = True
        self.auth_info     = {"type": "cookie", "cookie": name}

    def set_header(self, header_name: str, header_value: str):
        self.session.headers[header_name] = header_value
        self.auth_type     = "header"
        self.authenticated = True
        self.auth_info     = {"type": "header", "header": header_name}

    def token_login(
        self,
        url: str,
        username: str,
        password: str,
        user_field: str = "username",
        pass_field: str = "password",
        token_path: Optional[str] = None,
        extra_fields: Optional[dict] = None,
    ) -> dict:
        """
        POST JSON credentials to an API endpoint and capture the bearer token.

        Args:
            url:          Login/token endpoint (e.g. /api/auth/login)
            username:     Username or email
            password:     Password
            user_field:   JSON key for username (default: "username")
            pass_field:   JSON key for password (default: "password")
            token_path:   Dot-separated path to token in response JSON
                          (e.g. "data.access_token"). None = auto-detect.
            extra_fields: Additional JSON fields to include in the POST body

        Returns: {"success": bool, "message": str, "token": str (truncated)}
        """
        import json as _json

        payload = {user_field: username, pass_field: password}
        if extra_fields:
            payload.update(extra_fields)

        try:
            resp = self.session.post(
                url,
                json=payload,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except Exception as e:
            return {"success": False, "message": f"POST failed: {e}", "token": ""}

        # Must be a JSON response
        try:
            data = resp.json()
        except (ValueError, Exception):
            return {
                "success": False,
                "message": f"Response is not JSON (status {resp.status_code})",
                "token": "",
            }

        # Check for error indicators
        if resp.status_code >= 400:
            msg = data.get("message", data.get("error", f"HTTP {resp.status_code}"))
            return {"success": False, "message": f"Auth failed: {msg}", "token": ""}

        # Extract the token
        token = self._extract_token(data, token_path)
        if not token:
            return {
                "success": False,
                "message": "Token not found in response — use --token-path to specify location. "
                           f"Response keys: {list(data.keys()) if isinstance(data, dict) else 'non-dict'}",
                "token": "",
            }

        # Set the bearer token on the session
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.auth_type = "token"
        self.authenticated = True
        self.auth_info = {
            "type": "token",
            "url": url,
            "username": username,
            "token_preview": token[:20] + "..." if len(token) > 20 else token,
        }

        # Also capture any cookies the auth endpoint set
        cookies_captured = {c.name: c.value for c in self.session.cookies}

        return {
            "success": True,
            "message": f"Token captured ({len(token)} chars)",
            "token": token[:20] + "...",
            "cookies": cookies_captured,
        }

    @staticmethod
    def _extract_token(data, token_path: Optional[str] = None) -> Optional[str]:
        """
        Extract bearer token from JSON response.

        If token_path is given (e.g. "data.access_token"), traverse the dict.
        Otherwise, auto-search common token field names.
        """
        if not isinstance(data, dict):
            return None

        # Explicit path: traverse dot-separated keys
        if token_path:
            obj = data
            for key in token_path.split("."):
                if isinstance(obj, dict) and key in obj:
                    obj = obj[key]
                else:
                    return None
            return str(obj) if obj else None

        # Auto-detect: search common token field names at top level and one level deep
        _TOKEN_KEYS = [
            "token", "access_token", "accessToken", "jwt", "id_token",
            "bearer", "auth_token", "authToken", "session_token",
            "sessionToken", "api_token", "apiToken",
        ]

        # Top-level search
        for key in _TOKEN_KEYS:
            if key in data and isinstance(data[key], str) and len(data[key]) > 10:
                return data[key]

        # One level deep (common patterns: data.token, result.access_token, etc.)
        _WRAPPER_KEYS = ["data", "result", "response", "body", "payload", "auth", "user"]
        for wrapper in _WRAPPER_KEYS:
            if wrapper in data and isinstance(data[wrapper], dict):
                for key in _TOKEN_KEYS:
                    val = data[wrapper].get(key)
                    if isinstance(val, str) and len(val) > 10:
                        return val

        # Last resort: any string value that looks like a JWT (xxx.yyy.zzz)
        import re as _re
        _JWT_RE = _re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")
        for val in data.values():
            if isinstance(val, str) and _JWT_RE.match(val):
                return val

        return None

    def form_login(self, target: str, username: str, password: str) -> dict:
        """
        Attempt to detect and fill a login form at `target`.
        Returns: {"success": bool, "message": str, "cookies": dict}
        """
        try:
            resp = self.session.get(target, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            return {"success": False, "message": f"GET failed: {e}", "cookies": {}}

        parser = _FormParser()
        parser.feed(resp.text)

        login_form = self._find_login_form(parser.forms)
        if not login_form:
            return {"success": False, "message": "No login form detected", "cookies": {}}

        action  = login_form["action"] or resp.url
        method  = login_form["method"]
        payload = self._build_login_payload(login_form["inputs"], username, password)

        action_url = urljoin(resp.url, action)
        try:
            if method == "get":
                post_resp = self.session.get(action_url, params=payload, timeout=self.timeout)
            else:
                post_resp = self.session.post(action_url, data=payload, timeout=self.timeout)
        except Exception as e:
            return {"success": False, "message": f"POST failed: {e}", "cookies": {}}

        # Check success heuristics
        success = self._detect_login_success(post_resp, username)
        self.authenticated = success
        if success:
            self.auth_type = "form"
            self.auth_info = {
                "type":     "form",
                "url":      action_url,
                "username": username,
                "cookies":  list(self.session.cookies.keys()),
            }

        return {
            "success": success,
            "message": "Login successful" if success else "Login may have failed — check response",
            "cookies": dict(self.session.cookies),
            "status_code": post_resp.status_code,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_login_form(self, forms: list[dict]) -> Optional[dict]:
        """Pick the most likely login form."""
        for form in forms:
            has_password = any(
                info["type"] == "password"
                for info in form["inputs"].values()
            )
            if has_password:
                return form
        # fallback: any form with a text + hidden field combo
        for form in forms:
            if len(form["inputs"]) >= 2:
                return form
        return forms[0] if forms else None

    def _build_login_payload(self, inputs: dict, username: str, password: str) -> dict:
        """Fill form inputs with credentials, preserve CSRF tokens and hidden fields."""
        payload = {}
        for name, info in inputs.items():
            itype = info["type"]
            if itype == "password":
                payload[name] = password
            elif _USER_FIELD_HINTS.search(name) and itype in ("text", "email"):
                payload[name] = username
            elif _CSRF_FIELD_HINTS.search(name) or itype == "hidden":
                payload[name] = info.get("value", "")  # preserve CSRF token
            elif itype == "submit":
                payload[name] = info.get("value", "Submit")
            else:
                payload[name] = info.get("value", "")
        return payload

    def _detect_login_success(self, resp: requests.Response, username: str) -> bool:
        """Heuristic: logged in if we got session cookies and page doesn't say 'invalid'."""
        has_session_cookie = any(
            re.search(r"session|auth|token|logged|user", k, re.I)
            for k in self.session.cookies.keys()
        )
        body_lower = resp.text.lower()
        failure_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "not found", "unauthorized", "forbidden"
        ]
        has_failure = any(ind in body_lower for ind in failure_indicators)
        # If we got a session cookie and no failure message, likely success
        return (has_session_cookie and not has_failure) or (
            resp.status_code == 200 and not has_failure and username.lower() in body_lower
        )

    def browser_login(
        self,
        login_url: str,
        username: str,
        password: str,
        user_selector: Optional[str] = None,
        pass_selector: Optional[str] = None,
        submit_selector: Optional[str] = None,
    ) -> dict:
        """
        Headless browser login via Playwright — handles JS-rendered forms.
        Fills the login form, submits, captures cookies, and transfers them
        to self.session for use by crawler/fuzzer.

        Selectors default to auto-detection if not provided:
          user_selector:   CSS selector for username field (default: auto-detect)
          pass_selector:   CSS selector for password field (default: auto-detect)
          submit_selector: CSS selector for submit button (default: [type=submit])

        Returns: {"success": bool, "message": str, "cookies": dict, "method": str}
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {
                "success": False,
                "message": "Playwright not installed — falling back to requests login. "
                           "Install: pip install playwright && playwright install chromium",
                "cookies": {},
                "method": "fallback",
            }

        # Default selectors
        if not submit_selector:
            submit_selector = '[type=submit], button[type=submit], input[type=submit]'

        cookies_captured = {}
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--ignore-certificate-errors", "--no-sandbox"],
                )
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (DAST-Browser/2.0)",
                )
                page = ctx.new_page()

                # Navigate to login page
                page.goto(login_url, wait_until="networkidle", timeout=20000)

                # Auto-detect or use provided selectors for username field
                if user_selector:
                    page.fill(user_selector, username)
                else:
                    # Try common username selectors
                    filled_user = False
                    for sel in [
                        'input[type=email]',
                        'input[name*=user i]', 'input[name*=email i]',
                        'input[name*=login i]', 'input[name*=account i]',
                        'input[id*=user i]', 'input[id*=email i]',
                        'input[id*=login i]',
                        'input[autocomplete=username]',
                        'input[type=text]:first-of-type',
                    ]:
                        try:
                            el = page.query_selector(sel)
                            if el and el.is_visible():
                                el.fill(username)
                                filled_user = True
                                break
                        except Exception:
                            continue
                    if not filled_user:
                        browser.close()
                        return {
                            "success": False,
                            "message": "Could not find username field — use --user-field selector",
                            "cookies": {},
                            "method": "browser",
                        }

                # Fill password field
                if pass_selector:
                    page.fill(pass_selector, password)
                else:
                    filled_pass = False
                    for sel in [
                        'input[type=password]',
                        'input[name*=pass i]', 'input[name*=pwd i]',
                        'input[autocomplete=current-password]',
                    ]:
                        try:
                            el = page.query_selector(sel)
                            if el and el.is_visible():
                                el.fill(password)
                                filled_pass = True
                                break
                        except Exception:
                            continue
                    if not filled_pass:
                        browser.close()
                        return {
                            "success": False,
                            "message": "Could not find password field — use --pass-field selector",
                            "cookies": {},
                            "method": "browser",
                        }

                # Submit the form
                try:
                    page.click(submit_selector, timeout=5000)
                except Exception:
                    # Fallback: press Enter on password field
                    page.keyboard.press("Enter")

                # Wait for navigation after login
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass  # some SPAs don't trigger full navigation

                # Capture all cookies from browser context
                browser_cookies = ctx.cookies()
                for c in browser_cookies:
                    cookies_captured[c["name"]] = c["value"]
                    self.session.cookies.set(
                        c["name"], c["value"],
                        domain=c.get("domain", ""),
                        path=c.get("path", "/"),
                    )

                # Check for localStorage/sessionStorage tokens (JWT etc)
                try:
                    local_token = page.evaluate(
                        "() => localStorage.getItem('token') || "
                        "localStorage.getItem('access_token') || "
                        "localStorage.getItem('auth_token') || ''"
                    )
                    if local_token:
                        self.session.headers["Authorization"] = f"Bearer {local_token}"
                        cookies_captured["_localStorage_token"] = local_token[:20] + "..."
                except Exception:
                    pass

                browser.close()

        except Exception as e:
            return {
                "success": False,
                "message": f"Browser login failed: {e}",
                "cookies": {},
                "method": "browser",
            }

        # Determine success
        success = len(cookies_captured) > 0
        if success:
            self.authenticated = True
            self.auth_type = "browser"
            self.auth_info = {
                "type": "browser",
                "url": login_url,
                "username": username,
                "cookies": list(cookies_captured.keys()),
            }

        return {
            "success": success,
            "message": f"Browser login {'successful' if success else 'may have failed'} "
                       f"— {len(cookies_captured)} cookies captured",
            "cookies": cookies_captured,
            "method": "browser",
        }

    def transfer_cookies_to(self, target_session: requests.Session):
        """Copy all auth cookies and headers from this handler to another session."""
        for cookie in self.session.cookies:
            target_session.cookies.set_cookie(cookie)
        # Copy auth headers (Bearer, custom)
        for key in ("Authorization",):
            if key in self.session.headers:
                target_session.headers[key] = self.session.headers[key]

    def get_auth_summary(self) -> dict:
        return {
            "authenticated": self.authenticated,
            "auth_type":     self.auth_type,
            "info":          self.auth_info,
            "cookies":       list(self.session.cookies.keys()),
            "headers":       [k for k in self.session.headers if k.lower() not in (
                "user-agent", "accept-encoding", "accept", "connection"
            )],
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-USER / PER-ROLE AUTHENTICATED SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

# Users config JSON schema:
# {
#   "users": [
#     {
#       "name": "admin",
#       "role": "admin",
#       "auth_method": "token",          # token | form | bearer | cookie | basic
#       "url": "http://app/api/login",   # login URL (for token/form)
#       "username": "admin@co.com",
#       "password": "adminpass",
#       "token_field": "email",          # optional: JSON key for username
#       "pass_field": "password",        # optional: JSON key for password
#       "token_path": "data.token",      # optional: response JSON path
#       "token": "eyJ...",               # for bearer: pre-captured token
#       "cookie_name": "session",        # for cookie: cookie name
#       "cookie_value": "abc123",        # for cookie: cookie value
#       "header_name": "X-API-Key",      # for header: custom header
#       "header_value": "key123"         # for header: custom value
#     }
#   ]
# }

import json as _json
from difflib import SequenceMatcher


class UserContext:
    """Authenticated session for a named user/role."""
    __slots__ = ("name", "role", "session", "authenticated", "auth_summary")

    def __init__(self, name: str, role: str, session: requests.Session,
                 authenticated: bool = False, auth_summary: dict = None):
        self.name = name
        self.role = role
        self.session = session
        self.authenticated = authenticated
        self.auth_summary = auth_summary or {}

    def __repr__(self):
        return f"<UserContext {self.name} role={self.role} auth={self.authenticated}>"


class MultiUserScanner:
    """
    Manages multiple authenticated user contexts and performs access control
    comparison across roles to detect BAC / privilege escalation.

    Usage:
        scanner = MultiUserScanner.from_config("users.json")
        scanner.authenticate_all()
        findings = scanner.compare_access(urls, timeout=10)
    """

    def __init__(self, timeout: int = 15):
        self.users: list[UserContext] = []
        self.timeout = timeout

    @classmethod
    def from_config(cls, path: str, timeout: int = 15,
                    filter_users: list[str] = None) -> "MultiUserScanner":
        """Load users from JSON config file."""
        with open(path, "r") as f:
            config = _json.load(f)

        scanner = cls(timeout=timeout)
        for user_cfg in config.get("users", []):
            name = user_cfg.get("name", "unnamed")
            if filter_users and name not in filter_users:
                continue
            role = user_cfg.get("role", "user")
            # Create a fresh session per user
            session = requests.Session()
            session.verify = False
            session.headers["User-Agent"] = "Mozilla/5.0 (DAST-MultiUser/2.0)"
            scanner.users.append(UserContext(
                name=name, role=role, session=session,
            ))
        # Store raw config for auth step
        scanner._config = config
        scanner._filter = filter_users
        return scanner

    def authenticate_all(self) -> list[dict]:
        """Authenticate each user via their configured method. Returns results."""
        config = getattr(self, "_config", {})
        user_cfgs = {u.get("name"): u for u in config.get("users", [])}
        results = []

        for uctx in self.users:
            cfg = user_cfgs.get(uctx.name, {})
            method = cfg.get("auth_method", "token")
            auth = AuthHandler(timeout=self.timeout)

            if method == "token":
                result = auth.token_login(
                    url=cfg.get("url", ""),
                    username=cfg.get("username", ""),
                    password=cfg.get("password", ""),
                    user_field=cfg.get("token_field", "username"),
                    pass_field=cfg.get("pass_field", "password"),
                    token_path=cfg.get("token_path"),
                )
            elif method == "form":
                result = auth.form_login(
                    target=cfg.get("url", ""),
                    username=cfg.get("username", ""),
                    password=cfg.get("password", ""),
                )
            elif method == "bearer":
                token = cfg.get("token", "")
                auth.set_bearer(token)
                result = {"success": bool(token), "message": "Bearer token set"}
            elif method == "cookie":
                auth.set_cookie(cfg.get("cookie_name", "session"),
                                cfg.get("cookie_value", ""))
                result = {"success": True, "message": "Cookie set"}
            elif method == "basic":
                auth.set_basic(cfg.get("username", ""), cfg.get("password", ""))
                result = {"success": True, "message": "Basic auth set"}
            elif method == "header":
                auth.set_header(cfg.get("header_name", "Authorization"),
                                cfg.get("header_value", ""))
                result = {"success": True, "message": "Header set"}
            else:
                result = {"success": False, "message": f"Unknown auth method: {method}"}

            # Transfer auth state to user's session
            if result.get("success"):
                auth.transfer_cookies_to(uctx.session)
                if "Authorization" in auth.session.headers:
                    uctx.session.headers["Authorization"] = auth.session.headers["Authorization"]
                uctx.authenticated = True
                uctx.auth_summary = auth.get_auth_summary()

            results.append({
                "user": uctx.name,
                "role": uctx.role,
                "success": result.get("success", False),
                "message": result.get("message", ""),
            })

        return results

    def add_unauth_baseline(self):
        """Add an unauthenticated session for baseline comparison."""
        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = "Mozilla/5.0 (DAST-MultiUser/2.0)"
        self.users.insert(0, UserContext(
            name="(unauthenticated)",
            role="none",
            session=session,
            authenticated=False,
        ))

    def compare_access(
        self,
        urls: list[str],
        timeout: int = 10,
        callback=None,
    ) -> list[dict]:
        """
        Request each URL with every user session and compare responses
        to detect access control issues.

        Detection logic:
          - Vertical escalation: lower-priv user gets 200 where they should get 403
          - Horizontal access: same-role users see each other's data
          - Missing auth: unauthenticated gets 200 on protected resource

        Returns list of finding dicts.
        """
        if len(self.users) < 2:
            return []

        findings = []
        # Sort users by privilege: none < user/guest < moderator < admin/superadmin
        _ROLE_WEIGHT = {
            "none": 0, "guest": 1, "user": 2, "member": 2,
            "moderator": 3, "editor": 3, "manager": 4,
            "admin": 5, "superadmin": 6, "root": 6,
        }

        sorted_users = sorted(
            self.users,
            key=lambda u: _ROLE_WEIGHT.get(u.role.lower(), 2),
        )

        # Find the highest-privilege user as reference
        ref_user = sorted_users[-1]

        for url in urls:
            # Get reference response (highest privilege)
            try:
                ref_resp = ref_user.session.get(url, timeout=timeout, allow_redirects=True)
                ref_status = ref_resp.status_code
                ref_body = ref_resp.text[:8000]
            except Exception:
                continue

            # Skip if even admin gets 404/405 — not a real endpoint
            if ref_status in (404, 405):
                continue

            for uctx in sorted_users[:-1]:  # all except highest-priv
                try:
                    resp = uctx.session.get(url, timeout=timeout, allow_redirects=True)
                except Exception:
                    continue

                user_weight = _ROLE_WEIGHT.get(uctx.role.lower(), 2)
                ref_weight = _ROLE_WEIGHT.get(ref_user.role.lower(), 5)

                # Detection 1: Lower-priv user gets 200 where admin gets 200
                # but should they? Check body similarity
                if resp.status_code == 200 and ref_status == 200 and user_weight < ref_weight:
                    similarity = SequenceMatcher(
                        None, resp.text[:4000], ref_body[:4000]
                    ).quick_ratio()

                    if similarity > 0.85:
                        # Very similar content — possible BAC
                        severity = "high" if user_weight <= 1 else "medium"
                        finding = {
                            "url": url,
                            "vuln_type": "broken_access_control",
                            "severity": severity,
                            "category": "Access Control",
                            "finding": (
                                f"Vertical escalation — '{uctx.name}' (role={uctx.role}) "
                                f"gets {similarity:.0%} similar content as '{ref_user.name}' "
                                f"(role={ref_user.role})"
                            ),
                            "user": uctx.name,
                            "ref_user": ref_user.name,
                            "similarity": round(similarity, 3),
                            "phase": "access_control",
                        }
                        findings.append(finding)
                        if callback:
                            callback(finding)

                # Detection 2: Unauthenticated gets 200 on protected endpoint
                elif (not uctx.authenticated and resp.status_code == 200
                      and ref_status == 200):
                    # Check it's not just a public page (login, home, etc)
                    path = urlparse(url).path.lower()
                    public_hints = ("/login", "/signin", "/register", "/signup",
                                    "/forgot", "/reset", "/public", "/health",
                                    "/status", "/favicon", "/robots", "/sitemap")
                    if not any(hint in path for hint in public_hints):
                        similarity = SequenceMatcher(
                            None, resp.text[:4000], ref_body[:4000]
                        ).quick_ratio()
                        if similarity > 0.7:
                            findings.append({
                                "url": url,
                                "vuln_type": "missing_authentication",
                                "severity": "high",
                                "category": "Access Control",
                                "finding": (
                                    f"Missing authentication — unauthenticated access returns "
                                    f"{similarity:.0%} similar content as authenticated user"
                                ),
                                "user": uctx.name,
                                "ref_user": ref_user.name,
                                "similarity": round(similarity, 3),
                                "phase": "access_control",
                            })
                            if callback:
                                callback(findings[-1])

                # Detection 3: Lower-priv gets 200 where they should get 403/401
                elif (resp.status_code == 200 and ref_status == 200
                      and user_weight < ref_weight - 1):
                    # Only flag if path looks admin-ish
                    path = urlparse(url).path.lower()
                    admin_hints = ("/admin", "/manage", "/dashboard", "/settings",
                                   "/config", "/internal", "/users", "/roles",
                                   "/audit", "/system", "/console")
                    if any(hint in path for hint in admin_hints):
                        findings.append({
                            "url": url,
                            "vuln_type": "privilege_escalation",
                            "severity": "critical",
                            "category": "Access Control",
                            "finding": (
                                f"Privilege escalation — '{uctx.name}' (role={uctx.role}) "
                                f"can access admin path: {urlparse(url).path}"
                            ),
                            "user": uctx.name,
                            "ref_user": ref_user.name,
                            "phase": "access_control",
                        })
                        if callback:
                            callback(findings[-1])

        return findings
