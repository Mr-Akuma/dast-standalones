"""
Authentication Module — handles form-based login, browser-based login (Playwright),
Bearer token, Basic auth, cookie injection, and multi-step scripted auth flows.
Maintains session for authenticated scanning.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import time as _time_mod
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from .event_bus import safe_publish, AUTH_REFRESHED, AUTH_FAILED


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

    def set_client_cert(self, cert_path: str, key_path: str | None = None) -> None:
        """
        Configure mTLS client certificate authentication (PEM format).

        Port of Burp Suite's client certificate feature — wires a client cert +
        private key into the requests.Session so every request in this scan
        presents the certificate for mutual TLS handshakes.

        Args:
            cert_path: Path to PEM-encoded client certificate (or combined cert+key).
            key_path:  Path to PEM-encoded private key (None if cert_path is combined).

        Example:
            auth.set_client_cert("/certs/client.crt", "/certs/client.key")
        """
        self.session.cert  = (cert_path, key_path) if key_path else cert_path
        self.auth_type     = "mtls"
        self.authenticated = True
        self.auth_info     = {"type": "mtls", "cert": cert_path}

    def set_pkcs12(self, p12_path: str, password: str | bytes = "") -> None:
        """
        Configure mTLS using a PKCS#12 (.p12 / .pfx) bundle.

        Extracts the PEM certificate and private key from the bundle and writes
        them to temp files, then calls set_client_cert(). Requires the
        ``cryptography`` package (pip install cryptography).

        Args:
            p12_path: Path to the PKCS#12 file.
            password: Bundle password (str or bytes). Empty string = no password.

        Raises:
            ImportError: if the ``cryptography`` package is not installed.
            ValueError:  if the PKCS#12 bundle cannot be parsed.
        """
        import tempfile
        try:
            from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PrivateFormat, NoEncryption,
            )
        except ImportError as exc:
            raise ImportError(
                "set_pkcs12 requires 'cryptography': pip install cryptography"
            ) from exc

        pwd = password.encode() if isinstance(password, str) else (password or b"")
        with open(p12_path, "rb") as fh:
            p12 = load_pkcs12(fh.read(), pwd)

        cert_pem = p12.cert.certificate.public_bytes(Encoding.PEM)
        key_pem  = p12.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

        # Write to temp files that persist for the session lifetime
        tf_cert = tempfile.NamedTemporaryFile(suffix=".crt", delete=False)
        tf_key  = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
        tf_cert.write(cert_pem); tf_cert.flush(); tf_cert.close()
        tf_key.write(key_pem);   tf_key.flush();  tf_key.close()

        self.set_client_cert(tf_cert.name, tf_key.name)
        self.auth_info["pkcs12"] = p12_path

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

        # Track token expiry for proactive refresh
        expires_in = data.get("expires_in") if isinstance(data, dict) else None
        refresh_tok = data.get("refresh_token") if isinstance(data, dict) else None
        if expires_in:
            self._setup_token_expiry(int(expires_in), refresh_token=refresh_tok, token_url=url)

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

    # ── Multi-step scripted authentication ────────────────────────────────

    def script_login(self, script_path: str, extra_vars: Optional[dict] = None) -> dict:
        """
        Run a multi-step auth script (JSON).
        Returns: {"success": bool, "message": str, "steps_completed": int, "cookies": list}
        """
        runner = AuthScriptRunner(self.session, timeout=self.timeout)
        result = runner.run_script(script_path, extra_vars=extra_vars)
        if result["success"]:
            self.auth_type = "script"
            self.authenticated = True
            self.auth_info = {"type": "script", "script": script_path,
                              "steps": result["steps_completed"]}
        return result

    # ── Credential storage for re-authentication ───────────────────────────

    def store_credentials(self, method: str, **kwargs):
        """
        Store auth credentials so re-authentication can replay them on 401.
        method: "token", "form", "browser", or "script"
        kwargs: original arguments passed to the login method.
        """
        self._stored_auth = {"method": method, **kwargs}

    def re_authenticate(self) -> bool:
        """
        Replay stored credentials to refresh the session.
        Returns True on success, False on failure.
        """
        stored = getattr(self, "_stored_auth", None)
        if not stored:
            # Static session (cookie/header import) — nothing to replay, not an error
            return False

        method = stored["method"]
        try:
            if method == "token":
                result = self.token_login(
                    url=stored.get("url", ""),
                    username=stored.get("username", ""),
                    password=stored.get("password", ""),
                    user_field=stored.get("user_field", "username"),
                    pass_field=stored.get("pass_field", "password"),
                    token_path=stored.get("token_path"),
                )
                return result.get("success", False)

            elif method == "form":
                result = self.form_login(
                    target=stored.get("target", ""),
                    username=stored.get("username", ""),
                    password=stored.get("password", ""),
                )
                return result.get("success", False)

            elif method == "browser":
                result = self.browser_login(
                    login_url=stored.get("login_url", ""),
                    username=stored.get("username", ""),
                    password=stored.get("password", ""),
                    user_selector=stored.get("user_selector"),
                    pass_selector=stored.get("pass_selector"),
                    submit_selector=stored.get("submit_selector"),
                )
                if result.get("method") == "fallback":
                    result = self.form_login(
                        stored.get("login_url", ""),
                        stored.get("username", ""),
                        stored.get("password", ""),
                    )
                return result.get("success", False)

            elif method == "script":
                result = self.script_login(
                    script_path=stored.get("script_path", ""),
                    extra_vars=stored.get("extra_vars"),
                )
                return result.get("success", False)

        except Exception:
            return False

        return False

    # ── OAuth2 PKCE Login ─────────────────────────────────────────────────────

    def oauth2_pkce_login(
        self,
        authorize_url: str,
        token_url: str,
        client_id: str,
        redirect_uri: str = "http://localhost:8443/callback",
        scope: str = "openid profile",
    ) -> dict:
        """
        Perform an OAuth2 Authorization Code flow with PKCE (S256).

        Generates a code verifier/challenge, hits the authorize endpoint,
        extracts the authorization code from the redirect, then exchanges it
        for tokens at the token endpoint.

        Returns: {"success": bool, "message": str, "access_token": str, ...}
        """
        from urllib.parse import parse_qs, urlparse as _urlparse

        # 1. Generate PKCE code_verifier (43-128 chars, URL-safe base64)
        code_verifier = secrets.token_urlsafe(64)[:128]
        if len(code_verifier) < 43:
            code_verifier = secrets.token_urlsafe(64)

        # 2. Compute code_challenge = base64url(sha256(code_verifier))
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        # 3. Build authorize URL parameters
        state = secrets.token_urlsafe(32)
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }

        # 4. Send GET to authorize endpoint, follow redirects
        try:
            resp = self.session.get(
                authorize_url,
                params=params,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except Exception as e:
            return {"success": False, "message": f"Authorize request failed: {e}"}

        # 5. Extract authorization code from final URL or Location header
        code = None
        final_url = resp.url or ""
        parsed = _urlparse(final_url)
        qs = parse_qs(parsed.query)
        if "code" in qs:
            code = qs["code"][0]

        # Fallback: check Location header in redirect history
        if not code:
            for hist_resp in resp.history:
                loc = hist_resp.headers.get("Location", "")
                if "code=" in loc:
                    loc_parsed = _urlparse(loc)
                    loc_qs = parse_qs(loc_parsed.query)
                    if "code" in loc_qs:
                        code = loc_qs["code"][0]
                        break

        if not code:
            return {
                "success": False,
                "message": "Authorization code not found in redirect. "
                           f"Final URL: {final_url[:200]}",
            }

        # 6. Exchange code for tokens at token_url
        token_payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        }

        try:
            token_resp = self.session.post(
                token_url,
                data=token_payload,
                timeout=self.timeout,
            )
        except Exception as e:
            return {"success": False, "message": f"Token exchange failed: {e}"}

        try:
            token_data = token_resp.json()
        except (ValueError, Exception):
            return {
                "success": False,
                "message": f"Token response is not JSON (status {token_resp.status_code})",
            }

        if token_resp.status_code >= 400:
            msg = token_data.get("error_description", token_data.get("error", f"HTTP {token_resp.status_code}"))
            return {"success": False, "message": f"Token exchange failed: {msg}"}

        # 7. Extract tokens
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")

        if not access_token:
            return {
                "success": False,
                "message": f"No access_token in response. Keys: {list(token_data.keys())}",
            }

        # 8. Set bearer and track expiry
        self.set_bearer(access_token)
        self.auth_info.update({"oauth2_pkce": True, "scope": scope})

        if expires_in:
            self._setup_token_expiry(int(expires_in), refresh_token=refresh_token, token_url=token_url)

        return {
            "success": True,
            "message": f"OAuth2 PKCE login successful ({len(access_token)} char token)",
            "access_token": access_token[:20] + "..." if len(access_token) > 20 else access_token,
            "refresh_token": bool(refresh_token),
            "expires_in": expires_in,
        }

    # ── Proactive Token Refresh ───────────────────────────────────────────────

    def _setup_token_expiry(self, expires_in: int, refresh_token: Optional[str] = None,
                            token_url: Optional[str] = None):
        """Track token expiry and enable proactive refresh."""
        self._token_issued_at = _time_mod.time()
        self._token_expires_in = expires_in
        self._refresh_token = refresh_token
        self._token_url = token_url

    def ensure_token_fresh(self):
        """
        Check if token is near expiry (80% of lifetime elapsed) and refresh
        proactively. No-op if no expiry info is tracked.
        """
        issued = getattr(self, "_token_issued_at", None)
        expires_in = getattr(self, "_token_expires_in", None)
        if issued is None or expires_in is None:
            return

        elapsed = _time_mod.time() - issued
        if elapsed > 0.8 * expires_in:
            self._do_token_refresh()

    def _do_token_refresh(self):
        """POST to the token URL with the refresh_token grant to get a new access token."""
        refresh_token = getattr(self, "_refresh_token", None)
        token_url = getattr(self, "_token_url", None)

        if not refresh_token or not token_url:
            # Cannot refresh — try full re-authentication
            self.re_authenticate()
            return

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        try:
            resp = self.session.post(token_url, data=payload, timeout=self.timeout)
            data = resp.json()
        except Exception:
            self.re_authenticate()
            return

        new_token = data.get("access_token")
        if not new_token:
            self.re_authenticate()
            return

        # Update bearer header and refresh tracking
        self.session.headers["Authorization"] = f"Bearer {new_token}"
        self._token_issued_at = _time_mod.time()
        safe_publish(AUTH_REFRESHED, {"auth_type": getattr(self, "auth_type", "bearer")})

        new_refresh = data.get("refresh_token")
        if new_refresh:
            self._refresh_token = new_refresh

        new_expires = data.get("expires_in")
        if new_expires:
            self._token_expires_in = int(new_expires)

    # ── API Key Rotation ──────────────────────────────────────────────────────

    def set_api_keys(self, keys: list[str], header_name: str = "X-API-Key"):
        """Configure multiple API keys for rotation."""
        if not keys:
            raise ValueError("At least one API key is required")
        self._api_keys = list(keys)
        self._api_key_index = 0
        self._api_key_header = header_name
        self.session.headers[header_name] = keys[0]
        self.auth_type = "api_key"
        self.authenticated = True
        self.auth_info = {"type": "api_key", "header": header_name, "key_count": len(keys)}

    def rotate_api_key(self):
        """Switch to next API key in the rotation list."""
        keys = getattr(self, "_api_keys", None)
        if not keys:
            return
        self._api_key_index = (self._api_key_index + 1) % len(keys)
        header = self._api_key_header
        self.session.headers[header] = keys[self._api_key_index]

    def handle_auth_failure(self) -> bool:
        """
        Called on 401/403 — try rotating API key before re-authenticating.
        Returns True if a recovery action was taken.
        """
        keys = getattr(self, "_api_keys", None)
        if keys and len(keys) > 1:
            original_index = self._api_key_index
            self.rotate_api_key()
            # If we haven't cycled through all keys yet, rotation may help
            if self._api_key_index != original_index:
                return True

        # All keys exhausted or no rotation available — full re-auth
        result = self.re_authenticate()
        if not result:
            safe_publish(AUTH_FAILED, {
                "reason": "all recovery options exhausted (key rotation + re-auth failed)",
                "auth_type": getattr(self, "auth_type", "unknown"),
            })
        return result


class MultiRoleSessionManager:
    """Manages parallel authenticated sessions for different roles."""

    def __init__(self):
        self.sessions: dict[str, AuthHandler] = {}  # role_name -> AuthHandler

    def add_role(self, role_name: str, auth_handler: AuthHandler):
        """Register an AuthHandler for a named role."""
        self.sessions[role_name] = auth_handler

    def get_session(self, role_name: str) -> requests.Session:
        """Return the requests.Session for a given role."""
        handler = self.sessions.get(role_name)
        if handler is None:
            raise KeyError(f"No session registered for role: {role_name!r}")
        return handler.session

    def get_handler(self, role_name: str) -> AuthHandler:
        """Return the AuthHandler for a given role."""
        handler = self.sessions.get(role_name)
        if handler is None:
            raise KeyError(f"No handler registered for role: {role_name!r}")
        return handler

    def ensure_all_fresh(self):
        """Call ensure_token_fresh on every registered handler."""
        for handler in self.sessions.values():
            handler.ensure_token_fresh()

    def list_roles(self) -> list[str]:
        """Return all registered role names."""
        return list(self.sessions.keys())

    def remove_role(self, role_name: str):
        """Remove a role and its handler."""
        self.sessions.pop(role_name, None)


# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-STEP AUTH SCRIPT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════


def _generate_totp(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    """
    Pure-Python TOTP (RFC 6238) — no pyotp dependency.
    secret_b32: base32-encoded shared secret.
    Returns: current TOTP code as zero-padded string.
    """
    # Decode base32 secret (allow padding issues)
    secret_b32 = secret_b32.upper().replace(" ", "")
    padding = 8 - (len(secret_b32) % 8)
    if padding != 8:
        secret_b32 += "=" * padding
    key = base64.b32decode(secret_b32)

    # Time counter
    counter = int(_time_mod.time()) // period
    counter_bytes = struct.pack(">Q", counter)

    # HMAC-SHA1
    h = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10 ** digits)
    return str(code).zfill(digits)


class AuthScriptRunner:
    """
    Executes multi-step authentication flows defined in a JSON config file.

    JSON format:
    {
      "name": "My Auth Flow",
      "variables": {"username": "admin", "password": "secret", "totp_secret": "BASE32KEY"},
      "steps": [
        {"type": "request", "method": "GET", "url": "{{target}}/login",
         "extract": {"csrf": {"from": "regex", "pattern": "name=\"csrf\" value=\"(.+?)\""}}},
        {"type": "request", "method": "POST", "url": "{{target}}/login",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
         "body": "username={{username}}&password={{password}}&csrf={{csrf}}"},
        {"type": "totp", "secret": "{{totp_secret}}", "var": "otp_code"},
        {"type": "request", "method": "POST", "url": "{{target}}/mfa",
         "json": {"code": "{{otp_code}}"},
         "extract": {"token": {"from": "jsonpath", "path": "access_token"}}},
        {"type": "set_header", "header": "Authorization", "value": "Bearer {{token}}"},
        {"type": "set_cookie", "name": "session", "value": "{{session_cookie}}"},
        {"type": "sleep", "seconds": 1}
      ]
    }

    Step types:
      request    — HTTP request (GET/POST/PUT/etc.)
      browser    — Playwright page action (navigate, fill, click, wait)
      extract    — Extract value from last response (auto-runs with request too)
      set_header — Set header on the session
      set_cookie — Set cookie on the session
      totp       — Generate TOTP code from base32 secret
      sleep      — Wait N seconds
    """

    def __init__(self, session: requests.Session, timeout: int = 15):
        self.session = session
        self.timeout = timeout
        self.context: dict[str, str] = {}
        self._last_response: Optional[requests.Response] = None

    def run_script(self, script_path: str, extra_vars: Optional[dict] = None) -> dict:
        """
        Load and execute an auth script.
        Returns: {"success": bool, "message": str, "steps_completed": int, "cookies": list}
        """
        try:
            with open(script_path, "r") as f:
                script = json.load(f)
        except FileNotFoundError:
            print(f"[DAST] Auth script not found: {script_path}\n  Schema: modules/auth_script_schema.json")
            raise
        except json.JSONDecodeError as exc:
            print(f"[DAST] Auth script JSON parse error in {script_path}: {exc}\n  Schema: modules/auth_script_schema.json")
            raise

        # Initialize variables from script + overrides
        self.context = dict(script.get("variables", {}))
        if extra_vars:
            self.context.update(extra_vars)

        steps = script.get("steps", [])
        name = script.get("name", script_path)
        print(f"[DAST] Auth script: {name} ({len(steps)} steps)")

        for i, step in enumerate(steps):
            step_type = step.get("type", "")
            step_name = step.get("name", f"step-{i + 1}")
            try:
                self._execute_step(step)
                print(f"[DAST]  Step {i + 1}/{len(steps)}: {step_type} — ✓ {step_name}")
            except Exception as e:
                print(f"[DAST]  Step {i + 1}/{len(steps)}: {step_type} — ✗ {e}")
                return {
                    "success": False,
                    "message": f"Step {i + 1} ({step_type}) failed: {e}",
                    "steps_completed": i,
                    "cookies": list(self.session.cookies.keys()),
                }

        return {
            "success": True,
            "message": f"All {len(steps)} steps completed",
            "steps_completed": len(steps),
            "cookies": list(self.session.cookies.keys()),
        }

    def _interpolate(self, text: str) -> str:
        """Replace {{var_name}} placeholders with context values."""
        if not text or "{{" not in text:
            return text

        def replacer(m):
            key = m.group(1)
            return self.context.get(key, m.group(0))

        return re.sub(r"\{\{(\w+)\}\}", replacer, text)

    def _interpolate_obj(self, obj):
        """Recursively interpolate variables in dicts, lists, and strings."""
        if isinstance(obj, str):
            return self._interpolate(obj)
        elif isinstance(obj, dict):
            return {k: self._interpolate_obj(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._interpolate_obj(item) for item in obj]
        return obj

    def _execute_step(self, step: dict):
        """Execute a single auth step."""
        step_type = step["type"]

        if step_type == "request":
            self._step_request(step)
        elif step_type == "browser":
            self._step_browser(step)
        elif step_type == "extract":
            self._step_extract(step)
        elif step_type == "set_header":
            header = self._interpolate(step["header"])
            value = self._interpolate(step["value"])
            self.session.headers[header] = value
        elif step_type == "set_cookie":
            name = self._interpolate(step["name"])
            value = self._interpolate(step["value"])
            self.session.cookies.set(name, value)
        elif step_type == "totp":
            secret = self._interpolate(step["secret"])
            code = _generate_totp(secret)
            var_name = step.get("var", "totp_code")
            self.context[var_name] = code
        elif step_type == "sleep":
            _time_mod.sleep(step.get("seconds", 1))
        else:
            raise ValueError(f"Unknown step type: {step_type}")

    def _step_request(self, step: dict):
        """Execute an HTTP request step."""
        method = self._interpolate(step.get("method", "GET")).upper()
        url = self._interpolate(step.get("url", ""))
        headers = self._interpolate_obj(step.get("headers", {}))
        body = None
        json_body = None

        if "json" in step:
            json_body = self._interpolate_obj(step["json"])
        elif "body" in step:
            raw = step["body"]
            if isinstance(raw, dict):
                body = {k: self._interpolate(str(v)) for k, v in raw.items()}
            else:
                body = self._interpolate(str(raw))

        resp = self.session.request(
            method, url, headers=headers, data=body, json=json_body,
            timeout=self.timeout, allow_redirects=step.get("follow_redirects", True),
        )
        self._last_response = resp

        # Store useful response metadata in context
        self.context["_status"] = str(resp.status_code)
        self.context["_url"] = resp.url

        # Auto-extract if defined in step
        if "extract" in step:
            for var_name, extract_def in step["extract"].items():
                value = self._extract_value(extract_def, resp)
                if value is not None:
                    self.context[var_name] = value

    def _step_browser(self, step: dict):
        """Execute a Playwright browser action step."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError("Playwright not installed — browser steps require: pip install playwright")

        action = step.get("action", "navigate")
        url = self._interpolate(step.get("url", ""))

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            if action == "navigate":
                page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
            elif action == "fill":
                if url:
                    page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
                selector = self._interpolate(step["selector"])
                value = self._interpolate(step["value"])
                page.fill(selector, value)
            elif action == "click":
                selector = self._interpolate(step["selector"])
                page.click(selector)
            elif action == "wait":
                selector = self._interpolate(step.get("selector", ""))
                if selector:
                    page.wait_for_selector(selector, timeout=self.timeout * 1000)
                else:
                    page.wait_for_load_state("networkidle", timeout=self.timeout * 1000)
            elif action == "fill_and_submit":
                if url:
                    page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
                for fill in step.get("fields", []):
                    sel = self._interpolate(fill["selector"])
                    val = self._interpolate(fill["value"])
                    page.fill(sel, val)
                submit_sel = self._interpolate(step.get("submit", "button[type=submit]"))
                page.click(submit_sel)
                page.wait_for_load_state("networkidle", timeout=self.timeout * 1000)

            # Extract cookies from browser context
            cookies = page.context.cookies()
            for c in cookies:
                self.session.cookies.set(c["name"], c["value"],
                                         domain=c.get("domain", ""),
                                         path=c.get("path", "/"))

            # Auto-extract if defined
            if "extract" in step:
                body = page.content()
                for var_name, extract_def in step["extract"].items():
                    if extract_def.get("from") == "regex":
                        pattern = extract_def["pattern"]
                        m = re.search(pattern, body)
                        if m:
                            self.context[var_name] = m.group(1) if m.lastindex else m.group(0)

            browser.close()

    def _step_extract(self, step: dict):
        """Standalone extract step — pulls from last response."""
        if not self._last_response:
            raise RuntimeError("No previous response to extract from")
        for var_name, extract_def in step.get("extract", step.get("extractions", {})).items():
            value = self._extract_value(extract_def, self._last_response)
            if value is not None:
                self.context[var_name] = value
            elif extract_def.get("required", False):
                raise RuntimeError(f"Required extraction '{var_name}' failed")

    def _extract_value(self, extract_def: dict, resp: requests.Response) -> Optional[str]:
        """Extract a value from a response using various strategies."""
        source = extract_def.get("from", "")

        if source == "jsonpath" or source == "json":
            # Dot-path JSON extraction
            path = extract_def.get("path", "")
            try:
                data = resp.json()
                for key in path.split("."):
                    if isinstance(data, dict):
                        data = data.get(key)
                    elif isinstance(data, list) and key.isdigit():
                        data = data[int(key)]
                    else:
                        return None
                return str(data) if data is not None else None
            except (json.JSONDecodeError, ValueError):
                return None

        elif source == "regex":
            pattern = extract_def.get("pattern", "")
            m = re.search(pattern, resp.text)
            if m:
                return m.group(1) if m.lastindex else m.group(0)
            return None

        elif source == "header":
            header_name = extract_def.get("name", extract_def.get("header", ""))
            return resp.headers.get(header_name)

        elif source == "cookie":
            cookie_name = extract_def.get("name", extract_def.get("cookie", ""))
            for c in resp.cookies:
                if c.name == cookie_name:
                    return c.value
            return None

        return None


# ═══════════════════════════════════════════════════════════════════════════════
# RE-AUTH SESSION — transparent 401 interception and credential refresh
# ═══════════════════════════════════════════════════════════════════════════════


class ReAuthSession:
    """
    Wraps a requests.Session + AuthHandler to transparently re-authenticate
    when a 401 response is received mid-scan.

    Only triggers on HTTP 401 (Unauthorized). HTTP 403 (Forbidden) is left
    alone — it indicates an authorization failure, not session expiry.

    Cooldown: max 3 re-auth attempts per 60-second window to prevent loops.
    """

    _MAX_RETRIES = 3
    _COOLDOWN_WINDOW = 60  # seconds

    def __init__(self, target_session: requests.Session, auth_handler: AuthHandler):
        self.target_session = target_session
        self.auth_handler = auth_handler
        self._retry_timestamps: list[float] = []
        self._original_request = target_session.request
        # Monkey-patch
        target_session.request = self._intercepting_request

    def _intercepting_request(self, method, url, **kwargs):
        """Intercept requests — on 401, re-auth and retry."""
        resp = self._original_request(method, url, **kwargs)

        # Only intercept 401, not 403
        if resp.status_code != 401:
            return resp

        # Check cooldown — purge old timestamps
        now = _time_mod.time()
        self._retry_timestamps = [
            t for t in self._retry_timestamps
            if now - t < self._COOLDOWN_WINDOW
        ]

        if len(self._retry_timestamps) >= self._MAX_RETRIES:
            # Exhausted retries in this window — pass through
            return resp

        # Attempt re-authentication
        self._retry_timestamps.append(now)
        print(f"[DAST] ⚠ 401 detected on {url[:80]} — re-authenticating "
              f"(attempt {len(self._retry_timestamps)}/{self._MAX_RETRIES})...")

        success = self.auth_handler.re_authenticate()
        if success:
            # Transfer refreshed cookies/headers to scan session
            self.auth_handler.transfer_cookies_to(self.target_session)
            print(f"[DAST] ✓ Re-authentication successful — retrying request")
            # Retry the original request
            return self._original_request(method, url, **kwargs)
        else:
            print(f"[DAST] ✗ Re-authentication failed — passing through 401")
            return resp

    def stop(self):
        """Restore the original request method."""
        self.target_session.request = self._original_request


# ═══════════════════════════════════════════════════════════════════════════════
# PROACTIVE RE-AUTH SESSION — timer/counter-based session refresh
# ═══════════════════════════════════════════════════════════════════════════════


class ProactiveReAuthSession:
    """
    Proactively refreshes authentication before session expiry — does NOT
    wait for a 401. Refreshes based on request count OR elapsed time,
    whichever threshold is hit first.

    Inspired by Burp's session handling rules + macro replay pattern.

    Also intercepts 401s as a fallback (same as ReAuthSession).

    Args:
        target_session:   The requests.Session used by the scanner.
        auth_handler:     AuthHandler with stored credentials.
        refresh_interval: Seconds between proactive refreshes (default 300 = 5 min).
        refresh_every_n:  Refresh after every N requests (default 100).
    """

    _MIN_COOLDOWN = 30  # never refresh more than once per 30 seconds

    def __init__(
        self,
        target_session: requests.Session,
        auth_handler: "AuthHandler",
        refresh_interval: int = 300,
        refresh_every_n: int = 100,
    ):
        self.target_session   = target_session
        self.auth_handler     = auth_handler
        self.refresh_interval = refresh_interval
        self.refresh_every_n  = refresh_every_n
        self._request_count   = 0
        self._last_refresh    = _time_mod.time()
        self._refresh_count   = 0
        self._original_request = target_session.request
        # Monkey-patch
        target_session.request = self._intercepting_request

    def _intercepting_request(self, method, url, **kwargs):
        """Intercept every request — proactively refresh if thresholds hit."""
        self._request_count += 1
        now = _time_mod.time()

        # Check if proactive refresh is needed
        time_elapsed = (now - self._last_refresh) >= self.refresh_interval
        count_elapsed = self._request_count >= self.refresh_every_n
        cooldown_ok = (now - self._last_refresh) >= self._MIN_COOLDOWN

        if (time_elapsed or count_elapsed) and cooldown_ok:
            self._do_refresh(reason="proactive")

        # Make the actual request
        resp = self._original_request(method, url, **kwargs)

        # Fallback: also handle 401 reactively
        if resp.status_code == 401 and cooldown_ok:
            self._do_refresh(reason="401")
            resp = self._original_request(method, url, **kwargs)

        return resp

    def _do_refresh(self, reason: str = "proactive") -> bool:
        """Execute re-authentication and transfer credentials."""
        self._refresh_count += 1
        try:
            success = self.auth_handler.re_authenticate()
            if success:
                self.auth_handler.transfer_cookies_to(self.target_session)
                self._request_count = 0
                self._last_refresh = _time_mod.time()
                print(f"[DAST] ✓ Proactive session refresh #{self._refresh_count} "
                      f"({reason}) — credentials refreshed")
                return True
            else:
                print(f"[DAST] ⚠ Proactive session refresh #{self._refresh_count} "
                      f"({reason}) — re-auth failed, continuing with existing session")
                self._last_refresh = _time_mod.time()  # reset timer even on failure
                return False
        except Exception as exc:
            print(f"[DAST] ⚠ Proactive session refresh error: {exc}")
            self._last_refresh = _time_mod.time()
            return False

    def stats(self) -> dict:
        """Return refresh statistics."""
        return {
            "total_refreshes": self._refresh_count,
            "requests_since_refresh": self._request_count,
            "refresh_interval": self.refresh_interval,
            "refresh_every_n": self.refresh_every_n,
        }

    def stop(self):
        """Restore original request method."""
        self.target_session.request = self._original_request


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

    def test_horizontal_idor(
        self,
        id_map: dict[str, list[str]],
        url_template: str,
        timeout: int = 10,
        callback=None,
    ) -> list[dict]:
        """
        Test horizontal privilege escalation — can User A access User B's resources?

        Args:
            id_map: {user_name: [object_ids]} — IDs harvested per user context
            url_template: URL with {id} placeholder, e.g. "/api/users/{id}/profile"
            timeout: request timeout
            callback: finding callback

        Returns: list of finding dicts
        """
        findings = []
        users_with_ids = {
            name: ids for name, ids in id_map.items()
            if ids and any(u.name == name for u in self.users)
        }

        if len(users_with_ids) < 2:
            return findings

        # For each user, try to access OTHER users' object IDs
        user_sessions = {u.name: u for u in self.users if u.authenticated}

        for owner_name, owner_ids in users_with_ids.items():
            for accessor_name, accessor_ctx in user_sessions.items():
                if accessor_name == owner_name:
                    continue  # Skip same user

                # Same role = horizontal, different role = vertical (already tested)
                owner_ctx = user_sessions.get(owner_name)
                if not owner_ctx:
                    continue
                if owner_ctx.role != accessor_ctx.role:
                    continue  # Only horizontal (same role)

                for obj_id in owner_ids[:5]:  # Cap at 5 IDs per pair
                    test_url = url_template.replace("{id}", str(obj_id))

                    try:
                        import time as _time
                        _time.sleep(0.3)
                        resp = accessor_ctx.session.get(
                            test_url, timeout=timeout, allow_redirects=True,
                        )
                    except Exception:
                        continue

                    # If accessor gets 200 on owner's resource = horizontal IDOR
                    if resp.status_code == 200:
                        # Verify it's not a generic/empty response
                        if len(resp.text) > 50:
                            finding = {
                                "url": test_url,
                                "vuln_type": "horizontal_privilege_escalation",
                                "severity": "high",
                                "category": "Access Control",
                                "finding": (
                                    f"Horizontal IDOR — '{accessor_name}' (role={accessor_ctx.role}) "
                                    f"can access '{owner_name}'s resource (id={obj_id})"
                                ),
                                "accessor": accessor_name,
                                "owner": owner_name,
                                "object_id": obj_id,
                                "response_length": len(resp.text),
                                "phase": "access_control",
                            }
                            findings.append(finding)
                            if callback:
                                callback(finding)
                            break  # One finding per user pair

        return findings

    def test_cross_user_idor(
        self,
        harvested_ids: list[tuple[str, str, str]],
        base_url: str,
        endpoint_patterns: list[str] | None = None,
        timeout: int = 10,
        callback=None,
    ) -> list[dict]:
        """
        Cross-user IDOR testing using harvested object IDs.

        Each user's session tries to access IDs that belong to other users.
        Tests multiple endpoint patterns to find IDOR across different resources.

        Args:
            harvested_ids: list of (param_name, id_value, owner_context) tuples
            base_url: base URL of the application
            endpoint_patterns: URL patterns with {param} and {id} placeholders
                e.g. ["/api/{param}/{id}", "/api/v1/{param}/{id}"]
            timeout: request timeout
            callback: finding callback

        Returns: list of finding dicts
        """
        if not endpoint_patterns:
            endpoint_patterns = [
                "/api/{param}/{id}",
                "/api/v1/{param}/{id}",
                "/{param}/{id}",
                "/api/{param}?id={id}",
                "/api/{param}/{id}/detail",
            ]

        findings = []
        user_sessions = {u.name: u for u in self.users if u.authenticated}

        if len(user_sessions) < 2:
            return findings

        # Group harvested IDs by owner context
        ids_by_owner: dict[str, list[tuple[str, str]]] = {}
        for param_name, id_value, owner_ctx in harvested_ids:
            ids_by_owner.setdefault(owner_ctx, []).append((param_name, id_value))

        tested = set()  # Avoid duplicate tests

        for owner_name, owner_ids in ids_by_owner.items():
            for accessor_name, accessor_ctx in user_sessions.items():
                if accessor_name == owner_name:
                    continue

                for param_name, id_value in owner_ids[:10]:  # Cap per owner
                    # Normalize param name for URL (remove _id suffix)
                    resource = param_name.rstrip("_id").rstrip("_")
                    if not resource:
                        resource = "resource"

                    for pattern in endpoint_patterns:
                        test_url = base_url.rstrip("/") + pattern.replace(
                            "{param}", resource
                        ).replace("{id}", str(id_value))

                        test_key = (accessor_name, test_url)
                        if test_key in tested:
                            continue
                        tested.add(test_key)

                        try:
                            import time as _time
                            _time.sleep(0.3)
                            resp = accessor_ctx.session.get(
                                test_url, timeout=timeout, allow_redirects=True,
                            )
                        except Exception:
                            continue

                        # 200 with substantive body = potential IDOR
                        if resp.status_code == 200 and len(resp.text) > 100:
                            # Check for PII/sensitive patterns
                            sensitive_patterns = [
                                r'"email"', r'"phone"', r'"address"',
                                r'"ssn"', r'"password"', r'"credit_card"',
                                r'"balance"', r'"salary"', r'"dob"',
                                r'@\w+\.\w+',  # email pattern
                            ]
                            has_sensitive = any(
                                re.search(p, resp.text[:4000], re.I)
                                for p in sensitive_patterns
                            )

                            severity = "critical" if has_sensitive else "high"
                            detail = " (contains PII)" if has_sensitive else ""

                            finding = {
                                "url": test_url,
                                "vuln_type": "cross_user_idor",
                                "severity": severity,
                                "category": "Access Control",
                                "finding": (
                                    f"Cross-user IDOR{detail} — '{accessor_name}' accessed "
                                    f"'{owner_name}'s {resource} (id={id_value})"
                                ),
                                "accessor": accessor_name,
                                "owner": owner_name,
                                "param_name": param_name,
                                "object_id": id_value,
                                "response_length": len(resp.text),
                                "has_sensitive_data": has_sensitive,
                                "phase": "access_control",
                            }
                            findings.append(finding)
                            if callback:
                                callback(finding)
                            break  # First working pattern is enough

        return findings


# ---------------------------------------------------------------------------
# Feature 9 — Auth Bypass Probes
# ---------------------------------------------------------------------------

import json as _json
import urllib.request
import urllib.error
from dataclasses import dataclass, field


@dataclass
class AuthBypassResult:
    """Result of an authentication/authorization bypass probe."""

    probe_type: str           # "no_auth" | "expired_token" | "idor" | "admin_claim"
    url: str
    method: str
    bypassed: bool            # True if bypass succeeded
    evidence: str             # HTTP status code + response snippet
    original_status: int = 0  # Status with valid auth
    bypass_status: int = 0    # Status without/with manipulated auth
    severity: str = "high"


# -- helper utilities -------------------------------------------------------

def _expire_jwt(token: str) -> str:
    """Modify JWT payload to set exp=0 (instant expiry)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return token
        # Decode payload (add padding)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = _json.loads(
            base64.b64decode(payload_b64).decode("utf-8", errors="replace")
        )
        payload["exp"] = 0
        new_payload = (
            base64.b64encode(_json.dumps(payload).encode()).decode().rstrip("=")
        )
        return f"{parts[0]}.{new_payload}.{parts[2]}"
    except Exception:
        return token


def _inject_admin_claims(token: str) -> str:
    """Inject admin role claims into JWT payload."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return token
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = _json.loads(
            base64.b64decode(payload_b64).decode("utf-8", errors="replace")
        )
        payload.update({
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "scope": "admin",
        })
        new_payload = (
            base64.b64encode(_json.dumps(payload).encode()).decode().rstrip("=")
        )
        return f"{parts[0]}.{new_payload}.{parts[2]}"
    except Exception:
        return token


def _increment_url_ids(url: str) -> list[str]:
    """Return URL variants with numeric IDs incremented/decremented by 1."""
    variants: list[str] = []
    pattern = re.compile(r"(\d+)")
    for match in pattern.finditer(url):
        n = int(match.group())
        for delta in (1, -1, 2):
            new_url = url[: match.start()] + str(n + delta) + url[match.end() :]
            variants.append(new_url)
    return variants[:3]  # Limit to 3 variants


def _extract_token_from_session(session: dict | None) -> str | None:
    """Extract a Bearer token or JWT from the session dict."""
    if not session:
        return None
    # Check common key names
    for key in ("Authorization", "authorization", "token", "access_token", "jwt"):
        val = session.get(key)
        if val and isinstance(val, str):
            # Strip "Bearer " prefix if present
            if val.lower().startswith("bearer "):
                return val[7:]
            return val
    # Check nested headers dict
    headers = session.get("headers") or session.get("Headers") or {}
    if isinstance(headers, dict):
        for key in ("Authorization", "authorization"):
            val = headers.get(key)
            if val and isinstance(val, str):
                if val.lower().startswith("bearer "):
                    return val[7:]
                return val
    return None


def _do_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    timeout: int = 10,
) -> tuple[int, str]:
    """Perform an HTTP request via urllib. Returns (status_code, body_snippet)."""
    req = urllib.request.Request(url, method=method.upper(), headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            return resp.status, body[:200]
    except urllib.error.HTTPError as exc:
        body = ""
        if exc.fp:
            try:
                body = exc.fp.read(4096).decode("utf-8", errors="replace")[:200]
            except Exception:
                pass
        return exc.code, body
    except Exception as exc:
        raise


# -- probe functions --------------------------------------------------------

def probe_no_auth(
    url: str,
    method: str = "GET",
    session: dict | None = None,
    timeout: int = 10,
) -> AuthBypassResult:
    """Test if endpoint accessible without authentication (Microsoft MSRC auth bypass technique)."""
    try:
        # First, get the original status with auth (if session provided)
        original_status = 0
        if session:
            auth_headers = {}
            token = _extract_token_from_session(session)
            if token:
                auth_headers["Authorization"] = f"Bearer {token}"
            # Merge any session headers
            sess_headers = session.get("headers") or session.get("Headers") or {}
            if isinstance(sess_headers, dict):
                auth_headers.update(sess_headers)
            try:
                original_status, _ = _do_request(url, method, auth_headers, timeout)
            except Exception:
                pass

        # Now make request with NO auth headers at all
        status, body = _do_request(url, method, {}, timeout)
        bypassed = 200 <= status <= 299
        return AuthBypassResult(
            probe_type="no_auth",
            url=url,
            method=method,
            bypassed=bypassed,
            evidence=f"Status {status}: {body}",
            original_status=original_status,
            bypass_status=status,
            severity="critical" if bypassed else "info",
        )
    except Exception as exc:
        return AuthBypassResult(
            probe_type="no_auth",
            url=url,
            method=method,
            bypassed=False,
            evidence=str(exc),
        )


def probe_expired_token(
    url: str,
    method: str = "GET",
    session: dict | None = None,
    timeout: int = 10,
) -> AuthBypassResult:
    """Test if server accepts expired/manipulated authentication tokens."""
    try:
        token = _extract_token_from_session(session)
        if not token:
            return AuthBypassResult(
                probe_type="expired_token",
                url=url,
                method=method,
                bypassed=False,
                evidence="No token found in session",
            )

        # Get original status with valid token
        original_status = 0
        try:
            original_status, _ = _do_request(
                url, method, {"Authorization": f"Bearer {token}"}, timeout
            )
        except Exception:
            pass

        # Manipulate JWT to expire it
        expired_token = _expire_jwt(token)
        status, body = _do_request(
            url, method, {"Authorization": f"Bearer {expired_token}"}, timeout
        )
        bypassed = 200 <= status <= 299
        return AuthBypassResult(
            probe_type="expired_token",
            url=url,
            method=method,
            bypassed=bypassed,
            evidence=f"Status {status}: {body}",
            original_status=original_status,
            bypass_status=status,
            severity="critical" if bypassed else "info",
        )
    except Exception as exc:
        return AuthBypassResult(
            probe_type="expired_token",
            url=url,
            method=method,
            bypassed=False,
            evidence=str(exc),
        )


def probe_idor(
    url: str,
    method: str = "GET",
    session: dict | None = None,
    alt_token: str | None = None,
    timeout: int = 10,
) -> AuthBypassResult:
    """Test for IDOR by accessing resource with different user context."""
    try:
        # Build auth headers from session
        auth_headers: dict[str, str] = {}
        token = _extract_token_from_session(session)
        if token:
            auth_headers["Authorization"] = f"Bearer {token}"
        sess_headers = (session or {}).get("headers") or (session or {}).get("Headers") or {}
        if isinstance(sess_headers, dict):
            auth_headers.update(sess_headers)

        # Get original response
        original_status = 0
        original_body = ""
        try:
            original_status, original_body = _do_request(
                url, method, auth_headers, timeout
            )
        except Exception:
            pass

        if alt_token:
            # Use alternative token to access the same resource
            alt_headers = dict(auth_headers)
            alt_headers["Authorization"] = f"Bearer {alt_token}"
            status, body = _do_request(url, method, alt_headers, timeout)
            bypassed = (200 <= status <= 299) and body != original_body
            return AuthBypassResult(
                probe_type="idor",
                url=url,
                method=method,
                bypassed=bypassed,
                evidence=f"Status {status}: {body}",
                original_status=original_status,
                bypass_status=status,
                severity="high" if bypassed else "info",
            )

        # No alt_token — try URL ID manipulation
        variants = _increment_url_ids(url)
        if not variants:
            return AuthBypassResult(
                probe_type="idor",
                url=url,
                method=method,
                bypassed=False,
                evidence="No numeric IDs found in URL to manipulate",
            )

        for variant_url in variants:
            try:
                status, body = _do_request(variant_url, method, auth_headers, timeout)
                if 200 <= status <= 299:
                    bypassed = body != original_body
                    return AuthBypassResult(
                        probe_type="idor",
                        url=variant_url,
                        method=method,
                        bypassed=bypassed,
                        evidence=f"Status {status}: {body}",
                        original_status=original_status,
                        bypass_status=status,
                        severity="high" if bypassed else "info",
                    )
            except Exception:
                continue

        return AuthBypassResult(
            probe_type="idor",
            url=url,
            method=method,
            bypassed=False,
            evidence="All IDOR variants returned non-200 responses",
            original_status=original_status,
            bypass_status=0,
        )
    except Exception as exc:
        return AuthBypassResult(
            probe_type="idor",
            url=url,
            method=method,
            bypassed=False,
            evidence=str(exc),
        )


def probe_admin_claim(
    url: str,
    method: str = "GET",
    session: dict | None = None,
    timeout: int = 10,
) -> AuthBypassResult:
    """Test for privilege escalation by injecting admin claims into JWT."""
    try:
        token = _extract_token_from_session(session)
        if not token:
            return AuthBypassResult(
                probe_type="admin_claim",
                url=url,
                method=method,
                bypassed=False,
                evidence="No token found in session",
            )

        # Get original status with valid token
        original_status = 0
        try:
            original_status, _ = _do_request(
                url, method, {"Authorization": f"Bearer {token}"}, timeout
            )
        except Exception:
            pass

        # Inject admin claims into JWT
        admin_token = _inject_admin_claims(token)
        status, body = _do_request(
            url, method, {"Authorization": f"Bearer {admin_token}"}, timeout
        )

        # Bypass if we got access (200) when original was forbidden (403)
        bypassed = (200 <= status <= 299) and original_status in (401, 403)
        # Also flag if 200 with different/expanded content
        if not bypassed and (200 <= status <= 299) and (200 <= original_status <= 299):
            # Could still be escalation if response differs — mark as potential
            bypassed = False  # Conservative: same-level access is not escalation

        return AuthBypassResult(
            probe_type="admin_claim",
            url=url,
            method=method,
            bypassed=bypassed,
            evidence=f"Status {status}: {body}",
            original_status=original_status,
            bypass_status=status,
            severity="critical" if bypassed else "info",
        )
    except Exception as exc:
        return AuthBypassResult(
            probe_type="admin_claim",
            url=url,
            method=method,
            bypassed=False,
            evidence=str(exc),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# MACRO RE-AUTH SESSION — 401 re-auth via full AuthScriptRunner macro replay
# ═══════════════════════════════════════════════════════════════════════════════


class MacroReAuthSession:
    """
    On 401, replays a multi-step AuthScriptRunner JSON macro to refresh
    credentials, then transfers all cookies/headers to the scan session.

    Use instead of ReAuthSession when login requires multi-step flows
    (CSRF extraction, MFA, OAuth, etc.). Shares the same 3/60s cooldown.
    """

    _MAX_RETRIES     = 3
    _COOLDOWN_WINDOW = 60  # seconds

    def __init__(
        self,
        target_session: requests.Session,
        script_path:    str,
        extra_vars:     Optional[dict] = None,
        timeout:        int = 15,
    ):
        self.target_session  = target_session
        self.script_path     = script_path
        self.extra_vars      = extra_vars or {}
        self.timeout         = timeout
        self._retry_timestamps: list[float] = []
        self._original_request = target_session.request
        target_session.request = self._intercepting_request

    def _intercepting_request(self, method, url, **kwargs):
        resp = self._original_request(method, url, **kwargs)
        if resp.status_code != 401:
            return resp

        # Cooldown guard
        now = _time_mod.time()
        self._retry_timestamps = [
            t for t in self._retry_timestamps
            if now - t < self._COOLDOWN_WINDOW
        ]
        if len(self._retry_timestamps) >= self._MAX_RETRIES:
            return resp

        self._retry_timestamps.append(now)
        attempt = len(self._retry_timestamps)
        print(f"[DAST] ⚠ 401 on {url[:80]} — replaying macro "
              f"(attempt {attempt}/{self._MAX_RETRIES})...")

        if not os.path.exists(self.script_path):
            print(f"[DAST] ✗ Macro script not found: {self.script_path}")
            return resp

        # Run macro in a fresh session so scan session stays clean
        macro_session = requests.Session()
        runner = AuthScriptRunner(macro_session, timeout=self.timeout)
        result = runner.run_script(self.script_path, extra_vars=self.extra_vars)

        if result.get("success"):
            # Transfer cookies from macro session to scan session
            for cookie in macro_session.cookies:
                self.target_session.cookies.set_cookie(cookie)
            # Transfer any auth headers the macro set
            for header, value in macro_session.headers.items():
                if header.lower() in ("authorization", "x-auth-token", "x-api-key"):
                    self.target_session.headers[header] = value
            print(f"[DAST] ✓ Macro re-auth successful "
                  f"({len(result.get('cookies', []))} cookies) — retrying request")
            return self._original_request(method, url, **kwargs)
        else:
            print(f"[DAST] ✗ Macro re-auth failed: {result.get('message', 'unknown')}")
            return resp

    def stop(self):
        """Restore original request method."""
        self.target_session.request = self._original_request


# ═══════════════════════════════════════════════════════════════════════════════
# COOKIE JAR RULES — filter/transform outbound cookies per request
# ═══════════════════════════════════════════════════════════════════════════════


class CookieJarRules:
    """
    Intercepts outbound cookies before each request and applies rules.

    Rule types:
      {"action": "block",         "name": "tracking_id"}          — remove named cookie
      {"action": "block_pattern", "pattern": "^_ga"}              — remove by regex
      {"action": "scope",         "domain": "api.target.com"}     — send NO cookies outside domain
      {"action": "add",           "name": "session", "value": "x"} — force-inject cookie
      {"action": "rename",        "from": "old",     "to": "new"} — rename cookie in header
    """

    def __init__(self, session: requests.Session, rules: list[dict]):
        self.session      = session
        self.rules        = rules
        self._orig_send   = session.send
        session.send      = self._filtered_send

    def _filtered_send(self, request, **kwargs):
        if "Cookie" in request.headers and self.rules:
            cookies = self._parse_header(request.headers["Cookie"])
            cookies = self._apply_rules(cookies, request.url)
            if cookies:
                request.headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in cookies.items()
                )
            else:
                del request.headers["Cookie"]
        return self._orig_send(request, **kwargs)

    @staticmethod
    def _parse_header(header: str) -> dict:
        """Parse 'a=1; b=2' into {'a': '1', 'b': '2'}."""
        result = {}
        for part in header.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                result[k.strip()] = v.strip()
            elif part:
                result[part] = ""
        return result

    def _apply_rules(self, cookies: dict, url: str) -> dict:
        import re as _re
        from urllib.parse import urlparse as _up
        hostname = _up(url).hostname or ""
        result   = dict(cookies)

        for rule in self.rules:
            action = rule.get("action", "")

            if action == "block":
                result.pop(rule.get("name", ""), None)

            elif action == "block_pattern":
                pat = _re.compile(rule.get("pattern", "(?!)"))
                result = {k: v for k, v in result.items() if not pat.search(k)}

            elif action == "scope":
                domain = rule.get("domain", "")
                if domain and domain not in hostname:
                    result = {}  # send no cookies to out-of-scope host

            elif action == "add":
                result[rule["name"]] = rule.get("value", "")

            elif action == "rename":
                old = rule.get("from", "")
                new = rule.get("to", "")
                if old and new and old in result:
                    result[new] = result.pop(old)

        return result

    def stop(self):
        """Restore original send method."""
        self.session.send = self._orig_send


# ═══════════════════════════════════════════════════════════════════════════════
# API KEY DESTINATION ENUM — Burp Suite Montoya ApikeyAuthentication port
# ═══════════════════════════════════════════════════════════════════════════════

import enum as _enum


class ApiKeyDestination(_enum.Enum):
    """
    Where to inject an API key in a request.
    Mirrors Burp Suite Montoya's ApikeyAuthentication destination enum.
    """
    HEADER = "header"   # HTTP request header (most common: X-API-Key)
    QUERY  = "query"    # URL query parameter  (?api_key=...)
    COOKIE = "cookie"   # Cookie jar           (Cookie: api_key=...)


class _ApiKeyQueryAuth(requests.auth.AuthBase):
    """Transparently injects an API key as a URL query parameter per request."""
    def __init__(self, name: str, key: str):
        self.name = name
        self.key  = key

    def __call__(self, r):
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        parsed = urlparse(r.url)
        qs     = parse_qsl(parsed.query)
        qs.append((self.name, self.key))
        r.url = urlunparse(parsed._replace(query=urlencode(qs)))
        return r


def set_api_key(
    handler:     "AuthHandler",
    key:         str,
    name:        str = "X-API-Key",
    destination: ApiKeyDestination = ApiKeyDestination.HEADER,
) -> None:
    """
    Apply a single API key to an AuthHandler session.

    This extends the existing AuthHandler.set_api_keys() (which only supports
    HEADER) with full HEADER / QUERY / COOKIE destination support.

    Args:
        handler:     An AuthHandler instance.
        key:         The API key value.
        name:        Header name, query param name, or cookie name.
        destination: Where the key is sent.
    """
    if destination is ApiKeyDestination.HEADER:
        handler.session.headers[name] = key

    elif destination is ApiKeyDestination.QUERY:
        handler.session.auth = _ApiKeyQueryAuth(name, key)

    elif destination is ApiKeyDestination.COOKIE:
        handler.session.cookies.set(name, key)

    handler.auth_type     = f"api_key_{destination.value}"
    handler.authenticated = True
    handler.auth_info     = {
        "type":        "api_key",
        "name":        name,
        "destination": destination.value,
        "key_preview": key[:8] + "..." if len(key) > 8 else key,
    }


def detect_auth_from_spec(spec: dict) -> dict:
    """
    Auto-detect authentication type from an OpenAPI securitySchemes block.

    Handles both:
      - OAS3:     spec["components"]["securitySchemes"]
      - Swagger 2: spec["securityDefinitions"]

    Returns a dict describing the first recognized scheme:
      {"type": "apiKey",  "name": "X-API-Key",  "in": "header"}
      {"type": "bearer"}
      {"type": "basic"}
      {"type": "none"}
    """
    # OAS3
    schemes = (
        spec.get("components", {}).get("securitySchemes")
        or spec.get("securityDefinitions")
        or {}
    )

    for scheme_name, scheme in schemes.items():
        scheme_type = (scheme.get("type") or "").lower()

        if scheme_type == "apikey":
            return {
                "type": "apiKey",
                "name": scheme.get("name", "X-API-Key"),
                "in":   scheme.get("in", "header"),
            }

        if scheme_type == "http":
            http_scheme = (scheme.get("scheme") or "").lower()
            if http_scheme == "bearer":
                return {"type": "bearer", "bearerFormat": scheme.get("bearerFormat", "JWT")}
            if http_scheme == "basic":
                return {"type": "basic"}

        if scheme_type == "oauth2":
            return {"type": "oauth2"}

    return {"type": "none"}


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION HANDLING ACTIONS — Burp Suite Montoya SessionHandlingAction port
# ═══════════════════════════════════════════════════════════════════════════════

from abc import ABC as _ABC, abstractmethod as _abstractmethod


class SessionHandlingAction(_ABC):
    """
    Abstract base class for pluggable session actions.
    Actions fire before and after each HTTP request in the pipeline.

    Port of Burp Suite Montoya's SessionHandlingAction interface.
    """

    def before_request(self, session: requests.Session, url: str, kwargs: dict) -> None:
        """
        Called before each HTTP request.  Modify ``kwargs`` in-place to inject
        headers, params, body fields, etc.

        Args:
            session: The requests.Session about to make the request.
            url:     The target URL.
            kwargs:  The keyword arguments dict that will be passed to session.request().
                     Modify this dict in-place to affect the outgoing request.
        """

    def after_response(self, response: requests.Response) -> None:
        """
        Called after each HTTP response.  Use to extract tokens (CSRF, session)
        from the response for use in subsequent requests.

        Args:
            response: The completed HTTP response.
        """


class CsrfTokenAction(SessionHandlingAction):
    """
    Extracts a CSRF token from each response and injects it into the next request.

    Port of the CSRF-handling pattern from Burp Suite's session handling rule
    'Set header from response'.

    Usage:
        action = CsrfTokenAction(
            pattern=r'name="_csrf" value="([^"]+)"',  # regex to extract token
            header_name="X-CSRF-Token",               # header to inject
        )
        pipeline = SessionActionPipeline()
        pipeline.add_action(action)
        pipeline.install(session)
    """

    def __init__(
        self,
        pattern:     str = r'(?:csrf[_-]?token|_token|authenticity_token)["\']?\s*[=:]\s*["\']?([A-Za-z0-9+/=_-]{16,})',
        header_name: str = "X-CSRF-Token",
        field_name:  Optional[str] = None,  # if set, also inject into form body
    ):
        self._pattern    = re.compile(pattern, re.IGNORECASE)
        self.header_name = header_name
        self.field_name  = field_name
        self._token:     Optional[str] = None

    def update_from_response(self, response: requests.Response) -> None:
        """Extract CSRF token from response body or Set-Cookie headers."""
        text = ""
        try:
            text = response.text or ""
        except Exception:
            pass

        m = self._pattern.search(text)
        if m:
            self._token = m.group(1)
            return

        # Fallback: check response headers (some frameworks send it there)
        for header in ("X-CSRF-Token", "X-CSRFToken", "csrf-token"):
            val = response.headers.get(header)
            if val:
                self._token = val
                return

    def after_response(self, response: requests.Response) -> None:
        self.update_from_response(response)

    def before_request(self, session: requests.Session, url: str, kwargs: dict) -> None:
        if not self._token:
            return
        # Inject into request headers
        headers = kwargs.setdefault("headers", {})
        headers[self.header_name] = self._token
        # Optionally also inject into form body
        if self.field_name:
            data = kwargs.get("data")
            if isinstance(data, dict):
                data[self.field_name] = self._token


class SessionActionPipeline:
    """
    Chains multiple SessionHandlingAction instances and hooks them into a
    requests.Session so they fire automatically before and after every request.

    Port of Burp Suite Montoya's SessionHandlingAction pipeline.

    Usage:
        pipeline = SessionActionPipeline()
        pipeline.add_action(CsrfTokenAction())
        pipeline.install(session)
        # ... run scan ...
        pipeline.uninstall(session)
    """

    def __init__(self):
        self._actions:  list[SessionHandlingAction] = []
        self._orig_req  = None

    def add_action(self, action: SessionHandlingAction) -> "SessionActionPipeline":
        """Append an action to the pipeline. Returns self for chaining."""
        self._actions.append(action)
        return self

    def install(self, session: requests.Session) -> None:
        """
        Monkey-patch session.request to run all actions before/after each call.
        Call uninstall() to restore the original behaviour.
        """
        if self._orig_req is not None:
            return  # already installed
        self._orig_req = session.request
        pipeline = self

        def _patched_request(method, url, **kwargs):
            for action in pipeline._actions:
                try:
                    action.before_request(session, url, kwargs)
                except Exception:
                    pass
            resp = pipeline._orig_req(method, url, **kwargs)
            for action in pipeline._actions:
                try:
                    action.after_response(resp)
                except Exception:
                    pass
            return resp

        session.request = _patched_request

    def uninstall(self, session: requests.Session) -> None:
        """Restore the original session.request method."""
        if self._orig_req is not None:
            session.request = self._orig_req
            self._orig_req  = None
