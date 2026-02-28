"""
Authentication Module — handles form-based login, Bearer token, Basic auth,
and cookie injection. Maintains session for authenticated scanning.
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
