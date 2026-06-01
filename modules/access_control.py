"""
Access Control Testing — automated role-based access control (RBAC) matrix testing.
Equivalent to ZAP's Access Control Testing add-on.

Tests horizontal privilege escalation (same-role cross-user),
vertical privilege escalation (low-priv accessing high-priv resources),
unauthenticated access to protected resources, and HTTP verb tampering.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, asdict
from typing import Optional
import requests


@dataclass
class AccessControlFinding:
    url: str
    method: str
    test_type: str
    role: str
    finding: str
    severity: str
    evidence: str
    cwe: str
    agent_id: str = "access_control"
    icon: str = "\U0001f510"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AccessMatrix:
    role: str
    url: str
    method: str
    expected_accessible: bool
    actual_status: int
    bypassed: bool
    evidence: str

    def to_dict(self) -> dict:
        return asdict(self)


class AccessControlTester:
    """Automated RBAC matrix tester — checks horizontal/vertical escalation,
    unauthenticated access, verb tampering, and path traversal bypasses."""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        session: requests.Session,
        method: str,
        url: str,
        **kwargs,
    ) -> tuple[Optional[requests.Response], Optional[str]]:
        """Safe request wrapper. Returns (response, None) on success or
        (None, error_string) on failure."""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        try:
            resp = session.request(method, url, **kwargs)
            return resp, None
        except requests.RequestException as exc:
            return None, str(exc)

    # ------------------------------------------------------------------
    # Test: Unauthenticated access
    # ------------------------------------------------------------------

    def test_unauthenticated_access(
        self,
        url: str,
        method: str = "GET",
        expected_status: int = 401,
    ) -> list[AccessControlFinding]:
        """Makes a request with no session/cookies. If the server responds
        with 200 or a 302 that does NOT redirect to a login page, it is
        considered a bypass (missing authentication)."""
        findings: list[AccessControlFinding] = []
        clean_session = requests.Session()

        resp, err = self._request(clean_session, method, url)
        if err:
            return findings

        bypassed = False
        evidence = f"status={resp.status_code}"

        if resp.status_code == 200:
            bypassed = True
            evidence = f"status=200, content_length={len(resp.content)}"
        elif resp.status_code == 302:
            location = resp.headers.get("Location", "")
            # If redirect does NOT point to a login-like path, treat as bypass
            login_keywords = ("login", "signin", "sign-in", "auth", "sso", "cas")
            if not any(kw in location.lower() for kw in login_keywords):
                bypassed = True
                evidence = f"status=302, location={location} (no login redirect)"

        if bypassed:
            findings.append(
                AccessControlFinding(
                    url=url,
                    method=method,
                    test_type="unauthenticated_access",
                    role="anonymous",
                    finding=(
                        f"Resource accessible without authentication "
                        f"(expected {expected_status})"
                    ),
                    severity="High",
                    evidence=evidence,
                    cwe="CWE-306",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Test: Horizontal privilege escalation (IDOR)
    # ------------------------------------------------------------------

    def test_horizontal_escalation(
        self,
        session_a: requests.Session,
        session_b: requests.Session,
        url: str,
        method: str = "GET",
    ) -> list[AccessControlFinding]:
        """Two sessions at the *same* privilege level but different users.
        session_a 'owns' the resource; session_b should NOT be able to
        access it. If session_b gets 200 with a similar content length,
        we flag possible IDOR / horizontal escalation."""
        findings: list[AccessControlFinding] = []

        # Establish baseline with session_a (resource owner)
        resp_a, err_a = self._request(session_a, method, url)
        if err_a or resp_a is None or resp_a.status_code != 200:
            return findings  # Cannot establish baseline

        # Attempt with session_b (different user, same role)
        resp_b, err_b = self._request(session_b, method, url)
        if err_b or resp_b is None:
            return findings

        if resp_b.status_code == 200:
            len_a = len(resp_a.content)
            len_b = len(resp_b.content)
            # Content-length similarity check (within 20%)
            threshold = max(len_a, 1) * 0.2
            similar_content = abs(len_a - len_b) <= threshold

            if similar_content:
                findings.append(
                    AccessControlFinding(
                        url=url,
                        method=method,
                        test_type="horizontal_escalation",
                        role="same_level_peer",
                        finding=(
                            "Possible IDOR — another user at the same privilege "
                            "level can access this resource with similar response"
                        ),
                        severity="High",
                        evidence=(
                            f"owner_status=200 (len={len_a}), "
                            f"peer_status=200 (len={len_b}), "
                            f"delta={abs(len_a - len_b)}"
                        ),
                        cwe="CWE-639",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Test: Vertical privilege escalation
    # ------------------------------------------------------------------

    def test_vertical_escalation(
        self,
        low_session: requests.Session,
        high_session: requests.Session,
        url: str,
        method: str = "GET",
    ) -> list[AccessControlFinding]:
        """high_session (admin) establishes the baseline. If low_session
        (regular user) gets 200 for the same resource, privilege
        escalation is possible."""
        findings: list[AccessControlFinding] = []

        # Admin baseline
        resp_high, err_high = self._request(high_session, method, url)
        if err_high or resp_high is None:
            return findings

        # Skip if admin cannot access (not actually an admin resource)
        if resp_high.status_code != 200:
            return findings

        # Low-privilege attempt
        resp_low, err_low = self._request(low_session, method, url)
        if err_low or resp_low is None:
            return findings

        if resp_low.status_code == 200:
            findings.append(
                AccessControlFinding(
                    url=url,
                    method=method,
                    test_type="vertical_escalation",
                    role="low_privilege",
                    finding=(
                        "Privilege escalation — low-privilege user can access "
                        "admin-level resource"
                    ),
                    severity="Critical",
                    evidence=(
                        f"admin_status={resp_high.status_code} "
                        f"(len={len(resp_high.content)}), "
                        f"low_priv_status={resp_low.status_code} "
                        f"(len={len(resp_low.content)})"
                    ),
                    cwe="CWE-269",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Test: HTTP verb tampering
    # ------------------------------------------------------------------

    def test_http_verb_tampering(
        self,
        session: requests.Session,
        url: str,
    ) -> list[AccessControlFinding]:
        """Baseline with GET. Then try alternative HTTP verbs. If any verb
        returns 200 when GET returned 401/403, verb tampering is possible."""
        findings: list[AccessControlFinding] = []

        resp_get, err_get = self._request(session, "GET", url)
        if err_get or resp_get is None:
            return findings

        # Only interesting when GET is blocked
        if resp_get.status_code not in (401, 403):
            return findings

        alternative_verbs = [
            "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
            "TRACE", "CONNECT", "PROPFIND", "MKCOL",
        ]

        for verb in alternative_verbs:
            resp, err = self._request(session, verb, url)
            if err or resp is None:
                continue

            if resp.status_code == 200:
                findings.append(
                    AccessControlFinding(
                        url=url,
                        method=verb,
                        test_type="http_verb_tampering",
                        role="current_session",
                        finding=(
                            f"Verb tampering bypass — {verb} returns 200 "
                            f"while GET returns {resp_get.status_code}"
                        ),
                        severity="High",
                        evidence=(
                            f"GET_status={resp_get.status_code}, "
                            f"{verb}_status=200, "
                            f"content_length={len(resp.content)}"
                        ),
                        cwe="CWE-650",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Test: Path traversal / bypass
    # ------------------------------------------------------------------

    def test_path_traversal_bypass(
        self,
        session: requests.Session,
        url: str,
    ) -> list[AccessControlFinding]:
        """If the original URL returns 403, try path manipulation variants
        that might bypass simplistic path-based access controls."""
        findings: list[AccessControlFinding] = []

        resp_orig, err_orig = self._request(session, "GET", url)
        if err_orig or resp_orig is None:
            return findings

        # Only interesting when original is blocked
        if resp_orig.status_code != 403:
            return findings

        # Build bypass variants from the URL path
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)
        path = parsed.path

        # Generate path variants
        variants: list[tuple[str, str]] = []

        # 1. Path traversal: /admin/../admin/users → insert /../<first_segment>
        segments = [s for s in path.split("/") if s]
        if len(segments) >= 1:
            traversal_path = f"/{segments[0]}/../{path.lstrip('/')}"
            variants.append((traversal_path, "path_traversal (/../)"))

        # 2. Case variation: /ADMIN/users
        if segments:
            cased = "/" + "/".join(
                s.upper() if i == 0 else s for i, s in enumerate(segments)
            )
            variants.append((cased, "case_variation (upper)"))

        # 3. Double slash: //admin/users
        double_slash = "/" + path
        variants.append((double_slash, "double_slash"))

        # 4. Dot segment: /admin/./users
        if len(segments) >= 2:
            dot_path = f"/{segments[0]}/./{'/'.join(segments[1:])}"
            variants.append((dot_path, "dot_segment (/./)"))

        # 5. URL encoding of first segment: /%61dmin/users
        if segments:
            encoded_first = "".join(f"%{ord(c):02x}" for c in segments[0])
            encoded_path = f"/{encoded_first}"
            if len(segments) > 1:
                encoded_path += "/" + "/".join(segments[1:])
            variants.append((encoded_path, "url_encoding"))

        for variant_path, description in variants:
            variant_url = urlunparse(
                (parsed.scheme, parsed.netloc, variant_path,
                 parsed.params, parsed.query, parsed.fragment)
            )
            resp, err = self._request(session, "GET", variant_url)
            if err or resp is None:
                continue

            if resp.status_code == 200:
                findings.append(
                    AccessControlFinding(
                        url=variant_url,
                        method="GET",
                        test_type="path_traversal_bypass",
                        role="current_session",
                        finding=(
                            f"Path-based access control bypass via "
                            f"{description}"
                        ),
                        severity="High",
                        evidence=(
                            f"original_url={url} (status=403), "
                            f"bypass_url={variant_url} (status=200), "
                            f"technique={description}"
                        ),
                        cwe="CWE-22",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Build access matrix
    # ------------------------------------------------------------------

    def build_matrix(
        self,
        sessions_dict: dict[str, requests.Session],
        urls: list[tuple[str, str]],
    ) -> list[AccessMatrix]:
        """For every (url, method) tuple test every role-session.
        Returns a full access matrix."""
        matrix: list[AccessMatrix] = []

        for url, method in urls:
            for role, session in sessions_dict.items():
                resp, err = self._request(session, method, url)
                if err or resp is None:
                    matrix.append(
                        AccessMatrix(
                            role=role,
                            url=url,
                            method=method,
                            expected_accessible=False,
                            actual_status=0,
                            bypassed=False,
                            evidence=f"error: {err}" if err else "no response",
                        )
                    )
                    continue

                accessible = resp.status_code == 200
                matrix.append(
                    AccessMatrix(
                        role=role,
                        url=url,
                        method=method,
                        expected_accessible=True,
                        actual_status=resp.status_code,
                        bypassed=False,
                        evidence=f"status={resp.status_code}, len={len(resp.content)}",
                    )
                )

        return matrix

    # ------------------------------------------------------------------
    # Full scan orchestrator
    # ------------------------------------------------------------------

    def scan(
        self,
        sessions_dict: dict[str, requests.Session],
        urls: list[tuple[str, str]],
    ) -> list[AccessControlFinding]:
        """Run all applicable access control tests.

        With 1 session  : unauthenticated access + verb tampering + path bypass
        With 2+ sessions: all of the above + horizontal & vertical escalation
        """
        findings: list[AccessControlFinding] = []
        roles = list(sessions_dict.keys())
        sessions = list(sessions_dict.values())

        for url, method in urls:
            # Always run: unauthenticated access
            findings.extend(
                self.test_unauthenticated_access(url, method)
            )

            # Always run: verb tampering (use first session)
            if sessions:
                findings.extend(
                    self.test_http_verb_tampering(sessions[0], url)
                )

            # Always run: path traversal bypass (use first session)
            if sessions:
                findings.extend(
                    self.test_path_traversal_bypass(sessions[0], url)
                )

            # Multi-session tests
            if len(sessions) >= 2:
                # Horizontal escalation: test each pair of sessions
                for i in range(len(sessions)):
                    for j in range(i + 1, len(sessions)):
                        findings.extend(
                            self.test_horizontal_escalation(
                                sessions[i], sessions[j], url, method,
                            )
                        )

                # Vertical escalation: treat first session as high-priv,
                # all others as low-priv
                high_session = sessions[0]
                for low_session in sessions[1:]:
                    findings.extend(
                        self.test_vertical_escalation(
                            low_session, high_session, url, method,
                        )
                    )

        return findings
