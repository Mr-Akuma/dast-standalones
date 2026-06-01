"""
Tests for modules/scanner.py — VulnerabilityScanner passive checks.

Focuses on pure-logic paths exercised without live HTTP:
  - _check_mixed_content   (HTTP resources on HTTPS pages)
  - _check_insecure_forms  (HTTP form actions, password autocomplete)
  - _check_error_disclosure (stack traces in error responses)
  - _check_cookie_scope    (Secure flag, broad domain, SameSite)
"""
import threading
from unittest.mock import MagicMock, patch
import pytest
import requests

from modules.scanner import VulnerabilityScanner


@pytest.fixture
def scanner(scope, mock_session):
    return VulnerabilityScanner(
        target="https://example.com",
        scope=scope,
        session=mock_session,
        rate_limit=0.0,
        stop_event=threading.Event(),
    )


def _sitemap(pages: dict) -> MagicMock:
    """Return a minimal sitemap-like object."""
    sm = MagicMock()
    sm.pages = pages
    return sm


def _resp(status_code: int = 200, body: str = "") -> MagicMock:
    """Return a minimal mock HTTP response."""
    r = MagicMock()
    r.status_code = status_code
    r.text = body
    return r


# ── _check_mixed_content ──────────────────────────────────────────────────────

@pytest.mark.scanner
class TestCheckMixedContent:

    def test_http_target_returns_empty(self, scanner):
        """Mixed content check only applies to HTTPS targets."""
        scanner.target = "http://example.com"
        body = '<img src="http://cdn.evil.com/track.png">'
        result = scanner._check_mixed_content(
            _sitemap({"http://example.com/": {"body": body}})
        )
        assert result == []

    def test_https_page_with_http_img_src_flagged(self, scanner):
        """HTTPS page with <img src='http://...'> produces mixed_content finding."""
        body = '<html><img src="http://cdn.evil.com/tracker.png"></html>'
        result = scanner._check_mixed_content(
            _sitemap({"https://example.com/": {"body": body}})
        )
        assert len(result) == 1
        assert result[0].vuln_type == "mixed_content"

    def test_https_page_with_https_resources_clean(self, scanner):
        """HTTPS page referencing only HTTPS resources → no finding."""
        body = '<img src="https://cdn.example.com/safe.png">'
        result = scanner._check_mixed_content(
            _sitemap({"https://example.com/": {"body": body}})
        )
        assert result == []

    def test_uses_cached_body_no_extra_request(self, scanner):
        """When body is in sitemap page dict, _req must not be called."""
        body = '<a href="http://external.com/resource">'
        with patch.object(scanner, "_req") as mock_req:
            result = scanner._check_mixed_content(
                _sitemap({"https://example.com/": {"body": body}})
            )
        mock_req.assert_not_called()
        assert len(result) == 1

    def test_stop_event_prevents_processing(self, scanner):
        """Stop event set before call → no pages processed, no findings."""
        scanner.stop_event.set()
        body = '<img src="http://evil.com/spy.png">'
        result = scanner._check_mixed_content(
            _sitemap({"https://example.com/page": {"body": body}})
        )
        assert result == []

    def test_http_url_page_in_sitemap_skipped(self, scanner):
        """HTTP page URL inside HTTPS target's sitemap is skipped."""
        body = '<img src="http://evil.com/x.png">'
        result = scanner._check_mixed_content(
            _sitemap({"http://example.com/redirect": {"body": body}})
        )
        assert result == []

    def test_finding_proof_contains_matched_reference(self, scanner):
        """Finding proof must include the matched HTTP reference."""
        body = '<script src="http://evil.com/track.js"></script>'
        result = scanner._check_mixed_content(
            _sitemap({"https://example.com/": {"body": body}})
        )
        assert result
        assert "http://" in result[0].proof


# ── _check_insecure_forms ─────────────────────────────────────────────────────

@pytest.mark.scanner
class TestCheckInsecureForms:

    def test_https_page_http_form_action_flagged(self, scanner):
        """Form with HTTP action on HTTPS page → insecure_form_action finding."""
        body = '<form action="http://example.com/submit" method="POST"><input type="text"></form>'
        result = scanner._check_insecure_forms(
            _sitemap({"https://example.com/login": {"body": body}})
        )
        assert any(f.vuln_type == "insecure_form_action" for f in result)

    def test_password_field_without_autocomplete_off_flagged(self, scanner):
        """Password input without autocomplete=off → password_autocomplete finding."""
        body = '<form><input type="password" name="pass"></form>'
        result = scanner._check_insecure_forms(
            _sitemap({"https://example.com/login": {"body": body}})
        )
        assert any(f.vuln_type == "password_autocomplete" for f in result)

    def test_password_field_with_autocomplete_off_clean(self, scanner):
        """Password input with autocomplete="off" → no password_autocomplete finding."""
        body = '<input type="password" name="pass" autocomplete="off">'
        result = scanner._check_insecure_forms(
            _sitemap({"https://example.com/login": {"body": body}})
        )
        assert not any(f.vuln_type == "password_autocomplete" for f in result)

    def test_secure_form_no_findings(self, scanner):
        """Page with HTTPS form action and no password fields → no findings."""
        body = '<form action="https://example.com/submit"><input type="text" name="q"></form>'
        result = scanner._check_insecure_forms(
            _sitemap({"https://example.com/form": {"body": body}})
        )
        assert result == []

    def test_http_page_http_form_action_not_flagged(self, scanner):
        """HTTP page with HTTP form → no insecure_form_action (HTTPS-only rule)."""
        body = '<form action="http://example.com/submit" method="POST"></form>'
        result = scanner._check_insecure_forms(
            _sitemap({"http://example.com/form": {"body": body}})
        )
        assert not any(f.vuln_type == "insecure_form_action" for f in result)

    def test_stop_event_skips_all_pages(self, scanner):
        """Stop event → no findings even for vulnerable page."""
        scanner.stop_event.set()
        body = '<form action="http://bad.com/s"><input type="password"></form>'
        result = scanner._check_insecure_forms(
            _sitemap({"https://example.com/login": {"body": body}})
        )
        assert result == []


# ── _check_error_disclosure ───────────────────────────────────────────────────

@pytest.mark.scanner
class TestCheckErrorDisclosure:

    def test_python_traceback_in_4xx_flagged(self, scanner):
        """4xx response with Python traceback → error_disclosure finding.

        _check_error_disclosure first fetches the baseline (main page) to avoid
        flagging sites that always return error patterns. We must return a clean
        200 for the baseline call and the error body for subsequent trigger calls.
        """
        err_body = "Traceback (most recent call last):\n  File 'app.py', line 10, in handler"
        clean = _resp(200, "<html><body>Home</body></html>")
        err   = _resp(500, err_body)
        with patch.object(scanner, "_req", side_effect=[clean] + [err] * 20):
            result = scanner._check_error_disclosure(_sitemap({}))
        assert any(f.vuln_type == "error_disclosure" for f in result)

    def test_php_fatal_error_in_500_flagged(self, scanner):
        """500 response with PHP Fatal error → error_disclosure finding."""
        err_body = "Fatal error: Call to undefined function something() on line 42"
        clean = _resp(200, "<html><body>Home</body></html>")
        err   = _resp(500, err_body)
        with patch.object(scanner, "_req", side_effect=[clean] + [err] * 20):
            result = scanner._check_error_disclosure(_sitemap({}))
        assert any(f.vuln_type == "error_disclosure" for f in result)

    def test_200_ok_body_not_flagged(self, scanner):
        """200 OK response not flagged even if body contains error text."""
        # error_triggers only flag when status_code >= 400
        # debug_paths only flag when status_code == 200 AND len(body) > 100
        err_body = "Traceback"  # < 100 chars → debug path won't trigger
        with patch.object(scanner, "_req", return_value=_resp(200, err_body)):
            result = scanner._check_error_disclosure(_sitemap({}))
        assert result == []

    def test_clean_error_page_no_finding(self, scanner):
        """Generic 404 without stack trace → no finding."""
        clean_body = "<html><body><h1>Page Not Found</h1></body></html>"
        with patch.object(scanner, "_req", return_value=_resp(404, clean_body)):
            result = scanner._check_error_disclosure(_sitemap({}))
        assert result == []

    def test_req_none_no_crash(self, scanner):
        """None response from _req → no crash, returns empty."""
        with patch.object(scanner, "_req", return_value=None):
            result = scanner._check_error_disclosure(_sitemap({}))
        assert result == []

    def test_finding_severity_is_medium(self, scanner):
        """Error disclosure findings carry medium severity."""
        err_body = "Traceback (most recent call last):\n  File 'x.py', line 1"
        with patch.object(scanner, "_req", return_value=_resp(500, err_body)):
            result = scanner._check_error_disclosure(_sitemap({}))
        if result:
            assert result[0].severity == "medium"


# ── _check_cookie_scope ───────────────────────────────────────────────────────

@pytest.mark.scanner
class TestCheckCookieScope:

    def _make_resp(self, cookie_name="session", secure=True, domain=".example.com",
                   samesite="Lax"):
        """Build a mock response with one cookie and configurable attributes.

        Pass samesite=None to omit the SameSite attribute from Set-Cookie.
        """
        resp = MagicMock()

        cookie = MagicMock()
        cookie.name  = cookie_name
        cookie.value = "secretvalue12345"
        cookie.secure = secure
        cookie.domain = domain
        cookie.path = "/"
        resp.cookies = [cookie]

        raw_header = f"{cookie_name}=secretvalue12345; Path=/"
        if samesite:
            raw_header += f"; SameSite={samesite}"
        resp.raw.headers.getlist.return_value = [raw_header]
        resp.headers = {"Set-Cookie": raw_header}
        return resp

    def test_insecure_cookie_on_https_flagged(self, scanner):
        """Cookie without Secure flag on HTTPS → finding mentioning Secure."""
        resp = self._make_resp(secure=False, samesite="Lax")
        with patch.object(scanner, "_req", return_value=resp):
            result = scanner._check_cookie_scope(_sitemap({}))
        assert any("Secure" in f.finding for f in result)

    def test_secure_cookie_no_secure_flag_finding(self, scanner):
        """Cookie with Secure=True → no 'missing Secure flag' finding."""
        resp = self._make_resp(secure=True, samesite="Lax")
        with patch.object(scanner, "_req", return_value=resp):
            result = scanner._check_cookie_scope(_sitemap({}))
        assert not any("missing Secure flag" in f.finding for f in result)

    def test_broad_domain_scope_flagged(self, scanner):
        """Cookie scoped to .example.com (2-part domain) → broad domain finding."""
        resp = self._make_resp(secure=True, domain=".example.com", samesite="Lax")
        with patch.object(scanner, "_req", return_value=resp):
            result = scanner._check_cookie_scope(_sitemap({}))
        assert any("broad domain" in f.finding.lower() for f in result)

    def test_no_samesite_attribute_flagged(self, scanner):
        """Cookie missing SameSite → CSRF vulnerability finding."""
        resp = self._make_resp(secure=True, domain="example.com", samesite=None)
        with patch.object(scanner, "_req", return_value=resp):
            result = scanner._check_cookie_scope(_sitemap({}))
        assert any("SameSite" in f.finding for f in result)

    def test_req_none_returns_empty(self, scanner):
        """None response from _req → no crash, returns empty list."""
        with patch.object(scanner, "_req", return_value=None):
            result = scanner._check_cookie_scope(_sitemap({}))
        assert result == []


# ── ScanFinding timing fields ─────────────────────────────────────────────────

@pytest.mark.scanner
class TestScanFindingTimingFields:
    """ISC-24/25: ScanFinding has baseline_time_ms and time_delta_ms; to_dict emits them."""

    def _make_finding(self, scanner):
        return scanner._make_finding(
            url="https://example.com/login",
            method="POST",
            param="username",
            param_type="json",
            vuln_type="sqli_blind_time",
            finding="Time-based blind SQLi confirmed",
            severity="high",
            proof="delayed 5s",
            payload="' OR SLEEP(5)--",
            resp_time_ms=5200.0,
            baseline_time_ms=120.0,
            time_delta_ms=5080.0,
        )

    def test_scan_finding_has_baseline_time_ms(self, scanner):
        sf = self._make_finding(scanner)
        assert hasattr(sf, "baseline_time_ms")
        assert sf.baseline_time_ms == 120.0

    def test_scan_finding_has_time_delta_ms(self, scanner):
        sf = self._make_finding(scanner)
        assert hasattr(sf, "time_delta_ms")
        assert sf.time_delta_ms == 5080.0

    def test_scan_finding_default_baseline_zero(self, scanner):
        sf = scanner._make_finding(
            url="https://example.com/", method="GET", param="q", param_type="query",
            vuln_type="xss_reflected", finding="XSS", severity="medium",
            proof="<script>", payload="<script>alert(1)</script>",
        )
        assert sf.baseline_time_ms == 0.0
        assert sf.time_delta_ms == 0.0

    def test_to_dict_emits_baseline_time_ms(self, scanner):
        sf = self._make_finding(scanner)
        d = sf.to_dict()
        assert "baseline_time_ms" in d
        assert d["baseline_time_ms"] == 120.0

    def test_to_dict_emits_time_delta_ms(self, scanner):
        sf = self._make_finding(scanner)
        d = sf.to_dict()
        assert "time_delta_ms" in d
        assert d["time_delta_ms"] == 5080.0
