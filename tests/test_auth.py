"""
Tests for modules/auth.py — AuthHandler and module-level helpers.

Covers:
  - _extract_token() static method (explicit path + auto-detect)
  - _extract_token_from_session() module-level function
  - set_bearer / set_basic / set_cookie / set_header public API
  - get_auth_summary() contract
  - token_login() success, failure, and edge cases
  - _find_login_form() form selection heuristics
  - _build_login_payload() credential injection
  - _detect_login_success() heuristic detection
  - store_credentials() / re_authenticate() lifecycle
"""
import threading
from unittest.mock import MagicMock, patch
import pytest
import requests

from modules.auth import AuthHandler, _extract_token_from_session


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def handler():
    """AuthHandler with a mocked requests session injected."""
    h = AuthHandler(timeout=5)
    h.session = MagicMock(spec=requests.Session)
    # Requests session needs headers dict-like for setitem
    h.session.headers = {}
    h.session.cookies = MagicMock()
    return h


def _mock_post_response(status_code: int = 200, json_data=None):
    """Build a mock response for session.post()."""
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("not json")
    return resp


# ── _extract_token() static method ───────────────────────────────────────────

@pytest.mark.auth
class TestExtractToken:

    def test_explicit_token_path_top_level(self):
        """token_path='access_token' extracts value from dict."""
        data = {"access_token": "abc123def456789xyz"}
        assert AuthHandler._extract_token(data, token_path="access_token") == "abc123def456789xyz"

    def test_explicit_dot_path_nested(self):
        """token_path='data.access_token' traverses nested dict."""
        data = {"data": {"access_token": "nested_token_value_xyz"}}
        assert AuthHandler._extract_token(data, token_path="data.access_token") == "nested_token_value_xyz"

    def test_missing_key_in_dot_path_returns_none(self):
        """Dot-path with missing intermediate key returns None."""
        data = {"data": {"other": "value"}}
        assert AuthHandler._extract_token(data, token_path="data.access_token") is None

    def test_auto_detect_token_key(self):
        """Auto-detect finds 'token' key at top level."""
        data = {"token": "auto_detected_token_value_xyz"}
        assert AuthHandler._extract_token(data) == "auto_detected_token_value_xyz"

    def test_auto_detect_access_token_key(self):
        """Auto-detect finds 'access_token' key at top level."""
        data = {"access_token": "bearer_access_value_123xyz"}
        assert AuthHandler._extract_token(data) == "bearer_access_value_123xyz"

    def test_auto_detect_nested_under_data_wrapper(self):
        """Auto-detect traverses 'data' wrapper to find token."""
        data = {"data": {"token": "nested_under_data_wrapper_xyz"}}
        assert AuthHandler._extract_token(data) == "nested_under_data_wrapper_xyz"

    def test_jwt_pattern_fallback(self):
        """JWT-shaped string (xxx.yyy.zzz) detected as last resort."""
        header = "eyJhbGciOiJIUzI1NiJ9"   # 20 chars
        payload = "eyJ1c2VyX2lkIjoxMjN9"  # 20 chars
        sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # 44 chars
        jwt = f"{header}.{payload}.{sig}"
        data = {"custom_field": jwt}
        assert AuthHandler._extract_token(data) == jwt

    def test_non_dict_data_returns_none(self):
        """Non-dict input (list, string, None) returns None."""
        assert AuthHandler._extract_token(["token"]) is None
        assert AuthHandler._extract_token("raw string") is None
        assert AuthHandler._extract_token(None) is None

    def test_short_value_not_returned(self):
        """Token value shorter than 11 chars is rejected (noise filter)."""
        data = {"token": "shortval"}   # 8 chars — below threshold
        assert AuthHandler._extract_token(data) is None


# ── _extract_token_from_session() module-level function ──────────────────────

@pytest.mark.auth
class TestExtractTokenFromSession:

    def test_authorization_key_strips_bearer_prefix(self):
        """'Authorization: Bearer <token>' key strips the prefix."""
        session = {"Authorization": "Bearer my_actual_token_value"}
        assert _extract_token_from_session(session) == "my_actual_token_value"

    def test_authorization_lowercase_returns_value(self):
        """'authorization' lowercase without 'Bearer ' returns raw value."""
        session = {"authorization": "raw_token_value_xyz"}
        assert _extract_token_from_session(session) == "raw_token_value_xyz"

    def test_token_key_returns_value(self):
        """'token' key returns value directly."""
        session = {"token": "direct_token_value_abc"}
        assert _extract_token_from_session(session) == "direct_token_value_abc"

    def test_access_token_key_returns_value(self):
        """'access_token' key returns value directly."""
        session = {"access_token": "access_token_value_xyz"}
        assert _extract_token_from_session(session) == "access_token_value_xyz"

    def test_nested_headers_dict_with_bearer(self):
        """Nested 'headers' dict with Authorization + Bearer prefix extracted."""
        session = {"headers": {"Authorization": "Bearer from_headers_dict"}}
        assert _extract_token_from_session(session) == "from_headers_dict"

    def test_none_session_returns_none(self):
        """None input returns None without error."""
        assert _extract_token_from_session(None) is None

    def test_empty_dict_returns_none(self):
        """Empty session dict returns None."""
        assert _extract_token_from_session({}) is None


# ── set_bearer / set_basic / set_cookie / set_header ─────────────────────────

@pytest.mark.auth
class TestPublicSetters:

    def test_set_bearer_adds_authorization_header(self, handler):
        """set_bearer sets 'Bearer <token>' in session headers."""
        handler.set_bearer("my_bearer_token_xyz")
        assert handler.session.headers["Authorization"] == "Bearer my_bearer_token_xyz"

    def test_set_bearer_marks_authenticated(self, handler):
        """set_bearer sets auth_type='bearer' and authenticated=True."""
        handler.set_bearer("token_value")
        assert handler.authenticated is True
        assert handler.auth_type == "bearer"

    def test_set_basic_sets_session_auth_tuple(self, handler):
        """set_basic assigns (username, password) tuple to session.auth."""
        handler.set_basic("admin", "secret123")
        assert handler.session.auth == ("admin", "secret123")

    def test_set_basic_marks_authenticated(self, handler):
        """set_basic sets authenticated=True and auth_type='basic'."""
        handler.set_basic("user", "pass")
        assert handler.authenticated is True
        assert handler.auth_type == "basic"

    def test_set_cookie_calls_session_set(self, handler):
        """set_cookie calls session.cookies.set with name and value."""
        handler.set_cookie("auth_session", "cookie_value_abc")
        handler.session.cookies.set.assert_called_once_with("auth_session", "cookie_value_abc")

    def test_set_header_adds_named_header(self, handler):
        """set_header adds the specified header key to session headers."""
        handler.set_header("X-API-Key", "my_api_key_12345")
        assert handler.session.headers["X-API-Key"] == "my_api_key_12345"

    def test_get_auth_summary_has_required_keys(self, handler):
        """get_auth_summary returns dict with all required keys."""
        handler.set_bearer("tok")
        handler.session.cookies = MagicMock()
        handler.session.cookies.__iter__ = MagicMock(return_value=iter([]))
        handler.session.cookies.keys = MagicMock(return_value=[])
        summary = handler.get_auth_summary()
        assert {"authenticated", "auth_type", "info", "cookies", "headers"}.issubset(summary.keys())

    def test_get_auth_summary_authenticated_reflects_state(self, handler):
        """get_auth_summary.authenticated matches handler.authenticated."""
        handler.session.cookies.keys = MagicMock(return_value=[])
        handler.session.headers = {}
        assert handler.get_auth_summary()["authenticated"] is False
        handler.set_bearer("t")
        assert handler.get_auth_summary()["authenticated"] is True


# ── token_login() ─────────────────────────────────────────────────────────────

@pytest.mark.auth
class TestTokenLogin:

    def test_successful_login_sets_bearer_header(self, handler):
        """Successful token_login sets 'Authorization: Bearer <token>' header."""
        handler.session.post.return_value = _mock_post_response(
            200, {"access_token": "eyJ.payload.signature_long_enough"}
        )
        result = handler.token_login("https://api.example.com/auth", "user", "pass")
        assert result["success"] is True
        assert "Bearer " in handler.session.headers.get("Authorization", "")

    def test_successful_login_sets_authenticated(self, handler):
        """Successful token_login sets authenticated=True."""
        handler.session.post.return_value = _mock_post_response(
            200, {"token": "a_very_long_token_value_here"}
        )
        handler.token_login("https://api.example.com/auth", "user", "pass")
        assert handler.authenticated is True

    def test_non_json_response_returns_failure(self, handler):
        """Non-JSON response body → success=False with informative message."""
        handler.session.post.return_value = _mock_post_response(200, None)
        result = handler.token_login("https://api.example.com/auth", "user", "pass")
        assert result["success"] is False
        assert "not JSON" in result["message"] or "JSON" in result["message"]

    def test_http_4xx_returns_failure(self, handler):
        """HTTP 401 response → success=False."""
        handler.session.post.return_value = _mock_post_response(
            401, {"error": "Invalid credentials"}
        )
        result = handler.token_login("https://api.example.com/auth", "user", "wrongpass")
        assert result["success"] is False

    def test_token_not_in_response_returns_failure(self, handler):
        """JSON response with no token field → success=False with hint."""
        handler.session.post.return_value = _mock_post_response(
            200, {"status": "ok", "user_id": 42}
        )
        result = handler.token_login("https://api.example.com/auth", "user", "pass")
        assert result["success"] is False
        assert "token-path" in result["message"].lower() or "token_path" in result["message"].lower() or "token" in result["message"].lower()

    def test_network_exception_returns_failure(self, handler):
        """Network exception (ConnectionError) → success=False."""
        handler.session.post.side_effect = Exception("Connection refused")
        result = handler.token_login("https://api.example.com/auth", "user", "pass")
        assert result["success"] is False
        assert "POST failed" in result["message"]

    def test_token_path_param_extracts_nested_token(self, handler):
        """token_path='data.jwt' traverses nested response JSON."""
        handler.session.post.return_value = _mock_post_response(
            200, {"data": {"jwt": "nested_jwt_token_long_enough_here"}}
        )
        result = handler.token_login(
            "https://api.example.com/auth", "u", "p", token_path="data.jwt"
        )
        assert result["success"] is True

    def test_extra_fields_in_payload(self, handler):
        """extra_fields dict merged into POST payload sent to endpoint."""
        handler.session.post.return_value = _mock_post_response(
            200, {"token": "test_token_long_enough_here_xyz"}
        )
        handler.token_login(
            "https://api.example.com/auth", "u", "p",
            extra_fields={"otp": "123456", "realm": "admin"}
        )
        call_kwargs = handler.session.post.call_args
        sent_json = call_kwargs[1]["json"]
        assert sent_json.get("otp") == "123456"
        assert sent_json.get("realm") == "admin"


# ── _find_login_form() ────────────────────────────────────────────────────────

@pytest.mark.auth
class TestFindLoginForm:

    def test_form_with_password_field_selected(self, handler):
        """Form containing a password-type input is chosen preferentially."""
        forms = [
            {"action": "/search", "method": "get", "inputs": {"q": {"type": "text", "value": ""}}},
            {"action": "/login", "method": "post",
             "inputs": {"user": {"type": "text", "value": ""},
                        "pass": {"type": "password", "value": ""}}},
        ]
        result = handler._find_login_form(forms)
        assert result["action"] == "/login"

    def test_empty_forms_returns_none(self, handler):
        """Empty forms list returns None."""
        assert handler._find_login_form([]) is None

    def test_fallback_to_form_with_two_inputs(self, handler):
        """No password field → fallback to first form with 2+ inputs."""
        forms = [
            {"action": "/login", "method": "post",
             "inputs": {"name": {"type": "text", "value": ""},
                        "token": {"type": "text", "value": ""}}},
        ]
        result = handler._find_login_form(forms)
        assert result is not None


# ── _build_login_payload() ────────────────────────────────────────────────────

@pytest.mark.auth
class TestBuildLoginPayload:

    def test_password_field_gets_password(self, handler):
        """Input with type=password receives the password value."""
        inputs = {"passwd": {"type": "password", "value": ""}}
        payload = handler._build_login_payload(inputs, "user@example.com", "secret123")
        assert payload["passwd"] == "secret123"

    def test_user_hint_field_gets_username(self, handler):
        """Input with 'email' in name and type=email receives username."""
        inputs = {"email": {"type": "email", "value": ""}}
        payload = handler._build_login_payload(inputs, "admin@example.com", "pass")
        assert payload["email"] == "admin@example.com"

    def test_csrf_hidden_field_preserves_token(self, handler):
        """Hidden CSRF token field preserves its existing value."""
        inputs = {"_csrf_token": {"type": "hidden", "value": "csrf_abc123_value"}}
        payload = handler._build_login_payload(inputs, "u", "p")
        assert payload["_csrf_token"] == "csrf_abc123_value"

    def test_submit_field_preserves_value(self, handler):
        """Submit-type input preserves its value label."""
        inputs = {"submit_btn": {"type": "submit", "value": "Sign In"}}
        payload = handler._build_login_payload(inputs, "u", "p")
        assert payload["submit_btn"] == "Sign In"


# ── _detect_login_success() ───────────────────────────────────────────────────

@pytest.mark.auth
class TestDetectLoginSuccess:

    def _make_resp(self, status_code=200, body="Welcome back, admin"):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = status_code
        resp.text = body
        return resp

    def test_session_cookie_and_no_failure_returns_true(self, handler):
        """Session cookie present and no failure words in body → True."""
        handler.session.cookies.keys.return_value = ["session_id"]
        resp = self._make_resp(200, "Welcome to the dashboard")
        assert handler._detect_login_success(resp, "admin") is True

    def test_failure_word_invalid_returns_false(self, handler):
        """'invalid' in response body → False even with session cookie."""
        handler.session.cookies.keys.return_value = ["session_id"]
        resp = self._make_resp(200, "Invalid username or password")
        assert handler._detect_login_success(resp, "admin") is False

    def test_username_in_200_body_returns_true(self, handler):
        """Username present in 200 body → True even without session cookie."""
        handler.session.cookies.keys.return_value = []
        resp = self._make_resp(200, "Hello, testuser! You are now logged in.")
        assert handler._detect_login_success(resp, "testuser") is True

    def test_no_cookie_no_username_returns_false(self, handler):
        """No session cookie and username not in body → False."""
        handler.session.cookies.keys.return_value = []
        resp = self._make_resp(200, "Please log in to continue.")
        assert handler._detect_login_success(resp, "admin") is False


# ── store_credentials() / re_authenticate() ──────────────────────────────────

@pytest.mark.auth
class TestReAuthentication:

    def test_store_credentials_saves_method_and_kwargs(self, handler):
        """store_credentials sets _stored_auth with method and kwargs."""
        handler.store_credentials("token", url="https://api.example.com/auth",
                                  username="user", password="pass")
        assert handler._stored_auth["method"] == "token"
        assert handler._stored_auth["username"] == "user"

    def test_re_authenticate_without_stored_creds_returns_false(self, handler):
        """re_authenticate with no stored credentials returns False."""
        assert handler.re_authenticate() is False

    def test_re_authenticate_token_method_calls_token_login(self, handler):
        """re_authenticate with method='token' delegates to token_login."""
        handler._stored_auth = {
            "method": "token",
            "url": "https://api.example.com/auth",
            "username": "user",
            "password": "pass",
        }
        with patch.object(handler, "token_login", return_value={"success": True}) as mock_tl:
            result = handler.re_authenticate()
        mock_tl.assert_called_once()
        assert result is True

    def test_re_authenticate_form_method_calls_form_login(self, handler):
        """re_authenticate with method='form' delegates to form_login."""
        handler._stored_auth = {
            "method": "form",
            "target": "https://example.com/login",
            "username": "user",
            "password": "pass",
        }
        with patch.object(handler, "form_login", return_value={"success": True}) as mock_fl:
            result = handler.re_authenticate()
        mock_fl.assert_called_once()
        assert result is True

    def test_re_authenticate_exception_returns_false(self, handler):
        """Exception inside re_authenticate is caught and returns False."""
        handler._stored_auth = {
            "method": "token",
            "url": "https://api.example.com/auth",
            "username": "user",
            "password": "pass",
        }
        with patch.object(handler, "token_login", side_effect=Exception("Network down")):
            result = handler.re_authenticate()
        assert result is False


# ── ApiKeyDestination enum ────────────────────────────────────────────────────

@pytest.mark.auth
class TestApiKeyDestination:
    def test_enum_has_three_members(self):
        from modules.auth import ApiKeyDestination
        assert len(ApiKeyDestination) == 3

    def test_header_value(self):
        from modules.auth import ApiKeyDestination
        assert ApiKeyDestination.HEADER.value == "header"

    def test_query_value(self):
        from modules.auth import ApiKeyDestination
        assert ApiKeyDestination.QUERY.value == "query"

    def test_cookie_value(self):
        from modules.auth import ApiKeyDestination
        assert ApiKeyDestination.COOKIE.value == "cookie"


# ── set_api_key function ──────────────────────────────────────────────────────

@pytest.mark.auth
class TestSetApiKey:
    def test_header_destination_sets_session_header(self, handler):
        from modules.auth import ApiKeyDestination, set_api_key
        set_api_key(handler, "mykey", "X-API-Key", ApiKeyDestination.HEADER)
        assert handler.session.headers["X-API-Key"] == "mykey"

    def test_header_destination_marks_authenticated(self, handler):
        from modules.auth import ApiKeyDestination, set_api_key
        set_api_key(handler, "mykey", "X-API-Key", ApiKeyDestination.HEADER)
        assert handler.authenticated is True

    def test_cookie_destination_calls_cookies_set(self, handler):
        from modules.auth import ApiKeyDestination, set_api_key
        set_api_key(handler, "mykey", "api_key", ApiKeyDestination.COOKIE)
        handler.session.cookies.set.assert_called_once_with("api_key", "mykey")

    def test_query_destination_sets_session_auth(self, handler):
        from modules.auth import ApiKeyDestination, set_api_key, _ApiKeyQueryAuth
        set_api_key(handler, "mykey", "api_key", ApiKeyDestination.QUERY)
        assert isinstance(handler.session.auth, _ApiKeyQueryAuth)

    def test_default_destination_is_header(self, handler):
        from modules.auth import set_api_key
        set_api_key(handler, "mykey", "X-Key")
        assert handler.session.headers["X-Key"] == "mykey"

    def test_auth_info_contains_destination(self, handler):
        from modules.auth import ApiKeyDestination, set_api_key
        set_api_key(handler, "mykey", "X-API-Key", ApiKeyDestination.HEADER)
        assert handler.auth_info["destination"] == "header"


# ── detect_auth_from_spec ─────────────────────────────────────────────────────

@pytest.mark.auth
class TestDetectAuthFromSpec:
    def test_apikey_in_header_oas3(self):
        from modules.auth import detect_auth_from_spec
        spec = {"components": {"securitySchemes": {
            "ApiKeyAuth": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
        }}}
        result = detect_auth_from_spec(spec)
        assert result["type"] == "apiKey"
        assert result["name"] == "X-API-Key"
        assert result["in"] == "header"

    def test_bearer_scheme_oas3(self):
        from modules.auth import detect_auth_from_spec
        spec = {"components": {"securitySchemes": {
            "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        }}}
        result = detect_auth_from_spec(spec)
        assert result["type"] == "bearer"

    def test_basic_scheme_oas3(self):
        from modules.auth import detect_auth_from_spec
        spec = {"components": {"securitySchemes": {
            "BasicAuth": {"type": "http", "scheme": "basic"}
        }}}
        result = detect_auth_from_spec(spec)
        assert result["type"] == "basic"

    def test_swagger2_security_definitions(self):
        from modules.auth import detect_auth_from_spec
        spec = {"securityDefinitions": {
            "ApiKey": {"type": "apiKey", "name": "api_key", "in": "query"}
        }}
        result = detect_auth_from_spec(spec)
        assert result["type"] == "apiKey"
        assert result["in"] == "query"

    def test_no_schemes_returns_none(self):
        from modules.auth import detect_auth_from_spec
        result = detect_auth_from_spec({})
        assert result["type"] == "none"

    def test_empty_schemes_returns_none(self):
        from modules.auth import detect_auth_from_spec
        result = detect_auth_from_spec({"components": {"securitySchemes": {}}})
        assert result["type"] == "none"


# ── CsrfTokenAction ───────────────────────────────────────────────────────────

@pytest.mark.auth
class TestCsrfTokenAction:
    def test_extracts_token_from_response_body(self):
        from modules.auth import CsrfTokenAction
        import requests
        action = CsrfTokenAction()
        resp = MagicMock(spec=requests.Response)
        # Format: csrf_token="VALUE" — directly matches the default extraction pattern
        resp.text = '_csrf_token="abc123def456ghi789xyz"'
        resp.headers = {}
        action.after_response(resp)
        assert action._token is not None

    def test_injects_token_into_request_headers(self):
        from modules.auth import CsrfTokenAction
        action = CsrfTokenAction(header_name="X-CSRF-Token")
        action._token = "test-csrf-token-here"
        kwargs = {}
        action.before_request(MagicMock(), "http://x.com", kwargs)
        assert kwargs["headers"]["X-CSRF-Token"] == "test-csrf-token-here"

    def test_no_injection_when_no_token(self):
        from modules.auth import CsrfTokenAction
        action = CsrfTokenAction()
        kwargs = {}
        action.before_request(MagicMock(), "http://x.com", kwargs)
        assert "headers" not in kwargs

    def test_field_name_injects_into_form_data(self):
        from modules.auth import CsrfTokenAction
        action = CsrfTokenAction(field_name="_csrf")
        action._token = "tok123"
        kwargs = {"data": {"username": "admin"}}
        action.before_request(MagicMock(), "http://x.com", kwargs)
        assert kwargs["data"]["_csrf"] == "tok123"


# ── SessionActionPipeline ─────────────────────────────────────────────────────

@pytest.mark.auth
class TestSessionActionPipeline:
    def test_add_action_returns_self(self):
        from modules.auth import SessionActionPipeline, CsrfTokenAction
        pipeline = SessionActionPipeline()
        result = pipeline.add_action(CsrfTokenAction())
        assert result is pipeline

    def test_install_wraps_session_request(self):
        from modules.auth import SessionActionPipeline
        pipeline = SessionActionPipeline()
        session = MagicMock()
        original = session.request
        pipeline.install(session)
        assert session.request is not original

    def test_uninstall_restores_session_request(self):
        from modules.auth import SessionActionPipeline
        pipeline = SessionActionPipeline()
        session = MagicMock()
        original = session.request
        pipeline.install(session)
        pipeline.uninstall(session)
        assert session.request is original

    def test_before_request_called_on_each_action(self):
        from modules.auth import SessionActionPipeline, SessionHandlingAction
        calls = []
        class TrackingAction(SessionHandlingAction):
            def before_request(self, session, url, kwargs):
                calls.append("before")
        pipeline = SessionActionPipeline()
        pipeline.add_action(TrackingAction())
        session = MagicMock()
        session.request.return_value = MagicMock()
        pipeline.install(session)
        session.request("GET", "http://x.com")
        assert "before" in calls

    def test_install_is_idempotent(self):
        from modules.auth import SessionActionPipeline
        pipeline = SessionActionPipeline()
        session = MagicMock()
        pipeline.install(session)
        first_patched = session.request
        pipeline.install(session)  # second call — should be no-op
        assert session.request is first_patched
