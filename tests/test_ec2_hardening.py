"""Production/internal-EC2 hardening regressions for the Flask dashboard."""

from werkzeug.security import generate_password_hash


def _client(monkeypatch):
    import app as app_module

    app_module.app.config["TESTING"] = True
    app_module.app.config["SECRET_KEY"] = "test-secret"
    app_module.app.config["DAST_CSRF_PROTECT"] = False
    if hasattr(app_module, "_login_attempts"):
        app_module._login_attempts.clear()
    return app_module.app.test_client(), app_module


def test_default_admin_login_is_disabled_unless_explicitly_allowed(monkeypatch):
    monkeypatch.delenv("DAST_ADMIN_USER", raising=False)
    monkeypatch.delenv("DAST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("DAST_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("DAST_ALLOW_DEFAULT_LOGIN", raising=False)

    client, _ = _client(monkeypatch)

    resp = client.post("/login", data={"username": "admin", "password": "admin"})

    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert not sess.get("authenticated")


def test_env_password_allows_dashboard_login(monkeypatch):
    monkeypatch.setenv("DAST_ADMIN_USER", "secops")
    monkeypatch.setenv("DAST_ADMIN_PASSWORD", "correct horse battery staple")
    monkeypatch.delenv("DAST_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("DAST_ALLOW_DEFAULT_LOGIN", raising=False)

    client, _ = _client(monkeypatch)

    resp = client.post(
        "/login",
        data={"username": "secops", "password": "correct horse battery staple"},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")
    with client.session_transaction() as sess:
        assert sess["authenticated"] is True
        assert sess["username"] == "secops"


def test_hashed_env_password_allows_dashboard_login(monkeypatch):
    monkeypatch.setenv("DAST_ADMIN_USER", "secops")
    monkeypatch.delenv("DAST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("DAST_ADMIN_PASSWORD_HASH", generate_password_hash("s3cret!"))
    monkeypatch.delenv("DAST_ALLOW_DEFAULT_LOGIN", raising=False)

    client, _ = _client(monkeypatch)

    resp = client.post(
        "/login",
        data={"username": "secops", "password": "s3cret!"},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess["authenticated"] is True


def test_login_rate_limit_blocks_repeated_failures(monkeypatch):
    monkeypatch.setenv("DAST_ADMIN_USER", "secops")
    monkeypatch.setenv("DAST_ADMIN_PASSWORD", "right-password")
    monkeypatch.setenv("DAST_LOGIN_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("DAST_LOGIN_WINDOW_SECONDS", "60")
    monkeypatch.delenv("DAST_ADMIN_PASSWORD_HASH", raising=False)

    client, _ = _client(monkeypatch)

    for _ in range(2):
        resp = client.post("/login", data={"username": "secops", "password": "wrong"})
        assert resp.status_code == 200

    blocked = client.post("/login", data={"username": "secops", "password": "wrong"})

    assert blocked.status_code == 429


def test_state_changing_api_requires_csrf_when_enabled(monkeypatch):
    client, app_module = _client(monkeypatch)
    app_module.app.config["DAST_CSRF_PROTECT"] = True
    app_module.app.config["DAST_TEST_CSRF_ENABLED"] = True

    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["username"] = "secops"
        sess["_csrf_token"] = "known-token"

    missing = client.post("/api/keys", json={"use_headless_browser": True})
    assert missing.status_code == 403
    assert missing.get_json()["error"] == "csrf_failed"

    ok = client.post(
        "/api/keys",
        json={"use_headless_browser": True},
        headers={"X-CSRF-Token": "known-token"},
    )
    assert ok.status_code == 200


def test_index_exposes_csrf_token_for_same_origin_fetches(monkeypatch):
    client, _ = _client(monkeypatch)

    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["username"] = "secops"
        sess["_csrf_token"] = "known-token"

    resp = client.get("/")
    body = resp.get_data(as_text=True)

    assert resp.status_code == 200
    assert 'name="csrf-token" content="known-token"' in body
    assert "X-CSRF-Token" in body
    assert "window.fetch" in body


def test_session_cookie_security_defaults_are_hardened():
    import app as app_module

    assert app_module.app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app_module.app.config["SESSION_COOKIE_SAMESITE"] in {"Strict", "Lax"}
    assert app_module.app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() <= 8 * 3600
