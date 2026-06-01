import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_coverage_registry_reports_expected_assurance_capabilities():
    from modules.coverage_registry import default_registry

    registry = default_registry()
    check_ids = {check.check_id for check in registry.list_checks()}

    expected = {
        "COV-REGISTRY-001",
        "AUTH-JOURNEY-001",
        "API-DATA-DIFF-001",
        "OAUTH-OIDC-001",
        "WEBAUTHN-001",
        "BROWSER-CLIENT-001",
        "FP-LAB-001",
        "RESUME-STATE-001",
        "EVIDENCE-REPLAY-001",
    }
    assert expected.issubset(check_ids)

    gaps = registry.gap_report(["COV-REGISTRY-001"])
    assert gaps["total_checks"] >= len(expected)
    assert gaps["covered_count"] == 1
    assert gaps["missing_count"] == gaps["total_checks"] - 1
    assert any("OWASP" in ref for ref in registry.get("API-DATA-DIFF-001").references)


def test_api_exposure_diff_flags_sensitive_fields_not_rendered_by_ui():
    from modules.api_exposure_diff import ApiExposureDiffer

    result = ApiExposureDiffer().compare(
        ui_fields={"id", "email"},
        api_json={
            "id": 7,
            "email": "a@example.test",
            "role": "admin",
            "internalCost": 99,
            "token": "secret-token",
        },
    )

    paths = {item["path"] for item in result["excessive_fields"]}
    assert {"role", "internalCost", "token"}.issubset(paths)
    assert result["finding_count"] == 3
    assert result["severity"] == "high"


def test_browser_security_analyzer_finds_client_side_risks():
    from modules.browser_security import BrowserSecurityAnalyzer

    html = """
    <script>
      window.postMessage({token: localStorage.getItem('jwt')}, '*');
      localStorage.setItem('apiKey', 'abc');
      navigator.serviceWorker.register('/sw.js');
    </script>
    """
    result = BrowserSecurityAnalyzer().analyze(
        url="https://example.test",
        html=html,
        headers={"content-security-policy": "script-src 'unsafe-inline' *"},
    )

    vuln_types = {finding["vuln_type"] for finding in result}
    assert "postmessage_wildcard_target" in vuln_types
    assert "browser_storage_secret" in vuln_types
    assert "weak_csp" in vuln_types
    assert "missing_cross_origin_isolation" in vuln_types


def test_oauth_oidc_webauthn_analyzer_flags_protocol_misconfigurations():
    from modules.oauth_oidc_scanner import OAuthOIDCAnalyzer

    result = OAuthOIDCAnalyzer().analyze_metadata(
        issuer="https://idp.example.test",
        metadata={
            "response_types_supported": ["token", "id_token token"],
            "grant_types_supported": ["authorization_code", "implicit"],
            "code_challenge_methods_supported": ["plain"],
            "id_token_signing_alg_values_supported": ["none", "RS256"],
            "authorization_endpoint": "https://idp.example.test/auth",
        },
        callback_url="https://app.example.test/callback?code=abc",
        webauthn_js="navigator.credentials.create({publicKey:{authenticatorSelection:{userVerification:'discouraged'}}})",
    )

    vuln_types = {finding["vuln_type"] for finding in result}
    assert "oauth_implicit_flow_enabled" in vuln_types
    assert "oauth_pkce_plain_only" in vuln_types
    assert "oidc_none_alg_supported" in vuln_types
    assert "oauth_missing_state" in vuln_types
    assert "webauthn_user_verification_discouraged" in vuln_types


def test_authenticated_journey_scanner_detects_cross_role_data_leak():
    from modules.auth_journey import Journey, JourneyStep, JourneyScanner

    class FakeResponse:
        def __init__(self, status_code, text, json_body):
            self.status_code = status_code
            self.text = text
            self._json = json_body
            self.headers = {"content-type": "application/json"}
            self.url = "https://app.example.test/api/profile"

        def json(self):
            return self._json

    class FakeSession:
        def __init__(self, body):
            self.body = body

        def request(self, **kwargs):
            return FakeResponse(200, str(self.body), self.body)

    journey = Journey("profile", [JourneyStep("GET", "https://app.example.test/api/profile")])
    scanner = JourneyScanner()
    result = scanner.compare_roles(
        journey,
        {
            "user": FakeSession({"id": 1, "email": "u@example.test"}),
            "guest": FakeSession({"id": 1, "email": "u@example.test", "role": "admin", "token": "x"}),
        },
    )

    assert result["finding_count"] >= 1
    assert any(f["vuln_type"] == "cross_role_data_exposure" for f in result["findings"])


def test_resumable_scan_store_round_trips_pending_surfaces(tmp_path):
    from modules.resumable_scan import ResumableScanStore

    store = ResumableScanStore(tmp_path / "resume.json")
    store.start_scan("scan-1", "https://example.test", ["a", "b", "c"])
    store.mark_done("scan-1", "a")
    state = store.load("scan-1")

    assert state["pending"] == ["b", "c"]
    assert state["done"] == ["a"]
    assert state["coverage"]["total"] == 3
    assert state["coverage"]["done"] == 1


def test_evidence_replay_bundle_contains_curl_and_response_diff():
    from modules.evidence_replay import EvidenceReplayBuilder

    bundle = EvidenceReplayBuilder().build(
        {
            "url": "https://example.test/search?q=1",
            "method": "GET",
            "headers": {"User-Agent": "DAST"},
            "param": "q",
            "payload": "' OR 1=1--",
            "baseline": {"status_code": 200, "body": "normal"},
            "attack": {"status_code": 500, "body": "SQL syntax error near OR"},
        }
    )

    assert "curl" in bundle["curl"]
    assert "' OR 1=1--" in bundle["curl"]
    assert bundle["diff"]["status_changed"] is True
    assert "SQL syntax" in bundle["proof"]


def test_false_positive_lab_scores_expected_findings():
    from modules.false_positive_lab import FalsePositiveLab

    lab = FalsePositiveLab()
    report = lab.score(
        "basic-web",
        [
            {"vuln_type": "xss_reflected", "url": "https://lab.local/search"},
            {"vuln_type": "sqli_error", "url": "https://lab.local/item"},
            {"vuln_type": "made_up", "url": "https://lab.local/noise"},
        ],
    )

    assert report["expected_count"] >= 2
    assert report["true_positive_count"] == 2
    assert report["false_positive_count"] == 1
    assert report["precision"] < 1.0


def test_assurance_api_endpoints_are_wired():
    import app as app_module

    app_module.app.config["TESTING"] = True
    app_module.app.config["SECRET_KEY"] = "test"
    with app_module.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["authenticated"] = True

        coverage = client.get("/api/assurance/coverage").get_json()
        assert coverage["total_checks"] >= 8

        diff = client.post(
            "/api/assurance/api-diff",
            json={"ui_fields": ["id"], "api_json": {"id": 1, "token": "secret"}},
        ).get_json()
        assert diff["finding_count"] == 1

        replay = client.post(
            "/api/assurance/evidence-replay",
            json={"url": "https://example.test", "payload": "x"},
        ).get_json()
        assert "curl" in replay
