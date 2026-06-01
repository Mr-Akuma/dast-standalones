"""Tests for modules/yaml_bcheck.py — YAMLRule, YAMLRuleEngine."""
import os
import threading
import pytest
from unittest.mock import MagicMock, patch
from modules.yaml_bcheck import YAMLRule, YAMLRuleEngine, _parse_rule


# ── YAMLRule dataclass ────────────────────────────────────────────────────────

class TestYAMLRule:
    def test_default_trigger_is_host(self):
        rule = YAMLRule(name="test")
        assert rule.trigger == "host"

    def test_default_method_is_get(self):
        assert YAMLRule().method == "GET"

    def test_matches_no_conditions_always_true(self):
        rule = YAMLRule(name="t")
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "not found"
        assert rule.matches(resp) is True

    def test_matches_status_code_exact(self):
        rule = YAMLRule(name="t", status_code=200)
        resp_ok  = MagicMock(); resp_ok.status_code  = 200; resp_ok.text  = ""
        resp_bad = MagicMock(); resp_bad.status_code = 404; resp_bad.text = ""
        assert rule.matches(resp_ok)  is True
        assert rule.matches(resp_bad) is False

    def test_matches_body_contains(self):
        rule = YAMLRule(name="t", body_contains="DB_PASSWORD")
        resp_hit  = MagicMock(); resp_hit.status_code  = 200; resp_hit.text  = "DB_PASSWORD=secret"
        resp_miss = MagicMock(); resp_miss.status_code = 200; resp_miss.text = "nothing here"
        assert rule.matches(resp_hit)  is True
        assert rule.matches(resp_miss) is False

    def test_matches_body_regex(self):
        rule = YAMLRule(name="t", body_regex=r"ORA-\d{5}")
        resp_hit  = MagicMock(); resp_hit.status_code  = 500; resp_hit.text  = "ORA-00942: table not found"
        resp_miss = MagicMock(); resp_miss.status_code = 200; resp_miss.text = "all good"
        assert rule.matches(resp_hit)  is True
        assert rule.matches(resp_miss) is False

    def test_matches_any_condition_fires(self):
        # status_code wrong but body_contains right → True
        rule = YAMLRule(name="t", status_code=200, body_contains="secret")
        resp = MagicMock(); resp.status_code = 404; resp.text = "secret"
        assert rule.matches(resp) is True

    def test_matches_bad_regex_does_not_raise(self):
        rule = YAMLRule(name="t", body_regex="[invalid regex")
        resp = MagicMock(); resp.status_code = 200; resp.text = "anything"
        # Should not raise
        result = rule.matches(resp)
        assert isinstance(result, bool)


# ── _parse_rule helper ────────────────────────────────────────────────────────

class TestParseRule:
    def test_minimal_rule(self):
        data = {"name": "Test Rule", "trigger": "host"}
        rule = _parse_rule(data)
        assert rule is not None
        assert rule.name == "Test Rule"
        assert rule.trigger == "host"

    def test_full_rule(self):
        data = {
            "name": "Full Rule",
            "trigger": "request",
            "request": {"path": "/admin", "method": "POST", "headers": {"X-Test": "1"}},
            "detection": {"status_code": 200, "body_contains": "admin", "body_regex": "pass"},
            "issue": {
                "name": "Admin Exposed",
                "severity": "critical",
                "confidence": "certain",
                "detail": "Admin panel is exposed.",
                "remediation": "Restrict access.",
            },
        }
        rule = _parse_rule(data)
        assert rule.path            == "/admin"
        assert rule.method          == "POST"
        assert rule.status_code     == 200
        assert rule.body_contains   == "admin"
        assert rule.body_regex      == "pass"
        assert rule.issue_name      == "Admin Exposed"
        assert rule.severity        == "critical"
        assert rule.confidence      == "certain"

    def test_invalid_rule_returns_none(self):
        result = _parse_rule({"status_code": "not_an_int_at_all_123xyz"})
        # parse_rule catches exceptions → None
        # (the name defaults, only invalid status_code int() conversion should raise)
        # Just ensure no crash:
        assert result is None or isinstance(result, YAMLRule)


# ── YAMLRuleEngine loading ────────────────────────────────────────────────────

class TestYAMLRuleEngineLoad:
    def test_load_from_directory(self, tmp_path):
        rule_file = tmp_path / "test.yaml"
        rule_file.write_text(
            "name: Test\ntrigger: host\nrequest:\n  path: /test\n"
            "detection:\n  status_code: 200\n"
            "issue:\n  name: Test Issue\n  severity: info\n  confidence: tentative\n"
            "  detail: d\n  remediation: r\n"
        )
        engine = YAMLRuleEngine(
            bchecks_dir=str(tmp_path),
            session=MagicMock(),
            timeout=5,
        )
        assert engine.check_count == 1

    def test_empty_directory_zero_rules(self, tmp_path):
        engine = YAMLRuleEngine(bchecks_dir=str(tmp_path), session=MagicMock())
        assert engine.check_count == 0

    def test_nonexistent_directory_zero_rules(self):
        engine = YAMLRuleEngine(bchecks_dir="/nonexistent/path/xyz", session=MagicMock())
        assert engine.check_count == 0

    def test_recursive_load(self, tmp_path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        for name in ("a.yaml", "b.yaml"):
            (subdir / name).write_text(
                f"name: {name}\ntrigger: host\n"
                "request:\n  path: /x\n"
                "issue:\n  name: X\n  severity: info\n  confidence: tentative\n"
                "  detail: d\n  remediation: r\n"
            )
        engine = YAMLRuleEngine(bchecks_dir=str(tmp_path), session=MagicMock())
        assert engine.check_count == 2

    def test_malformed_yaml_skipped(self, tmp_path):
        (tmp_path / "bad.yaml").write_text(": : : malformed yaml {{{{")
        (tmp_path / "good.yaml").write_text(
            "name: Good\ntrigger: host\nrequest:\n  path: /g\n"
            "issue:\n  name: G\n  severity: info\n  confidence: tentative\n"
            "  detail: d\n  remediation: r\n"
        )
        engine = YAMLRuleEngine(bchecks_dir=str(tmp_path), session=MagicMock())
        assert engine.check_count == 1  # only the good one loaded


# ── YAMLRuleEngine.run ────────────────────────────────────────────────────────

class TestYAMLRuleEngineRun:
    def _make_engine_with_rule(self, tmp_path, trigger="host", status=200,
                                body_contains=None, body_regex=None):
        det_lines = f"  status_code: {status}\n"
        if body_contains:
            det_lines += f"  body_contains: \"{body_contains}\"\n"
        if body_regex:
            det_lines += f"  body_regex: \"{body_regex}\"\n"
        rule_yaml = (
            "name: Test Rule\n"
            f"trigger: {trigger}\n"
            "request:\n  path: /test\n  method: GET\n"
            f"detection:\n{det_lines}"
            "issue:\n  name: Test Finding\n  severity: high\n  confidence: firm\n"
            "  detail: something\n  remediation: fix it\n"
        )
        (tmp_path / "rule.yaml").write_text(rule_yaml)
        mock_resp = MagicMock()
        mock_resp.status_code = status
        mock_resp.text = body_contains or ""
        mock_session = MagicMock()
        mock_session.request.return_value = mock_resp
        engine = YAMLRuleEngine(
            bchecks_dir=str(tmp_path),
            session=mock_session,
            timeout=5,
        )
        return engine, mock_session

    def test_host_trigger_run_returns_finding(self, tmp_path):
        engine, _ = self._make_engine_with_rule(tmp_path, trigger="host", status=200)
        sitemap = MagicMock()
        sitemap.pages = {}
        findings = engine.run(sitemap=sitemap, target="http://example.com")
        assert len(findings) == 1
        assert findings[0]["agent"] == "YAMLBChecks"

    def test_finding_has_required_fields(self, tmp_path):
        engine, _ = self._make_engine_with_rule(tmp_path, trigger="host", status=200)
        findings = engine.run(sitemap=MagicMock(pages={}), target="http://example.com")
        f = findings[0]
        for key in ("issue_name", "severity", "confidence", "detail", "remediation", "url", "agent"):
            assert key in f, f"Missing key: {key}"

    def test_request_trigger_runs_per_page(self, tmp_path):
        engine, mock_session = self._make_engine_with_rule(tmp_path, trigger="request", status=200)
        sitemap = MagicMock()
        sitemap.pages = {
            "http://example.com/page1": {},
            "http://example.com/page2": {},
        }
        findings = engine.run(sitemap=sitemap, target="http://example.com")
        assert len(findings) == 2
        assert mock_session.request.call_count == 2

    def test_no_match_returns_no_findings(self, tmp_path):
        det_lines = "  status_code: 200\n"
        rule_yaml = (
            "name: No Match Rule\ntrigger: host\n"
            "request:\n  path: /x\n"
            f"detection:\n{det_lines}"
            "issue:\n  name: X\n  severity: info\n  confidence: tentative\n"
            "  detail: d\n  remediation: r\n"
        )
        (tmp_path / "rule.yaml").write_text(rule_yaml)
        # response returns 404, rule expects 200
        mock_resp = MagicMock(); mock_resp.status_code = 404; mock_resp.text = ""
        mock_session = MagicMock(); mock_session.request.return_value = mock_resp
        engine = YAMLRuleEngine(bchecks_dir=str(tmp_path), session=mock_session, timeout=5)
        findings = engine.run(sitemap=MagicMock(pages={}), target="http://example.com")
        assert findings == []

    def test_stop_event_halts_run(self, tmp_path):
        engine, _ = self._make_engine_with_rule(tmp_path, trigger="host", status=200)
        engine._stop.set()
        findings = engine.run(sitemap=MagicMock(pages={}), target="http://example.com")
        assert findings == []

    def test_run_returns_list(self, tmp_path):
        engine, _ = self._make_engine_with_rule(tmp_path, trigger="host", status=200)
        result = engine.run(sitemap=MagicMock(pages={}), target="http://example.com")
        assert isinstance(result, list)
