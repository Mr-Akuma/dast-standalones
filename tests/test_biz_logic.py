"""Tests for modules/biz_logic.py — BusinessLogicTester."""
from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
import requests

from modules.biz_logic import (
    BusinessLogicTester,
    BizLogicFinding,
    WorkflowStep,
)


# ─── fixtures ────────────────────────────────────────────────────────────────

def _step(name: str, url: str = "http://app/step", method: str = "POST",
          data: dict | None = None, expected_status: int = 200,
          success_pattern: str = "", extract: dict | None = None) -> WorkflowStep:
    return WorkflowStep(
        name=name, url=url, method=method,
        data=data or {}, expected_status=expected_status,
        success_pattern=success_pattern, extract=extract or {},
    )


def _ok(text: str = '{"ok":true}', status: int = 200) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.status_code = status
    r.text = text
    return r


def _err(status: int = 400) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.status_code = status
    r.text = '{"error":"bad request"}'
    return r


@pytest.fixture
def tester() -> BusinessLogicTester:
    t = BusinessLogicTester(timeout=5, rate_limit=0)
    t.session = MagicMock(spec=requests.Session)
    t.session.headers = {}
    t.session.verify = False
    return t


def _mock_session(return_value=None, side_effect=None) -> MagicMock:
    """Return a mock requests.Session whose .request is pre-wired."""
    s = MagicMock(spec=requests.Session)
    s.headers = {}
    s.verify = False
    if side_effect is not None:
        s.request = MagicMock(side_effect=side_effect)
    else:
        s.request = MagicMock(return_value=return_value or _ok())
    return s


@contextmanager
def _patch_cloned_session(return_value=None, side_effect=None):
    """Patch requests.Session so _clone_session() returns a controllable mock."""
    mock_cls = MagicMock()
    instance = _mock_session(return_value=return_value, side_effect=side_effect)
    mock_cls.return_value = instance
    with patch("modules.biz_logic.requests.Session", mock_cls):
        yield instance


# ─── test_state_confusion: probe 1 (concurrent race) ─────────────────────────

class TestStateConfusionProbe1:
    """Concurrent race — sessions jump to final step after only step-1."""

    def test_returns_empty_for_single_step(self, tester):
        result = tester.test_state_confusion([_step("only")])
        assert result == []

    def test_no_finding_when_final_step_rejected(self, tester):
        # step-1 succeeds, final step returns 400
        tester.session.request = MagicMock(side_effect=[
            _ok(), _err(),   # session 0: step-1 ok, final rejected
            _ok(), _err(),   # session 1: step-1 ok, final rejected
            _ok(), _err(),   # anchor session: step-1 ok, final rejected (probe 2)
            _err(),          # out-of-order probe 3: reversed final rejected
            _ok(),           # out-of-order step-1 ok
        ])
        steps = [_step("s1"), _step("final")]
        result = tester.test_state_confusion(steps, sessions=2)
        confusion_findings = [f for f in result if f.vuln_type == "state_confusion"]
        assert confusion_findings == []

    def test_finding_when_both_sessions_reach_final(self, tester):
        steps = [_step("s1"), _step("final")]
        with _patch_cloned_session(return_value=_ok()):
            result = tester.test_state_confusion(steps, sessions=2)
        types = [f.vuln_type for f in result]
        assert "state_confusion" in types

    def test_finding_severity_is_high(self, tester):
        steps = [_step("s1"), _step("final")]
        with _patch_cloned_session(return_value=_ok()):
            result = tester.test_state_confusion(steps, sessions=2)
        assert all(f.severity == "high" for f in result)

    def test_callback_called_for_each_finding(self, tester):
        steps = [_step("s1"), _step("final")]
        cb = MagicMock()
        with _patch_cloned_session(return_value=_ok()):
            tester.test_state_confusion(steps, sessions=2, callback=cb)
        assert cb.call_count >= 1
        for call_args in cb.call_args_list:
            finding = call_args[0][0]
            assert isinstance(finding, BizLogicFinding)

    def test_success_pattern_required_when_set(self, tester):
        # Final step has a success_pattern that never matches
        ok_no_match = _ok('{"status":"pending"}')
        tester.session.request = MagicMock(return_value=ok_no_match)
        steps = [
            _step("s1"),
            _step("final", success_pattern="confirmed"),
        ]
        result = tester.test_state_confusion(steps, sessions=2)
        # Probe 1 and 2 should not fire (pattern never matches)
        probe1_2 = [f for f in result
                    if "concurrent" in f.finding or "replay" in f.finding]
        assert probe1_2 == []

    def test_findings_appended_to_self_findings(self, tester):
        tester.session.request = MagicMock(return_value=_ok())
        steps = [_step("s1"), _step("final")]
        initial_count = len(tester.findings)
        result = tester.test_state_confusion(steps, sessions=2)
        assert len(tester.findings) >= initial_count + len(result)


# ─── test_state_confusion: probe 2 (state replay) ────────────────────────────

class TestStateConfusionProbe2:
    """State replay — N sessions reuse step-1 tokens concurrently."""

    def test_replay_finding_when_multiple_sessions_accepted(self, tester):
        # All cloned sessions return ok — probe 2 sees multiple successes → replay finding
        step1 = _step("step1", extract={"token": "session_token"})
        final = _step("final")
        with _patch_cloned_session(return_value=_ok('{"session_token":"abc123"}')):
            result = tester.test_state_confusion([step1, final], sessions=2)
        replay_findings = [f for f in result if "replay" in f.finding]
        assert len(replay_findings) >= 1

    def test_no_replay_finding_when_only_one_session_accepted(self, tester):
        # probe 1: both fail final; probe 2: only 1 session succeeds final
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            n = call_count[0]
            # probe 1: step1 ok, final err (x2 sessions) = calls 1-4
            # probe 2 anchor: step1 ok = call 5
            # probe 2 replay: only call 6 ok, call 7 err
            # probe 3: all err
            if n in (2, 4):   # final steps in probe 1
                return _err()
            if n == 7:        # second replay session → reject
                return _err()
            if n >= 8:        # probe 3
                return _err()
            return _ok()

        tester.session.request = MagicMock(side_effect=side_effect)
        steps = [_step("s1"), _step("final")]
        result = tester.test_state_confusion(steps, sessions=2)
        replay_findings = [f for f in result if "replay" in f.finding]
        assert replay_findings == []


# ─── test_state_confusion: probe 3 (out-of-order) ────────────────────────────

class TestStateConfusionProbe3:
    """Out-of-order step delivery."""

    def test_out_of_order_finding_when_final_accepted_first(self, tester):
        # All cloned sessions return ok → probe 3 (out-of-order) accepts final first
        steps = [_step("step1", url="http://app/step1"),
                 _step("final", url="http://app/final")]
        with _patch_cloned_session(return_value=_ok()):
            result = tester.test_state_confusion(steps, sessions=2)
        oo_findings = [f for f in result
                       if "out-of-order" in f.finding.lower() or "Out-of-order" in f.finding]
        assert len(oo_findings) >= 1

    def test_no_out_of_order_finding_when_final_rejected(self, tester):
        # All requests fail
        tester.session.request = MagicMock(return_value=_err())
        steps = [_step("s1"), _step("final")]
        result = tester.test_state_confusion(steps, sessions=2)
        oo_findings = [f for f in result if "out-of-order" in f.finding.lower()]
        assert oo_findings == []

    def test_out_of_order_includes_step_sequence_in_evidence(self, tester):
        tester.session.request = MagicMock(return_value=_ok())
        steps = [_step("first"), _step("middle"), _step("last")]
        result = tester.test_state_confusion(steps, sessions=2)
        oo_findings = [f for f in result if "out-of-order" in f.finding.lower() or "Out-of-order" in f.finding]
        if oo_findings:
            assert "last" in oo_findings[0].finding or "last" in oo_findings[0].evidence


# ─── test_state_confusion: general behaviour ─────────────────────────────────

class TestStateConfusionGeneral:
    def test_findings_url_is_final_step_url(self, tester):
        tester.session.request = MagicMock(return_value=_ok())
        steps = [_step("s1", url="http://app/s1"),
                 _step("final", url="http://app/checkout")]
        result = tester.test_state_confusion(steps, sessions=2)
        for f in result:
            if f.vuln_type == "state_confusion":
                assert f.url == "http://app/checkout"

    def test_three_step_workflow(self, tester):
        tester.session.request = MagicMock(return_value=_ok())
        steps = [_step("login"), _step("add-to-cart"), _step("checkout")]
        result = tester.test_state_confusion(steps, sessions=2)
        # Should not raise; findings may or may not exist
        assert isinstance(result, list)

    def test_sessions_parameter_respected(self, tester):
        """5 concurrent sessions → more request calls than default 2."""
        call_log = []

        def side_effect(*args, **kwargs):
            call_log.append(1)
            return _ok()

        steps = [_step("s1"), _step("final")]
        with _patch_cloned_session(side_effect=side_effect):
            tester.test_state_confusion(steps, sessions=5)
        # probe 1: 5 sessions × 2 step calls = 10 minimum
        assert len(call_log) >= 10

    def test_network_errors_dont_raise(self, tester):
        tester.session.request = MagicMock(side_effect=Exception("network down"))
        steps = [_step("s1"), _step("final")]
        result = tester.test_state_confusion(steps, sessions=2)
        assert isinstance(result, list)


# ─── detect_critical_flows (existing, regression) ────────────────────────────

class TestDetectCriticalFlows:
    def test_checkout_url_detected(self):
        result = BusinessLogicTester.detect_critical_flows(
            ["https://shop.example.com/checkout/confirm"]
        )
        assert any(flow == "checkout" for flow, _ in result)

    def test_payment_url_detected(self):
        result = BusinessLogicTester.detect_critical_flows(
            ["https://app.example.com/payment/process"]
        )
        assert any(flow == "payment" for flow, _ in result)

    def test_unrelated_url_not_detected(self):
        result = BusinessLogicTester.detect_critical_flows(
            ["https://example.com/api/products"]
        )
        assert result == []

    def test_empty_list(self):
        assert BusinessLogicTester.detect_critical_flows([]) == []


# ─── discover_manipulable_fields ──────────────────────────────────────────────

class TestDiscoverManipulableFields:
    def test_price_field_detected(self, tester):
        result = tester.discover_manipulable_fields(
            "http://x", sample_data={"unit_price": 9.99, "name": "Widget"}
        )
        assert "unit_price" in result["price"]

    def test_quantity_field_detected(self, tester):
        result = tester.discover_manipulable_fields(
            "http://x", sample_data={"qty": 1}
        )
        assert "qty" in result["quantity"]

    def test_discount_field_detected(self, tester):
        result = tester.discover_manipulable_fields(
            "http://x", sample_data={"coupon_code": "SAVE10"}
        )
        assert "coupon_code" in result["discount"]

    def test_empty_data_returns_empty_lists(self, tester):
        result = tester.discover_manipulable_fields("http://x", sample_data={})
        assert result == {"price": [], "quantity": [], "discount": []}
