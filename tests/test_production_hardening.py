"""Production hardening tests for scanner output quality and scan safety."""

import importlib
import threading
from unittest.mock import MagicMock

import pytest

from modules.crawler import InputSurface
from modules.fuzzer import Fuzzer


def _finding(**overrides):
    base = {
        "url": "https://example.com/search?q=test",
        "method": "GET",
        "param": "q",
        "param_type": "query",
        "vuln_type": "xss_reflected",
        "finding": "Reflected marker observed",
        "severity": "high",
        "proof": "",
        "payload": "<xss-marker>",
        "cwe": "CWE-79",
    }
    base.update(overrides)
    return base


def _load_postprocessor():
    try:
        return importlib.import_module("modules.finding_postprocessor")
    except ModuleNotFoundError as exc:
        pytest.fail(f"missing finding postprocessor module: {exc}")


def test_postprocess_findings_scores_and_keeps_highest_confidence_duplicate():
    postprocessor = _load_postprocessor()
    low_signal = _finding(
        finding="Possible reflected XSS marker observed",
        proof="",
        confidence_score=0.2,
    )
    confirmed = _finding(
        finding="Reflected XSS CONFIRMED - payload reflected unencoded",
        proof="<xss-marker>",
        payload="<script>alert(1)</script>",
        confidence_score=0.95,
    )

    processed, summary = postprocessor.postprocess_findings([low_signal, confirmed])

    assert len(processed) == 1
    assert processed[0]["proof"] == "<xss-marker>"
    assert processed[0]["audit_confidence"] == "Certain"
    assert processed[0]["confidence_score"] >= 0.85
    assert summary["raw_count"] == 2
    assert summary["deduplicated_count"] == 1
    assert summary["duplicates_removed"] == 1


def test_postprocess_findings_keeps_distinct_parameters():
    postprocessor = _load_postprocessor()
    q_finding = _finding(param="q")
    page_finding = _finding(param="page", url="https://example.com/search?page=1")

    processed, summary = postprocessor.postprocess_findings([q_finding, page_finding])

    assert len(processed) == 2
    assert summary["duplicates_removed"] == 0
    assert {f["param"] for f in processed} == {"q", "page"}
    assert all("audit_confidence" in f for f in processed)


def test_fuzzer_blocks_sensitive_payment_endpoint_by_default(scope, mock_session):
    fuzzer = Fuzzer(
        scope=scope,
        session=mock_session,
        rate_limit=0.0,
        stop_event=threading.Event(),
    )
    surface = InputSurface(
        "https://example.com/api/v1/payments/refund",
        "POST",
        "amount",
        "form",
        "10",
    )

    fuzzer._send_payload(surface, "xss_reflected", "<svg/onload=alert(1)>", None)

    mock_session.request.assert_not_called()


def test_fuzzer_still_sends_to_non_sensitive_endpoint(scope, mock_session):
    response = MagicMock()
    response.text = "ok"
    response.content = b"ok"
    response.headers = {}
    response.status_code = 200
    mock_session.request.return_value = response
    fuzzer = Fuzzer(
        scope=scope,
        session=mock_session,
        rate_limit=0.0,
        stop_event=threading.Event(),
    )
    surface = InputSurface(
        "https://example.com/api/v1/search",
        "POST",
        "q",
        "form",
        "test",
    )

    fuzzer._send_payload(surface, "xss_reflected", "<svg/onload=alert(1)>", None)

    mock_session.request.assert_called_once()
