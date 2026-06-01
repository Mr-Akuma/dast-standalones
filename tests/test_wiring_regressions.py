"""Regression tests for cross-module DAST wiring."""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest
import requests

from modules.api_tester import ApiActiveTester
from modules.automation import load_scan_config
from modules.crawler import InputSurface
from modules.race_condition import RaceConditionTester
from modules.scanner import VulnerabilityScanner
from modules.scope import ScopeManager


def test_scan_config_accepts_nested_template_keys(tmp_path):
    cfg_path = tmp_path / "scan.yml"
    cfg_path.write_text(
        """
target: https://example.com
scan:
  timeout: 17
  max_pages: 33
  max_depth: 4
  no_fuzz: true
  allow_dangerous_endpoints: true
  pattern_packs:
    - examples/pattern-pack.json
  oast_public_base_url: https://oast.example.net/callbacks
wordlists:
  forced_browse: wordlists/api-endpoints.txt
reporting:
  fail_on: medium
hooks:
  post_scan: ./notify.sh
""",
        encoding="utf-8",
    )

    config, hooks = load_scan_config(str(cfg_path))

    assert config["target"] == "https://example.com"
    assert config["timeout"] == 17
    assert config["max_pages"] == 33
    assert config["depth"] == 4
    assert config["no_fuzz"] is True
    assert config["allow_dangerous_endpoints"] is True
    assert config["pattern_pack"] == ["examples/pattern-pack.json"]
    assert config["oast_public_base_url"] == "https://oast.example.net/callbacks"
    assert config["wordlist"] == "wordlists/api-endpoints.txt"
    assert config["fail_on"] == "medium"
    assert hooks["post_scan"] == "./notify.sh"


def test_pattern_pack_updates_already_imported_runtime_modules(tmp_path):
    from modules import api_tester, fuzzer, industry_patterns, llm_app_scanner, nuclei_tokens

    pack_path = tmp_path / "runtime-pack.json"
    pack_path.write_text(json.dumps({
        "payloads": {
            "wire_runtime_probe": ["DAST_RUNTIME_PAYLOAD"],
        },
        "detectors": {
            "wire_runtime_probe": [["DAST_RUNTIME_SIGNAL", "Runtime detector fired"]],
        },
        "param_name_rules": [
            {"pattern": "(?i)^runtime_sink$", "types": ["wire_runtime_probe"]},
        ],
        "api_ssrf_url_params": ["runtime_callback_url"],
        "api_webhook_ssrf_payloads": ["http://runtime-metadata.example/internal"],
        "api_hidden_endpoints": ["/api/runtime-hidden"],
        "llm_extra_paths": ["/api/runtime-ai"],
        "token_patterns": [
            {
                "pattern": "\\bruntime_live_[A-Za-z0-9]{16}\\b",
                "finding": "Runtime live token exposed",
                "severity": "High",
                "cwe": "CWE-522",
            }
        ],
    }), encoding="utf-8")

    industry_patterns.load_pattern_packs([str(pack_path)])

    assert "DAST_RUNTIME_PAYLOAD" in fuzzer.PAYLOADS["wire_runtime_probe"]
    assert ("DAST_RUNTIME_SIGNAL", "Runtime detector fired") in (
        fuzzer.DETECTORS["wire_runtime_probe"]
    )
    assert fuzzer.Fuzzer.name_based_vuln_types("runtime_sink")[:1] == ["wire_runtime_probe"]
    assert "runtime_callback_url" in api_tester._SSRF_URL_PARAMS
    assert "http://runtime-metadata.example/internal" in api_tester._WEBHOOK_SSRF_PAYLOADS
    assert "/api/runtime-hidden" in api_tester._HIDDEN_ENDPOINTS

    token_hits = nuclei_tokens.run_checks(
        "https://example.com/config",
        "token=runtime_live_ABCDEFGHIJKLMNOP",
        {},
        {},
    )
    assert any("Runtime live token" in finding["finding"] for finding in token_hits)

    session = MagicMock(spec=requests.Session)
    session.get.return_value.status_code = 405
    session.get.return_value.text = ""
    scanner = llm_app_scanner.LLMAppScanner(
        target="https://example.com",
        session=session,
        stop_event=threading.Event(),
        timeout=1,
    )
    urls = {url for url, _ in scanner._detect_llm_endpoints([])}
    assert "https://example.com/api/runtime-ai" in urls


def test_vulnerability_scanner_passes_safety_flag_to_internal_fuzzer(scope, mock_session):
    scanner = VulnerabilityScanner(
        target="https://example.com",
        scope=scope,
        session=mock_session,
        rate_limit=0.0,
        stop_event=threading.Event(),
        allow_dangerous_endpoints=True,
    )

    with patch("modules.scanner.Fuzzer") as fuzzer_cls:
        fuzzer_cls.return_value.fuzz_all.return_value = []
        scanner._active_fuzz_phase([])

    assert fuzzer_cls.call_args.kwargs["allow_dangerous_endpoints"] is True


def test_api_tester_skips_dangerous_endpoint_by_default():
    session = MagicMock(spec=requests.Session)
    tester = ApiActiveTester(
        session=session,
        scope=ScopeManager("https://example.com"),
        rate_limit=0.0,
    )
    surface = InputSurface(
        "https://example.com/api/payments/refund",
        "POST",
        "amount",
        "json",
        "10",
    )

    findings = tester.scan([surface], base_url="https://example.com")

    assert findings == []
    assert session.method_calls == []


def test_race_condition_scanner_skips_dangerous_endpoint_by_default():
    session = MagicMock(spec=requests.Session)
    tester = RaceConditionTester(
        session=session,
        scope=ScopeManager("https://example.com"),
        rate_limit=0.0,
        stop_event=threading.Event(),
    )
    sitemap = MagicMock()
    sitemap.surfaces = [
        InputSurface(
            "https://example.com/api/payments/refund",
            "POST",
            "amount",
            "form",
            "10",
        )
    ]

    with patch.object(tester, "_test_endpoint") as test_endpoint:
        findings = tester.scan("https://example.com", sitemap)

    assert findings == []
    test_endpoint.assert_not_called()
