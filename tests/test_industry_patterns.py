"""Regression tests for industry-grade DAST pattern extensions."""
import re

import pytest

from modules.fuzzer import DETECTORS, PAYLOADS, Fuzzer
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
def test_bola_and_bopla_parameter_names_are_prioritized():
    assert Fuzzer.name_based_vuln_types("tenant_id")[:3] == [
        "idor", "acl_bypass", "sqli_error",
    ]
    assert Fuzzer.name_based_vuln_types("isAdmin")[:3] == [
        "mass_assignment", "prototype_pollution_body", "acl_bypass",
    ]


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
