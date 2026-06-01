"""Regression tests for real-world DAST foundations beyond payload lists."""
import json
import threading
from unittest.mock import MagicMock

import pytest

import modules.industry_patterns as industry_patterns
from modules.crawler import InputSurface
from modules.fuzzer import Fuzzer
from modules.oast import CollaboratorClient, OASTServer
from modules.proof_validator import ProofValidator
from modules.scope import ScopeManager


def _surface(param="q", param_type="query", method="GET", url="https://example.com/search"):
    return InputSurface(
        url=url,
        method=method,
        param=param,
        param_type=param_type,
        original_value="test",
    )


@pytest.mark.fuzzer
def test_public_oast_base_url_is_used_for_legacy_and_collaborator_payloads():
    server = OASTServer()
    assert hasattr(server, "set_public_base_url"), "OAST must support externally reachable callback URLs"

    server.set_public_base_url("https://oast.example.net/callbacks/")
    server.start()
    try:
        legacy_url = server.make_url("ssrf", "https://target.example/api", "callback_url")
        collaborator_url = CollaboratorClient(server).generate_payload(
            "ssrf", "https://target.example/api", "callback_url",
        ).http_url

        assert legacy_url.startswith("https://oast.example.net/callbacks/")
        assert collaborator_url.startswith("https://oast.example.net/callbacks/")
        assert server.status()["public_base_url"] == "https://oast.example.net/callbacks"
    finally:
        server.stop()


@pytest.mark.fuzzer
def test_external_pattern_pack_extends_payloads_detectors_rules_and_upload_probes(tmp_path):
    assert hasattr(industry_patterns, "load_pattern_pack_file")
    assert hasattr(industry_patterns, "apply_pattern_pack")

    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps({
        "payloads": {
            "custom_runtime_probe": ["DAST_CUSTOM_PAYLOAD"],
        },
        "detectors": {
            "custom_runtime_probe": [
                ["DAST_CUSTOM_SIGNAL", "Custom runtime detector fired"],
            ],
        },
        "param_name_rules": [
            {"pattern": "(?i)(?:^|_|-)custom_sink(?:$|_|-)", "types": ["custom_runtime_probe"]},
        ],
        "upload_probes": [
            {
                "filename": "custom-polyglot.gif.php",
                "content": "GIF89a\n<?php echo 'dast-custom-polyglot'; ?>",
                "content_type": "image/gif",
                "description": "Custom safe polyglot upload probe",
                "requires_execution": True,
            },
        ],
    }), encoding="utf-8")

    pack = industry_patterns.load_pattern_pack_file(str(pack_path))
    industry_patterns.apply_pattern_pack(pack)

    assert "DAST_CUSTOM_PAYLOAD" in industry_patterns.ACTIVE_PAYLOAD_EXTENSIONS["custom_runtime_probe"]
    assert ("DAST_CUSTOM_SIGNAL", "Custom runtime detector fired") in (
        industry_patterns.DETECTOR_EXTENSIONS["custom_runtime_probe"]
    )
    assert industry_patterns.PARAM_NAME_RULE_EXTENSIONS[0][0].search("custom_sink")
    assert any(
        probe["filename"] == "custom-polyglot.gif.php"
        for probe in industry_patterns.UPLOAD_PROBE_EXTENSIONS
    )


@pytest.mark.fuzzer
@pytest.mark.parametrize(
    ("vuln_type", "payload", "body", "headers", "expected"),
    [
        ("nosql_injection", '{"$ne":null}', "MongoServerError: unknown top level operator $ne", {}, "NoSQL"),
        ("jwt_confusion", '{"jku":"https://evil.example/jwks.json"}', "JWKS not found for kid dast", {}, "JWT"),
        ("cache_poisoning", "X-Forwarded-Host: dast-cache.example.com", "", {"X-Cache": "HIT"}, "Cache"),
        ("mass_assignment", '{"is_admin": true}', '{"id":1,"is_admin":true,"role":"admin"}', {}, "Mass Assignment"),
        ("xxe", "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", "root:x:0:0:root:/root:/bin/bash", {}, "XXE"),
        ("deserialization", 'O:8:"stdClass":1:{}', "java.io.StreamCorruptedException: invalid stream", {}, "Deserialization"),
    ],
)
def test_proof_validator_confirms_modern_api_families(vuln_type, payload, body, headers, expected):
    session = MagicMock()
    resp = MagicMock()
    resp.text = body
    resp.headers = headers
    resp.status_code = 200

    validator = ProofValidator(session=session, timeout=1)
    label, data = validator.validate(
        vuln_type,
        _surface(),
        "https://example.com/search?q=test",
        payload,
        resp,
    )

    assert label is not None
    assert expected in label
    assert data


@pytest.mark.fuzzer
def test_fuzzer_blocks_destructive_payloads_before_http_request():
    scope = ScopeManager("https://example.com")
    session = MagicMock()
    fake_resp = MagicMock()
    fake_resp.text = ""
    fake_resp.content = b""
    fake_resp.headers = {}
    fake_resp.status_code = 200
    session.request.return_value = fake_resp
    fuzzer = Fuzzer(
        scope=scope,
        session=session,
        rate_limit=0.0,
        stop_event=threading.Event(),
    )

    fuzzer._send_payload(
        _surface(),
        "sqli_error",
        "1; DROP TABLE users--",
        baseline=None,
    )

    session.request.assert_not_called()


@pytest.mark.fuzzer
def test_upload_probes_are_safe_and_cover_modern_file_attack_shapes():
    scope = ScopeManager("https://example.com")
    session = MagicMock()
    sent = []
    fake_resp = MagicMock()
    fake_resp.text = "no-match"
    fake_resp.status_code = 200
    fake_resp.headers = {}

    def fake_request(*_args, **kwargs):
        for file_tuple in (kwargs.get("files") or {}).values():
            sent.append(file_tuple)
        return fake_resp

    session.request.side_effect = fake_request
    fuzzer = Fuzzer(
        scope=scope,
        session=session,
        rate_limit=0.0,
        stop_event=threading.Event(),
    )

    fuzzer._fuzz_upload_surfaces([
        _surface(param="file", method="POST", url="https://example.com/upload")
    ])

    filenames = {item[0] for item in sent}
    contents = [
        item[1].decode("utf-8", errors="ignore") if isinstance(item[1], bytes) else str(item[1])
        for item in sent
    ]

    assert "polyglot.gif.php" in filenames
    assert "avatar.svg" in filenames
    assert "zipslip.zip" in filenames
    assert not any("system(" in content or "/tmp/pwned" in content for content in contents)
