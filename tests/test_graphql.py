"""
Tests for the four new GraphQL checks in modules/graphql.py:
  19. Directive injection
  20. Fragment cyclomatic complexity
  21. APQ bypass
  22. Union type boundary bypass
"""
import hashlib
import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from modules.graphql import GraphQLScanner


# ── helpers ──────────────────────────────────────────────────────────────────

def _scanner(target="https://gql.example.com") -> GraphQLScanner:
    s = GraphQLScanner(target=target, timeout=5)
    s._alive_urls = [target + "/graphql"]
    return s


def _mock_resp(body: dict, status: int = 200, delay: float = 0.0):
    r = MagicMock()
    r.status_code = status
    r.text = json.dumps(body)
    r.json.return_value = body
    if delay:
        # simulate slow response
        original_json = r.json
        def slow_json():
            time.sleep(delay)
            return original_json()
        r.json = slow_json
    return r


# ── TEST 19: directive injection ─────────────────────────────────────────────

class TestDirectiveInjection:
    def test_deprecated_in_query_accepted_fires_finding(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        with patch.object(scanner, "_gql_post") as mock_post:
            # Server returns data without errors for @deprecated in query
            mock_post.return_value = _mock_resp({"data": {"__typename": "Query"}})
            findings = scanner._test_directive_injection(url)

        assert len(findings) == 1
        f = findings[0]
        assert f["vuln_type"] == "graphql_directive_injection"
        assert f["severity"] == "medium"
        assert f["url"] == url

    def test_no_finding_when_server_returns_errors(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        with patch.object(scanner, "_gql_post") as mock_post:
            # Compliant server rejects the directive with an error
            mock_post.return_value = _mock_resp(
                {"errors": [{"message": "Unknown directive '@deprecated'."}]}
            )
            findings = scanner._test_directive_injection(url)

        assert findings == []

    def test_no_finding_on_failed_request(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        with patch.object(scanner, "_gql_post", return_value=None):
            findings = scanner._test_directive_injection(url)

        assert findings == []


# ── TEST 20: fragment cyclomatic complexity ───────────────────────────────────

class TestFragmentComplexity:
    def test_slow_fan_out_fires_finding(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        baseline = _mock_resp({"data": {"__typename": "Query"}})
        slow_resp = _mock_resp({"data": {"__typename": "Query"}})

        call_count = [0]
        def side_effect(u, payload, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            # Simulate 3-second slow response for the fan-out query
            time.sleep(0.01)  # don't actually sleep 3s in tests
            return slow_resp

        with patch.object(scanner, "_gql_post", side_effect=side_effect):
            with patch("time.time", side_effect=[
                0.0, 0.001,   # baseline start/end → 1 ms
                0.002, 3.5,   # complexity start/end → 3498 ms
            ]):
                findings = scanner._test_fragment_complexity(url)

        assert len(findings) == 1
        f = findings[0]
        assert f["vuln_type"] == "graphql_fragment_complexity"
        assert f["severity"] == "medium"

    def test_fast_response_no_finding(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        resp = _mock_resp({"data": {"__typename": "Query"}})
        with patch.object(scanner, "_gql_post", return_value=resp):
            with patch("time.time", side_effect=[0.0, 0.05, 0.06, 0.07]):
                findings = scanner._test_fragment_complexity(url)

        assert findings == []


# ── TEST 21: APQ bypass ──────────────────────────────────────────────────────

class TestApqBypass:
    def test_apq_not_supported_returns_no_findings(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        with patch.object(scanner, "_gql_post") as mock_post:
            # Server doesn't mention PersistedQuery in errors
            mock_post.return_value = _mock_resp(
                {"errors": [{"message": "Field '__typename' doesn't exist"}]}
            )
            findings = scanner._test_apq_bypass(url)

        assert findings == []

    def test_apq_enabled_emits_info_finding(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        call_count = [0]
        def side_effect(u, payload, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                # Phase 1: APQ enabled response
                return _mock_resp({"errors": [{"message": "PersistedQueryNotFound"}]})
            # Phase 2: compliant server rejects hash mismatch with error
            return _mock_resp({"errors": [{"message": "provided sha does not match query"}]})

        with patch.object(scanner, "_gql_post", side_effect=side_effect):
            findings = scanner._test_apq_bypass(url)

        vuln_types = [f["vuln_type"] for f in findings]
        assert "graphql_apq_bypass" in vuln_types
        severities = [f["severity"] for f in findings]
        assert "info" in severities

    def test_apq_hash_mismatch_bypass_emits_high(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        call_count = [0]
        def side_effect(u, payload, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp({"errors": [{"message": "PersistedQueryNotFound"}]})
            if call_count[0] == 2:
                # Phase 2: server accepted mismatched hash!
                return _mock_resp({"data": {"__typename": "Query"}})
            return _mock_resp({"errors": [{"message": "PersistedQueryNotFound"}]})

        with patch.object(scanner, "_gql_post", side_effect=side_effect):
            findings = scanner._test_apq_bypass(url)

        high = [f for f in findings if f["severity"] == "high"]
        assert len(high) == 1
        assert high[0]["vuln_type"] == "graphql_apq_bypass"

    def test_random_hash_returns_data_emits_critical(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        with patch.object(scanner, "_gql_post") as mock_post:
            mock_post.return_value = _mock_resp({"data": {"adminUsers": [{"id": 1}]}})
            findings = scanner._test_apq_bypass(url)

        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["vuln_type"] == "graphql_apq_bypass"


# ── TEST 22: union type boundary bypass ──────────────────────────────────────

class TestUnionBypass:
    def test_privileged_type_fields_fire_finding(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        with patch.object(scanner, "_gql_post") as mock_post:
            # Server leaked admin fields across union boundary
            mock_post.return_value = _mock_resp({
                "data": {"__typename": "Query", "role": "admin", "isAdmin": True}
            })
            findings = scanner._test_union_bypass(url)

        assert len(findings) == 1
        f = findings[0]
        assert f["vuln_type"] == "graphql_union_bypass"
        assert f["severity"] == "high"

    def test_only_typename_no_finding(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        with patch.object(scanner, "_gql_post") as mock_post:
            # Server only returns __typename, no privileged fields
            mock_post.return_value = _mock_resp({"data": {"__typename": "Query"}})
            findings = scanner._test_union_bypass(url)

        assert findings == []

    def test_no_finding_on_server_error(self):
        scanner = _scanner()
        url = "https://gql.example.com/graphql"

        with patch.object(scanner, "_gql_post") as mock_post:
            mock_post.return_value = _mock_resp(
                {"errors": [{"message": "Unknown type 'AdminUser'"}]}
            )
            findings = scanner._test_union_bypass(url)

        assert findings == []
