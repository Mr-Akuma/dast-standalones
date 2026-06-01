"""Tests for app._apply_findings_filter — server-side findings filter helper."""
import pytest
from app import _apply_findings_filter


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _finding(**kwargs):
    """Build a minimal finding dict with sensible defaults."""
    base = {
        "vuln_type":       "xss_reflected",
        "severity":        "medium",
        "status_code":     200,
        "url":             "https://example.com/search",
        "param":           "q",
        "agent":           "Fuzzer",
        "confidence_level": "firm",
    }
    base.update(kwargs)
    return base


SAMPLE = [
    _finding(vuln_type="sqli_error", severity="high",   url="https://example.com/login",
             param="user", agent="Fuzzer",   confidence_level="certain"),
    _finding(vuln_type="xss_reflected", severity="medium", url="https://example.com/search",
             param="q",    agent="Passive",  confidence_level="firm"),
    _finding(vuln_type="ssrf",          severity="critical", url="https://api.example.com/fetch",
             param="url",  agent="Fuzzer",  confidence_level="tentative",
             status_code=500),
    _finding(vuln_type="open_redirect", severity="low",    url="https://example.com/redir",
             param="next", agent="Passive",  confidence_level="tentative"),
]


# ── No-filter passthrough ─────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestNoFilter:
    def test_empty_filters_returns_all(self):
        result = _apply_findings_filter(SAMPLE, {})
        assert result == SAMPLE

    def test_none_values_returns_all(self):
        result = _apply_findings_filter(SAMPLE, {
            "severity": None, "vuln_type": None, "status_code": None,
            "url_contains": None, "param": None, "agent": None, "min_confidence": None,
        })
        assert result == SAMPLE

    def test_empty_string_filters_returns_all(self):
        result = _apply_findings_filter(SAMPLE, {
            "severity": "", "vuln_type": "", "url_contains": "", "param": "",
            "agent": "", "min_confidence": "",
        })
        assert result == SAMPLE

    def test_empty_findings_returns_empty(self):
        result = _apply_findings_filter([], {"severity": "high"})
        assert result == []


# ── Severity filter ───────────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestSeverityFilter:
    def test_high_severity_returns_only_high(self):
        result = _apply_findings_filter(SAMPLE, {"severity": "high"})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "sqli_error"

    def test_severity_case_insensitive(self):
        result = _apply_findings_filter(SAMPLE, {"severity": "HIGH"})
        assert len(result) == 1

    def test_critical_returns_ssrf(self):
        result = _apply_findings_filter(SAMPLE, {"severity": "critical"})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "ssrf"

    def test_unknown_severity_returns_empty(self):
        result = _apply_findings_filter(SAMPLE, {"severity": "catastrophic"})
        assert result == []


# ── vuln_type filter ──────────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestVulnTypeFilter:
    def test_exact_vuln_type(self):
        result = _apply_findings_filter(SAMPLE, {"vuln_type": "sqli_error"})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "sqli_error"

    def test_substring_vuln_type(self):
        result = _apply_findings_filter(SAMPLE, {"vuln_type": "xss"})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "xss_reflected"

    def test_partial_match_sqli(self):
        result = _apply_findings_filter(SAMPLE, {"vuln_type": "sqli"})
        assert len(result) == 1

    def test_type_field_fallback(self):
        """Filter must also check the 'type' key (raw engine finding format)."""
        findings = [{"type": "sqli_union", "severity": "high", "url": "https://x.com/",
                     "status_code": 200, "param": "id", "agent": "Fuzzer",
                     "confidence_level": "firm"}]
        result = _apply_findings_filter(findings, {"vuln_type": "union"})
        assert len(result) == 1


# ── url_contains filter ───────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestUrlContainsFilter:
    def test_url_contains_login(self):
        result = _apply_findings_filter(SAMPLE, {"url_contains": "login"})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "sqli_error"

    def test_url_contains_example_com(self):
        # api.example.com also contains "example.com" — all 4 findings match
        result = _apply_findings_filter(SAMPLE, {"url_contains": "example.com"})
        assert len(result) == 4

    def test_target_field_fallback(self):
        """Filter must also check 'target' key (raw passive finding format)."""
        findings = [{"target": "https://internal.corp/admin", "severity": "high",
                     "vuln_type": "ssrf", "status_code": 200, "param": "url",
                     "agent": "Passive", "confidence_level": "firm"}]
        result = _apply_findings_filter(findings, {"url_contains": "internal"})
        assert len(result) == 1

    def test_no_match_url(self):
        result = _apply_findings_filter(SAMPLE, {"url_contains": "notreal.xyz"})
        assert result == []


# ── param filter ──────────────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestParamFilter:
    def test_param_exact(self):
        result = _apply_findings_filter(SAMPLE, {"param": "url"})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "ssrf"

    def test_param_substring(self):
        result = _apply_findings_filter(SAMPLE, {"param": "ur"})
        assert len(result) == 1

    def test_param_no_match(self):
        result = _apply_findings_filter(SAMPLE, {"param": "zzz"})
        assert result == []


# ── agent filter ──────────────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestAgentFilter:
    def test_agent_fuzzer(self):
        result = _apply_findings_filter(SAMPLE, {"agent": "Fuzzer"})
        assert len(result) == 2

    def test_agent_case_insensitive(self):
        result = _apply_findings_filter(SAMPLE, {"agent": "passive"})
        assert len(result) == 2

    def test_agent_substring(self):
        result = _apply_findings_filter(SAMPLE, {"agent": "uzz"})
        assert len(result) == 2


# ── status_code filter ────────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestStatusCodeFilter:
    def test_status_500(self):
        result = _apply_findings_filter(SAMPLE, {"status_code": 500})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "ssrf"

    def test_status_200(self):
        result = _apply_findings_filter(SAMPLE, {"status_code": 200})
        assert len(result) == 3

    def test_status_as_string(self):
        result = _apply_findings_filter(SAMPLE, {"status_code": "500"})
        assert len(result) == 1

    def test_invalid_status_ignored(self):
        result = _apply_findings_filter(SAMPLE, {"status_code": "notanint"})
        assert result == SAMPLE


# ── min_confidence filter ─────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestMinConfidenceFilter:
    def test_min_certain_returns_only_certain(self):
        result = _apply_findings_filter(SAMPLE, {"min_confidence": "certain"})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "sqli_error"

    def test_min_firm_excludes_tentative(self):
        result = _apply_findings_filter(SAMPLE, {"min_confidence": "firm"})
        assert len(result) == 2
        vts = {f["vuln_type"] for f in result}
        assert "sqli_error" in vts
        assert "xss_reflected" in vts
        assert "ssrf" not in vts

    def test_min_tentative_returns_all(self):
        result = _apply_findings_filter(SAMPLE, {"min_confidence": "tentative"})
        assert len(result) == 4


# ── filter chaining ───────────────────────────────────────────────────────────

@pytest.mark.findings_filter
class TestFilterChaining:
    def test_severity_and_agent_chain(self):
        result = _apply_findings_filter(SAMPLE, {"severity": "high", "agent": "Fuzzer"})
        assert len(result) == 1
        assert result[0]["vuln_type"] == "sqli_error"

    def test_url_and_vuln_type_chain(self):
        result = _apply_findings_filter(SAMPLE, {
            "url_contains": "example.com", "vuln_type": "xss"
        })
        assert len(result) == 1
        assert result[0]["vuln_type"] == "xss_reflected"

    def test_chain_no_match(self):
        result = _apply_findings_filter(SAMPLE, {"severity": "high", "agent": "Passive"})
        assert result == []

    def test_three_filters(self):
        result = _apply_findings_filter(SAMPLE, {
            "severity": "critical", "url_contains": "api.example.com", "param": "url"
        })
        assert len(result) == 1
        assert result[0]["vuln_type"] == "ssrf"
