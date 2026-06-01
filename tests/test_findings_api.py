"""
Integration tests for /api/findings — verifies ALL scanner sources are visible.

Covers the class of bug where a scanner populates its own list but never feeds
into the main _findings list, making results invisible on the Findings page.
"""
import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def app_client():
    """Flask test client with session auth bypassed."""
    import app as app_module
    app_module.app.config["TESTING"] = True
    app_module.app.config["SECRET_KEY"] = "test"
    with app_module.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["authenticated"] = True
        yield client, app_module


# ── /api/findings returns a valid response ────────────────────────────────────

def test_findings_endpoint_returns_json(app_client):
    client, _ = app_client
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "findings" in data
    assert "count" in data
    assert isinstance(data["findings"], list)


def test_findings_count_matches_list_length(app_client):
    client, _ = app_client
    resp = client.get("/api/findings")
    data = resp.get_json()
    assert data["count"] == len(data["findings"])


def test_discovery_path_records_do_not_inflate_main_findings_count(app_client):
    client, app_module = app_client

    original_findings = list(app_module._findings)
    try:
        app_module._findings.clear()
        for idx in range(3):
            app_module._findings.append({
                "agent": "gobuster",
                "severity": "info",
                "type": "path_found",
                "finding": f"Path discovered: /admin-{idx} (HTTP 200)",
                "url": f"https://example.com/admin-{idx}",
            })
        app_module._findings.append({
            "agent": "Engine Fuzzer",
            "severity": "high",
            "type": "sqli_error",
            "finding": "SQL injection error-based on param id",
            "url": "https://example.com/?id=1",
            "param": "id",
        })

        status_resp = client.get("/api/scan/status")
        assert status_resp.status_code == 200
        assert status_resp.get_json()["findings"] == 1

        findings_resp = client.get("/api/findings?grouped=0")
        data = findings_resp.get_json()
        assert data["count"] == 1
        assert data["findings"][0]["type"] == "sqli_error"
    finally:
        app_module._findings.clear()
        app_module._findings.extend(original_findings)


def test_forcebrowse_reports_candidate_paths_not_findings(app_client, monkeypatch):
    client, app_module = app_client

    class FakeThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    original_running = app_module._browse_running
    original_results = list(app_module._browse_results)
    original_status = app_module._browse_status
    try:
        app_module._browse_running = False
        app_module._browse_results = []
        monkeypatch.setattr(app_module.threading, "Thread", FakeThread)

        resp = client.post(
            "/api/engine/forcebrowse",
            json={"target": "https://example.com", "wordlist": "proviesec-admin"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["wordlist_size"] == 1441
        assert data["count_unit"] == "paths"
        assert "findings" not in data.get("count_label", "").lower()
        assert "paths" in data.get("count_label", "").lower()
    finally:
        app_module._browse_running = original_running
        app_module._browse_results = original_results
        app_module._browse_status = original_status


# ── Passive scanner findings appear in /api/findings ─────────────────────────

def test_passive_findings_visible_in_main_endpoint(app_client):
    client, app_module = app_client

    passive_finding = {
        "finding":    "Nginx version disclosed in Server header",
        "severity":   "Low",
        "category":   "info_disclosure",
        "cwe":        "CWE-200",
        "evidence":   "server: nginx/1.25.5",
        "remediation": "Remove or genericize server/version headers",
        "url":        "https://example.com/",
    }

    original = list(app_module._passive_findings)
    try:
        app_module._passive_findings.clear()
        app_module._passive_findings.append(passive_finding)

        resp = client.get("/api/findings")
        data = resp.get_json()
        findings = data["findings"]

        texts = [f["finding"] for f in findings]
        assert "Nginx version disclosed in Server header" in texts, (
            "Passive scanner finding not in /api/findings — _passive_findings not merged"
        )

        # Check normalized fields
        pf = next(f for f in findings if f["finding"] == "Nginx version disclosed in Server header")
        assert pf["agent"] == "Passive Scanner"
        assert pf["type"] == "info_disclosure"
        assert pf["proof"] == "server: nginx/1.25.5"
        assert pf["remediation"] != ""
    finally:
        app_module._passive_findings.clear()
        app_module._passive_findings.extend(original)


def test_passive_findings_count_included_in_total(app_client):
    client, app_module = app_client

    original_passive = list(app_module._passive_findings)
    original_findings = list(app_module._findings)
    try:
        app_module._passive_findings.clear()
        app_module._findings.clear()

        app_module._passive_findings.append({
            "finding": "Test passive A", "severity": "Low",
            "category": "test", "url": "https://example.com/",
            "evidence": "", "remediation": "", "cwe": "",
        })
        app_module._passive_findings.append({
            "finding": "Test passive B", "severity": "Medium",
            "category": "test", "url": "https://example.com/page",
            "evidence": "", "remediation": "", "cwe": "",
        })

        resp = client.get("/api/findings")
        data = resp.get_json()
        assert data["count"] >= 2, "Expected at least 2 passive findings in count"
    finally:
        app_module._passive_findings.clear()
        app_module._passive_findings.extend(original_passive)
        app_module._findings.clear()
        app_module._findings.extend(original_findings)


# ── Engine findings appear in /api/findings ───────────────────────────────────

def test_engine_fuzzer_findings_visible(app_client):
    client, app_module = app_client

    original = list(app_module._findings)
    try:
        app_module._findings.clear()
        app_module._findings.append({
            "agent":    "Engine Fuzzer",
            "severity": "high",
            "type":     "sqli_error",
            "finding":  "SQL injection error-based on param id",
            "url":      "https://example.com/?id=1",
            "param":    "id",
            "payload":  "' OR 1=1--",
            "phase":    "Active Scanning",
        })

        resp = client.get("/api/findings")
        data = resp.get_json()
        texts = [f["finding"] for f in data["findings"]]
        assert "SQL injection error-based on param id" in texts
    finally:
        app_module._findings.clear()
        app_module._findings.extend(original)


def test_tls_findings_visible(app_client):
    """TLS scanner calls _record_finding — verify it flows through correctly."""
    client, app_module = app_client

    original = list(app_module._findings)
    try:
        app_module._findings.clear()
        app_module._findings.append({
            "agent":    "TLS Analyzer",
            "agent_id": "tls",
            "icon":     "🔒",
            "phase":    "tls_scan",
            "finding":  "TLS 1.0 enabled — deprecated protocol",
            "severity": "medium",
            "target":   "https://example.com",
            "url":      "https://example.com",
        })

        resp = client.get("/api/findings")
        data = resp.get_json()
        texts = [f["finding"] for f in data["findings"]]
        assert "TLS 1.0 enabled — deprecated protocol" in texts, (
            "TLS finding not visible in /api/findings"
        )
    finally:
        app_module._findings.clear()
        app_module._findings.extend(original)


# ── Grouped response shape ────────────────────────────────────────────────────

def test_grouped_finding_has_required_fields(app_client):
    client, app_module = app_client

    original = list(app_module._findings)
    try:
        app_module._findings.clear()
        app_module._findings.append({
            "agent": "Engine Fuzzer", "severity": "high",
            "type": "xss_reflected", "finding": "Reflected XSS in search param",
            "url": "https://example.com/search?q=x", "param": "q",
            "payload": "<script>alert(1)</script>", "phase": "Active Scanning",
            "proof": "XSS CONFIRMED", "owasp": "A03:2025", "cwe": "CWE-79",
            "remediation": "Escape output",
        })

        resp = client.get("/api/findings")
        data = resp.get_json()
        assert data["findings"], "No findings returned"
        f = data["findings"][0]
        for field in ("finding", "severity", "agent", "affected_urls", "count", "type"):
            assert field in f, f"Missing field '{field}' in grouped finding"
    finally:
        app_module._findings.clear()
        app_module._findings.extend(original)


def test_severity_sorted_critical_first(app_client):
    client, app_module = app_client

    original = list(app_module._findings)
    try:
        app_module._findings.clear()
        app_module._findings.extend([
            {"agent": "X", "severity": "low",      "type": "t", "finding": "Low issue",      "url": "https://example.com/1", "phase": ""},
            {"agent": "X", "severity": "critical",  "type": "t", "finding": "Critical issue", "url": "https://example.com/2", "phase": ""},
            {"agent": "X", "severity": "medium",    "type": "t", "finding": "Medium issue",   "url": "https://example.com/3", "phase": ""},
        ])

        resp = client.get("/api/findings")
        data = resp.get_json()
        sevs = [f["severity"].lower() for f in data["findings"]]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        assert sevs == sorted(sevs, key=lambda s: rank.get(s, 9)), (
            f"Findings not sorted by severity. Got: {sevs}"
        )
    finally:
        app_module._findings.clear()
        app_module._findings.extend(original)


def test_passive_and_engine_findings_merge_without_duplication(app_client):
    """Both sources should coexist; dedup only within same (type, text) key."""
    client, app_module = app_client

    orig_findings = list(app_module._findings)
    orig_passive  = list(app_module._passive_findings)
    try:
        app_module._findings.clear()
        app_module._passive_findings.clear()

        app_module._findings.append({
            "agent": "Engine Fuzzer", "severity": "high",
            "type": "sqli_error", "finding": "SQLi in id param",
            "url": "https://example.com/", "phase": "",
        })
        app_module._passive_findings.append({
            "finding": "Missing X-Frame-Options header", "severity": "Low",
            "category": "security_header", "url": "https://example.com/",
            "evidence": "header absent", "remediation": "Add X-Frame-Options", "cwe": "CWE-1021",
        })

        resp = client.get("/api/findings")
        data = resp.get_json()
        texts = {f["finding"] for f in data["findings"]}
        assert "SQLi in id param" in texts
        assert "Missing X-Frame-Options header" in texts
        assert data["count"] == 2
    finally:
        app_module._findings.clear()
        app_module._findings.extend(orig_findings)
        app_module._passive_findings.clear()
        app_module._passive_findings.extend(orig_passive)


# ── Phase filter works across all sources ─────────────────────────────────────

def test_phase_filter_passive_only(app_client):
    client, app_module = app_client

    orig_findings = list(app_module._findings)
    orig_passive  = list(app_module._passive_findings)
    try:
        app_module._findings.clear()
        app_module._passive_findings.clear()

        app_module._findings.append({
            "agent": "Engine Fuzzer", "severity": "high",
            "type": "sqli", "finding": "Active finding",
            "url": "https://example.com/", "phase": "Active Scanning",
        })
        app_module._passive_findings.append({
            "finding": "Passive finding", "severity": "Low",
            "category": "info", "url": "https://example.com/",
            "evidence": "", "remediation": "", "cwe": "",
        })

        resp = client.get("/api/findings?phase=Passive")
        data = resp.get_json()
        texts = [f["finding"] for f in data["findings"]]
        assert "Passive finding" in texts
        assert "Active finding" not in texts
    finally:
        app_module._findings.clear()
        app_module._findings.extend(orig_findings)
        app_module._passive_findings.clear()
        app_module._passive_findings.extend(orig_passive)
