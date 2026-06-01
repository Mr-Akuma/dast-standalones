"""Shared pytest fixtures for DAST scanner tests."""
import sys
import os
import pytest
import requests
from unittest.mock import MagicMock

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.scope import ScopeManager


@pytest.fixture
def scope():
    return ScopeManager("https://example.com")


@pytest.fixture
def mock_session():
    return MagicMock(spec=requests.Session)


@pytest.fixture
def sample_finding():
    """Standard ScanFinding-compatible dict."""
    return {
        "url": "https://example.com/page?id=1",
        "vuln_type": "sqli_error",
        "param": "id",
        "param_type": "query",
        "finding": "SQL injection (error-based) — MySQL syntax error in response",
        "severity": "high",
        "proof": "You have an error in your SQL syntax",
        "payload": "' OR 1=1--",
        "status_code": 200,
        "owasp_category": "A03:2025 Injection",
        "cwe": "CWE-89",
        "method": "GET",
    }


@pytest.fixture
def sample_finding_dup(sample_finding):
    """Duplicate of sample_finding with lower confidence."""
    dup = dict(sample_finding)
    dup["confidence_score"] = 0.3
    return dup


@pytest.fixture
def sample_finding_different():
    """Different finding (different param)."""
    return {
        "url": "https://example.com/page?id=1",
        "vuln_type": "xss_reflected",
        "param": "name",
        "param_type": "query",
        "finding": "Reflected XSS — payload echoed in response body",
        "severity": "high",
        "proof": "<script>alert(1)</script>",
        "payload": "<script>alert(1)</script>",
        "status_code": 200,
        "owasp_category": "A03:2025 Injection",
        "cwe": "CWE-79",
        "method": "GET",
    }
