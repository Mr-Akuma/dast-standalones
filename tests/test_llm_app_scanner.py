"""
Tests for modules/llm_app_scanner.py — LLMAppScanner.

Covers:
  - Path heuristic detection (_detect_llm_endpoints)
  - Response shape detection (SSE, JSON keys, HTTP 405/422/400)
  - Injection probing (_probe_endpoint)
  - System prompt leak detection
  - Model disclosure check
  - scan() return format and contract
"""
import threading
from unittest.mock import MagicMock, patch
import pytest
import requests

from modules.llm_app_scanner import LLMAppScanner


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_session():
    return MagicMock(spec=requests.Session)


@pytest.fixture
def scanner(mock_session):
    return LLMAppScanner(
        target="https://example.com",
        session=mock_session,
        stop_event=threading.Event(),
        timeout=5,
    )


def _resp(status_code: int = 200, body: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.text = body
    return r


# ── Path heuristic detection ──────────────────────────────────────────────────

@pytest.mark.llm_scanner
class TestPathHeuristics:

    def test_chat_url_detected(self, scanner):
        """URL containing /chat path → detected via path heuristic."""
        urls = ["https://example.com/chat"]
        # Suppress the extra-paths HTTP probes
        scanner.session.get.return_value = _resp(404)
        candidates = scanner._detect_llm_endpoints(urls)
        assert any("chat" in url for url, _ in candidates)

    def test_api_completions_url_detected(self, scanner):
        """URL containing /api/completions → detected via path heuristic."""
        urls = ["https://example.com/api/completions"]
        scanner.session.get.return_value = _resp(404)
        candidates = scanner._detect_llm_endpoints(urls)
        assert any("completions" in url for url, _ in candidates)

    def test_ask_url_detected(self, scanner):
        """URL containing /ask → detected via path heuristic."""
        urls = ["https://example.com/ask"]
        scanner.session.get.return_value = _resp(404)
        candidates = scanner._detect_llm_endpoints(urls)
        assert any("ask" in url for url, _ in candidates)

    def test_regular_url_not_detected(self, scanner):
        """Normal URL without LLM path patterns → not in candidates."""
        urls = ["https://example.com/products", "https://example.com/about"]
        scanner.session.get.return_value = _resp(404)
        candidates = scanner._detect_llm_endpoints(urls)
        # All candidates come from path heuristics on passed-in URLs
        for url, _ in candidates:
            # The passed-in regular URLs must not appear
            assert url not in urls


# ── Response shape detection ──────────────────────────────────────────────────

@pytest.mark.llm_scanner
class TestResponseShapeDetection:

    def test_405_on_get_marks_endpoint_as_candidate(self, scanner):
        """HTTP 405 on GET probe → strong LLM API signal, endpoint added."""
        scanner.session.get.return_value = _resp(405, "")
        candidates = scanner._detect_llm_endpoints([])
        assert len(candidates) > 0

    def test_422_on_get_marks_endpoint_as_candidate(self, scanner):
        """HTTP 422 on GET → schema validation signal, endpoint added."""
        scanner.session.get.return_value = _resp(422, "")
        candidates = scanner._detect_llm_endpoints([])
        assert len(candidates) > 0

    def test_json_choices_key_detected(self, scanner):
        """200 response with 'choices' key → LLM response shape detected."""
        body = '{"choices": [{"message": {"role": "assistant", "content": "Hi"}}]}'
        scanner.session.get.return_value = _resp(200, body)
        candidates = scanner._detect_llm_endpoints([])
        assert len(candidates) > 0

    def test_sse_stream_detected(self, scanner):
        """200 response with SSE prefix and LLM key → streaming endpoint detected."""
        # _detect_llm_endpoints adds 200-status endpoints only when _LLM_RESPONSE_KEYS
        # matches; the SSE prefix updates the detection reason but is not the trigger.
        body = 'data: {"id":"chatcmpl-1","content":"Hello, how can I help?"}\n'
        scanner.session.get.return_value = _resp(200, body)
        candidates = scanner._detect_llm_endpoints([])
        assert len(candidates) > 0
        # Detection reason should mention SSE
        assert any("SSE" in reason for _, reason in candidates)

    def test_404_on_all_probes_no_candidates(self, scanner):
        """404 on all GET probes and no heuristic URLs → no candidates."""
        scanner.session.get.return_value = _resp(404, "")
        candidates = scanner._detect_llm_endpoints([])
        assert candidates == []


# ── Injection probe detection ─────────────────────────────────────────────────

@pytest.mark.llm_scanner
class TestInjectionProbing:

    def test_direct_injection_pwned_in_response_flagged(self, scanner):
        """Response containing 'PWNED' → direct_override finding recorded."""
        scanner.session.post.return_value = _resp(200, "Sure! PWNED")
        findings = scanner._probe_endpoint("https://example.com/chat")
        assert any("PWNED" in f["finding"] or "direct" in f["finding"].lower()
                   for f in findings)

    def test_system_prompt_leak_in_response_flagged(self, scanner):
        """Response containing system prompt indicator → exfiltration finding."""
        body = "You are a helpful assistant. Here is my system prompt..."
        scanner.session.post.return_value = _resp(200, body)
        findings = scanner._probe_endpoint("https://example.com/chat")
        assert any("exfil" in f["finding"].lower() or "system" in f["finding"].lower()
                   for f in findings)

    def test_clean_response_no_finding(self, scanner):
        """Response with no injection indicators → no findings."""
        scanner.session.post.return_value = _resp(200, "I can help you with many things.")
        findings = scanner._probe_endpoint("https://example.com/chat")
        assert findings == []

    def test_500_response_skipped(self, scanner):
        """500 server error → _send_prompt returns None, probe skipped gracefully."""
        scanner.session.post.return_value = _resp(500, "Internal Server Error")
        # status_code >= 500 → _send_prompt returns None → no crash
        findings = scanner._probe_endpoint("https://example.com/chat")
        assert isinstance(findings, list)

    def test_network_error_no_crash(self, scanner):
        """Network exception in _send_prompt → no crash, returns empty list."""
        scanner.session.post.side_effect = Exception("Connection refused")
        findings = scanner._probe_endpoint("https://example.com/chat")
        assert isinstance(findings, list)


# ── Model disclosure ──────────────────────────────────────────────────────────

@pytest.mark.llm_scanner
class TestModelDisclosure:

    def test_gpt4_in_response_flagged(self, scanner):
        """Response mentioning 'gpt-4' → model disclosure finding."""
        scanner.session.post.return_value = _resp(200, "I am powered by gpt-4-turbo")
        result = scanner._check_model_disclosure("https://example.com/chat")
        assert result is not None
        assert "gpt-4" in result["finding"].lower() or "gpt-4" in result["evidence"].lower()

    def test_claude_in_response_flagged(self, scanner):
        """Response mentioning 'claude' → model disclosure finding."""
        scanner.session.post.return_value = _resp(200, "I am Claude, an AI assistant.")
        result = scanner._check_model_disclosure("https://example.com/chat")
        assert result is not None

    def test_llama_in_response_flagged(self, scanner):
        """Response mentioning 'llama' → model disclosure finding."""
        scanner.session.post.return_value = _resp(200, "Running on llama-3-70b-instruct")
        result = scanner._check_model_disclosure("https://example.com/chat")
        assert result is not None

    def test_no_model_name_no_finding(self, scanner):
        """Response with no model name → no model disclosure finding."""
        scanner.session.post.return_value = _resp(200, "I am an AI assistant here to help.")
        result = scanner._check_model_disclosure("https://example.com/chat")
        assert result is None


# ── scan() contract ───────────────────────────────────────────────────────────

@pytest.mark.llm_scanner
class TestScanContract:

    REQUIRED_KEYS = {"url", "category", "finding", "severity", "evidence",
                     "remediation", "cwe"}

    def test_scan_returns_list(self, scanner):
        """scan() always returns a list."""
        scanner.session.get.return_value = _resp(404, "")
        result = scanner.scan(["https://example.com/nothing"])
        assert isinstance(result, list)

    def test_scan_no_llm_urls_returns_empty(self, scanner):
        """No LLM candidates detected → scan returns empty list."""
        scanner.session.get.return_value = _resp(404, "")
        result = scanner.scan(["https://example.com/products"])
        assert result == []

    def test_finding_has_required_keys(self, scanner):
        """Every finding dict must contain all required keys."""
        finding = LLMAppScanner._make_finding(
            url="https://example.com/chat",
            desc="Test finding",
            severity="High",
            evidence="evidence text",
            cwe="CWE-77",
        )
        assert self.REQUIRED_KEYS.issubset(finding.keys())

    def test_finding_category_is_llm_injection(self, scanner):
        """Findings always carry category='llm_injection'."""
        finding = LLMAppScanner._make_finding(
            url="https://example.com/chat",
            desc="Prompt injection",
            severity="High",
            evidence="PWNED in response",
            cwe="CWE-77",
        )
        assert finding["category"] == "llm_injection"

    def test_stop_event_aborts_scan(self, scanner):
        """Stop event set → scan exits immediately after detecting candidates."""
        scanner.stop_event.set()
        scanner.session.get.return_value = _resp(405, "")
        result = scanner.scan([])
        assert result == []

    def test_scan_info_finding_on_detection(self, scanner):
        """Detected LLM endpoint produces an Info-severity detection finding."""
        # Return 405 on GET probes → will be detected
        scanner.session.get.return_value = _resp(405, "")
        # Return clean content on POST probes → no injection finding
        scanner.session.post.return_value = _resp(200, "Hello, how can I help?")
        result = scanner.scan([])
        info_findings = [f for f in result if f["severity"] == "Info"]
        assert len(info_findings) > 0
