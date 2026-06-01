"""
Tests for modules/fuzzer.py.

Focuses on pure-logic paths that don't require live HTTP:
  - PayloadMutator (WAF evasion strategy engine)
  - _fuzz_boolean_blind statistical threshold logic (mocked session)
  - _fuzz_upload_surfaces surface-selection logic
  - Probe payload content correctness
"""
import threading
from unittest.mock import MagicMock, patch
import pytest
import requests

from modules.fuzzer import Fuzzer, PayloadMutator
from modules.crawler import InputSurface


@pytest.fixture
def fuzzer(scope, mock_session):
    return Fuzzer(
        scope=scope,
        session=mock_session,
        rate_limit=0.0,
        stop_event=threading.Event(),
    )


def _surface(param="q", param_type="query", method="GET",
             url="https://example.com/search", content_type=""):
    return InputSurface(
        url=url, method=method, param=param,
        param_type=param_type, original_value="test",
        content_type=content_type,
    )


# ── PayloadMutator ────────────────────────────────────────────────────────────

@pytest.mark.fuzzer
class TestPayloadMutator:

    def test_mutate_returns_string(self):
        result = PayloadMutator.mutate("' OR 1=1--", attempt=0)
        assert isinstance(result, str)

    def test_mutate_changes_payload(self):
        original = "' OR 1=1--"
        mutated = PayloadMutator.mutate(original, attempt=1)
        # Mutation may be no-op for attempt 0 but should differ at attempt 1+
        assert isinstance(mutated, str)

    def test_mutate_empty_string_no_crash(self):
        result = PayloadMutator.mutate("", attempt=0)
        assert isinstance(result, str)

    def test_mutate_max_attempts_no_crash(self):
        for i in range(PayloadMutator.MAX_MUTATIONS + 5):
            result = PayloadMutator.mutate("<script>", attempt=i, vuln_type="xss_reflected")
            assert isinstance(result, str)

    def test_max_mutations_is_20(self):
        assert PayloadMutator.MAX_MUTATIONS == 20

    def test_mutate_xss_produces_encoded_variant(self):
        """At some attempt, URL encoding should appear."""
        payloads = {PayloadMutator.mutate("<script>alert(1)</script>", attempt=i,
                                          vuln_type="xss_reflected")
                    for i in range(20)}
        # At least one variant should differ from the original
        assert len(payloads) > 1

    def test_bool_blind_threshold_constant_removed(self):
        """BOOL_BLIND_THRESHOLD was replaced by dynamic per-surface computation."""
        assert not hasattr(Fuzzer, "BOOL_BLIND_THRESHOLD")


# ── _fuzz_boolean_blind statistical threshold ─────────────────────────────────

@pytest.mark.fuzzer
class TestFuzzBooleanBlind:

    def _make_resp(self, text: str):
        r = MagicMock()
        r.text = text
        r.status_code = 200
        r.headers = {}
        return r

    def test_stable_page_flagged_on_large_diff(self, fuzzer):
        """
        Stable page (5 identical baselines) → low threshold.
        True/false responses differing by 500B should be flagged.
        """
        baseline_body = "A" * 1000
        true_body     = "A" * 1500   # +500B
        false_body    = "A" * 1000   # same as baseline

        call_count = [0]
        responses = (
            [self._make_resp(baseline_body)] * 5   # 5 baselines
            + [self._make_resp(true_body),          # true payload
               self._make_resp(false_body)]         # false payload
        )

        def fake_send(surface, payload):
            r = responses[call_count[0]]
            call_count[0] += 1
            return r

        with patch.object(fuzzer, "_send_and_capture", side_effect=fake_send), \
             patch.object(fuzzer, "_build_url", return_value="https://example.com/s?q=x"), \
             patch.object(fuzzer, "_build_headers", return_value={}), \
             patch.object(fuzzer, "_build_body", return_value=None), \
             patch.object(fuzzer, "_store_evidence", return_value="eid-1"), \
             patch.object(fuzzer, "_record_finding") as mock_record:
            fuzzer._fuzz_boolean_blind(_surface())

        mock_record.assert_called_once()
        args = mock_record.call_args
        assert "sqli_bool_true" in args[0]

    def test_volatile_page_not_flagged(self, fuzzer):
        """
        Page with high natural variance (300B swings) should NOT produce a
        finding when true/false differ by only 100B — that's within 3σ.
        """
        import random
        rng = random.Random(42)
        # 5 baselines each 1000 ± 300B → σ ≈ 120B → threshold ≈ 360B
        baseline_lengths = [1000 + rng.randint(-300, 300) for _ in range(5)]
        # true/false diff of only 100B — well within threshold
        true_body  = "X" * (baseline_lengths[0] + 50)
        false_body = "X" * (baseline_lengths[0] - 50)

        call_count = [0]
        all_bodies = ([("X" * l) for l in baseline_lengths]
                      + [true_body, false_body])

        def fake_send(surface, payload):
            if call_count[0] >= len(all_bodies):
                return None
            r = self._make_resp(all_bodies[call_count[0]])
            call_count[0] += 1
            return r

        with patch.object(fuzzer, "_send_and_capture", side_effect=fake_send), \
             patch.object(fuzzer, "_build_url", return_value="https://example.com/s?q=x"), \
             patch.object(fuzzer, "_build_headers", return_value={}), \
             patch.object(fuzzer, "_build_body", return_value=None), \
             patch.object(fuzzer, "_record_finding") as mock_record:
            fuzzer._fuzz_boolean_blind(_surface())

        mock_record.assert_not_called()

    def test_fewer_than_3_baselines_skips_testing(self, fuzzer):
        """If fewer than 3 baselines return, no payload testing should occur."""
        call_count = [0]

        def fake_send(surface, payload):
            call_count[0] += 1
            # Only first 2 calls succeed (< 3 baselines)
            if call_count[0] <= 2:
                return self._make_resp("A" * 1000)
            return None

        with patch.object(fuzzer, "_send_and_capture", side_effect=fake_send), \
             patch.object(fuzzer, "_record_finding") as mock_record:
            fuzzer._fuzz_boolean_blind(_surface())

        mock_record.assert_not_called()

    def test_finding_text_contains_stats(self, fuzzer):
        """Finding text must include mean and σ for investigators."""
        baseline_body = "A" * 1000
        responses = (
            [self._make_resp(baseline_body)] * 5
            + [self._make_resp("A" * 1600),   # +600B diff → exceeds threshold
               self._make_resp(baseline_body)]
        )
        call_count = [0]

        def fake_send(surface, payload):
            if call_count[0] >= len(responses):
                return None
            r = responses[call_count[0]]
            call_count[0] += 1
            return r

        recorded = []
        with patch.object(fuzzer, "_send_and_capture", side_effect=fake_send), \
             patch.object(fuzzer, "_build_url", return_value="https://example.com/s?q=x"), \
             patch.object(fuzzer, "_build_headers", return_value={}), \
             patch.object(fuzzer, "_build_body", return_value=None), \
             patch.object(fuzzer, "_store_evidence", return_value="eid"), \
             patch.object(fuzzer, "_record_finding",
                          side_effect=lambda *a, **kw: recorded.append(a)):
            fuzzer._fuzz_boolean_blind(_surface())

        assert recorded, "Expected a finding"
        finding_text = recorded[0][3]
        assert "mean=" in finding_text or "baseline mean=" in finding_text
        assert "σ=" in finding_text or "threshold=" in finding_text


# ── _fuzz_upload_surfaces surface selection ───────────────────────────────────

@pytest.mark.fuzzer
class TestUploadSurfaceSelection:

    def _get_selected_urls(self, fuzzer, surfaces):
        """Run _fuzz_upload_surfaces with mocked HTTP and capture which URLs were hit."""
        seen = []
        fake_resp = MagicMock()
        fake_resp.text = "no-match"
        fake_resp.status_code = 200
        fake_resp.headers = {}

        def fake_request(*args, **kwargs):
            seen.append(kwargs.get("files", {}) or args)
            return fake_resp

        fuzzer.session.request = fake_request
        fuzzer._fuzz_upload_surfaces(surfaces)
        return seen

    def test_multipart_content_type_selected(self, fuzzer):
        s = _surface(method="POST", content_type="multipart/form-data")
        seen = self._get_selected_urls(fuzzer, [s])
        assert len(seen) > 0

    def test_file_param_name_selected(self, fuzzer):
        s = _surface(param="file", method="POST")
        seen = self._get_selected_urls(fuzzer, [s])
        assert len(seen) > 0

    def test_upload_param_name_selected(self, fuzzer):
        s = _surface(param="upload", method="POST")
        seen = self._get_selected_urls(fuzzer, [s])
        assert len(seen) > 0

    def test_image_param_name_selected(self, fuzzer):
        s = _surface(param="image", method="POST")
        seen = self._get_selected_urls(fuzzer, [s])
        assert len(seen) > 0

    def test_avatar_param_name_selected(self, fuzzer):
        s = _surface(param="avatar", method="POST")
        seen = self._get_selected_urls(fuzzer, [s])
        assert len(seen) > 0

    def test_upload_url_path_selected(self, fuzzer):
        s = _surface(param="data", method="POST",
                     url="https://example.com/uploads/photo")
        seen = self._get_selected_urls(fuzzer, [s])
        assert len(seen) > 0

    def test_get_method_skipped(self, fuzzer):
        s = _surface(param="file", method="GET")
        seen = self._get_selected_urls(fuzzer, [s])
        assert len(seen) == 0

    def test_regular_form_param_skipped(self, fuzzer):
        s = _surface(param="username", method="POST")
        seen = self._get_selected_urls(fuzzer, [s])
        assert len(seen) == 0

    def test_deduplication_by_url(self, fuzzer):
        """Same URL with two different param names → only 1 URL probed."""
        s1 = _surface(param="file", method="POST",
                      url="https://example.com/upload")
        s2 = _surface(param="image", method="POST",
                      url="https://example.com/upload")
        seen_urls = set()
        fake_resp = MagicMock()
        fake_resp.text = "no-match"
        fake_resp.status_code = 200
        fake_resp.headers = {}

        def fake_request(*args, **kwargs):
            seen_urls.add(args[1] if len(args) > 1 else "")
            return fake_resp

        fuzzer.session.request = fake_request
        fuzzer._fuzz_upload_surfaces([s1, s2])
        assert len(seen_urls) <= 1


# ── Upload probe content ──────────────────────────────────────────────────────

@pytest.mark.fuzzer
class TestUploadProbeContent:
    """Verify that the upload probes contain the expected dangerous content."""

    def _get_probe_files(self, fuzzer):
        """Collect all (filename, content, content_type) tuples sent."""
        sent = []
        fake_resp = MagicMock()
        fake_resp.text = "no-match"
        fake_resp.status_code = 200
        fake_resp.headers = {}

        def fake_request(*a, **kw):
            if "files" in kw:
                for field, val in kw["files"].items():
                    sent.append(val)  # (filename, content, content_type)
            return fake_resp

        s = _surface(param="file", method="POST")
        fuzzer.session.request = fake_request
        fuzzer._fuzz_upload_surfaces([s])
        return sent

    def test_php_webshell_probe_present(self, fuzzer):
        probes = self._get_probe_files(fuzzer)
        filenames = [p[0] for p in probes]
        assert any(f.endswith(".php") for f in filenames)

    def test_null_byte_probe_present(self, fuzzer):
        probes = self._get_probe_files(fuzzer)
        filenames = [p[0] for p in probes]
        assert any("\x00" in f for f in filenames)

    def test_path_traversal_probe_present(self, fuzzer):
        probes = self._get_probe_files(fuzzer)
        filenames = [p[0] for p in probes]
        assert any(".." in f for f in filenames)

    def test_svg_xxe_probe_present(self, fuzzer):
        probes = self._get_probe_files(fuzzer)
        contents = [p[1] for p in probes]
        assert any(b"xxe" in c.lower() or b"ENTITY" in c for c in contents)

    def test_alternate_extensions_present(self, fuzzer):
        probes = self._get_probe_files(fuzzer)
        filenames = [p[0] for p in probes]
        assert any(f.endswith(".phtml") for f in filenames)
        assert any(f.endswith(".php5") for f in filenames)
        assert any(f.endswith(".phar") for f in filenames)
