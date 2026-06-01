"""
Tests that PARAM_TYPE_MAP assigns correct vuln types to each param surface type,
and that the surface cap does not silently truncate consolidated surfaces.

Guards against regressions where newly-discovered surfaces (AJAX spider, forced
browse) get registered as 'path' or 'query' type but miss critical vuln types.
"""
import sys
import os
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.fuzzer import Fuzzer

PARAM_TYPE_MAP = Fuzzer.PARAM_TYPE_MAP


# ── PARAM_TYPE_MAP coverage checks ───────────────────────────────────────────

def test_path_has_open_redirect():
    assert "open_redirect" in PARAM_TYPE_MAP["path"], \
        "path surfaces should test open_redirect (URL segments in REST paths)"


def test_path_has_xss_stored():
    assert "xss_stored" in PARAM_TYPE_MAP["path"], \
        "path surfaces should test xss_stored (POST path segments may persist)"


def test_path_has_xxe():
    assert "xxe" in PARAM_TYPE_MAP["path"], \
        "path surfaces should test xxe (REST APIs accepting path as XML input)"


def test_json_has_ssrf():
    assert "ssrf" in PARAM_TYPE_MAP["json"], \
        "json body surfaces should test ssrf (URL fields in JSON bodies)"


def test_json_has_lfi():
    assert "lfi" in PARAM_TYPE_MAP["json"], \
        "json body surfaces should test lfi (file path fields in JSON bodies)"


def test_json_has_cmdi():
    assert "cmdi" in PARAM_TYPE_MAP["json"], \
        "json body surfaces should test cmdi (command fields in JSON bodies)"


def test_json_has_rfi():
    assert "rfi" in PARAM_TYPE_MAP["json"], \
        "json body surfaces should test rfi (remote include fields in JSON bodies)"


def test_cookie_has_sqli_blind_time():
    assert "sqli_blind_time" in PARAM_TYPE_MAP["cookie"], \
        "cookie surfaces should test sqli_blind_time (time-based blind SQLi via cookies)"


def test_cookie_has_ssrf():
    assert "ssrf" in PARAM_TYPE_MAP["cookie"], \
        "cookie surfaces should test ssrf (URL values stored in cookies)"


# ── No duplicate vuln types within any param type ────────────────────────────

@pytest.mark.parametrize("param_type", list(PARAM_TYPE_MAP.keys()))
def test_no_duplicate_vuln_types(param_type):
    types = PARAM_TYPE_MAP[param_type]
    assert len(types) == len(set(types)), \
        f"PARAM_TYPE_MAP['{param_type}'] contains duplicate vuln types: " \
        f"{[t for t in types if types.count(t) > 1]}"


# ── path additions are consistent with request_line (already has open_redirect) ──

def test_path_open_redirect_consistent_with_request_line():
    assert "open_redirect" in PARAM_TYPE_MAP.get("request_line", []), \
        "request_line already had open_redirect — path should match for consistency"


# ── Surface cap ───────────────────────────────────────────────────────────────

def test_default_max_surfaces_is_at_least_1000():
    """Default cap must accommodate AJAX + forced-browse consolidated surfaces."""
    import inspect
    sig = inspect.signature(Fuzzer.__init__)
    default = sig.parameters["max_surfaces"].default
    assert default >= 1000, \
        f"Default max_surfaces is {default} — should be >= 1000 to prevent truncation of consolidated surfaces"


def test_surface_cap_1200_not_truncated_to_500():
    """
    A list of 1200 surfaces with default cap should NOT be sliced to 500.
    Verifies the cap was updated from 500 → 1000.
    """
    from modules.crawler import InputSurface

    surfaces = [
        InputSurface(f"https://example.com/p{i}", "GET", "q", "query", "v")
        for i in range(1200)
    ]

    scope = MagicMock()
    scope.in_scope.return_value = True
    session = MagicMock()

    fuzzer = Fuzzer(scope=scope, session=session, timeout=5)
    # Access the cap that would be applied:
    limited = surfaces[:fuzzer.max_surfaces]
    assert len(limited) >= 1000, \
        f"With 1200 surfaces, cap yields {len(limited)} — should be >= 1000"
    assert len(limited) < 1200, \
        "Cap should still apply (1200 > 1000), just at the higher threshold"
