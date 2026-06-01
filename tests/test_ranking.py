"""Tests for modules/ranking.py — RequestRankingAlgorithm and rank_surfaces."""
import pytest
from modules.ranking import (
    RequestRankingAlgorithm,
    RankedHttpRequestResponse,
    rank_surfaces,
)
from modules.crawler import InputSurface


# ── Helpers ────────────────────────────────────────────────────────────────────

def _surf(param_type="query", method="GET", param="q",
          url="http://example.com/search", headers=None):
    return InputSurface(
        url=url, method=method, param=param,
        param_type=param_type, original_value="",
        headers=headers or {},
    )


_algo = RequestRankingAlgorithm()


# ── RankedHttpRequestResponse structure ───────────────────────────────────────

class TestRankedHttpRequestResponse:
    def test_dataclass_has_surface_field(self):
        s = _surf()
        r = _algo.score(s)
        assert r.surface is s

    def test_dataclass_has_rank_score_field(self):
        r = _algo.score(_surf())
        assert isinstance(r.rank_score, float)

    def test_dataclass_has_rank_factors_dict(self):
        r = _algo.score(_surf())
        assert isinstance(r.rank_factors, dict)

    def test_rank_factors_contains_expected_keys(self):
        r = _algo.score(_surf())
        for key in ("param_type", "method", "url_depth", "param_interest",
                    "auth_header", "post_json_combo"):
            assert key in r.rank_factors, f"Missing factor: {key}"


# ── Param type scoring ────────────────────────────────────────────────────────

class TestParamTypeScore:
    def test_json_scores_10(self):
        r = _algo.score(_surf(param_type="json"))
        assert r.rank_factors["param_type"] == 10

    def test_xml_scores_10(self):
        r = _algo.score(_surf(param_type="xml"))
        assert r.rank_factors["param_type"] == 10

    def test_multipart_scores_8(self):
        assert _algo.score(_surf(param_type="multipart")).rank_factors["param_type"] == 8

    def test_form_scores_7(self):
        assert _algo.score(_surf(param_type="form")).rank_factors["param_type"] == 7

    def test_cookie_scores_7(self):
        assert _algo.score(_surf(param_type="cookie")).rank_factors["param_type"] == 7

    def test_header_scores_6(self):
        assert _algo.score(_surf(param_type="header")).rank_factors["param_type"] == 6

    def test_path_scores_5(self):
        assert _algo.score(_surf(param_type="path")).rank_factors["param_type"] == 5

    def test_path_filename_scores_5(self):
        assert _algo.score(_surf(param_type="path_filename")).rank_factors["param_type"] == 5

    def test_request_line_scores_4(self):
        assert _algo.score(_surf(param_type="request_line")).rank_factors["param_type"] == 4

    def test_query_scores_3(self):
        assert _algo.score(_surf(param_type="query")).rank_factors["param_type"] == 3

    def test_unknown_type_defaults_to_3(self):
        assert _algo.score(_surf(param_type="unknown_xyz")).rank_factors["param_type"] == 3


# ── Method scoring ────────────────────────────────────────────────────────────

class TestMethodScore:
    def test_post_scores_5(self):
        assert _algo.score(_surf(method="POST")).rank_factors["method"] == 5

    def test_put_scores_5(self):
        assert _algo.score(_surf(method="PUT")).rank_factors["method"] == 5

    def test_patch_scores_5(self):
        assert _algo.score(_surf(method="PATCH")).rank_factors["method"] == 5

    def test_delete_scores_4(self):
        assert _algo.score(_surf(method="DELETE")).rank_factors["method"] == 4

    def test_get_scores_2(self):
        assert _algo.score(_surf(method="GET")).rank_factors["method"] == 2

    def test_head_scores_2(self):
        assert _algo.score(_surf(method="HEAD")).rank_factors["method"] == 2


# ── URL depth scoring ─────────────────────────────────────────────────────────

class TestUrlDepthScore:
    def test_deeper_url_scores_higher(self):
        shallow = _surf(url="http://example.com/api")
        deep    = _surf(url="http://example.com/api/v2/users/profile/settings")
        r_shallow = _algo.score(shallow)
        r_deep    = _algo.score(deep)
        assert r_deep.rank_factors["url_depth"] > r_shallow.rank_factors["url_depth"]

    def test_root_url_depth_is_zero(self):
        r = _algo.score(_surf(url="http://example.com/"))
        assert r.rank_factors["url_depth"] == 0

    def test_depth_capped_at_5(self):
        very_deep = _surf(url="http://example.com/a/b/c/d/e/f/g/h")
        r = _algo.score(very_deep)
        assert r.rank_factors["url_depth"] == 5


# ── Param name interest ───────────────────────────────────────────────────────

class TestParamNameInterest:
    @pytest.mark.parametrize("param", ["id", "token", "password", "auth", "key", "secret",
                                        "userid", "api_key", "cmd", "redirect", "file"])
    def test_sensitive_param_scores_3(self, param):
        r = _algo.score(_surf(param=param))
        assert r.rank_factors["param_interest"] == 3

    def test_innocuous_param_scores_0(self):
        r = _algo.score(_surf(param="color"))
        assert r.rank_factors["param_interest"] == 0


# ── Auth header presence ──────────────────────────────────────────────────────

class TestAuthHeaderScore:
    def test_authorization_header_adds_4(self):
        r = _algo.score(_surf(headers={"Authorization": "Bearer tok"}))
        assert r.rank_factors["auth_header"] == 4

    def test_cookie_header_adds_4(self):
        r = _algo.score(_surf(headers={"Cookie": "session=abc"}))
        assert r.rank_factors["auth_header"] == 4

    def test_no_auth_header_scores_0(self):
        r = _algo.score(_surf(headers={"Content-Type": "application/json"}))
        assert r.rank_factors["auth_header"] == 0


# ── POST+JSON combo bonus ─────────────────────────────────────────────────────

class TestPostJsonCombo:
    def test_post_json_adds_3(self):
        r = _algo.score(_surf(method="POST", param_type="json"))
        assert r.rank_factors["post_json_combo"] == 3

    def test_post_xml_adds_3(self):
        r = _algo.score(_surf(method="POST", param_type="xml"))
        assert r.rank_factors["post_json_combo"] == 3

    def test_get_json_no_bonus(self):
        r = _algo.score(_surf(method="GET", param_type="json"))
        assert r.rank_factors["post_json_combo"] == 0

    def test_post_query_no_bonus(self):
        r = _algo.score(_surf(method="POST", param_type="query"))
        assert r.rank_factors["post_json_combo"] == 0


# ── rank_surfaces public API ──────────────────────────────────────────────────

class TestRankSurfaces:
    def test_returns_list_of_input_surfaces(self):
        surfaces = [_surf("query"), _surf("json")]
        result = rank_surfaces(surfaces)
        assert all(isinstance(s, InputSurface) for s in result)

    def test_sorted_descending_by_rank_score(self):
        low  = _surf(param_type="query",  method="GET")   # low score
        high = _surf(param_type="json",   method="POST",  # high score
                     param="id", url="http://x.com/api/v2/users",
                     headers={"Authorization": "Bearer x"})
        result = rank_surfaces([low, high])
        assert result[0] is high
        assert result[1] is low

    def test_original_list_not_modified(self):
        surfaces = [_surf("query"), _surf("json"), _surf("form")]
        original = list(surfaces)
        rank_surfaces(surfaces)
        assert surfaces == original

    def test_empty_list_returns_empty(self):
        assert rank_surfaces([]) == []

    def test_single_element_list(self):
        s = _surf()
        assert rank_surfaces([s]) == [s]

    def test_accepts_sitemap_kwarg(self):
        # sitemap=None is the default; passing it explicitly must not error
        result = rank_surfaces([_surf()], sitemap=None)
        assert len(result) == 1
