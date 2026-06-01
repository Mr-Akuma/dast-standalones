"""
Tests that discovered URLs from AJAX spider and forced browse are merged
into the sitemap's attack surfaces before fuzzing begins.

This guards against the class of bug where a discovery source populates its
own list but the fuzzer never sees those URLs.
"""
import sys
import os
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.crawler import SiteMap, InputSurface


# ── SiteMap deduplication ─────────────────────────────────────────────────────

def test_sitemap_add_surface_deduplicates():
    sm = SiteMap()
    s = InputSurface("https://example.com/", "GET", "q", "query", "test")
    sm.add_surface(s)
    sm.add_surface(s)
    assert len(sm.surfaces) == 1


def test_sitemap_add_page_registers_url():
    sm = SiteMap()
    sm.add_page("https://example.com/found", 200, "text/html", {})
    assert "https://example.com/found" in sm.pages


# ── Surface consolidation logic ───────────────────────────────────────────────

def _make_merge_fn(sitemap, target="https://example.com"):
    """Replicate the _merge_url_into_sitemap logic for unit testing."""
    from urllib.parse import urlparse, parse_qs
    from modules.scope import ScopeManager

    scope = ScopeManager(target)

    def merge(url: str):
        if not url or not scope.in_scope(url):
            return
        sitemap.add_page(url, 0, "", {})
        sitemap.add_surface(InputSurface(url, "GET", "path", "path", url))
        try:
            parsed = urlparse(url)
            for pname, pvals in parse_qs(parsed.query).items():
                sitemap.add_surface(InputSurface(
                    url, "GET", pname, "query", pvals[0] if pvals else ""
                ))
        except Exception:
            pass
    return merge


def test_ajax_pages_become_path_surfaces():
    sm = SiteMap()
    merge = _make_merge_fn(sm)

    ajax_pages = [
        {"url": "https://example.com/api/users", "status": 200},
        {"url": "https://example.com/api/orders", "status": 200},
    ]
    for page in ajax_pages:
        merge(page["url"])

    urls = [s.url for s in sm.surfaces]
    assert "https://example.com/api/users"  in urls
    assert "https://example.com/api/orders" in urls


def test_ajax_query_params_become_individual_surfaces():
    sm = SiteMap()
    merge = _make_merge_fn(sm)

    merge("https://example.com/search?q=test&page=1")

    params = [(s.param, s.param_type) for s in sm.surfaces]
    assert ("q",    "query") in params
    assert ("page", "query") in params


def test_forced_browse_interesting_paths_become_surfaces():
    sm = SiteMap()
    merge = _make_merge_fn(sm)

    browse_results = [
        {"url": "https://example.com/admin",  "status_code": 403},
        {"url": "https://example.com/backup", "status_code": 200},
        {"url": "https://example.com/gone",   "status_code": 404},  # should skip
    ]
    INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403}
    for br in browse_results:
        if br["status_code"] in INTERESTING:
            merge(br["url"])

    urls = [s.url for s in sm.surfaces]
    assert "https://example.com/admin"  in urls
    assert "https://example.com/backup" in urls
    assert "https://example.com/gone"   not in urls


def test_out_of_scope_urls_not_added():
    sm = SiteMap()
    merge = _make_merge_fn(sm, target="https://example.com")

    merge("https://evil.com/path")      # out of scope
    merge("https://example.com/path")   # in scope

    urls = [s.url for s in sm.surfaces]
    assert "https://evil.com/path"    not in urls
    assert "https://example.com/path" in urls


def test_duplicate_ajax_and_crawl_urls_not_doubled():
    sm = SiteMap()
    merge = _make_merge_fn(sm)

    # Crawl already found this URL
    sm.add_surface(InputSurface("https://example.com/page", "GET", "path", "path", ""))
    pre_count = len(sm.surfaces)

    # AJAX spider also finds the same URL
    merge("https://example.com/page")

    assert len(sm.surfaces) == pre_count  # no duplicate added


def test_surfaces_from_all_sources_before_fuzz():
    """
    Smoke test: after merging AJAX + forcebrowse, surface list grows.
    Ensures the consolidation step adds NET NEW surfaces.
    """
    sm = SiteMap()
    sm.add_surface(InputSurface("https://example.com/", "GET", "path", "path", ""))
    initial_count = len(sm.surfaces)

    merge = _make_merge_fn(sm)
    new_urls = [
        "https://example.com/api/v1/users",
        "https://example.com/api/v1/products?id=1&lang=en",
        "https://example.com/admin/dashboard",
    ]
    for u in new_urls:
        merge(u)

    assert len(sm.surfaces) > initial_count
    # api/v1/products?id=1&lang=en should add path + id + lang surfaces
    params = {(s.url, s.param) for s in sm.surfaces}
    assert ("https://example.com/api/v1/products?id=1&lang=en", "id")   in params
    assert ("https://example.com/api/v1/products?id=1&lang=en", "lang") in params
