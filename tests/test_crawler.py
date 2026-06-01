from collections import deque

import pytest
import requests
from unittest.mock import MagicMock, patch

from modules.crawler import _PageParser, InputSurface, SiteMap, Crawler


def _make_response(url="https://example.com/", text="<html></html>", status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": "text/html"}
    resp.text = text
    resp.url = url
    return resp


def _make_crawler(scope, mock_session, max_pages=10, delay=0.0, **kwargs):
    return Crawler(
        target="https://example.com/",
        scope=scope,
        session=mock_session,
        max_pages=max_pages,
        delay=delay,
        **kwargs,
    )


class TestPageParser:

    def test_links_populated_from_a_href(self):
        parser = _PageParser("https://example.com/")
        parser.feed('<a href="/about">About</a><a href="/contact">Contact</a>')
        assert "/about" in parser.links
        assert "/contact" in parser.links

    def test_forms_populated_with_action_method_inputs(self):
        html = (
            '<form action="/submit" method="post">'
            '<input name="username" type="text" value="user">'
            '<input name="password" type="password">'
            '</form>'
        )
        parser = _PageParser("https://example.com/")
        parser.feed(html)
        assert len(parser.forms) == 1
        form = parser.forms[0]
        assert form["action"] == "/submit"
        assert form["method"] == "post"
        assert "username" in form["inputs"]
        assert "password" in form["inputs"]

    def test_scripts_populated_from_script_src(self):
        html = '<script src="/static/app.js"></script><script src="/static/vendor.js"></script>'
        parser = _PageParser("https://example.com/")
        parser.feed(html)
        assert "/static/app.js" in parser.scripts
        assert "/static/vendor.js" in parser.scripts

    def test_submit_button_image_reset_inputs_excluded(self):
        html = (
            '<form action="/go" method="get">'
            '<input name="q" type="text">'
            '<input name="sub" type="submit">'
            '<input name="btn" type="button">'
            '<input name="img" type="image">'
            '<input name="rst" type="reset">'
            '</form>'
        )
        parser = _PageParser("https://example.com/")
        parser.feed(html)
        assert len(parser.forms) == 1
        inputs = parser.forms[0]["inputs"]
        assert "q" in inputs
        assert "sub" not in inputs
        assert "btn" not in inputs
        assert "img" not in inputs
        assert "rst" not in inputs

    def test_malformed_html_does_not_raise(self):
        parser = _PageParser("https://example.com/")
        parser.feed("<<<not valid>>> <a href= <form <input name=bad")


class TestInputSurface:

    def test_slots_prevents_dynamic_attribute(self):
        s = InputSurface(url="https://example.com/", method="GET", param="q", param_type="query")
        with pytest.raises(AttributeError):
            s.not_a_real_attr = "boom"

    def test_repr_contains_method_url_param_type_param(self):
        s = InputSurface(
            url="https://example.com/search",
            method="get",
            param="query",
            param_type="query",
        )
        r = repr(s)
        assert "GET" in r
        assert "https://example.com/search" in r
        assert "query" in r

    def test_headers_defaults_to_empty_dict(self):
        s = InputSurface(url="https://example.com/", method="GET", param="p", param_type="form")
        assert s.headers == {}

    def test_method_uppercased(self):
        s = InputSurface(url="https://example.com/", method="post", param="x", param_type="form")
        assert s.method == "POST"


class TestSiteMap:

    def test_add_page_stores_at_url_key(self):
        sm = SiteMap()
        sm.add_page("https://example.com/page", 200, "text/html", {})
        assert "https://example.com/page" in sm.pages
        assert sm.pages["https://example.com/page"]["status"] == 200

    def test_add_surface_deduplicates_by_key(self):
        sm = SiteMap()
        s1 = InputSurface(url="https://example.com/", method="GET", param="q", param_type="query")
        s2 = InputSurface(url="https://example.com/", method="GET", param="q", param_type="query")
        sm.add_surface(s1)
        sm.add_surface(s2)
        assert len(sm.surfaces) == 1

    def test_to_dict_has_required_keys(self):
        sm = SiteMap()
        d = sm.to_dict()
        assert "pages" in d
        assert "surfaces" in d
        assert "tech" in d
        assert "stats" in d

    def test_to_dict_stats_pages_equals_pages_added(self):
        sm = SiteMap()
        sm.add_page("https://example.com/a", 200, "text/html", {})
        sm.add_page("https://example.com/b", 200, "text/html", {})
        sm.add_page("https://example.com/c", 404, "text/html", {})
        d = sm.to_dict()
        assert d["stats"]["pages"] == 3

    def test_pages_is_dict_iteration_yields_url_strings(self):
        sm = SiteMap()
        sm.add_page("https://example.com/x", 200, "text/html", {})
        sm.add_page("https://example.com/y", 200, "text/html", {})
        for key in sm.pages:
            assert isinstance(key, str)
            assert key.startswith("https://")


class TestDetectLogout:

    def _crawler(self, scope, auth_callback=None):
        session = MagicMock(spec=requests.Session)
        return Crawler(
            target="https://example.com/",
            scope=scope,
            session=session,
            delay=0.0,
            auth_callback=auth_callback,
        )

    def test_returns_false_when_auth_callback_is_none(self, scope):
        crawler = self._crawler(scope, auth_callback=None)
        resp = MagicMock()
        resp.url = "https://example.com/page"
        resp.text = "please log in"
        assert crawler._detect_logout(resp, "https://example.com/page") is False

    def test_returns_false_when_url_is_login_url(self, scope):
        crawler = self._crawler(scope, auth_callback=lambda: None)
        resp = MagicMock()
        resp.url = "https://example.com/login"
        resp.text = "normal login page"
        assert crawler._detect_logout(resp, "https://example.com/login") is False

    def test_returns_true_when_redirect_to_login(self, scope):
        crawler = self._crawler(scope, auth_callback=lambda: None)
        resp = MagicMock()
        resp.url = "https://example.com/login"
        resp.text = "some content"
        assert crawler._detect_logout(resp, "https://example.com/dashboard") is True

    def test_returns_true_when_body_contains_please_log_in(self, scope):
        crawler = self._crawler(scope, auth_callback=lambda: None)
        resp = MagicMock()
        resp.url = "https://example.com/dashboard"
        resp.text = "Access denied. Please log in to continue."
        assert crawler._detect_logout(resp, "https://example.com/dashboard") is True


class TestCrawlBFS:

    def _setup_session(self, mock_session, text="<html><body></body></html>", url="https://example.com/"):
        resp = _make_response(url=url, text=text)
        mock_session.get.return_value = resp
        return resp

    def test_stop_flag_before_crawl_skips_all_pages(self, scope, mock_session):
        self._setup_session(mock_session)
        crawler = _make_crawler(scope, mock_session, max_pages=1, delay=0.0)
        crawler._stop = True
        sitemap = crawler.crawl()
        assert len(sitemap.pages) == 0

    def test_max_pages_stops_after_limit(self, scope, mock_session):
        html = (
            '<html><body>'
            '<a href="/page1">1</a><a href="/page2">2</a>'
            '<a href="/page3">3</a><a href="/page4">4</a>'
            '</body></html>'
        )
        mock_session.get.side_effect = lambda url, **kw: _make_response(url=url, text=html)
        crawler = _make_crawler(scope, mock_session, max_pages=2, delay=0.0)
        sitemap = crawler.crawl()
        assert len(sitemap.pages) <= 2

    def test_out_of_scope_links_not_added_to_sitemap(self, scope, mock_session):
        html = (
            '<html><body>'
            '<a href="https://evil.com/steal">evil</a>'
            '</body></html>'
        )
        self._setup_session(mock_session, text=html)
        crawler = _make_crawler(scope, mock_session, delay=0.0)
        sitemap = crawler.crawl()
        for page_url in sitemap.pages:
            assert "evil.com" not in page_url

    def test_query_param_produces_query_surface(self, scope, mock_session):
        def side_effect(url, **kwargs):
            return _make_response(url=url, text="<html></html>")

        mock_session.get.side_effect = side_effect
        crawler = Crawler(
            target="https://example.com/search?foo=bar",
            scope=scope,
            session=mock_session,
            max_pages=1,
            delay=0.0,
        )
        sitemap = crawler.crawl()
        query_surfaces = [s for s in sitemap.surfaces if s.param_type == "query"]
        params = [s.param for s in query_surfaces]
        assert "foo" in params

    def test_header_surfaces_added_for_crawled_page(self, scope, mock_session):
        self._setup_session(mock_session)
        crawler = _make_crawler(scope, mock_session, max_pages=1, delay=0.0)
        sitemap = crawler.crawl()
        header_surfaces = [s for s in sitemap.surfaces if s.param_type == "header"]
        header_params = [s.param for s in header_surfaces]
        assert "User-Agent" in header_params
        assert "Referer" in header_params
        assert "X-Forwarded-For" in header_params

    def test_form_in_html_produces_form_surface(self, scope, mock_session):
        html = (
            '<html><body>'
            '<form action="/submit" method="post">'
            '<input name="username" type="text">'
            '<input name="password" type="password">'
            '</form>'
            '</body></html>'
        )
        self._setup_session(mock_session, text=html)
        crawler = _make_crawler(scope, mock_session, max_pages=1, delay=0.0)
        sitemap = crawler.crawl()
        form_surfaces = [s for s in sitemap.surfaces if s.param_type == "form"]
        assert len(form_surfaces) >= 1
        form_params = [s.param for s in form_surfaces]
        assert "username" in form_params or "password" in form_params

    def test_extract_api_paths_finds_api_users(self, scope, mock_session):
        crawler = _make_crawler(scope, mock_session, delay=0.0)
        js_text = 'var endpoint = "/api/users";'
        queue = deque()
        crawler._extract_api_paths_from_js(js_text, "https://example.com/", queue)
        queued_urls = [item[0] for item in queue]
        assert any("/api/users" in u for u in queued_urls)

    def test_extract_api_paths_finds_fetch_endpoint(self, scope, mock_session):
        crawler = _make_crawler(scope, mock_session, delay=0.0)
        js_text = 'fetch("/endpoint/data").then(r => r.json())'
        queue = deque()
        crawler._extract_api_paths_from_js(js_text, "https://example.com/", queue)
        queued_urls = [item[0] for item in queue]
        assert any("/endpoint/data" in u for u in queued_urls)

    def test_extract_api_paths_empty_string_no_crash(self, scope, mock_session):
        crawler = _make_crawler(scope, mock_session, delay=0.0)
        crawler._extract_api_paths_from_js("", "https://example.com/", deque())
