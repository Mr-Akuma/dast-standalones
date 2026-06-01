"""Tests for modules/http_transform.py — HttpTransformation enum and apply_transformation."""
import pytest
from modules.http_transform import HttpTransformation, apply_transformation


class TestHttpTransformationEnum:
    def test_has_six_members(self):
        assert len(HttpTransformation) == 6

    def test_none_value(self):
        assert HttpTransformation.NONE.value == "none"

    def test_url_encode_all_value(self):
        assert HttpTransformation.URL_ENCODE_ALL.value == "url_encode_all"

    def test_double_url_encode_value(self):
        assert HttpTransformation.DOUBLE_URL_ENCODE.value == "double_url_encode"

    def test_html_encode_value(self):
        assert HttpTransformation.HTML_ENCODE.value == "html_encode"

    def test_unicode_escape_value(self):
        assert HttpTransformation.UNICODE_ESCAPE.value == "unicode_escape"


class TestApplyTransformationNone:
    def test_none_returns_payload_unchanged(self):
        assert apply_transformation("' OR 1=1--", HttpTransformation.NONE) == "' OR 1=1--"

    def test_none_on_empty_string(self):
        assert apply_transformation("", HttpTransformation.NONE) == ""


class TestApplyTransformationUrlEncodeAll:
    def test_single_quote_encoded(self):
        result = apply_transformation("'", HttpTransformation.URL_ENCODE_ALL)
        assert result == "%27"

    def test_space_encoded(self):
        result = apply_transformation(" ", HttpTransformation.URL_ENCODE_ALL)
        assert result == "%20"

    def test_slash_encoded(self):
        # URL_ENCODE_ALL encodes even normally-safe chars like /
        result = apply_transformation("/", HttpTransformation.URL_ENCODE_ALL)
        assert result == "%2F"

    def test_full_sqli_payload_encoded(self):
        result = apply_transformation("' OR 1=1--", HttpTransformation.URL_ENCODE_ALL)
        # All special chars must be encoded; no literal quote, space, or dash
        assert "'" not in result
        assert " " not in result


class TestApplyTransformationUrlEncodePath:
    def test_special_chars_encoded(self):
        result = apply_transformation("<script>", HttpTransformation.URL_ENCODE_PATH)
        assert "<" not in result
        assert ">" not in result

    def test_slash_preserved(self):
        # URL_ENCODE_PATH keeps / as safe
        result = apply_transformation("/path/here", HttpTransformation.URL_ENCODE_PATH)
        assert "/" in result


class TestApplyTransformationDoubleUrlEncode:
    def test_percent_itself_encoded(self):
        # ' → %27 → %2527
        result = apply_transformation("'", HttpTransformation.DOUBLE_URL_ENCODE)
        assert result == "%2527"

    def test_different_from_single_encode(self):
        single = apply_transformation("'", HttpTransformation.URL_ENCODE_ALL)
        double = apply_transformation("'", HttpTransformation.DOUBLE_URL_ENCODE)
        assert single != double

    def test_a_simple_char(self):
        # 'a' → 'a' → 'a' (unreserved chars don't get encoded by URL_ENCODE_ALL)
        # Actually urllib.parse.quote('a', safe='') = 'a', so double is also 'a'
        result = apply_transformation("a", HttpTransformation.DOUBLE_URL_ENCODE)
        assert result == "a"


class TestApplyTransformationHtmlEncode:
    def test_less_than_encoded(self):
        result = apply_transformation("<", HttpTransformation.HTML_ENCODE)
        assert result == "&lt;"

    def test_greater_than_encoded(self):
        result = apply_transformation(">", HttpTransformation.HTML_ENCODE)
        assert result == "&gt;"

    def test_ampersand_encoded(self):
        result = apply_transformation("&", HttpTransformation.HTML_ENCODE)
        assert result == "&amp;"

    def test_double_quote_encoded(self):
        result = apply_transformation('"', HttpTransformation.HTML_ENCODE)
        assert result == "&quot;"

    def test_xss_payload_encoded(self):
        result = apply_transformation('<script>alert(1)</script>', HttpTransformation.HTML_ENCODE)
        assert "<" not in result
        assert ">" not in result


class TestApplyTransformationUnicodeEscape:
    def test_single_char_escaped(self):
        result = apply_transformation("a", HttpTransformation.UNICODE_ESCAPE)
        assert result == "\\u0061"

    def test_quote_escaped(self):
        result = apply_transformation("'", HttpTransformation.UNICODE_ESCAPE)
        assert result == "\\u0027"

    def test_string_all_escaped(self):
        result = apply_transformation("AB", HttpTransformation.UNICODE_ESCAPE)
        assert result == "\\u0041\\u0042"

    def test_each_char_is_four_hex(self):
        result = apply_transformation("X", HttpTransformation.UNICODE_ESCAPE)
        # format is \uXXXX — 6 chars total
        assert len(result) == 6
        assert result.startswith("\\u")
        assert all(c in "0123456789abcdef" for c in result[2:])
