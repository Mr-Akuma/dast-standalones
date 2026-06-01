"""
HTTP Request Transformation Pipeline — port of Burp Suite Montoya API
HttpTransformation.java.

Named encoding transforms applied to payloads before injection.
Primary use case: WAF bypass — try different encodings when a WAF blocks
the raw payload.

Usage in fuzzer:
    from .http_transform import HttpTransformation, apply_transformation
    encoded = apply_transformation(payload, HttpTransformation.URL_ENCODE_ALL)
"""
from __future__ import annotations

import enum
import html
import urllib.parse


class HttpTransformation(enum.Enum):
    """
    Named transformations that can be applied to a payload string.
    Maps to Burp Suite's HttpTransformation enum.
    """
    NONE             = "none"
    URL_ENCODE_ALL   = "url_encode_all"    # encode every character (WAF bypass)
    URL_ENCODE_PATH  = "url_encode_path"   # encode path-unsafe chars only
    DOUBLE_URL_ENCODE = "double_url_encode" # %XX → %25XX (double-encode)
    HTML_ENCODE      = "html_encode"       # < > " & → HTML entities
    UNICODE_ESCAPE   = "unicode_escape"    # a → \u0061 (JS unicode escape)


def apply_transformation(payload: str, mode: HttpTransformation) -> str:
    """
    Apply the specified transformation to a payload string.

    Args:
        payload: The raw attack payload string.
        mode:    Which HttpTransformation to apply.

    Returns:
        The transformed payload string.
    """
    if mode is HttpTransformation.NONE:
        return payload

    if mode is HttpTransformation.URL_ENCODE_ALL:
        # Encode every character, even normally-safe ones
        return urllib.parse.quote(payload, safe="")

    if mode is HttpTransformation.URL_ENCODE_PATH:
        # Standard URL encoding — keeps `/` and other path chars safe
        return urllib.parse.quote(payload, safe="/!$&'()*+,;:@")

    if mode is HttpTransformation.DOUBLE_URL_ENCODE:
        # First pass — standard URL encode
        first = urllib.parse.quote(payload, safe="")
        # Second pass — encode the percent signs themselves
        return urllib.parse.quote(first, safe="")

    if mode is HttpTransformation.HTML_ENCODE:
        return html.escape(payload, quote=True)

    if mode is HttpTransformation.UNICODE_ESCAPE:
        # Convert each character to its \\uXXXX representation
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    # Unknown mode — return unchanged (defensive)
    return payload
