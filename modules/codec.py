"""Standalone codec utility for DAST scanner — stdlib only."""

import base64
import gzip
import hashlib
import hmac
import html
import io
import json
import re
import time
import urllib.parse

__all__ = ["decode_auto", "encode", "CodecChain", "jwt_analyze"]


def decode_auto(data):
    # 1. gzip
    if isinstance(data, (bytes, bytearray)) and data[:2] == b"\x1f\x8b":
        try:
            decoded = gzip.decompress(data).decode("utf-8")
            return {"detected": "gzip", "decoded": decoded, "format": "gzip"}
        except Exception:
            pass

    text = data if isinstance(data, str) else data.decode("utf-8", errors="replace")

    # 2. jwt
    if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", text):
        return {"detected": "jwt", "decoded": text, "format": "jwt"}

    # 3. base64
    if re.fullmatch(r"[A-Za-z0-9+/]{4,}={0,2}", text) and len(text) % 4 == 0:
        try:
            decoded = base64.b64decode(text).decode("utf-8")
            return {"detected": "base64", "decoded": decoded, "format": "base64"}
        except Exception:
            pass

    # 4. url
    if re.search(r"%[0-9A-Fa-f]{2}", text):
        decoded = urllib.parse.unquote(text)
        return {"detected": "url", "decoded": decoded, "format": "url"}

    # 5. html
    if re.search(r"&amp;|&lt;|&gt;|&#|&quot;", text):
        decoded = html.unescape(text)
        return {"detected": "html", "decoded": decoded, "format": "html"}

    # 6. hex
    m = re.fullmatch(r"(0x)?([0-9A-Fa-f]{2,})", text)
    if m and len(m.group(2)) % 2 == 0:
        try:
            decoded = bytes.fromhex(m.group(2)).decode("utf-8")
            return {"detected": "hex", "decoded": decoded, "format": "hex"}
        except Exception:
            pass

    # 7. unicode escapes
    if re.search(r"\\u[0-9A-Fa-f]{4}", text):
        try:
            decoded = text.encode("utf-8").decode("unicode_escape")
            return {"detected": "unicode", "decoded": decoded, "format": "unicode"}
        except Exception:
            pass

    # 8. fallback
    return {"detected": "plain", "decoded": str(data), "format": "plain"}


def encode(data, fmt):
    if fmt == "base64":
        return base64.b64encode(data.encode()).decode()
    elif fmt == "url":
        return urllib.parse.quote(data, safe="")
    elif fmt == "html":
        return html.escape(data)
    elif fmt == "hex":
        return data.encode().hex()
    elif fmt == "gzip":
        compressed = gzip.compress(data.encode())
        return base64.b64encode(compressed).decode()
    elif fmt == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in data)
    elif fmt == "double_url":
        once = urllib.parse.quote(data, safe="")
        return urllib.parse.quote(once, safe="")
    else:
        raise ValueError(f"Unknown encoding format: {fmt}")


class CodecChain:
    def __init__(self, transforms):
        self.transforms = transforms

    def apply(self, data):
        result = data
        for fmt in self.transforms:
            result = encode(result, fmt)
        return result

    def decode_chain(self, data):
        result = data
        for _ in self.transforms:
            decoded = decode_auto(result)
            result = decoded["decoded"]
        return result


def _pad_b64url(s):
    return s + "=" * (-len(s) % 4)


def jwt_analyze(token):
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Not a valid JWT (expected 3 dot-separated segments)"}

    # Decode header
    try:
        header = json.loads(base64.urlsafe_b64decode(_pad_b64url(parts[0])))
    except Exception:
        header = {"error": "decode_failed"}

    # Decode payload
    try:
        payload = json.loads(base64.urlsafe_b64decode(_pad_b64url(parts[1])))
    except Exception:
        payload = {"error": "decode_failed"}

    signature_present = len(parts[2]) > 0

    alg = header.get("alg", "") if isinstance(header, dict) else ""
    alg_none = alg in ("none", "None", "NONE")

    # Expiration check
    exp_ts = payload.get("exp") if isinstance(payload, dict) else None
    if exp_ts is not None:
        expired = exp_ts < time.time()
    else:
        expired = None

    # nbf check
    nbf = payload.get("nbf") if isinstance(payload, dict) else None
    if nbf is not None:
        nbf_ok = nbf < time.time()
    else:
        nbf_ok = None

    # Build issues
    issues = []
    if alg_none:
        issues.append("CRITICAL: alg:none \u2014 signature bypass possible")
    if alg in ("HS256", "HS384", "HS512"):
        issues.append("INFO: HMAC algorithm \u2014 brute-force with jwt_cracker tools")
    if expired is True:
        issues.append("HIGH: Token is expired")
    if isinstance(payload, dict):
        if payload.get("admin") is True or payload.get("role") == "admin":
            issues.append("INFO: Admin claim present \u2014 test privilege escalation")
        if any(k in payload for k in ("sub", "user_id", "uid")):
            issues.append("INFO: User identifier present \u2014 test IDOR")

    return {
        "header": header,
        "payload": payload,
        "signature_present": signature_present,
        "analysis": {
            "alg_none": alg_none,
            "alg": alg,
            "expired": expired,
            "exp_ts": exp_ts,
            "nbf_ok": nbf_ok,
            "issues": issues,
        },
    }
