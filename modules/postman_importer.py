"""
Postman Importer — imports Postman Collection v2.0/v2.1 as scan targets.
Equivalent to ZAP's Postman Support add-on.

Parses Postman collection JSON, resolves variables, and returns
a list of ready-to-use HTTP requests for the scanner.
"""
from __future__ import annotations
import json
import re
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, parse_qsl


@dataclass
class PostmanRequest:
    """A single HTTP request extracted from a Postman collection."""
    name: str
    method: str
    url: str
    headers: dict[str, str]
    body: str
    description: str
    auth_type: str
    folder_path: str

    def to_dict(self) -> dict:
        return asdict(self)

    def to_input_surfaces(self, base_url: str = "") -> list:
        """
        Convert this PostmanRequest into a list of fuzzer-ready InputSurface objects.

        Each parameter (query param, JSON body field, form field, header) becomes
        one InputSurface so the fuzzer can independently test each injection point.

        Args:
            base_url: Optional URL override (replaces the host portion of self.url).
                      If empty, self.url is used as-is.
        """
        from .crawler import InputSurface

        effective_url = self.url
        if base_url:
            # Replace scheme+host with base_url, keep path+query
            parsed = urlparse(self.url)
            base_parsed = urlparse(base_url.rstrip("/"))
            effective_url = base_parsed.scheme + "://" + base_parsed.netloc + parsed.path
            if parsed.query:
                effective_url += "?" + parsed.query

        surfaces: list = []
        parsed_url = urlparse(effective_url)
        url_no_qs = (parsed_url.scheme + "://" + parsed_url.netloc
                     + parsed_url.path) if parsed_url.netloc else effective_url

        # ── 1. Query parameters from URL ──────────────────────────────────
        for name, value in parse_qsl(parsed_url.query):
            surfaces.append(InputSurface(
                url=url_no_qs, method=self.method, param=name,
                param_type="query", original_value=value,
                headers=self.headers,
            ))

        # ── 2. Request body ───────────────────────────────────────────────
        ct = self.headers.get("Content-Type", "")
        body = self.body

        if body and "application/json" in ct:
            try:
                body_obj = json.loads(body)
                if isinstance(body_obj, dict):
                    for fname, fval in list(body_obj.items())[:30]:
                        surfaces.append(InputSurface(
                            url=url_no_qs, method=self.method, param=fname,
                            param_type="json", original_value=str(fval),
                            headers=self.headers,
                            content_type="application/json",
                        ))
            except (json.JSONDecodeError, ValueError):
                # Treat as single opaque body param
                surfaces.append(InputSurface(
                    url=url_no_qs, method=self.method, param="body",
                    param_type="json", original_value=body[:500],
                    headers=self.headers,
                    content_type="application/json",
                ))

        elif body and "application/x-www-form-urlencoded" in ct:
            for fname, fval in parse_qsl(body):
                surfaces.append(InputSurface(
                    url=url_no_qs, method=self.method, param=fname,
                    param_type="form", original_value=fval,
                    headers=self.headers,
                    content_type="application/x-www-form-urlencoded",
                ))

        # ── 3. Interesting headers (skip auth/content headers) ────────────
        _SKIP_HEADERS = {
            "content-type", "authorization", "content-length",
            "accept", "accept-encoding", "user-agent", "host",
        }
        for hname, hval in self.headers.items():
            if hname.lower() in _SKIP_HEADERS:
                continue
            surfaces.append(InputSurface(
                url=url_no_qs, method=self.method, param=hname,
                param_type="header", original_value=hval,
                headers=self.headers,
            ))

        return surfaces


class PostmanImporter:
    """Parses Postman Collection v2.0/v2.1 JSON into scanner-ready requests."""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Variable resolution
    # ------------------------------------------------------------------

    def _resolve_vars(self, text: str, env: dict[str, str]) -> str:
        """Replace ``{{variable_name}}`` placeholders with values from *env*."""
        if not text or not env:
            return text or ""
        def _replacer(m: re.Match) -> str:
            return env.get(m.group(1), "")
        return re.sub(r"\{\{(\w+)\}\}", _replacer, text)

    # ------------------------------------------------------------------
    # Auth parsing
    # ------------------------------------------------------------------

    def _parse_auth(
        self, auth_obj: dict[str, Any] | None, env: dict[str, str]
    ) -> dict[str, str]:
        """Convert a Postman auth object into HTTP headers."""
        if not auth_obj:
            return {}

        auth_type = auth_obj.get("type", "")
        headers: dict[str, str] = {}

        if auth_type == "bearer":
            token_entries = auth_obj.get("bearer", [])
            for entry in token_entries:
                if entry.get("key") == "token":
                    token = self._resolve_vars(entry.get("value", ""), env)
                    headers["Authorization"] = f"Bearer {token}"
                    break

        elif auth_type == "apikey":
            key_entries = auth_obj.get("apikey", [])
            header_key = "X-API-Key"
            header_value = ""
            for entry in key_entries:
                if entry.get("key") == "key":
                    header_key = self._resolve_vars(entry.get("value", ""), env)
                elif entry.get("key") == "value":
                    header_value = self._resolve_vars(entry.get("value", ""), env)
            headers[header_key] = header_value

        elif auth_type == "basic":
            import base64
            username = ""
            password = ""
            basic_entries = auth_obj.get("basic", [])
            for entry in basic_entries:
                if entry.get("key") == "username":
                    username = self._resolve_vars(entry.get("value", ""), env)
                elif entry.get("key") == "password":
                    password = self._resolve_vars(entry.get("value", ""), env)
            credentials = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"

        return headers

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------

    def _parse_headers(
        self, headers_list: list[dict[str, Any]] | None, env: dict[str, str]
    ) -> dict[str, str]:
        """Convert Postman header list to a simple ``{key: value}`` dict."""
        if not headers_list:
            return {}
        result: dict[str, str] = {}
        for h in headers_list:
            if h.get("disabled", False):
                continue
            key = self._resolve_vars(h.get("key", ""), env)
            value = self._resolve_vars(h.get("value", ""), env)
            if key:
                result[key] = value
        return result

    # ------------------------------------------------------------------
    # Body parsing
    # ------------------------------------------------------------------

    def _parse_body(
        self, body_obj: dict[str, Any] | None, env: dict[str, str]
    ) -> tuple[str, str]:
        """Parse Postman body into ``(body_string, content_type_hint)``."""
        if not body_obj:
            return ("", "")

        mode = body_obj.get("mode", "")

        if mode == "raw":
            raw = self._resolve_vars(body_obj.get("raw", ""), env)
            # Detect JSON content type hint
            options = body_obj.get("options", {})
            language = options.get("raw", {}).get("language", "")
            content_type = "application/json" if language == "json" else "text/plain"
            return (raw, content_type)

        elif mode in ("formdata", "urlencoded"):
            entries = body_obj.get(mode, [])
            pairs: list[str] = []
            for entry in entries:
                if entry.get("disabled", False):
                    continue
                key = self._resolve_vars(entry.get("key", ""), env)
                value = self._resolve_vars(entry.get("value", ""), env)
                pairs.append(f"{key}={value}")
            body_str = "&".join(pairs)
            content_type = "application/x-www-form-urlencoded"
            return (body_str, content_type)

        return ("", "")

    # ------------------------------------------------------------------
    # URL parsing
    # ------------------------------------------------------------------

    def _parse_url(
        self, url_obj: str | dict[str, Any], env: dict[str, str]
    ) -> str:
        """Normalize a Postman URL (string or structured dict) into a URL string."""
        if isinstance(url_obj, str):
            return self._resolve_vars(url_obj, env)

        # If it has a 'raw' key, prefer reconstructing from parts for accuracy
        if "raw" in url_obj and not url_obj.get("host"):
            return self._resolve_vars(url_obj["raw"], env)

        protocol = url_obj.get("protocol", "https")
        host_parts = url_obj.get("host", [])
        host = ".".join(host_parts) if isinstance(host_parts, list) else str(host_parts)
        path_parts = url_obj.get("path", [])
        path = "/".join(path_parts) if isinstance(path_parts, list) else str(path_parts)

        url = f"{protocol}://{host}"
        if path:
            url += f"/{path}"

        # Append query parameters
        query_params = url_obj.get("query", [])
        if query_params:
            qs_parts = []
            for q in query_params:
                if q.get("disabled", False):
                    continue
                k = self._resolve_vars(q.get("key", ""), env)
                v = self._resolve_vars(q.get("value", ""), env)
                qs_parts.append(f"{k}={v}")
            if qs_parts:
                url += "?" + "&".join(qs_parts)

        return self._resolve_vars(url, env)

    # ------------------------------------------------------------------
    # Recursive item extraction
    # ------------------------------------------------------------------

    def _extract_items(
        self,
        items: list[dict[str, Any]],
        env: dict[str, str],
        folder_path: str = "",
    ) -> list[PostmanRequest]:
        """Recursively walk Postman items (folders and requests)."""
        results: list[PostmanRequest] = []

        for item in items:
            name = item.get("name", "Unnamed")

            # Folder — has nested 'item' list
            if "item" in item and isinstance(item["item"], list):
                sub_path = f"{folder_path}/{name}" if folder_path else name
                results.extend(self._extract_items(item["item"], env, sub_path))
                continue

            # Request
            req_obj = item.get("request")
            if not req_obj:
                continue

            # Method
            method = "GET"
            if isinstance(req_obj, str):
                # Shorthand — just a URL
                results.append(
                    PostmanRequest(
                        name=name,
                        method="GET",
                        url=self._resolve_vars(req_obj, env),
                        headers={},
                        body="",
                        description="",
                        auth_type="",
                        folder_path=folder_path,
                    )
                )
                continue

            method = req_obj.get("method", "GET").upper()
            url = self._parse_url(req_obj.get("url", ""), env)
            headers = self._parse_headers(req_obj.get("header", []), env)

            # Auth headers
            auth_obj = req_obj.get("auth")
            auth_type = auth_obj.get("type", "") if auth_obj else ""
            auth_headers = self._parse_auth(auth_obj, env)
            headers.update(auth_headers)

            # Body
            body_str, content_type = self._parse_body(req_obj.get("body"), env)
            if content_type and "Content-Type" not in headers:
                headers["Content-Type"] = content_type

            # Description
            desc = req_obj.get("description", "")
            if isinstance(desc, dict):
                desc = desc.get("content", "")

            results.append(
                PostmanRequest(
                    name=name,
                    method=method,
                    url=url,
                    headers=headers,
                    body=body_str,
                    description=desc,
                    auth_type=auth_type,
                    folder_path=folder_path,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_collection(
        self,
        source: str | dict[str, Any],
        env: dict[str, str] | None = None,
    ) -> list[PostmanRequest]:
        """Load a Postman collection from a file path or parsed dict.

        Handles both Collection v2.0 and v2.1 formats.
        """
        env = env if env is not None else {}

        if isinstance(source, str):
            with open(source, "r", encoding="utf-8") as f:
                collection = json.load(f)
        else:
            collection = source

        # v2.0 wraps everything under 'collection', v2.1 is flat
        if "collection" in collection:
            collection = collection["collection"]

        # Merge collection-level variables into env (env takes precedence)
        coll_vars = collection.get("variable", [])
        for var in coll_vars:
            key = var.get("key", "")
            value = var.get("value", "")
            if key and key not in env:
                env[key] = str(value)

        items = collection.get("item", [])
        return self._extract_items(items, env)

    def load_environment(self, env_file_path: str) -> dict[str, str]:
        """Parse a Postman environment JSON file and return enabled variables."""
        with open(env_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        result: dict[str, str] = {}
        for entry in data.get("values", []):
            if entry.get("enabled", True):
                result[entry.get("key", "")] = str(entry.get("value", ""))

        return result
