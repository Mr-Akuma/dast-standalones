"""
OpenAPI / Swagger Importer — parses API specs and generates InputSurface objects.

Supports:
- OpenAPI 3.0 / 3.1 (JSON or YAML)
- Swagger 2.0 (JSON or YAML)
- Input: URL, file path, or raw dict

Zero hard dependencies (YAML support auto-detected via PyYAML if installed).
Falls back to JSON-only if PyYAML absent.
"""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Optional
from urllib.parse import urlencode

from .crawler import InputSurface


# ── Schema value resolver ──────────────────────────────────────────────────────

def _resolve_ref(ref: str, spec: dict) -> dict:
    """Resolve a $ref like '#/components/schemas/Foo' to its schema dict."""
    parts = ref.lstrip("#/").split("/")
    node  = spec
    for p in parts:
        node = node.get(p, {})
    return node


def _sample_value(schema: dict, spec: dict, depth: int = 0) -> str:
    """Return a safe sample value string for a JSON schema."""
    if depth > 4 or not schema:
        return "test"

    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], spec)
        return _sample_value(schema, spec, depth + 1)

    typ = schema.get("type", "string")

    if schema.get("example") is not None:
        return str(schema["example"])
    if schema.get("default") is not None:
        return str(schema["default"])
    if schema.get("enum"):
        return str(schema["enum"][0])

    if typ in ("integer", "number"):
        return "1"
    if typ == "boolean":
        return "true"
    if typ == "array":
        item_val = _sample_value(schema.get("items", {}), spec, depth + 1)
        return f"[{item_val}]"
    if typ == "object":
        props = schema.get("properties", {})
        result = {}
        for k, v in list(props.items())[:5]:
            result[k] = _sample_value(v, spec, depth + 1)
        return json.dumps(result)

    # string
    fmt = schema.get("format", "")
    if fmt == "date":        return "2024-01-01"
    if fmt == "date-time":   return "2024-01-01T00:00:00Z"
    if fmt == "email":       return "test@example.com"
    if fmt == "uri":         return "http://example.com"
    if fmt == "uuid":        return "00000000-0000-0000-0000-000000000000"
    return "test"


def _clean_path(path: str) -> str:
    """Replace {param} placeholders with '1' so the URL is valid."""
    return re.sub(r"\{[^}]+\}", "1", path)


# ── Loader ────────────────────────────────────────────────────────────────────

def load_spec(source) -> dict:
    """
    Load an OpenAPI/Swagger spec from:
    - dict          (already parsed)
    - str URL       (http/https)
    - str file path (local .json / .yaml)
    - str raw JSON  (inline)
    """
    if isinstance(source, dict):
        return source

    # Raw JSON string
    if isinstance(source, str) and source.strip().startswith("{"):
        return json.loads(source)

    # URL
    if isinstance(source, str) and source.startswith("http"):
        resp    = urllib.request.urlopen(source, timeout=15)
        content = resp.read()
    else:
        with open(source, "rb") as f:
            content = f.read()

    # Try JSON first
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        pass

    # Try YAML
    try:
        import yaml  # type: ignore
        return yaml.safe_load(content)
    except ImportError:
        raise ValueError(
            "Spec appears to be YAML but PyYAML is not installed. "
            "Install it: pip install pyyaml  OR  provide a JSON spec."
        )


# ── Importer ──────────────────────────────────────────────────────────────────

class OpenAPIImporter:
    """
    Parses OpenAPI 2.0 or 3.x spec and returns a list of InputSurface objects
    covering every endpoint × parameter combination.
    """

    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")

    # ── Public API ────────────────────────────────────────────────────────────

    def import_spec(self, spec: dict) -> list[InputSurface]:
        version = str(spec.get("openapi", spec.get("swagger", "")))
        if version.startswith("3"):
            return self._parse_oas3(spec)
        elif version.startswith("2"):
            return self._parse_swagger2(spec)
        else:
            raise ValueError(
                f"Unrecognized spec version: {version!r}. "
                "Expected 'openapi: 3.x' or 'swagger: 2.0'."
            )

    def import_from_source(self, source) -> list[InputSurface]:
        """Convenience: load + import in one call."""
        return self.import_spec(load_spec(source))

    # ── Base URL resolution ───────────────────────────────────────────────────

    def _get_base(self, spec: dict) -> str:
        if self.base_url:
            return self.base_url
        # OAS3
        servers = spec.get("servers", [])
        if servers:
            url = servers[0].get("url", "http://localhost")
            # Strip trailing slash and template vars
            url = re.sub(r"\{[^}]+\}", "1", url)
            return url.rstrip("/")
        # Swagger 2
        host   = spec.get("host", "localhost")
        scheme = (spec.get("schemes") or ["http"])[0]
        base   = spec.get("basePath", "")
        return f"{scheme}://{host}{base}".rstrip("/")

    # ── OpenAPI 3.x ───────────────────────────────────────────────────────────

    def _parse_oas3(self, spec: dict) -> list[InputSurface]:
        surfaces = []
        base     = self._get_base(spec)

        for path_template, path_item in spec.get("paths", {}).items():
            full_url = base + _clean_path(path_template)

            # Resolve path-level parameters
            path_params = self._resolve_params(path_item.get("parameters", []), spec)

            for method, operation in path_item.items():
                if method.lower() not in (
                    "get", "post", "put", "patch", "delete", "options", "head"
                ):
                    continue

                # Merge path-level + operation-level params (operation wins)
                op_params  = self._resolve_params(operation.get("parameters", []), spec)
                all_params = {**path_params, **op_params}

                for name, meta in all_params.items():
                    location = meta.get("in", "query")
                    schema   = meta.get("schema", {})
                    example  = _sample_value(schema, spec)
                    p_type   = {"query":"query", "path":"path",
                                "header":"header", "cookie":"cookie"}.get(location, "query")

                    surfaces.append(InputSurface(
                        url=full_url, method=method.upper(), param=name,
                        param_type=p_type, original_value=example,
                    ))

                # Request body
                body_surfs = self._extract_body_oas3(full_url, method.upper(),
                                                      operation.get("requestBody", {}), spec)
                surfaces.extend(body_surfs)

        return surfaces

    def _resolve_params(self, params: list, spec: dict) -> dict:
        """Resolve $ref params and return {name: param_object}."""
        result = {}
        for p in params:
            if "$ref" in p:
                p = _resolve_ref(p["$ref"], spec)
            name = p.get("name", "")
            if name:
                result[name] = p
        return result

    def _extract_body_oas3(self, url: str, method: str, body: dict, spec: dict) -> list[InputSurface]:
        surfaces = []
        for ct, ct_info in body.get("content", {}).items():
            schema = ct_info.get("schema", {})
            if "$ref" in schema:
                schema = _resolve_ref(schema["$ref"], spec)

            props = schema.get("properties", {})
            if not props and schema.get("type") == "object":
                props = {}

            if "application/json" in ct:
                for fname, fschema in list(props.items())[:30]:
                    surfaces.append(InputSurface(
                        url=url, method=method, param=fname,
                        param_type="json",
                        original_value=_sample_value(fschema, spec),
                        content_type="application/json",
                    ))
                # If no properties, add a generic body param
                if not props:
                    surfaces.append(InputSurface(
                        url=url, method=method, param="body",
                        param_type="json",
                        original_value=_sample_value(schema, spec),
                        content_type="application/json",
                    ))

            elif "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct:
                for fname, fschema in list(props.items())[:30]:
                    surfaces.append(InputSurface(
                        url=url, method=method, param=fname,
                        param_type="form",
                        original_value=_sample_value(fschema, spec),
                        content_type="application/x-www-form-urlencoded",
                    ))
        return surfaces

    # ── Swagger 2.0 ───────────────────────────────────────────────────────────

    def _parse_swagger2(self, spec: dict) -> list[InputSurface]:
        surfaces = []
        base     = self._get_base(spec)

        for path_template, path_item in spec.get("paths", {}).items():
            full_url = base + _clean_path(path_template)

            for method, operation in path_item.items():
                if method.lower() not in (
                    "get", "post", "put", "patch", "delete", "options", "head"
                ):
                    continue

                for param in operation.get("parameters", []):
                    if "$ref" in param:
                        param = _resolve_ref(param["$ref"], spec)

                    name     = param.get("name", "")
                    location = param.get("in", "query")

                    if not name:
                        continue

                    if location == "body":
                        schema = param.get("schema", {})
                        if "$ref" in schema:
                            schema = _resolve_ref(schema["$ref"], spec)
                        props = schema.get("properties", {})
                        for fname, fschema in list(props.items())[:30]:
                            surfaces.append(InputSurface(
                                url=full_url, method=method.upper(), param=fname,
                                param_type="json",
                                original_value=_sample_value(fschema, spec),
                                content_type="application/json",
                            ))
                        if not props:
                            surfaces.append(InputSurface(
                                url=full_url, method=method.upper(), param="body",
                                param_type="json",
                                original_value=_sample_value(schema, spec),
                                content_type="application/json",
                            ))

                    elif location == "formData":
                        schema = param.get("schema", {})
                        surfaces.append(InputSurface(
                            url=full_url, method=method.upper(), param=name,
                            param_type="form",
                            original_value=_sample_value(schema, spec),
                            content_type="application/x-www-form-urlencoded",
                        ))

                    else:
                        p_type = {"query":"query", "path":"path",
                                  "header":"header"}.get(location, "query")
                        schema  = param.get("schema", {})
                        example = _sample_value(schema, spec) if schema else param.get("default", "test")
                        surfaces.append(InputSurface(
                            url=full_url, method=method.upper(), param=name,
                            param_type=p_type, original_value=str(example),
                        ))

        return surfaces


# ── Convenience function ──────────────────────────────────────────────────────

def import_openapi(source, base_url: str = "") -> list[InputSurface]:
    """Load and parse an OpenAPI/Swagger spec. Returns InputSurface list."""
    return OpenAPIImporter(base_url=base_url).import_from_source(source)
