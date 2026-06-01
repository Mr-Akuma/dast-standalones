"""API response vs UI exposure diffing."""
from __future__ import annotations

import re
from typing import Any, Iterable


_SENSITIVE_RE = re.compile(
    r"(token|secret|password|passwd|pwd|session|cookie|jwt|api[_-]?key|role|admin|"
    r"permission|scope|internal|cost|price|ssn|dob|credit|card|private|debug|"
    r"feature|flag|tenant|accountid|userid)",
    re.I,
)


def _flatten_json(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out.extend(_flatten_json(child, path))
    elif isinstance(value, list):
        for idx, child in enumerate(value[:10]):
            path = f"{prefix}[{idx}]"
            out.extend(_flatten_json(child, path))
    else:
        out.append((prefix, value))
    return out


def _field_tokens(path: str) -> set[str]:
    parts = re.split(r"[\.\[\]_\-\s]+", path)
    tokens = {p.lower() for p in parts if p}
    tokens.add(path.lower())
    if "." in path:
        tokens.add(path.rsplit(".", 1)[-1].lower())
    return tokens


class ApiExposureDiffer:
    def compare(self, ui_fields: Iterable[str], api_json: Any) -> dict:
        ui = {str(f).strip().lower() for f in ui_fields if str(f).strip()}
        flattened = _flatten_json(api_json)
        excessive: list[dict] = []
        hidden_non_sensitive: list[dict] = []

        for path, value in flattened:
            tokens = _field_tokens(path)
            rendered = bool(tokens & ui)
            if rendered:
                continue
            item = {
                "path": path,
                "value_preview": self._preview(value),
                "sensitive": bool(_SENSITIVE_RE.search(path)),
            }
            if item["sensitive"]:
                excessive.append(item)
            else:
                hidden_non_sensitive.append(item)

        severity = "info"
        if any(re.search(r"(token|secret|password|jwt|api[_-]?key)", f["path"], re.I) for f in excessive):
            severity = "high"
        elif excessive:
            severity = "medium"

        return {
            "finding_count": len(excessive),
            "severity": severity,
            "excessive_fields": excessive,
            "hidden_non_sensitive": hidden_non_sensitive[:50],
            "total_api_fields": len(flattened),
            "rendered_field_count": len(ui),
            "vuln_type": "excessive_data_exposure",
        }

    @staticmethod
    def _preview(value: Any) -> str:
        text = str(value)
        return text if len(text) <= 80 else text[:77] + "..."
