"""
Object ID Harvester — collects numeric IDs, GUIDs, slugs, and identifiers
from HTTP responses during crawl. Used by IDOR/BAC testing to perform
cross-user access tests with real object IDs instead of guesses.
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("id_harvester")


@dataclass
class HarvestedID:
    """A single harvested identifier."""
    value: str
    id_type: str           # "numeric", "uuid", "slug", "encoded"
    source: str            # "url_path", "url_query", "json_body", "html_body", "header"
    param_name: str        # The parameter or field name where it was found
    url: str               # The URL where it was harvested
    context: str = ""      # Optional: the user/role context when harvested


class ObjectIDHarvester:
    """
    Collects object identifiers from HTTP responses during scanning.

    Usage:
        harvester = ObjectIDHarvester()
        harvester.harvest_response(url, status_code, headers, body, params)
        harvester.harvest_url(url)

        # Later, for IDOR testing:
        ids = harvester.get_ids_for_param("user_id")
        all_ids = harvester.get_all_ids()
        id_map = harvester.get_param_id_map()  # {param_name: [ids]}
    """

    # ── Regex patterns for ID extraction ──────────────────────────────────────

    # Numeric IDs (at least 1 digit, max 20 to avoid matching random numbers)
    _NUMERIC_ID = re.compile(r'(?:^|["\s/=:,\[({])(\d{1,20})(?:["\s/=:,\])}]|$)')

    # UUIDs (v1-v5, with or without dashes)
    _UUID = re.compile(
        r'[0-9a-f]{8}-?[0-9a-f]{4}-?[1-5][0-9a-f]{3}-?[89ab][0-9a-f]{3}-?[0-9a-f]{12}',
        re.I,
    )

    # MongoDB ObjectIDs (24 hex chars)
    _MONGO_OID = re.compile(r'\b[0-9a-f]{24}\b', re.I)

    # Base64-encoded IDs (likely JWT-less tokens or encoded PKs)
    _BASE64_ID = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')

    # URL path segment IDs: /users/123, /api/v1/orders/abc-def-123
    _PATH_ID = re.compile(r'/(?:api/)?(?:v\d+/)?(\w+)/([0-9a-f-]{4,}|[0-9]+)(?:/|$)', re.I)

    # JSON key patterns that typically hold object IDs
    _ID_KEY_PATTERNS = re.compile(
        r'"((?:\w*_)?(?:id|Id|ID|uuid|guid|pk|key|ref|token|slug|code|number|num|oid))"'
        r'\s*:\s*"?([^",}\s]+)"?',
        re.I,
    )

    # HTML form hidden field IDs
    _HIDDEN_FIELD = re.compile(
        r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']',
        re.I,
    )

    # Param names that suggest ID-like values
    _ID_PARAM_NAMES = re.compile(
        r'(?:^|_)(id|uuid|guid|pk|key|ref|token|slug|code|number|num|oid|user|account|order|item|product|session)(?:_|$)',
        re.I,
    )

    def __init__(self):
        self._ids: list[HarvestedID] = []
        self._seen: set[tuple[str, str]] = set()  # (param_name, value) dedup
        self._url_ids: set[str] = set()  # dedup URL path IDs

    def harvest_url(self, url: str) -> list[HarvestedID]:
        """Extract IDs from URL path segments and query parameters."""
        results = []
        parsed = urlparse(url)

        # Path segment IDs: /users/123, /orders/abc-def
        for match in self._PATH_ID.finditer(parsed.path):
            resource, value = match.group(1), match.group(2)
            param_name = f"{resource}_id"
            id_type = self._classify_id(value)
            if id_type and (param_name, value) not in self._seen:
                hid = HarvestedID(
                    value=value, id_type=id_type, source="url_path",
                    param_name=param_name, url=url,
                )
                results.append(hid)
                self._ids.append(hid)
                self._seen.add((param_name, value))

        # Query parameter IDs
        params = parse_qs(parsed.query)
        for key, values in params.items():
            if self._ID_PARAM_NAMES.search(key):
                for val in values:
                    id_type = self._classify_id(val)
                    if id_type and (key, val) not in self._seen:
                        hid = HarvestedID(
                            value=val, id_type=id_type, source="url_query",
                            param_name=key, url=url,
                        )
                        results.append(hid)
                        self._ids.append(hid)
                        self._seen.add((key, val))

        return results

    def harvest_response(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
        context: str = "",
    ) -> list[HarvestedID]:
        """Extract IDs from response body (JSON keys, hidden fields, patterns)."""
        results = []
        if not body or status_code >= 400:
            return results

        body_sample = body[:16000]  # Cap to avoid regex on huge bodies

        # JSON key-value ID extraction
        for match in self._ID_KEY_PATTERNS.finditer(body_sample):
            key, value = match.group(1), match.group(2)
            id_type = self._classify_id(value)
            if id_type and (key, value) not in self._seen:
                hid = HarvestedID(
                    value=value, id_type=id_type, source="json_body",
                    param_name=key, url=url, context=context,
                )
                results.append(hid)
                self._ids.append(hid)
                self._seen.add((key, value))

        # HTML hidden field extraction
        for match in self._HIDDEN_FIELD.finditer(body_sample):
            name, value = match.group(1), match.group(2)
            if self._ID_PARAM_NAMES.search(name):
                id_type = self._classify_id(value)
                if id_type and (name, value) not in self._seen:
                    hid = HarvestedID(
                        value=value, id_type=id_type, source="html_body",
                        param_name=name, url=url, context=context,
                    )
                    results.append(hid)
                    self._ids.append(hid)
                    self._seen.add((name, value))

        # UUID extraction from body
        for match in self._UUID.finditer(body_sample):
            uuid_val = match.group(0)
            if ("_uuid", uuid_val) not in self._seen:
                hid = HarvestedID(
                    value=uuid_val, id_type="uuid", source="json_body",
                    param_name="_uuid", url=url, context=context,
                )
                results.append(hid)
                self._ids.append(hid)
                self._seen.add(("_uuid", uuid_val))

        # MongoDB ObjectID extraction
        for match in self._MONGO_OID.finditer(body_sample):
            oid = match.group(0)
            # Avoid false positives with UUIDs (which are longer)
            if len(oid) == 24 and ("_mongo_oid", oid) not in self._seen:
                hid = HarvestedID(
                    value=oid, id_type="mongo_oid", source="json_body",
                    param_name="_mongo_oid", url=url, context=context,
                )
                results.append(hid)
                self._ids.append(hid)
                self._seen.add(("_mongo_oid", oid))

        # Set-Cookie header IDs (session tokens that look like IDs)
        for hdr_name, hdr_val in headers.items():
            if hdr_name.lower() == "set-cookie":
                for part in hdr_val.split(";"):
                    if "=" in part:
                        ck_name, ck_val = part.strip().split("=", 1)
                        if self._ID_PARAM_NAMES.search(ck_name):
                            id_type = self._classify_id(ck_val)
                            if id_type and (ck_name, ck_val) not in self._seen:
                                hid = HarvestedID(
                                    value=ck_val, id_type=id_type, source="header",
                                    param_name=ck_name, url=url, context=context,
                                )
                                results.append(hid)
                                self._ids.append(hid)
                                self._seen.add((ck_name, ck_val))

        return results

    def _classify_id(self, value: str) -> str | None:
        """Classify an ID value by type. Returns None if not an ID."""
        if not value or len(value) > 200:
            return None

        # UUID
        if self._UUID.fullmatch(value):
            return "uuid"

        # MongoDB ObjectID
        if len(value) == 24 and self._MONGO_OID.fullmatch(value):
            return "mongo_oid"

        # Numeric (1-20 digits, not just 0)
        if value.isdigit() and 1 <= len(value) <= 20:
            # Filter out common non-ID numbers (HTTP codes, years, etc.)
            num = int(value)
            if num == 0 or (1900 <= num <= 2100 and len(value) == 4):
                return None  # Likely a year, not an ID
            return "numeric"

        # Slug-like (alphanumeric with dashes/underscores, 3-100 chars)
        if re.fullmatch(r'[a-zA-Z0-9][-a-zA-Z0-9_]{2,99}', value):
            # Must contain at least one digit or dash to look ID-like, not just a word
            if re.search(r'\d', value) or '-' in value:
                return "slug"

        # Base64-encoded (16+ chars, valid base64 alphabet)
        if len(value) >= 16 and self._BASE64_ID.fullmatch(value):
            return "encoded"

        return None

    # ── Query methods ─────────────────────────────────────────────────────────

    def get_all_ids(self) -> list[HarvestedID]:
        """Return all harvested IDs."""
        return list(self._ids)

    def get_ids_for_param(self, param_name: str) -> list[str]:
        """Get all unique ID values for a specific parameter name."""
        return list({h.value for h in self._ids if h.param_name == param_name})

    def get_ids_by_type(self, id_type: str) -> list[HarvestedID]:
        """Get all IDs of a specific type (numeric, uuid, slug, encoded, mongo_oid)."""
        return [h for h in self._ids if h.id_type == id_type]

    def get_ids_by_context(self, context: str) -> list[HarvestedID]:
        """Get all IDs harvested under a specific user/role context."""
        return [h for h in self._ids if h.context == context]

    def get_param_id_map(self) -> dict[str, list[str]]:
        """Get a map of param_name → [unique_id_values]."""
        result: dict[str, list[str]] = {}
        for h in self._ids:
            result.setdefault(h.param_name, [])
            if h.value not in result[h.param_name]:
                result[h.param_name].append(h.value)
        return result

    def get_cross_user_test_pairs(self) -> list[tuple[str, str, str]]:
        """
        Generate (param_name, id_value, original_context) tuples for cross-user testing.
        Returns IDs that were seen in one user context, for testing with another user.
        """
        # Group by context
        by_context: dict[str, list[HarvestedID]] = {}
        for h in self._ids:
            if h.context:
                by_context.setdefault(h.context, []).append(h)

        pairs = []
        contexts = list(by_context.keys())
        for i, ctx in enumerate(contexts):
            for h in by_context[ctx]:
                # This ID belongs to ctx — test it with all other contexts
                pairs.append((h.param_name, h.value, ctx))

        return pairs

    def summary(self) -> dict[str, Any]:
        """Return a summary of harvested IDs."""
        by_type: dict[str, int] = {}
        by_source: dict[str, int] = {}
        by_param: dict[str, int] = {}

        for h in self._ids:
            by_type[h.id_type] = by_type.get(h.id_type, 0) + 1
            by_source[h.source] = by_source.get(h.source, 0) + 1
            by_param[h.param_name] = by_param.get(h.param_name, 0) + 1

        return {
            "total_ids": len(self._ids),
            "unique_values": len(self._seen),
            "by_type": by_type,
            "by_source": by_source,
            "top_params": dict(sorted(by_param.items(), key=lambda x: -x[1])[:20]),
        }

    def clear(self):
        """Reset all harvested data."""
        self._ids.clear()
        self._seen.clear()
        self._url_ids.clear()
