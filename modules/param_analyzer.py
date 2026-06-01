"""
Parameter context analyzer for DAST scanner.

Infers what type of input a parameter expects before fuzzing,
so the fuzzer can select the most relevant payloads.

"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ParamProfile:
    """Profile describing a parameter's inferred type and attack surface."""
    name: str
    inferred_type: str  # numeric_id, uuid, email, url, filename, search_query, date, boolean, json, html, auth_token, unknown
    confidence: float  # 0.0 - 1.0
    suggested_vuln_types: list[str] = field(default_factory=list)
    evidence: str = ""


# Vuln-type priority weights (lower = higher priority during sorting)
_VULN_PRIORITY = {
    "cmdi": 0,
    "sqli": 1,
    "ssti": 2,
    "lfi": 3,
    "ssrf": 4,
    "xss": 5,
    "idor": 6,
    "open_redirect": 7,
    "header_injection": 8,
    "auth_bypass": 9,
    "session_fixation": 10,
}

# Name-based inference rules: (pattern, inferred_type, vuln_types)
_NAME_RULES = [
    (re.compile(r"(^|[_\-.])(cmd|exec|command|run|shell|ping)($|[_\-.])", re.I),
     "search_query", ["cmdi"]),
    (re.compile(r"(^|[_\-.])(ip|host)($|[_\-.])", re.I),
     "search_query", ["cmdi"]),
    (re.compile(r"(email|mail)", re.I),
     "email", ["xss", "sqli", "header_injection"]),
    (re.compile(r"(url|uri|link|redirect|next|return|callback)", re.I),
     "url", ["ssrf", "open_redirect"]),
    (re.compile(r"(file|path|dir|doc|template|page|include)", re.I),
     "filename", ["lfi", "ssti"]),
    (re.compile(r"(search|query|keyword|term)", re.I),
     "search_query", ["xss", "sqli"]),
    (re.compile(r"(^|[_\-.])(q)($|[_\-.])", re.I),
     "search_query", ["xss", "sqli"]),
    (re.compile(r"(token|jwt|session|auth|api_key)", re.I),
     "auth_token", ["auth_bypass"]),
    (re.compile(r"(sort|order|column|field)", re.I),
     "search_query", ["sqli"]),
    (re.compile(r"(date|time)", re.I),
     "date", ["sqli"]),
    (re.compile(r"(^|[_\-.])(from|to|start|end)($|[_\-.])", re.I),
     "date", ["sqli"]),
    (re.compile(r"(id|pk|key|num)", re.I),
     "numeric_id", ["idor", "sqli"]),
]

# Value-based inference patterns
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_NUMERIC_RE = re.compile(r"^-?\d+(\.\d+)?$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
_URL_RE = re.compile(r"^https?://", re.I)
_FILEPATH_RE = re.compile(r"[/\\][\w.\-]+[/\\]|\.\.(/|\\)|^\w+\.\w{1,5}$")
_JSON_RE = re.compile(r"^\s*[\[{]")
_HTML_RE = re.compile(r"<[a-zA-Z][^>]*>")
_BOOL_RE = re.compile(r"^(true|false|0|1|yes|no)$", re.I)


class ParamAnalyzer:
    """Analyzes parameter names and sample values to infer input types."""

    def __init__(self):
        pass

    def analyze(
        self,
        param_name: str,
        sample_values: list[str] = None,
        param_location: str = "query",
    ) -> ParamProfile:
        """
        Analyze a single parameter and return its profile.

        Args:
            param_name: The parameter name (e.g. "user_id").
            sample_values: Optional list of observed values.
            param_location: One of "query", "header", "cookie", "path", "body".

        Returns:
            ParamProfile with inferred type and suggested vuln types.
        """
        # Phase 1: name-based inference
        name_profile = self._infer_from_name(param_name)

        # Phase 2: value-based inference (can override name)
        value_profile = None
        if sample_values:
            value_profile = self._infer_from_values(param_name, sample_values)

        # Pick the higher-confidence result
        if value_profile and (
            name_profile is None or value_profile.confidence > name_profile.confidence
        ):
            profile = value_profile
        elif name_profile:
            profile = name_profile
        else:
            profile = ParamProfile(
                name=param_name,
                inferred_type="unknown",
                confidence=0.1,
                suggested_vuln_types=["xss", "sqli"],
                evidence="no matching pattern in name or values",
            )

        # Phase 3: location-based adjustments
        self._adjust_for_location(profile, param_location)

        return profile

    def analyze_batch(
        self, params: list[tuple[str, list[str], str]]
    ) -> list[ParamProfile]:
        """
        Analyze multiple parameters at once.

        Args:
            params: List of (param_name, sample_values, param_location) tuples.

        Returns:
            List of ParamProfile objects.
        """
        return [
            self.analyze(name, values, location)
            for name, values, location in params
        ]

    def get_priority_vulns(self, profile: ParamProfile) -> list[str]:
        """
        Return the profile's suggested vuln types sorted by priority
        (most critical first).
        """
        return sorted(
            profile.suggested_vuln_types,
            key=lambda v: _VULN_PRIORITY.get(v, 99),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _infer_from_name(self, param_name: str) -> ParamProfile | None:
        """Match param name against known naming patterns."""
        for pattern, inferred_type, vuln_types in _NAME_RULES:
            if pattern.search(param_name):
                return ParamProfile(
                    name=param_name,
                    inferred_type=inferred_type,
                    confidence=0.8,
                    suggested_vuln_types=list(vuln_types),
                    evidence=f"name '{param_name}' matches pattern for {inferred_type}",
                )
        return None

    def _infer_from_values(
        self, param_name: str, sample_values: list[str]
    ) -> ParamProfile | None:
        """Analyze sample values to infer type. Returns profile at 0.9 confidence."""
        if not sample_values:
            return None

        # Filter out empty strings
        values = [v for v in sample_values if v]
        if not values:
            return None

        # Count how many values match each pattern
        checks: list[tuple[str, re.Pattern, list[str]]] = [
            ("uuid", _UUID_RE, ["idor"]),
            ("email", _EMAIL_RE, ["xss", "sqli", "header_injection"]),
            ("url", _URL_RE, ["ssrf", "open_redirect"]),
            ("boolean", _BOOL_RE, ["auth_bypass"]),
            ("numeric_id", _NUMERIC_RE, ["idor", "sqli"]),
        ]

        for type_name, regex, vulns in checks:
            matches = sum(1 for v in values if regex.search(v))
            if matches >= len(values) * 0.6:
                return ParamProfile(
                    name=param_name,
                    inferred_type=type_name,
                    confidence=0.9,
                    suggested_vuln_types=list(vulns),
                    evidence=f"{matches}/{len(values)} values match {type_name} pattern",
                )

        # Patterns that need different checking (partial match is fine)
        for val in values:
            if _JSON_RE.search(val):
                return ParamProfile(
                    name=param_name,
                    inferred_type="json",
                    confidence=0.9,
                    suggested_vuln_types=["sqli", "xss"],
                    evidence=f"value starts with JSON delimiter: {val[:40]}",
                )

        for val in values:
            if _HTML_RE.search(val):
                return ParamProfile(
                    name=param_name,
                    inferred_type="html",
                    confidence=0.9,
                    suggested_vuln_types=["xss"],
                    evidence=f"value contains HTML tags: {val[:40]}",
                )

        for val in values:
            if _FILEPATH_RE.search(val):
                return ParamProfile(
                    name=param_name,
                    inferred_type="filename",
                    confidence=0.9,
                    suggested_vuln_types=["lfi"],
                    evidence=f"value resembles file path: {val[:40]}",
                )

        return None

    def _adjust_for_location(
        self, profile: ParamProfile, param_location: str
    ) -> None:
        """Mutate profile based on where the parameter lives."""
        location = param_location.lower()

        if location == "header":
            if "header_injection" not in profile.suggested_vuln_types:
                profile.suggested_vuln_types.append("header_injection")
            profile.evidence += "; header param — added header_injection"

        elif location == "cookie":
            if "session_fixation" not in profile.suggested_vuln_types:
                profile.suggested_vuln_types.append("session_fixation")
            profile.evidence += "; cookie param — added session_fixation"

        elif location == "path":
            if "idor" not in profile.suggested_vuln_types:
                profile.suggested_vuln_types.append("idor")
            profile.confidence = min(1.0, profile.confidence + 0.05)
            profile.evidence += "; path param — boosted idor confidence"
