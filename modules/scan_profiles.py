"""
Pre-built scan profiles for the DAST engine.

Each profile is a dict with keys that map directly to the engine config
consumed by ``_engine_scan_worker`` plus metadata for the UI.
"""
from __future__ import annotations
from typing import Optional

PROFILES = {
    "quick": {
        "name": "Quick",
        "description": "Passive-only scan — crawl, passive checks, fingerprint. No fuzzing or external tools. Good for CI/CD.",
        "max_pages": 50,
        "max_depth": 3,
        "delay": 0.05,
        "timeout": 8,
        "max_per_type": 0,
        "phases_enabled": [
            "crawl",
            "passive",
            "fingerprint",
        ],
        "external_tools": False,
    },
    "standard": {
        "name": "Standard",
        "description": (
            "Balanced scan — crawl, passive, fingerprint, deep discovery, "
            "active fuzzing, OWASP checks, WebSocket/GraphQL/IDOR testing, "
            "cache poisoning, external tools, and post-processing."
        ),
        "max_pages": 200,
        "max_depth": 5,
        "delay": 0.05,
        "timeout": 10,
        "max_per_type": 8,
        "phases_enabled": [
            "crawl",
            "passive",
            "fingerprint",
            "deep_discovery",   # API route discovery from JS, source discovery, DOM XSS active
            "fuzz",
            "owasp_checks",
            "api_race_testing",
            "idor_tests",       # IDOR / multi-user access control testing
            "websocket",        # WebSocket security (CSWSH, injection, auth bypass)
            "graphql",          # GraphQL introspection, injection, batching
            "cache_poison",     # Cache poisoning (Vary header abuse, unkeyed headers)
            "external_tools",
            "post_processing",  # CVSS scoring, dedup, vuln chaining, finding correlation
        ],
        "external_tools": True,
    },
    "full": {
        "name": "Full",
        "description": (
            "Comprehensive scan — all standard phases plus UA diffing, "
            "business logic testing, BChecks (261 CVE + vuln-class rules), "
            "SAML scanner, shadow API discovery."
        ),
        "max_pages": 500,
        "max_depth": 8,
        "delay": 0.05,
        "timeout": 15,
        "max_per_type": 15,
        "phases_enabled": [
            "crawl",
            "passive",
            "fingerprint",
            "deep_discovery",
            "fuzz",
            "owasp_checks",
            "api_race_testing",
            "idor_tests",
            "websocket",
            "graphql",
            "cache_poison",
            "ua_diff",          # User-Agent behavioral diffing (bot detection, CDN variance)
            "biz_logic",        # Business logic flaws (mass assignment, price abuse, TOCTOU)
            "bchecks",          # 261 BCheck rules: CVEs + vulnerability class patterns
            "saml",             # SAML assertion signing, XXE, replay attacks
            "shadow_api",       # Undocumented endpoint discovery from JS + route analysis
            "external_tools",
            "post_processing",
        ],
        "external_tools": True,
    },
    "api-only": {
        "name": "API Only",
        "description": (
            "API-focused — no crawl, import OpenAPI spec, fuzz all surfaces, "
            "API Top-10 tests (BOLA, mass assignment, verb tampering), "
            "GraphQL/race/IDOR/shadow API testing, post-processing."
        ),
        "max_pages": 0,
        "max_depth": 0,
        "delay": 0.05,
        "timeout": 12,
        "max_per_type": 10,
        "phases_enabled": [
            "passive",
            "fingerprint",
            "deep_discovery",   # API route discovery from JS bundles
            "fuzz",
            "owasp_checks",
            "api_race_testing",
            "idor_tests",
            "graphql",
            "shadow_api",       # Undocumented endpoint discovery
            "post_processing",
        ],
        "external_tools": False,
    },
    "stealth": {
        "name": "Stealth",
        "description": "Low and slow — small crawl with delay, passive checks plus light fuzzing. No external tools. For WAF-protected targets.",
        "max_pages": 100,
        "max_depth": 3,
        "delay": 0.5,
        "timeout": 15,
        "max_per_type": 3,
        "phases_enabled": [
            "crawl",
            "passive",
            "fingerprint",
            "fuzz",
        ],
        "external_tools": False,
    },
}


def get_profile(name: str) -> Optional[dict]:
    """Return a copy of the named profile, or None."""
    p = PROFILES.get(name)
    return dict(p) if p else None


def get_engine_config(profile_name: str) -> dict:
    """Return the engine-config subset that ``_engine_scan_worker`` consumes.

    Falls back to *standard* defaults when the profile is unknown.
    """
    p = PROFILES.get(profile_name, PROFILES["standard"])
    return {
        "max_pages":    p["max_pages"],
        "max_depth":    p["max_depth"],
        "timeout":      p["timeout"],
        "delay":        p["delay"],
        "max_per_type": p["max_per_type"],
    }


def list_profiles() -> list[dict]:
    """Return a summary list suitable for the ``/api/scan/profiles`` response."""
    out = []
    for key, p in PROFILES.items():
        out.append({
            "id":              key,
            "name":            p["name"],
            "description":     p["description"],
            "max_pages":       p["max_pages"],
            "max_depth":       p["max_depth"],
            "delay":           p["delay"],
            "max_per_type":    p["max_per_type"],
            "phases_enabled":  p["phases_enabled"],
            "external_tools":  p["external_tools"],
        })
    return out
