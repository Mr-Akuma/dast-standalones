"""
YAML Configuration loader and validator for DAST scanner.
Supports scan policy, per-check toggles, scope, auth, and wordlists.
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

_VALID_POLICIES = {"quick", "standard", "full", "api", "stealth"}
_VALID_AUTH_TYPES = {"none", "bearer", "cookie", "basic", "header"}
_VALID_FORMATS = {"html", "sarif", "pdf", "json", "csv"}
_VALID_FAIL_ON = {"low", "medium", "high", "critical"}

_DEFAULT_CONFIG: dict[str, Any] = {
    "scan": {
        "policy": "standard",
        "timeout": 10,
        "max_pages": 100,
        "max_depth": 5,
        "workers": 10,
    },
    "checks": {
        "disable": [],
        "enable_only": [],
    },
    "scope": {
        "include": [],
        "exclude": [],
        "exclude_extensions": [".jpg", ".png", ".gif", ".css", ".woff2", ".ico", ".svg"],
    },
    "auth": {
        "type": "none",
        "token": "",
        "username": "",
        "password": "",
        "cookie_name": "",
        "cookie_value": "",
        "header_name": "",
        "header_value": "",
    },
    "wordlists": {
        "forced_browse": "",
        "passwords": "",
        "usernames": "",
    },
    "reporting": {
        "format": ["html", "sarif"],
        "output_dir": "./reports",
        "fail_on": "high",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning new dict."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def validate_config(config: dict) -> list[str]:
    """Validate config dict. Returns list of error strings (empty = valid)."""
    errors: list[str] = []

    scan = config.get("scan", {})
    if scan.get("policy") and scan["policy"] not in _VALID_POLICIES:
        errors.append(f"scan.policy '{scan['policy']}' not in {_VALID_POLICIES}")
    timeout = scan.get("timeout")
    if timeout is not None and (not isinstance(timeout, (int, float)) or timeout < 1 or timeout > 120):
        errors.append(f"scan.timeout must be 1-120, got {timeout}")
    max_pages = scan.get("max_pages")
    if max_pages is not None and (not isinstance(max_pages, int) or max_pages < 0 or max_pages > 10000):
        errors.append(f"scan.max_pages must be 0-10000, got {max_pages}")
    workers = scan.get("workers")
    if workers is not None and (not isinstance(workers, int) or workers < 1 or workers > 50):
        errors.append(f"scan.workers must be 1-50, got {workers}")

    auth = config.get("auth", {})
    auth_type = auth.get("type", "none")
    if auth_type not in _VALID_AUTH_TYPES:
        errors.append(f"auth.type '{auth_type}' not in {_VALID_AUTH_TYPES}")

    reporting = config.get("reporting", {})
    formats = reporting.get("format", [])
    if isinstance(formats, list):
        for fmt in formats:
            if fmt not in _VALID_FORMATS:
                errors.append(f"reporting.format '{fmt}' not in {_VALID_FORMATS}")
    fail_on = reporting.get("fail_on")
    if fail_on and fail_on not in _VALID_FAIL_ON:
        errors.append(f"reporting.fail_on '{fail_on}' not in {_VALID_FAIL_ON}")

    # Warn (not error) on missing wordlist paths
    wordlists = config.get("wordlists", {})
    for wl_key in ("forced_browse", "passwords", "usernames"):
        path = wordlists.get(wl_key, "")
        if path and not os.path.exists(path):
            log.warning("Wordlist path '%s' for %s does not exist", path, wl_key)

    return errors


def load_config(path: str | None = None) -> dict:
    """
    Load YAML config from path, validate, and return merged config dict.
    Returns default config if path is None or file doesn't exist.
    Raises ValueError if config has validation errors.
    """
    if path is None:
        return dict(_DEFAULT_CONFIG)

    if not _HAS_YAML:
        raise ImportError("PyYAML required for config files — pip install pyyaml")

    if not os.path.exists(path):
        log.warning("Config file '%s' not found, using defaults", path)
        return dict(_DEFAULT_CONFIG)

    with open(path) as f:
        user_config = yaml.safe_load(f) or {}

    config = _deep_merge(_DEFAULT_CONFIG, user_config)

    errors = validate_config(config)
    if errors:
        raise ValueError(f"Config validation failed:\n" + "\n".join(f"  - {e}" for e in errors))

    return config
