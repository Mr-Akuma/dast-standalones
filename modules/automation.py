"""
Automation Module — YAML scan configuration and hook execution.

Loads declarative scan plans from YAML, maps to CLI args, runs hooks.

YAML config maps 1:1 to CLI options:
    target: http://example.com
    max_pages: 100
    force_browse: true
    output_sarif: report.sarif
    hooks:
      pre_scan: ./scripts/pre.sh
      post_scan: ./scripts/post.sh
      on_finding: ./scripts/notify.sh

Usage:
    --scan-config scan.yaml   Load scan configuration from YAML file
    --pre-scan-hook CMD       Run CMD before scan starts
    --post-scan-hook CMD      Run CMD after scan completes
    --on-finding-hook CMD     Run CMD for each finding (JSON on stdin)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════════
# YAML CONFIG LOADER
# ═══════════════════════════════════════════════════════════════════════════════

# All valid YAML keys → argparse dest names
# Keys match argparse dest attributes in main.py
_YAML_KEY_MAP = {
    # Core
    "target":              "target",
    "output":              "output",
    "headless":            "headless",

    # Crawl
    "max_pages":           "max_pages",
    "depth":               "depth",
    "max_depth":           "depth",
    "timeout":             "timeout",
    "no_crawl":            "no_crawl",

    # Fuzz
    "no_fuzz":             "no_fuzz",
    "allow_dangerous_endpoints": "allow_dangerous_endpoints",

    # Forced browse
    "force_browse":        "force_browse",
    "wordlist":            "wordlist",
    "wordlist_categories": "wordlist_categories",

    # Token analysis
    "no_token_analysis":   "no_token_analysis",

    # AJAX spider, GraphQL, WebSocket
    "ajax_spider":         "ajax_spider",
    "no_graphql":          "no_graphql",
    "no_websocket":        "no_websocket",
    "pattern_pack":        "pattern_pack",
    "pattern_packs":       "pattern_pack",
    "oast_public_base_url": "oast_public_base_url",
    "oast_host":           "oast_host",

    # OpenAPI
    "openapi":             "openapi",

    # Auth — browser
    "login_url":           "login_url",
    "login_user":          "login_user",
    "login_pass":          "login_pass",
    "user_field":          "user_field",
    "pass_field":          "pass_field",
    "submit_field":        "submit_field",

    # Auth — token
    "token_url":           "token_url",
    "token_field":         "token_field",
    "token_pass_field":    "token_pass_field",
    "token_path":          "token_path",

    # Auth — script
    "auth_script":         "auth_script",

    # Multi-user
    "users_file":          "users_file",
    "users":               "users",

    # Session
    "record_session":      "record_session",
    "replay_session":      "replay_session",

    # Traffic visibility
    "traffic_log":         "traffic_log",

    # Reporting
    "output_sarif":        "output_sarif",
    "policy":              "policy",
    "suppress":            "suppress",
    "generate_suppress":   "generate_suppress",
    "fail_on":             "fail_on",

    # Hooks (handled separately — not CLI args)
    "hooks":               "_hooks",
}


def load_scan_config(config_path: str) -> dict:
    """
    Load a YAML scan configuration file.

    Returns a dict of {argparse_dest: value} ready to merge into args namespace.
    Raises ValueError with clear message on malformed input.
    """
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for --scan-config. Install: pip install pyyaml"
        )

    if not os.path.isfile(config_path):
        raise ValueError(f"Scan config not found: {config_path}")

    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {config_path}: {e}")

    if data is None:
        raise ValueError(f"Empty YAML config: {config_path}")

    if not isinstance(data, dict):
        raise ValueError(
            f"YAML config must be a mapping (got {type(data).__name__}). "
            f"Expected format:\n  target: http://example.com\n  max_pages: 100"
        )

    data = _interpolate_recursive(data)

    config = {}
    hooks = {}
    unknown_keys = []

    for key, value in data.items():
        if key == "hooks" and isinstance(value, dict):
            hooks = value
            continue

        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                flat_key = f"{key}.{sub_key}"
                dest = _NESTED_KEY_MAP.get(flat_key)
                if dest is None:
                    unknown_keys.append(flat_key)
                    continue
                config[dest] = sub_value
            continue

        dest = _YAML_KEY_MAP.get(key)
        if dest is None:
            unknown_keys.append(key)
            continue
        if dest == "_hooks":
            continue

        config[dest] = value

    if unknown_keys:
        print(f"[DAST] ⚠ Unknown YAML config keys (ignored): {', '.join(unknown_keys)}",
              file=sys.stderr)

    return config, hooks


def merge_config_into_args(args, config: dict):
    """
    Merge YAML config values into argparse namespace.
    CLI args take precedence — YAML only fills in defaults.
    """
    for dest, value in config.items():
        current = getattr(args, dest, None)
        # CLI arg takes precedence if it was explicitly set (non-default)
        if current is None or current is False:
            setattr(args, dest, value)


# ═══════════════════════════════════════════════════════════════════════════════
# HOOK EXECUTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# Keys that must NEVER appear in hook data
_CREDENTIAL_KEYS = frozenset({
    "password", "pass", "secret", "token", "api_key", "apikey",
    "authorization", "credential", "login_pass", "cookie",
})


def _sanitize_for_hook(data: dict) -> dict:
    """Remove credential fields from data before passing to hooks."""
    sanitized = {}
    for k, v in data.items():
        if k.lower() in _CREDENTIAL_KEYS:
            continue
        if isinstance(v, dict):
            v = _sanitize_for_hook(v)
        sanitized[k] = v
    return sanitized


def run_hook(
    command: str,
    hook_name: str,
    data: Optional[dict] = None,
    timeout: int = 30,
) -> bool:
    """
    Execute a hook command.

    For on_finding hooks, finding data is passed as JSON on stdin.
    Returns True if hook succeeded, False otherwise.
    """
    if not command:
        return True

    env = {**os.environ, "DAST_HOOK": hook_name}

    stdin_data = None
    if data:
        sanitized = _sanitize_for_hook(data)
        stdin_data = json.dumps(sanitized)
        env["DAST_FINDING_JSON"] = stdin_data

    try:
        kwargs = {
            "shell": True,
            "capture_output": True,
            "timeout": timeout,
            "env": env,
        }
        if stdin_data:
            kwargs["input"] = stdin_data.encode()
        else:
            kwargs["stdin"] = subprocess.DEVNULL

        result = subprocess.run(command, **kwargs)
        if result.returncode != 0:
            stderr = result.stderr.decode()[:200] if result.stderr else ""
            print(f"[DAST] ⚠ Hook '{hook_name}' exited {result.returncode}: {stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"[DAST] ⚠ Hook '{hook_name}' timed out after {timeout}s")
        return False
    except Exception as e:
        print(f"[DAST] ⚠ Hook '{hook_name}' failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# NESTED YAML CONFIG (CLI-first interface)
# ═══════════════════════════════════════════════════════════════════════════════

import re as _re


def _interpolate_env(value: str) -> str:
    """
    Replace ${VAR} and ${VAR:-default} with environment variable values.

    Supports:
        ${HOME}           → value of $HOME (empty string if unset)
        ${AUTH_TOKEN:-x}  → value of $AUTH_TOKEN, or "x" if unset/empty
    """
    if not isinstance(value, str):
        return value

    def _replace(match):
        var_name = match.group(1)
        default = match.group(3)  # group 3 is after :- (may be None)
        env_val = os.environ.get(var_name)
        if env_val is not None and env_val != "":
            return env_val
        if default is not None:
            return default
        return ""

    return _re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}', _replace, value)


def _interpolate_recursive(obj):
    """Apply env interpolation to all string values in a nested structure."""
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, list):
        return [_interpolate_recursive(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _interpolate_recursive(v) for k, v in obj.items()}
    return obj


# Nested YAML key → flat argparse dest
_NESTED_KEY_MAP = {
    # auth.*
    "auth.type":        "auth_type",
    "auth.token":       "auth_token",
    "auth.username":    "login_user",
    "auth.password":    "login_pass",
    "auth.login_url":   "login_url",
    # scan.*
    "scan.depth":       "depth",
    "scan.max_depth":   "depth",
    "scan.max_pages":   "max_pages",
    "scan.openapi":     "openapi",
    "scan.timeout":     "timeout",
    "scan.no_fuzz":     "no_fuzz",
    "scan.allow_dangerous_endpoints": "allow_dangerous_endpoints",
    "scan.no_crawl":    "no_crawl",
    "scan.pattern_pack": "pattern_pack",
    "scan.pattern_packs": "pattern_pack",
    "scan.oast_public_base_url": "oast_public_base_url",
    "scan.oast_host": "oast_host",
    # wordlists.*
    "wordlists.forced_browse": "wordlist",
    "wordlists.wordlist": "wordlist",
    # reporting.*
    "reporting.fail_on": "fail_on",
    "reporting.output_sarif": "output_sarif",
    # thresholds.*
    "thresholds.fail_on": "fail_on",
    "thresholds.warn_on": "warn_on",
}

# Top-level keys passed through directly
_DIRECT_KEYS = {
    "target", "output", "output_sarif", "scope",
}


def load_nested_config(config_path: str) -> dict:
    """
    Load nested YAML config and flatten to argparse-compatible dict.

    Supports nested structure:
        target: https://example.com
        scope:
          - https://example.com/api/
        auth:
          type: bearer
          token: ${AUTH_TOKEN}
        scan:
          depth: 3
          max_pages: 100
        thresholds:
          fail_on: critical
          warn_on: high

    All string values get ${VAR} and ${VAR:-default} interpolation.

    Returns:
        dict of {argparse_dest: value} ready to set on a Namespace.

    Raises:
        ValueError: If config file is missing, empty, or malformed.
        ImportError: If PyYAML is not installed.
    """
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for --config. Install: pip install pyyaml"
        )

    if not os.path.isfile(config_path):
        raise ValueError(f"Config file not found: {config_path}")

    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {config_path}: {e}")

    if data is None:
        raise ValueError(f"Empty YAML config: {config_path}")

    if not isinstance(data, dict):
        raise ValueError(
            f"YAML config must be a mapping (got {type(data).__name__})"
        )

    # Interpolate env vars across the entire tree
    data = _interpolate_recursive(data)

    result = {}

    for key, value in data.items():
        # Direct top-level keys
        if key in _DIRECT_KEYS:
            result[key] = value
            continue

        # Nested sections → flatten
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                flat_key = f"{key}.{sub_key}"
                dest = _NESTED_KEY_MAP.get(flat_key)
                if dest:
                    result[dest] = sub_value
                else:
                    print(f"[DAST] Unknown nested config key (ignored): {flat_key}",
                          file=sys.stderr)
            continue

        # Fall back to the existing flat key map
        dest = _YAML_KEY_MAP.get(key)
        if dest and dest != "_hooks":
            result[dest] = value
        elif key != "hooks":
            print(f"[DAST] Unknown config key (ignored): {key}", file=sys.stderr)

    return result
