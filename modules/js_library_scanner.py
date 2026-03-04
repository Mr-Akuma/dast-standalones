"""
JS Library Vulnerability Scanner — powered by Retire.js database.

Detects known-vulnerable JavaScript library versions in response bodies
by auto-importing the full Retire.js jsrepository.json (64 libraries,
454 vulnerability ranges).

Detection methods (from Retire.js extractors):
  - filecontent: regex patterns matched against response body
  - uri / filename: regex patterns matched against the request URL
  - filecontentreplace: regex + substitution to extract version from minified code
  - hashes: SHA-256 hash matching for known vulnerable minified files

The public entry point is ``scan_js_libraries()`` which returns a list of
finding dicts compatible with the rest of the scanner pipeline.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Dict, List, NamedTuple, Optional, Tuple


class VulnRange(NamedTuple):
    """A vulnerable version range for a JS library."""
    below: Tuple[int, ...]       # Versions below this are vulnerable
    at_or_above: Tuple[int, ...] # Only applies if version >= this (empty = any)
    severity: str                # high / medium / low
    cves: str                    # CVE identifiers
    info: str                    # Brief description


class _ExtractorSet(NamedTuple):
    """Compiled extractors for a single library."""
    filecontent: List[re.Pattern]                      # body regex patterns
    filecontent_replace: List[Tuple[re.Pattern, str]]  # (regex, replacement)
    uri: List[re.Pattern]                              # URL patterns
    filename: List[re.Pattern]                         # filename patterns
    hashes: Dict[str, str]                             # sha256 -> version


# ═══════════════════════════════════════════════════════════════════════════
# Version utilities
# ═══════════════════════════════════════════════════════════════════════════

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:[^.\d]|$)")

def _parse_version(v: str) -> Optional[Tuple[int, ...]]:
    """Parse '3.5.1' -> (3, 5, 1). Returns None on failure."""
    if not v:
        return None
    try:
        m = _VERSION_RE.match(v.strip())
        if m:
            return tuple(int(x) for x in m.group(1).split("."))
        return tuple(int(x) for x in v.strip().split("."))
    except (ValueError, AttributeError):
        return None


def _is_vulnerable(version: Tuple[int, ...], vuln: VulnRange) -> bool:
    """Check if version falls within a vulnerable range."""
    if vuln.at_or_above and version < vuln.at_or_above:
        return False
    return version < vuln.below


# ═══════════════════════════════════════════════════════════════════════════
# Retire.js database loader
# ═══════════════════════════════════════════════════════════════════════════

# The §§version§§ placeholder in Retire.js patterns gets replaced with a
# version-capturing regex group.  We use a simple approach: replace the
# placeholder, compile, then search ALL groups for a version-like string.
_VERSION_CAPTURE = r"(\d+\.\d+(?:\.\d+)*(?:[-+][\w.]*)?)"
_VERSION_LIKE = re.compile(r"^\d+\.\d+(?:\.\d+)*")


def _convert_retirejs_pattern(pattern_str: str) -> Optional[re.Pattern]:
    """Convert a Retire.js pattern with §§version§§ to a compiled regex.

    Returns the compiled regex or None on failure.
    When matched, call _extract_version_group(match) to get the version.
    """
    if "§§version§§" not in pattern_str:
        return None

    py_pattern = pattern_str.replace("§§version§§", _VERSION_CAPTURE)

    try:
        return re.compile(py_pattern, re.I)
    except re.error:
        return None


def _extract_version_group(m: re.Match) -> Optional[str]:
    """Find the version string from any capture group in a match."""
    for i in range(1, m.lastindex + 1 if m.lastindex else 1):
        try:
            val = m.group(i)
            if val and _VERSION_LIKE.match(val):
                return val
        except IndexError:
            continue
    return None


def _convert_retirejs_replace(pattern_str: str, replacement: str) -> Optional[Tuple[re.Pattern, str]]:
    """Convert a filecontentreplace pattern to (regex, replacement_template)."""
    if "§§version§§" not in replacement:
        return None
    py_replacement = replacement.replace("§§version§§", _VERSION_CAPTURE)
    try:
        compiled = re.compile(pattern_str, re.I)
        return (compiled, py_replacement)
    except re.error:
        return None


def _load_retirejs_db() -> Tuple[Dict[str, dict], int, int]:
    """Load jsrepository.json and convert to internal format.

    Returns (db_dict, lib_count, vuln_count).
    """
    db_path = os.path.join(os.path.dirname(__file__), "data", "jsrepository.json")
    if not os.path.isfile(db_path):
        return {}, 0, 0

    with open(db_path, "r") as f:
        raw = json.load(f)

    db: Dict[str, dict] = {}
    total_vulns = 0
    skipped = {"dont check", "retire-example"}

    for lib_key, lib_data in raw.items():
        if lib_key in skipped:
            continue

        extractors = lib_data.get("extractors", {})

        # Build extractor set
        fc_patterns: List[re.Pattern] = []
        fc_replace: List[Tuple[re.Pattern, str]] = []
        uri_patterns: List[re.Pattern] = []
        fn_patterns: List[re.Pattern] = []
        hash_map: Dict[str, str] = {}

        # filecontent — main body patterns
        for pat_str in extractors.get("filecontent", []):
            compiled = _convert_retirejs_pattern(pat_str)
            if compiled:
                fc_patterns.append(compiled)

        # filecontentreplace — JS-style regex with substitution
        # Format: list of strings like "/pattern/replacement/" or dict {pattern: replacement}
        fcr = extractors.get("filecontentreplace", [])
        if isinstance(fcr, list):
            for item in fcr:
                if isinstance(item, str):
                    # Parse JS regex literal: /pattern/replacement/
                    parts = item.split("/")
                    if len(parts) >= 3:
                        pat_str = parts[1] if parts[0] == "" else parts[0]
                        repl_str = parts[-1] if parts[-1] else parts[-2]
                        # For version extraction, just compile the pattern part
                        # and we'll search for version in the match
                        compiled = _convert_retirejs_pattern(pat_str)
                        if compiled:
                            fc_patterns.append(compiled)  # Add as regular filecontent
                elif isinstance(item, dict):
                    for pat_str, repl_str in item.items():
                        result = _convert_retirejs_replace(pat_str, repl_str)
                        if result:
                            fc_replace.append(result)
        elif isinstance(fcr, dict):
            for pat_str, repl_str in fcr.items():
                result = _convert_retirejs_replace(pat_str, repl_str)
                if result:
                    fc_replace.append(result)

        # uri — URL path patterns
        for pat_str in extractors.get("uri", []):
            compiled = _convert_retirejs_pattern(pat_str)
            if compiled:
                uri_patterns.append(compiled)

        # filename — URL filename patterns
        for pat_str in extractors.get("filename", []):
            compiled = _convert_retirejs_pattern(pat_str)
            if compiled:
                fn_patterns.append(compiled)

        # hashes — sha256 -> version
        for sha, version in extractors.get("hashes", {}).items():
            hash_map[sha.lower()] = version

        ext_set = _ExtractorSet(
            filecontent=fc_patterns,
            filecontent_replace=fc_replace,
            uri=uri_patterns,
            filename=fn_patterns,
            hashes=hash_map,
        )

        # Build vulnerability list
        vulns: List[VulnRange] = []
        for v in lib_data.get("vulnerabilities", []):
            below_str = v.get("below", "")
            below = _parse_version(below_str)
            if not below:
                continue

            at_or_above_str = v.get("atOrAbove", "")
            at_or_above = _parse_version(at_or_above_str) if at_or_above_str else ()

            severity = v.get("severity", "medium").lower()

            # Extract CVEs
            identifiers = v.get("identifiers", {})
            cve_list = identifiers.get("CVE", [])
            cve_str = ", ".join(cve_list) if cve_list else identifiers.get("githubID", "")
            summary = identifiers.get("summary", "")

            vulns.append(VulnRange(
                below=below,
                at_or_above=at_or_above,
                severity=severity,
                cves=cve_str,
                info=summary,
            ))

        total_vulns += len(vulns)

        # Use a display name
        display_name = lib_key
        bower = lib_data.get("bowername", [])
        if bower and isinstance(bower, list) and bower[0]:
            display_name = bower[0]

        db[lib_key] = {
            "display_name": display_name,
            "extractors": ext_set,
            "vulns": vulns,
        }

    return db, len(db), total_vulns


# Load at module init
_RETIRE_DB, _LIB_COUNT, _VULN_COUNT = _load_retirejs_db()


# ═══════════════════════════════════════════════════════════════════════════
# Version extraction helpers
# ═══════════════════════════════════════════════════════════════════════════

def _extract_version_from_body(
    body: str,
    ext: _ExtractorSet,
) -> Optional[str]:
    """Try to extract a version string from response body using filecontent patterns."""
    # filecontent patterns (primary)
    for pat in ext.filecontent:
        m = pat.search(body)
        if m:
            ver = _extract_version_group(m)
            if ver:
                return ver

    # filecontentreplace patterns (for minified code)
    for pat, replacement in ext.filecontent_replace:
        m = pat.search(body)
        if m:
            try:
                replaced = pat.sub(replacement, m.group(0))
                vm = re.search(r"(\d+\.\d+(?:\.\d+)*)", replaced)
                if vm:
                    return vm.group(1)
            except (re.error, IndexError):
                continue

    return None


def _extract_version_from_url(
    url: str,
    ext: _ExtractorSet,
) -> Optional[str]:
    """Try to extract a version from the URL using uri/filename patterns."""
    for pat in ext.uri:
        m = pat.search(url)
        if m:
            ver = _extract_version_group(m)
            if ver:
                return ver

    # filename patterns — match against the last path component
    filename = url.rsplit("/", 1)[-1] if "/" in url else url
    for pat in ext.filename:
        m = pat.search(filename)
        if m:
            ver = _extract_version_group(m)
            if ver:
                return ver

    return None


def _check_hash(body: str, ext: _ExtractorSet) -> Optional[str]:
    """Check if the response body SHA-256 matches a known vulnerable version."""
    if not ext.hashes:
        return None
    sha = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest().lower()
    return ext.hashes.get(sha)


# ═══════════════════════════════════════════════════════════════════════════
# Severity normalization
# ═══════════════════════════════════════════════════════════════════════════

_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "none": "Info",
}

_SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

def _normalize_severity(s: str) -> str:
    return _SEVERITY_MAP.get(s.lower(), "Medium")


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def scan_js_libraries(
    url: str,
    body: str,
    headers: dict,
    cookies: dict,
) -> List[dict]:
    """Detect known-vulnerable JavaScript libraries in response body.

    Uses the full Retire.js database for detection (64 libraries, 454 vuln ranges).
    Scans for library version fingerprints via body regex, URL patterns,
    minified code analysis, and SHA-256 hash matching.

    Returns list of finding dicts compatible with PassiveScanner output.
    """
    findings: List[dict] = []

    if not _RETIRE_DB:
        return findings

    # Only scan text/html, javascript, json, xml, text/* responses
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower() if isinstance(v, str) else str(v).lower()
            break
    if ct and not any(t in ct for t in ("html", "javascript", "json", "xml", "text/")):
        return findings

    # Cap body scan at 128KB
    b = body[:131_072] if body else ""
    if not b and not url:
        return findings

    seen_libs: set = set()

    for lib_key, lib_data in _RETIRE_DB.items():
        if lib_key in seen_libs:
            continue

        ext: _ExtractorSet = lib_data["extractors"]
        display_name = lib_data["display_name"]
        version_str: Optional[str] = None

        # Try body patterns first (most common)
        if b:
            version_str = _extract_version_from_body(b, ext)

        # Try URL patterns
        if not version_str and url:
            version_str = _extract_version_from_url(url, ext)

        # Try hash matching
        if not version_str and b:
            version_str = _check_hash(b, ext)

        if not version_str:
            continue

        detected_version = _parse_version(version_str)
        if not detected_version:
            continue

        seen_libs.add(lib_key)

        # Check against all known vulnerable ranges
        worst_severity = "Info"
        all_cves: List[str] = []
        all_descriptions: List[str] = []

        for vuln in lib_data["vulns"]:
            if _is_vulnerable(detected_version, vuln):
                if vuln.cves:
                    all_cves.append(vuln.cves)
                if vuln.info:
                    all_descriptions.append(vuln.info)
                norm_sev = _normalize_severity(vuln.severity)
                if _SEVERITY_RANK.get(norm_sev, 0) > _SEVERITY_RANK.get(worst_severity, 0):
                    worst_severity = norm_sev

        if all_cves:
            cve_str = "; ".join(dict.fromkeys(all_cves))  # dedupe, preserve order
            desc_str = "; ".join(dict.fromkeys(all_descriptions))
            findings.append({
                "url": url,
                "category": "vulnerable_js_library",
                "finding": f"Vulnerable {display_name} {version_str} detected ({cve_str})",
                "severity": worst_severity,
                "evidence": f"Library: {display_name} v{version_str} — {desc_str}",
                "remediation": f"Upgrade {display_name} to the latest version. "
                               f"See https://snyk.io/vuln/ for details.",
                "cwe": "CWE-1104",
            })
        else:
            findings.append({
                "url": url,
                "category": "js_library_detected",
                "finding": f"{display_name} {version_str} detected (version appears current)",
                "severity": "Info",
                "evidence": f"Library: {display_name} v{version_str}",
                "remediation": "Keep JavaScript libraries updated to latest stable versions",
                "cwe": "CWE-1104",
            })

    return findings


def get_db_stats() -> dict:
    """Return database statistics for diagnostics."""
    return {
        "libraries": _LIB_COUNT,
        "vulnerability_ranges": _VULN_COUNT,
        "source": "Retire.js jsrepository.json",
    }


# ═══════════════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    stats = get_db_stats()
    print(f"Database: {stats['libraries']} libraries, {stats['vulnerability_ranges']} vuln ranges")
    print(f"Source: {stats['source']}\n")

    # Test strings use REAL library source code banners (as Retire.js expects)
    test_cases = [
        # (label, url, body, expect_vuln)
        ("jQuery 1.11 banner",  "https://test.com",
         "/*! jQuery v1.11.3 | jquery.org/license */", True),
        ("jQuery 3.7 current",  "https://test.com",
         "/*! jQuery v3.7.1 | jquery.org/license */", False),
        ("jQuery filename URL", "https://test.com/js/jquery-1.12.4.min.js", "", True),
        ("AngularJS banner",    "https://test.com",
         "/**\n * @license AngularJS v1.4.14\n * (c) Google */", True),
        ("Bootstrap banner",    "https://test.com",
         "/*!\n * Bootstrap v3.3.7 (https://getbootstrap.com)\n */", True),
        ("Lodash banner",       "https://test.com",
         "/**\n * @license\n * Lodash v4.17.10 <https://lodash.com/license>", True),
        ("Moment banner",       "https://test.com",
         "//! moment.js\n//! version : 2.29.1", True),
        ("Handlebars assign",   "https://test.com",
         'Handlebars.VERSION = "4.1.0";', True),
        ("DOMPurify assign",    "https://test.com",
         "DOMPurify.version = '2.0.0';", True),
        ("React license",       "https://test.com",
         "/** @license React v16.2.0\n * react.", True),
        ("Axios banner",        "https://test.com",
         "/*! Axios v0.21.0 Copyright (c) */", True),
        ("TinyMCE banner",      "https://test.com",
         "/**\n * TinyMCE version 5.8.0", True),
        ("Vue banner",          "https://test.com",
         "/*!\n * Vue.js v2.4.0\n * (c) 2014-2018 Evan You", True),
        ("Vue version assign",  "https://test.com",
         "Vue.version = '2.4.0';", True),
        ("No match",            "https://test.com",
         "<html><body>Hello</body></html>", False),
    ]

    passed = 0
    total = len(test_cases)
    for label, url, body, expect_vuln in test_cases:
        results = scan_js_libraries(url, body, {"Content-Type": "text/html"}, {})
        has_vuln = any(r["category"] == "vulnerable_js_library" for r in results)
        ok = has_vuln == expect_vuln
        passed += ok
        status = "PASS" if ok else "FAIL"
        detail = ""
        if results:
            detail = f" → {results[0]['finding'][:60]}"
        print(f"  [{status}] {label}: vuln={has_vuln} (expected {expect_vuln}){detail}")

    print(f"\n  {passed}/{total} tests passed")
