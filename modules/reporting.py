"""
Reporting Module — SARIF output, per-rule policy, false-positive suppression, CI exit codes.

SARIF v2.1.0 output for GitHub Code Scanning and GitLab SAST.
Policy engine for per-rule IGNORE/INFO/WARN/FAIL severity overrides.
Suppression file for fingerprint-based false positive filtering.
CI exit codes: 0=pass, 1=fail (High/Critical), 2=warn (Medium).

Usage:
    --output-sarif report.sarif   Export SARIF report
    --policy policy.json          Per-rule severity overrides
    --suppress .dast-suppress.json  False positive suppression
    --generate-suppress           Generate suppression template from findings
    --fail-on medium              CI failure threshold (low/medium/high/critical)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════════════════════
# SEVERITY CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

_SEVERITY_ORDER = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

_SARIF_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

# CWE taxonomy URL
_CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING FINGERPRINT — stable hash for suppression
# ═══════════════════════════════════════════════════════════════════════════════

def finding_fingerprint(finding: dict) -> str:
    """Generate a stable fingerprint for a finding (URL + vuln_type + param)."""
    key = "|".join([
        finding.get("url", ""),
        finding.get("vuln_type", finding.get("category", "")),
        finding.get("param", ""),
        finding.get("finding", "")[:80],
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════════════════════════
# AI FIX SUGGESTION — LLM-powered root-cause remediation
# ═══════════════════════════════════════════════════════════════════════════════

_log = logging.getLogger(__name__)

_FIX_SYSTEM_PROMPT = (
    "You are a senior application security engineer. "
    "When given a security vulnerability finding, provide a concise remediation. "
    "CRITICAL: Address the ROOT CAUSE, not the symptom. "
    "Do NOT suggest: adding null checks to hide the crash, try/except to suppress errors, "
    "or any fix that merely prevents the vulnerability from being reported without actually fixing it. "
    "Provide: (1) root cause in one sentence, (2) fix in 3-5 concrete lines of pseudocode or the actual language if determinable, "
    "(3) one-line verification step."
)

_FIX_PROMPTS: dict[str, str] = {
    "sqli": "SQL injection found at {url} parameter '{param}'. Evidence: {evidence}. Provide root-cause fix.",
    "xss": "XSS found at {url} parameter '{param}'. Evidence: {evidence}. Provide root-cause fix.",
    "cmdi": "OS command injection found at {url} parameter '{param}'. Evidence: {evidence}. Provide root-cause fix.",
    "ssti": "Server-side template injection found at {url}. Evidence: {evidence}. Provide root-cause fix.",
    "lfi": "Path traversal/LFI found at {url} parameter '{param}'. Evidence: {evidence}. Provide root-cause fix.",
    "ssrf": "SSRF found at {url} parameter '{param}'. Evidence: {evidence}. Provide root-cause fix.",
    "xxe": "XXE injection found at {url}. Evidence: {evidence}. Provide root-cause fix.",
    "idor": "IDOR/broken access control found at {url}. Evidence: {evidence}. Provide root-cause fix.",
    "default": "Security vulnerability '{vuln_type}' found at {url}. Finding: {finding}. Provide root-cause fix.",
}


def generate_fix_suggestion(finding: dict, llm_provider) -> str | None:
    """
    Generate an AI-powered fix suggestion for a security finding.

    Uses the LLM provider to produce root-cause remediation advice based on
    the Meta AutoPatchBench framing (fix the root cause, not the symptom).

    Returns the suggestion string, or None if unavailable or on error.
    """
    if llm_provider is None or not llm_provider.is_available:
        return None

    try:
        vuln_type = finding.get("vuln_type", finding.get("category", "unknown"))
        url = finding.get("url", "")
        param = finding.get("param", "")
        evidence = finding.get("evidence", "")[:300]
        finding_text = finding.get("finding", "")

        # Select prompt template — match on lowercase vuln_type
        vt_lower = vuln_type.lower()
        template = _FIX_PROMPTS.get(vt_lower, _FIX_PROMPTS["default"])

        user_msg = template.format(
            vuln_type=vuln_type,
            url=url,
            param=param,
            evidence=evidence,
            finding=finding_text,
        )

        response = llm_provider.chat([
            {"role": "system", "content": _FIX_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ])

        return response
    except Exception:
        _log.debug("Failed to generate fix suggestion for %s", finding.get("url", ""), exc_info=True)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY ENGINE — per-rule severity overrides
# ═══════════════════════════════════════════════════════════════════════════════

class PolicyEngine:
    """
    Loads a policy JSON that maps vuln_type or category to a severity level.

    Policy format:
    {
      "rules": {
        "xss_reflected": "FAIL",
        "missing_csp": "WARN",
        "info_disclosure": "INFO",
        "missing_x_frame": "IGNORE"
      },
      "default": "WARN"
    }

    Levels: IGNORE (remove), INFO, WARN, FAIL
    FAIL = treat as High, WARN = treat as Medium, INFO = treat as Info
    """

    _LEVEL_MAP = {
        "IGNORE": None,
        "INFO": "Info",
        "WARN": "Medium",
        "FAIL": "High",
    }

    def __init__(self, policy_path: Optional[str] = None):
        self.rules: dict[str, str] = {}
        self.default: Optional[str] = None
        if policy_path:
            self._load(policy_path)

    def _load(self, path: str):
        with open(path, "r") as f:
            data = json.load(f)
        self.rules = data.get("rules", {})
        self.default = data.get("default")

    def apply(self, findings: list[dict]) -> list[dict]:
        """Apply policy to findings — filter IGNORE, remap severities."""
        if not self.rules and not self.default:
            return findings

        result = []
        for f in findings:
            vuln_type = f.get("vuln_type", f.get("category", ""))
            level = self.rules.get(vuln_type, self.default)

            if level is None:
                # No policy for this rule — keep original
                result.append(f)
                continue

            level = level.upper()
            if level == "IGNORE":
                continue  # Remove from output

            mapped_severity = self._LEVEL_MAP.get(level)
            if mapped_severity:
                f = {**f, "severity": mapped_severity, "policy_override": level}
            result.append(f)

        return result


# ═══════════════════════════════════════════════════════════════════════════════
# FALSE POSITIVE SUPPRESSION
# ═══════════════════════════════════════════════════════════════════════════════

class SuppressionFile:
    """
    Loads a suppression file to filter out known false positives.

    Suppression format:
    {
      "suppressions": [
        {
          "fingerprint": "a1b2c3d4e5f67890",
          "reason": "Known false positive — WAF test endpoint",
          "vuln_type": "xss_reflected",
          "url": "http://app/test"
        }
      ]
    }
    """

    def __init__(self, suppress_path: Optional[str] = None):
        self.fingerprints: set[str] = set()
        self.entries: list[dict] = []
        if suppress_path:
            self._load(suppress_path)

    def _load(self, path: str):
        with open(path, "r") as f:
            data = json.load(f)
        self.entries = data.get("suppressions", [])
        self.fingerprints = {e["fingerprint"] for e in self.entries if "fingerprint" in e}

    def filter(self, findings: list[dict]) -> tuple[list[dict], int]:
        """
        Remove suppressed findings.
        Returns: (filtered_findings, suppressed_count)
        """
        if not self.fingerprints:
            return findings, 0

        result = []
        suppressed = 0
        for f in findings:
            fp = finding_fingerprint(f)
            if fp in self.fingerprints:
                suppressed += 1
            else:
                result.append(f)
        return result, suppressed

    def mark_false_positive(self, finding: dict, reason: str, suppress_path: str) -> str:
        """
        Mark a finding as false positive and persist to suppression file.
        Appends to existing suppressions or creates new file.
        Returns the fingerprint of the marked finding.
        """
        fp = finding_fingerprint(finding)

        # Load existing file or create new structure
        data = _load_suppression_data(suppress_path)

        # Check for duplicate fingerprint
        existing_fps = {e.get("fingerprint") for e in data.get("suppressions", [])}
        if fp in existing_fps:
            return fp  # Already suppressed, skip duplicate

        entry = {
            "fingerprint": fp,
            "reason": reason,
            "vuln_type": finding.get("vuln_type", finding.get("category", "")),
            "url": finding.get("url", ""),
            "marked_at": datetime.now(timezone.utc).isoformat(),
        }
        data.setdefault("suppressions", []).append(entry)

        _save_suppression_data(data, suppress_path)

        # Update in-memory state
        self.fingerprints.add(fp)
        self.entries.append(entry)

        return fp

    def unmark_false_positive(self, fingerprint: str, suppress_path: str) -> bool:
        """
        Remove a false positive marking by fingerprint.
        Returns True if the fingerprint was found and removed, False otherwise.
        """
        data = _load_suppression_data(suppress_path)

        original_len = len(data.get("suppressions", []))
        data["suppressions"] = [
            e for e in data.get("suppressions", [])
            if e.get("fingerprint") != fingerprint
        ]
        removed = len(data["suppressions"]) < original_len

        if removed:
            _save_suppression_data(data, suppress_path)
            # Update in-memory state
            self.fingerprints.discard(fingerprint)
            self.entries = [e for e in self.entries if e.get("fingerprint") != fingerprint]

        return removed

    @staticmethod
    def generate(findings: list[dict], output_path: str) -> int:
        """Generate a suppression template from current findings."""
        suppressions = []
        for f in findings:
            suppressions.append({
                "fingerprint": finding_fingerprint(f),
                "reason": "",
                "vuln_type": f.get("vuln_type", f.get("category", "")),
                "url": f.get("url", ""),
                "finding": f.get("finding", "")[:100],
            })
        data = {"suppressions": suppressions}
        with open(output_path, "w") as fh:
            json.dump(data, fh, indent=2)
        return len(suppressions)


# ═══════════════════════════════════════════════════════════════════════════════
# SARIF v2.1.0 REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class SarifReport:
    """
    Generates SARIF v2.1.0 JSON for GitHub Code Scanning and GitLab SAST.
    """

    SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    VERSION = "2.1.0"

    def __init__(self, tool_name: str = "DAST-Standalone", tool_version: str = "2.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, findings: list[dict], target: str, llm_provider=None) -> dict:
        """Generate full SARIF document from findings."""
        rules = {}
        results = []

        for i, f in enumerate(findings):
            vuln_type = f.get("vuln_type", f.get("category", "unknown"))
            severity = f.get("severity", "Info").lower()
            cwe = f.get("cwe", "")
            url = f.get("url", target)
            finding_text = f.get("finding", "")
            evidence = f.get("evidence", "")
            remediation = f.get("remediation", "")
            owasp = f.get("category", "")
            param = f.get("param", "")

            # Build rule if not already seen
            rule_id = vuln_type.replace(" ", "_").lower()
            if rule_id not in rules:
                rules[rule_id] = self._build_rule(
                    rule_id, vuln_type, cwe, owasp, severity, remediation
                )

            # Build result
            result = {
                "ruleId": rule_id,
                "ruleIndex": list(rules.keys()).index(rule_id),
                "level": _SARIF_LEVEL.get(severity, "note"),
                "message": {
                    "text": finding_text,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": url,
                                "uriBaseId": "%SRCROOT%",
                            },
                        },
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": url,
                                "kind": "url",
                            }
                        ],
                    }
                ],
                "fingerprints": {
                    "dast/v1": finding_fingerprint(f),
                },
            }

            # Add properties
            props = {}
            if param:
                props["param"] = param
            props["phase"] = f.get("phase", "")
            if f.get("confidence_level"):
                props["confidence"] = f["confidence_level"]
            if f.get("confidence_score") is not None:
                props["confidence_score"] = f["confidence_score"]
            if llm_provider:
                fix = generate_fix_suggestion(f, llm_provider)
                if fix:
                    props["suggested_fix"] = fix
            result["properties"] = props

            # Add evidence as related location
            if evidence:
                result["relatedLocations"] = [
                    {
                        "id": 0,
                        "message": {"text": evidence[:500]},
                        "physicalLocation": {
                            "artifactLocation": {"uri": url},
                        },
                    }
                ]

            # Add CWE taxa reference
            if cwe and cwe.startswith("CWE-"):
                cwe_id = cwe.replace("CWE-", "")
                result["taxa"] = [
                    {
                        "id": cwe_id,
                        "toolComponent": {"name": "CWE", "index": 0},
                    }
                ]

            results.append(result)

        # Build SARIF document
        sarif = {
            "$schema": self.SCHEMA,
            "version": self.VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/dast-standalone",
                            "rules": list(rules.values()),
                        },
                    },
                    "taxonomies": self._build_taxonomies(findings),
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "commandLine": f"dast-standalone --target {target}",
                            "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "properties": {
                        "target": target,
                        "findingsCount": len(findings),
                    },
                }
            ],
        }

        return sarif

    def _build_rule(self, rule_id: str, vuln_type: str, cwe: str,
                    owasp: str, severity: str, remediation: str) -> dict:
        """Build a SARIF rule object."""
        rule = {
            "id": rule_id,
            "name": vuln_type.replace("_", " ").title(),
            "shortDescription": {
                "text": vuln_type.replace("_", " ").title(),
            },
            "fullDescription": {
                "text": f"{vuln_type.replace('_', ' ').title()} vulnerability detected by DAST scanner.",
            },
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(severity, "note"),
            },
            "properties": {
                "tags": [owasp] if owasp else [],
                "precision": "medium",
                "severity": severity,
            },
        }

        if remediation:
            rule["help"] = {
                "text": remediation,
                "markdown": f"**Remediation:** {remediation}",
            }

        if cwe and cwe.startswith("CWE-"):
            cwe_id = cwe.replace("CWE-", "")
            rule["helpUri"] = _CWE_URL.format(cwe_id)
            rule["relationships"] = [
                {
                    "target": {
                        "id": cwe_id,
                        "toolComponent": {"name": "CWE", "index": 0},
                    },
                    "kinds": ["superset"],
                }
            ]

        return rule

    def _build_taxonomies(self, findings: list[dict]) -> list[dict]:
        """Build CWE taxonomy reference."""
        cwe_taxa = []
        seen_cwes = set()

        for f in findings:
            cwe = f.get("cwe", "")
            if cwe and cwe.startswith("CWE-") and cwe not in seen_cwes:
                cwe_id = cwe.replace("CWE-", "")
                cwe_taxa.append({
                    "id": cwe_id,
                    "name": cwe,
                    "shortDescription": {"text": cwe},
                    "helpUri": _CWE_URL.format(cwe_id),
                })
                seen_cwes.add(cwe)

        return [
            {
                "name": "CWE",
                "version": "4.15",
                "organization": "MITRE",
                "shortDescription": {"text": "Common Weakness Enumeration"},
                "downloadUri": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
                "informationUri": "https://cwe.mitre.org",
                "taxa": cwe_taxa,
                "isComprehensive": False,
            }
        ]

    def save(self, findings: list[dict], target: str, path: str) -> int:
        """Generate and save SARIF to file. Returns finding count."""
        sarif = self.generate(findings, target)
        with open(path, "w") as f:
            json.dump(sarif, f, indent=2)
        return len(findings)


# ═══════════════════════════════════════════════════════════════════════════════
# CI EXIT CODE CALCULATOR
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_exit_code(findings: list[dict], fail_on: str = "high") -> int:
    """
    Calculate CI exit code based on findings and threshold.

    fail_on: "low", "medium", "high", "critical"
    Returns: 0 = pass, 1 = fail (findings at or above threshold), 2 = warn (findings below threshold)
    """
    threshold = _SEVERITY_ORDER.get(fail_on.lower(), 3)

    has_above = False
    has_below = False

    for f in findings:
        sev = f.get("severity", "Info").lower()
        sev_level = _SEVERITY_ORDER.get(sev, 0)
        if sev_level >= threshold:
            has_above = True
        elif sev_level >= 2:  # Medium or above but below threshold
            has_below = True

    if has_above:
        return 1  # FAIL
    elif has_below:
        return 2  # WARN
    return 0  # PASS


# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

import html as _html


class HtmlReport:
    """
    Generates a standalone HTML pentest report matching the Aikido professional format:
    - Cover page with dark navy gradient
    - Table of Contents
    - Executive Summary (confidentiality, overview, key findings)
    - Findings: vertical bar chart, master table with PT-N IDs, per-finding detail sections
    - Light background, print-friendly, self-contained — no external dependencies
    """

    _SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#2563eb",
        "low": "#16a34a",
        "info": "#6366f1",
    }

    _SEVERITY_BG = {
        "critical": "#fef2f2",
        "high": "#fff7ed",
        "medium": "#eff6ff",
        "low": "#f0fdf4",
        "info": "#eef2ff",
    }

    _CSS = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #f8fafc; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.65; }
        a { color: #2563eb; text-decoration: none; }
        a:hover { text-decoration: underline; }

        /* Cover page */
        .cover { background: linear-gradient(150deg, #0a1628 0%, #1e3a5f 60%, #0f2d5a 100%); color: #fff; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: flex-start; padding: 6rem 5rem; position: relative; overflow: hidden; page-break-after: always; }
        .cover-arc { position: absolute; right: -120px; top: 50%; transform: translateY(-50%); width: 600px; height: 600px; border-radius: 50%; border: 80px solid rgba(255,255,255,0.05); pointer-events: none; }
        .cover-arc2 { position: absolute; right: -200px; top: 50%; transform: translateY(-50%); width: 800px; height: 800px; border-radius: 50%; border: 40px solid rgba(255,255,255,0.03); pointer-events: none; }
        .cover-tag { display: inline-block; background: rgba(255,255,255,0.15); border: 1px solid rgba(255,255,255,0.3); border-radius: 999px; padding: 0.3rem 1rem; font-size: 0.8rem; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 2rem; }
        .cover h1 { font-size: 3.5rem; font-weight: 700; line-height: 1.15; margin-bottom: 0.75rem; }
        .cover-for { font-size: 1.4rem; color: rgba(255,255,255,0.7); margin-bottom: 2.5rem; }
        .cover-date { display: inline-block; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); border-radius: 999px; padding: 0.4rem 1.2rem; font-size: 0.9rem; color: rgba(255,255,255,0.85); }
        .cover-footer { position: absolute; bottom: 3rem; left: 5rem; font-size: 0.8rem; color: rgba(255,255,255,0.4); }

        /* Page layout */
        .page { max-width: 900px; margin: 0 auto; padding: 3rem 4rem; }
        .section { margin-bottom: 3.5rem; }
        .section-label { font-size: 0.72rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: #64748b; margin-bottom: 0.4rem; }
        h2.section-title { font-size: 1.6rem; font-weight: 700; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.6rem; margin-bottom: 1.5rem; }
        h3.subsection { font-size: 1.15rem; font-weight: 600; color: #1e293b; margin: 1.5rem 0 0.75rem; }
        h4.finding-heading { font-size: 1.05rem; font-weight: 700; color: #0f172a; margin: 2rem 0 0.5rem; }

        /* ToC */
        .toc { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem 2rem; }
        .toc-entry { display: flex; justify-content: space-between; align-items: baseline; padding: 0.45rem 0; border-bottom: 1px dotted #e2e8f0; color: #334155; font-size: 0.95rem; }
        .toc-entry:last-child { border-bottom: none; }
        .toc-entry a { color: #334155; }
        .toc-entry a:hover { color: #2563eb; }
        .toc-num { font-weight: 600; min-width: 2rem; color: #64748b; }
        .toc-dots { flex: 1; border-bottom: 1px dotted #cbd5e1; margin: 0 0.5rem; align-self: flex-end; }

        /* Executive summary */
        .overview-table { width: 100%; border-collapse: collapse; font-size: 0.95rem; margin-top: 0.5rem; }
        .overview-table td { padding: 0.6rem 1rem; border-bottom: 1px solid #f1f5f9; }
        .overview-table td:first-child { font-weight: 600; color: #64748b; width: 160px; }
        .overview-table tr:last-child td { border-bottom: none; }
        .overview-table { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
        .key-findings { margin-top: 0.75rem; }
        .key-finding-item { display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.6rem 0; border-bottom: 1px solid #f1f5f9; }
        .key-finding-item:last-child { border-bottom: none; }

        /* Vertical bar chart */
        .bar-chart-v { display: flex; align-items: flex-end; gap: 1.5rem; height: 220px; padding: 0 1rem 0; border-bottom: 2px solid #e2e8f0; margin-bottom: 0.5rem; }
        .bar-col { display: flex; flex-direction: column; align-items: center; flex: 1; }
        .bar-block { width: 100%; border-radius: 4px 4px 0 0; display: flex; align-items: flex-end; justify-content: center; padding-bottom: 6px; font-size: 0.85rem; font-weight: 700; color: #fff; transition: height 0.3s; min-height: 4px; }
        .bar-axis-label { font-size: 0.72rem; text-transform: uppercase; font-weight: 600; margin-top: 0.5rem; letter-spacing: 0.06em; }
        .bar-chart-area { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem 1.5rem 0.75rem; }

        /* Master findings table */
        .findings-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
        .findings-table th { background: #f8fafc; color: #64748b; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; padding: 0.7rem 1rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        .findings-table td { padding: 0.65rem 1rem; border-bottom: 1px solid #f1f5f9; color: #334155; vertical-align: middle; }
        .findings-table tr:last-child td { border-bottom: none; }
        .findings-table tr:hover td { background: #f8fafc; }
        .pt-id { font-family: monospace; font-size: 0.8rem; color: #64748b; white-space: nowrap; }

        /* Severity pills */
        .pill { display: inline-block; padding: 0.2rem 0.75rem; border-radius: 999px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; border: 1.5px solid; }
        .pill-critical { color: #dc2626; border-color: #dc2626; background: #fef2f2; }
        .pill-high { color: #ea580c; border-color: #ea580c; background: #fff7ed; }
        .pill-medium { color: #2563eb; border-color: #2563eb; background: #eff6ff; }
        .pill-low { color: #16a34a; border-color: #16a34a; background: #f0fdf4; }
        .pill-info { color: #6366f1; border-color: #6366f1; background: #eef2ff; }

        /* Per-finding detail */
        .finding-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem 2rem; margin-bottom: 1.5rem; page-break-inside: avoid; }
        .finding-card-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
        .finding-card-header .pill { flex-shrink: 0; }
        .finding-card-meta { font-size: 0.8rem; color: #94a3b8; margin-bottom: 1.25rem; }
        .field-label { font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #94a3b8; margin-top: 1rem; margin-bottom: 0.35rem; }
        .field-body { font-size: 0.9rem; color: #334155; }
        pre.evidence { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.75rem 1rem; font-size: 0.78rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin-top: 0.35rem; }
        .cwe-link { font-size: 0.85rem; }

        /* Appendix */
        .appendix-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem 2rem; }

        /* Footer */
        .report-footer { text-align: center; font-size: 0.75rem; color: #94a3b8; padding: 2rem 0 3rem; border-top: 1px solid #e2e8f0; margin-top: 3rem; }

        @media print {
            .cover { min-height: unset; padding: 4rem 3rem; }
            .page { padding: 2rem 2.5rem; }
            .finding-card { page-break-inside: avoid; }
            pre.evidence { white-space: pre-wrap; }
        }
    """

    def __init__(self, tool_name: str = "DAST-Standalone", tool_version: str = "2.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, findings: list[dict], target: str, output_path: str) -> int:
        """Generate HTML report file. Returns number of findings written."""
        esc = _html.escape
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        date_display = datetime.now(timezone.utc).strftime("%B %d, %Y")

        sev_order = ("critical", "high", "medium", "low", "info")
        sev_counts: dict[str, int] = {s: 0 for s in sev_order}
        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev if sev in sev_counts else "info"] += 1
        total = len(findings)

        # Sort findings: critical → info, then assign PT-N IDs
        sorted_findings = sorted(
            findings,
            key=lambda f: -_SEVERITY_ORDER.get(f.get("severity", "info").lower(), 0),
        )

        # ── Cover page ────────────────────────────────────────────────────────
        cover_html = (
            f'<div class="cover" id="cover">'
            f'<div class="cover-arc"></div><div class="cover-arc2"></div>'
            f'<span class="cover-tag">Security Assessment</span>'
            f'<h1>Pentest Report</h1>'
            f'<div class="cover-for">For {esc(target)}</div>'
            f'<span class="cover-date">{esc(date_display)}</span>'
            f'<div class="cover-footer">Generated by {esc(self.tool_name)} v{esc(self.tool_version)}</div>'
            f'</div>\n'
        )

        # ── Table of Contents ─────────────────────────────────────────────────
        toc_html = (
            f'<div class="page" id="toc"><div class="section">'
            f'<div class="section-label">Contents</div>'
            f'<h2 class="section-title">Table of Contents</h2>'
            f'<div class="toc">'
            f'<div class="toc-entry"><span class="toc-num">1.</span><a href="#exec-summary">Executive Summary</a><span class="toc-dots"></span></div>'
            f'<div class="toc-entry"><span class="toc-num">2.</span><a href="#findings">Findings</a><span class="toc-dots"></span></div>'
            f'<div class="toc-entry" style="padding-left:2rem"><span class="toc-num">2.1</span><a href="#chart">Severity Distribution</a><span class="toc-dots"></span></div>'
            f'<div class="toc-entry" style="padding-left:2rem"><span class="toc-num">2.2</span><a href="#findings-table">Findings Overview</a><span class="toc-dots"></span></div>'
            f'<div class="toc-entry" style="padding-left:2rem"><span class="toc-num">2.3</span><a href="#findings-detail">Detailed Findings</a><span class="toc-dots"></span></div>'
            f'<div class="toc-entry"><span class="toc-num">A.</span><a href="#appendix">Appendix: Scope &amp; Methodology</a><span class="toc-dots"></span></div>'
            f'</div>'
            f'</div></div>\n'
        )

        # ── Section 1: Executive Summary ──────────────────────────────────────
        key_findings_html = ""
        for i, f in enumerate(sorted_findings[:10]):
            sev = f.get("severity", "info").lower()
            pill_cls = f"pill pill-{sev}"
            title = esc(f.get("vuln_type", f.get("category", "Finding")))
            key_findings_html += (
                f'<div class="key-finding-item">'
                f'<span class="{pill_cls}">{sev}</span>'
                f'<span>{title}</span>'
                f'</div>'
            )

        exec_html = (
            f'<div class="page" id="exec-summary"><div class="section">'
            f'<div class="section-label">Section 1</div>'
            f'<h2 class="section-title">Executive Summary</h2>'

            f'<h3 class="subsection">1.1 Confidentiality</h3>'
            f'<p class="field-body">This report is confidential and intended solely for the '
            f'named recipient. It contains sensitive security findings that should not be '
            f'distributed beyond the security and engineering teams responsible for remediation. '
            f'All findings must be remediated before public disclosure.</p>'

            f'<h3 class="subsection">1.2 Scan Overview</h3>'
            f'<table class="overview-table"><tbody>'
            f'<tr><td>Target</td><td>{esc(target)}</td></tr>'
            f'<tr><td>Scan Date</td><td>{esc(date_display)}</td></tr>'
            f'<tr><td>Scanner</td><td>{esc(self.tool_name)} v{esc(self.tool_version)}</td></tr>'
            f'<tr><td>Scan Type</td><td>Automated DAST (Dynamic Application Security Testing)</td></tr>'
            f'<tr><td>Total Findings</td><td>{total}</td></tr>'
            f'<tr><td>Critical</td><td>{sev_counts["critical"]}</td></tr>'
            f'<tr><td>High</td><td>{sev_counts["high"]}</td></tr>'
            f'<tr><td>Medium</td><td>{sev_counts["medium"]}</td></tr>'
            f'<tr><td>Low</td><td>{sev_counts["low"]}</td></tr>'
            f'</tbody></table>'

            f'<h3 class="subsection">1.3 Key Findings</h3>'
            f'<div class="key-findings">{key_findings_html or "<p class=field-body>No findings identified.</p>"}</div>'

            f'</div></div>\n'
        )

        # ── Section 2.1: Vertical bar chart ──────────────────────────────────
        max_count = max(sev_counts.values(), default=1) or 1
        chart_height = 180
        bar_cols = ""
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts[sev]
            bar_h = max(4, int(count / max_count * chart_height))
            color = self._SEVERITY_COLORS[sev]
            label_text = count if count > 0 else ""
            bar_cols += (
                f'<div class="bar-col">'
                f'<div class="bar-block" style="background:{color};height:{bar_h}px">{label_text}</div>'
                f'<div class="bar-axis-label" style="color:{color}">{sev}</div>'
                f'</div>'
            )

        chart_html = (
            f'<div class="section" id="chart">'
            f'<h3 class="subsection">2.1 Severity Distribution</h3>'
            f'<div class="bar-chart-area">'
            f'<div class="bar-chart-v">{bar_cols}</div>'
            f'</div>'
            f'</div>\n'
        )

        # ── Section 2.2: Master findings table ───────────────────────────────
        table_rows = ""
        for idx, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "info").lower()
            pill_cls = f"pill pill-{sev}"
            title = esc(f.get("vuln_type", f.get("category", "Finding")))
            url_short = esc(f.get("url", "")[:80])
            table_rows += (
                f'<tr>'
                f'<td class="pt-id">PT-{idx}</td>'
                f'<td>{title}</td>'
                f'<td>{url_short}</td>'
                f'<td><span class="{pill_cls}">{sev}</span></td>'
                f'</tr>'
            )

        table_html = (
            f'<div class="section" id="findings-table">'
            f'<h3 class="subsection">2.2 Findings Overview</h3>'
            f'<table class="findings-table">'
            f'<thead><tr>'
            f'<th>ID</th><th>Title</th><th>Location</th><th>Severity</th>'
            f'</tr></thead>'
            f'<tbody>{table_rows if table_rows else "<tr><td colspan=4 style=text-align:center;padding:1.5rem;color:#94a3b8>No findings</td></tr>"}</tbody>'
            f'</table>'
            f'</div>\n'
        )

        # ── Section 2.3: Per-finding detail ───────────────────────────────────
        detail_cards = ""
        for idx, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "info").lower()
            pill_cls = f"pill pill-{sev}"
            title = esc(f.get("vuln_type", f.get("category", "Finding")))
            url = esc(f.get("url", ""))
            method = esc(f.get("method", "GET"))
            param = f.get("param", "")
            description = esc(f.get("finding", f.get("description", "")))
            business_impact = esc(f.get("business_impact", ""))
            evidence = f.get("evidence", "")
            remediation = esc(f.get("remediation", ""))
            cwe = f.get("cwe", "")
            confidence_level = f.get("confidence_level", "")

            location_line = f"{method} {url}" + (f" — param: {esc(param)}" if param else "")

            cwe_html = ""
            if cwe and cwe.startswith("CWE-"):
                cwe_id = cwe.replace("CWE-", "")
                cwe_html = (
                    f'<div class="field-label">CWE Reference</div>'
                    f'<div class="field-body cwe-link"><a href="{_CWE_URL.format(cwe_id)}" target="_blank">{esc(cwe)}</a></div>'
                )

            evidence_html = ""
            if evidence:
                evidence_html = (
                    f'<div class="field-label">Evidence</div>'
                    f'<pre class="evidence">{esc(evidence[:2000])}</pre>'
                )

            remediation_html = ""
            if remediation:
                remediation_html = (
                    f'<div class="field-label">Remediation</div>'
                    f'<div class="field-body">{remediation}</div>'
                )

            impact_html = ""
            if business_impact:
                impact_html = (
                    f'<div class="field-label">Business Impact</div>'
                    f'<div class="field-body">{business_impact}</div>'
                )

            confidence_html = ""
            if confidence_level:
                confidence_html = (
                    f'<div class="field-label">Confidence</div>'
                    f'<div class="field-body">{esc(confidence_level)}</div>'
                )

            # Auto-generate clickjacking PoC as a data-URI link for framing findings
            poc_html = ""
            if f.get("vuln_type", "") == "clickjacking" and url:
                poc_src = generate_clickjacking_poc(f.get("url", ""), title=f"PT-{idx} Clickjacking PoC")
                import base64 as _b64
                poc_b64 = _b64.b64encode(poc_src.encode()).decode()
                poc_html = (
                    f'<div class="field-label">Clickjacking PoC</div>'
                    f'<div class="field-body">'
                    f'<a href="data:text/html;base64,{poc_b64}" target="_blank" '
                    f'style="display:inline-block;padding:0.4rem 1rem;background:#e63946;color:#fff;'
                    f'border-radius:4px;font-size:0.82rem;font-weight:600;text-decoration:none">'
                    f'▶ Open PoC Page</a>'
                    f' <span style="font-size:0.78rem;color:#94a3b8;margin-left:0.5rem">'
                    f'Self-contained PoC — opens in new tab</span>'
                    f'</div>'
                )

            detail_cards += (
                f'<div class="finding-card">'
                f'<h4 class="finding-heading">2.3.{idx} &nbsp; PT-{idx} — {title}</h4>'
                f'<div class="finding-card-header"><span class="{pill_cls}">{sev}</span></div>'
                f'<div class="finding-card-meta">Identified on: {esc(date_display)} &nbsp;|&nbsp; {esc(location_line)}</div>'
                f'<div class="field-label">Description</div>'
                f'<div class="field-body">{description if description else "See evidence below."}</div>'
                f'{impact_html}'
                f'{evidence_html}'
                f'{cwe_html}'
                f'{remediation_html}'
                f'{confidence_html}'
                f'{poc_html}'
                f'</div>'
            )

        detail_html = (
            f'<div class="section" id="findings-detail">'
            f'<h3 class="subsection">2.3 Detailed Findings</h3>'
            f'{detail_cards or "<p class=field-body>No findings to detail.</p>"}'
            f'</div>\n'
        )

        findings_page_html = (
            f'<div class="page" id="findings"><div class="section">'
            f'<div class="section-label">Section 2</div>'
            f'<h2 class="section-title">Findings</h2>'
            f'{chart_html}'
            f'{table_html}'
            f'{detail_html}'
            f'</div></div>\n'
        )

        # ── Appendix ──────────────────────────────────────────────────────────
        appendix_html = (
            f'<div class="page" id="appendix"><div class="section">'
            f'<div class="section-label">Appendix</div>'
            f'<h2 class="section-title">Scope &amp; Methodology</h2>'
            f'<div class="appendix-card">'
            f'<h3 class="subsection">Scope</h3>'
            f'<p class="field-body">The assessment covered the target: <strong>{esc(target)}</strong>. '
            f'All testing was performed using automated dynamic analysis techniques against the '
            f'publicly accessible endpoints discovered during the crawl phase.</p>'
            f'<h3 class="subsection">Methodology</h3>'
            f'<p class="field-body">Testing followed the OWASP API Security Top 10 (2023) and Web '
            f'Application Testing Guide (WSTG). The scanner performed active probing for injection '
            f'flaws, authentication weaknesses, authorization bypasses, information disclosure, '
            f'and configuration issues. All findings were verified with proof-of-concept requests '
            f'before inclusion in this report.</p>'
            f'<h3 class="subsection">Tools Used</h3>'
            f'<p class="field-body">{esc(self.tool_name)} v{esc(self.tool_version)} — automated DAST scanner</p>'
            f'</div>'
            f'</div></div>\n'
        )

        # ── Footer ────────────────────────────────────────────────────────────
        footer_html = (
            f'<div class="page"><div class="report-footer">'
            f'Generated by {esc(self.tool_name)} v{esc(self.tool_version)} &nbsp;|&nbsp; {esc(now)}'
            f'</div></div>\n'
        )

        # ── Assemble full HTML ────────────────────────────────────────────────
        page_html = (
            f'<!DOCTYPE html>\n'
            f'<html lang="en">\n'
            f'<head>\n'
            f'<meta charset="UTF-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            f'<title>Pentest Report &mdash; {esc(target)}</title>\n'
            f'<style>{self._CSS}</style>\n'
            f'</head>\n'
            f'<body>\n'
            f'{cover_html}'
            f'{toc_html}'
            f'{exec_html}'
            f'{findings_page_html}'
            f'{appendix_html}'
            f'{footer_html}'
            f'</body>\n'
            f'</html>'
        )

        with open(output_path, "w") as fh:
            fh.write(page_html)

        return total


# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED FALSE POSITIVE MARKING
# ═══════════════════════════════════════════════════════════════════════════════

def _load_suppression_data(suppress_path: str) -> dict:
    """Load suppression file or return empty structure."""
    if os.path.exists(suppress_path):
        with open(suppress_path, "r") as f:
            return json.load(f)
    return {"suppressions": []}


def _save_suppression_data(data: dict, suppress_path: str) -> None:
    """Write suppression data to file."""
    with open(suppress_path, "w") as f:
        json.dump(data, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# PDF REPORT GENERATOR — pure stdlib, no external dependencies
# ═══════════════════════════════════════════════════════════════════════════════

class PdfReport:
    """
    Generates a basic PDF 1.4 security report using raw PDF spec.
    No external dependencies (reportlab not required).
    """

    def __init__(self, findings: list[dict], target: str,
                 metadata: dict | None = None):
        self.findings = findings
        self.target = target
        self.metadata = metadata or {}

    def generate(self) -> bytes:
        """Generate PDF bytes containing the scan report."""
        scan_date = self.metadata.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

        # Count severities
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        owasp_counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            owasp = f.get("owasp_category", "Uncategorized")
            owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

        # Build text content
        lines = []
        lines.append("DAST Security Scan Report")
        lines.append("=" * 40)
        lines.append(f"Target: {self.target}")
        lines.append(f"Date: {scan_date}")
        lines.append(f"Total Findings: {len(self.findings)}")
        lines.append("")
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 30)
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts[sev]
            if count:
                lines.append(f"  {sev.upper():12s}: {count}")
        lines.append("")

        if owasp_counts:
            lines.append("OWASP CATEGORY BREAKDOWN")
            lines.append("-" * 30)
            for cat, cnt in sorted(owasp_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  {cat}: {cnt}")
            lines.append("")

        lines.append("FINDINGS")
        lines.append("-" * 30)
        for i, f in enumerate(self.findings, 1):
            lines.append(f"[{i}] [{f.get('severity', 'info').upper()}] {f.get('vuln_type', 'unknown')}")
            lines.append(f"    URL: {f.get('url', 'N/A')[:100]}")
            lines.append(f"    Param: {f.get('param', 'N/A')} ({f.get('param_type', 'N/A')})")
            lines.append(f"    Finding: {f.get('finding', 'N/A')[:120]}")
            proof = f.get("proof", "")
            if proof:
                lines.append(f"    Proof: {proof[:120]}")
            lines.append("")

        text = "\n".join(lines)
        return self._text_to_pdf(text)

    @staticmethod
    def _text_to_pdf(text: str) -> bytes:
        """Convert plain text to a valid PDF 1.4 document."""
        # Escape special PDF characters
        def _esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

        text_lines = text.split("\n")
        # Build PDF page streams — ~60 lines per page at 12pt font
        lines_per_page = 58
        pages_text = []
        for i in range(0, len(text_lines), lines_per_page):
            pages_text.append(text_lines[i:i + lines_per_page])

        if not pages_text:
            pages_text = [[""]]

        objects: list[bytes] = []
        offsets: list[int] = []
        pos = 0

        header = b"%PDF-1.4\n"
        pos += len(header)

        # Object 1: Catalog
        offsets.append(pos)
        obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        objects.append(obj1)
        pos += len(obj1)

        # Object 2: Pages
        page_refs = " ".join(f"{3 + i * 2} 0 R" for i in range(len(pages_text)))
        offsets.append(pos)
        obj2 = f"2 0 obj\n<< /Type /Pages /Kids [{page_refs}] /Count {len(pages_text)} >>\nendobj\n".encode()
        objects.append(obj2)
        pos += len(obj2)

        # Object 3: Font
        offsets.append(pos)
        obj3 = b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
        objects.append(obj3)
        pos += len(obj3)

        next_obj = 4

        for page_lines in pages_text:
            # Build stream content
            stream_lines = ["BT", "/F1 9 Tf", "36 756 Td", "12 TL"]
            for line in page_lines:
                clean = _esc(line[:120])  # Truncate long lines
                stream_lines.append(f"({clean}) '")
            stream_lines.append("ET")
            stream_content = "\n".join(stream_lines).encode()

            # Page content stream
            offsets.append(pos)
            content_obj = (
                f"{next_obj} 0 obj\n"
                f"<< /Length {len(stream_content)} >>\n"
                f"stream\n"
            ).encode() + stream_content + b"\nendstream\nendobj\n"
            objects.append(content_obj)
            pos += len(content_obj)
            content_ref = next_obj
            next_obj += 1

            # Page object
            offsets.append(pos)
            page_obj = (
                f"{next_obj} 0 obj\n"
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 612 792] "
                f"/Contents {content_ref} 0 R "
                f"/Resources << /Font << /F1 3 0 R >> >> >>\n"
                f"endobj\n"
            ).encode()
            objects.append(page_obj)
            pos += len(page_obj)
            next_obj += 1

        # Cross-reference table
        xref_pos = pos
        xref = f"xref\n0 {len(offsets) + 1}\n0000000000 65535 f \n"
        for off in offsets:
            xref += f"{off:010d} 00000 n \n"

        trailer = (
            f"trailer\n<< /Size {len(offsets) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        )

        return header + b"".join(objects) + xref.encode() + trailer.encode()


def generate_pdf_report(findings: list[dict], target: str,
                        metadata: dict | None = None) -> bytes:
    """Convenience function to generate a PDF report."""
    return PdfReport(findings, target, metadata).generate()


def generate_clickjacking_poc(target_url: str, title: str = "Clickjacking PoC") -> str:
    """
    Generate a self-contained HTML proof-of-concept page for clickjacking.

    Port of Burp Suite's Clickbandit — creates a framing page that overlays a
    fake UI on top of the target iframe to demonstrate clickjacking exploitability.

    Args:
        target_url: The URL of the page confirmed to be frameable.
        title:      Optional title for the PoC page.

    Returns:
        A self-contained HTML string ready to save as a .html file.
    """
    esc = _html.escape
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Clickjacking PoC — {esc(title)}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: sans-serif; background: #1a1a2e; color: #eee; }}
  #banner {{
    background: #e63946; color: #fff; padding: 0.75rem 1.5rem;
    font-size: 0.9rem; font-weight: 600; letter-spacing: 0.04em;
    display: flex; align-items: center; gap: 1rem;
  }}
  #banner span {{ opacity: 0.8; font-weight: 400; }}
  #wrapper {{
    position: relative; width: 100vw; height: calc(100vh - 42px);
    overflow: hidden;
  }}
  #victim-frame {{
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    border: none; opacity: 0.2;
    pointer-events: none;
  }}
  #decoy-ui {{
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    display: flex; align-items: center; justify-content: center;
    z-index: 10; pointer-events: none;
  }}
  #decoy-btn {{
    background: #2563eb; color: #fff; border: none;
    padding: 1rem 2.5rem; font-size: 1.1rem; font-weight: 700;
    border-radius: 8px; cursor: pointer; pointer-events: all;
    box-shadow: 0 4px 24px rgba(37,99,235,0.4);
    transition: background 0.2s;
  }}
  #decoy-btn:hover {{ background: #1d4ed8; }}
  #info {{
    position: fixed; bottom: 1rem; left: 1rem; right: 1rem;
    background: rgba(0,0,0,0.7); border-radius: 6px;
    padding: 0.6rem 1rem; font-size: 0.78rem; color: #aaa;
    z-index: 20;
  }}
</style>
</head>
<body>
<div id="banner">
  ⚠️ Clickjacking PoC — {esc(title)}
  <span>Target: {esc(target_url)}</span>
  <span>The "Click Here" button is positioned over a sensitive action on the framed page.</span>
</div>
<div id="wrapper">
  <iframe id="victim-frame" src="{esc(target_url)}" sandbox="allow-same-origin allow-forms allow-scripts"></iframe>
  <div id="decoy-ui">
    <button id="decoy-btn" onclick="document.getElementById('result').textContent='Button clicked — underlying action triggered!'">
      🎁 Click Here to Claim Your Prize
    </button>
  </div>
</div>
<div id="info">
  <strong>How this works:</strong> The target page is loaded in a transparent iframe (opacity=0.2 for visibility).
  The attacker's "Click Here" button is overlaid on top. When a victim clicks the button,
  they unknowingly interact with the hidden target page. Increase <code>opacity</code> to 0 in production to make
  the iframe invisible. The <code>pointer-events: none</code> on the iframe is removed in a real attack.
  <span id="result" style="color:#4ade80;margin-left:1rem;font-weight:700"></span>
</div>
<script>
  // In a real attack: set iframe opacity to 0 and enable pointer-events
  // Here we keep it semi-transparent so the PoC is visible for demonstration
  console.log("Clickjacking PoC loaded. Target:", {repr(target_url)!r});
</script>
</body>
</html>"""


class JiraWebhook:
    """
    Creates Jira tickets from DAST findings via webhook or REST API.

    Supports:
    - Jira Cloud REST API (Basic auth with API token)
    - Generic webhook URL (POST JSON payload)
    """

    _PRIORITY_MAP = {
        "critical": "Highest",
        "high":     "High",
        "medium":   "Medium",
        "low":      "Low",
        "info":     "Lowest",
    }

    def __init__(
        self,
        webhook_url: "Optional[str]" = None,
        jira_url: "Optional[str]" = None,
        jira_user: "Optional[str]" = None,
        jira_token: "Optional[str]" = None,
        project_key: str = "SEC",
    ):
        self.webhook_url = webhook_url
        self.jira_url = jira_url.rstrip("/") if jira_url else None
        self.jira_user = jira_user
        self.jira_token = jira_token
        self.project_key = project_key

        if not self.webhook_url and not self.jira_url:
            raise ValueError("Either webhook_url or jira_url must be provided")

        try:
            import requests as _req
            self._requests = _req
        except ImportError:
            raise ImportError(
                "The 'requests' library is required for Jira integration. "
                "Install it with: pip install requests"
            )

    def create_tickets(
        self,
        findings: list[dict],
        target: str,
        max_tickets: int = 50,
    ) -> list[dict]:
        """
        Create Jira tickets for findings.

        Deduplicates by (vuln_type, endpoint) so the same issue on the same
        URL does not generate multiple tickets.  Respects *max_tickets* to
        prevent flooding.

        Returns list of response dicts from Jira/webhook.
        """
        seen: set = set()
        unique_findings = []

        for f in findings:
            vuln_type = f.get("vuln_type", f.get("category", "unknown"))
            url = f.get("url", "")
            dedup_key = f"{vuln_type}|{url}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            unique_findings.append(f)

        results = []
        for f in unique_findings[:max_tickets]:
            payload = self._build_ticket_payload(f, target)
            try:
                if self.jira_url:
                    resp = self._send_jira_api(payload)
                else:
                    resp = self._send_webhook(payload)
                results.append(resp)
            except Exception as exc:
                results.append({"error": str(exc), "finding": f.get("url", "")})

        return results

    def _build_ticket_payload(self, finding: dict, target: str) -> dict:
        """Build Jira issue JSON payload from a finding."""
        severity    = finding.get("severity", "info").lower()
        vuln_type   = finding.get("vuln_type", finding.get("category", "unknown"))
        url         = finding.get("url", target)
        method      = finding.get("method", "GET")
        param       = finding.get("param", "")
        cwe         = finding.get("cwe", "")
        owasp       = finding.get("owasp", "")
        evidence    = finding.get("evidence", finding.get("finding", ""))
        remediation = finding.get("remediation", "")

        priority = self._PRIORITY_MAP.get(severity, "Medium")

        summary = f"[DAST] {vuln_type} on {url}"
        if param:
            summary += f" (param: {param})"
        if len(summary) > 255:
            summary = summary[:252] + "..."

        desc_lines = [
            "h2. Vulnerability Details",
            "",
            f"*Severity:* {severity.capitalize()}",
        ]
        if owasp:
            desc_lines.append(f"*OWASP:* {owasp}")
        if cwe:
            cwe_id = cwe.replace("CWE-", "") if cwe.startswith("CWE-") else cwe
            desc_lines.append(f"*CWE:* [{cwe}|https://cwe.mitre.org/data/definitions/{cwe_id}.html]")
        desc_lines.append(f"*Endpoint:* {method} {url}")
        if param:
            desc_lines.append(f"*Parameter:* {param}")
        if evidence:
            desc_lines += ["", "h2. Evidence", "{code}", evidence[:2000], "{code}"]
        if remediation:
            desc_lines += ["", "h2. Remediation", remediation]
        desc_lines += ["", "----", "_Created by DAST-Standalone Scanner_"]

        return {
            "fields": {
                "project":     {"key": self.project_key},
                "issuetype":   {"name": "Bug"},
                "priority":    {"name": priority},
                "summary":     summary,
                "description": "\n".join(desc_lines),
                "labels":      ["dast", "security", "automated"],
            }
        }

    def _send_webhook(self, payload: dict) -> dict:
        """POST payload to generic webhook URL."""
        resp = self._requests.post(
            self.webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"status": resp.status_code, "text": resp.text[:500]}

    def _send_jira_api(self, payload: dict) -> dict:
        """POST to Jira Cloud REST API with Basic auth."""
        import base64
        credentials = base64.b64encode(
            f"{self.jira_user}:{self.jira_token}".encode()
        ).decode()
        url = f"{self.jira_url}/rest/api/2/issue"
        resp = self._requests.post(
            url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {credentials}",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()


class DefectDojoExporter:
    """
    Push DAST findings to DefectDojo via its REST API v2.

    Uses the Generic Findings Import endpoint so no scan-type mapping is
    needed.  Each finding becomes a DefectDojo Finding with severity,
    title, description, and CWE mapped from the DAST finding dict.

    Usage:
        exporter = DefectDojoExporter(
            host="https://defectdojo.example.com",
            api_key="abc123...",
            engagement_id=12,
        )
        result = exporter.push(findings, target="https://app.example.com")
    """

    _SEVERITY_MAP = {
        "critical": "Critical",
        "high":     "High",
        "medium":   "Medium",
        "low":      "Low",
        "info":     "Info",
        "informational": "Info",
    }

    def __init__(
        self,
        host: str,
        api_key: str,
        engagement_id: int,
        verified: bool = False,
        active: bool = True,
        close_old_findings: bool = False,
    ):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.engagement_id = engagement_id
        self.verified = verified
        self.active = active
        self.close_old_findings = close_old_findings

        try:
            import requests as _req
            self._requests = _req
        except ImportError:
            raise ImportError("'requests' library required — pip install requests")

    def push(self, findings: list[dict], target: str = "") -> dict:
        """
        Convert findings to DefectDojo Generic Findings format and import.

        Returns the DefectDojo API response dict.
        """
        dd_findings = [self._to_dd_finding(f) for f in findings]
        payload = json.dumps({"findings": dd_findings}).encode()

        resp = self._requests.post(
            f"{self.host}/api/v2/import-scan/",
            headers={"Authorization": f"Token {self.api_key}"},
            data={
                "engagement":         self.engagement_id,
                "scan_type":          "Generic Findings Import",
                "active":             str(self.active).lower(),
                "verified":           str(self.verified).lower(),
                "close_old_findings": str(self.close_old_findings).lower(),
                "scan_date":          datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "version":            target or "unknown",
            },
            files={"file": ("findings.json", payload, "application/json")},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    def _to_dd_finding(self, f: dict) -> dict:
        severity = self._SEVERITY_MAP.get(
            f.get("severity", "info").lower(), "Info"
        )
        vuln_type = f.get("vuln_type", f.get("category", "Unknown"))
        url = f.get("url", "")
        param = f.get("param", "")
        evidence = f.get("evidence", f.get("finding", f.get("proof", "")))
        cwe_raw = f.get("cwe", "")
        cwe_id = None
        if cwe_raw:
            m = __import__("re").search(r"\d+", cwe_raw)
            if m:
                cwe_id = int(m.group())

        title = f"[DAST] {vuln_type}"
        if url:
            title += f" — {url}"
        if param:
            title += f" [{param}]"

        dd: dict = {
            "title":       title[:500],
            "severity":    severity,
            "description": evidence[:4000] if evidence else vuln_type,
            "url":         url,
            "active":      self.active,
            "verified":    self.verified,
        }
        if cwe_id:
            dd["cwe"] = cwe_id
        remediation = f.get("remediation", "")
        if remediation:
            dd["mitigation"] = remediation[:2000]
        return dd


class SlackNotifier:
    """
    Post a DAST scan summary to a Slack channel via Incoming Webhook.

    Sends a rich Block Kit message with:
    - Scan target + timestamp header
    - Severity breakdown (Critical / High / Medium / Low / Info counts)
    - Top N critical/high findings as individual sections
    - Link to full report if report_url is provided

    Usage:
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/services/...")
        notifier.notify(findings, target="https://app.example.com", report_url="...")
    """

    _SEVERITY_EMOJI = {
        "critical": ":red_circle:",
        "high":     ":large_orange_circle:",
        "medium":   ":large_yellow_circle:",
        "low":      ":large_blue_circle:",
        "info":     ":white_circle:",
    }

    def __init__(self, webhook_url: str, max_findings_shown: int = 5):
        self.webhook_url = webhook_url
        self.max_findings_shown = max_findings_shown
        try:
            import requests as _req
            self._requests = _req
        except ImportError:
            raise ImportError("'requests' library required — pip install requests")

    def notify(
        self,
        findings: list[dict],
        target: str = "",
        report_url: str = "",
    ) -> dict:
        """Build Block Kit payload and POST to Slack webhook."""
        blocks = self._build_blocks(findings, target, report_url)
        resp = self._requests.post(
            self.webhook_url,
            json={"blocks": blocks},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        return {"status": resp.status_code, "text": resp.text}

    def _build_blocks(
        self, findings: list[dict], target: str, report_url: str
    ) -> list[dict]:
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        header_text = f":shield: *DAST Scan Complete* — `{target}`" if target else ":shield: *DAST Scan Complete*"

        blocks: list[dict] = [
            {"type": "header", "text": {"type": "plain_text", "text": "DAST Scan Results", "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"{header_text}\n_{timestamp}_"}},
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f":red_circle: *Critical:* {counts['critical']}"},
                    {"type": "mrkdwn", "text": f":large_orange_circle: *High:* {counts['high']}"},
                    {"type": "mrkdwn", "text": f":large_yellow_circle: *Medium:* {counts['medium']}"},
                    {"type": "mrkdwn", "text": f":large_blue_circle: *Low:* {counts['low']}"},
                ],
            },
        ]

        priority = [f for f in findings if f.get("severity", "").lower() in ("critical", "high")]
        if priority:
            blocks.append({"type": "divider"})
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Top findings:*"}})
            for f in priority[: self.max_findings_shown]:
                sev = f.get("severity", "info").lower()
                emoji = self._SEVERITY_EMOJI.get(sev, ":white_circle:")
                vuln = f.get("vuln_type", f.get("category", "unknown"))
                url = f.get("url", "")
                param = f.get("param", "")
                line = f"{emoji} *{vuln}*"
                if url:
                    line += f"\n`{url}`"
                if param:
                    line += f"  param: `{param}`"
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": line}})

        if report_url:
            blocks += [
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"<{report_url}|View full report>"},
                },
            ]

        return blocks
