"""
Vulnerability Chaining Engine — annotates ScanFindings with chain_id/chain_desc.

After the scanner collects all findings, VulnChainer.analyze_and_annotate() runs a
rule-based graph traversal to detect multi-step attack chains (e.g. SSRF → Cloud
Metadata → IAM Exfiltration) and stamps every contributing finding with the chain ID
and a human-readable chain title.

15 chain rules covering OWASP Top 10:2025 attack paths.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import ScanFinding


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackChain:
    chain_id:     str
    title:        str           # "SSRF → AWS IAM → Data Exfiltration"
    severity:     str           # escalated severity for the chain
    steps:        list[dict]    # [{finding_id, step_no, role, description}]
    narrative:    str           # human-readable attack story
    owasp_mapping: str
    impact:       str
    finding_ids:  list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "chain_id":     self.chain_id,
            "title":        self.title,
            "severity":     self.severity,
            "steps":        self.steps,
            "narrative":    self.narrative,
            "owasp_mapping": self.owasp_mapping,
            "impact":       self.impact,
            "finding_ids":  self.finding_ids,
        }


# ══════════════════════════════════════════════════════════════════════════════
# CHAIN RULES
# ══════════════════════════════════════════════════════════════════════════════
# Each rule:
#   trigger          — list of vuln_type values that fire the rule
#   requires_evidence— (optional) strings that must appear in finding.proof
#   companion        — (optional) additional vuln_type that strengthens the chain
#   chain_title      — human-readable chain name
#   chain_severity   — severity assigned to the chain (usually escalated)
#   narrative        — attack story
#   owasp_mapping    — primary OWASP category
#   impact           — real-world consequence
# ══════════════════════════════════════════════════════════════════════════════

CHAIN_RULES: list[dict] = [
    # ── Rule 1: SSRF → Cloud Metadata → IAM Exfiltration ─────────────────────
    {
        "id": "CR-001",
        "trigger": ["ssrf"],
        "requires_evidence": ["ami-id", "instance-id", "computeMetadata", "iam/security"],
        "chain_title": "SSRF → Cloud Metadata → IAM Credential Exfiltration",
        "chain_severity": "critical",
        "narrative": (
            "SSRF allows the attacker to reach the internal cloud metadata service "
            "(169.254.169.254 / metadata.google.internal). From there, IAM credentials "
            "or instance identity tokens can be retrieved, leading to full cloud account compromise."
        ),
        "owasp_mapping": "A10:2025 Server-Side Request Forgery",
        "impact": "AWS/GCP IAM credentials exposed — full cloud account compromise possible",
    },

    # ── Rule 2: LFI → /etc/passwd Read → Credential Mapping ──────────────────
    {
        "id": "CR-002",
        "trigger": ["lfi"],
        "requires_evidence": ["root:x:0:0:", "root:*:0:0:", "daemon:x:"],
        "chain_title": "LFI → /etc/passwd Read → System User Enumeration",
        "chain_severity": "critical",
        "narrative": (
            "Local File Inclusion confirmed /etc/passwd is readable. An attacker can enumerate "
            "all system users and target accounts for brute-force against SSH, FTP, or other services."
        ),
        "owasp_mapping": "A01:2025 Broken Access Control",
        "impact": "System user enumeration enables targeted brute-force against SSH/services",
    },

    # ── Rule 3: CMDi → Root Shell → Full System Compromise ───────────────────
    {
        "id": "CR-003",
        "trigger": ["cmdi"],
        "requires_evidence": ["uid=0(root)", "uid=0"],
        "chain_title": "Command Injection as Root → Full System Compromise",
        "chain_severity": "critical",
        "narrative": (
            "Command injection confirmed with root-level execution. The attacker has full control "
            "over the operating system — data exfiltration, persistence, lateral movement all possible."
        ),
        "owasp_mapping": "A03:2025 Injection",
        "impact": "Command injection running as root — complete server compromise",
    },

    # ── Rule 4: SSTI → Remote Code Execution ─────────────────────────────────
    {
        "id": "CR-004",
        "trigger": ["ssti"],
        "requires_evidence": ["49", "7777777", "<class '", "Traceback"],
        "chain_title": "SSTI → Remote Code Execution",
        "chain_severity": "critical",
        "narrative": (
            "Template injection allows arbitrary Python/Java/Ruby execution on the server. "
            "Payloads like {{7*7}}=49 or {{lipsum.__globals__.os.popen('id').read()}} confirm "
            "code evaluation, enabling full RCE."
        ),
        "owasp_mapping": "A03:2025 Injection",
        "impact": "Template injection evaluated server-side — arbitrary code execution",
    },

    # ── Rule 5: XSS + Missing HttpOnly → Session Hijacking ───────────────────
    {
        "id": "CR-005",
        "trigger": ["xss_reflected"],
        "companion": ["missing_httponly"],
        "chain_title": "XSS + Missing HttpOnly Cookie → Session Hijacking",
        "chain_severity": "high",
        "narrative": (
            "Reflected XSS combined with session cookies lacking the HttpOnly flag allows an "
            "attacker to execute document.cookie in the victim's browser context and exfiltrate "
            "the session token to an attacker-controlled server."
        ),
        "owasp_mapping": "A03:2025 Injection / A07:2025 Identification and Authentication Failures",
        "impact": "XSS can steal session cookies — complete account takeover",
    },

    # ── Rule 6: CORS Misconfiguration + Auth Endpoints → Account Takeover ────
    {
        "id": "CR-006",
        "trigger": ["cors_critical"],
        "chain_title": "CORS Misconfiguration → Cross-Origin Account Takeover",
        "chain_severity": "critical",
        "narrative": (
            "CORS is configured to reflect arbitrary origins with Access-Control-Allow-Credentials: true. "
            "An attacker can host a page that makes credentialed cross-origin requests to the API, "
            "reading authenticated responses including tokens and user data."
        ),
        "owasp_mapping": "A05:2025 Security Misconfiguration",
        "impact": "Arbitrary origin CORS + credentials = cross-origin session reads",
    },

    # ── Rule 7: Open Redirect + OAuth → Authorization Code Theft ─────────────
    {
        "id": "CR-007",
        "trigger": ["open_redirect"],
        "chain_title": "Open Redirect → OAuth Authorization Code Theft",
        "chain_severity": "high",
        "narrative": (
            "Open redirect in the application can be used as a crafted redirect_uri in OAuth flows. "
            "When a victim follows an authorization link, the authorization code is leaked to the "
            "attacker's server via the open redirect."
        ),
        "owasp_mapping": "A01:2025 Broken Access Control",
        "impact": "Open redirect weaponizes OAuth flows — authorization code theft possible",
    },

    # ── Rule 8: SQL Injection → Full Database Exfiltration ───────────────────
    {
        "id": "CR-008",
        "trigger": ["sqli_error", "sqli_blind_time"],
        "chain_title": "SQL Injection → Full Database Exfiltration",
        "chain_severity": "critical",
        "narrative": (
            "Confirmed SQL injection (error-based or time-based blind) allows the attacker to "
            "enumerate tables via UNION SELECT or information_schema queries, then extract all "
            "data including credentials, PII, and secrets."
        ),
        "owasp_mapping": "A03:2025 Injection",
        "impact": "SQL injection confirmed — full database dump, credential extraction possible",
    },

    # ── Rule 9: XXE → SSRF → Internal Network ────────────────────────────────
    {
        "id": "CR-009",
        "trigger": ["xxe"],
        "chain_title": "XXE → Internal SSRF → Internal Network Pivot",
        "chain_severity": "critical",
        "narrative": (
            "XXE allows external entity inclusion which can be weaponized as SSRF — the XML parser "
            "makes server-side HTTP requests to internal URLs, enabling enumeration of internal "
            "services, cloud metadata access, and potential data exfiltration."
        ),
        "owasp_mapping": "A03:2025 Injection",
        "impact": "XXE enables SSRF — internal network scanning, metadata access",
    },

    # ── Rule 10: JWT alg=none → Authentication Bypass ────────────────────────
    {
        "id": "CR-010",
        "trigger": ["jwt_alg_none", "jwt_weak_secret", "jwt_kid_injection"],
        "chain_title": "JWT Vulnerability → Authentication Bypass → Privilege Escalation",
        "chain_severity": "critical",
        "narrative": (
            "JWT vulnerability (alg=none bypass, weak HMAC secret, or kid injection) allows "
            "forging valid tokens with arbitrary claims including elevated roles. An attacker "
            "can impersonate any user including administrators."
        ),
        "owasp_mapping": "A07:2025 Identification and Authentication Failures",
        "impact": "JWT forging enables authentication bypass and privilege escalation",
    },

    # ── Rule 11: Prototype Pollution → Code Execution ────────────────────────
    {
        "id": "CR-011",
        "trigger": ["prototype_pollution"],
        "chain_title": "Prototype Pollution → Client/Server-Side Code Execution",
        "chain_severity": "high",
        "narrative": (
            "Prototype pollution allows injecting properties onto Object.prototype. In Node.js "
            "applications this can escalate to RCE via gadget chains. In browsers it enables DOM XSS "
            "by poisoning properties used in sinks like innerHTML or eval."
        ),
        "owasp_mapping": "A03:2025 Injection",
        "impact": "Prototype pollution — Node.js RCE gadget chains or browser DOM XSS",
    },

    # ── Rule 12: Missing HSTS + HTTP → SSL Strip ─────────────────────────────
    {
        "id": "CR-012",
        "trigger": ["missing_hsts"],
        "chain_title": "Missing HSTS → SSL Strip Attack → Credential Interception",
        "chain_severity": "high",
        "narrative": (
            "Without HSTS, a network-level attacker (coffee shop WiFi, BGP hijack) can perform "
            "an SSL strip attack — downgrading HTTPS to HTTP transparently. All credentials and "
            "session tokens transmitted in plain text are intercepted."
        ),
        "owasp_mapping": "A02:2025 Cryptographic Failures",
        "impact": "SSL stripping enables plaintext credential/session interception on the network",
    },

    # ── Rule 13: Default Credentials → Admin Access → Compromise ─────────────
    {
        "id": "CR-013",
        "trigger": ["default_creds"],
        "chain_title": "Default Credentials → Admin Panel Access → Full Compromise",
        "chain_severity": "critical",
        "narrative": (
            "Default credentials (admin/admin, admin/password, etc.) grant access to admin panels "
            "or privileged API endpoints. From administrative access, an attacker can typically "
            "achieve RCE via file upload, config change, or template injection."
        ),
        "owasp_mapping": "A07:2025 Identification and Authentication Failures",
        "impact": "Admin access via default credentials — full application/server compromise",
    },

    # ── Rule 14: LFI + Log File → Log Poisoning → RCE ────────────────────────
    {
        "id": "CR-014",
        "trigger": ["lfi"],
        "requires_evidence": ["/var/log", "access.log", "auth.log", "error.log"],
        "chain_title": "LFI + Log Poisoning → Remote Code Execution",
        "chain_severity": "critical",
        "narrative": (
            "LFI can read web server log files. If the attacker injects PHP/ASP code into the "
            "User-Agent header, that code gets written to access.log. When LFI reads the log, "
            "the injected code executes — classic log poisoning RCE."
        ),
        "owasp_mapping": "A01:2025 Broken Access Control",
        "impact": "LFI + log write access = log poisoning for Remote Code Execution",
    },

    # ── Rule 15: No Rate Limiting + Auth Endpoint → Brute Force ──────────────
    {
        "id": "CR-015",
        "trigger": ["missing_rate_limit"],
        "chain_title": "No Rate Limiting on Auth Endpoint → Credential Brute Force",
        "chain_severity": "high",
        "narrative": (
            "Authentication endpoints (login, password reset, OTP verification) accept unlimited "
            "requests without throttling or lockout. An attacker can perform automated brute-force "
            "or credential stuffing attacks without any friction."
        ),
        "owasp_mapping": "A07:2025 Identification and Authentication Failures",
        "impact": "Unlimited auth attempts enable brute-force and credential stuffing attacks",
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# CHAINER
# ══════════════════════════════════════════════════════════════════════════════

class VulnChainer:
    """
    Analyzes a list of ScanFindings and annotates them with chain_id / chain_desc
    where multi-step attack chains are detected.

    Call analyze_and_annotate() after the scanner completes all checks.
    Mutates findings in-place (sets chain_id, chain_desc) and returns
    the list of detected AttackChains.
    """

    def analyze_and_annotate(self, findings: list) -> list[AttackChain]:
        """
        Run all chain rules against the findings list.
        Stamps each matching finding with chain_id and chain_desc.
        Returns list of AttackChain objects.
        """
        chains: list[AttackChain] = []

        # Build fast lookup structures
        by_vuln_type: dict[str, list] = {}
        for f in findings:
            vt = getattr(f, "vuln_type", "") or ""
            by_vuln_type.setdefault(vt, []).append(f)

        for rule in CHAIN_RULES:
            chain = self._evaluate_rule(rule, findings, by_vuln_type)
            if chain:
                chains.append(chain)

        return chains

    def _evaluate_rule(
        self,
        rule: dict,
        all_findings: list,
        by_type: dict[str, list],
    ) -> AttackChain | None:
        """Evaluate one chain rule. Returns AttackChain if triggered, else None."""

        # Step 1: Collect trigger findings
        trigger_findings: list = []
        for trigger_type in rule["trigger"]:
            trigger_findings.extend(by_type.get(trigger_type, []))

        if not trigger_findings:
            return None

        # Step 2: Filter by required evidence strings
        if "requires_evidence" in rule:
            evidence_strings = rule["requires_evidence"]
            trigger_findings = [
                f for f in trigger_findings
                if any(ev in (getattr(f, "proof", "") or "") for ev in evidence_strings)
            ]
            if not trigger_findings:
                return None

        # Step 3: Optional companion check (strengthens but doesn't gate)
        companion_findings: list = []
        if "companion" in rule:
            for comp_type in rule["companion"]:
                companion_findings.extend(by_type.get(comp_type, []))
            # Companion required for this rule to fire
            if rule.get("companion_required", False) and not companion_findings:
                return None

        # Step 4: Build chain
        chain_id = f"chain_{uuid.uuid4().hex[:8]}"
        all_chain_findings = trigger_findings + companion_findings

        # Annotate findings in-place
        for f in all_chain_findings:
            if not getattr(f, "chain_id", None):
                f.chain_id = chain_id
                f.chain_desc = rule["chain_title"]

        # Build steps list
        steps = []
        for i, f in enumerate(trigger_findings, start=1):
            steps.append({
                "step_no":     i,
                "finding_id":  getattr(f, "id", ""),
                "role":        "trigger",
                "vuln_type":   getattr(f, "vuln_type", ""),
                "url":         getattr(f, "url", ""),
                "description": getattr(f, "finding", ""),
            })
        for i, f in enumerate(companion_findings, start=len(trigger_findings) + 1):
            steps.append({
                "step_no":     i,
                "finding_id":  getattr(f, "id", ""),
                "role":        "companion",
                "vuln_type":   getattr(f, "vuln_type", ""),
                "url":         getattr(f, "url", ""),
                "description": getattr(f, "finding", ""),
            })

        return AttackChain(
            chain_id      = chain_id,
            title         = rule["chain_title"],
            severity      = rule["chain_severity"],
            steps         = steps,
            narrative     = rule.get("narrative", ""),
            owasp_mapping = rule.get("owasp_mapping", ""),
            impact        = rule.get("impact", ""),
            finding_ids   = [getattr(f, "id", "") for f in all_chain_findings],
        )

    def summarize(self, chains: list[AttackChain]) -> dict:
        """Return a summary dict of all chains for reporting."""
        return {
            "total_chains": len(chains),
            "critical":     sum(1 for c in chains if c.severity == "critical"),
            "high":         sum(1 for c in chains if c.severity == "high"),
            "chains":       [c.to_dict() for c in chains],
        }
