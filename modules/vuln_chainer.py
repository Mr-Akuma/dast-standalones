"""
Vulnerability Chaining Engine — annotates ScanFindings with chain_id/chain_desc.

After the scanner collects all findings, VulnChainer.analyze_and_annotate() runs:
  1. Rule-based matching   — 18 CHAIN_RULES covering OWASP Top 10:2025
  2. BFS graph traversal   — builds a finding graph and walks edges up to 3 hops
  3. LLM reasoning layer   — optional; enriches each chain with AI reachability analysis

Call: VulnChainer().analyze_and_annotate(findings, llm_call=_llm_call)
"""
from __future__ import annotations

import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    pass


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackChain:
    chain_id:      str
    title:         str           # "SSRF → AWS IAM → Data Exfiltration"
    severity:      str           # escalated severity for the chain
    steps:         list[dict]    # [{finding_id, step_no, role, description}]
    narrative:     str           # human-readable attack story
    owasp_mapping: str
    impact:        str
    finding_ids:   list[str]     = field(default_factory=list)
    hop_depth:     int           = 1     # number of distinct hops in this chain
    llm_reasoning: str           = ""   # AI-generated reachability analysis

    def to_dict(self) -> dict:
        return {
            "chain_id":      self.chain_id,
            "title":         self.title,
            "severity":      self.severity,
            "steps":         self.steps,
            "narrative":     self.narrative,
            "owasp_mapping": self.owasp_mapping,
            "impact":        self.impact,
            "finding_ids":   self.finding_ids,
            "hop_depth":     self.hop_depth,
            "llm_reasoning": self.llm_reasoning,
        }


# ══════════════════════════════════════════════════════════════════════════════
# BFS EDGE MAP
# Each entry: vuln_type → list of vuln_types reachable in the NEXT hop.
# Used by _bfs_traverse() to walk the finding graph up to MAX_HOP_DEPTH.
# ══════════════════════════════════════════════════════════════════════════════

MAX_HOP_DEPTH = 3

CHAIN_TYPE_EDGES: dict[str, list[str]] = {
    # SSRF pivots
    "ssrf":             ["lfi", "idor", "xxe", "cors_critical"],
    # LFI pivots
    "lfi":              ["sqli_error", "sqli_blind_time", "auth_bypass", "cmdi"],
    # SQLi pivots
    "sqli_error":       ["idor", "auth_bypass", "missing_rate_limit"],
    "sqli_blind_time":  ["idor", "auth_bypass", "missing_rate_limit"],
    # XSS pivots
    "xss_stored":       ["idor", "csrf", "missing_httponly"],
    "xss_reflected":    ["open_redirect", "missing_httponly"],
    # Open redirect pivots
    "open_redirect":    ["xss_reflected", "xss_stored"],
    # XXE pivots
    "xxe":              ["ssrf", "lfi"],
    # CMDi pivots
    "cmdi":             ["lfi", "sqli_error"],
    # JWT pivots
    "jwt_alg_none":     ["idor", "auth_bypass"],
    "jwt_weak_secret":  ["idor", "auth_bypass"],
    "jwt_kid_injection":["idor", "auth_bypass"],
    # CORS pivots
    "cors_critical":    ["idor", "auth_bypass"],
    # Auth bypass pivots
    "auth_bypass":      ["idor", "sqli_error"],
    # Prototype pollution pivots
    "prototype_pollution": ["xss_reflected", "xss_stored", "cmdi"],
}


# ══════════════════════════════════════════════════════════════════════════════
# CHAIN RULES
# ══════════════════════════════════════════════════════════════════════════════

CHAIN_RULES: list[dict] = [
    # ── Rule 1: SSRF → Cloud Metadata → IAM Exfiltration ─────────────────────
    {
        "id": "CR-001",
        "trigger": ["ssrf"],
        "requires_evidence": ["ami-id", "instance-id", "computeMetadata", "iam/security",
                               "169.254.169.254", "metadata.google.internal"],
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

    # ── Rule 2: LFI → /etc/passwd Read → System User Enumeration ─────────────
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

    # ── Rule 5: Reflected XSS + Missing HttpOnly → Session Hijacking ─────────
    {
        "id": "CR-005",
        "trigger": ["xss_reflected"],
        "companion": ["missing_httponly"],
        "chain_title": "Reflected XSS + Missing HttpOnly Cookie → Session Hijacking",
        "chain_severity": "high",
        "narrative": (
            "Reflected XSS combined with session cookies lacking the HttpOnly flag allows an "
            "attacker to execute document.cookie in the victim's browser context and exfiltrate "
            "the session token to an attacker-controlled server."
        ),
        "owasp_mapping": "A03:2025 Injection / A07:2025 Identification and Authentication Failures",
        "impact": "XSS can steal session cookies — complete account takeover",
    },

    # ── Rule 6: CORS Misconfiguration → Cross-Origin Account Takeover ─────────
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

    # ── Rule 7: Open Redirect → OAuth Authorization Code Theft ───────────────
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

    # ── Rule 16: LFI → /proc/environ or .env → Credential Extraction ─────────
    # Spec: "LFI → read /proc/environ or /app/.env → credentials extracted → auth bypass"
    {
        "id": "CR-016",
        "trigger": ["lfi"],
        "requires_evidence": [
            "proc/environ", "app/.env", ".env", "DATABASE_URL", "SECRET_KEY",
            "DB_PASSWORD", "AWS_SECRET", "API_KEY", "PASSWORD=", "TOKEN=",
        ],
        "companion": ["auth_bypass", "sqli_error", "sqli_blind_time", "idor"],
        "chain_title": "LFI → /proc/environ → Credential Extraction → Auth Bypass",
        "chain_severity": "critical",
        "narrative": (
            "LFI confirmed reading environment files (/proc/environ, /app/.env). These files "
            "commonly contain DATABASE_URL, SECRET_KEY, AWS credentials, and API tokens in "
            "plaintext. Extracted credentials enable direct authentication bypass or lateral "
            "movement to backend databases and cloud services."
        ),
        "owasp_mapping": "A01:2025 Broken Access Control / A02:2025 Cryptographic Failures",
        "impact": "Environment file exposed — database credentials, cloud keys, and secrets extracted",
    },

    # ── Rule 17: Stored XSS → Admin Session → Privilege Escalation ───────────
    # Spec: "Stored XSS → victim admin visits page → session hijacking → privilege escalation"
    {
        "id": "CR-017",
        "trigger": ["xss_stored"],
        "companion": ["missing_httponly", "idor"],
        "chain_title": "Stored XSS → Admin Session Hijacking → Privilege Escalation",
        "chain_severity": "critical",
        "narrative": (
            "Stored XSS payload is persisted in the application and executes in the browser of "
            "every visitor — including administrators. When an admin loads the page, the attacker's "
            "script runs in their privileged context: cookies are stolen (if HttpOnly is absent), "
            "admin actions are performed via CSRF, or the admin session is fully hijacked, "
            "leading to complete privilege escalation."
        ),
        "owasp_mapping": "A03:2025 Injection / A01:2025 Broken Access Control",
        "impact": "Stored XSS targeting admins — session hijack + privilege escalation to admin",
    },

    # ── Rule 18: Open Redirect → Phishing → Credential Harvest → Account Takeover
    # Spec: "Open Redirect → phishing landing → credential harvest → account takeover"
    {
        "id": "CR-018",
        "trigger": ["open_redirect"],
        "requires_evidence": ["redirect", "url=", "next=", "return=", "goto=", "Location:"],
        "chain_title": "Open Redirect → Phishing Landing → Credential Harvest → Account Takeover",
        "chain_severity": "high",
        "narrative": (
            "The open redirect passes victim to an attacker-controlled phishing page that mirrors "
            "the legitimate login UI. Because the initial URL is on the trusted domain, the victim "
            "does not suspect deception. Credentials entered on the phishing page are harvested "
            "and replayed for immediate account takeover. Social engineering via email/SMS is "
            "trivially weaponized with this vector."
        ),
        "owasp_mapping": "A01:2025 Broken Access Control",
        "impact": "Trusted-domain redirect → phishing → credential theft → full account takeover",
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# CHAINER
# ══════════════════════════════════════════════════════════════════════════════

class VulnChainer:
    """
    Analyzes a list of ScanFindings and detects multi-step attack chains via:
      1. Rule-based matching (flat + companion)
      2. BFS graph traversal (CHAIN_TYPE_EDGES, max 3 hops)
      3. Optional LLM reasoning layer (requires llm_call callable)

    Call analyze_and_annotate(findings, llm_call=None) after all scans complete.
    Mutates findings in-place (sets chain_id, chain_desc) and returns list[AttackChain].
    """

    def analyze_and_annotate(
        self,
        findings: list,
        llm_call: Optional[Callable] = None,
    ) -> list[AttackChain]:
        """
        Main entry point. Runs rule matching + BFS traversal, then optional LLM enrichment.
        """
        # Build fast lookup by vuln_type
        by_type: dict[str, list] = {}
        for f in findings:
            vt = self._vtype(f)
            if vt:
                by_type.setdefault(vt, []).append(f)

        # Phase 1: rule-based matching
        chains: list[AttackChain] = []
        seen_rule_types: set[frozenset] = set()

        for rule in CHAIN_RULES:
            chain = self._evaluate_rule(rule, findings, by_type)
            if chain:
                # Deduplicate by trigger type set to avoid rule 7+18 double-firing open_redirect
                key = frozenset(rule["trigger"])
                if key not in seen_rule_types or rule.get("requires_evidence"):
                    chains.append(chain)
                    if not rule.get("requires_evidence"):
                        seen_rule_types.add(key)

        # Phase 2: BFS graph traversal — find cross-rule multi-hop chains
        bfs_chains = self._bfs_traverse(findings, by_type, existing_chains=chains)
        chains.extend(bfs_chains)

        # Phase 3: LLM reasoning layer (optional)
        if llm_call and chains:
            self._llm_enrich(chains, llm_call)

        return chains

    # ── Phase 1: Rule-based matching ──────────────────────────────────────────

    def _evaluate_rule(
        self,
        rule: dict,
        all_findings: list,
        by_type: dict[str, list],
    ) -> AttackChain | None:
        """Evaluate one chain rule. Returns AttackChain if triggered, else None."""

        # Collect trigger findings
        trigger_findings: list = []
        for t in rule["trigger"]:
            trigger_findings.extend(by_type.get(t, []))

        if not trigger_findings:
            return None

        # Filter by required evidence strings (proof field)
        if "requires_evidence" in rule:
            trigger_findings = [
                f for f in trigger_findings
                if any(ev in (self._proof(f)) for ev in rule["requires_evidence"])
            ]
            if not trigger_findings:
                return None

        # Optional companion findings
        companion_findings: list = []
        if "companion" in rule:
            for ct in rule["companion"]:
                companion_findings.extend(by_type.get(ct, []))
            if rule.get("companion_required", False) and not companion_findings:
                return None

        chain_id = f"chain_{uuid.uuid4().hex[:8]}"
        all_chain_findings = trigger_findings + companion_findings
        hop_depth = 1 + (1 if companion_findings else 0)

        self._annotate(all_chain_findings, chain_id, rule["chain_title"])

        steps = self._build_steps(trigger_findings, companion_findings)

        return AttackChain(
            chain_id      = chain_id,
            title         = rule["chain_title"],
            severity      = rule["chain_severity"],
            steps         = steps,
            narrative     = rule.get("narrative", ""),
            owasp_mapping = rule.get("owasp_mapping", ""),
            impact        = rule.get("impact", ""),
            finding_ids   = [self._fid(f) for f in all_chain_findings],
            hop_depth     = hop_depth,
        )

    # ── Phase 2: BFS graph traversal ─────────────────────────────────────────

    def _bfs_traverse(
        self,
        findings: list,
        by_type: dict[str, list],
        existing_chains: list[AttackChain],
    ) -> list[AttackChain]:
        """
        Walk the finding graph using CHAIN_TYPE_EDGES.
        Starting from each finding, BFS up to MAX_HOP_DEPTH hops.
        Only emit a chain when the path is ≥ 2 hops AND not already covered
        by an existing rule-based chain.
        """
        # Types already covered by rule-based chains
        covered_type_pairs: set[tuple[str, str]] = set()
        for ch in existing_chains:
            vtypes = [s.get("vuln_type", "") for s in ch.steps]
            for i in range(len(vtypes) - 1):
                covered_type_pairs.add((vtypes[i], vtypes[i + 1]))

        new_chains: list[AttackChain] = []
        visited_paths: set[tuple[str, ...]] = set()

        for start_f in findings:
            start_type = self._vtype(start_f)
            if not start_type or start_type not in CHAIN_TYPE_EDGES:
                continue

            # BFS queue: (current_type, path_so_far, findings_so_far)
            queue: deque[tuple[str, tuple[str, ...], list]] = deque()
            queue.append((start_type, (start_type,), [start_f]))

            while queue:
                cur_type, path, path_findings = queue.popleft()

                if len(path) > MAX_HOP_DEPTH:
                    continue

                # Emit chain if path >= 2 hops and not covered
                if len(path) >= 2:
                    pair = (path[0], path[-1])
                    if pair not in covered_type_pairs and path not in visited_paths:
                        visited_paths.add(path)
                        chain = self._build_bfs_chain(path, path_findings)
                        if chain:
                            new_chains.append(chain)
                            covered_type_pairs.add(pair)

                # Extend path
                if len(path) < MAX_HOP_DEPTH:
                    for next_type in CHAIN_TYPE_EDGES.get(cur_type, []):
                        if next_type in path:
                            continue  # prevent cycles
                        next_findings = by_type.get(next_type, [])
                        if next_findings:
                            queue.append((
                                next_type,
                                path + (next_type,),
                                path_findings + [next_findings[0]],
                            ))

        return new_chains

    def _build_bfs_chain(self, path: tuple[str, ...], path_findings: list) -> AttackChain | None:
        """Build an AttackChain from a BFS-discovered path."""
        if len(path_findings) < 2:
            return None

        title = " → ".join(t.upper().replace("_", " ") for t in path)
        chain_id = f"chain_{uuid.uuid4().hex[:8]}"
        severity = self._escalate_severity(path_findings)

        steps = []
        for i, (vtype, f) in enumerate(zip(path, path_findings), start=1):
            steps.append({
                "step_no":     i,
                "finding_id":  self._fid(f),
                "role":        "trigger" if i == 1 else "escalation",
                "vuln_type":   vtype,
                "url":         self._url(f),
                "description": self._desc(f),
            })

        self._annotate(path_findings, chain_id, title)

        return AttackChain(
            chain_id      = chain_id,
            title         = f"Attack Chain: {title}",
            severity      = severity,
            steps         = steps,
            narrative     = (
                f"BFS-detected multi-hop attack path: {title}. "
                f"Each step enables the next — an attacker exploiting the initial vulnerability "
                f"gains access to exploit the subsequent weaknesses in sequence."
            ),
            owasp_mapping = "Multi-vector — see individual step types",
            impact        = f"{len(path)}-hop chain: {path[0]} enables {path[-1]}",
            finding_ids   = [self._fid(f) for f in path_findings],
            hop_depth     = len(path),
        )

    def _escalate_severity(self, findings: list) -> str:
        """Escalate severity: any critical in chain → critical, else highest found."""
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        best = "medium"
        for f in findings:
            sev = (getattr(f, "severity", None) or f.get("severity", "medium") if isinstance(f, dict) else "medium").lower()
            if rank.get(sev, 99) < rank.get(best, 99):
                best = sev
        # Chains always escalate one level (finding graph = combined risk)
        escalation = {"high": "critical", "medium": "high", "low": "medium"}
        return escalation.get(best, best)

    # ── Phase 3: LLM reasoning ────────────────────────────────────────────────

    def _llm_enrich(self, chains: list[AttackChain], llm_call: Callable) -> None:
        """
        For each chain, call the LLM to generate a reachability analysis.
        Prompt: "Given {vuln_type} at {url}, what internal endpoints/services are reachable?"
        Modifies chains in-place (sets llm_reasoning).
        """
        for chain in chains:
            try:
                trigger_step = next((s for s in chain.steps if s["role"] in ("trigger", "initial_access")), None)
                if not trigger_step:
                    continue

                vtype = trigger_step.get("vuln_type", "unknown")
                url   = trigger_step.get("url", "unknown endpoint")

                prompt = (
                    f"You are a security researcher analyzing a confirmed vulnerability.\n\n"
                    f"Vulnerability: {vtype.upper().replace('_', ' ')}\n"
                    f"Endpoint: {url}\n"
                    f"Attack chain detected: {chain.title}\n\n"
                    f"Given this {vtype} vulnerability at {url}, answer concisely:\n"
                    f"1. What internal endpoints or services are likely reachable from this vector?\n"
                    f"2. What is the most likely next exploitation step an attacker would take?\n"
                    f"3. What data is most at risk?\n\n"
                    f"Keep your answer under 150 words. Focus on practical attacker actions."
                )

                result = llm_call([{"role": "user", "content": prompt}])
                if result:
                    chain.llm_reasoning = result.strip()

            except Exception:
                pass  # LLM enrichment is best-effort, never block chains

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _vtype(self, f) -> str:
        if isinstance(f, dict):
            return (f.get("vuln_type") or f.get("type") or "").lower()
        return (getattr(f, "vuln_type", "") or "").lower()

    def _proof(self, f) -> str:
        if isinstance(f, dict):
            return (f.get("proof") or f.get("detail") or f.get("finding") or "").lower()
        return (getattr(f, "proof", "") or "").lower()

    def _fid(self, f) -> str:
        if isinstance(f, dict):
            return f.get("id", "")
        return getattr(f, "id", "")

    def _url(self, f) -> str:
        if isinstance(f, dict):
            return f.get("url", "")
        return getattr(f, "url", "")

    def _desc(self, f) -> str:
        if isinstance(f, dict):
            return f.get("finding", "") or f.get("detail", "")
        return getattr(f, "finding", "") or getattr(f, "detail", "")

    def _annotate(self, findings: list, chain_id: str, title: str) -> None:
        """Stamp findings in-place with chain_id / chain_desc."""
        for f in findings:
            if isinstance(f, dict):
                if not f.get("chain_id"):
                    f["chain_id"]   = chain_id
                    f["chain_desc"] = title
            else:
                if not getattr(f, "chain_id", None):
                    f.chain_id   = chain_id
                    f.chain_desc = title

    def _build_steps(self, trigger: list, companion: list) -> list[dict]:
        steps = []
        for i, f in enumerate(trigger, start=1):
            steps.append({
                "step_no":     i,
                "finding_id":  self._fid(f),
                "role":        "trigger",
                "vuln_type":   self._vtype(f),
                "url":         self._url(f),
                "description": self._desc(f),
            })
        for i, f in enumerate(companion, start=len(trigger) + 1):
            steps.append({
                "step_no":     i,
                "finding_id":  self._fid(f),
                "role":        "companion",
                "vuln_type":   self._vtype(f),
                "url":         self._url(f),
                "description": self._desc(f),
            })
        return steps

    def summarize(self, chains: list[AttackChain]) -> dict:
        """Return a summary dict of all chains for reporting."""
        return {
            "total_chains": len(chains),
            "critical":     sum(1 for c in chains if c.severity == "critical"),
            "high":         sum(1 for c in chains if c.severity == "high"),
            "chains":       [c.to_dict() for c in chains],
        }

    @staticmethod
    def chains_to_mermaid(chains: list[AttackChain]) -> str:
        """Generate a Mermaid flowchart showing attack paths for all chains."""
        if not chains:
            return "graph LR\n    A[No Attack Chains Detected]"

        lines = ["graph LR"]
        node_ids: dict[str, str] = {}
        node_counter = [0]

        def _nid(raw: str) -> str:
            if raw not in node_ids:
                node_ids[raw] = f"N{node_counter[0]}"
                node_counter[0] += 1
            return node_ids[raw]

        sev_styles = {
            "critical": "fill:#450a0a,stroke:#dc2626,color:#fca5a5",
            "high":     "fill:#431407,stroke:#ea580c,color:#fdba74",
            "medium":   "fill:#422006,stroke:#ca8a04,color:#fde68a",
        }

        for chain in chains:
            sev_style  = sev_styles.get(chain.severity, "fill:#082f49,stroke:#0891b2,color:#67e8f9")
            chain_label = chain.title.replace('"', "'")[:60]
            chain_node  = f"C{chain.chain_id[-6:]}"
            lines.append(f'    {chain_node}["{chain_label}"]')
            lines.append(f'    style {chain_node} {sev_style}')

            sorted_steps = sorted(chain.steps, key=lambda s: s["step_no"])
            prev_node = None

            for step in sorted_steps:
                fid   = step.get("finding_id") or f"s{step['step_no']}_{chain.chain_id[-4:]}"
                vtype = (step.get("vuln_type") or "unknown").upper().replace("_", " ")
                url   = step.get("url", "")
                url_short = url.split("?")[0][-28:] if url else ""
                label = f"{vtype}\\n{url_short}" if url_short else vtype

                nid = _nid(fid)
                lines.append(f'    {nid}["{label}"]')

                if step["step_no"] == 1:
                    lines.append(f'    {chain_node} --> {nid}')
                elif prev_node:
                    edge_label = "escalates to" if step["role"] == "escalation" else "enables"
                    lines.append(f'    {prev_node} -->|{edge_label}| {nid}')
                prev_node = nid

        return "\n".join(lines)
