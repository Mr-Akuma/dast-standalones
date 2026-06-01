"""
LLM-Adaptive Fuzzer — AI-driven payload generation with response feedback.

Inspired by AnvilSecure's ByteBanter Burp extension. Instead of only using
static payload lists, this module asks an LLM to generate context-aware attack
payloads based on endpoint context (URL, param name, param type, tech stack).

Key innovation: **stateful response feedback** — after each payload is sent,
the server's response (status code, error snippets, timing) is fed back to the
LLM so it can adapt its next payload. This turns the fuzzer from spray-and-pray
into an adaptive attacker that evolves based on what the target reveals.

Uses the existing LLMProvider abstraction (Anthropic/OpenAI/Ollama).
Graceful no-op when no LLM is configured.
"""
from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger("dast.llm_fuzzer")

# ── Destructive patterns — payloads matching these are rejected ──────────────
_DESTRUCTIVE_PATTERNS = re.compile(
    r"(?i)\b("
    r"DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|DELETE\s+FROM|"
    r"INSERT\s+INTO|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|CREATE\s+TABLE|"
    r"rm\s+-rf|rm\s+-f|rmdir|del\s+/[sfq]|format\s+[a-z]:|"
    r"shutdown|reboot|halt|poweroff|init\s+0|"
    r"mkfs|dd\s+if=|wipefs|fdisk|"
    r"net\s+stop|sc\s+delete|taskkill\s+/f|"
    r"xp_cmdshell.*(?:del|rm|format|shutdown|net\s+user)"
    r")\b"
)

# ── System prompt — security researcher persona with safety rails ────────────
SYSTEM_PROMPT = """You are an expert penetration tester generating attack payloads for authorized DAST (Dynamic Application Security Testing) scanning.

RULES:
1. Generate ONLY detection payloads — payloads that reveal vulnerabilities through information disclosure, error messages, timing differences, or behavioral changes.
2. NEVER generate destructive payloads: no DROP, DELETE, INSERT, UPDATE, TRUNCATE, rm, format, shutdown, or any data-modification commands.
3. Each payload should be a single line — one payload per line.
4. Return ONLY the payloads, one per line. No explanations, no markdown, no code blocks, no numbering.
5. Payloads should be diverse — try different techniques, encodings, and bypass methods.
6. Tailor payloads to the specific technology stack when provided.

SAFETY: This is authorized security testing. All payloads are sent to targets the operator has explicit permission to test. Focus on DETECTING vulnerabilities, not exploiting them destructively."""

# ── User prompt template ─────────────────────────────────────────────────────
_INITIAL_PROMPT_TEMPLATE = """Generate {count} unique {vuln_desc} detection payloads for this endpoint:

- URL: {url}
- Parameter: {param_name} (location: {param_type})
- HTTP Method: {method}
{tech_context}
The parameter's current value is: {original_value}

Generate payloads that will reveal whether this parameter is vulnerable. Focus on detection, not destruction."""

_FEEDBACK_PROMPT_TEMPLATE = """The target responded to the payload `{payload}` with:
- HTTP Status: {status_code}
- Response Time: {elapsed_ms:.0f}ms
- Response Snippet: {snippet}

Based on this response, generate {count} improved payloads that dig deeper into this potential vulnerability. Adapt your approach based on what the server revealed."""


# ── Vuln type descriptions for prompt context ────────────────────────────────
_VULN_DESCRIPTIONS: dict[str, str] = {
    "sqli_error":       "SQL injection (error-based)",
    "sqli_bool_true":   "SQL injection (boolean blind)",
    "sqli_blind_time":  "SQL injection (time-based blind)",
    "xss_reflected":    "Cross-Site Scripting (reflected XSS)",
    "xss_stored":       "Cross-Site Scripting (stored XSS)",
    "lfi":              "Local File Inclusion / Path Traversal",
    "cmdi":             "OS Command Injection",
    "ssti":             "Server-Side Template Injection",
    "ssrf":             "Server-Side Request Forgery",
    "xxe":              "XML External Entity injection",
    "open_redirect":    "Open Redirect",
    "header_injection": "HTTP Header Injection",
    "crlf_injection":   "CRLF Injection",
    "nosql_injection":  "NoSQL Injection",
    "ldap_injection":   "LDAP Injection",
    "xpath_injection":  "XPath Injection",
    "el_injection":     "Expression Language Injection",
    "deserialization":  "Insecure Deserialization",
    "log4shell":        "Log4Shell / JNDI Injection",
    "ssi_injection":    "Server-Side Includes Injection",
    "rfi":              "Remote File Inclusion",
    "format_string":    "Format String Vulnerability",
}


class LLMFuzzer:
    """
    LLM-driven payload generator with stateful response feedback.

    Usage::

        llm_fuzz = LLMFuzzer(provider, max_rounds=3, max_payloads_per_round=5)
        payloads = llm_fuzz.generate_payloads(
            url="https://target.com/search",
            param_name="q", param_type="query", method="GET",
            vuln_types=["sqli_error", "xss_reflected"],
            tech_fingerprint={"framework": ["django"]},
            original_value="test",
        )
        # Send payloads, then feed response back:
        llm_fuzz.feed_response(payload="' OR 1=1--", status_code=500,
                               snippet="SQL syntax error near...", elapsed_ms=45)
        # Get adapted payloads:
        more_payloads = llm_fuzz.generate_payloads(...)
    """

    def __init__(
        self,
        provider: Any,
        max_rounds: int = 3,
        max_payloads_per_round: int = 5,
        max_history: int = 6,
    ):
        self._provider = provider
        self.max_rounds = max_rounds
        self.max_payloads_per_round = max_payloads_per_round
        self.max_history = max_history  # max conversation exchanges to keep
        self._messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
        ]
        self._round = 0
        self._total_calls = 0

    # ── Public API ────────────────────────────────────────────────────────

    def generate_payloads(
        self,
        url: str = "",
        param_name: str = "",
        param_type: str = "query",
        method: str = "GET",
        vuln_types: list[str] | None = None,
        tech_fingerprint: dict | None = None,
        original_value: str = "",
    ) -> list[str]:
        """Generate payloads for the given endpoint context.

        Returns list of payload strings, or empty list on failure/exhaustion.
        """
        if not self._provider or not getattr(self._provider, 'is_available', False):
            return []

        if self._round >= self.max_rounds:
            return []

        self._round += 1
        vtypes = vuln_types or ["sqli_error", "xss_reflected"]
        vuln_desc = ", ".join(_VULN_DESCRIPTIONS.get(v, v) for v in vtypes[:3])

        # Build tech context string
        tech_ctx = ""
        if tech_fingerprint:
            parts = []
            for key, val in tech_fingerprint.items():
                if isinstance(val, list):
                    parts.append(f"  - {key}: {', '.join(str(v) for v in val)}")
                else:
                    parts.append(f"  - {key}: {val}")
            if parts:
                tech_ctx = "- Detected technology:\n" + "\n".join(parts)

        prompt = _INITIAL_PROMPT_TEMPLATE.format(
            count=self.max_payloads_per_round,
            vuln_desc=vuln_desc,
            url=url,
            param_name=param_name,
            param_type=param_type,
            method=method,
            tech_context=tech_ctx,
            original_value=original_value or "(empty)",
        )

        self._messages.append({"role": "user", "content": prompt})
        self._prune_history()

        try:
            self._total_calls += 1
            response = self._provider.chat(self._messages)
            self._messages.append({"role": "assistant", "content": response})
            payloads = self._parse_payloads(response)
            payloads = [p for p in payloads if self._is_safe(p)]
            log.info("[LLMFuzzer] Round %d: generated %d payloads for %s [%s]",
                     self._round, len(payloads), param_name, vuln_desc)
            return payloads[:self.max_payloads_per_round]
        except Exception as exc:
            log.warning("[LLMFuzzer] LLM call failed: %s", exc)
            return []

    def feed_response(
        self,
        payload: str,
        status_code: int,
        snippet: str,
        elapsed_ms: float,
    ) -> None:
        """Feed a server response back into the conversation for adaptation."""
        if self._round >= self.max_rounds:
            return

        feedback = _FEEDBACK_PROMPT_TEMPLATE.format(
            payload=payload,
            status_code=status_code,
            snippet=snippet[:500],  # cap snippet length
            elapsed_ms=elapsed_ms,
            count=self.max_payloads_per_round,
        )
        self._messages.append({"role": "user", "content": feedback})
        self._prune_history()

    def reset(self) -> None:
        """Reset conversation for a new surface."""
        self._messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self._round = 0

    @property
    def rounds_remaining(self) -> int:
        return max(0, self.max_rounds - self._round)

    @property
    def total_llm_calls(self) -> int:
        return self._total_calls

    # ── Internal ──────────────────────────────────────────────────────────

    def _parse_payloads(self, text: str) -> list[str]:
        """Extract individual payloads from LLM response text.

        Handles various LLM output formats:
        - Plain lines (one payload per line)
        - Numbered lists (1. payload, 2. payload)
        - Markdown code blocks (```...```)
        - Bullet lists (- payload, * payload)
        """
        # Strip markdown code blocks
        text = re.sub(r'```[\w]*\n?', '', text)

        lines = text.strip().split('\n')
        payloads = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Remove numbering: "1. ", "1) ", "- ", "* "
            line = re.sub(r'^(?:\d+[\.\)]\s*|[-*]\s+)', '', line)
            # Remove surrounding backticks
            line = line.strip('`').strip()
            # Remove surrounding quotes
            if len(line) >= 2 and line[0] == line[-1] and line[0] in ('"', "'"):
                line = line[1:-1]
            if not line:
                continue
            # Skip obvious non-payload lines (explanations)
            if len(line) > 200:
                continue
            if line.lower().startswith(('note:', 'explanation:', 'these ', 'the ', 'here ')):
                continue
            payloads.append(line)
        return payloads

    @staticmethod
    def _is_safe(payload: str) -> bool:
        """Reject payloads containing destructive operations."""
        return not _DESTRUCTIVE_PATTERNS.search(payload)

    def _prune_history(self) -> None:
        """Keep conversation from growing unbounded.

        Preserves system prompt + last N exchanges (user+assistant pairs).
        """
        if len(self._messages) <= 1 + (self.max_history * 2):
            return
        # Keep system prompt + last max_history exchanges
        system = self._messages[0]
        tail = self._messages[-(self.max_history * 2):]
        self._messages = [system] + tail
