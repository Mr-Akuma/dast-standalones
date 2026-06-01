"""
Sequence Scanner — multi-step workflow security testing.
Equivalent to ZAP's Sequence Scanner add-on.

Records sequences of HTTP requests representing workflows (login -> action -> logout)
and tests them for CSRF bypass, authentication bypass, and parameter manipulation.
"""
from __future__ import annotations
import re
import time
import json
import copy
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
import requests


@dataclass
class SequenceStep:
    """A single HTTP request step within a sequence."""
    method: str
    url: str
    headers: dict
    body: str
    expected_status: int
    extract_vars: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SequenceFinding:
    """A security finding discovered during sequence testing."""
    sequence_name: str
    step_index: int
    step_url: str
    test_type: str
    finding: str
    severity: str
    evidence: str
    cwe: str
    agent_id: str = "sequence_scanner"
    icon: str = "\U0001f504"

    def to_dict(self) -> dict:
        return asdict(self)


class Sequence:
    """An ordered collection of HTTP request steps forming a workflow."""

    def __init__(self, name: str, steps: list[SequenceStep] | None = None):
        self.name = name
        self.steps: list[SequenceStep] = steps if steps is not None else []

    def add_step(self, step: SequenceStep) -> None:
        self.steps.append(step)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
        }


class SequenceScanner:
    """Tests multi-step workflows for CSRF bypass, auth bypass, and param manipulation."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _substitute_vars(self, text: str, variables: dict[str, str]) -> str:
        """Replace ``{{var_name}}`` placeholders with values from *variables*."""
        if not text or not variables:
            return text or ""
        for var_name, value in variables.items():
            text = text.replace("{{" + var_name + "}}", str(value))
        return text

    def _extract_vars(
        self, response_text: str, extract_patterns: dict[str, str]
    ) -> dict[str, str]:
        """Run regex patterns against *response_text* and return captured values."""
        extracted: dict[str, str] = {}
        for var_name, pattern in extract_patterns.items():
            match = re.search(pattern, response_text)
            if match:
                extracted[var_name] = match.group(1)
        return extracted

    # ------------------------------------------------------------------
    # Playback
    # ------------------------------------------------------------------

    def play(
        self,
        session: requests.Session,
        sequence: Sequence,
        variables: dict[str, str] | None = None,
    ) -> list[tuple[SequenceStep, requests.Response]]:
        """Execute every step in *sequence* and return ``(step, response)`` pairs.

        Variables are substituted into URLs, headers, and bodies.  New variables
        extracted from responses are merged back for subsequent steps.
        """
        variables = dict(variables) if variables else {}
        results: list[tuple[SequenceStep, requests.Response]] = []

        for step in sequence.steps:
            try:
                url = self._substitute_vars(step.url, variables)
                headers = {
                    k: self._substitute_vars(v, variables)
                    for k, v in step.headers.items()
                }
                body = self._substitute_vars(step.body, variables)

                response = session.request(
                    method=step.method,
                    url=url,
                    headers=headers,
                    data=body if body else None,
                    timeout=self.timeout,
                    allow_redirects=True,
                )

                # Extract variables from response for later steps
                if step.extract_vars:
                    new_vars = self._extract_vars(response.text, step.extract_vars)
                    variables.update(new_vars)

                results.append((step, response))

                if response.status_code != step.expected_status:
                    break

            except Exception:
                break

        return results

    # ------------------------------------------------------------------
    # Test: CSRF bypass
    # ------------------------------------------------------------------

    def test_csrf_bypass(
        self, session: requests.Session, sequence: Sequence
    ) -> list[SequenceFinding]:
        """Re-play steps that carry CSRF tokens *without* the token and check for bypass."""
        csrf_patterns = re.compile(
            r"(csrf|_token|authenticity_token|csrfmiddlewaretoken)", re.IGNORECASE
        )
        findings: list[SequenceFinding] = []

        # First, do a baseline play to capture cookies / session state
        baseline = self.play(session, sequence)
        if not baseline:
            return findings

        for idx, step in enumerate(sequence.steps):
            if not csrf_patterns.search(step.body or ""):
                continue

            # Build a body without the CSRF param
            stripped_body = "&".join(
                part
                for part in (step.body or "").split("&")
                if not csrf_patterns.search(part)
            )

            try:
                response = session.request(
                    method=step.method,
                    url=step.url,
                    headers=step.headers,
                    data=stripped_body if stripped_body else None,
                    timeout=self.timeout,
                    allow_redirects=True,
                )

                baseline_status = (
                    baseline[idx][1].status_code if idx < len(baseline) else None
                )

                if response.status_code == 200 or response.status_code == baseline_status:
                    findings.append(
                        SequenceFinding(
                            sequence_name=sequence.name,
                            step_index=idx,
                            step_url=step.url,
                            test_type="csrf_bypass",
                            finding=(
                                f"Step {idx} accepted request without CSRF token "
                                f"(status {response.status_code})"
                            ),
                            severity="High",
                            evidence=f"Status {response.status_code} without CSRF param",
                            cwe="CWE-352",
                        )
                    )
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # Test: authentication step skip
    # ------------------------------------------------------------------

    def test_auth_step_skip(
        self, session: requests.Session, sequence: Sequence
    ) -> list[SequenceFinding]:
        """Skip the first step (typically auth) and attempt later steps on a fresh session."""
        if len(sequence.steps) < 3:
            return []

        findings: list[SequenceFinding] = []
        fresh_session = requests.Session()

        for idx in range(1, len(sequence.steps)):
            step = sequence.steps[idx]
            try:
                response = fresh_session.request(
                    method=step.method,
                    url=step.url,
                    headers=step.headers,
                    data=step.body if step.body else None,
                    timeout=self.timeout,
                    allow_redirects=True,
                )

                if response.status_code == 200:
                    findings.append(
                        SequenceFinding(
                            sequence_name=sequence.name,
                            step_index=idx,
                            step_url=step.url,
                            test_type="auth_step_skip",
                            finding=(
                                f"Step {idx} returned 200 without prior authentication step"
                            ),
                            severity="Critical",
                            evidence=(
                                f"Fresh session got status {response.status_code} "
                                f"on {step.url}"
                            ),
                            cwe="CWE-287",
                        )
                    )
            except Exception:
                continue

        fresh_session.close()
        return findings

    # ------------------------------------------------------------------
    # Test: parameter manipulation
    # ------------------------------------------------------------------

    def test_parameter_manipulation(
        self,
        session: requests.Session,
        sequence: Sequence,
        step_idx: int = 0,
    ) -> list[SequenceFinding]:
        """Mutate numeric parameters in *step_idx* and look for unexpected behaviour."""
        if step_idx >= len(sequence.steps):
            return []

        step = sequence.steps[step_idx]
        findings: list[SequenceFinding] = []

        # Baseline
        try:
            baseline = session.request(
                method=step.method,
                url=step.url,
                headers=step.headers,
                data=step.body if step.body else None,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except Exception:
            return findings

        mutations = ["0", "-1", "99999", "admin", "../../../etc/passwd"]
        params = (step.body or "").split("&")

        for pidx, param in enumerate(params):
            if "=" not in param:
                continue
            key, value = param.split("=", 1)

            for mutation in mutations:
                mutated_params = list(params)
                mutated_params[pidx] = f"{key}={mutation}"
                mutated_body = "&".join(mutated_params)

                try:
                    response = session.request(
                        method=step.method,
                        url=step.url,
                        headers=step.headers,
                        data=mutated_body,
                        timeout=self.timeout,
                        allow_redirects=True,
                    )

                    if response.status_code != baseline.status_code or (
                        len(response.text) != len(baseline.text)
                    ):
                        findings.append(
                            SequenceFinding(
                                sequence_name=sequence.name,
                                step_index=step_idx,
                                step_url=step.url,
                                test_type="parameter_manipulation",
                                finding=(
                                    f"Parameter '{key}' responded differently with "
                                    f"value '{mutation}'"
                                ),
                                severity="Medium",
                                evidence=(
                                    f"Original status={baseline.status_code} len={len(baseline.text)}, "
                                    f"mutated status={response.status_code} len={len(response.text)}"
                                ),
                                cwe="CWE-20",
                            )
                        )
                except Exception:
                    continue

        return findings

    # ------------------------------------------------------------------
    # Full scan
    # ------------------------------------------------------------------

    def scan(
        self, session: requests.Session, sequence: Sequence
    ) -> list[SequenceFinding]:
        """Run all sequence tests and return deduplicated findings."""
        all_findings: list[SequenceFinding] = []
        all_findings.extend(self.test_csrf_bypass(session, sequence))
        all_findings.extend(self.test_auth_step_skip(session, sequence))

        for idx in range(len(sequence.steps)):
            all_findings.extend(
                self.test_parameter_manipulation(session, sequence, step_idx=idx)
            )

        # Deduplicate by (step_index, test_type, finding)
        seen: set[tuple[int, str, str]] = set()
        deduped: list[SequenceFinding] = []
        for f in all_findings:
            key = (f.step_index, f.test_type, f.finding)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped
