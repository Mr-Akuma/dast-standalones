"""Authenticated journey replay and role comparison."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .api_exposure_diff import _flatten_json


@dataclass
class JourneyStep:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    expected_status: int | None = None
    name: str = ""


@dataclass
class Journey:
    name: str
    steps: list[JourneyStep]


class JourneyScanner:
    def replay(self, journey: Journey, session, role: str = "default") -> dict:
        responses: list[dict] = []
        findings: list[dict] = []
        for idx, step in enumerate(journey.steps):
            resp = session.request(
                method=step.method.upper(),
                url=step.url,
                headers=step.headers or None,
                json=step.body if isinstance(step.body, (dict, list)) else None,
                data=step.body if isinstance(step.body, str) else None,
            )
            parsed = self._response_to_dict(resp)
            parsed["step_index"] = idx
            parsed["step_name"] = step.name or f"step-{idx + 1}"
            parsed["role"] = role
            responses.append(parsed)
            if step.expected_status is not None and parsed["status_code"] != step.expected_status:
                findings.append({
                    "vuln_type": "journey_unexpected_status",
                    "severity": "medium",
                    "finding": f"{role} got HTTP {parsed['status_code']} for {step.url}; expected {step.expected_status}",
                    "url": step.url,
                    "proof": str(parsed["status_code"]),
                })
        return {"journey": journey.name, "role": role, "responses": responses, "findings": findings}

    def compare_roles(self, journey: Journey, role_sessions: Mapping[str, Any]) -> dict:
        runs = {role: self.replay(journey, sess, role) for role, sess in role_sessions.items()}
        findings: list[dict] = []
        roles = list(runs)
        if len(roles) < 2:
            return {"journey": journey.name, "runs": runs, "findings": [], "finding_count": 0}

        base_role = roles[0]
        base_fields = self._fields_by_step(runs[base_role])
        for role in roles[1:]:
            role_fields = self._fields_by_step(runs[role])
            for step_index, fields in role_fields.items():
                extra = fields - base_fields.get(step_index, set())
                sensitive = {f for f in extra if self._is_sensitive(f)}
                if sensitive:
                    findings.append({
                        "agent": "Authenticated Journey Scanner",
                        "vuln_type": "cross_role_data_exposure",
                        "type": "cross_role_data_exposure",
                        "severity": "high",
                        "finding": f"Role {role} receives sensitive fields not seen by {base_role}",
                        "url": self._step_url(journey, step_index),
                        "proof": ", ".join(sorted(sensitive)),
                        "role": role,
                        "baseline_role": base_role,
                    })
        return {"journey": journey.name, "runs": runs, "findings": findings, "finding_count": len(findings)}

    @staticmethod
    def _response_to_dict(resp) -> dict:
        try:
            json_body = resp.json()
        except Exception:
            json_body = None
        return {
            "status_code": getattr(resp, "status_code", 0),
            "url": getattr(resp, "url", ""),
            "headers": dict(getattr(resp, "headers", {}) or {}),
            "body": (getattr(resp, "text", "") or "")[:4000],
            "json": json_body,
        }

    @staticmethod
    def _fields_by_step(run: dict) -> dict[int, set[str]]:
        out: dict[int, set[str]] = {}
        for response in run.get("responses", []):
            if response.get("json") is None:
                continue
            out[response["step_index"]] = {path for path, _ in _flatten_json(response["json"])}
        return out

    @staticmethod
    def _is_sensitive(path: str) -> bool:
        lowered = path.lower()
        return any(token in lowered for token in (
            "token", "secret", "role", "admin", "permission", "internal",
            "ssn", "password", "apikey", "api_key", "cost", "tenant",
        ))

    @staticmethod
    def _step_url(journey: Journey, step_index: int) -> str:
        if 0 <= step_index < len(journey.steps):
            return journey.steps[step_index].url
        return ""
