"""Replayable evidence bundle generation."""
from __future__ import annotations

import difflib
import shlex
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


class EvidenceReplayBuilder:
    def build(self, finding: dict) -> dict:
        method = (finding.get("method") or "GET").upper()
        url = finding.get("url") or finding.get("target") or ""
        headers = finding.get("headers") or finding.get("request_headers") or {}
        payload = str(finding.get("payload") or "")
        param = finding.get("param") or finding.get("parameter") or ""
        body = finding.get("body") or finding.get("request_body") or ""

        replay_url = self._inject_query(url, param, payload) if method == "GET" and param and payload else url
        curl = self._curl(method, replay_url, headers, body, payload, param)
        baseline = finding.get("baseline") or {}
        attack = finding.get("attack") or {}
        diff = self._diff(baseline, attack)
        proof = finding.get("proof") or diff.get("summary") or "Replay bundle generated"
        attack_body = str(attack.get("body") or "")
        if attack_body and attack_body[:120] not in proof:
            proof = f"{proof}; attack excerpt: {attack_body[:120]}"
        return {
            "url": replay_url,
            "method": method,
            "curl": curl,
            "proof": proof,
            "diff": diff,
            "baseline": baseline,
            "attack": attack,
        }

    @staticmethod
    def _inject_query(url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        out = []
        for key, value in pairs:
            if key == param:
                out.append((key, payload))
                replaced = True
            else:
                out.append((key, value))
        if not replaced:
            out.append((param, payload))
        return urlunparse(parsed._replace(query=urlencode(out)))

    @staticmethod
    def _curl(method: str, url: str, headers: dict, body: str, payload: str, param: str = "") -> str:
        parts = ["curl", "-i", "-X", shlex.quote(method), shlex.quote(url)]
        for key, value in headers.items():
            parts.extend(["-H", shlex.quote(f"{key}: {value}")])
        if method == "GET" and payload and param:
            parts.extend(["--get", "--data-urlencode", shlex.quote(f"{param}={payload}")])
            return " ".join(parts)
        data = payload or body
        if data:
            parts.extend(["--data-raw", shlex.quote(str(data))])
        return " ".join(parts)

    @staticmethod
    def _diff(baseline: dict, attack: dict) -> dict:
        b_status = baseline.get("status_code")
        a_status = attack.get("status_code")
        b_body = str(baseline.get("body") or "")
        a_body = str(attack.get("body") or "")
        lines = list(difflib.unified_diff(
            b_body.splitlines(),
            a_body.splitlines(),
            fromfile="baseline",
            tofile="attack",
            lineterm="",
        ))[:80]
        summary_parts = []
        if b_status != a_status:
            summary_parts.append(f"status changed {b_status}->{a_status}")
        if lines:
            summary_parts.append("response body changed")
        if "sql" in a_body.lower() or "syntax" in a_body.lower():
            summary_parts.append("attack response contains SQL/error indicator")
        return {
            "status_changed": b_status != a_status,
            "body_changed": b_body != a_body,
            "unified_diff": lines,
            "summary": "; ".join(summary_parts),
        }
