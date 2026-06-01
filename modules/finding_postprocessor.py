"""Global finding post-processing for report-quality DAST output.

The scanner has many engines that can independently discover the same issue.
This module performs the final report pass: confidence annotation, stable
deduplication, and a small audit summary for downstream reports.
"""

from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlparse

from .confidence import ConfidenceScorer, score_to_burp_confidence


_SEVERITY_RANK = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_path(url: str) -> tuple[str, str]:
    parsed = urlparse(url or "")
    host = (parsed.netloc or "").lower()
    path = parsed.path.rstrip("/") or "/"
    return host, path


def _dedup_key(finding: dict) -> tuple[str, ...]:
    """Build a cross-engine key for the same issue at the same insertion point."""
    url = str(finding.get("url", ""))
    host, path = _normalize_path(url)
    method = str(finding.get("method", "")).upper()
    param = str(finding.get("param", finding.get("parameter", ""))).lower()
    param_type = str(finding.get("param_type", "")).lower()
    vuln = str(finding.get("vuln_type", finding.get("category", ""))).lower()
    cwe = str(finding.get("cwe", "")).lower()

    if not any((host, path, method, param, vuln, cwe)):
        fallback = str(finding.get("finding", ""))[:160].lower()
        severity = str(finding.get("severity", "")).lower()
        return ("fallback", fallback, severity)

    return (host, path, method, param_type, param, vuln, cwe)


def _severity_rank(finding: dict) -> int:
    severity = str(finding.get("severity", "info")).lower()
    return _SEVERITY_RANK.get(severity, 0)


def _rank(finding: dict) -> tuple[float, int, int, int, int]:
    """Rank duplicates so the strongest evidence survives."""
    confidence = _as_float(finding.get("confidence_score"), 0.0)
    proof_len = len(str(finding.get("proof", "") or ""))
    has_evidence = 1 if finding.get("evidence_id") else 0
    finding_len = len(str(finding.get("finding", "") or ""))
    return (confidence, _severity_rank(finding), proof_len, has_evidence, finding_len)


def _annotate_confidence(finding: dict, scorer: ConfidenceScorer) -> dict:
    """Annotate confidence without reducing a higher existing score."""
    annotated = scorer.score_and_annotate(dict(finding))
    existing = finding.get("confidence_score")
    existing_score = _as_float(existing, -1.0)
    computed_score = _as_float(annotated.get("confidence_score"), 0.0)

    if existing_score > computed_score:
        annotated["confidence_score"] = round(min(existing_score, 1.0), 3)
        annotated["confidence_level"] = ConfidenceScorer._score_to_level(existing_score)
        annotated["audit_confidence"] = score_to_burp_confidence(existing_score).value

    return annotated


def _confidence_summary(findings: list[dict]) -> dict[str, int]:
    counts = Counter(str(f.get("audit_confidence", "Unknown")) for f in findings)
    return dict(sorted(counts.items()))


def _severity_summary(findings: list[dict]) -> dict[str, int]:
    counts = Counter(str(f.get("severity", "Info")) for f in findings)
    return dict(sorted(counts.items()))


def postprocess_findings(findings: list[dict]) -> tuple[list[dict], dict]:
    """Annotate and deduplicate findings before report generation.

    Returns:
        (processed_findings, summary)
    """
    raw_count = len(findings or [])
    scorer = ConfidenceScorer()
    annotated: list[dict] = []
    for finding in findings or []:
        if isinstance(finding, dict):
            annotated.append(_annotate_confidence(finding, scorer))

    best_by_key: dict[tuple[str, ...], dict] = {}
    key_order: list[tuple[str, ...]] = []
    for finding in annotated:
        key = _dedup_key(finding)
        if key not in best_by_key:
            best_by_key[key] = finding
            key_order.append(key)
            continue
        if _rank(finding) > _rank(best_by_key[key]):
            best_by_key[key] = finding

    processed = [best_by_key[key] for key in key_order]
    duplicates_removed = raw_count - len(processed)
    summary = {
        "raw_count": raw_count,
        "deduplicated_count": len(processed),
        "duplicates_removed": max(0, duplicates_removed),
        "confidence_summary": _confidence_summary(processed),
        "severity_summary": _severity_summary(processed),
    }
    return processed, summary
