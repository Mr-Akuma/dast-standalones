from pathlib import Path


DASHBOARD_TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "index.html"


def _between(text: str, start: str, end: str) -> str:
    start_idx = text.index(start)
    end_idx = text.index(end, start_idx)
    return text[start_idx:end_idx]


def test_raw_finding_record_counts_are_not_labeled_total():
    html = DASHBOARD_TEMPLATE.read_text(encoding="utf-8")
    dot = "\u00b7"

    confusing_fragments = [
        f"unique {dot} ${{total}} total",
        f"unique {dot} ${{instanceTotal}} total",
        f"unique {dot} ${{histInstanceTotal}} total",
        f"unique {dot} 1120 total",
    ]
    for fragment in confusing_fragments:
        assert fragment not in html

    assert "raw records" in html.lower()


def test_raw_records_are_defined_on_overview_not_count_badges():
    html = DASHBOARD_TEMPLATE.read_text(encoding="utf-8")
    live_badge_block = _between(html, "async function loadFindings()", "function renderFindings")
    history_badge_block = _between(html, "async function viewHistoryScanFindings", "async function loadPassiveFindings")
    engine_last_scan_block = _between(html, "const lastScanStrip =", "summary.innerHTML")
    definition = (
        "Raw records are noisy scanner hits and false-positive candidates; "
        "unique findings are the filtered true-positive issues shown."
    )

    assert 'id="ov-raw-records-definition"' in html
    assert definition in html
    assert definition in engine_last_scan_block

    assert "raw record" not in live_badge_block.lower()
    assert "raw record" not in history_badge_block.lower()
    assert "_formatFindingBadgeTotals(totals)" in live_badge_block
    assert "_formatFindingBadgeTotals({" in history_badge_block
    assert "if (bft) bft.textContent = uniqueCount;" in live_badge_block
    assert "if (bft) bft.textContent = histUnique;" in history_badge_block


def test_finding_drawer_has_detailed_why_profiles_for_csp_and_common_dast_issues():
    html = DASHBOARD_TEMPLATE.read_text(encoding="utf-8")
    why_block = _between(html, "function _buildWhyReason(g)", "function _reconstructRequest(g)")

    assert "_findingKnowledgeProfile(g)" in why_block
    assert "weak_csp" in html
    assert "Content-Security-Policy is the browser-side safety net" in html
    assert "Attack path" in html
    assert "How to fix" in html
    assert "How to verify" in html
    assert "CSP Evaluator" in html

    for issue_type in [
        "xss_reflected",
        "sqli_error",
        "open_redirect",
        "cors",
        "ssrf",
        "path_traversal",
        "cookie",
        "csrf",
        "host_header_injection",
    ]:
        assert issue_type in html
