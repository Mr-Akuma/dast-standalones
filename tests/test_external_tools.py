import pytest
from modules.external_tools import _severity_map, SqlmapRunner, extract_dbms_hint


class TestSeverityMap:
    def test_critical_maps_to_critical(self):
        assert _severity_map("critical") == "Critical"

    def test_unknown_maps_to_info(self):
        assert _severity_map("unknown") == "Info"

    def test_informational_maps_to_info(self):
        assert _severity_map("informational") == "Info"

    def test_uppercase_medium_maps_to_medium(self):
        assert _severity_map("MEDIUM") == "Medium"

    def test_empty_string_maps_to_info(self):
        assert _severity_map("") == "Info"


class TestTamperForWaf:
    def test_none_returns_default_tamper(self):
        assert SqlmapRunner.tamper_for_waf(None) == SqlmapRunner._DEFAULT_TAMPER

    def test_cloudflare_contains_randomcase(self):
        result = SqlmapRunner.tamper_for_waf("Cloudflare")
        assert "randomcase" in result

    def test_unknown_waf_returns_default_tamper(self):
        assert SqlmapRunner.tamper_for_waf("UnknownWAF v9") == SqlmapRunner._DEFAULT_TAMPER


_SINGLE_TECHNIQUE_STDOUT = """\
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1-- -
    Vector: AND [INFERENCE]
"""

_CRITICAL_LINE_STDOUT = (
    "[14:23:11] [CRITICAL] all tested parameters do not appear to be injectable\n"
)

_WARNING_LINE_STDOUT = (
    "[14:23:11] [WARNING] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')\n"
)

_DBMS_LINE_STDOUT = "back-end DBMS: MySQL 5.x\n"

_TWO_PARAMS_STDOUT = """\
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1-- -
    Vector: AND [INFERENCE]

Parameter: name (POST)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: name=foo AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x71,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
    Vector: AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT([RANDSTR],FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)
"""


class TestParseOutput:
    def test_empty_stdout_returns_empty_list(self):
        assert SqlmapRunner._parse_output("http://target.com/", "") == []

    def test_single_technique_block_produces_one_finding(self):
        findings = SqlmapRunner._parse_output("http://target.com/", _SINGLE_TECHNIQUE_STDOUT)
        sqli = [f for f in findings if f.get("type") == "sqli_confirmed"]
        assert len(sqli) == 1

    def test_sqli_confirmed_has_required_fields(self):
        findings = SqlmapRunner._parse_output("http://target.com/?id=1", _SINGLE_TECHNIQUE_STDOUT)
        f = next(f for f in findings if f.get("type") == "sqli_confirmed")
        assert f["param"] == "id"
        assert f["technique"] == "boolean-based blind"
        assert "1 AND 1=1-- -" in f["payload"]
        assert f["url"] == "http://target.com/?id=1"

    def test_critical_injectable_line_produces_sqli_confirmed(self):
        findings = SqlmapRunner._parse_output("http://target.com/", _CRITICAL_LINE_STDOUT)
        types = [f["type"] for f in findings]
        assert "sqli_confirmed" in types

    def test_warning_waf_line_produces_sqli_warning_info(self):
        findings = SqlmapRunner._parse_output("http://target.com/", _WARNING_LINE_STDOUT)
        warn = [f for f in findings if f.get("type") == "sqli_warning"]
        assert len(warn) >= 1
        assert warn[0]["severity"] == "Info"

    def test_dbms_line_produces_dbms_fingerprint(self):
        findings = SqlmapRunner._parse_output("http://target.com/", _DBMS_LINE_STDOUT)
        dbms = [f for f in findings if f.get("type") == "dbms_fingerprint"]
        assert len(dbms) == 1
        assert "MySQL" in dbms[0]["finding"]

    def test_two_parameter_blocks_produce_two_findings(self):
        findings = SqlmapRunner._parse_output("http://target.com/", _TWO_PARAMS_STDOUT)
        sqli = [f for f in findings if f.get("type") == "sqli_confirmed"]
        params = {f["param"] for f in sqli}
        assert "id" in params
        assert "name" in params
        assert len(sqli) == 2


class TestDedupFindings:
    def test_identical_findings_deduplicated_to_one(self):
        f = {
            "url": "http://target.com/",
            "param": "id",
            "technique": "boolean-based blind",
            "type": "sqli_confirmed",
            "payload": "id=1 AND 1=1-- -",
        }
        result = SqlmapRunner._dedup_findings([f, dict(f)])
        assert len(result) == 1

    def test_different_technique_both_kept(self):
        base = {
            "url": "http://target.com/",
            "param": "id",
            "type": "sqli_confirmed",
            "payload": "id=1 AND 1=1-- -",
        }
        f1 = dict(base, technique="boolean-based blind")
        f2 = dict(base, technique="error-based")
        result = SqlmapRunner._dedup_findings([f1, f2])
        assert len(result) == 2


class TestExtractDbmsHint:
    def test_mysql_in_dbms_fingerprint_returns_mysql(self):
        findings = [
            {"type": "dbms_fingerprint", "finding": "Database identified: MySQL >= 5.0.12", "tool_detail": ""}
        ]
        assert extract_dbms_hint(findings) == "MySQL"

    def test_postgresql_finding_returns_postgresql(self):
        findings = [
            {"type": "dbms_fingerprint", "finding": "Database identified: PostgreSQL 14.2", "tool_detail": ""}
        ]
        assert extract_dbms_hint(findings) == "PostgreSQL"

    def test_findings_without_relevant_type_returns_none(self):
        findings = [
            {"type": "sqli_confirmed", "finding": "SQL injection confirmed — param 'id'", "tool_detail": ""}
        ]
        assert extract_dbms_hint(findings) is None

    def test_empty_list_returns_none(self):
        assert extract_dbms_hint([]) is None
