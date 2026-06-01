"""Tests for passive scanner checks."""
import pytest
from modules.passive import PassiveScanner


@pytest.fixture
def scanner():
    return PassiveScanner()


@pytest.mark.passive
class TestSecurityHeaders:
    def test_missing_hsts(self, scanner):
        """HSTS missing should produce a finding."""
        findings = scanner._check_security_headers(
            "https://example.com", {}, 200
        )
        hsts_findings = [f for f in findings if "hsts" in f.finding.lower()
                         or "strict-transport" in f.finding.lower()]
        assert len(hsts_findings) >= 1

    def test_present_hsts_no_finding(self, scanner):
        """HSTS present should not produce HSTS finding."""
        findings = scanner._check_security_headers(
            "https://example.com",
            {"strict-transport-security": "max-age=31536000; includeSubDomains"},
            200,
        )
        hsts_findings = [f for f in findings if "hsts" in f.finding.lower()
                         or "strict-transport" in f.finding.lower()]
        assert len(hsts_findings) == 0


@pytest.mark.passive
class TestPII:
    def test_real_card_detected(self, scanner):
        """Luhn-valid non-test card should be detected."""
        # 4532015112830366 is Luhn-valid but not a well-known test number
        findings = scanner._check_pii(
            "https://app.com/receipt", "Your card: 4532015112830366 was charged"
        )
        card_findings = [f for f in findings if "card" in f.finding.lower()]
        assert len(card_findings) >= 1

    def test_test_card_excluded(self, scanner):
        """Well-known test card numbers should be excluded."""
        findings = scanner._check_pii(
            "https://app.com/test", "Test payment: 4111111111111111"
        )
        card_findings = [f for f in findings if "Visa" in f.finding]
        assert len(card_findings) == 0

    def test_luhn_invalid_excluded(self, scanner):
        """Non-Luhn-valid card-like numbers should be excluded."""
        findings = scanner._check_pii(
            "https://app.com/page", "Reference: 4111111111111112"
        )
        card_findings = [f for f in findings if "card" in f.finding.lower()]
        assert len(card_findings) == 0


@pytest.mark.passive
class TestBodyErrors:
    def test_skips_on_500(self, scanner):
        """Error patterns on 500 responses should be skipped."""
        findings = scanner._check_body_errors(
            "https://app.com/error",
            "java.lang.NullPointerException at com.example.Servlet.doGet",
            status_code=500,
        )
        assert len(findings) == 0

    def test_fires_on_200(self, scanner):
        """Error patterns on 200 responses should be flagged."""
        findings = scanner._check_body_errors(
            "https://app.com/page",
            "java.lang.NullPointerException at com.example.Servlet.doGet(Servlet.java:42)",
            status_code=200,
        )
        assert len(findings) >= 1


@pytest.mark.passive
class TestEmailFP:
    def test_real_email_detected(self, scanner):
        """Real emails should be detected."""
        findings = scanner._check_body_info(
            "https://app.com/page", "Contact us at admin@company.com for support"
        )
        email_findings = [f for f in findings if "Email" in f.finding]
        assert len(email_findings) >= 1

    def test_example_email_excluded(self, scanner):
        """Emails from test domains should be excluded."""
        findings = scanner._check_body_info(
            "https://app.com/page", "Use user@example.com as placeholder"
        )
        email_findings = [f for f in findings if "Email" in f.finding]
        assert len(email_findings) == 0
