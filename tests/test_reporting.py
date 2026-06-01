"""Tests for reporting module."""
import json
import pytest
from modules.reporting import finding_fingerprint, PdfReport


@pytest.mark.reporting
class TestFindingFingerprint:
    def test_stability(self, sample_finding):
        """Same finding dict always produces same fingerprint."""
        fp1 = finding_fingerprint(sample_finding)
        fp2 = finding_fingerprint(sample_finding)
        assert fp1 == fp2

    def test_different_findings_differ(self, sample_finding, sample_finding_different):
        """Different findings produce different fingerprints."""
        fp1 = finding_fingerprint(sample_finding)
        fp2 = finding_fingerprint(sample_finding_different)
        assert fp1 != fp2

    def test_fingerprint_is_hex_string(self, sample_finding):
        """Fingerprint should be a 16-char hex string."""
        fp = finding_fingerprint(sample_finding)
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)


@pytest.mark.reporting
class TestPdfReport:
    def test_generates_valid_pdf(self, sample_finding):
        """PdfReport.generate() returns bytes starting with %PDF."""
        report = PdfReport([sample_finding], "https://example.com")
        pdf_bytes = report.generate()
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-1.4")
        assert b"%%EOF" in pdf_bytes

    def test_empty_findings(self):
        """PDF should generate successfully with no findings."""
        report = PdfReport([], "https://example.com")
        pdf_bytes = report.generate()
        assert pdf_bytes.startswith(b"%PDF-1.4")

    def test_contains_target(self, sample_finding):
        """PDF should contain the target URL."""
        report = PdfReport([sample_finding], "https://target.example.com")
        pdf_bytes = report.generate()
        assert b"target.example.com" in pdf_bytes

    def test_contains_severity_counts(self, sample_finding):
        """PDF should contain severity counts."""
        report = PdfReport([sample_finding], "https://example.com")
        pdf_bytes = report.generate()
        assert b"HIGH" in pdf_bytes
