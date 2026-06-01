"""Tests for finding deduplication."""
import pytest
from modules.dedup import FindingDeduplicator


@pytest.mark.dedup
class TestDeduplicator:
    def test_removes_exact_duplicates(self, sample_finding):
        """Two identical findings should be deduplicated to one."""
        dedup = FindingDeduplicator()
        result = dedup.deduplicate([sample_finding, dict(sample_finding)])
        assert len(result) == 1

    def test_keeps_highest_confidence(self, sample_finding):
        """When duplicates exist, the higher confidence one replaces the lower."""
        dedup = FindingDeduplicator()
        low = dict(sample_finding, confidence_score=0.3)
        high = dict(sample_finding, confidence_score=0.9)
        # add() returns True for both (first add + replacement), so deduplicate returns both
        # But the internal state keeps only the highest-confidence instance
        dedup.deduplicate([low, high])
        assert dedup.get_unique_count() == 1
        # Lower confidence duplicate after the highest is rejected
        rejected = dict(sample_finding, confidence_score=0.1)
        assert dedup.add(rejected) is False

    def test_different_params_kept(self, sample_finding, sample_finding_different):
        """Findings with different params should both be kept."""
        dedup = FindingDeduplicator()
        result = dedup.deduplicate([sample_finding, sample_finding_different])
        assert len(result) == 2

    def test_different_urls_kept(self, sample_finding):
        """Same vuln_type on different URL paths should both be kept."""
        dedup = FindingDeduplicator()
        f1 = dict(sample_finding, url="https://example.com/page1?id=1")
        f2 = dict(sample_finding, url="https://example.com/page2?id=1")
        result = dedup.deduplicate([f1, f2])
        assert len(result) == 2

    def test_empty_list(self):
        """Empty findings list should return empty."""
        dedup = FindingDeduplicator()
        assert dedup.deduplicate([]) == []

    def test_is_duplicate(self, sample_finding):
        """is_duplicate returns True after adding a finding."""
        dedup = FindingDeduplicator()
        dedup.add(sample_finding)
        assert dedup.is_duplicate(sample_finding) is True

    def test_unique_count(self, sample_finding, sample_finding_different):
        """get_unique_count tracks unique findings."""
        dedup = FindingDeduplicator()
        dedup.deduplicate([sample_finding, sample_finding_different, dict(sample_finding)])
        assert dedup.get_unique_count() == 2
