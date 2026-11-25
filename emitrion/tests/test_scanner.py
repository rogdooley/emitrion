"""Tests for the post-assembly bad character scanner and frequency analyzer."""
from __future__ import annotations

from emitrion.scanner import Violation, frequency, scan


class TestScan:
    def test_clean_payload(self):
        result = scan(b"\x01\x02\x03\x04", {0x00})
        assert result.clean
        assert result.violations == []

    def test_single_violation(self):
        result = scan(b"\x01\x00\x03", {0x00})
        assert not result.clean
        assert len(result.violations) == 1
        assert result.violations[0].offset == 1
        assert result.violations[0].value == 0x00

    def test_multiple_violations(self):
        result = scan(b"\x0a\x01\x0d\x03\x0a", {0x0a, 0x0d})
        assert not result.clean
        assert len(result.violations) == 3
        assert result.violations[0] == Violation(0, 0x0a)
        assert result.violations[1] == Violation(2, 0x0d)
        assert result.violations[2] == Violation(4, 0x0a)

    def test_empty_payload(self):
        result = scan(b"", {0x00})
        assert result.clean
        assert result.payload_size == 0

    def test_empty_badchars(self):
        result = scan(b"\x00\x0a\x0d", set())
        assert result.clean

    def test_all_bytes_forbidden(self):
        payload = bytes(range(256))
        result = scan(payload, set(range(256)))
        assert not result.clean
        assert len(result.violations) == 256

    def test_arbitrary_badchar_set(self):
        result = scan(b"\x30\x3c\x41\x42", {0x30, 0x3c})
        assert not result.clean
        assert len(result.violations) == 2
        assert result.violations[0].value == 0x30
        assert result.violations[1].value == 0x3c

    def test_payload_size_tracked(self):
        result = scan(b"\x01" * 100, {0x00})
        assert result.payload_size == 100


class TestScanResult:
    def test_summary_clean(self):
        result = scan(b"\x01\x02", {0x00})
        s = result.summary()
        assert "Violations     0" in s

    def test_summary_violations(self):
        result = scan(b"\x00\x01\x00", {0x00})
        s = result.summary()
        assert "Violations     2" in s
        assert "0x0000: 0x00" in s
        assert "0x0002: 0x00" in s


class TestViolation:
    def test_str(self):
        v = Violation(offset=0x23, value=0x0d)
        assert str(v) == "0x0023: 0x0d"


class TestFrequency:
    def test_basic_counts(self):
        result = frequency(b"\x41\x41\x42\x43\x41", {0x00})
        assert result.counts[0x41] == 3
        assert result.counts[0x42] == 1
        assert result.counts[0x43] == 1
        assert result.counts[0x00] == 0
        assert result.payload_size == 5

    def test_absent_bytes(self):
        result = frequency(b"\x01\x02\x03")
        absent = result.absent
        assert 0x00 in absent
        assert 0x01 not in absent
        assert len(absent) == 253

    def test_unnecessary_badchars(self):
        result = frequency(b"\x41\x42\x43", {0x00, 0x0A, 0x0D, 0x41})
        assert result.unnecessary_badchars == [0x00, 0x0A, 0x0D]
        assert result.present_badchars == [0x41]

    def test_top_n(self):
        result = frequency(b"\x41" * 10 + b"\x42" * 5 + b"\x43" * 1)
        top3 = result.top(3)
        assert top3[0] == (0x41, 10)
        assert top3[1] == (0x42, 5)
        assert top3[2] == (0x43, 1)

    def test_top_clips_to_distinct_count(self):
        result = frequency(b"\x41\x42")
        assert len(result.top(100)) == 2

    def test_empty_payload(self):
        result = frequency(b"")
        assert result.payload_size == 0
        assert all(c == 0 for c in result.counts)
        assert len(result.absent) == 256

    def test_all_256_bytes(self):
        result = frequency(bytes(range(256)))
        assert all(c == 1 for c in result.counts)
        assert len(result.absent) == 0

    def test_histogram_contains_badchar_markers(self):
        result = frequency(b"\x00\x41\x41", {0x00})
        hist = result.histogram()
        assert "!" in hist
        assert "Unnecessary" not in hist

    def test_histogram_reports_unnecessary(self):
        result = frequency(b"\x41\x42", {0x00, 0x0D})
        hist = result.histogram()
        assert "Unnecessary" in hist
        assert "00" in hist
        assert "0d" in hist

    def test_no_badchars(self):
        result = frequency(b"\x41\x42\x43")
        assert result.unnecessary_badchars == []
        assert result.present_badchars == []
        hist = result.histogram()
        assert "Badchars" not in hist
