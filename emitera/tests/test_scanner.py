"""Tests for the post-assembly bad character scanner."""
from __future__ import annotations

from emitera.scanner import Violation, scan


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
