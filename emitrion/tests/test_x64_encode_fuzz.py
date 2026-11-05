"""Fuzz-style edge-case tests for x64 badchar-safe encoding functions.

Validates that no badchar byte leaks into hex literals produced by the
encoder, across boundary values, all single-byte badchar sets, and
badchar-contaminated memory offsets.
"""
from __future__ import annotations

import re

import pytest

from emitrion.encode_x64 import (
    encode_dword_into_r64,
    encode_qword,
    safe_call_mem_x64,
    safe_dword_store_x64,
    safe_lea_x64,
    safe_mem_load_x64,
    safe_qword_store,
    safe_word_store_x64,
)

_HEX_RE = re.compile(r"\b0x([0-9a-fA-F]+)\b")


def _extract_hex_bytes(lines: list[str]) -> list[tuple[int, int]]:
    """Extract (value_byte, parent_value) pairs from all 0x literals in asm lines."""
    pairs: list[tuple[int, int]] = []
    for line in lines:
        for m in _HEX_RE.finditer(line):
            val = int(m.group(1), 16)
            nbytes = (len(m.group(1)) + 1) // 2
            for i in range(nbytes):
                pairs.append(((val >> (8 * i)) & 0xFF, val))
    return pairs


def _assert_no_badchar_leak(lines: list[str], badchars: set[int]) -> None:
    for byte_val, parent in _extract_hex_bytes(lines):
        assert byte_val not in badchars, (
            f"Badchar 0x{byte_val:02x} leaked in literal 0x{parent:x}; "
            f"lines: {lines}"
        )


# -- Boundary byte values placed at each position of a qword/dword --

_BOUNDARY_BYTES = [0x00, 0x7F, 0x80, 0xFF]

_BADCHAR_SETS: list[set[int]] = [
    {0x00},
    {0x0A, 0x0D},
    {0x00, 0x0A, 0x0D, 0xFF},
]


def _qword_with_byte_at(byte_val: int, position: int) -> int:
    return byte_val << (8 * position)


def _dword_with_byte_at(byte_val: int, position: int) -> int:
    return byte_val << (8 * position)


class TestEncodeQwordBoundaries:
    @pytest.mark.parametrize("byte_val", _BOUNDARY_BYTES)
    @pytest.mark.parametrize("position", range(8))
    @pytest.mark.parametrize("badchars", _BADCHAR_SETS, ids=lambda s: f"bc{'_'.join(f'{b:02x}' for b in sorted(s))}")
    def test_single_byte_at_position(self, byte_val: int, position: int, badchars: set[int]) -> None:
        value = _qword_with_byte_at(byte_val, position)
        lines = encode_qword(value, badchars, "rax")
        assert len(lines) >= 1
        _assert_no_badchar_leak(lines, badchars)

    @pytest.mark.parametrize("value", [
        0x0000000000000000,
        0xFFFFFFFFFFFFFFFF,
        0x7F7F7F7F7F7F7F7F,
        0x8080808080808080,
        0x0A0D0A0D0A0D0A0D,
    ])
    @pytest.mark.parametrize("badchars", _BADCHAR_SETS, ids=lambda s: f"bc{'_'.join(f'{b:02x}' for b in sorted(s))}")
    def test_full_patterns(self, value: int, badchars: set[int]) -> None:
        lines = encode_qword(value, badchars, "rcx")
        _assert_no_badchar_leak(lines, badchars)

    @pytest.mark.parametrize("reg", ["rax", "rcx", "r8", "r10", "r11", "rdi"])
    def test_all_scratch_paths(self, reg: str) -> None:
        badchars = {0x00, 0x0A, 0x0D}
        lines = encode_qword(0x0A0D000000000000, badchars, reg)
        _assert_no_badchar_leak(lines, badchars)


class TestEncodeDwordBoundaries:
    @pytest.mark.parametrize("byte_val", _BOUNDARY_BYTES)
    @pytest.mark.parametrize("position", range(4))
    @pytest.mark.parametrize("badchars", _BADCHAR_SETS, ids=lambda s: f"bc{'_'.join(f'{b:02x}' for b in sorted(s))}")
    def test_single_byte_at_position(self, byte_val: int, position: int, badchars: set[int]) -> None:
        value = _dword_with_byte_at(byte_val, position)
        lines = encode_dword_into_r64(value, badchars, "rax")
        assert len(lines) >= 1
        _assert_no_badchar_leak(lines, badchars)

    @pytest.mark.parametrize("value", [
        0x00000000,
        0xFFFFFFFF,
        0x7F7F7F7F,
        0x80808080,
        0x0A0D0A0D,
    ])
    @pytest.mark.parametrize("badchars", _BADCHAR_SETS, ids=lambda s: f"bc{'_'.join(f'{b:02x}' for b in sorted(s))}")
    def test_full_patterns(self, value: int, badchars: set[int]) -> None:
        lines = encode_dword_into_r64(value, badchars, "rdx")
        _assert_no_badchar_leak(lines, badchars)


class TestSafeMemOpsBadcharOffsets:
    _OFFSETS = [0x0A, 0x0D00, 0x000A0000, 0x0D0A0D0A]
    _BADCHARS = {0x0A, 0x0D}

    @pytest.mark.parametrize("offset", _OFFSETS)
    def test_safe_qword_store(self, offset: int) -> None:
        lines = safe_qword_store("rsp", offset, "rax", self._BADCHARS)
        _assert_no_badchar_leak(lines, self._BADCHARS)

    @pytest.mark.parametrize("offset", _OFFSETS)
    def test_safe_dword_store(self, offset: int) -> None:
        lines = safe_dword_store_x64("rsp", offset, "ecx", self._BADCHARS)
        _assert_no_badchar_leak(lines, self._BADCHARS)

    @pytest.mark.parametrize("offset", _OFFSETS)
    def test_safe_word_store(self, offset: int) -> None:
        lines = safe_word_store_x64("rsp", offset, "cx", self._BADCHARS)
        _assert_no_badchar_leak(lines, self._BADCHARS)

    @pytest.mark.parametrize("offset", _OFFSETS)
    def test_safe_mem_load(self, offset: int) -> None:
        lines = safe_mem_load_x64("rax", "rsp", offset, self._BADCHARS)
        _assert_no_badchar_leak(lines, self._BADCHARS)

    @pytest.mark.parametrize("offset", _OFFSETS)
    def test_safe_lea(self, offset: int) -> None:
        lines = safe_lea_x64("rcx", "rsp", offset, self._BADCHARS)
        _assert_no_badchar_leak(lines, self._BADCHARS)

    @pytest.mark.parametrize("offset", _OFFSETS)
    def test_safe_call_mem(self, offset: int) -> None:
        lines = safe_call_mem_x64("rsp", offset, self._BADCHARS)
        _assert_no_badchar_leak(lines, self._BADCHARS)

    def test_zero_offset_passthrough(self) -> None:
        lines = safe_qword_store("rsp", 0, "rax", self._BADCHARS)
        assert len(lines) == 1
        assert "[rsp]" in lines[0]

    def test_clean_offset_passthrough(self) -> None:
        lines = safe_call_mem_x64("rsp", 0x40, self._BADCHARS)
        assert len(lines) == 1
        assert "+0x40" in lines[0]


class TestEncodeQwordAllSingleBadchars:
    _VALUE = 0x0102030405060708

    @pytest.mark.parametrize("bc", range(256))
    def test_single_badchar(self, bc: int) -> None:
        badchars = {bc}
        lines = encode_qword(self._VALUE, badchars, "rax")
        _assert_no_badchar_leak(lines, badchars)


class TestEncodeDwordAllSingleBadchars:
    _VALUE = 0x01020304

    @pytest.mark.parametrize("bc", range(256))
    def test_single_badchar(self, bc: int) -> None:
        badchars = {bc}
        lines = encode_dword_into_r64(self._VALUE, badchars, "rax")
        _assert_no_badchar_leak(lines, badchars)
