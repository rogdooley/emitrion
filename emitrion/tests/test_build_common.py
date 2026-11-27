"""Tests for build_common.py - arch-independent build utilities."""
from __future__ import annotations

import os
import pathlib

from emitrion.build_common import (
    _bytes_to_c,
    _bytes_to_hex_str,
    _bytes_to_py,
    _build_timestamp,
    _call_disp_has_badchar,
    _strip_comments,
    _to_keystone,
    _to_nasm,
    _validate_badchars,
)

COMMON = {0x00, 0x0A, 0x0D}


# ---------------------------------------------------------------------------
# Byte formatting
# ---------------------------------------------------------------------------

class TestBytesToHexStr:
    def test_empty(self):
        assert _bytes_to_hex_str(b"") == ""

    def test_single_byte(self):
        assert _bytes_to_hex_str(b"\x41") == "\\x41"

    def test_16_bytes_one_line(self):
        raw = bytes(range(16))
        result = _bytes_to_hex_str(raw)
        assert "\n" not in result
        assert result.startswith("\\x00\\x01")

    def test_17_bytes_two_lines(self):
        raw = bytes(range(17))
        lines = _bytes_to_hex_str(raw).split("\n")
        assert len(lines) == 2
        assert len(lines[0]) == 16 * 4

    def test_round_trip(self):
        raw = b"\xde\xad\xbe\xef"
        hex_str = _bytes_to_hex_str(raw)
        rebuilt = bytes(
            int(hex_str[i + 2:i + 4], 16)
            for i in range(0, len(hex_str), 4)
            if hex_str[i:i + 2] == "\\x"
        )
        assert rebuilt == raw


class TestBytesToPy:
    def test_empty(self):
        result = _bytes_to_py(b"")
        assert "Length: 0 bytes" in result
        assert "shellcode" in result

    def test_contains_length(self):
        raw = b"\x41\x42\x43"
        result = _bytes_to_py(raw)
        assert "Length: 3 bytes" in result

    def test_valid_python(self):
        raw = b"\xde\xad\xbe\xef"
        result = _bytes_to_py(raw)
        assert result.startswith("shellcode = (")
        assert 'b"' in result


class TestBytesToC:
    def test_empty(self):
        result = _bytes_to_c(b"")
        assert "Length: 0 bytes" in result
        assert "unsigned char shellcode[]" in result

    def test_contains_length(self):
        raw = b"\x41\x42\x43"
        result = _bytes_to_c(raw)
        assert "Length: 3 bytes" in result

    def test_hex_format(self):
        raw = b"\xde\xad"
        result = _bytes_to_c(raw)
        assert "0xde" in result
        assert "0xad" in result

    def test_16_bytes_per_row(self):
        raw = bytes(range(32))
        result = _bytes_to_c(raw)
        body_lines = [l for l in result.split("\n") if l.strip().startswith("0x")]
        assert len(body_lines) == 2


# ---------------------------------------------------------------------------
# Comment stripping
# ---------------------------------------------------------------------------

class TestStripComments:
    def test_hash_comment(self):
        assert _strip_comments("mov eax, 1  # set eax") == "mov eax, 1  "

    def test_semicolon_comment(self):
        assert _strip_comments("xor eax, eax ; clear") == "xor eax, eax "

    def test_no_comment(self):
        assert _strip_comments("nop") == "nop"

    def test_unicode_in_comment(self):
        result = _strip_comments("nop ; --- stub ---")
        assert "---" not in result or result == "nop "

    def test_multiline(self):
        asm = "mov eax, 1 # first\nmov ebx, 2 ; second"
        result = _strip_comments(asm)
        lines = result.split("\n")
        assert lines[0] == "mov eax, 1 "
        assert lines[1] == "mov ebx, 2 "


# ---------------------------------------------------------------------------
# Keystone conversion
# ---------------------------------------------------------------------------

class TestToKeystone:
    def test_strips_comments(self):
        result = _to_keystone("mov eax, 1 # comment")
        assert "#" not in result
        assert "mov eax, 1" in result

    def test_jmp_short_to_jmp(self):
        result = _to_keystone("jmp short label")
        assert "jmp label" in result
        assert "short" not in result

    def test_drops_blank_lines(self):
        asm = "nop\n   \nmov eax, 1"
        result = _to_keystone(asm)
        lines = result.split("\n")
        assert all(l.strip() for l in lines)

    def test_preserves_labels(self):
        asm = "my_label:\n    nop"
        result = _to_keystone(asm)
        assert "my_label:" in result


# ---------------------------------------------------------------------------
# NASM conversion
# ---------------------------------------------------------------------------

class TestToNasm:
    def test_adds_bits32(self):
        result = _to_nasm("xor eax, eax")
        assert result.startswith("BITS 32")

    def test_strips_dword_ptr(self):
        result = _to_nasm("call dword ptr [ebp-0x28]")
        assert "dword [ebp-0x28]" in result
        assert "ptr" not in result

    def test_strips_word_ptr(self):
        result = _to_nasm("cmp word ptr [esi], 0x004b")
        assert "word [esi]" in result
        assert "ptr" not in result

    def test_strips_byte_ptr(self):
        result = _to_nasm("movzx eax, byte ptr [esi]")
        assert "byte [esi]" in result
        assert "ptr" not in result

    def test_fixes_fs_segment(self):
        result = _to_nasm("mov eax, fs:[ecx + 0x30]")
        assert "[fs:ecx + 0x30]" in result
        assert "fs:[" not in result

    def test_normal_instructions_unchanged(self):
        result = _to_nasm("push 0\npop eax")
        lines = result.split("\n")
        assert lines[1] == "push 0"
        assert lines[2] == "pop eax"


# ---------------------------------------------------------------------------
# CALL displacement badchar check
# ---------------------------------------------------------------------------

class TestCallDispHasBadchar:
    def test_no_call(self):
        assert not _call_disp_has_badchar(b"\x90\x90\x90", COMMON)

    def test_clean_call(self):
        raw = b"\xe8\x01\x02\x03\x04"
        assert not _call_disp_has_badchar(raw, COMMON)

    def test_dirty_call_null(self):
        raw = b"\xe8\x00\x01\x01\x01"
        assert _call_disp_has_badchar(raw, COMMON)

    def test_dirty_call_newline(self):
        raw = b"\xe8\x01\x0a\x01\x01"
        assert _call_disp_has_badchar(raw, COMMON)

    def test_e8_at_end_not_a_call(self):
        raw = b"\x90\x90\xe8\x01\x02"
        assert not _call_disp_has_badchar(raw, COMMON)

    def test_multiple_calls(self):
        raw = b"\xe8\x01\x01\x01\x01\x90\xe8\x01\x0d\x01\x01"
        assert _call_disp_has_badchar(raw, COMMON)


# ---------------------------------------------------------------------------
# Assembled badchar validation
# ---------------------------------------------------------------------------

class TestValidateBadchars:
    def test_clean(self):
        assert _validate_badchars(b"\x01\x02\x03", COMMON) == []

    def test_single_hit(self):
        result = _validate_badchars(b"\x01\x00\x03", {0x00})
        assert len(result) == 1
        assert "0x0001=0x00" in result[0]

    def test_multiple_hits(self):
        result = _validate_badchars(b"\x00\x0a\x0d", COMMON)
        assert len(result) == 1
        assert "3 total" not in result[0]

    def test_many_hits_truncated(self):
        raw = bytes([0x00] * 20)
        result = _validate_badchars(raw, {0x00})
        assert len(result) == 1
        assert "total" in result[0]

    def test_empty_badchars(self):
        assert _validate_badchars(b"\x00\x0a", set()) == []


# ---------------------------------------------------------------------------
# Build timestamp
# ---------------------------------------------------------------------------

class TestBuildTimestamp:
    def test_default_epoch_zero(self):
        result = _build_timestamp()
        assert result == "1970-01-01 00:00:00"

    def test_custom_epoch(self):
        old = os.environ.get("SOURCE_DATE_EPOCH")
        try:
            os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
            result = _build_timestamp()
            assert "2023" in result
        finally:
            if old is None:
                os.environ.pop("SOURCE_DATE_EPOCH", None)
            else:
                os.environ["SOURCE_DATE_EPOCH"] = old

    def test_now_produces_current_year(self):
        old = os.environ.get("SOURCE_DATE_EPOCH")
        try:
            os.environ["SOURCE_DATE_EPOCH"] = "now"
            result = _build_timestamp()
            assert "202" in result
        finally:
            if old is None:
                os.environ.pop("SOURCE_DATE_EPOCH", None)
            else:
                os.environ["SOURCE_DATE_EPOCH"] = old
