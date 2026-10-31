"""Unit tests for x64 badchar-safe encoding module."""
from __future__ import annotations

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

NO_BADCHARS: set[int] = set()
STANDARD_BC: set[int] = {0x00, 0x0A, 0x0D}


class TestEncodeQword:
    def test_zero(self) -> None:
        lines = encode_qword(0, NO_BADCHARS, "rax")
        asm = "\n".join(lines)
        assert "eax" in asm or "rax" in asm

    def test_small_value_uses_r32(self) -> None:
        lines = encode_qword(0x41414141, NO_BADCHARS, "rax")
        assert len(lines) == 1
        assert "eax" in lines[0]

    def test_large_value_uses_r64(self) -> None:
        lines = encode_qword(0x00007FFF12345678, NO_BADCHARS, "rax")
        assert any("rax" in l for l in lines)

    def test_badchar_avoidance_64bit(self) -> None:
        val = 0x00000000DEADBEEF
        lines = encode_qword(val, {0x00}, "rax")
        for line in lines:
            if "0x" in line and "mov" in line:
                hex_str = line.split("0x")[1].strip().rstrip(",")
                num = int(hex_str, 16)
                byte_vals = [(num >> (8 * i)) & 0xFF for i in range(len(hex_str) // 2)]
                for b in byte_vals:
                    assert b != 0x00

    def test_all_registers(self) -> None:
        for reg in ("rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11"):
            lines = encode_qword(0x1234, NO_BADCHARS, reg)
            assert len(lines) >= 1

    def test_full_64bit_value(self) -> None:
        lines = encode_qword(0xFFFFFFFF_FFFFFFFF, NO_BADCHARS, "rax")
        assert len(lines) >= 1


class TestEncodeDwordIntoR64:
    def test_clean_value(self) -> None:
        lines = encode_dword_into_r64(0x41424344, NO_BADCHARS, "rax")
        assert len(lines) == 1
        assert "eax" in lines[0]
        assert "0x41424344" in lines[0]

    def test_xor_encoding(self) -> None:
        lines = encode_dword_into_r64(0x0A0B0C0D, {0x0A, 0x0D}, "rcx")
        assert len(lines) == 2
        assert "xor" in lines[1]

    def test_zero_value(self) -> None:
        lines = encode_dword_into_r64(0, NO_BADCHARS, "rax")
        assert len(lines) == 1


class TestSafeQwordStore:
    def test_clean_offset(self) -> None:
        lines = safe_qword_store("rsp", 0x40, "rax", NO_BADCHARS)
        assert len(lines) == 1
        assert "qword ptr" in lines[0]
        assert "+0x40" in lines[0]

    def test_badchar_offset(self) -> None:
        lines = safe_qword_store("rsp", 0x0A, "rax", {0x0A})
        assert len(lines) > 1

    def test_zero_offset(self) -> None:
        lines = safe_qword_store("rsp", 0, "rax", NO_BADCHARS)
        assert len(lines) == 1
        assert "[rsp]" in lines[0]


class TestSafeDwordStoreX64:
    def test_clean(self) -> None:
        lines = safe_dword_store_x64("rsp", 0x20, "eax", NO_BADCHARS)
        assert len(lines) == 1
        assert "dword ptr" in lines[0]

    def test_badchar_displacement(self) -> None:
        lines = safe_dword_store_x64("rsp", 0x0D, "eax", {0x0D})
        assert len(lines) > 1


class TestSafeWordStoreX64:
    def test_clean(self) -> None:
        lines = safe_word_store_x64("rsp", 0x08, "ax", NO_BADCHARS)
        assert len(lines) == 1
        assert "word ptr" in lines[0]


class TestSafeMemLoadX64:
    def test_qword_load(self) -> None:
        lines = safe_mem_load_x64("rax", "rsp", 0x10, NO_BADCHARS)
        assert len(lines) == 1
        assert "[rsp+0x10]" in lines[0]

    def test_dword_load(self) -> None:
        lines = safe_mem_load_x64("eax", "rsp", 0x10, NO_BADCHARS, width="dword")
        assert "dword ptr" in lines[0]

    def test_badchar_offset(self) -> None:
        lines = safe_mem_load_x64("rax", "rsp", 0x0A, {0x0A})
        assert len(lines) > 1


class TestSafeLeaX64:
    def test_clean_offset(self) -> None:
        lines = safe_lea_x64("rdi", "rsp", 0x100, NO_BADCHARS)
        assert len(lines) == 1
        assert "lea" in lines[0]

    def test_badchar_offset(self) -> None:
        lines = safe_lea_x64("rdi", "rsp", 0x0D0D, {0x0D})
        assert len(lines) > 1


class TestSafeCallMemX64:
    def test_clean(self) -> None:
        lines = safe_call_mem_x64("rsp", 0x48, NO_BADCHARS)
        assert len(lines) == 1
        assert "call qword ptr" in lines[0]

    def test_badchar(self) -> None:
        lines = safe_call_mem_x64("rsp", 0x0A, {0x0A})
        assert len(lines) > 1
        assert any("call" in l for l in lines)
