"""Tests for encode_x64.py - badchar-safe x64 immediate and memory encoding."""

from emitrion.encode_x64 import (
    encode_dword_into_r64,
    encode_qword,
    safe_call_mem_x64,
    safe_dword_store_x64,
    safe_lea_x64,
    safe_mem_load_x64,
    safe_qword_store,
    safe_word_store_x64,
    _disp_has_badchar,
    _fmt_offset,
    _r64_to_r32,
    _reg_to_r64,
    _safe_tmp,
    _scratch_r64,
)

COMMON = {0x00, 0x0A, 0x0D}


def _extract_hex_immediates(lines: list[str]) -> list[int]:
    """Extract all hex literal values from assembly lines."""
    vals = []
    for line in lines:
        for token in line.split():
            token = token.rstrip(",").rstrip("]")
            if token.startswith("0x"):
                vals.append(int(token, 16))
    return vals


def _assert_no_badchars_in_immediates(lines: list[str], badchars: set[int], nbytes: int = 8):
    """Assert no immediate value byte falls in badchars."""
    for line in lines:
        for token in line.split():
            token = token.rstrip(",").rstrip("]")
            if token.startswith("0x"):
                raw = int(token, 16)
                for i in range(nbytes):
                    byte_val = (raw >> (8 * i)) & 0xFF
                    assert byte_val not in badchars, (
                        f"Badchar 0x{byte_val:02x} in token {token} on line: {line.strip()}"
                    )


def _eval_r64_lines(lines: list[str], reg: str = "rax") -> int:
    """Simulate mov/xor sequences on a 64-bit register, return final value."""
    r32 = _r64_to_r32(reg)
    val = 0
    for line in lines:
        parts = line.split()
        op = parts[0]
        dst = parts[1].rstrip(",")
        if op == "mov" and dst in (reg, r32):
            imm = int(parts[2].rstrip(","), 16)
            if dst == r32:
                val = imm & 0xFFFFFFFF
            else:
                val = imm & 0xFFFFFFFFFFFFFFFF
        elif op == "xor" and dst in (reg, r32):
            imm = int(parts[2].rstrip(","), 16)
            if dst == r32:
                val = (val ^ imm) & 0xFFFFFFFF
            else:
                val = (val ^ imm) & 0xFFFFFFFFFFFFFFFF
    return val


# ---------------------------------------------------------------------------
# encode_qword
# ---------------------------------------------------------------------------

class TestEncodeQword:
    def test_clean_32bit_value_uses_r32(self):
        lines = encode_qword(0x12345678, COMMON)
        assert len(lines) == 1
        assert "eax" in lines[0]

    def test_clean_64bit_value_single_mov(self):
        lines = encode_qword(0x1122334455667788, COMMON)
        assert len(lines) == 1
        assert "rax" in lines[0]
        assert "0x1122334455667788" in lines[0]

    def test_dirty_64bit_uses_xor_mask(self):
        value = 0x110022003300440A
        lines = encode_qword(value, COMMON)
        assert len(lines) == 3
        assert "xor" in lines[2]

    def test_dirty_64bit_decodes_correctly(self):
        value = 0x110022003300440A
        lines = encode_qword(value, COMMON)
        mov_val = int(lines[0].split()[-1].rstrip(","), 16)
        scratch_val = int(lines[1].split()[-1].rstrip(","), 16)
        assert (mov_val ^ scratch_val) == value

    def test_zero_value(self):
        lines = encode_qword(0, COMMON)
        result = _eval_r64_lines(lines)
        assert result == 0

    def test_all_null_bytes_64(self):
        value = 0x0000000000000000
        lines = encode_qword(value, COMMON)
        result = _eval_r64_lines(lines)
        assert result == 0

    def test_custom_register(self):
        lines = encode_qword(0x1122334455667788, COMMON, reg="rbx")
        for line in lines:
            assert "rbx" in line or "ebx" in line

    def test_32bit_boundary_uses_r32(self):
        lines = encode_qword(0xFFFFFFFF, COMMON)
        assert any("eax" in l for l in lines)

    def test_no_badchars_in_output_32bit(self):
        for value in [0x00, 0x0A, 0x0D00, 0x000A0000]:
            lines = encode_qword(value, COMMON)
            _assert_no_badchars_in_immediates(lines, COMMON, nbytes=4)

    def test_no_badchars_in_output_64bit(self):
        for value in [0x110022000A000001, 0x0D00000011000001, 0x0100110000000D0A]:
            lines = encode_qword(value, COMMON)
            _assert_no_badchars_in_immediates(lines, COMMON)

    def test_truncation_to_64_bits(self):
        big = 0x1_FFFFFFFFFFFFFFFF
        lines = encode_qword(big, COMMON)
        result = _eval_r64_lines(lines)
        assert result == big & 0xFFFFFFFFFFFFFFFF

    def test_scratch_register_for_r10(self):
        value = 0x110022000A000001
        lines = encode_qword(value, COMMON, reg="r10")
        assert any("rax" in l or "eax" in l for l in lines)

    def test_scratch_register_for_r11(self):
        value = 0x110022000A000001
        lines = encode_qword(value, COMMON, reg="r11")
        assert any("rax" in l or "eax" in l for l in lines)


# ---------------------------------------------------------------------------
# encode_dword_into_r64
# ---------------------------------------------------------------------------

class TestEncodeDwordIntoR64:
    def test_clean_value(self):
        lines = encode_dword_into_r64(0x12345678, COMMON)
        assert lines == ["    mov  eax, 0x12345678"]

    def test_dirty_value_uses_xor(self):
        lines = encode_dword_into_r64(0x0A000001, COMMON)
        assert len(lines) == 2
        assert "xor" in lines[1]

    def test_decodes_correctly(self):
        value = 0x0A0D0001
        lines = encode_dword_into_r64(value, COMMON)
        result = _eval_r64_lines(lines)
        assert result == value

    def test_no_badchars_in_output(self):
        for value in [0x00000000, 0x0A0D0001, 0x000000FF]:
            lines = encode_dword_into_r64(value, COMMON)
            _assert_no_badchars_in_immediates(lines, COMMON, nbytes=4)

    def test_custom_register(self):
        lines = encode_dword_into_r64(0x12345678, COMMON, reg="rcx")
        assert "ecx" in lines[0]

    def test_r8_through_r15(self):
        for reg in ["r8", "r9", "r12", "r15"]:
            lines = encode_dword_into_r64(0x12345678, COMMON, reg=reg)
            r32 = _r64_to_r32(reg)
            assert r32 in lines[0]

    def test_truncation_to_32_bits(self):
        lines = encode_dword_into_r64(0x1_DEADBEEF, COMMON)
        result = _eval_r64_lines(lines)
        assert result == 0xDEADBEEF


# ---------------------------------------------------------------------------
# Register mapping helpers
# ---------------------------------------------------------------------------

class TestRegisterHelpers:
    def test_r64_to_r32_standard(self):
        assert _r64_to_r32("rax") == "eax"
        assert _r64_to_r32("rbx") == "ebx"
        assert _r64_to_r32("rsp") == "esp"

    def test_r64_to_r32_extended(self):
        assert _r64_to_r32("r8") == "r8d"
        assert _r64_to_r32("r15") == "r15d"

    def test_r64_to_r32_unknown_passthrough(self):
        assert _r64_to_r32("xmm0") == "xmm0"

    def test_scratch_map_default(self):
        assert _scratch_r64("rax") == "r11"
        assert _scratch_r64("rcx") == "r11"
        assert _scratch_r64("rbx") == "r11"

    def test_scratch_map_avoids_self(self):
        assert _scratch_r64("r10") == "rax"
        assert _scratch_r64("r11") == "rax"

    def test_scratch_unknown_defaults_r11(self):
        assert _scratch_r64("xmm0") == "r11"

    def test_reg_to_r64_from_r32(self):
        assert _reg_to_r64("eax") == "rax"
        assert _reg_to_r64("r8d") == "r8"

    def test_reg_to_r64_from_r64(self):
        assert _reg_to_r64("rax") == "rax"
        assert _reg_to_r64("r15") == "r15"

    def test_reg_to_r64_from_r16(self):
        assert _reg_to_r64("ax") == "rax"
        assert _reg_to_r64("r8w") == "r8"

    def test_safe_tmp_no_conflict(self):
        assert _safe_tmp("rax", "r11") == "r11"
        assert _safe_tmp("rcx", "r11") == "r11"

    def test_safe_tmp_with_conflict(self):
        result = _safe_tmp("r11", "r11")
        assert result != "r11"
        assert result == "rax"

    def test_safe_tmp_r32_alias_conflict(self):
        result = _safe_tmp("eax", "r11")
        assert result == "r11"
        result = _safe_tmp("r11d", "r11")
        assert result != "r11"


# ---------------------------------------------------------------------------
# _fmt_offset
# ---------------------------------------------------------------------------

class TestFmtOffset:
    def test_zero(self):
        assert _fmt_offset(0) == ""

    def test_positive_small(self):
        assert _fmt_offset(0x10) == "+0x10"

    def test_positive_large(self):
        assert _fmt_offset(0x200) == "+0x200"

    def test_negative(self):
        assert _fmt_offset(-0x45) == "-0x45"


# ---------------------------------------------------------------------------
# _disp_has_badchar
# ---------------------------------------------------------------------------

class TestDispHasBadchar:
    def test_zero_is_clean(self):
        assert not _disp_has_badchar(0, COMMON)

    def test_small_positive_clean(self):
        assert not _disp_has_badchar(0x10, COMMON)

    def test_small_positive_dirty(self):
        assert _disp_has_badchar(0x0A, COMMON)

    def test_small_negative_clean(self):
        assert not _disp_has_badchar(-0x10, COMMON)

    def test_small_negative_dirty(self):
        assert _disp_has_badchar(-0x45, {0xBB})

    def test_large_offset_dirty(self):
        assert _disp_has_badchar(0x100, COMMON)

    def test_large_offset_clean(self):
        assert not _disp_has_badchar(0x12345678, COMMON)


# ---------------------------------------------------------------------------
# safe_qword_store
# ---------------------------------------------------------------------------

DIRTY_BC = {0x00, 0x0A, 0x0D, 0xBB}


class TestSafeQwordStore:
    def test_clean_offset_single_mov(self):
        lines = safe_qword_store("rsp", 0x20, "rax", COMMON)
        assert len(lines) == 1
        assert "qword ptr [rsp+0x20]" in lines[0]

    def test_dirty_offset_uses_tmp(self):
        lines = safe_qword_store("rsp", -0x45, "rax", DIRTY_BC)
        assert len(lines) > 1
        assert any("add" in l for l in lines)
        assert lines[-1].startswith("    mov  qword ptr [")

    def test_zero_offset(self):
        lines = safe_qword_store("rsp", 0, "rcx", COMMON)
        assert lines == ["    mov  qword ptr [rsp], rcx"]

    def test_tmp_avoids_src_conflict(self):
        lines = safe_qword_store("rsp", -0x45, "r11", DIRTY_BC)
        for line in lines:
            if "add" in line:
                parts = line.split()
                tmp_used = parts[1].rstrip(",")
                assert tmp_used != "r11"


# ---------------------------------------------------------------------------
# safe_dword_store_x64
# ---------------------------------------------------------------------------

class TestSafeDwordStoreX64:
    def test_clean_offset(self):
        lines = safe_dword_store_x64("rsp", 0x10, "eax", COMMON)
        assert len(lines) == 1
        assert "dword ptr [rsp+0x10]" in lines[0]

    def test_dirty_offset(self):
        lines = safe_dword_store_x64("rsp", -0x45, "eax", DIRTY_BC)
        assert len(lines) > 1
        assert lines[-1].startswith("    mov  dword ptr [")


# ---------------------------------------------------------------------------
# safe_word_store_x64
# ---------------------------------------------------------------------------

class TestSafeWordStoreX64:
    def test_clean_offset(self):
        lines = safe_word_store_x64("rsp", 0x10, "ax", COMMON)
        assert len(lines) == 1
        assert "word ptr [rsp+0x10]" in lines[0]

    def test_dirty_offset(self):
        lines = safe_word_store_x64("rsp", -0x45, "ax", DIRTY_BC)
        assert len(lines) > 1
        assert lines[-1].startswith("    mov  word ptr [")


# ---------------------------------------------------------------------------
# safe_mem_load_x64
# ---------------------------------------------------------------------------

class TestSafeMemLoadX64:
    def test_clean_qword_load(self):
        lines = safe_mem_load_x64("rax", "rsp", 0x20, COMMON)
        assert lines == ["    mov  rax, [rsp+0x20]"]

    def test_clean_dword_load(self):
        lines = safe_mem_load_x64("eax", "rsp", 0x20, COMMON, width="dword")
        assert lines == ["    mov  eax, dword ptr [rsp+0x20]"]

    def test_clean_word_load(self):
        lines = safe_mem_load_x64("ax", "rsp", 0x20, COMMON, width="word")
        assert lines == ["    mov  ax, word ptr [rsp+0x20]"]

    def test_clean_byte_load(self):
        lines = safe_mem_load_x64("al", "rsp", 0x20, COMMON, width="byte")
        assert lines == ["    mov  al, byte ptr [rsp+0x20]"]

    def test_dirty_offset_uses_tmp(self):
        lines = safe_mem_load_x64("rax", "rsp", -0x45, DIRTY_BC)
        assert len(lines) > 1
        assert any("add" in l for l in lines)

    def test_tmp_avoids_base_conflict(self):
        lines = safe_mem_load_x64("rax", "r11", -0x45, DIRTY_BC)
        for line in lines:
            if "add" in line:
                parts = line.split()
                tmp_used = parts[1].rstrip(",")
                assert tmp_used != "r11"


# ---------------------------------------------------------------------------
# safe_lea_x64
# ---------------------------------------------------------------------------

class TestSafeLeaX64:
    def test_clean_offset(self):
        lines = safe_lea_x64("rcx", "rsp", 0x20, COMMON)
        assert lines == ["    lea  rcx, [rsp+0x20]"]

    def test_dirty_offset(self):
        lines = safe_lea_x64("rcx", "rsp", -0x45, DIRTY_BC)
        assert len(lines) > 1
        assert any("add" in l for l in lines)

    def test_dst_equals_tmp_no_extra_mov(self):
        lines = safe_lea_x64("r11", "rsp", -0x45, DIRTY_BC)
        assert not any("mov  r11, r11" in l for l in lines)

    def test_dst_differs_from_tmp_has_mov(self):
        lines = safe_lea_x64("rcx", "rsp", -0x45, DIRTY_BC)
        assert any("mov  rcx" in l for l in lines)


# ---------------------------------------------------------------------------
# safe_call_mem_x64
# ---------------------------------------------------------------------------

class TestSafeCallMemX64:
    def test_clean_offset(self):
        lines = safe_call_mem_x64("rbp", 0x20, COMMON)
        assert lines == ["    call qword ptr [rbp+0x20]"]

    def test_dirty_offset(self):
        lines = safe_call_mem_x64("rbp", -0x45, DIRTY_BC)
        assert len(lines) > 1
        assert lines[-1].startswith("    call qword ptr [")

    def test_tmp_avoids_base_conflict(self):
        lines = safe_call_mem_x64("r11", -0x45, DIRTY_BC)
        for line in lines:
            if "add" in line:
                parts = line.split()
                tmp_used = parts[1].rstrip(",")
                assert tmp_used != "r11"


# ---------------------------------------------------------------------------
# No-badchar guarantee across all safe_* helpers
# ---------------------------------------------------------------------------

class TestNoBadcharsInDisplacements:
    """When a dirty offset forces the indirect path, the displacement must
    not appear as a raw immediate in any instruction."""

    OFFSET = 0x0D0A
    BC = {0x00, 0x0A, 0x0D}

    def _check(self, lines: list[str]):
        _assert_no_badchars_in_immediates(lines, self.BC, nbytes=4)

    def test_qword_store(self):
        self._check(safe_qword_store("rsp", self.OFFSET, "rax", self.BC))

    def test_dword_store(self):
        self._check(safe_dword_store_x64("rsp", self.OFFSET, "eax", self.BC))

    def test_word_store(self):
        self._check(safe_word_store_x64("rsp", self.OFFSET, "ax", self.BC))

    def test_mem_load(self):
        self._check(safe_mem_load_x64("rax", "rsp", self.OFFSET, self.BC))

    def test_lea(self):
        self._check(safe_lea_x64("rcx", "rsp", self.OFFSET, self.BC))

    def test_call_mem(self):
        self._check(safe_call_mem_x64("rbp", self.OFFSET, self.BC))
