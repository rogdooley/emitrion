"""Tests for encode.py - badchar-safe immediate encoding."""

from emitrion.encode import (
    encode_dword,
    encode_word,
    safe_push_dword,
    safe_push_word_as_dword,
)

COMMON = {0x00, 0x0a, 0x0d}


# ---------------------------------------------------------------------------
# encode_dword
# ---------------------------------------------------------------------------

class TestEncodeDword:
    def test_clean_value_single_mov(self):
        lines = encode_dword(0x12345678, COMMON)
        assert lines == ["    mov  eax, 0x12345678"]

    def test_null_byte_produces_xor_pair(self):
        lines = encode_dword(0x00000001, COMMON)
        assert len(lines) == 2
        assert lines[0].startswith("    mov  eax,")
        assert lines[1].startswith("    xor  eax,")

    def test_result_decodes_correctly(self):
        value = 0xc0a8010a  # 192.168.1.10 in big-endian
        lines = encode_dword(value, COMMON)
        # Parse and verify: mov then optional xor
        result = _eval_dword_lines(lines)
        assert result == value

    def test_null_ip_encodes_correctly(self):
        # 192.168.1.0 - last byte is 0x00
        value = 0xc0a80100
        lines = encode_dword(value, COMMON)
        assert _eval_dword_lines(lines) == value

    def test_all_null_bytes(self):
        lines = encode_dword(0x00000000, COMMON)
        assert _eval_dword_lines(lines) == 0x00000000

    def test_custom_register(self):
        lines = encode_dword(0xdeadbeef, COMMON, reg="ebx")
        for line in lines:
            assert "ebx" in line

    def test_no_badchars_in_output(self):
        for value in [0x00000000, 0xc0a8010a, 0x00003000, 0x40000000]:
            lines = encode_dword(value, COMMON)
            for line in lines:
                for token in line.split():
                    if token.startswith("0x"):
                        raw = int(token.rstrip(","), 16)
                        for i in range(4):
                            byte = (raw >> (8 * i)) & 0xFF
                            assert byte not in COMMON, (
                                f"Badchar 0x{byte:02x} in encoded output for value 0x{value:08x}"
                            )


# ---------------------------------------------------------------------------
# encode_word
# ---------------------------------------------------------------------------

class TestEncodeWord:
    def test_clean_value_single_mov(self):
        lines = encode_word(0x1234, COMMON)
        assert lines == ["    mov  ax, 0x1234"]

    def test_null_byte_produces_xor_pair(self):
        lines = encode_word(0x0202, COMMON)  # MAKEWORD(2,2) zero-extended has no null in word itself
        # 0x0202 bytes are 0x02, 0x02 - both clean
        assert lines == ["    mov  ax, 0x0202"]

    def test_port_with_null(self):
        # Port 256 big-endian = 0x0100 - low byte is 0x00
        value = 0x0100
        lines = encode_word(value, COMMON)
        assert _eval_word_lines(lines) == value

    def test_no_badchars_in_output(self):
        for value in [0x0100, 0x0d00, 0x0a0d]:
            lines = encode_word(value, COMMON)
            for line in lines:
                for token in line.split():
                    if token.startswith("0x"):
                        raw = int(token.rstrip(","), 16)
                        for i in range(2):
                            byte = (raw >> (8 * i)) & 0xFF
                            assert byte not in COMMON

    def test_custom_register(self):
        lines = encode_word(0x1234, COMMON, reg="bx")
        for line in lines:
            assert "bx" in line


# ---------------------------------------------------------------------------
# safe_push_dword
# ---------------------------------------------------------------------------

class TestSafePushDword:
    def test_ends_with_push_eax(self):
        lines = safe_push_dword(0xdeadbeef, COMMON)
        assert lines[-1] == "    push eax"

    def test_clean_value_two_lines(self):
        lines = safe_push_dword(0x12345678, COMMON)
        assert len(lines) == 2  # mov + push

    def test_dirty_value_three_lines(self):
        lines = safe_push_dword(0x00000080, COMMON)
        assert len(lines) == 3  # mov + xor + push

    def test_file_attribute_normal(self):
        # 0x80 has null bytes when encoded as imm32 - this was the sign-extension bug
        lines = safe_push_dword(0x80, COMMON)
        result = _eval_dword_lines(lines[:-1])  # exclude push
        assert result == 0x80


# ---------------------------------------------------------------------------
# safe_push_word_as_dword
# ---------------------------------------------------------------------------

class TestSafePushWordAsDword:
    def test_starts_with_xor(self):
        lines = safe_push_word_as_dword(0x0202, COMMON)
        assert lines[0] == "    xor  eax, eax"

    def test_ends_with_push_eax(self):
        lines = safe_push_word_as_dword(0x0202, COMMON)
        assert lines[-1] == "    push eax"

    def test_makeword_2_2(self):
        # 0x0202: both bytes clean, should be three lines: xor + mov + push
        lines = safe_push_word_as_dword(0x0202, COMMON)
        assert len(lines) == 3

    def test_dirty_word(self):
        # 0x0a02: 0x0a is a badchar
        lines = safe_push_word_as_dword(0x0a02, COMMON)
        assert len(lines) == 4  # xor + mov + xor + push


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _eval_dword_lines(lines: list[str]) -> int:
    """Simulate 'mov reg, X' and optional 'xor reg, Y', return final value."""
    val = 0
    for line in lines:
        parts = line.split()
        if parts[0] == "mov":
            val = int(parts[2].rstrip(","), 16)
        elif parts[0] == "xor":
            val ^= int(parts[2].rstrip(","), 16)
    return val


def _eval_word_lines(lines: list[str]) -> int:
    """Same as _eval_dword_lines but masked to 16 bits."""
    return _eval_dword_lines(lines) & 0xFFFF


# ---------------------------------------------------------------------------
# ecx clobber avoidance
# ---------------------------------------------------------------------------

class TestTmpRegisterConflict:
    """Verify that memory-arithmetic helpers pick a non-conflicting scratch register.

    Offset -0x45 encodes as the DWORD 0xFFFFFFBB, so 0xBB must be in the
    badchar set to force the dirty-displacement path through _safe_addr.
    """

    DIRTY_BC = {0x00, 0x0a, 0x0d, 0xBB}

    def _assert_no_clobber(self, lines: list[str], dst: str, base: str):
        """Verify the scratch register differs from both dst and base."""
        for line in lines:
            if "add" in line and base in line and dst not in line:
                parts = line.split()
                tmp_used = parts[1].rstrip(",")
                assert tmp_used != dst, f"scratch {tmp_used} clobbers dst {dst}"
                assert tmp_used != base, f"scratch {tmp_used} clobbers base {base}"

    def test_safe_sub_from_mem_ecx_dst(self):
        from emitrion.encode import safe_sub_from_mem
        lines = safe_sub_from_mem("ecx", "ebp", -0x45, self.DIRTY_BC)
        assert len(lines) > 1, "should use dirty-displacement path"
        self._assert_no_clobber(lines, "ecx", "ebp")
        assert any("sub  ecx" in l for l in lines)

    def test_safe_sub_from_mem_base_conflict(self):
        from emitrion.encode import safe_sub_from_mem
        lines = safe_sub_from_mem("ecx", "edx", -0x45, self.DIRTY_BC)
        assert len(lines) > 1, "should use dirty-displacement path"
        self._assert_no_clobber(lines, "ecx", "edx")

    def test_safe_add_from_mem_ecx_dst(self):
        from emitrion.encode import safe_add_from_mem
        lines = safe_add_from_mem("ecx", "ebp", -0x45, self.DIRTY_BC)
        assert len(lines) > 1, "should use dirty-displacement path"
        self._assert_no_clobber(lines, "ecx", "ebp")
        assert any("add  ecx" in l for l in lines)

    def test_safe_add_to_mem_ecx_src(self):
        from emitrion.encode import safe_add_to_mem
        lines = safe_add_to_mem("ebp", -0x45, "ecx", self.DIRTY_BC)
        assert len(lines) > 1, "should use dirty-displacement path"
        self._assert_no_clobber(lines, "ecx", "ebp")

    def test_safe_cmp_with_mem_ecx_reg(self):
        from emitrion.encode import safe_cmp_with_mem
        lines = safe_cmp_with_mem("ecx", "ebp", -0x45, self.DIRTY_BC)
        assert len(lines) > 1, "should use dirty-displacement path"
        self._assert_no_clobber(lines, "ecx", "ebp")
        assert any("cmp  ecx" in l for l in lines)

    def test_pick_tmp_avoids_dst_and_base(self):
        from emitrion.encode import _pick_tmp
        assert _pick_tmp("ecx", "ecx", "ebp") != "ecx"
        assert _pick_tmp("edx", "edx", "ebp") != "edx"
        assert _pick_tmp("ecx", "eax", "ebp") == "ecx"
        result = _pick_tmp("ecx", "ecx", "edx")
        assert result not in ("ecx", "edx")


# ---------------------------------------------------------------------------
# Frame size
# ---------------------------------------------------------------------------

class TestFrameSize:

    def test_frame_size_rounds_up(self):
        import pathlib

        from emitrion.schema import load
        from emitrion.stack_alloc import build_layout
        manifest_dir = pathlib.Path(__file__).parent.parent / "manifests"
        manifest = load(str(manifest_dir / "revshell.yaml"))
        layout = build_layout(manifest)
        assert layout.frame_size >= max(s.offset for s in layout.all_slots())
        assert layout.frame_size % 0x100 == 0
