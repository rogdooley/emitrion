"""Tests for forwarded export detection in both x86 and x64 resolvers.

A PE forwarded export has its AddressOfFunctions RVA pointing inside the
export directory itself (to an ASCII forwarder string like "NTDLL.RtlExitUserProcess"),
not to executable code.  The resolver must detect this and trap (int3) rather than
calling the forwarder string as if it were a function address.
"""
from __future__ import annotations

import re

import pytest


class TestForwarderDetectionX64:
    """Verify the x64 framework stubs include forwarded-export detection."""

    @pytest.fixture()
    def stubs(self) -> str:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        return _emit_framework_stubs_x64(set())

    def test_forwarded_export_label_present(self, stubs: str) -> None:
        assert "forwarded_export:" in stubs

    def test_not_forwarded_label_present(self, stubs: str) -> None:
        assert "not_forwarded:" in stubs

    def test_int3_at_forwarded_export(self, stubs: str) -> None:
        lines = stubs.splitlines()
        for i, line in enumerate(lines):
            if line.strip() == "forwarded_export:":
                assert "int3" in lines[i + 1]
                return
        pytest.fail("forwarded_export label not found")

    def test_pe_header_export_dir_read(self, stubs: str) -> None:
        """The check re-derives export dir bounds from PE+0x88 and PE+0x8C."""
        assert "0x88" in stubs
        assert "0x8c" in stubs

    def test_lower_bound_check(self, stubs: str) -> None:
        """Function RVA compared against export_dir_rva (lower bound)."""
        block = _extract_resolve_block(stubs)
        assert "cmp  eax, esi" in block
        assert "jb   not_forwarded" in block

    def test_upper_bound_check(self, stubs: str) -> None:
        """Function RVA compared against export_dir_end (upper bound)."""
        block = _extract_resolve_block(stubs)
        assert "cmp  eax, edi" in block
        assert "jb   forwarded_export" in block

    def test_normal_export_path_returns(self, stubs: str) -> None:
        """The not_forwarded path adds module_base and returns."""
        block = _extract_resolve_block(stubs)
        assert "add  rax, rcx" in block
        assert "ret" in block

    def test_e_lfanew_read(self, stubs: str) -> None:
        """Reads e_lfanew from module_base + 0x3c."""
        block = _extract_resolve_block(stubs)
        assert "0x3c" in block


class TestForwarderDetectionX86:
    """Verify the x86 framework stubs include forwarded-export detection."""

    @pytest.fixture()
    def stubs(self) -> str:
        from emitrion.build import _emit_framework_stubs_part2
        return _emit_framework_stubs_part2(set())

    def test_forwarded_export_label_present(self, stubs: str) -> None:
        assert "forwarded_export:" in stubs

    def test_not_forwarded_label_present(self, stubs: str) -> None:
        assert "not_forwarded:" in stubs

    def test_int3_at_forwarded_export(self, stubs: str) -> None:
        lines = stubs.splitlines()
        for i, line in enumerate(lines):
            if line.strip() == "forwarded_export:":
                assert "int3" in lines[i + 1]
                return
        pytest.fail("forwarded_export label not found")

    def test_pe_header_export_dir_read(self, stubs: str) -> None:
        """The check re-derives export dir bounds from PE+0x78 and PE+0x7C."""
        assert "0x78" in stubs or "+0x78]" in stubs
        assert "0x7c" in stubs or "+0x7c]" in stubs

    def test_lower_bound_check(self, stubs: str) -> None:
        block = _extract_resolve_block(stubs)
        assert "cmp eax, esi" in block or "sub" in block
        assert "jb not_forwarded" in block

    def test_upper_bound_check(self, stubs: str) -> None:
        block = _extract_resolve_block(stubs)
        assert "cmp eax, edi" in block or "sub" in block
        assert "jb forwarded_export" in block

    def test_normal_export_path_returns(self, stubs: str) -> None:
        block = _extract_resolve_block(stubs)
        assert "add eax, ecx" in block
        assert "ret" in block

    def test_e_lfanew_read(self, stubs: str) -> None:
        block = _extract_resolve_block(stubs)
        assert "0x3c" in block


class TestForwarderDetectionX86Badchars:
    """Verify the x86 forwarder check works with various badchar sets."""

    def _stubs(self, badchars: set[int]) -> str:
        from emitrion.build import _emit_framework_stubs_part2
        return _emit_framework_stubs_part2(badchars)

    def test_no_badchars(self) -> None:
        stubs = self._stubs(set())
        assert "forwarded_export:" in stubs
        assert "not_forwarded:" in stubs

    def test_cmp_opcode_badchar(self) -> None:
        """When 0x3B is a badchar, cmp is replaced with sub-based comparison."""
        stubs = self._stubs({0x3b})
        block = _extract_resolve_block(stubs)
        assert "cmp eax" not in block
        assert "sub" in block
        assert "jb not_forwarded" in block
        assert "jb forwarded_export" in block

    def test_null_badchar(self) -> None:
        stubs = self._stubs({0x00})
        assert "forwarded_export:" in stubs
        assert "not_forwarded:" in stubs

    def test_common_badchars(self) -> None:
        """Standard badchar set (null, LF, CR)."""
        stubs = self._stubs({0x00, 0x0a, 0x0d})
        assert "forwarded_export:" in stubs
        assert "not_forwarded:" in stubs

    def test_pe_offset_as_badchar(self) -> None:
        """0x78 and 0x7C as badchars: safe_mem_load encodes around them."""
        stubs = self._stubs({0x78, 0x7c})
        assert "forwarded_export:" in stubs
        assert "not_forwarded:" in stubs
        block = _extract_resolve_block(stubs)
        assert "jb not_forwarded" in block
        assert "jb forwarded_export" in block

    def test_e_lfanew_offset_as_badchar(self) -> None:
        """0x3C as a badchar: safe_mem_load encodes the e_lfanew read."""
        stubs = self._stubs({0x3c})
        assert "forwarded_export:" in stubs


class TestForwarderDetectionInBuild:
    """Verify forwarder detection appears in full build output."""

    def test_x86_build_contains_forwarder_labels(self, manifest_dir) -> None:
        from emitrion.build import build
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir="/dev/null",
            assemble=False,
        )
        assert "forwarded_export:" in result.asm
        assert "not_forwarded:" in result.asm

    def test_x64_build_contains_forwarder_labels(self) -> None:
        from emitrion.build_x64 import build_x64
        result = build_x64(
            "emitrion/manifests/x64/run_command_x64.yaml",
            assemble=False,
        )
        assert "forwarded_export:" in result.asm
        assert "not_forwarded:" in result.asm


class TestForwarderDetectionInstruction:
    """Verify the actual instruction sequence is correct for the forwarder check."""

    def test_x64_check_sequence(self) -> None:
        """Validate the x64 instruction sequence: read PE header, bounds check."""
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        block = _extract_resolve_block(stubs)
        lines = [l.strip() for l in block.splitlines() if l.strip()]

        # Find the forwarder check sequence after "mov eax, dword ptr [rsi + rax*4]"
        func_rva_idx = None
        for i, line in enumerate(lines):
            if "mov  eax, dword ptr [rsi + rax*4]" in line:
                func_rva_idx = i
                break
        assert func_rva_idx is not None, "function RVA load not found"

        # After func_rva load, expect: load module_base, read e_lfanew, add,
        # read export dir RVA, cmp, jb, read export dir size, add, cmp, jb
        remaining = lines[func_rva_idx + 1:]
        ops = " ".join(remaining)
        assert "mov  rcx, qword ptr [rbp - 0x08]" in ops
        assert "0x3c" in ops
        assert "0x88" in ops
        assert "0x8c" in ops

    def test_x86_preserves_func_rva(self) -> None:
        """The x86 check pushes/pops EAX to preserve the function RVA."""
        from emitrion.build import _emit_framework_stubs_part2
        stubs = _emit_framework_stubs_part2(set())
        block = _extract_resolve_block(stubs)
        assert "push eax" in block
        assert "pop eax" in block


def _extract_resolve_block(stubs: str) -> str:
    """Extract the resolve_matched_export block from framework stubs."""
    lines = stubs.splitlines()
    start = None
    for i, line in enumerate(lines):
        if "resolve_matched_export:" in line:
            start = i
        elif start is not None and re.match(r"\S+:", line.strip()) and "not_forwarded" not in line and "forwarded_export" not in line:
            return "\n".join(lines[start:i])
    if start is not None:
        return "\n".join(lines[start:])
    return ""
