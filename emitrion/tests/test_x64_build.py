"""Tests for the x64 build pipeline, framework stubs, and compose_asm_x64."""
from __future__ import annotations

import pathlib
import re

import pytest

from emitrion.build_x64 import (
    _emit_framework_stubs_x64,
    _emit_stack_reserve_x64,
    _emit_strings_x64,
    _emit_struct_init_x64,
    _emit_api_resolution_x64,
    compose_asm_x64,
    generate_debug_runner_x64,
    build_x64,
)
from emitrion.payload_templates.base import TemplateConfig
from emitrion.schema import Manifest, StringEntry, VariableEntry
from emitrion.stack_alloc_x64 import build_layout_x64

MANIFEST_DIR = pathlib.Path(__file__).parent.parent / "manifests" / "x64"


def _make_manifest(
    functions: list[str] | None = None,
    variables: list[str] | None = None,
    strings: list[tuple[str, str]] | None = None,
) -> Manifest:
    return Manifest(
        badchars={0x00, 0x0A, 0x0D},
        functions=functions or [],
        strings=[
            StringEntry(label=l, value=v, method="mov", dest="rdi")
            for l, v in (strings or [])
        ],
        variables=[VariableEntry(name=n) for n in (variables or [])],
        template="ir_run_command",
        arch="x64",
    )


class TestFrameworkStubsX64:
    def test_peb_walk_uses_gs(self) -> None:
        stubs = _emit_framework_stubs_x64(set())
        assert "gs:" in stubs.lower()
        assert "0x60" in stubs

    def test_pe32plus_export_directory(self) -> None:
        stubs = _emit_framework_stubs_x64(set())
        assert "0x88" in stubs

    def test_has_all_labels(self) -> None:
        stubs = _emit_framework_stubs_x64(set())
        for label in (
            "get_first_ldr_entry:",
            "find_kernel32_entry:",
            "next_module:",
            "find_module:",
            "get_export_directory:",
            "get_export_tables:",
            "save_export_context:",
            "compute_hash:",
            "resolve_export_by_hash:",
        ):
            assert label in stubs, f"Missing label: {label}"

    def test_hash_computation(self) -> None:
        stubs = _emit_framework_stubs_x64(set())
        assert "ror" in stubs
        assert "0x0d" in stubs.lower()

    def test_no_32bit_addressing(self) -> None:
        stubs = _emit_framework_stubs_x64(set())
        assert "[esp" not in stubs
        assert "[ebp" not in stubs
        assert "fs:" not in stubs.lower()

    def test_badchar_safe_displacements(self) -> None:
        stubs_clean = _emit_framework_stubs_x64(set())
        stubs_bc = _emit_framework_stubs_x64({0x60})
        assert len(stubs_bc) >= len(stubs_clean)


class TestStackReserveX64:
    def test_produces_sub_rsp(self) -> None:
        lines = _emit_stack_reserve_x64(0x200, set())
        asm = "\n".join(lines)
        assert "sub" in asm
        assert "rsp" in asm

    def test_badchar_safe(self) -> None:
        lines = _emit_stack_reserve_x64(0x0D00, {0x0D})
        asm = "\n".join(lines)
        for line in lines:
            if "mov" in line and "0x" in line:
                match = re.search(r"0x([0-9a-fA-F]+)", line)
                if match:
                    val = int(match.group(1), 16)
                    byte_vals = [(val >> (i * 8)) & 0xFF for i in range(4)]
                    assert 0x0D not in byte_vals


class TestStringsX64:
    def test_string_construction(self) -> None:
        m = _make_manifest(
            functions=["WinExec"],
            strings=[("cmd", "calc.exe")],
        )
        layout = build_layout_x64(m)
        asm = _emit_strings_x64(m, layout)
        assert "calc.exe" in asm or "cmd" in asm

    def test_null_termination(self) -> None:
        m = _make_manifest(
            functions=["WinExec"],
            strings=[("cmd", "A")],
        )
        layout = build_layout_x64(m)
        asm = _emit_strings_x64(m, layout)
        assert "xor  eax, eax" in asm

    def test_skip_labels(self) -> None:
        m = _make_manifest(
            functions=["WinExec"],
            strings=[("cmd", "calc.exe"), ("skip_me", "foo")],
        )
        layout = build_layout_x64(m)
        asm = _emit_strings_x64(m, layout, skip_labels={"skip_me"})
        assert "skip_me" not in asm
        assert "cmd" in asm


class TestStructInitX64:
    def test_zero_init_startupinfoa(self) -> None:
        m = _make_manifest(functions=["CreateProcessA"])
        layout = build_layout_x64(m)
        asm = _emit_struct_init_x64(m, layout)
        assert "STARTUPINFOA" in asm
        assert "xor  eax, eax" in asm

    def test_uses_stosq_for_large_structs(self) -> None:
        m = _make_manifest(functions=["CreateProcessA"])
        layout = build_layout_x64(m)
        asm = _emit_struct_init_x64(m, layout)
        assert "stosq" in asm or "qword ptr" in asm


class TestComposeAsmX64:
    def test_has_bits64_directive(self) -> None:
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        asm = compose_asm_x64(m, layout, "test.yaml")
        assert "[BITS 64]" in asm

    def test_has_framework_stubs(self) -> None:
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        asm = compose_asm_x64(m, layout, "test.yaml")
        assert "find_module:" in asm
        assert "resolve_export_by_hash:" in asm

    def test_has_api_resolution(self) -> None:
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        asm = compose_asm_x64(m, layout, "test.yaml")
        assert "resolve WinExec" in asm

    def test_has_string_section(self) -> None:
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        asm = compose_asm_x64(m, layout, "test.yaml")
        assert "String Construction (x64)" in asm

    def test_hang_label(self) -> None:
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        asm = compose_asm_x64(m, layout, "test.yaml")
        assert "hang:" in asm
        assert "jmp hang" in asm


class TestDebugRunnerX64:
    def test_uses_mode_64(self) -> None:
        runner = generate_debug_runner_x64("nop")
        assert "KS_MODE_64" in runner
        assert "KS_MODE_32" not in runner

    def test_contains_shellcode(self) -> None:
        runner = generate_debug_runner_x64("xor eax, eax")
        assert "xor eax, eax" in runner

    def test_has_virtualalloc(self) -> None:
        runner = generate_debug_runner_x64("nop")
        assert "VirtualAlloc" in runner

    def test_has_windbg_address(self) -> None:
        runner = generate_debug_runner_x64("nop")
        assert "WinDbg" in runner


class TestBuildX64Integration:
    def test_run_command_no_assemble(self) -> None:
        result = build_x64(str(MANIFEST_DIR / "run_command_x64.yaml"), assemble=False)
        assert result.asm
        assert result.contract_md
        assert result.debug_runner
        assert result.shellcode_bytes is None

    def test_revshell_no_assemble(self) -> None:
        result = build_x64(str(MANIFEST_DIR / "revshell_x64.yaml"), assemble=False)
        assert result.asm
        assert "WSAStartup" in result.asm
        assert "connect" in result.asm

    def test_deterministic_output(self) -> None:
        path = str(MANIFEST_DIR / "run_command_x64.yaml")
        a = build_x64(path, assemble=False)
        b = build_x64(path, assemble=False)
        assert a.asm == b.asm
        assert a.contract_md == b.contract_md

    def test_config_override(self) -> None:
        config = TemplateConfig(arch="x64", command="powershell.exe")
        result = build_x64(
            str(MANIFEST_DIR / "run_command_x64.yaml"),
            config=config, assemble=False,
        )
        assert result.asm
