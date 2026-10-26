"""Tests for api_emitter.emit_api_resolution."""
from __future__ import annotations

import pytest


@pytest.fixture
def revshell_asm(manifest_dir, revshell_layout):
    from emitrion.api_emitter import emit_api_resolution
    from emitrion.schema import load
    manifest = load(str(manifest_dir / "revshell.yaml"))
    return emit_api_resolution(manifest, revshell_layout)


def test_createprocessa_hash(revshell_asm):
    assert "0x16b3fe72" in revshell_asm


def test_createprocessa_slot(revshell_asm):
    assert "[ebp-0x28]" in revshell_asm


def test_createprocessa_name_in_comment(revshell_asm):
    assert "CreateProcessA" in revshell_asm


def test_call_instruction_present(revshell_asm):
    assert "call resolve_export_by_hash" in revshell_asm


def test_wsastartup_hash(revshell_asm):
    assert "0x3bfcedcb" in revshell_asm


def test_connect_hash(revshell_asm):
    assert "0x60aaf9ec" in revshell_asm


def test_loadlibrarya_hash(revshell_asm):
    assert "0xec0e4e8e" in revshell_asm


def test_all_functions_present(revshell_asm, manifest_dir):
    from emitrion.schema import load
    manifest = load(str(manifest_dir / "revshell.yaml"))
    for name in manifest.functions:
        assert name in revshell_asm, f"{name} not found in output"


def test_all_hashes_correct(revshell_asm, manifest_dir):
    """Verify every hash is present - either as a plain mov or XOR-encoded pair."""
    import re

    from emitrion.hash_gen import ror13
    from emitrion.schema import load
    manifest = load(str(manifest_dir / "revshell.yaml"))
    for name in manifest.functions:
        expected = ror13(name)
        hex_str = f"0x{expected:08x}"
        if hex_str in revshell_asm:
            continue
        # Hash was XOR-encoded - find mov+xor pair after the function comment
        comment_pos = revshell_asm.index(name)
        block = revshell_asm[comment_pos:comment_pos + 200]
        mov_m = re.search(r'mov\s+eax,\s+0x([0-9a-f]{8})', block)
        xor_m = re.search(r'xor\s+eax,\s+0x([0-9a-f]{8})', block)
        assert mov_m and xor_m, (
            f"Hash for {name} ({hex_str}) not found as plain or XOR-encoded"
        )
        decoded = int(mov_m.group(1), 16) ^ int(xor_m.group(1), 16)
        assert decoded == expected, (
            f"XOR-decoded hash for {name}: got 0x{decoded:08x}, want {hex_str}"
        )


def test_all_slots_present(revshell_asm, revshell_layout, manifest_dir):
    from emitrion.schema import load
    manifest = load(str(manifest_dir / "revshell.yaml"))
    for name in manifest.functions:
        slot_ref = revshell_layout.slot(name).ebp_ref
        assert slot_ref in revshell_asm, f"Slot for {name} ({slot_ref}) not found"


def test_module_headers_present(revshell_asm):
    assert "kernel32.dll" in revshell_asm
    assert "ws2_32.dll" in revshell_asm


def test_kernel32_before_ws2_32(revshell_asm):
    k32_pos = revshell_asm.index("kernel32.dll")
    ws2_pos = revshell_asm.index("ws2_32.dll")
    assert k32_pos < ws2_pos


def test_no_trailing_whitespace(revshell_asm):
    for i, line in enumerate(revshell_asm.splitlines(), 1):
        assert line == line.rstrip(), f"Trailing whitespace on line {i}: {line!r}"


def test_no_payload_instructions(revshell_asm):
    forbidden = [
        "call find_module",
        "call get_export_directory",
        "call save_export_context",
        "call ws2_32",
        "jmp",
        "ret",
        "main:",
    ]
    for f in forbidden:
        assert f not in revshell_asm, f"Forbidden instruction/label found: {f!r}"


def test_calc_manifest_minimal(manifest_dir):
    from emitrion.api_emitter import emit_api_resolution
    from emitrion.schema import load
    from emitrion.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "calc.yaml"))
    layout = build_layout(manifest)
    asm = emit_api_resolution(manifest, layout)
    assert "WinExec" in asm
    assert "ExitProcess" in asm
    assert "WSAStartup" not in asm
    assert "0x0e8afe98" in asm   # WinExec hash
    assert "0x73e2d87e" in asm   # ExitProcess hash
