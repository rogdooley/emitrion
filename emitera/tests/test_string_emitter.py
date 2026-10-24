"""Tests for string_emitter.py."""
from __future__ import annotations

import pathlib
import sys

import pytest

_TOOLS_DIR = str(pathlib.Path(__file__).parent.parent.parent)
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)


def test_push_string_no_slot_lea(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.string_emitter import emit_string
    manifest = load(str(manifest_dir / "revshell.yaml"))
    ws2_entry = next(e for e in manifest.strings if e.method == "push")
    result = emit_string(ws2_entry, revshell_layout, manifest.badchars)
    # push method should NOT emit `lea edi, [ebp-...]` for the slot address
    slot_ref = revshell_layout.slot(ws2_entry.label).ebp_ref
    assert "push" in result
    assert f"lea  edi, {slot_ref}" not in result


def test_push_string_contains_pushes(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.string_emitter import emit_string
    manifest = load(str(manifest_dir / "revshell.yaml"))
    ws2_entry = next(e for e in manifest.strings if e.method == "push")
    result = emit_string(ws2_entry, revshell_layout, manifest.badchars)
    # emit_push ends with mov esi, esp
    assert "mov  esi, esp" in result


def test_mov_string_uses_lea_slot(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.string_emitter import emit_string
    manifest = load(str(manifest_dir / "revshell.yaml"))
    cmd_entry = next(e for e in manifest.strings if e.method == "mov")
    result = emit_string(cmd_entry, revshell_layout, manifest.badchars)
    slot_ref = revshell_layout.slot(cmd_entry.label).ebp_ref
    assert f"lea  edi, {slot_ref}" in result


def test_mov_string_delegates_to_strings_py(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.string_emitter import emit_string
    from emitera.strings import emit_mov
    manifest = load(str(manifest_dir / "revshell.yaml"))
    cmd_entry = next(e for e in manifest.strings if e.method == "mov")
    expected = emit_mov(cmd_entry.value, dest="edi", badchars=manifest.badchars)
    result = emit_string(cmd_entry, revshell_layout, manifest.badchars)
    # Every non-comment instruction line from emit_mov should appear in result
    for line in expected.asm.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(";"):
            assert line in result, f"Expected line not found: {line!r}"


def test_emit_all_strings_contains_cmd(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.string_emitter import emit_all_strings
    manifest = load(str(manifest_dir / "revshell.yaml"))
    result = emit_all_strings(manifest, revshell_layout)
    assert "cmd" in result


def test_emit_all_strings_skip_labels(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.string_emitter import emit_all_strings
    manifest = load(str(manifest_dir / "revshell.yaml"))
    # Skip ws2_dll label
    result = emit_all_strings(manifest, revshell_layout, skip_labels={"ws2_dll"})
    assert "ws2_32.dll" not in result or "cmd.exe" in result


def test_string_header_present(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.string_emitter import emit_string
    manifest = load(str(manifest_dir / "revshell.yaml"))
    cmd_entry = next(e for e in manifest.strings if e.method == "mov")
    result = emit_string(cmd_entry, revshell_layout, manifest.badchars)
    assert "; --- cmd:" in result


def test_no_null_in_immediates_push(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.string_emitter import emit_string
    import re
    manifest = load(str(manifest_dir / "revshell.yaml"))
    ws2_entry = next(e for e in manifest.strings if e.method == "push")
    result = emit_string(ws2_entry, revshell_layout, manifest.badchars)
    # extract all hex immediates that are 4 bytes (0x........ form)
    immediates = re.findall(r'\b0x([0-9a-f]{8})\b', result)
    for imm in immediates:
        val = int(imm, 16)
        for byte_pos in range(4):
            b = (val >> (byte_pos * 8)) & 0xFF
            assert b != 0x00, f"Null byte in immediate 0x{imm} in push string output"
