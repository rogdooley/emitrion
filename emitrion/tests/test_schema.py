"""Tests for schema.py manifest loading and validation."""
from __future__ import annotations

import pytest

from ..schema import load


def test_load_revshell(manifest_dir):
    m = load(str(manifest_dir / "revshell.yaml"))
    assert "CreateProcessA" in m.functions
    assert "WSAStartup" in m.functions
    assert 0x00 in m.badchars
    assert 0x0a in m.badchars


def test_load_calc(manifest_dir):
    m = load(str(manifest_dir / "calc.yaml"))
    assert m.functions == ["WinExec", "ExitProcess"]
    assert 0x00 in m.badchars
    assert len(m.strings) == 1
    assert m.strings[0].label == "cmd"
    assert m.strings[0].value == "calc.exe"
    assert m.strings[0].method == "mov"


def test_unknown_api_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("badchars: ['00']\nfunctions:\n  - FakeAPI\nstrings: []\n")
    with pytest.raises(ValueError, match="Unknown API"):
        load(str(bad))


def test_duplicate_function_raises(tmp_path):
    bad = tmp_path / "dup.yaml"
    bad.write_text("badchars: ['00']\nfunctions:\n  - WinExec\n  - WinExec\nstrings: []\n")
    with pytest.raises(ValueError, match="Duplicate function"):
        load(str(bad))


def test_unknown_string_method_raises(tmp_path):
    bad = tmp_path / "badmethod.yaml"
    content = (
        "badchars: ['00']\nfunctions:\n  - WinExec\n"
        "strings:\n  - label: x\n    value: x.exe\n    method: magic\n"
    )
    bad.write_text(content)
    with pytest.raises(ValueError, match="Unknown string method"):
        load(str(bad))


def test_duplicate_string_label_raises(tmp_path):
    bad = tmp_path / "duplabel.yaml"
    content = (
        "badchars: ['00']\nfunctions:\n  - WinExec\n"
        "strings:\n"
        "  - label: cmd\n    value: cmd.exe\n    method: push\n"
        "  - label: cmd\n    value: other.exe\n    method: push\n"
    )
    bad.write_text(content)
    with pytest.raises(ValueError, match="Duplicate string label"):
        load(str(bad))


def test_invalid_dest_register_raises(tmp_path):
    bad = tmp_path / "badreg.yaml"
    content = (
        "badchars: ['00']\nfunctions:\n  - WinExec\n"
        "strings:\n  - label: x\n    value: x.exe\n    method: mov\n    dest: r8\n"
    )
    bad.write_text(content)
    with pytest.raises(ValueError, match="Invalid dest register"):
        load(str(bad))


def test_multiple_errors_reported_together(tmp_path):
    bad = tmp_path / "multi.yaml"
    content = (
        "badchars: ['00']\nfunctions:\n  - FakeAPI\n  - FakeAPI2\n"
        "strings: []\n"
    )
    bad.write_text(content)
    with pytest.raises(ValueError) as exc_info:
        load(str(bad))
    msg = str(exc_info.value)
    assert "FakeAPI" in msg
    assert "FakeAPI2" in msg


def test_no_silent_fallback_for_orphan_module(tmp_path):
    # covered by test_api_database.py::test_all_modules_are_known
    pass


# ---------------------------------------------------------------------------
# Variable validation (emitter-v1 schema extension)
# ---------------------------------------------------------------------------

def test_variables_loaded(manifest_dir):
    m = load(str(manifest_dir / "revshell.yaml"))
    names = [v.name for v in m.variables]
    assert "socket_handle" in names


def test_no_variables_defaults_empty(manifest_dir):
    m = load(str(manifest_dir / "calc.yaml"))
    assert m.variables == []


def test_duplicate_variable_raises(tmp_path):
    bad = tmp_path / "dupvar.yaml"
    bad.write_text(
        "badchars: ['00']\nfunctions:\n  - WinExec\nstrings: []\n"
        "variables:\n  - socket_handle\n  - socket_handle\n"
    )
    with pytest.raises(ValueError, match="Duplicate variable"):
        load(str(bad))


def test_variable_slot_allocated(revshell_layout):
    slot = revshell_layout.slot("socket_handle")
    assert slot.category == "variable"
    assert slot.size == 4


def test_variable_slot_after_api_slots(revshell_layout):
    connect_slot = revshell_layout.slot("connect")
    socket_slot = revshell_layout.slot("socket_handle")
    assert socket_slot.offset > connect_slot.offset


def test_variable_slot_before_struct_zone(revshell_layout):
    from emitrion.stack_alloc import STRUCT_ZONE_START
    socket_slot = revshell_layout.slot("socket_handle")
    assert socket_slot.offset + socket_slot.size <= STRUCT_ZONE_START


# ---------------------------------------------------------------------------
# Manifest template field
# ---------------------------------------------------------------------------

def test_template_loaded_from_manifest(manifest_dir):
    m = load(str(manifest_dir / "calc.yaml"))
    assert m.template == "run_command"


def test_template_defaults_none(tmp_path):
    f = tmp_path / "no_tmpl.yaml"
    f.write_text("badchars: ['00']\nfunctions:\n  - WinExec\nstrings: []\n")
    m = load(str(f))
    assert m.template is None


def test_unknown_template_raises(tmp_path):
    f = tmp_path / "bad_tmpl.yaml"
    f.write_text(
        "template: fake_template\nbadchars: ['00']\n"
        "functions:\n  - WinExec\nstrings: []\n"
    )
    with pytest.raises(ValueError, match="Unknown template"):
        load(str(f))
