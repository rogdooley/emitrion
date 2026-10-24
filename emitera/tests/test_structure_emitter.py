"""Tests for structure_emitter.py."""
from __future__ import annotations

DEFAULT_BADCHARS = {0x00}


def test_startupinfoa_cb_field(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("STARTUPINFOA", revshell_layout, DEFAULT_BADCHARS)
    assert "0x44" in asm


def test_startupinfoa_dwflags_offset(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("STARTUPINFOA", revshell_layout, DEFAULT_BADCHARS)
    assert "0x2c" in asm


def test_startupinfoa_dwflags_value(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("STARTUPINFOA", revshell_layout, DEFAULT_BADCHARS)
    # STARTF_USESTDHANDLES = 0x100 expressed via rol
    assert "rol  eax, 8" in asm


def test_startupinfoa_slot_referenced(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("STARTUPINFOA", revshell_layout, DEFAULT_BADCHARS)
    slot_ref = revshell_layout.slot("STARTUPINFOA").ebp_ref
    assert slot_ref in asm


def test_startupinfoa_zero_loop_present(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("STARTUPINFOA", revshell_layout, DEFAULT_BADCHARS)
    assert "loop" in asm
    assert "17" in asm  # ecx = 17 for 17 DWORDs


def test_process_information_slot_referenced(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("PROCESS_INFORMATION", revshell_layout, DEFAULT_BADCHARS)
    slot_ref = revshell_layout.slot("PROCESS_INFORMATION").ebp_ref
    assert slot_ref in asm


def test_process_information_zeroed(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("PROCESS_INFORMATION", revshell_layout, DEFAULT_BADCHARS)
    assert "0x0c" in asm  # last field offset


def test_wsadata_no_instructions(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("WSADATA", revshell_layout, DEFAULT_BADCHARS)
    # WSADATA is comment-only (WSAStartup populates it)
    non_comment = [
        l for l in asm.splitlines()
        if l.strip() and not l.strip().startswith(";")
    ]
    assert len(non_comment) == 0, f"Unexpected instructions in WSADATA init: {non_comment}"


def test_sockaddr_in_sin_family(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("sockaddr_in", revshell_layout, DEFAULT_BADCHARS)
    assert "0x02" in asm  # AF_INET


def test_sockaddr_in_slot_referenced(revshell_layout):
    from emitera.structure_emitter import emit_structure
    asm = emit_structure("sockaddr_in", revshell_layout, DEFAULT_BADCHARS)
    slot_ref = revshell_layout.slot("sockaddr_in").ebp_ref
    assert slot_ref in asm


def test_emit_all_structures_all_present(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.structure_emitter import emit_all_structures
    manifest = load(str(manifest_dir / "revshell.yaml"))
    asm = emit_all_structures(manifest, revshell_layout)
    for struct_name in ("STARTUPINFOA", "PROCESS_INFORMATION", "WSADATA", "sockaddr_in"):
        assert struct_name in asm, f"{struct_name} not found in emit_all_structures output"


def test_emit_all_structures_no_duplicate_labels(manifest_dir, revshell_layout):
    from emitera.schema import load
    from emitera.structure_emitter import emit_all_structures
    manifest = load(str(manifest_dir / "revshell.yaml"))
    asm = emit_all_structures(manifest, revshell_layout)
    # Zero-loop label should appear only once (one STARTUPINFOA)
    assert asm.count("startupinfoa_zero_loop") == 2  # label definition + loop target


def test_unknown_structure_fallback(revshell_layout):
    # Inject a fake slot
    from emitera.stack_alloc import Slot, StackLayout
    from emitera.structure_emitter import emit_structure
    fake_slot = Slot(name="FakeStruct", offset=0x400, size=0x20, category="structure")
    layout = StackLayout(revshell_layout.all_slots() + [fake_slot])
    asm = emit_structure("FakeStruct", layout, DEFAULT_BADCHARS)
    assert "FakeStruct" in asm
    assert "No initialization template" in asm
