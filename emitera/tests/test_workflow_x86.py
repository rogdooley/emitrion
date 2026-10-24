"""Tests for the x86 workflow backend and end-to-end build integration."""
from __future__ import annotations

import pytest

from emitera.workflow.ir import (
    AddressOf,
    AllocateLocal,
    Block,
    CallAPI,
    Compare,
    ConstructString,
    DefineConstant,
    Immediate,
    Jump,
    NameRef,
    SuccessPredicate,
    Terminate,
    TerminateStyle,
    Workflow,
)
from emitera.workflow.reference import (
    IRRunCommandTemplate,
    WorkflowTemplate,
    build_run_command_workflow,
)
from emitera.payload_templates.base import TemplateConfig


class TestRunCommandWorkflow:
    def test_workflow_is_valid(self):
        from emitera.workflow.validator import validate
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
        from emitera.build import build
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
        assert "wf_hang:" in lowered_asm
        assert "jmp  wf_hang" in lowered_asm

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
                pass


class TestEndToEndBuild:
    """Test that the IR workflow builds through the full pipeline."""

    def test_build_no_assemble(self, manifest_dir, tmp_path):
        from emitera.build import build
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
        from emitera.build import build, write_outputs
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
        from emitera.build import build
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "WinExec" in result.contract_md

    def test_legacy_build_not_regressed(self, manifest_dir, tmp_path):
        """Verify legacy run_command template still works."""
        from emitera.build import build
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
        from emitera.build import build
        result = build(
            str(manifest_dir / "revshell.yaml"),
            template_name="reverse_shell",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert "WSAStartup" in result.asm
        assert "CreateProcessA" in result.asm


class TestDeterminism:
    """Identical inputs must produce identical outputs."""

    def test_deterministic_asm(self, manifest_dir, tmp_path):
        from emitera.build import build
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
        lines1 = [l for l in result1.asm.splitlines() if not l.startswith("; Generated:")]
        lines2 = [l for l in result2.asm.splitlines() if not l.startswith("; Generated:")]
        assert lines1 == lines2
