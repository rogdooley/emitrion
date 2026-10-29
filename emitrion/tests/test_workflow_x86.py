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
from emitrion.workflow.ir import ExitStrategy
from emitrion.workflow.reference import (
    WorkflowTemplate,
    build_bind_shell_workflow,
    build_check_path_workflow,
    build_copy_file_workflow,
    build_copy_then_run_workflow,
    build_move_then_run_workflow,
    build_reverse_shell_workflow,
    build_run_command_workflow,
    IRCheckPathTemplate,
    IRCopyFileTemplate,
    IRCopyThenRunTemplate,
    IRMoveThenRunTemplate,
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
# IR Bind Shell Workflow
# ---------------------------------------------------------------------------


class TestBindShellWorkflow:
    def test_workflow_is_valid(self):
        from emitrion.workflow.validator import validate
        w = build_bind_shell_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_workflow_has_eight_blocks(self):
        w = build_bind_shell_workflow()
        assert len(w.blocks) == 8
        names = {b.name for b in w.blocks}
        assert names == {
            "entry", "create_socket", "bind_socket",
            "listen_socket_block", "accept_conn",
            "setup_process", "success", "fail",
        }

    def test_workflow_with_custom_params(self):
        from emitrion.workflow.validator import validate
        w = build_bind_shell_workflow(lport=8080, command="powershell.exe")
        result = validate(w)
        assert result.valid, result.errors


class TestBindShellTemplate:
    def test_probe_slots_finds_apis(self):
        w = build_bind_shell_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig(lport=4444)
        slots = tmpl.probe_slots(config)
        assert "WSAStartup" in slots
        assert "WSASocketA" in slots
        assert "bind" in slots
        assert "listen" in slots
        assert "accept" in slots
        assert "CreateProcessA" in slots
        assert "ExitProcess" in slots

    def test_probe_slots_finds_structs(self):
        w = build_bind_shell_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig(lport=4444)
        slots = tmpl.probe_slots(config)
        assert "WSADATA" in slots
        assert "sockaddr_in" in slots
        assert "STARTUPINFOA" in slots
        assert "PROCESS_INFORMATION" in slots

    def test_probe_structs(self):
        w = build_bind_shell_workflow()
        tmpl = WorkflowTemplate(w)
        structs = tmpl.probe_structs()
        assert structs == {
            "wsadata": "WSADATA",
            "sa": "sockaddr_in",
            "si": "STARTUPINFOA",
            "pi": "PROCESS_INFORMATION",
        }

    def test_probe_slots_finds_variables(self):
        w = build_bind_shell_workflow()
        tmpl = WorkflowTemplate(w)
        config = TemplateConfig(lport=4444)
        slots = tmpl.probe_slots(config)
        assert "listen_socket" in slots
        assert "client_socket" in slots
        assert "bind_ret" in slots
        assert "listen_ret" in slots
        assert "cpa_ret" in slots


class TestBindShellLowering:
    """Test that the IR bind shell lowers to valid assembly."""

    @pytest.fixture
    def bindshell_asm(self, manifest_dir):
        from emitrion.build import build
        config = TemplateConfig(lport=4444)
        result = build(
            str(manifest_dir / "bindshell.yaml"),
            template_name="ir_bind_shell",
            config=config,
            out_dir="/dev/null",
            assemble=False,
        )
        return result.asm

    def test_contains_all_block_labels(self, bindshell_asm):
        for label in ("wf_entry:", "wf_create_socket:", "wf_bind_socket:",
                       "wf_listen_socket_block:", "wf_accept_conn:",
                       "wf_setup_process:", "wf_success:", "wf_fail:"):
            assert label in bindshell_asm, f"Missing label: {label}"

    def test_contains_api_calls(self, bindshell_asm):
        for api in ("WSAStartup", "WSASocketA", "bind", "listen",
                     "accept", "CreateProcessA", "ExitProcess"):
            assert api in bindshell_asm, f"Missing API: {api}"

    def test_contains_struct_operations(self, bindshell_asm):
        assert "si.cb" in bindshell_asm
        assert "si.dwFlags" in bindshell_asm
        assert "si.hStdInput" in bindshell_asm
        assert "si.hStdOutput" in bindshell_asm
        assert "si.hStdError" in bindshell_asm

    def test_contains_branching(self, bindshell_asm):
        assert "test eax, eax" in bindshell_asm or "cmp  eax" in bindshell_asm

    def test_no_null_bytes_in_immediates(self, bindshell_asm):
        import re
        for match in re.finditer(r'mov\s+\w+,\s+0x([0-9a-f]{8})', bindshell_asm):
            hex_val = match.group(1)
            for i in range(0, 8, 2):
                byte_str = hex_val[i:i+2]
                assert byte_str != "00", (
                    f"Null byte in immediate: 0x{hex_val}"
                )


class TestBindShellClobberLiveness:
    """Prove that stored results survive subsequent argument lowering.

    _resolve_value always clobbers eax. When a NameRef("listen_socket")
    appears as an argument to listen/accept, the backend must reload it
    from its stack slot, not rely on a stale eax from the previous push.
    Same for client_socket in the setup_process block.
    """

    @pytest.fixture
    def bindshell_asm(self, manifest_dir):
        from emitrion.build import build
        config = TemplateConfig(lport=4444)
        result = build(
            str(manifest_dir / "bindshell.yaml"),
            template_name="ir_bind_shell",
            config=config,
            out_dir="/dev/null",
            assemble=False,
        )
        return result.asm

    def _extract_block(self, asm: str, label: str) -> str:
        """Extract assembly between wf_<label>: and the next top-level block label.

        Internal labels like wf_zero_si: appear mid-block and must not
        act as block boundaries.
        """
        import re
        block_labels = {
            "entry", "create_socket", "bind_socket",
            "listen_socket_block", "accept_conn",
            "setup_process", "success", "fail",
        }
        boundary = "|".join(rf"wf_{b}:" for b in block_labels if b != label)
        pattern = rf'wf_{label}:.*?(?=\n(?:{boundary})|hang:|$)'
        match = re.search(pattern, asm, re.DOTALL)
        assert match, f"Block wf_{label} not found"
        return match.group(0)

    def test_listen_socket_loaded_from_stack_for_bind(self, bindshell_asm):
        """bind(listen_socket, ...) must load listen_socket from [ebp-0xNN]."""
        block = self._extract_block(bindshell_asm, "bind_socket")
        import re
        loads = re.findall(r'mov\s+eax,\s*\[ebp[+-]0x[0-9a-f]+\]', block)
        assert len(loads) >= 1, (
            "bind block must load listen_socket from a stack slot"
        )

    def test_listen_socket_loaded_from_stack_for_listen(self, bindshell_asm):
        """listen(listen_socket, 1) must load listen_socket from its slot."""
        block = self._extract_block(bindshell_asm, "listen_socket_block")
        import re
        loads = re.findall(r'mov\s+eax,\s*\[ebp[+-]0x[0-9a-f]+\]', block)
        assert len(loads) >= 1, (
            "listen block must load listen_socket from a stack slot"
        )

    def test_listen_socket_loaded_from_stack_for_accept(self, bindshell_asm):
        """accept(listen_socket, NULL, NULL) must reload from the slot."""
        block = self._extract_block(bindshell_asm, "accept_conn")
        import re
        loads = re.findall(r'mov\s+eax,\s*\[ebp[+-]0x[0-9a-f]+\]', block)
        assert len(loads) >= 1, (
            "accept block must load listen_socket from a stack slot"
        )

    def test_client_socket_loaded_from_stack_for_stdio(self, bindshell_asm):
        """hStdInput/Output/Error must load client_socket from its slot.

        client_socket is stored by accept's result. setup_process uses it
        three times for WriteStructField. Each use must reload from the
        stack because _resolve_value clobbers eax on every call.
        """
        block = self._extract_block(bindshell_asm, "setup_process")
        import re
        loads = re.findall(r'mov\s+eax,\s*\[ebp[+-]0x[0-9a-f]+\]', block)
        assert len(loads) >= 3, (
            f"setup_process must load client_socket at least 3 times "
            f"(hStdInput/Output/Error), found {len(loads)}"
        )

    def test_client_socket_slot_consistent(self, bindshell_asm):
        """The slot used for client_socket in accept and setup_process must match."""
        import re
        accept_block = self._extract_block(bindshell_asm, "accept_conn")
        setup_block = self._extract_block(bindshell_asm, "setup_process")

        accept_stores = re.findall(
            r'mov\s+\[ebp-(0x[0-9a-f]+)\],\s*eax\s*\n\s*;\s*->\s*client_socket',
            accept_block,
        )
        assert len(accept_stores) == 1, "accept must store client_socket once"
        cs_offset = accept_stores[0]

        stdio_loads = re.findall(
            rf'mov\s+eax,\s*\[ebp-{cs_offset}\]',
            setup_block,
        )
        assert len(stdio_loads) >= 3, (
            f"setup_process must load client_socket (ebp-{cs_offset}) "
            f"at least 3 times for hStdInput/Output/Error, found {len(stdio_loads)}"
        )


class TestBindShellEndToEnd:
    """Test that the IR bind shell builds through the full pipeline."""

    def test_build_no_assemble(self, manifest_dir, tmp_path):
        from emitrion.build import build
        config = TemplateConfig(lport=4444)
        result = build(
            str(manifest_dir / "bindshell.yaml"),
            template_name="ir_bind_shell",
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert "main:" in result.asm
        assert result.contract_md
        assert "WSAStartup" in result.contract_md
        assert "bind" in result.contract_md
        assert "listen" in result.contract_md
        assert "accept" in result.contract_md
        assert "CreateProcessA" in result.contract_md

    def test_build_write_outputs(self, manifest_dir, tmp_path):
        from emitrion.build import build, write_outputs
        config = TemplateConfig(lport=4444)
        result = build(
            str(manifest_dir / "bindshell.yaml"),
            template_name="ir_bind_shell",
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
        config = TemplateConfig(lport=4444)
        result1 = build(
            str(manifest_dir / "bindshell.yaml"),
            template_name="ir_bind_shell",
            config=config,
            out_dir=str(tmp_path / "a"),
            assemble=False,
        )
        result2 = build(
            str(manifest_dir / "bindshell.yaml"),
            template_name="ir_bind_shell",
            config=config,
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


# ---------------------------------------------------------------------------
# Copy file workflow
# ---------------------------------------------------------------------------


class TestCopyFileWorkflow:
    def test_workflow_is_valid(self):
        from emitrion.workflow.validator import validate
        w = build_copy_file_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_workflow_has_three_blocks(self):
        w = build_copy_file_workflow()
        assert len(w.blocks) == 3
        names = {b.name for b in w.blocks}
        assert names == {"entry", "success", "fail"}


class TestCopyFileTemplate:
    def test_probe_slots_finds_apis(self):
        tmpl = IRCopyFileTemplate()
        config = TemplateConfig(src_path=r"C:\a.txt", dst_path=r"C:\b.txt")
        slots = tmpl.probe_slots(config)
        assert "CopyFileA" in slots
        assert "ExitProcess" in slots

    def test_probe_slots_finds_strings(self):
        tmpl = IRCopyFileTemplate()
        config = TemplateConfig(src_path=r"C:\a.txt", dst_path=r"C:\b.txt")
        slots = tmpl.probe_slots(config)
        assert "src_path" in slots
        assert "dst_path" in slots


class TestCopyFileLowering:
    @pytest.fixture
    def lowered_asm(self, manifest_dir):
        from emitrion.build import build
        result = build(
            str(manifest_dir / "ir_copy_file.yaml"),
            template_name="ir_copy_file",
            out_dir="/dev/null",
            assemble=False,
        )
        return result.asm

    def test_contains_workflow_labels(self, lowered_asm):
        assert "wf_entry:" in lowered_asm
        assert "wf_success:" in lowered_asm
        assert "wf_fail:" in lowered_asm

    def test_contains_copy_file_call(self, lowered_asm):
        assert "CopyFileA" in lowered_asm

    def test_contains_exit_process(self, lowered_asm):
        assert "ExitProcess" in lowered_asm

    def test_bfailif_exists_is_zero(self, lowered_asm):
        assert "push 0x00000000" in lowered_asm or "xor" in lowered_asm


class TestCopyFileEndToEnd:
    def test_build_produces_assembly(self, manifest_dir, tmp_path, monkeypatch):
        from emitrion.build import build
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        result = build(
            str(manifest_dir / "ir_copy_file.yaml"),
            template_name="ir_copy_file",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert result.contract_md


# ---------------------------------------------------------------------------
# Copy then run workflow
# ---------------------------------------------------------------------------


class TestCopyThenRunWorkflow:
    def test_workflow_is_valid(self):
        from emitrion.workflow.validator import validate
        w = build_copy_then_run_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_workflow_has_four_blocks(self):
        w = build_copy_then_run_workflow()
        assert len(w.blocks) == 4
        names = {b.name for b in w.blocks}
        assert names == {"entry", "run_payload", "success", "fail"}


class TestCopyThenRunTemplate:
    def test_probe_slots_finds_apis(self):
        tmpl = IRCopyThenRunTemplate()
        config = TemplateConfig(
            src_path=r"C:\src.exe", dst_path=r"C:\dst.exe",
        )
        slots = tmpl.probe_slots(config)
        assert "CopyFileA" in slots
        assert "WinExec" in slots
        assert "ExitProcess" in slots


class TestCopyThenRunLowering:
    @pytest.fixture
    def lowered_asm(self, manifest_dir):
        from emitrion.build import build
        result = build(
            str(manifest_dir / "ir_copy_then_run.yaml"),
            template_name="ir_copy_then_run",
            out_dir="/dev/null",
            assemble=False,
        )
        return result.asm

    def test_contains_run_payload_label(self, lowered_asm):
        assert "wf_run_payload:" in lowered_asm

    def test_contains_winexec(self, lowered_asm):
        assert "WinExec" in lowered_asm

    def test_copy_before_exec(self, lowered_asm):
        copy_pos = lowered_asm.index("CopyFileA")
        exec_pos = lowered_asm.index("WinExec")
        assert copy_pos < exec_pos


class TestCopyThenRunEndToEnd:
    def test_build_produces_assembly(self, manifest_dir, tmp_path, monkeypatch):
        from emitrion.build import build
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        result = build(
            str(manifest_dir / "ir_copy_then_run.yaml"),
            template_name="ir_copy_then_run",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert result.contract_md


# ---------------------------------------------------------------------------
# Move then run workflow
# ---------------------------------------------------------------------------


class TestMoveThenRunWorkflow:
    def test_workflow_is_valid(self):
        from emitrion.workflow.validator import validate
        w = build_move_then_run_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_workflow_has_four_blocks(self):
        w = build_move_then_run_workflow()
        assert len(w.blocks) == 4
        names = {b.name for b in w.blocks}
        assert names == {"entry", "run_payload", "success", "fail"}


class TestMoveThenRunTemplate:
    def test_probe_slots_finds_apis(self):
        tmpl = IRMoveThenRunTemplate()
        config = TemplateConfig(
            src_path=r"\\share\p.exe", dst_path=r"C:\dst.exe",
        )
        slots = tmpl.probe_slots(config)
        assert "MoveFileA" in slots
        assert "WinExec" in slots
        assert "ExitProcess" in slots


class TestMoveThenRunLowering:
    @pytest.fixture
    def lowered_asm(self, manifest_dir):
        from emitrion.build import build
        result = build(
            str(manifest_dir / "ir_move_then_run.yaml"),
            template_name="ir_move_then_run",
            out_dir="/dev/null",
            assemble=False,
        )
        return result.asm

    def test_contains_movefile(self, lowered_asm):
        assert "MoveFileA" in lowered_asm

    def test_move_before_exec(self, lowered_asm):
        move_pos = lowered_asm.index("MoveFileA")
        exec_pos = lowered_asm.index("WinExec")
        assert move_pos < exec_pos


class TestMoveThenRunEndToEnd:
    def test_build_produces_assembly(self, manifest_dir, tmp_path, monkeypatch):
        from emitrion.build import build
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        result = build(
            str(manifest_dir / "ir_move_then_run.yaml"),
            template_name="ir_move_then_run",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert result.contract_md


# ---------------------------------------------------------------------------
# Check path workflow
# ---------------------------------------------------------------------------


class TestCheckPathWorkflow:
    def test_workflow_is_valid(self):
        from emitrion.workflow.validator import validate
        w = build_check_path_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_workflow_has_three_blocks(self):
        w = build_check_path_workflow()
        assert len(w.blocks) == 3
        names = {b.name for b in w.blocks}
        assert names == {"entry", "success", "fail"}


class TestCheckPathTemplate:
    def test_probe_slots_finds_apis(self):
        tmpl = IRCheckPathTemplate()
        config = TemplateConfig(dst_path=r"C:\test.exe")
        slots = tmpl.probe_slots(config)
        assert "GetFileAttributesA" in slots
        assert "ExitProcess" in slots

    def test_probe_slots_finds_path_attrs(self):
        tmpl = IRCheckPathTemplate()
        config = TemplateConfig(dst_path=r"C:\test.exe")
        slots = tmpl.probe_slots(config)
        assert "path_attrs" in slots


class TestCheckPathLowering:
    @pytest.fixture
    def lowered_asm(self, manifest_dir):
        from emitrion.build import build
        result = build(
            str(manifest_dir / "ir_check_path.yaml"),
            template_name="ir_check_path",
            out_dir="/dev/null",
            assemble=False,
        )
        return result.asm

    def test_contains_get_file_attributes(self, lowered_asm):
        assert "GetFileAttributesA" in lowered_asm

    def test_invalid_handle_check(self, lowered_asm):
        assert "0xffffffff" in lowered_asm.lower() or "INVALID" in lowered_asm


class TestCheckPathEndToEnd:
    def test_build_produces_assembly(self, manifest_dir, tmp_path, monkeypatch):
        from emitrion.build import build
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        result = build(
            str(manifest_dir / "ir_check_path.yaml"),
            template_name="ir_check_path",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert result.contract_md


# ---------------------------------------------------------------------------
# Exit strategy tests (cross-workflow)
# ---------------------------------------------------------------------------


class TestExitStrategy:
    """Verify that all three exit strategies produce correct IR blocks."""

    @pytest.fixture(params=[
        ("ir_copy_file", build_copy_file_workflow),
        ("ir_run_command", build_run_command_workflow),
        ("ir_check_path", build_check_path_workflow),
    ])
    def builder(self, request):
        return request.param

    def test_exit_process_calls_exit(self, builder):
        _, build_fn = builder
        w = build_fn(exit_strategy=ExitStrategy.EXIT_PROCESS)
        success_block = next(b for b in w.blocks if b.name == "success")
        ops = [type(op).__name__ for op in success_block.operations]
        assert "CallAPI" in ops
        call = next(op for op in success_block.operations if hasattr(op, "api_name"))
        assert call.api_name == "ExitProcess"

    def test_terminate_process_uses_pseudo_handle(self, builder):
        _, build_fn = builder
        w = build_fn(exit_strategy=ExitStrategy.TERMINATE_PROCESS)
        success_block = next(b for b in w.blocks if b.name == "success")
        call = next(op for op in success_block.operations if hasattr(op, "api_name"))
        assert call.api_name == "TerminateProcess"
        assert call.arguments[0].value == 0xFFFFFFFF

    def test_thread_only_has_no_api_call(self, builder):
        _, build_fn = builder
        w = build_fn(exit_strategy=ExitStrategy.THREAD_ONLY)
        success_block = next(b for b in w.blocks if b.name == "success")
        ops = [type(op).__name__ for op in success_block.operations]
        assert "CallAPI" not in ops
        assert "Terminate" in ops

    def test_terminate_process_fail_uses_exit_code_1(self, builder):
        _, build_fn = builder
        w = build_fn(exit_strategy=ExitStrategy.TERMINATE_PROCESS)
        fail_block = next(b for b in w.blocks if b.name == "fail")
        call = next(op for op in fail_block.operations if hasattr(op, "api_name"))
        assert call.arguments[1].value == 1


class TestExitStrategyAssembly:
    """Verify exit strategies produce correct lowered assembly."""

    def test_terminate_process_in_assembly(self, manifest_dir, monkeypatch):
        from emitrion.build import build
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        config = TemplateConfig(
            src_path=r"C:\a.txt",
            dst_path=r"C:\b.txt",
            exit_strategy="terminate_process",
        )
        result = build(
            str(manifest_dir / "ir_copy_file.yaml"),
            template_name="ir_copy_file",
            config=config,
            out_dir="/dev/null",
            assemble=False,
        )
        assert "TerminateProcess" in result.asm
        assert "0xffffffff" in result.asm.lower()

    def test_thread_only_hangs_without_exit_call(self, manifest_dir, monkeypatch):
        from emitrion.build import build
        import re
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        config = TemplateConfig(
            src_path=r"C:\a.txt",
            dst_path=r"C:\b.txt",
            exit_strategy="thread_only",
        )
        result = build(
            str(manifest_dir / "ir_copy_file.yaml"),
            template_name="ir_copy_file",
            config=config,
            out_dir="/dev/null",
            assemble=False,
        )
        success_start = result.asm.index("wf_success:")
        fail_start = result.asm.index("wf_fail:", success_start)
        success_body = result.asm[success_start:fail_start]
        assert "jmp" in success_body
        assert "call" not in success_body
