"""x64 backend: lower validated Workflow IR to Windows x64 assembly text.

Generates the payload section of the assembly output for x64 targets.
Implements Microsoft x64 calling convention:
  - First 4 integer/pointer args in RCX, RDX, R8, R9
  - 32-byte shadow space always reserved by caller
  - Additional args on the stack (RSP+0x28, RSP+0x30, ...)
  - 16-byte stack alignment at CALL instruction
  - Return value in RAX

All stack references go through StackLayoutX64.slot().rsp_ref so the
allocation system owns physical offsets.

Entry assumptions for x64 shellcode:
  - RSP is 8-byte aligned but NOT 16-byte aligned (standard after a CALL)
  - The prologue adjusts RSP to achieve 16-byte alignment
  - No assumptions about register contents except RSP
"""
from __future__ import annotations

import socket
import struct

from ..api_database import STRUCT_DATABASE, STRUCT_DATABASE_X64
from ..encode_x64 import (
    encode_dword_into_r64,
    encode_qword,
    safe_call_mem_x64,
    safe_dword_store_x64,
    safe_lea_x64,
    safe_mem_load_x64,
    safe_qword_store,
    safe_word_store_x64,
)
from ..stack_alloc_x64 import StackLayoutX64
from .catalog import get_abi
from .ir import (
    AddressOf,
    AddressOfField,
    AllocateLocal,
    AllocateStruct,
    ArithOp,
    Block,
    CallAPI,
    CallSlot,
    CarveBuffer,
    Compare,
    CompareStrings,
    ConstructString,
    DefineConstant,
    Immediate,
    Input,
    Jump,
    MemCopy,
    NameRef,
    Operation,
    ReadStructField,
    SuccessPredicate,
    Terminate,
    TerminateStyle,
    ValueRef,
    Workflow,
    WriteSlot,
    WriteStructField,
    ZeroStruct,
)

_ARG_REGS = ("rcx", "rdx", "r8", "r9")

_WORD_REG_X64 = {
    "rax": "ax", "rbx": "bx", "rcx": "cx", "rdx": "dx",
    "rsi": "si", "rdi": "di", "rbp": "bp", "rsp": "sp",
    "r8": "r8w", "r9": "r9w", "r10": "r10w", "r11": "r11w",
    "eax": "ax", "ecx": "cx", "edx": "dx",
    "r8d": "r8w", "r9d": "r9w",
}

_DWORD_REG_X64 = {
    "rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
    "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp",
    "r8": "r8d", "r9": "r9d", "r10": "r10d", "r11": "r11d",
    "r12": "r12d", "r13": "r13d", "r14": "r14d", "r15": "r15d",
}


def lower_workflow_x64(
    workflow: Workflow,
    layout: StackLayoutX64,
    badchars: set[int],
    config: object | None = None,
) -> str:
    """Lower a validated Workflow IR to x64 assembly text.

    Returns the payload section only. The caller is responsible for
    framework stubs, API resolution, string construction, and
    structure initialization.
    """
    ctx = _LoweringContextX64(layout, badchars, config)
    lines: list[str] = []

    lines.append(f"; -- Workflow (x64): {workflow.name} --")
    lines.append("")

    lowered = {block.name: ctx.lower_block(block) for block in workflow.blocks}

    terminal = [b.name for b in workflow.blocks if _is_terminal(b)]
    normal = [b.name for b in workflow.blocks if not _is_terminal(b)]

    if terminal and workflow.entry in normal:
        lines.append(f"    jmp  wf_{workflow.entry}")
        lines.append("")
        for name in terminal:
            lines.extend(lowered[name])
        for name in normal:
            lines.extend(lowered[name])
    else:
        for block in workflow.blocks:
            lines.extend(lowered[block.name])

    return "\n".join(lines)


def _is_terminal(block: Block) -> bool:
    return any(isinstance(op, (Terminate, CallSlot)) for op in block.operations)


class _LoweringContextX64:
    """Stateful lowering context for x64 workflow lowering."""

    def __init__(
        self,
        layout: StackLayoutX64,
        badchars: set[int],
        config: object | None,
    ) -> None:
        self.layout = layout
        self.bc = badchars
        self.config = config
        self.constants: dict[str, int] = {}
        self.struct_types: dict[str, str] = {}
        self._hang_counter = 0
        self._strcmp_counter = 0

    def lower_block(self, block: Block) -> list[str]:
        lines: list[str] = []
        lines.append(f"wf_{block.name}:")
        for op in block.operations:
            lines.extend(self._lower_op(op))
        lines.append("")
        return lines

    def _lower_op(self, op: Operation) -> list[str]:
        if isinstance(op, DefineConstant):
            self.constants[op.name] = op.value
            return [f"    ; const {op.name} = 0x{op.value:x}"]

        if isinstance(op, AllocateStruct):
            self.struct_types[op.name] = op.struct_type
            return []

        if isinstance(op, (ConstructString, AllocateLocal)):
            return []

        if isinstance(op, ReadStructField):
            return self._lower_read_struct_field(op)

        if isinstance(op, ZeroStruct):
            return self._lower_zero_struct(op)

        if isinstance(op, WriteStructField):
            return self._lower_write_struct_field(op)

        if isinstance(op, CallAPI):
            return self._lower_call(op)

        if isinstance(op, WriteSlot):
            return self._lower_write_slot(op)

        if isinstance(op, ArithOp):
            return self._lower_arith(op)

        if isinstance(op, CarveBuffer):
            return self._lower_carve_buffer(op)

        if isinstance(op, MemCopy):
            return self._lower_mem_copy(op)

        if isinstance(op, Compare):
            return self._lower_compare(op)

        if isinstance(op, CompareStrings):
            return self._lower_compare_strings(op)

        if isinstance(op, Jump):
            return [f"    jmp  wf_{op.target}"]

        if isinstance(op, CallSlot):
            return self._lower_call_slot(op)

        if isinstance(op, Terminate):
            return self._lower_terminate(op)

        raise ValueError(f"Unsupported IR operation for x64: {type(op).__name__}")

    def _resolve_value(self, ref: ValueRef, target_reg: str = "rax") -> tuple[list[str], str]:
        """Resolve a value ref to (setup_lines, register).

        Places the value into target_reg and returns that register name.
        For Immediate(0), uses xor r32, r32 for zero-extension.
        """
        r32 = _DWORD_REG_X64.get(target_reg, target_reg)

        if isinstance(ref, Immediate):
            if ref.value == 0:
                return ([f"    xor  {r32}, {r32}"], target_reg)
            if 0 < ref.value <= 0xFFFFFFFF:
                lines = list(encode_dword_into_r64(ref.value, self.bc, target_reg))
                return (lines, target_reg)
            lines = list(encode_qword(ref.value, self.bc, target_reg))
            return (lines, target_reg)

        if isinstance(ref, NameRef):
            name = ref.name
            if name in self.constants:
                val = self.constants[name]
                if val == 0:
                    return ([f"    xor  {r32}, {r32}"], target_reg)
                if 0 < val <= 0xFFFFFFFF:
                    lines = list(encode_dword_into_r64(val, self.bc, target_reg))
                    return (lines, target_reg)
                lines = list(encode_qword(val, self.bc, target_reg))
                return (lines, target_reg)
            slot = self.layout.slot(name)
            lines = list(safe_mem_load_x64(target_reg, "rsp", slot.offset, self.bc))
            return (lines, target_reg)

        if isinstance(ref, AddressOf):
            name = ref.name
            stype = self.struct_types.get(name)
            if stype is not None:
                slot = self.layout.slot(stype)
            else:
                slot = self.layout.slot(name)
            lines = list(safe_lea_x64(target_reg, "rsp", slot.offset, self.bc))
            return (lines, target_reg)

        if isinstance(ref, AddressOfField):
            stype = self.struct_types.get(ref.struct_name)
            if stype is None:
                err = f"    ; ERROR: AddressOfField struct '{ref.struct_name}' unknown"
                return ([err], target_reg)
            st_rec = STRUCT_DATABASE_X64.get(stype) or STRUCT_DATABASE.get(stype)
            if st_rec is None:
                return ([f"    ; ERROR: struct type '{stype}' not in database"], target_reg)
            field_info = None
            for f in st_rec.fields:
                if f.name == ref.field_name:
                    field_info = f
                    break
            if field_info is None:
                return ([f"    ; ERROR: field '{ref.field_name}' not in '{stype}'"], target_reg)
            struct_slot = self.layout.slot(stype)
            field_abs = struct_slot.offset + field_info.offset
            lines = list(safe_lea_x64(target_reg, "rsp", field_abs, self.bc))
            return (lines, target_reg)

        if isinstance(ref, Input):
            return self._resolve_input(ref, target_reg)

        return ([], target_reg)

    def _resolve_input(self, ref: Input, target_reg: str = "rax") -> tuple[list[str], str]:
        r32 = _DWORD_REG_X64.get(target_reg, target_reg)

        if self.config is None:
            return ([f"    ; WARNING: no config for Input('{ref.name}')"], target_reg)

        name = ref.name
        val = getattr(self.config, name, None)
        if val is None:
            return ([f"    ; WARNING: config has no '{name}'"], target_reg)

        if isinstance(val, int):
            if val == 0:
                return ([f"    xor  {r32}, {r32}"], target_reg)
            if 0 < val <= 0xFFFFFFFF:
                lines = list(encode_dword_into_r64(val, self.bc, target_reg))
                return (lines, target_reg)
            lines = list(encode_qword(val, self.bc, target_reg))
            return (lines, target_reg)

        if isinstance(val, str):
            if name == "lhost":
                ip_le = struct.unpack("<I", socket.inet_aton(val))[0]
                lines = list(encode_dword_into_r64(ip_le, self.bc, target_reg))
                return (lines, target_reg)
            slot = self.layout.slot(name)
            lines = list(safe_lea_x64(target_reg, "rsp", slot.offset, self.bc))
            return (lines, target_reg)

        return ([f"    ; WARNING: cannot resolve Input('{name}')"], target_reg)

    def _lower_call(self, op: CallAPI) -> list[str]:
        """Lower a CallAPI to Microsoft x64 calling convention.

        Arguments 0-3 go in RCX, RDX, R8, R9.
        Arguments 4+ go on the stack at [RSP+0x20], [RSP+0x28], etc.
        Shadow space (32 bytes) is always reserved at [RSP+0x00..0x1F].
        The stack must be 16-byte aligned at the CALL instruction.
        """
        lines: list[str] = []
        api_slot = self.layout.slot(op.api_name)

        abi = get_abi(op.api_name)
        arg_names = []
        if abi:
            arg_names = [a.name for a in abi.arguments]

        lines.append("")
        proto = f"{op.api_name}({', '.join(arg_names)})" if arg_names else op.api_name
        lines.append(f"    ; {proto}")

        args = list(op.arguments)

        for i in range(4, len(args)):
            arg = args[i]
            arg_name = arg_names[i] if i < len(arg_names) else f"arg{i}"
            setup, reg = self._resolve_value(arg, "rax")
            lines.extend(setup)
            stack_offset = 0x20 + (i - 4) * 8
            lines.extend(safe_qword_store("rsp", stack_offset, reg, self.bc))
            lines.append(f"    ; stack arg {arg_name}")

        reg_args = min(len(args), 4)

        for i in range(reg_args):
            arg = args[i]
            arg_name = arg_names[i] if i < len(arg_names) else f"arg{i}"
            target = _ARG_REGS[i]
            setup, reg = self._resolve_value(arg, target)
            lines.extend(setup)
            if reg != target:
                lines.append(f"    mov  {target}, {reg}")
            lines.append(f"    ; {arg_name}")

        lines.extend(safe_call_mem_x64("rsp", api_slot.offset, self.bc))

        if op.result is not None:
            result_slot = self.layout.slot(op.result)
            lines.extend(safe_qword_store("rsp", result_slot.offset, "rax", self.bc))
            lines.append(f"    ; -> {op.result}")

        return lines

    def _lower_write_slot(self, op: WriteSlot) -> list[str]:
        """Lower a WriteSlot to a mov into the slot's RSP-relative location."""
        lines: list[str] = []
        lines.append(f"    ; {op.name} = ...")
        setup, reg = self._resolve_value(op.value)
        lines.extend(setup)
        slot = self.layout.slot(op.name)
        lines.extend(safe_qword_store("rsp", slot.offset, reg, self.bc))
        return lines

    def _lower_write_struct_field(self, op: WriteStructField) -> list[str]:
        stype = self.struct_types.get(op.struct_name)
        if stype is None:
            raise ValueError(
                f"WriteStructField references '{op.struct_name}' which has no "
                f"AllocateStruct in the workflow. "
                f"Add AllocateStruct('{op.struct_name}', ...) first."
            )

        st_rec = STRUCT_DATABASE_X64.get(stype) or STRUCT_DATABASE.get(stype)
        if st_rec is None:
            raise ValueError(
                f"Struct type '{stype}' (from '{op.struct_name}') not found in "
                f"STRUCT_DATABASE or STRUCT_DATABASE_X64."
            )

        field_info = None
        for f in st_rec.fields:
            if f.name == op.field_name:
                field_info = f
                break

        if field_info is None:
            raise ValueError(
                f"Field '{op.field_name}' not found in struct '{stype}'. "
                f"Available fields: {[f.name for f in st_rec.fields]}"
            )

        lines: list[str] = []
        lines.append(f"    ; {op.struct_name}.{op.field_name}")

        setup, reg = self._resolve_value(op.value, "rax")
        lines.extend(setup)

        struct_slot = self.layout.slot(stype)
        field_abs = struct_slot.offset + field_info.offset

        if field_info.size <= 2:
            word_reg = _WORD_REG_X64.get(reg, reg)
            lines.extend(safe_word_store_x64("rsp", field_abs, word_reg, self.bc))
        elif field_info.size <= 4:
            dword_reg = _DWORD_REG_X64.get(reg, reg)
            lines.extend(safe_dword_store_x64("rsp", field_abs, dword_reg, self.bc))
        else:
            lines.extend(safe_qword_store("rsp", field_abs, reg, self.bc))

        return lines

    def _lower_zero_struct(self, op: ZeroStruct) -> list[str]:
        stype = self.struct_types.get(op.name)
        if stype is None:
            raise ValueError(
                f"ZeroStruct references '{op.name}' which has no "
                f"AllocateStruct in the workflow. Add AllocateStruct('{op.name}', ...) first."
            )

        st_rec = STRUCT_DATABASE_X64.get(stype) or STRUCT_DATABASE.get(stype)
        if st_rec is None:
            raise ValueError(
                f"Struct type '{stype}' (from '{op.name}') not found in "
                f"STRUCT_DATABASE or STRUCT_DATABASE_X64."
            )

        size = st_rec.size
        slot = self.layout.slot(stype)
        offset = slot.offset

        qwords = size // 8
        remainder = size % 8
        lines: list[str] = []
        lines.append(f"    ; zero {op.name} ({stype}, 0x{size:x} bytes)")
        lines.append("    xor  eax, eax")
        lines.extend(safe_lea_x64("rdi", "rsp", offset, self.bc))

        if qwords <= 6:
            for i in range(qwords):
                lines.extend(safe_qword_store("rdi", i * 8, "rax", self.bc))
            if remainder >= 4:
                lines.extend(safe_dword_store_x64("rdi", qwords * 8, "eax", self.bc))
        else:
            lines.append(f"    mov  ecx, 0x{qwords:02x}")
            lines.append("    rep  stosq")
            if remainder >= 4:
                lines.append("    stosd")

        return lines

    def _lower_compare(self, op: Compare) -> list[str]:
        lines: list[str] = []
        slot = self.layout.slot(op.value)
        lines.extend(safe_mem_load_x64("rax", "rsp", slot.offset, self.bc))

        if op.predicate == SuccessPredicate.NONZERO:
            lines.append("    test rax, rax")
            lines.append(f"    jnz  wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate in (SuccessPredicate.ZERO, SuccessPredicate.NULL):
            lines.append("    test rax, rax")
            lines.append(f"    jz   wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.INVALID_HANDLE:
            lines.extend(encode_qword(0xFFFFFFFFFFFFFFFF, self.bc, "r11"))
            if 0x3b in self.bc:
                lines.append("    sub  rax, r11")
            else:
                lines.append("    cmp  rax, r11")
            lines.append(f"    jne  wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.SIGNED_NEGATIVE:
            lines.append("    test rax, rax")
            lines.append(f"    jns  wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.SIGNED_POSITIVE:
            lines.append("    test rax, rax")
            lines.append(f"    jg   wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")

        return lines

    def _lower_arith(self, op: ArithOp) -> list[str]:
        """Lower ArithOp: load left into r11, load right into rax, operate, store."""
        lines: list[str] = []
        op_word = op.operator
        lines.append(f"    ; {op.result} = ... {op_word} ...")

        left_setup, _left_reg = self._resolve_value(op.left)
        lines.extend(left_setup)
        lines.append("    mov  r11, rax")

        right_setup, _right_reg = self._resolve_value(op.right)
        lines.extend(right_setup)

        if op_word == "add":
            lines.append("    add  r11, rax")
        else:
            lines.append("    sub  r11, rax")

        result_slot = self.layout.slot(op.result)
        lines.extend(safe_qword_store("rsp", result_slot.offset, "r11", self.bc))
        return lines

    def _lower_read_struct_field(self, op: ReadStructField) -> list[str]:
        """Lower ReadStructField: load a value from a struct field into a slot."""
        stype = self.struct_types.get(op.struct_name)
        if stype is None:
            return [f"    ; ERROR: ReadStructField struct '{op.struct_name}' unknown"]
        st_rec = STRUCT_DATABASE_X64.get(stype) or STRUCT_DATABASE.get(stype)
        if st_rec is None:
            return [f"    ; ERROR: struct type '{stype}' not in database"]
        field_info = None
        for f in st_rec.fields:
            if f.name == op.field_name:
                field_info = f
                break
        if field_info is None:
            return [f"    ; ERROR: field '{op.field_name}' not in '{stype}'"]

        lines: list[str] = []
        lines.append(f"    ; {op.result} = {op.struct_name}.{op.field_name}")
        struct_slot = self.layout.slot(stype)
        field_abs = struct_slot.offset + field_info.offset
        if field_info.size <= 4:
            lines.extend(safe_mem_load_x64("rax", "rsp", field_abs, self.bc, width="dword"))
        else:
            lines.extend(safe_mem_load_x64("rax", "rsp", field_abs, self.bc))
        result_slot = self.layout.slot(op.result)
        lines.extend(safe_qword_store("rsp", result_slot.offset, "rax", self.bc))
        return lines

    def _lower_compare_strings(self, op: CompareStrings) -> list[str]:
        """Lower CompareStrings to inline byte-by-byte comparison loop."""
        lines: list[str] = []
        lines.append("    ; strcmp")

        left_setup, _ = self._resolve_value(op.left)
        lines.extend(left_setup)
        lines.append("    mov  rsi, rax")

        right_setup, _ = self._resolve_value(op.right)
        lines.extend(right_setup)
        lines.append("    mov  rdi, rax")

        cmp_label = f"wf_strcmp_{self._strcmp_counter}"
        end_label = f"wf_strcmp_end_{self._strcmp_counter}"
        self._strcmp_counter += 1

        lines.append(f"{cmp_label}:")
        lines.append("    lodsb")
        lines.append("    mov  cl, byte [rdi]")
        lines.append("    inc  rdi")
        lines.append("    test al, al")
        lines.append(f"    jz   {end_label}")
        if op.case_insensitive:
            lines.append("    or   al, 0x20")
            lines.append("    or   cl, 0x20")
        lines.append("    cmp  al, cl")
        lines.append(f"    jne  wf_{op.nomatch_block}")
        lines.append(f"    jmp  {cmp_label}")

        lines.append(f"{end_label}:")
        lines.append("    test cl, cl")
        lines.append(f"    jz   wf_{op.match_block}")
        lines.append(f"    jmp  wf_{op.nomatch_block}")

        return lines

    def _lower_carve_buffer(self, op: CarveBuffer) -> list[str]:
        """Lower CarveBuffer: sub rsp, size; mov [rsp+slot], rsp.

        On x64, CarveBuffer adjusts RSP directly. The carved space
        sits below the managed frame.
        """
        lines: list[str] = []
        lines.append(f"    ; carve {op.name} ({op.size} bytes below RSP)")
        size_lines = list(encode_dword_into_r64(op.size, self.bc, "rax"))
        lines.extend(size_lines)
        lines.append("    sub  rsp, rax")
        slot = self.layout.slot(op.name)
        lines.extend(safe_qword_store("rsp", slot.offset, "rsp", self.bc))
        return lines

    def _lower_mem_copy(self, op: MemCopy) -> list[str]:
        """Lower MemCopy: set up rsi/rdi/rcx then cld; rep movsb."""
        lines: list[str] = []
        lines.append("    ; memcopy")

        src_setup, _ = self._resolve_value(op.src)
        lines.extend(src_setup)
        lines.append("    mov  rsi, rax")

        dst_setup, _ = self._resolve_value(op.dst)
        lines.extend(dst_setup)
        lines.append("    mov  rdi, rax")

        count_setup, _ = self._resolve_value(op.count)
        lines.extend(count_setup)
        lines.append("    mov  rcx, rax")

        lines.append("    cld")
        lines.append("    rep movsb")
        return lines

    def _lower_call_slot(self, op: CallSlot) -> list[str]:
        """Lower a CallSlot to call [rsp+offset] (transfer to shellcode)."""
        lines: list[str] = []
        slot = self.layout.slot(op.target)
        lines.append(f"    ; call [{op.target}]")
        lines.extend(safe_call_mem_x64("rsp", slot.offset, self.bc))
        return lines

    def _lower_write_slot(self, op: WriteSlot) -> list[str]:
        """Lower a WriteSlot to a mov into the slot's RSP-relative location."""
        lines: list[str] = []
        lines.append(f"    ; {op.name} = ...")
        setup, reg = self._resolve_value(op.value)
        lines.extend(setup)
        slot = self.layout.slot(op.name)
        lines.extend(safe_qword_store("rsp", slot.offset, reg, self.bc))
        return lines

    def _lower_terminate(self, op: Terminate) -> list[str]:
        if op.style == TerminateStyle.HANG:
            label = f"wf_hang_{self._hang_counter}"
            self._hang_counter += 1
            return [
                f"{label}:",
                f"    jmp  {label}",
            ]
        return ["    ; unknown terminate style"]
