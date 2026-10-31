"""Badchar-safe immediate value encoding for x64 payload templates.

Extends the x86 encode module with 64-bit immediate and addressing helpers.
x64 instructions cannot embed 64-bit immediates directly in most cases;
mov r64, imm64 (REX.W + B8+rd) is the exception. This module provides
helpers that produce badchar-free instruction sequences for 64-bit values.
"""
from __future__ import annotations

from .encode import _find_mask_byte


def _has_badchar_bytes(value: int, nbytes: int, badchars: set[int]) -> bool:
    return any(((value >> (8 * i)) & 0xFF) in badchars for i in range(nbytes))


def encode_qword(value: int, badchars: set[int], reg: str = "rax") -> list[str]:
    """Return assembly lines that load a 64-bit value into reg, free of badchars.

    Strategy: if the value fits in 32 bits unsigned, use mov r32, imm32
    (implicit zero-extension). Otherwise use mov r64, imm64 with XOR mask.
    """
    value = value & 0xFFFFFFFFFFFFFFFF

    if value <= 0xFFFFFFFF:
        return encode_dword_into_r64(value, badchars, reg)

    v_bytes = [(value >> (8 * i)) & 0xFF for i in range(8)]
    if not any(b in badchars for b in v_bytes):
        return [f"    mov  {reg}, 0x{value:016x}"]

    mask_bytes = [_find_mask_byte(b, badchars) for b in v_bytes]
    mask = sum(m << (8 * i) for i, m in enumerate(mask_bytes))
    encoded = value ^ mask
    return [
        f"    mov  {reg}, 0x{encoded:016x}",
        f"    mov  {_scratch_r64(reg)}, 0x{mask:016x}",
        f"    xor  {reg}, {_scratch_r64(reg)}",
    ]


def encode_dword_into_r64(value: int, badchars: set[int], reg: str = "rax") -> list[str]:
    """Load a 32-bit value into a 64-bit register via zero-extending mov r32, imm32."""
    value = value & 0xFFFFFFFF
    r32 = _r64_to_r32(reg)
    v_bytes = [(value >> (8 * i)) & 0xFF for i in range(4)]
    if not any(b in badchars for b in v_bytes):
        return [f"    mov  {r32}, 0x{value:08x}"]
    mask_bytes = [_find_mask_byte(b, badchars) for b in v_bytes]
    mask = sum(m << (8 * i) for i, m in enumerate(mask_bytes))
    encoded = value ^ mask
    return [
        f"    mov  {r32}, 0x{encoded:08x}",
        f"    xor  {r32}, 0x{mask:08x}",
    ]


_R64_TO_R32 = {
    "rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
    "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp",
    "r8": "r8d", "r9": "r9d", "r10": "r10d", "r11": "r11d",
    "r12": "r12d", "r13": "r13d", "r14": "r14d", "r15": "r15d",
}

_SCRATCH_MAP = {
    "rax": "r11", "rbx": "r11", "rcx": "r11", "rdx": "r11",
    "r8": "r11", "r9": "r11", "r10": "rax", "r11": "rax",
    "rsi": "r11", "rdi": "r11", "rbp": "r11", "rsp": "r11",
    "r12": "r11", "r13": "r11", "r14": "r11", "r15": "r11",
}


_REG_FAMILY = {}
for _r64, _r32 in _R64_TO_R32.items():
    _REG_FAMILY[_r64] = _r64
    _REG_FAMILY[_r32] = _r64
for _r64, _w in {
    "rax": "ax", "rbx": "bx", "rcx": "cx", "rdx": "dx",
    "rsi": "si", "rdi": "di", "rbp": "bp", "rsp": "sp",
    "r8": "r8w", "r9": "r9w", "r10": "r10w", "r11": "r11w",
}.items():
    _REG_FAMILY[_w] = _r64


def _reg_to_r64(reg: str) -> str:
    return _REG_FAMILY.get(reg, reg)


def _safe_tmp(src_reg: str, tmp: str) -> str:
    """Pick a tmp register that does not alias src_reg."""
    if _reg_to_r64(src_reg) != _reg_to_r64(tmp):
        return tmp
    return _scratch_r64(_reg_to_r64(src_reg))


def _r64_to_r32(reg: str) -> str:
    return _R64_TO_R32.get(reg, reg)


def _scratch_r64(reg: str) -> str:
    return _SCRATCH_MAP.get(reg, "r11")


def safe_qword_store(
    base: str, offset: int, src_reg: str, badchars: set[int],
    *, tmp: str = "r11",
) -> list[str]:
    """Emit a badchar-safe mov qword ptr [base+offset], src_reg."""
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    mov  qword ptr [{base}{fmt}], {src_reg}"]
    tmp = _safe_tmp(src_reg, tmp)
    lines = list(encode_dword_into_r64(offset & 0xFFFFFFFF, badchars, tmp))
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    mov  qword ptr [{tmp}], {src_reg}")
    return lines


def safe_dword_store_x64(
    base: str, offset: int, src_reg: str, badchars: set[int],
    *, tmp: str = "r11",
) -> list[str]:
    """Emit a badchar-safe mov dword ptr [base+offset], src_reg (x64)."""
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    mov  dword ptr [{base}{fmt}], {src_reg}"]
    tmp = _safe_tmp(src_reg, tmp)
    lines = list(encode_dword_into_r64(offset & 0xFFFFFFFF, badchars, tmp))
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    mov  dword ptr [{tmp}], {src_reg}")
    return lines


def safe_word_store_x64(
    base: str, offset: int, src_reg: str, badchars: set[int],
    *, tmp: str = "r11",
) -> list[str]:
    """Emit a badchar-safe mov word ptr [base+offset], src_reg (x64)."""
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    mov  word ptr [{base}{fmt}], {src_reg}"]
    tmp = _safe_tmp(src_reg, tmp)
    lines = list(encode_dword_into_r64(offset & 0xFFFFFFFF, badchars, tmp))
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    mov  word ptr [{tmp}], {src_reg}")
    return lines


def safe_mem_load_x64(
    dst: str, base: str, offset: int, badchars: set[int],
    *, width: str = "qword", tmp: str = "r11",
) -> list[str]:
    """Emit a badchar-safe memory load for x64: dst = [base + offset]."""
    size_prefix = {"dword": "dword ptr ", "word": "word ptr ", "byte": "byte ptr "}
    pfx = size_prefix.get(width, "")
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    mov  {dst}, {pfx}[{base}{fmt}]"]
    tmp = _safe_tmp(base, tmp)
    lines = list(encode_dword_into_r64(offset & 0xFFFFFFFF, badchars, tmp))
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    mov  {dst}, {pfx}[{tmp}]")
    return lines


def safe_lea_x64(
    dst: str, base: str, offset: int, badchars: set[int],
    *, tmp: str = "r11",
) -> list[str]:
    """Emit a badchar-safe lea dst, [base+offset] for x64."""
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    lea  {dst}, [{base}{fmt}]"]
    tmp = _safe_tmp(base, tmp)
    lines = list(encode_dword_into_r64(offset & 0xFFFFFFFF, badchars, tmp))
    lines.append(f"    add  {tmp}, {base}")
    if tmp != dst:
        lines.append(f"    mov  {dst}, {tmp}")
    return lines


def safe_call_mem_x64(
    base: str, offset: int, badchars: set[int],
    *, tmp: str = "r11",
) -> list[str]:
    """Emit a badchar-safe call qword ptr [base+offset] for x64."""
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    call qword ptr [{base}{fmt}]"]
    tmp = _safe_tmp(base, tmp)
    lines = list(encode_dword_into_r64(offset & 0xFFFFFFFF, badchars, tmp))
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    call qword ptr [{tmp}]")
    return lines


def _fmt_offset(offset: int) -> str:
    if offset == 0:
        return ""
    if offset > 0:
        return f"+0x{offset:02x}"
    return f"-0x{-offset:02x}"


def _disp_has_badchar(offset: int, badchars: set[int]) -> bool:
    if offset == 0:
        return False
    if -128 <= offset <= 127:
        return (offset & 0xFF) in badchars
    as_unsigned = offset & 0xFFFFFFFF
    return any(((as_unsigned >> (8 * i)) & 0xFF) in badchars for i in range(4))
