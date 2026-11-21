# Emitrion

> **Educational alpha: not ready for production or operational use.**
>
> Emitrion generates and documents Windows shellcode artifacts for study in an
> isolated lab. Its public API, generated output, supported workflows, and
> behavior may change. Host-side tests and byte scans do **not** prove that an
> artifact executes correctly on a native Windows target.

Emitrion is a typed workflow-to-assembly emitter for studying how a declared
Windows API workflow becomes position-independent assembly, shellcode bytes,
and reviewable documentation. It is designed for learners, educators, and
researchers who want to inspect that chain rather than treat payload generation
as a black box.

The project grew from OSED-oriented Windows lab work. Use it only in systems
you own or are explicitly authorized to test, and only within an isolated lab.

## Current state

| Area | Status |
|---|---|
| Windows x86 | Source-level alpha: manifest/IR validation, generated-artifact tests, and optional assembly/byte scans. Native Windows/WinDbg acceptance is incomplete. |
| Windows x64 | Source-level alpha: separate ABI-aware lowering, layout, encoding, and harness paths. Native Windows x64 acceptance is incomplete. |
| Linux and macOS | Not implemented. Manifests targeting either are rejected. |

The implementation has a substantial unit, lowering, and golden-artifact test
suite, but native execution remains the release-critical evidence. Do not rely
on generated output outside a controlled Windows lab.

## What it provides

- YAML manifests for target selection, bad characters, APIs, strings, and
  workflow configuration.
- A typed, validated Windows workflow IR with explicit control flow,
  structures, API calls, and success predicates.
- Windows x86 and x64 lowering paths, including ABI-appropriate stack layout
  and API-resolution scaffolding.
- Bad-character-aware construction plus optional whole-payload XOR encoding.
- Generated assembly, a debugger-oriented runner, raw bytes when an assembler
  is available, and a generated contract describing layout and APIs.
- A three-tier verification path: source-level checks, assembly/byte checks,
  and manual native validation with WinDbg.

Emitrion is intentionally not a general-purpose assembly builder, an operator
framework, or a cross-platform payload language.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- NASM or Keystone only when assembling bytes
- An isolated Windows VM and debugger for native validation

## Quick start: generate reviewable artifacts

Install the development environment:

```bash
uv sync
```

Generate source artifacts without assembling them:

```bash
# Windows x86 example
uv run emitrion emitrion/manifests/calc.yaml \
  --template ir_run_command \
  --no-assemble \
  --out emitter_out/

# Windows x64 example (the main entry point reads arch: x64 from the manifest)
uv run emitrion emitrion/manifests/x64/run_command_x64.yaml \
  --template ir_run_command \
  --no-assemble \
  --out emitter_out-x64/
```

This produces artifacts to inspect; it does not establish native correctness.

## Output

The selected output directory contains:

```text
asm/generated.asm              Generated assembly source
asm/debug_runner.py            Windows lab/debugger runner
asm/code_snippet.py            Source-oriented code snippet
Documentation/contract.md      Stack layout, API, and structure contract
bin/shellcode.*                Raw artifacts, when assembly succeeds
bin/test_harness.py            Generated harness, when assembly succeeds
bin/xor_wrapper.py             Optional offline XOR wrapper
```

Assembly availability is environment-specific. `--no-assemble` is the
recommended starting point on non-Windows development hosts.

## Reference workflows

All current workflow templates are IR-backed. Available templates include:

| Template | Illustrates |
|---|---|
| `ir_run_command` | Process command execution and result branching |
| `ir_reverse_shell`, `ir_bind_shell` | Winsock setup and process creation |
| `ir_copy_file`, `ir_copy_then_run`, `ir_move_file`, `ir_move_then_run` | File operations and conditional flow |
| `ir_check_path`, `ir_get_username` | Environment and path-oriented API use |
| `ir_http_download`, `ir_url_download` | Download-oriented API workflows |
| `ir_copy_to_userdir`, `ir_move_to_userdir`, `ir_http_download_to_userdir`, `ir_url_download_to_userdir` | Runtime user-directory path construction |
| `ir_registry_persistence` | Registry API workflow modeling |

Template availability means the workflow can be generated and tested at the
source/artifact level; it is not a claim of native runtime acceptance.

## Verification

Run the host-side quality gates:

```bash
uv run pytest
uv run ruff check .
uv run mypy emitrion/workflow/
```

With an assembler available, run the verification pipeline:

```bash
uv run python -m emitrion.verify emitrion/manifests/calc.yaml \
  --template ir_run_command \
  --json
```

Verification has three distinct tiers:

1. **Cross-platform:** manifest loading, IR validation, deterministic generated
   assembly, layouts, contracts, and host-side tests.
2. **Assembly and byte scan:** assembled bytes, declared bad-character checks,
   and byte determinism where an assembler is available.
3. **Native Windows lab:** run the generated debugger runner, attach WinDbg,
   observe expected control flow and API results, and record the outcome.

Only Tier 3 provides target-native evidence. See
[the native workflow validation guide](Documentation/Development/NativeWorkflowValidation.md),
[the verification guide](Documentation/Development/VerificationLane.md) and
[the x86 lab test plan](Documentation/x86_test_plan.md) before making support
claims.

## Design and project boundaries

The workflow IR currently models Windows behavior; it is not a promise of
portable workflow semantics. Windows x86 and x64 have target-specific ABI,
layout, resolver, encoding, and validation requirements. More detail is in the
[product requirements document](Documentation/Design/PRD.md),
[workflow IR design](Documentation/Design/WorkflowIR.md), and
[x64 backend notes](Documentation/x64_backend.md).

## Contributing

Contributions should preserve artifact readability and keep target-specific
claims evidence-based. At minimum, changes should include focused tests and
pass linting and workflow type checks. A feature is not “supported” merely
because it generates assembly or passes host-side tests; native lab evidence is
required for that claim.

## License

[MIT](LICENSE)
