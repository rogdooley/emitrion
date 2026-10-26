# Verification Lane

## Overview

The verification lane validates that generated shellcode is correct, clean,
and deterministic before it reaches the Windows lab environment. It separates
the pipeline into three tiers that run in different environments.

## Tiers

### Tier 1: Cross-platform (any developer machine, CI)

Runs without an assembler. Validates:

- All manifests load and generate assembly without errors.
- IR workflows pass validation (control-flow, ABI categories, predicates).
- Generated assembly is deterministic for identical inputs.
- Stack layout is consistent and within page limits.
- Contract documentation is generated and includes expected API entries.
- Debug runner and code snippet are produced.

```bash
uv run pytest emitrion/tests/ -v -k "not requires_assembler"
```

### Tier 2: Assembly and byte scan (requires NASM or Keystone)

Runs with an assembler available. Validates:

- All manifests assemble to shellcode bytes.
- No declared bad characters appear in assembled output.
- Identical inputs produce identical bytes (determinism).
- Verification report (JSON) is generated with full diagnostics.

```bash
uv run pytest emitrion/tests/test_verify.py -v
```

Or via the verification script directly:

```bash
uv run python -m emitrion.verify emitrion/manifests/calc.yaml --template ir_run_command
```

The `--json` flag outputs the report as structured JSON for CI integration:

```bash
uv run python -m emitrion.verify emitrion/manifests/calc.yaml --template ir_run_command --json
```

Exit code is 0 for pass, 1 for fail.

### Tier 3: Execution (Windows x86 lab VM only)

Manual verification in the isolated lab environment. Never automated in CI.

1. Run the verification script on a machine with an assembler to produce
   artifacts:

   ```bash
   uv run python -m emitrion.verify emitrion/manifests/calc.yaml \
       --template ir_run_command --out verify_out
   ```

2. Transfer `verify_out/asm/debug_runner.py` to the Windows x86 lab VM.

3. On the lab VM (requires `pip install keystone-engine`):

   ```
   python debug_runner.py
   ```

4. Attach WinDbg before pressing Enter. The script prints the shellcode
   address for setting a breakpoint:

   ```
   bp <address>
   ```

5. Step through execution and verify the expected outcome:
   - For `ir_run_command` / `run_command` with calc.yaml: `calc.exe` launches.
   - For `reverse_shell`: a connection is established to the listener.

6. Record the WinDbg session and attach the verification_report.json to the
   release artifacts.

## Verification Report

The JSON report (`verification_report.json`) includes:

| Field | Type | Description |
|-------|------|-------------|
| `passed` | bool | True only if assembled, bad-char clean, no errors |
| `assembled` | bool | Assembler produced bytes |
| `shellcode_size` | int | Raw shellcode byte count |
| `shellcode_sha256` | string | SHA-256 of raw bytes |
| `badchars_declared` | list | Hex strings of declared bad characters |
| `badchar_violations` | list | Each violation with offset and context |
| `badchar_clean` | bool | No violations found |
| `deterministic` | bool | Identical inputs produced identical bytes |
| `encoded` | bool | XOR encoding was applied |
| `errors` | list | Any errors encountered |

## CI Integration

Recommended CI matrix:

```yaml
# Tier 1: every push, all platforms
test-cross-platform:
  runs-on: [ubuntu-latest, macos-latest, windows-latest]
  steps:
    - run: uv run pytest -v -k "not requires_assembler"
    - run: uv run ruff check emitrion/
    - run: uv run mypy --strict emitrion/workflow/

# Tier 2: every push, assembler-available runner
test-assembly:
  runs-on: ubuntu-latest  # NASM available via apt
  steps:
    - run: sudo apt-get install -y nasm
    - run: uv run pytest emitrion/tests/test_verify.py -v
    - run: |
        uv run python -m emitrion.verify emitrion/manifests/calc.yaml \
            --template ir_run_command --json > report.json
    - uses: actions/upload-artifact@v4
      with:
        name: verification-report
        path: report.json
```

Tier 3 is manual and documented per release.

## Adding a New Manifest to Verification

1. Add the manifest YAML to `emitrion/manifests/`.
2. The `test_all_manifests_generate` and `test_all_manifests_assemble` tests
   pick it up automatically.
3. For specific behavioral verification, add a dedicated test in
   `test_verify.py::TestAssemblyPhase`.
4. Document the expected Tier 3 outcome in this file.
