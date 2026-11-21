# Native Workflow Validation Guide

This guide is the operating procedure for deciding whether an Emitrion workflow
works on its declared Windows target. It is intentionally separate from unit,
assembly, bad-character, and determinism tests: those are necessary build
evidence, not native-execution evidence.

Use the guide only in an isolated, authorized Windows lab. Begin with the
benign `ir_run_command` workflow and use `calc.exe` as the observable outcome.
Do not label an architecture, backend, or workflow supported until its required
native evidence is recorded.

## What a native pass means

A workflow passes only when all of the following hold on the declared target:

1. The generated artifact reaches its intended API call without an unexpected
   exception or debugger break.
2. The expected, benign observable result occurs.
3. The selected success and controlled-failure paths behave as documented.
4. The debugger confirms the architecture-specific call convention at one
   representative API call.
5. The run record captures the manifest, command, generated-artifact hash,
   target image, tool versions, outcome, and any limitations.

A source-level test pass, successful assembly, or a clean bad-character scan
is not a substitute for this evidence.

## Lab boundaries and preparation

- Use disposable Windows VMs with a snapshot taken before every validation
  campaign. Do not use a workstation or production network.
- Match shellcode architecture to the execution process: x86 artifacts require
  a 32-bit process and debugger session; x64 artifacts require a 64-bit
  process and debugger session.
- Keep test inputs harmless and local whenever possible: `calc.exe`, a text
  file, and a local HTTP service in the lab network are sufficient.
- Record the Windows edition/build, process bitness, Python version, assembler
  version, debugger version, and the exact repository revision.
- Use a short, explicit allowlist or lab policy when security controls block a
  controlled test. Do not disable protections broadly.

Before a native run, execute the host-side gates:

```bash
uv run pytest
uv run ruff check .
uv run mypy emitrion/workflow/
```

Save their output with the validation record. These commands qualify the build;
the Windows procedure below qualifies the target behavior.

## Minimum validation matrix

Run the matrix in order. A failure in an earlier row blocks later rows for that
architecture because later workflows depend on the same resolver, lowering, or
stack machinery.

| Order | Workflow | x86 manifest | x64 manifest | Evidence it adds |
|---:|---|---|---|---|
| 1 | `ir_run_command` | `emitrion/manifests/win-x86/calc.yaml` | `emitrion/manifests/win-x64/run_command_x64.yaml` | Entry, PEB walk, export resolution, basic API call, terminal path |
| 2 | `ir_get_username` | `emitrion/manifests/win-x86/get_username.yaml` | `emitrion/manifests/win-x64/get_username_x64.yaml` | Secondary-DLL loading, output buffer, string handling |
| 3 | `ir_copy_file` | `emitrion/manifests/win-x86/ir_copy_file.yaml` | `emitrion/manifests/win-x64/copy_file_x64.yaml` | Pointer arguments and file API behavior |
| 4 | `ir_http_download` | `emitrion/manifests/win-x86/http_download.yaml` | `emitrion/manifests/win-x64/http_download_x64.yaml` | Multi-call flow, buffers, handles, lab-local networking |
| 5 | `ir_reverse_shell` | `emitrion/manifests/win-x86/revshell.yaml` | `emitrion/manifests/win-x64/revshell_x64.yaml` | Winsock initialization, structures, process creation, failure path |

`ir_bind_shell`, user-directory, move, URL-download, and registry workflows
should be validated after their dependencies above pass. Record them as
individual workflow claims; do not infer their native behavior from a related
workflow.

## x86 procedure

Use a 32-bit Windows process and 32-bit WinDbg/x64dbg. The generated x86 debug
runner assembles the source on the VM, allocates executable memory, prints an
attach point, then waits for the debugger.

Generate an x86 smoke-test artifact on the development host:

```bash
uv run emitrion emitrion/manifests/win-x86/calc.yaml \
  --template ir_run_command \
  --command "calc.exe" \
  --no-assemble \
  --out validation/x86/run-command
```

Transfer `validation/x86/run-command/asm/debug_runner.py` and the matching
`Documentation/contract.md` to the 32-bit VM. Install the runner's documented
dependency (Keystone) in the same 32-bit Python environment, then:

1. Start the runner and copy its printed shellcode address.
2. Attach the 32-bit debugger and set a breakpoint at that address.
3. Continue to the first resolved API call. Confirm the expected stack-based
   x86 arguments and inspect the command string in memory.
4. Continue execution. `calc.exe` should appear and the runner process should
   exit according to its configured exit strategy.
5. Save the debugger log, generated contract, runner output, and a SHA-256 of
   the generated assembly or bytes if assembly was performed.

For later x86 workflows, change only the manifest and inputs. For example,
validate file copying with a harmless source and destination inside the VM:

```bash
uv run emitrion emitrion/manifests/win-x86/ir_copy_file.yaml \
  --src "C:\\OSED\\input.txt" \
  --dst "C:\\OSED\\output.txt" \
  --no-assemble \
  --out validation/x86/copy-file
```

Verify both the API result in the debugger and the resulting file contents.
The existing [x86 test plan](../x86_test_plan.md) contains workflow-specific
details; this guide is the acceptance and evidence standard.

## x64 procedure

Use a 64-bit Windows process and 64-bit WinDbg. The x64 native harness runs
shellcode in a disposable worker process and emits structured results even when
the worker crashes or the workflow invokes a process-exit API.

On the x64 Windows VM, run the benign smoke test from a checkout containing the
same revision used to generate the validation record:

```powershell
python -m emitrion.native_harness_x64 `
  --manifest emitrion/manifests/win-x64/run_command_x64.yaml `
  --json
```

Expected evidence:

- the JSON result identifies `x64` and records `native_execution: true`;
- `calc.exe` starts for the `ir_run_command` scenario; and
- no unexpected exception or resolver `int3` occurs.

For debugger inspection, use the harness's interactive mode:

```powershell
python -m emitrion.native_harness_x64 shellcode.bin --interactive
```

At a representative API call, confirm the Microsoft x64 ABI:

```text
r rcx rdx r8 r9       ; first four integer/pointer arguments
dqs rsp L8            ; shadow space and stack arguments
? rsp & f             ; must be 0 at the call site
```

Continue with the remaining x64 manifests in the minimum matrix. The
[x64 native-harness guide](../x64_native_validation.md) defines result statuses
and debugger procedures. Treat `indeterminate`, `timeout`, `exception`, or
`worker_crash` as a failure needing debugger classification, not as a pass.

## Failure-path checks

Every accepted workflow needs one controlled failure observation in addition to
its success case. Use an input that is invalid but non-destructive, such as a
missing local source file or an unreachable address within the isolated lab.

Record:

- whether the workflow takes its documented failure block;
- the process/thread exit behavior selected by `--exit-strategy`;
- any resolver breakpoint or native exception; and
- whether the failure leaves unexpected files, processes, or network listeners.

Do not use an `int3` resolver failure as evidence of correct workflow failure
handling. It is diagnostic evidence that resolution did not complete.

## Evidence record

Create one record per architecture, workflow, and case (success or failure).
Store it under a non-versioned `validation/` directory or attach it to a release
artifact; do not overwrite an earlier run.

```markdown
# Native validation record

- Date/time and operator:
- Repository revision:
- Target: Windows <edition/build>, x86 or x64
- Host process and debugger bitness:
- Python / Keystone / debugger versions:
- Manifest and exact CLI or harness command:
- Workflow, case, and expected result:
- Generated assembly SHA-256 / shellcode SHA-256:
- Host-side gate results:
- Native result: pass / fail / indeterminate
- Observed API and debugger evidence:
- Observable outcome (for example, calc.exe launched or file hashes matched):
- Failure-path outcome, if applicable:
- Artifacts attached: debugger log, runner or harness JSON, contract, screenshots
- Limitations or follow-up issue:
```

## How to report maturity

Use these terms consistently:

- **Source-level alpha:** host-side tests and generated-artifact checks pass;
  native execution is absent or incomplete.
- **Native-validated workflow:** the matrix row has a recorded success and
  controlled-failure result for the declared target.
- **Supported target:** all required workflows for that target have current,
  reproducible native evidence and the release documentation links to it.

Until the final condition is met, keep README and release language at
“educational alpha” and identify each workflow's validation status explicitly.
