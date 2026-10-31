# x64 Native Validation Harness

## Overview

The native validation harness (`emitrion/native_harness_x64.py`) executes assembled x64 shellcode on a Windows x64 system via process isolation and reports structured results. A controller process spawns a disposable worker subprocess that performs the actual VirtualAlloc + CreateThread execution. If shellcode crashes, calls ExitProcess, or triggers an unhandled exception, only the worker dies. The controller inspects the worker's exit code and produces JSON regardless.

## Requirements

- Windows 10/11 or Server 2019+ (x64)
- Python 3.12+ (64-bit)
- No external dependencies (ctypes only)
- Keystone-engine (optional, for assembly-from-source)

## Architecture

```
    Controller (Python process)
        |
        | subprocess.run(worker, timeout)
        v
    Worker (disposable Python process)
        +-- SetErrorMode (suppress WER dialogs, preserve existing flags)
        +-- VirtualAlloc RWX
        +-- RtlMoveMemory shellcode
        +-- CreateThread
        +-- WaitForSingleObject(timeout_ms)
        +-- GetExitCodeThread
        +-- Write JSON to stdout
        +-- sys.exit(0)
        |
        | If worker crashes (ExitProcess, unhandled exception, etc.):
        |   - No JSON on stdout
        |   - Controller reads worker exit code
        |   - Maps to WORKER_CRASH with exception name if recognized
        v
    Controller reads stdout or exit code
        |
        v
    +------------------+
    | ExecutionResult  |
    | status           |
    | exit_code        |
    | exception_code   |
    | worker_exit_code |
    | duration_ms      |
    | to_json()        |
    +------------------+
```

### Why process isolation

An unhandled native exception in a secondary thread can terminate the entire Windows process, not just the faulting thread. This includes:

- Access violations (0xC0000005)
- int3 breakpoints (0x80000003) without a debugger attached
- ExitProcess / TerminateProcess called by shellcode

Without process isolation, any of these would kill the Python controller before it could serialize results. The subprocess boundary guarantees JSON output for every execution attempt.

## Usage

### Command Line

```bash
# Execute a .bin file
python -m emitrion.native_harness_x64 shellcode.bin --json

# Execute with timeout
python -m emitrion.native_harness_x64 shellcode.bin --timeout 5000

# Interactive mode (WinDbg attach point)
python -m emitrion.native_harness_x64 shellcode.bin --interactive

# Build from manifest and execute
python -m emitrion.native_harness_x64 --manifest emitrion/manifests/x64/run_command_x64.yaml

# Run a named scenario
python -m emitrion.native_harness_x64 --scenario test_a_winexec

# Run all scenarios
python -m emitrion.native_harness_x64 all --json
```

### Python API

```python
from emitrion.native_harness_x64 import execute_shellcode, HarnessConfig

shellcode = open("shellcode.bin", "rb").read()
config = HarnessConfig(timeout_ms=5000, test_id="smoke_test")
result = execute_shellcode(shellcode, config)

if result.passed:
    print(f"OK: {result.duration_ms}ms")
else:
    print(f"FAIL: {result.status} -- {result.failure_reason}")

print(result.to_json())
```

### Build Pipeline Integration

```python
from emitrion.native_harness_x64 import execute_from_build, HarnessConfig

result = execute_from_build(
    "emitrion/manifests/x64/run_command_x64.yaml",
    HarnessConfig(test_id="winexec_smoke"),
)
print(result.to_json())
```

## JSON Result Format

```json
{
  "test_id": "test_a_winexec",
  "arch": "x64",
  "shellcode_size": 384,
  "status": "success",
  "exit_code": 0,
  "exception_code": null,
  "exception_name": null,
  "duration_ms": 42.5,
  "alloc_address": 140698832470016,
  "failure_reason": null,
  "timeout_ms": 10000,
  "native_execution": true
}
```

### Status Values

| Status | Meaning |
|--------|---------|
| `success` | Worker thread completed without exception |
| `indeterminate` | Timeout expired. Does not distinguish success from failure. Shellcode may have succeeded then entered a terminal loop, or may have never reached the API call. Requires WinDbg to classify. |
| `timeout` | Legacy alias. Worker-level timeout before process isolation was added. |
| `exception` | Worker thread terminated with a Windows exception code (worker produced JSON) |
| `worker_crash` | Worker process terminated by unhandled exception or ExitProcess (no JSON recovered, controller decoded exit code) |
| `setup_failure` | VirtualAlloc, CreateThread, or config validation failed |
| `not_windows` | Attempted execution on a non-Windows platform |

### Exception Codes

| Code | Name | Typical Cause |
|------|------|---------------|
| `0x80000003` | EXCEPTION_BREAKPOINT | `int3` hit: resolver or module enumeration failure |
| `0xC0000005` | EXCEPTION_ACCESS_VIOLATION | Bad pointer dereference or write to protected memory |
| `0xC000001D` | EXCEPTION_ILLEGAL_INSTRUCTION | Invalid opcode (truncated shellcode, x86 in x64 context) |
| `0xC0000094` | EXCEPTION_INT_DIVIDE_BY_ZERO | Division by zero (uncommon in shellcode) |
| `0xC00000FD` | EXCEPTION_STACK_OVERFLOW | RSP corruption or infinite recursion |

## Test Scenarios

### A: WinExec (test_a_winexec)

Manifest: `run_command_x64.yaml` (ir_run_command, WinExec)

Validates:
- PEB walk finds kernel32.dll
- ROR-13 hash resolution finds WinExec
- 2-argument call (RCX=lpCmdLine, RDX=uCmdShow) executes

Expected: SUCCESS (calc.exe spawns)

### B: DLL Loading (test_b_dll_load)

Manifest: `revshell_x64.yaml` (ir_reverse_shell, LoadLibraryA + WSA APIs)

Validates:
- LoadLibraryA resolves from kernel32
- ws2_32.dll loads successfully
- WSA APIs resolve from loaded DLL
- Multi-module resolution pipeline works

Expected: TIMEOUT or EXCEPTION (connect() blocks or fails with no listener). Reaching connect() means all DLL loading and API resolution succeeded.

### C: Multi-Argument (test_c_multi_arg)

Manifest: `run_command_x64.yaml`

Validates:
- Register arguments (RCX, RDX, R8, R9)
- Stack arguments (5th+ via RSP-relative)
- 32-byte shadow space present
- RSP 16-byte aligned at CALL

For full 10-argument validation, use revshell's CreateProcessA call path.

### D: Failure Handling (test_d_failure)

Custom shellcode with deliberately invalid API hash.

Validates:
- Resolver hits export_not_found path
- `int3` fires (EXCEPTION_BREAKPOINT, 0x80000003)
- No silent NULL dereference

Expected: EXCEPTION with code 0x80000003.

## WinDbg Integration

### Initial Setup

```
# Launch WinDbg, attach to Python process
windbg -pn python.exe

# Or launch with the harness
windbg python.exe -m emitrion.native_harness_x64 shellcode.bin --interactive
```

### Setting Breakpoints

When using `--interactive` mode, the harness prints the allocation address:

```
[+] Shellcode:  384 bytes
[+] Address:    0x000001a2b3c40000
[+] WinDbg:     bp 0x000001a2b3c40000
```

Set a breakpoint at that address in WinDbg:

```
bp 0x000001a2b3c40000
g
```

### ABI Verification Breakpoints

To verify register values at API call sites, set breakpoints on the CALLs:

```
# After initial breakpoint at shellcode entry:
# Step through to first API resolution
p                           ; step over one instruction

# Find the API call instruction
# Look for: call qword ptr [rsp+0xNN]
# Set breakpoint there:
bp <call_address>
g

# At the call site, verify ABI:
r rcx                      ; 1st arg
r rdx                      ; 2nd arg
r r8                       ; 3rd arg
r r9                       ; 4th arg
dqs rsp L8                 ; shadow space + stack args
? rsp & f                  ; alignment check (must be 0)
```

### Common Debugging Commands

```
# View shellcode memory
db <alloc_address> L100

# Disassemble from current position
u rip L20

# Check stack frame
dqs rsp L10

# View PEB (for debugging resolver)
!peb

# View loaded modules
lm

# Trace one instruction
t

# Run to next call
pc
```

### Debugging Resolver Failures

If execution hits `int3` (EXCEPTION_BREAKPOINT):

```
# Check where int3 fired
u rip-1 L5                 ; should show "cc" (int3)

# Look at context:
# If near module_not_found label: R15D hit zero (64 iterations exhausted)
r r15d

# If near export_not_found label: hash not in export table
# Check what module was being searched:
r rbx                       ; module base
!lmi rbx                    ; module info
```

### Automated WinDbg Script

Save as `validate_abi.wds`:

```
$$ ABI validation script for Emitrion x64 shellcode
$$ Usage: $$>< validate_abi.wds

bp @$exentry "r rcx; r rdx; r r8; r r9; .printf \"RSP alignment: %d\\n\", (@rsp & 0xf); dqs @rsp L5; gc"

$$ Break on exceptions
sxe bpe
sxe av

g
```

## Windows-Only Validations

The following validations require native Windows x64 execution and cannot be verified by static analysis or assembly-text inspection:

1. **PEB walk correctness**: GS:[0x60] resolves to actual PEB on target OS version
2. **Export directory parsing**: PE32+ header offsets match actual DLL layouts
3. **ROR-13 hash collisions**: No hash collision with other exports in target DLLs
4. **SSE alignment sensitivity**: Win32 APIs using SSE instructions fault on misaligned RSP
5. **Stack argument placement**: 5th+ arguments read from correct RSP-relative offsets
6. **Shadow space writes**: Callee-saved register spills land in shadow space correctly
7. **DLL load order**: InInitializationOrderModuleList traversal matches expected order
8. **API return values**: Actual return codes from Win32 APIs in RAX
9. **Exception dispatch**: int3 properly triggers EXCEPTION_BREAKPOINT through SEH chain
10. **Thread exit codes**: GetExitCodeThread captures the correct exception or return value

## Running the Full Validation Suite

On the Windows lab VM:

```bash
# 1. Transfer files
# Copy emitrion/ directory to the Windows VM

# 2. Install dependencies
pip install pyyaml
pip install keystone-engine

# 3. Run all scenarios
python -m emitrion.native_harness_x64 all --json > results.json

# 4. Run individual scenarios
python -m emitrion.native_harness_x64 --scenario test_a_winexec --json

# 5. Build and test from manifest
python -m emitrion.native_harness_x64 --manifest emitrion/manifests/x64/run_command_x64.yaml --json

# 6. Interactive debugging
python -m emitrion.native_harness_x64 shellcode.bin --interactive
```

### Interpreting Results

A typical suite run looks like:

```
[PASS] test_a_winexec: success
       42.5ms, 384 bytes
[????] test_b_dll_load: indeterminate
       Execution exceeded 5000ms. Timeout does not distinguish success from failure.
       5001.2ms, 1024 bytes
[PASS] test_c_multi_arg: success
       38.1ms, 384 bytes
[EXCP] test_d_failure: exception
       EXCEPTION_BREAKPOINT (int3): resolver or module enumeration hit a terminal failure path
       0.8ms, 64 bytes
```

- test_a: SUCCESS means WinExec resolved and executed
- test_b: INDETERMINATE is expected (connect blocks with no listener). This does not prove success. WinDbg is needed to confirm that DLL loading and API resolution completed before connect() blocked. EXCEPTION_BREAKPOINT or WORKER_CRASH means resolution failed before reaching connect().
- test_c: SUCCESS means multi-arg call completed
- test_d: EXCEPTION_BREAKPOINT is expected (deliberate bad hash)

### Classifying indeterminate results

A timeout alone does not establish success or failure. Use WinDbg to distinguish:

| Observation | Classification |
|-------------|---------------|
| API called successfully, shellcode entered terminal loop | Workflow succeeded |
| API resolution failed (int3 before call) | Framework failure |
| Exception before API call | Shellcode correctness failure |
| Incorrect API arguments (wrong register values at CALL) | ABI/lowering failure |
| Timeout with no execution evidence | Indeterminate |
| Worker process crashes before JSON | Unhandled exception (controller reports WORKER_CRASH) |

## Limitations

- No register-level ABI verification without WinDbg. The harness validates execution outcomes (success/failure/exception) but cannot inspect register values at call sites without debugger instrumentation.
- Exit code interpretation is heuristic. Thread exit codes below 0x80000000 are treated as success. Some Win32 APIs return error codes in EAX that could be misinterpreted.
- Timeouts are classified as INDETERMINATE, not success or failure. Terminal shellcode intentionally enters infinite loops after successful execution. A timeout without independent observation of the expected API behavior (e.g., WinDbg breakpoint confirming the call was reached) does not prove success.
- Worker process crash loses thread-level detail. When shellcode triggers a process-level termination (ExitProcess, unhandled exception that kills the process), the controller can only read the process exit code, not the thread exit code or exception record. The exception code in the process exit status is usually the same, but some edge cases (e.g., ExitProcess(0) from shellcode) are indistinguishable from clean exit.
- No VEH/SEH integration. The worker relies on SetErrorMode + GetExitCodeThread for exception detection. Structured exception handlers within the shellcode could mask faults.
- Single-threaded validation only. The harness does not test shellcode that spawns additional threads.
