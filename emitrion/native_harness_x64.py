"""Native Windows x64 shellcode validation harness.

Executes assembled x64 shellcode on a Windows x64 system via process
isolation and reports structured results. The controller spawns a
subprocess worker that performs the actual VirtualAlloc + CreateThread
execution. If the shellcode crashes, calls ExitProcess, or triggers an
unhandled exception, only the worker dies. The controller inspects the
worker's exit code and produces JSON regardless.

Usage (standalone):
    python -m emitrion.native_harness_x64 emitter_out/bin/shellcode.bin
    python -m emitrion.native_harness_x64 emitter_out/bin/shellcode.bin --timeout 10
    python -m emitrion.native_harness_x64 emitter_out/bin/shellcode.bin --interactive

Usage (from build pipeline):
    from emitrion.native_harness_x64 import execute_shellcode, HarnessConfig
    result = execute_shellcode(shellcode_bytes, HarnessConfig(timeout_ms=5000))

Architecture:
    Controller (this process)
        |
        | subprocess.run(worker script, timeout)
        v
    Worker (disposable Python process)
        +-- SetErrorMode (suppress WER dialogs)
        +-- VirtualAlloc RWX
        +-- RtlMoveMemory shellcode
        +-- CreateThread
        +-- WaitForSingleObject(timeout)
        +-- GetExitCodeThread
        +-- Write JSON result to stdout
        +-- sys.exit(0)  [or process dies from shellcode]

    If worker crashes or is killed, controller reads its exit code
    and produces a result. JSON output is always available.

Requirements:
    - Windows x64 (10/11/Server 2019+)
    - Python 3.12+ (64-bit)
    - No external dependencies (ctypes only)

ABI verification limitations:
    Without debugger instrumentation, this harness cannot inspect register
    values at call sites. It validates execution success/failure and
    exception codes. Register-level ABI verification requires WinDbg
    breakpoints at each CALL instruction. See Documentation/x64_native_validation.md.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path


class ExecutionStatus(str, Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    INDETERMINATE = "indeterminate"
    EXCEPTION = "exception"
    WORKER_CRASH = "worker_crash"
    SETUP_FAILURE = "setup_failure"
    NOT_WINDOWS = "not_windows"


# Windows exception codes
EXCEPTION_NAMES: dict[int, str] = {
    0x80000003: "EXCEPTION_BREAKPOINT",
    0x80000004: "EXCEPTION_SINGLE_STEP",
    0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
    0xC0000008: "EXCEPTION_INVALID_HANDLE",
    0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
    0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
    0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
    0xC0000096: "EXCEPTION_PRIV_INSTRUCTION",
    0x40010006: "DBG_PRINTEXCEPTION_C",
}


@dataclass
class HarnessConfig:
    timeout_ms: int = 10000
    interactive: bool = False
    test_id: str = ""
    collect_exit_code: bool = True

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.timeout_ms < 100:
            errors.append(f"timeout_ms must be >= 100, got {self.timeout_ms}")
        if self.timeout_ms > 300000:
            errors.append(f"timeout_ms must be <= 300000, got {self.timeout_ms}")
        return errors


@dataclass
class ExecutionResult:
    test_id: str
    arch: str = "x64"
    shellcode_size: int = 0
    status: str = ExecutionStatus.SETUP_FAILURE.value
    exit_code: int | None = None
    exception_code: int | None = None
    exception_name: str | None = None
    duration_ms: float = 0.0
    alloc_address: int | None = None
    failure_reason: str | None = None
    timeout_ms: int = 0
    native_execution: bool = False
    worker_pid: int | None = None
    worker_exit_code: int | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> ExecutionResult:
        d = json.loads(data)
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)

    @property
    def passed(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS.value


def _is_windows() -> bool:
    return sys.platform == "win32"


def _is_64bit_python() -> bool:
    return sys.maxsize > 2**32


# ---------------------------------------------------------------------------
# Worker script template (runs in isolated subprocess)
# ---------------------------------------------------------------------------

_WORKER_SCRIPT = textwrap.dedent(r'''
    """Shellcode execution worker. Runs in an isolated subprocess."""
    import ctypes
    import json
    import sys
    import time

    EXCEPTION_NAMES = {
        0x80000003: "EXCEPTION_BREAKPOINT",
        0x80000004: "EXCEPTION_SINGLE_STEP",
        0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
        0xC0000008: "EXCEPTION_INVALID_HANDLE",
        0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
        0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
        0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
        0xC0000096: "EXCEPTION_PRIV_INSTRUCTION",
        0x40010006: "DBG_PRINTEXCEPTION_C",
    }

    def main():
        shellcode_path = sys.argv[1]
        timeout_ms = int(sys.argv[2])
        interactive = sys.argv[3] == "1"

        with open(shellcode_path, "rb") as f:
            shellcode = f.read()

        kernel32 = ctypes.windll.kernel32

        kernel32.SetErrorMode.argtypes = [ctypes.c_uint]
        kernel32.SetErrorMode.restype = ctypes.c_uint
        SEM_FAILCRITICALERRORS = 0x0001
        SEM_NOGPFAULTERRORBOX = 0x0002
        prev = kernel32.SetErrorMode(0)
        kernel32.SetErrorMode(prev | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)

        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        kernel32.VirtualAlloc.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong,
        ]
        kernel32.RtlMoveMemory.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ]
        kernel32.CreateThread.restype = ctypes.c_void_p
        kernel32.CreateThread.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
        ]
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        kernel32.GetExitCodeThread.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.GetExitCodeThread.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.VirtualFree.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
        ]

        MEM_COMMIT_RESERVE = 0x3000
        PAGE_EXECUTE_READWRITE = 0x40
        MEM_RELEASE = 0x8000
        WAIT_TIMEOUT = 0x00000102
        STILL_ACTIVE = 259

        result = {
            "shellcode_size": len(shellcode),
            "status": "setup_failure",
            "native_execution": False,
        }

        ptr = kernel32.VirtualAlloc(
            None, len(shellcode), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE,
        )
        if not ptr:
            result["failure_reason"] = "VirtualAlloc failed"
            print(json.dumps(result))
            sys.exit(0)

        result["alloc_address"] = ptr

        buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
        kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), len(shellcode))

        if interactive:
            sys.stderr.write(f"[+] Shellcode:  {len(shellcode)} bytes\n")
            sys.stderr.write(f"[+] Address:    {ptr:#018x}\n")
            sys.stderr.write(f"[+] WinDbg:     bp {ptr:#018x}\n")
            sys.stderr.write(f"[+] PID:        {ctypes.windll.kernel32.GetCurrentProcessId()}\n\n")
            input("... attach WinDbg, set breakpoints, then press Enter ...")

        t0 = time.perf_counter()

        ht = kernel32.CreateThread(None, 0, ptr, None, 0, None)
        if not ht:
            result["failure_reason"] = "CreateThread failed"
            kernel32.VirtualFree(ptr, 0, MEM_RELEASE)
            print(json.dumps(result))
            sys.exit(0)

        wait_result = kernel32.WaitForSingleObject(ht, timeout_ms)

        t1 = time.perf_counter()
        result["duration_ms"] = round((t1 - t0) * 1000, 2)
        result["native_execution"] = True

        if wait_result == WAIT_TIMEOUT:
            result["status"] = "indeterminate"
            result["failure_reason"] = (
                f"Execution exceeded {timeout_ms}ms. "
                "Timeout does not distinguish success from failure."
            )
            kernel32.CloseHandle(ht)
            kernel32.VirtualFree(ptr, 0, MEM_RELEASE)
            print(json.dumps(result))
            sys.exit(0)

        exit_code = ctypes.c_ulong(0)
        kernel32.GetExitCodeThread(ht, ctypes.byref(exit_code))
        result["exit_code"] = exit_code.value

        if exit_code.value in EXCEPTION_NAMES:
            result["status"] = "exception"
            result["exception_code"] = exit_code.value
            result["exception_name"] = EXCEPTION_NAMES[exit_code.value]
            if exit_code.value == 0x80000003:
                result["failure_reason"] = (
                    "EXCEPTION_BREAKPOINT (int3): resolver or module "
                    "enumeration hit a terminal failure path"
                )
            else:
                result["failure_reason"] = (
                    f"{EXCEPTION_NAMES[exit_code.value]} "
                    f"(0x{exit_code.value:08X})"
                )
        elif exit_code.value == STILL_ACTIVE:
            result["status"] = "indeterminate"
            result["failure_reason"] = "Thread still active after wait returned"
        else:
            result["status"] = "success"

        kernel32.CloseHandle(ht)
        kernel32.VirtualFree(ptr, 0, MEM_RELEASE)

        print(json.dumps(result))
        sys.exit(0)

    if __name__ == "__main__":
        main()
''').lstrip()


def execute_shellcode(
    shellcode: bytes,
    config: HarnessConfig | None = None,
) -> ExecutionResult:
    """Execute x64 shellcode via an isolated worker subprocess.

    On non-Windows platforms, returns a NOT_WINDOWS result without
    attempting execution.
    """
    config = config or HarnessConfig()
    result = ExecutionResult(
        test_id=config.test_id,
        shellcode_size=len(shellcode),
        timeout_ms=config.timeout_ms,
    )

    errors = config.validate()
    if errors:
        result.failure_reason = "; ".join(errors)
        return result

    if not _is_windows():
        result.status = ExecutionStatus.NOT_WINDOWS.value
        result.failure_reason = f"Platform is {sys.platform}, not win32"
        return result

    if not _is_64bit_python():
        result.status = ExecutionStatus.SETUP_FAILURE.value
        result.failure_reason = "32-bit Python cannot execute x64 shellcode"
        return result

    if not shellcode:
        result.failure_reason = "Empty shellcode"
        return result

    return _execute_via_worker(shellcode, config, result)


def _execute_via_worker(
    shellcode: bytes,
    config: HarnessConfig,
    result: ExecutionResult,
) -> ExecutionResult:
    """Spawn an isolated worker subprocess to execute shellcode."""
    with tempfile.TemporaryDirectory(prefix="emitera_harness_") as tmpdir:
        tmp = Path(tmpdir)
        sc_path = tmp / "shellcode.bin"
        worker_path = tmp / "worker.py"

        sc_path.write_bytes(shellcode)
        worker_path.write_text(_WORKER_SCRIPT, encoding="utf-8")

        cmd = [
            sys.executable, "-I", str(worker_path),
            str(sc_path),
            str(config.timeout_ms),
            "1" if config.interactive else "0",
        ]

        subprocess_timeout_s = (config.timeout_ms / 1000.0) + 5.0

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=subprocess_timeout_s,
            )
        except subprocess.TimeoutExpired:
            t1 = time.perf_counter()
            result.duration_ms = round((t1 - t0) * 1000, 2)
            result.status = ExecutionStatus.INDETERMINATE.value
            result.native_execution = True
            result.failure_reason = (
                f"Worker subprocess exceeded {subprocess_timeout_s:.0f}s. "
                "Timeout does not distinguish success from failure."
            )
            return result

        t1 = time.perf_counter()
        result.worker_exit_code = proc.returncode

        if proc.stdout.strip():
            try:
                worker_data = json.loads(proc.stdout.strip())
                result.shellcode_size = worker_data.get("shellcode_size", result.shellcode_size)
                result.status = worker_data.get("status", result.status)
                result.exit_code = worker_data.get("exit_code")
                result.exception_code = worker_data.get("exception_code")
                result.exception_name = worker_data.get("exception_name")
                result.duration_ms = worker_data.get("duration_ms", 0.0)
                result.alloc_address = worker_data.get("alloc_address")
                result.failure_reason = worker_data.get("failure_reason")
                result.native_execution = worker_data.get("native_execution", False)
                result.worker_pid = worker_data.get("worker_pid")
                return result
            except json.JSONDecodeError:
                pass

        result.duration_ms = round((t1 - t0) * 1000, 2)

        if proc.returncode != 0:
            result.native_execution = True
            exit_unsigned = proc.returncode & 0xFFFFFFFF

            if exit_unsigned in EXCEPTION_NAMES:
                result.status = ExecutionStatus.WORKER_CRASH.value
                result.exception_code = exit_unsigned
                result.exception_name = EXCEPTION_NAMES[exit_unsigned]
                result.failure_reason = (
                    f"Worker process terminated by {EXCEPTION_NAMES[exit_unsigned]} "
                    f"(0x{exit_unsigned:08X}). Shellcode caused unrecoverable "
                    f"process-level exception."
                )
            else:
                result.status = ExecutionStatus.WORKER_CRASH.value
                result.failure_reason = (
                    f"Worker process exited with code {proc.returncode} "
                    f"(0x{exit_unsigned:08X}). No JSON output recovered."
                )
                if proc.stderr.strip():
                    result.failure_reason += f" stderr: {proc.stderr.strip()[:500]}"
        else:
            result.failure_reason = "Worker exited 0 but produced no JSON output"

        return result


def execute_from_asm(
    asm_text: str,
    config: HarnessConfig | None = None,
) -> ExecutionResult:
    """Assemble x64 text and execute. Requires keystone-engine."""
    config = config or HarnessConfig()
    result = ExecutionResult(
        test_id=config.test_id,
        timeout_ms=config.timeout_ms,
    )

    try:
        from keystone import KS_ARCH_X86, KS_MODE_64, Ks
    except ImportError:
        result.failure_reason = "keystone-engine not installed"
        return result

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    cleaned = asm_text.replace("jmp short ", "jmp ")
    try:
        encoding, _ = ks.asm(cleaned)
    except Exception as e:
        result.failure_reason = f"Assembly failed: {e}"
        return result

    shellcode = bytes(encoding)
    return execute_shellcode(shellcode, config)


def execute_from_build(
    manifest_path: str,
    config: HarnessConfig | None = None,
    assemble: bool = True,
) -> ExecutionResult:
    """Build from manifest and execute. Full pipeline test."""
    config = config or HarnessConfig()

    from .build_x64 import build_x64

    build_result = build_x64(manifest_path, assemble=assemble)

    if build_result.asm_errors:
        return ExecutionResult(
            test_id=config.test_id,
            failure_reason="; ".join(build_result.asm_errors),
            timeout_ms=config.timeout_ms,
        )

    if build_result.shellcode_bytes is None:
        return ExecutionResult(
            test_id=config.test_id,
            failure_reason="No shellcode produced (assembler unavailable or badchar violation)",
            timeout_ms=config.timeout_ms,
        )

    return execute_shellcode(build_result.shellcode_bytes, config)


# -- Test scenario definitions --

SCENARIOS: dict[str, dict] = {
    "test_a_winexec": {
        "description": "WinExec: API resolution and command execution",
        "manifest": "emitrion/manifests/x64/run_command_x64.yaml",
        "timeout_ms": 10000,
        "expect_success": True,
    },
    "test_b_dll_load": {
        "description": "LoadLibraryA: secondary DLL loading (ws2_32)",
        "manifest": "emitrion/manifests/x64/revshell_x64.yaml",
        "timeout_ms": 5000,
        "expect_success": False,
        "expect_note": (
            "Expected to timeout or exception: revshell blocks on connect() "
            "with no listener. Success = DLL loaded, APIs resolved, "
            "shellcode reached connect()."
        ),
    },
    "test_c_multi_arg": {
        "description": "CreateProcessA: 10 arguments (4 reg + 6 stack)",
        "manifest": "emitrion/manifests/x64/run_command_x64.yaml",
        "timeout_ms": 10000,
        "expect_success": True,
        "expect_note": (
            "Uses ir_run_command which calls WinExec (2 args). "
            "For full 10-arg testing, use revshell's CreateProcessA path."
        ),
    },
    "test_d_failure": {
        "description": "Unresolved export: terminal int3 behavior",
        "timeout_ms": 5000,
        "expect_success": False,
        "expect_exception": 0x80000003,
        "expect_note": (
            "Requires custom shellcode with a deliberately bad API hash. "
            "Expected: EXCEPTION_BREAKPOINT from int3."
        ),
    },
}


def run_scenario(
    scenario_id: str,
    base_dir: str = ".",
) -> ExecutionResult:
    """Run a named test scenario."""
    if scenario_id not in SCENARIOS:
        return ExecutionResult(
            test_id=scenario_id,
            failure_reason=f"Unknown scenario: {scenario_id}",
        )

    scenario = SCENARIOS[scenario_id]
    manifest = scenario.get("manifest")

    if manifest is None:
        return ExecutionResult(
            test_id=scenario_id,
            failure_reason="Scenario requires custom shellcode (not auto-buildable)",
        )

    manifest_path = str(Path(base_dir) / manifest)
    config = HarnessConfig(
        test_id=scenario_id,
        timeout_ms=scenario.get("timeout_ms", 10000),
    )

    return execute_from_build(manifest_path, config)


def run_all_scenarios(base_dir: str = ".") -> list[ExecutionResult]:
    """Run all defined test scenarios and return results."""
    results: list[ExecutionResult] = []
    for scenario_id in SCENARIOS:
        result = run_scenario(scenario_id, base_dir)
        results.append(result)
    return results


def _cli() -> None:
    """Command-line entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Emitera x64 native shellcode validation harness",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Shellcode .bin file, .asm file, or 'all' to run all scenarios",
    )
    parser.add_argument(
        "--timeout", type=int, default=10000,
        help="Execution timeout in milliseconds (default: 10000)",
    )
    parser.add_argument(
        "--interactive", action="store_true",
        help="Pause before execution for WinDbg attach",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--test-id", type=str, default="",
        help="Test identifier for result tracking",
    )
    parser.add_argument(
        "--manifest", type=str,
        help="Build and execute from a manifest YAML",
    )
    parser.add_argument(
        "--scenario", type=str,
        help="Run a named test scenario",
    )

    args = parser.parse_args()

    config = HarnessConfig(
        timeout_ms=args.timeout,
        interactive=args.interactive,
        test_id=args.test_id,
    )

    if args.input == "all" or (args.input is None and args.scenario is None and args.manifest is None):
        if args.input == "all":
            results = run_all_scenarios()
        else:
            parser.print_help()
            sys.exit(1)
            return

        if args.json:
            print(json.dumps([asdict(r) for r in results], indent=2))
        else:
            for r in results:
                status_icon = {
                    "success": "[PASS]",
                    "indeterminate": "[????]",
                    "timeout": "[TIME]",
                    "exception": "[EXCP]",
                    "worker_crash": "[DEAD]",
                    "setup_failure": "[FAIL]",
                    "not_windows": "[SKIP]",
                }.get(r.status, "[????]")
                print(f"  {status_icon} {r.test_id}: {r.status}")
                if r.failure_reason:
                    print(f"         {r.failure_reason}")
                if r.duration_ms > 0:
                    print(f"         {r.duration_ms:.1f}ms, {r.shellcode_size} bytes")
        sys.exit(0 if all(
            r.passed or r.status == ExecutionStatus.NOT_WINDOWS.value
            for r in results
        ) else 1)

    if args.scenario:
        result = run_scenario(args.scenario)
    elif args.manifest:
        config.test_id = config.test_id or Path(args.manifest).stem
        result = execute_from_build(args.manifest, config)
    elif args.input:
        p = Path(args.input)
        config.test_id = config.test_id or p.stem
        if p.suffix == ".bin":
            shellcode = p.read_bytes()
            result = execute_shellcode(shellcode, config)
        elif p.suffix == ".asm":
            asm_text = p.read_text()
            result = execute_from_asm(asm_text, config)
        else:
            result = ExecutionResult(
                test_id=config.test_id,
                failure_reason=f"Unsupported file type: {p.suffix}",
            )
    else:
        parser.print_help()
        sys.exit(1)
        return

    if args.json:
        print(result.to_json())
    else:
        print(f"Test:     {result.test_id}")
        print(f"Arch:     {result.arch}")
        print(f"Size:     {result.shellcode_size} bytes")
        print(f"Status:   {result.status}")
        if result.alloc_address:
            print(f"Address:  {result.alloc_address:#018x}")
        if result.duration_ms > 0:
            print(f"Duration: {result.duration_ms:.1f}ms")
        if result.exit_code is not None:
            print(f"Exit:     0x{result.exit_code:08X}")
        if result.exception_name:
            print(f"Exception: {result.exception_name}")
        if result.worker_exit_code is not None:
            print(f"Worker:   exit {result.worker_exit_code}")
        if result.failure_reason:
            print(f"Reason:   {result.failure_reason}")
        print(f"Native:   {result.native_execution}")

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    _cli()
