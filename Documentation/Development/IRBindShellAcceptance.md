# IR Bind-Shell Acceptance Matrix

This matrix defines the evidence required to accept `ir_bind_shell`. It is a
validation companion to the generated contract, not a runtime claim. Passing
source, assembly, or byte-level checks does not demonstrate execution on the
Windows x86 lab VM.

## Preconditions

- Generate the payload from `emitrion/manifests/bindshell.yaml` using the
  `ir_bind_shell` template.
- Treat the manifest `lport` as the listening port. The workflow binds
  `INADDR_ANY` (`0.0.0.0`), so the operator connects to the lab VM's reachable
  address, not `0.0.0.0`.
- Retain the generated assembly, contract, bytes, and verification report with
  the VM evidence. Regenerate artifacts for each port or command change.

## Evidence Matrix

| Stage | Expected success state | Failure condition and expected result | Required evidence |
|---|---|---|---|
| `WSAStartup` | returns `0` | nonzero return transfers to `fail` and `ExitProcess(1)` | Saved `wsa_ret` and observed branch direction |
| `WSASocketA` | returns a value other than `INVALID_SOCKET` | `INVALID_SOCKET` transfers to `fail` | Saved `listen_socket`; it is the handle used by `bind` and `listen` |
| `bind` | returns `0` | nonzero return transfers to `fail` | `sockaddr_in`: family `AF_INET` (`2`), configured port in network byte order, address `INADDR_ANY`; saved `bind_ret` |
| `listen` | returns `0` | nonzero return transfers to `fail` | Saved `listen_ret`; listener is visible on the configured port before a client connects |
| `accept` | returns a value other than `INVALID_SOCKET` | `INVALID_SOCKET` transfers to `fail` | Saved `client_socket`; breakpoint/trace shows it differs in role from `listen_socket` |
| `STARTUPINFOA` setup | `cb == 0x44`; `STARTF_USESTDHANDLES` is set | malformed fields must not be interpreted as process-launch success | `hStdInput`, `hStdOutput`, and `hStdError` each equal `client_socket`, not `listen_socket` |
| `CreateProcessA` | nonzero return transfers to `success` then `ExitProcess(0)` | zero return transfers to `fail` | Saved `cpa_ret`; child process exists and command I/O is reachable through the client connection |

## Static and Assembly Gates

Run these before the VM session. Preserve their output with the generated
artifacts. A failure stops the acceptance run; it is not resolved by changing a
golden fixture without explaining the output difference.

```bash
rtk uv run pytest emitrion/tests/test_workflow_validator.py emitrion/tests/test_workflow_x86.py emitrion/tests/test_workflow_goldens.py -q
```

```bash
rtk uv run python -m emitrion.verify emitrion/manifests/bindshell.yaml --template ir_bind_shell --out verify_out
```

The verification report must show `passed: true`, `assembled: true`,
`badchar_clean: true`, `deterministic: true`, no errors, a non-empty SHA-256,
and a nonzero shellcode size.

Review the generated contract and assembly for these invariants:

- Each API result has a named stack slot and an explicit branch.
- `listen_socket` is used only as the listening handle for `bind`, `listen`,
  and `accept`.
- `client_socket` is used for all three standard handles passed to
  `CreateProcessA`.
- Argument lowering reloads named values from their slots; no correctness claim
  depends on a value remaining in `eax` across another argument resolution.

## Windows x86 Lab VM Procedure

1. Copy the generated `debug_runner.py`, assembly, contract, bytes, and
   verification report to the isolated Windows x86 VM.
2. Launch the runner and attach WinDbg to the specific paused 32-bit
   `python.exe` process. Confirm the printed shellcode address maps to the
   selected process before setting breakpoints.
3. At each API return boundary, inspect `eax`, the corresponding saved result
   slot, and the following branch. Record the result in the evidence table.
4. Once `listen` succeeds, confirm the VM is listening on the configured port.
   Connect from the isolated test client only after that observation.
5. At `accept`, record both socket values. Confirm that `STARTUPINFOA` standard
   handles contain the accepted client handle before `CreateProcessA`.
6. Record `CreateProcessA`'s return value and the child process identity.
   On success, verify interactive command I/O through the client connection.
7. Exercise at least one controlled failure path (for example, an occupied
   listening port) and record that it reaches `ExitProcess(1)` rather than the
   success path.

The operator retains execution control in WinDbg. This matrix intentionally
does not prescribe continue, step, or trace commands.

## Acceptance Record

Mark each item `PASS`, `FAIL`, or `INCOMPLETE`; do not infer VM success from
the static gates.

| Gate | Status | Evidence location | Notes |
|---|---|---|---|
| Workflow validation and focused tests | INCOMPLETE |  |  |
| Assembly, bad-character, and determinism report | INCOMPLETE |  |  |
| Listener observed after `listen` | INCOMPLETE |  |  |
| Accepted socket correctly wired to child stdio | INCOMPLETE |  |  |
| `CreateProcessA` success and interactive I/O | INCOMPLETE |  |  |
| Controlled failure reaches fail exit | INCOMPLETE |  |  |
