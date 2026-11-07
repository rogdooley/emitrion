# Shellcode Contract

Generated from manifest.

---

# Stack Layout

Frame: `mov ebp, esp` / `sub esp, 0x300` (0x300 bytes reserved)

## Export Context (reserved - do not allocate)

| Offset | Description |
|--------|-------------|
| `[ebp-0x04]` | Module base (transient) |
| `[ebp-0x08]` | AddressOfNames VA |
| `[ebp-0x0c]` | AddressOfNameOrdinals VA |
| `[ebp-0x10]` | AddressOfFunctions VA |
| `[ebp-0x14]` | NumberOfNames |
| `[ebp-0x18]` | Target hash (transient) |

## Module Bases

| Offset | Module |
|--------|--------|
| `[ebp-0x20]` | kernel32.dll |

## API Table

| Offset | API | Module |
|--------|-----|--------|
| `[ebp-0x24]` | LoadLibraryA | kernel32.dll |
| `[ebp-0x28]` | CreateToolhelp32Snapshot | kernel32.dll |
| `[ebp-0x2c]` | Process32First | kernel32.dll |
| `[ebp-0x30]` | Process32Next | kernel32.dll |
| `[ebp-0x34]` | OpenProcess | kernel32.dll |
| `[ebp-0x38]` | TerminateProcess | kernel32.dll |
| `[ebp-0x3c]` | WaitForSingleObject | kernel32.dll |
| `[ebp-0x40]` | CloseHandle | kernel32.dll |
| `[ebp-0x44]` | CopyFileA | kernel32.dll |
| `[ebp-0x48]` | WinExec | kernel32.dll |
| `[ebp-0x4c]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x50]` | snapshot | 4 |
| `[ebp-0x54]` | p32f_ret | 4 |
| `[ebp-0x58]` | p32n_ret | 4 |
| `[ebp-0x5c]` | target_pid | 4 |
| `[ebp-0x60]` | proc_handle | 4 |
| `[ebp-0x64]` | copy_ret | 4 |
| `[ebp-0x68]` | exec_ret | 4 |

## Structures

| Offset | Structure | Size |
|--------|-----------|------|
| `[ebp-0x228]` | PROCESSENTRY32 | 0x128 |

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x234]` | process_name | target.exe | 12 |
| `[ebp-0x244]` | src_path | C:\source.txt | 16 |
| `[ebp-0x250]` | dst_path | C:\dest.txt | 12 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x24]` | library |
| CreateToolhelp32Snapshot | `0xe454dfed` | `[ebp-0x28]` | process |
| Process32First | `0x3249baa7` | `[ebp-0x2c]` | process |
| Process32Next | `0x4776654a` | `[ebp-0x30]` | process |
| OpenProcess | `0xefe297c0` | `[ebp-0x34]` | process |
| TerminateProcess | `0x78b5b983` | `[ebp-0x38]` | process |
| WaitForSingleObject | `0xce05d9ad` | `[ebp-0x3c]` | synchronization |
| CloseHandle | `0x0ffd97fb` | `[ebp-0x40]` | synchronization |
| CopyFileA | `0x99ec895e` | `[ebp-0x44]` | filesystem |
| WinExec | `0x0e8afe98` | `[ebp-0x48]` | process |
| ExitProcess | `0x73e2d87e` | `[ebp-0x4c]` | process |

### API Details

#### LoadLibraryA

**Slot:** `[ebp-0x24]`
**Hash:** `0xec0e4e8e`
**Module:** kernel32.dll
**Category:** library

```c
HMODULE LoadLibraryA(LPCSTR lpLibFileName)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpLibFileName | LPCSTR | e.g. ws2_32.dll |

---

#### CreateToolhelp32Snapshot

**Slot:** `[ebp-0x28]`
**Hash:** `0xe454dfed`
**Module:** kernel32.dll
**Category:** process

```c
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | dwFlags | DWORD | TH32CS_SNAPPROCESS = 0x02 |
| 2 | th32ProcessID | DWORD | 0 for all processes |

---

#### Process32First

**Slot:** `[ebp-0x2c]`
**Hash:** `0x3249baa7`
**Module:** kernel32.dll
**Category:** process

```c
BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hSnapshot | HANDLE | from CreateToolhelp32Snapshot |
| 2 | lppe | LPPROCESSENTRY32 | cb must be set to sizeof(PROCESSENTRY32) |

---

#### Process32Next

**Slot:** `[ebp-0x30]`
**Hash:** `0x4776654a`
**Module:** kernel32.dll
**Category:** process

```c
BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hSnapshot | HANDLE | from CreateToolhelp32Snapshot |
| 2 | lppe | LPPROCESSENTRY32 | reused from Process32First |

---

#### OpenProcess

**Slot:** `[ebp-0x34]`
**Hash:** `0xefe297c0`
**Module:** kernel32.dll
**Category:** process

```c
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | dwDesiredAccess | DWORD | PROCESS_TERMINATE = 0x0001 |
| 2 | bInheritHandle | BOOL | FALSE |
| 3 | dwProcessId | DWORD | from PROCESSENTRY32.th32ProcessID |

---

#### TerminateProcess

**Slot:** `[ebp-0x38]`
**Hash:** `0x78b5b983`
**Module:** kernel32.dll
**Category:** process

```c
BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hProcess | HANDLE | from OpenProcess |
| 2 | uExitCode | UINT | 0 |

---

#### WaitForSingleObject

**Slot:** `[ebp-0x3c]`
**Hash:** `0xce05d9ad`
**Module:** kernel32.dll
**Category:** synchronization

```c
DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hHandle | HANDLE | thread or process handle to wait on |
| 2 | dwMilliseconds | DWORD | INFINITE = 0xFFFFFFFF; or timeout in ms |

---

#### CloseHandle

**Slot:** `[ebp-0x40]`
**Hash:** `0x0ffd97fb`
**Module:** kernel32.dll
**Category:** synchronization

```c
BOOL CloseHandle(HANDLE hObject)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hObject | HANDLE | handle to close; returns nonzero on success |

---

#### CopyFileA

**Slot:** `[ebp-0x44]`
**Hash:** `0x99ec895e`
**Module:** kernel32.dll
**Category:** filesystem

```c
BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpExistingFileName | LPCSTR |  |
| 2 | lpNewFileName | LPCSTR |  |
| 3 | bFailIfExists | BOOL | FALSE to overwrite |

---

#### WinExec

**Slot:** `[ebp-0x48]`
**Hash:** `0x0e8afe98`
**Module:** kernel32.dll
**Category:** process

```c
UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpCmdLine | LPCSTR | pointer to command string, e.g. cmd.exe |
| 2 | uCmdShow | UINT | SW_SHOWNORMAL = 1 or SW_HIDE = 0 |

---

#### ExitProcess

**Slot:** `[ebp-0x4c]`
**Hash:** `0x73e2d87e`
**Module:** kernel32.dll
**Category:** process

```c
VOID ExitProcess(UINT uExitCode)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | uExitCode | UINT | 0 for clean exit |

---

---

# Structure Layouts

## PROCESSENTRY32

**Size:** `0x128`
**Required by:** Process32First, Process32Next

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| `+0x00` | dwSize | 4 | must be 0x128 = sizeof(PROCESSENTRY32) |
| `+0x08` | th32ProcessID | 4 | PID of the process |
| `+0x24` | szExeFile | 260 | null-terminated process name (MAX_PATH) |

---

---

# Operational Cheatsheet

**Template:** IRProcessReplaceTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Target process:**
```
target.exe
```

**Source file:**
```
C:\source.txt
```

**Destination (also executed):**
```
C:\dest.txt
```

## Encoding (if needed)

Remove bad chars with msfvenom (requires `shellcode.bin`):
```
cat shellcode.bin | msfvenom --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -f python -v shellcode
```

---

# WinDbg Cheatsheet

Run `debug_runner.py` under 32-bit Python. Attach WinDbg to the
python.exe process. Set `bp <address>` using the printed shellcode
address, then press Enter in the script to start execution.

## Quick Reference

| Command | Description |
|---------|-------------|
| `bp <addr>` | Set breakpoint |
| `bl` | List breakpoints |
| `g` | Go (continue) |
| `t` | Step into |
| `p` | Step over |
| `pt` | Step to next return |
| `r` | Show all registers |
| `r eax` | Show one register |
| `u eip L10` | Disassemble next 16 instructions |
| `db <addr> L<n>` | Dump bytes |
| `dd <addr> L<n>` | Dump dwords |
| `da <addr>` | Dump ASCII string |
| `!address <addr>` | Show memory region info |

## Inspect API Pointers After Resolution

After the PEB walk and hash resolution, each resolved function
pointer is stored at its stack slot. Verify with:

```
dd ebp-0x24 L1    ; LoadLibraryA
dd ebp-0x28 L1    ; CreateToolhelp32Snapshot
dd ebp-0x2c L1    ; Process32First
dd ebp-0x30 L1    ; Process32Next
dd ebp-0x34 L1    ; OpenProcess
dd ebp-0x38 L1    ; TerminateProcess
dd ebp-0x3c L1    ; WaitForSingleObject
dd ebp-0x40 L1    ; CloseHandle
dd ebp-0x44 L1    ; CopyFileA
dd ebp-0x48 L1    ; WinExec
dd ebp-0x4c L1    ; ExitProcess
```

## Inspect Structures Before API Calls

### PROCESSENTRY32 (0x128 bytes)

Base address: `ebp-0x228`

```
dd ebp-0x228 L8    ; first 8 dwords
db ebp-0x228 L20    ; raw bytes
```

Key fields:

- `dd ebp-0x228 L1`  dwSize (+0x00)
- `dd ebp-0x220 L1`  th32ProcessID (+0x08)
- `dd ebp-0x204 L1`  szExeFile (+0x24)

## Inspect Stack Strings

```
da ebp-0x234    ; process_name
```

```
da ebp-0x244    ; src_path
```

```
da ebp-0x250    ; dst_path
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_LoadLibraryA>
bp <sc_base>+<offset_of_call_CreateToolhelp32Snapshot>
bp <sc_base>+<offset_of_call_Process32First>
bp <sc_base>+<offset_of_call_Process32Next>
bp <sc_base>+<offset_of_call_OpenProcess>
bp <sc_base>+<offset_of_call_TerminateProcess>
bp <sc_base>+<offset_of_call_WaitForSingleObject>
bp <sc_base>+<offset_of_call_CloseHandle>
bp <sc_base>+<offset_of_call_CopyFileA>
bp <sc_base>+<offset_of_call_WinExec>  ; eax>31 on success
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.