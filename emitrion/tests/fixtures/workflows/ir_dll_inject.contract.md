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
| `[ebp-0x38]` | VirtualAllocEx | kernel32.dll |
| `[ebp-0x3c]` | WriteProcessMemory | kernel32.dll |
| `[ebp-0x40]` | GetModuleHandleA | kernel32.dll |
| `[ebp-0x44]` | GetProcAddress | kernel32.dll |
| `[ebp-0x48]` | CreateRemoteThread | kernel32.dll |
| `[ebp-0x4c]` | CloseHandle | kernel32.dll |
| `[ebp-0x50]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x54]` | snapshot | 4 |
| `[ebp-0x58]` | p32f_ret | 4 |
| `[ebp-0x5c]` | p32n_ret | 4 |
| `[ebp-0x60]` | target_pid | 4 |
| `[ebp-0x64]` | proc_handle | 4 |
| `[ebp-0x68]` | remote_buf | 4 |
| `[ebp-0x6c]` | wpm_ret | 4 |
| `[ebp-0x70]` | k32_handle | 4 |
| `[ebp-0x74]` | loadlib_addr | 4 |
| `[ebp-0x78]` | thread_handle | 4 |

## Structures

| Offset | Structure | Size |
|--------|-----------|------|
| `[ebp-0x228]` | PROCESSENTRY32 | 0x128 |

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x234]` | process_name | target.exe | 12 |
| `[ebp-0x240]` | dll_path | C:\dest.txt | 12 |
| `[ebp-0x250]` | kernel32_str | kernel32.dll | 16 |
| `[ebp-0x260]` | loadlib_str | LoadLibraryA | 16 |

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
| VirtualAllocEx | `0x6e1a959c` | `[ebp-0x38]` | memory |
| WriteProcessMemory | `0xd83d6aa1` | `[ebp-0x3c]` | memory |
| GetModuleHandleA | `0xd3324904` | `[ebp-0x40]` | library |
| GetProcAddress | `0x7c0dfcaa` | `[ebp-0x44]` | library |
| CreateRemoteThread | `0x72bd9cdd` | `[ebp-0x48]` | process |
| CloseHandle | `0x0ffd97fb` | `[ebp-0x4c]` | synchronization |
| ExitProcess | `0x73e2d87e` | `[ebp-0x50]` | process |

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

#### VirtualAllocEx

**Slot:** `[ebp-0x38]`
**Hash:** `0x6e1a959c`
**Module:** kernel32.dll
**Category:** memory

```c
LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hProcess | HANDLE | target process handle from OpenProcess |
| 2 | lpAddress | LPVOID | NULL to let OS choose |
| 3 | dwSize | SIZE_T | size of region in bytes |
| 4 | flAllocationType | DWORD | MEM_COMMIT|MEM_RESERVE = 0x3000 |
| 5 | flProtect | DWORD | PAGE_EXECUTE_READWRITE = 0x40 |

---

#### WriteProcessMemory

**Slot:** `[ebp-0x3c]`
**Hash:** `0xd83d6aa1`
**Module:** kernel32.dll
**Category:** memory

```c
BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hProcess | HANDLE | target process handle |
| 2 | lpBaseAddress | LPVOID | address in target process from VirtualAllocEx |
| 3 | lpBuffer | LPCVOID | local buffer to write from |
| 4 | nSize | SIZE_T | number of bytes to write |
| 5 | lpNumberOfBytesWritten | SIZE_T* | NULL or pointer to SIZE_T |

---

#### GetModuleHandleA

**Slot:** `[ebp-0x40]`
**Hash:** `0xd3324904`
**Module:** kernel32.dll
**Category:** library

```c
HMODULE GetModuleHandleA(LPCSTR lpModuleName)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpModuleName | LPCSTR | NULL returns base of current process; or e.g. kernel32.dll |

---

#### GetProcAddress

**Slot:** `[ebp-0x44]`
**Hash:** `0x7c0dfcaa`
**Module:** kernel32.dll
**Category:** library

```c
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hModule | HMODULE | base address of loaded module |
| 2 | lpProcName | LPCSTR | function name string |

---

#### CreateRemoteThread

**Slot:** `[ebp-0x48]`
**Hash:** `0x72bd9cdd`
**Module:** kernel32.dll
**Category:** process

```c
HANDLE CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hProcess | HANDLE | target process handle |
| 2 | lpThreadAttributes | LPSECURITY_ATTRIBUTES | NULL |
| 3 | dwStackSize | SIZE_T | 0 for default |
| 4 | lpStartAddress | LPTHREAD_START_ROUTINE | LoadLibraryA address in target |
| 5 | lpParameter | LPVOID | remote buffer with DLL path |
| 6 | dwCreationFlags | DWORD | 0 to run immediately |
| 7 | lpThreadId | LPDWORD | NULL |

---

#### CloseHandle

**Slot:** `[ebp-0x4c]`
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

#### ExitProcess

**Slot:** `[ebp-0x50]`
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

**Template:** IRDllInjectTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Target process:**
```
target.exe
```

**DLL to inject:**
```
C:\dest.txt
```

**Verify injection:**
```
tasklist /m /fi "imagename eq target.exe"
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
dd ebp-0x38 L1    ; VirtualAllocEx
dd ebp-0x3c L1    ; WriteProcessMemory
dd ebp-0x40 L1    ; GetModuleHandleA
dd ebp-0x44 L1    ; GetProcAddress
dd ebp-0x48 L1    ; CreateRemoteThread
dd ebp-0x4c L1    ; CloseHandle
dd ebp-0x50 L1    ; ExitProcess
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
da ebp-0x240    ; dll_path
```

```
da ebp-0x250    ; kernel32_str
```

```
da ebp-0x260    ; loadlib_str
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
bp <sc_base>+<offset_of_call_VirtualAllocEx>
bp <sc_base>+<offset_of_call_WriteProcessMemory>
bp <sc_base>+<offset_of_call_GetModuleHandleA>
bp <sc_base>+<offset_of_call_GetProcAddress>
bp <sc_base>+<offset_of_call_CreateRemoteThread>
bp <sc_base>+<offset_of_call_CloseHandle>
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.