# Shellcode Contract

Generated from manifest.

---

# Stack Layout

Frame: `mov ebp, esp` / `sub esp, 0x100` (0x100 bytes reserved)

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
| `[ebp-0x2c]` | RegOpenKeyExA | advapi32.dll |
| `[ebp-0x30]` | RegSetValueExA | advapi32.dll |
| `[ebp-0x34]` | RegCloseKey | advapi32.dll |
| `[ebp-0x38]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x3c]` | reg_handle | 4 |
| `[ebp-0x40]` | regopen_ret | 4 |
| `[ebp-0x44]` | regset_ret | 4 |

## Structures

_No structures._

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0xb0]` | reg_subkey | SOFTWARE\Microsoft\Windows\CurrentVersion\Run | 48 |
| `[ebp-0xbc]` | reg_value_name | UpdateSvc | 12 |
| `[ebp-0xc8]` | dst_path | C:\dest.txt | 12 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x28]` | library |
| ExitProcess | `0x73e2d87e` | `[ebp-0x38]` | process |

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

**Slot:** `[ebp-0x38]`
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
| RegOpenKeyExA | `0xa84aeb81` | `[ebp-0x2c]` | registry |
| RegSetValueExA | `0x2d1c9add` | `[ebp-0x30]` | registry |
| RegCloseKey | `0x35e273e6` | `[ebp-0x34]` | registry |

### API Details

#### RegOpenKeyExA

**Slot:** `[ebp-0x2c]`
**Hash:** `0xa84aeb81`
**Module:** advapi32.dll
**Category:** registry

```c
LSTATUS RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hKey | HKEY | HKEY_LOCAL_MACHINE = 0x80000002 or HKEY_CURRENT_USER = 0x80000001 |
| 2 | lpSubKey | LPCSTR | registry path string |
| 3 | ulOptions | DWORD | 0 |
| 4 | samDesired | REGSAM | KEY_SET_VALUE = 0x0002 |
| 5 | phkResult | PHKEY | pointer to HKEY output |

---

#### RegSetValueExA

**Slot:** `[ebp-0x30]`
**Hash:** `0x2d1c9add`
**Module:** advapi32.dll
**Category:** registry

```c
LSTATUS RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hKey | HKEY | opened registry key handle |
| 2 | lpValueName | LPCSTR | value name string |
| 3 | Reserved | DWORD | 0 |
| 4 | dwType | DWORD | REG_SZ = 1 |
| 5 | lpData | const BYTE* | pointer to data (string for REG_SZ) |
| 6 | cbData | DWORD | size of data in bytes including null terminator |

---

#### RegCloseKey

**Slot:** `[ebp-0x34]`
**Hash:** `0x35e273e6`
**Module:** advapi32.dll
**Category:** registry

```c
LSTATUS RegCloseKey(HKEY hKey)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hKey | HKEY | opened registry key handle |

---

---

# Structure Layouts

---

# Operational Cheatsheet

**Template:** IRRegistryPersistTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Registry hive:**
```
HKEY_CURRENT_USER
```

**Run key:**
```
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**Value name:**
```
UpdateSvc
```

**Binary path on target:**
```
C:\dest.txt
```

**Check value:**
```
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v UpdateSvc
```

**Remove value:**
```
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v UpdateSvc /f
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
dd ebp-0x2c L1    ; RegOpenKeyExA
dd ebp-0x30 L1    ; RegSetValueExA
dd ebp-0x34 L1    ; RegCloseKey
dd ebp-0x38 L1    ; ExitProcess
```

## Inspect Structures Before API Calls

## Inspect Stack Strings

```
da ebp-0xb0    ; reg_subkey
```

```
da ebp-0xbc    ; reg_value_name
```

```
da ebp-0xc8    ; dst_path
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_LoadLibraryA>
bp <sc_base>+<offset_of_call_RegOpenKeyExA>
bp <sc_base>+<offset_of_call_RegSetValueExA>
bp <sc_base>+<offset_of_call_RegCloseKey>
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.