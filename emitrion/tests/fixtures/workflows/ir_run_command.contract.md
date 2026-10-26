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
| `[ebp-0x24]` | WinExec | kernel32.dll |
| `[ebp-0x28]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x2c]` | wexec_result | 4 |

## Structures

_No structures._

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x8c]` | cmd | calc.exe | 12 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| WinExec | `0x0e8afe98` | `[ebp-0x24]` | process |
| ExitProcess | `0x73e2d87e` | `[ebp-0x28]` | process |

### API Details

#### WinExec

**Slot:** `[ebp-0x24]`
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

**Slot:** `[ebp-0x28]`
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

**Template:** IRRunCommandTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Command executed on target:**
```
calc.exe
```

## Encoding (if needed)

Remove bad chars with msfvenom (requires `shellcode.bin`):
```
cat shellcode.bin | msfvenom --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -f python -v shellcode
```
