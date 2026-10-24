"""Check-path primitive.

Calls GetFileAttributesA on a target path and branches on the result.
This is the simplest observable primitive: one API call, deterministic
outcome, no side effects.

Contract:
  Precondition:  check_path string slot contains a null-terminated path.
  Postcondition: eax = file attributes (path exists) or
                 eax = INVALID_FILE_ATTRIBUTES / 0xFFFFFFFF (missing/error).
  Branch:        cp_present if path exists, cp_missing otherwise.
  Observation:   break on cp_present / cp_missing in WinDbg to verify.

Template sequence:
  GetFileAttributesA(check_path) -> branch on INVALID_FILE_ATTRIBUTES

Required functions: GetFileAttributesA
Required variables: path_attrs
Required strings:   check_path
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from ..encode import (
    safe_lea, safe_mem_store,
    safe_call_mem,
)


class CheckPathTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars

        getattr_off = -layout.slot("GetFileAttributesA").offset
        attrs_off   = -layout.slot("path_attrs").offset
        path_off    = -layout.slot("check_path").offset

        return "\n".join([
            "; -- Check Path Primitive --",
            "; Precondition:  check_path string on stack",
            "; Postcondition: eax = attributes or 0xFFFFFFFF",
            "; Branches to cp_present or cp_missing",
            "",

            "    ; GetFileAttributesA(check_path)",
            *safe_lea("eax", "ebp", path_off, bc),
            "    push eax                    ; lpFileName",
            *safe_call_mem("ebp", getattr_off, bc),
            *safe_mem_store("ebp", attrs_off, "eax", bc),
            "",

            "    ; INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF",
            "    cmp  eax, 0xFFFFFFFF",
            "    je   cp_missing",
            "",

            "cp_present:",
            "    ; Path exists, eax = file attributes",
            "    nop                          ; observation point",
            "    jmp  cp_done",
            "",

            "cp_missing:",
            "    ; Path does not exist or error",
            "    nop                          ; observation point",
            "",

            "cp_done:",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        path = config.dst_path or "(manifest check_path string)"
        return [
            ("Path checked", path),
            ("Break on present", "bp cp_present"),
            ("Break on missing", "bp cp_missing"),
            ("Read result", "r eax  ; 0xFFFFFFFF = missing"),
        ]
