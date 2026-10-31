"""Target architecture definitions for the shellcode emitter."""
from __future__ import annotations

from enum import Enum


class Arch(Enum):
    X86 = "x86"
    X64 = "x64"

    @property
    def ptr_size(self) -> int:
        return 4 if self == Arch.X86 else 8

    @property
    def bits(self) -> int:
        return 32 if self == Arch.X86 else 64
