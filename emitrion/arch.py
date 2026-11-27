"""Typed target identity for the shellcode emitter.

Supports Windows x86/x64 and Linux x64. Keeping the operating system and
ABI beside the instruction-set architecture prevents future targets from
being modelled as architecture-only special cases.
"""
from __future__ import annotations

from dataclasses import dataclass
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


class TargetOS(Enum):
    """Operating systems planned or supported as shellcode targets."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class CallingConvention(Enum):
    """Calling conventions currently modelled by target selection."""

    WINDOWS_X86_STDCALL = "windows_x86_stdcall"
    WINDOWS_X64 = "windows_x64"
    LINUX_X64_SYSCALL = "linux_x64_syscall"


@dataclass(frozen=True)
class TargetSpec:
    """The OS, ISA, and ABI contract selected for a build.

    Linux and macOS are named here to make the extension point explicit, but
    they are intentionally not accepted by the current Windows-only pipeline.
    """

    os: TargetOS
    arch: Arch

    @classmethod
    def from_values(cls, os: str, arch: str) -> TargetSpec:
        """Construct a target from manifest-compatible string values."""
        return cls(os=TargetOS(os), arch=Arch(arch))

    @property
    def calling_convention(self) -> CallingConvention:
        """Return the ABI implied by a currently supported target."""
        if self.os is TargetOS.LINUX:
            if self.arch is Arch.X64:
                return CallingConvention.LINUX_X64_SYSCALL
            raise ValueError(f"Linux {self.arch.value} is not yet supported")
        if self.os is not TargetOS.WINDOWS:
            raise ValueError(f"No calling convention is defined for target OS '{self.os.value}'")
        if self.arch is Arch.X86:
            return CallingConvention.WINDOWS_X86_STDCALL
        return CallingConvention.WINDOWS_X64

    @property
    def is_currently_supported(self) -> bool:
        """Whether the current emitter has a pipeline for this target."""
        if self.os is TargetOS.LINUX and self.arch is Arch.X64:
            return True
        return self.os is TargetOS.WINDOWS
