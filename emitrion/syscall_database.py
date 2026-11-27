"""Static database of Linux x86_64 syscall records for shellcode development.

Parallel to api_database.py for Windows. Maps syscall names to their numbers,
argument registers, and return value semantics. Only x86_64 (64-bit) syscall
numbers are included; x86 (32-bit int 0x80) uses different numbers.

Linux x86_64 syscall convention:
  - Syscall number in RAX
  - Arguments in RDI, RSI, RDX, R10, R8, R9 (up to 6)
  - Return value in RAX
  - RCX and R11 are clobbered by the kernel
  - All other registers are preserved
"""
from __future__ import annotations

from dataclasses import dataclass

from .workflow.ir import SuccessPredicate


SYSCALL_ARG_REGS = ("rdi", "rsi", "rdx", "r10", "r8", "r9")


@dataclass(frozen=True)
class SyscallArg:
    name: str
    register: str


@dataclass(frozen=True)
class SyscallReturn:
    type_name: str
    success: SuccessPredicate


@dataclass(frozen=True)
class SyscallRecord:
    name: str
    number: int
    arguments: tuple[SyscallArg, ...]
    returns: SyscallReturn | None = None


def _args(*names: str) -> tuple[SyscallArg, ...]:
    return tuple(SyscallArg(n, SYSCALL_ARG_REGS[i]) for i, n in enumerate(names))


SYSCALL_DATABASE: dict[str, SyscallRecord] = {
    "read": SyscallRecord(
        "read", 0,
        _args("fd", "buf", "count"),
        SyscallReturn("ssize_t", SuccessPredicate.SIGNED_NEGATIVE),
    ),
    "write": SyscallRecord(
        "write", 1,
        _args("fd", "buf", "count"),
        SyscallReturn("ssize_t", SuccessPredicate.SIGNED_NEGATIVE),
    ),
    "open": SyscallRecord(
        "open", 2,
        _args("filename", "flags", "mode"),
        SyscallReturn("int", SuccessPredicate.SIGNED_NEGATIVE),
    ),
    "close": SyscallRecord(
        "close", 3,
        _args("fd"),
        SyscallReturn("int", SuccessPredicate.ZERO),
    ),
    "mmap": SyscallRecord(
        "mmap", 9,
        _args("addr", "length", "prot", "flags", "fd", "offset"),
        SyscallReturn("void*", SuccessPredicate.SIGNED_NEGATIVE),
    ),
    "mprotect": SyscallRecord(
        "mprotect", 10,
        _args("addr", "len", "prot"),
        SyscallReturn("int", SuccessPredicate.ZERO),
    ),
    "dup2": SyscallRecord(
        "dup2", 33,
        _args("oldfd", "newfd"),
        SyscallReturn("int", SuccessPredicate.SIGNED_NEGATIVE),
    ),
    "socket": SyscallRecord(
        "socket", 41,
        _args("domain", "type", "protocol"),
        SyscallReturn("int", SuccessPredicate.SIGNED_NEGATIVE),
    ),
    "connect": SyscallRecord(
        "connect", 42,
        _args("sockfd", "addr", "addrlen"),
        SyscallReturn("int", SuccessPredicate.ZERO),
    ),
    "accept": SyscallRecord(
        "accept", 43,
        _args("sockfd", "addr", "addrlen"),
        SyscallReturn("int", SuccessPredicate.SIGNED_NEGATIVE),
    ),
    "bind": SyscallRecord(
        "bind", 49,
        _args("sockfd", "addr", "addrlen"),
        SyscallReturn("int", SuccessPredicate.ZERO),
    ),
    "listen": SyscallRecord(
        "listen", 50,
        _args("sockfd", "backlog"),
        SyscallReturn("int", SuccessPredicate.ZERO),
    ),
    "execve": SyscallRecord(
        "execve", 59,
        _args("filename", "argv", "envp"),
        SyscallReturn("int", SuccessPredicate.SIGNED_NEGATIVE),
    ),
    "exit": SyscallRecord(
        "exit", 60,
        _args("status"),
        returns=None,
    ),
}
