"""ABI-enhanced API catalog for workflow validation and lowering.

Extends API_DATABASE entries with typed argument descriptors, return value
semantics, and success predicates.  Only APIs marked workflow_supported
are available for IR workflows; all others remain legacy_only.

The first milestone annotates only the APIs used by the reference workflow.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .ir import SuccessPredicate


class ArgDirection(Enum):
    IN = "in"
    OUT = "out"
    INOUT = "inout"


class ArgCategory(Enum):
    IMMEDIATE = "immediate"
    STRING_PTR = "string_ptr"
    STRUCT_PTR = "struct_ptr"
    BUFFER_PTR = "buffer_ptr"
    HANDLE = "handle"
    NULL_PTR = "null_ptr"


@dataclass(frozen=True)
class ArgDescriptor:
    """Typed descriptor for a single API argument."""
    name: str
    direction: ArgDirection
    category: ArgCategory
    struct_type: str | None = None


@dataclass(frozen=True)
class ReturnDescriptor:
    """Typed descriptor for an API return value."""
    type_name: str
    success: SuccessPredicate


@dataclass(frozen=True)
class ABIRecord:
    """ABI-complete description of a Win32 API for workflow use."""
    calling_convention: str
    arguments: tuple[ArgDescriptor, ...]
    returns: ReturnDescriptor | None
    workflow_supported: bool = False


# ---------------------------------------------------------------------------
# ABI catalog: workflow-supported entries
# ---------------------------------------------------------------------------

ABI_CATALOG: dict[str, ABIRecord] = {
    "WinExec": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpCmdLine", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("uCmdShow", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("UINT", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "ExitProcess": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("uExitCode", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=None,
        workflow_supported=True,
    ),
    "CreateProcessA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpApplicationName", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpCommandLine", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("lpProcessAttributes", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpThreadAttributes", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("bInheritHandles", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwCreationFlags", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpEnvironment", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpCurrentDirectory", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpStartupInfo", ArgDirection.IN, ArgCategory.STRUCT_PTR,
                          struct_type="STARTUPINFOA"),
            ArgDescriptor("lpProcessInformation", ArgDirection.OUT, ArgCategory.STRUCT_PTR,
                          struct_type="PROCESS_INFORMATION"),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "WSAStartup": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("wVersionRequested", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpWSAData", ArgDirection.OUT, ArgCategory.STRUCT_PTR,
                          struct_type="WSADATA"),
        ),
        returns=ReturnDescriptor("int", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
    "WSASocketA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("af", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("type", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("protocol", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpProtocolInfo", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("g", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwFlags", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("SOCKET", SuccessPredicate.INVALID_HANDLE),
        workflow_supported=True,
    ),
    "connect": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("s", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("name", ArgDirection.IN, ArgCategory.STRUCT_PTR,
                          struct_type="sockaddr_in"),
            ArgDescriptor("namelen", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("int", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
    "bind": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("s", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("addr", ArgDirection.IN, ArgCategory.STRUCT_PTR,
                          struct_type="sockaddr_in"),
            ArgDescriptor("namelen", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("int", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
    "listen": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("s", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("backlog", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("int", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
    "accept": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("s", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("addr", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("addrlen", ArgDirection.IN, ArgCategory.NULL_PTR),
        ),
        returns=ReturnDescriptor("SOCKET", SuccessPredicate.INVALID_HANDLE),
        workflow_supported=True,
    ),
    "CopyFileA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpExistingFileName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("lpNewFileName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("bFailIfExists", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "LoadLibraryA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpLibFileName", ArgDirection.IN, ArgCategory.STRING_PTR),
        ),
        returns=ReturnDescriptor("HMODULE", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
}


def get_abi(api_name: str) -> ABIRecord | None:
    """Look up an ABI record.  Returns None for APIs not in the catalog."""
    return ABI_CATALOG.get(api_name)
