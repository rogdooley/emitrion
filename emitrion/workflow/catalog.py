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
    "TerminateProcess": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hProcess", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("uExitCode", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
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
    "MoveFileA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpExistingFileName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("lpNewFileName", ArgDirection.IN, ArgCategory.STRING_PTR),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "GetFileAttributesA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpFileName", ArgDirection.IN, ArgCategory.STRING_PTR),
        ),
        returns=ReturnDescriptor("DWORD", SuccessPredicate.INVALID_HANDLE),
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
    "RegOpenKeyExA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hKey", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpSubKey", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("ulOptions", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("samDesired", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("phkResult", ArgDirection.OUT, ArgCategory.HANDLE),
        ),
        returns=ReturnDescriptor("LSTATUS", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
    "RegSetValueExA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hKey", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpValueName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("Reserved", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwType", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpData", ArgDirection.IN, ArgCategory.BUFFER_PTR),
            ArgDescriptor("cbData", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("LSTATUS", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
    "RegCloseKey": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hKey", ArgDirection.IN, ArgCategory.HANDLE),
        ),
        returns=ReturnDescriptor("LSTATUS", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
    "OpenSCManagerA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpMachineName", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpDatabaseName", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("dwDesiredAccess", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("SC_HANDLE", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "CreateServiceA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hSCManager", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpServiceName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("lpDisplayName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("dwDesiredAccess", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwServiceType", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwStartType", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwErrorControl", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpBinaryPathName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("lpLoadOrderGroup", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpdwTagId", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpDependencies", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpServiceStartName", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpPassword", ArgDirection.IN, ArgCategory.NULL_PTR),
        ),
        returns=ReturnDescriptor("SC_HANDLE", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "StartServiceA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hService", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("dwNumServiceArgs", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpServiceArgVectors", ArgDirection.IN, ArgCategory.NULL_PTR),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "CloseServiceHandle": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hSCObject", ArgDirection.IN, ArgCategory.HANDLE),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "recv": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("s", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("buf", ArgDirection.IN, ArgCategory.BUFFER_PTR),
            ArgDescriptor("len", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("flags", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("int", SuccessPredicate.SIGNED_POSITIVE),
        workflow_supported=True,
    ),
    "closesocket": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("s", ArgDirection.IN, ArgCategory.HANDLE),
        ),
        returns=ReturnDescriptor("int", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
    "VirtualAlloc": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpAddress", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("dwSize", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("flAllocationType", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("flProtect", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("LPVOID", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "CreateFileA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpFileName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("dwDesiredAccess", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwShareMode", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpSecurityAttributes", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("dwCreationDisposition", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwFlagsAndAttributes", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("hTemplateFile", ArgDirection.IN, ArgCategory.NULL_PTR),
        ),
        returns=ReturnDescriptor("HANDLE", SuccessPredicate.INVALID_HANDLE),
        workflow_supported=True,
    ),
    "WriteFile": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hFile", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpBuffer", ArgDirection.IN, ArgCategory.BUFFER_PTR),
            ArgDescriptor("nNumberOfBytesToWrite", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpNumberOfBytesWritten", ArgDirection.OUT, ArgCategory.BUFFER_PTR),
            ArgDescriptor("lpOverlapped", ArgDirection.IN, ArgCategory.NULL_PTR),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "CloseHandle": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hObject", ArgDirection.IN, ArgCategory.HANDLE),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "ReadFile": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hFile", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpBuffer", ArgDirection.IN, ArgCategory.BUFFER_PTR),
            ArgDescriptor("nNumberOfBytesToRead", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpNumberOfBytesRead", ArgDirection.OUT, ArgCategory.BUFFER_PTR),
            ArgDescriptor("lpOverlapped", ArgDirection.IN, ArgCategory.NULL_PTR),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "InternetOpenA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpszAgent", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("dwAccessType", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpszProxy", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpszProxyBypass", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("dwFlags", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("HINTERNET", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "InternetOpenUrlA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hInternet", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpszUrl", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("lpszHeaders", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("dwHeadersLength", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwFlags", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwContext", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("HINTERNET", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "InternetReadFile": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hFile", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpBuffer", ArgDirection.IN, ArgCategory.BUFFER_PTR),
            ArgDescriptor("dwNumberOfBytesToRead", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpdwNumberOfBytesRead", ArgDirection.OUT, ArgCategory.BUFFER_PTR),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "InternetCloseHandle": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hInternet", ArgDirection.IN, ArgCategory.HANDLE),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "InternetConnectA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hInternet", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpszServerName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("nServerPort", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpszUserName", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpszPassword", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("dwService", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwFlags", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwContext", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("HINTERNET", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "HttpOpenRequestA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hConnect", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpszVerb", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("lpszObjectName", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("lpszVersion", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lpszReferrer", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("lplpszAcceptTypes", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("dwFlags", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("dwContext", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("HINTERNET", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),
    "HttpSendRequestA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("hRequest", ArgDirection.IN, ArgCategory.HANDLE),
            ArgDescriptor("lpszHeaders", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("dwHeadersLength", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpOptional", ArgDirection.IN, ArgCategory.BUFFER_PTR),
            ArgDescriptor("dwOptionalLength", ArgDirection.IN, ArgCategory.IMMEDIATE),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),

    # -- advapi32: username --
    "GetUserNameA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("lpBuffer", ArgDirection.OUT, ArgCategory.BUFFER_PTR),
            ArgDescriptor("pcbBuffer", ArgDirection.INOUT, ArgCategory.BUFFER_PTR),
        ),
        returns=ReturnDescriptor("BOOL", SuccessPredicate.NONZERO),
        workflow_supported=True,
    ),

    # -- urlmon: download file --
    "URLDownloadToFileA": ABIRecord(
        calling_convention="stdcall",
        arguments=(
            ArgDescriptor("pCaller", ArgDirection.IN, ArgCategory.NULL_PTR),
            ArgDescriptor("szURL", ArgDirection.IN, ArgCategory.STRING_PTR),
            ArgDescriptor("szFileName", ArgDirection.IN, ArgCategory.BUFFER_PTR),
            ArgDescriptor("dwReserved", ArgDirection.IN, ArgCategory.IMMEDIATE),
            ArgDescriptor("lpfnCB", ArgDirection.IN, ArgCategory.NULL_PTR),
        ),
        returns=ReturnDescriptor("HRESULT", SuccessPredicate.ZERO),
        workflow_supported=True,
    ),
}


def get_abi(api_name: str) -> ABIRecord | None:
    """Look up an ABI record.  Returns None for APIs not in the catalog."""
    return ABI_CATALOG.get(api_name)
