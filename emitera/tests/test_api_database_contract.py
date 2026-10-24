"""Semantic contract tests for API_DATABASE.

These tests assert specific values - module ownership, category, argument count,
and struct dependencies - for every API that appears in project manifests.
A failing test here means the database has drifted from reality.
"""
from __future__ import annotations

from ..api_database import API_DATABASE


# ---------------------------------------------------------------------------
# kernel32.dll - process
# ---------------------------------------------------------------------------

def test_winexec_contract():
    r = API_DATABASE["WinExec"]
    assert r.module   == "kernel32.dll"
    assert r.category == "process"
    assert len(r.arguments) == 2
    assert r.requires_structs == ()


def test_exitprocess_contract():
    r = API_DATABASE["ExitProcess"]
    assert r.module   == "kernel32.dll"
    assert r.category == "process"
    assert len(r.arguments) == 1
    assert r.requires_structs == ()


def test_createprocessa_contract():
    r = API_DATABASE["CreateProcessA"]
    assert r.module   == "kernel32.dll"
    assert r.category == "process"
    assert len(r.arguments) == 10
    assert r.requires_structs == ("STARTUPINFOA", "PROCESS_INFORMATION")


# ---------------------------------------------------------------------------
# kernel32.dll - library
# ---------------------------------------------------------------------------

def test_loadlibrarya_contract():
    r = API_DATABASE["LoadLibraryA"]
    assert r.module   == "kernel32.dll"
    assert r.category == "library"
    assert len(r.arguments) == 1
    assert r.requires_structs == ()


def test_getprocaddress_contract():
    r = API_DATABASE["GetProcAddress"]
    assert r.module   == "kernel32.dll"
    assert r.category == "library"
    assert len(r.arguments) == 2
    assert r.requires_structs == ()


# ---------------------------------------------------------------------------
# kernel32.dll - filesystem
# ---------------------------------------------------------------------------

def test_copyfile_contract():
    r = API_DATABASE["CopyFileA"]
    assert r.module   == "kernel32.dll"
    assert r.category == "filesystem"
    assert len(r.arguments) == 3
    assert r.requires_structs == ()


def test_deletefilea_contract():
    r = API_DATABASE["DeleteFileA"]
    assert r.module   == "kernel32.dll"
    assert r.category == "filesystem"
    assert len(r.arguments) == 1
    assert r.requires_structs == ()


def test_movefilea_contract():
    r = API_DATABASE["MoveFileA"]
    assert r.module   == "kernel32.dll"
    assert r.category == "filesystem"
    assert len(r.arguments) == 2
    assert r.requires_structs == ()


# ---------------------------------------------------------------------------
# ws2_32.dll - network
# ---------------------------------------------------------------------------

def test_wsastartup_contract():
    r = API_DATABASE["WSAStartup"]
    assert r.module   == "ws2_32.dll"
    assert r.category == "network"
    assert len(r.arguments) == 2
    assert r.requires_structs == ("WSADATA",)


def test_wsasocketa_contract():
    r = API_DATABASE["WSASocketA"]
    assert r.module   == "ws2_32.dll"
    assert r.category == "network"
    assert len(r.arguments) == 6
    assert r.requires_structs == ()


def test_connect_contract():
    r = API_DATABASE["connect"]
    assert r.module   == "ws2_32.dll"
    assert r.category == "network"
    assert len(r.arguments) == 3
    assert r.requires_structs == ("sockaddr_in",)


# ---------------------------------------------------------------------------
# kernel32.dll - memory
# ---------------------------------------------------------------------------

def test_virtualalloc_contract():
    r = API_DATABASE["VirtualAlloc"]
    assert r.module   == "kernel32.dll"
    assert r.category == "memory"
    assert len(r.arguments) == 4
    assert r.requires_structs == ()


def test_virtualprotect_contract():
    r = API_DATABASE["VirtualProtect"]
    assert r.module   == "kernel32.dll"
    assert r.category == "memory"
    assert len(r.arguments) == 4
    assert r.requires_structs == ()


# ---------------------------------------------------------------------------
# kernel32.dll - process (additional)
# ---------------------------------------------------------------------------

def test_createthread_contract():
    r = API_DATABASE["CreateThread"]
    assert r.module   == "kernel32.dll"
    assert r.category == "process"
    assert len(r.arguments) == 6
    assert r.requires_structs == ()


def test_getlasterror_contract():
    r = API_DATABASE["GetLastError"]
    assert r.module   == "kernel32.dll"
    assert r.category == "process"
    assert len(r.arguments) == 0
    assert r.requires_structs == ()


# ---------------------------------------------------------------------------
# kernel32.dll - synchronization
# ---------------------------------------------------------------------------

def test_waitforsingleobject_contract():
    r = API_DATABASE["WaitForSingleObject"]
    assert r.module   == "kernel32.dll"
    assert r.category == "synchronization"
    assert len(r.arguments) == 2
    assert r.requires_structs == ()


def test_closehandle_contract():
    r = API_DATABASE["CloseHandle"]
    assert r.module   == "kernel32.dll"
    assert r.category == "synchronization"
    assert len(r.arguments) == 1
    assert r.requires_structs == ()


# ---------------------------------------------------------------------------
# kernel32.dll - filesystem (additional)
# ---------------------------------------------------------------------------

def test_readfile_contract():
    r = API_DATABASE["ReadFile"]
    assert r.module   == "kernel32.dll"
    assert r.category == "filesystem"
    assert len(r.arguments) == 5
    assert r.requires_structs == ()


def test_writefile_contract():
    r = API_DATABASE["WriteFile"]
    assert r.module   == "kernel32.dll"
    assert r.category == "filesystem"
    assert len(r.arguments) == 5
    assert r.requires_structs == ()


def test_gettemppatha_contract():
    r = API_DATABASE["GetTempPathA"]
    assert r.module   == "kernel32.dll"
    assert r.category == "filesystem"
    assert len(r.arguments) == 2
    assert r.requires_structs == ()


# ---------------------------------------------------------------------------
# kernel32.dll - library (additional)
# ---------------------------------------------------------------------------

def test_getmodulehandlea_contract():
    r = API_DATABASE["GetModuleHandleA"]
    assert r.module   == "kernel32.dll"
    assert r.category == "library"
    assert len(r.arguments) == 1
    assert r.requires_structs == ()


# ---------------------------------------------------------------------------
# ws2_32.dll - network (additional)
# ---------------------------------------------------------------------------

def test_bind_contract():
    r = API_DATABASE["bind"]
    assert r.module   == "ws2_32.dll"
    assert r.category == "network"
    assert len(r.arguments) == 3
    assert r.requires_structs == ("sockaddr_in",)


def test_listen_contract():
    r = API_DATABASE["listen"]
    assert r.module   == "ws2_32.dll"
    assert r.category == "network"
    assert len(r.arguments) == 2
    assert r.requires_structs == ()


def test_accept_contract():
    r = API_DATABASE["accept"]
    assert r.module   == "ws2_32.dll"
    assert r.category == "network"
    assert len(r.arguments) == 3
    assert r.requires_structs == ("sockaddr_in",)


def test_closesocket_contract():
    r = API_DATABASE["closesocket"]
    assert r.module   == "ws2_32.dll"
    assert r.category == "network"
    assert len(r.arguments) == 1
    assert r.requires_structs == ()


def test_wsagetlasterror_contract():
    r = API_DATABASE["WSAGetLastError"]
    assert r.module   == "ws2_32.dll"
    assert r.category == "network"
    assert len(r.arguments) == 0
    assert r.requires_structs == ()
