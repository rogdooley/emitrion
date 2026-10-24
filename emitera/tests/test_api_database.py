"""Tests for api_database.py."""
from __future__ import annotations

import pytest

from ..api_database import (
    API_DATABASE,
    MODULE_LOAD_ORDER,
    STRUCT_DATABASE,
    get_record,
)


def test_all_modules_are_known():
    known = {m.dll for m in MODULE_LOAD_ORDER}
    for name, record in API_DATABASE.items():
        assert record.module in known, f"{name}.module={record.module!r} not in MODULE_LOAD_ORDER"


def test_categories_are_valid():
    valid = {"process", "filesystem", "library", "network", "memory", "synchronization", "token", "service", "internet", "registry", "identity"}
    for name, record in API_DATABASE.items():
        assert record.category in valid, f"{name}.category={record.category!r} is invalid"


def test_all_records_have_arguments():
    for name, record in API_DATABASE.items():
        assert isinstance(record.arguments, list)


def test_createprocessa_has_10_args():
    assert len(API_DATABASE["CreateProcessA"].arguments) == 10


def test_struct_sizes():
    assert STRUCT_DATABASE["STARTUPINFOA"].size        == 0x44
    assert STRUCT_DATABASE["PROCESS_INFORMATION"].size == 0x10
    assert STRUCT_DATABASE["sockaddr_in"].size         == 0x10
    assert STRUCT_DATABASE["WSADATA"].size             == 0x190


def test_struct_dependency_forward():
    # Dependency is now owned by APIRecord.requires_structs, not StructRecord.
    assert "STARTUPINFOA"      in API_DATABASE["CreateProcessA"].requires_structs
    assert "PROCESS_INFORMATION" in API_DATABASE["CreateProcessA"].requires_structs
    assert "sockaddr_in"       in API_DATABASE["connect"].requires_structs
    assert "WSADATA"           in API_DATABASE["WSAStartup"].requires_structs


def test_get_record_known():
    r = get_record("WinExec")
    assert r.module == "kernel32.dll"


def test_get_record_unknown_raises():
    with pytest.raises(KeyError):
        get_record("FakeAPIThatDoesNotExist")


def test_module_ownership():
    assert API_DATABASE["CreateProcessA"].module == "kernel32.dll"
    assert API_DATABASE["WSAStartup"].module      == "ws2_32.dll"
    assert API_DATABASE["LoadLibraryA"].module    == "kernel32.dll"
    assert API_DATABASE["connect"].module         == "ws2_32.dll"
