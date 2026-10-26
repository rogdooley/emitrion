"""Tests for hash_gen.py - ground truth from shellcode-04.py and RevShellV1.md."""
from __future__ import annotations

from ..hash_gen import compute_hashes, ror13


def test_known_hashes():
    assert ror13("WinExec")        == 0x0e8afe98
    assert ror13("ExitProcess")    == 0x73e2d87e
    assert ror13("LoadLibraryA")   == 0xec0e4e8e
    assert ror13("GetProcAddress") == 0x7c0dfcaa
    assert ror13("CreateProcessA") == 0x16b3fe72
    assert ror13("WSAStartup")     == 0x3bfcedcb
    assert ror13("WSASocketA")     == 0xadf509d9
    assert ror13("connect")        == 0x60aaf9ec


def test_compute_hashes_returns_all():
    names = ["WinExec", "connect"]
    result = compute_hashes(names)
    assert result == {"WinExec": 0x0e8afe98, "connect": 0x60aaf9ec}


def test_hash_is_32bit():
    for name in ["CreateProcessA", "WSAStartup", "connect"]:
        assert 0 <= ror13(name) <= 0xFFFFFFFF
