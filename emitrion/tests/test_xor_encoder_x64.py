"""Tests for the x64 XOR encoder stub and xor_encode_x64."""
from __future__ import annotations

import pytest

from emitrion.xor_encoder import (
    EncoderResult,
    _build_stub_x64,
    _try_build_stub_x64,
    xor_encode_x64,
)


class TestXorEncodeX64Basic:
    def test_basic_encode(self) -> None:
        payload = bytes(range(1, 65))
        result = xor_encode_x64(payload, {0x00, 0x0A, 0x0D})
        assert result.success
        assert result.encoded is not None
        assert result.key is not None
        assert result.strategy == "xor8-x64"
        for b in result.encoded:
            assert b not in {0x00, 0x0A, 0x0D}

    def test_roundtrip(self) -> None:
        payload = b"\xcc\x90\x48\x31\xc0\x48\x89\xc1\xc3"
        result = xor_encode_x64(payload, {0x00, 0x0A, 0x0D})
        assert result.success
        assert result.encoded is not None
        assert result.key is not None
        encoded_body = result.encoded[result.stub_size:]
        decoded = bytes(b ^ result.key for b in encoded_body)
        assert decoded == payload

    def test_empty_payload(self) -> None:
        result = xor_encode_x64(b"", {0x00})
        assert result.success
        assert result.encoded == b""
        assert result.key is None

    def test_too_large(self) -> None:
        result = xor_encode_x64(b"\x41" * 70000, {0x00})
        assert not result.success
        assert "too large" in result.diagnostics.lower()

    def test_broad_badchars(self) -> None:
        payload = bytes(range(0x21, 0x60))
        broad = {0x00, 0x0A, 0x0D, 0x20, 0x09, 0x0B, 0x0C}
        result = xor_encode_x64(payload, broad)
        assert result.success
        assert result.encoded is not None
        for b in result.encoded:
            assert b not in broad


class TestStubX64Encoding:
    def test_inc_rsi_is_rex_prefixed(self) -> None:
        """inc rsi must be 48 FF C6, NOT 0x46 (which is REX.R in x64)."""
        stub = _build_stub_x64(64, 0x41, set())
        assert stub is not None
        assert b"\x48\xff\xc6" in stub
        # 0x46 as a standalone byte would be REX.R, not inc esi.
        # It may appear as part of other instructions, but the inc rsi
        # sequence must be the 3-byte REX form.
        idx = stub.index(b"\x48\xff\xc6")
        assert idx > 0

    def test_xor_rcx_rcx_has_rex(self) -> None:
        """xor rcx, rcx must be 48 31 C9 (REX.W prefix)."""
        stub = _build_stub_x64(64, 0x41, set())
        assert stub is not None
        assert b"\x48\x31\xc9" in stub

    def test_pop_rsi_encoding(self) -> None:
        """pop rsi is 5E (same in x86 and x64)."""
        stub = _build_stub_x64(64, 0x41, set())
        assert stub is not None
        assert 0x5E in stub

    def test_loop_instruction_present(self) -> None:
        """loop (E2) must be present for the decode loop."""
        stub = _build_stub_x64(64, 0x41, set())
        assert stub is not None
        assert 0xE2 in stub

    def test_stub_no_badchars(self) -> None:
        badchars = {0x00, 0x0A, 0x0D}
        stub = _build_stub_x64(64, 0x41, badchars)
        assert stub is not None
        for b in stub:
            assert b not in badchars

    def test_stub_returns_none_on_key_badchar(self) -> None:
        stub = _build_stub_x64(64, 0x41, {0x41})
        assert stub is None

    def test_stub_small_vs_large(self) -> None:
        small = _build_stub_x64(100, 0x41, set())
        large = _build_stub_x64(300, 0x41, set())
        assert small is not None
        assert large is not None
        assert len(large) > len(small)

    def test_padding_shifts_displacements(self) -> None:
        stub_no_pad = _build_stub_x64(64, 0x41, set(), pre_pad=0, mid_pad=0)
        stub_padded = _build_stub_x64(64, 0x41, set(), pre_pad=2, mid_pad=1)
        assert stub_no_pad is not None
        assert stub_padded is not None
        assert len(stub_padded) == len(stub_no_pad) + 3


class TestTryBuildStubX64:
    def test_finds_stub_with_standard_badchars(self) -> None:
        stub = _try_build_stub_x64(64, 0x41, {0x00, 0x0A, 0x0D})
        assert stub is not None

    def test_returns_none_when_impossible(self) -> None:
        all_neutrals_bad = {0x90, 0xFC, 0xF8, 0xF9, 0xF5}
        stub = _try_build_stub_x64(64, 0x41, all_neutrals_bad | {0x41})
        assert stub is None


class TestXorEncodeX64Exhaustion:
    def test_all_keys_exhausted(self) -> None:
        """A payload of all identical bytes makes every XOR key produce
        a zero byte (when byte == key), so with 0x00 forbidden, no key
        works for a payload that contains every non-zero byte value."""
        payload = bytes(range(1, 256))
        result = xor_encode_x64(payload, {0x00})
        assert not result.success
        assert result.payload_clean_keys == 0

    def test_diagnostics_on_failure(self) -> None:
        payload = bytes(range(1, 256))
        result = xor_encode_x64(payload, {0x00})
        assert "FAILURE" in result.diagnostics
        assert "XOR8-x64" in result.diagnostics
