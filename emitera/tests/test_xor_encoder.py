"""Tests for the XOR payload encoder."""
from __future__ import annotations

from emitera.scanner import scan
from emitera.xor_encoder import xor_encode


class TestCleanPayload:
    """Payloads that are already badchar-free still encode correctly."""

    def test_clean_payload_encodes(self):
        payload = b"\x01\x02\x03\x04\x05"
        result = xor_encode(payload, {0x00})
        assert result.success
        assert result.encoded is not None
        assert result.key is not None

    def test_clean_payload_output_also_clean(self):
        payload = b"\x01\x02\x03\x04\x05"
        result = xor_encode(payload, {0x00})
        scan_result = scan(result.encoded, {0x00})
        assert scan_result.clean


class TestRequiresEncoding:
    """Payloads that contain bad bytes should be fixed by encoding."""

    def test_null_bytes_encoded(self):
        payload = b"\x00\x01\x02\x03"
        result = xor_encode(payload, {0x00})
        assert result.success
        assert 0x00 not in result.encoded

    def test_multiple_badchars(self):
        payload = b"\x00\x0a\x0d\x01\x02"
        result = xor_encode(payload, {0x00, 0x0a, 0x0d})
        assert result.success
        scan_result = scan(result.encoded, {0x00, 0x0a, 0x0d})
        assert scan_result.clean

    def test_decoder_restores_payload(self):
        """The encoded body, when XOR-decoded, should match the original."""
        payload = b"\x00\x0a\x0d\x41\x42\x43"
        result = xor_encode(payload, {0x00, 0x0a, 0x0d})
        assert result.success
        encoded_body = result.encoded[result.stub_size:]
        decoded = bytes(b ^ result.key for b in encoded_body)
        assert decoded == payload


class TestImpossibleBadchars:
    """Cases where no valid XOR key exists."""

    def test_all_keys_forbidden(self):
        payload = b"\x00"
        result = xor_encode(payload, set(range(256)))
        assert not result.success
        assert "FAILURE" in result.diagnostics or "forbidden" in result.diagnostics.lower()

    def test_all_neutrals_forbidden(self):
        """If every NOP-like byte is forbidden, stub padding can't work."""
        neutrals = {0x90, 0xFC, 0xF8, 0xF9, 0xF5}
        payload = b"\x01\x02\x03"
        result = xor_encode(payload, neutrals | {0xEB})
        assert not result.success


class TestDecoderStubViolation:
    """The decoder stub introduces its own bytes into the output."""

    def test_stub_bytes_checked(self):
        payload = b"\x01\x02\x03"
        result = xor_encode(payload, {0x00})
        assert result.success
        scan_result = scan(result.encoded, {0x00})
        assert scan_result.clean

    def test_length_byte_is_badchar(self):
        """Payload length itself might be a forbidden byte value."""
        payload = b"\x01" * 10
        result = xor_encode(payload, {0x0a})
        assert not result.success
        assert "length" in result.diagnostics.lower()


class TestSuccessfulEncoding:
    """Integration tests for various payload sizes."""

    def test_small_payload(self):
        payload = bytes(range(1, 20))
        result = xor_encode(payload, {0x00})
        assert result.success
        assert result.stub_size >= 20

    def test_medium_payload(self):
        payload = b"\x01" * 257  # > 255 bytes, needs 16-bit length
        result = xor_encode(payload, {0x00})
        assert result.success
        assert result.stub_size >= 22

    def test_payload_255_bytes(self):
        """Boundary: exactly 255 bytes uses the small stub."""
        payload = b"\x01" * 255
        result = xor_encode(payload, {0x00})
        assert result.success
        assert result.stub_size >= 20

    def test_payload_256_bytes(self):
        """Boundary: 256 bytes switches to the large stub."""
        payload = b"\x01" * 257
        result = xor_encode(payload, {0x00})
        assert result.success
        assert result.stub_size >= 22

    def test_length_with_null_low_byte(self):
        """Length 256 = 0x0100 has null low byte - should fail with {0x00}."""
        payload = b"\x01" * 256
        result = xor_encode(payload, {0x00})
        assert not result.success
        assert "length" in result.diagnostics.lower()

    def test_empty_payload(self):
        result = xor_encode(b"", {0x00})
        assert result.success
        assert result.encoded == b""


class TestArbitraryBadchars:
    """Tests with exotic badchar sets beyond the usual 00/0a/0d."""

    def test_stress_badchar_set(self):
        payload = b"\x30\x3c\x01\x02\x03"
        result = xor_encode(payload, {0x00, 0x0a, 0x0d, 0x30, 0x3c})
        assert result.success
        scan_result = scan(result.encoded, {0x00, 0x0a, 0x0d, 0x30, 0x3c})
        assert scan_result.clean

    def test_large_badchar_set(self):
        """Many forbidden bytes; fewer candidate keys."""
        payload = b"\x01\x02\x03\x04\x05"
        badchars = set(range(128))
        result = xor_encode(payload, badchars)
        if result.success:
            scan_result = scan(result.encoded, badchars)
            assert scan_result.clean

    def test_high_byte_badchars(self):
        payload = b"\xff\xfe\xfd\x01\x02"
        result = xor_encode(payload, {0x00, 0xff, 0xfe})
        assert result.success
        scan_result = scan(result.encoded, {0x00, 0xff, 0xfe})
        assert scan_result.clean


class TestDiagnostics:
    """The diagnostics string should be informative."""

    def test_success_diagnostics(self):
        result = xor_encode(b"\x00\x01\x02", {0x00})
        assert result.success
        assert "XOR8" in result.diagnostics
        assert "SUCCESS" in result.diagnostics

    def test_failure_diagnostics(self):
        result = xor_encode(b"\x00", set(range(256)))
        assert not result.success
        assert "FAILURE" in result.diagnostics or "forbidden" in result.diagnostics.lower()

    def test_keys_tested_reported(self):
        result = xor_encode(b"\x00\x01\x02", {0x00})
        assert result.keys_tested > 0

    def test_payload_clean_keys_reported(self):
        result = xor_encode(b"\x00\x01\x02", {0x00})
        assert result.payload_clean_keys > 0


class TestOutputIntegrity:
    """The full output (stub + encoded body) must decode correctly."""

    def test_full_output_structure(self):
        payload = b"\x00\x0a\x0d\x41\x42\x43\x44\x45"
        result = xor_encode(payload, {0x00, 0x0a, 0x0d})
        assert result.success
        assert len(result.encoded) == result.stub_size + len(payload)

    def test_no_badchars_in_full_output(self):
        """Final validation: no forbidden byte anywhere in stub+body."""
        payload = b"\x41" * 100 + b"\x00" * 10 + b"\x0a\x0d" * 5
        badchars = {0x00, 0x0a, 0x0d}
        result = xor_encode(payload, badchars)
        assert result.success
        for i, b in enumerate(result.encoded):
            assert b not in badchars, f"badchar 0x{b:02x} at offset {i}"
