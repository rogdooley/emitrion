"""Tests for the verification lane.

Cross-platform tests cover generation, bad-character scanning logic, and
report structure. Assembly-dependent tests are skipped when no assembler
is available.
"""
from __future__ import annotations

import json

from emitrion.build import _check_badchars, build
from emitrion.payload_templates.base import TemplateConfig
from emitrion.tests.conftest import requires_assembler
from emitrion.verify import VerificationReport, verify, write_verification


class TestBadcharScanning:
    """Test _check_badchars on synthetic byte sequences."""

    def test_clean_bytes(self):
        data = bytes([0x41, 0x42, 0x43])
        badchars = {0x00, 0x0A, 0x0D}
        assert _check_badchars(data, badchars) == []

    def test_null_byte_detected(self):
        data = bytes([0x41, 0x00, 0x43])
        badchars = {0x00}
        violations = _check_badchars(data, badchars)
        assert len(violations) > 0
        assert any("0x00" in v for v in violations)

    def test_multiple_violations(self):
        data = bytes([0x0A, 0x41, 0x0D, 0x00])
        badchars = {0x00, 0x0A, 0x0D}
        violations = _check_badchars(data, badchars)
        badchar_lines = [v for v in violations if "BADCHAR" in v]
        assert len(badchar_lines) == 3

    def test_empty_badchars(self):
        data = bytes([0x00, 0x0A, 0x0D])
        assert _check_badchars(data, set()) == []

    def test_violation_includes_offset(self):
        data = bytes([0x41] * 10 + [0x00] + [0x41] * 5)
        violations = _check_badchars(data, {0x00})
        assert any("offset 10" in v for v in violations)

    def test_violation_includes_context(self):
        data = bytes([0x41, 0x42, 0x00, 0x43, 0x44])
        violations = _check_badchars(data, {0x00})
        assert any("context" in v for v in violations)


class TestVerificationReportStructure:
    """Test that VerificationReport has correct semantics."""

    def test_passed_requires_assembled_and_clean(self):
        report = VerificationReport(
            manifest="test.yaml",
            template="run_command",
            assembler="nasm",
            assembled=True,
            shellcode_size=100,
            shellcode_sha256="abc123",
            badchars_declared=["0x00"],
            badchar_violations=[],
            badchar_clean=True,
            encoded=False,
            encoded_size=None,
            deterministic=True,
            asm_line_count=50,
            timestamp="2026-01-01T00:00:00Z",
            errors=[],
        )
        assert report.passed is True

    def test_failed_when_not_assembled(self):
        report = VerificationReport(
            manifest="test.yaml",
            template="run_command",
            assembler=None,
            assembled=False,
            shellcode_size=None,
            shellcode_sha256=None,
            badchars_declared=["0x00"],
            badchar_violations=[],
            badchar_clean=False,
            encoded=False,
            encoded_size=None,
            deterministic=None,
            asm_line_count=50,
            timestamp="2026-01-01T00:00:00Z",
            errors=["Assembly failed"],
        )
        assert report.passed is False

    def test_failed_with_badchar_violations(self):
        report = VerificationReport(
            manifest="test.yaml",
            template="run_command",
            assembler="nasm",
            assembled=True,
            shellcode_size=100,
            shellcode_sha256="abc123",
            badchars_declared=["0x00"],
            badchar_violations=["BADCHAR 0x00 at offset 5"],
            badchar_clean=False,
            encoded=False,
            encoded_size=None,
            deterministic=True,
            asm_line_count=50,
            timestamp="2026-01-01T00:00:00Z",
            errors=[],
        )
        assert report.passed is False

    def test_failed_with_errors(self):
        report = VerificationReport(
            manifest="test.yaml",
            template="run_command",
            assembler="nasm",
            assembled=True,
            shellcode_size=100,
            shellcode_sha256="abc123",
            badchars_declared=["0x00"],
            badchar_violations=[],
            badchar_clean=True,
            encoded=False,
            encoded_size=None,
            deterministic=False,
            asm_line_count=50,
            timestamp="2026-01-01T00:00:00Z",
            errors=["Determinism check failed"],
        )
        assert report.passed is False


class TestGenerationPhase:
    """Test the generation phase of verify (no assembler needed)."""

    def test_build_produces_asm(self, manifest_dir, tmp_path):
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.asm
        assert "main:" in result.asm
        assert result.debug_runner is not None

    def test_build_produces_debug_runner(self, manifest_dir, tmp_path):
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "VirtualAlloc" in result.debug_runner
        assert "WinDbg" in result.debug_runner
        assert "keystone" in result.debug_runner

    def test_build_produces_contract(self, manifest_dir, tmp_path):
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert result.contract_md
        assert "WinExec" in result.contract_md

    def test_all_manifests_generate(self, manifest_dir, tmp_path):
        for yaml_file in sorted(manifest_dir.glob("*.yaml")):
            out = tmp_path / yaml_file.stem
            result = build(
                str(yaml_file),
                out_dir=str(out),
                assemble=False,
            )
            assert result.asm, f"{yaml_file.name} produced empty assembly"


@requires_assembler
class TestAssemblyPhase:
    """Tests requiring an assembler (NASM or Keystone)."""

    def test_verify_ir_run_command(self, manifest_dir, tmp_path, monkeypatch):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        report = verify(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            check_determinism=True,
        )
        assert report.assembled, report.errors
        assert report.shellcode_size > 0
        assert report.shellcode_sha256 is not None
        assert report.badchar_clean, report.badchar_violations
        assert report.deterministic is True

    def test_verify_legacy_run_command(self, manifest_dir, tmp_path, monkeypatch):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        report = verify(
            str(manifest_dir / "calc.yaml"),
            template_name="run_command",
            out_dir=str(tmp_path),
            check_determinism=False,
        )
        assert report.assembled, report.errors
        assert report.badchar_clean, report.badchar_violations

    def test_verify_revshell(self, manifest_dir, tmp_path, monkeypatch):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        config = TemplateConfig(lhost="192.168.1.100", lport=9001)
        report = verify(
            str(manifest_dir / "revshell.yaml"),
            template_name="reverse_shell",
            config=config,
            out_dir=str(tmp_path),
            check_determinism=False,
        )
        assert report.assembled, report.errors

    def test_write_verification_produces_json(self, manifest_dir, tmp_path, monkeypatch):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        report = verify(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            check_determinism=False,
        )
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="ir_run_command",
            out_dir=str(tmp_path),
            assemble=True,
        )
        write_verification(report, result, str(tmp_path))

        report_path = tmp_path / "verification_report.json"
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert data["passed"] is True
        assert data["assembled"] is True
        digest = data["shellcode_sha256"]
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)
        assert isinstance(data["badchar_violations"], list)

    def test_all_manifests_assemble(self, manifest_dir, tmp_path, monkeypatch):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
        config = TemplateConfig(lhost="192.168.1.100", lport=9001)
        for yaml_file in sorted(manifest_dir.glob("*.yaml")):
            out = tmp_path / yaml_file.stem
            result = build(
                str(yaml_file),
                config=config,
                out_dir=str(out),
                assemble=True,
            )
            assert result.shellcode_bytes is not None, (
                f"{yaml_file.name} failed to assemble: {result.asm_errors}"
            )
