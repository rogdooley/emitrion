"""Reviewed output fixtures for the supported IR workflows.

These fixtures make instruction-selection and contract changes visible in a
normal code review.  They intentionally cover fixed manifests and inputs; new
workflow behaviour gets its own fixture rather than silently updating one.
"""
from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

import pytest

from emitrion.build import build

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "workflows"


def _normalise_assembly(assembly: str) -> str:
    """Remove the checkout-specific manifest path from generated assembly."""
    return re.sub(
        r"^; Manifest: .+$",
        "; Manifest: <manifest>",
        assembly,
        flags=re.MULTILINE,
    )


@pytest.mark.parametrize(
    ("manifest_name", "template_name"),
    [
        ("calc.yaml", "ir_run_command"),
        ("revshell.yaml", "ir_reverse_shell"),
        ("bindshell.yaml", "ir_bind_shell"),
        ("ir_copy_file.yaml", "ir_copy_file"),
        ("ir_copy_then_run.yaml", "ir_copy_then_run"),
        ("ir_move_then_run.yaml", "ir_move_then_run"),
        ("ir_check_path.yaml", "ir_check_path"),
    ],
)
def test_ir_workflow_matches_reviewed_assembly_and_contract(
    manifest_dir,
    monkeypatch,
    manifest_name: str,
    template_name: str,
):
    """Fixed workflow inputs must match their reviewed build artifacts."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    result = build(
        str(manifest_dir / manifest_name),
        template_name=template_name,
        out_dir="/dev/null",
        assemble=False,
    )

    assert _normalise_assembly(result.asm).rstrip("\n") == (
        _FIXTURE_DIR / f"{template_name}.asm"
    ).read_text().rstrip("\n")
    assert result.contract_md.rstrip("\n") == (
        _FIXTURE_DIR / f"{template_name}.contract.md"
    ).read_text().rstrip("\n")


@pytest.mark.skipif(not shutil.which("nasm"), reason="NASM is required for binary fixtures")
@pytest.mark.parametrize(
    ("manifest_name", "template_name"),
    [
        ("calc.yaml", "ir_run_command"),
        ("revshell.yaml", "ir_reverse_shell"),
        ("bindshell.yaml", "ir_bind_shell"),
        ("ir_copy_file.yaml", "ir_copy_file"),
        ("ir_copy_then_run.yaml", "ir_copy_then_run"),
        ("ir_move_then_run.yaml", "ir_move_then_run"),
        ("ir_check_path.yaml", "ir_check_path"),
    ],
)
def test_ir_workflow_binary_matches_reviewed_digest(
    manifest_dir,
    monkeypatch,
    manifest_name: str,
    template_name: str,
):
    """The NASM output must remain byte-for-byte identical for fixed inputs."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    result = build(
        str(manifest_dir / manifest_name),
        template_name=template_name,
        out_dir="/dev/null",
        assemble=True,
    )

    assert result.shellcode_bytes is not None
    assert hashlib.sha256(result.shellcode_bytes).hexdigest() == (
        _FIXTURE_DIR / f"{template_name}.sha256"
    ).read_text().strip()
