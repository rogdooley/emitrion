"""Shared fixtures for emitter tests."""
from __future__ import annotations

import pathlib
import shutil

import pytest

requires_assembler = pytest.mark.skipif(
    not shutil.which("nasm"),
    reason="nasm not available (assembler tests run on Windows lab VM)",
)


@pytest.fixture
def manifest_dir() -> pathlib.Path:
    return pathlib.Path(__file__).parent.parent / "manifests"


@pytest.fixture
def revshell_layout(manifest_dir):
    from emitrion.schema import load
    from emitrion.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "revshell.yaml"))
    return build_layout(manifest)


@pytest.fixture
def calc_layout(manifest_dir):
    from emitrion.schema import load
    from emitrion.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "calc.yaml"))
    return build_layout(manifest)


@pytest.fixture
def revshell_doc(revshell_layout, manifest_dir):
    from emitrion.doc_gen import emit_full_contract_md
    from emitrion.schema import load
    manifest = load(str(manifest_dir / "revshell.yaml"))
    return emit_full_contract_md(manifest, revshell_layout)


@pytest.fixture
def revshell_doc_with_cheatsheet(revshell_layout, manifest_dir):
    from emitrion.build_common import _load_template
    from emitrion.doc_gen import emit_full_contract_md
    from emitrion.payload_templates.base import TemplateConfig
    from emitrion.schema import load
    manifest = load(str(manifest_dir / "revshell.yaml"))
    template = _load_template("ir_reverse_shell")
    config = TemplateConfig(lhost="192.168.1.100", lport=9001, badchars=manifest.badchars)
    return emit_full_contract_md(manifest, revshell_layout, template, config, shellcode_size=512)
