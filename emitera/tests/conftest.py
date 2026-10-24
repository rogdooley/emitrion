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
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "revshell.yaml"))
    return build_layout(manifest)


@pytest.fixture
def calc_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "calc.yaml"))
    return build_layout(manifest)


@pytest.fixture
def http_download_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "http_download.yaml"))
    return build_layout(manifest)


@pytest.fixture
def process_replace_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "process_replace.yaml"))
    return build_layout(manifest)


@pytest.fixture
def service_persist_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "service_persist.yaml"))
    return build_layout(manifest)


@pytest.fixture
def dll_inject_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "dll_inject.yaml"))
    return build_layout(manifest)


@pytest.fixture
def check_path_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "check_path.yaml"))
    return build_layout(manifest)


@pytest.fixture
def registry_persist_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "registry_persist.yaml"))
    return build_layout(manifest)


@pytest.fixture
def http_exfil_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "http_exfil.yaml"))
    return build_layout(manifest)


@pytest.fixture
def revshell_doc(revshell_layout, manifest_dir):
    from emitera.schema import load
    from emitera.doc_gen import emit_full_contract_md
    manifest = load(str(manifest_dir / "revshell.yaml"))
    return emit_full_contract_md(manifest, revshell_layout)


@pytest.fixture
def revshell_doc_with_cheatsheet(revshell_layout, manifest_dir):
    from emitera.schema import load
    from emitera.doc_gen import emit_full_contract_md
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    from emitera.payload_templates.base import TemplateConfig
    manifest = load(str(manifest_dir / "revshell.yaml"))
    template = ReverseShellTemplate()
    config = TemplateConfig(lhost="192.168.1.100", lport=9001, badchars=manifest.badchars)
    return emit_full_contract_md(manifest, revshell_layout, template, config, shellcode_size=512)
