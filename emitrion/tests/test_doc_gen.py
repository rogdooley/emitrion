"""Tests for doc_gen.py - Phase 3 Markdown documentation generator."""
from __future__ import annotations

import pathlib


def test_createprocessa_hash(revshell_doc):
    assert "0x16b3fe72" in revshell_doc


def test_wsastartup_module(revshell_doc):
    assert "ws2_32.dll" in revshell_doc
    assert "WSAStartup" in revshell_doc


def test_startupinfoa_size(revshell_doc):
    assert "STARTUPINFOA" in revshell_doc
    assert "0x44" in revshell_doc


def test_startupinfoa_fields(revshell_doc):
    assert "cb" in revshell_doc
    assert "dwFlags" in revshell_doc
    assert "hStdInput" in revshell_doc
    assert "hStdOutput" in revshell_doc
    assert "hStdError" in revshell_doc


def test_process_information_size(revshell_doc):
    assert "PROCESS_INFORMATION" in revshell_doc
    assert "0x10" in revshell_doc


def test_sockaddr_in_fields(revshell_doc):
    assert "sockaddr_in" in revshell_doc
    assert "sin_family" in revshell_doc
    assert "sin_port" in revshell_doc
    assert "sin_addr" in revshell_doc
    assert "sin_zero" in revshell_doc


def test_module_bases_section_exists(revshell_doc):
    assert "## Module Bases" in revshell_doc


def test_api_table_section_exists(revshell_doc):
    assert "## API Table" in revshell_doc


def test_module_bases_separate_from_api_table(revshell_doc):
    base_pos = revshell_doc.index("## Module Bases")
    api_pos  = revshell_doc.index("## API Table")
    assert base_pos < api_pos  # Module Bases section precedes API Table


def test_kernel32_base_in_module_bases_section(revshell_doc):
    # kernel32.dll must appear in the Module Bases section,
    # not only in the API Table module column
    bases_start = revshell_doc.index("## Module Bases")
    api_start   = revshell_doc.index("## API Table")
    bases_section = revshell_doc[bases_start:api_start]
    assert "kernel32.dll" in bases_section


def test_hash_from_ror13_not_hardcoded():
    # Verify the doc generation uses ror13 dynamically
    from emitrion.doc_gen import emit_api_contracts_md
    from emitrion.hash_gen import ror13
    from emitrion.schema import load
    from emitrion.stack_alloc import build_layout
    manifest_dir = pathlib.Path(__file__).parent.parent / "manifests"
    manifest = load(str(manifest_dir / "revshell.yaml"))
    layout = build_layout(manifest)
    doc = emit_api_contracts_md(manifest, layout)
    for name in manifest.functions:
        expected = f"0x{ror13(name):08x}"
        assert expected in doc, f"Hash for {name} ({expected}) not found in doc"


def test_calc_manifest_no_network_structs(manifest_dir):
    from emitrion.doc_gen import emit_full_contract_md
    from emitrion.schema import load
    from emitrion.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "calc.yaml"))
    layout = build_layout(manifest)
    doc = emit_full_contract_md(manifest, layout)
    assert "WinExec" in doc
    assert "WSAStartup" not in doc
    assert "WSADATA" not in doc
    assert "sockaddr_in" not in doc


def test_no_trailing_whitespace(revshell_doc):
    for i, line in enumerate(revshell_doc.splitlines(), 1):
        assert line == line.rstrip(), f"Trailing whitespace on line {i}: {line!r}"


def test_struct_layouts_section_exists(revshell_doc):
    assert "# Structure Layouts" in revshell_doc


def test_full_contract_contains_all_sections(revshell_doc):
    assert "# Stack Layout" in revshell_doc
    assert "# API Contracts" in revshell_doc
    assert "# Structure Layouts" in revshell_doc


# --- Cheatsheet tests ---


def test_cheatsheet_present_when_template_provided(revshell_doc_with_cheatsheet):
    assert "# Operational Cheatsheet" in revshell_doc_with_cheatsheet


def test_cheatsheet_absent_without_template(revshell_doc):
    assert "# Operational Cheatsheet" not in revshell_doc


def test_cheatsheet_contains_listener_command(revshell_doc_with_cheatsheet):
    assert "nc -lnvp 9001" in revshell_doc_with_cheatsheet


def test_cheatsheet_contains_target_info(revshell_doc_with_cheatsheet):
    assert "192.168.1.100:9001" in revshell_doc_with_cheatsheet


def test_cheatsheet_contains_shellcode_size(revshell_doc_with_cheatsheet):
    assert "512 bytes" in revshell_doc_with_cheatsheet


def test_cheatsheet_contains_bad_chars(revshell_doc_with_cheatsheet):
    assert "`0x00`" in revshell_doc_with_cheatsheet
    assert "`0x0a`" in revshell_doc_with_cheatsheet
    assert "`0x0d`" in revshell_doc_with_cheatsheet


def test_cheatsheet_contains_msfvenom(revshell_doc_with_cheatsheet):
    assert "msfvenom" in revshell_doc_with_cheatsheet
    assert "shikata_ga_nai" in revshell_doc_with_cheatsheet


def test_cheatsheet_no_trailing_whitespace(revshell_doc_with_cheatsheet):
    for i, line in enumerate(revshell_doc_with_cheatsheet.splitlines(), 1):
        assert line == line.rstrip(), f"Trailing whitespace on line {i}: {line!r}"


def test_cheatsheet_standalone_emitter():
    from emitrion.doc_gen import emit_cheatsheet_md
    from emitrion.payload_templates.base import TemplateConfig
    from emitrion.payload_templates.tcp_stager import TcpStagerTemplate
    template = TcpStagerTemplate()
    config = TemplateConfig(lhost="10.0.0.1", lport=8080)
    result = emit_cheatsheet_md(template, config, shellcode_size=256)
    assert "tcp_stage_server.py" in result
    assert "10.0.0.1" in result
    assert "8080" in result
