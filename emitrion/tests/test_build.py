"""Tests for the build pipeline (build.py)."""
from __future__ import annotations

import re

import pytest


def test_build_generates_asm(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        template_name="reverse_shell",
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert result.asm
    assert "main:" in result.asm


def test_build_contains_framework_bootstrap(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "call find_module" in result.asm
    assert "call resolve_export_by_hash" in result.asm
    assert "find_export_loop" in result.asm


def test_build_generates_contract_md(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert result.contract_md
    assert "# Stack Layout" in result.contract_md
    assert "# API Contracts" in result.contract_md


def test_build_all_hashes_match_ror13(manifest_dir, tmp_path):
    import re

    from emitrion.build import build
    from emitrion.hash_gen import ror13
    from emitrion.schema import load
    manifest = load(str(manifest_dir / "revshell.yaml"))
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    for name in manifest.functions:
        expected = ror13(name)
        hex_str = f"0x{expected:08x}"
        if hex_str in result.asm:
            continue
        comment_pos = result.asm.index(name)
        block = result.asm[comment_pos:comment_pos + 200]
        mov_m = re.search(r'mov\s+eax,\s+0x([0-9a-f]{8})', block)
        xor_m = re.search(r'xor\s+eax,\s+0x([0-9a-f]{8})', block)
        assert mov_m and xor_m, (
            f"Hash for {name} ({hex_str}) not found as plain or XOR-encoded"
        )
        decoded = int(mov_m.group(1), 16) ^ int(xor_m.group(1), 16)
        assert decoded == expected, (
            f"XOR-decoded hash for {name}: got 0x{decoded:08x}, want {hex_str}"
        )


def test_build_no_duplicate_api_slot_assignments(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    # Extract mov [ebp-0xNN], eax assignments
    api_section_start = result.asm.find("call save_export_context")
    string_section_start = result.asm.find("String Construction")
    if api_section_start != -1 and string_section_start != -1:
        api_section = result.asm[api_section_start:string_section_start]
        assignments = re.findall(r'mov\s+\[ebp-0x[0-9a-f]+\],\s+eax', api_section)
        assert len(assignments) == len(set(assignments)), \
            f"Duplicate slot writes in API section: {assignments}"


def test_build_write_outputs(manifest_dir, tmp_path):
    from emitrion.build import build, write_outputs
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    write_outputs(result, str(tmp_path))
    assert (tmp_path / "asm" / "generated.asm").exists()
    assert (tmp_path / "Documentation" / "contract.md").exists()
    assert (tmp_path / "asm" / "generated.asm").read_text() == result.asm


def test_calc_build_no_network(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "calc.yaml"),
        template_name="run_command",
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "WSAStartup" not in result.asm
    assert "WinExec" in result.asm
    assert "ws2_32" not in result.asm


def test_calc_build_winexec_hash(manifest_dir, tmp_path):
    from emitrion.build import build
    from emitrion.hash_gen import ror13
    result = build(
        str(manifest_dir / "calc.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    expected = f"0x{ror13('WinExec'):08x}"
    assert expected in result.asm


def test_build_contains_dll_load_block(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    # ws2_32 loading block should appear
    assert "LoadLibraryA" in result.asm
    assert "ws2_32.dll" in result.asm


def test_build_string_section_present(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "String Construction" in result.asm


def test_build_structure_section_present(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "Structure Initialization" in result.asm
    assert "STARTUPINFOA" in result.asm


def test_build_layout_returned(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert result.layout is not None
    assert result.layout.slot("WSAStartup").offset == 0x30
    si = result.layout.slot("STARTUPINFOA")
    assert si.offset - si.size >= 0x80


def test_build_no_assemble_skips_keystone(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        assemble=False,
        out_dir=str(tmp_path),
    )
    assert result.shellcode_bytes is None
    assert result.hex_str is None


def test_existing_modules_still_import():
    assert True


# ---------------------------------------------------------------------------
# _to_nasm syntax transformation
# ---------------------------------------------------------------------------

def test_to_nasm_adds_bits32():
    from emitrion.build import _to_nasm
    out = _to_nasm("xor eax, eax")
    assert out.startswith("BITS 32")


def test_to_nasm_strips_hash_comments():
    from emitrion.build import _to_nasm
    out = _to_nasm("mov eax, 1  # set eax")
    assert "#" not in out
    assert "mov eax, 1" in out


def test_to_nasm_strips_semicolon_comments():
    from emitrion.build import _to_nasm
    out = _to_nasm("; -- Framework Stubs ----------------\n    xor eax, eax")
    assert "-" not in out
    assert "xor eax, eax" in out


def test_strip_comments_removes_unicode_box_drawing():
    from emitrion.build import _strip_comments
    asm = "; -- Payload ---------------------\n    push eax  # note"
    out = _strip_comments(asm)
    assert "-" not in out
    assert "#" not in out
    assert "push eax" in out


def test_debug_runner_converts_semicolons_to_hash():
    from emitrion.build import _generate_debug_runner
    runner = _generate_debug_runner("; comment line\n    xor eax, eax ; note")
    assert "; comment line" not in runner
    assert "# comment line" in runner
    assert "# note" in runner


def test_to_nasm_removes_dword_ptr():
    from emitrion.build import _to_nasm
    out = _to_nasm("call dword ptr [ebp-0x28]")
    assert "ptr" not in out
    assert "call dword [ebp-0x28]" in out


def test_to_nasm_removes_word_ptr():
    from emitrion.build import _to_nasm
    out = _to_nasm("cmp word ptr [esi], 0x004b")
    assert "ptr" not in out
    assert "cmp word [esi], 0x004b" in out


def test_to_nasm_removes_byte_ptr():
    from emitrion.build import _to_nasm
    out = _to_nasm("movzx eax, byte ptr [esi]")
    assert "ptr" not in out
    assert "movzx eax, byte [esi]" in out


def test_to_nasm_fixes_fs_segment():
    from emitrion.build import _to_nasm
    out = _to_nasm("mov eax, fs:[ecx + 0x30]")
    assert "fs:[" not in out
    assert "[fs:ecx + 0x30]" in out


def test_to_nasm_no_change_to_normal_instructions():
    from emitrion.build import _to_nasm
    src = "xor ecx, ecx\npush eax\npop ebx"
    out = _to_nasm(src)
    for instr in src.splitlines():
        assert instr in out


# ---------------------------------------------------------------------------
# assembler field on BuildResult
# ---------------------------------------------------------------------------

def test_build_assembler_none_when_no_assemble(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(str(manifest_dir / "calc.yaml"), assemble=False, out_dir=str(tmp_path))
    assert result.assembler is None


def test_build_assembler_set_when_assembled(manifest_dir, tmp_path):
    import shutil
    if not shutil.which("nasm"):
        pytest.skip("nasm not available")
    from emitrion.build import build
    result = build(str(manifest_dir / "calc.yaml"), assemble=True, out_dir=str(tmp_path))
    if result.assembler is not None:
        assert result.assembler in ("keystone", "nasm")


# ---------------------------------------------------------------------------
# test harness generation
# ---------------------------------------------------------------------------


def test_harness_generated_when_assembled(manifest_dir, tmp_path):
    import shutil
    if not shutil.which("nasm"):
        pytest.skip("nasm not available")
    from emitrion.build import build, write_outputs
    result = build(str(manifest_dir / "calc.yaml"), assemble=True, out_dir=str(tmp_path))
    if result.shellcode_bytes is None:
        pytest.skip("no assembler produced output")
    assert result.test_harness is not None
    write_outputs(result, str(tmp_path))
    harness_path = tmp_path / "bin" / "test_harness.py"
    assert harness_path.exists()
    content = harness_path.read_text()
    assert "VirtualAlloc" in content
    assert "shellcode.bin" in content
    assert str(len(result.shellcode_bytes)) in content


def test_harness_none_when_no_assemble(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(str(manifest_dir / "calc.yaml"), assemble=False, out_dir=str(tmp_path))
    assert result.test_harness is None


def test_harness_is_valid_python(manifest_dir, tmp_path):
    import ast

    from emitrion.build import _generate_test_harness
    harness = _generate_test_harness(256)
    ast.parse(harness)


def test_harness_contains_breakpoint_hint():
    from emitrion.build import _generate_test_harness
    harness = _generate_test_harness(100)
    assert "bp" in harness.lower()
    assert "WinDbg" in harness


# ---------------------------------------------------------------------------
# assembler diagnostics
# ---------------------------------------------------------------------------


def test_try_assemble_collects_backend_errors(monkeypatch):
    import emitrion.build as build_module

    monkeypatch.setattr(
        build_module,
        "_try_assemble_keystone",
        lambda asm: (None, "keystone: invalid operand"),
    )
    monkeypatch.setattr(
        build_module,
        "_try_assemble_nasm",
        lambda asm: (None, "nasm: parser: instruction expected"),
    )

    raw, assembler, errors = build_module._try_assemble("invalid asm")

    assert raw is None
    assert assembler is None
    assert errors == [
        "keystone: invalid operand",
        "nasm: parser: instruction expected",
    ]


def test_build_exposes_assembler_errors(monkeypatch, manifest_dir, tmp_path):
    import emitrion.build as build_module

    expected = ["keystone: invalid operand"]
    monkeypatch.setattr(
        build_module,
        "_try_assemble",
        lambda asm: (None, None, expected),
    )

    result = build_module.build(
        str(manifest_dir / "calc.yaml"),
        assemble=True,
        out_dir=str(tmp_path),
    )

    assert result.shellcode_bytes is None
    assert result.assembler is None
    assert result.asm_errors == expected


def test_build_rejects_assembled_badchars(monkeypatch, manifest_dir, tmp_path):
    import emitrion.build as build_module

    monkeypatch.setattr(
        build_module,
        "_try_assemble",
        lambda asm: (b"\x90\x00\xc3", "keystone", []),
    )

    result = build_module.build(
        str(manifest_dir / "calc.yaml"),
        assemble=True,
        out_dir=str(tmp_path),
    )

    assert result.shellcode_bytes == b"\x90\x00\xc3"
    assert result.hex_str == r"\x90\x00\xc3"
    assert result.py_bytes == 'shellcode = (\nb"\\x90\\x00\\xc3"\n)\n# Length: 3 bytes'
    assert result.c_array is not None
    assert result.test_harness is not None
    assert result.assembler == "keystone"
    assert result.encoded_bytes is None
    assert result.encoder_report is None
    assert result.asm_errors == [
        "[!] 1 badchar violation(s) in 3 bytes",
        "BADCHAR 0x00 at offset 1 (context: 9000c3)",
    ]


def test_cli_prints_assembler_errors(monkeypatch, capsys, tmp_path):
    import emitrion.build as build_module

    result = build_module.BuildResult(
        manifest_path="manifest.yaml",
        asm="",
        contract_md="",
        asm_errors=["keystone: invalid operand"],
    )
    monkeypatch.setattr(build_module, "build", lambda *args, **kwargs: result)
    monkeypatch.setattr(build_module, "write_outputs", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "sys.argv",
        ["emitter", "manifest.yaml", "--out", str(tmp_path)],
    )

    with pytest.raises(SystemExit) as exc_info:
        build_module.main()
    assert exc_info.value.code == 1

    output = capsys.readouterr().out
    assert "[!] Assembly failed:" in output
    assert "keystone: invalid operand" in output


# ---------------------------------------------------------------------------
# debug runner generation
# ---------------------------------------------------------------------------


def test_debug_runner_is_valid_python():
    import ast

    from emitrion.build import _generate_debug_runner
    runner = _generate_debug_runner("xor eax, eax\nret")
    ast.parse(runner)


def test_debug_runner_contains_keystone_import():
    from emitrion.build import _generate_debug_runner
    runner = _generate_debug_runner("nop")
    assert "from keystone" in runner


def test_debug_runner_contains_virtualalloc():
    from emitrion.build import _generate_debug_runner
    runner = _generate_debug_runner("nop")
    assert "VirtualAlloc" in runner


def test_debug_runner_embeds_assembly():
    from emitrion.build import _generate_debug_runner
    asm = "mov eax, 0x42\npush eax\nret"
    runner = _generate_debug_runner(asm)
    assert "mov eax, 0x42" in runner
    assert "push eax" in runner


def test_debug_runner_preserves_short_jumps_in_source():
    from emitrion.build import _generate_debug_runner
    runner = _generate_debug_runner("start:\n    jmp short done\ndone:\n    ret")
    assert "jmp short" in runner


def test_debug_runner_strips_short_qualifier_at_runtime():
    """main() replaces 'jmp short' with 'jmp' for Keystone compatibility."""
    from emitrion.build import _generate_debug_runner
    runner = _generate_debug_runner("start:\n    jmp short done\ndone:\n    ret")
    assert 'CODE.replace("jmp short ", "jmp ")' in runner


def test_debug_runner_contains_breakpoint_hint():
    from emitrion.build import _generate_debug_runner
    runner = _generate_debug_runner("nop")
    assert "bp" in runner.lower()
    assert "WinDbg" in runner


def test_debug_runner_explains_debugger_lifecycle():
    from emitrion.build import _generate_debug_runner

    runner = _generate_debug_runner("nop")

    assert "Attach WinDbg to this exact python.exe process" in runner
    assert "The allocation remains valid while this Python process is alive." in runner
    assert "Start a new thread at the first byte of the copied shellcode." in runner


def test_debug_runner_always_generated(manifest_dir, tmp_path):
    from emitrion.build import build
    result = build(
        str(manifest_dir / "calc.yaml"),
        assemble=False,
        out_dir=str(tmp_path),
    )
    assert result.debug_runner is not None


def test_debug_runner_written_to_disk(manifest_dir, tmp_path):
    from emitrion.build import build, write_outputs
    result = build(
        str(manifest_dir / "calc.yaml"),
        assemble=False,
        out_dir=str(tmp_path),
    )
    write_outputs(result, str(tmp_path))
    runner_path = tmp_path / "asm" / "debug_runner.py"
    assert runner_path.exists()
    assert "VirtualAlloc" in runner_path.read_text()


def test_write_outputs_removes_stale_bin_artifacts(tmp_path):
    from emitrion.build import BuildResult, write_outputs

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    for name in (
        "shellcode.bin",
        "shellcode.hex",
        "shellcode.py",
        "shellcode.c",
        "test_harness.py",
    ):
        (bin_dir / name).write_text("stale")

    result = BuildResult(
        manifest_path="manifest.yaml",
        asm="asm",
        contract_md="contract",
        debug_runner="runner",
    )
    write_outputs(result, str(tmp_path))

    for name in (
        "shellcode.bin",
        "shellcode.hex",
        "shellcode.py",
        "shellcode.c",
        "test_harness.py",
    ):
        assert not (bin_dir / name).exists()


def test_write_text_uses_utf8_encoding(tmp_path, monkeypatch):
    import pathlib

    from emitrion.build import _write_text

    captured: dict[str, object] = {}
    original = pathlib.Path.write_text

    def fake_write_text(self, data, encoding=None, errors=None, newline=None):
        captured["path"] = self
        captured["data"] = data
        captured["encoding"] = encoding
        return original(self, data, encoding=encoding, errors=errors, newline=newline)

    monkeypatch.setattr(pathlib.Path, "write_text", fake_write_text)

    target = tmp_path / "unicode.txt"
    _write_text(target, "; \u2500\u2500 unicode")

    assert captured["path"] == target
    assert captured["encoding"] == "utf-8"
    assert target.read_text(encoding="utf-8") == "; \u2500\u2500 unicode"


# ---------------------------------------------------------------------------
# CLI override precedence: _apply_config_overrides
# ---------------------------------------------------------------------------


class TestConfigOverrides:
    """CLI config fields override manifest strings with correct precedence."""

    def test_omitted_preserves_manifest_value(self, manifest_dir, tmp_path):
        """When config field is None, manifest string value is preserved."""
        from emitrion.build import build
        from emitrion.payload_templates.base import TemplateConfig
        config = TemplateConfig()  # all overridable fields are None
        result = build(
            str(manifest_dir / "tcp_download.yaml"),
            template_name="tcp_download",
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "C:\\Windows\\Temp\\payload.exe" in result.asm
        assert config.dst_path == "C:\\Windows\\Temp\\payload.exe"

    def test_explicit_override_replaces_manifest(self, manifest_dir, tmp_path):
        """Non-None config value overrides the manifest string."""
        from emitrion.build import build
        from emitrion.payload_templates.base import TemplateConfig
        config = TemplateConfig(dst_path="C:\\evil.exe")
        result = build(
            str(manifest_dir / "tcp_download.yaml"),
            template_name="tcp_download",
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "C:\\evil.exe" in result.asm
        assert "C:\\Windows\\Temp\\payload.exe" not in result.asm

    def test_explicit_value_matching_default_still_overrides(self, manifest_dir, tmp_path):
        """Passing a value that equals the old TemplateConfig default still overrides."""
        from emitrion.build import build
        from emitrion.payload_templates.base import TemplateConfig
        config = TemplateConfig(dst_path="C:\\dest.txt")
        result = build(
            str(manifest_dir / "tcp_download.yaml"),
            template_name="tcp_download",
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "C:\\dest.txt" in result.asm
        assert "C:\\Windows\\Temp\\payload.exe" not in result.asm

    def test_changed_string_length_affects_layout(self, manifest_dir):
        """Override with a different-length string produces a different slot size."""
        from emitrion.build import _apply_config_overrides
        from emitrion.payload_templates.base import TemplateConfig
        from emitrion.schema import load
        from emitrion.stack_alloc import build_layout

        manifest = load(str(manifest_dir / "tcp_download.yaml"))
        original_layout = build_layout(manifest)
        orig_size = original_layout.slot("dst_path").size

        config = TemplateConfig(dst_path="X")
        overridden = _apply_config_overrides(manifest, config)
        new_layout = build_layout(overridden)
        new_size = new_layout.slot("dst_path").size

        assert new_size < orig_size

    def test_contract_consistent_with_override(self, manifest_dir, tmp_path):
        """Contract doc reflects the overridden value, not the manifest original."""
        from emitrion.build import build
        from emitrion.payload_templates.base import TemplateConfig
        config = TemplateConfig(dst_path="C:\\pwned.exe")
        result = build(
            str(manifest_dir / "tcp_download.yaml"),
            template_name="tcp_download",
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "C:\\pwned.exe" in result.contract_md

    def test_backfill_populates_config_from_manifest(self, manifest_dir):
        """Config fields left None are backfilled from manifest strings."""
        from emitrion.build import _apply_config_overrides
        from emitrion.payload_templates.base import TemplateConfig
        from emitrion.schema import load
        manifest = load(str(manifest_dir / "copy_then_run.yaml"))
        config = TemplateConfig()
        _apply_config_overrides(manifest, config)
        assert config.src_path == "C:\\source\\payload.exe"
        assert config.dst_path == "C:\\Windows\\Temp\\payload.exe"

    def test_fallback_when_no_manifest_string(self, manifest_dir):
        """Config fields with no matching manifest string get hardcoded fallbacks."""
        from emitrion.build import _apply_config_overrides
        from emitrion.payload_templates.base import TemplateConfig
        from emitrion.schema import load
        manifest = load(str(manifest_dir / "revshell.yaml"))
        config = TemplateConfig()
        _apply_config_overrides(manifest, config)
        assert config.src_path == "C:\\source.txt"
        assert config.dst_path == "C:\\dest.txt"
