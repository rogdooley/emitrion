"""Tests for the --raw build mode and xor_wrapper.py generation.

Validates that:
- raw=True skips inline badchar avoidance, producing shorter or equal ASM
- raw=True preserves manifest badchars for post-assembly validation
- raw=True combined with encode=True works without error
- xor_wrapper is populated on BuildResult for both architectures
- generate_xor_wrapper() produces valid Python for various configs
- CLI --raw flag parsing works for both x86 and x64
"""
from __future__ import annotations

import pathlib
import sys

import pytest

from emitrion.build import build, write_outputs
from emitrion.build_x64 import build_x64, generate_xor_wrapper
from emitrion.payload_templates.base import TemplateConfig

MANIFEST_DIR = pathlib.Path(__file__).parent.parent / "manifests"
X86_MANIFEST = str(MANIFEST_DIR / "revshell.yaml")
X64_MANIFEST = str(MANIFEST_DIR / "x64" / "run_command_x64.yaml")


# ---------------------------------------------------------------------------
# raw=True produces shorter or equal ASM (no inline XOR-mask pairs)
# ---------------------------------------------------------------------------


class TestRawProducesShorterAsm:
    def test_x86_raw_shorter_or_equal(self) -> None:
        normal = build(X86_MANIFEST, assemble=False, raw=False)
        raw_result = build(X86_MANIFEST, assemble=False, raw=True)
        normal_lines = len(normal.asm.splitlines())
        raw_lines = len(raw_result.asm.splitlines())
        assert raw_lines <= normal_lines

    def test_x64_raw_shorter_or_equal(self) -> None:
        normal = build_x64(X64_MANIFEST, assemble=False, raw=False)
        raw_result = build_x64(X64_MANIFEST, assemble=False, raw=True)
        normal_lines = len(normal.asm.splitlines())
        raw_lines = len(raw_result.asm.splitlines())
        assert raw_lines <= normal_lines

    def test_x86_raw_no_xor_mask_lines(self) -> None:
        raw_result = build(X86_MANIFEST, assemble=False, raw=True)
        normal = build(X86_MANIFEST, assemble=False, raw=False)
        raw_xor_count = raw_result.asm.count("    xor  e")
        normal_xor_count = normal.asm.count("    xor  e")
        assert raw_xor_count <= normal_xor_count

    def test_x86_revshell_raw_actually_differs(self) -> None:
        normal = build(X86_MANIFEST, assemble=False, raw=False)
        raw_result = build(X86_MANIFEST, assemble=False, raw=True)
        assert raw_result.asm != normal.asm or len(raw_result.asm) <= len(normal.asm)


# ---------------------------------------------------------------------------
# raw=True preserves manifest_badchars for post-assembly validation
# ---------------------------------------------------------------------------


class TestRawPreservesManifestBadchars:
    def test_x86_raw_still_validates_badchars_postassembly(self) -> None:
        result = build(X86_MANIFEST, assemble=False, raw=True)
        assert result.asm
        assert result.xor_wrapper is not None
        assert "0x00" in result.xor_wrapper
        assert "0x0a" in result.xor_wrapper
        assert "0x0d" in result.xor_wrapper

    def test_x64_raw_still_validates_badchars_postassembly(self) -> None:
        result = build_x64(X64_MANIFEST, assemble=False, raw=True)
        assert result.asm
        assert result.xor_wrapper is not None
        assert "0x00" in result.xor_wrapper
        assert "0x0a" in result.xor_wrapper
        assert "0x0d" in result.xor_wrapper

    def test_x86_raw_config_badchars_empty(self) -> None:
        config = TemplateConfig()
        result = build(X86_MANIFEST, config=config, assemble=False, raw=True)
        assert config.badchars == set()

    def test_x64_raw_config_badchars_empty(self) -> None:
        config = TemplateConfig(arch="x64")
        result = build_x64(X64_MANIFEST, config=config, assemble=False, raw=True)
        assert config.badchars == set()


# ---------------------------------------------------------------------------
# raw=True + encode=True path (no assembler, just code path validation)
# ---------------------------------------------------------------------------


class TestRawWithEncode:
    def test_x86_raw_encode_no_error(self) -> None:
        result = build(X86_MANIFEST, assemble=False, raw=True, encode=True)
        assert result.asm
        assert result.shellcode_bytes is None
        assert result.encoded_bytes is None

    def test_x64_raw_encode_no_error(self) -> None:
        result = build_x64(X64_MANIFEST, assemble=False, raw=True, encode=True)
        assert result.asm
        assert result.shellcode_bytes is None
        assert result.encoded_bytes is None


# ---------------------------------------------------------------------------
# xor_wrapper field on BuildResult
# ---------------------------------------------------------------------------


class TestXorWrapperOnBuildResult:
    def test_x86_has_xor_wrapper(self) -> None:
        result = build(X86_MANIFEST, assemble=False)
        assert result.xor_wrapper is not None
        assert len(result.xor_wrapper) > 100

    def test_x64_has_xor_wrapper(self) -> None:
        result = build_x64(X64_MANIFEST, assemble=False)
        assert result.xor_wrapper is not None
        assert len(result.xor_wrapper) > 100

    def test_x86_wrapper_arch_is_x86(self) -> None:
        result = build(X86_MANIFEST, assemble=False)
        assert 'ARCH = "x86"' in result.xor_wrapper

    def test_x64_wrapper_arch_is_x64(self) -> None:
        result = build_x64(X64_MANIFEST, assemble=False)
        assert 'ARCH = "x64"' in result.xor_wrapper

    def test_x86_raw_mode_still_has_wrapper(self) -> None:
        result = build(X86_MANIFEST, assemble=False, raw=True)
        assert result.xor_wrapper is not None

    def test_x64_raw_mode_still_has_wrapper(self) -> None:
        result = build_x64(X64_MANIFEST, assemble=False, raw=True)
        assert result.xor_wrapper is not None

    def test_wrapper_contains_default_badchars(self) -> None:
        result = build(X86_MANIFEST, assemble=False)
        assert "0x00" in result.xor_wrapper
        assert "0x0a" in result.xor_wrapper
        assert "0x0d" in result.xor_wrapper


# ---------------------------------------------------------------------------
# xor_wrapper content is valid Python
# ---------------------------------------------------------------------------


class TestXorWrapperValidPython:
    def test_x86_wrapper_compiles(self) -> None:
        result = build(X86_MANIFEST, assemble=False)
        compile(result.xor_wrapper, "<xor_wrapper_x86>", "exec")

    def test_x64_wrapper_compiles(self) -> None:
        result = build_x64(X64_MANIFEST, assemble=False)
        compile(result.xor_wrapper, "<xor_wrapper_x64>", "exec")

    def test_x86_raw_wrapper_compiles(self) -> None:
        result = build(X86_MANIFEST, assemble=False, raw=True)
        compile(result.xor_wrapper, "<xor_wrapper_x86_raw>", "exec")


# ---------------------------------------------------------------------------
# generate_xor_wrapper() unit tests
# ---------------------------------------------------------------------------


class TestGenerateXorWrapper:
    def test_x86_default(self) -> None:
        w = generate_xor_wrapper(arch="x86")
        assert 'ARCH = "x86"' in w
        compile(w, "<gen_x86>", "exec")

    def test_x64_default(self) -> None:
        w = generate_xor_wrapper(arch="x64")
        assert 'ARCH = "x64"' in w
        compile(w, "<gen_x64>", "exec")

    def test_custom_badchars(self) -> None:
        w = generate_xor_wrapper(arch="x86", badchars={0x00, 0x20, 0xFF})
        assert "0x00" in w
        assert "0x20" in w
        assert "0xff" in w
        compile(w, "<gen_custom>", "exec")

    def test_empty_badchars_uses_default(self) -> None:
        w = generate_xor_wrapper(arch="x64", badchars=None)
        assert "0x00" in w
        assert "0x0a" in w
        assert "0x0d" in w

    def test_single_badchar(self) -> None:
        w = generate_xor_wrapper(arch="x86", badchars={0x00})
        assert "0x00" in w
        compile(w, "<gen_single>", "exec")

    def test_broad_badchars(self) -> None:
        broad = set(range(0x00, 0x20)) | {0x7F, 0xFF}
        w = generate_xor_wrapper(arch="x64", badchars=broad)
        compile(w, "<gen_broad>", "exec")

    def test_contains_find_xor_key(self) -> None:
        w = generate_xor_wrapper(arch="x86")
        assert "def find_xor_key" in w

    def test_contains_both_stub_builders(self) -> None:
        w = generate_xor_wrapper(arch="x86")
        assert "def build_decoder_stub_x86" in w
        assert "def build_decoder_stub_x64" in w

    def test_contains_main_entry(self) -> None:
        w = generate_xor_wrapper(arch="x86")
        assert 'if __name__ == "__main__":' in w


# ---------------------------------------------------------------------------
# write_outputs writes xor_wrapper.py to disk
# ---------------------------------------------------------------------------


class TestXorWrapperWrittenToDisk:
    def test_x86_wrapper_on_disk(self, tmp_path) -> None:
        result = build(X86_MANIFEST, assemble=False)
        write_outputs(result, str(tmp_path))
        wrapper_path = tmp_path / "bin" / "xor_wrapper.py"
        assert wrapper_path.exists()
        content = wrapper_path.read_text()
        compile(content, "<disk_x86>", "exec")
        assert 'ARCH = "x86"' in content

    def test_x64_wrapper_on_disk(self, tmp_path) -> None:
        result = build_x64(X64_MANIFEST, assemble=False)
        write_outputs(result, str(tmp_path))
        wrapper_path = tmp_path / "bin" / "xor_wrapper.py"
        assert wrapper_path.exists()
        content = wrapper_path.read_text()
        compile(content, "<disk_x64>", "exec")
        assert 'ARCH = "x64"' in content


# ---------------------------------------------------------------------------
# CLI --raw flag parsing
# ---------------------------------------------------------------------------


class TestCLIRawFlag:
    def test_x86_cli_raw_flag(self, tmp_path, monkeypatch) -> None:
        from emitrion.build import main
        out = str(tmp_path / "out")
        monkeypatch.setattr(
            "sys.argv",
            ["emitrion", X86_MANIFEST, "--no-assemble", "--raw", "--out", out],
        )
        main()
        assert (tmp_path / "out" / "asm" / "generated.asm").exists()

    def test_x64_cli_raw_flag(self, tmp_path, monkeypatch) -> None:
        from emitrion.build_x64 import main_x64
        out = str(tmp_path / "out")
        monkeypatch.setattr(
            "sys.argv",
            ["emitrion-x64", X64_MANIFEST, "--no-assemble", "--raw", "--out", out],
        )
        main_x64()
        assert (tmp_path / "out" / "asm" / "generated.asm").exists()

    def test_x86_cli_raw_encode_flags(self, tmp_path, monkeypatch) -> None:
        from emitrion.build import main
        out = str(tmp_path / "out")
        monkeypatch.setattr(
            "sys.argv",
            ["emitrion", X86_MANIFEST, "--no-assemble", "--raw", "--encode",
             "--out", out],
        )
        main()
        assert (tmp_path / "out" / "asm" / "generated.asm").exists()

    def test_x64_cli_raw_encode_flags(self, tmp_path, monkeypatch) -> None:
        from emitrion.build_x64 import main_x64
        out = str(tmp_path / "out")
        monkeypatch.setattr(
            "sys.argv",
            ["emitrion-x64", X64_MANIFEST, "--no-assemble", "--raw", "--encode",
             "--out", out],
        )
        main_x64()
        assert (tmp_path / "out" / "asm" / "generated.asm").exists()


# ---------------------------------------------------------------------------
# Edge case: manifest with no badchars
# ---------------------------------------------------------------------------


class TestRawNoBadchars:
    def test_x86_no_badchars_raw(self, tmp_path) -> None:
        manifest_content = """\
template: ir_run_command
badchars: []
"""
        manifest_path = tmp_path / "no_bc.yaml"
        manifest_path.write_text(manifest_content)
        result = build(str(manifest_path), assemble=False, raw=True)
        assert result.asm
        assert result.xor_wrapper is not None

    def test_x64_no_badchars_raw(self, tmp_path) -> None:
        manifest_content = """\
arch: x64
template: ir_run_command
badchars: []
functions:
  - WinExec
variables: []
strings:
  - label: cmd
    value: calc.exe
    method: mov
    dest: rdi
"""
        manifest_path = tmp_path / "no_bc_x64.yaml"
        manifest_path.write_text(manifest_content)
        result = build_x64(str(manifest_path), assemble=False, raw=True)
        assert result.asm
        assert result.xor_wrapper is not None

    def test_no_badchars_normal_equals_raw(self, tmp_path) -> None:
        manifest_content = """\
template: ir_run_command
badchars: []
"""
        manifest_path = tmp_path / "no_bc_eq.yaml"
        manifest_path.write_text(manifest_content)
        normal = build(str(manifest_path), assemble=False, raw=False)
        raw_result = build(str(manifest_path), assemble=False, raw=True)
        assert normal.asm == raw_result.asm
