"""Tests for Linux x64 workflows: IR construction, validation, and lowering."""
from __future__ import annotations

import pytest

from emitrion.arch import Arch, CallingConvention, TargetOS, TargetSpec
from emitrion.payload_templates.base import TemplateConfig
from emitrion.stack_alloc_linux_x64 import (
    LinuxManifestInfo,
    RecordingLayoutLinuxX64,
    build_layout_linux_x64,
)
from emitrion.workflow.ir import (
    AddressOf,
    Block,
    CallAPI,
    Immediate,
    NameRef,
    Syscall,
    Terminate,
    TerminateStyle,
    Workflow,
)
from emitrion.workflow.linux_reference import (
    IRLinuxExecveShellTemplate,
    IRLinuxReverseShellTemplate,
    build_linux_execve_shell_workflow,
    build_linux_reverse_shell_workflow,
)
from emitrion.workflow.validator import validate


class TestSyscallIRNode:
    def test_syscall_creation(self):
        sc = Syscall(number=59, arguments=(Immediate(0),), result="ret")
        assert sc.number == 59
        assert len(sc.arguments) == 1
        assert sc.result == "ret"

    def test_syscall_no_result(self):
        sc = Syscall(number=60, arguments=(Immediate(0),))
        assert sc.result is None

    def test_syscall_frozen(self):
        sc = Syscall(number=1, arguments=())
        with pytest.raises(AttributeError):
            sc.number = 2


class TestExecveShellWorkflow:
    def test_builds_valid_workflow(self):
        wf = build_linux_execve_shell_workflow()
        result = validate(wf)
        assert result.valid, f"Errors: {result.errors}"

    def test_contains_execve_syscall(self):
        wf = build_linux_execve_shell_workflow()
        ops = wf.blocks[0].operations
        syscalls = [op for op in ops if isinstance(op, Syscall)]
        assert len(syscalls) == 1
        assert syscalls[0].number == 59

    def test_has_string_construction(self):
        wf = build_linux_execve_shell_workflow()
        from emitrion.workflow.ir import ConstructString
        ops = wf.blocks[0].operations
        strings = [op for op in ops if isinstance(op, ConstructString)]
        assert len(strings) == 1
        assert strings[0].value == "/bin/sh"

    def test_template_instantiation(self):
        t = IRLinuxExecveShellTemplate()
        assert t is not None


class TestReverseShellWorkflow:
    def test_builds_valid_workflow(self):
        wf = build_linux_reverse_shell_workflow("127.0.0.1", 4444)
        result = validate(wf)
        assert result.valid, f"Errors: {result.errors}"

    def test_contains_expected_syscalls(self):
        wf = build_linux_reverse_shell_workflow()
        all_syscalls = []
        for block in wf.blocks:
            for op in block.operations:
                if isinstance(op, Syscall):
                    all_syscalls.append(op.number)
        assert 41 in all_syscalls  # socket
        assert 42 in all_syscalls  # connect
        assert 33 in all_syscalls  # dup2
        assert 59 in all_syscalls  # execve
        assert 60 in all_syscalls  # exit

    def test_has_five_blocks(self):
        wf = build_linux_reverse_shell_workflow()
        assert len(wf.blocks) == 5

    def test_template_instantiation(self):
        t = IRLinuxReverseShellTemplate()
        assert t is not None

    def test_template_resolve_uses_config(self):
        t = IRLinuxReverseShellTemplate()
        cfg = TemplateConfig(lhost="10.0.0.1", lport=8080)
        wf = t._resolve_workflow(cfg)
        assert wf.name == "ir_linux_reverse_shell"


class TestValidatorWithSyscalls:
    def test_too_many_syscall_args(self):
        wf = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    Syscall(99, tuple(Immediate(0) for _ in range(7))),
                    Terminate(TerminateStyle.HANG),
                )),
            ),
            entry="entry",
        )
        result = validate(wf)
        assert not result.valid
        assert any("max 6" in e for e in result.errors)

    def test_syscall_result_becomes_defined(self):
        wf = Workflow(
            name="test",
            blocks=(
                Block("entry", (
                    Syscall(41, (Immediate(2), Immediate(1), Immediate(0)),
                            result="fd"),
                    Syscall(3, (NameRef("fd"),)),
                    Terminate(TerminateStyle.HANG),
                )),
            ),
            entry="entry",
        )
        result = validate(wf)
        assert result.valid, f"Errors: {result.errors}"

    def test_syscall_undefined_ref_fails(self):
        wf = Workflow(
            name="test",
            blocks=(
                Block("entry", (
                    Syscall(3, (NameRef("nonexistent"),)),
                    Terminate(TerminateStyle.HANG),
                )),
            ),
            entry="entry",
        )
        result = validate(wf)
        assert not result.valid
        assert any("undefined" in e.lower() for e in result.errors)


class TestLinuxBackendLowering:
    def _make_config(self) -> TemplateConfig:
        cfg = TemplateConfig(
            lhost="127.0.0.1",
            lport=4444,
            arch="x64",
        )
        cfg.target = TargetSpec(os=TargetOS.LINUX, arch=Arch.X64)
        cfg.badchars = {0x00, 0x0A, 0x0D}
        return cfg

    def test_execve_shell_emits_syscall(self):
        t = IRLinuxExecveShellTemplate()
        cfg = self._make_config()
        info = LinuxManifestInfo(
            variables=[],
            structs=[],
            strings=[("shell", 8)],
        )
        layout = build_layout_linux_x64(info)
        asm = t.emit(layout, cfg)
        assert "syscall" in asm
        assert "ir_linux_execve_shell" in asm

    def test_reverse_shell_emits_multiple_syscalls(self):
        t = IRLinuxReverseShellTemplate()
        cfg = self._make_config()
        info = LinuxManifestInfo(
            variables=["sockfd", "conn_ret"],
            structs=[("sockaddr_in", 16)],
            strings=[("shell", 8)],
        )
        layout = build_layout_linux_x64(info)
        asm = t.emit(layout, cfg)
        assert asm.count("syscall") >= 6  # socket, connect, 3x dup2, execve, exit

    def test_callapi_raises_in_linux_backend(self):
        from emitrion.workflow.linux_x64_backend import lower_workflow_linux_x64
        wf = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    CallAPI("WinExec", (Immediate(0),)),
                    Terminate(TerminateStyle.HANG),
                )),
            ),
            entry="entry",
        )
        rec = RecordingLayoutLinuxX64()
        with pytest.raises(ValueError, match="CallAPI.*not supported"):
            lower_workflow_linux_x64(wf, rec, set())


class TestArchUpdates:
    def test_linux_x64_calling_convention(self):
        spec = TargetSpec(os=TargetOS.LINUX, arch=Arch.X64)
        assert spec.calling_convention == CallingConvention.LINUX_X64_SYSCALL

    def test_linux_x64_is_supported(self):
        spec = TargetSpec(os=TargetOS.LINUX, arch=Arch.X64)
        assert spec.is_currently_supported

    def test_linux_x86_not_supported(self):
        spec = TargetSpec(os=TargetOS.LINUX, arch=Arch.X86)
        with pytest.raises(ValueError, match="not yet supported"):
            spec.calling_convention

    def test_windows_still_supported(self):
        spec = TargetSpec(os=TargetOS.WINDOWS, arch=Arch.X64)
        assert spec.is_currently_supported
        assert spec.calling_convention == CallingConvention.WINDOWS_X64


class TestSchemaLinuxManifest:
    def test_linux_x64_manifest_loads(self, tmp_path):
        from emitrion.schema import load
        p = tmp_path / "test.yaml"
        p.write_text(
            "arch: x64\nos: linux\n"
            "template: ir_linux_execve_shell\n"
            "badchars: ['00']\n"
        )
        m = load(str(p))
        assert m.os == "linux"
        assert m.arch == "x64"
        assert m.template == "ir_linux_execve_shell"
        assert m.functions == []

    def test_linux_rejects_functions(self, tmp_path):
        from emitrion.schema import load
        p = tmp_path / "test.yaml"
        p.write_text(
            "arch: x64\nos: linux\n"
            "template: ir_linux_execve_shell\n"
            "badchars: ['00']\n"
            "functions: [WinExec]\n"
        )
        with pytest.raises(ValueError, match="should not declare"):
            load(str(p))

    def test_linux_rejects_windows_template(self, tmp_path):
        from emitrion.schema import load
        p = tmp_path / "test.yaml"
        p.write_text(
            "arch: x64\nos: linux\n"
            "template: ir_run_command\n"
            "badchars: ['00']\n"
        )
        with pytest.raises(ValueError, match="Unknown Linux template"):
            load(str(p))
