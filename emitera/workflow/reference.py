"""Reference workflows and the WorkflowTemplate adapter.

WorkflowTemplate bridges the Workflow IR into the existing build pipeline
by implementing the PayloadTemplate interface.  It extracts manifest
requirements (APIs, strings, structs, locals) from the IR and delegates
payload assembly generation to the x86 backend.

The first reference workflow is run_command: WinExec + ExitProcess with
a branch on the WinExec result.
"""
from __future__ import annotations

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
