"""Immutable typed data model for Windows API workflows.

A workflow is an ordered set of blocks, each containing typed operations
that model API calls, value definitions, structure manipulation, and
control flow.  Values are references, not formatted assembly strings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

# ---------------------------------------------------------------------------
# Value references
# ---------------------------------------------------------------------------


class ValueKind(Enum):
    IMMEDIATE = auto()
    NAME_REF = auto()
    ADDRESS_OF = auto()
    INPUT = auto()


@dataclass(frozen=True)
class Immediate:
    """A literal integer value."""
    value: int
    kind: ValueKind = field(default=ValueKind.IMMEDIATE, init=False, repr=False)


@dataclass(frozen=True)
class NameRef:
    """Reference to a named value (local, API return, constant)."""
    name: str
    kind: ValueKind = field(default=ValueKind.NAME_REF, init=False, repr=False)


@dataclass(frozen=True)
class AddressOf:
    """Address of a named allocation (string, struct, local buffer)."""
    name: str
    kind: ValueKind = field(default=ValueKind.ADDRESS_OF, init=False, repr=False)


@dataclass(frozen=True)
class Input:
    """A manifest or config-derived input value (lhost, lport, etc.)."""
    name: str
    kind: ValueKind = field(default=ValueKind.INPUT, init=False, repr=False)


ValueRef = Immediate | NameRef | AddressOf | Input


# ---------------------------------------------------------------------------
# Success predicates for API return values
# ---------------------------------------------------------------------------


class SuccessPredicate(Enum):
    ZERO = "zero"
    NONZERO = "nonzero"
    NULL = "null"
    INVALID_HANDLE = "invalid_handle"
    SIGNED_NEGATIVE = "signed_negative"


# ---------------------------------------------------------------------------
# Termination styles
# ---------------------------------------------------------------------------


class TerminateStyle(Enum):
    HANG = "hang"


class ExitStrategy(Enum):
    """How a workflow exits after its payload completes (or fails)."""
    EXIT_PROCESS = "exit_process"
    TERMINATE_PROCESS = "terminate_process"
    THREAD_ONLY = "thread_only"


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DefineConstant:
    """Define a named constant integer value."""
    name: str
    value: int


@dataclass(frozen=True)
class ConstructString:
    """Declare a null-terminated string for stack construction."""
    name: str
    value: str


@dataclass(frozen=True)
class AllocateLocal:
    """Allocate a named 4-byte local value on the stack."""
    name: str


@dataclass(frozen=True)
class AllocateStruct:
    """Allocate a named structure on the stack."""
    name: str
    struct_type: str


@dataclass(frozen=True)
class ZeroStruct:
    """Zero-initialize a previously allocated structure."""
    name: str


@dataclass(frozen=True)
class WriteStructField:
    """Write a scalar value to a declared structure field."""
    struct_name: str
    field_name: str
    value: ValueRef


@dataclass(frozen=True)
class CallAPI:
    """Call a catalogued API with explicit ordered arguments.

    Arguments are in source-order (left to right as in the C prototype).
    The backend reverses them for stdcall push order.
    """
    api_name: str
    arguments: tuple[ValueRef, ...]
    result: str | None = None


@dataclass(frozen=True)
class Compare:
    """Branch on a named value using a success predicate."""
    value: str
    predicate: SuccessPredicate
    true_block: str
    false_block: str


@dataclass(frozen=True)
class Jump:
    """Unconditional jump to a named block."""
    target: str


@dataclass(frozen=True)
class Terminate:
    """End the workflow with a specified termination style."""
    style: TerminateStyle = TerminateStyle.HANG


Operation = (
    DefineConstant | ConstructString | AllocateLocal | AllocateStruct
    | ZeroStruct | WriteStructField | CallAPI | Compare | Jump | Terminate
)

TERMINATOR_TYPES = (Compare, Jump, Terminate)


# ---------------------------------------------------------------------------
# Block and Workflow
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Block:
    """A named sequence of operations ending with a terminator."""
    name: str
    operations: tuple[Operation, ...]


@dataclass(frozen=True)
class Workflow:
    """An immutable, validated workflow definition."""
    name: str
    blocks: tuple[Block, ...]
    entry: str
