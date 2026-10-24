"""Workflow IR validation.

Checks a Workflow for structural correctness before lowering:
  - all referenced values are defined before use
  - no duplicate value names
  - CallAPI argument counts match the ABI catalog
  - all referenced blocks exist
  - entry block exists
  - all blocks are reachable from entry
  - every block ends with exactly one terminator
  - Compare references a defined value
  - AllocateStruct references a known struct type
  - WriteStructField references a defined struct and a valid field
"""
from __future__ import annotations

from dataclasses import dataclass

from ..api_database import API_DATABASE, STRUCT_DATABASE
from .catalog import ABI_CATALOG, ArgCategory, get_abi
from .ir import (
    AddressOf,
    AllocateLocal,
    AllocateStruct,
    Block,
    CallAPI,
    Compare,
    ConstructString,
    DefineConstant,
    Input,
    Jump,
    Immediate,
    NameRef,
    TERMINATOR_TYPES,
    Terminate,
    ValueRef,
    Workflow,
    WriteStructField,
    ZeroStruct,
)


@dataclass
class ValidationResult:
    """Collected validation diagnostics."""
    errors: list[str]
    warnings: list[str]

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0


def validate(workflow: Workflow) -> ValidationResult:
    """Validate a Workflow IR, returning all diagnostics found."""
    errors: list[str] = []
    warnings: list[str] = []

    block_map: dict[str, Block] = {}
    for block in workflow.blocks:
        if block.name in block_map:
            errors.append(f"Duplicate block name: '{block.name}'")
        block_map[block.name] = block

    if workflow.entry not in block_map:
        errors.append(f"Entry block '{workflow.entry}' does not exist")

    defined_values: set[str] = set()
    defined_allocations: set[str] = set()
    all_names: set[str] = set()
    struct_allocations: dict[str, str] = {}
    result_apis: dict[str, str] = {}
    string_names: set[str] = set()

    for block in workflow.blocks:
        _validate_block(
            block, block_map, defined_values, defined_allocations,
            all_names, struct_allocations, result_apis, string_names,
            errors, warnings,
        )

    _check_reachability(workflow, block_map, errors)

    return ValidationResult(errors=errors, warnings=warnings)


def _validate_block(
    block: Block,
    block_map: dict[str, Block],
    defined_values: set[str],
    defined_allocations: set[str],
    all_names: set[str],
    struct_allocations: dict[str, str],
    result_apis: dict[str, str],
    string_names: set[str],
    errors: list[str],
    warnings: list[str],
) -> None:
    """Validate a single block's operations."""
    ops = block.operations
    if not ops:
        errors.append(f"Block '{block.name}' has no operations")
        return

    last = ops[-1]
    if not isinstance(last, TERMINATOR_TYPES):
        errors.append(
            f"Block '{block.name}' does not end with a terminator "
            f"(Compare, Jump, or Terminate); last op is {type(last).__name__}"
        )

    for i, op in enumerate(ops):
        if isinstance(op, TERMINATOR_TYPES) and i < len(ops) - 1:
            errors.append(
                f"Block '{block.name}': terminator {type(op).__name__} "
                f"at position {i} is not the last operation"
            )

        if isinstance(op, DefineConstant):
            _check_unique_name(op.name, all_names, block.name, errors)
            defined_values.add(op.name)

        elif isinstance(op, ConstructString):
            _check_unique_name(op.name, all_names, block.name, errors)
            defined_allocations.add(op.name)
            string_names.add(op.name)

        elif isinstance(op, AllocateLocal):
            _check_unique_name(op.name, all_names, block.name, errors)
            defined_values.add(op.name)
            defined_allocations.add(op.name)

        elif isinstance(op, AllocateStruct):
            _check_unique_name(op.name, all_names, block.name, errors)
            defined_allocations.add(op.name)
            struct_allocations[op.name] = op.struct_type
            if op.struct_type not in STRUCT_DATABASE:
                errors.append(
                    f"Block '{block.name}': AllocateStruct '{op.name}' "
                    f"references unknown struct type '{op.struct_type}'"
                )

        elif isinstance(op, ZeroStruct):
            if op.name not in defined_allocations:
                errors.append(
                    f"Block '{block.name}': ZeroStruct references "
                    f"undefined allocation '{op.name}'"
                )

        elif isinstance(op, WriteStructField):
            if op.struct_name not in struct_allocations:
                errors.append(
                    f"Block '{block.name}': WriteStructField references "
                    f"undefined struct '{op.struct_name}'"
                )
            else:
                stype = struct_allocations[op.struct_name]
                if stype in STRUCT_DATABASE:
                    field_names = {
                        f.name for f in STRUCT_DATABASE[stype].fields
                    }
                    if op.field_name not in field_names:
                        errors.append(
                            f"Block '{block.name}': WriteStructField "
                            f"'{op.field_name}' not found in struct "
                            f"'{stype}' (available: {sorted(field_names)})"
                        )
            _validate_value_ref(
                op.value, defined_values, defined_allocations,
                block.name, errors,
            )

        elif isinstance(op, CallAPI):
            _validate_call(op, defined_values, defined_allocations,
                           struct_allocations, string_names,
                           block.name, errors, warnings)
            if op.result is not None:
                _check_unique_name(op.result, all_names, block.name, errors)
                defined_values.add(op.result)
                result_apis[op.result] = op.api_name

        elif isinstance(op, Compare):
            if op.value not in defined_values:
                errors.append(
                    f"Block '{block.name}': Compare references "
                    f"undefined value '{op.value}'"
                )
            else:
                api_name = result_apis.get(op.value)
                if api_name:
                    abi = get_abi(api_name)
                    if abi and abi.returns and abi.returns.success != op.predicate:
                        warnings.append(
                            f"Block '{block.name}': Compare on '{op.value}' "
                            f"uses predicate {op.predicate.value} but "
                            f"{api_name} documents {abi.returns.success.value}"
                        )
            if op.true_block not in block_map:
                errors.append(
                    f"Block '{block.name}': Compare true_block "
                    f"'{op.true_block}' does not exist"
                )
            if op.false_block not in block_map:
                errors.append(
                    f"Block '{block.name}': Compare false_block "
                    f"'{op.false_block}' does not exist"
                )

        elif isinstance(op, Jump):
            if op.target not in block_map:
                errors.append(
                    f"Block '{block.name}': Jump target "
                    f"'{op.target}' does not exist"
                )


def _check_unique_name(
    name: str, all_names: set[str], block_name: str, errors: list[str],
) -> None:
    if name in all_names:
        errors.append(f"Block '{block_name}': duplicate name '{name}'")
    all_names.add(name)


def _validate_value_ref(
    ref: ValueRef,
    defined_values: set[str],
    defined_allocations: set[str],
    block_name: str,
    errors: list[str],
) -> None:
    """Check that a value reference is resolvable."""
    if isinstance(ref, Immediate):
        pass
    elif isinstance(ref, Input):
        pass
    elif isinstance(ref, NameRef):
        if ref.name not in defined_values:
            errors.append(
                f"Block '{block_name}': NameRef '{ref.name}' is undefined"
            )
    elif isinstance(ref, AddressOf):
        if ref.name not in defined_allocations:
            errors.append(
                f"Block '{block_name}': AddressOf '{ref.name}' references "
                f"undefined allocation"
            )


def _validate_call(
    op: CallAPI,
    defined_values: set[str],
    defined_allocations: set[str],
    struct_allocations: dict[str, str],
    string_names: set[str],
    block_name: str,
    errors: list[str],
    warnings: list[str],
) -> None:
    """Validate a CallAPI operation against the ABI catalog."""
    if op.api_name not in API_DATABASE:
        errors.append(
            f"Block '{block_name}': CallAPI '{op.api_name}' "
            f"is not in API_DATABASE"
        )
        return

    abi = get_abi(op.api_name)
    if abi is None:
        warnings.append(
            f"Block '{block_name}': CallAPI '{op.api_name}' has no "
            f"ABI catalog entry (legacy_only); argument validation skipped"
        )
    elif not abi.workflow_supported:
        warnings.append(
            f"Block '{block_name}': CallAPI '{op.api_name}' is not "
            f"marked workflow_supported"
        )
    else:
        expected = len(abi.arguments)
        actual = len(op.arguments)
        if actual != expected:
            errors.append(
                f"Block '{block_name}': CallAPI '{op.api_name}' expects "
                f"{expected} arguments, got {actual}"
            )
        else:
            _validate_arg_categories(
                op, abi, struct_allocations, string_names,
                block_name, warnings,
            )

    for arg in op.arguments:
        _validate_value_ref(arg, defined_values, defined_allocations,
                            block_name, errors)


def _validate_arg_categories(
    op: CallAPI,
    abi,
    struct_allocations: dict[str, str],
    string_names: set[str],
    block_name: str,
    warnings: list[str],
) -> None:
    """Check that argument value types match declared ABI categories."""
    for i, (arg, desc) in enumerate(zip(op.arguments, abi.arguments)):
        cat = desc.category

        if cat == ArgCategory.STRING_PTR:
            if isinstance(arg, Immediate):
                warnings.append(
                    f"Block '{block_name}': {op.api_name} arg '{desc.name}' "
                    f"expects a string pointer, got Immediate"
                )
            elif isinstance(arg, AddressOf) and arg.name not in string_names:
                if arg.name not in struct_allocations:
                    warnings.append(
                        f"Block '{block_name}': {op.api_name} arg '{desc.name}' "
                        f"expects AddressOf a string, but '{arg.name}' is not "
                        f"a ConstructString"
                    )

        elif cat == ArgCategory.STRUCT_PTR:
            if isinstance(arg, AddressOf) and desc.struct_type:
                actual_type = struct_allocations.get(arg.name)
                if actual_type and actual_type != desc.struct_type:
                    warnings.append(
                        f"Block '{block_name}': {op.api_name} arg '{desc.name}' "
                        f"expects struct type '{desc.struct_type}', got "
                        f"'{actual_type}'"
                    )

        elif cat == ArgCategory.NULL_PTR:
            if not isinstance(arg, Immediate) or arg.value != 0:
                warnings.append(
                    f"Block '{block_name}': {op.api_name} arg '{desc.name}' "
                    f"should be NULL (Immediate(0))"
                )


def _check_reachability(
    workflow: Workflow,
    block_map: dict[str, Block],
    errors: list[str],
) -> None:
    """Check that all blocks are reachable from the entry block."""
    if workflow.entry not in block_map:
        return

    reachable: set[str] = set()
    stack = [workflow.entry]
    while stack:
        name = stack.pop()
        if name in reachable:
            continue
        reachable.add(name)
        block = block_map.get(name)
        if block is None:
            continue
        for op in block.operations:
            if isinstance(op, Compare):
                stack.append(op.true_block)
                stack.append(op.false_block)
            elif isinstance(op, Jump):
                stack.append(op.target)

    unreachable = set(block_map.keys()) - reachable
    for name in sorted(unreachable):
        errors.append(f"Block '{name}' is unreachable from entry")
