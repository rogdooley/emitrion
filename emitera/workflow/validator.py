"""Workflow IR validation.

Checks a Workflow for structural correctness before lowering:
  - all referenced values are defined before use (control-flow aware)
  - no duplicate value names
  - CallAPI argument counts and categories match the ABI catalog
  - Compare predicates match the API's documented return semantics
  - Input references use known TemplateConfig field names
  - all referenced blocks exist
  - entry block exists
  - all blocks are reachable from entry
  - every block ends with exactly one terminator
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

KNOWN_INPUTS = frozenset({
    "lhost", "lport", "command", "src_path", "dst_path",
    "url", "url_path", "alloc_size", "process_name", "service_name",
})


@dataclass
class ValidationResult:
    """Collected validation diagnostics."""
    errors: list[str]
    warnings: list[str]

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0


@dataclass
class _BlockDefs:
    """Definitions exported by a validated block."""
    values: set[str]
    allocations: set[str]
    struct_allocations: dict[str, str]
    result_apis: dict[str, str]
    string_names: set[str]

    def copy(self) -> _BlockDefs:
        return _BlockDefs(
            values=set(self.values),
            allocations=set(self.allocations),
            struct_allocations=dict(self.struct_allocations),
            result_apis=dict(self.result_apis),
            string_names=set(self.string_names),
        )

    @staticmethod
    def empty() -> _BlockDefs:
        return _BlockDefs(
            values=set(),
            allocations=set(),
            struct_allocations={},
            result_apis={},
            string_names=set(),
        )

    @staticmethod
    def intersect(defs_list: list[_BlockDefs]) -> _BlockDefs:
        if not defs_list:
            return _BlockDefs.empty()
        if len(defs_list) == 1:
            return defs_list[0].copy()
        values = set.intersection(*(d.values for d in defs_list))
        allocations = set.intersection(*(d.allocations for d in defs_list))
        common_struct_keys = set.intersection(
            *(set(d.struct_allocations.keys()) for d in defs_list)
        )
        struct_allocations = {
            k: defs_list[0].struct_allocations[k]
            for k in common_struct_keys
            if all(d.struct_allocations.get(k) == defs_list[0].struct_allocations[k]
                   for d in defs_list)
        }
        common_result_keys = set.intersection(
            *(set(d.result_apis.keys()) for d in defs_list)
        )
        result_apis = {
            k: defs_list[0].result_apis[k]
            for k in common_result_keys
            if all(d.result_apis.get(k) == defs_list[0].result_apis[k]
                   for d in defs_list)
        }
        string_names = set.intersection(*(d.string_names for d in defs_list))
        return _BlockDefs(
            values=values,
            allocations=allocations,
            struct_allocations=struct_allocations,
            result_apis=result_apis,
            string_names=string_names,
        )


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
        return ValidationResult(errors=errors, warnings=warnings)

    all_names: set[str] = set()

    predecessors: dict[str, list[str]] = {name: [] for name in block_map}
    for block in workflow.blocks:
        if block.operations:
            last = block.operations[-1]
            if isinstance(last, Compare):
                if last.true_block in predecessors:
                    predecessors[last.true_block].append(block.name)
                if last.false_block in predecessors:
                    predecessors[last.false_block].append(block.name)
            elif isinstance(last, Jump):
                if last.target in predecessors:
                    predecessors[last.target].append(block.name)

    reachable = _compute_reachable(workflow, block_map)
    for name in sorted(set(block_map.keys()) - reachable):
        errors.append(f"Block '{name}' is unreachable from entry")

    block_output: dict[str, _BlockDefs] = {}
    visit_order = _topological_order(workflow.entry, block_map, reachable)

    for block_name in visit_order:
        block = block_map[block_name]

        if block_name == workflow.entry:
            incoming = _BlockDefs.empty()
        else:
            pred_defs = [
                block_output[p] for p in predecessors[block_name]
                if p in block_output
            ]
            if not pred_defs:
                incoming = _BlockDefs.empty()
            else:
                incoming = _BlockDefs.intersect(pred_defs)

        outgoing = _validate_block(
            block, block_map, incoming, all_names, errors, warnings,
        )
        block_output[block_name] = outgoing

    return ValidationResult(errors=errors, warnings=warnings)


def _compute_reachable(
    workflow: Workflow, block_map: dict[str, Block],
) -> set[str]:
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
    return reachable


def _topological_order(
    entry: str, block_map: dict[str, Block], reachable: set[str],
) -> list[str]:
    """BFS from entry, yielding blocks in a valid processing order."""
    visited: set[str] = set()
    order: list[str] = []
    queue = [entry]
    while queue:
        name = queue.pop(0)
        if name in visited or name not in reachable or name not in block_map:
            continue
        visited.add(name)
        order.append(name)
        block = block_map.get(name)
        if block is None or not block.operations:
            continue
        last = block.operations[-1]
        if isinstance(last, Compare):
            queue.append(last.true_block)
            queue.append(last.false_block)
        elif isinstance(last, Jump):
            queue.append(last.target)
    return order


def _validate_block(
    block: Block,
    block_map: dict[str, Block],
    incoming: _BlockDefs,
    all_names: set[str],
    errors: list[str],
    warnings: list[str],
) -> _BlockDefs:
    """Validate a single block's operations. Returns outgoing definitions."""
    defs = incoming.copy()
    ops = block.operations

    if not ops:
        errors.append(f"Block '{block.name}' has no operations")
        return defs

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
            defs.values.add(op.name)

        elif isinstance(op, ConstructString):
            _check_unique_name(op.name, all_names, block.name, errors)
            defs.allocations.add(op.name)
            defs.string_names.add(op.name)

        elif isinstance(op, AllocateLocal):
            _check_unique_name(op.name, all_names, block.name, errors)
            defs.values.add(op.name)
            defs.allocations.add(op.name)

        elif isinstance(op, AllocateStruct):
            _check_unique_name(op.name, all_names, block.name, errors)
            defs.allocations.add(op.name)
            defs.struct_allocations[op.name] = op.struct_type
            if op.struct_type not in STRUCT_DATABASE:
                errors.append(
                    f"Block '{block.name}': AllocateStruct '{op.name}' "
                    f"references unknown struct type '{op.struct_type}'"
                )

        elif isinstance(op, ZeroStruct):
            if op.name not in defs.allocations:
                errors.append(
                    f"Block '{block.name}': ZeroStruct references "
                    f"undefined allocation '{op.name}'"
                )

        elif isinstance(op, WriteStructField):
            if op.struct_name not in defs.struct_allocations:
                errors.append(
                    f"Block '{block.name}': WriteStructField references "
                    f"undefined struct '{op.struct_name}'"
                )
            else:
                stype = defs.struct_allocations[op.struct_name]
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
                op.value, defs.values, defs.allocations,
                block.name, errors,
            )

        elif isinstance(op, CallAPI):
            _validate_call(op, defs, block.name, errors, warnings)
            if op.result is not None:
                _check_unique_name(op.result, all_names, block.name, errors)
                defs.values.add(op.result)
                defs.result_apis[op.result] = op.api_name

        elif isinstance(op, Compare):
            if op.value not in defs.values:
                errors.append(
                    f"Block '{block.name}': Compare references "
                    f"undefined value '{op.value}'"
                )
            else:
                api_name = defs.result_apis.get(op.value)
                if api_name:
                    abi = get_abi(api_name)
                    if abi and abi.returns and abi.returns.success != op.predicate:
                        errors.append(
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

    return defs


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
        if ref.name not in KNOWN_INPUTS:
            errors.append(
                f"Block '{block_name}': Input '{ref.name}' is not a "
                f"known config field (valid: {sorted(KNOWN_INPUTS)})"
            )
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
    defs: _BlockDefs,
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
                op, abi, defs.struct_allocations, defs.string_names,
                block_name, errors,
            )

    for arg in op.arguments:
        _validate_value_ref(arg, defs.values, defs.allocations,
                            block_name, errors)


def _validate_arg_categories(
    op: CallAPI,
    abi,
    struct_allocations: dict[str, str],
    string_names: set[str],
    block_name: str,
    errors: list[str],
) -> None:
    """Check that argument value types match declared ABI categories."""
    for i, (arg, desc) in enumerate(zip(op.arguments, abi.arguments)):
        cat = desc.category

        if cat == ArgCategory.STRING_PTR:
            if isinstance(arg, Immediate):
                errors.append(
                    f"Block '{block_name}': {op.api_name} arg '{desc.name}' "
                    f"expects a string pointer, got Immediate"
                )
            elif isinstance(arg, AddressOf) and arg.name not in string_names:
                if arg.name not in struct_allocations:
                    errors.append(
                        f"Block '{block_name}': {op.api_name} arg '{desc.name}' "
                        f"expects AddressOf a string, but '{arg.name}' is not "
                        f"a ConstructString"
                    )

        elif cat == ArgCategory.STRUCT_PTR:
            if isinstance(arg, AddressOf) and desc.struct_type:
                actual_type = struct_allocations.get(arg.name)
                if actual_type and actual_type != desc.struct_type:
                    errors.append(
                        f"Block '{block_name}': {op.api_name} arg '{desc.name}' "
                        f"expects struct type '{desc.struct_type}', got "
                        f"'{actual_type}'"
                    )

        elif cat == ArgCategory.NULL_PTR:
            if not isinstance(arg, Immediate) or arg.value != 0:
                errors.append(
                    f"Block '{block_name}': {op.api_name} arg '{desc.name}' "
                    f"should be NULL (Immediate(0))"
                )
