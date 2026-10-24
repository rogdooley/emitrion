"""Tests for Workflow IR validation."""
from __future__ import annotations

import pytest

from emitera.workflow.ir import (
    AddressOf,
    AllocateLocal,
    AllocateStruct,
    Block,
    CallAPI,
    Compare,
    ConstructString,
    DefineConstant,
    Immediate,
    Jump,
    NameRef,
    SuccessPredicate,
    Terminate,
    TerminateStyle,
    Workflow,
    WriteStructField,
    ZeroStruct,
)
from emitera.workflow.validator import validate


def _minimal_workflow(**kwargs) -> Workflow:
    """Build a minimal valid workflow, with overrides."""
    defaults = dict(
        name="test",
        blocks=(Block("entry", (Terminate(),)),),
        entry="entry",
    )
    defaults.update(kwargs)
    return Workflow(**defaults)


class TestValidWorkflows:
    def test_minimal_workflow_is_valid(self):
        w = _minimal_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_run_command_workflow_valid(self):
        from emitera.workflow.reference import build_run_command_workflow
        w = build_run_command_workflow()
        result = validate(w)
        assert result.valid, result.errors

    def test_multi_block_workflow(self):
        w = Workflow(
            name="branch",
            blocks=(
                Block("entry", (
                    CallAPI("WinExec", (Immediate(0), Immediate(0)), result="ret"),
                    Compare("ret", SuccessPredicate.NONZERO, "ok", "fail"),
                )),
                Block("ok", (Terminate(),)),
                Block("fail", (Terminate(),)),
            ),
            entry="entry",
        )
        result = validate(w)
        assert result.valid, result.errors


class TestEntryBlockErrors:
    def test_missing_entry_block(self):
        w = Workflow(
            name="bad",
            blocks=(Block("main", (Terminate(),)),),
            entry="nonexistent",
        )
        result = validate(w)
        assert not result.valid
        assert any("nonexistent" in e for e in result.errors)


class TestDuplicateErrors:
    def test_duplicate_block_names(self):
        w = Workflow(
            name="dup",
            blocks=(
                Block("entry", (Terminate(),)),
                Block("entry", (Terminate(),)),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("Duplicate block" in e for e in result.errors)

    def test_duplicate_value_names(self):
        w = Workflow(
            name="dup",
            blocks=(
                Block("entry", (
                    AllocateLocal("x"),
                    AllocateLocal("x"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("duplicate name 'x'" in e for e in result.errors)


class TestTerminatorErrors:
    def test_no_terminator(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    DefineConstant("x", 1),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("does not end with a terminator" in e for e in result.errors)

    def test_empty_block(self):
        w = Workflow(
            name="bad",
            blocks=(Block("entry", ()),),
            entry="entry",
        )
        result = validate(w)
        assert any("no operations" in e for e in result.errors)

    def test_terminator_not_last(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    Terminate(),
                    DefineConstant("x", 1),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("not the last operation" in e for e in result.errors)


class TestValueRefErrors:
    def test_undefined_name_ref(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    CallAPI("WinExec", (NameRef("nonexistent"), Immediate(0))),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("nonexistent" in e and "undefined" in e for e in result.errors)

    def test_undefined_address_of(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    CallAPI("WinExec", (AddressOf("missing"), Immediate(0))),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("missing" in e and "undefined" in e for e in result.errors)


class TestCallAPIErrors:
    def test_wrong_argument_count(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    CallAPI("WinExec", (Immediate(0),)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("expects 2 arguments, got 1" in e for e in result.errors)

    def test_unknown_api(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    CallAPI("FakeAPI", (Immediate(0),)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("not in API_DATABASE" in e for e in result.errors)


class TestStructErrors:
    def test_unknown_struct_type(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    AllocateStruct("s", "NONEXISTENT_STRUCT"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("unknown struct type" in e for e in result.errors)

    def test_zero_struct_undefined(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    ZeroStruct("missing"),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("undefined allocation" in e for e in result.errors)

    def test_write_undefined_struct(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    WriteStructField("missing", "cb", Immediate(0)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("undefined struct 'missing'" in e for e in result.errors)

    def test_write_unknown_field(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    AllocateStruct("si", "STARTUPINFOA"),
                    WriteStructField("si", "nonexistent_field", Immediate(0)),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("nonexistent_field" in e and "not found" in e for e in result.errors)


class TestCompareAndBranchErrors:
    def test_compare_undefined_value(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    Compare("missing", SuccessPredicate.NONZERO, "ok", "fail"),
                )),
                Block("ok", (Terminate(),)),
                Block("fail", (Terminate(),)),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("undefined value 'missing'" in e for e in result.errors)

    def test_compare_missing_target_blocks(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (
                    AllocateLocal("r"),
                    Compare("r", SuccessPredicate.NONZERO, "gone1", "gone2"),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("gone1" in e for e in result.errors)
        assert any("gone2" in e for e in result.errors)

    def test_jump_missing_target(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (Jump("nowhere"),)),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("nowhere" in e for e in result.errors)


class TestReachability:
    def test_unreachable_block(self):
        w = Workflow(
            name="bad",
            blocks=(
                Block("entry", (Terminate(),)),
                Block("orphan", (Terminate(),)),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("orphan" in e and "unreachable" in e for e in result.errors)

    def test_all_reachable_via_compare(self):
        w = Workflow(
            name="ok",
            blocks=(
                Block("entry", (
                    AllocateLocal("r"),
                    Compare("r", SuccessPredicate.NONZERO, "a", "b"),
                )),
                Block("a", (Terminate(),)),
                Block("b", (Terminate(),)),
            ),
            entry="entry",
        )
        result = validate(w)
        unreachable = [e for e in result.errors if "unreachable" in e]
        assert unreachable == []


class TestWarnings:
    def test_legacy_api_produces_warning(self):
        w = Workflow(
            name="legacy",
            blocks=(
                Block("entry", (
                    CallAPI("GetLastError", ()),
                    Terminate(),
                )),
            ),
            entry="entry",
        )
        result = validate(w)
        assert any("legacy_only" in w or "no ABI" in w for w in result.warnings)
