"""Tests for Workflow IR data types and construction."""
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
    Input,
    Jump,
    NameRef,
    SuccessPredicate,
    Terminate,
    TerminateStyle,
    ValueKind,
    Workflow,
    WriteStructField,
    ZeroStruct,
)


class TestValueRefs:
    def test_immediate_kind(self):
        v = Immediate(42)
        assert v.kind == ValueKind.IMMEDIATE
        assert v.value == 42

    def test_name_ref_kind(self):
        v = NameRef("socket_handle")
        assert v.kind == ValueKind.NAME_REF
        assert v.name == "socket_handle"

    def test_address_of_kind(self):
        v = AddressOf("cmd")
        assert v.kind == ValueKind.ADDRESS_OF
        assert v.name == "cmd"

    def test_input_kind(self):
        v = Input("lhost")
        assert v.kind == ValueKind.INPUT
        assert v.name == "lhost"

    def test_frozen(self):
        v = Immediate(10)
        with pytest.raises(AttributeError):
            v.value = 20


class TestOperations:
    def test_define_constant(self):
        op = DefineConstant("SW_HIDE", 0)
        assert op.name == "SW_HIDE"
        assert op.value == 0

    def test_construct_string(self):
        op = ConstructString("cmd", "calc.exe")
        assert op.name == "cmd"
        assert op.value == "calc.exe"

    def test_allocate_local(self):
        op = AllocateLocal("result")
        assert op.name == "result"

    def test_allocate_struct(self):
        op = AllocateStruct("si", "STARTUPINFOA")
        assert op.name == "si"
        assert op.struct_type == "STARTUPINFOA"

    def test_zero_struct(self):
        op = ZeroStruct("si")
        assert op.name == "si"

    def test_write_struct_field(self):
        op = WriteStructField("si", "dwFlags", Immediate(0x100))
        assert op.struct_name == "si"
        assert op.field_name == "dwFlags"
        assert isinstance(op.value, Immediate)

    def test_call_api_no_result(self):
        op = CallAPI("ExitProcess", (Immediate(0),))
        assert op.api_name == "ExitProcess"
        assert len(op.arguments) == 1
        assert op.result is None

    def test_call_api_with_result(self):
        op = CallAPI("WinExec", (AddressOf("cmd"), Immediate(0)), result="ret")
        assert op.result == "ret"

    def test_compare(self):
        op = Compare("ret", SuccessPredicate.NONZERO, "ok", "fail")
        assert op.value == "ret"
        assert op.true_block == "ok"
        assert op.false_block == "fail"

    def test_jump(self):
        op = Jump("cleanup")
        assert op.target == "cleanup"

    def test_terminate_default(self):
        op = Terminate()
        assert op.style == TerminateStyle.HANG

    def test_all_operations_frozen(self):
        ops = [
            ("name", DefineConstant("x", 1)),
            ("name", ConstructString("s", "a")),
            ("name", AllocateLocal("l")),
            ("name", AllocateStruct("st", "WSADATA")),
            ("name", ZeroStruct("st")),
            ("struct_name", WriteStructField("st", "f", Immediate(0))),
            ("api_name", CallAPI("WinExec", (Immediate(0),))),
            ("value", Compare("x", SuccessPredicate.ZERO, "a", "b")),
            ("target", Jump("a")),
            ("style", Terminate()),
        ]
        for attr, op in ops:
            with pytest.raises(AttributeError):
                setattr(op, attr, "changed")


class TestBlockAndWorkflow:
    def test_block_construction(self):
        b = Block("main", (
            CallAPI("ExitProcess", (Immediate(0),)),
            Terminate(),
        ))
        assert b.name == "main"
        assert len(b.operations) == 2

    def test_workflow_construction(self):
        w = Workflow(
            name="test",
            blocks=(
                Block("entry", (Terminate(),)),
            ),
            entry="entry",
        )
        assert w.name == "test"
        assert w.entry == "entry"
        assert len(w.blocks) == 1

    def test_workflow_frozen(self):
        w = Workflow("test", (Block("e", (Terminate(),)),), "e")
        with pytest.raises(AttributeError):
            w.name = "other"
