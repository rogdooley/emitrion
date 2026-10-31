"""Unit tests for x64 stack allocator."""
from __future__ import annotations

import pytest

from emitrion.schema import Manifest, StringEntry, VariableEntry
from emitrion.stack_alloc_x64 import (
    SHADOW_SPACE,
    RecordingLayoutX64,
    SlotX64,
    StackLayoutX64,
    build_layout_x64,
)


def _make_manifest(
    functions: list[str] | None = None,
    variables: list[str] | None = None,
    strings: list[tuple[str, str]] | None = None,
) -> Manifest:
    return Manifest(
        badchars={0x00},
        functions=functions or [],
        strings=[
            StringEntry(label=l, value=v, method="mov", dest="rdi")
            for l, v in (strings or [])
        ],
        variables=[VariableEntry(name=n) for n in (variables or [])],
        template="ir_run_command",
        arch="x64",
    )


class TestSlotX64:
    def test_rsp_ref(self) -> None:
        slot = SlotX64(name="test", offset=0x40, size=8, category="api")
        assert slot.rsp_ref == "[rsp+0x40]"

    def test_rsp_ref_zero(self) -> None:
        slot = SlotX64(name="test", offset=0, size=8, category="api")
        assert slot.rsp_ref == "[rsp+0x00]"


class TestBuildLayoutX64:
    def test_winexec_only(self) -> None:
        m = _make_manifest(functions=["WinExec"])
        layout = build_layout_x64(m)
        assert isinstance(layout, StackLayoutX64)
        slot = layout.slot("WinExec")
        assert slot.size == 8
        assert slot.offset >= SHADOW_SPACE

    def test_frame_alignment(self) -> None:
        m = _make_manifest(
            functions=["WinExec"],
            variables=["handle"],
            strings=[("cmd", "calc.exe")],
        )
        layout = build_layout_x64(m)
        assert layout.frame_size % 16 == 0

    def test_module_base_slots(self) -> None:
        m = _make_manifest(functions=["CreateProcessA", "LoadLibraryA", "WSAStartup"])
        layout = build_layout_x64(m)
        k32 = layout.slot("kernel32.dll")
        assert k32.size == 8
        assert k32.category == "module_base"

    def test_variable_slots(self) -> None:
        m = _make_manifest(
            functions=["WinExec"],
            variables=["handle", "counter"],
        )
        layout = build_layout_x64(m)
        h = layout.slot("handle")
        c = layout.slot("counter")
        assert h.offset != c.offset
        assert h.size == 8

    def test_string_slots(self) -> None:
        m = _make_manifest(
            functions=["WinExec"],
            strings=[("cmd", "calc.exe"), ("msg", "hello")],
        )
        layout = build_layout_x64(m)
        cmd = layout.slot("cmd")
        msg = layout.slot("msg")
        assert cmd.offset != msg.offset
        assert cmd.offset % 8 == 0

    def test_struct_slots(self) -> None:
        m = _make_manifest(functions=["CreateProcessA"])
        layout = build_layout_x64(m)
        si = layout.slot("STARTUPINFOA")
        pi = layout.slot("PROCESS_INFORMATION")
        assert si.offset % 8 == 0
        assert pi.offset % 8 == 0

    def test_frame_size_limit(self) -> None:
        m = _make_manifest(functions=["WinExec"])
        layout = build_layout_x64(m)
        assert layout.frame_size <= 0x2000

    def test_no_slot_overlap(self) -> None:
        m = _make_manifest(
            functions=["CreateProcessA", "LoadLibraryA", "WSAStartup", "WSASocketA", "connect"],
            variables=["socket_handle"],
            strings=[("cmd", "cmd.exe"), ("ws2_dll", "ws2_32.dll")],
        )
        layout = build_layout_x64(m)
        ranges = []
        for s in layout.all_slots():
            ranges.append((s.offset, s.offset + s.size, s.name))
        ranges.sort()
        for i in range(len(ranges) - 1):
            end_a = ranges[i][1]
            start_b = ranges[i + 1][0]
            assert end_a <= start_b, (
                f"Overlap: {ranges[i][2]} ends at 0x{end_a:x}, "
                f"{ranges[i + 1][2]} starts at 0x{start_b:x}"
            )


class TestRecordingLayoutX64:
    def test_records_accesses(self) -> None:
        rec = RecordingLayoutX64()
        rec.slot("foo")
        rec.slot("bar")
        rec.slot("foo")
        assert rec.accessed == ["foo", "bar", "foo"]

    def test_returns_valid_slot(self) -> None:
        rec = RecordingLayoutX64()
        slot = rec.slot("test")
        assert isinstance(slot, SlotX64)
        assert slot.size == 8
