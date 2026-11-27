"""Tests for the Linux x64 stack allocator."""
from __future__ import annotations

import pytest

from emitrion.stack_alloc_linux_x64 import (
    STRUCT_ZONE_START_LINUX_X64,
    LinuxManifestInfo,
    RecordingLayoutLinuxX64,
    SlotLinuxX64,
    StackLayoutLinuxX64,
    build_layout_linux_x64,
)


class TestSlotLinuxX64:
    def test_rsp_ref(self):
        slot = SlotLinuxX64("x", offset=0x20, size=8, category="variable")
        assert slot.rsp_ref == "[rsp+0x20]"

    def test_rsp_ref_zero(self):
        slot = SlotLinuxX64("x", offset=0, size=8, category="variable")
        assert slot.rsp_ref == "[rsp+0x00]"


class TestStackLayoutLinuxX64:
    def test_slot_lookup(self):
        slots = [SlotLinuxX64("foo", 0, 8, "variable")]
        layout = StackLayoutLinuxX64(slots, 16)
        assert layout.slot("foo").offset == 0

    def test_missing_slot_raises(self):
        layout = StackLayoutLinuxX64([], 16)
        with pytest.raises(KeyError, match="nope"):
            layout.slot("nope")

    def test_duplicate_slot_raises(self):
        slots = [
            SlotLinuxX64("x", 0, 8, "variable"),
            SlotLinuxX64("x", 8, 8, "variable"),
        ]
        with pytest.raises(ValueError, match="Duplicate"):
            StackLayoutLinuxX64(slots, 16)

    def test_slots_by_category(self):
        slots = [
            SlotLinuxX64("a", 0, 8, "variable"),
            SlotLinuxX64("b", 8, 16, "structure"),
            SlotLinuxX64("c", 24, 8, "variable"),
        ]
        layout = StackLayoutLinuxX64(slots, 48)
        assert len(layout.slots_by_category("variable")) == 2
        assert len(layout.slots_by_category("structure")) == 1
        assert len(layout.slots_by_category("string")) == 0

    def test_all_slots(self):
        slots = [
            SlotLinuxX64("a", 0, 8, "variable"),
            SlotLinuxX64("b", 8, 8, "variable"),
        ]
        layout = StackLayoutLinuxX64(slots, 16)
        assert len(layout.all_slots()) == 2

    def test_frame_size(self):
        layout = StackLayoutLinuxX64([], 0x100)
        assert layout.frame_size == 0x100


class TestBuildLayoutLinuxX64:
    def test_empty_manifest(self):
        info = LinuxManifestInfo(variables=[], structs=[], strings=[])
        layout = build_layout_linux_x64(info)
        assert layout.frame_size == 16
        assert layout.all_slots() == []

    def test_variables_at_offset_zero(self):
        info = LinuxManifestInfo(variables=["a", "b"], structs=[], strings=[])
        layout = build_layout_linux_x64(info)
        assert layout.slot("a").offset == 0
        assert layout.slot("b").offset == 8
        assert layout.slot("a").category == "variable"

    def test_structs_start_at_zone_boundary(self):
        info = LinuxManifestInfo(
            variables=["x"],
            structs=[("mystruct", 16)],
            strings=[],
        )
        layout = build_layout_linux_x64(info)
        assert layout.slot("mystruct").offset == STRUCT_ZONE_START_LINUX_X64
        assert layout.slot("mystruct").size == 16
        assert layout.slot("mystruct").category == "structure"

    def test_strings_after_structs(self):
        info = LinuxManifestInfo(
            variables=[],
            structs=[("s", 16)],
            strings=[("label", 8)],
        )
        layout = build_layout_linux_x64(info)
        s_end = layout.slot("s").offset + layout.slot("s").size
        assert layout.slot("label").offset >= s_end
        assert layout.slot("label").category == "string"

    def test_frame_is_16_byte_aligned(self):
        for n_vars in range(1, 10):
            info = LinuxManifestInfo(
                variables=[f"v{i}" for i in range(n_vars)],
                structs=[],
                strings=[("str", 7)],
            )
            layout = build_layout_linux_x64(info)
            assert layout.frame_size % 16 == 0

    def test_variable_zone_overflow_raises(self):
        many_vars = [f"v{i}" for i in range(20)]
        info = LinuxManifestInfo(variables=many_vars, structs=[], strings=[])
        with pytest.raises(ValueError, match="overflow"):
            build_layout_linux_x64(info)

    def test_frame_too_large_raises(self):
        big_structs = [(f"s{i}", 512) for i in range(20)]
        info = LinuxManifestInfo(variables=[], structs=big_structs, strings=[])
        with pytest.raises(ValueError, match="exceeds two pages"):
            build_layout_linux_x64(info)

    def test_no_overlap(self):
        info = LinuxManifestInfo(
            variables=["a", "b", "c"],
            structs=[("sa", 24), ("sb", 16)],
            strings=[("s1", 10), ("s2", 20)],
        )
        layout = build_layout_linux_x64(info)
        slots = layout.all_slots()
        for i, s1 in enumerate(slots):
            for s2 in slots[i + 1:]:
                s1_end = s1.offset + s1.size
                s2_end = s2.offset + s2.size
                assert s1_end <= s2.offset or s2_end <= s1.offset, (
                    f"Overlap: {s1.name}@[{s1.offset}..{s1_end}) vs "
                    f"{s2.name}@[{s2.offset}..{s2_end})"
                )


class TestRecordingLayoutLinuxX64:
    def test_records_accesses(self):
        rec = RecordingLayoutLinuxX64()
        rec.slot("foo")
        rec.slot("bar")
        assert rec.accessed == ["foo", "bar"]

    def test_returns_slot(self):
        rec = RecordingLayoutLinuxX64()
        s = rec.slot("test")
        assert isinstance(s, SlotLinuxX64)
        assert s.name == "test"

    def test_frame_size(self):
        rec = RecordingLayoutLinuxX64()
        assert rec.frame_size == 0x400
