"""Tests for the stack slot allocator (Phase 2)."""
from __future__ import annotations

import pytest




# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def revshell_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "revshell.yaml"))
    return build_layout(manifest)


@pytest.fixture
def calc_layout(manifest_dir):
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / "calc.yaml"))
    return build_layout(manifest)


@pytest.fixture(params=["revshell.yaml", "calc.yaml", "tcp_stager.yaml",
                         "tcp_download.yaml", "copy_then_run.yaml"])
def any_layout(request, manifest_dir):
    """Parameterised fixture: runs the test once per manifest."""
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    manifest = load(str(manifest_dir / request.param))
    return build_layout(manifest)


# ---------------------------------------------------------------------------
# Module-base offset assertions
# ---------------------------------------------------------------------------

def test_module_base_offsets(revshell_layout):
    assert revshell_layout.slot("kernel32.dll").offset == 0x20
    assert revshell_layout.slot("ws2_32.dll").offset == 0x24


# ---------------------------------------------------------------------------
# API slot offset assertions
# revshell.yaml declares 5 functions in order:
#   CreateProcessA, LoadLibraryA, WSAStartup, WSASocketA, connect
# Module bases occupy 0x20 and 0x24 (2 slots), so API slots start at 0x28.
# ---------------------------------------------------------------------------

def test_api_slot_offsets(revshell_layout):
    assert revshell_layout.slot("CreateProcessA").offset == 0x28
    assert revshell_layout.slot("LoadLibraryA").offset == 0x2c
    assert revshell_layout.slot("WSAStartup").offset == 0x30
    assert revshell_layout.slot("WSASocketA").offset == 0x34
    assert revshell_layout.slot("connect").offset == 0x38


# ---------------------------------------------------------------------------
# Struct size assertions
# ---------------------------------------------------------------------------

def test_struct_sizes(revshell_layout):
    assert revshell_layout.slot("STARTUPINFOA").size == 0x44
    assert revshell_layout.slot("PROCESS_INFORMATION").size == 0x10
    assert revshell_layout.slot("WSADATA").size == 0x190
    assert revshell_layout.slot("sockaddr_in").size == 0x10


# ---------------------------------------------------------------------------
# Struct zone starts at hard constant 0x80
# ---------------------------------------------------------------------------

def test_struct_zone_starts_at_0x80(revshell_layout):
    si = revshell_layout.slot("STARTUPINFOA")
    assert si.offset == 0x80 + si.size


# ---------------------------------------------------------------------------
# Category assertions
# ---------------------------------------------------------------------------

def test_slot_categories(revshell_layout):
    assert revshell_layout.slot("kernel32.dll").category == "module_base"
    assert revshell_layout.slot("ws2_32.dll").category == "module_base"
    assert revshell_layout.slot("CreateProcessA").category == "api"
    assert revshell_layout.slot("STARTUPINFOA").category == "structure"
    assert revshell_layout.slot("WSADATA").category == "structure"


def test_slots_by_category_module_base(revshell_layout):
    bases = revshell_layout.slots_by_category("module_base")
    names = [s.name for s in bases]
    assert names == ["kernel32.dll", "ws2_32.dll"]


def test_slots_by_category_api(revshell_layout):
    apis = revshell_layout.slots_by_category("api")
    names = [s.name for s in apis]
    assert names == [
        "CreateProcessA", "LoadLibraryA", "WSAStartup", "WSASocketA", "connect",
    ]


# ---------------------------------------------------------------------------
# No overlap
# ---------------------------------------------------------------------------

def test_no_slot_overlap(revshell_layout):
    all_slots = revshell_layout.all_slots()
    # Each slot occupies addresses [ebp-offset, ebp-offset+size-1].
    # In ebp-distance terms: [offset-size+1, offset].
    for i, a in enumerate(all_slots):
        a_lo = a.offset - a.size + 1
        a_hi = a.offset
        for b in all_slots[i + 1:]:
            b_lo = b.offset - b.size + 1
            b_hi = b.offset
            assert not (a_lo <= b_hi and b_lo <= a_hi), (
                f"Slot '{a.name}' [{a_lo:#x}..{a_hi:#x}] overlaps "
                f"'{b.name}' [{b_lo:#x}..{b_hi:#x}]"
            )


def test_struct_zone_does_not_overlap_api_zone(revshell_layout):
    api_slots = revshell_layout.slots_by_category("api")
    var_slots = revshell_layout.slots_by_category("variable")
    struct_slots = revshell_layout.slots_by_category("structure")
    if (api_slots or var_slots) and struct_slots:
        all_small = api_slots + var_slots
        highest_small_addr = max(s.offset for s in all_small)
        lowest_struct_addr = min(s.offset - s.size + 1 for s in struct_slots)
        assert highest_small_addr < lowest_struct_addr, (
            f"API/variable zone (up to 0x{highest_small_addr:x}) overlaps "
            f"struct zone (from 0x{lowest_struct_addr:x})"
        )


# ---------------------------------------------------------------------------
# ebp_ref format
# ---------------------------------------------------------------------------

def test_ebp_ref_format(revshell_layout):
    assert revshell_layout.slot("CreateProcessA").ebp_ref == "[ebp-0x28]"
    assert revshell_layout.slot("kernel32.dll").ebp_ref == "[ebp-0x20]"


# ---------------------------------------------------------------------------
# String sizing
# ---------------------------------------------------------------------------

def test_string_slot_label(revshell_layout):
    slot = revshell_layout.slot("cmd")
    assert slot.category == "string"
    # "cmd.exe" = 7 chars + 1 null = 8 bytes -> padded to 8 (already aligned)
    assert slot.size == 8


def test_string_slot_follows_struct_zone(revshell_layout):
    struct_slots = revshell_layout.slots_by_category("structure")
    string_slots = revshell_layout.slots_by_category("string")
    if struct_slots and string_slots:
        highest_struct_addr = max(s.offset for s in struct_slots)
        lowest_string_addr = min(s.offset - s.size + 1 for s in string_slots)
        assert highest_struct_addr < lowest_string_addr


# ---------------------------------------------------------------------------
# Unknown slot raises
# ---------------------------------------------------------------------------

def test_unknown_slot_raises(revshell_layout):
    with pytest.raises(KeyError):
        revshell_layout.slot("NotARealSlot")


# ---------------------------------------------------------------------------
# Minimal (calc) manifest
# ---------------------------------------------------------------------------

def test_calc_layout_minimal(calc_layout):
    # calc.yaml has only WinExec, ExitProcess (both kernel32)
    assert calc_layout.slot("kernel32.dll").offset == 0x20
    # No ws2_32 module base
    with pytest.raises(KeyError):
        calc_layout.slot("ws2_32.dll")
    assert calc_layout.slot("WinExec").offset == 0x24
    assert calc_layout.slot("ExitProcess").offset == 0x28
    # No WSA structs
    with pytest.raises(KeyError):
        calc_layout.slot("WSADATA")


def test_calc_layout_only_one_module_base(calc_layout):
    bases = calc_layout.slots_by_category("module_base")
    assert len(bases) == 1
    assert bases[0].name == "kernel32.dll"


# ---------------------------------------------------------------------------
# Invariant tests - run against every manifest
# ---------------------------------------------------------------------------


def _addr_range(slot):
    """Return (lo, hi) in ebp-distance terms for a slot's address footprint."""
    return (slot.offset - slot.size + 1, slot.offset)


def test_invariant_no_address_overlap(any_layout):
    """No two slots may occupy the same byte in the stack frame."""
    slots = any_layout.all_slots()
    for i, a in enumerate(slots):
        a_lo, a_hi = _addr_range(a)
        for b in slots[i + 1:]:
            b_lo, b_hi = _addr_range(b)
            assert not (a_lo <= b_hi and b_lo <= a_hi), (
                f"'{a.name}' [{a_lo:#x}..{a_hi:#x}] overlaps "
                f"'{b.name}' [{b_lo:#x}..{b_hi:#x}]"
            )


def test_invariant_all_slots_within_frame(any_layout):
    """Every slot must fit inside the dynamically computed frame."""
    frame = any_layout.frame_size
    for s in any_layout.all_slots():
        assert s.offset <= frame, (
            f"'{s.name}' offset 0x{s.offset:x} exceeds frame size 0x{frame:x}"
        )
        lo, _ = _addr_range(s)
        assert lo >= 0, (
            f"'{s.name}' extends past ebp (lowest distance {lo:#x})"
        )


def test_invariant_positive_offset_writes_stay_in_bounds(any_layout):
    """For multi-byte slots, writing at [base+0..base+size-1] must not
    reach into any other slot's territory."""
    slots = any_layout.all_slots()
    for s in slots:
        if s.size <= 4:
            continue
        s_lo, s_hi = _addr_range(s)
        for other in slots:
            if other is s:
                continue
            o_lo, o_hi = _addr_range(other)
            assert not (s_lo <= o_hi and o_lo <= s_hi), (
                f"'{s.name}' writes [{s_lo:#x}..{s_hi:#x}] collide with "
                f"'{other.name}' [{o_lo:#x}..{o_hi:#x}]"
            )


def test_invariant_api_slots_below_struct_zone(any_layout):
    """API/variable/module_base slots must not intersect structure or string slots."""
    from emitera.stack_alloc import STRUCT_ZONE_START
    small_cats = {"module_base", "api", "variable"}
    for s in any_layout.all_slots():
        if s.category in small_cats:
            _, hi = _addr_range(s)
            assert hi < STRUCT_ZONE_START, (
                f"'{s.name}' (category={s.category}) at offset 0x{s.offset:x} "
                f"reaches into struct zone (>= 0x{STRUCT_ZONE_START:x})"
            )


def test_invariant_slots_4byte_aligned(any_layout):
    """Every slot base address must be 4-byte aligned."""
    for s in any_layout.all_slots():
        assert s.offset % 4 == 0, (
            f"'{s.name}' offset 0x{s.offset:x} is not 4-byte aligned"
        )
