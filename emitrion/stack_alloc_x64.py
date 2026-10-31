"""x64 stack slot allocator for the shellcode emitter.

Assigns RSP-relative stack offsets for x64 shellcode. Unlike x86 which uses
EBP-relative addressing with a frame pointer, x64 shellcode uses RSP-relative
addressing with a fixed frame (RSP does not move after the prologue).

Layout (stack grows downward, RSP at bottom):

    [entry RSP]
    [return addr]   <- RSP on entry (misaligned by 8 from 16-byte boundary)
    [saved RBP]     <- optional, for debugging
    [... locals ...]
    [... shadow space for deepest call ...]
    [RSP after sub]  <- 16-byte aligned

All offsets are positive from RSP (upward). The allocator produces a frame
where RSP is subtracted once in the prologue.

Zones (from RSP upward):
  Zone 0: Shadow space + extra stack args for the deepest API call (32+ bytes)
  Zone 1: Module base pointers (8 bytes each)
  Zone 2: API function pointers (8 bytes each)
  Zone 3: Variables (8 bytes each)
  Zone 4: Structures (natural alignment, x64 layout)
  Zone 5: Strings (8-byte aligned)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .api_database import (
    API_DATABASE,
    MODULE_LOAD_ORDER,
    STRUCT_DATABASE,
    STRUCT_DATABASE_X64,
)
from .schema import Manifest


def _ceil8(n: int) -> int:
    return (n + 7) & ~7


def _ceil16(n: int) -> int:
    return (n + 15) & ~15


SHADOW_SPACE = 0x20

MODULE_BASE_START_X64 = 0x40

STRUCT_ZONE_START_X64 = 0x100


@dataclass(frozen=True)
class SlotX64:
    name: str
    offset: int
    size: int
    category: Literal["shadow", "module_base", "api", "variable", "structure", "string"]

    @property
    def rsp_ref(self) -> str:
        return f"[rsp+0x{self.offset:02x}]"


class StackLayoutX64:
    """Immutable mapping from slot names to SlotX64 objects.

    All offsets are positive, relative to RSP after the prologue sub.
    """

    def __init__(self, slots: list[SlotX64], frame_size: int) -> None:
        self._slots: list[SlotX64] = list(slots)
        self._frame_size = frame_size
        self._by_name: dict[str, SlotX64] = {}
        for slot in self._slots:
            if slot.name in self._by_name:
                raise ValueError(
                    f"Duplicate slot name '{slot.name}' detected during x64 layout construction."
                )
            self._by_name[slot.name] = slot

    def slot(self, name: str) -> SlotX64:
        if name not in self._by_name:
            raise KeyError(f"No slot named '{name}' in StackLayoutX64.")
        return self._by_name[name]

    def slots_by_category(self, category: str) -> list[SlotX64]:
        return [s for s in self._slots if s.category == category]

    def all_slots(self) -> list[SlotX64]:
        return list(self._slots)

    @property
    def frame_size(self) -> int:
        return self._frame_size

    @property
    def shadow_offset(self) -> int:
        return 0


class RecordingLayoutX64:
    """Dummy layout that records slot accesses for probe_slots discovery."""

    def __init__(self) -> None:
        self._accessed: list[str] = []
        self._counter = 0x200

    def slot(self, name: str) -> SlotX64:
        self._accessed.append(name)
        self._counter += 8
        return SlotX64(name=name, offset=self._counter, size=8, category="api")

    @property
    def accessed(self) -> list[str]:
        return list(self._accessed)

    @property
    def shadow_offset(self) -> int:
        return 0

    @property
    def frame_size(self) -> int:
        return 0x400


def build_layout_x64(
    manifest: Manifest,
    extra_structs: list[str] | None = None,
    max_stack_args: int = 0,
) -> StackLayoutX64:
    """Build an x64 stack layout from a manifest.

    The frame is RSP-relative. Zone 0 reserves shadow space (32 bytes minimum)
    plus room for any stack arguments beyond the 4 register args.

    Args:
        max_stack_args: maximum number of stack arguments for any single API call
                        in the workflow (args beyond the first 4). The shadow space
                        is extended to accommodate these.
    """
    slots: list[SlotX64] = []

    shadow_size = SHADOW_SPACE
    if max_stack_args > 0:
        shadow_size = max(SHADOW_SPACE, _ceil16(SHADOW_SPACE + max_stack_args * 8))

    module_order: dict[str, int] = {
        info.dll: idx for idx, info in enumerate(MODULE_LOAD_ORDER)
    }

    needed_modules: set[str] = set()
    for func_name in manifest.functions:
        record = API_DATABASE[func_name]
        dll = record.module
        if dll not in module_order:
            raise ValueError(
                f"Function '{func_name}' belongs to module '{dll}'"
                f" which has no entry in MODULE_LOAD_ORDER."
            )
        needed_modules.add(dll)

    ordered_modules = [
        info.dll for info in MODULE_LOAD_ORDER if info.dll in needed_modules
    ]

    cursor = shadow_size

    for dll in ordered_modules:
        slots.append(SlotX64(name=dll, offset=cursor, size=8, category="module_base"))
        cursor += 8

    for func_name in manifest.functions:
        slots.append(SlotX64(name=func_name, offset=cursor, size=8, category="api"))
        cursor += 8

    for var_entry in manifest.variables:
        slots.append(SlotX64(name=var_entry.name, offset=cursor, size=8, category="variable"))
        cursor += 8

    if cursor > STRUCT_ZONE_START_X64:
        raise ValueError(
            f"API/module-base zone overflow: next free offset 0x{cursor:02x}"
            f" exceeds STRUCT_ZONE_START_X64 0x{STRUCT_ZONE_START_X64:02x}."
        )

    struct_cursor = STRUCT_ZONE_START_X64

    seen_struct_names: set[str] = set()
    ordered_structs: list[str] = []
    for func_name in manifest.functions:
        for struct_name in API_DATABASE[func_name].requires_structs:
            if struct_name not in seen_struct_names:
                seen_struct_names.add(struct_name)
                ordered_structs.append(struct_name)

    for struct_name in (extra_structs or []):
        if struct_name not in seen_struct_names:
            seen_struct_names.add(struct_name)
            ordered_structs.append(struct_name)

    for struct_name in ordered_structs:
        struct_rec = STRUCT_DATABASE_X64.get(struct_name)
        if struct_rec is None:
            struct_rec = STRUCT_DATABASE.get(struct_name)
        if struct_rec is None:
            raise ValueError(f"Struct '{struct_name}' not in STRUCT_DATABASE")

        struct_cursor = _ceil8(struct_cursor)
        slots.append(
            SlotX64(
                name=struct_name,
                offset=struct_cursor,
                size=struct_rec.size,
                category="structure",
            )
        )
        struct_cursor += struct_rec.size

    string_cursor = _ceil8(struct_cursor)
    for entry in manifest.strings:
        raw_len = len(entry.value.encode("ascii")) + 1
        slot_size = _ceil8(raw_len)
        slots.append(
            SlotX64(
                name=entry.label,
                offset=string_cursor,
                size=slot_size,
                category="string",
            )
        )
        string_cursor += slot_size

    frame_size = _ceil16(string_cursor)

    if frame_size > 0x2000:
        raise ValueError(
            f"x64 frame size 0x{frame_size:x} exceeds two pages (0x2000). "
            f"Stack probing is not yet implemented."
        )

    return StackLayoutX64(slots, frame_size)
