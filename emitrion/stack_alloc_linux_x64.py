"""Linux x64 stack slot allocator for the shellcode emitter.

Assigns RSP-relative stack offsets for Linux x64 shellcode. Much simpler
than the Windows x64 allocator: no shadow space, no module base pointers,
no API function pointer slots, no export context reserve.

Layout (stack grows downward, RSP at bottom):

    [entry RSP]
    [... locals ...]
    [RSP after sub]  <- 16-byte aligned

All offsets are positive from RSP (upward). The allocator produces a frame
where RSP is subtracted once in the prologue.

Zones (from RSP upward):
  Zone 0: Variables (8 bytes each)
  Zone 1: Structures (8-byte aligned)
  Zone 2: Strings (8-byte aligned)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


def _ceil8(n: int) -> int:
    return (n + 7) & ~7


def _ceil16(n: int) -> int:
    return (n + 15) & ~15


STRUCT_ZONE_START_LINUX_X64 = 0x80


@dataclass(frozen=True)
class SlotLinuxX64:
    name: str
    offset: int
    size: int
    category: Literal["variable", "structure", "string"]

    @property
    def rsp_ref(self) -> str:
        return f"[rsp+0x{self.offset:02x}]"


class StackLayoutLinuxX64:
    """Immutable mapping from slot names to SlotLinuxX64 objects.

    All offsets are positive, relative to RSP after the prologue sub.
    """

    def __init__(self, slots: list[SlotLinuxX64], frame_size: int) -> None:
        self._slots: list[SlotLinuxX64] = list(slots)
        self._frame_size = frame_size
        self._by_name: dict[str, SlotLinuxX64] = {}
        for slot in self._slots:
            if slot.name in self._by_name:
                raise ValueError(
                    f"Duplicate slot name '{slot.name}' in Linux x64 layout."
                )
            self._by_name[slot.name] = slot

    def slot(self, name: str) -> SlotLinuxX64:
        if name not in self._by_name:
            raise KeyError(f"No slot named '{name}' in StackLayoutLinuxX64.")
        return self._by_name[name]

    def slots_by_category(self, category: str) -> list[SlotLinuxX64]:
        return [s for s in self._slots if s.category == category]

    def all_slots(self) -> list[SlotLinuxX64]:
        return list(self._slots)

    @property
    def frame_size(self) -> int:
        return self._frame_size


class RecordingLayoutLinuxX64:
    """Dummy layout that records slot accesses for probe_slots discovery."""

    def __init__(self) -> None:
        self._accessed: list[str] = []
        self._counter = 0x100

    def slot(self, name: str) -> SlotLinuxX64:
        self._accessed.append(name)
        self._counter += 8
        return SlotLinuxX64(name=name, offset=self._counter, size=8, category="variable")

    @property
    def accessed(self) -> list[str]:
        return list(self._accessed)

    @property
    def frame_size(self) -> int:
        return 0x400


@dataclass
class LinuxManifestInfo:
    """Lightweight manifest-like input for the Linux stack allocator."""
    variables: list[str]
    structs: list[tuple[str, int]]
    strings: list[tuple[str, int]]


def build_layout_linux_x64(
    info: LinuxManifestInfo,
) -> StackLayoutLinuxX64:
    """Build a Linux x64 stack layout.

    The frame is RSP-relative. No shadow space, no API resolution slots.
    """
    slots: list[SlotLinuxX64] = []
    cursor = 0

    for var_name in info.variables:
        slots.append(SlotLinuxX64(name=var_name, offset=cursor, size=8, category="variable"))
        cursor += 8

    if cursor > STRUCT_ZONE_START_LINUX_X64:
        raise ValueError(
            f"Variable zone overflow: next free offset 0x{cursor:02x}"
            f" exceeds STRUCT_ZONE_START_LINUX_X64 0x{STRUCT_ZONE_START_LINUX_X64:02x}."
        )

    struct_cursor = STRUCT_ZONE_START_LINUX_X64 if info.structs else cursor

    for struct_name, struct_size in info.structs:
        struct_cursor = _ceil8(struct_cursor)
        slots.append(SlotLinuxX64(
            name=struct_name,
            offset=struct_cursor,
            size=struct_size,
            category="structure",
        ))
        struct_cursor += struct_size

    string_cursor = _ceil8(struct_cursor)
    for label, raw_len in info.strings:
        slot_size = _ceil8(raw_len)
        slots.append(SlotLinuxX64(
            name=label,
            offset=string_cursor,
            size=slot_size,
            category="string",
        ))
        string_cursor += slot_size

    frame_size = _ceil16(string_cursor) if string_cursor > 0 else _ceil16(struct_cursor)
    if frame_size == 0:
        frame_size = 16

    if frame_size > 0x2000:
        raise ValueError(
            f"Linux x64 frame size 0x{frame_size:x} exceeds two pages (0x2000). "
            f"Stack probing is not yet implemented."
        )

    return StackLayoutLinuxX64(slots, frame_size)
