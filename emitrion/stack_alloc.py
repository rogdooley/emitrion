"""Stack slot allocator for the shellcode emitter.

Assigns stack offsets (relative to ebp) to module bases, API function pointers,
structures, and strings described in a Manifest.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .api_database import API_DATABASE, MODULE_LOAD_ORDER, STRUCT_DATABASE
from .schema import Manifest

# Offset at which module-base slots begin (after export-context reserved zone 0x04-0x18).
MODULE_BASE_START = 0x20

# Hard constant: struct zone always starts here regardless of how many API/module slots exist.
# Intentional gap allows adding API slots without shifting struct offsets.
STRUCT_ZONE_START = 0x80


def _ceil4(n: int) -> int:
    """Round n up to the nearest multiple of 4."""
    return (n + 3) & ~3


@dataclass(frozen=True)
class Slot:
    name: str
    offset: int       # positive integer, e.g. 0x28 for [ebp-0x28]
    size: int         # bytes
    category: Literal["module_base", "api", "variable", "structure", "string"]

    @property
    def ebp_ref(self) -> str:
        """Return '[ebp-0xNN]' string for use in assembly or documentation."""
        return f"[ebp-{hex(self.offset)}]"


class StackLayout:
    """Immutable mapping from slot names to Slot objects."""

    def __init__(self, slots: list[Slot]) -> None:
        self._slots: list[Slot] = list(slots)
        self._by_name: dict[str, Slot] = {}
        for slot in self._slots:
            if slot.name in self._by_name:
                raise ValueError(
                    f"Duplicate slot name '{slot.name}' detected during layout construction."
                )
            self._by_name[slot.name] = slot

    def slot(self, name: str) -> Slot:
        """Return the Slot for the given name.

        Raises KeyError with a clear message if name is not in the layout.
        Never returns None.
        """
        if name not in self._by_name:
            raise KeyError(f"No slot named '{name}' in StackLayout.")
        return self._by_name[name]

    def slots_by_category(self, category: str) -> list[Slot]:
        """Return all slots of the given category, in allocation order.

        Returns empty list (not error) for a valid category with no slots.
        """
        return [s for s in self._slots if s.category == category]

    def all_slots(self) -> list[Slot]:
        """All slots in allocation order: module_base -> api -> variable -> structure -> string."""
        return list(self._slots)

    @property
    def frame_size(self) -> int:
        """Total frame bytes needed, rounded up to next 0x100 boundary."""
        if not self._slots:
            return 0x100
        high_water = max(s.offset for s in self._slots)
        return ((high_water + 0xFF) & ~0xFF)


class RecordingLayout:
    """Dummy layout that records every slot() call without needing a real manifest.

    Used by PayloadTemplate.probe_slots() to discover which slot names
    a template's emit() actually references.  Returns a valid Slot
    (with a placeholder offset) for any name, so emit() runs to completion.
    """

    def __init__(self) -> None:
        self._accessed: list[str] = []
        self._counter = 0x100

    def slot(self, name: str) -> Slot:
        self._accessed.append(name)
        self._counter += 4
        return Slot(name=name, offset=self._counter, size=4, category="api")

    @property
    def accessed(self) -> list[str]:
        return list(self._accessed)


def build_layout(manifest: Manifest, extra_structs: list[str] | None = None) -> StackLayout:
    """Given a Manifest, produce a fully-populated StackLayout.

    Allocation zones:
      Zone 2 - module_base  starts at MODULE_BASE_START (0x20)
      Zone 3 - api          starts immediately after last module_base slot
      Zone 4 - structure    starts at STRUCT_ZONE_START (0x80), 4-byte aligned per slot
      Zone 5 - string       starts immediately after last structure slot, 4-byte aligned

    Raises ValueError for:
      - a function whose module is not in MODULE_LOAD_ORDER
      - API zone overflow into struct zone
      - duplicate slot names (caught in StackLayout.__init__)
    """
    slots: list[Slot] = []

    # Build fast lookup: dll name -> index in MODULE_LOAD_ORDER
    module_order: dict[str, int] = {
        info.dll: idx for idx, info in enumerate(MODULE_LOAD_ORDER)
    }

    # --- Zone 2: module_base slots ---
    # Determine which modules are needed (own at least one function in manifest)
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

    # Order needed modules by MODULE_LOAD_ORDER sequence
    ordered_modules = [
        info.dll
        for info in MODULE_LOAD_ORDER
        if info.dll in needed_modules
    ]

    cursor = MODULE_BASE_START
    for dll in ordered_modules:
        slots.append(Slot(name=dll, offset=cursor, size=4, category="module_base"))
        cursor += 4

    # --- Zone 3: api slots ---
    for func_name in manifest.functions:
        slots.append(Slot(name=func_name, offset=cursor, size=4, category="api"))
        cursor += 4

    # --- Zone 3b: variable slots (intermediate values like SOCKET handles) ---
    for var_entry in manifest.variables:
        slots.append(Slot(name=var_entry.name, offset=cursor, size=4, category="variable"))
        cursor += 4

    # Guard: API/module-base/variable zone must not overflow into struct zone
    if cursor > STRUCT_ZONE_START:
        raise ValueError(
            f"API/module-base zone overflow: next free offset 0x{cursor:02x}"
            f" exceeds STRUCT_ZONE_START 0x{STRUCT_ZONE_START:02x}."
        )

    # --- Zone 4: structure slots ---
    # Collect structs in first-seen order by scanning manifest.functions in declaration order.
    # Forward lookup: API_DATABASE[func].requires_structs drives discovery,
    # not an inverted scan of STRUCT_DATABASE.required_by.
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

    struct_cursor = STRUCT_ZONE_START
    for struct_name in ordered_structs:
        struct_rec = STRUCT_DATABASE[struct_name]
        struct_cursor = _ceil4(struct_cursor)
        struct_cursor += struct_rec.size
        slots.append(
            Slot(name=struct_name, offset=struct_cursor, size=struct_rec.size, category="structure")
        )

    # --- Zone 5: string slots ---
    string_cursor = _ceil4(struct_cursor)
    for entry in manifest.strings:
        raw_len = len(entry.value.encode("ascii")) + 1  # +1 for null terminator
        slot_size = _ceil4(raw_len)
        string_cursor += slot_size
        slots.append(
            Slot(name=entry.label, offset=string_cursor, size=slot_size, category="string")
        )

    layout = StackLayout(slots)
    if layout.frame_size > 0x1000:
        raise ValueError(
            f"Frame size 0x{layout.frame_size:x} exceeds one page (0x1000). "
            f"Windows commits stack pages via a guard page that must be touched "
            f"sequentially; a single sub esp,N that skips past the guard causes "
            f"an access violation. Stack probing is not yet implemented -- "
            f"reduce string lengths or split the manifest."
        )
    return layout
