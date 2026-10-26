"""String construction emitter - wraps strings.py with layout awareness.

Option B: for non-push methods, emits `lea edi, [slot]` then delegates to
strings.py emitters. For push method, emits the push sequence only (ESP = pointer).
"""
from __future__ import annotations

from emitrion.strings import emit_mov, emit_push, emit_shiftor, emit_xor

from .encode import safe_lea
from .schema import Manifest, StringEntry
from .stack_alloc import StackLayout


def emit_string(entry: StringEntry, layout: StackLayout, badchars: set[int]) -> str:
    """Emit assembly to construct a single string in the frame.

    For method 'push':
        Emits the push sequence from strings.py. ESP points to the string
        after the sequence. The slot is for documentation only.

    For 'mov', 'shiftor', 'xor':
        Emits `lea edi, [slot]` then delegates to strings.py with dest='edi'.
        The result is a null-terminated string at the pre-allocated slot address.
    """
    slot = layout.slot(entry.label)
    header = f'; --- {entry.label}: "{entry.value}" ({entry.method}) ---'

    if entry.method == "push":
        result = emit_push(entry.value, badchars=badchars)
        return f"{header}\n{result.asm}\n"

    lea_lines = safe_lea("edi", "ebp", -slot.offset, badchars)

    if entry.method == "mov":
        result = emit_mov(entry.value, dest="edi", badchars=badchars)
    elif entry.method == "shiftor":
        result = emit_shiftor(entry.value, dest="edi", badchars=badchars)
    elif entry.method == "xor":
        result = emit_xor(entry.value, dest="edi", badchars=badchars)
    else:
        raise ValueError(f"Unknown string method: {entry.method!r}")

    return f"{header}\n" + "\n".join(lea_lines) + f"\n{result.asm}\n"


def emit_all_strings(
    manifest: Manifest,
    layout: StackLayout,
    skip_labels: set[str] | None = None,
) -> str:
    """Emit string construction code for all manifest strings.

    skip_labels: labels to omit (e.g. DLL names handled in module-loading blocks).
    """
    skip = skip_labels or set()
    parts = []
    for entry in manifest.strings:
        if entry.label in skip:
            continue
        parts.append(emit_string(entry, layout, manifest.badchars))
    return "\n".join(parts)
