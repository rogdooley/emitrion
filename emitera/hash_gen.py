"""ROR13 export hash computation for Windows x86 shellcode."""
from __future__ import annotations


def ror13(name: str) -> int:
    """Compute ROR13 export hash for an ASCII function name."""
    h = 0
    for ch in name:
        h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
        h = (h + ord(ch)) & 0xFFFFFFFF
    return h


def compute_hashes(names: list[str]) -> dict[str, int]:
    """Return {name: hash} for every name in the list."""
    return {name: ror13(name) for name in names}
