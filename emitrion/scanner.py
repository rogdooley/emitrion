"""Post-assembly bad character scanner.

Inspects assembled machine code for bytes that violate the manifest's
badchar set.  Operates on the final byte stream, not assembly text.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Violation:
    offset: int
    value: int

    def __str__(self) -> str:
        return f"0x{self.offset:04x}: 0x{self.value:02x}"


@dataclass
class ScanResult:
    payload_size: int
    badchars: set[int]
    violations: list[Violation] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return len(self.violations) == 0

    def summary(self) -> str:
        lines = [
            f"Payload        {self.payload_size} bytes",
            f"Forbidden      {' '.join(f'{b:02x}' for b in sorted(self.badchars))}",
            f"Violations     {len(self.violations)}",
        ]
        if self.violations:
            lines.append("")
            for v in self.violations:
                lines.append(f"  {v}")
        return "\n".join(lines)


def scan(payload: bytes, badchars: set[int]) -> ScanResult:
    """Scan *payload* for any byte in *badchars*.

    Returns a ScanResult with every offending offset and value.
    """
    violations = [
        Violation(offset=i, value=b)
        for i, b in enumerate(payload)
        if b in badchars
    ]
    return ScanResult(
        payload_size=len(payload),
        badchars=badchars,
        violations=violations,
    )
