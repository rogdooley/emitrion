"""Post-assembly bad character scanner and byte frequency analyzer.

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


# ---------------------------------------------------------------------------
# Byte frequency analyzer
# ---------------------------------------------------------------------------

@dataclass
class FrequencyResult:
    payload_size: int
    counts: list[int]
    badchars: set[int]

    @property
    def absent(self) -> list[int]:
        """Byte values that never appear in the payload."""
        return [b for b in range(256) if self.counts[b] == 0]

    @property
    def unnecessary_badchars(self) -> list[int]:
        """Badchars that never appear, so banning them costs encoder effort for no gain."""
        return [b for b in sorted(self.badchars) if self.counts[b] == 0]

    @property
    def present_badchars(self) -> list[int]:
        """Badchars that actually appear and must be encoded away."""
        return [b for b in sorted(self.badchars) if self.counts[b] > 0]

    def top(self, n: int = 16) -> list[tuple[int, int]]:
        """Most frequent byte values as (value, count) pairs."""
        pairs = [(b, self.counts[b]) for b in range(256) if self.counts[b] > 0]
        pairs.sort(key=lambda p: p[1], reverse=True)
        return pairs[:n]

    def histogram(self, columns: int = 64, badchars_only: bool = False) -> str:
        """Render a text histogram of byte frequencies.

        Each row is one byte value. The bar is scaled to fit *columns*
        characters. Badchar rows are marked with a '!' prefix. Absent
        bytes are omitted unless *badchars_only* is True, in which case
        only badchar bytes are shown (including absent ones, so you can
        see which badchars the payload actually contains).
        """
        show_bytes = sorted(self.badchars) if badchars_only else range(256)
        visible_counts = [self.counts[b] for b in show_bytes if self.counts[b] > 0]
        max_count = max(visible_counts) if visible_counts else 1
        lines: list[str] = []
        lines.append(f"Payload: {self.payload_size} bytes")
        lines.append(f"Distinct values: {sum(1 for c in self.counts if c > 0)}/256")
        if self.badchars:
            lines.append(
                f"Badchars: {' '.join(f'{b:02x}' for b in sorted(self.badchars))}"
            )
            present = self.present_badchars
            lines.append(
                f"Present: {len(present)}/{len(self.badchars)} "
                f"({', '.join(f'{b:02x}' for b in present) if present else 'none'})"
            )
            if self.unnecessary_badchars:
                lines.append(
                    f"Unnecessary (never appear): "
                    f"{' '.join(f'{b:02x}' for b in self.unnecessary_badchars)}"
                )
        lines.append("")
        lines.append(f"{'Byte':>4}  {'Count':>5}  {'%':>5}  Bar")
        lines.append(f"{'----':>4}  {'-----':>5}  {'-----':>5}  " + "-" * columns)

        for b in show_bytes:
            count = self.counts[b]
            if count == 0 and not badchars_only:
                continue
            pct = 100.0 * count / self.payload_size if self.payload_size > 0 else 0.0
            bar_len = max(1, round(columns * count / max_count)) if count > 0 else 0
            marker = "!" if b in self.badchars else " "
            bar_char = "#" if b in self.badchars else "="
            bar = bar_char * bar_len if count > 0 else "-"
            lines.append(
                f"{marker}{b:02x}   {count:5d}  {pct:5.1f}  {bar}"
            )
        return "\n".join(lines)


    def badchars_histogram(self, columns: int = 64) -> str:
        """Shorthand for histogram(badchars_only=True)."""
        return self.histogram(columns=columns, badchars_only=True)


def frequency(payload: bytes, badchars: set[int] | None = None) -> FrequencyResult:
    """Count the frequency of every byte value in *payload*."""
    counts = [0] * 256
    for b in payload:
        counts[b] += 1
    return FrequencyResult(
        payload_size=len(payload),
        counts=counts,
        badchars=badchars or set(),
    )


def main() -> None:
    """CLI: analyze byte frequency of a binary file."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Byte frequency analyzer for shellcode",
    )
    parser.add_argument("file", help="Path to binary file (e.g. shellcode.bin)")
    parser.add_argument(
        "--badchars", default=None, metavar="HEX,...",
        help="Comma-separated hex bytes to highlight (e.g. 00,0a,0d)",
    )
    parser.add_argument(
        "--top", type=int, default=0, metavar="N",
        help="Show only the top N most frequent bytes",
    )
    parser.add_argument(
        "--badchars-only", action="store_true",
        help="Show only badchar byte frequencies (requires --badchars)",
    )
    parser.add_argument(
        "--columns", type=int, default=50,
        help="Histogram bar width (default 50)",
    )
    args = parser.parse_args()

    try:
        with open(args.file, "rb") as f:
            payload = f.read()
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    if not payload:
        print("[!] File is empty.", file=sys.stderr)
        sys.exit(1)

    bc: set[int] = set()
    if args.badchars:
        for token in args.badchars.split(","):
            bc.add(int(token.strip(), 16))

    result = frequency(payload, bc)

    if args.top > 0:
        print(f"Payload: {result.payload_size} bytes")
        print(f"Top {args.top} byte values:")
        print()
        for value, count in result.top(args.top):
            pct = 100.0 * count / result.payload_size
            marker = " !" if value in bc else "  "
            print(f"  0x{value:02x}  {count:5d}  ({pct:5.1f}%){marker}")
        if bc:
            print()
            if result.unnecessary_badchars:
                print(
                    f"Unnecessary badchars (never appear): "
                    f"{' '.join(f'0x{b:02x}' for b in result.unnecessary_badchars)}"
                )
            if result.present_badchars:
                print(
                    f"Must encode: "
                    f"{' '.join(f'0x{b:02x}' for b in result.present_badchars)}"
                )
    else:
        print(result.histogram(columns=args.columns, badchars_only=args.badchars_only))


if __name__ == "__main__":
    main()
