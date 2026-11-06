"""PE-level fixtures for forwarded export detection.

Builds minimal synthetic PE export directories in memory and runs the
resolver's forwarder-check algorithm (same logic as the generated assembly)
against them. Proves that the detection correctly distinguishes forwarded
exports (RVA inside the export directory) from ordinary code exports.

PE export directory layout (IMAGE_EXPORT_DIRECTORY, 40 bytes):
  +0x00  Characteristics
  +0x04  TimeDateStamp
  +0x08  MajorVersion / MinorVersion
  +0x0C  Name RVA
  +0x10  Base
  +0x14  NumberOfFunctions
  +0x18  NumberOfNames
  +0x1C  AddressOfFunctions RVA
  +0x20  AddressOfNames RVA
  +0x24  AddressOfNameOrdinals RVA

A forwarded export: its entry in AddressOfFunctions is an RVA that falls
within [export_dir_rva, export_dir_rva + export_dir_size). The bytes at
that RVA are an ASCII string like "NTDLL.RtlExitUserProcess", not code.
"""
from __future__ import annotations

import struct

import pytest


def _is_forwarded(func_rva: int, export_dir_rva: int, export_dir_size: int) -> bool:
    """Python implementation of the assembly forwarder-check algorithm.

    Mirrors the logic in both x86 and x64 resolve_matched_export:
      if func_rva >= export_dir_rva and func_rva < export_dir_rva + export_dir_size:
          forwarded (int3)
      else:
          normal (module_base + func_rva)
    """
    return export_dir_rva <= func_rva < export_dir_rva + export_dir_size


class PEFixture:
    """Minimal synthetic PE with an export directory for testing."""

    def __init__(
        self,
        *,
        image_base: int = 0x10000000,
        export_dir_rva: int = 0x1000,
        export_dir_size: int = 0x200,
        functions: list[tuple[str, int, bool]],
    ) -> None:
        """Build a synthetic PE export directory.

        Args:
            image_base: Simulated module base address.
            export_dir_rva: RVA of the export directory.
            export_dir_size: Size of the export directory (includes the
                directory structure, name/ordinal/address arrays, and any
                forwarder strings embedded within it).
            functions: List of (name, rva, is_forwarded) tuples. Forwarded
                functions have their RVA inside [export_dir_rva, export_dir_rva
                + export_dir_size).  The caller is responsible for making the
                RVAs consistent with the export dir range.
        """
        self.image_base = image_base
        self.export_dir_rva = export_dir_rva
        self.export_dir_size = export_dir_size
        self.functions = functions

    def verify_consistency(self) -> None:
        """Assert that each function's RVA matches its declared forwarding status."""
        for name, rva, declared_forwarded in self.functions:
            detected = _is_forwarded(rva, self.export_dir_rva, self.export_dir_size)
            assert detected == declared_forwarded, (
                f"{name}: RVA 0x{rva:x} declared_forwarded={declared_forwarded} "
                f"but detection says {'forwarded' if detected else 'not forwarded'} "
                f"(export dir 0x{self.export_dir_rva:x}-0x{self.export_dir_rva + self.export_dir_size:x})"
            )

    def build_pe_bytes(self) -> tuple[bytearray, int]:
        """Build a minimal PE image as a bytearray.

        Returns (image_bytes, pe_header_offset). The image contains a valid
        enough PE header for the resolver to read e_lfanew, the export
        directory data directory entry, and the AddressOfFunctions array.
        """
        pe_offset = 0x80
        num_funcs = len(self.functions)

        image = bytearray(self.export_dir_rva + self.export_dir_size + 0x100)

        # DOS header: e_lfanew at offset 0x3C
        image[0:2] = b"MZ"
        struct.pack_into("<I", image, 0x3C, pe_offset)

        # PE signature
        image[pe_offset:pe_offset + 4] = b"PE\x00\x00"

        # For PE32: export dir RVA at PE+0x78, size at PE+0x7C
        # For PE32+: export dir RVA at PE+0x88, size at PE+0x8C
        # Write both so the fixture works for either architecture test.
        struct.pack_into("<I", image, pe_offset + 0x78, self.export_dir_rva)
        struct.pack_into("<I", image, pe_offset + 0x7C, self.export_dir_size)
        struct.pack_into("<I", image, pe_offset + 0x88, self.export_dir_rva)
        struct.pack_into("<I", image, pe_offset + 0x8C, self.export_dir_size)

        # Export directory at export_dir_rva
        ed = self.export_dir_rva
        struct.pack_into("<I", image, ed + 0x14, num_funcs)
        struct.pack_into("<I", image, ed + 0x18, num_funcs)

        # AddressOfFunctions array immediately after the 40-byte directory
        addr_of_functions_rva = ed + 40
        struct.pack_into("<I", image, ed + 0x1C, addr_of_functions_rva)

        for i, (name, rva, _) in enumerate(self.functions):
            struct.pack_into("<I", image, addr_of_functions_rva + i * 4, rva)

        return image, pe_offset


# ---------------------------------------------------------------------------
# Fixtures: realistic PE export scenarios
# ---------------------------------------------------------------------------

KERNEL32_LIKE = PEFixture(
    image_base=0x76000000,
    export_dir_rva=0x8_0000,
    export_dir_size=0x1_0000,
    functions=[
        ("CreateProcessA",    0x2_1000, False),
        ("LoadLibraryA",      0x1_8000, False),
        ("GetProcAddress",    0x1_A000, False),
        ("ExitProcess",       0x3_0000, False),
        ("VirtualAlloc",      0x4_2000, False),
    ],
)

WS2_32_LIKE = PEFixture(
    image_base=0x74000000,
    export_dir_rva=0x5000,
    export_dir_size=0x800,
    functions=[
        ("WSAStartup",  0x1000, False),
        ("WSASocketA",  0x2000, False),
        ("connect",     0x3000, False),
        ("bind",        0x3500, False),
        ("listen",      0x3800, False),
        ("accept",      0x3A00, False),
    ],
)

# A module where some exports are forwarded. This is the critical test case.
# Example: kernel32!RtlExitUserProcess forwards to ntdll!RtlExitUserProcess.
# The forwarder string sits inside the export directory.
MIXED_FORWARDED = PEFixture(
    image_base=0x76000000,
    export_dir_rva=0x8_0000,
    export_dir_size=0x1_0000,
    functions=[
        ("CreateProcessA",       0x2_1000, False),   # code at 0x21000 (outside export dir)
        ("LoadLibraryA",         0x1_8000, False),   # code at 0x18000 (outside export dir)
        ("RtlExitUserProcess",   0x8_0100, True),    # forwarder at 0x80100 (inside export dir)
        ("HeapAlloc",            0x8_0200, True),     # forwarder at 0x80200 (inside export dir)
        ("VirtualAlloc",         0x4_2000, False),   # code at 0x42000 (outside export dir)
    ],
)

# Edge cases: RVA exactly at export dir boundary
BOUNDARY_CASES = PEFixture(
    image_base=0x10000000,
    export_dir_rva=0x1000,
    export_dir_size=0x200,
    functions=[
        ("before_dir",    0x0FFF, False),   # one byte before export dir
        ("at_dir_start",  0x1000, True),    # exactly at export dir start
        ("inside_dir",    0x1100, True),    # middle of export dir
        ("at_dir_end",    0x11FF, True),    # last byte of export dir
        ("after_dir",     0x1200, False),   # first byte after export dir
        ("well_outside",  0x5000, False),   # clearly outside
    ],
)

# All exports forwarded (pathological but valid PE)
ALL_FORWARDED = PEFixture(
    image_base=0x10000000,
    export_dir_rva=0x2000,
    export_dir_size=0x500,
    functions=[
        ("Func1", 0x2010, True),
        ("Func2", 0x2100, True),
        ("Func3", 0x24FF, True),
    ],
)

# Zero-size export directory (degenerate, should not detect forwarders)
ZERO_SIZE_DIR = PEFixture(
    image_base=0x10000000,
    export_dir_rva=0x1000,
    export_dir_size=0,
    functions=[
        ("SomeFunc", 0x1000, False),
        ("OtherFunc", 0x2000, False),
    ],
)


class TestForwarderAlgorithm:
    """Test the Python implementation of the forwarder-check algorithm."""

    @pytest.mark.parametrize("fixture", [
        KERNEL32_LIKE, WS2_32_LIKE, MIXED_FORWARDED,
        BOUNDARY_CASES, ALL_FORWARDED, ZERO_SIZE_DIR,
    ], ids=[
        "kernel32_like", "ws2_32_like", "mixed_forwarded",
        "boundary_cases", "all_forwarded", "zero_size_dir",
    ])
    def test_fixture_consistency(self, fixture: PEFixture) -> None:
        fixture.verify_consistency()

    def test_forwarded_rva_inside_directory(self) -> None:
        assert _is_forwarded(0x8_0100, 0x8_0000, 0x1_0000)

    def test_normal_rva_outside_directory(self) -> None:
        assert not _is_forwarded(0x2_1000, 0x8_0000, 0x1_0000)

    def test_rva_at_exact_lower_bound(self) -> None:
        assert _is_forwarded(0x1000, 0x1000, 0x200)

    def test_rva_at_exact_upper_bound(self) -> None:
        """Upper bound is exclusive: RVA == dir_rva + dir_size is NOT forwarded."""
        assert not _is_forwarded(0x1200, 0x1000, 0x200)

    def test_rva_one_before_lower_bound(self) -> None:
        assert not _is_forwarded(0x0FFF, 0x1000, 0x200)

    def test_rva_one_before_upper_bound(self) -> None:
        assert _is_forwarded(0x11FF, 0x1000, 0x200)

    def test_zero_size_never_forwarded(self) -> None:
        assert not _is_forwarded(0x1000, 0x1000, 0)


class TestPEFixtureByteLevelX64:
    """Read export dir RVA/size from synthetic PE bytes using the x64 algorithm.

    Simulates what the x64 assembly does:
      mov  edx, dword ptr [rcx + 0x3c]   ; e_lfanew
      add  rdx, rcx                       ; PE header VA
      mov  esi, dword ptr [rdx + 0x88]    ; export dir RVA
      mov  edi, dword ptr [rdx + 0x8c]    ; export dir size
    """

    @pytest.mark.parametrize("fixture", [
        KERNEL32_LIKE, WS2_32_LIKE, MIXED_FORWARDED,
        BOUNDARY_CASES, ALL_FORWARDED, ZERO_SIZE_DIR,
    ], ids=[
        "kernel32_like", "ws2_32_like", "mixed_forwarded",
        "boundary_cases", "all_forwarded", "zero_size_dir",
    ])
    def test_pe_bytes_round_trip_x64(self, fixture: PEFixture) -> None:
        image, _ = fixture.build_pe_bytes()
        # Simulate resolver: read e_lfanew, then export dir entry
        e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
        pe_header = e_lfanew
        export_dir_rva = struct.unpack_from("<I", image, pe_header + 0x88)[0]
        export_dir_size = struct.unpack_from("<I", image, pe_header + 0x8C)[0]

        assert export_dir_rva == fixture.export_dir_rva
        assert export_dir_size == fixture.export_dir_size

        # Now simulate AddressOfFunctions lookup
        addr_of_funcs_rva = struct.unpack_from("<I", image, export_dir_rva + 0x1C)[0]
        for i, (name, expected_rva, expected_forwarded) in enumerate(fixture.functions):
            func_rva = struct.unpack_from("<I", image, addr_of_funcs_rva + i * 4)[0]
            assert func_rva == expected_rva, f"{name}: expected RVA 0x{expected_rva:x}, got 0x{func_rva:x}"
            detected = _is_forwarded(func_rva, export_dir_rva, export_dir_size)
            assert detected == expected_forwarded, (
                f"{name}: RVA 0x{func_rva:x} expected_forwarded={expected_forwarded}, "
                f"detected={detected}"
            )


class TestPEFixtureByteLevelX86:
    """Same as x64 but reads PE+0x78 and PE+0x7C (PE32 offsets)."""

    @pytest.mark.parametrize("fixture", [
        KERNEL32_LIKE, WS2_32_LIKE, MIXED_FORWARDED,
        BOUNDARY_CASES, ALL_FORWARDED, ZERO_SIZE_DIR,
    ], ids=[
        "kernel32_like", "ws2_32_like", "mixed_forwarded",
        "boundary_cases", "all_forwarded", "zero_size_dir",
    ])
    def test_pe_bytes_round_trip_x86(self, fixture: PEFixture) -> None:
        image, _ = fixture.build_pe_bytes()
        e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
        pe_header = e_lfanew
        export_dir_rva = struct.unpack_from("<I", image, pe_header + 0x78)[0]
        export_dir_size = struct.unpack_from("<I", image, pe_header + 0x7C)[0]

        assert export_dir_rva == fixture.export_dir_rva
        assert export_dir_size == fixture.export_dir_size

        addr_of_funcs_rva = struct.unpack_from("<I", image, export_dir_rva + 0x1C)[0]
        for i, (name, expected_rva, expected_forwarded) in enumerate(fixture.functions):
            func_rva = struct.unpack_from("<I", image, addr_of_funcs_rva + i * 4)[0]
            assert func_rva == expected_rva
            detected = _is_forwarded(func_rva, export_dir_rva, export_dir_size)
            assert detected == expected_forwarded, f"{name}: detection mismatch"


class TestAssemblyMatchesPEAlgorithm:
    """Verify the generated assembly implements the same algorithm as the PE fixtures."""

    def test_x64_check_reads_correct_pe_offsets(self) -> None:
        """x64 resolver reads PE+0x88 (export dir RVA) and PE+0x8C (size)."""
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        block = _extract_between(stubs, "resolve_matched_export:", "resolve_export_by_hash:")

        assert "[rdx + 0x88]" in block, "missing export dir RVA read (PE+0x88)"
        assert "[rdx + 0x8c]" in block, "missing export dir size read (PE+0x8C)"
        assert "[rcx + 0x3c]" in block, "missing e_lfanew read"

    def test_x86_check_reads_correct_pe_offsets(self) -> None:
        """x86 resolver reads PE+0x78 (export dir RVA) and PE+0x7C (size)."""
        from emitrion.build import _emit_framework_stubs_part2
        stubs = _emit_framework_stubs_part2(set())
        block = _extract_between(stubs, "resolve_matched_export:", "resolve_export_by_hash:")

        # safe_mem_load may encode the offset, so check for the label and structure
        assert "not_forwarded:" in block
        assert "forwarded_export:" in block
        # With no badchars, the offsets should appear literally
        assert "0x78" in block, "missing export dir RVA read (PE+0x78)"
        assert "0x7c" in block, "missing export dir size read (PE+0x7C)"
        assert "0x3c" in block, "missing e_lfanew read"

    def test_x64_lower_bound_is_inclusive(self) -> None:
        """cmp eax, esi; jb not_forwarded means: if func_rva < dir_rva, skip."""
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        block = _extract_between(stubs, "resolve_matched_export:", "resolve_export_by_hash:")
        lines = [l.strip() for l in block.splitlines()]
        # Find cmp/jb pair for lower bound
        for i, line in enumerate(lines):
            if line == "cmp  eax, esi" and i + 1 < len(lines):
                assert lines[i + 1] == "jb   not_forwarded"
                return
        pytest.fail("lower bound cmp/jb pair not found")

    def test_x64_upper_bound_is_exclusive(self) -> None:
        """cmp eax, edi; jb forwarded_export means: if func_rva < dir_end, forward."""
        from emitrion.build_x64 import _emit_framework_stubs_x64
        stubs = _emit_framework_stubs_x64(set())
        block = _extract_between(stubs, "resolve_matched_export:", "resolve_export_by_hash:")
        lines = [l.strip() for l in block.splitlines()]
        for i, line in enumerate(lines):
            if line == "cmp  eax, edi" and i + 1 < len(lines):
                assert lines[i + 1] == "jb   forwarded_export"
                return
        pytest.fail("upper bound cmp/jb pair not found")

    def test_boundary_algorithm_matches_assembly_semantics(self) -> None:
        """The [lower_inclusive, upper_exclusive) range matches jb semantics.

        jb (jump if below) is unsigned: func_rva < bound. Combined:
          if func_rva < dir_rva:       jb not_forwarded  (skip check)
          if func_rva < dir_rva+size:  jb forwarded      (trap)
          else:                        fall through       (not forwarded)

        This is equivalent to: dir_rva <= func_rva < dir_rva + dir_size.
        """
        fixture = BOUNDARY_CASES
        for name, rva, expected in fixture.functions:
            lower_bound = fixture.export_dir_rva
            upper_bound = fixture.export_dir_rva + fixture.export_dir_size

            # Simulate jb semantics
            if rva < lower_bound:
                detected = False    # jb not_forwarded taken
            elif rva < upper_bound:
                detected = True     # jb forwarded_export taken
            else:
                detected = False    # fall through to not_forwarded

            assert detected == expected, (
                f"{name}: RVA 0x{rva:x}, expected={expected}, "
                f"jb_simulation={detected}"
            )


def _extract_between(text: str, start_label: str, end_label: str) -> str:
    """Extract text between two labels (inclusive of start, exclusive of end)."""
    lines = text.splitlines()
    capturing = False
    result = []
    for line in lines:
        if start_label in line:
            capturing = True
        elif end_label in line and capturing:
            break
        if capturing:
            result.append(line)
    return "\n".join(result)
