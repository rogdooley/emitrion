# x64 Backend Correctness and Reliability Audit Report

## Summary

Three correctness defects found and fixed. All 730 tests pass (596 x86, 134 x64). Zero regressions.

## Audit Scope

| Section | Area | Result |
|---------|------|--------|
| 1. Baseline | 679 tests, clean build | PASS |
| 2. Microsoft x64 ABI | 0-10 arg calls, alignment, nested calls, failure paths | 1 DEFECT FIXED |
| 3. Stack Layout | Overlap detection, shadow space, framework context isolation | 1 DEFECT FIXED |
| 4. Position Independence | No absolute addresses, no x86 addressing modes | PASS |
| 5. API Resolution | PEB walk, PE32+ parsing, ROR-13 hashing, scratch registers | 1 DEFECT FIXED |
| 6. Workflow Execution | WinExec, reverse shell, compare predicates, E2E builds | PASS |
| 7. x86 Regression | Full 596-test x86 suite | PASS (0 regressions) |
| 8. Defect Fixes | 3 defects fixed with 51 regression tests | COMPLETE |

## Defects Found and Fixed

### Defect 1: Scratch Register Conflict (encode_x64.py)

**Severity**: High (data corruption in generated shellcode)
**Confidence**: Source-reviewed, assembly-validated

When `safe_qword_store`, `safe_dword_store_x64`, or `safe_word_store_x64` were called with `r11` as the source register AND a displacement containing badchar bytes, the badchar-safe path loaded the displacement into `r11` (the default tmp register), destroying the value that was supposed to be stored. The final `mov qword ptr [r11], r11` stored the computed address instead of the original value.

**Before (broken)**:
```asm
mov  r11d, 0x0101010b    ; offset with XOR mask -> clobbers r11
xor  r11d, 0x01010101
add  r11, rsp
mov  qword ptr [r11], r11  ; stores address, not original value
```

**After (fixed)**:
```asm
mov  eax, 0x0101010b     ; uses rax as tmp instead
xor  eax, 0x01010101
add  rax, rsp
mov  qword ptr [rax], r11  ; r11 value preserved
```

**Fix**: Added `_safe_tmp()` function that detects when `src_reg` and `tmp` alias the same physical register (checking all width variants: r11/r11d/r11w) and selects an alternate scratch via `_SCRATCH_MAP`. Applied to all six safe store/load/lea/call functions.

**Primary collision site**: `_emit_strings_x64()` in `build_x64.py` encodes string chunks into `r11d` then calls `safe_dword_store_x64("rsp", offset, "r11d", bc)`. If the string slot offset contains a badchar byte, the old code would corrupt the string data.

### Defect 2: Stack Alignment Not Guaranteed (build_x64.py)

**Severity**: High (potential crashes in called Win32 APIs)
**Confidence**: Source-reviewed, assembly-validated

The prologue did `mov rbp, rsp; sub rsp, frame_size` where `frame_size` is 16-byte aligned. If entry RSP was 8-mod-16 (standard after a CALL instruction), RSP after the subtraction remained 8-mod-16. The Microsoft x64 ABI requires RSP to be 16-byte aligned at the point of a CALL instruction. Many Win32 APIs use SSE instructions internally that fault on unaligned RSP.

**Fix**: Added `and rsp, -16` between `mov rbp, rsp` and `sub rsp, frame_size`. This guarantees 16-byte alignment regardless of the shellcode's entry context (whether entered via CALL, JMP, or direct execution).

### Defect 3: Framework Context / Slot Overlap (stack_alloc_x64.py)

**Severity**: High (data corruption between framework and payload)
**Confidence**: Source-reviewed, assembly-validated

The PEB walk framework stubs save export context (module base, name tables, ordinal tables, function count, pending hash) to `[rbp-0x08]` through `[rbp-0x30]` (6 qwords, 48 bytes). After `mov rbp, rsp; sub rsp, frame_size`, these map to `[RSP + frame_size - 0x08]` through `[RSP + frame_size - 0x30]`, the top 48 bytes of the stack frame.

The allocator computed `frame_size = _ceil16(string_cursor)` without reserving this region. For manifests with strings extending near the frame boundary (which is most non-trivial manifests, e.g., reverse shell), allocated string slots would overlap with the framework's export context saves.

**Concrete example before fix**: Reverse shell manifest had `sockaddr_in` at `[RSP+0x310..0x320)` while framework context occupied `[RSP+0x310..0x340)`.

**Fix**: Added `EXPORT_CONTEXT_RESERVE = 0x30` to the frame size calculation: `frame_size = _ceil16(string_cursor + EXPORT_CONTEXT_RESERVE)`. This guarantees at least 48 bytes between the highest allocated slot and the framework context area.

## Validation Methodology

| Level | Description | Defects Verified At |
|-------|-------------|-------------------|
| Source-reviewed | Code path analysis, manual trace | All 3 |
| Assembly-validated | Generated assembly output inspected, instruction semantics verified | All 3 |
| Emulator-tested | Not performed (no x64 emulator in CI) | None |
| Native-tested | Not performed (no Windows x64 lab VM in CI) | None |

## Test Coverage Added

51 new tests in `emitrion/tests/test_x64_audit.py`:

- **ABI correctness** (10 tests): 0, 1, 2, 4, 5, 6, 10 args; nested calls; failure paths; stack alignment
- **Stack layout** (7 tests): Overlap detection (3 manifests), shadow space isolation, extended shadow for stack args, framework context isolation (2 manifests), 16-byte frame alignment
- **Position independence** (4 tests): Framework stubs, full compose, workflow, no absolute jumps
- **API resolution** (12 tests): PEB offsets (5), PE32+ parsing (6), hash consistency (1)
- **Scratch register** (6 tests): r11 source with badchar offset for qword/dword/word stores, non-conflicting case, mem_load with dst=tmp, string emission collision site
- **Workflow execution** (8 tests): API resolution storage, WinExec E2E, reverse shell struct zeroing, all 5 compare predicates
- **E2E build pipeline** (2 tests): run_command and revshell through full build_x64()

## Final Test Results

```
730 passed in 1.52s
  596 x86 tests (zero regressions)
  134 x64 tests (83 pre-existing + 51 audit)
```

## Out of Scope

Per audit constraints, the following were NOT performed:
- Major feature additions
- Backend redesign or rewrite
- Native execution testing (requires Windows x64 VM)
- Emulator-based shellcode execution
- New payload template development
