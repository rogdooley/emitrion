# x64 Backend Correctness and Reliability Audit Report

## Summary

Phase 1: Three correctness defects found and fixed.
Phase A (code review): Four P0 and five P1 defects addressed (8 fixed, 1 documented limitation). All 746 tests pass (596 x86, 150 x64). Zero regressions.

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

## Known Limitations

The following are known limitations that unit tests cannot validate. They require native Windows x64 execution to confirm or refute.

### Nonvolatile register preservation

The generated shellcode freely clobbers RBX, RBP, RDI, RSI, R12-R15 (all nonvolatile under MS x64 ABI). This is acceptable for terminal shellcode that never returns to its caller, but would corrupt the caller's state if the shellcode were expected to return. Any future "return-to-caller" workflow would need a save/restore prologue/epilogue.

### Stack restoration after dynamic alignment

The prologue does `mov rbp, rsp; and rsp, -16; sub rsp, frame_size`. Restoration via `mov rsp, rbp` correctly undoes both the alignment and the sub. However, if any future code path modifies RSP between prologue and epilogue (e.g., dynamic alloca, additional pushes for API calls), the restoration path would need adjustment. Current workflows do not modify RSP post-prologue.

### Call-site alignment beyond prologue

The prologue guarantees RSP is 16-byte aligned after setup. Since the lowering backend does not push/pop or adjust RSP between the prologue and API calls (all args go to registers or pre-allocated shadow space slots), call-site alignment is maintained by construction. This invariant is not enforced by assertion and would break silently if future lowering patterns introduced RSP modifications.

### Encoder register clobber contract

The safe_* functions in encode_x64.py may clobber one volatile scratch register (RAX or R11) beyond their explicit operands. The clobber contract is now documented in the module docstring. Callers that hold live values in RAX or R11 across a safe_* call must save those values first. The current lowering pipeline avoids this by resolving into RAX then moving to the target register before any safe_* call, but this ordering is implicit, not enforced.

### Native execution not validated

Generated shellcode has been validated at the assembly-text level (instruction semantics, register usage, offset correctness) but has NOT been executed on a Windows x64 system. The recommended validation before merging to main is:

1. `WinExec("calc.exe", SW_SHOW)` -- simplest smoke test
2. `CopyFileA` -- exercises stack arguments beyond 4 registers
3. Reverse shell -- exercises WSA APIs, struct initialization, multi-block workflow

## Hardening Added Post-Audit

### Frame-invariant assertion (stack_alloc_x64.py)

`build_layout_x64()` now asserts at construction time that:
- No allocated slot overlaps the framework export context area (top 0x30 bytes of frame)
- No non-shadow slot intrudes into shadow space (bottom 0x20+ bytes of frame)

A violation raises `ValueError` identifying the offending slot. This catches allocator bugs at build time rather than producing silently corrupt shellcode.

### Explicit clobber documentation (encode_x64.py)

Module docstring now documents which registers each function may clobber, the _SCRATCH_MAP policy, and the caller's responsibility to save RAX/R11 if they hold live values.

## Phase A: Code Review Fixes

### P0-1: Export Resolver Fall-Through (build_x64.py)

`resolve_export_by_hash` had no explicit failure path. When the target hash was not found in the export table, execution fell through past `jl find_export_loop` into whatever code followed.

**Fix (v1)**: Added `xor eax, eax; ret` after the loop boundary check.

**Fix (v2)**: Changed to `int3` (debug break). Returning NULL was insufficient: callers stored the NULL pointer and later executed `call qword ptr [rsp+offset]`, transferring control to address 0. The `int3` halts execution immediately, visible in WinDbg. A missing export in position-independent shellcode is unrecoverable at runtime.

### P0-2: DLL Loader RSP Mutation (build_x64.py)

`_dll_load_block_x64()` used `emit_push()` to construct DLL name strings on the stack via PUSH instructions, then called LoadLibraryA with `mov rcx, rsp`. The PUSH instructions mutated RSP, invalidating all RSP-relative offsets for the LoadLibraryA call and the subsequent module_slot store.

**Fix**: Rewrote to construct the DLL name in a pre-allocated string slot using mov-based encoding (same approach as `_emit_strings_x64`), then `lea rcx, [rsp+offset]`. No RSP mutation. Removed `emit_push`/`to_dwords` imports.

### P0-3: Register Argument Clobbering (x64_backend.py)

`_lower_call()` resolved all register arguments through RAX first, then emitted in reverse order. While sources (stack slots, immediates) don't conflict with arg registers, the RAX routing was fragile: any future _resolve_value path touching an arg register would silently corrupt prepared args.

**Fix**: Each argument is now resolved directly into its target register (RCX, RDX, R8, R9) in forward order. All sources read from stack-relative offsets or encode immediates, so no inter-argument dependency exists. Scratch clobber (R11/RAX via _SCRATCH_MAP) never conflicts with arg registers.

### P0-4: Post-Assembly Badchar Validation (build_x64.py)

The encoder validates immediate bytes for badchars but not the complete assembled output (opcodes, REX prefixes, ModR/M, SIB, displacements, branch offsets).

**Fix**: Added post-assembly scan of the raw shellcode bytes against the badchar set. Violations are reported in `asm_errors` with byte value, offset, and count. When violations are found, `shellcode_bytes` is set to None (hard failure: no usable binary produced). This catches encoder blind spots at build time.

### P1-1: Export Forwarding (build_x64.py) [documented limitation, not fixed]

Added explicit comment documenting that forwarded exports (RVA inside the export directory) are not detected. Current targets (kernel32.dll, ws2_32.dll) do not forward the APIs we resolve.

### P1-2: Bounded Module Enumeration (build_x64.py)

The `find_kernel32_entry`/`next_module` loop walked the InInitializationOrderModuleList with no termination condition. On a corrupted or unexpected PEB, this would loop forever.

**Fix**: Added R15D as a 64-iteration countdown. `find_module` initializes `r15d = 0x40`, `next_module` decrements and jumps to `module_not_found` on zero. `module_not_found` executes `int3` (hard stop), preventing invalid PE parsing through `rbx=0`.

**R15 lifetime**: R15 is nonvolatile under MS x64 ABI. The loop body is all inline assembly (no CALL instructions): `safe_mem_load_x64` inlines, `cmp`/`jne`/`sub`/`jmp` are scalar. No instruction in the loop body writes to R15 except the `dec r15d` counter. Verified by test.

### P1-3: Error Conditions as Exceptions (x64_backend.py)

`_lower_write_struct_field` and `_lower_zero_struct` emitted error conditions as assembly comments (e.g., `; ERROR: WriteStructField 'x' has no known type`). These produced silently broken shellcode.

**Fix**: All five error paths now raise `ValueError` with diagnostic messages naming the missing struct, the available fields, or the database that lacks the type. Errors are caught at build time.

### P1-4: Duplicate Struct Initialization (build_x64.py)

The compose pipeline called `_emit_struct_init_x64()` AND the workflow IR contained `ZeroStruct` operations, zeroing the same structs twice.

**Fix**: When the template is a `WorkflowTemplate`, the compose-level struct init is skipped with a comment noting it's handled by workflow IR.

### P1-5: Signed Immediate Handling (x64_backend.py)

`Immediate(-1)` with `ref.value <= 0xFFFFFFFF` evaluated True (Python: -1 <= 4294967295), routing through `encode_dword_into_r64` which masked to 0xFFFFFFFF. The 32-bit mov zero-extends to 0x00000000FFFFFFFF, not the intended 0xFFFFFFFFFFFFFFFF.

**Fix**: Changed condition to `0 < ref.value <= 0xFFFFFFFF`. Negative values now fall through to `encode_qword` which handles full 64-bit representation. Applied to all three sites: `_resolve_value` (Immediate), `_resolve_value` (NameRef constant), `_resolve_input`.

## Phase A Test Coverage

16 new tests in `test_x64_audit.py`:
- P0-1: Resolver failure halts via int3 (2 tests)
- P0-2: DLL loader no RSP mutation (3 tests)
- P0-3: Direct register resolution + semantic trace (2 tests)
- P0-4: Post-assembly badchar validation (1 test)
- P1-2: Bounded module enumeration + R15 lifetime (3 tests)
- P1-3: Errors as exceptions (2 tests)
- P1-4: No duplicate struct init (1 test)
- P1-5: Signed immediate handling (2 tests)

## Final Test Results (Phase A)

```
746 passed in 1.61s
  596 x86 tests (zero regressions)
  150 x64 tests (83 pre-existing + 51 audit + 16 code review)
```

## Out of Scope

Per audit constraints, the following were NOT performed:
- Major feature additions
- Backend redesign or rewrite
- Native execution testing (requires Windows x64 VM)
- Emulator-based shellcode execution
- New payload template development
