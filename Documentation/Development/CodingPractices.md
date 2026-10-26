# Coding Practices

## Purpose

Emitrion is an educational Windows API workflow emitter.  The project must be
easy to read, explicit about its platform guarantees, and difficult to extend
incorrectly.  This document defines the engineering standard for code,
documentation, and tests.

## Architecture Rules

- Treat the workflow IR as the future authoring boundary.  New reusable
  workflow behavior belongs in the typed IR and its backend, not in a new
  handwritten assembly template, unless an approved design explains why the
  IR cannot express it.
- Keep responsibilities separate:
  - manifests provide inputs and configuration;
  - the API/ABI catalog defines callable contracts;
  - the IR models intent and control flow;
  - validation rejects invalid models before emission;
  - an architecture backend lowers validated IR; and
  - the build pipeline coordinates, but does not contain, those concerns.
- Do not expose arbitrary assembly through a public workflow operation.
  Architecture-specific escape hatches, if ever required, are internal,
  reviewed primitives with a documented invariant and dedicated tests.
- Preserve legacy templates only as compatibility implementations.  Each
  migrated workflow must declare dependencies through the IR rather than infer
  them by executing template code.
- Do not claim architecture, ABI, or API support until it has a tested backend
  path.  A catalog entry is `legacy_only` until its workflow semantics are
  complete and verified.

## Python Style

- Target the Python version declared in `pyproject.toml`; use modern typing,
  `match` where it makes operation dispatch clearer, and standard-library
  constructs before adding dependencies.
- Prefer small pure functions and frozen dataclasses for IR nodes, catalog
  records, layouts, and diagnostics.  Make mutable state local and explicit.
- Use `Protocol` or a concrete typed interface at subsystem boundaries.  Do
  not use `object`, untyped dictionaries, or stringly typed values where a
  dataclass, enum, or union expresses the contract.
- Keep imports static and registries typed.  A registry maps public names to
  known constructors; it must not rely on unchecked dotted-path imports.
- Names describe the domain, not the implementation detail.  Use a verb for
  functions, a noun for types, and an adjective only when it distinguishes a
  meaningful variant.
- Comments explain non-obvious constraints and decisions: ABI behavior,
  bad-character constraints, stack invariants, or a deliberate trade-off.
  Delete comments that merely restate code.  Generated assembly comments may
  remain detailed because they are part of the educational output.
- Generated source and contracts are deterministic by default.  Put timestamps
  and other provenance in an explicitly requested separate artifact.

## Error and Validation Rules

- Validate before lowering.  Invalid workflows must produce structured,
  actionable diagnostics rather than partially generated assembly.
- A call validator checks API availability, workflow-support status, calling
  convention, argument count, argument category, direction, required structure
  type, return contract, and success predicate.
- Validate control flow semantically: every block is reachable as intended,
  references are defined along every path that reaches their use, and all
  terminating behavior has a unique emitted label.
- Lowering does not silently ignore an IR operation.  An unsupported operation
  is a hard error, not a comment in generated assembly.
- Keep success/failure semantics in the API catalog.  Workflows name a result
  and branch through its declared predicate; they do not embed untyped raw
  comparisons.

## Test Standard

A passing test is evidence only when it could have failed for the defect it is
meant to prevent.  Every test should state the observable behavior or invariant
it protects.

- Test a result, diagnostic, generated artifact, or externally observable
  effect—not just successful construction, non-empty text, or a method call.
- Include at least one negative test for each validation rule and one positive
  test that demonstrates the valid boundary.
- For emitted assembly, assert exact normalized fragments, control-flow
  structure, stack/layout facts, and absence of forbidden bytes after assembly.
  Do not rely solely on substring checks such as `"WinExec" in asm`.
- Test all supported IR operations through lowering.  In particular, a test
  that constructs `ZeroStruct`, `ConstructString`, or `WriteStructField` is
  insufficient unless the emitted assembly and layout prove that operation was
  realized correctly.
- Run source-level unit tests without an assembler.  Mark assembler-dependent
  tests as skipped when the capability is unavailable, with a clear reason;
  do not knowingly leave the normal suite red on a supported developer host.
- Run assembled-output checks in a documented Windows x86 environment.  A
  generated `.asm` file is not proof of valid bytes or target behavior.
- Use deterministic golden fixtures for normalized assembly and contracts.
  Never make a determinism test pass by stripping a nondeterministic field
  while leaving that field in the product output.
- Test compatibility at the public boundary: CLI parsing, manifest acceptance,
  output paths, contract schema, and documented error messages.
- A regression test must fail against the pre-fix behavior.  When practical,
  demonstrate this in review or record the defect and the test's failure mode.

## Review Checklist

Before merging a change, verify:

- The change has one clear architectural home and does not duplicate a legacy
  pathway without a compatibility reason.
- Public names, manifests, CLI choices, catalog entries, and documentation are
  updated together.
- No IR operation is accepted but ignored during lowering.
- Tests cover the new behavior, its invalid boundary, and the generated output
  at the appropriate layer.
- The affected suite is green or every skip is capability-based and explained.
- Generated output is reproducible for identical normalized inputs.
- Documentation uses `Documentation/` and PascalCase directory names.

## Current Remediation Priorities

1. Make `ir_run_command` available through the schema and CLI, or remove its
   public-facing claims until it is.
2. Replace source-only assertions with an assembled IR workflow check and fix
   duplicate termination-label emission before enabling that check.
3. Implement or reject each accepted IR operation; do not leave no-op lowering
   for structure initialization or string construction.
4. Enforce ABI argument categories and result predicates in the validator.
5. Make generated output deterministic and make the default test command
   capability-aware and green.
