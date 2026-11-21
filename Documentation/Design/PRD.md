# Emitrion Product Requirements Document

**Status:** active draft  
**Audience:** maintainers, contributors, and users of the educational emitter

## 1. Purpose

Emitrion is an educational shellcode emitter for studying how a declared
payload workflow becomes position-independent assembly, shellcode bytes, and
reviewable documentation. Its value is traceability: a user can inspect the
manifest, typed workflow, target-specific lowering, generated assembly, and
validation evidence as one chain.

Emitrion is not an operator framework, a general-purpose arbitrary-assembly
builder, or a claim that generated output is reliable on every system.

## 2. Problem and users

Students and researchers need a repeatable way to examine Windows shellcode
construction without manually reconciling API declarations, stack layout,
bad-character constraints, assembly, and debugger validation. Existing output
must remain understandable enough to step through in an isolated lab.

Primary users are:

- learners using isolated Windows lab VMs and debuggers;
- maintainers adding or reviewing typed workflows and target backends; and
- researchers who need reproducible source-level and assembled-byte evidence.

## 3. Product principles

- **Evidence before claims.** Source generation, linting, type checks, and
  byte scans do not establish native runtime behavior.
- **Target-specific behavior stays target-specific.** OS API catalogues,
  resolver/bootstrap logic, ABI, pointer width, layout, encoding, and native
  validation belong to the selected target backend.
- **Readable artifacts are a product surface.** Generated assembly and
  contracts are reviewed artifacts, not incidental build by-products.
- **Small, explicit abstractions.** A shared abstraction is added only when
  its semantics are genuinely common across targets.
- **Compatibility is deliberate.** Existing Windows manifests and CLI paths
  remain supported unless a versioned contract change says otherwise.

## 4. Current scope and support status

| Target | Status | Supported evidence |
|---|---|---|
| Windows x86 | source-level alpha | manifest/IR validation, generated-artifact tests, optional assembly and byte scanning; live Windows/WinDbg acceptance remains target-specific |
| Windows x64 | source-level alpha | separate x64 lowering, layout, and harness paths; native acceptance remains target-specific |
| Linux (any ISA) | not implemented | no backend, API catalogue, resolver, ABI lowering, or runtime claim |
| macOS (any ISA) | not implemented | no backend, API catalogue, resolver, ABI lowering, or runtime claim |

The manifest target defaults to `windows` + `x86` for compatibility. The typed
target model records operating system, architecture, and the implied Windows
ABI. Linux and macOS are recognized future target identities, but the current
pipeline rejects them rather than silently treating them as Windows.

## 5. User-facing requirements

### Inputs

- YAML manifests declare the selected template, bad characters, functions,
  strings, variables, and target architecture.
- CLI configuration may override documented template inputs without bypassing
  manifest validation.
- A target must be selected before layout or lowering. Unsupported targets
  fail clearly and before generated output is presented as valid.

### Outputs

For a valid supported target, Emitrion produces:

- generated assembly source;
- a target-appropriate debugger or execution harness where available;
- raw bytes when an assembler is available;
- generated contract documentation; and
- verification output describing assembly, bad-character, and determinism
  results.

Output compatibility means stable CLI behavior and output paths/file schemas.
Instruction layout and byte sequences may change only through reviewed
fixtures and validation evidence.

### Workflow model

- Typed workflows model API calls, values, structures, control flow, and
  success predicates before lowering.
- The current workflow IR is a **Windows workflow model**, not a universal
  cross-platform payload language.
- A future cross-platform intent layer is optional. It must not replace the
  existing Windows workflow layer until a concrete shared semantic use case is
  proven.

## 6. Quality and acceptance requirements

Every supported source change must keep these host-side gates green:

1. Ruff linting for the repository.
2. Strict type checking for the workflow module.
3. Unit, lowering, golden-artifact, and regression tests.
4. Byte-level assembly, bad-character, and determinism checks whenever an
   assembler is available.

Native support claims require additional target evidence:

- run the generated artifact on the declared OS/architecture in an isolated
  lab;
- use the target debugger to observe expected control flow and API behavior;
- exercise both expected-success and controlled-failure paths where relevant;
- record the target, toolchain, inputs, outputs, and unresolved limitations.

See [VerificationLane.md](../Development/VerificationLane.md) for the current
three-tier validation process.

## 7. Planned milestones

### M1: Stabilize Windows source contracts

- Keep manifest, target, workflow, API-catalogue, and generated-output
  contracts aligned.
- Maintain clean lint and type gates and reviewed golden fixtures.
- Resolve known Windows reliability gaps before calling a target supported.

### M2: Define a portable backend contract

Before implementing another OS, document and test the backend responsibilities
for layout, resolver/bootstrap, ABI argument lowering, string/data placement,
encoding, assembly, contract generation, and native validation. Split the
Windows API and structure data into target-owned catalogues only when this
contract is ready.

### M3: Evaluate one additional target

Select one OS/ISA pair based on a concrete educational workflow. Build its
catalogue, resolver/bootstrap, ABI lowering, artifacts, and isolated native
acceptance plan together. Do not advertise it as supported until the M2 gates
and target-native evidence pass.

## 8. Explicit non-goals

- Implementing Linux or macOS support as part of current Windows work.
- Promising identical workflows or bytes across operating systems.
- General YAML programming, inline assembly escape hatches, or unreviewed
  code generation.
- Replacing the existing typed Windows workflow layer with a broad universal
  operation framework.
- Treating host-side test success as proof of native execution.

## 9. Open decisions

- Which concrete OS/ISA pair should be evaluated first after Windows
  stabilization?
- Which Windows workflows have sufficient debugger evidence to advance beyond
  source-level alpha?
- What versioning policy should apply when manifest or contract schemas change?

Until these are resolved, contributors should preserve the current scope and
describe unvalidated behavior as incomplete.
