# Workflow IR Design

## Intent

Evolve Emitera from a collection of handwritten assembly templates into a
reference implementation for studying how Windows API workflows are modeled,
validated, and lowered to position-independent Windows x86 assembly.  The
design preserves the current manifest-to-assembly workflow while creating a
clear extension boundary for additional Windows ABIs in the future.

Emitera is a public educational and research project.  It is not an execution
framework, an operator tool, or a general-purpose arbitrary-assembly builder.

## Current State

The current pipeline is:

```text
YAML manifest -> Manifest -> PayloadTemplate.emit() -> assembly -> assembler -> outputs
```

`Manifest` contains API names, strings, variables, a template name, and
bad-character constraints.  `API_DATABASE` supplies documentation and
structure requirements.  Each `PayloadTemplate` emits handwritten assembly
and references named stack slots.  A `RecordingLayout` executes the template
to infer its slot dependencies.

This has produced a useful Windows x86 emitter, but API argument marshalling,
return-value handling, local state, control flow, and error behavior remain
implicit in individual templates.  The API records' prototypes are
documentation, not compiler-enforced contracts.

## Goals

- Model an API workflow independently of the x86 assembly used to implement
  it.
- Validate API calls, value lifetimes, structures, and control flow before
  lowering to assembly.
- Generate a contract from the same model used to generate code.
- Preserve existing manifest and template behavior during migration.
- Establish an explicit backend boundary before any x64 work begins.
- Keep emitted artifacts deterministic for identical inputs.

## Non-Goals

- A general-purpose assembly language, embedded scripting environment, or
  arbitrary inline-assembly escape hatch.
- x64 support in the first milestone.
- A YAML programming language with loops, expressions, and hidden side
  effects.
- Changing every existing template at once.
- Claiming that source generation or unit tests validate behavior on a real
  Windows target.

## Approaches Considered

### Retain Handwritten Templates

Continue adding APIs and workflows directly in `PayloadTemplate.emit()`.
This has the least short-term cost, but repeats calling logic, leaves the API
catalog unenforced, and makes a second architecture expensive.  It is not
selected.

### Build a Declarative YAML Workflow Language First

Move all workflow control flow into YAML immediately.  This is attractive for
simple examples but would require designing, parsing, validating, versioning,
and documenting a programming language before the workflow model is proven.
It is not selected for the initial implementation.

### Typed Python Workflow IR with an x86 Backend

Introduce a small, immutable in-memory workflow model.  Build the model in
Python, validate it, and lower it through the existing x86 helpers.  Retain
YAML for manifest inputs and template selection.  This is selected because it
adds flexibility without hiding behavior in an unbounded configuration format.

## Target Architecture

```text
Manifest and caller inputs
            |
            v
Workflow builder ------> API and ABI catalog
            |                    |
            v                    v
       Workflow IR --------> validation diagnostics
            |
            v
      x86 workflow backend
            |
            v
assembly, contract, and optional assembled bytes
```

### API and ABI Catalog

Expand each API record from documentation-only metadata into a typed contract:

- module and resolution strategy;
- architecture availability;
- calling convention;
- ordered argument descriptors, including direction and pointer/structure
  requirements;
- return-value descriptor and failure convention;
- required imported structures; and
- documentation category and source reference.

The existing prototype string remains useful for documentation, but does not
serve as the authoritative ABI definition.  API catalog entries are data only;
they do not generate an unreviewed call sequence.

The first milestone makes ABI-complete only the APIs used by its reference
workflow.  Those entries are marked `workflow_supported`; all other entries
remain `legacy_only` until migrated.  Documentation and validation must not
imply that an API has workflow support merely because it appears in the
catalog.

### Workflow IR

A workflow is an ordered, typed set of operations and named values.  The
initial operation set is deliberately small:

- define a constant or manifest-derived input;
- construct or reference a string;
- allocate a named local value or declared structure;
- initialize a structure to zero or write a declared scalar field;
- call a catalogued API with explicit ordered arguments;
- save an API return value to a named value;
- compare a result to an explicit success/failure condition; and
- branch to a named block or terminate.

Values are references rather than formatted assembly strings.  They express
roles such as immediate value, string address, structure address, local
address, or API return value.  Validation rejects undefined values, duplicate
names, invalid argument counts, incompatible argument roles, unavailable APIs,
and unreachable or unterminated blocks.

The initial IR does not model nested structure graphs, variable-length arrays,
or resource cleanup.  A workflow may use only structures whose required
initialization can be represented through zero initialization and declared
scalar-field writes.  Resource cleanup is added only when a selected workflow
and its documented API contract require it.

API records define a success predicate from a fixed initial set: `zero`,
`nonzero`, `null`, `invalid_handle`, or `signed_negative`.  A workflow branches
on the named API result using that predicate; arbitrary raw register or flag
comparisons are outside the public IR.  This keeps failure semantics visible in
the catalog and generated contract.

The IR contains no raw assembly operation.  An architecture backend may expose
carefully reviewed internal primitives, but workflow authors cannot bypass API
and ABI validation through the public model.

### x86 Backend

The first backend owns x86-specific concerns now embedded in templates:

- stdcall argument ordering and caller/callee stack responsibility;
- API resolver selection and module loading;
- register-scratch conventions;
- allocation of named values, structures, and string storage;
- bad-character-safe instruction selection; and
- lowering of result tests and branches.

`StackLayout` continues to own named-slot allocation initially.  Its fixed
zones are retained for compatibility, but workflow values are modeled as
virtual slots before physical offsets are assigned.  A later backend can use a
different allocation strategy without changing workflow definitions.

The first x86 backend supports only the resolution mechanisms already used by
Emitera: PEB-based resolution for bootstrap modules and `LoadLibraryA` followed
by the existing export-hash resolver for additional modules.  Alternative
resolvers are a future backend capability, not a first-milestone requirement.

### Output Contract and Determinism

The contract is generated from the validated workflow plus layout, rather than
from template-specific commentary.  It records API calls, argument bindings,
locals, structures, value ownership, and explicit control-flow outcomes.

Generated assembly must not include a wall-clock timestamp by default.  Build
metadata belongs in a separate optional provenance file or an explicit
reproducible-build opt-out.

The compatibility promise is stable CLI behavior and stable output paths/file
schemas.  Existing templates retain their current output path structure while
the IR is introduced.  Byte-for-byte assembly and contract identity is not
promised: normalized deterministic fixtures define the supported compatibility
baseline.  If the contract schema changes, it receives an explicit version.

## Migration Plan

1. Introduce the immutable IR data types, API ABI fields, and validator without
   changing existing templates or CLI behavior.
2. Add an x86 lowering interface that reuses existing bad-character and
   assembly helpers.
3. Implement one non-destructive reference workflow, selected for its ability
   to exercise typed arguments, a returned value, and a documented branch.
4. Compare its generated assembly/contract against checked-in golden fixtures;
   independently validate assembled bytes where an assembler is available.
5. Add a compatibility adapter so an existing template can coexist with an IR
   workflow under the same manifest and output structure.
6. Migrate remaining templates individually only when their behavior and
   generated contract are understood and testable.
7. Remove `RecordingLayout` dependency inference after all maintained
   workflows declare dependencies through the IR.

The first milestone succeeds when an IR-backed workflow can be built via the
existing CLI, produces deterministic source and a complete contract, and does
not regress legacy manifest generation.

## Testing and Validation

- Unit-test IR construction and validation without an assembler.
- Use golden fixtures for normalized assembly and generated contracts.
- Test x86 lowering independently from API-catalog validation.
- Detect assembler availability and skip assembler-specific tests with an
  explicit reason; a normal test command must not knowingly fail on macOS.
- Run assembly and target-behavior validation in a documented Windows x86 CI
  environment.  Local source generation does not prove target behavior.
- Add reproducibility tests: identical normalized inputs must yield identical
  assembly and contract output.

## Repository Shape

New explanatory material belongs under PascalCase `Documentation/` paths:

```text
Documentation/
  Architecture/
  Design/
  Research/
```

The existing `emitera/` package remains a code directory.  Future implementation
modules can be organized within it using ordinary Python naming conventions.

## Future Decisions Left to the Builder

- Exact Python representation for IR nodes: frozen dataclasses are the default
  unless a stronger type system or serialization need justifies another choice.
- The first non-destructive reference workflow, selected for teaching value and
  platform testability.
- The normalized-assembly fixture format and Windows CI provider, provided the
  resulting verification matrix is documented.
- A versioned serialized workflow format, only after two or more workflows
  demonstrate stable shared semantics.
