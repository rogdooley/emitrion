# Changelog

All notable changes to emitera are documented in this file.

## [Unreleased]

### Added
- **IR reverse shell workflow**: full reverse shell chain (WSAStartup,
  WSASocketA, connect, CreateProcessA) as typed IR with pre-computed network
  byte order, struct initialization, and error branching at each stage.
  Registered as `ir_reverse_shell` template.
- **Verification lane** (`emitera.verify`): three-tier validation pipeline
  (cross-platform generation, assembly + bad-char scan, manual Windows lab).
  Produces JSON reports, supports determinism checks and XOR encoding.
  Runnable via `python -m emitera.verify`.
- **Quality gates**: ruff linting across the codebase, mypy strict on the
  workflow module.
- **Workflow IR hardening**: control-flow-aware validation with
  definitions tracked per block and intersected at join points. ABI-checked
  argument categories, reproducible builds via `SOURCE_DATE_EPOCH`.
- **DefineConstant IR node**: named constants that resolve as inline
  immediates with no layout slot needed.
- **ZeroStruct and WriteStructField IR nodes**: typed struct initialization
  in the IR, lowered to zeroing loops and field-offset writes.
- **INVALID_HANDLE success predicate**: compares eax with 0xFFFFFFFF for
  socket handle validation.
- **Development coding practices document** (`Documentation/Development/`).
- **README** with features, quick start, verification workflow, pipeline
  diagram, and project structure.
- **MIT license**.

### Fixed
- Word-size struct field writes in the IR x86 backend: `sin_family` and
  `sin_port` (16-bit fields) were emitting `mov word ptr [...], eax`
  instead of `mov word ptr [...], ax`, causing NASM assembly errors.
- Workflow validator now rejects mismatched predicates, null pointer
  dereferences, and string pointer immediates as errors (previously
  warnings).

## [0.1.0] - 2026-10-20

Initial release.

- YAML manifest-driven shellcode generation for Windows x86.
- PEB walking and ROR13 API hash resolution framework.
- 18 legacy payload templates: reverse_shell, run_command, bind_shell,
  copy_file, copy_then_run, move_then_run, tcp_download, tcp_stager,
  http_download, http_exfil, process_replace, service_persist, dll_inject,
  registry_persist, check_path, get_username, download_to_userpath,
  tcp_download_to_userpath.
- Bad-character avoidance via XOR-mask pairs and arithmetic sequences.
- Stack string construction (mov, push, shiftor, xor methods).
- Structure initialization for Win32 structs (WSADATA, sockaddr_in,
  STARTUPINFOA, PROCESS_INFORMATION).
- Debug runner generation for WinDbg lab testing.
- Contract documentation generation (stack map, API table, cheatsheet).
- Keystone and NASM assembler backends.
- IR run_command workflow (`ir_run_command`): first typed workflow with
  WinExec + ExitProcess and result branching.
- 500+ tests covering encoding, templates, manifests, IR validation,
  and end-to-end builds.
