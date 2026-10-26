"""Manifest loading and validation for the shellcode emitter."""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from .api_database import API_DATABASE, MODULE_LOAD_ORDER

_VALID_METHODS = {"mov", "shiftor", "push", "xor"}
_VALID_REGS = {"eax", "ebx", "ecx", "edx", "esi", "edi"}
_VALID_TEMPLATES = {
    "reverse_shell", "run_command", "copy_file", "copy_then_run",
    "move_then_run", "tcp_download", "tcp_stager", "bind_shell",
    "http_download",
    "http_exfil",
    "process_replace",
    "service_persist",
    "dll_inject",
    "registry_persist",
    "check_path",
    "get_username",
    "download_to_userpath",
    "tcp_download_to_userpath",
    "ir_run_command",
    "ir_reverse_shell",
}


@dataclass
class StringEntry:
    label: str
    value: str
    method: str
    dest: str = "edi"


@dataclass
class VariableEntry:
    name: str


@dataclass
class Manifest:
    badchars: set[int]
    functions: list[str]
    strings: list[StringEntry]
    variables: list[VariableEntry] = field(default_factory=list)
    template: str | None = None


def load(path: str) -> Manifest:
    """Parse and validate a manifest YAML file. Raises ValueError listing all errors found."""
    with open(path) as fh:
        data = yaml.safe_load(fh)

    errors: list[str] = []

    # --- badchars ---
    raw_badchars = data.get("badchars", [])
    badchars: set[int] = set()
    for token in raw_badchars:
        try:
            value = int(str(token), 16)
            if not (0 <= value <= 0xFF):
                errors.append(f"Badchar out of byte range: '{token}'.")
            else:
                badchars.add(value)
        except ValueError:
            errors.append(f"Cannot parse badchar as hex byte: '{token}'.")

    # --- functions ---
    raw_functions: list[str] = data.get("functions", [])
    functions: list[str] = []
    seen_funcs: set[str] = set()
    known_modules = {m.dll for m in MODULE_LOAD_ORDER}

    for name in raw_functions:
        if name not in API_DATABASE:
            errors.append(f"Unknown API: '{name}'. Not in API_DATABASE.")
            continue
        if name in seen_funcs:
            errors.append(f"Duplicate function: '{name}'.")
            continue
        seen_funcs.add(name)
        functions.append(name)
        record = API_DATABASE[name]
        if record.module not in known_modules:
            errors.append(
                f"API '{name}' belongs to module '{record.module}'"
                f" which has no entry in MODULE_LOAD_ORDER."
            )

    # --- strings ---
    raw_strings: list[dict] = data.get("strings", [])
    strings: list[StringEntry] = []
    seen_labels: set[str] = set()

    for entry in raw_strings:
        label = entry.get("label", "")
        value = entry.get("value", "")
        method = entry.get("method", "")
        dest = entry.get("dest", "edi")

        entry_ok = True

        if method not in _VALID_METHODS:
            errors.append(f"Unknown string method: '{method}'.")
            entry_ok = False

        if label in seen_labels:
            errors.append(f"Duplicate string label: '{label}'.")
            entry_ok = False
        else:
            seen_labels.add(label)

        if dest not in _VALID_REGS:
            errors.append(f"Invalid dest register: '{dest}'.")
            entry_ok = False

        if entry_ok:
            strings.append(StringEntry(label=label, value=value, method=method, dest=dest))

    # --- variables ---
    raw_variables = data.get("variables", [])
    variables: list[VariableEntry] = []
    seen_var_names: set[str] = set()

    for name in raw_variables:
        if name in seen_var_names:
            errors.append(f"Duplicate variable: '{name}'.")
            continue
        if name in seen_funcs:
            errors.append(f"Variable name conflicts with function: '{name}'.")
            continue
        seen_var_names.add(name)
        variables.append(VariableEntry(name=name))

    # --- template ---
    raw_template = data.get("template", None)
    template: str | None = None
    if raw_template is not None:
        if raw_template not in _VALID_TEMPLATES:
            errors.append(
                f"Unknown template: '{raw_template}'. "
                f"Available: {sorted(_VALID_TEMPLATES)}"
            )
        else:
            template = raw_template

    if errors:
        raise ValueError("\n".join(errors))

    return Manifest(
        badchars=badchars, functions=functions, strings=strings,
        variables=variables, template=template,
    )
