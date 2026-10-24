"""Markdown documentation generator for the shellcode emitter.

Pure functions only - no file I/O.  All functions take data objects and
return strings.
"""
from __future__ import annotations

from .api_database import API_DATABASE, STRUCT_DATABASE, MODULE_LOAD_ORDER
from .hash_gen import ror13
from .payload_templates.base import PayloadTemplate, TemplateConfig
from .schema import Manifest
from .stack_alloc import StackLayout

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_EXPORT_CONTEXT_ROWS: list[tuple[str, str]] = [
    ("[ebp-0x04]", "Module base (transient)"),
    ("[ebp-0x08]", "AddressOfNames VA"),
    ("[ebp-0x0c]", "AddressOfNameOrdinals VA"),
    ("[ebp-0x10]", "AddressOfFunctions VA"),
    ("[ebp-0x14]", "NumberOfNames"),
    ("[ebp-0x18]", "Target hash (transient)"),
]


def _fmt_offset(offset: str) -> str:
    """Wrap an offset string in a backtick code span."""
    return f"`{offset}`"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    """Render a Markdown pipe table with the given headers and rows."""
    sep = "|" + "|".join("-" * (len(h) + 2) for h in headers) + "|"
    header_line = "| " + " | ".join(headers) + " |"
    lines = [header_line, sep]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def emit_stack_layout_md(manifest: Manifest, layout: StackLayout) -> str:
    """Render the full stack layout as Markdown."""
    lines: list[str] = []

    # Title + frame info
    lines.append("# Stack Layout")
    lines.append("")
    frame = layout.frame_size
    lines.append(
        f"Frame: `mov ebp, esp` / `sub esp, 0x{frame:x}` (0x{frame:x} bytes reserved)"
    )
    lines.append("")

    # --- Export Context (static) ---
    lines.append("## Export Context (reserved - do not allocate)")
    lines.append("")
    rows = [[_fmt_offset(offset), desc] for offset, desc in _EXPORT_CONTEXT_ROWS]
    lines.append(_table(["Offset", "Description"], rows))
    lines.append("")

    # --- Module Bases ---
    lines.append("## Module Bases")
    lines.append("")
    module_slots = layout.slots_by_category("module_base")
    if module_slots:
        rows = [[_fmt_offset(s.ebp_ref), s.name] for s in module_slots]
        lines.append(_table(["Offset", "Module"], rows))
    else:
        lines.append("_No module bases._")
    lines.append("")

    # --- API Table ---
    lines.append("## API Table")
    lines.append("")
    api_slots = layout.slots_by_category("api")
    if api_slots:
        rows = [
            [_fmt_offset(s.ebp_ref), s.name, API_DATABASE[s.name].module]
            for s in api_slots
        ]
        lines.append(_table(["Offset", "API", "Module"], rows))
    else:
        lines.append("_No API slots._")
    lines.append("")

    # --- Variables ---
    var_slots = layout.slots_by_category("variable")
    lines.append("## Variables")
    lines.append("")
    if var_slots:
        rows = [[_fmt_offset(s.ebp_ref), s.name, "4"] for s in var_slots]
        lines.append(_table(["Offset", "Variable", "Size"], rows))
    else:
        lines.append("_No variables._")
    lines.append("")

    # --- Structures ---
    struct_slots = layout.slots_by_category("structure")
    lines.append("## Structures")
    lines.append("")
    if struct_slots:
        rows = [
            [_fmt_offset(s.ebp_ref), s.name, f"0x{STRUCT_DATABASE[s.name].size:x}"]
            for s in struct_slots
        ]
        lines.append(_table(["Offset", "Structure", "Size"], rows))
    else:
        lines.append("_No structures._")
    lines.append("")

    # --- Strings ---
    string_slots = layout.slots_by_category("string")
    lines.append("## Strings")
    lines.append("")
    if string_slots:
        # Build a label -> StringEntry map
        str_map = {se.label: se for se in manifest.strings}
        rows = []
        for s in string_slots:
            entry = str_map.get(s.name)
            value = entry.value if entry else ""
            rows.append([_fmt_offset(s.ebp_ref), s.name, value, str(s.size)])
        lines.append(_table(["Offset", "Label", "Value", "Size"], rows))
    else:
        lines.append("_No strings._")

    # Strip trailing blank line(s) and ensure no trailing whitespace per line
    result = "\n".join(line.rstrip() for line in lines)
    return result


def emit_api_contracts_md(manifest: Manifest, layout: StackLayout) -> str:
    """Render per-module API tables with hashes, slots, and argument lists."""
    lines: list[str] = []

    lines.append("# API Contracts")

    # Determine which modules are actually used in this manifest, in MODULE_LOAD_ORDER sequence
    needed_modules: dict[str, list[str]] = {}  # dll -> list of func names (in manifest order)
    for func_name in manifest.functions:
        dll = API_DATABASE[func_name].module
        needed_modules.setdefault(dll, []).append(func_name)

    ordered_dlls = [m.dll for m in MODULE_LOAD_ORDER if m.dll in needed_modules]

    for dll in ordered_dlls:
        lines.append("")
        lines.append(f"## {dll}")
        lines.append("")

        # Resolution description
        module_info = next(m for m in MODULE_LOAD_ORDER if m.dll == dll)
        if module_info.load_via == "peb":
            lines.append("Resolution: PEB walk")
        else:
            dll_slot = layout.slot(dll)
            lines.append(
                f"Resolution: `LoadLibraryA(\"{dll}\")` -> base stored at `{dll_slot.ebp_ref}`"
            )
        lines.append("")

        # API Table subsection
        lines.append("### API Table")
        lines.append("")
        funcs = needed_modules[dll]
        rows = []
        for func_name in funcs:
            rec = API_DATABASE[func_name]
            h = ror13(func_name)
            slot = layout.slot(func_name)
            rows.append([
                func_name,
                f"`0x{h:08x}`",
                _fmt_offset(slot.ebp_ref),
                rec.category,
            ])
        lines.append(_table(["API", "Hash", "Slot", "Category"], rows))
        lines.append("")

        # API Details subsection
        lines.append("### API Details")
        for func_name in funcs:
            rec = API_DATABASE[func_name]
            h = ror13(func_name)
            slot = layout.slot(func_name)
            lines.append("")
            lines.append(f"#### {func_name}")
            lines.append("")
            lines.append(f"**Slot:** `{slot.ebp_ref}`")
            lines.append(f"**Hash:** `0x{h:08x}`")
            lines.append(f"**Module:** {dll}")
            lines.append(f"**Category:** {rec.category}")
            lines.append("")
            lines.append(f"```c\n{rec.prototype}\n```")
            lines.append("")
            if rec.arguments:
                arg_rows = [
                    [str(i + 1), arg.name, arg.type, arg.notes]
                    for i, arg in enumerate(rec.arguments)
                ]
                lines.append(_table(["#", "Parameter", "Type", "Notes"], arg_rows))
            else:
                lines.append("_No parameters._")
            lines.append("")
            lines.append("---")

    result = "\n".join(line.rstrip() for line in lines)
    return result


def emit_struct_layouts_md(manifest: Manifest, layout: StackLayout) -> str:
    """Render struct field tables for all structures required by the manifest."""
    lines: list[str] = []

    lines.append("# Structure Layouts")

    struct_slots = layout.slots_by_category("structure")

    # Build inverted map: struct_name -> list of API names that require it
    required_by: dict[str, list[str]] = {}
    for func_name in manifest.functions:
        rec = API_DATABASE[func_name]
        for struct_name in rec.requires_structs:
            required_by.setdefault(struct_name, []).append(func_name)

    for slot in struct_slots:
        struct_name = slot.name
        struct_rec = STRUCT_DATABASE[struct_name]
        lines.append("")
        lines.append(f"## {struct_name}")
        lines.append("")
        lines.append(f"**Size:** `0x{struct_rec.size:x}`")

        # Required by
        apis = required_by.get(struct_name, [])
        if apis:
            lines.append(f"**Required by:** {', '.join(apis)}")
        lines.append("")

        if struct_rec.fields:
            rows = [
                [
                    f"`+0x{f.offset:02x}`",
                    f.name,
                    str(f.size),
                    f.notes,
                ]
                for f in struct_rec.fields
            ]
            lines.append(_table(["Offset", "Field", "Size", "Notes"], rows))
        else:
            lines.append("_No field documentation (opaque output buffer)._")

        lines.append("")
        lines.append("---")

    result = "\n".join(line.rstrip() for line in lines)
    return result


def emit_cheatsheet_md(
    template: PayloadTemplate | None,
    config: TemplateConfig | None,
    shellcode_size: int | None = None,
    bad_chars: set[int] | None = None,
) -> str:
    """Render attacker-side operational commands as a Markdown section.

    Returns empty string when no template is provided.
    """
    if template is None or config is None:
        return ""

    lines: list[str] = ["# Operational Cheatsheet", ""]

    # Summary block
    lines.append(f"**Template:** {type(template).__name__}")
    lines.append(f"**Target:** `{config.lhost}:{config.lport}`")
    if shellcode_size is not None:
        lines.append(f"**Shellcode size:** {shellcode_size} bytes")
    if bad_chars:
        sorted_chars = sorted(bad_chars)
        char_str = " ".join(f"`0x{b:02x}`" for b in sorted_chars)
        lines.append(f"**Bad characters:** {char_str}")
    lines.append("")

    # Template-specific commands
    entries = template.cheatsheet(config)
    if entries:
        lines.append("## Setup Commands")
        lines.append("")
        for desc, cmd in entries:
            if cmd is None:
                continue
            lines.append(f"**{desc}:**")
            lines.append(f"```")
            lines.append(cmd)
            lines.append(f"```")
            lines.append("")

    # Common post-exploitation helpers
    lines.append("## Encoding (if needed)")
    lines.append("")
    lines.append("Remove bad chars with msfvenom (requires `shellcode.bin`):")
    bc_flag = "".join(f"\\x{b:02x}" for b in sorted(bad_chars or {0x00}))
    lines.append("```")
    lines.append(
        f'cat shellcode.bin | msfvenom --platform windows -a x86 '
        f'-e x86/shikata_ga_nai -b "{bc_flag}" -f python -v shellcode'
    )
    lines.append("```")

    result = "\n".join(line.rstrip() for line in lines)
    return result


def emit_full_contract_md(
    manifest: Manifest,
    layout: StackLayout,
    template: PayloadTemplate | None = None,
    config: TemplateConfig | None = None,
    shellcode_size: int | None = None,
) -> str:
    """Concatenate all sections into one Markdown document."""
    stack_section = emit_stack_layout_md(manifest, layout)
    api_section = emit_api_contracts_md(manifest, layout)
    struct_section = emit_struct_layouts_md(manifest, layout)
    cheatsheet_section = emit_cheatsheet_md(
        template, config, shellcode_size, manifest.badchars
    )

    parts = [
        "# Shellcode Contract",
        "",
        "Generated from manifest.",
        "",
        "---",
        "",
        stack_section,
        "",
        "---",
        "",
        api_section,
        "",
        "---",
        "",
        struct_section,
    ]

    if cheatsheet_section:
        parts += [
            "",
            "---",
            "",
            cheatsheet_section,
        ]

    result = "\n".join(line.rstrip() for line in parts)
    return result
