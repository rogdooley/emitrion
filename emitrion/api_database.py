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
    # --- advapi32.dll : registry ---
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
}


MODULE_LOAD_ORDER: list[ModuleInfo] = [
    ModuleInfo(dll="kernel32.dll", load_via="peb"),
    ModuleInfo(dll="ws2_32.dll",   load_via="LoadLibraryA"),
    ModuleInfo(dll="wininet.dll",  load_via="LoadLibraryA"),
    ModuleInfo(dll="advapi32.dll", load_via="LoadLibraryA"),
    ModuleInfo(dll="urlmon.dll",   load_via="LoadLibraryA"),
]


def get_record(name: str) -> APIRecord:
    """Look up an API by name. Raises KeyError with a clear message if not found."""
    if name not in API_DATABASE:
        raise KeyError(f"'{name}' not found in API_DATABASE")
    return API_DATABASE[name]
