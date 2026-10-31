"""Tests for native_harness_x64 configuration, serialization, and scenarios.

These tests validate the harness module's data structures, JSON
serialization, config validation, and scenario definitions. They do NOT
execute shellcode and run on any platform.

Tests that require Windows native execution should be marked with
@pytest.mark.windows and run on the Windows lab VM.
"""
from __future__ import annotations

import json
import sys

import pytest

from emitrion.native_harness_x64 import (
    EXCEPTION_NAMES,
    SCENARIOS,
    ExecutionResult,
    ExecutionStatus,
    HarnessConfig,
    _WORKER_SCRIPT,
    execute_shellcode,
)


# ---------------------------------------------------------------------------
# HarnessConfig validation
# ---------------------------------------------------------------------------

class TestHarnessConfig:
    def test_default_config(self):
        cfg = HarnessConfig()
        assert cfg.timeout_ms == 10000
        assert cfg.interactive is False
        assert cfg.test_id == ""
        assert cfg.collect_exit_code is True

    def test_validate_ok(self):
        cfg = HarnessConfig(timeout_ms=5000)
        assert cfg.validate() == []

    def test_validate_timeout_too_low(self):
        cfg = HarnessConfig(timeout_ms=50)
        errors = cfg.validate()
        assert len(errors) == 1
        assert "100" in errors[0]

    def test_validate_timeout_too_high(self):
        cfg = HarnessConfig(timeout_ms=500000)
        errors = cfg.validate()
        assert len(errors) == 1
        assert "300000" in errors[0]

    def test_validate_boundary_100(self):
        cfg = HarnessConfig(timeout_ms=100)
        assert cfg.validate() == []

    def test_validate_boundary_300000(self):
        cfg = HarnessConfig(timeout_ms=300000)
        assert cfg.validate() == []


# ---------------------------------------------------------------------------
# ExecutionResult serialization
# ---------------------------------------------------------------------------

class TestExecutionResult:
    def test_default_result(self):
        r = ExecutionResult(test_id="t1")
        assert r.test_id == "t1"
        assert r.arch == "x64"
        assert r.status == ExecutionStatus.SETUP_FAILURE.value
        assert r.native_execution is False
        assert r.worker_pid is None
        assert r.worker_exit_code is None

    def test_json_roundtrip(self):
        r = ExecutionResult(
            test_id="roundtrip",
            shellcode_size=256,
            status=ExecutionStatus.SUCCESS.value,
            exit_code=0,
            duration_ms=42.5,
            alloc_address=0x7FF000000000,
            timeout_ms=5000,
            native_execution=True,
            worker_exit_code=0,
        )
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["test_id"] == "roundtrip"
        assert parsed["shellcode_size"] == 256
        assert parsed["status"] == "success"
        assert parsed["alloc_address"] == 0x7FF000000000
        assert parsed["native_execution"] is True
        assert parsed["worker_exit_code"] == 0

    def test_from_json(self):
        data = json.dumps({
            "test_id": "from_json",
            "arch": "x64",
            "shellcode_size": 100,
            "status": "exception",
            "exit_code": 0xC0000005,
            "exception_code": 0xC0000005,
            "exception_name": "EXCEPTION_ACCESS_VIOLATION",
            "duration_ms": 1.5,
            "alloc_address": None,
            "failure_reason": "AV",
            "timeout_ms": 10000,
            "native_execution": True,
            "worker_pid": None,
            "worker_exit_code": 0,
        })
        r = ExecutionResult.from_json(data)
        assert r.test_id == "from_json"
        assert r.status == "exception"
        assert r.exception_code == 0xC0000005

    def test_from_json_ignores_unknown_fields(self):
        data = json.dumps({
            "test_id": "compat",
            "arch": "x64",
            "shellcode_size": 0,
            "status": "success",
            "future_field": "should_be_ignored",
        })
        r = ExecutionResult.from_json(data)
        assert r.test_id == "compat"
        assert not hasattr(r, "future_field")

    def test_passed_property_success(self):
        r = ExecutionResult(test_id="p", status="success")
        assert r.passed is True

    def test_passed_property_failure(self):
        r = ExecutionResult(test_id="p", status="exception")
        assert r.passed is False

    def test_passed_property_timeout(self):
        r = ExecutionResult(test_id="p", status="timeout")
        assert r.passed is False

    def test_passed_property_indeterminate(self):
        r = ExecutionResult(test_id="p", status="indeterminate")
        assert r.passed is False

    def test_passed_property_worker_crash(self):
        r = ExecutionResult(test_id="p", status="worker_crash")
        assert r.passed is False

    def test_json_contains_all_fields(self):
        r = ExecutionResult(test_id="fields")
        parsed = json.loads(r.to_json())
        expected_keys = {
            "test_id", "arch", "shellcode_size", "status", "exit_code",
            "exception_code", "exception_name", "duration_ms",
            "alloc_address", "failure_reason", "timeout_ms",
            "native_execution", "worker_pid", "worker_exit_code",
        }
        assert set(parsed.keys()) == expected_keys


# ---------------------------------------------------------------------------
# ExecutionStatus enum
# ---------------------------------------------------------------------------

class TestExecutionStatus:
    def test_all_values(self):
        assert ExecutionStatus.SUCCESS.value == "success"
        assert ExecutionStatus.TIMEOUT.value == "timeout"
        assert ExecutionStatus.INDETERMINATE.value == "indeterminate"
        assert ExecutionStatus.EXCEPTION.value == "exception"
        assert ExecutionStatus.WORKER_CRASH.value == "worker_crash"
        assert ExecutionStatus.SETUP_FAILURE.value == "setup_failure"
        assert ExecutionStatus.NOT_WINDOWS.value == "not_windows"

    def test_string_coercion(self):
        assert str(ExecutionStatus.SUCCESS) == "ExecutionStatus.SUCCESS"


# ---------------------------------------------------------------------------
# Exception name registry
# ---------------------------------------------------------------------------

class TestExceptionNames:
    def test_breakpoint_code(self):
        assert EXCEPTION_NAMES[0x80000003] == "EXCEPTION_BREAKPOINT"

    def test_access_violation_code(self):
        assert EXCEPTION_NAMES[0xC0000005] == "EXCEPTION_ACCESS_VIOLATION"

    def test_stack_overflow_code(self):
        assert EXCEPTION_NAMES[0xC00000FD] == "EXCEPTION_STACK_OVERFLOW"

    def test_all_codes_are_valid(self):
        for code, name in EXCEPTION_NAMES.items():
            assert isinstance(code, int)
            assert code > 0
            assert isinstance(name, str)
            assert name.startswith("EXCEPTION_") or name.startswith("DBG_")


# ---------------------------------------------------------------------------
# Worker script
# ---------------------------------------------------------------------------

class TestWorkerScript:
    def test_worker_script_is_valid_python(self):
        compile(_WORKER_SCRIPT, "<worker>", "exec")

    def test_worker_script_contains_set_error_mode(self):
        assert "SetErrorMode" in _WORKER_SCRIPT

    def test_worker_script_preserves_existing_flags(self):
        assert "prev" in _WORKER_SCRIPT
        assert "prev |" in _WORKER_SCRIPT

    def test_worker_script_sets_argtypes(self):
        assert "SetErrorMode.argtypes" in _WORKER_SCRIPT
        assert "SetErrorMode.restype" in _WORKER_SCRIPT

    def test_worker_script_uses_indeterminate_for_timeout(self):
        assert '"indeterminate"' in _WORKER_SCRIPT


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

class TestScenarios:
    def test_four_scenarios_defined(self):
        assert len(SCENARIOS) == 4

    def test_scenario_ids(self):
        expected = {"test_a_winexec", "test_b_dll_load", "test_c_multi_arg", "test_d_failure"}
        assert set(SCENARIOS.keys()) == expected

    def test_all_have_description(self):
        for sid, s in SCENARIOS.items():
            assert "description" in s, f"{sid} missing description"

    def test_all_have_timeout(self):
        for sid, s in SCENARIOS.items():
            assert "timeout_ms" in s, f"{sid} missing timeout_ms"
            assert s["timeout_ms"] >= 1000

    def test_all_have_expect_success(self):
        for sid, s in SCENARIOS.items():
            assert "expect_success" in s, f"{sid} missing expect_success"

    def test_manifests_exist(self):
        from pathlib import Path
        for sid, s in SCENARIOS.items():
            manifest = s.get("manifest")
            if manifest is not None:
                assert Path(manifest).exists(), f"{sid}: manifest {manifest} not found"


# ---------------------------------------------------------------------------
# Non-Windows execution path
# ---------------------------------------------------------------------------

class TestNonWindowsExecution:
    @pytest.mark.skipif(sys.platform == "win32", reason="Tests non-Windows path")
    def test_returns_not_windows(self):
        r = execute_shellcode(b"\xcc", HarnessConfig(test_id="nonwin"))
        assert r.status == ExecutionStatus.NOT_WINDOWS.value
        assert r.native_execution is False
        assert "win32" not in r.failure_reason or sys.platform in r.failure_reason

    def test_empty_shellcode(self):
        r = execute_shellcode(b"", HarnessConfig(test_id="empty"))
        if sys.platform != "win32":
            assert r.status == ExecutionStatus.NOT_WINDOWS.value
        else:
            assert r.failure_reason == "Empty shellcode"

    def test_config_validation_checked_before_platform(self):
        cfg = HarnessConfig(timeout_ms=1, test_id="badcfg")
        r = execute_shellcode(b"\xcc", cfg)
        assert r.status == ExecutionStatus.SETUP_FAILURE.value
        assert "100" in r.failure_reason


# ---------------------------------------------------------------------------
# Build integration (no execution)
# ---------------------------------------------------------------------------

class TestBuildIntegration:
    def test_execute_from_build_produces_result(self):
        from emitrion.native_harness_x64 import execute_from_build
        cfg = HarnessConfig(test_id="build_test")
        r = execute_from_build(
            "emitrion/manifests/x64/run_command_x64.yaml",
            cfg,
            assemble=False,
        )
        assert r.test_id == "build_test"
        assert "assembler" in r.failure_reason.lower() or "shellcode" in r.failure_reason.lower()

    def test_run_scenario_unknown(self):
        from emitrion.native_harness_x64 import run_scenario
        r = run_scenario("nonexistent_scenario")
        assert "Unknown scenario" in r.failure_reason
