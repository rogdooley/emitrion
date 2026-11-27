"""Tests for the Linux x86_64 syscall database."""
from __future__ import annotations

import pytest

from emitrion.syscall_database import (
    SYSCALL_ARG_REGS,
    SYSCALL_DATABASE,
    SyscallArg,
    SyscallRecord,
    SyscallReturn,
)
from emitrion.workflow.ir import SuccessPredicate


class TestSyscallRecords:
    def test_all_entries_are_syscall_records(self):
        for name, rec in SYSCALL_DATABASE.items():
            assert isinstance(rec, SyscallRecord), f"{name} is not a SyscallRecord"

    def test_names_match_keys(self):
        for key, rec in SYSCALL_DATABASE.items():
            assert rec.name == key, f"Key '{key}' != record name '{rec.name}'"

    def test_numbers_are_non_negative(self):
        for name, rec in SYSCALL_DATABASE.items():
            assert rec.number >= 0, f"{name} has negative syscall number"

    def test_no_duplicate_numbers(self):
        seen: dict[int, str] = {}
        for name, rec in SYSCALL_DATABASE.items():
            if rec.number in seen:
                pytest.fail(
                    f"Duplicate syscall number {rec.number}: "
                    f"'{name}' and '{seen[rec.number]}'"
                )
            seen[rec.number] = name

    def test_arguments_use_valid_registers(self):
        for name, rec in SYSCALL_DATABASE.items():
            for arg in rec.arguments:
                assert arg.register in SYSCALL_ARG_REGS, (
                    f"{name} arg '{arg.name}' uses invalid register '{arg.register}'"
                )

    def test_arguments_at_most_six(self):
        for name, rec in SYSCALL_DATABASE.items():
            assert len(rec.arguments) <= 6, (
                f"{name} has {len(rec.arguments)} arguments (max 6)"
            )

    def test_argument_registers_are_in_order(self):
        for name, rec in SYSCALL_DATABASE.items():
            for i, arg in enumerate(rec.arguments):
                expected_reg = SYSCALL_ARG_REGS[i]
                assert arg.register == expected_reg, (
                    f"{name} arg {i} '{arg.name}' has register '{arg.register}', "
                    f"expected '{expected_reg}'"
                )


class TestKnownSyscalls:
    """Verify specific syscall numbers match the x86_64 kernel ABI."""

    EXPECTED = {
        "read": 0,
        "write": 1,
        "open": 2,
        "close": 3,
        "mmap": 9,
        "mprotect": 10,
        "dup2": 33,
        "socket": 41,
        "connect": 42,
        "accept": 43,
        "bind": 49,
        "listen": 50,
        "execve": 59,
        "exit": 60,
    }

    @pytest.mark.parametrize("name,number", EXPECTED.items())
    def test_syscall_number(self, name: str, number: int):
        rec = SYSCALL_DATABASE[name]
        assert rec.number == number

    def test_exit_has_no_return(self):
        assert SYSCALL_DATABASE["exit"].returns is None

    def test_execve_has_signed_negative_return(self):
        ret = SYSCALL_DATABASE["execve"].returns
        assert ret is not None
        assert ret.success == SuccessPredicate.SIGNED_NEGATIVE

    def test_connect_has_zero_return(self):
        ret = SYSCALL_DATABASE["connect"].returns
        assert ret is not None
        assert ret.success == SuccessPredicate.ZERO

    def test_socket_has_signed_negative_return(self):
        ret = SYSCALL_DATABASE["socket"].returns
        assert ret is not None
        assert ret.success == SuccessPredicate.SIGNED_NEGATIVE

    def test_mmap_has_six_arguments(self):
        assert len(SYSCALL_DATABASE["mmap"].arguments) == 6


class TestSyscallArgRegs:
    def test_register_order(self):
        assert SYSCALL_ARG_REGS == ("rdi", "rsi", "rdx", "r10", "r8", "r9")

    def test_six_registers(self):
        assert len(SYSCALL_ARG_REGS) == 6
