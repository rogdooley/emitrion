"""Verification lane for assembled shellcode.

Wraps the build pipeline to produce a structured verification report:
  1. Generate assembly from a manifest via the normal build() path.
  2. Assemble with the available assembler (Keystone or NASM).
  3. Scan the final bytes for bad-character violations.
  4. Write a machine-readable report (JSON) and all build artifacts.
  5. Optionally write the debug_runner.py for manual lab execution.

Cross-platform steps (generate, scan) run anywhere.
Assembly requires Keystone or NASM.
Execution is manual, in the isolated Windows lab environment only.

Usage:
  uv run python -m emitera.verify emitera/manifests/calc.yaml --template ir_run_command
  uv run python -m emitera.verify emitera/manifests/revshell.yaml --lhost 10.0.0.1 --lport 9001
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .build import BuildResult, build, write_outputs
from .payload_templates.base import TemplateConfig


@dataclass(frozen=True)
class VerificationReport:
    """Structured result of the verification pipeline."""
    manifest: str
    template: str
    assembler: str | None
    assembled: bool
    shellcode_size: int | None
    shellcode_sha256: str | None
    badchars_declared: list[str]
    badchar_violations: list[str]
    badchar_clean: bool
    encoded: bool
    encoded_size: int | None
    deterministic: bool | None
    asm_line_count: int
    timestamp: str
    errors: list[str]

    @property
    def passed(self) -> bool:
        return self.assembled and self.badchar_clean and not self.errors


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(
    manifest_path: str,
    template_name: str | None = None,
    config: TemplateConfig | None = None,
    out_dir: str = "verify_out",
    check_determinism: bool = True,
    encode: bool = False,
) -> VerificationReport:
    """Run the full verification pipeline.

    Returns a VerificationReport with pass/fail status and diagnostics.
    Raises nothing on verification failure (failures are in the report).
    """
    config = config or TemplateConfig()
    errors: list[str] = []

    result = build(
        manifest_path,
        template_name=template_name,
        config=config,
        out_dir=out_dir,
        assemble=True,
        encode=encode,
    )

    assembled = result.shellcode_bytes is not None
    if not assembled:
        errors.append("Assembly failed: no shellcode bytes produced")
        if result.asm_errors:
            errors.extend(result.asm_errors)

    badchar_violations: list[str] = []
    if result.asm_errors and assembled:
        badchar_violations = [
            e for e in result.asm_errors if "BADCHAR" in e or "badchar" in e
        ]

    badchars_hex = sorted(f"0x{b:02x}" for b in config.badchars)

    sha = _sha256(result.shellcode_bytes) if result.shellcode_bytes else None

    deterministic: bool | None = None
    if check_determinism and assembled:
        saved_epoch = os.environ.get("SOURCE_DATE_EPOCH")
        os.environ["SOURCE_DATE_EPOCH"] = "0"
        try:
            r1 = build(
                manifest_path,
                template_name=template_name,
                config=config,
                out_dir=os.path.join(out_dir, "_det_a"),
                assemble=True,
                encode=encode,
            )
            r2 = build(
                manifest_path,
                template_name=template_name,
                config=config,
                out_dir=os.path.join(out_dir, "_det_b"),
                assemble=True,
                encode=encode,
            )
            if r1.shellcode_bytes and r2.shellcode_bytes:
                deterministic = r1.shellcode_bytes == r2.shellcode_bytes
                if not deterministic:
                    errors.append("Determinism check failed: identical inputs produced different bytes")
            else:
                deterministic = None
        finally:
            if saved_epoch is None:
                os.environ.pop("SOURCE_DATE_EPOCH", None)
            else:
                os.environ["SOURCE_DATE_EPOCH"] = saved_epoch

    from .schema import load as load_manifest
    manifest = load_manifest(manifest_path)
    effective_template = template_name or manifest.template

    report = VerificationReport(
        manifest=manifest_path,
        template=effective_template,
        assembler=result.assembler,
        assembled=assembled,
        shellcode_size=len(result.shellcode_bytes) if result.shellcode_bytes else None,
        shellcode_sha256=sha,
        badchars_declared=badchars_hex,
        badchar_violations=badchar_violations,
        badchar_clean=assembled and len(badchar_violations) == 0,
        encoded=result.encoded_bytes is not None,
        encoded_size=len(result.encoded_bytes) if result.encoded_bytes else None,
        deterministic=deterministic,
        asm_line_count=result.asm.count("\n") + 1,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        errors=errors,
    )

    return report


def write_verification(
    report: VerificationReport,
    result: BuildResult,
    out_dir: str,
) -> None:
    """Write all verification artifacts to out_dir."""
    write_outputs(result, out_dir)

    report_path = Path(out_dir) / "verification_report.json"
    report_dict = {
        "manifest": report.manifest,
        "template": report.template,
        "assembler": report.assembler,
        "assembled": report.assembled,
        "shellcode_size": report.shellcode_size,
        "shellcode_sha256": report.shellcode_sha256,
        "badchars_declared": report.badchars_declared,
        "badchar_violations": report.badchar_violations,
        "badchar_clean": report.badchar_clean,
        "encoded": report.encoded,
        "encoded_size": report.encoded_size,
        "deterministic": report.deterministic,
        "asm_line_count": report.asm_line_count,
        "timestamp": report.timestamp,
        "passed": report.passed,
        "errors": report.errors,
    }
    report_path.write_text(json.dumps(report_dict, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="emitera.verify",
        description="Verification lane: generate, assemble, scan, report.",
    )
    parser.add_argument("manifest", help="Path to manifest YAML file")
    parser.add_argument(
        "--template",
        choices=[
            "reverse_shell", "run_command", "copy_file", "copy_then_run",
            "move_then_run", "tcp_download", "tcp_stager", "bind_shell",
            "http_download", "http_exfil", "process_replace",
            "service_persist", "dll_inject", "registry_persist",
            "check_path", "ir_run_command", "ir_reverse_shell",
        ],
    )
    parser.add_argument("--out", default="verify_out", help="Output directory")
    parser.add_argument("--lhost", default="127.0.0.1")
    parser.add_argument("--lport", type=int, default=4444)
    parser.add_argument("--command", default=None)
    parser.add_argument("--no-determinism", action="store_true",
                        help="Skip determinism check")
    parser.add_argument("--encode", action="store_true",
                        help="Apply XOR encoding when badchar violations exist")
    parser.add_argument("--json", action="store_true",
                        help="Print report as JSON to stdout")

    args = parser.parse_args()

    config = TemplateConfig(
        lhost=args.lhost,
        lport=args.lport,
        command=args.command,
    )

    print(f"[*] Verifying: {args.manifest}")
    print(f"[*] Template:  {args.template or '(from manifest)'}")
    print()

    report = verify(
        args.manifest,
        template_name=args.template,
        config=config,
        out_dir=args.out,
        check_determinism=not args.no_determinism,
        encode=args.encode,
    )

    result = build(
        args.manifest,
        template_name=args.template,
        config=config,
        out_dir=args.out,
        assemble=True,
        encode=args.encode,
    )
    write_verification(report, result, args.out)

    if args.json:
        report_path = Path(args.out) / "verification_report.json"
        print(report_path.read_text())
    else:
        _print_report(report)

    sys.exit(0 if report.passed else 1)


def _print_report(report: VerificationReport) -> None:
    status = "PASS" if report.passed else "FAIL"
    print(f"{'=' * 60}")
    print(f"  Verification Report: {status}")
    print(f"{'=' * 60}")
    print(f"  Manifest:      {report.manifest}")
    print(f"  Template:      {report.template}")
    print(f"  Assembler:     {report.assembler or 'none (assembly failed)'}")
    print(f"  Assembled:     {'yes' if report.assembled else 'NO'}")
    if report.shellcode_size is not None:
        print(f"  Shellcode:     {report.shellcode_size} bytes")
        print(f"  SHA-256:       {report.shellcode_sha256}")
    print(f"  Bad chars:     {', '.join(report.badchars_declared)}")
    print(f"  Violations:    {len(report.badchar_violations)}")
    print(f"  Bad-char free: {'yes' if report.badchar_clean else 'NO'}")
    if report.encoded:
        print(f"  XOR encoded:   {report.encoded_size} bytes")
    if report.deterministic is not None:
        print(f"  Deterministic: {'yes' if report.deterministic else 'NO'}")
    print(f"  ASM lines:     {report.asm_line_count}")
    print(f"  Timestamp:     {report.timestamp}")
    if report.errors:
        print()
        print("  Errors:")
        for err in report.errors:
            print(f"    - {err}")
    print(f"{'=' * 60}")
    print()
    if report.passed:
        print("  All checks passed. Transfer debug_runner.py to the")
        print("  Windows lab VM for manual execution verification.")
    else:
        print("  Verification FAILED. See errors above.")


if __name__ == "__main__":
    main()
