"""GitHub Action execution wrapper and step summary coordinator for Caulk.

Coordinates input validation, scanner invocation, JSON report parsing,
Markdown step summary generation, and GitHub Action output emission.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import TextIO

from caulk.cli import (
    EXIT_EXECUTION_ERROR,
    EXIT_FINDINGS_BREACH_THRESHOLD,
    EXIT_SUCCESS_CLEAN,
    EXIT_USAGE_ERROR,
)
from caulk.models import Severity
from caulk.reporting.summary import generate_error_summary, generate_step_summary

# Allowed boolean strings for action inputs
BOOLEAN_TRUE_VALUES = {"true", "1", "yes"}
BOOLEAN_FALSE_VALUES = {"false", "0", "no"}


def parse_action_boolean(value: str | None, param_name: str = "check-vulns") -> bool:
    """Safely parse boolean inputs from GitHub Actions environment."""
    if value is None:
        return False
    norm = value.strip().lower()
    if norm in BOOLEAN_TRUE_VALUES:
        return True
    if norm in BOOLEAN_FALSE_VALUES:
        return False
    allowed = ", ".join(sorted(BOOLEAN_TRUE_VALUES | BOOLEAN_FALSE_VALUES))
    raise ValueError(f"Invalid boolean value '{value}' for {param_name}. Allowed: {allowed}")


def resolve_target_path(raw_path: str | None, workspace_root: str | None = None) -> Path:
    """Resolve target path against GITHUB_WORKSPACE if relative, or default to current dir."""
    target_str = (raw_path or ".").strip()
    target = Path(target_str)

    if target.is_absolute():
        return target

    if workspace_root:
        return (Path(workspace_root) / target).resolve()

    return target.resolve()


def validate_action_inputs(
    raw_path: str | None,
    raw_threshold: str | None,
    raw_check_vulns: str | None,
    raw_python_version: str | None = None,
    workspace_root: str | None = None,
    raw_scan_history: str | None = None,
) -> tuple[Path, Severity, bool, bool]:
    """Validate all inputs supplied to the GitHub Action."""
    # 1. Target path resolution
    target_path = resolve_target_path(raw_path, workspace_root)

    # 2. Severity threshold
    thresh_str = (raw_threshold or "HIGH").strip()
    try:
        threshold = Severity.from_string(thresh_str)
    except ValueError as err:
        valid_sevs = ", ".join(s.value for s in Severity)
        raise ValueError(
            f"Invalid severity-threshold '{raw_threshold}'. Must be one of: {valid_sevs}"
        ) from err

    # 3. Advisory check flag
    check_vulns = parse_action_boolean(raw_check_vulns, "check-vulns")

    # 4. Scan history flag
    scan_history = parse_action_boolean(raw_scan_history, "scan-history")

    # 5. Python version input validation (restricted to tested series: 3.11, 3.12, 3.13)
    if raw_python_version:
        v_str = raw_python_version.strip()
        parts = v_str.split(".")
        if not parts or not parts[0].isdigit() or (len(parts) > 1 and not parts[1].isdigit()):
            raise ValueError(
                f"Invalid python-version '{raw_python_version}'. Supported versions: 3.11, 3.12, 3.13."
            )
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        if (major, minor) not in {(3, 11), (3, 12), (3, 13)}:
            raise ValueError(
                f"Unsupported Python version '{raw_python_version}'. Caulk is tested and supported exclusively on Python 3.11, 3.12, and 3.13."
            )

    if sys.version_info < (3, 11):  # noqa: UP036
        raise ValueError(
            f"Unsupported Python runtime '{sys.version}'. Caulk requires Python 3.11 or newer."
        )

    return target_path, threshold, check_vulns, scan_history


def write_step_summary(summary_md: str, summary_file: Path | str | None = None) -> None:
    """Append Markdown report to GITHUB_STEP_SUMMARY if available."""
    target = summary_file or os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return

    path = Path(target)
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(summary_md.strip() + "\n\n")
    except Exception as err:
        sys.stderr.write(f"Warning: Failed to write to GITHUB_STEP_SUMMARY: {err}\n")


def write_action_outputs(
    outputs: dict[str, str],
    output_file: Path | str | None = None,
) -> None:
    """Write key-value outputs to GITHUB_OUTPUT for composite action consumption."""
    target = output_file or os.environ.get("GITHUB_OUTPUT")
    if not target:
        return

    path = Path(target)
    try:
        with path.open("a", encoding="utf-8") as f:
            for key, val in outputs.items():
                f.write(f"{key}={val}\n")
    except Exception as err:
        sys.stderr.write(f"Warning: Failed to write to GITHUB_OUTPUT: {err}\n")


def run_action(
    environ: dict[str, str] | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Execute Caulk GitHub Action pipeline.

    Returns the standard Caulk exit code:
      0: Scan clean (no findings breach threshold).
      1: Findings breach threshold.
      2: Input or configuration error.
      3: Scanner execution error.
    """
    env = environ if environ is not None else os.environ
    err_stream = stderr or sys.stderr

    raw_path = env.get("INPUT_PATH", ".")
    raw_threshold = env.get("INPUT_SEVERITY_THRESHOLD", "HIGH")
    raw_check_vulns = env.get("INPUT_CHECK_VULNS", "false")
    raw_scan_history = env.get("INPUT_SCAN_HISTORY", "false")
    raw_python_version = env.get("INPUT_PYTHON_VERSION", "3.12")
    workspace = env.get("GITHUB_WORKSPACE")

    summary_file = env.get("GITHUB_STEP_SUMMARY")
    output_file = env.get("GITHUB_OUTPUT")

    # 1. Input Validation
    try:
        target_path, threshold, check_vulns, scan_history = validate_action_inputs(
            raw_path=raw_path,
            raw_threshold=raw_threshold,
            raw_check_vulns=raw_check_vulns,
            raw_python_version=raw_python_version,
            workspace_root=workspace,
            raw_scan_history=raw_scan_history,
        )
    except Exception as err:
        err_msg = f"Input validation error: {err}"
        err_stream.write(f"{err_msg}\n")
        write_step_summary(
            generate_error_summary(err_msg, error_code=EXIT_USAGE_ERROR),
            summary_file=summary_file,
        )
        write_action_outputs(
            {"scan-result": "error", "findings-count": "0", "report-path": ""},
            output_file=output_file,
        )
        return EXIT_USAGE_ERROR

    # 2. Check if target exists before invoking scanner
    if not target_path.exists():
        err_msg = f"Target path does not exist: {target_path}"
        err_stream.write(f"{err_msg}\n")
        write_step_summary(
            generate_error_summary(err_msg, error_code=EXIT_USAGE_ERROR),
            summary_file=summary_file,
        )
        write_action_outputs(
            {"scan-result": "error", "findings-count": "0", "report-path": ""},
            output_file=output_file,
        )
        return EXIT_USAGE_ERROR

    # 3. Determine Report Output Destination in Runner Temp
    runner_temp = env.get("RUNNER_TEMP") or tempfile.gettempdir()
    report_file = Path(runner_temp) / f"caulk-report-{uuid.uuid4().hex[:8]}.json"

    # 4. Resolve CLI Executable and build command
    cli_exe = shutil.which("caulk-security")
    cmd: list[str] = [cli_exe] if cli_exe else [sys.executable, "-m", "caulk.cli"]

    if scan_history:
        cmd.extend(
            [
                "history",
                "scan",
                str(target_path),
                "--severity-threshold",
                threshold.value,
                "--output",
                str(report_file),
            ]
        )
    else:
        cmd.extend(
            [
                "scan",
                str(target_path),
                "--severity-threshold",
                threshold.value,
                "--output",
                str(report_file),
            ]
        )
        if check_vulns:
            cmd.append("--check-vulns")
        else:
            cmd.append("--offline")

    # 5. Execute Scanner Subprocess
    try:
        proc = subprocess.run(cmd, check=False)
        scan_code = proc.returncode
    except Exception as err:
        err_msg = f"Failed to execute scanner: {err}"
        err_stream.write(f"{err_msg}\n")
        write_step_summary(
            generate_error_summary(err_msg, error_code=EXIT_EXECUTION_ERROR),
            summary_file=summary_file,
        )
        write_action_outputs(
            {"scan-result": "error", "findings-count": "0", "report-path": ""},
            output_file=output_file,
        )
        return EXIT_EXECUTION_ERROR

    # 6. Process Scan Results
    if report_file.exists():
        try:
            report_data = json.loads(report_file.read_text(encoding="utf-8"))
        except Exception as err:
            err_msg = f"Failed to parse generated JSON report: {err}"
            err_stream.write(f"{err_msg}\n")
            write_step_summary(
                generate_error_summary(err_msg, error_code=EXIT_EXECUTION_ERROR),
                summary_file=summary_file,
            )
            write_action_outputs(
                {"scan-result": "error", "findings-count": "0", "report-path": ""},
                output_file=output_file,
            )
            return EXIT_EXECUTION_ERROR

        is_complete = bool(report_data.get("summary", {}).get("is_complete", True))

        # Enforce execution error if an incomplete scan somehow reported clean exit
        if not is_complete and scan_code == EXIT_SUCCESS_CLEAN:
            scan_code = EXIT_EXECUTION_ERROR

        # Generate and write step summary from report
        summary_md = generate_step_summary(report_data, threshold=threshold)
        write_step_summary(summary_md, summary_file=summary_file)

        # Emit action outputs
        total_findings = str(report_data.get("summary", {}).get("total_findings", 0))
        if scan_code == EXIT_SUCCESS_CLEAN and is_complete:
            action_status = "passed"
        elif scan_code == EXIT_FINDINGS_BREACH_THRESHOLD:
            action_status = "failed"
        else:
            action_status = "error"

        write_action_outputs(
            {
                "scan-result": action_status,
                "findings-count": total_findings,
                "report-path": str(report_file),
            },
            output_file=output_file,
        )

        return scan_code

    # 7. Scanner Error Handling when report file was not produced (exit code 2 or 3)
    error_summary = generate_error_summary(
        f"Scanner exited with code {scan_code} on target: {target_path}",
        error_code=scan_code,
    )
    write_step_summary(error_summary, summary_file=summary_file)
    write_action_outputs(
        {"scan-result": "error", "findings-count": "0", "report-path": ""},
        output_file=output_file,
    )
    return scan_code


if __name__ == "__main__":
    sys.exit(run_action())
