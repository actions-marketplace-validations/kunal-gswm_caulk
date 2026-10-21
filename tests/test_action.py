"""Comprehensive unit and integration tests for Caulk GitHub Action."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from caulk.action import (
    parse_action_boolean,
    resolve_target_path,
    run_action,
    validate_action_inputs,
    write_action_outputs,
    write_step_summary,
)
from caulk.cli import (
    EXIT_FINDINGS_BREACH_THRESHOLD,
    EXIT_SUCCESS_CLEAN,
    EXIT_USAGE_ERROR,
)
from caulk.models import Severity
from caulk.reporting.summary import generate_error_summary, generate_step_summary


def test_action_yml_structure():
    """Verify action.yml metadata, inputs, outputs, and composite steps."""
    action_yml_path = Path(__file__).resolve().parent.parent / "action.yml"
    assert action_yml_path.exists(), "action.yml missing at repository root"

    content = action_yml_path.read_text(encoding="utf-8")

    # Verify essential composite metadata
    assert "name: 'Caulk Security Scanner'" in content
    assert "using: 'composite'" in content

    # Verify required inputs
    assert "path:" in content
    assert "default: '.'" in content
    assert "severity-threshold:" in content
    assert "default: 'HIGH'" in content
    assert "check-vulns:" in content
    assert "default: 'false'" in content
    assert "python-version:" in content
    assert "default: '3.12'" in content

    # Verify declared outputs
    assert "scan-result:" in content
    assert "steps.run-caulk.outputs.scan-result" in content
    assert "findings-count:" in content
    assert "steps.run-caulk.outputs.findings-count" in content
    assert "report-path:" in content
    assert "steps.run-caulk.outputs.report-path" in content

    # Verify supply chain security: pinned setup-python commit SHA
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in content

    # Verify safe environment variable passing (no direct ${{ inputs... }} shell interpolation)
    assert "python -m caulk.action" in content
    assert "INPUT_PATH: ${{ inputs.path }}" in content
    assert "INPUT_SEVERITY_THRESHOLD: ${{ inputs.severity-threshold }}" in content


def test_parse_action_boolean():
    """Verify boolean parsing for action parameters."""
    assert parse_action_boolean("true") is True
    assert parse_action_boolean("True") is True
    assert parse_action_boolean("1") is True
    assert parse_action_boolean("yes") is True

    assert parse_action_boolean("false") is False
    assert parse_action_boolean("False") is False
    assert parse_action_boolean("0") is False
    assert parse_action_boolean("no") is False
    assert parse_action_boolean(None) is False

    with pytest.raises(ValueError, match="Invalid boolean value 'maybe'"):
        parse_action_boolean("maybe")


def test_resolve_target_path(tmp_path: Path):
    """Verify target path resolution with and without GITHUB_WORKSPACE."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sub_dir = workspace / "subproject"
    sub_dir.mkdir()

    # Relative path with workspace
    resolved = resolve_target_path("subproject", str(workspace))
    assert resolved == sub_dir

    # Absolute path ignores workspace
    abs_dir = tmp_path / "absolute_dir"
    resolved_abs = resolve_target_path(str(abs_dir), str(workspace))
    assert resolved_abs == abs_dir

    # Default '.' with workspace
    resolved_dot = resolve_target_path(".", str(workspace))
    assert resolved_dot == workspace


def test_validate_action_inputs():
    """Verify input validation rules and error messages."""
    # Valid default inputs
    target, thresh, check_v = validate_action_inputs(".", "HIGH", "false")
    assert thresh == Severity.HIGH
    assert check_v is False

    # Valid custom severity (case-insensitive)
    _, thresh_crit, _ = validate_action_inputs(".", "critical", "false")
    assert thresh_crit == Severity.CRITICAL

    # Invalid severity
    with pytest.raises(ValueError, match="Invalid severity-threshold 'INVALID'"):
        validate_action_inputs(".", "INVALID", "false")

    # Invalid check-vulns
    with pytest.raises(ValueError, match="Invalid boolean value 'not_a_bool'"):
        validate_action_inputs(".", "HIGH", "not_a_bool")

    # Unsupported Python version input
    with pytest.raises(ValueError, match="Unsupported Python version '3.9'"):
        validate_action_inputs(".", "HIGH", "false", raw_python_version="3.9")


def test_step_summary_generation_clean():
    """Verify step summary format for a completely clean scan."""
    mock_report = {
        "caulk_version": "0.1.0",
        "target_path": "my-project",
        "summary": {
            "files_scanned": 12,
            "files_skipped": 1,
            "duration_seconds": 0.045,
            "total_findings": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
            "checks_not_performed": ["External advisories skipped (offline mode)."],
        },
        "findings": [],
    }

    summary = generate_step_summary(mock_report, threshold=Severity.HIGH)

    assert "## Caulk Security Scan Report" in summary
    assert "Scan Result: ✅ Passed (Threshold: HIGH)" in summary
    assert "Inspected:** 12 files" in summary
    assert "Total** | **0**" in summary
    assert "External advisories skipped (offline mode)" in summary
    assert "Security Disclaimer:" in summary


def test_step_summary_generation_breached():
    """Verify step summary format when findings breach the threshold."""
    mock_report = {
        "caulk_version": "0.1.0",
        "target_path": "vulnerable-app",
        "summary": {
            "files_scanned": 8,
            "files_skipped": 0,
            "duration_seconds": 0.03,
            "total_findings": 2,
            "severity_counts": {
                "CRITICAL": 1,
                "HIGH": 1,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
        },
        "findings": [
            {
                "rule_id": "SEC002",
                "title": "AWS Access Key ID Detected",
                "severity": "CRITICAL",
                "category": "SECRET",
                "file_path": "app/config.py",
                "line_number": 14,
                "evidence": "AKIA************MPLE",
            },
            {
                "rule_id": "CFG001",
                "title": "Django DEBUG Mode Enabled",
                "severity": "HIGH",
                "category": "CONFIGURATION",
                "file_path": "app/settings.py",
                "line_number": 45,
                "evidence": "DEBUG = True",
            },
        ],
    }

    summary = generate_step_summary(mock_report, threshold=Severity.HIGH)

    assert "Scan Result: ❌ Failed (Threshold: HIGH)" in summary
    assert "Found **2** finding(s)" in summary
    assert (
        "| `SEC002` | **CRITICAL** | SECRET | `app/config.py:14` | AWS Access Key ID Detected |"
        in summary
    )
    assert (
        "| `CFG001` | **HIGH** | CONFIGURATION | `app/settings.py:45` | Django DEBUG Mode Enabled |"
        in summary
    )
    # Verify raw evidence is omitted from summary table
    assert "AKIA************MPLE" not in summary
    assert "DEBUG = True" not in summary


def test_step_summary_below_threshold():
    """Verify step summary format when findings exist but remain below threshold."""
    mock_report = {
        "caulk_version": "0.1.0",
        "target_path": "low-risk-app",
        "summary": {
            "files_scanned": 5,
            "files_skipped": 0,
            "duration_seconds": 0.02,
            "total_findings": 1,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 1,
                "INFO": 0,
            },
        },
        "findings": [
            {
                "rule_id": "DEP001",
                "title": "Unpinned Dependency",
                "severity": "LOW",
                "category": "DEPENDENCY",
                "file_path": "requirements.txt",
                "line_number": 2,
                "evidence": "flask",
            }
        ],
    }

    # Threshold is HIGH -> scan passes even though 1 LOW finding exists
    summary = generate_step_summary(mock_report, threshold=Severity.HIGH)

    assert "Scan Result: ✅ Passed (Threshold: HIGH)" in summary
    assert "1 finding(s) detected below the HIGH failure threshold" in summary


def test_error_summary_generation():
    """Verify error summary markdown generation."""
    err_summary = generate_error_summary("Directory does not exist", error_code=2)
    assert "Usage / Configuration Error" in err_summary
    assert "Exit Code 2" in err_summary
    assert "Directory does not exist" in err_summary

    exec_summary = generate_error_summary("Memory allocation failed", error_code=3)
    assert "Scanner Execution Error" in exec_summary
    assert "Exit Code 3" in exec_summary


def test_write_helpers(tmp_path: Path):
    """Verify write_step_summary and write_action_outputs file operations."""
    summary_file = tmp_path / "step_summary.md"
    output_file = tmp_path / "github_output.txt"

    write_step_summary("## Test Header", summary_file=summary_file)
    write_step_summary("Additional text", summary_file=summary_file)
    assert "## Test Header" in summary_file.read_text(encoding="utf-8")
    assert "Additional text" in summary_file.read_text(encoding="utf-8")

    write_action_outputs(
        {"scan-result": "passed", "findings-count": "0"},
        output_file=output_file,
    )
    content = output_file.read_text(encoding="utf-8")
    assert "scan-result=passed\n" in content
    assert "findings-count=0\n" in content


def test_run_action_clean_fixture(fixtures_dir: Path, tmp_path: Path):
    """Verify full run_action pipeline on clean fixture."""
    clean_dir = fixtures_dir / "clean"
    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"

    env = {
        "INPUT_PATH": str(clean_dir),
        "INPUT_SEVERITY_THRESHOLD": "HIGH",
        "INPUT_CHECK_VULNS": "false",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    exit_code = run_action(environ=env)
    assert exit_code == EXIT_SUCCESS_CLEAN

    # Verify step summary
    summary_text = summary_file.read_text(encoding="utf-8")
    assert "Scan Result: ✅ Passed" in summary_text
    assert "CRITICAL" in summary_text

    # Verify action outputs
    out_text = output_file.read_text(encoding="utf-8")
    assert "scan-result=passed" in out_text
    assert "findings-count=0" in out_text
    assert "report-path=" in out_text

    # Verify report file exists and is valid JSON
    report_line = [line for line in out_text.splitlines() if line.startswith("report-path=")][0]
    report_path = Path(report_line.split("=", 1)[1])
    assert report_path.exists()
    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_data["caulk_version"] == "0.1.0"
    assert report_data["summary"]["total_findings"] == 0


def test_run_action_vulnerable_fixture_fails(fixtures_dir: Path, tmp_path: Path):
    """Verify vulnerable fixture breaches threshold, writes summary, and exits with 1."""
    vuln_dir = fixtures_dir / "vulnerable"
    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"

    env = {
        "INPUT_PATH": str(vuln_dir),
        "INPUT_SEVERITY_THRESHOLD": "HIGH",
        "INPUT_CHECK_VULNS": "false",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    exit_code = run_action(environ=env)
    assert exit_code == EXIT_FINDINGS_BREACH_THRESHOLD

    # Proves summary is written EVEN THOUGH the run failed!
    summary_text = summary_file.read_text(encoding="utf-8")
    assert "Scan Result: ❌ Failed (Threshold: HIGH)" in summary_text
    assert "Breached Findings (HIGH or Higher)" in summary_text

    # Verify outputs
    out_text = output_file.read_text(encoding="utf-8")
    assert "scan-result=failed" in out_text
    assert "findings-count=" in out_text
    assert "findings-count=0" not in out_text


def test_run_action_secret_values_never_printed_in_summary(fixtures_dir: Path, tmp_path: Path):
    """Verify synthetic secret strings never leak into the Markdown summary."""
    vuln_dir = fixtures_dir / "vulnerable"
    summary_file = tmp_path / "summary.md"

    env = {
        "INPUT_PATH": str(vuln_dir),
        "INPUT_SEVERITY_THRESHOLD": "HIGH",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    run_action(environ=env)

    summary_text = summary_file.read_text(encoding="utf-8")

    # Passwords or tokens from synthetic fixture must NOT appear in summary
    assert "N3v3rGu3ssMeP@ss!" not in summary_text
    assert "caulk_test_secret_token_9481948104810481" not in summary_text
    assert "sample_token_fixture_94819481" not in summary_text


def test_run_action_threshold_override_permits_clean(fixtures_dir: Path, tmp_path: Path):
    """Verify that setting threshold to CRITICAL allows HIGH-only findings to pass."""
    proj = tmp_path / "high_only_proj"
    proj.mkdir()
    # Write only a HIGH finding (DEBUG = True in settings.py)
    (proj / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")

    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"

    env = {
        "INPUT_PATH": str(proj),
        "INPUT_SEVERITY_THRESHOLD": "CRITICAL",  # Threshold set higher than HIGH
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    exit_code = run_action(environ=env)
    assert exit_code == EXIT_SUCCESS_CLEAN

    out_text = output_file.read_text(encoding="utf-8")
    assert "scan-result=passed" in out_text


def test_run_action_invalid_inputs(tmp_path: Path):
    """Verify invalid threshold and invalid boolean fail safely with exit code 2."""
    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"
    err_stream = io.StringIO()

    # Bad threshold
    env_bad_thresh = {
        "INPUT_PATH": ".",
        "INPUT_SEVERITY_THRESHOLD": "SUPER_CRITICAL",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
    }
    code = run_action(environ=env_bad_thresh, stderr=err_stream)
    assert code == EXIT_USAGE_ERROR
    assert "scan-result=error" in output_file.read_text(encoding="utf-8")
    assert "Input validation error" in summary_file.read_text(encoding="utf-8")


def test_run_action_missing_directory(tmp_path: Path):
    """Verify non-existent target directory fails safely with exit code 2."""
    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"
    err_stream = io.StringIO()

    non_existent = tmp_path / "does_not_exist_xyz"

    env = {
        "INPUT_PATH": str(non_existent),
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
    }
    code = run_action(environ=env, stderr=err_stream)
    assert code == EXIT_USAGE_ERROR
    assert "Target path does not exist" in summary_file.read_text(encoding="utf-8")
    assert "scan-result=error" in output_file.read_text(encoding="utf-8")


def test_run_action_path_with_spaces(tmp_path: Path):
    """Verify scanning paths with spaces works reliably across platforms."""
    spaced_dir = tmp_path / "dir with spaces" / "sub proj"
    spaced_dir.mkdir(parents=True)
    (spaced_dir / "clean.py").write_text("print('clean')\n", encoding="utf-8")

    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"

    env = {
        "INPUT_PATH": str(spaced_dir),
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    exit_code = run_action(environ=env)
    assert exit_code == EXIT_SUCCESS_CLEAN
    assert "scan-result=passed" in output_file.read_text(encoding="utf-8")


def test_run_action_as_subprocess(fixtures_dir: Path, tmp_path: Path):
    """Verify python -m caulk.action runs as a separate subprocess."""
    clean_dir = fixtures_dir / "clean"
    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"

    env = {
        **subprocess.os.environ,
        "INPUT_PATH": str(clean_dir),
        "INPUT_SEVERITY_THRESHOLD": "HIGH",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    res = subprocess.run(
        [sys.executable, "-m", "caulk.action"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    assert summary_file.exists()
    assert "Scan Result: ✅ Passed" in summary_file.read_text(encoding="utf-8")
    assert "scan-result=passed" in output_file.read_text(encoding="utf-8")


def test_run_action_corrupted_report_handling(
    fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Verify scanner execution error (code 3) if report JSON is corrupted."""
    from caulk.cli import EXIT_EXECUTION_ERROR

    clean_dir = fixtures_dir / "clean"
    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"

    env = {
        "INPUT_PATH": str(clean_dir),
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    # Intercept subprocess.run to write corrupted JSON to the expected report file
    orig_run = subprocess.run

    def mock_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        # Find the --output argument
        if "--output" in cmd:
            out_idx = cmd.index("--output") + 1
            out_path = Path(cmd[out_idx])
            out_path.write_text("CORRUPTED_NOT_JSON!{[[", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, returncode=0)
        return orig_run(cmd, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(subprocess, "run", mock_run)

    exit_code = run_action(environ=env)
    assert exit_code == EXIT_EXECUTION_ERROR
    assert "scan-result=error" in output_file.read_text(encoding="utf-8")
    assert "Failed to parse generated JSON report" in summary_file.read_text(encoding="utf-8")


def test_no_project_scripts_executed(tmp_path: Path):
    """Verify that project setup.py, package.json or other scripts are never executed during scanning."""
    marker_file = tmp_path / "should_never_exist.txt"

    # Malicious/active setup.py that creates marker_file if run
    malicious_setup = f"import os\nwith open(r'{marker_file}', 'w') as f: f.write('PWNED')\n"
    (tmp_path / "setup.py").write_text(malicious_setup, encoding="utf-8")

    # package.json with preinstall script
    package_json = {
        "name": "untrusted-pkg",
        "scripts": {
            "preinstall": f"echo PWNED > {marker_file}",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(package_json), encoding="utf-8")

    summary_file = tmp_path / "summary.md"
    output_file = tmp_path / "output.txt"

    env = {
        "INPUT_PATH": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    exit_code = run_action(environ=env)
    assert exit_code in (EXIT_SUCCESS_CLEAN, EXIT_FINDINGS_BREACH_THRESHOLD)

    # CRITICAL: Verify marker file was NEVER created
    assert not marker_file.exists(), "Target project script was executed!"
