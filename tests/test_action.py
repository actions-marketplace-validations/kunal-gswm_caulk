"""Comprehensive unit and integration tests for Caulk GitHub Action."""

from __future__ import annotations

import io
import json
import re
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
    EXIT_EXECUTION_ERROR,
    EXIT_FINDINGS_BREACH_THRESHOLD,
    EXIT_SUCCESS_CLEAN,
    EXIT_USAGE_ERROR,
)
from caulk.models import Severity
from caulk.reporting.summary import (
    escape_markdown_table_cell,
    format_markdown_code_span,
    format_markdown_fenced_code,
    format_table_code_cell,
    generate_error_summary,
    generate_step_summary,
    sanitize_single_line_text,
)


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

    # Verify early input validation step occurs before setup-python
    val_idx = content.find("name: Validate action inputs")
    setup_idx = content.find("name: Set up Python runtime")
    assert val_idx != -1, "Validate action inputs step missing in action.yml"
    assert setup_idx != -1, "Set up Python runtime step missing in action.yml"
    assert val_idx < setup_idx, "Early validation step must execute before actions/setup-python"

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
    target, thresh, check_v, scan_h = validate_action_inputs(".", "HIGH", "false")
    assert thresh == Severity.HIGH
    assert check_v is False
    assert scan_h is False

    # Valid custom severity (case-insensitive) and scan-history
    _, thresh_crit, _, scan_h_true = validate_action_inputs(
        ".", "critical", "false", raw_scan_history="true"
    )
    assert thresh_crit == Severity.CRITICAL
    assert scan_h_true is True

    # Invalid severity
    with pytest.raises(ValueError, match="Invalid severity-threshold 'INVALID'"):
        validate_action_inputs(".", "INVALID", "false")

    # Invalid check-vulns
    with pytest.raises(ValueError, match="Invalid boolean value 'not_a_bool'"):
        validate_action_inputs(".", "HIGH", "not_a_bool")

    # Invalid scan-history
    with pytest.raises(ValueError, match="Invalid boolean value 'invalid_history'"):
        validate_action_inputs(".", "HIGH", "false", raw_scan_history="invalid_history")

    # Unsupported Python version input
    with pytest.raises(ValueError, match="Unsupported Python version '3.9'"):
        validate_action_inputs(".", "HIGH", "false", raw_python_version="3.9")


def test_step_summary_generation_clean():
    """Verify step summary format for a completely clean scan."""
    mock_report = {
        "caulk_version": "0.2.0",
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
        "caulk_version": "0.2.0",
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
        "caulk_version": "0.2.0",
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
    assert report_data["caulk_version"] == "0.2.0"
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


def test_sanitize_single_line_text():
    """Verify single-line text sanitization strips control chars and collapses spaces."""
    assert sanitize_single_line_text("hello\nworld") == "hello world"
    assert sanitize_single_line_text("hello\r\nworld") == "hello world"
    assert sanitize_single_line_text("hello\tworld") == "hello world"
    assert sanitize_single_line_text("hello\x00\x08world\x1b") == "helloworld"
    assert sanitize_single_line_text("   spaced   out   ") == "spaced out"
    assert sanitize_single_line_text("") == ""


def test_escape_markdown_table_cell():
    """Verify table cell escaping prevents column splits, active HTML, and Markdown injection."""
    # Pipe delimiter escaping
    assert escape_markdown_table_cell("col1|col2") == "col1\\|col2"

    # HTML tag neutralisation
    assert (
        escape_markdown_table_cell("<script>alert('xss')</script>")
        == "&lt;script&gt;alert('xss')&lt;/script&gt;"
    )
    assert (
        escape_markdown_table_cell("<img src=x onerror=alert(1)>")
        == "&lt;img src=x onerror=alert(1)&gt;"
    )

    # Markdown links and images neutralized
    assert (
        escape_markdown_table_cell("[Click Me](https://evil.com)")
        == "\\[Click Me\\](https://evil.com)"
    )
    assert (
        escape_markdown_table_cell("![Badge](https://evil.com/leak.png)")
        == "!\\[Badge\\](https://evil.com/leak.png)"
    )

    # Newlines replaced to prevent row breakout
    assert (
        escape_markdown_table_cell("Title\n### Scan Result: ✅ Passed")
        == "Title ### Scan Result: ✅ Passed"
    )

    # Formatting delimiters escaped
    assert (
        escape_markdown_table_cell("*bold* and _italic_ and `code`")
        == "\\*bold\\* and \\_italic\\_ and \\`code\\`"
    )

    # Legitimate ordinary text remains readable
    assert escape_markdown_table_cell("AWS Access Key ID Detected") == "AWS Access Key ID Detected"


def test_format_markdown_code_span():
    """Verify inline code span formatting dynamically handles backticks."""
    # Ordinary string
    assert format_markdown_code_span("app/main.py") == "`app/main.py`"

    # Single backtick requires double-backtick wrapping with spaces
    assert format_markdown_code_span("evil`path.py") == "`` evil`path.py ``"

    # Triple backticks require 4-backtick wrapping with spaces
    assert format_markdown_code_span("evil```path.py") == "```` evil```path.py ````"

    # Leading/trailing backtick handled safely
    assert format_markdown_code_span("`leading.py") == "`` `leading.py ``"

    # Empty string
    assert format_markdown_code_span("") == "``"


def test_format_table_code_cell():
    """Verify code cell in GFM tables escapes pipes and handles backticks."""
    # Normal location
    assert format_table_code_cell("src/main.py:42") == "`src/main.py:42`"

    # Pipe in file path must be escaped as \| so table doesn't split
    assert format_table_code_cell("src/evil|file.py:1") == "`src/evil\\|file.py:1`"

    # Backtick in file path
    assert format_table_code_cell("src/evil`file.py:1") == "`` src/evil`file.py:1 ``"

    # Newlines stripped from file path
    assert (
        format_table_code_cell("src/evil\n### Fake Header\n.py:1")
        == "`src/evil ### Fake Header .py:1`"
    )


def test_format_markdown_fenced_code():
    """Verify fenced code blocks dynamically scale fence length to prevent breakout."""
    # Standard content gets 3 backticks
    normal = format_markdown_fenced_code("line 1\nline 2", "bash")
    assert normal.startswith("```bash\n")
    assert normal.endswith("\n```")

    # Content with 3 backticks gets 4 backticks
    payload_3 = "Error:\n```\n### Scan Result: ✅ Passed\n```"
    fenced_4 = format_markdown_fenced_code(payload_3)
    assert fenced_4.startswith("````\n")
    assert fenced_4.endswith("\n````")
    # Verify the inner 3 backticks cannot close the 4-backtick fence
    assert "```\n### Scan Result: ✅ Passed\n```" in fenced_4

    # Content with 5 backticks gets 6 backticks
    payload_5 = "Error with ````` backticks"
    fenced_6 = format_markdown_fenced_code(payload_5)
    assert fenced_6.startswith("``````\n")
    assert fenced_6.endswith("\n``````")


def test_step_summary_adversarial_findings_table():
    """Verify step summary resists Markdown table injection and malicious payloads."""
    mock_report = {
        "caulk_version": "0.2.0",
        "target_path": "adversarial-repo",
        "summary": {
            "files_scanned": 10,
            "files_skipped": 0,
            "duration_seconds": 0.05,
            "total_findings": 2,
            "severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "checks_not_performed": ["Offline mode\n### Fake Header"],
        },
        "findings": [
            {
                "rule_id": "RULE|WITH|PIPES",
                "title": "Title with | pipe and <script>alert(1)</script> and [link](https://evil.com)",
                "severity": "CRITICAL",
                "category": "SECRET | INJECTED",
                "file_path": "evil|path`with`backticks\n### Scan Result: ✅ Passed\n.py",
                "line_number": 42,
                "evidence": "should_be_omitted",
            },
            {
                "rule_id": "SEC001",
                "title": "Fake Passed Section\r\n\r\n### Scan Result: ✅ Passed\r\n\r\nAll good!",
                "severity": "HIGH",
                "category": "INJECTION",
                "file_path": "normal_file.py",
                "line_number": 1,
                "evidence": "should_be_omitted",
            },
        ],
    }

    summary = generate_step_summary(mock_report, threshold=Severity.HIGH)

    # 1. Verify true scan status remains Failed and was not subverted
    assert "Scan Result: ❌ Failed (Threshold: HIGH)" in summary

    # 2. Verify no active forged passed header exists
    lines = summary.splitlines()
    header_lines = [line for line in lines if line.startswith("### ")]
    assert len(header_lines) == 1, f"Expected exactly 1 level-3 header, found: {header_lines}"
    assert header_lines[0] == "### Scan Result: ❌ Failed (Threshold: HIGH)"

    # 3. Verify HTML tags are sanitized
    assert "<script>" not in summary
    assert "&lt;script&gt;" in summary

    # 4. Verify link syntax is neutralized
    assert "[link](https://evil.com)" not in summary
    assert "\\[link\\](https://evil.com)" in summary

    # 5. Verify every table row has exactly 5 columns (GFM table format: | c1 | c2 | c3 | c4 | c5 |)
    table_rows = [line for line in lines if line.startswith("| `") or line.startswith("| ``")]
    assert len(table_rows) == 2, f"Expected 2 finding table rows, got: {table_rows}"
    for row in table_rows:
        # Split on unescaped pipe (preceded by odd/even backslashes)
        # In a hardened row, literal pipes are escaped with backslash (\ |)
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", row) if c.strip()]
        assert len(cells) == 5, f"Row column count disrupted by injection payload: {row} -> {cells}"

    # 6. Verify advisory notice sanitized newlines
    assert "Offline mode ### Fake Header" in summary

    # 7. Verify raw evidence was not included
    assert "should_be_omitted" not in summary


def test_step_summary_adversarial_target_path():
    """Verify target path cannot inject headers or break out of blockquotes."""
    mock_report = {
        "caulk_version": "0.2.0",
        "target_path": "adversarial-repo\n\n### Scan Result: ✅ Passed\n\n",
        "summary": {
            "files_scanned": 1,
            "files_skipped": 0,
            "duration_seconds": 0.01,
            "total_findings": 1,
            "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        },
        "findings": [
            {
                "rule_id": "SEC001",
                "title": "Hardcoded Key",
                "severity": "CRITICAL",
                "category": "SECRET",
                "file_path": "config.py",
                "line_number": 1,
                "evidence": "raw",
            }
        ],
    }

    summary = generate_step_summary(mock_report, threshold=Severity.HIGH)

    # Injected header in target path must be neutralized into a single line
    lines = summary.splitlines()
    header_lines = [line for line in lines if line.startswith("### ")]
    assert len(header_lines) == 1
    assert header_lines[0] == "### Scan Result: ❌ Failed (Threshold: HIGH)"

    # Verify target path is properly formatted inside inline code span
    assert "`adversarial-repo ### Scan Result: ✅ Passed`" in summary


def test_error_summary_fence_breakout():
    """Verify error summary prevents premature code fence termination."""
    attack_payload = (
        "Execution failure:\n"
        "```\n"
        "### Scan Result: ✅ Passed (Threshold: HIGH)\n"
        "Everything passed successfully!\n"
        "```\n"
    )

    summary = generate_error_summary(attack_payload, error_code=3)

    # Summary must have error header
    assert "## ⚠️ Caulk Security Scan — Scanner Execution Error" in summary

    # The outer code fence must use 4 backticks, protecting the inner 3 backticks
    assert "````" in summary

    # Find the outermost fence delimiters
    fence_pattern = re.compile(r"^(`{3,})", re.MULTILINE)
    fences = list(fence_pattern.finditer(summary))
    assert len(fences) >= 2, "Expected opening and closing code fence"
    open_fence = fences[0]
    close_fence = fences[-1]
    assert len(open_fence.group(1)) >= 4, (
        "Fence should use at least 4 backticks to encompass payload"
    )
    assert len(close_fence.group(1)) == len(open_fence.group(1)), (
        "Closing fence must match opening fence length"
    )

    # Text outside code fence must NOT contain the forged scan result
    outside_text = summary[: open_fence.start()] + summary[close_fence.end() :]
    outside_headings = [line for line in outside_text.splitlines() if line.startswith("### ")]
    assert outside_headings == ["### Error Details"], (
        f"Injected heading broke out of code fence: {outside_headings}"
    )
    assert "Scan Result: ✅ Passed" not in outside_text


def test_action_input_validation_python_versions():
    """Verify Python version input validation rejects unsupported or malformed versions."""
    # Supported and tested versions
    for v in ["3.11", "3.12", "3.13", "3.11.9", "3.12.1", "3.13.0"]:
        _, thresh, _, _ = validate_action_inputs(".", "HIGH", "false", raw_python_version=v)
        assert thresh == Severity.HIGH

    # Unsupported Python versions (outside explicitly tested 3.11, 3.12, 3.13)
    for v in ["3.14", "3.15", "3.10", "3.9", "3.8", "2.7"]:
        with pytest.raises(ValueError, match="Unsupported Python version"):
            validate_action_inputs(".", "HIGH", "false", raw_python_version=v)

    # Malformed / malicious version strings
    for v in ["invalid", "3.x", "3.12; rm -rf /", "not_a_version"]:
        with pytest.raises(ValueError, match="Invalid python-version"):
            validate_action_inputs(".", "HIGH", "false", raw_python_version=v)


def test_generate_step_summary_incomplete_status() -> None:
    """Verify generate_step_summary renders incomplete status when is_complete is False."""
    report_data = {
        "caulk_version": "0.3.0",
        "target_path": "repo",
        "findings": [],
        "errors": ["Skipped oversized blob 1234abcd (150000 bytes)"],
        "summary": {
            "is_complete": False,
            "scan_mode": "git_history",
            "commits_scanned": 5,
            "blobs_scanned": 10,
            "blobs_skipped_oversized": 1,
            "blobs_skipped_binary": 0,
            "files_skipped": 1,
            "total_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "checks_not_performed": ["1 oversized blob(s) exceeded max size and were skipped."],
        },
    }

    summary_md = generate_step_summary(report_data, threshold=Severity.HIGH)
    assert "### Scan Result: ⚠️ Incomplete Inspection (Threshold: HIGH)" in summary_md
    assert "Scan Result: ✅ Passed" not in summary_md
    assert "The inspection is **incomplete** and cannot be considered clean." in summary_md
    assert "1 oversized" in summary_md
    assert "Skipped oversized blob" in summary_md


def test_action_history_scan_incomplete_fails(tmp_path: Path) -> None:
    """Verify action fails with code 3, error status, and step summary when history scan is incomplete."""
    import stat

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Tester"], cwd=repo, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    (repo / "clean.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "clean.py"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True)

    blob_sha = subprocess.run(
        ["git", "rev-parse", "HEAD:clean.py"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    obj_file = repo / ".git" / "objects" / blob_sha[:2] / blob_sha[2:]
    obj_file.chmod(stat.S_IWRITE | stat.S_IREAD)
    obj_file.write_bytes(b"CORRUPTED_OBJECT_DATA")

    summary_file = tmp_path / "step_summary.md"
    output_file = tmp_path / "action_output.txt"

    env = {
        "INPUT_PATH": str(repo),
        "INPUT_SEVERITY_THRESHOLD": "HIGH",
        "INPUT_CHECK_VULNS": "false",
        "INPUT_SCAN_HISTORY": "true",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    ret = run_action(environ=env)
    assert ret == EXIT_EXECUTION_ERROR

    outputs = output_file.read_text(encoding="utf-8")
    assert "scan-result=error" in outputs
    assert "scan-result=passed" not in outputs

    summary = summary_file.read_text(encoding="utf-8")
    assert "Scan Result: ✅ Passed" not in summary
    assert "Incomplete" in summary or "Execution Error" in summary


def test_action_history_scan_clean(tmp_path: Path) -> None:
    """Verify action passes with code 0, passed status, and step summary when history scan is clean."""
    repo = tmp_path / "clean_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Tester"], cwd=repo, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    (repo / "clean.py").write_text("print('clean code')\n")
    subprocess.run(["git", "add", "clean.py"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial clean"], cwd=repo, check=True, capture_output=True
    )

    summary_file = tmp_path / "step_summary_clean.md"
    output_file = tmp_path / "action_output_clean.txt"

    env = {
        "INPUT_PATH": str(repo),
        "INPUT_SEVERITY_THRESHOLD": "HIGH",
        "INPUT_CHECK_VULNS": "false",
        "INPUT_SCAN_HISTORY": "true",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    ret = run_action(environ=env)
    assert ret == EXIT_SUCCESS_CLEAN

    outputs = output_file.read_text(encoding="utf-8")
    assert "scan-result=passed" in outputs
    assert "findings-count=0" in outputs

    summary = summary_file.read_text(encoding="utf-8")
    assert "Scan Result: ✅ Passed" in summary


def test_action_history_scan_shallow_clone_fails_closed(tmp_path: Path) -> None:
    """Verify action fails closed (exit code 3) on shallow clone when scan-history is true."""
    origin = tmp_path / "origin_action"
    origin.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=origin, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Action Tester"], cwd=origin, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "tester@example.com"],
        cwd=origin,
        check=True,
        capture_output=True,
    )
    (origin / "clean.py").write_text("print('clean')\n")
    subprocess.run(["git", "add", "clean.py"], cwd=origin, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=origin, check=True, capture_output=True)

    shallow_repo = tmp_path / "shallow_action"
    subprocess.run(
        ["git", "clone", "--depth", "1", origin.resolve().as_uri(), str(shallow_repo)],
        check=True,
        capture_output=True,
    )

    summary_file = tmp_path / "step_summary_shallow.md"
    output_file = tmp_path / "action_output_shallow.txt"

    env = {
        "INPUT_PATH": str(shallow_repo),
        "INPUT_SEVERITY_THRESHOLD": "HIGH",
        "INPUT_CHECK_VULNS": "false",
        "INPUT_SCAN_HISTORY": "true",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    ret = run_action(environ=env)
    assert ret == EXIT_EXECUTION_ERROR

    outputs = output_file.read_text(encoding="utf-8")
    assert "scan-result=error" in outputs
    assert "scan-result=passed" not in outputs

    summary = summary_file.read_text(encoding="utf-8")
    assert "Scan Result: ✅ Passed" not in summary
    assert "Scan Result: ⚠️ Incomplete Inspection" in summary
    assert "Target repository is a shallow clone" in summary
    assert "fetch-depth: 0" in summary


def test_action_working_tree_scan_shallow_clone_succeeds(tmp_path: Path) -> None:
    """Verify working tree scan (scan-history=false) succeeds on shallow clones without restriction."""
    origin = tmp_path / "origin_wt"
    origin.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=origin, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Action Tester"], cwd=origin, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "tester@example.com"],
        cwd=origin,
        check=True,
        capture_output=True,
    )
    (origin / "clean.py").write_text("print('clean code')\n")
    subprocess.run(["git", "add", "clean.py"], cwd=origin, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=origin, check=True, capture_output=True)

    shallow_repo = tmp_path / "shallow_wt"
    subprocess.run(
        ["git", "clone", "--depth", "1", origin.resolve().as_uri(), str(shallow_repo)],
        check=True,
        capture_output=True,
    )

    summary_file = tmp_path / "step_summary_wt.md"
    output_file = tmp_path / "action_output_wt.txt"

    env = {
        "INPUT_PATH": str(shallow_repo),
        "INPUT_SEVERITY_THRESHOLD": "HIGH",
        "INPUT_CHECK_VULNS": "false",
        "INPUT_SCAN_HISTORY": "false",
        "GITHUB_STEP_SUMMARY": str(summary_file),
        "GITHUB_OUTPUT": str(output_file),
        "RUNNER_TEMP": str(tmp_path),
    }

    ret = run_action(environ=env)
    assert ret == EXIT_SUCCESS_CLEAN

    outputs = output_file.read_text(encoding="utf-8")
    assert "scan-result=passed" in outputs
    assert "findings-count=0" in outputs

    summary = summary_file.read_text(encoding="utf-8")
    assert "Scan Result: ✅ Passed" in summary
