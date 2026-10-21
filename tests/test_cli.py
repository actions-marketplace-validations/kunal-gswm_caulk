"""Tests for Caulk command-line interface and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from caulk.cli import (
    EXIT_FINDINGS_BREACH_THRESHOLD,
    EXIT_SUCCESS_CLEAN,
    EXIT_USAGE_ERROR,
    app,
)


def test_cli_help(cli_runner: CliRunner):
    result = cli_runner.invoke(app, ["--help"])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert "scan" in result.output
    assert "init" in result.output
    assert "rules" in result.output
    assert "history" in result.output


def test_cli_history_help(cli_runner: CliRunner):
    result = cli_runner.invoke(app, ["history", "--help"])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert "scan" in result.output

    res_scan = cli_runner.invoke(app, ["history", "scan", "--help"])
    assert res_scan.exit_code == EXIT_SUCCESS_CLEAN
    assert "--max-depth" in res_scan.output
    assert "--severity-threshold" in res_scan.output
    assert "--max-blob-size" in res_scan.output


def test_cli_version(cli_runner: CliRunner):
    result = cli_runner.invoke(app, ["--version"])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert "caulk-security v0.2.0" in result.output


def test_distribution_console_scripts():
    """Verify 'caulk-security' is the sole registered console entrypoint and 'caulk' is not registered."""
    import importlib.metadata

    eps = importlib.metadata.entry_points(group="console_scripts")
    caulk_eps = {ep.name: ep.value for ep in eps if "caulk" in ep.name}
    assert "caulk-security" in caulk_eps
    assert caulk_eps["caulk-security"] == "caulk.cli:app"
    assert "caulk" not in caulk_eps


def test_cli_scan_clean(cli_runner: CliRunner, fixtures_dir: Path):
    clean_dir = fixtures_dir / "clean"
    result = cli_runner.invoke(app, ["scan", str(clean_dir)])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert "Scan Clean" in result.output


def test_cli_scan_vulnerable_exit_code(cli_runner: CliRunner, fixtures_dir: Path):
    vuln_dir = fixtures_dir / "vulnerable"
    result = cli_runner.invoke(app, ["scan", str(vuln_dir)])
    # Default failure threshold is HIGH, vulnerable fixture has CRITICAL and HIGH findings
    assert result.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD
    assert "Findings (" in result.output


def test_cli_scan_threshold_override(cli_runner: CliRunner, tmp_path: Path):
    # Project with only a LOW finding (e.g. unpinned package.json without lockfile)
    (tmp_path / "package.json").write_text('{"dependencies": {"test": "*"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {}}', encoding="utf-8"
    )

    # When threshold is HIGH, LOW finding does not trigger exit code 1
    res1 = cli_runner.invoke(app, ["scan", str(tmp_path), "--severity-threshold", "HIGH"])
    assert res1.exit_code == EXIT_SUCCESS_CLEAN

    # When threshold is LOW, LOW finding triggers exit code 1
    res2 = cli_runner.invoke(app, ["scan", str(tmp_path), "--severity-threshold", "LOW"])
    assert res2.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD


def test_cli_scan_nonexistent_dir(cli_runner: CliRunner):
    result = cli_runner.invoke(app, ["scan", "directory_does_not_exist_xyz123"])
    assert result.exit_code == EXIT_USAGE_ERROR
    assert "Error:" in result.output


def test_cli_scan_format_json(cli_runner: CliRunner, fixtures_dir: Path):
    clean_dir = fixtures_dir / "clean"
    result = cli_runner.invoke(app, ["scan", str(clean_dir), "--format", "json"])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    parsed = json.loads(result.output)
    assert parsed["caulk_version"] == "0.2.0"
    assert "findings" in parsed
    assert "summary" in parsed


def test_cli_scan_output_file(cli_runner: CliRunner, fixtures_dir: Path, tmp_path: Path):
    clean_dir = fixtures_dir / "clean"
    out_file = tmp_path / "out-report.json"
    result = cli_runner.invoke(app, ["scan", str(clean_dir), "--output", str(out_file)])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert out_file.exists()
    parsed = json.loads(out_file.read_text(encoding="utf-8"))
    assert parsed["caulk_version"] == "0.2.0"


def test_cli_rules_list(cli_runner: CliRunner):
    result = cli_runner.invoke(app, ["rules", "list"])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert "SEC001" in result.output
    assert "CFG001" in result.output


def test_cli_rules_list_filtered(cli_runner: CliRunner):
    result = cli_runner.invoke(app, ["rules", "list", "--category", "SECRET"])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert "SEC001" in result.output
    assert "CFG001" not in result.output


def test_cli_init_command(cli_runner: CliRunner, tmp_path: Path):
    target_config = tmp_path / ".caulk.toml"
    res1 = cli_runner.invoke(app, ["init", "--path", str(target_config)])
    assert res1.exit_code == EXIT_SUCCESS_CLEAN
    assert target_config.exists()

    # Re-running without --force must fail with EXIT_USAGE_ERROR
    res2 = cli_runner.invoke(app, ["init", "--path", str(target_config)])
    assert res2.exit_code == EXIT_USAGE_ERROR

    # Re-running with --force succeeds
    res3 = cli_runner.invoke(app, ["init", "--path", str(target_config), "--force"])
    assert res3.exit_code == EXIT_SUCCESS_CLEAN


def test_executable_invocation(tmp_path: Path):
    """Verify that caulk-security executable can be invoked as an external process."""
    import shutil
    import subprocess
    import sys

    exe = shutil.which("caulk-security")
    if not exe:
        candidate = Path(sys.executable).parent / (
            "caulk-security.exe" if sys.platform == "win32" else "caulk-security"
        )
        if candidate.exists():
            exe = str(candidate)

    if not exe:
        import pytest

        pytest.skip("caulk-security executable not found in current environment")

    # 1. Test --version
    res_version = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    assert res_version.returncode == 0
    assert "caulk-security v0.2.0" in res_version.stdout

    # 2. Test --help
    res_help = subprocess.run([exe, "--help"], capture_output=True, text=True, check=False)
    assert res_help.returncode == 0
    assert "scan" in res_help.stdout

    # 3. Test clean scan via executable
    clean_dir = tmp_path / "clean_proj"
    clean_dir.mkdir()
    (clean_dir / "clean.py").write_text("print('hello')", encoding="utf-8")
    res_scan = subprocess.run(
        [exe, "scan", str(clean_dir)], capture_output=True, text=True, check=False
    )
    assert res_scan.returncode == 0
    assert "Scan Clean" in res_scan.stdout
