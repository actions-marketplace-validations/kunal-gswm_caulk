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


def test_cli_version(cli_runner: CliRunner):
    result = cli_runner.invoke(app, ["--version"])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert "caulk v0.1.0" in result.output


def test_distribution_console_scripts():
    """Verify both 'caulk' and 'caulk-security' console entrypoints are registered."""
    import importlib.metadata

    eps = importlib.metadata.entry_points(group="console_scripts")
    caulk_eps = {ep.name: ep.value for ep in eps if "caulk" in ep.name}
    assert caulk_eps.get("caulk") == "caulk.cli:app"
    assert caulk_eps.get("caulk-security") == "caulk.cli:app"


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
    assert parsed["caulk_version"] == "0.1.0"
    assert "findings" in parsed
    assert "summary" in parsed


def test_cli_scan_output_file(cli_runner: CliRunner, fixtures_dir: Path, tmp_path: Path):
    clean_dir = fixtures_dir / "clean"
    out_file = tmp_path / "out-report.json"
    result = cli_runner.invoke(app, ["scan", str(clean_dir), "--output", str(out_file)])
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert out_file.exists()
    parsed = json.loads(out_file.read_text(encoding="utf-8"))
    assert parsed["caulk_version"] == "0.1.0"


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
