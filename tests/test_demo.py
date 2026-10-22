"""Automated regression tests for the reproducible developer demo."""

from pathlib import Path

from typer.testing import CliRunner

from caulk.cli import (
    EXIT_FINDINGS_BREACH_THRESHOLD,
    EXIT_SUCCESS_CLEAN,
    app,
)


def test_demo_vulnerable_project():
    """Verify examples/demo/vulnerable triggers SAST001, SAST002, SEC002, and CFG001."""
    demo_vulnerable = Path("examples/demo/vulnerable")
    assert demo_vulnerable.is_dir(), "examples/demo/vulnerable directory must exist"

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(demo_vulnerable), "--format", "json"])
    assert result.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD

    import json

    data = json.loads(result.stdout)
    findings = data["findings"]
    rule_ids = {f["rule_id"] for f in findings}

    assert "SEC002" in rule_ids
    assert "CFG001" in rule_ids
    assert "SAST001" in rule_ids
    assert "SAST002" in rule_ids
    assert len(findings) == 4

    # Verify secret evidence sanitization
    sec_finding = next(f for f in findings if f["rule_id"] == "SEC002")
    assert "AKIAIOSFODNN7EXAMPLE" not in sec_finding["evidence"]
    assert "AKIA************MPLE" in sec_finding["evidence"]


def test_demo_safe_project():
    """Verify examples/demo/safe produces zero findings and clean exit code 0."""
    demo_safe = Path("examples/demo/safe")
    assert demo_safe.is_dir(), "examples/demo/safe directory must exist"

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(demo_safe), "--format", "json"])
    assert result.exit_code == EXIT_SUCCESS_CLEAN

    import json

    data = json.loads(result.stdout)
    assert len(data["findings"]) == 0
    assert data["summary"]["is_complete"] is True


def test_demo_category_filter():
    """Verify --category SAST on demo/vulnerable isolates SAST001 and SAST002."""
    demo_vulnerable = Path("examples/demo/vulnerable")
    runner = CliRunner()
    result = runner.invoke(
        app, ["scan", str(demo_vulnerable), "--category", "SAST", "--format", "json"]
    )
    assert result.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD

    import json

    data = json.loads(result.stdout)
    findings = data["findings"]
    rule_ids = {f["rule_id"] for f in findings}
    assert rule_ids == {"SAST001", "SAST002"}
    assert len(findings) == 2


def test_demo_disable_rule():
    """Verify --disable SAST001 suppresses SAST001 while retaining other rules."""
    demo_vulnerable = Path("examples/demo/vulnerable")
    runner = CliRunner()
    result = runner.invoke(
        app, ["scan", str(demo_vulnerable), "--disable", "SAST001", "--format", "json"]
    )
    assert result.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD

    import json

    data = json.loads(result.stdout)
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "SAST001" not in rule_ids
    assert {"SEC002", "CFG001", "SAST002"} == rule_ids
    assert len(data["findings"]) == 3
