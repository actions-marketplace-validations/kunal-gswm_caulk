"""Tests for report rendering and JSON output generation."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console

from caulk.models import Finding, ScanResult, ScanSummary, Severity
from caulk.reporting.json_report import generate_json_report, write_json_report
from caulk.reporting.terminal import render_terminal_report


def test_terminal_report_clean():
    """Terminal renderer handles clean scans with a disclaimer."""
    output = StringIO()
    test_console = Console(file=output, color_system=None, width=120)

    result = ScanResult(
        caulk_version="0.1.0",
        target_path="/test/clean",
        findings=[],
        summary=ScanSummary(files_scanned=5, files_skipped=1, total_findings=0),
    )

    render_terminal_report(result, console=test_console)
    text = output.getvalue()

    assert "CAULK v0.1.0" in text
    assert "Scan Clean" in text
    assert "A clean scan does not prove an application is secure" in text


def test_terminal_report_with_findings(sample_finding: Finding):
    output = StringIO()
    test_console = Console(file=output, color_system=None, width=120)

    summary = ScanSummary(
        files_scanned=10,
        files_skipped=2,
        total_findings=1,
        severity_counts={Severity.CRITICAL.value: 1},
    )
    result = ScanResult(
        caulk_version="0.1.0",
        target_path="/test/app",
        findings=[sample_finding],
        summary=summary,
    )

    render_terminal_report(result, console=test_console)
    text = output.getvalue()

    assert "CRITICAL" in text
    assert "AWS Access Key ID Detected" in text
    assert "Where:" in text
    assert "src/config.py:42" in text
    assert "What was found:" in text
    assert "Why it matters:" in text
    assert "What to do:" in text
    assert "Finding Severity Summary" in text


def test_json_report_generation(sample_finding: Finding, tmp_path: Path):
    result = ScanResult(
        caulk_version="0.1.0",
        target_path=str(tmp_path),
        findings=[sample_finding],
        summary=ScanSummary(total_findings=1),
    )

    json_str = generate_json_report(result)
    parsed = json.loads(json_str)

    assert parsed["caulk_version"] == "0.1.0"
    assert len(parsed["findings"]) == 1
    f = parsed["findings"][0]
    assert f["rule_id"] == "SEC002"
    assert f["severity"] == "CRITICAL"
    assert f["confidence"] == "HIGH"
    assert f["file_path"] == "src/config.py"
    assert f["line_number"] == 42
    assert "AKIA************TEST" in f["evidence"]

    # File output
    out_file = tmp_path / "report.json"
    write_json_report(result, out_file)
    assert out_file.exists()
    assert json.loads(out_file.read_text(encoding="utf-8")) == parsed
