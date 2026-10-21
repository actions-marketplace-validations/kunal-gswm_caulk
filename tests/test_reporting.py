"""Tests for report rendering and JSON output generation."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console

from caulk.models import (
    Confidence,
    Finding,
    FindingCategory,
    FindingStatus,
    ScanResult,
    ScanSummary,
    Severity,
)
from caulk.reporting.json_report import generate_json_report, write_json_report
from caulk.reporting.terminal import render_terminal_report


def test_terminal_report_clean():
    """Terminal renderer handles clean scans with a disclaimer."""
    output = StringIO()
    test_console = Console(file=output, color_system=None, width=120)

    result = ScanResult(
        caulk_version="0.2.0",
        target_path="/test/clean",
        findings=[],
        summary=ScanSummary(files_scanned=5, files_skipped=1, total_findings=0),
    )

    render_terminal_report(result, console=test_console)
    text = output.getvalue()

    assert "CAULK v0.2.0" in text
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
        caulk_version="0.2.0",
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
        caulk_version="0.2.0",
        target_path=str(tmp_path),
        findings=[sample_finding],
        summary=ScanSummary(total_findings=1),
    )

    json_str = generate_json_report(result)
    parsed = json.loads(json_str)

    assert parsed["caulk_version"] == "0.2.0"
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


def test_terminal_report_historical():
    """Verify terminal renderer formats historical findings with commit coordinates."""
    output = StringIO()
    test_console = Console(file=output, color_system=None, width=120)

    finding = Finding(
        rule_id="SEC002",
        title="AWS Access Key ID Detected",
        description="Key found in past commit",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=FindingCategory.SECRET,
        file_path="src/old_auth.py",
        line_number=10,
        evidence="AWS Key detected: AKIA************MPLE",
        impact="Compromise",
        remediation="1. HISTORICAL EXPOSURE: Rotate now.",
        status=FindingStatus.HISTORICAL,
        commit_sha="1234567890abcdef1234567890abcdef12345678",
        commit_author="Jane Doe <jane@example.com>",
        commit_timestamp="2026-10-21T10:00:00Z",
        commit_subject="Add old auth config",
    )

    summary = ScanSummary(
        scan_mode="git_history",
        commits_scanned=15,
        blobs_scanned=45,
        blobs_cached=10,
        refs_scanned=["refs/heads/main", "HEAD"],
        total_findings=1,
        severity_counts={Severity.CRITICAL.value: 1},
    )

    result = ScanResult(
        caulk_version="0.2.0",
        target_path="/test/repo",
        findings=[finding],
        summary=summary,
    )

    render_terminal_report(result, console=test_console)
    text = output.getvalue()

    assert "Commits inspected: 15" in text
    assert "Blobs inspected: 45" in text
    assert "Blobs cached: 10" in text
    assert "Refs inspected: refs/heads/main, HEAD" in text
    assert "[HISTORICAL]" in text
    assert "Commit: 12345678 (1234567890abcdef1234567890abcdef12345678)" in text
    assert "Author: Jane Doe <jane@example.com>" in text
    assert "Date:   2026-10-21T10:00:00Z" in text
    assert "Subject: Add old auth config" in text


def test_terminal_report_incomplete_with_findings(sample_finding: Finding):
    """Terminal renderer displays Scan Incomplete panel even when findings exist."""
    output = StringIO()
    test_console = Console(file=output, color_system=None, width=120)

    summary = ScanSummary(
        files_scanned=10,
        files_skipped=2,
        total_findings=1,
        severity_counts={Severity.CRITICAL.value: 1},
        is_complete=False,
    )
    result = ScanResult(
        caulk_version="0.2.0",
        target_path="/test/app",
        findings=[sample_finding],
        summary=summary,
        errors=["AST parsing failed for app/bad.py: syntax error on line 5"],
    )

    render_terminal_report(result, console=test_console)
    text = output.getvalue()

    assert "Scan Incomplete" in text
    assert "The scan was INCOMPLETE" in text
    assert "Findings (1):" in text
    assert "CRITICAL" in text
    assert "Scan Warnings / Non-fatal Errors:" in text
    assert "AST parsing failed for app/bad.py: syntax error on line 5" in text


def test_terminal_report_incomplete_without_findings():
    """Terminal renderer displays Scan Incomplete and suppresses Scan Clean when scan is incomplete."""
    output = StringIO()
    test_console = Console(file=output, color_system=None, width=120)

    summary = ScanSummary(
        files_scanned=5,
        files_skipped=1,
        total_findings=0,
        is_complete=False,
    )
    result = ScanResult(
        caulk_version="0.2.0",
        target_path="/test/clean",
        findings=[],
        summary=summary,
        errors=["AST parsing failed for broken.py: RecursionError"],
    )

    render_terminal_report(result, console=test_console)
    text = output.getvalue()

    assert "Scan Incomplete" in text
    assert "Scan Clean" not in text
    assert "cannot" in text and "clean" in text


def test_step_summary_incomplete_with_breach(sample_finding: Finding):
    """Step summary includes incomplete warning notice when findings also breach threshold."""
    from caulk.reporting.summary import generate_step_summary

    report_data = {
        "caulk_version": "0.2.0",
        "target_path": "/test/app",
        "findings": [sample_finding.to_dict()],
        "summary": {
            "files_scanned": 5,
            "files_skipped": 0,
            "total_findings": 1,
            "duration_seconds": 0.5,
            "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "is_complete": False,
        },
        "errors": ["AST parsing failed for bad.py: syntax error on line 2"],
    }

    md = generate_step_summary(report_data, threshold=Severity.HIGH)
    assert "Scan Result: ❌ Failed (Threshold: HIGH)" in md
    assert "The scan was also **incomplete** due to coverage gaps or errors." in md
    assert "AST parsing failed for bad.py: syntax error on line 2" in md
