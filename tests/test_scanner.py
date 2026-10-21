"""Tests for scan orchestrator end-to-end functionality."""

from __future__ import annotations

from pathlib import Path

from caulk.config import CaulkConfig
from caulk.models import Severity
from caulk.scanner import CaulkScanner


def test_scanner_clean_project(fixtures_dir: Path):
    """Clean fixture repository must produce zero findings."""
    clean_path = fixtures_dir / "clean"
    scanner = CaulkScanner()
    result = scanner.scan(clean_path)

    assert result.summary.files_scanned > 0
    assert len(result.findings) == 0
    assert result.summary.total_findings == 0
    assert result.has_findings_above(Severity.INFO) is False
    assert "python" in result.summary.ecosystems_detected
    assert "javascript" in result.summary.ecosystems_detected
    assert "docker" in result.summary.ecosystems_detected


def test_scanner_vulnerable_project(fixtures_dir: Path):
    """Vulnerable fixture repository must trigger expected deterministic findings."""
    vuln_path = fixtures_dir / "vulnerable"
    scanner = CaulkScanner()
    result = scanner.scan(vuln_path)

    assert len(result.findings) > 0
    assert result.summary.total_findings > 0

    rule_ids = {f.rule_id for f in result.findings}
    # Verify detections
    assert "SEC002" in rule_ids  # AWS Key
    assert "SEC003" in rule_ids  # GitHub Token
    assert "SEC005" in rule_ids  # Slack Webhook
    assert "SEC006" in rule_ids  # Database password
    assert "SEC007" in rule_ids  # Credential assignment
    assert "SEC008" in rule_ids  # Exposed .env
    assert "CFG001" in rule_ids  # Debug mode
    assert "CFG002" in rule_ids  # Permissive CORS
    assert "CFG003" in rule_ids  # Docker root user
    assert "CFG004" in rule_ids  # Docker secret copied
    assert "DEP001" in rule_ids  # Unpinned dependency

    # Check redaction: raw sensitive tokens must not appear in any finding's evidence
    for finding in result.findings:
        assert "SuperSecretProdPassword123" not in finding.evidence
        assert "N3v3rGu3ssMeP@ss!" not in finding.evidence
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence

    # Check deterministic ordering: highest severity first
    for i in range(len(result.findings) - 1):
        assert result.findings[i].severity.rank >= result.findings[i + 1].severity.rank


def test_scanner_disabled_rule(fixtures_dir: Path):
    """Disabled rules are not executed."""
    vuln_path = fixtures_dir / "vulnerable"
    cfg = CaulkConfig(disabled_rules={"SEC002", "CFG001"})
    scanner = CaulkScanner(config=cfg)
    result = scanner.scan(vuln_path)

    rule_ids = {f.rule_id for f in result.findings}
    assert "SEC002" not in rule_ids
    assert "CFG001" not in rule_ids
