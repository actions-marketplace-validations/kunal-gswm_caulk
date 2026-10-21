"""Tests for Caulk finding and scan result data models."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caulk.models import (
    Confidence,
    Finding,
    FindingCategory,
    FindingStatus,
    ScanResult,
    ScanSummary,
    Severity,
    compute_fingerprint,
    normalize_repo_path,
)


def test_severity_ordering():
    """Verify severity levels compare correctly by risk rank."""
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO

    assert Severity.HIGH >= Severity.HIGH
    assert Severity.LOW <= Severity.MEDIUM
    assert not (Severity.LOW > Severity.HIGH)


def test_severity_from_string():
    """Verify case-insensitive string parsing."""
    assert Severity.from_string("critical") == Severity.CRITICAL
    assert Severity.from_string("High") == Severity.HIGH
    assert Severity.from_string(" MEDIUM ") == Severity.MEDIUM

    with pytest.raises(ValueError, match="Invalid severity 'UNKNOWN'"):
        Severity.from_string("UNKNOWN")


def test_confidence_from_string():
    assert Confidence.from_string("confirmed") == Confidence.CONFIRMED
    assert Confidence.from_string("HIGH") == Confidence.HIGH

    with pytest.raises(ValueError, match="Invalid confidence"):
        Confidence.from_string("invalid")


def test_category_from_string():
    assert FindingCategory.from_string("secret") == FindingCategory.SECRET
    assert FindingCategory.from_string("CONFIGURATION") == FindingCategory.CONFIGURATION

    with pytest.raises(ValueError, match="Invalid category"):
        FindingCategory.from_string("invalid")


def test_normalize_repo_path():
    """Paths must use forward slashes and strip leading ./."""
    assert normalize_repo_path("src\\utils\\file.py") == "src/utils/file.py"
    assert normalize_repo_path("./config.toml") == "config.toml"
    assert normalize_repo_path(Path("nested/dir/foo.txt")) == "nested/dir/foo.txt"
    assert normalize_repo_path(None) == ""


def test_fingerprint_deterministic_stability():
    """Fingerprints must be stable across runs for identical finding coordinates."""
    fp1 = compute_fingerprint("SEC002", "src/auth.py", 10, "AWS Key")
    fp2 = compute_fingerprint("SEC002", "src/auth.py", 10, "AWS Key")
    assert fp1 == fp2
    assert len(fp1) == 32

    # Different line produces different fingerprint
    fp3 = compute_fingerprint("SEC002", "src/auth.py", 11, "AWS Key")
    assert fp1 != fp3


def test_finding_to_dict_and_from_dict(sample_finding: Finding):
    """Verify serialization and round-trip fidelity."""
    d = sample_finding.to_dict()
    assert d["rule_id"] == "SEC002"
    assert d["severity"] == "CRITICAL"
    assert d["confidence"] == "HIGH"
    assert d["category"] == "SECRET"

    reconstructed = Finding.from_dict(d)
    assert reconstructed.rule_id == sample_finding.rule_id
    assert reconstructed.severity == sample_finding.severity
    assert reconstructed.fingerprint == sample_finding.fingerprint


def test_scan_result_has_findings_above(sample_finding: Finding):
    """Verify threshold evaluation on ScanResult."""
    result = ScanResult(
        caulk_version="0.2.0",
        target_path=".",
        findings=[sample_finding],
        summary=ScanSummary(total_findings=1),
    )

    # Sample finding is CRITICAL
    assert result.has_findings_above(Severity.CRITICAL) is True
    assert result.has_findings_above(Severity.HIGH) is True

    # Empty result
    clean_result = ScanResult(
        caulk_version="0.2.0",
        target_path=".",
        findings=[],
        summary=ScanSummary(total_findings=0),
    )
    assert clean_result.has_findings_above(Severity.INFO) is False


def test_scan_result_json_serialization(sample_finding: Finding):
    """Verify valid JSON serialization."""
    result = ScanResult(
        caulk_version="0.2.0",
        target_path="/test/repo",
        findings=[sample_finding],
        summary=ScanSummary(total_findings=1),
    )
    json_str = result.to_json()
    parsed = json.loads(json_str)

    assert parsed["caulk_version"] == "0.2.0"
    assert len(parsed["findings"]) == 1
    assert parsed["summary"]["total_findings"] == 1


def test_historical_finding_model_and_fingerprint():
    """Verify historical finding properties, fingerprint variation by commit, and round-trip fidelity."""
    fp_c1 = compute_fingerprint(
        "SEC001", "src/key.pem", 1, "Private Key", commit_sha="abcdef1234567890"
    )
    fp_c2 = compute_fingerprint(
        "SEC001", "src/key.pem", 1, "Private Key", commit_sha="9876543210fedcba"
    )
    fp_no_commit = compute_fingerprint("SEC001", "src/key.pem", 1, "Private Key")

    assert fp_c1 != fp_c2
    assert fp_c1 != fp_no_commit

    finding = Finding(
        rule_id="SEC001",
        title="Private Key Exposed",
        description="Key in history",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        category=FindingCategory.SECRET,
        file_path="src/key.pem",
        line_number=1,
        evidence="-----BEGIN PRIVATE KEY----- [REDACTED]",
        impact="Compromise",
        remediation="Rotate",
        status=FindingStatus.HISTORICAL,
        commit_sha="abcdef1234567890",
        commit_timestamp="2026-10-21T10:00:00Z",
        commit_author="Dev <dev@example.com>",
        commit_subject="Add key",
    )

    assert finding.is_historical is True
    assert finding.status == FindingStatus.HISTORICAL
    assert finding.commit_sha == "abcdef1234567890"

    d = finding.to_dict()
    assert d["status"] == "HISTORICAL"
    assert d["commit_sha"] == "abcdef1234567890"
    assert d["commit_author"] == "Dev <dev@example.com>"

    reconstructed = Finding.from_dict(d)
    assert reconstructed.is_historical is True
    assert reconstructed.commit_sha == finding.commit_sha
    assert reconstructed.commit_timestamp == finding.commit_timestamp
    assert reconstructed.commit_author == finding.commit_author
    assert reconstructed.commit_subject == finding.commit_subject
    assert reconstructed.fingerprint == finding.fingerprint


def test_scan_summary_historical_fields():
    """Verify ScanSummary historical metadata defaults and serialization."""
    summary = ScanSummary(
        scan_mode="git_history",
        commits_scanned=42,
        blobs_scanned=100,
        blobs_cached=25,
        refs_scanned=["refs/heads/main", "HEAD"],
    )
    d = summary.to_dict()
    assert d["scan_mode"] == "git_history"
    assert d["commits_scanned"] == 42
    assert d["blobs_scanned"] == 100
    assert d["blobs_cached"] == 25
    assert d["refs_scanned"] == ["refs/heads/main", "HEAD"]
    assert d["is_complete"] is True
