"""Pytest fixtures and test environment configuration."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from caulk.config import CaulkConfig
from caulk.models import Confidence, Finding, FindingCategory, FindingStatus, Severity


@pytest.fixture
def cli_runner() -> CliRunner:
    """Typer CLI test runner."""
    return CliRunner()


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_finding() -> Finding:
    """Sample finding instance for model and reporting tests."""
    return Finding(
        rule_id="SEC002",
        title="AWS Access Key ID Detected",
        description="A 20-character AWS Access Key ID was detected in repository code.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=FindingCategory.SECRET,
        file_path="src/config.py",
        line_number=42,
        evidence="AWS Key detected: AKIA************TEST",
        impact="Compromise of AWS account and services.",
        remediation="Rotate and revoke the key in IAM console.",
        references=["https://docs.aws.amazon.com/"],
        detected_by="caulk-engine",
        status=FindingStatus.DETECTED,
    )


@pytest.fixture
def default_config() -> CaulkConfig:
    """Default configuration for tests."""
    return CaulkConfig()
