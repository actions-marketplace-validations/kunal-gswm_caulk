"""Tests for secret detection rules (positive, negative, and false-positive cases)."""

from __future__ import annotations

from pathlib import Path

from caulk.config import CaulkConfig
from caulk.discovery import DiscoveredFile, ProjectInventory
from caulk.rules.base import ScanContext
from caulk.rules.secrets import (
    AWSAccessKeyRule,
    DatabaseConnectionStringRule,
    GitHubTokenRule,
    GoogleAPIKeyRule,
    HardcodedCredentialAssignmentRule,
    PrivateKeyRule,
    SensitiveEnvFileRule,
    SlackWebhookRule,
)


def _make_context(
    tmp_path: Path, filename: str, content: str
) -> tuple[DiscoveredFile, ScanContext]:
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    dfile = DiscoveredFile(
        path=file_path, rel_path=filename, size_bytes=len(content.encode("utf-8"))
    )
    inv = ProjectInventory(root_path=tmp_path, files=[dfile])
    ctx = ScanContext(inventory=inv, config=CaulkConfig())
    return dfile, ctx


def test_private_key_positive(tmp_path: Path):
    rule = PrivateKeyRule()
    content = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0syntheticKeyMaterialHere...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    dfile, ctx = _make_context(tmp_path, "id_rsa", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert "MIIEowIBAAKCAQEA0" not in findings[0].evidence
    assert "[REDACTED]" in findings[0].evidence


def test_private_key_negative(tmp_path: Path):
    rule = PrivateKeyRule()
    content = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3 public key material user@host"
    dfile, ctx = _make_context(tmp_path, "id_rsa.pub", content)
    findings = rule.scan_file(dfile, ctx)
    assert len(findings) == 0


def test_aws_access_key_positive(tmp_path: Path):
    rule = AWSAccessKeyRule()
    content = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    dfile, ctx = _make_context(tmp_path, "aws.py", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC002"
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].evidence
    assert "AKIA************MPLE" in findings[0].evidence


def test_aws_access_key_dummy_negative(tmp_path: Path):
    rule = AWSAccessKeyRule()
    content = 'AWS_KEY = "AKIA0000000000000000"'  # Obvious dummy characters
    dfile, ctx = _make_context(tmp_path, "aws_dummy.py", content)
    findings = rule.scan_file(dfile, ctx)
    assert len(findings) == 0


def test_github_token_positive(tmp_path: Path):
    rule = GitHubTokenRule()
    content = 'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
    dfile, ctx = _make_context(tmp_path, "ci.py", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC003"
    assert "1234567890abcdef" not in findings[0].evidence
    assert "ghp_" in findings[0].evidence


def test_google_api_key_positive(tmp_path: Path):
    rule = GoogleAPIKeyRule()
    # Google API Key is AIza followed by 35 chars = 39 total chars
    content = 'GOOGLE_MAPS_KEY = "AIzaSyDa-exampleKey1234567890abcdef1234"'
    dfile, ctx = _make_context(tmp_path, "maps.ts", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"
    assert "exampleKey1234567890" not in findings[0].evidence


def test_slack_webhook_positive(tmp_path: Path):
    rule = SlackWebhookRule()
    content = (
        'url = "https://hooks.slack.com/services/T12345678/B12345678/sample_token_fixture_94819481"'
    )
    dfile, ctx = _make_context(tmp_path, "alerts.py", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"
    assert "sample_token_fixture_94819481" not in findings[0].evidence
    assert "[REDACTED_WEBHOOK]" in findings[0].evidence


def test_db_connection_string_positive(tmp_path: Path):
    rule = DatabaseConnectionStringRule()
    content = 'URI = "postgres://app_user:V3ryStr0ngP@ssw0rd!@db.internal.corp:5432/appdb"'
    dfile, ctx = _make_context(tmp_path, "db.py", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC006"
    assert "V3ryStr0ngP@ssw0rd!" not in findings[0].evidence
    assert "[REDACTED]@" in findings[0].evidence


def test_db_connection_string_localhost_negative(tmp_path: Path):
    rule = DatabaseConnectionStringRule()
    # Harmless dev connection strings to localhost with standard dummy passwords must not trigger
    content = 'DEV_URI = "postgres://postgres:postgres@localhost:5432/testdb"'
    dfile, ctx = _make_context(tmp_path, "dev_db.py", content)
    findings = rule.scan_file(dfile, ctx)
    assert len(findings) == 0


def test_credential_assignment_positive(tmp_path: Path):
    rule = HardcodedCredentialAssignmentRule()
    content = 'secret_key = "a8f9c1d2e3f4a5b6c7d8e9f0"'
    dfile, ctx = _make_context(tmp_path, "settings.py", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC007"
    assert "a8f9c1d2e3f4a5b6" not in findings[0].evidence


def test_credential_assignment_placeholder_negative(tmp_path: Path):
    rule = HardcodedCredentialAssignmentRule()
    content = 'api_key = "your_api_key_here"'
    dfile, ctx = _make_context(tmp_path, "example.py", content)
    findings = rule.scan_file(dfile, ctx)
    assert len(findings) == 0


def test_sensitive_env_file_positive(tmp_path: Path):
    rule = SensitiveEnvFileRule()
    content = "DATABASE_URL=postgres://user:pass@host/db\nAPI_KEY=1234567890\n"
    dfile, ctx = _make_context(tmp_path, ".env", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC008"


def test_sensitive_env_file_example_negative(tmp_path: Path):
    rule = SensitiveEnvFileRule()
    content = "DATABASE_URL=postgres://user:pass@host/db\n"
    dfile, ctx = _make_context(tmp_path, ".env.example", content)
    assert rule.applies_to_file(dfile) is False
    findings = rule.scan_file(dfile, ctx)
    assert len(findings) == 0
