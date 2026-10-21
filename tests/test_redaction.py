"""Tests for secret redaction and masking functions."""

from __future__ import annotations

from caulk.redaction import (
    mask_secret,
    redact_connection_string,
    redact_line,
    sanitize_evidence,
)


def test_mask_secret_short():
    """Short secrets must be completely replaced with [REDACTED]."""
    assert mask_secret("short") == "[REDACTED]"
    assert mask_secret("12345678") == "[REDACTED]"
    assert mask_secret("") == "[EMPTY]"


def test_mask_secret_long():
    """Long secrets preserve limited prefix and suffix."""
    masked = mask_secret(
        "my_super_secret_production_token_1234567890", unmasked_prefix=4, unmasked_suffix=4
    )
    assert masked.startswith("my_s")
    assert masked.endswith("7890")
    assert "production" not in masked
    assert "*" in masked


def test_redact_connection_string():
    """Connection passwords must be replaced with [REDACTED]."""
    uri = "postgres://admin:SuperSecretPassword123@db.example.com:5432/mydb"
    redacted = redact_connection_string(uri)
    assert "SuperSecretPassword123" not in redacted
    assert redacted == "postgres://admin:[REDACTED]@db.example.com:5432/mydb"


def test_redact_line_aws_key():
    line = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    redacted = redact_line(line)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "AKIA************" in redacted


def test_redact_line_github_token():
    prefix = "".join(["gh", "p_"])
    line = f'token = "{prefix}1234567890abcdef1234567890abcdef1234"'
    redacted = redact_line(line)
    assert "1234567890abcdef" not in redacted
    assert "ghp_[REDACTED_TOKEN]" in redacted


def test_redact_line_slack_webhook():
    webhook_host = "https://" + "hooks.slack.com/services/"
    line = f"webhook = '{webhook_host}T12345678/B12345678/abc123xyz987'"
    redacted = redact_line(line)
    assert "abc123xyz987" not in redacted
    assert "[REDACTED_WEBHOOK]" in redacted


def test_redact_credential_assignment():
    line = 'api_key = "caulk_test_token_99999999999999999999"'
    redacted = redact_line(line)
    assert "99999999999999999999" not in redacted
    assert "api_key" in redacted


def test_sanitize_evidence_multiline():
    aws_prefix = "".join(["AK", "IA"])
    multiline = (
        "def connect():\n"
        '    uri = "postgres://root:secretPass123@10.0.0.1:5432/db"\n'
        f'    key = "{aws_prefix}1111222233334444"\n'
        "    return uri, key\n"
    )
    sanitized = sanitize_evidence(multiline)
    assert "secretPass123" not in sanitized
    assert "1111222233334444" not in sanitized
    assert "[REDACTED]" in sanitized
