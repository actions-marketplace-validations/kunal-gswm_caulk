"""Secret redaction and sanitization utilities.

Ensures no raw credential, token, or private key material leaks into reports,
logs, terminal output, or diagnostic exceptions.
"""

from __future__ import annotations

import re

# Known secret signatures for global redaction passes
_REDACTION_PATTERNS = [
    # AWS Access Key IDs
    (re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), r"\1"),
    # GitHub personal access tokens
    (re.compile(r"\b(ghp_[A-Za-z0-9_]{36,})\b"), "ghp"),
    (re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"), "github_pat"),
    # Generic slack webhooks
    (
        re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Z_]+/B[0-9A-Z_]+/)[0-9A-Za-z_]+"),
        r"\1[REDACTED]",
    ),
    # Connection string credentials: scheme://user:pass@host
    (
        re.compile(r"([a-zA-Z][a-zA-Z0-9+\-.]*://[^:\s@]+):([^@\s]+)@"),
        r"\1:[REDACTED]@",
    ),
    # Google API Key
    (re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "AIza"),
    # Private Key material lines
    (
        re.compile(
            r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----",
            re.DOTALL,
        ),
        "-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY MATERIAL]\n-----END PRIVATE KEY-----",
    ),
]


def mask_secret(secret: str, unmasked_prefix: int = 4, unmasked_suffix: int = 2) -> str:
    """Mask a sensitive secret string, preserving minimal prefix/suffix for identification.

    If the string is short, masks it completely with [REDACTED].
    """
    secret = secret.strip()
    if not secret:
        return "[EMPTY]"

    length = len(secret)
    if length <= 8:
        return "[REDACTED]"

    if unmasked_prefix + unmasked_suffix >= length:
        # Too short for the requested unmasked amounts
        return secret[:2] + ("*" * (length - 4)) + secret[-2:]

    prefix = secret[:unmasked_prefix]
    suffix = secret[-unmasked_suffix:] if unmasked_suffix > 0 else ""
    masked_count = length - unmasked_prefix - unmasked_suffix
    return f"{prefix}{'*' * min(masked_count, 16)}{suffix}"


def redact_connection_string(uri: str) -> str:
    """Mask the password component in a database or protocol connection URI."""
    pattern = re.compile(r"([a-zA-Z][a-zA-Z0-9+\-.]*://[^:\s@]+):([^@\s]+)@")
    return pattern.sub(r"\1:[REDACTED]@", uri)


def redact_line(line: str) -> str:
    """Sanitize a code or log line by replacing known secret tokens with masked versions."""
    sanitized = line

    # 1. AWS Key
    sanitized = re.sub(
        r"\b(AKIA|ASIA)([0-9A-Z]{16})\b",
        lambda m: f"{m.group(1)}{'*' * 12}{m.group(2)[-4:]}",
        sanitized,
    )

    # 2. GitHub PAT
    sanitized = re.sub(
        r"\b(ghp_)[A-Za-z0-9_]{36,}\b",
        r"\1[REDACTED_TOKEN]",
        sanitized,
    )
    sanitized = re.sub(
        r"\b(github_pat_)[A-Za-z0-9_]{82}\b",
        r"\1[REDACTED_TOKEN]",
        sanitized,
    )

    # 3. Google API Key
    sanitized = re.sub(
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "AIza[REDACTED_KEY]",
        sanitized,
    )

    # 4. Slack webhooks
    sanitized = re.sub(
        r"(https://hooks\.slack\.com/services/T[0-9A-Z_]+/B[0-9A-Z_]+/)[0-9A-Za-z_]+",
        r"\1[REDACTED_WEBHOOK]",
        sanitized,
    )

    # 5. Connection string credentials
    sanitized = redact_connection_string(sanitized)

    # 6. Common credential assignments in code: (password|api_key|token|secret)\s*=\s*['"]...['"]
    def _mask_assignment(m: re.Match[str]) -> str:
        key = m.group(1)
        sep = m.group(2)
        quote = m.group(3)
        val = m.group(4)
        masked_val = mask_secret(val, unmasked_prefix=2, unmasked_suffix=2)
        return f"{key}{sep}{quote}{masked_val}{quote}"

    assign_pattern = re.compile(
        r"""\b(password|passwd|api_key|secret_key|auth_token|access_token|private_key|client_secret)"""
        r"""(\s*[:=]\s*)"""
        r"""(['"])([^'"]{6,})\3""",
        re.IGNORECASE,
    )
    sanitized = assign_pattern.sub(_mask_assignment, sanitized)

    return sanitized


def sanitize_evidence(evidence: str) -> str:
    """Sanitize multi-line evidence snippet to eliminate any credentials."""
    lines = evidence.splitlines()
    sanitized_lines = [redact_line(ln) for ln in lines]
    return "\n".join(sanitized_lines)
