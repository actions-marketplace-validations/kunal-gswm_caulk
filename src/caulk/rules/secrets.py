"""Deterministic rules for secret and credential exposure detection.

All detected secrets are sanitized so raw credential values never appear in evidence.
Heuristics suppress obvious examples, placeholders, and dummy values.
"""

from __future__ import annotations

import re
from pathlib import Path

from caulk.discovery import DiscoveredFile
from caulk.models import Confidence, Finding, FindingCategory, Severity
from caulk.redaction import mask_secret, redact_connection_string, redact_line
from caulk.rules.base import Rule, ScanContext

# Exact values that represent dummy placeholders
DUMMY_EXACT_VALUES = {
    "your_api_key",
    "your-api-key",
    "your_api_key_here",
    "your_key",
    "your_secret",
    "your_secret_key",
    "your_token",
    "my_api_key",
    "changeme",
    "change_me",
    "dummy",
    "fake",
    "placeholder",
    "test_key",
    "test_secret",
    "sample",
    "insert_key",
    "insert_key_here",
    "replace_me",
    "none",
    "null",
    "undefined",
    "true",
    "false",
}

DUMMY_CONNECTION_PATTERNS = [
    ":password@localhost",
    ":password@127.0.0.1",
    ":pass@localhost",
    ":pass@127.0.0.1",
    ":root@localhost",
    ":postgres@localhost",
    ":admin@localhost",
    ":password@db",
    ":test@localhost",
    ":<password>@",
]


def is_placeholder_string(value: str) -> bool:
    """Check if a string is an obvious placeholder or dummy value."""
    val_clean = value.strip().strip("'\"`")
    val_lower = val_clean.lower()

    if not val_clean or len(val_clean) < 4:
        return True

    # Check for template expressions like ${FOO} or <KEY> or {{KEY}} or %s
    if val_clean.startswith(("${", "<", "{{", "%")) and val_clean.endswith(("}", ">", "}}", "s")):
        return True

    # Exact match on known placeholder names
    if val_lower in DUMMY_EXACT_VALUES:
        return True

    # Repeating single character (e.g. '000000000000' or 'xxxxxxxxxxxx')
    return len(val_clean) >= 8 and len(set(val_lower)) <= 2


class PrivateKeyRule(Rule):
    """Detects embedded cryptographic private key material."""

    rule_id = "SEC001"
    title = "Private Key Material Exposed"
    description = (
        "An unencrypted private cryptographic key was detected in repository files. "
        "Private keys allow unauthorized parties to decrypt confidential data, impersonate "
        "services, or access infrastructure."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.CONFIRMED
    category = FindingCategory.SECRET
    impact = (
        "Compromise of the private key enables unauthorized identity assumption, data decryption, "
        "or arbitrary access to infrastructure associated with the certificate or SSH key."
    )
    remediation = (
        "1. Immediately revoke the exposed key and generate a new key pair.\n"
        "2. Remove the key file or string from the repository and git history.\n"
        "3. Store private keys in a secret manager or environment variable, never in source code."
    )
    references = [
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key",
        "https://cwe.mitre.org/data/definitions/321.html",
    ]

    _PATTERN = re.compile(
        r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE\s+KEY-----",
        re.IGNORECASE,
    )

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            line_str = line.strip()
            # Skip regex definitions or string pattern constants
            if "re.compile" in line_str or "[A-Z" in line_str or "_PATTERN" in line_str:
                continue

            if self._PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence="-----BEGIN [PRIVATE KEY HEADER]----- [REDACTED]",
                    )
                )
                break

        return findings


class AWSAccessKeyRule(Rule):
    """Detects hardcoded AWS Access Key IDs."""

    rule_id = "SEC002"
    title = "AWS Access Key ID Detected"
    description = (
        "A 20-character AWS Access Key ID (AKIA or ASIA prefix) was detected in repository code. "
        "Exposing AWS credentials can lead to complete cloud account takeover."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = FindingCategory.SECRET
    impact = (
        "An attacker can use this key to authenticate against AWS APIs, access S3 buckets, "
        "provision compute resources, and read sensitive cloud data."
    )
    remediation = (
        "1. Deactivate and delete this access key in the AWS IAM Console immediately.\n"
        "2. Audit AWS CloudTrail logs for unauthorized API calls.\n"
        "3. Use AWS IAM Roles or Secrets Manager instead of static long-term keys."
    )
    references = [
        "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html",
        "https://cwe.mitre.org/data/definitions/798.html",
    ]

    _PATTERN = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            for match in self._PATTERN.finditer(line):
                key = match.group(1)
                # Suppress obvious repeating keys e.g. AKIA0000000000000000 or AKIAXXXXXXXXXXXXXXXX
                suffix = key[4:]
                if len(set(suffix)) <= 1:
                    continue

                masked = mask_secret(key, unmasked_prefix=4, unmasked_suffix=4)
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"AWS Key detected: {masked}",
                    )
                )

        return findings


class GitHubTokenRule(Rule):
    """Detects exposed GitHub personal access tokens and OAuth tokens."""

    rule_id = "SEC003"
    title = "GitHub Personal Access Token Detected"
    description = (
        "A GitHub authentication token (personal access token or OAuth token) was detected. "
        "Exposed tokens allow unauthorized access to GitHub repositories, workflows, and packages."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = FindingCategory.SECRET
    impact = (
        "Attackers can clone private repositories, inject malicious commits or releases, "
        "and modify GitHub Actions workflows."
    )
    remediation = (
        "1. Revoke the token immediately in GitHub Settings > Developer settings.\n"
        "2. Review recent audit logs for unauthorized repository access or tokens created.\n"
        "3. Use GitHub Actions secrets or environment variables for token delivery."
    )
    references = [
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
        "https://cwe.mitre.org/data/definitions/798.html",
    ]

    _PATTERNS = [
        re.compile(r"\b(ghp_[A-Za-z0-9_]{36,})\b"),
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        re.compile(r"\b(gho_[A-Za-z0-9_]{36,})\b"),
        re.compile(r"\b(ghs_[A-Za-z0-9_]{36,})\b"),
    ]

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            for pattern in self._PATTERNS:
                for match in pattern.finditer(line):
                    token = match.group(1)
                    token_body = token.split("_", 1)[1] if "_" in token else token
                    if len(set(token_body)) <= 1:
                        continue

                    masked = mask_secret(token, unmasked_prefix=4, unmasked_suffix=2)
                    findings.append(
                        self.create_finding(
                            file_path=file.rel_path,
                            line_number=line_num,
                            evidence=f"GitHub token: {masked}",
                        )
                    )

        return findings


class GoogleAPIKeyRule(Rule):
    """Detects hardcoded Google Cloud / Maps / Firebase API keys."""

    rule_id = "SEC004"
    title = "Google Cloud API Key Detected"
    description = (
        "A Google Cloud or Firebase API key was detected in code. "
        "Depending on key restrictions, this can allow unauthorized use of Google Cloud APIs "
        "at your expense."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.SECRET
    impact = (
        "Unrestricted Google API keys can be abused to consume billable quotas, access Firebase databases, "
        "or query maps/translation APIs."
    )
    remediation = (
        "1. Restrict the API key in Google Cloud Console (HTTP referrer / IP restrictions and API restrictions).\n"
        "2. Move the key to an environment variable or Secret Manager.\n"
        "3. Rotate the key if it was published to a public repository."
    )
    references = [
        "https://cloud.google.com/docs/authentication/api-keys#securing-an-api-key",
    ]

    _PATTERN = re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            for match in self._PATTERN.finditer(line):
                key = match.group(1)
                suffix = key[4:]
                if len(set(suffix)) <= 1:
                    continue

                masked = mask_secret(key, unmasked_prefix=4, unmasked_suffix=2)
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"Google API Key: {masked}",
                    )
                )

        return findings


class SlackWebhookRule(Rule):
    """Detects exposed Slack incoming webhook URLs."""

    rule_id = "SEC005"
    title = "Slack Incoming Webhook URL Detected"
    description = (
        "A Slack incoming webhook URL was detected. Webhooks allow sending messages to specific "
        "Slack channels without further authentication."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.SECRET
    impact = (
        "Anyone who possesses this URL can post arbitrary messages to the configured Slack channel, "
        "enabling phishing or spoofed operational alerts."
    )
    remediation = (
        "1. Invalidate the webhook URL in Slack App settings.\n"
        "2. Generate a new webhook URL and store it as a protected environment variable."
    )
    references = [
        "https://api.slack.com/messaging/webhooks#security",
    ]

    _PATTERN = re.compile(
        r"https://hooks\.slack\.com/services/(T[A-Za-z0-9_]+)/(B[A-Za-z0-9_]+)/([A-Za-z0-9_]+)"
    )

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            for match in self._PATTERN.finditer(line):
                if is_placeholder_string(match.group(3)):
                    continue

                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"https://hooks.slack.com/services/{match.group(1)}/{match.group(2)}/[REDACTED_WEBHOOK]",
                    )
                )

        return findings


class DatabaseConnectionStringRule(Rule):
    """Detects database connection URIs containing hardcoded passwords."""

    rule_id = "SEC006"
    title = "Database Connection String with Embedded Password"
    description = (
        "A database connection string with embedded authentication credentials was detected. "
        "Exposing database passwords directly in source code allows direct unauthorized database access."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.SECRET
    impact = (
        "Direct access to production or staging databases allows exfiltration of customer data, "
        "data tampering, or deletion."
    )
    remediation = (
        "1. Rotate the database user password immediately.\n"
        "2. Provide connection parameters via environment variables (e.g. DATABASE_URL) injected at runtime.\n"
        "3. Never commit real database credentials to version control."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://12factor.net/config",
    ]
    file_patterns = [
        "*.py",
        "*.js",
        "*.ts",
        "*.json",
        "*.env*",
        "*.toml",
        "*.yaml",
        "*.yml",
        "*.ini",
        "*.conf",
    ]

    _PATTERN = re.compile(
        r"""\b((?:postgres|postgresql|mysql|mongodb|redis|amqp|amqps)://)([^:\s@'"]+):([^@\s'"]+)@([^\s/'"]+)""",
        re.IGNORECASE,
    )

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            for match in self._PATTERN.finditer(line):
                raw_match = match.group(0)
                user = match.group(2)
                password = match.group(3)
                host = match.group(4)

                # Check dummy or localhost combinations
                if is_placeholder_string(password) or is_placeholder_string(user):
                    continue
                if any(dummy in raw_match.lower() for dummy in DUMMY_CONNECTION_PATTERNS):
                    continue
                if host.lower() in ("localhost", "127.0.0.1", "0.0.0.0") and password.lower() in (
                    "root",
                    "password",
                    "postgres",
                    "admin",
                    "pass",
                    "test",
                ):
                    continue

                masked_evidence = redact_connection_string(raw_match)
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=masked_evidence,
                    )
                )

        return findings


class HardcodedCredentialAssignmentRule(Rule):
    """Detects credential variable assignments containing likely real secrets."""

    rule_id = "SEC007"
    title = "Hardcoded Secret Assigned to Credential Variable"
    description = (
        "A variable whose name suggests a secret or token (e.g., api_key, auth_token, secret_key) "
        "was assigned a hardcoded literal value."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = FindingCategory.SECRET
    impact = (
        "Hardcoded secrets in application source code become visible to anyone with read access "
        "to the codebase or build artifacts."
    )
    remediation = (
        "1. Extract the secret into an environment variable loaded via process.env or os.environ.\n"
        "2. Add the configuration file or local .env to .gitignore.\n"
        "3. Rotate the compromised key if it was committed."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
    ]

    _PATTERN = re.compile(
        r"""\b(api_key|secret_key|client_secret|auth_token|private_key|access_token|password)"""
        r"""\s*[:=]\s*"""
        r"""(['"])([^'"]{12,})\2""",
        re.IGNORECASE,
    )

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        # Do not flag inside documentation or lock files
        ext = Path(file.rel_path).suffix.lower()
        if ext in (".md", ".txt", ".rst", ".lock"):
            return []

        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            for match in self._PATTERN.finditer(line):
                var_name = match.group(1)
                value = match.group(3)

                if is_placeholder_string(value):
                    continue

                # Heuristic: must have some complexity (digits and letters or mixed case)
                has_digit = any(c.isdigit() for c in value)
                has_alpha = any(c.isalpha() for c in value)
                if not (has_digit and has_alpha):
                    continue

                masked_line = redact_line(line.strip())
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"Credential assignment '{var_name}': {masked_line}",
                    )
                )

        return findings


class SensitiveEnvFileRule(Rule):
    """Detects presence of sensitive environment files (.env, .env.local, .env.production)."""

    rule_id = "SEC008"
    title = "Sensitive Environment File Committed to Repository"
    description = (
        "An environment file (.env, .env.local, .env.production) containing configuration was found "
        "in the repository. Real .env files often contain production secrets and should be excluded from Git."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.SECRET
    impact = (
        "Committing .env files exposes database URLs, third-party API credentials, and application secrets "
        "to all contributors and in version control history."
    )
    remediation = (
        "1. Add '.env*' and '!*.example' to your project's .gitignore file.\n"
        "2. Provide an '.env.example' file containing variable names with dummy placeholders instead.\n"
        "3. Rotate any production keys that were placed inside this file."
    )
    references = [
        "https://12factor.net/config",
        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
    ]

    _ENV_FILENAMES = {
        ".env",
        ".env.local",
        ".env.production",
        ".env.prod",
        ".env.staging",
        ".env.development.local",
    }

    def applies_to_file(self, file: DiscoveredFile) -> bool:
        fname = Path(file.rel_path).name.lower()
        if fname.endswith((".example", ".sample", ".template", ".test")):
            return False
        return fname in self._ENV_FILENAMES or (
            fname.startswith(".env.")
            and not fname.endswith((".example", ".sample", ".template", ".test"))
        )

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        if not self.applies_to_file(file):
            return []

        text = context.read_text(file)
        # Verify file is not empty and contains actual key=value assignments
        has_assignments = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                has_assignments = True
                break

        if not has_assignments:
            return []

        return [
            self.create_finding(
                file_path=file.rel_path,
                line_number=1,
                evidence=f"Environment file with active assignments detected: {file.rel_path}",
            )
        ]
