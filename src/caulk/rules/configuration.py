"""Deterministic rules for security misconfigurations.

Covers debug mode in production configs, permissive CORS, Docker container security,
and unsafe deployment defaults.
"""

from __future__ import annotations

import re
from pathlib import Path

from caulk.discovery import DiscoveredFile
from caulk.models import Confidence, Finding, FindingCategory, Severity
from caulk.rules.base import Rule, ScanContext


class DebugModeRule(Rule):
    """Detects debug mode explicitly enabled in application configuration."""

    rule_id = "CFG001"
    title = "Application Debug Mode Explicitly Enabled"
    description = (
        "Application debug mode is hardcoded to enabled (True). In production, debug mode "
        "often exposes interactive execution consoles, sensitive stack traces, and environment variables."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.CONFIGURATION
    impact = (
        "An attacker can exploit debug consoles (such as Werkzeug or Django debug toolbar) "
        "to execute arbitrary code, or read sensitive internal system details from stack traces."
    )
    remediation = (
        "1. Set DEBUG via an environment variable that defaults to False (e.g. os.getenv('DEBUG', 'False').lower() == 'true').\n"
        "2. Ensure DEBUG is disabled (False) in all staging and production deployments."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/215.html",
        "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
    ]
    file_patterns = ["*.py", "*.json", "*.yaml", "*.yml", "*.toml"]

    _DJANGO_PATTERN = re.compile(r"^\s*DEBUG\s*=\s*True\b")
    _FLASK_PATTERN = re.compile(r"""\b(?:app\.run|server\.run)\s*\(.*debug\s*=\s*True.*\)""")
    _FLASK_CONFIG_PATTERN = re.compile(r"""\bapp\.config\s*\[\s*['"]DEBUG['"]\s*\]\s*=\s*True\b""")

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        # Exclude test files
        fname = Path(file.rel_path).name.lower()
        if "test" in fname or "fixture" in fname:
            return []

        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            line_str = line.strip()
            if line_str.startswith("#"):
                continue

            # Django DEBUG = True
            if self._DJANGO_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"Hardcoded Django debug mode: '{line_str}'",
                    )
                )

            # Flask app.run(debug=True)
            elif self._FLASK_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"Flask server run with debug=True: '{line_str}'",
                    )
                )

            # Flask app.config['DEBUG'] = True
            elif self._FLASK_CONFIG_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"Flask config debug enabled: '{line_str}'",
                    )
                )

        return findings


class PermissiveCORSRule(Rule):
    """Detects wildcard CORS origin paired with credentials."""

    rule_id = "CFG002"
    title = "Insecure Wildcard CORS Configuration with Credentials"
    description = (
        "Cross-Origin Resource Sharing (CORS) is configured with wildcard origin ('*') while allowing "
        "user credentials. This allows third-party origins to make authenticated cross-origin requests."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.CONFIGURATION
    impact = (
        "Malicious third-party websites visited by an authenticated user can read sensitive responses "
        "from your API on behalf of that user."
    )
    remediation = (
        "1. Do not use wildcard ('*') origins when credentials (cookies, authorization headers) are supported.\n"
        "2. Explicitly enumerate trusted allowed origin URLs (e.g. ['https://app.example.com']).\n"
        "3. If wildcard origin is required for a public API, set allow_credentials / credentials to False."
    )
    references = [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        "https://portswigger.net/web-security/cors",
        "https://cwe.mitre.org/data/definitions/942.html",
    ]
    file_patterns = ["*.py", "*.js", "*.ts", "*.json"]

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        text = context.read_text(file)
        lines = context.get_lines(file)

        # Check for FastAPI / Starlette CORSMiddleware pattern
        # Look for allow_origins=["*"] and allow_credentials=True within close proximity
        if "CORSMiddleware" in text or "cors(" in text.lower():
            has_wildcard = (
                'allow_origins=["*"]' in text.replace(" ", "")
                or "allow_origins=['*']" in text.replace(" ", "")
                or 'origin:"*"' in text.replace(" ", "")
                or "origin:'*'" in text.replace(" ", "")
            )
            has_credentials = "allow_credentials=true" in text.lower().replace(
                " ", ""
            ) or "credentials:true" in text.lower().replace(" ", "")

            if has_wildcard and has_credentials:
                # Find line number of the origin configuration
                target_line = 1
                for idx, line in enumerate(lines, start=1):
                    if "*" in line and ("origin" in line.lower() or "cors" in line.lower()):
                        target_line = idx
                        break

                return [
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=target_line,
                        evidence="CORS middleware configured with allow_origins=['*'] and allow_credentials=True",
                    )
                ]

        return []


class DockerRootUserRule(Rule):
    """Detects Docker container configurations lacking a non-root USER instruction."""

    rule_id = "CFG003"
    title = "Docker Container Runs as Default Root User"
    description = (
        "The Dockerfile does not define a non-root USER instruction before executing application commands. "
        "By default, containers execute as UID 0 (root), increasing the impact of potential container escapes."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = FindingCategory.CONFIGURATION
    impact = (
        "If an attacker exploits an application vulnerability inside the container, they possess "
        "root privileges within the container namespace, facilitating privilege escalation and filesystem tampering."
    )
    remediation = (
        "1. Create an unprivileged user and group inside the Dockerfile (e.g. RUN addgroup -S app && adduser -S app -G app).\n"
        "2. Add a 'USER app' instruction before the ENTRYPOINT or CMD statement."
    )
    references = [
        "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
        "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
    ]

    def applies_to_file(self, file: DiscoveredFile) -> bool:
        fname = Path(file.rel_path).name.lower()
        return (
            fname == "dockerfile"
            or fname.startswith("dockerfile.")
            or fname.endswith(".dockerfile")
        )

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        lines = context.get_lines(file)
        has_from = False
        has_user = False
        user_is_root = False
        last_from_line = 1

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue

            upper = stripped.upper()
            if upper.startswith("FROM "):
                has_from = True
                last_from_line = line_num
                # Reset user state for multi-stage builds
                has_user = False
                user_is_root = False

            if upper.startswith("USER "):
                parts = stripped.split()
                if len(parts) > 1:
                    user_val = parts[1].strip().lower()
                    if user_val in ("root", "0", "0:0"):
                        user_is_root = True
                        has_user = False
                    else:
                        has_user = True
                        user_is_root = False

        if has_from and (not has_user or user_is_root):
            evidence = (
                "Explicit 'USER root' configured in final stage"
                if user_is_root
                else "No non-root USER instruction specified before container entrypoint"
            )
            return [
                self.create_finding(
                    file_path=file.rel_path,
                    line_number=last_from_line,
                    evidence=evidence,
                )
            ]

        return []


class DockerfileSecretExposureRule(Rule):
    """Detects sensitive files or credentials embedded in Dockerfile commands."""

    rule_id = "CFG004"
    title = "Sensitive Credential or Key Copied in Dockerfile"
    description = (
        "A Dockerfile COPY or ADD instruction copies sensitive files (such as SSH private keys, "
        ".env files, or service account credentials) into the container image layers."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = FindingCategory.CONFIGURATION
    impact = (
        "Files copied into Docker image layers persist in the image history even if deleted in later RUN steps. "
        "Anyone who pulls or inspects the image can extract the private key or secret."
    )
    remediation = (
        "1. Do not COPY secret files (.env, id_rsa, credentials.json) into the image.\n"
        "2. Use Docker BuildKit secret mounts (RUN --mount=type=secret,id=...) during build.\n"
        "3. Provide secrets at runtime using environment variables or volume mounts."
    )
    references = [
        "https://docs.docker.com/build/building/secrets/",
        "https://cwe.mitre.org/data/definitions/538.html",
    ]

    _SENSITIVE_TARGETS = re.compile(
        r"""\b(?:COPY|ADD)\s+.*\b(?:id_rsa|id_ecdsa|id_ed25519|\.env|service-account.*\.json|credentials\.json)\b""",
        re.IGNORECASE,
    )
    _ENV_SECRET_PATTERN = re.compile(
        r"""^\s*ENV\s+(?:.*(?:API_KEY|SECRET_KEY|PASSWORD|AUTH_TOKEN|PRIVATE_KEY)\s*=\s*['"]?[a-zA-Z0-9_\-]{8,})""",
        re.IGNORECASE,
    )

    def applies_to_file(self, file: DiscoveredFile) -> bool:
        fname = Path(file.rel_path).name.lower()
        return (
            fname == "dockerfile"
            or fname.startswith("dockerfile.")
            or fname.endswith(".dockerfile")
        )

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if self._SENSITIVE_TARGETS.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"Sensitive file copied into image: '{stripped}'",
                    )
                )

            elif self._ENV_SECRET_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence="Hardcoded secret assigned in ENV instruction: [REDACTED]",
                    )
                )

        return findings
