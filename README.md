# Caulk

> **Deterministic, open-source security checker for modern application repositories.**

[![CI](https://github.com/kunal-gswm/caulk/actions/workflows/ci.yml/badge.svg)](https://github.com/kunal-gswm/caulk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Caulk helps developers identify common security vulnerabilities and dangerous configurations in their codebases **before** shipping their applications to production.

---

## 1. What Caulk Is — and Is Not

Caulk is designed for developers who build applications using modern frameworks and AI coding assistants, but may lack formal application-security training.

Every finding in Caulk answers four essential questions:
1. **What is wrong?**
2. **Where is the problem?** (path and line number)
3. **Why does it matter?** (realistic risk explanation)
4. **What should the developer do to fix it?** (clear, step-by-step remediation)

### What Caulk Is
- **Deterministic:** Detections originate from explicit rules, signatures, cryptographic headers, syntax structures, or verified advisory databases.
- **Local-First & Offline by Default:** Scans run entirely on your local machine. No code is transmitted to third-party cloud servers.
- **Self-Contained:** Zero dependencies on external security daemons or heavy container runtimes for core scans.
- **Safe by Design:** Caulk **never** runs untrusted repository scripts, executes `npm install`, or triggers build steps.

### What Caulk Is NOT
- **NOT an AI application:** Caulk uses **no** LLMs, generative AI, probabilistic machine learning, or AI agents.
- **NOT a SaaS or subscription:** Requires no account, no login, and collects **zero telemetry**.
- **NOT an exploitation tool:** Caulk never attempts to exploit a target or alter source code automatically.
- **NOT a security guarantee:** A clean scan does not prove an application is secure. Caulk inspects known static patterns and configurations, but cannot verify dynamic runtime behavior.

---

## 2. Supported Checks & Rules

Caulk ships with 14 built-in deterministic rules across three categories:

| Category | Rules | Description |
| :--- | :--- | :--- |
| **Secrets** | `SEC001` - `SEC008` | Detects private cryptographic keys (RSA/EC/OpenSSH), AWS access keys, GitHub tokens, Google API keys, Slack webhooks, database connection strings with embedded passwords, credential variable assignments, and accidentally committed `.env` files. |
| **Configuration** | `CFG001` - `CFG004` | Detects hardcoded `DEBUG = True` in application deployment configs, overly permissive wildcard CORS with credentials, Dockerfiles running as root (`UID 0`), and private keys/secrets copied into Docker images. |
| **Dependencies** | `DEP001` - `DEP003` | Inventories dependencies across `package.json`, `package-lock.json` (v1/v2/v3), `requirements.txt`, and `pyproject.toml`. Flags wildcard/unpinned dependencies and missing lockfiles. Includes optional OSV advisory vulnerability checks (`--check-vulns`). |

For complete rule documentation, see [docs/detection-coverage.md](docs/detection-coverage.md).

---

## 3. Installation

Caulk requires **Python 3.11** or newer.

### Standard Installation

```bash
pip install caulk
```

### Development Installation (Editable)

```bash
git clone https://github.com/kunal-gswm/caulk.git
cd caulk
pip install -e ".[dev]"
```

Using [`uv`](https://github.com/astral-sh/uv):
```bash
uv venv .venv --python 3.12
.venv/Scripts/activate  # Or 'source .venv/bin/activate' on Linux/macOS
uv pip install -e ".[dev]"
```

---

## 4. Usage Examples

### Scan the Current Directory

```bash
caulk scan .
```

### Scan a Specific Repository or Folder

```bash
caulk scan ./my-project
```

### Machine-Readable JSON Output

```bash
caulk scan . --format json
```

### Save Report to File

```bash
caulk scan . --output caulk-report.json
```

### Set Severity Failure Threshold for CI

```bash
# Fail only on CRITICAL findings:
caulk scan . --severity-threshold CRITICAL

# Fail on HIGH or CRITICAL (default):
caulk scan . --severity-threshold HIGH
```

### Optional External Dependency Vulnerability Check

```bash
caulk scan . --check-vulns
```
*(Queries OSV.dev batch API for exact resolved lockfile package versions. Only package names and versions are transmitted; source code and secrets are never sent.)*

### List All Active Rules

```bash
caulk rules list
caulk rules list --category SECRET
caulk rules list --format json
```

### Initialize Project Configuration

```bash
caulk init
```
Generates a starter `.caulk.toml` configuration file with safe default exclusions.

---

## 5. Sample Output

```
╭─────────────────────────────────── CAULK v0.1.0 ───────────────────────────────────╮
│ Scanning target: E:/my-project                                                     │
╰────────────────────────────────────────────────────────────────────────────────────╯
Files inspected: 42  Files skipped: 8  Ecosystems: python, docker  Duration: 0.12s

Findings (2):

╭─ CRITICAL  [SECRET] AWS Access Key ID Detected (SEC002) ───────────────────────────╮
│ Where: src/config.py:14                                                            │
│ Confidence: HIGH                                                                   │
│                                                                                    │
│ What was found:                                                                    │
│ A 20-character AWS Access Key ID (AKIA or ASIA prefix) was detected.              │
│                                                                                    │
│ Evidence:                                                                          │
│   AWS Key detected: AKIA************MPLE                                           │
│                                                                                    │
│ Why it matters:                                                                    │
│ An attacker can use this key to authenticate against AWS APIs, access S3 buckets,  │
│ and provision cloud compute resources at your expense.                             │
│                                                                                    │
│ What to do:                                                                        │
│ 1. Deactivate and delete this access key in the AWS IAM Console immediately.       │
│ 2. Audit AWS CloudTrail logs for unauthorized API calls.                           │
│ 3. Use AWS IAM Roles or Secrets Manager instead of static long-term keys.          │
╰────────────────────────────────────────────────────────────────────────────────────╯

╭─ HIGH  [CONFIGURATION] Application Debug Mode Explicitly Enabled (CFG001) ─────────╮
│ Where: settings.py:28                                                              │
│ Confidence: HIGH                                                                   │
│                                                                                    │
│ What was found:                                                                    │
│ Application debug mode is hardcoded to enabled (True).                             │
│                                                                                    │
│ Evidence:                                                                          │
│   Hardcoded Django debug mode: 'DEBUG = True'                                      │
│                                                                                    │
│ Why it matters:                                                                    │
│ In production, debug mode exposes interactive execution consoles, sensitive stack  │
│ traces, and environment variables to any remote user.                              │
│                                                                                    │
│ What to do:                                                                        │
│ 1. Set DEBUG via an environment variable defaulting to False.                      │
│ 2. Ensure DEBUG is False in all staging and production deployments.               │
╰────────────────────────────────────────────────────────────────────────────────────╯

Finding Severity Summary
+--------------------------+
| Severity Level   | Count |
|------------------+-------|
| CRITICAL         |     1 |
| HIGH             |     1 |
| MEDIUM           |     0 |
| LOW              |     0 |
| INFO             |     0 |
+--------------------------+
```

---

## 6. Configuration & Exclusions

Initialize a starter `.caulk.toml` by running `caulk init`:

```toml
[scanner]
# Minimum severity level to cause non-zero exit code (CRITICAL, HIGH, MEDIUM, LOW, INFO)
fail_threshold = "HIGH"

# Maximum file size in bytes to scan (default: 2MB)
max_file_size_bytes = 2097152

# Maximum directory depth to traverse (default: 30)
max_directory_depth = 30

# Exclude patterns (relative to repository root)
exclude = [
    "tests/fixtures/*",
    "docs/*",
]

[network]
# Outbound dependency vulnerability lookups via OSV.dev (default: false)
enable_advisories = false

[rules]
# Disable specific rules if needed
disabled = []
```

Default exclusions automatically protect against scanning `.git`, `node_modules`, virtualenvs (`.venv`, `venv`), build directories (`dist`, `build`), caches (`__pycache__`, `.pytest_cache`), and binary files.

---

## 7. Exit Codes

Caulk uses deterministic, distinct exit codes suitable for CI/CD automation:

| Exit Code | Meaning | Description |
| :---: | :--- | :--- |
| `0` | **Success / Clean** | Scan completed successfully; no findings breached the configured failure threshold. |
| `1` | **Vulnerabilities Detected** | Scan completed successfully, but one or more findings equaled or exceeded `fail_threshold` (default `HIGH`). |
| `2` | **Usage / Config Error** | Invalid command-line arguments, non-existent target path, or malformed `.caulk.toml`. |
| `3` | **Execution Error** | Unhandled internal exception or unreadable directory. |

---

## 8. Security & Privacy Design

- **Zero Telemetry:** Caulk collects no usage analytics, repository names, or user data.
- **Credential Redaction:** Secrets are automatically masked in evidence snippets, terminal tables, JSON reports, and logs.
- **Untrusted Input Protection:** Traversal defends against symlink boundary escapes, path traversal attacks, and recursion loops.
- **No Untrusted Execution:** Caulk never invokes project scripts, loads modules dynamically, or installs dependencies.
- **Network Boundaries:** Network calls are disabled by default. The optional `--check-vulns` flag queries only package coordinates (name + version) against the public OSV database; proprietary source code and secrets are never transmitted.

See [docs/threat-model.md](docs/threat-model.md) for detailed threat modeling.

---

## 9. Roadmap

- [x] Initial CLI, deterministic discovery engine, finding data models, and redaction.
- [x] MVP Secret rules (`SEC001`-`SEC008`).
- [x] MVP Configuration rules (`CFG001`-`CFG004`).
- [x] Python and JavaScript dependency inventory & optional OSV advisory integration.
- [x] Automated CI testing across Ubuntu and Windows for Python 3.11, 3.12, 3.13.
- [ ] Self-contained Windows `.exe` packaged via PyInstaller.
- [ ] Official GitHub Action for pull request and push checks.
- [ ] Git pre-commit hook integration.
- [ ] SARIF report format for GitHub Advanced Security code scanning tab.
- [ ] Standalone desktop GUI.

---

## 10. License & Security Reporting

- **License:** Open source under the [MIT License](LICENSE).
- **Security Vulnerabilities:** Please report security issues privately via [GitHub Private Vulnerability Reporting](https://github.com/kunal-gswm/caulk/security/advisories) as detailed in [SECURITY.md](SECURITY.md).
