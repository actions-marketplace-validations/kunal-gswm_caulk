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
- **NOT a security guarantee:** A clean scan does not prove an application is secure. Caulk inspects known static patterns and configurations, but cannot verify dynamic runtime behavior, business-logic flaws, or third-party service vulnerabilities.
- **NOT a dynamic analyzer:** Caulk analyzes static code structures and manifests offline without importing, executing, or instrumenting repository code. It does not perform interprocedural cross-file pointer analysis or evaluate runtime-constructed expressions.

---

## 2. Supported Checks & Rules

Caulk ships with 16 built-in deterministic rules across four categories:

| Category | Rules | Description |
| :--- | :--- | :--- |
| **Secrets** | `SEC001` - `SEC008` | Detects private cryptographic keys (RSA/EC/OpenSSH), AWS access keys, GitHub tokens, Google API keys, Slack webhooks, database connection strings with embedded passwords, credential variable assignments, and accidentally committed `.env` files. |
| **Configuration** | `CFG001` - `CFG004` | Detects hardcoded `DEBUG = True` in application deployment configs, overly permissive wildcard CORS with credentials, Dockerfiles running as root (`UID 0`), and private keys/secrets copied into Docker images. |
| **Dependencies** | `DEP001` - `DEP003` | Inventories dependencies across `package.json`, `package-lock.json` (v1/v2/v3), `requirements.txt`, and `pyproject.toml`. Flags wildcard/unpinned dependencies and missing lockfiles. Includes optional OSV advisory vulnerability checks (`--check-vulns`). |
| **SAST** | `SAST001` - `SAST002` | Deterministic Python AST analysis with intraprocedural taint tracking. Detects SQL injection (`SAST001`) and command injection via shell execution (`SAST002`) while actively avoiding false positives on parameterized queries and safe argument lists. |

For complete rule documentation, see [docs/detection-coverage.md](docs/detection-coverage.md).

---

## 3. Installation & Distribution

Caulk requires **Python 3.11** or newer (tested and supported on Python 3.11, 3.12, and 3.13).

> [!NOTE]
> **Package Naming:** The official PyPI distribution package name and installed console command is **`caulk-security`** (to prevent collision with the unrelated historical PyPI package and command named `caulk`). The Python import package remains `caulk` (`import caulk`).

### Standard Installation

```bash
pip install caulk-security
```

Or using [`uv`](https://github.com/astral-sh/uv):
```bash
uv pip install caulk-security
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

Caulk provides two complementary scanning modes:

1. **Working-Tree Scanning (`caulk-security scan`):** Inspects the files, static configurations (Dockerfiles, CORS, debug flags), dependency manifests, and Python AST taint propagation in your current active checkout. Fast, local, and recommended for pre-commit checks and regular pull request validation.
2. **Git History Scanning (`caulk-security history scan`):** Traverses the repository's historical Git commit graph and blob objects across reachable refs (branches, tags, HEAD). Detects credentials committed in the past even if deleted or replaced in subsequent commits. Requires a full clone (`fetch-depth: 0`).

### Scan the Current Directory

```bash
caulk-security scan .
```

### Scan a Specific Repository or Folder

```bash
caulk-security scan ./my-project
```

### Scan Git History for Committed Credentials (v0.3.0)

Caulk traverses reachable Git history across local branches, tags, and HEAD to catch credentials committed in the past—even if they were deleted or replaced in subsequent commits:

```bash
# Scan Git history of the current repository:
caulk-security history scan .

# Scan Git history of a specified repository path:
caulk-security history scan ./my-project

# Limit commit depth or scan since a specific date:
caulk-security history scan . --max-depth 100
caulk-security history scan . --since "2024-01-01"

# Scan a specific branch or ref instead of all local refs:
caulk-security history scan . --ref main

# Export machine-readable JSON history report:
caulk-security history scan . --format json --output history-report.json

# Adjust blob size limit (default 2MB) or exclude specific paths:
caulk-security history scan . --max-blob-size 500KB --exclude "tests/*"
```

> [!IMPORTANT]
> **Shallow Clone Protection:** Git history scanning requires a complete Git clone. If executed inside a shallow clone (e.g. created by `git clone --depth 1` or standard CI checkouts), Caulk detects the truncation using `git rev-parse --is-shallow-repository` and marks the scan incomplete (`is_complete = false`), failing closed with exit code 3 (`EXIT_EXECUTION_ERROR`) unless actionable findings are discovered (exit code 1). Older historical commits are never silently omitted from security evaluations. In CI, configure `actions/checkout` with `fetch-depth: 0`.
>
> **Unreachable Git Objects:** History scanning inspects all commits reachable from local refs (branches, tags, HEAD). Unreachable loose objects, unreferenced reflog entries, and remote branches that have not been fetched into local refs are not inspected.

### Machine-Readable JSON Output

```bash
caulk-security scan . --format json
```

### Save Report to File

```bash
caulk-security scan . --output caulk-report.json
```

### Set Severity Failure Threshold for CI

```bash
# Fail only on CRITICAL findings:
caulk-security scan . --severity-threshold CRITICAL

# Fail on HIGH or CRITICAL (default):
caulk-security scan . --severity-threshold HIGH
```

### Filter Scan by Rule Category or Disable Specific Rules

```bash
# Run only SAST analysis rules:
caulk-security scan . --category SAST

# Run secrets and SAST rules:
caulk-security scan . --category SECRET --category SAST

# Disable specific rules for a scan:
caulk-security scan . --disable SAST001
```

### Python AST Security Analysis (SAST001 & SAST002)

Caulk performs deterministic, local-first static analysis using Python standard library `ast` with intraprocedural taint tracking:

#### Rule Overview

- **`SAST001` (Python SQL Injection — Severity: HIGH):** Flags dynamic values formatted into SQL queries (via f-strings, concatenation `+`, `%` formatting, or `.format()`) and passed to database execution sinks:
  - **Sinks:** DB-API `.execute()`, `.executemany()`, SQLite `.executescript()`, Django `.raw()`.
  - **False-Positive Controls:** Parameterized queries (`cursor.execute("SELECT ... WHERE id = %s", (param,))`), static queries, and non-DB `.execute()` calls (e.g. `task_runner.execute(...)`) are **not** flagged.

- **`SAST002` (Command Injection via Shell Execution — Severity: HIGH):** Flags dynamic untrusted values passed to shell command execution sinks:
  - **Always-Shell Sinks:** `os.system()`, `os.popen()`, `subprocess.getoutput()`, `subprocess.getstatusoutput()`.
  - **Subprocess Sinks (requiring `shell=True`):** `subprocess.run()`, `subprocess.Popen()`, `subprocess.call()`, `subprocess.check_call()`, `subprocess.check_output()`.
  - **Import Aliasing:** Resolves module and function aliases (e.g. `import subprocess as sp`, `from subprocess import run as execute`, `from os import system as sys_exec`).
  - **False-Positive Controls:** Safe argument lists without `shell=True` (e.g. `subprocess.run(["ping", "-c", "1", host])`) and static commands are **not** flagged.

#### Supported Taint Sources

- **Flask:** `request.args`, `request.form`, `request.values`, `request.cookies`, `request.json`, `request.data`, `request.get_json()`, with indexing or `.get()`.
- **Django:** `request.GET`, `request.POST`, `request.COOKIES`, `request.headers`, with indexing or `.get()`.
- **Standard Input & CLI Arguments:** `input()`, `builtins.input()`, `sys.argv[...]`, `argv[...]`.

#### Safe vs Unsafe Patterns

```python
# ❌ VULNERABLE: Dynamic SQL string formatting (SAST001)
user_id = request.args.get("id")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ SAFE: Parameterized SQL query (Caulk does not flag)
user_id = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ❌ VULNERABLE: Command injection via shell=True (SAST002)
target = request.args.get("target")
subprocess.run(f"ping -c 1 {target}", shell=True)

# ✅ SAFE: Command argument list without shell invocation (Caulk does not flag)
target = request.args.get("target")
subprocess.run(["ping", "-c", "1", target])
```

> [!NOTE]
> **Static Analysis Scope & Boundaries:** Caulk's SAST is strictly bounded, intraprocedural static analysis. It tracks taint propagation across execution-order statements, assignments, branches, string methods (`.strip()`, `.lower()`, `.replace()`), and intermediate variables within each function and module scope. Caulk never executes or imports repository code. It does not perform interprocedural cross-file pointer analysis or dynamic symbolic execution.

### Optional External Dependency Vulnerability Check

```bash
caulk-security scan . --check-vulns
```
*(Queries OSV.dev batch API for exact resolved lockfile package versions. Only package names and versions are transmitted; source code and secrets are never sent.)*

### List All Active Rules

```bash
caulk-security rules list
caulk-security rules list --category SECRET
caulk-security rules list --format json
```

### Initialize Project Configuration

```bash
caulk-security init
```
Generates a starter `.caulk.toml` configuration file with safe default exclusions.

---

## 5. Sample Output

```
╭─────────────────────────────────── CAULK v0.3.0 ───────────────────────────────────╮
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

Initialize a starter `.caulk.toml` by running `caulk-security init`:

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
| `3` | **Execution Error / Incomplete Scan** | Unhandled internal exception, unreadable directory, or incomplete scan coverage (e.g. shallow clone during Git history scan, AST recursion or parsing limits exceeded). Fail-closed: prevents false-clean reporting when inspection could not complete. |

### Understanding Exit Code 3 (Fail-Closed Policy)

Security scanners must never silently report a clean status when inspection is incomplete. Caulk enforces a strict fail-closed policy: if a scan encounters an unrecoverable coverage gap without findings that breach the failure threshold, it terminates with **exit code 3** (`EXIT_EXECUTION_ERROR`) rather than exit code 0.

#### Common Causes & How to Respond:

1. **Shallow Clone Detected (`Partial history (shallow clone)`):**
   - *Cause:* `caulk-security history scan` was executed in a shallow Git repository (e.g. created by `git clone --depth 1` or standard CI checkouts).
   - *Response:* Fetch complete history before scanning. In GitHub Actions, configure `actions/checkout` with `fetch-depth: 0`. Locally, run `git fetch --unshallow`.

2. **Python AST Parsing or Recursion Limit Exceeded:**
   - *Cause:* A Python source file has syntax errors under the current runtime or deeply nested structures exceeding recursion limits.
   - *Response:* Review the reported file paths and diagnostic messages under the `Scan Incomplete` banner. Fix syntax errors or exclude generated/vendor code via `.caulk.toml`.

3. **Skipped Oversized Git Blobs or Corrupt Objects:**
   - *Cause:* Git history contains corrupt objects or blobs exceeding `--max-blob-size` (default: 2MB).
   - *Response:* Inspect the diagnostic output. Increase `--max-blob-size` if large text assets must be scanned, or exclude non-code paths via `--exclude`.

---

## 8. GitHub Action Integration

Caulk provides an official composite GitHub Action (`action.yml`) to scan repositories deterministically on pushes and pull requests across both **Ubuntu** (`ubuntu-latest`) and **Windows** (`windows-latest`) runners.

### Features
- **Deterministic & Local-First:** Runs without cloud accounts, telemetry, or external AI APIs.
- **Evidence Redaction:** Discovered credentials are never printed in GitHub Step Summaries or logs.
- **Job Summaries:** Renders a clean Markdown report with file inventory stats and severity tables directly into `GITHUB_STEP_SUMMARY`.
- **Zero Repo Execution:** Never installs repository dependencies or executes scanned repository scripts.
- **Supply-Chain Guarded:** Pinned composite actions and explicit read-only permissions.

### Example Consumer Workflow

Create `.github/workflows/security.yml` in your repository:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# Security best practice: Explicitly declare minimal read-only permissions
permissions:
  contents: read

jobs:
  caulk-scan:
    name: Caulk Security Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false

      - name: Run Caulk Security Checker
        # Note: Pin to an official release tag (e.g. @v0.3.0) or an immutable commit SHA
        uses: kunal-gswm/caulk@v0.3.0
        with:
          path: .
          severity-threshold: HIGH
          check-vulns: false
          scan-history: false
          python-version: "3.12"
```

#### Full Git History Scanning Workflow (Requires `fetch-depth: 0`)

To scan all commits across the repository's history rather than just the working tree, configure `actions/checkout` with `fetch-depth: 0` and set `scan-history: true`:

```yaml
name: Caulk Full History Scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  caulk-history-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Full Git History
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0 # Required: Caulk rejects shallow clones to prevent false-clean scans
          persist-credentials: false

      - name: Run Caulk Git History Scan
        uses: kunal-gswm/caulk@v0.3.0
        with:
          scan-history: true
          severity-threshold: HIGH
```

### Action Inputs

| Input | Description | Required | Default | Allowed Values |
| :--- | :--- | :---: | :---: | :--- |
| `path` | Path to repository or subfolder to scan | No | `.` | Directory path relative to `GITHUB_WORKSPACE` |
| `severity-threshold` | Minimum severity level to fail the job | No | `HIGH` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `check-vulns` | Enable outbound queries to OSV for package CVEs | No | `false` | `true`, `false` |
| `scan-history` | Scan Git repository history for exposed secrets (requires full clone with `fetch-depth: 0`) | No | `false` | `true`, `false` |
| `python-version` | Python runtime version for scanner environment | No | `3.12` | `3.11`, `3.12`, `3.13` |

### Action Outputs

| Output | Description | Example |
| :--- | :--- | :--- |
| `scan-result` | High-level outcome of the scan | `passed`, `failed`, or `error` |
| `findings-count` | Total count of security findings discovered | `0`, `3` |
| `report-path` | Absolute path to the generated JSON report | `/tmp/caulk-report-abc12345.json` |

### Consuming Action Outputs

```yaml
      - name: Run Caulk
        id: caulk
        uses: kunal-gswm/caulk@v0.3.0
        continue-on-error: true

      - name: Upload Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: caulk-security-report
          path: ${{ steps.caulk.outputs.report-path }}
```

---

## 9. Security & Privacy Design

- **Zero Telemetry:** Caulk collects no usage analytics, repository names, or user data.
- **Credential Redaction:** Secrets are automatically masked in evidence snippets, terminal tables, JSON reports, step summaries, and logs.
- **Untrusted Input Protection:** Traversal defends against symlink boundary escapes, path traversal attacks, and recursion loops.
- **No Untrusted Execution:** Caulk never invokes project scripts, loads modules dynamically, or installs dependencies from scanned manifests.
- **Network Boundaries:** Network calls are disabled by default. The optional `--check-vulns` flag queries only package coordinates (`name` and resolved `version`) against the public OSV batch API (`api.osv.dev`). Proprietary source code, file paths, and credentials are **never** transmitted.
- **Safe CI Permissions:** Example workflows and actions use minimal `contents: read` permissions. Caulk does not request write permissions or comment on PRs through privileged tokens.

See [docs/threat-model.md](docs/threat-model.md) for detailed threat modeling.

---

## 10. Roadmap

- [x] Initial CLI, deterministic discovery engine, finding data models, and redaction.
- [x] MVP Secret rules (`SEC001`-`SEC008`).
- [x] MVP Configuration rules (`CFG001`-`CFG004`).
- [x] Python and JavaScript dependency inventory & optional OSV advisory integration.
- [x] Automated CI testing across Ubuntu and Windows for Python 3.11, 3.12, 3.13.
- [x] Official GitHub Action composite action (`action.yml`) with automated step summary generation.
- [ ] Self-contained Windows `.exe` packaged via PyInstaller.
- [ ] Git pre-commit hook integration.
- [ ] SARIF report format for GitHub Advanced Security code scanning tab.
- [ ] Standalone desktop GUI.

---

## 11. License & Security Reporting

- **License:** Open source under the [MIT License](LICENSE).
- **Security Vulnerabilities:** Please report security issues privately via [GitHub Private Vulnerability Reporting](https://github.com/kunal-gswm/caulk/security/advisories) as detailed in [SECURITY.md](SECURITY.md).
