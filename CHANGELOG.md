# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-10-21

### Added
- **Official Composite GitHub Action (`action.yml`):** Production-ready composite action allowing automated security scanning in GitHub Actions on pushes and pull requests across Ubuntu and Windows runners.
- **Automated Markdown Step Summaries:** Structured report formatting (`src/caulk/reporting/summary.py`) appending scan outcomes, file inventory metrics, severity breakdown tables, and threshold-breaching findings to `GITHUB_STEP_SUMMARY`.
- **Markdown Injection & Forgery Hardening:** Safe dynamic Markdown rendering helpers (`escape_markdown_table_cell`, `format_table_code_cell`, `format_markdown_code_span`, `format_markdown_fenced_code`) preventing table splitting, row breakout, heading injection, active HTML tags, or code-fence escaping from malicious repository paths, filenames, or error outputs.
- **Early Composite Input Pre-Validation:** Added early bash validation in `action.yml` prior to `actions/setup-python` execution to immediately reject unsupported Python versions (< 3.11) and invalid input parameters.
- **Credential Redaction in Job Summaries:** Evidence is omitted from summary tables, referencing file paths and line numbers instead of raw source code snippets to prevent credential leaks into build logs.
- **Action Pipeline Coordinator (`src/caulk/action.py`):** Dedicated execution engine for input validation, safe temporary JSON report generation in `RUNNER_TEMP`, subprocess coordination, and exit code propagation.
- **Configurable Action Inputs:** Validated inputs for `path`, `severity-threshold` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), `check-vulns` (boolean), and `python-version`.
- **Action Step Outputs:** Exposes `scan-result` (`passed`, `failed`, `error`), `findings-count`, and `report-path`.
- **CI Action Integration Suite:** Extended `.github/workflows/ci.yml` with automated composite action validation on clean and vulnerable test fixtures, status code checks, and secret leakage assertions.

---

## [0.1.0] - 2026-10-21

### Added
- **Core CLI:** `caulk-security scan`, `caulk-security rules list`, and `caulk-security init` built with Typer and Rich.
- **Packaging & Distribution:** PyPI distribution package name configured as `caulk-security` with `caulk-security` as the sole console entrypoint to resolve command collisions with the unrelated historical PyPI package named `caulk`.
- **Deterministic Rule Engine:** Safe discovery walker with path traversal protection, symlink boundary validation, binary checks, and maximum depth guards.
- **Finding Model:** Typed, versionable security finding model with normalized paths, severity rank comparison, and SHA-256 deduplication fingerprints.
- **Secret Detection Rules (8 rules):**
  - `SEC001`: Private Key Material Exposed (RSA, EC, DSA, OPENSSH, PGP)
  - `SEC002`: AWS Access Key ID Detected (`AKIA` / `ASIA`)
  - `SEC003`: GitHub Personal Access Token Detected (`ghp_`, `github_pat_`, `gho_`, `ghs_`)
  - `SEC004`: Google Cloud API Key Detected (`AIza`)
  - `SEC005`: Slack Incoming Webhook URL Detected
  - `SEC006`: Database Connection String with Embedded Credentials
  - `SEC007`: Hardcoded Secret Assigned to Credential Variable
  - `SEC008`: Sensitive Environment File Committed to Repository (`.env`)
- **Security Configuration Rules (4 rules):**
  - `CFG001`: Application Debug Mode Explicitly Enabled (Django, Flask)
  - `CFG002`: Insecure Wildcard CORS Configuration with Credentials
  - `CFG003`: Docker Container Runs as Default Root User
  - `CFG004`: Sensitive Credential or Key Copied in Dockerfile
- **Dependency Inventory & Advisory Rules (3 rules):**
  - `DEP001`: Wildcard or Completely Unpinned Dependency in Manifest
  - `DEP002`: Application Manifest Present Without Corresponding Lockfile
  - `DEP003`: Known Vulnerability in Dependency (optional OSV advisory integration)
- **Dependency Parsers:** Native static parsing for `requirements.txt`, `pyproject.toml`, `package.json`, and `package-lock.json` (v1, v2, v3).
- **Redaction Engine:** Comprehensive masking of sensitive tokens in terminal outputs, JSON reports, and diagnostic logs.
- **Reporting:** Structured Rich terminal panels and deterministic machine-readable JSON reports.
- **Testing & Quality Gates:** 78 unit and integration tests covering positive, negative, and false-positive cases with >85% code coverage.
- **CI Workflow:** Automated GitHub Actions pipeline running test matrices on Ubuntu and Windows across Python 3.11, 3.12, and 3.13.
