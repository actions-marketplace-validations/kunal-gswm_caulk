# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
