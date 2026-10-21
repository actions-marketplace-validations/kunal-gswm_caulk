# Detection Coverage & Rule Matrix

Caulk emphasizes high-confidence, deterministic detections. This document outlines the security rules implemented in the current version alongside planned capabilities.

---

## 1. Implemented MVP Rules

### A. Secret Exposure (`SECRET`)

| Rule ID | Title | Severity | Confidence | Target Files | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC001` | Private Key Material Exposed | `CRITICAL` | `CONFIRMED` | All files | Detects unencrypted private cryptographic keys (RSA, EC, DSA, OPENSSH, PGP) using deterministic ASN.1/PEM headers. |
| `SEC002` | AWS Access Key ID Detected | `CRITICAL` | `HIGH` | All files | Detects 20-character AWS Access Key IDs (`AKIA` / `ASIA` prefixes), excluding uniform dummy character runs. |
| `SEC003` | GitHub Personal Access Token Detected | `CRITICAL` | `HIGH` | All files | Detects personal access tokens, fine-grained tokens, and OAuth keys (`ghp_`, `github_pat_`, `gho_`, `ghs_`). |
| `SEC004` | Google Cloud API Key Detected | `HIGH` | `HIGH` | All files | Detects 39-character Google Cloud/Firebase API keys (`AIza` prefix). |
| `SEC005` | Slack Incoming Webhook URL Detected | `HIGH` | `HIGH` | All files | Detects unauthenticated incoming Slack webhook URLs (`https://hooks.slack.com/services/...`). |
| `SEC006` | Database Connection String with Credentials | `HIGH` | `HIGH` | All files | Detects database connection URIs (`postgres://`, `mysql://`, `mongodb://`, `redis://`) containing embedded non-placeholder credentials. |
| `SEC007` | Hardcoded Secret Assigned to Credential Variable | `HIGH` | `MEDIUM` | Source code | Detects assignments to variables named `api_key`, `secret_key`, `auth_token`, etc. with high-entropy non-placeholder literal values. |
| `SEC008` | Sensitive Environment File Committed to Repository | `HIGH` | `HIGH` | `.env*` | Detects `.env`, `.env.local`, `.env.production` files containing active assignments. Does not flag `.env.example` or templates. |

### B. Security Configuration (`CONFIGURATION`)

| Rule ID | Title | Severity | Confidence | Target Files | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CFG001` | Application Debug Mode Explicitly Enabled | `HIGH` | `HIGH` | `*.py`, `*.json`, `*.toml` | Detects hardcoded `DEBUG = True` in Django settings or `app.run(debug=True)` in Flask without environment variable guards. |
| `CFG002` | Insecure Wildcard CORS Configuration with Credentials | `HIGH` | `HIGH` | `*.py`, `*.js`, `*.ts` | Detects `allow_origins=["*"]` or wildcard origin paired with `allow_credentials=True` in FastAPI, Flask-CORS, and Express. |
| `CFG003` | Docker Container Runs as Default Root User | `MEDIUM` | `HIGH` | `Dockerfile*` | Identifies Dockerfiles that omit a non-root `USER` instruction or explicitly set `USER root` before runtime entrypoints. |
| `CFG004` | Sensitive Credential or Key Copied in Dockerfile | `CRITICAL` | `HIGH` | `Dockerfile*` | Detects `COPY` or `ADD` statements that bake `.env`, `id_rsa`, or `credentials.json` directly into container image layers. |

### C. Dependency Manifests & Inventory (`DEPENDENCY`)

| Rule ID | Title | Severity | Confidence | Target Files | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `DEP001` | Wildcard or Completely Unpinned Dependency Version | `LOW` | `HIGH` | `package.json`, `requirements.txt` | Identifies packages specified as `*` or `latest` or naked package names without version constraints. |
| `DEP002` | Application Manifest Present Without Corresponding Lockfile | `INFO` | `HIGH` | `package.json` | Flags projects containing dependency manifests without a corresponding committed lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`). |
| `DEP003` | Known Vulnerability in Dependency (OSV Advisory) | `CRITICAL` / `HIGH` | `CONFIRMED` | Lockfiles / Pinned manifests | *(Optional)* Queries OSV.dev batch API for verified CVE/GHSA advisories against exact pinned package versions when run with `--check-vulns`. |

---

## 2. Planned Checks (Future Milestones)

The following capabilities are architected for upcoming releases and will be added under the same deterministic rule interface:

1. **Git Commit History Scanning:**
   - Scanning unreachable or historic Git commits for revoked or lingering secrets before pushing to public remotes.
2. **Lockfile Parsing Extensions:**
   - Full parser for `yarn.lock` (v1 and v2 Berry) and `pnpm-lock.yaml`.
   - Python `poetry.lock` and `Pipfile.lock` deep parsing.
3. **Advanced Infrastructure-as-Code (IaC) Rules:**
   - Terraform / OpenTofu security misconfiguration checks (unencrypted S3 buckets, open security groups `0.0.0.0/0`).
   - GitHub Actions workflow analysis (unpinned actions, dangerous `pull_request_target` triggers, secret exfiltration vectors).
4. **Targeted Semantic AST Checks:**
   - SQL injection detection for raw string interpolation in database driver queries (`cursor.execute(f"SELECT ... {user_input}")`).
   - Server-Side Request Forgery (SSRF) heuristics on unchecked URL fetching.
