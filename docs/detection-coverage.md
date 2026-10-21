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

### D. Git History Secret Scanning (`HISTORICAL`) — Added in v0.3.0

Caulk includes a dedicated Git history inspection subsystem (`caulk-security history scan`) reusing the deterministic secret rules (`SEC001`–`SEC008`) across all reachable commits in the repository:

- **Attribution:** Maps findings directly to commit SHA, author name/email, author timestamp (ISO 8601), and commit message subject.
- **Deduplication:** Uses parent-blob comparison to report findings exclusively in the commit where the secret was introduced or modified.
- **Deleted & Replaced Secrets:** Detects secrets even if removed, renamed, or replaced with placeholders in subsequent commits.
- **5-Point Remediation:** Generates tailored, actionable 5-step guidance (historical exposure, deletion ineffectiveness, immediate provider rotation, access log auditing, and safe post-rotation history rewriting).

### E. Python Static Application Security Testing (`SAST`) — Added in v0.3.0

Caulk implements deterministic AST-based static analysis with intraprocedural taint tracking across Python source files:

| Rule ID | Title | Severity | Confidence | Target Files | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SAST001` | Python SQL Injection | `HIGH` | `HIGH` | `*.py` | Detects unsanitized dynamic values (from Flask/Django requests, `input()`, `sys.argv`) formatted via f-strings, concatenation (`+`), `%` formatting, or `.format()` and executed by database sinks (`cursor.execute()`, `.executemany()`, `.executescript()`, `.raw()`). Parameterized queries (`%s`, `?`, `:param`) and static queries are not flagged. |
| `SAST002` | Command Injection via Shell Execution | `HIGH` | `HIGH` | `*.py` | Detects dynamic untrusted values passed to always-shell sinks (`os.system()`, `os.popen()`, `subprocess.getoutput()`, `subprocess.getstatusoutput()`) or subprocess calls with `shell=True` (`subprocess.run()`, `Popen()`, `call()`, `check_call()`, `check_output()`). Resolves import aliases. Safe argument lists without `shell=True` are not flagged. |

---

## 2. Planned Checks (Future Milestones)

The following capabilities are architected for upcoming releases and will be added under the same deterministic rule interface:

1. **Lockfile Parsing Extensions:**
   - Full parser for `yarn.lock` (v1 and v2 Berry) and `pnpm-lock.yaml`.
   - Python `poetry.lock` and `Pipfile.lock` deep parsing.
2. **Advanced Infrastructure-as-Code (IaC) Rules:**
   - Terraform / OpenTofu security misconfiguration checks (unencrypted S3 buckets, open security groups `0.0.0.0/0`).
   - GitHub Actions workflow analysis (unpinned actions, dangerous `pull_request_target` triggers, secret exfiltration vectors).
3. **Targeted Semantic AST Checks:**
   - Server-Side Request Forgery (SSRF) heuristics on unchecked URL fetching.
   - Insecure deserialization checks (`pickle.loads`, `yaml.load` with unsafe loaders).
