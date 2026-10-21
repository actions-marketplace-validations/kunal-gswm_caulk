# Threat Model & Security Design

Caulk is security software. As such, its own attack surface must be minimized. This document defines the threat model, trust boundaries, anticipated abuse vectors, and engineering mitigations implemented in Caulk.

---

## 1. Trust Boundaries & Threat Actors

### Primary Assumption: Untrusted Repository Contents
Caulk treats all scanned repositories, directory structures, filenames, manifest files, and configuration files as **untrusted input**.

### Threat Scenarios
1. **Malicious Repository Submission:** An attacker tricks a developer or automated CI into scanning a cloned repository specifically crafted to exploit the scanner (e.g. via path traversal, symlink escapes, or resource exhaustion).
2. **Secret Leaks via Scanner Output:** The scanner discovers legitimate credentials and inadvertently publishes or logs raw secrets into CI logs, diagnostic traces, or public consoles.
3. **Data Exfiltration / Network Snooping:** Proprietary source code or sensitive tokens leak over the network during vulnerability lookups.
4. **Arbitrary Code Execution via Package Ecosystems:** The scanner executes repository code (e.g. running `setup.py` or `npm install`) during discovery or inventory.

---

## 2. Attack Vectors & Mitigations

| Attack Vector | Realistic Impact | Caulk Mitigation |
| :--- | :--- | :--- |
| **Symlink Escapes / Arbitrary File Read** | A repository contains a symlink pointing to sensitive host paths (e.g. `/etc/shadow`, `~/.ssh/id_rsa`, or `C:\Windows\System32`). | `discovery.py` validates `resolved_path.is_relative_to(repo_root)`. Any symlink pointing outside the scan root is skipped immediately and recorded as `symlink_outside_root`. |
| **Directory Loops & Deep Traversal** | Deeply nested directory symlinks or recursion bombs intended to trigger infinite loops or stack overflows. | Symlinks are never followed recursively (`followlinks=False`), and traversal strictly terminates if directory depth exceeds `max_directory_depth` (default 30). |
| **Resource Exhaustion (Memory / CPU)** | Gigantic multi-gigabyte dump files, minified bundles, or binary blobs designed to exhaust host RAM. | Pre-read size limits (`max_file_size_bytes`, default 2MB). Files exceeding the limit are skipped. The first 8KB of files are checked for null bytes (`\x00`); binary files are rejected without reading the full contents into memory. |
| **Arbitrary Code Execution via Package Tools** | Project inspection executes `setup.py`, `npm install`, or `pip` hooks, executing arbitrary attacker code. | **Absolute rule:** Caulk **never** executes package managers, target scripts, or application entrypoints. Dependency inventory is performed purely via deterministic static file parsers (`tomllib`, `json`, regex). |
| **Unsafe Deserialization** | Malicious YAML or serialized objects in repository configs trigger remote code execution. | Zero use of `pickle`, `eval()`, or unsafe object loaders. Configuration parsing uses Python's standard `tomllib` and `json` libraries. |
| **Secret Leaks in CI Logs / Reports** | Discovered AWS keys or passwords are printed in full, leaking to build logs or screenshots. | Mandatory redaction pipeline (`redaction.py`). Secrets are masked (e.g. `AKIA************ABCD`, `postgres://user:[REDACTED]@host`). Raw credentials never appear in evidence strings, terminal reports, JSON output, or exception messages. |
| **Telemetry & Outbound Exfiltration** | Scanner uploads source code, environment variables, or private finding details to external services. | **Zero telemetry.** Caulk contains no telemetry, analytics, tracking, or cloud accounts. Repository scanning is strictly offline by default. |
| **Vulnerability Provider Information Leak** | Querying external vulnerability databases reveals source code or confidential secrets. | Advisory queries (`--check-vulns`) only transmit package names and versions (e.g. `requests@2.28.0`) to the public OSV.dev batch API (`api.osv.dev`). Source code, repository URLs, file paths, and secrets are **never** transmitted. |
| **CI Supply-Chain / Script Injection** | Malicious branch names, PR titles, or filenames trigger arbitrary shell execution via `${{ inputs... }}` interpolation. | Composite action passes inputs strictly through process environment variables (`INPUT_PATH`, `INPUT_SEVERITY_THRESHOLD`). Shell source code contains zero direct script interpolations. |
| **Privilege Escalation via CI Tokens** | Scanner runs with elevated GitHub permissions or via `pull_request_target`, allowing compromised actions or workflows to write to repository contents. | Caulk strictly advises and documents minimal `permissions: contents: read`. Caulk never requires write permissions, never posts comments requiring write tokens, and strictly discourages `pull_request_target`. Third-party actions are pinned to full commit SHAs. |
| **Credential Persistence in Step Summaries** | Job summaries published to `GITHUB_STEP_SUMMARY` persist unredacted secret fragments in PR check views. | `src/caulk/reporting/summary.py` intentionally excludes raw evidence and snippet strings from Markdown tables, referencing only file coordinates (`file_path:line_number`). |

---

## 3. GitHub Action & CI Security Posture

1. **Read-Only Permissions:**
   The action requires only `contents: read` to inspect checked-out repository files. It does not require `issues: write`, `pull-requests: write`, or `checks: write`.
2. **Pinned Action Dependencies:**
   All third-party composite action dependencies (e.g., `actions/setup-python`) are pinned to immutable 40-character commit SHAs rather than mutable branch or major version tags.
3. **No Execution of Repository Code:**
   The action installs Caulk directly from `GITHUB_ACTION_PATH`. It never executes `npm install`, `pip install`, `setup.py`, or application scripts from `GITHUB_WORKSPACE`.
4. **Temporary Report Isolation:**
   JSON reports are generated in `RUNNER_TEMP`, an ephemeral directory managed by the runner host that is cleared when the job completes, preventing artifact pollution in the target codebase.

---

## 4. Limitations & Residual Risks

1. **Static Analysis Limitations:** Static pattern matching cannot guarantee that every discovered secret is live or active, nor that every unflagged file is free of secrets. Pattern-based detection can produce false positives and false negatives.
2. **Clean Scan Disclaimer:** A clean scan indicates that no issues matched Caulk's active deterministic rules. **A clean scan does not prove an application is secure.**
3. **OS-Level Permissions:** Caulk operates within the permissions of the user executing the CLI. It should not be executed with elevated privileges (e.g. `sudo` or Administrator) when inspecting untrusted repositories.
