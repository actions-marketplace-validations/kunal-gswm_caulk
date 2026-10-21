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
| **Vulnerability Provider Information Leak** | Querying external vulnerability databases reveals source code or confidential secrets. | Advisory queries (`--check-vulns`) only transmit package names and versions (e.g. `requests@2.28.0`) to the public OSV.dev batch API. Source code, paths, and secrets are **never** transmitted. |

---

## 3. Limitations & Residual Risks

1. **Static Analysis Limitations:** Static pattern matching cannot guarantee that every discovered secret is live or active, nor that every unflagged file is free of secrets. Pattern-based detection can produce false positives and false negatives.
2. **Clean Scan Disclaimer:** A clean scan indicates that no issues matched Caulk's active deterministic rules. **A clean scan does not prove an application is secure.**
3. **OS-Level Permissions:** Caulk operates within the permissions of the user executing the CLI. It should not be executed with elevated privileges (e.g. `sudo` or Administrator) when inspecting untrusted repositories.
