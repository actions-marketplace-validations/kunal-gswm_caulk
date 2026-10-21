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
| **Markdown & Table Injection via Untrusted Filenames** | Scanned repositories contain malicious filenames, paths, or titles with pipes (`\|`), newlines, HTML tags, or links intended to split table columns, forge passing scan headers (`### Scan Result: ✅ Passed`), or inject active HTML/images into CI summaries. | `summary.py` renders all dynamic text through safe formatting helpers (`escape_markdown_table_cell`, `format_table_code_cell`, `format_markdown_code_span`). Newlines and control characters are stripped/replaced with spaces, pipes are escaped as `\|`, HTML brackets are escaped as `&lt;`/`&gt;`, links/images are neutralized as `\[...\]`, and code spans dynamically scale backtick delimiters. |
| **Code Fence Breakout in CI Error Reporting** | Scanner error output containing triple backticks (```` ``` ````) terminates fenced error blocks and executes arbitrary Markdown headings or text. | `format_markdown_fenced_code` counts the longest run of backticks in error content and dynamically opens and closes the fence with $\max(3, M+1)$ backticks, making breakout syntactically impossible under CommonMark/GFM rules. |
| **Unsupported or Malformed CI Action Inputs** | Workflow configurations supply invalid Python versions (e.g. `2.7`, `3.9`) or malformed parameters that could bypass runtime checks or trigger ambiguous setup failures. | `action.yml` enforces an early validation composite step running *before* `actions/setup-python`, validating `python-version` against supported releases (>=3.11) and checking `severity-threshold` and `check-vulns` against strict whitelists, aborting immediately on failure. |
| **Git Command Injection via Branch, Tag, or File Names** | Scanned repositories containing branch names, tag names, or commit messages with shell metacharacters (`$(rm -rf ...)`, `;`, `&`, `|`) intended to execute host commands. | All Git interactions strictly pass argument lists directly to OS `subprocess` APIs (`["git", "-C", path, ...]`) with `shell=False`. Shell interpreters are never invoked. |
| **Git Submodule Traversal & Arbitrary Checkout** | Crafted Git submodules (mode `160000`) intended to trigger remote cloning, network requests, or host directory creation. | Diffs matching file mode `160000` are detected and skipped immediately. Caulk operates entirely offline, never invokes `git checkout`, and never runs `git submodule update`. |
| **Stream Desynchronization via Oversized Historical Blobs** | Giant multi-megabyte blobs in Git history causing out-of-memory exhaustion or breaking stream alignment in persistent `git cat-file --batch` processes. | `GitBlobReader` validates the header blob size before buffering content. Blobs exceeding `max_blob_size` (default 2MB) are drained in 64KB chunks and discarded, preserving strict stream synchronization without unbounded memory growth. |
| **Git Option Injection via CLI `--ref` Parameter** | User-controlled ref parameters starting with hyphens (e.g. `--ref --help`, `-v`) hijack Git subcommands or pass unintended options. | `validate_git_ref()` strictly verifies that refs do not begin with `-`, contain whitespace, control characters, or invalid ref syntax prior to executing any subprocess. |
| **Subprocess Pipe Deadlocks during Git Streaming** | Verbose git stderr output filling OS pipe buffers while the parent process streams stdout, causing indefinite deadlocks. | `stream_git_log` and `GitBlobReader` start background daemon threads that continuously drain `proc.stderr` into bounded buffers, preventing pipe saturation deadlocks across all platforms. |
| **Silent False-Clean Scans on Incomplete History Traversal** | Subprocess failures, missing objects, corrupt packs, skipped oversized blobs, or timeouts silently producing an empty findings list and claiming a clean scan. | Typed blob outcome isolation (`BlobReadStatus`). If any coverage gap, missing object, corrupt object, skipped oversized blob, or traversal error occurs, `is_complete` is set to `False`, the coverage gap is disclosed in reports, and Caulk exits with code 3 (`EXIT_EXECUTION_ERROR`). |
| **Shallow Clone Truncation Evasion** | Default CI checkouts (`actions/checkout` with `fetch-depth: 1` or shallow clones) omit older historical commits, allowing historical credentials to evade detection and falsely pass CI as clean. | `is_shallow_repo()` executes `git rev-parse --is-shallow-repository`. If true, Caulk refuses to declare the scan complete (`is_complete = False`), records partial history scope, and fails closed with exit code 3 (`EXIT_EXECUTION_ERROR`) unless actionable findings are found (exit code 1). Action users are explicitly directed to configure `fetch-depth: 0`. |
| **Arbitrary Code Execution via Scanned Python Code** | Scanned Python files contain malicious module-level statements, decorators, or dunder hooks intended to trigger execution during static analysis. | Caulk parses code purely into syntax trees using Python's standard-library `ast.parse()`. Caulk **never** executes, imports, or dynamic-evaluates scanned repository files (`import`, `importlib`, `exec()`, and `eval()` are strictly prohibited). |
| **Scanner Crash via Syntax Errors or Malformed Python** | Malformed Python files with unclosed string literals, invalid indentation, or broken syntax intended to crash the scanner or abort remaining security checks. | `ScanContext.get_ast()` catches `SyntaxError`, `ValueError`, and `TypeError` gracefully, returning `None`. SAST analysis safely skips unparseable files without crashing, and remaining files continue to be evaluated. |
| **Secret Leakage in SAST Finding Evidence** | Sink call arguments contain sensitive credentials or tokens embedded in code lines. | All SAST evidence snippets are truncated to a maximum of 120 characters and sanitized through `sanitize_evidence()`, redacting AWS keys, tokens, passwords, and private keys. |

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
4. **Unreachable Git Objects & Remote Refs:** Git history scanning inspects commits reachable from local refs (branches, tags, HEAD). Unreachable loose objects, unreferenced reflog entries, and remote branches that have not been fetched into local refs are not inspected.
