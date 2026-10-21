# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-10-21

### Added
- **Python AST Static Application Security Testing (SAST001 & SAST002):**
  - Deterministic AST analysis and intraprocedural taint tracking implemented with Python standard-library `ast` and zero third-party dependencies.
  - `SAST001` (Python SQL Injection): Flags dynamic inputs formatted into SQL query strings (via f-strings, concatenation `+`, `%` formatting, or `.format()`) and executed by database sinks (`cursor.execute()`, `.executemany()`, `.executescript()`, `Model.objects.raw()`).
  - `SAST002` (Command Injection via Shell Execution): Flags dynamic untrusted inputs passed to shell sinks: always-shell calls (`os.system()`, `os.popen()`, `subprocess.getoutput()`, `subprocess.getstatusoutput()`) and subprocess calls requiring `shell=True` (`subprocess.run()`, `Popen()`, `call()`, `check_call()`, `check_output()`).
  - False-positive controls: Fully exempts parameterized queries (`cursor.execute("SELECT ...", (param,))`), static queries, non-DB `.execute()` calls (`task_runner.execute(...)`), safe subprocess argument lists without `shell=True`, and static shell commands.
  - Comprehensive source detection: Flask request properties and methods (`args`, `form`, `values`, `cookies`, `json`, `data`, `get_json()`), Django request attributes (`GET`, `POST`, `COOKIES`, `headers`), `input()`, `builtins.input()`, and `sys.argv[...]` / `argv[...]`.
  - Intraprocedural taint engine: Evaluates execution-order statements, tracks intermediate variable assignments, unions branch taints across `if/else` and `try/except` blocks, propagates taint through string transformations (`strip`, `lower`, `upper`, `replace`, etc.), and clears taint upon safe constant reassignment.
  - Scope isolation: Function and class definitions maintain strictly isolated local variable scopes.
  - Import aliasing resolution: Resolves module aliases (`import subprocess as sp`) and imported function symbols (`from os import system as sys_exec`, `from subprocess import run as execute`).
  - Shared AST and analysis result caching in `ScanContext` (`_ast_cache`, `_sast_cache`).
- **CLI Scan Category & Disable Flags:**
  - Added `--category` / `-C` option to `caulk-security scan` to restrict scanner evaluation to specific categories (e.g. `--category SAST`).
  - Added `--disable` / `-d` option to `caulk-security scan` to disable specific rules from the CLI (e.g. `--disable SAST001`).
- **Git History Secret Scanner (`caulk-security history scan`):**
  - Dedicated CLI command to scan historical Git commits for exposed credentials across reachable branches, tags, and HEAD.
  - Streaming commit metadata and file diffs using `git log -c --raw --no-renames --root --no-abbrev`.
  - Batch blob extraction via persistent `git cat-file --batch` process with guaranteed stream synchronization, memory bounds, and binary null-byte filtering.
  - Full attribution of historical credentials to the introducing commit SHA, author name/email, author timestamp (ISO 8601), and commit subject.
  - Detection of secrets even if deleted, renamed, or replaced with placeholders in subsequent commits.
  - In-memory blob-level caching (`blob_sha -> findings template`) eliminating redundant regex inspection on identical Git object hashes across commits.
  - Parent-blob delta comparison ensuring secrets are reported exclusively for the commit where they were introduced or modified, preventing phantom duplicates on merge commits or branching workflows.
  - Full handling of merge conflict resolutions (evil merges) and multiple independent root commits (orphan branches).
  - Mandatory 5-point remediation guidance on all historical findings (exposure window, deletion ineffectiveness, immediate provider rotation, access log auditing, and safe post-rotation history rewriting).
  - Configurable scan limits: `--severity-threshold`, `--max-depth`, `--since`, `--ref`, `--max-blob-size`, `--exclude`, and `--no-progress`.
  - Deterministic exit codes: `0` for clean, `1` for findings at or above threshold, `2` for usage errors, and `3` for execution errors or incomplete scans.
- **Fail-Safe Git Subprocess & Object Handling:**
  - Typed blob read outcome isolation (`BlobReadStatus`: `SUCCESS`, `SKIPPED_BINARY`, `SKIPPED_OVERSIZED`, `MISSING_OBJECT`, `CORRUPT_OBJECT`, `READ_ERROR`).
  - Concurrent background stderr draining threads preventing pipe buffer deadlocks during `git log` and `git cat-file --batch`.
  - Strict input validation for `--ref` preventing option injection and invalid ref syntax.
  - Scan completeness tracking (`is_complete = False` on missing objects, corrupt objects, skipped oversized blobs, or timeouts).
  - Transparent scan scope disclosure in terminal reports, JSON reports, and GitHub Step Summaries (`--max-depth`, `--since`, `--ref`).
  - Strict exit semantics: incomplete history scans cannot receive clean exit code `0`; exit `3` (`EXIT_EXECUTION_ERROR`) is enforced.
  - GitHub Action fail-safe enforcement: incomplete history scans emit `scan-result=error` and render `⚠️ Incomplete Inspection` step summaries.
- **GitHub Action History Scanning Support:**
  - Added optional `scan-history: 'false'` action input allowing CI workflows to run historical secret scanning instead of working-tree inspection.
  - Extended GitHub Step Summary reporting with commit SHA coordinates and history scan metrics.
- **Shallow Clone Detection & Coverage Protection:**
  - Reliable shallow clone detection via `git rev-parse --is-shallow-repository` in `is_shallow_repo()`.
  - Fail-safe history completeness: shallow clones refuse clean exit code `0`, marking `is_complete = False` and exiting with code `3` (`EXIT_EXECUTION_ERROR`) unless actionable findings are discovered (exit code `1`).
  - Actionable diagnostic reporting directing developers and CI workflows to configure `fetch-depth: 0` with `actions/checkout`.
  - Dynamic scope and limitation disclosure (`Partial history (shallow clone)`) across terminal reports, JSON reports, and GitHub Step Summaries.
- **Test Suite Expansion:**
  - Added 25 comprehensive unit and integration tests (`tests/test_history.py` and `tests/test_action.py`) covering all Git topologies (initial commit, deleted secrets, replaced secrets, merge commits, tags, orphan branches, duplicate blobs, oversized blobs, corrupt objects, shallow clone rejection, and secret redaction).

### Changed & Fixed
- **Python SAST Precision, Scope Handling & Robustness Hardening:**
  - **Exception Dataflow:** Fixed `ast.Try` taint propagation so reachable taints from `try`, `except`, and `else` blocks conservatively flow into `finalbody` rather than resetting to the pre-try state.
  - **Same-Line Sinks:** Replaced line-based deduplication with `(lineno, col_offset)` tracking and distinct fingerprints so multiple sinks on the same source line are all captured.
  - **False-Positive Elimination on `.raw()`:** Enforced database receiver tokens and SQL command keywords on `.raw()` methods, eliminating false positives on non-database methods such as `camera.raw(user_input)`.
  - **Refined Database Receivers:** Replaced generic `"client"` substring matching with specific `"db_client"` and `"sql_client"`, preventing false positives on HTTP/API client methods without SQL keywords.
  - **Walrus & Ternary Expressions:** Added taint propagation and variable assignment tracking for walrus operators (`ast.NamedExpr`) and ternary expressions (`ast.IfExp`).
  - **Loop Target Unpacking:** Supported tuple/list target unpacking in `for` and `async for` loops (`for k, v in request.form.items():`), propagating taint to all unpacked target names.
  - **Expanded Sources & Collection Methods:** Added `.getlist()`, `.keys()`, `.values()`, `.items()`, `.pop()`, `.popitem()`, `.setdefault()`, and Django `request.body` / `request.FILES` / `request.META` to taint sources.
  - **Branch Import Preservation:** Propagated module and function aliases declared inside `if` and `try` statements to the enclosing function/module scope.
  - **Multiline Evidence Formatting:** Replaced partial first-line excerpts with AST unparsed, whitespace-normalized snippets bounded to 120 characters with secret redaction.
  - **Case-Insensitive CLI Rule Disabling:** Normalized `--disable` arguments to uppercase so `--disable sast001` cleanly disables `SAST001`.
  - **Recursion Safety:** Safely handled `RecursionError` in `ScanContext.get_ast()` and `PythonASTSecurityAnalyzer.analyze()` on pathologically nested expressions without crashing scans.
- **Python SAST Incomplete Analysis Tracking & Fail-Safe Semantics:**
  - Replaced silent skipping of unparseable or deep Python ASTs with bounded per-file diagnostic tracking in `ScanContext` and `ScanResult.errors`.
  - Discloses coverage gaps when AST parsing fails (`RecursionError`, `SyntaxError`, `ValueError`, `TypeError`) or SAST traversal encounters `RecursionError`, without leaking source contents or embedded credentials.
  - Scan completeness enforcement: sets `ScanSummary.is_complete = False` when any eligible Python file cannot be fully analyzed, while preserving findings from all successfully inspected files.
  - Fail-safe CLI exit semantics: incomplete scans without threshold-breaching findings now exit with code `3` (`EXIT_EXECUTION_ERROR`); scans with threshold-breaching findings preserve exit code `1`; only fully completed scans with zero threshold breaches return `0`.
  - Terminal reporting transparency: displays an unmistakable `Scan Incomplete` banner even when findings are present, and never displays `Scan Clean` on incomplete scans.
  - GitHub Action integration: maps incomplete scans to `scan-result=error` when findings do not breach the configured severity threshold.


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
