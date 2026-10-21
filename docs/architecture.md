# Architecture & System Design

Caulk is engineered as a deterministic, local-first security scanner with minimal attack surface and small runtime dependencies.

```mermaid
flowchart TD
    CLI[CLI: caulk-security scan / init / rules] --> Config[CaulkConfig: .caulk.toml]
    CLI --> Scanner[CaulkScanner Orchestrator]
    Config --> Scanner

    subgraph Discovery ["Safe Filesystem Discovery"]
        Scanner --> DiscoveryEngine[discovery.py: Safe Walker]
        DiscoveryEngine --> DepthCheck[Max Depth & Loop Guard]
        DiscoveryEngine --> SymlinkCheck[Symlink Escape Validation]
        DiscoveryEngine --> SizeLimit[Max File Size Check]
        DiscoveryEngine --> BinaryFilter[Binary Content Heuristic]
        DiscoveryEngine --> Exclusions[Exclusion Matching]
        DiscoveryEngine --> EcosystemDetect[Ecosystem Manifest Detection]
    end

    subgraph RuleEngine ["Deterministic Rule Engine"]
        Scanner --> Registry[RuleRegistry: rules/registry.py]
        Registry --> Secrets[Secret Rules: SEC001-008]
        Registry --> ConfigRules[Config Rules: CFG001-004]
        Registry --> DepRules[Dependency Rules: DEP001-002]
        Scanner --> Context[ScanContext & Cached File Reader]
    end

    subgraph Advisories ["Optional Advisory Provider"]
        Scanner --> AdvScanner[DependencyVulnerabilityScanner]
        AdvScanner --> OfflineProv[OfflineAdvisoryProvider - Default]
        AdvScanner -.->|"--check-vulns"| OSVProv[OSVAdvisoryProvider - Batch API]
    end

    subgraph Processing ["Deduplication & Sanitization"]
        Scanner --> Redaction[Redaction Engine: Mask & Sanitize]
        Scanner --> Deduplication[Fingerprint Hash Deduplication]
        Scanner --> DeterministicSort[Severity Rank & Path Sorting]
    end

    subgraph Reporting ["Output Renderers"]
        Scanner --> TerminalRep[Rich Terminal Output]
        Scanner --> JsonRep[Deterministic JSON Serialization]
    end
```

---

## 1. Scanner Pipeline

1. **CLI Invocation:**
   The user invokes `caulk-security scan [PATH]` with flags like `--format [text|json]`, `--severity-threshold [SEV]`, `--output [FILE]`, or `--check-vulns`.
2. **Configuration Loading:**
   `CaulkConfig` loads `.caulk.toml` (if present) using Python standard library `tomllib`, applying safe default limits (2MB file size ceiling, 30-level directory depth limit, standard directory exclusions like `.git` and `node_modules`).
3. **Safe Filesystem Discovery (`discovery.py`):**
   - Resolves target paths canonicalized to absolute coordinates.
   - Prevents symlink escapes: any symlink resolving outside the repository root is skipped and logged.
   - Enforces depth limits to prevent recursion bombs.
   - Inspects the first 8KB of files for null bytes (`\x00`) to avoid reading binary objects or compiled code into memory.
   - Detects active software ecosystems (`python`, `javascript`, `docker`).
4. **Rule Selection & Safe Execution (`rules/`):**
   - Active rules are filtered by ecosystem and user disablement preferences.
   - Each rule executes within a guarded `try/except` block; errors in individual rules are logged as non-fatal warnings without crashing the scan.
5. **Secret Sanitization & Redaction (`redaction.py`):**
   - All evidence snippets and matched strings are passed through the redaction engine.
   - Credential values, access keys, private key materials, and database passwords are masked (e.g. `AKIA************ABCD`, `postgres://user:[REDACTED]@host`). Raw credentials never enter findings, reports, or logs.
6. **Deduplication & Deterministic Ordering:**
   - Findings compute a SHA-256 fingerprint over `(rule_id, normalized_relative_path, line_number, title)`.
   - Redundant findings are deduplicated.
   - Findings are deterministically sorted by:
     1. Severity rank descending (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`)
     2. Category
     3. Normalized relative file path
     4. Line number
     5. Rule ID
7. **Report Rendering (`reporting/`):**
   - **Terminal:** Structured visual panels rendered via `Rich`, answering the four core developer questions (*What*, *Where*, *Why*, *What to do*).
   - **JSON:** Clean, schema-consistent machine-readable JSON written to stdout or specified file.

---

## 2. Rule Architecture

Every rule inherits from `caulk.rules.base.Rule` and provides:

```python
class Rule(ABC):
    rule_id: str  # Unique identifier (e.g. SEC001, CFG001)
    title: str  # Human-readable summary
    description: str  # Technical observation
    severity: Severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: Confidence  # CONFIRMED, HIGH, MEDIUM, LOW
    category: FindingCategory  # SECRET, CONFIGURATION, DEPENDENCY, SAST
    impact: str  # Realistic security risk explanation
    remediation: str  # Actionable step-by-step fix
    references: list[str]  # External OWASP / CWE references
    file_patterns: list[str]  # Target file globs (e.g. ["Dockerfile*"])
    supported_ecosystems: list[str]  # Ecosystem filters (e.g. ["python"])

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]: ...
    def scan_project(self, context: ScanContext) -> list[Finding]: ...
```

---

## 3. GitHub Action Architecture

Caulk provides an official composite action (`action.yml`) paired with an action runtime coordinator (`src/caulk/action.py`) and step summary renderer (`src/caulk/reporting/summary.py`):

```mermaid
flowchart TD
    GHA[GitHub Actions Runner] --> ActionYml[action.yml: Composite Action]
    ActionYml --> SetupPy[setup-python: Pinned SHA]
    ActionYml --> PipInstall["pip install: GITHUB_ACTION_PATH"]
    ActionYml --> ActionPy[python -m caulk.action]

    subgraph ActionCoordinator ["Action Runtime Coordinator (action.py)"]
        ActionPy --> InputVal[Validate Inputs: path, threshold, check-vulns]
        ActionPy --> WorkspaceResolve[Resolve Path vs GITHUB_WORKSPACE]
        ActionPy --> RunScanner[Subprocess: caulk-security scan]
        RunScanner --> TempReport[Write JSON: RUNNER_TEMP]
        TempReport --> SummaryGen[generate_step_summary: summary.py]
        SummaryGen --> StepSummary[Append GITHUB_STEP_SUMMARY]
        SummaryGen --> ActionOutputs[Emit GITHUB_OUTPUT: scan-result, findings-count, report-path]
        ActionOutputs --> ExitHandler[Exit with Scanner Exit Code]
    end
```

### Key Architectural Safeguards in GitHub Actions
1. **Isolated Path Coordinates:**
   - `GITHUB_ACTION_PATH` strictly identifies the checked-out Caulk action repository files used for installing Caulk and its runtime dependencies.
   - `GITHUB_WORKSPACE` strictly identifies the scanned repository's working directory.
2. **Safe Input Passing:**
   - Action parameters are never interpolated into shell scripts (`${{ inputs.path }}` inside bash is avoided). All inputs pass through structured environment variables (`INPUT_PATH`, `INPUT_SEVERITY_THRESHOLD`, `INPUT_CHECK_VULNS`).
3. **Evidence Redaction in CI:**
   - `summary.py` formats Markdown tables with Rule IDs, Severity, and Location references (`file:line`). Code snippets and raw matched strings are excluded to prevent credentials from persisting in build summaries.
4. **Exit Code Propagation:**
   - Scanner exit codes (`0` clean, `1` breach, `2` usage error, `3` execution error) are preserved. Finding-based failures exit with code 1 **only after** the step summary and outputs have been written.

---

## 4. Git History Secret Scanning Architecture (`src/caulk/history/`)

Added in v0.3.0, the Git history scanning subsystem detects credentials committed to Git history across reachable branches, tags, and commits without altering the working directory or checking out branches.

```mermaid
flowchart TD
    CLI[caulk-security history scan] --> HistoryScanner[GitHistoryScanner: history/scanner.py]
    HistoryScanner --> GitLog[stream_git_log: git log -c --raw --root]
    GitLog --> Diffs[Stream CommitDiff Entries]

    subgraph BlobInspection ["Blob Batch Streaming & Caching"]
        Diffs --> BlobReader[GitBlobReader: git cat-file --batch]
        BlobReader --> BinaryFilter[Null Byte Binary Check]
        BlobReader --> SizeCheck[max_blob_size Ceiling]
        BlobReader --> BlobCache[Blob SHA In-Memory Cache]
    end

    subgraph DeltaEngine ["Parent-Delta Attribution Engine"]
        BlobCache --> SecretRules[Rules SEC001-SEC008]
        SecretRules --> ParentDiff[Compare with Parent src_blob_shas]
        ParentDiff --> AttributedFinding[Attribute to Commit SHA / Author / Timestamp]
    end

    AttributedFinding --> Remediation[Generate 5-Point Historical Remediation]
    Remediation --> Fingerprint[SHA-256 Fingerprint with Commit SHA]
    Fingerprint --> Results[ScanResult with Historical Summary]
```

### Key Architectural Principles
1. **Zero Working-Tree Modification:** Traversal operates exclusively via low-level Git object inspection (`git log -c --raw` and `git cat-file --batch`). No commits are checked out, no files on disk are touched, and HEAD never moves.
2. **Subprocess Isolation:** Git interactions strictly use argument lists (e.g. `["git", "-C", path, ...]`). Shell interpreters are never invoked (`shell=False`), preventing command injection.
3. **Blob-Level Caching:** Because Git object SHAs uniquely represent file content, every blob SHA is inspected against secret rules at most once. Subsequent references to the same blob SHA across commits or branches are instant cache hits.
4. **Parent Delta Deduplication:** Caulk compares findings in the destination blob against all parent blobs for that file in the commit. A finding is reported if and only if it was newly introduced or modified in that commit, eliminating phantom duplicates on merge commits.
5. **Mandatory 5-Point Remediation:** All historical findings generate actionable guidance explaining that deletion does not invalidate a secret, requiring immediate provider rotation, log auditing, and safe post-rotation history rewriting.
6. **Fail-Safe Completeness & Error Isolation:**
   - Typed blob read outcomes (`BlobReadStatus`) distinguish successful reads, intentionally skipped binary files, skipped oversized blobs, missing objects, corrupt objects, and I/O errors.
   - Any coverage gap, missing object, corrupt pack, skipped oversized blob, or traversal interruption sets `is_complete = False` and triggers non-zero exit code `3` (`EXIT_EXECUTION_ERROR`), preventing incomplete scans from falsely appearing clean.
   - Background daemon threads drain `stderr` concurrently, preventing OS pipe buffer deadlocks.
   - User-supplied refs are strictly validated against option injection (`--ref` cannot begin with `-`).
7. **Shallow Clone Detection & Coverage Protection:**
   - Before scanning historical refs, Caulk validates repository completeness via `is_shallow_repo()` executing `git rev-parse --is-shallow-repository`.
   - If the repository is a shallow clone (`true`), Caulk refuses to attest that the scan was a complete historical evaluation: `is_complete` is set to `False`, the scope is flagged as `is_shallow: True` (`Partial history (shallow clone)`), and an actionable error directing users to `fetch-depth: 0` is recorded.
   - If zero findings are discovered in available shallow commits, Caulk exits with `3` (`EXIT_EXECUTION_ERROR`), preventing truncated history from producing false clean results in CI.
   - Any valid findings discovered in the available commits are preserved and reported, returning exit code `1` (`EXIT_FINDINGS_BREACH_THRESHOLD`).

---

## 5. Python AST Security Analysis Architecture (`src/caulk/rules/python_sast.py`)

Added in v0.3.0, the Python SAST subsystem delivers deterministic static analysis with intraprocedural taint tracking using Python's standard-library `ast` module:

```mermaid
flowchart TD
    File[Python Source File] --> Context[ScanContext.get_ast: Cached AST Parse]
    Context --> Analyzer[PythonASTSecurityAnalyzer]

    subgraph TaintEngine ["Intraprocedural Taint Tracking Engine"]
        Analyzer --> ScopeManager[Scope Isolation: Functions & Classes]
        ScopeManager --> SourceDetect[Detect Taint Sources: request, input, argv]
        SourceDetect --> Propagation[Track Assignments, f-strings, +, %, .format]
        Propagation --> TaintClearing[Clear Taint on Safe Overwrite]
        Propagation --> BranchUnion[Union Taint Across if/else & try/except]
    end

    subgraph SinkEvaluation ["Sink Evaluation & False-Positive Controls"]
        BranchUnion --> SQLSink[SAST001: DB-API execute, SQLite executescript, Django raw]
        SQLSink --> SQLFilter[Filter: Receiver Tokens, SQL Keywords, Parameterized Query Exemption]
        BranchUnion --> ShellSink[SAST002: os.system, os.popen, subprocess shell=True]
        ShellSink --> ShellFilter[Filter: shell=True Check, Import Aliasing, Safe List Exemption]
    end

    SQLFilter --> Findings[Typed Finding with Exact Call Line Number]
    ShellFilter --> Findings
    Findings --> Sanitize[Sanitize Evidence Snippet <= 120 chars]
```

### Key Architectural Principles
1. **Zero External Dependencies:** Built purely on Python standard-library `ast`. Never imports or executes scanned repository code.
2. **ScanContext Caching:** AST trees are parsed at most once per file (`ScanContext.get_ast`). Analysis results are cached in `_sast_cache`, enabling `SAST001` and `SAST002` to share a single traversal pass.
3. **Execution-Order Statement Traversal:** Statements are evaluated in execution order. Taint propagates through assignments and intermediate variables (`a = input(); b = f"prefix_{a}"; c = b.strip()`), and is cleared when a variable is overwritten with a safe constant or expression.
4. **Scope Isolation:** Function definitions (`ast.FunctionDef`, `ast.AsyncFunctionDef`) and class definitions maintain independent local scopes. Taint in one function does not leak to other functions or the module level.
5. **False-Positive Resistance:**
   - Parameterized queries (`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`) evaluate the query string argument as an untainted constant, completely avoiding false positives.
   - Non-database `.execute()` calls (e.g. `task_runner.execute(...)`) are distinguished by checking receiver naming patterns (`cursor`, `cur`, `conn`, `db`, `session`) and SQL keyword presence.
   - Subprocess invocations without `shell=True` (e.g. `subprocess.run(["ping", host])`) are recognized as safe argument lists and omitted.
6. **Import Aliasing Resolution:** Tracks both module-level and function-level import aliases (e.g. `import subprocess as sp`, `from subprocess import run as execute`, `from os import system as exec_cmd`).
7. **Line-Accurate Attribution:** Reports the exact line number of the sink call (`call.lineno`), with bounded evidence snippets sanitized against secret leakage.

---

## 6. GUI & Extension Readiness

The CLI, rule engine, discovery walker, and reporting layers are strictly decoupled:
- All business logic lives in `caulk.scanner.CaulkScanner`, `caulk.discovery`, and `caulk.models`.
- A future desktop GUI (e.g., PySide / Electron wrapper) or CI integration imports `CaulkScanner` directly or consumes standard JSON reports without code duplication.
