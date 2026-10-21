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

## 3. GUI & Extension Readiness

The CLI, rule engine, discovery walker, and reporting layers are strictly decoupled:
- All business logic lives in `caulk.scanner.CaulkScanner`, `caulk.discovery`, and `caulk.models`.
- A future desktop GUI (e.g., PySide / Electron wrapper) or CI GitHub Action can import `CaulkScanner` directly or consume standard JSON reports without code duplication.
