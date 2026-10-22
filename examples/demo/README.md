# Caulk Reproducible Demo

This directory provides an isolated, safe demonstration project illustrating Caulk's deterministic detection and false-positive controls.

All examples use synthetic, documentation-standard placeholders. No production credentials or external services are used.

```
examples/demo/
├── vulnerable/
│   └── app.py       # Vulnerable patterns (SAST001, SAST002, SEC002, CFG001)
├── safe/
│   └── app.py       # Remediated secure patterns (0 findings)
└── README.md
```

---

## 1. Quick Evaluation (Under 60 Seconds)

### Step 1: Install Caulk

```bash
pip install caulk-security
```

### Step 2: Scan the Intentionally Vulnerable Example

```bash
caulk-security scan examples/demo/vulnerable
```

**Expected Outcome:**
- **Exit Code:** `1` (`EXIT_FINDINGS_BREACH_THRESHOLD`)
- **Findings Count:** `4`
  1. `SEC002` (CRITICAL | HIGH): AWS Access Key ID Detected (`AKIAIOSFODNN7EXAMPLE`, masked in evidence)
  2. `CFG001` (HIGH | HIGH): Application Debug Mode Explicitly Enabled (`DEBUG = True`)
  3. `SAST001` (HIGH | HIGH): Python SQL Injection (f-string query passed to `execute()`)
  4. `SAST002` (HIGH | HIGH): Command Injection via Shell Execution (`shell=True` with dynamic input)

### Step 3: Scan the Remediated Safe Example

```bash
caulk-security scan examples/demo/safe
```

**Expected Outcome:**
- **Exit Code:** `0` (`EXIT_SUCCESS_CLEAN`)
- **Findings Count:** `0`
- **False-Positive Controls Demonstrated:**
  - Parameterized database queries (`cursor.execute("...", (user_id,))`) are **exempt** from `SAST001`.
  - Subprocess calls with list arguments and `shell=False` are **exempt** from `SAST002`.
  - Secrets loaded via `os.environ.get(...)` are **exempt** from `SEC002`.
  - Dynamic debug configuration defaulting to `False` is **exempt** from `CFG001`.

---

## 2. Advanced Scan Options Demonstrated

### Run Only SAST Rules

```bash
caulk-security scan examples/demo/vulnerable --category SAST
```
*Evaluates only `SAST001` and `SAST002`, skipping secret and configuration checks (reports 2 findings).*

### Disable a Specific Rule

```bash
caulk-security scan examples/demo/vulnerable --disable SAST001
```
*Suppresses `SAST001` while retaining all other active rules (reports 3 findings).*

### Export Machine-Readable JSON

```bash
caulk-security scan examples/demo/vulnerable --format json
```
*Outputs structured JSON containing findings, file metrics, and scan metadata.*
