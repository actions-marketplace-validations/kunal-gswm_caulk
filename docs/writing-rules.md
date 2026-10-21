# Writing Security Rules

This guide explains how to author, test, and register new deterministic security rules in Caulk.

---

## 1. Rule Design Principles

Every rule in Caulk must satisfy five core requirements:

1. **Deterministic:** Given the same file content, the rule must always produce the same finding with the same fingerprint.
2. **Actionable:** The finding must clearly answer:
   - What is wrong?
   - Where is the problem?
   - Why does it matter?
   - What should the developer do to fix it?
3. **No AI / No Probabilistic Heuristics:** Findings must come from explicit signatures, cryptographic headers, syntax trees, or verified vulnerability data.
4. **Sanitized Evidence:** Raw secrets or credentials must **never** be included in evidence strings. Always use `mask_secret()`, `redact_line()`, or `redact_connection_string()`.
5. **False Positive Suppression:** Guard against obvious placeholders, dummy variables, documentation examples, and template expressions.

---

## 2. Rule Structure

Create your rule in the appropriate module under `src/caulk/rules/`:
- `secrets.py` for credential exposures (`SECxxx`).
- `configuration.py` for deployment and container misconfigurations (`CFGxxx`).
- `dependencies.py` for package manifest issues (`DEPxxx`).
- `sast.py` for Python AST and taint analysis rules (`SASTxxx`).

### Example Rule Implementation

```python
import re
from pathlib import Path
from caulk.discovery import DiscoveredFile
from caulk.models import Confidence, Finding, FindingCategory, Severity
from caulk.redaction import mask_secret
from caulk.rules.base import Rule, ScanContext


class MyNewSecretRule(Rule):
    """Detects exposed Acme Cloud authentication tokens."""

    rule_id = "SEC009"
    title = "Acme Cloud API Token Detected"
    description = (
        "An Acme Cloud API token was detected in repository code. "
        "Exposing this token allows unauthorized access to Acme Cloud infrastructure."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.SECRET
    impact = (
        "Attackers possessing this token can provision resources, alter services, "
        "and access sensitive customer data stored in Acme Cloud."
    )
    remediation = (
        "1. Revoke the token immediately in the Acme Cloud Dashboard.\n"
        "2. Store tokens as environment variables injected at runtime, never hardcoded in source."
    )
    references = [
        "https://docs.acme.example/security/tokens",
    ]
    file_patterns = ["*.py", "*.js", "*.ts", "*.json", "*.env*"]

    _PATTERN = re.compile(r"\b(acme_live_[0-9a-zA-Z]{32})\b")

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.get_lines(file)

        for line_num, line in enumerate(lines, start=1):
            for match in self._PATTERN.finditer(line):
                token = match.group(1)
                # Mask secret before placing into evidence
                masked = mask_secret(token, unmasked_prefix=4, unmasked_suffix=2)
                findings.append(
                    self.create_finding(
                        file_path=file.rel_path,
                        line_number=line_num,
                        evidence=f"Acme Token detected: {masked}",
                    )
                )

        return findings
```

---

## 3. Registering the Rule

Add the rule instance to `DEFAULT_RULES` in `src/caulk/rules/__init__.py`:

```python
DEFAULT_RULES: list[Rule] = [
    # ...
    MyNewSecretRule(),
]
```

---

## 4. Writing Required Tests

Every rule must have unit tests covering:
1. **Positive Match:** Verifies that vulnerable patterns trigger the finding.
2. **Negative Match:** Verifies that clean, secure code does not trigger the finding.
3. **False Positive Suppression:** Verifies that placeholders (e.g. `acme_live_00000000000000000000000000000000`) do not trigger.
4. **Sanitization:** Verifies that unredacted secret values never appear in `finding.evidence`.

Add your tests to `tests/test_secrets.py` or `tests/test_configuration.py`. Run tests with:

```bash
pytest -v -k "MyNewSecretRule"
```
