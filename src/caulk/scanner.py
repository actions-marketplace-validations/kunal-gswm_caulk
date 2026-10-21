"""Core scan orchestrator for Caulk.

Executes deterministic discovery, rule evaluation, deduplication, redaction,
and report generation.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path

from caulk import __version__
from caulk.config import CaulkConfig
from caulk.discovery import discover_project
from caulk.models import Finding, FindingCategory, ScanResult, ScanSummary, Severity
from caulk.redaction import sanitize_evidence
from caulk.rules import registry
from caulk.rules.advisories import OSVAdvisoryProvider
from caulk.rules.base import ScanContext
from caulk.rules.dependencies import DependencyVulnerabilityScanner


class CaulkScanner:
    """Deterministic security scanner."""

    def __init__(
        self,
        config: CaulkConfig | None = None,
        categories: Iterable[FindingCategory] | None = None,
        check_vulns: bool | None = None,
    ) -> None:
        self.config = config or CaulkConfig()
        if check_vulns is not None:
            self.config.enable_advisories = check_vulns
        self.categories = categories

    def scan(self, target_path: Path | str) -> ScanResult:
        """Execute a full deterministic scan on the target path."""
        start_time = time.perf_counter()
        errors: list[str] = []
        checks_not_performed: list[str] = []

        # 1. Discover project files and ecosystems
        inventory = discover_project(target_path, config=self.config)

        # 2. Prepare scan context
        context = ScanContext(inventory=inventory, config=self.config)

        # 3. Filter applicable rules
        active_rules = registry.filter_rules(
            categories=self.categories,
            disabled_ids=self.config.disabled_rules,
            ecosystems=inventory.ecosystems,
        )

        raw_findings: list[Finding] = []

        # 4. Run rules safely
        for rule in active_rules:
            try:
                rule_findings = rule.scan_project(context)
                raw_findings.extend(rule_findings)
            except Exception as err:
                errors.append(f"Rule {rule.rule_id} encountered an error: {err}")

        # 5. Optional advisory dependency scan
        if self.config.enable_advisories:
            dep_scanner = DependencyVulnerabilityScanner(provider=OSVAdvisoryProvider())
            dep_findings, dep_errors = dep_scanner.run(context)
            raw_findings.extend(dep_findings)
            errors.extend(dep_errors)
        else:
            checks_not_performed.append(
                "External dependency vulnerability advisories were skipped (offline mode). "
                "Enable with --check-vulns."
            )

        # 6. Sanitize and redact all evidence
        sanitized_findings: list[Finding] = []
        for f in raw_findings:
            cleaned_evidence = sanitize_evidence(f.evidence)
            # Recreate with cleaned evidence to ensure no leaks
            cleaned_finding = Finding(
                rule_id=f.rule_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                confidence=f.confidence,
                category=f.category,
                file_path=f.file_path,
                line_number=f.line_number,
                evidence=cleaned_evidence,
                impact=f.impact,
                remediation=f.remediation,
                references=f.references,
                fingerprint=f.fingerprint,
                detected_by=f.detected_by,
                status=f.status,
            )
            sanitized_findings.append(cleaned_finding)

        # 7. Deduplicate findings by fingerprint
        unique_findings: dict[str, Finding] = {}
        for finding in sanitized_findings:
            if finding.fingerprint not in unique_findings:
                unique_findings[finding.fingerprint] = finding

        # 8. Sort findings deterministically
        # Sort key: (-severity.rank, category.value, file_path, line_number or 0, rule_id)
        sorted_findings = sorted(
            unique_findings.values(),
            key=lambda x: (
                -x.severity.rank,
                x.category.value,
                x.file_path,
                x.line_number if x.line_number is not None else 0,
                x.rule_id,
            ),
        )

        duration = time.perf_counter() - start_time

        # 9. Build summary
        sev_counts = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        for f in sorted_findings:
            sev_counts[f.severity.value] += 1

        summary = ScanSummary(
            targets_scanned=1,
            files_scanned=len(inventory.files),
            files_skipped=len(inventory.skipped),
            duration_seconds=round(duration, 3),
            total_findings=len(sorted_findings),
            severity_counts=sev_counts,
            ecosystems_detected=sorted(inventory.ecosystems),
            checks_not_performed=checks_not_performed,
        )

        return ScanResult(
            caulk_version=__version__,
            target_path=str(inventory.root_path),
            findings=sorted_findings,
            summary=summary,
            errors=errors,
        )
