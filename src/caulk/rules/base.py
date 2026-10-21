"""Base interfaces for Caulk security inspection rules.

Every rule is deterministic, self-contained, and provides structured evidence,
impact explanations, and clear remediation guidance.
"""

from __future__ import annotations

import fnmatch
from abc import ABC
from dataclasses import dataclass, field
from pathlib import Path

from caulk.config import CaulkConfig
from caulk.discovery import DiscoveredFile, ProjectInventory
from caulk.models import Confidence, Finding, FindingCategory, FindingStatus, Severity


@dataclass
class ScanContext:
    """Contextual state and cached file access for a scan execution."""

    inventory: ProjectInventory
    config: CaulkConfig
    _file_cache: dict[Path, str] = field(default_factory=dict)
    _line_cache: dict[Path, list[str]] = field(default_factory=dict)

    def read_text(self, file: DiscoveredFile) -> str:
        """Safely read text content of a discovered file with caching."""
        if file.path in self._file_cache:
            return self._file_cache[file.path]

        try:
            # Files are guaranteed to be within max_file_size_bytes and non-binary
            text = file.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""

        self._file_cache[file.path] = text
        return text

    def get_lines(self, file: DiscoveredFile) -> list[str]:
        """Safely get split lines of a discovered file with caching."""
        if file.path in self._line_cache:
            return self._line_cache[file.path]

        text = self.read_text(file)
        lines = text.splitlines()
        self._line_cache[file.path] = lines
        return lines


class Rule(ABC):
    """Abstract base class for all deterministic security rules."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    impact: str
    remediation: str
    references: list[str] = []
    file_patterns: list[str] = []
    supported_ecosystems: list[str] = []

    def applies_to_ecosystem(self, ecosystems: set[str]) -> bool:
        """Check if this rule is relevant given detected project ecosystems."""
        if not self.supported_ecosystems:
            return True
        return bool(set(self.supported_ecosystems) & ecosystems)

    def applies_to_file(self, file: DiscoveredFile) -> bool:
        """Check if this rule applies to a specific discovered file path."""
        # Never scan Caulk's own rule definitions or redaction engine patterns
        norm = file.rel_path.replace("\\", "/")
        if norm.startswith("src/caulk/rules/") or norm == "src/caulk/redaction.py":
            return False

        if not self.file_patterns:
            return True

        filename = Path(file.rel_path).name.lower()
        rel_path = file.rel_path.lower()

        for pattern in self.file_patterns:
            p_lower = pattern.lower()
            if fnmatch.fnmatch(filename, p_lower):
                return True
            if fnmatch.fnmatch(rel_path, p_lower) or fnmatch.fnmatch(rel_path, f"*/{p_lower}"):
                return True

        return False

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        """Scan a single applicable file.

        Override in file-level rules.
        """
        return []

    def scan_project(self, context: ScanContext) -> list[Finding]:
        """Scan across the entire project inventory.

        Override in project-level or multi-file rules.
        """
        findings: list[Finding] = []
        for file in context.inventory.files:
            if self.applies_to_file(file):
                try:
                    file_findings = self.scan_file(file, context)
                    findings.extend(file_findings)
                except Exception:
                    # Individual file scan failure must not abort other checks
                    continue
        return findings

    def create_finding(
        self,
        file_path: str,
        line_number: int | None,
        evidence: str,
        title: str | None = None,
        description: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        remediation: str | None = None,
        impact: str | None = None,
        status: FindingStatus = FindingStatus.DETECTED,
    ) -> Finding:
        """Helper to construct a typed Finding using rule defaults."""
        return Finding(
            rule_id=self.rule_id,
            title=title or self.title,
            description=description or self.description,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            category=self.category,
            file_path=file_path,
            line_number=line_number,
            evidence=evidence,
            impact=impact or self.impact,
            remediation=remediation or self.remediation,
            references=list(self.references),
            detected_by="caulk-engine",
            status=status,
        )
