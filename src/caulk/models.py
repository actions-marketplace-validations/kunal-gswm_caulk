"""Data models for Caulk security scanner findings and scan results.

Deterministic, typed, versionable representations of security observations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    """Vulnerability severity levels ordered by risk."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numerical rank for sorting and comparison (higher rank = higher severity)."""
        ranks = {
            Severity.CRITICAL: 50,
            Severity.HIGH: 40,
            Severity.MEDIUM: 30,
            Severity.LOW: 20,
            Severity.INFO: 10,
        }
        return ranks[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Convert a case-insensitive string to Severity."""
        normalized = value.strip().upper()
        try:
            return cls(normalized)
        except ValueError as err:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"Invalid severity '{value}'. Allowed: {valid}") from err


class Confidence(StrEnum):
    """Degree of certainty in the finding."""

    CONFIRMED = "CONFIRMED"  # Direct unambiguous match (e.g. private key banner)
    HIGH = "HIGH"  # Strong signature match with low false-positive probability
    MEDIUM = "MEDIUM"  # Strong pattern with contextual assumptions
    LOW = "LOW"  # Heuristic indicator needing human review

    @classmethod
    def from_string(cls, value: str) -> Confidence:
        normalized = value.strip().upper()
        try:
            return cls(normalized)
        except ValueError as err:
            valid = ", ".join(c.value for c in cls)
            raise ValueError(f"Invalid confidence '{value}'. Allowed: {valid}") from err


class FindingCategory(StrEnum):
    """Broad classification of security findings."""

    SECRET = "SECRET"
    CONFIGURATION = "CONFIGURATION"
    DEPENDENCY = "DEPENDENCY"
    SAST = "SAST"

    @classmethod
    def from_string(cls, value: str) -> FindingCategory:
        normalized = value.strip().upper()
        try:
            return cls(normalized)
        except ValueError as err:
            valid = ", ".join(c.value for c in cls)
            raise ValueError(f"Invalid category '{value}'. Allowed: {valid}") from err


class FindingStatus(StrEnum):
    """Status of the finding."""

    DETECTED = "DETECTED"
    SUPPRESSED = "SUPPRESSED"
    VERIFIED = "VERIFIED"
    HISTORICAL = "HISTORICAL"


def normalize_repo_path(path: str | Path | None) -> str:
    """Normalize a path to a consistent forward-slash relative string."""
    if path is None:
        return ""
    p_str = str(path).replace("\\", "/").strip()
    # Strip leading ./ if present
    if p_str.startswith("./"):
        p_str = p_str[2:]
    return p_str


def compute_fingerprint(
    rule_id: str,
    file_path: str | Path | None,
    line_number: int | None,
    identity_hint: str = "",
    commit_sha: str | None = None,
) -> str:
    """Compute a deterministic, stable fingerprint for finding deduplication.

    Does NOT incorporate raw secrets, ensuring no leak occurs via fingerprints.
    """
    normalized_path = normalize_repo_path(file_path)
    line_str = str(line_number) if line_number is not None else "0"
    raw = f"{rule_id}:{normalized_path}:{line_str}:{identity_hint.strip()}"
    if commit_sha:
        raw = f"{raw}:{commit_sha.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class Finding:
    """A single deterministic security finding."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    file_path: str
    line_number: int | None
    evidence: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""
    detected_by: str = "caulk-engine"
    status: FindingStatus = FindingStatus.DETECTED
    commit_sha: str | None = None
    commit_timestamp: str | None = None
    commit_author: str | None = None
    commit_subject: str | None = None

    @property
    def is_historical(self) -> bool:
        """Whether this finding was detected in historical Git commits."""
        return self.status == FindingStatus.HISTORICAL or self.commit_sha is not None

    def __post_init__(self) -> None:
        # Enforce normalized file path and compute fingerprint if not provided
        normalized = normalize_repo_path(self.file_path)
        object.__setattr__(self, "file_path", normalized)

        if not self.fingerprint:
            fp = compute_fingerprint(
                rule_id=self.rule_id,
                file_path=normalized,
                line_number=self.line_number,
                identity_hint=self.title,
                commit_sha=self.commit_sha,
            )
            object.__setattr__(self, "fingerprint", fp)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to JSON-serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": list(self.references),
            "fingerprint": self.fingerprint,
            "detected_by": self.detected_by,
            "status": self.status.value,
            "commit_sha": self.commit_sha,
            "commit_timestamp": self.commit_timestamp,
            "commit_author": self.commit_author,
            "commit_subject": self.commit_subject,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Create finding from a serialized dictionary."""
        return cls(
            rule_id=str(data["rule_id"]),
            title=str(data["title"]),
            description=str(data["description"]),
            severity=Severity.from_string(data["severity"]),
            confidence=Confidence.from_string(data["confidence"]),
            category=FindingCategory.from_string(data["category"]),
            file_path=str(data.get("file_path", "")),
            line_number=data.get("line_number"),
            evidence=str(data.get("evidence", "")),
            impact=str(data.get("impact", "")),
            remediation=str(data.get("remediation", "")),
            references=list(data.get("references", [])),
            fingerprint=str(data.get("fingerprint", "")),
            detected_by=str(data.get("detected_by", "caulk-engine")),
            status=FindingStatus(str(data.get("status", "DETECTED"))),
            commit_sha=data.get("commit_sha"),
            commit_timestamp=data.get("commit_timestamp"),
            commit_author=data.get("commit_author"),
            commit_subject=data.get("commit_subject"),
        )


@dataclass
class ScanSummary:
    """Summary statistics for a completed scan."""

    targets_scanned: int = 1
    files_scanned: int = 0
    files_skipped: int = 0
    duration_seconds: float = 0.0
    total_findings: int = 0
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
    )
    ecosystems_detected: list[str] = field(default_factory=list)
    checks_not_performed: list[str] = field(default_factory=list)
    scan_mode: str = "working_tree"
    commits_scanned: int = 0
    blobs_scanned: int = 0
    blobs_cached: int = 0
    blobs_skipped_binary: int = 0
    blobs_skipped_oversized: int = 0
    blobs_skipped_missing: int = 0
    blobs_skipped_corrupt: int = 0
    blobs_skipped_error: int = 0
    scan_scope: dict[str, Any] = field(default_factory=dict)
    refs_scanned: list[str] = field(default_factory=list)
    is_complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete result of a repository scan."""

    caulk_version: str
    target_path: str
    findings: list[Finding]
    summary: ScanSummary
    scan_timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    errors: list[str] = field(default_factory=list)

    def has_findings_above(self, threshold: Severity) -> bool:
        """Check if any finding meets or exceeds the given severity threshold."""
        return any(f.severity >= threshold for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "caulk_version": self.caulk_version,
            "scan_timestamp": self.scan_timestamp,
            "target_path": normalize_repo_path(self.target_path),
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
