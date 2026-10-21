"""Deterministic Git history scanner for credential exposure detection.

Traverses reachable commit history, evaluates secret detection rules (SEC001-SEC008)
against added or modified blobs, deduplicates findings across commits using parent
blob comparisons, and produces structured historical findings with 5-point remediation.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from caulk import __version__
from caulk.config import DEFAULT_EXCLUDED_PATTERNS, CaulkConfig
from caulk.discovery import DiscoveredFile, ProjectInventory, matches_any_pattern
from caulk.history.git import (
    GitBlobReader,
    get_local_refs,
    is_git_repo,
    parse_blob_size,
    stream_git_log,
)
from caulk.models import (
    Confidence,
    Finding,
    FindingCategory,
    FindingStatus,
    ScanResult,
    ScanSummary,
    Severity,
)
from caulk.redaction import sanitize_evidence
from caulk.rules import register_default_rules
from caulk.rules.base import Rule, ScanContext
from caulk.rules.registry import RuleRegistry


def format_historical_remediation(
    rule_id: str,
    commit_sha: str | None = None,
) -> str:
    """Format mandatory 5-point remediation guidance for historical findings."""
    short_sha = commit_sha[:8] if commit_sha else "earlier commit"
    return (
        f"1. HISTORICAL EXPOSURE: This credential was exposed in commit {short_sha} and remains part of the repository's permanent Git history.\n"
        "2. REMOVAL INEFFECTIVE: Deleting, overwriting, or replacing this secret in later commits does NOT protect it; any clone of the repository retains the secret.\n"
        "3. IMMEDIATE ROTATION: Immediately revoke and rotate this credential with the service provider. Assume the secret has been compromised.\n"
        "4. AUDIT ACCESS LOGS: Check provider access and audit logs for unauthorized activity during the exposure window.\n"
        "5. REWRITE HISTORY SAFELY: After (and only after) rotating the active secret, purge it from Git history using tools such as 'git-filter-repo' or 'BFG Repo-Cleaner'. Note that rewriting history alone does NOT revoke the exposed credential."
    )


@dataclass(frozen=True)
class FindingTemplate:
    """Cached finding template for a scanned blob before commit attribution."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    line_number: int | None
    evidence: str
    impact: str
    references: tuple[str, ...]


class GitHistoryScanner:
    """Deterministic security scanner for Git repository history."""

    def __init__(
        self,
        repo_path: Path | str,
        config: CaulkConfig | None = None,
        max_blob_size: str | int = "2MB",
        max_depth: int | None = None,
        since: str | None = None,
        ref: str | None = None,
        extra_exclusions: list[str] | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.config = config or CaulkConfig()
        self.max_blob_size = (
            parse_blob_size(max_blob_size) if isinstance(max_blob_size, str) else max_blob_size
        )
        self.max_depth = max_depth
        self.since = since
        self.ref = ref
        self.timeout_seconds = timeout_seconds

        # Build exclusion list
        self.exclusions: list[str] = list(DEFAULT_EXCLUDED_PATTERNS)
        if self.config.exclude_patterns:
            self.exclusions.extend(self.config.exclude_patterns)
        if extra_exclusions:
            self.exclusions.extend(extra_exclusions)

        # Initialize secret rules registry
        self.registry = RuleRegistry()
        register_default_rules(self.registry)
        self.rules: list[Rule] = self.registry.filter_rules(
            categories=[FindingCategory.SECRET],
            disabled_ids=self.config.disabled_rules,
        )
        self.content_rules: list[Rule] = [r for r in self.rules if r.rule_id != "SEC008"]
        self.env_rule: Rule | None = next((r for r in self.rules if r.rule_id == "SEC008"), None)

        # Caches and counters
        self._blob_cache: dict[str, list[FindingTemplate]] = {}
        self._blobs_scanned: int = 0
        self._blobs_cached: int = 0
        self._commits_scanned: int = 0

    def _get_blob_findings(
        self,
        blob_sha: str,
        rel_path: str,
        blob_reader: GitBlobReader,
    ) -> list[FindingTemplate]:
        """Scan a blob for secrets or retrieve previously cached finding templates."""
        if not blob_sha or blob_sha.startswith("0000000000"):
            return []

        fake_path = Path(rel_path)
        discovered_file = DiscoveredFile(
            path=fake_path,
            rel_path=rel_path,
            size_bytes=0,
        )

        if blob_sha in self._blob_cache:
            self._blobs_cached += 1
            templates = list(self._blob_cache[blob_sha])
        else:
            self._blobs_scanned += 1
            text = blob_reader.read_blob_text(blob_sha, max_size=self.max_blob_size)
            if text is None:
                self._blob_cache[blob_sha] = []
                return []

            inventory = ProjectInventory(root_path=self.repo_path, files=[discovered_file])
            context = ScanContext(
                inventory=inventory,
                config=self.config,
                _file_cache={fake_path: text},
                _line_cache={fake_path: text.splitlines()},
            )

            templates = []
            for rule in self.content_rules:
                try:
                    rule_findings = rule.scan_file(discovered_file, context)
                    for f in rule_findings:
                        cleaned_ev = sanitize_evidence(f.evidence)
                        templates.append(
                            FindingTemplate(
                                rule_id=f.rule_id,
                                title=f.title,
                                description=f.description,
                                severity=f.severity,
                                confidence=f.confidence,
                                category=f.category,
                                line_number=f.line_number,
                                evidence=cleaned_ev,
                                impact=f.impact,
                                references=tuple(f.references),
                            )
                        )
                except Exception:
                    continue

            self._blob_cache[blob_sha] = list(templates)

        # Check path-specific SensitiveEnvFileRule if applicable
        if self.env_rule is not None and self.env_rule.applies_to_file(discovered_file):
            text = blob_reader.read_blob_text(blob_sha, max_size=self.max_blob_size)
            if text:
                context = ScanContext(
                    inventory=ProjectInventory(root_path=self.repo_path, files=[discovered_file]),
                    config=self.config,
                    _file_cache={fake_path: text},
                    _line_cache={fake_path: text.splitlines()},
                )
                try:
                    for f in self.env_rule.scan_file(discovered_file, context):
                        cleaned_ev = sanitize_evidence(f.evidence)
                        templates.append(
                            FindingTemplate(
                                rule_id=f.rule_id,
                                title=f.title,
                                description=f.description,
                                severity=f.severity,
                                confidence=f.confidence,
                                category=f.category,
                                line_number=f.line_number,
                                evidence=cleaned_ev,
                                impact=f.impact,
                                references=tuple(f.references),
                            )
                        )
                except Exception:
                    pass

        return templates

    def scan(
        self,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> ScanResult:
        """Execute historical Git secret scan.

        Returns a complete, typed ScanResult containing historical findings and statistics.
        """
        start_time = time.perf_counter()
        errors: list[str] = []

        if not is_git_repo(self.repo_path):
            return ScanResult(
                caulk_version=__version__,
                target_path=str(self.repo_path),
                findings=[],
                summary=ScanSummary(
                    scan_mode="git_history",
                    targets_scanned=1,
                    is_complete=False,
                ),
                errors=[f"Target path is not a valid Git repository: {self.repo_path}"],
            )

        refs_scanned = [self.ref] if self.ref else get_local_refs(self.repo_path)
        findings_by_fingerprint: dict[str, Finding] = {}
        is_complete = True

        with GitBlobReader(self.repo_path) as blob_reader:
            commit_generator = stream_git_log(
                repo_path=self.repo_path,
                max_depth=self.max_depth,
                since=self.since,
                ref=self.ref,
            )

            for commit_diff in commit_generator:
                self._commits_scanned += 1

                # Check timeout limit if set
                if (
                    self.timeout_seconds is not None
                    and (time.perf_counter() - start_time) > self.timeout_seconds
                ):
                    errors.append(
                        f"Scan exceeded timeout limit of {self.timeout_seconds:.1f} seconds. Traversal stopped early."
                    )
                    is_complete = False
                    break

                commit = commit_diff.commit
                for entry in commit_diff.entries:
                    filename = Path(entry.path).name
                    if matches_any_pattern(entry.path, filename, self.exclusions):
                        continue

                    dst_templates = self._get_blob_findings(
                        entry.dst_blob_sha, entry.path, blob_reader
                    )
                    if not dst_templates:
                        continue

                    # Collect findings already present in parent commit blobs
                    parent_findings: set[tuple[str, str]] = set()
                    for src_sha in entry.src_blob_shas:
                        src_templates = self._get_blob_findings(src_sha, entry.path, blob_reader)
                        for st in src_templates:
                            parent_findings.add((st.rule_id, st.evidence))

                    # Findings newly introduced in this commit
                    for tmpl in dst_templates:
                        if (tmpl.rule_id, tmpl.evidence) in parent_findings:
                            continue

                        remediation = format_historical_remediation(tmpl.rule_id, commit.sha)
                        finding = Finding(
                            rule_id=tmpl.rule_id,
                            title=tmpl.title,
                            description=tmpl.description,
                            severity=tmpl.severity,
                            confidence=tmpl.confidence,
                            category=tmpl.category,
                            file_path=entry.path,
                            line_number=tmpl.line_number,
                            evidence=tmpl.evidence,
                            impact=tmpl.impact,
                            remediation=remediation,
                            references=list(tmpl.references),
                            status=FindingStatus.HISTORICAL,
                            detected_by="caulk-history-engine",
                            commit_sha=commit.sha,
                            commit_timestamp=commit.timestamp,
                            commit_author=commit.author,
                            commit_subject=commit.subject,
                        )

                        if finding.fingerprint not in findings_by_fingerprint:
                            findings_by_fingerprint[finding.fingerprint] = finding

                if progress_callback is not None:
                    with contextlib.suppress(Exception):
                        progress_callback(self._commits_scanned, len(findings_by_fingerprint))

        # Sort findings deterministically:
        # Highest severity first, then by file path, line number, timestamp, rule ID
        sorted_findings = sorted(
            findings_by_fingerprint.values(),
            key=lambda x: (
                -x.severity.rank,
                x.file_path,
                x.line_number if x.line_number is not None else 0,
                x.commit_timestamp or "",
                x.rule_id,
            ),
        )

        duration = time.perf_counter() - start_time

        # Calculate severity counts
        sev_counts: dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        for f in sorted_findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        summary = ScanSummary(
            targets_scanned=1,
            files_scanned=self._blobs_scanned,
            files_skipped=0,
            duration_seconds=round(duration, 3),
            total_findings=len(sorted_findings),
            severity_counts=sev_counts,
            ecosystems_detected=["git"],
            checks_not_performed=[
                "External advisory lookup skipped in Git history mode.",
                "Non-secret rules skipped in Git history mode (SEC001-SEC008 active).",
                "Unreachable Git objects and un-fetched remote refs were not inspected.",
            ],
            scan_mode="git_history",
            commits_scanned=self._commits_scanned,
            blobs_scanned=self._blobs_scanned,
            blobs_cached=self._blobs_cached,
            refs_scanned=refs_scanned,
            is_complete=is_complete,
        )

        return ScanResult(
            caulk_version=__version__,
            target_path=str(self.repo_path),
            findings=sorted_findings,
            summary=summary,
            errors=errors,
        )
