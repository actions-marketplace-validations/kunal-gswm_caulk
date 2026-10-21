"""Dependency vulnerability advisory interfaces and OSV.dev integration.

Queries external vulnerability databases ONLY when explicitly enabled by user configuration.
Never sends source code, repository names, or secret credentials.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from caulk.models import Confidence, Finding, FindingCategory, Severity

logger = logging.getLogger("caulk.advisories")


@dataclass(frozen=True)
class PackageDependency:
    """An inventoried software dependency."""

    name: str
    version: str | None
    ecosystem: str  # "PyPI" or "npm"
    manifest_path: str
    is_direct: bool = True

    @property
    def is_exact_version(self) -> bool:
        """Check if the dependency specifies an exact, pinned version."""
        if not self.version:
            return False
        v = self.version.strip()
        # Non-exact if starts with ^, ~, >=, <=, >, <, *, or latest
        if any(v.startswith(prefix) for prefix in ("^", "~", ">", "<", "*", "!")):
            return False
        return v.lower() not in ("*", "latest")


@dataclass(frozen=True)
class VulnerabilityAdvisory:
    """A verified security advisory from an external database."""

    advisory_id: str
    package_name: str
    ecosystem: str
    installed_version: str
    summary: str
    details: str
    severity: Severity
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    manifest_path: str = ""

    def to_finding(self) -> Finding:
        """Convert advisory to a Caulk finding."""
        fix_text = (
            f"Upgrade {self.package_name} to version {', '.join(self.fixed_versions)}"
            if self.fixed_versions
            else f"Review security advisory {self.advisory_id} and update to a patched version."
        )

        return Finding(
            rule_id="DEP003",
            title=f"Known Vulnerability in Dependency: {self.package_name} ({self.advisory_id})",
            description=self.summary
            or f"Vulnerability {self.advisory_id} affects {self.package_name}.",
            severity=self.severity,
            confidence=Confidence.CONFIRMED,
            category=FindingCategory.DEPENDENCY,
            file_path=self.manifest_path,
            line_number=None,
            evidence=f"Package: {self.package_name}=={self.installed_version} [{self.ecosystem}]",
            impact=(
                f"Vulnerability {self.advisory_id} was reported for {self.package_name}@{self.installed_version}. "
                f"Details: {self.details[:300]}..."
                if len(self.details) > 300
                else self.details
            ),
            remediation=f"1. {fix_text}\n2. Verify compatibility with existing application code.",
            references=list(self.references),
            detected_by="caulk-osv-provider",
        )


class AdvisoryProvider(ABC):
    """Abstract interface for vulnerability advisory lookups."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the provider."""

    @abstractmethod
    def query(
        self, packages: list[PackageDependency]
    ) -> tuple[list[VulnerabilityAdvisory], list[str]]:
        """Query advisories for a list of dependencies.

        Returns (list_of_advisories, list_of_error_messages).
        """


class OfflineAdvisoryProvider(AdvisoryProvider):
    """Default offline provider when network access is disabled."""

    @property
    def name(self) -> str:
        return "offline"

    def query(
        self, packages: list[PackageDependency]
    ) -> tuple[list[VulnerabilityAdvisory], list[str]]:
        # Does not perform any network queries
        return [], []


class OSVAdvisoryProvider(AdvisoryProvider):
    """Queries OSV.dev batch API for verified open-source vulnerability records."""

    _API_URL = "https://api.osv.dev/v1/querybatch"
    _TIMEOUT_SECONDS = 6.0
    _MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB limit

    @property
    def name(self) -> str:
        return "osv"

    def query(
        self, packages: list[PackageDependency]
    ) -> tuple[list[VulnerabilityAdvisory], list[str]]:
        # Filter to packages with exact resolved versions
        queryable = [p for p in packages if p.is_exact_version and p.version]
        if not queryable:
            return [], []

        # Batch query in chunks of 100
        advisories: list[VulnerabilityAdvisory] = []
        errors: list[str] = []

        chunk_size = 100
        for i in range(0, len(queryable), chunk_size):
            chunk = queryable[i : i + chunk_size]
            queries_payload = [
                {
                    "package": {
                        "name": pkg.name,
                        "ecosystem": pkg.ecosystem,
                    },
                    "version": pkg.version,
                }
                for pkg in chunk
            ]

            payload_data = json.dumps({"queries": queries_payload}).encode("utf-8")
            req = urllib.request.Request(
                self._API_URL,
                data=payload_data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Caulk-Security-Checker/0.1.0",
                },
                method="POST",
            )

            try:
                with urllib.request.urlopen(req, timeout=self._TIMEOUT_SECONDS) as response:
                    raw_data = response.read(self._MAX_RESPONSE_BYTES)
                    response_json = json.loads(raw_data.decode("utf-8"))
            except (urllib.error.URLError, TimeoutError, OSError) as err:
                msg = f"Failed to query OSV advisory database: {err}"
                logger.warning(msg)
                errors.append(msg)
                continue
            except json.JSONDecodeError as err:
                msg = f"Invalid JSON response from OSV advisory API: {err}"
                logger.warning(msg)
                errors.append(msg)
                continue

            results = response_json.get("results", [])
            for pkg, res in zip(chunk, results, strict=False):
                vulns = res.get("vulns", [])
                for vuln in vulns:
                    adv = self._parse_osv_vuln(pkg, vuln)
                    if adv:
                        advisories.append(adv)

        return advisories, errors

    def _parse_osv_vuln(
        self, pkg: PackageDependency, data: dict[str, Any]
    ) -> VulnerabilityAdvisory | None:
        """Parse an individual OSV vulnerability entry."""
        vuln_id = str(data.get("id", ""))
        if not vuln_id:
            return None

        summary = str(data.get("summary", "")).strip()
        details = str(data.get("details", "")).strip()

        # Extract fixed versions from affected ranges
        fixed_versions: list[str] = []
        for affected in data.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(str(event["fixed"]))

        # Extract references
        references: list[str] = []
        for ref in data.get("references", []):
            url = ref.get("url")
            if url:
                references.append(str(url))

        # Determine severity from database_specific or CVSS if available
        severity = Severity.HIGH  # Default for confirmed vulnerabilities
        for sev_entry in data.get("severity", []):
            score_type = sev_entry.get("type")
            score = sev_entry.get("score")
            if (
                score_type == "CVSS_V3"
                and isinstance(score, str)
                and "AV:N" in score
                and "C:H" in score
            ):
                severity = Severity.CRITICAL

        return VulnerabilityAdvisory(
            advisory_id=vuln_id,
            package_name=pkg.name,
            ecosystem=pkg.ecosystem,
            installed_version=pkg.version or "unknown",
            summary=summary or f"Vulnerability {vuln_id}",
            details=details,
            severity=severity,
            fixed_versions=fixed_versions,
            references=references[:5],
            manifest_path=pkg.manifest_path,
        )
