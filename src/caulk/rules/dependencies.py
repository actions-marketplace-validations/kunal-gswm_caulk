"""Dependency manifest inventory and vulnerability analysis.

Inspects JavaScript and Python manifests without installing or executing code.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from caulk.discovery import ProjectInventory
from caulk.models import Confidence, Finding, FindingCategory, Severity
from caulk.rules.advisories import AdvisoryProvider, OfflineAdvisoryProvider, PackageDependency
from caulk.rules.base import Rule, ScanContext

# Regex to parse requirements.txt lines: package_name [==|>=|<=|~=|<|>|!=] version
_REQUIREMENT_LINE = re.compile(
    r"""^\s*([A-Za-z0-9_.\-]+)\s*(?:(==|>=|<=|~=|>|<|!=)\s*([A-Za-z0-9_.\-+*]+))?""",
)


def parse_requirements_txt(content: str, manifest_path: str) -> list[PackageDependency]:
    """Parse python requirements.txt content into PackageDependency list."""
    dependencies: list[PackageDependency] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        # Skip empty lines, comments, and pip options (-r, -i, -f, --extra-index-url)
        if not line or line.startswith(("#", "-", "--")):
            continue

        # Strip inline comments
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        # Handle environment markers e.g. "foo>=1.0 ; python_version > '3.8'"
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        match = _REQUIREMENT_LINE.match(line)
        if match:
            pkg_name = match.group(1).strip()
            op = match.group(2)
            ver = match.group(3)

            version_spec = None
            if op and ver:
                version_spec = ver if op == "==" else f"{op}{ver}"

            dependencies.append(
                PackageDependency(
                    name=pkg_name,
                    version=version_spec,
                    ecosystem="PyPI",
                    manifest_path=manifest_path,
                )
            )

    return dependencies


def parse_pyproject_toml(content: str, manifest_path: str) -> list[PackageDependency]:
    """Parse PEP 621 and Poetry dependencies from pyproject.toml."""
    dependencies: list[PackageDependency] = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return dependencies

    # 1. PEP 621 [project.dependencies]
    project = data.get("project", {})
    pep621_deps = project.get("dependencies", [])
    if isinstance(pep621_deps, list):
        for dep_str in pep621_deps:
            if isinstance(dep_str, str):
                match = _REQUIREMENT_LINE.match(dep_str)
                if match:
                    pkg_name = match.group(1).strip()
                    op = match.group(2)
                    ver = match.group(3)
                    version_spec = ver if op == "==" else (f"{op}{ver}" if op and ver else None)
                    dependencies.append(
                        PackageDependency(
                            name=pkg_name,
                            version=version_spec,
                            ecosystem="PyPI",
                            manifest_path=manifest_path,
                        )
                    )

    # 2. Poetry [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            ver = None
            if isinstance(spec, str):
                ver = spec
            elif isinstance(spec, dict) and "version" in spec:
                ver = str(spec["version"])
            dependencies.append(
                PackageDependency(
                    name=str(name),
                    version=ver,
                    ecosystem="PyPI",
                    manifest_path=manifest_path,
                )
            )

    return dependencies


def parse_package_json(content: str, manifest_path: str) -> list[PackageDependency]:
    """Parse dependencies from package.json."""
    dependencies: list[PackageDependency] = []
    try:
        data = json.loads(content)
    except Exception:
        return dependencies

    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name, ver in deps.items():
                dependencies.append(
                    PackageDependency(
                        name=str(name),
                        version=str(ver) if ver is not None else None,
                        ecosystem="npm",
                        manifest_path=manifest_path,
                        is_direct=(section == "dependencies"),
                    )
                )

    return dependencies


def parse_package_lock_json(content: str, manifest_path: str) -> list[PackageDependency]:
    """Parse resolved exact versions from package-lock.json (supports v1, v2, v3 formats)."""
    dependencies: list[PackageDependency] = []
    try:
        data = json.loads(content)
    except Exception:
        return dependencies

    # v2 / v3 format: packages object with "node_modules/<name>" keys
    packages = data.get("packages", {})
    if isinstance(packages, dict) and packages:
        for pkg_key, pkg_info in packages.items():
            if not isinstance(pkg_info, dict):
                continue
            # root package is ""
            if not pkg_key:
                continue

            # Extract name and version
            name = pkg_info.get("name")
            if not name:
                parts = pkg_key.split("node_modules/")
                name = parts[-1] if len(parts) > 1 else pkg_key

            version = pkg_info.get("version")
            if name and version:
                dependencies.append(
                    PackageDependency(
                        name=str(name),
                        version=str(version),
                        ecosystem="npm",
                        manifest_path=manifest_path,
                        is_direct=False,
                    )
                )
        return dependencies

    # v1 format: recursive dependencies object
    v1_deps = data.get("dependencies", {})
    if isinstance(v1_deps, dict):
        for name, info in v1_deps.items():
            if isinstance(info, dict):
                ver = info.get("version")
                if ver:
                    dependencies.append(
                        PackageDependency(
                            name=str(name),
                            version=str(ver),
                            ecosystem="npm",
                            manifest_path=manifest_path,
                            is_direct=False,
                        )
                    )

    return dependencies


def inventory_dependencies(inventory: ProjectInventory) -> list[PackageDependency]:
    """Extract all recognizable package dependencies across discovered manifests."""
    all_deps: list[PackageDependency] = []

    for file in inventory.files:
        fname = Path(file.rel_path).name.lower()

        if fname == "package-lock.json" or fname == "npm-shrinkwrap.json":
            try:
                content = file.path.read_text(encoding="utf-8", errors="replace")
                all_deps.extend(parse_package_lock_json(content, file.rel_path))
            except Exception:
                continue

        elif fname == "package.json":
            try:
                content = file.path.read_text(encoding="utf-8", errors="replace")
                all_deps.extend(parse_package_json(content, file.rel_path))
            except Exception:
                continue

        elif fname == "requirements.txt" or fname.endswith(".requirements.txt"):
            try:
                content = file.path.read_text(encoding="utf-8", errors="replace")
                all_deps.extend(parse_requirements_txt(content, file.rel_path))
            except Exception:
                continue

        elif fname == "pyproject.toml":
            try:
                content = file.path.read_text(encoding="utf-8", errors="replace")
                all_deps.extend(parse_pyproject_toml(content, file.rel_path))
            except Exception:
                continue

    return all_deps


class UnpinnedDependencyRule(Rule):
    """Detects dependencies with wildcard (*) or completely unpinned versions in manifests."""

    rule_id = "DEP001"
    title = "Wildcard or Completely Unpinned Dependency Version"
    description = (
        "A dependency in an application manifest uses a wildcard ('*') or unpinned version specifier. "
        "Unpinned dependencies can automatically pull breaking or compromised package versions without review."
    )
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = FindingCategory.DEPENDENCY
    impact = (
        "Builds become non-reproducible, and automated installations may silently adopt malicious "
        "or breaking updates published by upstream package maintainers."
    )
    remediation = (
        "1. Pin dependencies to specific version numbers or tight semantic version ranges (e.g. ^1.2.3 or ==1.2.3).\n"
        "2. Commit a lockfile (package-lock.json or poetry.lock) to guarantee deterministic builds."
    )
    references = [
        "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
    ]

    def scan_project(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for file in context.inventory.files:
            fname = Path(file.rel_path).name.lower()
            if fname == "package.json":
                content = context.read_text(file)
                deps = parse_package_json(content, file.rel_path)
                for dep in deps:
                    if dep.version in ("*", "latest"):
                        findings.append(
                            self.create_finding(
                                file_path=file.rel_path,
                                line_number=None,
                                evidence=f"Package '{dep.name}' specified with wildcard version '{dep.version}'",
                            )
                        )
            elif fname == "requirements.txt":
                lines = context.get_lines(file)
                for idx, line in enumerate(lines, start=1):
                    clean = line.strip()
                    if not clean or clean.startswith(("#", "-")):
                        continue
                    if (
                        "==" not in clean
                        and ">=" not in clean
                        and "<=" not in clean
                        and "~=" not in clean
                    ):
                        # Naked package name without version constraint
                        pkg_match = _REQUIREMENT_LINE.match(clean)
                        if pkg_match and not pkg_match.group(2):
                            findings.append(
                                self.create_finding(
                                    file_path=file.rel_path,
                                    line_number=idx,
                                    evidence=f"Unpinned Python package '{pkg_match.group(1)}' with no version constraint",
                                )
                            )

        return findings


class MissingLockfileRule(Rule):
    """Detects projects with package manifests but missing lockfiles."""

    rule_id = "DEP002"
    title = "Application Manifest Present Without Corresponding Lockfile"
    description = (
        "The repository contains an application dependency manifest (package.json) but no committed "
        "lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml)."
    )
    severity = Severity.INFO
    confidence = Confidence.HIGH
    category = FindingCategory.DEPENDENCY
    impact = (
        "Without a lockfile, different team members and CI pipelines may resolve different dependency trees, "
        "leading to subtle bugs and untested package versions in production."
    )
    remediation = (
        "1. Run 'npm install', 'yarn install', or 'pnpm install' to generate a lockfile.\n"
        "2. Commit package-lock.json, yarn.lock, or pnpm-lock.yaml to version control."
    )
    references = [
        "https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json",
    ]

    def scan_project(self, context: ScanContext) -> list[Finding]:
        filenames = {Path(f.rel_path).name.lower() for f in context.inventory.files}

        if "package.json" in filenames:
            lockfile_names = {
                "package-lock.json",
                "yarn.lock",
                "pnpm-lock.yaml",
                "npm-shrinkwrap.json",
            }
            if not (filenames & lockfile_names):
                pkg_file = next(
                    f
                    for f in context.inventory.files
                    if Path(f.rel_path).name.lower() == "package.json"
                )
                return [
                    self.create_finding(
                        file_path=pkg_file.rel_path,
                        line_number=1,
                        evidence="Found package.json without corresponding lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml)",
                    )
                ]

        return []


class DependencyVulnerabilityScanner:
    """Orchestrates dependency inventory and optional advisory lookups."""

    def __init__(self, provider: AdvisoryProvider | None = None) -> None:
        self.provider = provider or OfflineAdvisoryProvider()

    def run(self, context: ScanContext) -> tuple[list[Finding], list[str]]:
        """Collect dependencies and query advisories if network is enabled."""
        deps = inventory_dependencies(context.inventory)
        if not deps:
            return [], []

        # If offline provider, don't execute advisory search
        if isinstance(self.provider, OfflineAdvisoryProvider):
            return [], []

        advisories, errors = self.provider.query(deps)
        findings = [adv.to_finding() for adv in advisories]
        return findings, errors
