"""Tests for dependency parsing, lockfile detection, and advisory providers."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caulk.config import CaulkConfig
from caulk.discovery import DiscoveredFile, ProjectInventory
from caulk.rules.advisories import OfflineAdvisoryProvider, OSVAdvisoryProvider, PackageDependency
from caulk.rules.base import ScanContext
from caulk.rules.dependencies import (
    MissingLockfileRule,
    UnpinnedDependencyRule,
    parse_package_json,
    parse_package_lock_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)


def test_parse_requirements_txt():
    content = (
        "# Comments should be ignored\n"
        "--index-url https://pypi.org/simple\n"
        "requests==2.31.0\n"
        "flask>=2.0.0 # with inline comment\n"
        "pytest~=7.4.0 ; python_version > '3.8'\n"
        "naked-package\n"
    )
    deps = parse_requirements_txt(content, "requirements.txt")
    names = {d.name: d.version for d in deps}

    assert names["requests"] == "2.31.0"
    assert names["flask"] == ">=2.0.0"
    assert names["pytest"] == "~=7.4.0"
    assert names["naked-package"] is None


def test_parse_pyproject_toml():
    content = """
[project]
name = "my-project"
dependencies = [
    "pydantic==2.5.0",
    "fastapi>=0.100.0",
]

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
"""
    deps = parse_pyproject_toml(content, "pyproject.toml")
    names = {d.name: d.version for d in deps}

    assert names["pydantic"] == "2.5.0"
    assert names["fastapi"] == ">=0.100.0"
    assert names["requests"] == "^2.31.0"
    assert "python" not in names


def test_parse_package_json():
    content = json.dumps(
        {
            "dependencies": {
                "express": "^4.19.2",
                "lodash": "*",
            },
            "devDependencies": {"typescript": "^5.0.0"},
        }
    )
    deps = parse_package_json(content, "package.json")
    names = {d.name: d.version for d in deps}

    assert names["express"] == "^4.19.2"
    assert names["lodash"] == "*"
    assert names["typescript"] == "^5.0.0"


def test_parse_package_lock_json():
    content = json.dumps(
        {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/express": {"version": "4.19.2"},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
    )
    deps = parse_package_lock_json(content, "package-lock.json")
    names = {d.name: d.version for d in deps}

    assert names["express"] == "4.19.2"
    assert names["lodash"] == "4.17.21"


def test_unpinned_dependency_rule_positive(tmp_path: Path):
    rule = UnpinnedDependencyRule()
    pkg_content = json.dumps({"dependencies": {"lodash": "*"}})
    req_content = "requests\n"

    (tmp_path / "package.json").write_text(pkg_content, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text(req_content, encoding="utf-8")

    files = [
        DiscoveredFile(tmp_path / "package.json", "package.json", len(pkg_content)),
        DiscoveredFile(tmp_path / "requirements.txt", "requirements.txt", len(req_content)),
    ]
    inv = ProjectInventory(root_path=tmp_path, files=files)
    ctx = ScanContext(inventory=inv, config=CaulkConfig())

    findings = rule.scan_project(ctx)
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert "DEP001" in rule_ids


def test_missing_lockfile_rule(tmp_path: Path):
    rule = MissingLockfileRule()
    pkg_content = json.dumps({"dependencies": {"express": "4.18.2"}})
    (tmp_path / "package.json").write_text(pkg_content, encoding="utf-8")

    file = DiscoveredFile(tmp_path / "package.json", "package.json", len(pkg_content))
    inv = ProjectInventory(root_path=tmp_path, files=[file])
    ctx = ScanContext(inventory=inv, config=CaulkConfig())

    findings = rule.scan_project(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "DEP002"


def test_offline_advisory_provider_does_not_network():
    provider = OfflineAdvisoryProvider()
    deps = [
        PackageDependency("requests", "2.18.0", "PyPI", "requirements.txt"),
    ]
    advisories, errors = provider.query(deps)
    assert len(advisories) == 0
    assert len(errors) == 0


@patch("urllib.request.urlopen")
def test_osv_advisory_provider_mocked(mock_urlopen):
    # Mock successful OSV response
    mock_response = MagicMock()
    mock_payload = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-test-1234",
                        "summary": "Mock Test Vulnerability in Requests",
                        "details": "A test vulnerability detail description.",
                        "affected": [{"ranges": [{"events": [{"fixed": "2.20.0"}]}]}],
                        "references": [{"url": "https://example.com/advisory"}],
                    }
                ]
            }
        ]
    }
    mock_response.read.return_value = json.dumps(mock_payload).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    provider = OSVAdvisoryProvider()
    deps = [
        PackageDependency("requests", "2.18.0", "PyPI", "requirements.txt"),
    ]

    advisories, errors = provider.query(deps)
    assert len(errors) == 0
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv.advisory_id == "GHSA-test-1234"
    assert adv.fixed_versions == ["2.20.0"]

    # Finding conversion
    finding = adv.to_finding()
    assert finding.rule_id == "DEP003"
    assert "requests==2.18.0" in finding.evidence
