"""Configuration management for Caulk.

Reads and validates `.caulk.toml` files and provides safe default parameters.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from caulk.models import Severity

# Standard safe default exclusions for any project
DEFAULT_EXCLUDED_PATTERNS: list[str] = [
    # Version control
    ".git",
    ".svn",
    ".hg",
    # Python caches and virtualenvs
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    # JavaScript dependencies and caches
    "node_modules",
    ".next",
    ".nuxt",
    ".turbo",
    ".npm",
    ".yarn",
    # Build artifacts
    "dist",
    "build",
    "target",
    "out",
    "bin",
    "obj",
    "vendor",
    # IDEs and editors
    ".idea",
    ".vscode",
    # OS files
    ".DS_Store",
    "Thumbs.db",
]

DEFAULT_CONFIG_TEMPLATE = """# Caulk Security Scanner Configuration
# Documentation: https://github.com/kunal-gswm/caulk

[scanner]
# Minimum severity level to cause non-zero exit code (CRITICAL, HIGH, MEDIUM, LOW, INFO)
fail_threshold = "HIGH"

# Maximum file size in bytes to scan (default: 2MB)
max_file_size_bytes = 2097152

# Maximum directory depth to traverse
max_directory_depth = 30

# Exclude patterns (relative to repository root)
exclude = [
    # Add project-specific exclusions here
    # "docs/*",
    # "tests/fixtures/*",
]

[network]
# External network advisory checks (e.g. OSV.dev dependency vulnerability queries)
# Network queries are strictly disabled by default for privacy and deterministic local scanning.
enable_advisories = false

[rules]
# Disable specific rules by ID if necessary
# disabled = ["CFG002"]
disabled = []
"""


@dataclass
class CaulkConfig:
    """Loaded configuration for a Caulk scan."""

    fail_threshold: Severity = Severity.HIGH
    max_file_size_bytes: int = 2 * 1024 * 1024  # 2 MB
    max_directory_depth: int = 30
    exclude_patterns: list[str] = field(default_factory=list)
    enable_advisories: bool = False
    disabled_rules: set[str] = field(default_factory=set)
    config_file_path: Path | None = None

    @classmethod
    def load(cls, config_path: Path | None = None, base_dir: Path | None = None) -> CaulkConfig:
        """Load configuration from a path or auto-discover in base_dir.

        If no configuration file exists, returns safe default configuration.
        """
        target_file: Path | None = None

        if config_path is not None:
            if not config_path.is_file():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            target_file = config_path
        elif base_dir is not None:
            candidate = base_dir / ".caulk.toml"
            if candidate.is_file():
                target_file = candidate

        if target_file is None:
            return cls(exclude_patterns=list(DEFAULT_EXCLUDED_PATTERNS))

        try:
            with open(target_file, "rb") as f:
                data = tomllib.load(f)
        except Exception as err:
            raise ValueError(f"Failed to parse configuration file {target_file}: {err}") from err

        return cls.from_dict(data, config_file_path=target_file)

    @classmethod
    def from_dict(cls, data: dict[str, Any], config_file_path: Path | None = None) -> CaulkConfig:
        """Parse and validate configuration dictionary."""
        scanner_data = data.get("scanner", {})
        network_data = data.get("network", {})
        rules_data = data.get("rules", {})

        # Parse fail_threshold
        raw_threshold = scanner_data.get("fail_threshold", "HIGH")
        threshold = Severity.from_string(raw_threshold)

        # Parse max file size
        max_size = int(scanner_data.get("max_file_size_bytes", 2 * 1024 * 1024))
        if max_size <= 0:
            raise ValueError("max_file_size_bytes must be greater than 0")

        # Parse max directory depth
        max_depth = int(scanner_data.get("max_directory_depth", 30))
        if max_depth <= 0:
            raise ValueError("max_directory_depth must be greater than 0")

        # Parse user excludes and combine with safe defaults
        user_excludes = scanner_data.get("exclude", [])
        if not isinstance(user_excludes, list):
            raise ValueError("scanner.exclude must be a list of string patterns")

        combined_excludes = list(DEFAULT_EXCLUDED_PATTERNS)
        for pattern in user_excludes:
            if isinstance(pattern, str) and pattern.strip():
                combined_excludes.append(pattern.strip())

        # Parse network setting
        enable_advisories = bool(network_data.get("enable_advisories", False))

        # Parse disabled rules
        disabled = rules_data.get("disabled", [])
        if not isinstance(disabled, list):
            raise ValueError("rules.disabled must be a list of rule ID strings")
        disabled_set = {str(r).strip() for r in disabled if str(r).strip()}

        return cls(
            fail_threshold=threshold,
            max_file_size_bytes=max_size,
            max_directory_depth=max_depth,
            exclude_patterns=combined_excludes,
            enable_advisories=enable_advisories,
            disabled_rules=disabled_set,
            config_file_path=config_file_path,
        )


def write_default_config(target_path: Path, overwrite: bool = False) -> bool:
    """Generate starter .caulk.toml file."""
    if target_path.exists() and not overwrite:
        return False

    target_path.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    return True
