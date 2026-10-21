"""Tests for Caulk configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from caulk.config import CaulkConfig, write_default_config
from caulk.models import Severity


def test_default_config():
    """Default config has safe defaults and includes standard exclusions."""
    config = CaulkConfig.load()
    assert config.fail_threshold == Severity.HIGH
    assert config.max_file_size_bytes == 2 * 1024 * 1024
    assert config.max_directory_depth == 30
    assert config.enable_advisories is False
    assert ".git" in config.exclude_patterns
    assert "node_modules" in config.exclude_patterns


def test_custom_config_parsing(tmp_path: Path):
    """Custom configuration file overrides defaults appropriately."""
    cfg_file = tmp_path / ".caulk.toml"
    cfg_file.write_text(
        """
[scanner]
fail_threshold = "CRITICAL"
max_file_size_bytes = 1048576
max_directory_depth = 15
exclude = ["custom_dir/*", "*.tmp"]

[network]
enable_advisories = true

[rules]
disabled = ["CFG001", "SEC005"]
""",
        encoding="utf-8",
    )

    loaded = CaulkConfig.load(config_path=cfg_file)
    assert loaded.fail_threshold == Severity.CRITICAL
    assert loaded.max_file_size_bytes == 1048576
    assert loaded.max_directory_depth == 15
    assert loaded.enable_advisories is True
    assert "custom_dir/*" in loaded.exclude_patterns
    assert ".git" in loaded.exclude_patterns  # Preserves base exclusions
    assert "CFG001" in loaded.disabled_rules
    assert "SEC005" in loaded.disabled_rules


def test_config_invalid_threshold(tmp_path: Path):
    cfg_file = tmp_path / ".caulk.toml"
    cfg_file.write_text('[scanner]\nfail_threshold = "NONSENSE"', encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid severity 'NONSENSE'"):
        CaulkConfig.load(config_path=cfg_file)


def test_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        CaulkConfig.load(config_path=Path("non_existent_file.toml"))


def test_write_default_config(tmp_path: Path):
    out = tmp_path / ".caulk.toml"
    assert write_default_config(out) is True
    assert out.exists()

    # Second write without overwrite fails
    assert write_default_config(out, overwrite=False) is False
    # With overwrite succeeds
    assert write_default_config(out, overwrite=True) is True
