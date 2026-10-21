"""Tests for safe repository discovery and filesystem traversal."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from caulk.config import CaulkConfig
from caulk.discovery import discover_project, is_binary_content, matches_any_pattern


def test_is_binary_content():
    """Null bytes indicate binary content."""
    assert is_binary_content(b"Hello world\x00Binary") is True
    assert is_binary_content(b"Plain text source code\nwith lines") is False


def test_matches_any_pattern():
    patterns = [".git", "node_modules", "*.pyc", "dist/*"]
    assert matches_any_pattern(".git", ".git", patterns) is True
    assert matches_any_pattern("src/node_modules/pkg/index.js", "index.js", patterns) is True
    assert matches_any_pattern("dist/bundle.js", "bundle.js", patterns) is True
    assert matches_any_pattern("src/main.py", "main.py", patterns) is False


def test_discover_target_not_found():
    with pytest.raises(FileNotFoundError):
        discover_project("does_not_exist_at_all_12345")


def test_discover_target_not_dir(tmp_path: Path):
    file_path = tmp_path / "regular.txt"
    file_path.write_text("hello", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        discover_project(file_path)


def test_discover_clean_fixture(fixtures_dir: Path):
    clean_dir = fixtures_dir / "clean"
    inv = discover_project(clean_dir)

    assert len(inv.files) > 0
    rel_paths = [f.rel_path for f in inv.files]
    assert "clean_app.py" in rel_paths
    assert "package.json" in rel_paths
    assert "package-lock.json" in rel_paths
    assert "requirements.txt" in rel_paths
    assert "Dockerfile" in rel_paths

    # Check detected ecosystems
    assert "python" in inv.ecosystems
    assert "javascript" in inv.ecosystems
    assert "docker" in inv.ecosystems


def test_discover_respects_exclusions(tmp_path: Path):
    # Setup test project
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / "node_modules" / "test").mkdir(parents=True)
    (tmp_path / "node_modules" / "test" / "index.js").write_text("test", encoding="utf-8")
    (tmp_path / "custom_ignored").mkdir()
    (tmp_path / "custom_ignored" / "secret.py").write_text("x = 1", encoding="utf-8")

    cfg = CaulkConfig(exclude_patterns=[".git", "node_modules", "custom_ignored"])
    inv = discover_project(tmp_path, config=cfg)

    file_names = [Path(f.rel_path).name for f in inv.files]
    assert "app.py" in file_names
    assert "index.js" not in file_names
    assert "secret.py" not in file_names


def test_discover_skips_oversized_files(tmp_path: Path):
    large_file = tmp_path / "large.txt"
    # Create file slightly over 1KB limit
    large_file.write_bytes(b"A" * 2000)

    small_file = tmp_path / "small.txt"
    small_file.write_bytes(b"B" * 100)

    cfg = CaulkConfig(max_file_size_bytes=1000)
    inv = discover_project(tmp_path, config=cfg)

    rel_files = [f.rel_path for f in inv.files]
    assert "small.txt" in rel_files
    assert "large.txt" not in rel_files

    skipped_reasons = {s.rel_path: s.reason for s in inv.skipped}
    assert "large.txt" in skipped_reasons
    assert "file_too_large" in skipped_reasons["large.txt"]


def test_discover_skips_binary_files(tmp_path: Path):
    bin_file = tmp_path / "binary.bin"
    bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00")

    txt_file = tmp_path / "text.py"
    txt_file.write_text("print('text')", encoding="utf-8")

    inv = discover_project(tmp_path)
    rel_files = [f.rel_path for f in inv.files]
    assert "text.py" in rel_files
    assert "binary.bin" not in rel_files

    skipped_reasons = {s.rel_path: s.reason for s in inv.skipped}
    assert "binary.bin" in skipped_reasons
    assert skipped_reasons["binary.bin"] == "binary_file"


def test_discover_depth_limit(tmp_path: Path):
    deep_path = tmp_path / "a" / "b" / "c" / "d"
    deep_path.mkdir(parents=True)
    (deep_path / "deep.py").write_text("x = 1", encoding="utf-8")

    cfg = CaulkConfig(max_directory_depth=2)
    inv = discover_project(tmp_path, config=cfg)

    rel_files = [f.rel_path for f in inv.files]
    assert "deep.py" not in rel_files


def test_discover_symlink_escape_protection(tmp_path: Path):
    """Symlinks pointing outside the repository root must be rejected."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_secret = outside_dir / "secret.env"
    outside_secret.write_text("SECRET=123", encoding="utf-8")

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("print('ok')", encoding="utf-8")

    link_path = repo_dir / "escape_link.env"
    try:
        os.symlink(str(outside_secret), str(link_path))
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted or supported on this system")

    inv = discover_project(repo_dir)
    rel_files = [f.rel_path for f in inv.files]
    assert "escape_link.env" not in rel_files

    skipped_reasons = {s.rel_path: s.reason for s in inv.skipped}
    assert "escape_link.env" in skipped_reasons
    assert skipped_reasons["escape_link.env"] == "symlink_outside_root"
