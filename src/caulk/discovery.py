"""Safe project discovery and file system traversal.

Protects against symlink escapes, directory loops, path traversal, oversized files,
and binary files while identifying project ecosystems.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from caulk.config import CaulkConfig
from caulk.models import normalize_repo_path


@dataclass(frozen=True)
class DiscoveredFile:
    """A project file accepted for inspection."""

    path: Path
    rel_path: str
    size_bytes: int


@dataclass(frozen=True)
class SkippedFile:
    """A file or directory skipped during discovery."""

    rel_path: str
    reason: str


@dataclass
class ProjectInventory:
    """Complete inventory of discovered repository resources."""

    root_path: Path
    files: list[DiscoveredFile] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    ecosystems: set[str] = field(default_factory=set)

    def files_by_name(self, filename: str) -> list[DiscoveredFile]:
        """Find discovered files matching exact filename."""
        return [f for f in self.files if Path(f.rel_path).name.lower() == filename.lower()]

    def files_by_extension(self, *extensions: str) -> list[DiscoveredFile]:
        """Find discovered files matching any of the given extensions."""
        ext_set = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions}
        return [f for f in self.files if Path(f.rel_path).suffix.lower() in ext_set]


def is_binary_content(sample: bytes) -> bool:
    """Heuristic check for binary content using null byte detection."""
    return b"\x00" in sample


def matches_any_pattern(rel_path: str, name: str, patterns: list[str]) -> bool:
    """Check if a path or filename matches any exclusion pattern."""
    normalized_rel = normalize_repo_path(rel_path)
    parts = normalized_rel.split("/")

    for pattern in patterns:
        p_clean = pattern.strip().replace("\\", "/")
        if not p_clean:
            continue

        # Exact match on directory/file name
        if name == p_clean or name.lower() == p_clean.lower():
            return True

        # Match path component (e.g. "node_modules" in "src/node_modules/foo.js")
        if p_clean in parts:
            return True

        # Glob matching against relative path
        if fnmatch.fnmatch(normalized_rel, p_clean) or fnmatch.fnmatch(
            normalized_rel, f"*/{p_clean}"
        ):
            return True
        if fnmatch.fnmatch(name, p_clean):
            return True

    return False


def discover_project(
    target_dir: Path | str,
    config: CaulkConfig | None = None,
) -> ProjectInventory:
    """Safely traverse and inventory a target directory."""
    cfg = config or CaulkConfig()

    resolved_root = Path(target_dir).resolve()
    if not resolved_root.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target_dir}")
    if not resolved_root.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {target_dir}")

    inventory = ProjectInventory(root_path=resolved_root)

    # Walk directory tree safely
    for root, dirnames, filenames in os.walk(str(resolved_root), followlinks=False):
        current_dir = Path(root)

        # Depth check
        try:
            rel_dir = current_dir.relative_to(resolved_root)
        except ValueError:
            # Traversal escape
            inventory.skipped.append(
                SkippedFile(rel_path=str(current_dir), reason="symlink_escape")
            )
            dirnames.clear()
            continue

        depth = len(rel_dir.parts)
        if depth > cfg.max_directory_depth:
            inventory.skipped.append(
                SkippedFile(
                    rel_path=normalize_repo_path(rel_dir),
                    reason=f"exceeded_max_depth_{cfg.max_directory_depth}",
                )
            )
            dirnames.clear()
            continue

        # Prune excluded directories in-place to prevent traversing them
        kept_dirs: list[str] = []
        for d in dirnames:
            dir_path = current_dir / d
            rel_d = normalize_repo_path(dir_path.relative_to(resolved_root))

            # Symlink escape check for directory symlinks
            if dir_path.is_symlink():
                try:
                    resolved_d = dir_path.resolve()
                    if not resolved_d.is_relative_to(resolved_root):
                        inventory.skipped.append(
                            SkippedFile(rel_path=rel_d, reason="symlink_outside_root")
                        )
                        continue
                except (OSError, RuntimeError):
                    inventory.skipped.append(
                        SkippedFile(rel_path=rel_d, reason="unresolvable_symlink")
                    )
                    continue

            # Exclusion check
            if matches_any_pattern(rel_d, d, cfg.exclude_patterns):
                inventory.skipped.append(SkippedFile(rel_path=rel_d, reason="excluded_directory"))
                continue

            kept_dirs.append(d)

        dirnames[:] = kept_dirs

        # Process files in current directory
        for fname in filenames:
            file_path = current_dir / fname
            try:
                rel_f = normalize_repo_path(file_path.relative_to(resolved_root))
            except ValueError:
                inventory.skipped.append(
                    SkippedFile(rel_path=fname, reason="path_resolution_error")
                )
                continue

            # Symlink escape check
            if file_path.is_symlink():
                try:
                    resolved_f = file_path.resolve()
                    if not resolved_f.is_relative_to(resolved_root):
                        inventory.skipped.append(
                            SkippedFile(rel_path=rel_f, reason="symlink_outside_root")
                        )
                        continue
                except (OSError, RuntimeError):
                    inventory.skipped.append(
                        SkippedFile(rel_path=rel_f, reason="unresolvable_symlink")
                    )
                    continue

            # Exclusion check
            if matches_any_pattern(rel_f, fname, cfg.exclude_patterns):
                inventory.skipped.append(SkippedFile(rel_path=rel_f, reason="excluded_file"))
                continue

            # Stat file safely
            try:
                stat_result = file_path.stat()
            except (OSError, PermissionError) as err:
                inventory.skipped.append(
                    SkippedFile(rel_path=rel_f, reason=f"unreadable_file_{type(err).__name__}")
                )
                continue

            # Size limit check
            if stat_result.st_size > cfg.max_file_size_bytes:
                inventory.skipped.append(
                    SkippedFile(
                        rel_path=rel_f,
                        reason=f"file_too_large_{stat_result.st_size}_bytes",
                    )
                )
                continue

            # Empty files can be recorded without binary check
            if stat_result.st_size == 0:
                inventory.files.append(
                    DiscoveredFile(
                        path=file_path,
                        rel_path=rel_f,
                        size_bytes=0,
                    )
                )
                continue

            # Binary check on sample
            try:
                with open(file_path, "rb") as bf:
                    sample = bf.read(min(8192, stat_result.st_size))
                    if is_binary_content(sample):
                        inventory.skipped.append(SkippedFile(rel_path=rel_f, reason="binary_file"))
                        continue
            except (OSError, PermissionError) as err:
                inventory.skipped.append(
                    SkippedFile(rel_path=rel_f, reason=f"read_error_{type(err).__name__}")
                )
                continue

            inventory.files.append(
                DiscoveredFile(
                    path=file_path,
                    rel_path=rel_f,
                    size_bytes=stat_result.st_size,
                )
            )

    # Detect ecosystems from discovered manifests
    _detect_ecosystems(inventory)

    return inventory


def _detect_ecosystems(inventory: ProjectInventory) -> None:
    """Identify project ecosystems based on manifests present in inventory."""
    filenames_lower = {Path(f.rel_path).name.lower() for f in inventory.files}

    # Python ecosystem
    python_manifests = {
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
    }
    if python_manifests & filenames_lower:
        inventory.ecosystems.add("python")

    # JavaScript / Node.js ecosystem
    js_manifests = {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
    }
    if js_manifests & filenames_lower:
        inventory.ecosystems.add("javascript")

    # Docker ecosystem
    docker_manifests = {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
    }
    if (docker_manifests & filenames_lower) or any(
        f.startswith("dockerfile.") for f in filenames_lower
    ):
        inventory.ecosystems.add("docker")
