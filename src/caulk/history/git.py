"""Low-level Git operations and batch blob streaming for historical secret scanning.

Uses deterministic argument-list subprocess calls to interact with Git without
shell execution, workspace modification, or checkout changes.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import IO


@dataclass(frozen=True)
class CommitInfo:
    """Metadata for a Git commit in the traversed history."""

    sha: str
    timestamp: str
    author: str
    subject: str


@dataclass(frozen=True)
class DiffEntry:
    """A changed path and its associated blob object hashes in a commit."""

    status: str
    src_blob_shas: list[str]
    dst_blob_sha: str
    path: str


@dataclass(frozen=True)
class CommitDiff:
    """A commit and all file changes introduced in that commit."""

    commit: CommitInfo
    entries: list[DiffEntry]


def is_git_installed() -> bool:
    """Check if the git executable is installed and available in PATH."""
    return shutil.which("git") is not None


def is_git_repo(path: Path | str) -> bool:
    """Check if the given path is a valid Git repository root."""
    if not is_git_installed():
        return False
    target = Path(path).resolve()
    if not target.exists() or not target.is_dir():
        return False
    if (target / ".git").exists():
        return True
    try:
        res = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            toplevel = Path(res.stdout.strip()).resolve()
            return target == toplevel
        return False
    except Exception:
        return False


def get_local_refs(path: Path | str) -> list[str]:
    """Retrieve all local reachable refs (branches, tags, HEAD)."""
    target = Path(path).resolve()
    refs: list[str] = []
    try:
        res = subprocess.run(
            [
                "git",
                "-C",
                str(target),
                "for-each-ref",
                "--format=%(refname)",
                "refs/heads",
                "refs/tags",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                ref = line.strip()
                if ref and ref not in refs:
                    refs.append(ref)
    except Exception:
        pass

    if "HEAD" not in refs:
        refs.append("HEAD")
    return refs


def parse_blob_size(size_str: str) -> int:
    """Parse a human-readable size string (e.g. '2MB', '500KB', '1048576') to bytes."""
    s = size_str.strip().upper()
    if not s:
        return 2 * 1024 * 1024  # default 2MB

    if s.endswith("GB") or s.endswith("G"):
        num = s.rstrip("GB")
        return int(float(num) * 1024 * 1024 * 1024)
    if s.endswith("MB") or s.endswith("M"):
        num = s.rstrip("MB")
        return int(float(num) * 1024 * 1024)
    if s.endswith("KB") or s.endswith("K"):
        num = s.rstrip("KB")
        return int(float(num) * 1024)
    if s.endswith("B"):
        num = s.rstrip("B")
        return int(num)
    return int(s)


def stream_git_log(
    repo_path: Path | str,
    max_depth: int | None = None,
    since: str | None = None,
    ref: str | None = None,
) -> Generator[CommitDiff, None, None]:
    """Stream commits and raw diffs from Git history using `git log -c --raw`.

    Yields CommitDiff objects without loading the entire repository history into memory.
    """
    target = Path(repo_path).resolve()
    cmd: list[str] = [
        "git",
        "-C",
        str(target),
        "log",
        "-c",
        "--raw",
        "--no-renames",
        "--root",
        "--no-abbrev",
        "--format=COMMIT:%H%x00%aI%x00%an <%ae>%x00%s",
    ]

    if max_depth is not None and max_depth > 0:
        cmd.extend(["-n", str(max_depth)])

    if since:
        cmd.append(f"--since={since}")

    if ref:
        cmd.append(ref)
    else:
        cmd.extend(["--branches", "--tags", "HEAD"])

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except Exception:
        return

    current_commit: CommitInfo | None = None
    current_entries: list[DiffEntry] = []

    try:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\r\n")
            if not line:
                continue

            if line.startswith("COMMIT:"):
                # Yield previous commit diff if exists
                if current_commit is not None:
                    yield CommitDiff(commit=current_commit, entries=current_entries)
                    current_entries = []

                # Parse commit info
                parts = line[7:].split("\x00")
                sha = parts[0] if len(parts) > 0 else ""
                timestamp = parts[1] if len(parts) > 1 else ""
                author = parts[2] if len(parts) > 2 else ""
                subject = parts[3] if len(parts) > 3 else ""

                current_commit = CommitInfo(
                    sha=sha,
                    timestamp=timestamp,
                    author=author,
                    subject=subject,
                )
                continue

            if line.startswith(":") and current_commit is not None:
                # Parse raw diff line
                # Format: :<modes> <shas> <status>\t<path>
                if "\t" not in line:
                    continue
                meta_part, file_path = line.split("\t", 1)
                tokens = meta_part.split()
                if len(tokens) < 4:
                    continue

                status = tokens[-1]
                dst_sha = tokens[-2]

                # Count number of colons to determine number of parents
                colon_prefix = tokens[0]
                num_parents = len(colon_prefix) - len(colon_prefix.lstrip(":"))
                if num_parents < 1:
                    num_parents = 1

                # Check for submodule modes (160000)
                modes = tokens[: num_parents + 1]
                if any("160000" in m for m in modes):
                    continue

                # Extract parent src shas
                # tokens layout: [mode_0..mode_P, sha_0..sha_P-1, dst_sha, status]
                src_shas: list[str] = []
                src_start = num_parents + 1
                src_end = src_start + num_parents
                for s in tokens[src_start:src_end]:
                    if len(s) == 40 and not s.startswith("0000000000"):
                        src_shas.append(s)

                # Skip deletion diffs (no new content in dst)
                if status.startswith("D") or dst_sha.startswith("0000000000"):
                    continue

                current_entries.append(
                    DiffEntry(
                        status=status,
                        src_blob_shas=src_shas,
                        dst_blob_sha=dst_sha,
                        path=file_path.strip(),
                    )
                )

        if current_commit is not None:
            yield CommitDiff(commit=current_commit, entries=current_entries)

    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        proc.terminate()
        proc.wait()


class GitBlobReader:
    """Efficient batch blob reader maintaining a persistent `git cat-file --batch` process.

    Enforces maximum blob size limits, binary file skipping, and stream synchronization.
    """

    def __init__(self, repo_path: Path | str) -> None:
        self.repo_path = Path(repo_path).resolve()
        self._proc: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> GitBlobReader:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def start(self) -> None:
        """Start the persistent `git cat-file --batch` process."""
        if self._proc is not None:
            return
        cmd = ["git", "-C", str(self.repo_path), "cat-file", "--batch"]
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

    def close(self) -> None:
        """Terminate and clean up the persistent process."""
        if self._proc is not None:
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
                if self._proc.stdout:
                    self._proc.stdout.close()
                if self._proc.stderr:
                    self._proc.stderr.close()
                self._proc.terminate()
                self._proc.wait()
            except Exception:
                pass
            finally:
                self._proc = None

    def _read_exact(self, stream: IO[bytes], n: int) -> bytes:
        """Read exactly n bytes from stream, handling partial reads across OS pipes."""
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = stream.read(remaining)
            if not chunk:
                raise EOFError(
                    f"Unexpected EOF reading {n} bytes from git cat-file, received {n - remaining}"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _consume_bytes(self, stream: IO[bytes], n: int) -> None:
        """Consume n bytes from stream in 64KB blocks without keeping them in memory."""
        remaining = n
        buf_size = 65536
        while remaining > 0:
            to_read = min(remaining, buf_size)
            chunk = stream.read(to_read)
            if not chunk:
                raise EOFError(
                    f"Unexpected EOF consuming {n} bytes from git cat-file, received {n - remaining}"
                )
            remaining -= len(chunk)

    def read_blob_text(self, blob_sha: str, max_size: int = 2097152) -> str | None:
        """Read a blob from Git object database.

        Returns decoded text if blob exists, is within max_size, and is non-binary.
        Returns None otherwise, keeping the batch stream strictly synchronized.
        """
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            self.start()
            if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
                return None

        stdin = self._proc.stdin
        stdout = self._proc.stdout

        try:
            stdin.write(f"{blob_sha}\n".encode("ascii"))
            stdin.flush()

            header_line = stdout.readline().decode("ascii", errors="replace").strip()
            if not header_line:
                return None

            parts = header_line.split()
            if len(parts) < 3 or parts[1] != "blob":
                # Object is missing or not a blob (e.g. tree/commit)
                if len(parts) >= 3 and parts[2].isdigit():
                    size = int(parts[2])
                    self._consume_bytes(stdout, size + 1)
                return None

            size = int(parts[2])
            if size > max_size:
                # Oversized: consume blob bytes and trailing newline to keep stream aligned
                self._consume_bytes(stdout, size + 1)
                return None

            # Read raw bytes
            raw_data = self._read_exact(stdout, size)
            # Read trailing newline separator
            self._read_exact(stdout, 1)

            # Heuristic binary check (null byte in first 8KB)
            if b"\x00" in raw_data[:8192]:
                return None

            return raw_data.decode("utf-8", errors="replace")

        except (BrokenPipeError, EOFError, OSError):
            # Process crashed or pipe broken; reset process
            self.close()
            return None
