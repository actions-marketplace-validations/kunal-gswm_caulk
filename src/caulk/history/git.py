"""Low-level Git operations and batch blob streaming for historical secret scanning.

Uses deterministic argument-list subprocess calls to interact with Git without
shell execution, workspace modification, or checkout changes.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Generator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import IO

from caulk.redaction import sanitize_evidence


class GitError(Exception):
    """Base exception for Git operations in Caulk."""


class GitCommandError(GitError):
    """Raised when a Git command fails with a non-zero exit code or stderr output."""

    def __init__(self, message: str, returncode: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class BlobReadStatus(StrEnum):
    """Outcome status when attempting to read a Git blob object."""

    SUCCESS = "success"
    SKIPPED_BINARY = "skipped_binary"
    SKIPPED_OVERSIZED = "skipped_oversized"
    MISSING_OBJECT = "missing_object"
    CORRUPT_OBJECT = "corrupt_object"
    READ_ERROR = "read_error"


@dataclass(frozen=True)
class BlobReadResult:
    """Result of attempting to read a blob from the Git object database."""

    status: BlobReadStatus
    text: str | None = None
    size: int = 0
    error_message: str | None = None


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


def validate_git_ref(ref: str) -> None:
    """Validate a user-supplied Git reference to prevent option injection and syntax errors."""
    if not ref or not ref.strip():
        raise ValueError("Git ref cannot be empty.")
    stripped = ref.strip()
    if stripped.startswith("-"):
        raise ValueError(f"Git ref cannot start with '-': '{stripped}'")
    invalid_chars = set(" ~^:?*[\\")
    if any(c in invalid_chars or ord(c) < 32 or ord(c) == 127 for c in stripped):
        raise ValueError(f"Git ref contains invalid characters: '{stripped}'")
    if (
        ".." in stripped
        or stripped.endswith("/")
        or stripped.endswith(".lock")
        or stripped.startswith("/")
    ):
        raise ValueError(f"Git ref syntax is invalid: '{stripped}'")


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
    """Retrieve all local reachable refs (branches, tags, HEAD).

    Raises GitCommandError if git command fails unexpectedly.
    Returns empty list if repository has no commits yet.
    """
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
        if res.returncode != 0:
            err = res.stderr.strip()
            raise GitCommandError(
                f"git for-each-ref failed with exit code {res.returncode}: {err}",
                returncode=res.returncode,
                stderr=err,
            )
        for line in res.stdout.splitlines():
            ref = line.strip()
            if ref and ref not in refs:
                refs.append(ref)
    except GitCommandError:
        raise
    except Exception as err:
        raise GitCommandError(f"Failed to query local refs: {err}") from err

    head_res = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "--verify", "--quiet", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if head_res.returncode == 0 and "HEAD" not in refs:
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
    Raises GitCommandError if git log fails unexpectedly.
    """
    target = Path(repo_path).resolve()

    if ref is not None:
        try:
            validate_git_ref(ref)
        except ValueError as err:
            raise GitError(str(err)) from err

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
        local_refs = get_local_refs(target)
        if not local_refs:
            return
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
    except Exception as err:
        raise GitCommandError(f"Failed to start git log: {err}") from err

    stderr_lines: list[str] = []

    def _drain_stderr() -> None:
        try:
            if proc.stderr:
                for line in proc.stderr:
                    if sum(len(x) for x in stderr_lines) < 8192:
                        stderr_lines.append(line)
        except Exception:
            pass

    stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
    stderr_thread.start()

    current_commit: CommitInfo | None = None
    current_entries: list[DiffEntry] = []
    terminated_by_caller = False

    try:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\r\n")
            if not line:
                continue

            if line.startswith("COMMIT:"):
                if current_commit is not None:
                    yield CommitDiff(commit=current_commit, entries=current_entries)
                    current_entries = []

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
                if "\t" not in line:
                    continue
                meta_part, file_path = line.split("\t", 1)
                tokens = meta_part.split()
                if len(tokens) < 4:
                    continue

                status = tokens[-1]
                dst_sha = tokens[-2]

                colon_prefix = tokens[0]
                num_parents = len(colon_prefix) - len(colon_prefix.lstrip(":"))
                if num_parents < 1:
                    num_parents = 1

                modes = tokens[: num_parents + 1]
                if any("160000" in m for m in modes):
                    continue

                src_shas: list[str] = []
                src_start = num_parents + 1
                src_end = src_start + num_parents
                for s in tokens[src_start:src_end]:
                    if len(s) == 40 and not s.startswith("0000000000"):
                        src_shas.append(s)

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

    except GeneratorExit:
        terminated_by_caller = True
        raise
    except Exception:
        terminated_by_caller = True
        raise
    finally:
        try:
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()
        except Exception:
            pass

        if terminated_by_caller and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
        else:
            proc.wait()

        stderr_thread.join(timeout=1.0)
        try:
            if proc.stderr and not proc.stderr.closed:
                proc.stderr.close()
        except Exception:
            pass

        if not terminated_by_caller and proc.returncode != 0:
            raw_err = "".join(stderr_lines).strip()
            sanitized = sanitize_evidence(raw_err)[:1000] if raw_err else "Unknown git error"
            raise GitCommandError(
                f"git log failed with exit code {proc.returncode}: {sanitized}",
                returncode=proc.returncode,
                stderr=sanitized,
            )


class GitBlobReader:
    """Efficient batch blob reader maintaining a persistent `git cat-file --batch` process.

    Enforces maximum blob size limits, binary file skipping, error isolation,
    and stream synchronization.
    """

    def __init__(self, repo_path: Path | str) -> None:
        self.repo_path = Path(repo_path).resolve()
        self._proc: subprocess.Popen[bytes] | None = None
        self._stderr_buffer: list[str] = []
        self._stderr_thread: threading.Thread | None = None

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
        self._stderr_buffer = []
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        if not self._proc or not self._proc.stderr:
            return
        try:
            for raw_line in iter(self._proc.stderr.readline, b""):
                line = raw_line.decode("utf-8", errors="replace").strip()
                if line and len(self._stderr_buffer) < 50:
                    self._stderr_buffer.append(line)
        except Exception:
            pass

    def get_recent_stderr(self) -> str:
        """Retrieve and clear recent stderr output."""
        errs = list(self._stderr_buffer)
        self._stderr_buffer.clear()
        return " | ".join(errs)

    def close(self) -> None:
        """Terminate and clean up the persistent process."""
        if self._proc is not None:
            proc = self._proc
            self._proc = None
            try:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
                if proc.stdout and not proc.stdout.closed:
                    proc.stdout.close()
                if proc.stderr and not proc.stderr.closed:
                    proc.stderr.close()
            except Exception:
                pass
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
            if self._stderr_thread and self._stderr_thread.is_alive():
                self._stderr_thread.join(timeout=1.0)
            self._stderr_thread = None

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

    def read_blob(self, blob_sha: str, max_size: int = 2097152) -> BlobReadResult:
        """Read a blob from Git object database with typed outcome isolation."""
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            self.start()
            if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
                return BlobReadResult(
                    status=BlobReadStatus.READ_ERROR,
                    error_message="Failed to start git cat-file process",
                )

        stdin = self._proc.stdin
        stdout = self._proc.stdout

        try:
            stdin.write(f"{blob_sha}\n".encode("ascii"))
            stdin.flush()

            raw_header = stdout.readline()
            if not raw_header:
                err_detail = self.get_recent_stderr() or "Unexpected EOF from git cat-file"
                self.close()
                return BlobReadResult(
                    status=BlobReadStatus.READ_ERROR,
                    error_message=err_detail,
                )

            header_line = raw_header.decode("ascii", errors="replace").strip()
            parts = header_line.split()

            if len(parts) >= 2 and parts[1] == "missing":
                err_detail = self.get_recent_stderr()
                if err_detail and (
                    "corrupt" in err_detail.lower() or "error" in err_detail.lower()
                ):
                    return BlobReadResult(
                        status=BlobReadStatus.CORRUPT_OBJECT,
                        error_message=f"Corrupt object {blob_sha}: {err_detail}",
                    )
                return BlobReadResult(
                    status=BlobReadStatus.MISSING_OBJECT,
                    error_message=f"Git object {blob_sha} is missing",
                )

            if len(parts) >= 3 and parts[1] != "blob":
                if parts[2].isdigit():
                    size = int(parts[2])
                    self._consume_bytes(stdout, size + 1)
                return BlobReadResult(
                    status=BlobReadStatus.CORRUPT_OBJECT,
                    error_message=f"Object {blob_sha} has unexpected type '{parts[1]}' (expected 'blob')",
                )

            if len(parts) < 3 or not parts[2].isdigit():
                self.close()
                return BlobReadResult(
                    status=BlobReadStatus.CORRUPT_OBJECT,
                    error_message=f"Malformed header from git cat-file: '{header_line}'",
                )

            size = int(parts[2])
            if size > max_size:
                self._consume_bytes(stdout, size + 1)
                return BlobReadResult(
                    status=BlobReadStatus.SKIPPED_OVERSIZED,
                    size=size,
                )

            raw_data = self._read_exact(stdout, size)
            self._read_exact(stdout, 1)

            if b"\x00" in raw_data[:8192]:
                return BlobReadResult(
                    status=BlobReadStatus.SKIPPED_BINARY,
                    size=size,
                )

            text = raw_data.decode("utf-8", errors="replace")
            return BlobReadResult(
                status=BlobReadStatus.SUCCESS,
                text=text,
                size=size,
            )

        except (BrokenPipeError, EOFError, OSError) as err:
            self.close()
            return BlobReadResult(
                status=BlobReadStatus.READ_ERROR,
                error_message=f"I/O error reading object {blob_sha}: {err}",
            )

    def read_blob_text(self, blob_sha: str, max_size: int = 2097152) -> str | None:
        """Backward-compatible helper returning decoded text on success, None on skip/error."""
        res = self.read_blob(blob_sha, max_size=max_size)
        return res.text if res.status == BlobReadStatus.SUCCESS else None
