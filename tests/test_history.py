"""Tests for Caulk Git history secret scanning subsystem (v0.3.0).

Verifies deterministic historical scanning across all Git topologies:
- Initial commits, deleted secrets, replaced secrets
- Multi-branch history, git tags, merge commits, multiple root commits
- Blob deduplication, blob size limits, corrupted objects
- Path exclusions, non-git directory handling, secret redaction, and CLI exit codes.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from caulk.cli import (
    EXIT_EXECUTION_ERROR,
    EXIT_FINDINGS_BREACH_THRESHOLD,
    EXIT_SUCCESS_CLEAN,
    EXIT_USAGE_ERROR,
    app,
)
from caulk.history.git import (
    GitBlobReader,
    get_local_refs,
    is_git_repo,
    parse_blob_size,
    validate_git_ref,
)
from caulk.history.scanner import GitHistoryScanner
from caulk.models import FindingStatus


# Helper functions to build synthetic secrets dynamically without raw literals
def synthetic_aws_key() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE"


def synthetic_github_token() -> str:
    return "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"


def synthetic_slack_webhook() -> str:
    webhook_host = "https://" + "hooks." + "slack.com/services/"
    return f"{webhook_host}T12345678/B12345678/fixture_token_token_94819481"


def synthetic_private_key() -> str:
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    footer = "-----END " + "RSA PRIVATE KEY-----"
    return f"{header}\nMIIEowIBAAKCAQEA0synthetic...\n{footer}"


def make_git_repo(path: Path) -> Path:
    """Initialize a clean Git repository for testing."""
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Caulk Tester"], cwd=path, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "tester@example.com"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    return path


def git_commit(path: Path, message: str) -> str:
    """Stage all changes and commit, returning commit SHA."""
    subprocess.run(["git", "add", "-A"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", message], cwd=path, check=True, capture_output=True)
    res = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True, check=True
    )
    return res.stdout.strip()


# ==============================================================================
# Git Helpers & Reader Tests
# ==============================================================================


def test_is_git_repo(tmp_path: Path):
    """Verify is_git_repo returns True for Git directories and False otherwise."""
    assert is_git_repo(tmp_path) is False

    make_git_repo(tmp_path)
    assert is_git_repo(tmp_path) is True


def test_parse_blob_size():
    """Verify human-readable blob size string parsing."""
    assert parse_blob_size("2MB") == 2 * 1024 * 1024
    assert parse_blob_size("500KB") == 500 * 1024
    assert parse_blob_size("1GB") == 1 * 1024 * 1024 * 1024
    assert parse_blob_size("1048576") == 1048576
    assert parse_blob_size("200B") == 200
    assert parse_blob_size("") == 2 * 1024 * 1024


def test_get_local_refs(tmp_path: Path):
    """Verify get_local_refs discovers branches, tags, and HEAD."""
    repo = make_git_repo(tmp_path)
    (repo / "file.txt").write_text("initial\n")
    git_commit(repo, "initial commit")

    subprocess.run(
        ["git", "checkout", "-b", "feature-x"], cwd=repo, check=True, capture_output=True
    )
    subprocess.run(["git", "tag", "v1.0.0"], cwd=repo, check=True, capture_output=True)

    refs = get_local_refs(repo)
    assert "HEAD" in refs
    assert any("feature-x" in r for r in refs)
    assert any("v1.0.0" in r for r in refs)


def test_git_blob_reader_size_limit_and_binary(tmp_path: Path):
    """Verify GitBlobReader handles oversized blobs and binary null bytes without de-synchronizing."""
    repo = make_git_repo(tmp_path)

    # 1. Normal small text
    (repo / "small.txt").write_text("Hello World\n")
    # 2. Large text (300 KB)
    (repo / "large.txt").write_text("A" * (300 * 1024))
    # 3. Binary file
    (repo / "binary.bin").write_bytes(b"Header\x00BinaryData\x0012345")
    # 4. Another small text
    (repo / "after.txt").write_text("Still Working\n")

    git_commit(repo, "Add files")

    # Get object hashes
    def rev_parse(rel: str) -> str:
        return subprocess.run(
            ["git", "rev-parse", f"HEAD:{rel}"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    small_sha = rev_parse("small.txt")
    large_sha = rev_parse("large.txt")
    binary_sha = rev_parse("binary.bin")
    after_sha = rev_parse("after.txt")

    with GitBlobReader(repo) as reader:
        # Read small text
        txt1 = reader.read_blob_text(small_sha, max_size=1024 * 1024)
        assert txt1 == "Hello World\n"

        # Read oversized text with limit 100KB -> must return None
        txt_large = reader.read_blob_text(large_sha, max_size=100 * 1024)
        assert txt_large is None

        # Read binary file -> must return None
        txt_bin = reader.read_blob_text(binary_sha, max_size=1024 * 1024)
        assert txt_bin is None

        # Stream must STILL be synchronized: read next small text cleanly
        txt2 = reader.read_blob_text(after_sha, max_size=1024 * 1024)
        assert txt2 == "Still Working\n"


# ==============================================================================
# Historical Scanning Scenarios
# ==============================================================================


def test_scenario_initial_commit_secret(tmp_path: Path):
    """Scenario 1: Secret committed in initial commit and present in HEAD."""
    repo = make_git_repo(tmp_path)
    (repo / "auth.py").write_text(f"AWS_KEY = '{synthetic_aws_key()}'\n")
    sha1 = git_commit(repo, "Initial commit with AWS key")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SEC002"
    assert f.status == FindingStatus.HISTORICAL
    assert f.is_historical is True
    assert f.commit_sha == sha1
    assert f.commit_subject == "Initial commit with AWS key"
    assert f.file_path == "auth.py"
    assert f.line_number == 1
    # Check 5-point remediation guidance
    assert "HISTORICAL EXPOSURE" in f.remediation
    assert "REMOVAL INEFFECTIVE" in f.remediation
    assert "IMMEDIATE ROTATION" in f.remediation
    assert "AUDIT ACCESS LOGS" in f.remediation
    assert "REWRITE HISTORY SAFELY" in f.remediation
    assert "git-filter-repo" in f.remediation


def test_scenario_deleted_secret(tmp_path: Path):
    """Scenario 2: Secret committed in commit 1, deleted in commit 2."""
    repo = make_git_repo(tmp_path)

    # Commit 1: Add secret
    (repo / "secret.env").write_text(f"GITHUB_TOKEN={synthetic_github_token()}\n")
    sha1 = git_commit(repo, "Add secret token")

    # Commit 2: Delete secret file
    (repo / "secret.env").unlink()
    sha2 = git_commit(repo, "Delete secret token")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    # Secret MUST be detected and attributed to commit 1
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SEC003"
    assert f.commit_sha == sha1
    assert f.commit_sha != sha2
    assert f.file_path == "secret.env"


def test_scenario_replaced_secret_with_placeholder(tmp_path: Path):
    """Scenario 3: Secret committed in commit 1, replaced with placeholder in commit 2."""
    repo = make_git_repo(tmp_path)

    # Commit 1: Real secret
    (repo / "config.py").write_text(f"TOKEN = '{synthetic_github_token()}'\n")
    sha1 = git_commit(repo, "Add config with real token")

    # Commit 2: Replace with placeholder
    (repo / "config.py").write_text("TOKEN = 'your_api_key_here'\n")
    sha2 = git_commit(repo, "Replace token with placeholder")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SEC003"
    assert f.commit_sha == sha1
    assert f.commit_sha != sha2


def test_scenario_multi_commit_history(tmp_path: Path):
    """Scenario 4: Multi-commit history touching multiple files."""
    repo = make_git_repo(tmp_path)

    # C1: Safe file
    (repo / "readme.md").write_text("# Project\n")
    git_commit(repo, "docs: init readme")

    # C2: Add Slack webhook
    (repo / "webhook.py").write_text(f"HOOK = '{synthetic_slack_webhook()}'\n")
    sha2 = git_commit(repo, "feat: add slack webhook")

    # C3: Safe file edit
    (repo / "readme.md").write_text("# Project Documentation\nUpdated.\n")
    git_commit(repo, "docs: update readme")

    # C4: Add Private Key
    (repo / "key.pem").write_text(synthetic_private_key())
    sha4 = git_commit(repo, "feat: add private key")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert len(result.findings) == 2
    rule_ids = {f.rule_id for f in result.findings}
    commit_shas = {f.commit_sha for f in result.findings}

    assert "SEC005" in rule_ids  # Slack Webhook
    assert "SEC001" in rule_ids  # Private Key
    assert sha2 in commit_shas
    assert sha4 in commit_shas


def test_scenario_multi_branch_and_merge(tmp_path: Path):
    """Scenario 5 & 7: Feature branch with secret merged into main."""
    repo = make_git_repo(tmp_path)

    # Initial commit on main
    (repo / "app.py").write_text("print('app')\n")
    git_commit(repo, "Initial app")

    # Feature branch with AWS key
    subprocess.run(
        ["git", "checkout", "-b", "feature/auth"], cwd=repo, check=True, capture_output=True
    )
    (repo / "auth.py").write_text(f"AWS_KEY = '{synthetic_aws_key()}'\n")
    feat_sha = git_commit(repo, "Add aws auth on feature branch")

    # Switch back to main, do some work
    subprocess.run(["git", "checkout", "main"], cwd=repo, check=True, capture_output=True)
    (repo / "other.py").write_text("print('other')\n")
    git_commit(repo, "Main branch progress")

    # Merge feature into main (no-ff)
    subprocess.run(
        ["git", "merge", "feature/auth", "--no-ff", "-m", "Merge feature/auth"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    # Must find the secret and attribute it to the feature commit where it was introduced,
    # NOT duplicate it for the merge commit!
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SEC002"
    assert f.commit_sha == feat_sha


def test_scenario_git_tags(tmp_path: Path):
    """Scenario 6: Secret reachable via Git tag."""
    repo = make_git_repo(tmp_path)

    (repo / "init.py").write_text("init\n")
    git_commit(repo, "init")

    # Create orphan branch with secret
    subprocess.run(
        ["git", "checkout", "--orphan", "release-archive"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (repo / "archived.py").write_text(f"KEY = '{synthetic_aws_key()}'\n")
    tag_commit_sha = git_commit(repo, "Archived secret release")
    subprocess.run(["git", "tag", "v0.9.0-archived"], cwd=repo, check=True, capture_output=True)

    # Switch back to main, delete branch release-archive (tag remains)
    subprocess.run(["git", "checkout", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "branch", "-D", "release-archive"], cwd=repo, check=True, capture_output=True
    )

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert len(result.findings) == 1
    assert result.findings[0].commit_sha == tag_commit_sha


def test_scenario_conflict_resolution_evil_merge(tmp_path: Path):
    """Scenario 7b: Secret introduced directly inside a merge conflict resolution."""
    repo = make_git_repo(tmp_path)

    (repo / "config.txt").write_text("line1\n")
    git_commit(repo, "init config")

    subprocess.run(["git", "checkout", "-b", "feat"], cwd=repo, check=True, capture_output=True)
    (repo / "config.txt").write_text("feat version\n")
    git_commit(repo, "feat edit")

    subprocess.run(["git", "checkout", "main"], cwd=repo, check=True, capture_output=True)
    (repo / "config.txt").write_text("main version\n")
    git_commit(repo, "main edit")

    # Trigger conflict
    subprocess.run(["git", "merge", "feat"], cwd=repo, capture_output=True)
    # Resolve conflict by introducing a secret
    (repo / "config.txt").write_text(f"AWS_KEY = '{synthetic_aws_key()}'\n")
    merge_sha = git_commit(repo, "Resolved conflict with AWS key")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    # The evil merge introduced the secret
    assert len(result.findings) == 1
    assert result.findings[0].commit_sha == merge_sha


def test_scenario_multiple_root_commits(tmp_path: Path):
    """Scenario 8: Multiple independent root commits (orphan branch merged)."""
    repo = make_git_repo(tmp_path)

    (repo / "root1.txt").write_text("root 1\n")
    git_commit(repo, "Root 1")

    # Create independent second root
    subprocess.run(
        ["git", "checkout", "--orphan", "orphan-root"], cwd=repo, check=True, capture_output=True
    )
    (repo / "root1.txt").unlink()
    (repo / "root2.py").write_text(f"SLACK = '{synthetic_slack_webhook()}'\n")
    c2 = git_commit(repo, "Root 2 with secret")

    # Merge unrelated histories
    subprocess.run(["git", "checkout", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "merge", "orphan-root", "--allow-unrelated-histories", "-m", "Merge orphan root"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert len(result.findings) == 1
    assert result.findings[0].commit_sha == c2


def test_scenario_duplicate_blobs_across_commits(tmp_path: Path):
    """Scenario 9: Exact same blob copied to different files or touched across commits (deduplication & cache hit)."""
    repo = make_git_repo(tmp_path)

    secret_content = f"TOKEN = '{synthetic_github_token()}'\n"
    (repo / "auth1.py").write_text(secret_content)
    git_commit(repo, "Add auth1")

    # Re-use identical content in auth2.py
    (repo / "auth2.py").write_text(secret_content)
    git_commit(repo, "Copy to auth2")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    # Auth1 reported for commit 1, Auth2 reported for commit 2
    assert len(result.findings) == 2
    paths = {f.file_path for f in result.findings}
    assert paths == {"auth1.py", "auth2.py"}
    assert result.summary.blobs_cached >= 1


def test_scenario_clean_repository(tmp_path: Path):
    """Scenario 10: Completely clean Git repository produces 0 findings and exit code 0."""
    repo = make_git_repo(tmp_path)

    for i in range(5):
        (repo / f"file_{i}.py").write_text(f"def foo_{i}():\n    return {i}\n")
        git_commit(repo, f"Commit {i}")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert len(result.findings) == 0
    assert result.summary.commits_scanned == 5
    assert result.summary.total_findings == 0


def test_scenario_non_git_directory(tmp_path: Path, cli_runner: CliRunner):
    """Scenario 11: Non-git directory fails gracefully with exit code 2."""
    not_git = tmp_path / "not_a_git_repo"
    not_git.mkdir()
    (not_git / "file.txt").write_text("hello\n")

    res = cli_runner.invoke(app, ["history", "scan", str(not_git)])
    assert res.exit_code == EXIT_USAGE_ERROR
    assert "Target path is not a valid Git repository" in res.output


def test_scenario_blob_size_limit(tmp_path: Path, cli_runner: CliRunner):
    """Scenario 13: Blob exceeding max size is skipped without error."""
    repo = make_git_repo(tmp_path)

    # 1. Oversized file (200 KB) with secret
    large_secret_file = repo / "large.py"
    large_secret_file.write_text("A" * (200 * 1024) + f"\nKEY = '{synthetic_aws_key()}'\n")
    git_commit(repo, "Add large file")

    # 2. Normal file with secret
    (repo / "small.py").write_text(f"KEY = '{synthetic_aws_key()}'\n")
    git_commit(repo, "Add small file")

    # Set --max-blob-size 100KB: large file must be skipped, small file detected
    scanner = GitHistoryScanner(repo, max_blob_size="100KB")
    result = scanner.scan()

    assert len(result.findings) == 1
    assert result.findings[0].file_path == "small.py"


def test_scenario_excluded_paths(tmp_path: Path):
    """Scenario 14: Path exclusions match and skip files in history."""
    repo = make_git_repo(tmp_path)

    # Commit inside a test folder and vendor folder
    test_dir = repo / "tests" / "fixtures"
    test_dir.mkdir(parents=True)
    (test_dir / "vuln.py").write_text(f"KEY = '{synthetic_aws_key()}'\n")

    vendor_dir = repo / "vendor"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "lib.py").write_text(f"TOKEN = '{synthetic_github_token()}'\n")

    git_commit(repo, "Add vendor and test files")

    # Default exclusions already exclude 'vendor'
    # Add custom exclusion for 'tests/*'
    scanner = GitHistoryScanner(repo, extra_exclusions=["tests/*"])
    result = scanner.scan()

    assert len(result.findings) == 0


def test_scenario_secret_redaction(tmp_path: Path, cli_runner: CliRunner):
    """Scenario 15: Secret values NEVER appear unredacted in output or JSON."""
    repo = make_git_repo(tmp_path)

    raw_aws = synthetic_aws_key()
    (repo / "keys.py").write_text(f"AWS = '{raw_aws}'\n")
    git_commit(repo, "Commit credentials")

    # Run CLI in text mode
    res_text = cli_runner.invoke(app, ["history", "scan", str(repo)])
    assert res_text.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD
    # Verify raw secret is NEVER in output
    assert raw_aws not in res_text.output
    assert "AKIA************MPLE" in res_text.output

    # Run CLI in JSON mode
    json_path = repo / "report.json"
    res_json = cli_runner.invoke(
        app, ["history", "scan", str(repo), "--format", "json", "--output", str(json_path)]
    )
    assert res_json.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD

    report_text = json_path.read_text(encoding="utf-8")
    assert raw_aws not in report_text
    parsed = json.loads(report_text)
    assert len(parsed["findings"]) == 1
    evidence = parsed["findings"][0]["evidence"]
    assert raw_aws not in evidence
    assert "AKIA************MPLE" in evidence


def test_cli_exit_codes_and_options(tmp_path: Path, cli_runner: CliRunner):
    """Scenario 16: Verify exit codes (0 for clean, 1 for threshold breached, 2 for bad arguments)."""
    repo = make_git_repo(tmp_path)

    # 1. Clean repo -> Exit 0
    (repo / "clean.py").write_text("print('clean')\n")
    git_commit(repo, "clean commit")

    res_clean = cli_runner.invoke(app, ["history", "scan", str(repo)])
    assert res_clean.exit_code == EXIT_SUCCESS_CLEAN

    # 2. Add secret -> Exit 1
    (repo / "vuln.py").write_text(f"KEY = '{synthetic_aws_key()}'\n")
    git_commit(repo, "vuln commit")

    res_vuln = cli_runner.invoke(app, ["history", "scan", str(repo)])
    assert res_vuln.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD

    # 3. Invalid threshold -> Exit 2
    res_bad_thresh = cli_runner.invoke(
        app, ["history", "scan", str(repo), "--severity-threshold", "SUPER_CRITICAL"]
    )
    assert res_bad_thresh.exit_code == EXIT_USAGE_ERROR

    # 4. Filter with --max-depth 1 -> only newest commit inspected
    res_depth = cli_runner.invoke(
        app, ["history", "scan", str(repo), "--max-depth", "1", "--format", "json"]
    )
    assert res_depth.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD
    parsed = json.loads(res_depth.output)
    assert parsed["summary"]["commits_scanned"] == 1


# ==============================================================================
# Hardened Regression Tests (v0.3.0 Fail-Safe Audit)
# ==============================================================================


def test_validate_git_ref() -> None:
    """Verify validate_git_ref rejects option injection, empty refs, and invalid ref syntax."""
    # Valid refs
    validate_git_ref("main")
    validate_git_ref("feature/my-branch")
    validate_git_ref("v1.0.0")
    validate_git_ref("refs/heads/main")
    validate_git_ref("HEAD")
    validate_git_ref("b372ea9481948194819481948194819481948194")

    # Invalid refs
    import pytest

    for bad_ref in [
        "-v",
        "--help",
        "--upload-pack=foo",
        "",
        "   ",
        "bad ref with spaces",
        "bad..ref",
        "branch.lock",
        "branch/",
        "/leading-slash",
        "bad~ref",
        "bad^ref",
        "bad:ref",
        "bad?ref",
        "bad*ref",
        "bad[ref",
    ]:
        with pytest.raises(ValueError):
            validate_git_ref(bad_ref)


def test_git_log_command_failure_after_validation(tmp_path: Path, cli_runner: CliRunner) -> None:
    """Verify Git log command failure after repo validation sets is_complete=False and exits with code 3."""
    repo = make_git_repo(tmp_path)
    (repo / "file.txt").write_text("Hello\n")
    git_commit(repo, "Commit 1")

    # Corrupt HEAD to make git log fail
    head_file = repo / ".git" / "HEAD"
    head_file.write_text("ref: refs/heads/corrupted_nonexistent_branch\n")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert result.summary.is_complete is False
    assert len(result.errors) > 0
    assert any(
        "Git traversal failed" in e or "Failed to query repository refs" in e for e in result.errors
    )

    res = cli_runner.invoke(app, ["history", "scan", str(repo)])
    assert res.exit_code == EXIT_EXECUTION_ERROR


def test_invalid_and_missing_refs(tmp_path: Path, cli_runner: CliRunner) -> None:
    """Verify invalid refs yield usage error (exit 2) and missing refs yield execution error (exit 3)."""
    repo = make_git_repo(tmp_path)
    (repo / "clean.txt").write_text("Clean\n")
    git_commit(repo, "Clean commit")

    # 1. Option injection ref -> Exit 2
    res_bad_option = cli_runner.invoke(app, ["history", "scan", str(repo), "--ref", "-v"])
    assert res_bad_option.exit_code == EXIT_USAGE_ERROR
    assert "Git ref cannot start with '-'" in res_bad_option.output

    # 2. Syntax-invalid ref -> Exit 2
    res_bad_syntax = cli_runner.invoke(app, ["history", "scan", str(repo), "--ref", "bad..ref"])
    assert res_bad_syntax.exit_code == EXIT_USAGE_ERROR

    # 3. Missing non-existent ref -> Exit 3 with incomplete scan
    res_missing_ref = cli_runner.invoke(
        app, ["history", "scan", str(repo), "--ref", "nonexistent_branch_xyz"]
    )
    assert res_missing_ref.exit_code == EXIT_EXECUTION_ERROR


def test_corrupt_or_unavailable_objects(tmp_path: Path, cli_runner: CliRunner) -> None:
    """Verify corrupt or unavailable Git objects mark scan incomplete and exit with code 3."""
    import stat

    repo = make_git_repo(tmp_path)
    (repo / "data.txt").write_text("Important Data\n")
    git_commit(repo, "Add data")

    # Obtain blob SHA
    blob_sha = subprocess.run(
        ["git", "rev-parse", "HEAD:data.txt"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    # Corrupt the blob on disk
    obj_dir = repo / ".git" / "objects" / blob_sha[:2]
    obj_file = obj_dir / blob_sha[2:]
    assert obj_file.exists(), f"Object file {obj_file} should exist"

    # Make writable and overwrite with corrupt garbage
    obj_file.chmod(stat.S_IWRITE | stat.S_IREAD)
    obj_file.write_bytes(b"CORRUPTED_GARBAGE_DATA_1234567890")

    # Test scanner directly
    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert result.summary.is_complete is False
    assert (result.summary.blobs_skipped_corrupt + result.summary.blobs_skipped_missing) >= 1
    assert len(result.errors) > 0
    assert any("Corrupt Git object" in e or "Missing Git object" in e for e in result.errors)

    # Test CLI output and exit code
    res = cli_runner.invoke(app, ["history", "scan", str(repo)])
    assert res.exit_code == EXIT_EXECUTION_ERROR
    assert "Scan Incomplete" in res.output


def test_oversized_historical_blob_with_secret(tmp_path: Path, cli_runner: CliRunner) -> None:
    """Verify oversized blob containing a secret is skipped, marked incomplete, and exits with code 3."""
    repo = make_git_repo(tmp_path)

    # Create a 60KB file containing a synthetic secret
    secret_line = f"AWS_KEY = '{synthetic_aws_key()}'\n"
    padding = "X" * 60000 + "\n"
    (repo / "oversized.py").write_text(secret_line + padding)
    git_commit(repo, "Add oversized file with credential")

    # Scan with limit of 20KB
    scanner = GitHistoryScanner(repo, max_blob_size="20KB")
    result = scanner.scan()

    # Finding must NOT be reported because blob was not scanned
    assert len(result.findings) == 0
    # Scan must be marked incomplete
    assert result.summary.is_complete is False
    assert result.summary.blobs_skipped_oversized == 1
    assert result.summary.files_skipped >= 1
    assert any("Skipped oversized blob" in e for e in result.errors)

    # CLI must NOT report clean (code 0); must exit 3 (execution error)
    res = cli_runner.invoke(app, ["history", "scan", str(repo), "--max-blob-size", "20KB"])
    assert res.exit_code == EXIT_EXECUTION_ERROR
    assert "Scan Incomplete" in res.output
    assert "oversized" in res.output.lower()


def test_normal_binary_file_handling(tmp_path: Path, cli_runner: CliRunner) -> None:
    """Verify normal binary files are intentionally skipped without marking scan incomplete."""
    repo = make_git_repo(tmp_path)
    (repo / "logo.png").write_bytes(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    )
    (repo / "code.py").write_text("print('clean code')\n")
    git_commit(repo, "Add logo and clean code")

    scanner = GitHistoryScanner(repo)
    result = scanner.scan()

    assert len(result.findings) == 0
    assert result.summary.blobs_skipped_binary == 1
    assert result.summary.is_complete is True
    assert len(result.errors) == 0

    res = cli_runner.invoke(app, ["history", "scan", str(repo)])
    assert res.exit_code == EXIT_SUCCESS_CLEAN
    assert "Scan Clean" in res.output


def test_interrupted_traversal_and_timeout(tmp_path: Path) -> None:
    """Verify interrupted traversal due to timeout sets is_complete=False and records diagnostic message."""
    repo = make_git_repo(tmp_path)
    for i in range(5):
        (repo / f"file_{i}.txt").write_text(f"content {i}\n")
        git_commit(repo, f"commit {i}")

    # Set very small timeout
    scanner = GitHistoryScanner(repo, timeout_seconds=0.000001)
    result = scanner.scan()

    assert result.summary.is_complete is False
    assert any("timeout" in e.lower() for e in result.errors)


def test_explicit_depth_and_time_filters(tmp_path: Path, cli_runner: CliRunner) -> None:
    """Verify explicit depth and time filters define scan scope and disclose it in reports."""
    repo = make_git_repo(tmp_path)
    (repo / "f1.txt").write_text("v1\n")
    git_commit(repo, "commit 1")
    (repo / "f2.txt").write_text("v2\n")
    git_commit(repo, "commit 2")
    (repo / "f3.txt").write_text("v3\n")
    git_commit(repo, "commit 3")

    # Scan with max-depth 1
    scanner = GitHistoryScanner(repo, max_depth=1)
    result = scanner.scan()

    assert result.summary.commits_scanned == 1
    assert result.summary.scan_scope["max_depth"] == 1
    assert result.summary.scan_scope["full_history"] is False
    assert result.summary.is_complete is True
    assert any(
        "History scan scope was limited to 1 commit(s)" in c
        for c in result.summary.checks_not_performed
    )

    res_cli = cli_runner.invoke(app, ["history", "scan", str(repo), "--max-depth", "1"])
    assert res_cli.exit_code == EXIT_SUCCESS_CLEAN
    assert "Partial history" in res_cli.output

    # Scan with since
    scanner_since = GitHistoryScanner(repo, since="2026-01-01")
    res_since = scanner_since.scan()
    assert res_since.summary.scan_scope["since"] == "2026-01-01"
    assert any(
        "History scan scope was limited to commits since" in c
        for c in res_since.summary.checks_not_performed
    )


def test_zero_findings_with_incomplete_coverage(tmp_path: Path, cli_runner: CliRunner) -> None:
    """Verify a scan with zero findings but incomplete coverage exits 3 and displays Scan Incomplete."""
    repo = make_git_repo(tmp_path)
    (repo / "big_clean.txt").write_text("Hello Clean " * 5000)
    git_commit(repo, "Add big clean file")

    res = cli_runner.invoke(app, ["history", "scan", str(repo), "--max-blob-size", "5KB"])
    assert res.exit_code == EXIT_EXECUTION_ERROR
    assert "Scan Incomplete" in res.output
    assert "Scan Clean" not in res.output


def test_no_raw_credentials_in_diagnostics_or_reports(
    tmp_path: Path, cli_runner: CliRunner
) -> None:
    """Verify credentials never appear raw in diagnostic messages, JSON, or step summary."""
    repo = make_git_repo(tmp_path)
    raw_key = synthetic_aws_key()
    raw_tok = synthetic_github_token()
    (repo / "creds.py").write_text(f"AWS = '{raw_key}'\nGH = '{raw_tok}'\n")
    git_commit(repo, "Add credentials")

    json_path = repo / "out.json"
    res = cli_runner.invoke(
        app,
        ["history", "scan", str(repo), "--format", "json", "--output", str(json_path)],
    )
    assert res.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD

    # Terminal output
    res_term = cli_runner.invoke(app, ["history", "scan", str(repo)])
    assert raw_key not in res_term.output
    assert raw_tok not in res_term.output

    # JSON report
    report_content = json_path.read_text(encoding="utf-8")
    assert raw_key not in report_content
    assert raw_tok not in report_content
