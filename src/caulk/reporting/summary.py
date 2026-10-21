"""Markdown summary generation for GitHub Step Summary and CI reporting.

Produces clean, deterministic, redacted Markdown reports from Caulk scan results,
hardened against Markdown injection and forged CI output.
"""

from __future__ import annotations

import re
from typing import Any

from caulk.models import Severity

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NEWLINE_RE = re.compile(r"\r\n|[\r\n]")
_WHITESPACE_RUN_RE = re.compile(r"[ \t]+")
_BACKTICK_RUN_RE = re.compile(r"`+")


def sanitize_single_line_text(text: str) -> str:
    """Sanitize single-line untrusted text by stripping newlines and control characters."""
    cleaned = _NEWLINE_RE.sub(" ", text)
    cleaned = _CONTROL_CHAR_RE.sub("", cleaned)
    cleaned = _WHITESPACE_RUN_RE.sub(" ", cleaned)
    return cleaned.strip()


def escape_markdown_table_cell(text: str) -> str:
    """Escape untrusted text for safe inclusion in a GitHub Flavored Markdown table cell.

    Prevents:
    - Table column splitting via unescaped pipes (|).
    - Table row breakout and section injection via newlines.
    - Active HTML element injection via < and >.
    - Active Markdown hyperlinks and image embeds via [ and ].
    - Accidental markdown emphasis or formatting via *, _, ~, and `.
    """
    single_line = sanitize_single_line_text(text)
    if not single_line:
        return ""

    # 1. Escape backslashes first
    escaped = single_line.replace("\\", "\\\\")

    # 2. Escape table delimiter pipe
    escaped = escaped.replace("|", "\\|")

    # 3. Escape HTML entities to prevent raw HTML execution
    escaped = escaped.replace("&", "&amp;")
    escaped = escaped.replace("<", "&lt;")
    escaped = escaped.replace(">", "&gt;")

    # 4. Escape Markdown link, image, and emphasis control characters
    escaped = escaped.replace("[", "\\[")
    escaped = escaped.replace("]", "\\]")
    escaped = escaped.replace("*", "\\*")
    escaped = escaped.replace("_", "\\_")
    escaped = escaped.replace("~", "\\~")
    escaped = escaped.replace("`", "\\`")

    return escaped


def format_markdown_code_span(text: str) -> str:
    """Format untrusted text into a safe CommonMark inline code span.

    Calculates dynamic backtick delimiters to prevent backticks inside
    the text from prematurely terminating the code span.
    """
    single_line = sanitize_single_line_text(text)
    if not single_line:
        return "``"

    runs = _BACKTICK_RUN_RE.findall(single_line)
    max_run = max((len(r) for r in runs), default=0)

    if max_run == 0:
        return f"`{single_line}`"

    delim_len = max_run + 1
    delim = "`" * delim_len
    return f"{delim} {single_line} {delim}"


def format_table_code_cell(text: str) -> str:
    """Format an inline code span inside a GFM table cell safely.

    In GFM, pipes (|) inside code spans will split table columns unless
    preceded by a backslash. Backticks are handled dynamically.
    """
    single_line = sanitize_single_line_text(text)
    if not single_line:
        return "``"

    # In GFM tables, pipe must be escaped as \| even inside code spans
    escaped_pipe = single_line.replace("|", "\\|")

    runs = _BACKTICK_RUN_RE.findall(escaped_pipe)
    max_run = max((len(r) for r in runs), default=0)

    if max_run == 0:
        return f"`{escaped_pipe}`"

    delim_len = max_run + 1
    delim = "`" * delim_len
    return f"{delim} {escaped_pipe} {delim}"


def format_markdown_fenced_code(content: str, info_string: str = "") -> str:
    """Format content safely inside a Markdown fenced code block.

    Calculates dynamic fence delimiter length to prevent any backtick sequence
    inside content from prematurely terminating the code block.
    """
    clean = _NEWLINE_RE.sub("\n", content).strip("\n")
    runs = _BACKTICK_RUN_RE.findall(clean)
    max_run = max((len(r) for r in runs), default=0)
    fence_len = max(3, max_run + 1)
    fence = "`" * fence_len
    info = sanitize_single_line_text(info_string)
    return f"{fence}{info}\n{clean}\n{fence}"


def generate_step_summary(
    report_data: dict[str, Any],
    threshold: Severity = Severity.HIGH,
) -> str:
    """Generate a readable GitHub Step Summary in Markdown from scan report data.

    Evidence is intentionally excluded or redacted from the summary to prevent
    sensitive credentials or internal source fragments from persisting in CI artifacts.
    All dynamic strings derived from target repositories are safely escaped.
    """
    raw_caulk_version = str(report_data.get("caulk_version", "unknown"))
    caulk_version = sanitize_single_line_text(raw_caulk_version)

    raw_target_path = str(report_data.get("target_path", "."))
    target_path = sanitize_single_line_text(raw_target_path)
    target_code = format_markdown_code_span(target_path)

    summary = report_data.get("summary", {})
    try:
        files_scanned = int(summary.get("files_scanned", 0))
    except (ValueError, TypeError):
        files_scanned = 0
    try:
        files_skipped = int(summary.get("files_skipped", 0))
    except (ValueError, TypeError):
        files_skipped = 0
    try:
        duration_seconds = float(summary.get("duration_seconds", 0.0))
    except (ValueError, TypeError):
        duration_seconds = 0.0
    try:
        total_findings = int(summary.get("total_findings", 0))
    except (ValueError, TypeError):
        total_findings = 0

    sev_counts = summary.get("severity_counts", {})
    raw_checks_not_performed = summary.get("checks_not_performed", [])
    scan_mode = str(summary.get("scan_mode", "working_tree"))
    commits_scanned = summary.get("commits_scanned", 0)
    blobs_scanned = summary.get("blobs_scanned", 0)
    blobs_skipped_oversized = summary.get("blobs_skipped_oversized", 0)
    blobs_skipped_binary = summary.get("blobs_skipped_binary", 0)
    scan_scope = summary.get("scan_scope", {})
    is_complete = bool(summary.get("is_complete", True))
    errors: list[str] = report_data.get("errors", [])

    raw_findings: list[dict[str, Any]] = report_data.get("findings", [])

    # Filter findings breaching threshold
    breached: list[dict[str, Any]] = []
    below: list[dict[str, Any]] = []

    for f in raw_findings:
        try:
            f_sev = Severity.from_string(str(f.get("severity", "INFO")))
            if f_sev >= threshold:
                breached.append(f)
            else:
                below.append(f)
        except ValueError:
            below.append(f)

    is_failed = len(breached) > 0

    if scan_mode == "git_history":
        inspected_parts = [f"**Inspected:** {commits_scanned} commits, {blobs_scanned} blobs"]
        if files_skipped > 0:
            inspected_parts.append(
                f"**Skipped:** {files_skipped} blobs ({blobs_skipped_oversized} oversized, {blobs_skipped_binary} binary)"
            )
        if scan_scope and scan_scope.get("full_history") is False:
            if scan_scope.get("is_shallow"):
                inspected_parts.append("**Scope:** Partial history (shallow clone)")
            else:
                inspected_parts.append("**Scope:** Partial history")
        else:
            inspected_parts.append("**Scope:** Full reachable history")
        inspected_str = " | ".join(inspected_parts)
    else:
        inspected_str = f"**Inspected:** {files_scanned} files | **Skipped:** {files_skipped} files"

    lines: list[str] = [
        "## Caulk Security Scan Report",
        "",
        f"> **Deterministic Security Inspection** — Caulk `v{caulk_version}`  ",
        f"> **Target:** {target_code} | {inspected_str} | **Duration:** {duration_seconds}s",
        "",
    ]

    # Overall Status Conclusion
    if is_failed:
        lines.extend(
            [
                f"### Scan Result: ❌ Failed (Threshold: {threshold.value})",
                "",
                f"Found **{len(breached)}** finding(s) that meet or breach the **{threshold.value}** severity threshold.",
                "",
            ]
        )
        if not is_complete:
            lines.extend(
                [
                    "> [!WARNING]",
                    "> The scan was also **incomplete** due to coverage gaps or errors. Additional findings may exist.",
                    "",
                ]
            )
    elif not is_complete:
        lines.extend(
            [
                f"### Scan Result: ⚠️ Incomplete Inspection (Threshold: {threshold.value})",
                "",
                "The scan encountered coverage gaps, skipped oversized objects, or execution errors. "
                "The inspection is **incomplete** and cannot be considered clean.",
                "",
            ]
        )
    else:
        status_note = (
            f"No findings met or breached the **{threshold.value}** severity threshold."
            if total_findings == 0
            else f"No findings breached the **{threshold.value}** threshold ({total_findings} finding(s) below threshold)."
        )
        lines.extend(
            [
                f"### Scan Result: ✅ Passed (Threshold: {threshold.value})",
                "",
                status_note,
                "",
            ]
        )

    # Severity Breakdown Table
    lines.extend(
        [
            "#### Severity Breakdown",
            "",
            "| Severity | Findings Count |",
            "| :--- | :--- |",
            f"| **CRITICAL** | {sev_counts.get('CRITICAL', 0)} |",
            f"| **HIGH** | {sev_counts.get('HIGH', 0)} |",
            f"| **MEDIUM** | {sev_counts.get('MEDIUM', 0)} |",
            f"| **LOW** | {sev_counts.get('LOW', 0)} |",
            f"| **INFO** | {sev_counts.get('INFO', 0)} |",
            f"| **Total** | **{total_findings}** |",
            "",
        ]
    )

    # Breached Findings Table (if any)
    if breached:
        lines.extend(
            [
                f"#### Breached Findings ({threshold.value} or Higher)",
                "",
                "| Rule ID | Severity | Category | Location | Title |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for f in breached:
            rule_id_str = str(f.get("rule_id", "UNKNOWN"))
            sev_raw = str(f.get("severity", "INFO"))
            try:
                sev_str = Severity.from_string(sev_raw).value
            except ValueError:
                sev_str = "INFO"
            cat_str = str(f.get("category", "UNKNOWN"))
            file_path = str(f.get("file_path", ""))
            line_no = f.get("line_number")
            commit_sha = f.get("commit_sha")
            if commit_sha:
                short_sha = str(commit_sha)[:8]
                loc_str = (
                    f"{file_path}:{line_no} ({short_sha})"
                    if line_no is not None
                    else f"{file_path} ({short_sha})"
                )
            else:
                loc_str = f"{file_path}:{line_no}" if line_no is not None else file_path
            title_str = str(f.get("title", ""))

            safe_rule = format_table_code_cell(rule_id_str)
            safe_cat = escape_markdown_table_cell(cat_str)
            safe_loc = format_table_code_cell(loc_str)
            safe_title = escape_markdown_table_cell(title_str)

            lines.append(
                f"| {safe_rule} | **{sev_str}** | {safe_cat} | {safe_loc} | {safe_title} |"
            )
        lines.append("")

        if below:
            lines.extend(
                [
                    f"*{len(below)} additional finding(s) detected below the {threshold.value} threshold.*",
                    "",
                ]
            )

        # Local remediation command inside fenced block
        escaped_cmd_path = target_path.replace('"', '\\"')
        cmd_target_arg = f'"{escaped_cmd_path}"' if " " in target_path else target_path
        if scan_mode == "git_history":
            remediation_cmd = f"caulk-security history scan {cmd_target_arg}"
        else:
            remediation_cmd = f"caulk-security scan {cmd_target_arg}"

        runs = _BACKTICK_RUN_RE.findall(remediation_cmd)
        cmd_fence_len = max(3, max((len(r) for r in runs), default=0) + 1)
        cmd_fence = "`" * cmd_fence_len

        lines.extend(
            [
                "> [!NOTE]",
                "> To protect sensitive credentials, code snippets and raw evidence are omitted from this summary. "
                "Inspect findings and targeted remediation locally by running:",
                f"> {cmd_fence}bash",
                f"> {remediation_cmd}",
                f"> {cmd_fence}",
                "",
            ]
        )
    elif below:
        lines.extend(
            [
                f"*{len(below)} finding(s) detected below the {threshold.value} failure threshold.*",
                "",
            ]
        )

    # Document skipped / unperformed checks if any
    if raw_checks_not_performed:
        lines.append("#### Advisory Notice")
        for check in raw_checks_not_performed:
            safe_check = escape_markdown_table_cell(str(check))
            lines.append(f"- {safe_check}")
        lines.append("")

    # Scan errors / coverage warnings if any
    if errors:
        lines.append("#### Scan Warnings & Diagnostic Notices")
        for err in errors:
            safe_err = escape_markdown_table_cell(str(err))
            lines.append(f"- ⚠️ {safe_err}")
        lines.append("")

    # Security Disclaimer
    lines.extend(
        [
            "---",
            "> [!CAUTION]",
            "> **Security Disclaimer:** A clean scan indicates that no issues matched Caulk's active deterministic rules. "
            "A clean scan does not guarantee an application is free from security vulnerabilities or supply-chain defects.",
        ]
    )

    return "\n".join(lines)


def generate_error_summary(error_message: str, error_code: int = 3) -> str:
    """Generate an error summary for workflow reporting when the scan cannot execute."""
    error_type = "Usage / Configuration Error" if error_code == 2 else "Scanner Execution Error"
    fenced_error = format_markdown_fenced_code(error_message)
    lines = [
        f"## ⚠️ Caulk Security Scan — {error_type}",
        "",
        f"The security scanner failed to execute successfully (Exit Code {error_code}).",
        "",
        "### Error Details",
        fenced_error,
        "",
        "---",
        "> [!CAUTION]",
        "> **Notice:** Scanner execution errors indicate that the scan could not be completed. "
        "This run should NOT be interpreted as clean or passing.",
    ]
    return "\n".join(lines)
