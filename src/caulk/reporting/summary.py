"""Markdown summary generation for GitHub Step Summary and CI reporting.

Produces clean, deterministic, redacted Markdown reports from Caulk scan results.
"""

from __future__ import annotations

from typing import Any

from caulk.models import Severity


def generate_step_summary(
    report_data: dict[str, Any],
    threshold: Severity = Severity.HIGH,
) -> str:
    """Generate a readable GitHub Step Summary in Markdown from scan report data.

    Evidence is intentionally excluded or redacted from the summary to prevent
    sensitive credentials or internal source fragments from persisting in CI artifacts.
    """
    caulk_version = report_data.get("caulk_version", "unknown")
    target_path = report_data.get("target_path", ".")
    summary = report_data.get("summary", {})
    files_scanned = summary.get("files_scanned", 0)
    files_skipped = summary.get("files_skipped", 0)
    duration_seconds = summary.get("duration_seconds", 0.0)
    total_findings = summary.get("total_findings", 0)
    sev_counts = summary.get("severity_counts", {})
    checks_not_performed = summary.get("checks_not_performed", [])

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

    lines: list[str] = [
        "## Caulk Security Scan Report",
        "",
        f"> **Deterministic Security Inspection** — Caulk `v{caulk_version}`  ",
        f"> **Target:** `{target_path}` | **Inspected:** {files_scanned} files | "
        f"**Skipped:** {files_skipped} files | **Duration:** {duration_seconds}s",
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
            rule_id = f.get("rule_id", "UNKNOWN")
            sev = f.get("severity", "INFO")
            cat = f.get("category", "UNKNOWN")
            file_path = f.get("file_path", "")
            line_no = f.get("line_number")
            loc = f"`{file_path}:{line_no}`" if line_no is not None else f"`{file_path}`"
            title = f.get("title", "")
            lines.append(f"| `{rule_id}` | **{sev}** | {cat} | {loc} | {title} |")
        lines.append("")

        if below:
            lines.extend(
                [
                    f"*{len(below)} additional finding(s) detected below the {threshold.value} threshold.*",
                    "",
                ]
            )

        lines.extend(
            [
                "> [!NOTE]",
                "> To protect sensitive credentials, code snippets and raw evidence are omitted from this summary. "
                "Inspect findings and targeted remediation locally by running:",
                "> ```bash",
                f"> caulk-security scan {target_path}",
                "> ```",
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
    if checks_not_performed:
        lines.append("#### Advisory Notice")
        for check in checks_not_performed:
            lines.append(f"- {check}")
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
    lines = [
        f"## ⚠️ Caulk Security Scan — {error_type}",
        "",
        f"The security scanner failed to execute successfully (Exit Code {error_code}).",
        "",
        "### Error Details",
        "```",
        error_message.strip(),
        "```",
        "",
        "---",
        "> [!CAUTION]",
        "> **Notice:** Scanner execution errors indicate that the scan could not be completed. "
        "This run should NOT be interpreted as clean or passing.",
    ]
    return "\n".join(lines)
