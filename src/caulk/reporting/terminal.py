"""Rich terminal output for Caulk security scan results.

Presents findings in an approachable format for developers, answering:
1. What is wrong?
2. Where is the problem?
3. Why does it matter?
4. What should the developer do to fix it?
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from caulk.models import Finding, ScanResult, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "bold blue",
}


def render_terminal_report(result: ScanResult, console: Console | None = None) -> None:
    """Render a comprehensive scan report to the Rich terminal."""
    con = console or Console()

    # Header
    con.print()
    con.print(
        Panel(
            Text.assemble(
                ("CAULK ", "bold cyan"),
                (f"v{result.caulk_version} ", "dim"),
                ("— Deterministic Security Scanner\n", "bold white"),
                ("Scanning target: ", "dim"),
                (result.target_path, "yellow"),
            ),
            border_style="cyan",
            expand=False,
        )
    )

    # Discovered ecosystems & summary metadata
    if result.summary.scan_mode == "git_history":
        con.print(
            f"[dim]Commits inspected:[/dim] [bold]{result.summary.commits_scanned}[/bold]  "
            f"[dim]Blobs inspected:[/dim] [bold]{result.summary.blobs_scanned}[/bold]  "
            f"[dim]Blobs cached:[/dim] [bold]{result.summary.blobs_cached}[/bold]  "
            f"[dim]Duration:[/dim] [bold]{result.summary.duration_seconds}s[/bold]"
        )
        if result.summary.files_skipped > 0:
            con.print(
                f"[dim]Blobs skipped:[/dim] [bold]{result.summary.files_skipped}[/bold] "
                f"({result.summary.blobs_skipped_binary} binary, {result.summary.blobs_skipped_oversized} oversized)"
            )
        if result.summary.scan_scope:
            if result.summary.scan_scope.get("full_history") is False:
                scope_parts = []
                if result.summary.scan_scope.get("is_shallow"):
                    scope_parts.append("shallow clone")
                if result.summary.scan_scope.get("max_depth"):
                    scope_parts.append(f"max-depth: {result.summary.scan_scope['max_depth']}")
                if result.summary.scan_scope.get("since"):
                    scope_parts.append(f"since: {result.summary.scan_scope['since']}")
                if result.summary.scan_scope.get("ref"):
                    scope_parts.append(f"ref: {result.summary.scan_scope['ref']}")
                con.print(
                    f"[dim]Scan scope:[/dim] [yellow]Partial history ({', '.join(scope_parts)})[/yellow]"
                )
            else:
                con.print("[dim]Scan scope:[/dim] [green]All reachable history[/green]")
        if result.summary.refs_scanned:
            refs_str = ", ".join(result.summary.refs_scanned)
            con.print(f"[dim]Refs inspected:[/dim] [bold cyan]{refs_str}[/bold cyan]")
    else:
        ecosystems_str = ", ".join(result.summary.ecosystems_detected) or "generic"
        con.print(
            f"[dim]Files inspected:[/dim] [bold]{result.summary.files_scanned}[/bold]  "
            f"[dim]Files skipped:[/dim] [bold]{result.summary.files_skipped}[/bold]  "
            f"[dim]Ecosystems:[/dim] [bold cyan]{ecosystems_str}[/bold cyan]  "
            f"[dim]Duration:[/dim] [bold]{result.summary.duration_seconds}s[/bold]"
        )
    con.print()

    # Findings
    if not result.findings:
        if not result.summary.is_complete:
            con.print(
                Panel(
                    Text(
                        "No security issues detected in the inspected portion of the repository, but the scan was INCOMPLETE.\n\n"
                        "Coverage gaps, skipped oversized objects, or execution errors prevented complete inspection. "
                        "This repository cannot be considered clean.",
                        style="yellow",
                    ),
                    title="[bold yellow]Scan Incomplete[/bold yellow]",
                    border_style="yellow",
                )
            )
        else:
            con.print(
                Panel(
                    Text(
                        "No security issues detected by the active deterministic rules.\n\n"
                        "Note: A clean scan does not prove an application is secure. "
                        "Caulk inspects known static patterns and manifests, but cannot verify dynamic runtime behavior.",
                        style="green",
                    ),
                    title="[bold green]Scan Clean[/bold green]",
                    border_style="green",
                )
            )
    else:
        con.print(f"[bold]Findings ({len(result.findings)}):[/bold]")
        con.print()

        for idx, finding in enumerate(result.findings, start=1):
            _render_finding_card(con, idx, finding)

    # Summary table
    _render_summary_table(con, result)

    # Informational notes on checks not performed
    if result.summary.checks_not_performed:
        con.print()
        for note in result.summary.checks_not_performed:
            con.print(f"[dim]• {note}[/dim]")

    if result.errors:
        con.print()
        con.print("[bold red]Scan Warnings / Non-fatal Errors:[/bold red]")
        for err in result.errors:
            con.print(f"  [red]! {err}[/red]")

    con.print()


def _render_finding_card(con: Console, index: int, finding: Finding) -> None:
    """Render an individual finding card structured around beginner-friendly questions."""
    sev_style = SEVERITY_STYLES.get(finding.severity, "bold white")

    # Header with Severity, Category, and Rule ID
    title_text = Text()
    title_text.append(f" {finding.severity.value} ", style=sev_style)
    if finding.is_historical:
        title_text.append(" [HISTORICAL] ", style="bold magenta")
    else:
        title_text.append(f" [{finding.category.value}] ", style="bold white")
    title_text.append(f"{finding.title} ", style="bold white")
    title_text.append(f"({finding.rule_id})", style="dim")

    location = finding.file_path
    if finding.line_number:
        location = f"{finding.file_path}:{finding.line_number}"

    body_text = Text()

    # 1. Where
    body_text.append("Where: ", style="bold cyan")
    body_text.append(f"{location}\n", style="yellow")

    # Commit metadata for historical findings
    if finding.commit_sha:
        body_text.append("Commit: ", style="bold cyan")
        short_sha = finding.commit_sha[:8]
        body_text.append(f"{short_sha} ({finding.commit_sha})\n", style="yellow")
        if finding.commit_author:
            body_text.append("Author: ", style="bold cyan")
            body_text.append(f"{finding.commit_author}\n", style="white")
        if finding.commit_timestamp:
            body_text.append("Date:   ", style="bold cyan")
            body_text.append(f"{finding.commit_timestamp}\n", style="white")
        if finding.commit_subject:
            body_text.append("Subject:", style="bold cyan")
            body_text.append(f" {finding.commit_subject}\n", style="dim white")
        body_text.append("\n")

    # Confidence
    body_text.append("Confidence: ", style="bold cyan")
    body_text.append(f"{finding.confidence.value}\n\n", style="italic")

    # 2. What
    body_text.append("What was found:\n", style="bold cyan")
    body_text.append(f"{finding.description}\n\n", style="white")

    # Evidence
    if finding.evidence:
        body_text.append("Evidence:\n", style="bold cyan")
        for line in finding.evidence.splitlines():
            body_text.append(f"  {line}\n", style="dim red")
        body_text.append("\n")

    # 3. Why
    body_text.append("Why it matters:\n", style="bold cyan")
    body_text.append(f"{finding.impact}\n\n", style="white")

    # 4. Remediation
    body_text.append("What to do:\n", style="bold green")
    body_text.append(f"{finding.remediation}\n", style="green")

    # References
    if finding.references:
        body_text.append("\nReferences:\n", style="bold dim")
        for ref in finding.references:
            body_text.append(f"  • {ref}\n", style="dim blue underline")

    con.print(
        Panel(
            body_text,
            title=title_text,
            title_align="left",
            border_style=sev_style.split()[-1] if "on" not in sev_style else "red",
            expand=True,
        )
    )
    con.print()


def _render_summary_table(con: Console, result: ScanResult) -> None:
    """Render table of severity counts."""
    table = Table(title="Finding Severity Summary", show_header=True, header_style="bold")
    table.add_column("Severity Level", style="bold")
    table.add_column("Count", justify="right")

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = result.summary.severity_counts.get(sev.value, 0)
        style = SEVERITY_STYLES.get(sev, "white")
        table.add_row(f"[{style}]{sev.value}[/{style}]", str(count))

    con.print(table)
