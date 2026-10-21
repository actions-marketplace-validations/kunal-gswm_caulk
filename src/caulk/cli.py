"""Command-line interface for Caulk.

Deterministic exit codes:
  0: Scan succeeded, no findings breach the configured failure threshold.
  1: Scan succeeded, findings breach the configured failure threshold.
  2: Invalid CLI usage, bad arguments, or invalid configuration file.
  3: Scan execution error (e.g. unreadable directory or unhandled runtime failure).
"""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from caulk import __version__
from caulk.config import CaulkConfig, write_default_config
from caulk.models import FindingCategory, Severity
from caulk.reporting.json_report import generate_json_report, write_json_report
from caulk.reporting.terminal import render_terminal_report
from caulk.rules import registry
from caulk.scanner import CaulkScanner

# Standard Exit Codes
EXIT_SUCCESS_CLEAN = 0
EXIT_FINDINGS_BREACH_THRESHOLD = 1
EXIT_USAGE_ERROR = 2
EXIT_EXECUTION_ERROR = 3

app = typer.Typer(
    name="caulk-security",
    help="Deterministic, open-source security checker for repository code and dependencies.",
    no_args_is_help=True,
    add_completion=False,
)

rules_app = typer.Typer(
    name="rules",
    help="Inspect and list Caulk's built-in deterministic rules.",
    no_args_is_help=True,
)
app.add_typer(rules_app, name="rules")

console = Console()
err_console = Console(stderr=True)


class OutputFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


def version_callback(value: bool) -> None:
    if value:
        console.print(f"caulk-security v{__version__}")
        raise typer.Exit(code=EXIT_SUCCESS_CLEAN)


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Caulk deterministic application security checker."""
    pass


@app.command(name="scan")
def scan_command(
    target: Annotated[
        Path,
        typer.Argument(
            help="Path to repository or project directory to scan.",
            exists=False,  # Checked explicitly for clean error handling
        ),
    ] = Path("."),
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output report format (text or json).",
        ),
    ] = OutputFormat.TEXT,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Path to write the report file (e.g. caulk-report.json).",
        ),
    ] = None,
    threshold: Annotated[
        str | None,
        typer.Option(
            "--severity-threshold",
            "-t",
            help="Severity threshold to trigger non-zero exit code (CRITICAL, HIGH, MEDIUM, LOW, INFO).",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to .caulk.toml configuration file.",
        ),
    ] = None,
    check_vulns: Annotated[
        bool,
        typer.Option(
            "--check-vulns",
            help="Enable outbound network query to OSV database for dependency vulnerabilities.",
        ),
    ] = False,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Force strictly offline scan (overrides any configuration enabling network).",
        ),
    ] = False,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-e",
            help="Additional glob patterns or directory names to exclude.",
        ),
    ] = None,
) -> None:
    """Scan a project directory for security vulnerabilities and misconfigurations."""
    # 1. Validate target directory
    target_resolved = target.resolve()
    if not target_resolved.exists():
        err_console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}")
        raise typer.Exit(code=EXIT_USAGE_ERROR)
    if not target_resolved.is_dir():
        err_console.print(f"[bold red]Error:[/bold red] Target path is not a directory: {target}")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    # 2. Load configuration
    try:
        caulk_config = CaulkConfig.load(config_path=config, base_dir=target_resolved)
    except Exception as err:
        err_console.print(f"[bold red]Configuration Error:[/bold red] {err}")
        raise typer.Exit(code=EXIT_USAGE_ERROR) from err

    # 3. Apply CLI overrides
    if threshold:
        try:
            caulk_config.fail_threshold = Severity.from_string(threshold)
        except ValueError as err:
            err_console.print(f"[bold red]Error:[/bold red] {err}")
            raise typer.Exit(code=EXIT_USAGE_ERROR) from err

    if check_vulns and not offline:
        caulk_config.enable_advisories = True
    elif offline:
        caulk_config.enable_advisories = False

    if exclude:
        caulk_config.exclude_patterns.extend(exclude)

    # 4. Execute scan
    try:
        scanner = CaulkScanner(config=caulk_config)
        result = scanner.scan(target_resolved)
    except Exception as err:
        err_console.print(f"[bold red]Scanner Execution Error:[/bold red] {err}")
        raise typer.Exit(code=EXIT_EXECUTION_ERROR) from err

    # 5. Output reporting
    if format == OutputFormat.JSON:
        json_str = generate_json_report(result)
        if output:
            try:
                write_json_report(result, output)
            except Exception as err:
                err_console.print(f"[bold red]Error writing output file:[/bold red] {err}")
                raise typer.Exit(code=EXIT_EXECUTION_ERROR) from err
        else:
            sys.stdout.write(json_str + "\n")
            sys.stdout.flush()
    else:
        render_terminal_report(result, console=console)
        if output:
            try:
                write_json_report(result, output)
                console.print(f"[green]Report saved to:[/green] {output}")
            except Exception as err:
                err_console.print(f"[bold red]Error writing output file:[/bold red] {err}")
                raise typer.Exit(code=EXIT_EXECUTION_ERROR) from err

    # 6. Exit code logic
    breach = result.has_findings_above(caulk_config.fail_threshold)
    if breach:
        raise typer.Exit(code=EXIT_FINDINGS_BREACH_THRESHOLD)

    raise typer.Exit(code=EXIT_SUCCESS_CLEAN)


@rules_app.command(name="list")
def list_rules_command(
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output report format (text or json).",
        ),
    ] = OutputFormat.TEXT,
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help="Filter rules by category (SECRET, CONFIGURATION, DEPENDENCY, SAST).",
        ),
    ] = None,
) -> None:
    """List all available deterministic security rules."""
    cat_filter: list[FindingCategory] | None = None
    if category:
        try:
            cat_filter = [FindingCategory.from_string(category)]
        except ValueError as err:
            err_console.print(f"[bold red]Error:[/bold red] {err}")
            raise typer.Exit(code=EXIT_USAGE_ERROR) from err

    rules = registry.filter_rules(categories=cat_filter)

    if format == OutputFormat.JSON:
        import json

        data = [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "description": r.description,
                "severity": r.severity.value,
                "confidence": r.confidence.value,
                "category": r.category.value,
                "file_patterns": r.file_patterns,
                "references": r.references,
            }
            for r in rules
        ]
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        sys.stdout.flush()
        return

    table = Table(title=f"Caulk Security Rules ({len(rules)} active)", show_header=True)
    table.add_column("Rule ID", style="bold cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Severity", style="bold")
    table.add_column("Confidence", style="italic")
    table.add_column("Title", style="white")

    for r in rules:
        table.add_row(
            r.rule_id,
            r.category.value,
            r.severity.value,
            r.confidence.value,
            r.title,
        )

    console.print(table)


@app.command(name="init")
def init_command(
    target: Annotated[
        Path,
        typer.Option(
            "--path",
            "-p",
            help="Destination path for configuration file.",
        ),
    ] = Path(".caulk.toml"),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing configuration file without prompting.",
        ),
    ] = False,
) -> None:
    """Initialize a default .caulk.toml configuration file."""
    if target.exists() and not force:
        err_console.print(
            f"[bold yellow]Configuration already exists at:[/bold yellow] {target}\n"
            "Use [bold]--force[/bold] to overwrite."
        )
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    try:
        write_default_config(target, overwrite=True)
        console.print(f"[bold green]Initialized Caulk configuration at:[/bold green] {target}")
    except Exception as err:
        err_console.print(f"[bold red]Error creating configuration:[/bold red] {err}")
        raise typer.Exit(code=EXIT_EXECUTION_ERROR) from err


if __name__ == "__main__":
    app()
