from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from keyhound import __version__
from keyhound.history import scan_history
from keyhound.models import Severity
from keyhound.report import (
    history_to_json,
    print_history_table,
    print_summary,
    print_table,
    to_json,
)
from keyhound.rules import rules_by_severity
from keyhound.sarif import to_sarif
from keyhound.scanner import scan_directory
from keyhound.validate import validate_all

app = typer.Typer(
    help="Keyhound — find exposed credentials in your code.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


@app.command()
def scan(
    path: Annotated[
        Path, typer.Argument(help="Directory to scan.")
    ] = Path("."),
    min_severity: Annotated[
        Severity,
        typer.Option("--min-severity", "-m", help="Lowest severity to report."),
    ] = Severity.LOW,
    output_format: Annotated[
        str, typer.Option("--format", "-f", help="table, json or sarif.")
    ] = "table",
    fail_on: Annotated[
        Severity | None,
        typer.Option("--fail-on", help="Exit with code 1 at this severity or above."),
    ] = None,
    validate_keys: Annotated[
        bool,
        typer.Option(
            "--validate",
            help="Check whether found credentials are still active (makes network calls).",
        ),
    ] = False,
) -> None:
    """Scan a directory for hardcoded secrets."""
    root = path.resolve()
    if not root.is_dir():
        err_console.print(f"[bold red]Not a directory:[/] {root}")
        raise typer.Exit(code=2)

    findings = scan_directory(root, rules_by_severity(min_severity))

    statuses = None
    if validate_keys and findings:
        err_console.print(
            "[yellow]Validating credentials against the official service APIs. "
            "Only use this on credentials you own or are authorized to test.[/]"
        )
        statuses = validate_all(findings)

    if output_format == "json":
        console.print_json(to_json(findings, root, statuses))
    elif output_format == "sarif":
        print(to_sarif(findings, root))
    else:
        print_table(findings, root, console, statuses)
        print_summary(findings, console, statuses)

    if fail_on is not None and any(f.severity.weight >= fail_on.weight for f in findings):
        raise typer.Exit(code=1)


@app.command()
def history(
    path: Annotated[
        Path, typer.Argument(help="Git repository to scan.")
    ] = Path("."),
    min_severity: Annotated[
        Severity,
        typer.Option("--min-severity", "-m", help="Lowest severity to report."),
    ] = Severity.LOW,
    limit: Annotated[
        int | None,
        typer.Option("--limit", "-n", help="Scan only the N most recent commits."),
    ] = None,
    output_format: Annotated[
        str, typer.Option("--format", "-f", help="table or json.")
    ] = "table",
    fail_on: Annotated[
        Severity | None,
        typer.Option("--fail-on", help="Exit with code 1 at this severity or above."),
    ] = None,
) -> None:
    """Scan the git history for secrets that were committed and later removed."""
    root = path.resolve()
    if not root.is_dir():
        err_console.print(f"[bold red]Not a directory:[/] {root}")
        raise typer.Exit(code=2)

    items = scan_history(root, rules_by_severity(min_severity), max_commits=limit)

    if output_format == "json":
        console.print_json(history_to_json(items))
    else:
        print_history_table(items, console)

    if fail_on is not None and any(
        i.finding.severity.weight >= fail_on.weight for i in items
    ):
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show the version."""
    console.print(f"keyhound {__version__}")


if __name__ == "__main__":
    app()