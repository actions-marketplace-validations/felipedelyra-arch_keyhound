from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from keyhound.models import Finding, Severity

COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def print_table(findings: list[Finding], root: Path, console: Console) -> None:
    if not findings:
        console.print("[bold green]No secrets found.[/]")
        return

    table = Table(header_style="bold")
    table.add_column("Sev.", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("File:line", no_wrap=True)
    table.add_column("Value", no_wrap=True, max_width=28)
    table.add_column("Ent.", justify="right", no_wrap=True)

    for f in findings:
        table.add_row(
            f"[{COLORS[f.severity]}]{f.severity.value.upper()}[/]",
            f.rule_id,
            f"{_relative_path(f.path, root)}:{f.line}",
            f.masked(),
            f"{f.entropy:.2f}",
        )

    console.print(table)


def print_summary(findings: list[Finding], console: Console) -> None:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    parts = [
        f"[{COLORS[s]}]{counts[s]} {s.value}[/]"
        for s in Severity
        if counts[s]
    ]
    if parts:
        console.print(f"\n{len(findings)} finding(s): " + "  ".join(parts))


def to_json(findings: list[Finding], root: Path) -> str:
    return json.dumps(
        [
            {
                "rule": f.rule_id,
                "severity": f.severity.value,
                "file": _relative_path(f.path, root),
                "line": f.line,
                "masked_value": f.masked(),
                "entropy": f.entropy,
            }
            for f in findings
        ],
        indent=2,
        ensure_ascii=False,
    )


def print_history_table(items: list, console: Console) -> None:
    if not items:
        console.print("[bold green]No secrets found in git history.[/]")
        return

    table = Table(header_style="bold")
    table.add_column("Sev.", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Commit", no_wrap=True)
    table.add_column("Date", no_wrap=True)
    table.add_column("Author", overflow="ellipsis", max_width=18)
    table.add_column("File", overflow="fold")
    table.add_column("Value", no_wrap=True, max_width=24)

    for item in items:
        f = item.finding
        table.add_row(
            f"[{COLORS[f.severity]}]{f.severity.value.upper()}[/]",
            f.rule_id,
            item.commit,
            item.date,
            item.author,
            str(f.path),
            f.masked(),
        )

    console.print(table)
    console.print(f"\n{len(items)} finding(s) in git history")


def history_to_json(items: list) -> str:
    return json.dumps(
        [
            {
                "rule": i.finding.rule_id,
                "severity": i.finding.severity.value,
                "file": str(i.finding.path),
                "commit": i.commit,
                "author": i.author,
                "date": i.date,
                "masked_value": i.finding.masked(),
            }
            for i in items
        ],
        indent=2,
        ensure_ascii=False,
    )