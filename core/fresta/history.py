"""Varredura do histórico do Git."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from fresta.models import Finding, Rule
from fresta.rules import RULES
from fresta.scanner import _scan_line

COMMIT_SEPARATOR = "@@FRESTA-COMMIT@@"
MAX_LINE_LENGTH = 4096


@dataclass(frozen=True, slots=True)
class HistoryFinding:
    finding: Finding
    commit: str
    author: str
    date: str


def is_git_repository(root: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def _run_git_log(root: Path, max_commits: int | None) -> str:
    command = [
        "git", "-C", str(root), "log",
        f"--format={COMMIT_SEPARATOR}%H|%an|%ad",
        "--date=short",
        "-p",
        "--no-color",
        "--no-merges",
    ]
    if max_commits is not None:
        command.append(f"-{max_commits}")

    result = subprocess.run(command, capture_output=True, text=True, errors="ignore")
    if result.returncode != 0:
        return ""
    return result.stdout


def scan_history(
    root: Path | str,
    rules: list[Rule] | None = None,
    max_commits: int | None = None,
) -> list[HistoryFinding]:
    root = Path(root).resolve()
    rules = RULES if rules is None else rules

    if not is_git_repository(root):
        return []

    output = _run_git_log(root, max_commits)
    if not output:
        return []

    results: list[HistoryFinding] = []
    seen: set[tuple[str, str]] = set()

    for block in output.split(COMMIT_SEPARATOR):
        if not block.strip():
            continue

        header, _, body = block.partition("\n")
        parts = header.split("|", 2)
        if len(parts) != 3:
            continue
        commit, author, date = parts

        current_file = Path("desconhecido")
        for line in body.splitlines():
            if line.startswith("+++ b/"):
                current_file = Path(line[6:])
                continue
            # Linha removida é o segredo saindo; só a adição revela quem o introduziu.
            if not line.startswith("+") or line.startswith("+++"):
                continue
            if len(line) > MAX_LINE_LENGTH:
                continue

            for finding in _scan_line(line[1:], 0, current_file, rules):
                key = (commit, finding.value)
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    HistoryFinding(
                        finding=finding,
                        commit=commit[:8],
                        author=author,
                        date=date,
                    )
                )

    results.sort(key=lambda h: (-h.finding.severity.weight, h.date))
    return results