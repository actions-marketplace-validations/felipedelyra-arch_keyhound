"""O motor: percorre a árvore, aplica regras, devolve findings."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from keyhound.entropy import shannon_entropy
from keyhound.filters import is_ignored_path, is_noise, load_ignore_patterns
from keyhound.models import Finding, Rule
from keyhound.rules import RULES

IGNORED_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".next", "out", "target", "vendor",
})

MAX_FILE_SIZE = 2 * 1024 * 1024   # 2 MB
MAX_LINE_LENGTH = 4096            # linha maior que isso é arquivo minificado


def is_binary(path: Path) -> bool:
    """Byte nulo nos primeiros 1024 bytes = binário. Heurística do `grep`."""
    try:
        with path.open("rb") as f:
            return b"\0" in f.read(1024)
    except OSError:
        return True


def iter_files(root: Path, ignored: Iterable[str] = IGNORED_DIRS) -> Iterator[Path]:
    ignored = set(ignored)
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in ignored for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        if is_binary(path):
            continue
        yield path


def _scan_line(line: str, number: int, path: Path, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        for match in rule.regex.finditer(line):
            value = match.group(1) if match.groups() else match.group(0)
            if is_noise(value):
                continue
            entropy = shannon_entropy(value)
            if rule.min_entropy is not None and entropy < rule.min_entropy:
                continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    path=path,
                    line=number,
                    value=value,
                    entropy=round(entropy, 2),
                    severity=rule.severity,
                )
            )
    return findings


def scan_file(path: Path, rules: list[Rule] | None = None) -> list[Finding]:
    rules = RULES if rules is None else rules
    findings: list[Finding] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for number, line in enumerate(f, start=1):
                if len(line) > MAX_LINE_LENGTH:
                    continue
                findings.extend(_scan_line(line, number, path, rules))
    except OSError:
        return []
    return findings


def scan_directory(root: Path | str, rules: list[Rule] | None = None) -> list[Finding]:
    """Orquestra tudo. Ordena por severidade, depois arquivo e linha."""
    root = Path(root).resolve()
    rules = RULES if rules is None else rules
    ignore_patterns = load_ignore_patterns(root)

    findings: list[Finding] = []
    for path in iter_files(root):
        if is_ignored_path(path, root, ignore_patterns):
            continue
        findings.extend(scan_file(path, rules))

    findings.sort(key=lambda f: (-f.severity.weight, str(f.path), f.line))
    return findings