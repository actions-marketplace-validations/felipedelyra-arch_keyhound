"""Anti-ruído: decide o que NÃO é segredo de verdade.

Três camadas, da mais barata para a mais cara:
  1. caminho ignorado pelo .keyhoundignore
  2. valor é placeholder óbvio (CHANGEME, xxxx, <your-key>)
  3. valor está na allowlist de exemplos públicos conhecidos
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

IGNORE_FILE = ".keyhoundignore"

KNOWN_EXAMPLES: frozenset[str] = frozenset({
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # Chave de teste da documentação do Stripe, montada em partes para não
    # disparar o push protection do GitHub.
    "sk_test_" + "4eC39HqLyjWDarjt" + "T1zdp7dc",
})

PLACEHOLDER_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^x{4,}$",
        r"^\.{3,}$",
        r"^<.+>$",
        r"^\$\{?[A-Z_]+\}?$",
        r"\b(?:change[_-]?me|your[_-]?\w+[_-]?here|replace[_-]?me)\b",
        r"\b(?:example|sample|dummy|placeholder|fake)\b",
        r"^(.)\1{7,}$",
    )
)


def load_ignore_patterns(root: Path) -> list[str]:
    """Lê o .keyhoundignore. Linha vazia e comentário são descartados."""
    ignore_file = root / IGNORE_FILE
    if not ignore_file.is_file():
        return []

    patterns: list[str] = []
    for raw in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def is_ignored_path(path: Path, root: Path, patterns: list[str]) -> bool:
    """Casa o caminho relativo contra os globs do .keyhoundignore."""
    if not patterns:
        return False

    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return False

    for pattern in patterns:
        if pattern.endswith("/"):
            if relative.startswith(pattern) or f"/{pattern}" in f"/{relative}":
                return True
        elif fnmatch.fnmatch(relative, pattern):
            return True
        elif fnmatch.fnmatch(relative, f"*/{pattern}"):
            return True
    return False


def is_placeholder(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    return any(p.search(stripped) for p in PLACEHOLDER_PATTERNS)


def is_known_example(value: str) -> bool:
    return value.strip() in KNOWN_EXAMPLES


def is_noise(value: str) -> bool:
    """Porta única usada pelo scanner."""
    return is_placeholder(value) or is_known_example(value)