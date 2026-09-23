from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path

class Severity(str, Enum):
    CRITICAL =   "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]

@lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)

@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    description: str
    pattern: str
    severity: Severity
    min_entropy: float | None = None

    @property
    def regex(self) -> re.pattern[str]:
        return _compile(self.pattern)

@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    path: Path
    line: int
    value: str
    entropy: float
    severity: Severity

    def masked(self) -> str:
        if len(self.value) <= 8:
            return "*" * len(self.value)
        middle = "*" * (len(self.value) - 8)
        return f"{self.value[:4]}{middle}{self.value[-4:]}"