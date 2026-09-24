"""Saída em SARIF 2.1.0, o formato que o GitHub code scanning consome."""

from __future__ import annotations

import json
from pathlib import Path

from keyhound import __version__
from keyhound.models import Finding, Severity
from keyhound.rules import RULES

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"
REPO = "https://github.com/felipedelyra-arch/keyhound"

# O GitHub só aceita estes quatro níveis.
LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# security-severity alimenta o filtro de severidade da aba Security.
SCORES: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _rule_descriptors() -> list[dict]:
    return [
        {
            "id": rule.id,
            "name": rule.id.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": rule.description},
            "fullDescription": {
                "text": f"{rule.description}. Rotacione a credencial e remova-a do código."
            },
            "helpUri": f"{REPO}#o-que-detecta",
            "properties": {
                "tags": ["security", "secrets"],
                "security-severity": SCORES[rule.severity],
            },
            "defaultConfiguration": {"level": LEVELS[rule.severity]},
        }
        for rule in RULES
    ]


def _result(finding: Finding, root: Path) -> dict:
    return {
        "ruleId": finding.rule_id,
        "level": LEVELS[finding.severity],
        "message": {
            "text": f"Credencial exposta ({finding.rule_id}): {finding.masked()}"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _relative_path(finding.path, root),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
        "partialFingerprints": {
            "keyhound/v1": f"{finding.rule_id}:{finding.masked()}"
        },
    }


def to_sarif(findings: list[Finding], root: Path) -> str:
    report = {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Keyhound",
                        "version": __version__,
                        "informationUri": REPO,
                        "rules": _rule_descriptors(),
                    }
                },
                "results": [_result(f, root) for f in findings],
            }
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False)