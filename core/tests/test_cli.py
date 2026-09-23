import json
from pathlib import Path

from typer.testing import CliRunner

from fresta.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_table_output():
    result = runner.invoke(app, ["scan", str(FIXTURES)])
    assert result.exit_code == 0
    assert "10 finding(s)" in result.stdout
    assert "7 critical" in result.stdout


def test_scan_json_is_valid():
    result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) == 10
    assert {"rule", "severity", "file", "line", "masked_value", "entropy"} <= set(data[0])


def test_json_never_leaks_the_raw_value():
    result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "json"])
    assert "AKIA2R7XQ4MPZK9TLW3B" not in result.stdout
    assert "MinhaSenh4Forte" not in result.stdout


def test_fail_on_critical_returns_one():
    result = runner.invoke(app, ["scan", str(FIXTURES), "--fail-on", "critical"])
    assert result.exit_code == 1


def test_no_fail_on_returns_zero():
    result = runner.invoke(app, ["scan", str(FIXTURES)])
    assert result.exit_code == 0


def test_fail_on_above_findings_returns_zero(tmp_path):
    (tmp_path / "clean.py").write_text("x = 1\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0


def test_min_severity_filters():
    result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "json"])
    all_rules = {item["rule"] for item in json.loads(result.stdout)}

    result = runner.invoke(
        app, ["scan", str(FIXTURES), "--min-severity", "critical", "--format", "json"]
    )
    critical_rules = {item["rule"] for item in json.loads(result.stdout)}

    assert "generic-password" in all_rules
    assert "generic-password" not in critical_rules
    assert "aws-access-key" in critical_rules


def test_invalid_path_returns_two():
    result = runner.invoke(app, ["scan", "/caminho/que/nao/existe"])
    assert result.exit_code == 2


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "fresta" in result.stdout


def test_history_on_plain_directory(tmp_path):
    result = runner.invoke(app, ["history", str(tmp_path)])
    assert result.exit_code == 0
    assert "No secrets found" in result.stdout