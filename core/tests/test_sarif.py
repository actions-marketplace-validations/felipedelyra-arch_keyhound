import json
from pathlib import Path

from keyhound.rules import RULES
from keyhound.sarif import to_sarif
from keyhound.scanner import scan_directory

FIXTURES = Path(__file__).parent / "fixtures"


def _report() -> dict:
    findings = scan_directory(FIXTURES)
    return json.loads(to_sarif(findings, FIXTURES))


def test_is_valid_sarif_210():
    report = _report()
    assert report["version"] == "2.1.0"
    assert "$schema" in report
    assert len(report["runs"]) == 1


def test_tool_metadata():
    driver = _report()["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Keyhound"
    assert len(driver["rules"]) == len(RULES)


def test_results_match_findings():
    findings = scan_directory(FIXTURES)
    results = _report()["runs"][0]["results"]
    assert len(results) == len(findings)


def test_levels_are_github_compatible():
    allowed = {"error", "warning", "note", "none"}
    for result in _report()["runs"][0]["results"]:
        assert result["level"] in allowed


def test_never_leaks_the_raw_value():
    raw = to_sarif(scan_directory(FIXTURES), FIXTURES)
    assert "AKIA2R7XQ4MPZK9TLW3B" not in raw
    assert "MinhaSenh4Forte" not in raw


def test_locations_have_line_numbers():
    for result in _report()["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1


def test_fingerprints_present():
    for result in _report()["runs"][0]["results"]:
        assert "keyhound/v1" in result["partialFingerprints"]