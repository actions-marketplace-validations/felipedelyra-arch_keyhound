import json
import urllib.error
from pathlib import Path

import pytest

from keyhound import validate as v
from keyhound.models import Finding, Severity
from keyhound.report import to_json


def _finding(rule_id: str, value: str = "x" * 40) -> Finding:
    return Finding(
        rule_id=rule_id,
        path=Path("app.py"),
        line=1,
        value=value,
        entropy=4.0,
        severity=Severity.CRITICAL,
    )


def _fake(code: int, body: bytes = b""):
    def fake_request(url, headers, method="GET"):
        return code, body
    return fake_request


def test_unsupported_rule_makes_no_network_call(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("network was called")
    monkeypatch.setattr(v, "_request", fail)
    assert v.validate(_finding("aws-access-key")) is v.Status.UNSUPPORTED


@pytest.mark.parametrize(
    "code,expected",
    [(200, v.Status.ACTIVE), (401, v.Status.INACTIVE), (500, v.Status.UNKNOWN)],
)
def test_github_status_mapping(monkeypatch, code, expected):
    monkeypatch.setattr(v, "_request", _fake(code))
    assert v.validate(_finding("github-token")) is expected


def test_stripe_restricted_key_counts_as_active(monkeypatch):
    monkeypatch.setattr(v, "_request", _fake(403))
    assert v.validate(_finding("stripe-key")) is v.Status.ACTIVE


def test_slack_valid_token(monkeypatch):
    monkeypatch.setattr(v, "_request", _fake(200, b'{"ok": true}'))
    assert v.validate(_finding("slack-token")) is v.Status.ACTIVE


def test_slack_revoked_token(monkeypatch):
    body = b'{"ok": false, "error": "invalid_auth"}'
    monkeypatch.setattr(v, "_request", _fake(200, body))
    assert v.validate(_finding("slack-token")) is v.Status.INACTIVE


def test_network_failure_is_unknown(monkeypatch):
    def offline(*args, **kwargs):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(v, "_request", offline)
    assert v.validate(_finding("mercadopago-token")) is v.Status.UNKNOWN


def test_same_credential_is_checked_once(monkeypatch):
    calls = []

    def counting(url, headers, method="GET"):
        calls.append(url)
        return 200, b""

    monkeypatch.setattr(v, "_request", counting)
    token = "ghp_" + "a" * 36
    statuses = v.validate_all([_finding("github-token", token)] * 3)
    assert len(calls) == 1
    assert statuses == [v.Status.ACTIVE] * 3


def test_every_endpoint_uses_https(monkeypatch):
    urls = []

    def capture(url, headers, method="GET"):
        urls.append(url)
        return 401, b""

    monkeypatch.setattr(v, "_request", capture)
    for rule_id in v.VALIDATORS:
        v.validate(_finding(rule_id))
    assert len(urls) == len(v.VALIDATORS)
    assert all(url.startswith("https://") for url in urls)


def test_json_output_includes_status():
    findings = [_finding("github-token")]
    data = json.loads(to_json(findings, Path("."), [v.Status.INACTIVE]))
    assert data[0]["status"] == "inactive"