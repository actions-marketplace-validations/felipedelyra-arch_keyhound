"""Validação ativa: confere se uma credencial encontrada ainda funciona.

Só roda com --validate. Cada verificação é uma chamada de leitura ao
endpoint oficial do próprio serviço, por HTTPS.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from enum import Enum

from keyhound.models import Finding

TIMEOUT = 5
USER_AGENT = "keyhound-validator"


class Status(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Seguir um redirecionamento poderia reenviar a credencial para outro host.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _request(url: str, headers: dict[str, str], method: str = "GET") -> tuple[int, bytes]:
    request = urllib.request.Request(
        url, method=method, headers={"User-Agent": USER_AGENT, **headers}
    )
    try:
        with _opener.open(request, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, b""


def _by_status(code: int) -> Status:
    if code == 200:
        return Status.ACTIVE
    if code == 401:
        return Status.INACTIVE
    return Status.UNKNOWN


def _github(value: str) -> Status:
    code, _ = _request(
        "https://api.github.com/user",
        {"Authorization": f"Bearer {value}", "Accept": "application/vnd.github+json"},
    )
    return _by_status(code)


def _slack(value: str) -> Status:
    code, body = _request(
        "https://slack.com/api/auth.test",
        {"Authorization": f"Bearer {value}"},
        method="POST",
    )
    if code != 200:
        return Status.UNKNOWN
    try:
        data = json.loads(body)
    except ValueError:
        return Status.UNKNOWN
    if data.get("ok"):
        return Status.ACTIVE
    if data.get("error") in {"invalid_auth", "not_authed", "account_inactive", "token_revoked"}:
        return Status.INACTIVE
    return Status.UNKNOWN


def _stripe(value: str) -> Status:
    code, _ = _request(
        "https://api.stripe.com/v1/balance",
        {"Authorization": f"Bearer {value}"},
    )
    # 403 é chave restrita sem permissão de leitura do saldo: continua válida.
    if code in (200, 403):
        return Status.ACTIVE
    if code == 401:
        return Status.INACTIVE
    return Status.UNKNOWN


def _mercadopago(value: str) -> Status:
    code, _ = _request(
        "https://api.mercadopago.com/users/me",
        {"Authorization": f"Bearer {value}"},
    )
    return _by_status(code)


VALIDATORS: dict[str, Callable[[str], Status]] = {
    "github-token": _github,
    "slack-token": _slack,
    "stripe-key": _stripe,
    "mercadopago-token": _mercadopago,
}


def validate(finding: Finding) -> Status:
    check = VALIDATORS.get(finding.rule_id)
    if check is None:
        return Status.UNSUPPORTED
    try:
        return check(finding.value)
    except (OSError, http.client.HTTPException, ValueError):
        return Status.UNKNOWN


def validate_all(findings: list[Finding]) -> list[Status]:
    cache: dict[tuple[str, str], Status] = {}
    statuses: list[Status] = []
    for finding in findings:
        key = (finding.rule_id, finding.value)
        if key not in cache:
            cache[key] = validate(finding)
        statuses.append(cache[key])
    return statuses