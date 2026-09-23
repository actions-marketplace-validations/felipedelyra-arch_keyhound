import pytest

from fresta.entropy import shannon_entropy
from fresta.models import Severity
from fresta.rules import RULES, rules_by_severity

BY_ID = {r.id: r for r in RULES}

POSITIVES = [
    # ---- Global ----
    ("aws-access-key", 'key = "AKIA2R7XQ4MPZK9TLW3B"'),
    ("github-token", "ghp_" + "a" * 36),
    ("slack-token", "xoxb-1234567890-abcdefghij"),
    ("private-key", "-----BEGIN RSA PRIVATE KEY-----"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"),
    ("db-connection-string", "postgresql://admin:Segr3d0@db.local:5432/app"),
    ("google-api-key", "AIza" + "B" * 35),
    ("stripe-key", "sk_live_" + "4" * 24),
    ("generic-password", 'password = "MinhaSenh4Forte"'),
    ("generic-token", 'api_key = "xK9mPq2wRt7vNz4bYh6JdF3sLc8G"'),
    # ---- Brasil ----
    ("mercadopago-token", "APP_USR-1234567890123456-092312-a1b2c3d4e5f67890a1b2c3d4e5f67890-123456789"),
    ("asaas-key", "$aact_" + "Y" * 50),
    ("pagarme-key", "ak_live_" + "7" * 32),
    ("cielo-merchant-key", 'merchant_key = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"'),
    ("pagseguro-token", 'pagseguro_token = "' + "a1b2c3d4" * 4 + '"'),
    ("supabase-service-role",
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE2MDk0NTkyMDB9."
     "Xy7Qm2Lp9Rv4Nk8Tz"),
    ("supabase-secret-key", "sb_secret_" + "k" * 30),
    ("pix-key-evp", 'chave_pix = "3f2a91c4-7b8e-4d21-9a6f-1c5e8b0d47a2"'),
    ("a1-cert-password", 'pfx_senha = "C3rt1f1c@d0"'),
]

NEGATIVES = [
    ("aws-access-key", "PREFIXAKIA2R7XQ4MPZK9TLW3B"),
    ("github-token", "ghp_short"),
    ("google-api-key", "AIzaTooShort"),
    ("stripe-key", "sk_live_short"),
    ("db-connection-string", "postgresql://db.local:5432/app"),
    ("generic-token", 'api_key = "aaaaaaaaaaaaaaaaaaaaaaaa"'),
    # chave anon do Supabase: pública por design, NÃO pode virar finding
    ("supabase-service-role",
     "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIn0.Xy7Qm2Lp9Rv4"),
    ("pix-key-evp", 'chave_pix = "nao-e-um-uuid"'),
    ("asaas-key", "aact_sem_o_cifrao_inicial_1234567890"),
]


@pytest.mark.parametrize("rule_id,text", POSITIVES)
def test_positive_matches(rule_id, text):
    assert BY_ID[rule_id].regex.search(text) is not None


@pytest.mark.parametrize("rule_id,text", NEGATIVES)
def test_negatives_are_rejected(rule_id, text):
    """Ou o regex não casa, ou a entropia barra."""
    rule = BY_ID[rule_id]
    match = rule.regex.search(text)
    if match is None:
        return
    value = match.group(1) if match.groups() else match.group(0)
    assert rule.min_entropy is not None
    assert shannon_entropy(value) < rule.min_entropy


def test_unique_ids():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_rule_count():
    assert len(RULES) == 19


def test_filter_by_severity():
    critical = rules_by_severity(Severity.CRITICAL)
    assert all(r.severity is Severity.CRITICAL for r in critical)
    assert len(critical) < len(RULES)