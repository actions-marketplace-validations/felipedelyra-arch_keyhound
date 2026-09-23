"""Catálogo de regras. Só dados, nenhuma lógica."""

from keyhound.models import Rule, Severity

RULES: list[Rule] = [
    # ---------- Global services ----------
    Rule(
        id="aws-access-key",
        description="AWS access key ID",
        pattern=r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="github-token",
        description="GitHub personal access token",
        pattern=r"(?<![\w-])gh[pousr]_[A-Za-z0-9]{36,255}(?![\w-])",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="slack-token",
        description="Slack bot token",
        pattern=r"(?<![\w-])xox[baprs]-[A-Za-z0-9-]{10,72}(?![\w-])",
        severity=Severity.HIGH,
    ),
    Rule(
        id="private-key",
        description="PEM private key",
        pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="jwt",
        description="JSON Web Token",
        pattern=r"(?<![\w.])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        severity=Severity.HIGH,
    ),
    Rule(
        id="db-connection-string",
        description="Database URI with embedded credentials",
        pattern=r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s:@/]+@[^\s/\"']+",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="google-api-key",
        description="Google API key",
        pattern=r"(?<![\w-])AIza[A-Za-z0-9_-]{35}(?![\w-])",
        severity=Severity.HIGH,
    ),
    Rule(
        id="stripe-key",
        description="Stripe secret key",
        pattern=r"(?<![\w-])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,99}(?![\w-])",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="generic-password",
        description="Hardcoded password assignment",
        pattern=r"(?i)\b(?:senha|password|passwd|pwd)\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']",
        severity=Severity.MEDIUM,
    ),
    Rule(
        id="generic-token",
        description="Hardcoded token or secret assignment",
        pattern=(
            r"(?i)\b(?:api[_-]?key|secret|token|access[_-]?key)"
            r"\s*[=:]\s*[\"']([A-Za-z0-9_\-+/=]{20,})[\"']"
        ),
        severity=Severity.MEDIUM,
        min_entropy=3.5,
    ),

    # ---------- Serviços brasileiros (o diferencial do projeto) ----------
    Rule(
        id="mercadopago-token",
        description="Mercado Pago access token (produção ou teste)",
        pattern=r"(?<![\w-])(?:APP_USR|TEST)-\d{10,20}-\d{6}-[a-f0-9]{32}-\d{6,10}(?![\w-])",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="asaas-key",
        description="Chave de API do Asaas",
        pattern=r"\$aact_[A-Za-z0-9+/=_-]{40,}",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="pagarme-key",
        description="Chave de API Pagar.me / Stone",
        pattern=r"(?<![\w-])ak_(?:live|test)_[A-Za-z0-9]{28,40}(?![\w-])",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="cielo-merchant-key",
        description="MerchantKey da Cielo em atribuição",
        pattern=r"(?i)\bmerchant[_-]?key\s*[=:]\s*[\"']([A-Z0-9]{40})[\"']",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="pagseguro-token",
        description="Token do PagSeguro/PagBank em atribuição",
        pattern=r"(?i)\b(?:pagseguro|pagbank)[_-]?token\s*[=:]\s*[\"']([A-Fa-f0-9]{32})[\"']",
        severity=Severity.CRITICAL,
    ),
    Rule(
         id="supabase-service-role",
        description="Chave service_role do Supabase (ignora RLS)",
        pattern=(
            r"(?<![\w.])eyJ[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]*(?:InNlcnZpY2Vfcm9sZSI|NlcnZpY2Vfcm9sZS|zZXJ2aWNlX3JvbGU)"
            r"[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+"
        ),
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="supabase-secret-key",
        description="Chave secreta do Supabase (formato novo)",
        pattern=r"(?<![\w-])sb_secret_[A-Za-z0-9_-]{20,}(?![\w-])",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="pix-key-evp",
        description="Chave Pix aleatória (EVP) em atribuição",
        pattern=(
            r"(?i)\b(?:chave[_-]?pix|pix[_-]?key)\s*[=:]\s*[\"']"
            r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})[\"']"
        ),
        severity=Severity.HIGH,
    ),
    Rule(
        id="a1-cert-password",
        description="Senha de certificado digital A1 (.pfx/.p12)",
        pattern=r"(?i)\b(?:pfx|p12|cert(?:ificado)?)[_-]?(?:senha|password|pass)\s*[=:]\s*[\"']([^\"'\s]{4,})[\"']",
        severity=Severity.CRITICAL,
    ),
]


def rules_by_severity(minimum: Severity) -> list[Rule]:
    return [r for r in RULES if r.severity.weight >= minimum.weight]