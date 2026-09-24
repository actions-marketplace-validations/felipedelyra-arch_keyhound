"""Relatório em HTML para quem não é técnico, com leitura para a LGPD."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

from keyhound import __version__
from keyhound.models import Finding, Severity

REPO = "https://github.com/felipedelyra-arch/keyhound"

SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Média",
    Severity.LOW: "Baixa",
}

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#b42318",
    Severity.HIGH: "#c4320a",
    Severity.MEDIUM: "#b54708",
    Severity.LOW: "#667085",
}

PRIORITY: dict[Severity, str] = {
    Severity.CRITICAL: "Imediata",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Planejar",
    Severity.LOW: "Revisar",
}

STATUS_LABEL: dict[str, str] = {
    "active": "ATIVA",
    "inactive": "Inativa",
    "unknown": "Não confirmada",
    "unsupported": "Não verificável",
}

SERVICES: dict[str, str] = {
    "aws-access-key": "AWS",
    "github-token": "GitHub",
    "slack-token": "Slack",
    "private-key": "Chave privada",
    "jwt": "Token JWT",
    "db-connection-string": "Banco de dados",
    "google-api-key": "Google Cloud",
    "stripe-key": "Stripe",
    "generic-password": "Senha no código",
    "generic-token": "Token no código",
    "mercadopago-token": "Mercado Pago",
    "asaas-key": "Asaas",
    "pagarme-key": "Pagar.me / Stone",
    "cielo-merchant-key": "Cielo",
    "pagseguro-token": "PagSeguro / PagBank",
    "supabase-service-role": "Supabase (service_role)",
    "supabase-secret-key": "Supabase",
    "pix-key-evp": "Chave Pix",
    "a1-cert-password": "Certificado digital A1",
}

STYLE = """
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:#1d2939;background:#f2f4f7;line-height:1.55}
.page{max-width:920px;margin:0 auto;background:#fff;padding:48px}
header{border-bottom:3px solid #101828;padding-bottom:18px;margin-bottom:24px}
h1{font-size:26px;margin:0 0 6px}
h2{font-size:18px;margin:34px 0 12px;border-left:4px solid #101828;padding-left:10px}
.meta{color:#475467;font-size:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.card{border:1px solid #eaecf0;border-radius:8px;padding:14px}
.card .n{font-size:28px;font-weight:700}
.card .l{font-size:13px;color:#475467}
.alert{background:#fef3f2;border:1px solid #fecdca;color:#912018;padding:14px;border-radius:8px;margin-top:16px;font-weight:600}
.ok{background:#ecfdf3;border:1px solid #abefc6;color:#067647;padding:14px;border-radius:8px;margin-top:16px;font-weight:600}
.warn{background:#fffaeb;border:1px solid #fedf89;color:#93370d;padding:12px;border-radius:8px;margin-top:12px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#101828;color:#fff;text-align:left;padding:8px;white-space:nowrap}
td{border-bottom:1px solid #eaecf0;padding:8px;vertical-align:top}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.sev{font-weight:700}
ol,ul{padding-left:22px}
li{margin-bottom:6px}
.note{font-size:12px;color:#667085;border-top:1px solid #eaecf0;margin-top:36px;padding-top:12px}
@media (max-width:600px){.page{padding:20px}h1{font-size:22px}}
@media print{body{background:#fff}.page{padding:0;max-width:none}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _cards(findings: list[Finding], counts: dict[Severity, int]) -> str:
    items = [("Total", len(findings), "#101828")]
    for sev in Severity:
        items.append((SEVERITY_LABEL[sev], counts[sev], SEVERITY_COLOR[sev]))
    return "".join(
        f'<div class="card"><div class="n" style="color:{color}">{number}</div>'
        f'<div class="l">{label}</div></div>'
        for label, number, color in items
    )


def _rows(findings: list[Finding], root: Path, statuses: list | None) -> str:
    rows = []
    for index, f in enumerate(findings):
        service = escape(SERVICES.get(f.rule_id, f.rule_id))
        location = escape(f"{_relative(f.path, root)}:{f.line}")
        masked = escape(f.masked())
        color = SEVERITY_COLOR[f.severity]
        cells = [
            f"<td>{index + 1}</td>",
            f'<td class="sev" style="color:{color}">{SEVERITY_LABEL[f.severity]}</td>',
            f"<td>{service}</td>",
            f"<td><code>{location}</code></td>",
            f"<td><code>{masked}</code></td>",
        ]
        if statuses is not None:
            status = statuses[index].value
            label = STATUS_LABEL.get(status, status)
            attrs = ' class="sev" style="color:#b42318"' if status == "active" else ""
            cells.append(f"<td{attrs}>{label}</td>")
        cells.append(f"<td>{PRIORITY[f.severity]}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return "\n".join(rows)


def _verdict(findings: list[Finding], statuses: list | None) -> str:
    if not findings:
        return '<div class="ok">Nenhuma credencial exposta foi encontrada nos arquivos analisados.</div>'
    text = f"{len(findings)} credencial(is) exposta(s) encontrada(s) no código."
    if statuses is not None:
        active = sum(1 for s in statuses if s.value == "active")
        if active:
            text += f" {active} continua(m) ativa(s) e deve(m) ser revogada(s) imediatamente."
        else:
            text += " Nenhuma foi confirmada como ativa na verificação."
    return f'<div class="alert">{text}</div>'


def _findings_section(findings: list[Finding], root: Path, statuses: list | None) -> str:
    if not findings:
        return ""
    status_header = "<th>Status</th>" if statuses is not None else ""
    return f"""
<h2>Credenciais encontradas</h2>
<p>Os valores aparecem mascarados. Este relatório nunca exibe a credencial completa.</p>
<div class="scroll"><table>
<thead><tr><th>#</th><th>Severidade</th><th>Serviço</th><th>Local</th><th>Valor</th>{status_header}<th>Prioridade</th></tr></thead>
<tbody>
{_rows(findings, root, statuses)}
</tbody>
</table></div>
"""


def _actions_section(findings: list[Finding]) -> str:
    if not findings:
        return ""
    supabase = ""
    if any(f.rule_id == "supabase-service-role" for f in findings):
        supabase = (
            '<div class="warn"><strong>Atenção — Supabase service_role:</strong> esta chave ignora '
            "todas as políticas de Row Level Security. Quem a possui tem acesso total ao banco "
            "de dados. Trate como prioridade máxima.</div>"
        )
    return f"""
<h2>O que fazer</h2>
<ol>
<li><strong>Revogue</strong> cada credencial no painel do serviço correspondente e gere uma nova. Apagar do código não basta: quem copiou a chave antiga continua podendo usá-la.</li>
<li><strong>Guarde a nova credencial fora do código</strong>, em variável de ambiente no servidor. Nunca no site público nem dentro do aplicativo instalado no celular.</li>
<li><strong>Verifique os registros de acesso</strong> de cada serviço no período em que a chave esteve exposta.</li>
<li><strong>Trate o histórico do Git.</strong> A chave antiga continua nas versões anteriores do código; revogar é o que efetivamente resolve.</li>
<li><strong>Automatize a prevenção</strong> com o hook de pre-commit ou a GitHub Action do Keyhound, para bloquear novos casos antes de chegarem ao repositório.</li>
</ol>
{supabase}
"""


def to_html(
    findings: list[Finding],
    root: Path | str,
    statuses: list | None = None,
    client: str | None = None,
    generated_at: datetime | None = None,
) -> str:
    root = Path(root)
    when = (generated_at or datetime.now()).strftime("%d/%m/%Y %H:%M")
    subject = escape(client) if client else escape(root.name or str(root))

    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    if statuses is not None:
        validation = "Realizada nos serviços suportados (GitHub, Slack, Stripe e Mercado Pago)."
    else:
        validation = "Não realizada. Execute com <code>--validate</code> para confirmar quais credenciais ainda funcionam."

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatório Keyhound — {subject}</title>
<style>{STYLE}</style>
</head>
<body>
<div class="page">

<header>
<h1>Relatório de credenciais expostas</h1>
<div class="meta">{subject} · gerado em {when} · Keyhound {__version__}</div>
</header>

<h2>Resumo</h2>
<div class="cards">{_cards(findings, counts)}</div>
{_verdict(findings, statuses)}

<h2>Por que isso importa</h2>
<p>Credenciais são as senhas que conectam o sistema a serviços como gateways de pagamento, bancos de dados e provedores de nuvem. Quando ficam escritas no código, qualquer pessoa com acesso a ele — incluindo robôs que varrem repositórios públicos continuamente — pode usá-las para movimentar valores, acessar dados de clientes ou gerar custos em nome da empresa.</p>

{_findings_section(findings, root, statuses)}
{_actions_section(findings)}

<h2>Leitura pela LGPD</h2>
<p>O <strong>Art. 46 da Lei nº 13.709/2018 (LGPD)</strong> determina que os agentes de tratamento adotem medidas de segurança, técnicas e administrativas, aptas a proteger os dados pessoais de acessos não autorizados e de situações acidentais ou ilícitas.</p>
<p>Credenciais expostas podem permitir acesso não autorizado a sistemas que tratam dados pessoais, como cadastros de clientes e informações de pagamento. Se houver indício de uso indevido que possa acarretar risco ou dano relevante aos titulares, o <strong>Art. 48</strong> prevê a comunicação à Autoridade Nacional de Proteção de Dados (ANPD) e aos titulares.</p>
<p>A execução periódica desta verificação e a correção dos achados documentam uma medida técnica preventiva da empresa.</p>

<h2>Metodologia</h2>
<ul>
<li><strong>Ferramenta:</strong> Keyhound {__version__}, código aberto (<a href="{REPO}">{REPO}</a>).</li>
<li><strong>Escopo:</strong> arquivos atuais do diretório analisado. Dependências de terceiros (como <code>node_modules</code> e ambientes virtuais) e caminhos listados no <code>.keyhoundignore</code> ficam de fora.</li>
<li><strong>Histórico do Git:</strong> não incluído neste relatório. Execute <code>keyhound history</code> para verificar versões anteriores do código.</li>
<li><strong>Validação ativa:</strong> {validation}</li>
<li><strong>Privacidade:</strong> a análise roda localmente; nenhuma credencial é exibida por inteiro.</li>
</ul>

<div class="note">Este é um relatório técnico e não constitui parecer jurídico. Para a avaliação de obrigações legais, consulte o encarregado de dados (DPO) ou a assessoria jurídica da empresa. Trate este documento como confidencial: ele indica onde estão as falhas.</div>

</div>
</body>
</html>
"""