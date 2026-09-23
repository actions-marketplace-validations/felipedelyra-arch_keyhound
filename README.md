# Keyhound

Detector de credenciais expostas em código, com cobertura para serviços
brasileiros que ferramentas como gitleaks e trufflehog não reconhecem:
Mercado Pago, Asaas, Pagar.me, Cielo, PagSeguro, chave Pix, certificado
digital A1 e a chave `service_role` do Supabase.

![Keyhound em funcionamento](demo.png)

## Por que existe

Durante o desenvolvimento é comum colar a chave direto no arquivo para
testar — e esquecer. O código vai para o repositório e a chave vai junto.
Há robôs varrendo o GitHub atrás exatamente disso: o intervalo entre
publicar e a chave ser usada por terceiros costuma ser de minutos.

Remover a chave do arquivo não resolve: ela continua no histórico do Git,
recuperável por qualquer pessoa com acesso ao repositório.

## Instalação

```bash
pip install keyhound
```

Requer Python 3.11 ou superior.

## Uso

```bash
keyhound scan .                        # varre o diretório atual
keyhound scan ./src -m high            # só severidade alta ou acima
keyhound scan . -f json                # saída para pipeline
keyhound scan . --fail-on critical     # sai com código 1 se achar crítico

keyhound history .                     # varre todo o histórico do git
keyhound history . -n 100              # só os 100 commits mais recentes
keyhound history . -f json
```

O valor do segredo é sempre mascarado na saída — na tela, no JSON e em
qualquer log.

### Na integração contínua

```bash
keyhound scan . --fail-on critical
```

Código de saída `1` quando encontra algo no nível informado, `0` quando
está limpo.

## O que detecta

**Globais** — AWS, GitHub, Slack, chave privada PEM, JWT, string de
conexão de banco, Google API, Stripe, senha e token em atribuição literal.

**Brasileiros** — Mercado Pago, Asaas, Pagar.me/Stone, MerchantKey da
Cielo, token do PagSeguro/PagBank, `service_role` e chave secreta do
Supabase, chave Pix aleatória (EVP) e senha de certificado A1.

A regra do `service_role` merece destaque: essa chave ignora todas as
políticas de Row Level Security do Supabase. Vazada no frontend, expõe o
banco inteiro. É visualmente idêntica à chave `anon`, que é pública e
inofensiva — o Keyhound distingue as duas.

## Pre-commit hook

Bloqueia o commit automaticamente quando encontra credencial. No
`.pre-commit-config.yaml` do seu projeto:

```yaml
repos:
  - repo: https://github.com/felipedelyra-arch/keyhound
    rev: v0.2.0
    hooks:
      - id: keyhound
```

Depois:

```bash
pip install pre-commit
pre-commit install
```

A partir daí, todo `git commit` passa pelo Keyhound. Se encontrar algo de
severidade média ou acima, o commit é recusado.

## Reduzindo ruído

Ferramenta que grita demais é desinstalada. O Keyhound filtra em três
camadas antes de reportar:

- caminhos listados no `.keyhoundignore`
- valores que são claramente placeholder (`xxxx`, `<your-key>`,
  `${API_KEY}`, `CHANGEME`)
- chaves de exemplo que circulam em documentação oficial

Crie um `.keyhoundignore` na raiz do projeto:

```
tests/fixtures/
**/*.lock
docs/exemplos/
```

## Desenvolvimento

```bash
git clone https://github.com/felipedelyra-arch/keyhound.git
cd keyhound
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Contribuindo

Veja [CONTRIBUTING.md](CONTRIBUTING.md). Regras novas para serviços
brasileiros são especialmente bem-vindas.

## Licença

Apache License 2.0 — veja [LICENSE](LICENSE).