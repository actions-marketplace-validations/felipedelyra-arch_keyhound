# Fresta

**Segredo não é arrombado, ele escorre por uma fresta.**

Detector de credenciais expostas em código, com cobertura para serviços
brasileiros que ferramentas como gitleaks e trufflehog não reconhecem:
Mercado Pago, Asaas, Pagar.me, Cielo, PagSeguro, chave Pix, certificado
digital A1 e a chave `service_role` do Supabase.

---

## Por que existe

Durante o desenvolvimento é comum colar a chave direto no arquivo para
testar e esquecer. O código vai para o repositório e a chave vai junto.
Há robôs varrendo o GitHub atrás exatamente disso: o intervalo entre
publicar e a chave ser usada por terceiros costuma ser de minutos.

O Fresta encontra essas chaves antes que o código saia da sua máquina e
também no histórico, onde elas continuam mesmo depois de apagadas do
arquivo.

## Instalação

```bash
pip install fresta
```

Requer Python 3.11 ou superior.

## Uso

```bash
fresta scan .                        # varre o diretório atual
fresta scan ./src -m high            # só severidade alta ou acima
fresta scan . -f json                # saída para pipeline
fresta scan . --fail-on critical     # sai com código 1 se achar crítico

fresta history .                     # varre todo o histórico do git
fresta history . -n 100              # só os 100 commits mais recentes
fresta history . -f json
```

O valor do segredo é **sempre mascarado** na saída na tela, no JSON e
em qualquer log.

### Na integração contínua

```bash
fresta scan . --fail-on critical
```

Código de saída `1` quando encontra algo no nível informado, `0` quando
está limpo. É o que barra o merge.

## O que ele detecta

**Globais** AWS, GitHub, Slack, chave privada PEM, JWT, string de
conexão de banco, Google API, Stripe, senha e token em atribuição literal.

**Brasileiros** Mercado Pago, Asaas, Pagar.me/Stone, MerchantKey da
Cielo, token do PagSeguro/PagBank, `service_role` e chave secreta do
Supabase, chave Pix aleatória (EVP) e senha de certificado A1.

A regra do `service_role` merece destaque: essa chave ignora todas as
políticas de Row Level Security do Supabase. Vazada no frontend, expõe o
banco inteiro. Ela é visualmente idêntica à chave `anon`, que é pública e
inofensiva, o Fresta distingue as duas.

## Reduzindo ruído

Ferramenta que grita demais é desinstalada. O Fresta filtra em três
camadas antes de reportar:

- caminhos listados no `.frestaignore`
- valores que são claramente placeholder (`xxxx`, `<your-key>`,
  `${API_KEY}`, `CHANGEME`)
- chaves de exemplo que circulam em documentação oficial

Crie um `.frestaignore` na raiz do projeto:

```
core/tests/fixtures/
**/*.lock
docs/exemplos/
```

## Desenvolvimento

```bash
git clone https://github.com/<usuario>/fresta.git
cd fresta
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Licença

MIT
