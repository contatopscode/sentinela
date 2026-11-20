# Sentinela

[![CI](https://github.com/contatopscode/sentinela/actions/workflows/ci.yml/badge.svg)](https://github.com/contatopscode/sentinela/actions/workflows/ci.yml) [![Licença MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)](LICENSE) ![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)

O Sentinela revisa projetos Python com verificações determinísticas de QA, segurança e performance. Um classificador opcional só prioriza achados produzidos por essas ferramentas; o modo `fake` é o padrão e funciona sem chave ou acesso a provedor de modelos.

## Instalação

Requer Python 3.11 ou superior.

```bash
python -m pip install -e ".[analysis]"
sentinela --help
```

Para desenvolver, instale também as ferramentas de qualidade e testes:

```bash
python -m pip install -e ".[dev,openai]"
```

Para habilitar a integração OpenAI, instale o extra opcional `openai`. O identificador do modelo e os preços atuais por mil tokens são configurados por ambiente; nenhum nome de modelo ou endpoint é fixado no código.

## Uso

```bash
# Análise estática local; não executa os testes do projeto analisado
sentinela review /caminho/do/projeto

# Autoriza explicitamente executar testes do projeto analisado
sentinela review /caminho/do/projeto --run-tests

# Autoriza explicitamente consultar a rede para auditar dependências
sentinela review /caminho/do/projeto --network-pip-audit

# Saídas para terminal, integração contínua ou ferramentas SARIF
sentinela review /caminho/do/projeto --format json
sentinela review /caminho/do/projeto --format sarif

# Avaliação local, sem rede e com o classificador fake
sentinela eval

# Imagem não privilegiada; monte o alvo somente para leitura
docker build -t sentinela .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace:ro" sentinela
```

Executar os testes significa executar código do repositório analisado. Use isolamento, como um container, ao revisar código não confiável. O Sentinela não altera esse repositório. A auditoria `pip-audit` é opcional, acessa a rede e só roda com `--network-pip-audit`. Código de teste pode realizar operações próprias; rode-o em ambiente isolado.

Ferramentas externas recebem um ambiente mínimo (`PATH`, `HOME`, locale e diretórios temporários): chaves como `OPENAI_API_KEY` ou `GITHUB_TOKEN` não são repassadas por variável de ambiente ao código analisado. Se os testes do alvo precisarem de alguma variável, autorize-a por nome em `SENTINELA_PASSTHROUGH_ENV` (lista separada por vírgulas). Proxy e certificados só são repassados ao `pip-audit`.

No Markdown, prováveis falsos positivos aparecem agrupados por regra; use `--show-false-positives` para listá-los. JSON e SARIF sempre trazem todos os achados.

### GitHub Action

A Action local publica um único comentário por Pull Request e o atualiza a cada execução. Em PRs de forks, sem permissão de escrita, o relatório fica apenas no resumo do job. O workflow que a chama precisa conceder apenas as permissões indicadas no plano: `contents: read` e `pull-requests: write`.

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v7
    with:
      persist-credentials: false
  - uses: ./
```

Com `persist-credentials: false`, o token do checkout não fica gravado em `.git/config`, onde os testes do alvo poderiam lê-lo.

Por padrão, a Action não executa os testes do alvo nem consulta a rede para advisories. Ative essas opções deliberadamente ao usar os inputs `run-tests` e `audit-dependencies`. Não use `pull_request_target` para executar código de pull requests não confiáveis.

## Analisadores

- **QA:** só roda pytest com `--run-tests`; tenta uma repetição para identificar falhas instáveis e registra arquivos alterados sem linhas cobertas quando `pytest-cov` está instalado.
- **Segurança:** detecta padrões locais de segredos com evidência mascarada; usa Bandit se instalado. `pip-audit` consulta advisories apenas quando explicitamente autorizado na CLI.
- **Performance:** detecta laços aninhados como heurística, usa Radon para complexidade e mede duração de testes durante a execução QA autorizada.

Ferramentas externas ausentes não interrompem os outros analisadores; o relatório mostra avisos. Os analisadores podem ser selecionados por `SENTINELA_ANALYZERS` com uma lista separada por vírgulas (`qa,security,performance`).

## Classificação e privacidade

`SENTINELA_CLASSIFIER` aceita `fake` (padrão) ou `openai`. O modo fake não faz chamadas externas. Para habilitar OpenAI, configure `OPENAI_API_KEY`, `SENTINELA_CLASSIFIER_MODEL`, `SENTINELA_INPUT_COST_PER_1K_USD` e `SENTINELA_OUTPUT_COST_PER_1K_USD`. Os preços devem refletir a tabela atual do provedor. `SENTINELA_MAX_COST_USD` define o teto estimado por execução. A estimativa usa o uso de tokens retornado pelo SDK e uma reserva baseada no tamanho da entrada e no limite de saída; não é uma garantia exata de cobrança.

Antes de qualquer chamada ao modelo, padrões comuns de chaves, tokens, atribuições de credenciais e sequências de alta entropia são mascarados. O trecho enviado é limitado por `SENTINELA_MAX_EVIDENCE_CHARS`. A resposta precisa validar contra o esquema Pydantic e conter exatamente os IDs enviados; respostas inválidas recebem até duas tentativas adicionais. Se ainda forem inválidas, os achados mantêm a severidade original e ficam marcados como não classificados.

`SENTINELA_MAX_FINDINGS`, `SENTINELA_MAX_FINDINGS_PER_CALL`, `SENTINELA_MAX_OUTPUT_TOKENS`, `SENTINELA_TOOL_TIMEOUT_SECONDS`, `SENTINELA_REQUEST_TIMEOUT_SECONDS` e `SENTINELA_MAX_REPORT_CHARS` ajustam os limites do processo e do relatório.

As decisões do modelo podem ser guardadas em cache SQLite local em `~/.cache/sentinela/decisions.sqlite3` (ou no caminho definido por `SENTINELA_CACHE_PATH`). O cache armazena decisões, não texto de código ou evidências. Não configure modo OpenAI se não quiser enviar achados já mascarados ao provedor.

## Avaliação

`eval/` contém 12 casos sintéticos de código, um gabarito e uma execução offline com ferramentas estáticas e o classificador fake. Na execução validada neste ambiente, os analisadores encontraram os resultados esperados nos 12 casos (precisão e cobertura do conjunto: 1,00), com custo externo zero. Latência e percentis são medidos a cada execução por `python eval/run_eval.py`.

O conjunto é pequeno e criado para validar o fluxo local; não representa uma avaliação independente de desempenho em repositórios reais nem mede qualidade de um modelo remoto. O JEV e o explicador ficaram fora desta versão: não há adaptador baseado em documentação verificada para o JEV, e o explicador é opcional no plano.

## Desenvolvimento

```bash
python -m pip install -e ".[dev,openai]"
pre-commit install

ruff check .
ruff format --check .
mypy src
pytest --cov=sentinela   # cobertura mínima: 80%
python eval/run_eval.py
```

O CI roda esses passos em Linux, macOS e Windows, com Python 3.11 a 3.13.

## Contribuindo

Contribuições são bem-vindas! Leia o [guia de contribuição](CONTRIBUTING.md) e o [código de conduta](CODE_OF_CONDUCT.md). Vulnerabilidades devem ser relatadas de forma privada, conforme a [política de segurança](SECURITY.md). As mudanças de cada versão estão no [CHANGELOG](CHANGELOG.md).

Veja [docs/architecture.md](docs/architecture.md) para contratos e limites. As regras do repositório estão em [AGENTS.md](AGENTS.md). O Sentinela é distribuído sob a licença [MIT](LICENSE).
