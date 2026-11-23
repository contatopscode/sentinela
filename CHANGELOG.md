# Changelog

Todas as mudanças relevantes deste projeto são registradas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto adota o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não publicado]

### Adicionado

- Opção `--exclude` (repetível) e variável `SENTINELA_EXCLUDE` (lista separada por vírgulas) para ignorar diretórios.
- Novas exclusões padrão: `node_modules`, `.tox`, `.nox`, `.eggs`, caches de ferramentas e `.claude/worktrees`.
- Eval ampliado de 12 para 22 casos (segredos, SQL, YAML, TLS, controles negativos e regressão de exclusões), com métricas por regra.
- Integração com o code scanning do GitHub: inputs `upload-sarif` e `exclude` e output `sarif-file` na Action, além de um workflow que revisa o próprio repositório.
- Opção `--sarif-output` para gravar o SARIF junto com o relatório principal.

### Alterado

- SARIF passa a incluir `$schema`, versão da ferramenta, descrições e ajuda das regras, `ruleIndex`, tags e `security-severity` nas regras de segurança. Achados sem arquivo viram notificações da execução, e achados de arquivo inteiro apontam para a linha 1.

### Corrigido

- Exclusões passam a valer só sobre o caminho relativo à raiz analisada; antes, uma pasta `venv` acima do projeto fazia todos os arquivos serem ignorados.
- O Bandit recebe as mesmas exclusões do coletor; antes varria a raiz inteira.
- `sentinela eval` explica que o eval só existe em um clone do repositório, em vez de falhar com erro de arquivo.

## [0.2.0] - 2026-11-20

### Adicionado

- `SENTINELA_PASSTHROUGH_ENV` para autorizar, por nome, variáveis repassadas às ferramentas externas.
- Opção `--show-false-positives` para listar cada provável falso positivo no relatório Markdown.
- Tabela de contagem por severidade no relatório Markdown.
- Licença MIT, guia de contribuição, política de segurança, código de conduta e templates de issue e pull request.
- CI em Linux, macOS e Windows com Python 3.11 a 3.13, cobertura mínima de 80% e verificação do pacote.
- Workflow de release com publicação no PyPI por trusted publishing.
- Dependabot e configuração de pre-commit.
- Marcador `py.typed` para consumidores com verificação de tipos.

### Alterado

- O pacote passa a ser distribuído no PyPI como `sentinela-review`; o comando e o módulo continuam `sentinela`.
- Ferramentas externas recebem um ambiente mínimo; credenciais do processo pai não chegam mais ao código analisado.
- Prováveis falsos positivos aparecem agrupados por regra no relatório Markdown.
- A GitHub Action mantém um único comentário por pull request e não falha em PRs de forks.

### Corrigido

- Caminhos dos achados no formato POSIX também no Windows (SARIF, falsos positivos e arquivos alterados no QA).

## [0.1.0] - 2026-11-19

### Adicionado

- Primeira versão: analisadores de QA, segurança e performance, classificador `fake` e OpenAI opcional, relatórios Markdown, JSON e SARIF, avaliação offline e GitHub Action.

[Não publicado]: https://github.com/contatopscode/sentinela/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/contatopscode/sentinela/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/contatopscode/sentinela/releases/tag/v0.1.0
