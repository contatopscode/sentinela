# Como contribuir

Obrigado pelo interesse no Sentinela! Contribuições de código, documentação, casos de avaliação e relatos de bugs são bem-vindas.

_English speakers: issues and pull requests in English are welcome too._

## Antes de começar

- Leia as [regras do repositório](AGENTS.md). As principais: nada de segredos ou dados de terceiros no código e no histórico; tudo configurável por variável de ambiente; o projeto inteiro roda e testa sem chave de API.
- Para mudanças grandes, abra uma issue antes, para alinhar a abordagem.
- Vulnerabilidades **não** devem ir para issues públicas. Veja [SECURITY.md](SECURITY.md).

## Ambiente de desenvolvimento

Requer Python 3.11 ou superior.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
pre-commit install
```

## Antes de abrir o pull request

Rode os mesmos gates do CI:

```bash
ruff check .
ruff format --check .
mypy src
pytest --cov=sentinela          # cobertura mínima: 80%
python eval/run_eval.py
```

- Toda mudança de comportamento vem com teste.
- Novos analisadores ou regras devem ganhar um caso em `eval/cases/` e uma entrada em `eval/expected.yaml`.
- Atualize o [CHANGELOG.md](CHANGELOG.md) na seção `Não publicado`.
- Mudanças visíveis ao usuário atualizam o `README.md` e o `README.en.md`.

## Commits e pull requests

- Commits pequenos, com mensagem clara em português, no imperativo da 3ª pessoa: "Adiciona…", "Corrige…".
- Um pull request por assunto. Descreva o que muda, por que e como foi testado.
- O CI precisa passar em Linux, macOS e Windows.

## Versionamento e releases

O projeto segue o [Versionamento Semântico](https://semver.org/lang/pt-BR/). Para publicar uma versão, o mantenedor:

1. atualiza `version` no `pyproject.toml` e move as entradas de `Não publicado` para a nova versão no `CHANGELOG.md`;
2. cria a tag `vX.Y.Z` no commit da `main`;
3. o workflow `Release` confere a tag, gera o pacote e publica no PyPI por trusted publishing.

## Código de conduta

Ao participar, você concorda com o [Código de Conduta](CODE_OF_CONDUCT.md).
