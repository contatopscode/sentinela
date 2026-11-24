# Sentinela

[![CI](https://github.com/contatopscode/sentinela/actions/workflows/ci.yml/badge.svg)](https://github.com/contatopscode/sentinela/actions/workflows/ci.yml) [![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)

Sentinela reviews Python projects with deterministic QA, security, and performance checks. For JavaScript and TypeScript projects it currently runs the secret scan only. An optional classifier only prioritizes findings produced by those tools; `fake` is the default and works without an API key or model-provider access.

## Installation

Python 3.11 or newer is required. The package is named `sentinela-review` on PyPI; the command is `sentinela`.

```bash
python -m pip install "sentinela-review[analysis]"
sentinela --help
```

From source:

```bash
python -m pip install -e ".[analysis]"
```

For development, install the quality and test tools as well:

```bash
python -m pip install -e ".[dev,openai]"
```

To enable the OpenAI integration, install the optional `openai` extra. The model identifier and current per-thousand-token prices are configured through the environment; no model name or endpoint is fixed in the code.

## Usage

```bash
# Local static analysis; does not run tests from the reviewed project
sentinela review /path/to/project

# Explicitly authorizes running tests from the reviewed project
sentinela review /path/to/project --run-tests

# Explicitly authorizes a network request to audit dependencies
sentinela review /path/to/project --network-pip-audit

# Terminal, CI, or SARIF output
sentinela review /path/to/project --format json
sentinela review /path/to/project --format sarif

# Local evaluation, with no network and the fake classifier
sentinela eval

# Unprivileged image; mount the target read-only
docker build -t sentinela .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace:ro" sentinela
```

Running tests executes code from the reviewed repository. Use isolation, such as a container, when reviewing untrusted code. Sentinela does not modify that repository. `pip-audit` is optional, accesses the network, and only runs with `--network-pip-audit`. Test code may perform its own operations; run it in an isolated environment.

External tools receive a minimal environment (`PATH`, `HOME`, locale and temp directories): keys such as `OPENAI_API_KEY` or `GITHUB_TOKEN` are not passed to the reviewed code through environment variables. If the target's tests need a variable, allow it by name in `SENTINELA_PASSTHROUGH_ENV` (comma-separated). Proxy and certificate settings are passed to `pip-audit` only.

In Markdown, likely false positives are grouped by rule; use `--show-false-positives` to list them. JSON and SARIF always include every finding.

Virtual environments, `node_modules`, caches and `.git` are skipped. To skip other directories, use `--exclude PATH` (repeatable) or `SENTINELA_EXCLUDE` (comma-separated). A bare name matches at any depth; a path containing `/` is matched from the root.

### GitHub Action

The local Action posts a single pull request comment and updates it on every run. On fork PRs without write permission, the report stays in the job summary only. The calling workflow must grant only the permissions specified in the plan: `contents: read` and `pull-requests: write`.

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

With `persist-credentials: false`, the checkout token is not stored in `.git/config`, where the target's tests could read it.

By default, the Action does not run target tests or query the network for advisories. Enable those options deliberately with the `run-tests` and `audit-dependencies` inputs. Do not use `pull_request_target` to run untrusted pull request code.

## Analyzers

- **QA:** runs pytest only with `--run-tests`; retries once to identify flaky failures and reports changed files with no covered lines when `pytest-cov` is installed.
- **Security:** detects local secret patterns with masked evidence in Python, JavaScript and TypeScript files (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`; not `.d.ts` or `*.min.*`) and uses Bandit when installed. `pip-audit` queries advisories only when explicitly enabled on the CLI.
- **Performance:** detects nested loops as a heuristic, uses Radon for complexity, and measures test durations during an authorized QA run.

Missing external tools do not stop other analyzers; the report includes warnings. Select analyzers with the comma-separated `SENTINELA_ANALYZERS` variable (`qa,security,performance`).

## Classification and privacy

`SENTINELA_CLASSIFIER` accepts `fake` (default) or `openai`. Fake mode makes no external calls. To enable OpenAI, set `OPENAI_API_KEY`, `SENTINELA_CLASSIFIER_MODEL`, `SENTINELA_INPUT_COST_PER_1K_USD`, and `SENTINELA_OUTPUT_COST_PER_1K_USD`. Prices must match the provider's current pricing. `SENTINELA_MAX_COST_USD` sets the per-run estimated budget. The estimate uses token usage returned by the SDK and a reservation based on input size and the output limit; it cannot guarantee the exact billed amount.

Before any model call, common keys, tokens, credential assignments, and high-entropy strings are masked. Sent evidence is limited by `SENTINELA_MAX_EVIDENCE_CHARS`. The response must validate against the Pydantic schema and contain exactly the submitted IDs; invalid responses receive up to two retries. If they remain invalid, the original severity is retained and the finding is marked unclassified.

`SENTINELA_MAX_FINDINGS`, `SENTINELA_MAX_FINDINGS_PER_CALL`, `SENTINELA_MAX_OUTPUT_TOKENS`, `SENTINELA_TOOL_TIMEOUT_SECONDS`, `SENTINELA_REQUEST_TIMEOUT_SECONDS`, and `SENTINELA_MAX_REPORT_CHARS` adjust process and report limits.

Model decisions can be stored in a local SQLite cache at `~/.cache/sentinela/decisions.sqlite3` (or the path set by `SENTINELA_CACHE_PATH`). The cache stores decisions, not code or evidence. Do not enable OpenAI mode if you do not want masked findings sent to the provider.

## Evaluation

`eval/` contains 25 synthetic code cases (Python and TypeScript), expected results, and an offline run using static tools and the fake classifier. In the run validated in this environment, analyzers matched all 25 expected cases (dataset precision and recall: 1.00), with zero external cost. Latency and percentiles are measured on each run by `python eval/run_eval.py`.

This small curated set validates the local workflow; it is not an independent evaluation on real-world repositories and does not measure a remote model's quality. JEV and the explainer are not included in this version: there is no adapter based on verified JEV documentation, and the explainer is optional in the plan.

## Development

```bash
python -m pip install -e ".[dev,openai]"
pre-commit install

ruff check .
ruff format --check .
mypy src
pytest --cov=sentinela   # minimum coverage: 80%
python eval/run_eval.py
```

CI runs these steps on Linux, macOS and Windows with Python 3.11 to 3.13.

## Contributing

Contributions are welcome! Read the [contributing guide](CONTRIBUTING.md) (Portuguese; issues and PRs in English are fine) and the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in the [security policy](SECURITY.md). Release notes are in the [CHANGELOG](CHANGELOG.md).

See [docs/architecture.md](docs/architecture.md) for contracts and limits. Repository rules are in [AGENTS.md](AGENTS.md). Sentinela is distributed under the [MIT License](LICENSE).
