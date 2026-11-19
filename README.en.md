# Sentinela

Sentinela reviews Python projects with deterministic QA, security, and performance checks. An optional classifier only prioritizes findings produced by those tools; `fake` is the default and works without an API key or model-provider access.

## Installation

Python 3.11 or newer is required.

```bash
python -m pip install -e ".[analysis]"
sentinela --help
```

For development, install the quality and test tools as well:

```bash
python -m pip install -e ".[dev]"
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

### GitHub Action

The local Action can post a pull request comment. The calling workflow must grant only the permissions specified in the plan: `contents: read` and `pull-requests: write`.

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  - uses: ./
```

By default, the Action does not run target tests or query the network for advisories. Enable those options deliberately with the `run-tests` and `audit-dependencies` inputs. Do not use `pull_request_target` to run untrusted pull request code.

## Analyzers

- **QA:** runs pytest only with `--run-tests`; retries once to identify flaky failures and reports changed files with no covered lines when `pytest-cov` is installed.
- **Security:** detects local secret patterns with masked evidence and uses Bandit when installed. `pip-audit` queries advisories only when explicitly enabled on the CLI.
- **Performance:** detects nested loops as a heuristic, uses Radon for complexity, and measures test durations during an authorized QA run.

Missing external tools do not stop other analyzers; the report includes warnings. Select analyzers with the comma-separated `SENTINELA_ANALYZERS` variable (`qa,security,performance`).

## Classification and privacy

`SENTINELA_CLASSIFIER` accepts `fake` (default) or `openai`. Fake mode makes no external calls. To enable OpenAI, set `OPENAI_API_KEY`, `SENTINELA_CLASSIFIER_MODEL`, `SENTINELA_INPUT_COST_PER_1K_USD`, and `SENTINELA_OUTPUT_COST_PER_1K_USD`. Prices must match the provider's current pricing. `SENTINELA_MAX_COST_USD` sets the per-run estimated budget. The estimate uses token usage returned by the SDK and a reservation based on input size and the output limit; it cannot guarantee the exact billed amount.

Before any model call, common keys, tokens, credential assignments, and high-entropy strings are masked. Sent evidence is limited by `SENTINELA_MAX_EVIDENCE_CHARS`. The response must validate against the Pydantic schema and contain exactly the submitted IDs; invalid responses receive up to two retries. If they remain invalid, the original severity is retained and the finding is marked unclassified.

`SENTINELA_MAX_FINDINGS`, `SENTINELA_MAX_FINDINGS_PER_CALL`, `SENTINELA_MAX_OUTPUT_TOKENS`, `SENTINELA_TOOL_TIMEOUT_SECONDS`, `SENTINELA_REQUEST_TIMEOUT_SECONDS`, and `SENTINELA_MAX_REPORT_CHARS` adjust process and report limits.

Model decisions can be stored in a local SQLite cache at `~/.cache/sentinela/decisions.sqlite3` (or the path set by `SENTINELA_CACHE_PATH`). The cache stores decisions, not code or evidence. Do not enable OpenAI mode if you do not want masked findings sent to the provider.

## Evaluation

`eval/` contains 12 synthetic code cases, expected results, and an offline run using static tools and the fake classifier. In the run validated in this environment, analyzers matched all 12 expected cases (dataset precision and recall: 1.00), with zero external cost. Latency and percentiles are measured on each run by `python eval/run_eval.py`.

This small curated set validates the local workflow; it is not an independent evaluation on real-world repositories and does not measure a remote model's quality. JEV and the explainer are not included in this version: there is no adapter based on verified JEV documentation, and the explainer is optional in the plan.

## Development

```bash
pytest
ruff check .
ruff format --check .
mypy src
python eval/run_eval.py
```

See [docs/architecture.md](docs/architecture.md) for contracts and limits. Repository rules are in [AGENTS.md](AGENTS.md). The license choice is pending; no license has been assumed.
