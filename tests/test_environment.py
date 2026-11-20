import json
import sys
from pathlib import Path

import pytest

from sentinela.analyzers.commands import ToolUnavailableError, child_environment, run_command
from sentinela.collector import AnalysisContext
from sentinela.config import load_settings

_FAKE_ENV = {
    "PATH": "/usr/bin",
    "HOME": "/home/teste",
    "OPENAI_API_KEY": "valor-de-teste",
    "GITHUB_TOKEN": "valor-de-teste",
    "HTTPS_PROXY": "http://proxy.invalid:3128",
    "CUSTOM_VAR": "x",
}


def _child_env(command_name: str, context: AnalysisContext) -> dict[str, str]:
    code, stdout, _ = run_command(
        [command_name, "-c", "import json, os; print(json.dumps(dict(os.environ)))"], context
    )
    assert code == 0
    result: dict[str, str] = json.loads(stdout)
    return result


def test_child_environment_drops_credentials() -> None:
    environment = child_environment("pytest", source=_FAKE_ENV)

    assert environment["PATH"] == "/usr/bin"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert "OPENAI_API_KEY" not in environment
    assert "GITHUB_TOKEN" not in environment
    assert "HTTPS_PROXY" not in environment
    assert "CUSTOM_VAR" not in environment


def test_child_environment_honors_explicit_passthrough() -> None:
    environment = child_environment("pytest", ("CUSTOM_VAR",), source=_FAKE_ENV)

    assert environment["CUSTOM_VAR"] == "x"
    assert "OPENAI_API_KEY" not in environment


def test_network_settings_only_reach_network_tools() -> None:
    assert "HTTPS_PROXY" in child_environment("pip-audit", source=_FAKE_ENV)
    assert "HTTPS_PROXY" not in child_environment("bandit", source=_FAKE_ENV)


def test_run_command_does_not_leak_parent_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "valor-de-teste")
    context = AnalysisContext(root=tmp_path, python_files=())

    assert "OPENAI_API_KEY" not in _child_env("python", context)


def test_run_command_preserves_coverage_file(tmp_path: Path) -> None:
    context = AnalysisContext(root=tmp_path, python_files=(), coverage_file=tmp_path / ".coverage")

    assert _child_env("python", context)["COVERAGE_FILE"] == str(tmp_path / ".coverage")


def test_run_command_passes_proxy_only_to_pip_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setattr(
        "sentinela.analyzers.commands.find_executable", lambda _name: sys.executable
    )
    context = AnalysisContext(root=tmp_path, python_files=())

    assert _child_env("pip-audit", context)["HTTPS_PROXY"] == "http://proxy.invalid:3128"
    assert "HTTPS_PROXY" not in _child_env("pytest", context)


def test_run_command_reports_missing_tool(tmp_path: Path) -> None:
    context = AnalysisContext(root=tmp_path, python_files=())

    with pytest.raises(ToolUnavailableError):
        run_command(["ferramenta-inexistente-sentinela"], context)


def test_run_command_enforces_timeout(tmp_path: Path) -> None:
    context = AnalysisContext(root=tmp_path, python_files=(), timeout_seconds=1)

    with pytest.raises(TimeoutError, match="excedeu"):
        run_command(["python", "-c", "import time; time.sleep(5)"], context)


def test_passthrough_setting_is_parsed_and_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELA_PASSTHROUGH_ENV", "DATABASE_URL, APP_MODE")
    assert load_settings().passthrough_env == ("DATABASE_URL", "APP_MODE")

    monkeypatch.setenv("SENTINELA_PASSTHROUGH_ENV", "NOME INVALIDO")
    with pytest.raises(ValueError, match="SENTINELA_PASSTHROUGH_ENV"):
        load_settings()
