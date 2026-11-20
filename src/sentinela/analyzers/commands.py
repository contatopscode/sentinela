"""Execução limitada de ferramentas externas."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from sentinela.collector import AnalysisContext


class ToolUnavailableError(RuntimeError):
    """A ferramenta solicitada não está instalada."""


# Variáveis necessárias para localizar ferramentas e interpretar texto. Nada que
# costume carregar credenciais: o código do repositório analisado roda com este
# ambiente quando os testes são autorizados.
_BASE_ENVIRONMENT = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TZ",
        "TMPDIR",
        "TEMP",
        "TMP",
        # Interpretadores e ambientes Python (venv, pyenv, conda, toolcache do CI).
        "VIRTUAL_ENV",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONUTF8",
        "PYENV_ROOT",
        "PYENV_VERSION",
        "CONDA_PREFIX",
        "CONDA_DEFAULT_ENV",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        # Windows: sem estes, Path.home() e ferramentas do sistema falham.
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATHEXT",
        "WINDIR",
        "USERPROFILE",
        "USERNAME",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
    }
)

# Somente ferramentas que consultam a rede por autorização explícita recebem
# configuração de proxy e certificados, que pode conter credenciais.
_NETWORK_ENVIRONMENT = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PIP_CERT",
    }
)
_NETWORK_TOOLS = frozenset({"pip-audit"})


def child_environment(
    tool: str,
    passthrough: tuple[str, ...] = (),
    source: dict[str, str] | None = None,
) -> dict[str, str]:
    """Monta o ambiente mínimo de um processo externo, sem herdar segredos."""
    origin = dict(os.environ) if source is None else source
    allowed = set(_BASE_ENVIRONMENT) | set(passthrough)
    if tool in _NETWORK_TOOLS:
        allowed |= _NETWORK_ENVIRONMENT
    environment = {name: value for name, value in origin.items() if name in allowed}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def find_executable(name: str) -> str | None:
    """Procura no PATH e ao lado do interpretador Python ativo."""
    found = shutil.which(name)
    if found is not None:
        return found
    sibling = Path(sys.executable).parent / name
    return str(sibling) if sibling.is_file() else None


def run_command(command: list[str], context: AnalysisContext) -> tuple[int, str, str]:
    executable = find_executable(command[0])
    if executable is None:
        raise ToolUnavailableError(command[0])
    argv = [executable, *command[1:]]
    environment = child_environment(command[0], context.passthrough_env)
    if context.coverage_file is not None:
        environment["COVERAGE_FILE"] = str(context.coverage_file)
    try:
        result = subprocess.run(
            argv,
            cwd=context.root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=context.timeout_seconds,
            check=False,
            shell=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else exc.stdout or ""
        )
        stderr = (
            exc.stderr.decode(errors="replace")
            if isinstance(exc.stderr, bytes)
            else exc.stderr or ""
        )
        raise TimeoutError(
            f"Comando excedeu {context.timeout_seconds}s: {command[0]}\n{stdout}\n{stderr}"
        ) from exc
    return result.returncode, result.stdout, result.stderr
