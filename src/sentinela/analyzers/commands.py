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
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if context.coverage_file is not None:
        environment["COVERAGE_FILE"] = str(context.coverage_file)
    try:
        result = subprocess.run(
            argv,
            cwd=context.root,
            capture_output=True,
            text=True,
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
