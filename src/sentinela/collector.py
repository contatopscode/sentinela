"""Coleta metadados locais sem modificar o repositório analisado."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Diretórios que nunca contêm código do projeto: ambientes, caches e artefatos de build.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "site-packages",
    "node_modules",
    ".tox",
    ".nox",
    ".eggs",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".claude/worktrees",
)


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    root: Path
    python_files: tuple[Path, ...]
    run_tests: bool = False
    allow_network_audit: bool = False
    enabled_analyzers: tuple[str, ...] = ("qa", "security", "performance")
    coverage_file: Path | None = None
    max_findings: int = 200
    max_evidence_chars: int = 1000
    timeout_seconds: int = 120
    test_durations: tuple[tuple[str, float], ...] = ()
    passthrough_env: tuple[str, ...] = ()
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES


def is_excluded(relative: Path, excludes: tuple[str, ...]) -> bool:
    """Compara só o caminho relativo à raiz; nomes simples valem em qualquer nível."""
    parts = relative.parts
    for entry in excludes:
        wanted = tuple(part for part in entry.strip("/").split("/") if part)
        if not wanted:
            continue
        size = len(wanted)
        if size == 1:
            if wanted[0] in parts[:-1]:
                return True
        elif parts[:size] == wanted:
            return True
    return False


def collect_context(
    root: str | Path,
    *,
    run_tests: bool = False,
    allow_network_audit: bool = False,
    enabled_analyzers: tuple[str, ...] = ("qa", "security", "performance"),
    max_findings: int = 200,
    max_evidence_chars: int = 1000,
    timeout_seconds: int = 120,
    passthrough_env: tuple[str, ...] = (),
    extra_excludes: tuple[str, ...] = (),
) -> AnalysisContext:
    """Valida o diretório e lista fontes Python sem seguir symlinks."""
    resolved = Path(root).expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"O caminho não é um diretório: {resolved}")
    excludes = DEFAULT_EXCLUDES + tuple(extra_excludes)
    files = tuple(
        path
        for path in sorted(resolved.rglob("*.py"))
        if not path.is_symlink() and not is_excluded(path.relative_to(resolved), excludes)
    )
    return AnalysisContext(
        root=resolved,
        python_files=files,
        run_tests=run_tests,
        allow_network_audit=allow_network_audit,
        enabled_analyzers=enabled_analyzers,
        max_findings=max_findings,
        max_evidence_chars=max_evidence_chars,
        timeout_seconds=timeout_seconds,
        passthrough_env=passthrough_env,
        excludes=excludes,
    )
