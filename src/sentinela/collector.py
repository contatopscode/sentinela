"""Coleta metadados locais sem modificar o repositório analisado."""

from __future__ import annotations

import os
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
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
)

# Fontes JavaScript e TypeScript; por ora só a varredura de segredos as lê.
SCRIPT_SUFFIXES: frozenset[str] = frozenset(
    {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
)


def is_script_source(path: Path) -> bool:
    """Declarações de tipo e bundles minificados não são código escrito no projeto."""
    name = path.name
    if name.endswith((".d.ts", ".d.mts", ".d.cts")) or ".min." in name:
        return False
    return path.suffix in SCRIPT_SUFFIXES


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    root: Path
    python_files: tuple[Path, ...]
    script_files: tuple[Path, ...] = ()
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
    """Valida o diretório e lista fontes Python, JavaScript e TypeScript sem seguir symlinks."""
    resolved = Path(root).expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"O caminho não é um diretório: {resolved}")
    excludes = DEFAULT_EXCLUDES + tuple(extra_excludes)
    python_files: list[Path] = []
    script_files: list[Path] = []
    for directory, dirnames, filenames in os.walk(resolved):
        base = Path(directory)
        relative_dir = base.relative_to(resolved)
        # Poda diretórios excluídos antes de descer (node_modules pode ter milhares de arquivos).
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not (base / name).is_symlink()
            and not is_excluded(relative_dir / name / "_", excludes)
        )
        for filename in filenames:
            path = base / filename
            if path.suffix != ".py" and not is_script_source(path):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            if is_excluded(path.relative_to(resolved), excludes):
                continue
            (python_files if path.suffix == ".py" else script_files).append(path)
    return AnalysisContext(
        root=resolved,
        python_files=tuple(sorted(python_files)),
        script_files=tuple(sorted(script_files)),
        run_tests=run_tests,
        allow_network_audit=allow_network_audit,
        enabled_analyzers=enabled_analyzers,
        max_findings=max_findings,
        max_evidence_chars=max_evidence_chars,
        timeout_seconds=timeout_seconds,
        passthrough_env=passthrough_env,
        excludes=excludes,
    )
