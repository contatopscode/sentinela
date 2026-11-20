"""Coleta metadados locais sem modificar o repositório analisado."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
) -> AnalysisContext:
    """Valida o diretório e lista fontes Python sem seguir symlinks."""
    resolved = Path(root).expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"O caminho não é um diretório: {resolved}")
    files = tuple(
        path
        for path in sorted(resolved.rglob("*.py"))
        if not any(
            part in {".git", ".venv", "venv", "__pycache__", "site-packages"} for part in path.parts
        )
        and not path.is_symlink()
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
    )
