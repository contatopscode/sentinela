"""Análise de QA: testes explícitos e duração por caso."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

from sentinela.analyzers.base import CommandRunner
from sentinela.analyzers.commands import ToolUnavailableError, run_command
from sentinela.collector import AnalysisContext
from sentinela.models import Analyzer, Finding, Severity


class QAAnalyzer:
    name = "qa"

    def __init__(self, runner: CommandRunner = run_command) -> None:
        self.runner = runner

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings, _ = self.run_with_durations(context)
        return findings

    def run_with_durations(
        self, context: AnalysisContext
    ) -> tuple[list[Finding], tuple[tuple[str, float], ...]]:
        if not context.run_tests:
            return [], ()
        if importlib.util.find_spec("pytest_cov") is None:
            # Testes ainda rodam mesmo sem o plugin de cobertura. A indisponibilidade
            # da cobertura não deve transformar um erro de importação em falha da suíte.
            coverage_enabled = False
        else:
            coverage_enabled = True
        findings: list[Finding] = []
        durations: tuple[tuple[str, float], ...] = ()
        with tempfile.TemporaryDirectory(prefix="sentinela-qa-") as temp_dir:
            junit = Path(temp_dir) / "results.xml"
            coverage_json = Path(temp_dir) / "coverage.json"
            command = ["pytest", "--junitxml", str(junit), "--durations=0", "-q"]
            if coverage_enabled:
                command.extend(["--cov", f"--cov-report=json:{coverage_json}"])
            command.extend(["-p", "no:cacheprovider"])
            command_context = replace(
                context,
                coverage_file=Path(temp_dir) / ".coverage",
            )
            try:
                code, stdout, _ = self.runner(command, command_context)
            except ToolUnavailableError:
                return [], ()
            except TimeoutError:
                return [
                    self._finding(
                        "qa-timeout", "pytest excedeu o limite de tempo", None, Severity.HIGH
                    )
                ], ()
            durations = _parse_durations(stdout)

            if code != 0:
                try:
                    retry_code, retry_stdout, _ = self.runner(command, command_context)
                except TimeoutError:
                    retry_code = 124
                    retry_stdout = ""
                durations = _parse_durations(retry_stdout or stdout)
                if retry_code == 0:
                    findings.append(
                        self._finding(
                            "qa-flaky",
                            "Um ou mais testes falharam e passaram na repetição",
                            None,
                            Severity.MEDIUM,
                        )
                    )
                else:
                    findings.append(
                        self._finding(
                            "qa-failure",
                            "A suíte pytest falhou",
                            None,
                            Severity.HIGH,
                            f"pytest retornou código {code}; detalhes omitidos.",
                        )
                    )

            if coverage_json.exists():
                findings.extend(self._uncovered_findings(coverage_json, context))
        return findings, durations

    def _uncovered_findings(self, coverage_json: Path, context: AnalysisContext) -> list[Finding]:
        """Reporta fontes alteradas sem linhas cobertas."""
        try:
            coverage = json.loads(coverage_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        changed = _changed_python_files(context)
        findings: list[Finding] = []
        for filename, details in coverage.get("files", {}).items():
            path = Path(filename)
            try:
                candidate = (
                    (context.root / path).resolve() if not path.is_absolute() else path.resolve()
                )
                relative = candidate.relative_to(context.root).as_posix()
            except (ValueError, OSError):
                relative = filename
            if relative not in changed:
                continue
            summary = details.get("summary", {})
            if summary.get("covered_lines", 0) == 0:
                findings.append(
                    self._finding(
                        f"qa-uncovered-file:{relative}",
                        "Arquivo Python alterado sem linhas cobertas",
                        relative,
                        Severity.MEDIUM,
                    )
                )
        return findings

    @staticmethod
    def _finding(
        rule: str,
        title: str,
        file: str | None,
        severity: Severity,
        evidence: str = "",
    ) -> Finding:
        return Finding(
            id=rule,
            analyzer=Analyzer.QA,
            rule=rule,
            title=title,
            file=file or "<execução>",
            evidence=evidence,
            raw_severity=severity,
        )


def _changed_python_files(context: AnalysisContext) -> set[str]:
    commands = [
        ["git", "diff", "--name-only", "--diff-filter=ACMRT", "HEAD"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    ]
    paths: set[str] = set()
    for command in commands:
        try:
            result = subprocess.run(
                command,
                cwd=context.root,
                capture_output=True,
                text=True,
                timeout=min(context.timeout_seconds, 10),
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            paths.update(line for line in result.stdout.splitlines() if line.endswith(".py"))
    return paths


def _parse_durations(output: str) -> tuple[tuple[str, float], ...]:
    return tuple(
        (node, float(duration))
        for duration, node in re.findall(r"([0-9]+\.[0-9]+)s\s+call\s+(.+)", output)
    )
