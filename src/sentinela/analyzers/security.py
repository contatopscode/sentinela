"""Análise de segurança local e ferramentas externas opcionais."""

from __future__ import annotations

import json
import re
from pathlib import Path

from sentinela.analyzers.base import CommandRunner
from sentinela.analyzers.commands import ToolUnavailableError, run_command
from sentinela.collector import AnalysisContext
from sentinela.models import Analyzer, Finding, Severity

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "generic-assignment",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|password)\s*[:=]\s*['\"]([^'\"]{12,})['\"]"),
    ),
)


class SecurityAnalyzer:
    name = "security"

    def __init__(self, runner: CommandRunner = run_command) -> None:
        self.runner = runner

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings = self._scan_secrets(context)
        findings.extend(self._bandit(context))
        if context.allow_network_audit:
            findings.extend(self._pip_audit(context))
        return findings

    def _scan_secrets(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in context.python_files:
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, start=1):
                for rule, pattern in _SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        # Never retain the matching value in Finding evidence.
                        masked = pattern.sub("[SEGREDO:mascarado]", line)
                        findings.append(
                            Finding(
                                id=f"{rule}:{path.relative_to(context.root).as_posix()}:{number}",
                                analyzer=Analyzer.SECURITY,
                                rule=rule,
                                title="Possível segredo embutido no código",
                                file=path.relative_to(context.root).as_posix(),
                                line=number,
                                evidence=masked[:500],
                                raw_severity=Severity.HIGH,
                            )
                        )
                        break
        return findings

    def _bandit(self, context: AnalysisContext) -> list[Finding]:
        try:
            code, stdout, _ = self.runner(["bandit", "-f", "json", "-r", "-q", "."], context)
        except ToolUnavailableError:
            return []
        except TimeoutError:
            return []
        if code not in {0, 1}:
            return []
        try:
            results = json.loads(stdout).get("results", [])
        except (json.JSONDecodeError, AttributeError):
            return []
        findings: list[Finding] = []
        for item in results:
            severity = _severity(item.get("issue_severity"))
            filename = str(item.get("filename", ""))
            try:
                path = Path(filename)
                candidate = (
                    (context.root / path).resolve() if not path.is_absolute() else path.resolve()
                )
                filename = candidate.relative_to(context.root).as_posix()
            except (ValueError, OSError):
                filename = Path(filename).name
            findings.append(
                Finding(
                    id=f"bandit:{item.get('test_id')}:{filename}:{item.get('line_number')}",
                    analyzer=Analyzer.SECURITY,
                    rule=str(item.get("test_id", "bandit")),
                    title=str(item.get("issue_text", "Padrão inseguro"))[:200],
                    file=filename,
                    line=item.get("line_number"),
                    evidence="[conteúdo de código omitido]",
                    raw_severity=severity,
                )
            )
        return findings

    def _pip_audit(self, context: AnalysisContext) -> list[Finding]:
        try:
            code, stdout, _ = self.runner(["pip-audit", "--format", "json"], context)
        except ToolUnavailableError:
            return []
        except TimeoutError:
            return []
        if code not in {0, 1}:
            return []
        try:
            packages = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for package in packages:
            for vulnerability in package.get("vulns", []):
                identifier = str(vulnerability.get("id", "unknown"))
                findings.append(
                    Finding(
                        id=f"pip-audit:{package.get('name')}:{identifier}",
                        analyzer=Analyzer.SECURITY,
                        rule=identifier,
                        title=f"Vulnerabilidade reportada em {package.get('name', 'dependência')}",
                        file="<dependências>",
                        evidence=f"Versão instalada: {package.get('version', 'desconhecida')}",
                        raw_severity=Severity.HIGH,
                    )
                )
        return findings


def _severity(value: object) -> Severity:
    normalized = str(value).lower()
    return {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}.get(
        normalized, Severity.INFO
    )
