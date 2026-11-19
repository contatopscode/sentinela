"""Análise de performance baseada em complexidade e duração de testes."""

from __future__ import annotations

import ast

from sentinela.analyzers.base import CommandRunner
from sentinela.analyzers.commands import ToolUnavailableError, run_command
from sentinela.collector import AnalysisContext
from sentinela.models import Analyzer, Finding, Severity


class PerformanceAnalyzer:
    name = "performance"

    def __init__(self, runner: CommandRunner = run_command) -> None:
        self.runner = runner

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings = self._complexity(context)
        findings.extend(self._slow_tests(context))
        return findings

    def _complexity(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in context.python_files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                nested_functions = has_nested_loops(source)
            except (OSError, SyntaxError):
                continue
            for line, name in nested_functions:
                relative = str(path.relative_to(context.root))
                findings.append(
                    Finding(
                        id=f"nested-loop:{relative}:{line}:{name}",
                        analyzer=Analyzer.PERFORMANCE,
                        rule="nested-loops-review",
                        title=f"Laços aninhados para revisão em {name}",
                        file=relative,
                        line=line,
                        evidence="Heurística estrutural; revisar custo em tempo de execução.",
                        raw_severity=Severity.INFO,
                    )
                )
        try:
            code, stdout, _ = self.runner(["radon", "cc", "-j", "-n", "C", "."], context)
        except (ToolUnavailableError, TimeoutError):
            return findings
        if code not in {0, 1}:
            return findings
        import json

        try:
            result = json.loads(stdout)
        except json.JSONDecodeError:
            return findings
        for filename, blocks in result.items():
            for block in blocks:
                findings.append(
                    Finding(
                        id=f"radon:{filename}:{block.get('lineno')}:{block.get('name')}",
                        analyzer=Analyzer.PERFORMANCE,
                        rule="high-cyclomatic-complexity",
                        title=f"Complexidade ciclomática elevada em {block.get('name', 'função')}",
                        file=str(filename),
                        line=block.get("lineno"),
                        evidence=f"Complexidade: {block.get('complexity', 'desconhecida')}",
                        raw_severity=Severity.MEDIUM,
                    )
                )
        return findings

    def _slow_tests(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for node, duration in context.test_durations:
            if duration >= 1.0:
                findings.append(
                    Finding(
                        id=f"slow-test:{node}",
                        analyzer=Analyzer.PERFORMANCE,
                        rule="slow-test",
                        title="Teste com duração elevada",
                        file=node.split("::", 1)[0],
                        evidence=f"Duração: {duration:.2f}s",
                        raw_severity=Severity.LOW,
                    )
                )
        return findings


def has_nested_loops(source: str) -> list[tuple[int, str]]:
    """Retorna funções com laços aninhados; heurística local sem alegar custo real."""
    tree = ast.parse(source)
    found: list[tuple[int, str]] = []

    class NestedLoopVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.loop_depth = 0
            self.function_name = "<module>"

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

        def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            previous_name = self.function_name
            previous_depth = self.loop_depth
            self.function_name = node.name
            self.loop_depth = 0
            for statement in node.body:
                self.visit(statement)
            self.function_name = previous_name
            self.loop_depth = previous_depth

        def visit_For(self, node: ast.For) -> None:
            self._visit_loop(node)

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            self._visit_loop(node)

        def visit_While(self, node: ast.While) -> None:
            self._visit_loop(node)

        def _visit_loop(self, node: ast.For | ast.AsyncFor | ast.While) -> None:
            if self.loop_depth:
                found.append((node.lineno, self.function_name))
            self.loop_depth += 1
            for statement in node.body:
                self.visit(statement)
            for statement in node.orelse:
                self.visit(statement)
            self.loop_depth -= 1

    NestedLoopVisitor().visit(tree)
    return found
