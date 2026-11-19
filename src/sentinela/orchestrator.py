"""Orquestra análises locais e classifica achados."""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from time import monotonic

from sentinela.analyzers.base import Analyzer
from sentinela.analyzers.commands import ToolUnavailableError, find_executable, run_command
from sentinela.analyzers.performance import PerformanceAnalyzer
from sentinela.analyzers.qa import QAAnalyzer
from sentinela.analyzers.security import SecurityAnalyzer
from sentinela.classify.base import Classifier
from sentinela.collector import AnalysisContext
from sentinela.guardrails import cap_findings
from sentinela.models import ExecutionMetadata, Finding, Report


def review(context: AnalysisContext, classifier: Classifier | None = None) -> Report:
    started = monotonic()
    tools_warnings: list[str] = []
    analyzers: list[Analyzer] = []
    factories: dict[str, Analyzer] = {
        "qa": QAAnalyzer(),
        "security": SecurityAnalyzer(),
        "performance": PerformanceAnalyzer(_warning_runner(tools_warnings)),
    }
    for name in context.enabled_analyzers:
        analyzer = factories[name]
        analyzers.append(analyzer)
        commands = {"qa": ("pytest",), "security": ("bandit",), "performance": ("radon",)}
        for executable in commands[name]:
            if (name != "qa" or context.run_tests) and find_executable(executable) is None:
                tools_warnings.append(f"Ferramenta opcional ausente: {executable}")
    if (
        "qa" in context.enabled_analyzers
        and context.run_tests
        and importlib.util.find_spec("pytest_cov") is None
    ):
        tools_warnings.append(
            "Cobertura indisponível: instale pytest-cov para medir arquivos sem cobertura"
        )
    if (
        "security" in context.enabled_analyzers
        and context.allow_network_audit
        and find_executable("pip-audit") is None
    ):
        tools_warnings.append("Ferramenta opcional ausente: pip-audit")
    findings: list[Finding] = []

    if "qa" in context.enabled_analyzers and context.run_tests:
        try:
            qa_findings, durations = QAAnalyzer().run_with_durations(context)
            findings.extend(qa_findings)
            context = replace(context, test_durations=durations)
        except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
            tools_warnings.append(f"Analisador qa falhou: {type(exc).__name__}")

    remaining = [analyzer for analyzer in analyzers if analyzer.name != "qa"]
    with ThreadPoolExecutor(max_workers=max(1, len(remaining))) as pool:
        futures = {pool.submit(analyzer.run, context): analyzer.name for analyzer in remaining}
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
                # Falha isolada não impede os outros analisadores.
                tools_warnings.append(f"Analisador {futures[future]} falhou: {type(exc).__name__}")

    findings, limit_warning = cap_findings(findings, context.max_findings)
    if limit_warning:
        tools_warnings.append(limit_warning)

    selected_classifier: Classifier
    if classifier is None:
        from sentinela.classify.fake import FakeClassifier

        selected_classifier = FakeClassifier()
    else:
        selected_classifier = classifier
    decisions = selected_classifier.classify(findings)
    unclassified = sum(not item.classified for item in decisions)
    if unclassified:
        tools_warnings.append(f"{unclassified} achado(s) ficaram sem classificação validada.")
    estimated_cost = float(getattr(selected_classifier, "estimated_cost_usd", 0))
    input_tokens = int(getattr(selected_classifier, "input_tokens", 0))
    output_tokens = int(getattr(selected_classifier, "output_tokens", 0))
    model = getattr(selected_classifier, "model", None)
    return Report(
        summary=f"Revisão concluída: {len(findings)} achado(s) em {len(analyzers)} analisador(es).",
        findings=tuple(findings),
        decisions=tuple(decisions),
        warnings=tuple(sorted(set(tools_warnings))),
        metadata=ExecutionMetadata(
            duration_seconds=monotonic() - started,
            models_used=(model,) if isinstance(model, str) else (),
            tokens_used=input_tokens + output_tokens,
            estimated_cost_usd=estimated_cost,
        ),
    )


def _warning_runner(
    warnings: list[str],
) -> Callable[[list[str], AnalysisContext], tuple[int, str, str]]:
    def run(command: list[str], command_context: AnalysisContext) -> tuple[int, str, str]:
        try:
            return run_command(command, command_context)
        except ToolUnavailableError:
            warnings.append(f"Ferramenta opcional ausente: {command[0]}")
            raise

    return run
