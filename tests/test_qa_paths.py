from pathlib import Path

from sentinela.analyzers.commands import ToolUnavailableError
from sentinela.analyzers.qa import QAAnalyzer
from sentinela.collector import AnalysisContext
from sentinela.models import Finding, Severity


def _qa_with(results: list[tuple[int, str] | type[Exception]]) -> list[Finding]:
    calls = iter(results)

    def runner(command: list[str], context: AnalysisContext) -> tuple[int, str, str]:
        result = next(calls)
        if isinstance(result, type):
            raise result("simulado")
        return result[0], result[1], ""

    context = AnalysisContext(root=Path("."), python_files=(), run_tests=True)
    return QAAnalyzer(runner=runner).run(context)


def test_qa_reports_flaky_suite() -> None:
    (finding,) = _qa_with([(1, ""), (0, "")])
    assert finding.rule == "qa-flaky"


def test_qa_reports_failing_suite() -> None:
    (finding,) = _qa_with([(1, ""), (1, "")])
    assert finding.rule == "qa-failure"
    assert finding.raw_severity is Severity.HIGH


def test_qa_reports_timeout() -> None:
    (finding,) = _qa_with([TimeoutError])
    assert finding.rule == "qa-timeout"


def test_qa_skips_when_pytest_is_missing() -> None:
    assert _qa_with([ToolUnavailableError]) == []
