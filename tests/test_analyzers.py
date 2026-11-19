import json
from pathlib import Path

from sentinela.analyzers.performance import PerformanceAnalyzer
from sentinela.analyzers.qa import QAAnalyzer
from sentinela.analyzers.security import SecurityAnalyzer
from sentinela.collector import AnalysisContext
from sentinela.models import Analyzer, Severity


def test_qa_does_not_run_tests_without_explicit_opt_in(tmp_path: Path) -> None:
    def forbidden_runner(command: list[str], context: AnalysisContext) -> tuple[int, str, str]:
        raise AssertionError("pytest não deveria ser chamado")

    context = AnalysisContext(root=tmp_path, python_files=())

    assert QAAnalyzer(runner=forbidden_runner).run(context) == []


def test_qa_collects_test_durations_in_one_execution(tmp_path: Path) -> None:
    calls = 0

    def runner(command: list[str], context: AnalysisContext) -> tuple[int, str, str]:
        nonlocal calls
        calls += 1
        assert "--durations=0" in command
        return 0, "1.50s call tests/test_slow.py::test_slow\n", ""

    context = AnalysisContext(root=tmp_path, python_files=(), run_tests=True)

    findings, durations = QAAnalyzer(runner=runner).run_with_durations(context)

    assert findings == []
    assert durations == (("tests/test_slow.py::test_slow", 1.5),)
    assert calls == 1


def test_secret_evidence_is_masked(tmp_path: Path) -> None:
    secret_value = "ghp_" + "A" * 36
    source = tmp_path / "sample.py"
    source.write_text(f'TOKEN = "{secret_value}"\n', encoding="utf-8")
    context = AnalysisContext(root=tmp_path, python_files=(source,))

    findings = SecurityAnalyzer(runner=lambda *_: (127, "", "")).run(context)

    (finding,) = findings
    assert finding.analyzer is Analyzer.SECURITY
    assert finding.raw_severity is Severity.HIGH
    assert secret_value not in finding.evidence
    assert "[SEGREDO:mascarado]" in finding.evidence


def test_bandit_and_pip_audit_commands_are_controlled_by_context(tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def runner(command: list[str], context: AnalysisContext) -> tuple[int, str, str]:
        commands.append(command)
        return 0, "[]", ""

    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    base = AnalysisContext(root=tmp_path, python_files=(source,))
    SecurityAnalyzer(runner=runner).run(base)
    assert [command[0] for command in commands] == ["bandit"]

    commands.clear()
    network = AnalysisContext(root=tmp_path, python_files=(source,), allow_network_audit=True)
    SecurityAnalyzer(runner=runner).run(network)
    assert [command[0] for command in commands] == ["bandit", "pip-audit"]


def test_performance_finds_nested_loops_without_tool_output(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def scan(items):\n    for item in items:\n        for child in item:\n            pass\n",
        encoding="utf-8",
    )
    context = AnalysisContext(root=tmp_path, python_files=(source,))
    analyzer = PerformanceAnalyzer(runner=lambda *_: (127, "", ""))

    findings = analyzer.run(context)

    assert len(findings) == 1
    assert findings[0].rule == "nested-loops-review"
    assert findings[0].line == 3


def test_performance_uses_qa_durations_without_running_pytest_again(tmp_path: Path) -> None:
    def runner(command: list[str], context: AnalysisContext) -> tuple[int, str, str]:
        assert command[0] == "radon"
        return 127, "", ""

    context = AnalysisContext(
        root=tmp_path,
        python_files=(),
        run_tests=True,
        test_durations=(("tests/test_slow.py::test_slow", 2.25),),
    )

    findings = PerformanceAnalyzer(runner=runner).run(context)

    (slow,) = [finding for finding in findings if finding.rule == "slow-test"]
    assert slow.file == "tests/test_slow.py"


def test_performance_parses_radon_json(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def f():\n    return 1\n", encoding="utf-8")
    context = AnalysisContext(root=tmp_path, python_files=(source,))
    payload = json.dumps({"app.py": [{"lineno": 1, "name": "f", "complexity": 12}]})
    analyzer = PerformanceAnalyzer(runner=lambda *_: (0, payload, ""))

    findings = analyzer.run(context)

    assert len(findings) == 1
    assert findings[0].rule == "high-cyclomatic-complexity"
