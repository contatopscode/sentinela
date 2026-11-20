from pathlib import Path

import pytest

from sentinela.cli import main
from sentinela.models import Analyzer, Decision, Finding, Report, Severity
from sentinela.report.markdown import render as render_markdown


def _finding(identifier: str, rule: str, severity: Severity, file: str = "app.py") -> Finding:
    return Finding(
        id=identifier,
        analyzer=Analyzer.SECURITY,
        rule=rule,
        title=f"Título {identifier}",
        file=file,
        raw_severity=severity,
    )


def _report() -> Report:
    findings = (
        _finding("low", "B603", Severity.LOW),
        _finding("high", "B324", Severity.HIGH),
        _finding("fp-1", "B101", Severity.LOW, "tests/test_a.py"),
        _finding("fp-2", "B101", Severity.LOW, "tests/test_b.py"),
    )
    decisions = tuple(
        Decision(
            finding_id=item.id,
            severity=item.raw_severity,
            false_positive=item.id.startswith("fp"),
            confidence=1,
        )
        for item in findings
    )
    return Report(summary="Revisão concluída", findings=findings, decisions=decisions)


def test_markdown_groups_false_positives_and_sorts_by_severity() -> None:
    output = render_markdown(_report())

    assert output.index("Título high") < output.index("Título low")
    assert "| high | 1 |" in output
    assert "Prováveis falsos positivos (2)" in output
    assert "`B101` (security): 2 ocorrência(s)" in output
    assert "Título fp-1" not in output


def test_markdown_can_list_false_positives() -> None:
    output = render_markdown(_report(), show_false_positives=True)

    assert "Título fp-1" in output
    assert "Título fp-2" in output


def test_markdown_with_only_false_positives_has_no_severity_table() -> None:
    finding = _finding("fp", "B101", Severity.LOW, "tests/test_a.py")
    report = Report(
        summary="Revisão concluída",
        findings=(finding,),
        decisions=(
            Decision(finding_id="fp", severity=Severity.LOW, false_positive=True, confidence=1),
        ),
    )

    output = render_markdown(report)

    assert "Nenhum achado que exija ação." in output
    assert "| Severidade |" not in output


def test_cli_wires_show_false_positives_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_config.py").write_text('password = "exemplo-de-teste"\n', encoding="utf-8")
    monkeypatch.setenv("SENTINELA_ANALYZERS", "security")
    monkeypatch.delenv("SENTINELA_CLASSIFIER", raising=False)

    assert main(["review", str(tmp_path)]) == 0
    grouped = capsys.readouterr().out
    assert main(["review", str(tmp_path), "--show-false-positives"]) == 0
    listed = capsys.readouterr().out

    assert "`generic-assignment` (security): 1 ocorrência(s)" in grouped
    assert "tests/test_config.py" not in grouped
    assert "tests/test_config.py" in listed
