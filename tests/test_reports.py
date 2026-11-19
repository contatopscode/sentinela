from sentinela.models import Analyzer, Decision, Finding, Report, Severity
from sentinela.report.markdown import render as render_markdown


def test_markdown_identifies_false_positive_and_unclassified_findings() -> None:
    findings = (
        Finding(
            id="known-example",
            analyzer=Analyzer.SECURITY,
            rule="B101",
            title="Exemplo de teste",
            file="tests/test_example.py",
            raw_severity=Severity.LOW,
        ),
        Finding(
            id="unknown",
            analyzer=Analyzer.SECURITY,
            rule="unknown",
            title="Achado não validado",
            file="app.py",
            raw_severity=Severity.HIGH,
        ),
    )
    report = Report(
        summary="Revisão concluída",
        findings=findings,
        decisions=(
            Decision(
                finding_id="known-example",
                severity=Severity.LOW,
                false_positive=True,
                confidence=0.9,
            ),
            Decision(
                finding_id="unknown",
                severity=Severity.HIGH,
                confidence=0,
                classified=False,
            ),
        ),
    )

    output = render_markdown(report)

    assert "possível falso positivo" in output
    assert "não validada" in output


def test_markdown_respects_report_size_limit() -> None:
    report = Report(summary="x" * 1000)

    output = render_markdown(report, max_chars=100)

    assert len(output) <= 100
    assert "truncado pelo limite configurado" in output
