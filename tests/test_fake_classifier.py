from sentinela.classify.fake import FakeClassifier
from sentinela.models import Analyzer, Finding, Severity


def test_fake_classifier_preserves_input_order_and_severity() -> None:
    findings = [
        Finding(
            id="finding-1",
            analyzer=Analyzer.SECURITY,
            rule="example",
            title="Achado de exemplo",
            file="app.py",
            raw_severity=Severity.HIGH,
        ),
        Finding(
            id="finding-2",
            analyzer=Analyzer.QA,
            rule="example-test",
            title="Falha de teste",
            file="test_app.py",
            line=12,
            raw_severity=Severity.MEDIUM,
        ),
    ]

    decisions = FakeClassifier().classify(findings)

    assert [decision.finding_id for decision in decisions] == ["finding-1", "finding-2"]
    assert [decision.severity for decision in decisions] == [Severity.HIGH, Severity.MEDIUM]
    assert all(decision.confidence == 1 for decision in decisions)
    assert [decision.false_positive for decision in decisions] == [False, True]


def test_fake_classifier_accepts_empty_batch() -> None:
    assert FakeClassifier().classify([]) == []
