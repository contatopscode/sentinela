import hashlib
import json
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

from sentinela.classify.cache import CachingClassifier
from sentinela.classify.openai_classifier import DecisionBatch, OpenAIClassifier
from sentinela.classify.router import BudgetedClassifier
from sentinela.collector import AnalysisContext
from sentinela.guardrails import cap_findings
from sentinela.masking import mask_finding, mask_text
from sentinela.models import Analyzer, Decision, Finding, Report, Severity
from sentinela.report.sarif import render as render_sarif


def _finding(identifier: str = "finding-1", evidence: str = "") -> Finding:
    return Finding(
        id=identifier,
        analyzer=Analyzer.SECURITY,
        rule="example-rule",
        title="Finding title",
        file="sample.py",
        line=3,
        evidence=evidence,
        raw_severity=Severity.HIGH,
    )


class FakeResponses:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    def parse(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self.responses.pop(0)


def test_openai_classifier_masks_before_request_and_validates_response() -> None:
    secret_text = "password='local-demo-value-123'"
    safe_id = f"finding-0-{hashlib.sha256(b'finding-1').hexdigest()[:16]}"
    decision = Decision(finding_id=safe_id, severity=Severity.MEDIUM, confidence=0.8)
    parsed = DecisionBatch(decisions=[decision])
    response = SimpleNamespace(
        output_parsed=parsed,
        usage=SimpleNamespace(input_tokens=21, output_tokens=8),
    )
    responses = FakeResponses([response])
    classifier = OpenAIClassifier(
        model="configured-model",
        client=SimpleNamespace(responses=responses),
    )

    decisions = classifier.classify([_finding(evidence=secret_text)])

    request = responses.calls[0]
    assert request["model"] == "configured-model"
    assert request["text_format"] is DecisionBatch
    assert request["store"] is False
    assert "local-demo-value-123" not in str(request["input"])
    assert "[SEGREDO:mascarado]" in str(request["input"])
    assert decisions[0].severity is Severity.MEDIUM
    assert classifier.input_tokens == 21
    assert classifier.output_tokens == 8


def test_openai_classifier_retries_invalid_output_twice_then_marks_unclassified() -> None:
    responses = FakeResponses(
        [
            SimpleNamespace(output_parsed=None, usage=None),
            SimpleNamespace(output_parsed=None, usage=None),
            SimpleNamespace(output_parsed=None, usage=None),
        ]
    )
    classifier = OpenAIClassifier(
        model="configured-model",
        client=SimpleNamespace(responses=responses),
    )

    (decision,) = classifier.classify([_finding()])

    assert len(responses.calls) == 3
    assert decision.confidence == 0
    assert decision.classified is False
    assert decision.severity is Severity.HIGH


def test_openai_classifier_does_not_send_local_finding_ids() -> None:
    local_id = "password='local-demo-value-123'"
    safe_id = f"finding-0-{hashlib.sha256(local_id.encode()).hexdigest()[:16]}"
    responses = FakeResponses(
        [
            SimpleNamespace(
                output_parsed=DecisionBatch(
                    decisions=[Decision(finding_id=safe_id, severity=Severity.LOW, confidence=0.9)]
                ),
                usage=None,
            )
        ]
    )
    classifier = OpenAIClassifier(
        model="configured-model",
        client=SimpleNamespace(responses=responses),
    )

    (decision,) = classifier.classify([_finding(identifier=local_id)])

    assert local_id not in str(responses.calls[0]["input"])
    assert decision.finding_id == local_id


def test_masking_covers_all_finding_text_fields() -> None:
    original = _finding(identifier="path-secret", evidence="api_key='local-demo-value-123'")
    masked = mask_finding(original, max_evidence_chars=20)

    assert "local-demo-value-123" not in masked.evidence
    assert len(masked.evidence) <= 20
    assert mask_text("api_key='local-demo-value-123'").find("local-demo-value-123") == -1


def test_cache_reuses_decision_and_remaps_finding_id(tmp_path: Path) -> None:
    class CountingClassifier:
        name = "counting"

        def __init__(self) -> None:
            self.calls = 0

        def classify(self, findings: list[Finding]) -> list[Decision]:
            self.calls += 1
            return [
                Decision(
                    finding_id=finding.id,
                    severity=finding.raw_severity,
                    false_positive=False,
                    confidence=1,
                )
                for finding in findings
            ]

    base = CountingClassifier()
    cached = CachingClassifier(base, tmp_path / "cache.sqlite3")
    (first,) = cached.classify([_finding("first-id")])
    (second,) = cached.classify([_finding("second-id")])

    assert first.finding_id == "first-id"
    assert second.finding_id == "second-id"
    assert base.calls == 1


def test_budget_skips_a_batch_that_could_exceed_limit() -> None:
    class CountingClassifier:
        name = "counting"
        calls = 0

        def classify(self, findings: list[Finding]) -> list[Decision]:
            self.calls += 1
            return []

    base = CountingClassifier()
    budgeted = BudgetedClassifier(
        base,
        max_cost_usd=Decimal("0.001"),
        input_cost_per_1k_usd=Decimal(1),
        output_cost_per_1k_usd=Decimal(1),
        max_findings_per_call=10,
        max_evidence_chars=1000,
        max_output_tokens=2000,
    )

    (decision,) = budgeted.classify([_finding()])

    assert base.calls == 0
    assert decision.classified is False
    assert decision.confidence == 0


def test_budget_tracks_usage_from_a_successful_call() -> None:
    class CountingClassifier:
        name = "counting"
        model = "configured-model"
        input_tokens = 0
        output_tokens = 0

        def classify(self, findings: list[Finding]) -> list[Decision]:
            self.input_tokens += 100
            self.output_tokens += 20
            return [
                Decision(finding_id=item.id, severity=item.raw_severity, confidence=1)
                for item in findings
            ]

    budgeted = BudgetedClassifier(
        CountingClassifier(),
        max_cost_usd=Decimal(1),
        input_cost_per_1k_usd=Decimal("0.01"),
        output_cost_per_1k_usd=Decimal("0.02"),
        max_findings_per_call=10,
        max_evidence_chars=1000,
        max_output_tokens=2000,
    )

    decisions = budgeted.classify([_finding()])

    assert decisions[0].classified is True
    assert budgeted.input_tokens == 100
    assert budgeted.output_tokens == 20
    assert budgeted.estimated_cost_usd == Decimal("0.0014")


def test_finding_cap_reports_omitted_count() -> None:
    kept, warning = cap_findings([_finding("one"), _finding("two")], 1)

    assert [finding.id for finding in kept] == ["one"]
    assert warning == "Achados limitados a 1; 1 foram omitidos."


def test_sarif_output_is_valid_and_does_not_include_evidence() -> None:
    report = Report(
        summary="test",
        findings=(_finding(evidence="secret must not appear"),),
        decisions=(Decision(finding_id="finding-1", severity=Severity.HIGH, confidence=1),),
    )

    payload = json.loads(render_sarif(report))

    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["level"] == "error"
    assert "secret must not appear" not in json.dumps(payload)


def test_analysis_context_uses_python_only_defaults(tmp_path: Path) -> None:
    context = AnalysisContext(root=tmp_path, python_files=())

    assert context.max_findings == 200
    assert context.max_evidence_chars == 1000
