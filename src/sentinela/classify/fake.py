"""Classificador local determinístico, sem rede ou credenciais."""

from __future__ import annotations

from sentinela.models import Decision, Finding


class FakeClassifier:
    name = "fake"

    def classify(self, findings: list[Finding]) -> list[Decision]:
        """Mantém a severidade original e marca os achados como classificados."""
        return [
            Decision(
                finding_id=finding.id,
                severity=finding.raw_severity,
                false_positive=_is_known_false_positive(finding),
                confidence=1.0,
                classified=True,
            )
            for finding in findings
        ]


def _is_known_false_positive(finding: Finding) -> bool:
    path = finding.file.lower()
    evidence = finding.evidence.lower()
    return (
        finding.rule in {"B101", "B404"}
        or path.startswith(("tests/", "test_"))
        or "example" in path
        or "example" in evidence
    )
