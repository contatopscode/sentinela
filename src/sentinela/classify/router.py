"""Escolha, cache e controle de custo para classificadores."""

from __future__ import annotations

import json
from decimal import ROUND_CEILING, Decimal

from sentinela.classify.base import Classifier
from sentinela.classify.cache import CachingClassifier
from sentinela.classify.fake import FakeClassifier
from sentinela.classify.openai_classifier import OpenAIClassifier
from sentinela.config import Settings
from sentinela.masking import mask_finding
from sentinela.models import Decision, Finding


class BudgetedClassifier:
    """Limita os lotes remotos com uma estimativa conservadora baseada em caracteres."""

    name = "budgeted"

    def __init__(
        self,
        classifier: Classifier,
        *,
        max_cost_usd: Decimal,
        input_cost_per_1k_usd: Decimal,
        output_cost_per_1k_usd: Decimal,
        max_findings_per_call: int,
        max_evidence_chars: int,
        max_output_tokens: int,
    ) -> None:
        self.classifier = classifier
        self.max_cost_usd = max_cost_usd
        self.input_cost_per_1k_usd = input_cost_per_1k_usd
        self.output_cost_per_1k_usd = output_cost_per_1k_usd
        self.max_findings_per_call = max_findings_per_call
        self.max_evidence_chars = max_evidence_chars
        self.max_output_tokens = max_output_tokens
        self.input_tokens = 0
        self.output_tokens = 0
        self.estimated_cost_usd = Decimal(0)
        self._reserved_cost_usd = Decimal(0)
        self.model = getattr(classifier, "model", None)

    def classify(self, findings: list[Finding]) -> list[Decision]:
        decisions: dict[str, Decision] = {}
        for start in range(0, len(findings), self.max_findings_per_call):
            batch = findings[start : start + self.max_findings_per_call]
            estimated = self._estimate_batch_cost(batch)
            if self._reserved_cost_usd + estimated > self.max_cost_usd:
                break
            miss_counter_available = hasattr(self.classifier, "misses")
            before_misses = int(getattr(self.classifier, "misses", 0))
            before_input = int(getattr(self.classifier, "input_tokens", 0))
            before_output = int(getattr(self.classifier, "output_tokens", 0))
            for decision in self.classifier.classify(batch):
                decisions[decision.finding_id] = decision
            misses = (
                int(getattr(self.classifier, "misses", 0)) - before_misses
                if miss_counter_available
                else len(batch)
            )
            input_delta = int(getattr(self.classifier, "input_tokens", 0)) - before_input
            output_delta = int(getattr(self.classifier, "output_tokens", 0)) - before_output
            self.input_tokens += input_delta
            self.output_tokens += output_delta
            if misses:
                observed_tokens = input_delta + output_delta
                batch_cost = (
                    self._actual_cost(input_delta, output_delta) if observed_tokens else estimated
                )
                self.estimated_cost_usd += batch_cost
            self._reserved_cost_usd += estimated

        return [decisions.get(finding.id, _unclassified(finding)) for finding in findings]

    def _estimate_batch_cost(self, findings: list[Finding]) -> Decimal:
        safe = [mask_finding(item, self.max_evidence_chars) for item in findings]
        payload = json.dumps([item.model_dump(mode="json") for item in safe], ensure_ascii=False)
        input_tokens = 500 + int(
            (Decimal(len(payload)) / Decimal(3)).to_integral_value(rounding=ROUND_CEILING)
        )
        return self._actual_cost(input_tokens, self.max_output_tokens)

    def _actual_cost(self, input_tokens: int, output_tokens: int) -> Decimal:
        return (
            Decimal(input_tokens) * self.input_cost_per_1k_usd
            + Decimal(output_tokens) * self.output_cost_per_1k_usd
        ) / Decimal(1000)


def build_classifier(settings: Settings) -> Classifier:
    if settings.classifier == "fake":
        return FakeClassifier()
    if settings.classifier != "openai":
        raise ValueError(f"Classificador não disponível: {settings.classifier}")
    if settings.input_cost_per_1k_usd is None or settings.output_cost_per_1k_usd is None:
        raise ValueError(
            "Configure SENTINELA_INPUT_COST_PER_1K_USD e SENTINELA_OUTPUT_COST_PER_1K_USD "
            "com os preços atuais do modelo antes de habilitar OpenAI"
        )
    base: Classifier = OpenAIClassifier(
        settings.classifier_model,
        max_evidence_chars=settings.max_evidence_chars,
        max_output_tokens=settings.max_output_tokens,
        timeout_seconds=settings.request_timeout_seconds,
    )
    cached = CachingClassifier(base, settings.cache_path)
    return BudgetedClassifier(
        cached,
        max_cost_usd=settings.max_cost_usd,
        input_cost_per_1k_usd=settings.input_cost_per_1k_usd,
        output_cost_per_1k_usd=settings.output_cost_per_1k_usd,
        max_findings_per_call=settings.max_findings_per_call,
        max_evidence_chars=settings.max_evidence_chars,
        max_output_tokens=settings.max_output_tokens,
    )


def _unclassified(finding: Finding) -> Decision:
    return Decision(
        finding_id=finding.id,
        severity=finding.raw_severity,
        confidence=0,
        classified=False,
    )
