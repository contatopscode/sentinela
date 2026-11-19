"""Contrato comum para classificadores."""

from __future__ import annotations

from typing import Protocol

from sentinela.models import Decision, Finding


class Classifier(Protocol):
    name: str

    def classify(self, findings: list[Finding]) -> list[Decision]: ...
