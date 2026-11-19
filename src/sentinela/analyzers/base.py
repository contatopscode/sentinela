"""Contrato e funções compartilhadas por analisadores."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeAlias

from sentinela.collector import AnalysisContext
from sentinela.models import Finding


class Analyzer(Protocol):
    name: str

    def run(self, context: AnalysisContext) -> list[Finding]: ...


CommandRunner: TypeAlias = Callable[[list[str], AnalysisContext], tuple[int, str, str]]
