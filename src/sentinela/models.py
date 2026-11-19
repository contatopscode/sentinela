"""Contratos de dados entre os componentes do Sentinela."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Analyzer(StrEnum):
    QA = "qa"
    SECURITY = "security"
    PERFORMANCE = "performance"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    analyzer: Analyzer
    rule: str
    title: str
    file: str
    line: int | None = Field(default=None, ge=1)
    evidence: str = ""
    raw_severity: Severity


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    severity: Severity
    false_positive: bool = False
    duplicate_group: str | None = None
    confidence: float = Field(ge=0, le=1)
    classified: bool = True


class ExecutionMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    duration_seconds: float = Field(default=0, ge=0)
    models_used: tuple[str, ...] = ()
    tokens_used: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(default=0, ge=0)


class Report(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str
    findings: tuple[Finding, ...] = ()
    decisions: tuple[Decision, ...] = ()
    suggestions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    metadata: ExecutionMetadata = Field(default_factory=ExecutionMetadata)


def json_compatible(value: Any) -> Any:
    """Converte modelos Sentinela em estruturas Python serializáveis em JSON."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"Tipo não suportado: {type(value).__name__}")
