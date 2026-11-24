"""Configuração do Sentinela por variáveis de ambiente."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation


@dataclass(frozen=True, slots=True)
class Settings:
    classifier: str = "fake"
    classifier_model: str | None = None
    explainer_model: str | None = None
    max_cost_usd: Decimal = Decimal("0.50")
    analyzers: tuple[str, ...] = ("qa", "security", "performance")
    input_cost_per_1k_usd: Decimal | None = None
    output_cost_per_1k_usd: Decimal | None = None
    max_findings: int = 200
    max_report_chars: int = 50000
    max_findings_per_call: int = 20
    max_evidence_chars: int = 1000
    max_output_tokens: int = 2000
    request_timeout_seconds: int = 30
    tool_timeout_seconds: int = 120
    cache_path: str | None = None
    passthrough_env: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()


_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_settings() -> Settings:
    """Carrega opções do ambiente sem exigir credenciais."""
    classifier = os.getenv("SENTINELA_CLASSIFIER", "fake").strip().lower()
    if classifier not in {"fake", "openai"}:
        raise ValueError(
            "SENTINELA_CLASSIFIER deve ser fake ou openai; jev ainda não está disponível"
        )

    raw_cost = os.getenv("SENTINELA_MAX_COST_USD", "0.50")
    try:
        max_cost = Decimal(raw_cost)
    except InvalidOperation as exc:
        raise ValueError("SENTINELA_MAX_COST_USD deve ser um número decimal") from exc
    if not max_cost.is_finite() or max_cost < 0:
        raise ValueError("SENTINELA_MAX_COST_USD deve ser finito e não negativo")

    raw_analyzers = os.getenv("SENTINELA_ANALYZERS", "qa,security,performance")
    analyzers = tuple(part.strip().lower() for part in raw_analyzers.split(",") if part.strip())
    invalid = set(analyzers) - {"qa", "security", "performance"}
    if invalid:
        raise ValueError(
            "SENTINELA_ANALYZERS contém valores inválidos: " + ", ".join(sorted(invalid))
        )

    raw_passthrough = os.getenv("SENTINELA_PASSTHROUGH_ENV", "")
    passthrough = tuple(part.strip() for part in raw_passthrough.split(",") if part.strip())
    invalid_names = [name for name in passthrough if not _ENV_NAME.fullmatch(name)]
    if invalid_names:
        raise ValueError(
            "SENTINELA_PASSTHROUGH_ENV contém nomes inválidos: " + ", ".join(invalid_names)
        )

    raw_excludes = os.getenv("SENTINELA_EXCLUDE", "")
    excludes = tuple(part.strip() for part in raw_excludes.split(",") if part.strip())

    def decimal_setting(name: str) -> Decimal | None:
        raw = os.getenv(name)
        if raw is None or not raw.strip():
            return None
        try:
            value = Decimal(raw)
        except InvalidOperation as exc:
            raise ValueError(f"{name} deve ser um número decimal") from exc
        if not value.is_finite() or value < 0:
            raise ValueError(f"{name} deve ser finito e não negativo")
        return value

    limits = {
        "max_findings": ("SENTINELA_MAX_FINDINGS", 200, 1, 10000),
        "max_report_chars": ("SENTINELA_MAX_REPORT_CHARS", 50000, 1000, 500000),
        "max_findings_per_call": ("SENTINELA_MAX_FINDINGS_PER_CALL", 20, 1, 100),
        "max_evidence_chars": ("SENTINELA_MAX_EVIDENCE_CHARS", 1000, 1, 10000),
        "max_output_tokens": ("SENTINELA_MAX_OUTPUT_TOKENS", 2000, 100, 10000),
        "request_timeout_seconds": ("SENTINELA_REQUEST_TIMEOUT_SECONDS", 30, 1, 600),
        "tool_timeout_seconds": ("SENTINELA_TOOL_TIMEOUT_SECONDS", 120, 1, 3600),
    }
    parsed_limits: dict[str, int] = {}
    for field, (env_name, default, minimum, maximum) in limits.items():
        raw = os.getenv(env_name)
        try:
            value = default if raw is None else int(raw)
        except ValueError as exc:
            raise ValueError(f"{env_name} deve ser um inteiro") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"{env_name} deve estar entre {minimum} e {maximum}")
        parsed_limits[field] = value

    return Settings(
        classifier=classifier,
        classifier_model=os.getenv("SENTINELA_CLASSIFIER_MODEL") or None,
        explainer_model=os.getenv("SENTINELA_EXPLAINER_MODEL") or None,
        max_cost_usd=max_cost,
        analyzers=analyzers,
        input_cost_per_1k_usd=decimal_setting("SENTINELA_INPUT_COST_PER_1K_USD"),
        output_cost_per_1k_usd=decimal_setting("SENTINELA_OUTPUT_COST_PER_1K_USD"),
        max_findings=parsed_limits["max_findings"],
        max_report_chars=parsed_limits["max_report_chars"],
        max_findings_per_call=parsed_limits["max_findings_per_call"],
        max_evidence_chars=parsed_limits["max_evidence_chars"],
        max_output_tokens=parsed_limits["max_output_tokens"],
        request_timeout_seconds=parsed_limits["request_timeout_seconds"],
        tool_timeout_seconds=parsed_limits["tool_timeout_seconds"],
        cache_path=os.getenv("SENTINELA_CACHE_PATH") or None,
        passthrough_env=passthrough,
        excludes=excludes,
    )
