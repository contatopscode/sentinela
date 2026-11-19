"""Limites locais aplicados antes de classificar e renderizar achados."""

from __future__ import annotations

from sentinela.models import Finding


def cap_findings(findings: list[Finding], limit: int) -> tuple[list[Finding], str | None]:
    if len(findings) <= limit:
        return findings, None
    omitted = len(findings) - limit
    return findings[:limit], f"Achados limitados a {limit}; {omitted} foram omitidos."
