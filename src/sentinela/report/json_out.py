"""Renderização de relatório em JSON."""

from sentinela.models import Report


def render(report: Report) -> str:
    return report.model_dump_json(indent=2)
