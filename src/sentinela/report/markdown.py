"""Renderização de relatório em Markdown."""

from __future__ import annotations

from sentinela.models import Report


def render(report: Report, *, max_chars: int = 50000) -> str:
    lines = ["# Relatório Sentinela", "", report.summary, "", "## Achados"]
    decisions = {decision.finding_id: decision for decision in report.decisions}
    if not report.findings:
        lines.extend(["", "Nenhum achado registrado."])
    for finding in report.findings:
        decision = decisions.get(finding.id)
        severity = decision.severity.value if decision else finding.raw_severity.value
        lines.extend(
            [
                "",
                f"### [{severity.upper()}] {finding.title}",
                f"- Analisador: {finding.analyzer.value} (`{finding.rule}`)",
                f"- Local: `{finding.file}`" + (f":{finding.line}" if finding.line else ""),
            ]
        )
        if finding.evidence:
            lines.append(f"- Evidência: {finding.evidence}")
        if decision and decision.false_positive:
            lines.append(
                f"- Classificação: possível falso positivo (confiança {decision.confidence:.2f})"
            )
        elif decision and not decision.classified:
            lines.append("- Classificação: não validada; severidade original mantida")
    if report.warnings:
        lines.extend(["", "## Avisos", ""])
        lines.extend(f"- {warning}" for warning in report.warnings)
    output = "\n".join(lines) + "\n"
    if len(output) <= max_chars:
        return output
    marker = "\n\n_[Relatório truncado pelo limite configurado.]_\n"
    return output[: max(0, max_chars - len(marker))] + marker
