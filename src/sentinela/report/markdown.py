"""Renderização de relatório em Markdown."""

from __future__ import annotations

from collections import Counter

from sentinela.models import Decision, Finding, Report, Severity

_ORDER = {severity: index for index, severity in enumerate(Severity)}


def render(
    report: Report,
    *,
    max_chars: int = 50000,
    show_false_positives: bool = False,
) -> str:
    decisions = {decision.finding_id: decision for decision in report.decisions}
    actionable: list[tuple[Finding, Decision | None]] = []
    suppressed: list[tuple[Finding, Decision]] = []
    for finding in report.findings:
        decision = decisions.get(finding.id)
        if decision is not None and decision.false_positive:
            suppressed.append((finding, decision))
        else:
            actionable.append((finding, decision))
    actionable.sort(key=lambda item: (_ORDER[_severity(*item)], item[0].file, item[0].line or 0))

    lines = ["# Relatório Sentinela", "", report.summary]
    if actionable:
        counts = Counter(_severity(*item) for item in actionable)
        lines.extend(["", "| Severidade | Achados |", "|---|---|"])
        lines.extend(
            f"| {severity.value} | {counts[severity]} |"
            for severity in Severity
            if counts[severity]
        )
    lines.extend(["", "## Achados"])
    if not actionable:
        lines.extend(["", "Nenhum achado que exija ação."])
    for finding, decision in actionable:
        lines.extend(_finding_lines(finding, decision))

    if suppressed:
        lines.extend(["", f"## Prováveis falsos positivos ({len(suppressed)})"])
        if show_false_positives:
            for finding, decision in suppressed:
                lines.extend(_finding_lines(finding, decision))
        else:
            groups = Counter((finding.analyzer.value, finding.rule) for finding, _ in suppressed)
            lines.append("")
            lines.extend(
                f"- `{rule}` ({analyzer}): {count} ocorrência(s)"
                for (analyzer, rule), count in sorted(groups.items())
            )
            lines.extend(
                [
                    "",
                    (
                        "_Cada ocorrência aparece nos formatos JSON e SARIF, ou no Markdown com "
                        "`--show-false-positives`._"
                    ),
                ]
            )

    if report.warnings:
        lines.extend(["", "## Avisos", ""])
        lines.extend(f"- {warning}" for warning in report.warnings)
    output = "\n".join(lines) + "\n"
    if len(output) <= max_chars:
        return output
    marker = "\n\n_[Relatório truncado pelo limite configurado.]_\n"
    return output[: max(0, max_chars - len(marker))] + marker


def _severity(finding: Finding, decision: Decision | None) -> Severity:
    return decision.severity if decision else finding.raw_severity


def _finding_lines(finding: Finding, decision: Decision | None) -> list[str]:
    lines = [
        "",
        f"### [{_severity(finding, decision).value.upper()}] {finding.title}",
        f"- Analisador: {finding.analyzer.value} (`{finding.rule}`)",
        f"- Local: `{finding.file}`" + (f":{finding.line}" if finding.line else ""),
    ]
    if finding.evidence:
        lines.append(f"- Evidência: {finding.evidence}")
    if decision and decision.false_positive:
        lines.append(
            f"- Classificação: possível falso positivo (confiança {decision.confidence:.2f})"
        )
    elif decision and not decision.classified:
        lines.append("- Classificação: não validada; severidade original mantida")
    return lines
