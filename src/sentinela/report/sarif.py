"""Renderização SARIF 2.1.0, compatível com o code scanning do GitHub, sem trechos de código."""

from __future__ import annotations

import json

from sentinela import __version__
from sentinela.models import Analyzer, Finding, Report, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Escala do GitHub: > 9,0 crítica; 7,0–8,9 alta; 4,0–6,9 média; 0,1–3,9 baixa.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}

_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)

_TAGS = {
    Analyzer.SECURITY: ["security"],
    Analyzer.QA: ["quality"],
    Analyzer.PERFORMANCE: ["performance"],
}


def _has_location(finding: Finding) -> bool:
    """Achados como `<dependências>` não apontam para um arquivo do repositório."""
    return bool(finding.file) and not finding.file.startswith("<")


def _rule(rule_id: str, finding: Finding, severity: Severity) -> dict[str, object]:
    text = finding.title[:1000]
    properties: dict[str, object] = {"tags": list(_TAGS[finding.analyzer])}
    if finding.analyzer is Analyzer.SECURITY and severity in _SECURITY_SEVERITY:
        properties["security-severity"] = _SECURITY_SEVERITY[severity]
    return {
        "id": rule_id,
        "name": finding.rule[:255],
        "shortDescription": {"text": text},
        "fullDescription": {"text": text},
        "help": {"text": f"{text} (regra {finding.rule}, analisador {finding.analyzer.value})"},
        "defaultConfiguration": {"level": _LEVELS[severity]},
        "properties": properties,
    }


def render(report: Report) -> str:
    decisions = {decision.finding_id: decision for decision in report.decisions}
    rules: dict[str, dict[str, object]] = {}
    rule_severity: dict[str, Severity] = {}
    results: list[dict[str, object]] = []
    notifications: list[dict[str, object]] = []
    for finding in report.findings:
        rule_id = f"{finding.analyzer.value}/{finding.rule}"
        decision = decisions.get(finding.id)
        severity = decision.severity if decision else finding.raw_severity
        if not _has_location(finding):
            # Sem arquivo não há alerta no code scanning; vira notificação da execução.
            notifications.append(
                {
                    "level": _LEVELS[severity],
                    "message": {"text": f"{finding.file}: {finding.title[:500]}"},
                    "descriptor": {"id": rule_id},
                }
            )
            continue
        previous = rule_severity.get(rule_id)
        if previous is None or _ORDER.index(severity) > _ORDER.index(previous):
            rule_severity[rule_id] = severity
            rules[rule_id] = _rule(rule_id, finding, severity)
        result: dict[str, object] = {
            "ruleId": rule_id,
            "level": _LEVELS[severity],
            "message": {"text": finding.title[:500]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        # Achados de arquivo inteiro apontam para a primeira linha.
                        "region": {"startLine": finding.line or 1},
                    }
                }
            ],
        }
        if decision and decision.false_positive:
            result["suppressions"] = [{"kind": "external", "status": "accepted"}]
        results.append(result)
    rule_list = list(rules.values())
    rule_index = {rule["id"]: index for index, rule in enumerate(rule_list)}
    for result in results:
        result["ruleIndex"] = rule_index[result["ruleId"]]
    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "Sentinela",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": rule_list,
            }
        },
        "results": results,
    }
    if notifications:
        run["invocations"] = [
            {"executionSuccessful": True, "toolExecutionNotifications": notifications}
        ]
    payload = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(payload, ensure_ascii=False, indent=2)
