"""Renderização SARIF 2.1.0 sem incluir trechos de código."""

from __future__ import annotations

from sentinela.models import Report, Severity

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(report: Report) -> str:
    decisions = {decision.finding_id: decision for decision in report.decisions}
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in report.findings:
        rule_id = f"{finding.analyzer.value}/{finding.rule}"
        rules[rule_id] = {"id": rule_id, "shortDescription": {"text": finding.title[:200]}}
        decision = decisions.get(finding.id)
        severity = decision.severity if decision else finding.raw_severity
        result: dict[str, object] = {
            "ruleId": rule_id,
            "level": _LEVELS[severity],
            "message": {"text": finding.title[:500]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        **(
                            {"region": {"startLine": finding.line}}
                            if finding.line is not None
                            else {}
                        ),
                    }
                }
            ],
        }
        if decision and decision.false_positive:
            result["suppressions"] = [{"kind": "external", "status": "accepted"}]
        results.append(result)
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Sentinela", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    import json

    return json.dumps(payload, ensure_ascii=False, indent=2)
