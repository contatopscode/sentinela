import json
from pathlib import Path

import pytest

from sentinela import __version__
from sentinela.cli import main
from sentinela.models import Analyzer, Decision, Finding, Report, Severity
from sentinela.report.sarif import SARIF_SCHEMA, render


def _finding(
    finding_id: str,
    *,
    analyzer: Analyzer = Analyzer.SECURITY,
    rule: str = "B602",
    file: str = "app.py",
    line: int | None = 3,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        analyzer=analyzer,
        rule=rule,
        title=f"Título {finding_id}",
        file=file,
        line=line,
        evidence="trecho que não pode sair",
        raw_severity=severity,
    )


def _payload(*findings: Finding, decisions: tuple[Decision, ...] = ()) -> dict:
    return json.loads(render(Report(summary="s", findings=findings, decisions=decisions)))


def test_sarif_has_schema_driver_version_and_required_rule_texts() -> None:
    payload = _payload(_finding("a"))

    assert payload["$schema"] == SARIF_SCHEMA
    driver = payload["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    rule = driver["rules"][0]
    assert rule["id"] == "security/B602"
    assert rule["fullDescription"]["text"]
    assert rule["help"]["text"]
    assert payload["runs"][0]["results"][0]["ruleIndex"] == 0
    assert "trecho que não pode sair" not in json.dumps(payload)


def test_security_rules_carry_tag_and_highest_security_severity() -> None:
    payload = _payload(
        _finding("low", severity=Severity.LOW),
        _finding("critical", severity=Severity.CRITICAL),
    )

    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["properties"]["tags"] == ["security"]
    assert rules[0]["properties"]["security-severity"] == "9.5"
    assert rules[0]["defaultConfiguration"]["level"] == "error"


def test_non_security_rules_have_no_security_severity() -> None:
    payload = _payload(_finding("q", analyzer=Analyzer.QA, rule="low-coverage"))

    properties = payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    assert properties == {"tags": ["quality"]}


def test_info_security_finding_has_no_security_severity() -> None:
    payload = _payload(_finding("i", severity=Severity.INFO))

    assert "security-severity" not in payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]


def test_file_level_finding_points_to_first_line() -> None:
    payload = _payload(_finding("f", line=None))

    region = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 1}


def test_finding_without_file_becomes_notification() -> None:
    payload = _payload(_finding("d", rule="PYSEC-1", file="<dependências>", line=None))

    run = payload["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    notification = run["invocations"][0]["toolExecutionNotifications"][0]
    assert notification["descriptor"]["id"] == "security/PYSEC-1"
    assert notification["message"]["text"].startswith("<dependências>:")


def test_false_positive_is_suppressed_and_decision_overrides_level() -> None:
    decision = Decision(finding_id="fp", severity=Severity.LOW, false_positive=True, confidence=0.9)
    payload = _payload(_finding("fp"), decisions=(decision,))

    result = payload["runs"][0]["results"][0]
    assert result["level"] == "note"
    assert result["suppressions"] == [{"kind": "external", "status": "accepted"}]


def test_cli_writes_sarif_file_alongside_markdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SENTINELA_ANALYZERS", "")
    target = tmp_path / "out.sarif"

    assert main(["review", str(tmp_path), "--sarif-output", str(target)]) == 0

    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "Sentinela" in capsys.readouterr().out


def test_cli_reports_unwritable_sarif_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SENTINELA_ANALYZERS", "")

    assert main(["review", str(tmp_path), "--sarif-output", str(tmp_path / "x" / "y")]) == 2
    assert "SARIF" in capsys.readouterr().err
