"""Avalia a detecção estática e o baseline fake sem executar casos ou usar rede."""

from __future__ import annotations

import statistics
from pathlib import Path
from time import monotonic

import yaml

ROOT = Path(__file__).resolve().parent
from sentinela.analyzers.performance import PerformanceAnalyzer
from sentinela.analyzers.security import SecurityAnalyzer
from sentinela.classify.fake import FakeClassifier
from sentinela.collector import collect_context


def main() -> int:
    expected = yaml.safe_load((ROOT / "expected.yaml").read_text(encoding="utf-8"))["cases"]
    latencies: list[float] = []
    true_positive = false_positive = false_negative = exact_cases = 0
    rows: list[tuple[str, str, str]] = []
    mismatches: list[tuple[str, str, str]] = []

    for case in expected:
        case_root = ROOT / "cases" / case["id"]
        context = collect_context(case_root, enabled_analyzers=("security", "performance"))
        started = monotonic()
        findings = SecurityAnalyzer().run(context) + PerformanceAnalyzer().run(context)
        latencies.append(monotonic() - started)
        expected_rules = set(case["expected_rules"])
        actual_rules = {finding.rule for finding in findings}
        exact_cases += actual_rules == expected_rules
        if actual_rules != expected_rules:
            mismatches.append(
                (case["id"], ",".join(sorted(expected_rules)), ",".join(sorted(actual_rules)))
            )
        true_positive += len(actual_rules & expected_rules)
        false_positive += len(actual_rules - expected_rules)
        false_negative += len(expected_rules - actual_rules)

        decisions = FakeClassifier().classify(findings)
        for decision in decisions:
            rows.append(
                (
                    case["id"],
                    decision.severity.value,
                    "false-positive" if decision.false_positive else "finding",
                )
            )

    precision = (
        true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
    )
    recall = (
        true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
    )
    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    median = statistics.median(latencies)
    print("Sentinela offline evaluation (static analyzers + fake classifier)")
    print(
        f"cases={len(expected)} exact={exact_cases}/{len(expected)} precision={precision:.3f} recall={recall:.3f}"
    )
    print(
        f"latency_median_ms={median * 1000:.2f} latency_p95_ms={p95 * 1000:.2f} cost_usd=0.000000"
    )
    for row in rows:
        print(f"case={row[0]} severity={row[1]} decision={row[2]}")
    for case_id, wanted, got in mismatches:
        print(f"mismatch={case_id} expected=[{wanted}] actual=[{got}]")
    return 0 if exact_cases == len(expected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
