"""Interface de linha de comando inicial do Sentinela."""

from __future__ import annotations

import argparse
import sys

from sentinela import __version__
from sentinela.classify.router import build_classifier
from sentinela.collector import collect_context
from sentinela.config import load_settings
from sentinela.orchestrator import review
from sentinela.report import json_out, markdown, sarif


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinela", description="Revisão local de código")
    subparsers = parser.add_subparsers(dest="command")

    review = subparsers.add_parser("review", help="Revisa um repositório")
    review.add_argument("path", nargs="?", default=".", help="Caminho do repositório")
    review.add_argument(
        "--run-tests",
        action="store_true",
        help="Autoriza explicitamente a execução dos testes do repositório analisado",
    )
    review.add_argument(
        "--network-pip-audit",
        action="store_true",
        help="Autoriza o pip-audit a consultar a rede para auditar dependências",
    )
    review.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown")
    review.add_argument(
        "--sarif-output",
        metavar="ARQUIVO",
        help="Grava também o relatório SARIF neste arquivo, sem rodar a análise de novo",
    )
    review.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="CAMINHO",
        help="Ignora um diretório (nome em qualquer nível ou caminho relativo); repetível",
    )
    review.add_argument(
        "--show-false-positives",
        action="store_true",
        help="Lista cada provável falso positivo no relatório Markdown, em vez de agrupá-los",
    )

    subparsers.add_parser("eval", help="Executa a avaliação local")
    subparsers.add_parser("version", help="Exibe a versão instalada")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        settings = load_settings()
    except ValueError as exc:
        parser.error(str(exc))

    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "review":
        try:
            context = collect_context(
                args.path,
                run_tests=args.run_tests,
                allow_network_audit=args.network_pip_audit,
                enabled_analyzers=settings.analyzers,
                max_findings=settings.max_findings,
                max_evidence_chars=settings.max_evidence_chars,
                timeout_seconds=settings.tool_timeout_seconds,
                passthrough_env=settings.passthrough_env,
                extra_excludes=settings.excludes + tuple(args.exclude),
            )
            report = review(context, classifier=build_classifier(settings))
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"sentinela: {exc}", file=sys.stderr)
            return 2
        if args.format == "markdown":
            rendered = markdown.render(
                report,
                max_chars=settings.max_report_chars,
                show_false_positives=args.show_false_positives,
            )
        elif args.format == "json":
            rendered = json_out.render(report)
        else:
            rendered = sarif.render(report)
        if args.sarif_output:
            from pathlib import Path

            try:
                Path(args.sarif_output).write_text(sarif.render(report) + "\n", encoding="utf-8")
            except OSError as exc:
                print(f"sentinela: não foi possível gravar o SARIF: {exc}", file=sys.stderr)
                return 2
        print(rendered)
        return 0
    if args.command == "eval":
        import runpy
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        if not (project_root / "eval" / "run_eval.py").is_file():
            print(
                "sentinela: o eval acompanha o código-fonte; rode a partir de um clone do "
                "repositório (pip install -e .)",
                file=sys.stderr,
            )
            return 2
        evaluation = runpy.run_path(str(project_root / "eval" / "run_eval.py"))
        return int(evaluation["main"]())

    return 0
