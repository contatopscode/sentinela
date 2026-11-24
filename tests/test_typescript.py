from __future__ import annotations

from pathlib import Path

import pytest

from sentinela.analyzers.commands import ToolUnavailableError
from sentinela.analyzers.security import SecurityAnalyzer
from sentinela.collector import AnalysisContext, collect_context, is_script_source


def _write(root: Path, relative: str, content: str = "export const x = 1;\n") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _no_tools(command: list[str], context: AnalysisContext) -> tuple[int, str, str]:
    raise ToolUnavailableError(command[0])


def test_collector_separates_python_and_script_sources(tmp_path: Path) -> None:
    for relative in (
        "app.py",
        "web/src/index.ts",
        "web/src/App.tsx",
        "web/lib/util.mjs",
        "web/types/globals.d.ts",
        "web/public/vendor.min.js",
        "web/node_modules/pkg/index.js",
        "web/.next/server/page.js",
        "README.md",
    ):
        _write(tmp_path, relative)

    context = collect_context(tmp_path)

    assert [p.relative_to(tmp_path).as_posix() for p in context.python_files] == ["app.py"]
    assert {p.relative_to(tmp_path).as_posix() for p in context.script_files} == {
        "web/src/index.ts",
        "web/src/App.tsx",
        "web/lib/util.mjs",
    }


def test_script_source_filter() -> None:
    assert is_script_source(Path("a.cts"))
    assert not is_script_source(Path("a.d.mts"))
    assert not is_script_source(Path("bundle.min.mjs"))
    assert not is_script_source(Path("a.py"))


def test_symlinked_script_is_not_followed(tmp_path: Path) -> None:
    _write(tmp_path, "real/a.ts")
    try:
        (tmp_path / "link.ts").symlink_to(tmp_path / "real" / "a.ts")
        (tmp_path / "linkdir").symlink_to(tmp_path / "real", target_is_directory=True)
    except OSError:
        pytest.skip("o sistema não permite criar symlinks sem privilégio")

    context = collect_context(tmp_path)

    assert [p.name for p in context.script_files] == ["a.ts"]


def test_secret_scan_covers_typescript_and_masks_value(tmp_path: Path) -> None:
    _write(tmp_path, "src/config.ts", 'export const awsKey = "AKIAIOSFODNN7EXAMPLE";\n')
    _write(tmp_path, "src/safe.ts", "export const key = process.env.API_KEY ?? '';\n")

    findings = SecurityAnalyzer(runner=_no_tools).run(collect_context(tmp_path))

    assert [(f.rule, f.file, f.line) for f in findings] == [("aws-access-key", "src/config.ts", 1)]
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].evidence
