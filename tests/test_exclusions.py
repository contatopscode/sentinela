from __future__ import annotations

from pathlib import Path

import pytest

from sentinela.analyzers.security import _bandit_command
from sentinela.cli import build_parser
from sentinela.collector import DEFAULT_EXCLUDES, collect_context, is_excluded
from sentinela.config import load_settings


def _touch(root: Path, relative: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x = 1\n", encoding="utf-8")


def test_default_directories_are_skipped(tmp_path: Path) -> None:
    for relative in (
        "app.py",
        "node_modules/pkg/a.py",
        ".claude/worktrees/w/b.py",
        "pkg/.tox/c.py",
        "pkg/ok.py",
    ):
        _touch(tmp_path, relative)
    context = collect_context(tmp_path)
    found = {path.relative_to(context.root).as_posix() for path in context.python_files}
    assert found == {"app.py", "pkg/ok.py"}


def test_parent_directory_names_do_not_exclude_the_project(tmp_path: Path) -> None:
    root = tmp_path / "venv" / "projeto"
    _touch(root, "app.py")
    assert len(collect_context(root).python_files) == 1


def test_extra_excludes_by_name_and_relative_path(tmp_path: Path) -> None:
    for relative in ("legacy/a.py", "src/legacy/b.py", "gen/out/c.py", "gen/keep.py"):
        _touch(tmp_path, relative)
    context = collect_context(tmp_path, extra_excludes=("legacy", "gen/out"))
    found = {path.relative_to(context.root).as_posix() for path in context.python_files}
    assert found == {"gen/keep.py"}


@pytest.mark.parametrize(
    ("relative", "excluded"),
    [
        ("a/node_modules/x.py", True),
        ("node_modules.py", False),
        (".claude/worktrees/x/y.py", True),
        ("src/.claude/worktrees/y.py", False),
    ],
)
def test_is_excluded(relative: str, excluded: bool) -> None:
    assert is_excluded(Path(relative), DEFAULT_EXCLUDES) is excluded


def test_bandit_receives_the_same_exclusions(tmp_path: Path) -> None:
    context = collect_context(tmp_path, extra_excludes=("legacy",))
    command = _bandit_command(context)
    patterns = command[command.index("-x") + 1].split(",")
    assert "*/node_modules/*" in patterns
    assert "./.claude/worktrees" in patterns
    assert "*/legacy/*" in patterns


def test_env_and_cli_exclude(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELA_EXCLUDE", "a, b/c")
    assert load_settings().excludes == ("a", "b/c")
    args = build_parser().parse_args(["review", ".", "--exclude", "x", "--exclude", "y"])
    assert args.exclude == ["x", "y"]
