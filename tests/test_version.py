import tomllib
from pathlib import Path

import sentinela


def test_module_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]

    assert sentinela.__version__ == project["version"]
