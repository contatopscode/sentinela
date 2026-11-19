import json

from sentinela.cli import main


def test_help_returns_success(capsys) -> None:
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0

    assert "review" in capsys.readouterr().out


def test_version_command(capsys) -> None:
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip()


def test_sarif_format_is_valid_without_analyzers(monkeypatch, capsys) -> None:
    monkeypatch.setenv("SENTINELA_ANALYZERS", "")

    assert main(["review", ".", "--format", "sarif"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
