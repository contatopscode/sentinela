from decimal import Decimal

import pytest

from sentinela.config import load_settings


def test_fake_is_default_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINELA_CLASSIFIER", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SENTINELA_JEV_API_KEY", raising=False)

    settings = load_settings()

    assert settings.classifier == "fake"
    assert settings.max_cost_usd == Decimal("0.50")


def test_rejects_unknown_classifier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELA_CLASSIFIER", "unknown")

    with pytest.raises(ValueError, match="SENTINELA_CLASSIFIER"):
        load_settings()


def test_rejects_negative_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELA_MAX_COST_USD", "-1")

    with pytest.raises(ValueError, match="não negativo"):
        load_settings()
