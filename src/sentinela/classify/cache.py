"""Cache local SQLite de decisões sem conteúdo de código."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from sentinela.classify.base import Classifier
from sentinela.masking import mask_finding
from sentinela.models import Decision, Finding, Severity


class CachedDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    false_positive: bool
    duplicate_group: str | None
    confidence: float
    classified: bool


class CachingClassifier:
    name = "cache"

    def __init__(self, classifier: Classifier, path: str | Path | None = None) -> None:
        self.classifier = classifier
        self.path = Path(path) if path else _default_path()
        self.enabled = True
        self.cache_hits = 0
        self.cache_misses = 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS decisions (cache_key TEXT PRIMARY KEY, decision_json TEXT NOT NULL)"
                )
        except (OSError, sqlite3.Error):
            self.enabled = False

    @property
    def input_tokens(self) -> int:
        return int(getattr(self.classifier, "input_tokens", 0))

    @property
    def output_tokens(self) -> int:
        return int(getattr(self.classifier, "output_tokens", 0))

    @property
    def model(self) -> str | None:
        model = getattr(self.classifier, "model", None)
        return model if isinstance(model, str) else None

    @property
    def misses(self) -> int:
        return self.cache_misses

    def classify(self, findings: list[Finding]) -> list[Decision]:
        if not self.enabled:
            self.cache_misses += len(findings)
            return self.classifier.classify(findings)
        decisions: dict[str, Decision] = {}
        misses: list[Finding] = []
        keys: dict[str, str] = {}
        for finding in findings:
            key = self._key(finding)
            keys[finding.id] = key
            decision = self._get(key)
            if decision is None:
                self.cache_misses += 1
                misses.append(finding)
            else:
                self.cache_hits += 1
                decisions[finding.id] = decision.model_copy(update={"finding_id": finding.id})
        if misses:
            for decision in self.classifier.classify(misses):
                decisions[decision.finding_id] = decision
                if decision.classified:
                    self._put(keys[decision.finding_id], decision)
        return [decisions.get(finding.id, _unclassified(finding)) for finding in findings]

    def _key(self, finding: Finding) -> str:
        masked = mask_finding(finding)
        payload = masked.model_dump(mode="json", exclude={"id"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        model = getattr(self.classifier, "model", "")
        raw = f"schema-v1\0{self.classifier.name}\0{model}\0{canonical}".encode()
        return hashlib.sha256(raw).hexdigest()

    def _get(self, key: str) -> Decision | None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT decision_json FROM decisions WHERE cache_key = ?", (key,)
                ).fetchone()
            if row is None:
                return None
            cached = CachedDecision.model_validate_json(row[0])
            return Decision(finding_id="", **cached.model_dump())
        except (OSError, sqlite3.Error, ValueError):
            self.enabled = False
            return None

    def _put(self, key: str, decision: Decision) -> None:
        stored = CachedDecision.model_validate(
            decision.model_dump(exclude={"finding_id"})
        ).model_dump(mode="json")
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO decisions(cache_key, decision_json) VALUES(?, ?)",
                    (key, json.dumps(stored, sort_keys=True)),
                )
        except (OSError, sqlite3.Error):
            self.enabled = False

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=2)


def _default_path() -> Path:
    cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_root / "sentinela" / "decisions.sqlite3"


def _unclassified(finding: Finding) -> Decision:
    return Decision(
        finding_id=finding.id,
        severity=finding.raw_severity,
        confidence=0,
        classified=False,
    )
