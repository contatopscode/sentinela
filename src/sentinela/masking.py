"""Mascaramento local de padrões comuns de credenciais."""

from __future__ import annotations

import math
import re

from sentinela.models import Finding

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)(\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"])([^'\"]{8,})(['\"])",
        ),
    ),
    ("jwt", re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b")),
    ("long_token", re.compile(r"\b[A-Za-z0-9_+/=-]{32,}\b")),
)


def mask_text(value: str, max_chars: int = 1000) -> str:
    """Mascara credenciais conhecidas e limita o texto que pode ir a um modelo."""
    masked = value
    for label, pattern in _PATTERNS:
        if label == "credential_assignment":
            masked = pattern.sub(r"\1[SEGREDO:mascarado]\3", masked)
        else:

            def replacement(match: re.Match[str], current_label: str = label) -> str:
                if current_label != "long_token" or _high_entropy(match.group(0)):
                    return f"[SEGREDO:{current_label}]"
                return match.group(0)

            masked = pattern.sub(replacement, masked)
    return masked[:max_chars]


def _high_entropy(candidate: str) -> bool:
    frequencies = [candidate.count(character) / len(candidate) for character in set(candidate)]
    entropy = -sum(frequency * math.log2(frequency) for frequency in frequencies)
    character_groups = sum(
        bool(re.search(pattern, candidate))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    )
    return entropy >= 3.5 and character_groups >= 3


def mask_finding(finding: Finding, max_evidence_chars: int = 1000) -> Finding:
    """Retorna uma cópia com todos os campos textuais mascarados."""
    return finding.model_copy(
        update={
            "id": mask_text(finding.id, max_evidence_chars),
            "rule": mask_text(finding.rule, max_evidence_chars),
            "title": mask_text(finding.title, max_evidence_chars),
            "file": mask_text(finding.file, max_evidence_chars),
            "evidence": mask_text(finding.evidence, max_evidence_chars),
        }
    )
