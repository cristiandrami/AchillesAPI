"""Best-effort redaction before evidence is sent to the local model."""
from __future__ import annotations

import re
from typing import Any

_SENSITIVE_KEY = re.compile(
    r"authorization|cookie|set-cookie|password|passwd|secret|token|api[_-]?key|"
    r"client[_-]?secret|private[_-]?key|access[_-]?key|refresh[_-]?token",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*)"
    r"([^\s,;]+)"
)


def redact_text(value: str) -> str:
    """Redact common credentials and personal identifiers from arbitrary text."""
    # IN PRATICA: Sostituisce stringhe potenzialmente segrete con un segnaposto.
    # SICUREZZA: Non contatta direttamente l'API target.
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _JWT.sub("[REDACTED_JWT]", value)
    value = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
    value = _EMAIL.sub("[REDACTED_EMAIL]", value)
    return value


def sanitize(value: Any, *, parent_key: str = "") -> Any:
    """Recursively sanitize JSON-compatible evidence; never mutate the input."""
    # IN PRATICA: Elimina campi sensibili prima di condividere metadati con l'AI.
    # SICUREZZA: Non contatta direttamente l'API target.
    if _SENSITIVE_KEY.search(parent_key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(key): sanitize(item, parent_key=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
