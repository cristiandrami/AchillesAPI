"""AI-assisted interpretation layered on deterministic passive assessment."""
from __future__ import annotations

from typing import Any

from achillesapi.ai.local import analyze_with_ollama
from achillesapi.core.assessment import assess_api
from achillesapi.models.api import ParsedAPI


def analyze_api_locally(
    parsed: ParsedAPI,
    *,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "achilles-local",
    timeout: float = 120.0,
) -> dict[str, Any]:
    """In pratica: Prepara l'analisi della specifica e la affida al modello locale.

    Attenzione: Puo contattare Ollama sul computer locale, ma non l'API target.
    """
    deterministic = [item.model_dump(mode="json") for item in assess_api(parsed)]
    ai = analyze_with_ollama(
        parsed, deterministic, endpoint=endpoint, model=model, timeout=timeout
    )
    return {
        "engine": "achillesapi-local-ai",
        "provider": "ollama-local-only",
        "model": model,
        "confirmed_vulnerabilities": 0,
        "deterministic_assessment": {
            "status": "passive_hypotheses",
            "findings": deterministic,
        },
        "ai_analysis": ai,
        "note": "AI interpretation is advisory. Validate all hypotheses with authorized tests.",
    }
