"""Secondo livello di verifica, conservativo e senza richieste attive."""
from __future__ import annotations

from typing import Any

from achillesapi.core.verification_v080 import classify_findings


def review_assessment(assessment: dict[str, Any]) -> dict[str, Any]:
    """Arricchisce i finding con cosa verificare, senza confermarli automaticamente."""
    base = classify_findings(assessment)
    for item in base['findings']:
        item['next_verification'] = [
            'Riproduci con due identità autorizzate quando pertinente.',
            'Conserva richiesta e risposta opportunamente oscurate.',
            'Confronta il comportamento con policy e impatto reali.',
        ]
        item['verified_automatically'] = False
    base['engine'] = 'achilles-verification-review-v090'
    base['evidence_quality'] = ('requires_operator_evidence' if base['findings']
                               else 'no_indicators_in_input')
    return base
