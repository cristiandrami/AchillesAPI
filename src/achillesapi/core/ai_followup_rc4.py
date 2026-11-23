"""RC4 — Ollama locale propone, il validatore decide cosa può essere pianificato.

Non convertiamo testo del modello in comandi shell, URL, headers o payload.
Il risultato è un suggerimento da revisionare: NON avvia un penetration test.
"""
from __future__ import annotations

from typing import Any

from achillesapi.ai.local import analyze_with_ollama
from achillesapi.core.ai_guard_v099 import validate_advisory_plan
from achillesapi.core.ai_planner_v080 import ALLOWED
from achillesapi.core.evidence_package_v099 import build_evidence_package
from achillesapi.core.openapi import parse_openapi


def local_followup_review(spec: dict[str, Any], assessment: dict[str, Any], *,
                          model: str = 'achilles-local') -> dict[str, Any]:
    """Chiede a Ollama solo suggerimenti a partire da metadati minimizzati."""
    # Il pacchetto di evidenze contiene impronte e categorie, non corpi/token.
    minimal = build_evidence_package(assessment)
    analysis = analyze_with_ollama(parse_openapi(spec), minimal['findings'], model=model)
    proposals = []
    for suggestion in analysis.get('recommended_tests', [])[:30]:
        # Accettiamo SOLO il nome esatto di una funzione supportata.
        # Qualsiasi testo libero o URL inventato dall'AI rimane fuori dal piano.
        if isinstance(suggestion, str) and suggestion.strip() in ALLOWED:
            proposals.append({'action': suggestion.strip()})
    checked = validate_advisory_plan(spec, {'actions': proposals})
    return {'engine': 'achilles-local-followup-rc4', 'provider': 'ollama-loopback',
            'model': model, 'auto_executed': False, 'target_requests_sent': 0,
            'suggestions_reviewed': len(analysis.get('recommended_tests', [])),
            # Preserve only bounded advisory fields for the read-only AI dossier.
            # Rejected free-text instructions are NEVER stored or made executable.
            'local_ai_advice': {
                'executive_summary': str(analysis.get('executive_summary', ''))[:3000],
                'risk_observations': [x[:700] for x in analysis.get('risk_observations', [])[:30]
                                      if isinstance(x, str)],
                'recommended_tests': [x for x in analysis.get('recommended_tests', [])[:30]
                                       if isinstance(x, str) and x.strip() in ALLOWED],
                'limitations': [x[:700] for x in analysis.get('limitations', [])[:20]
                                if isinstance(x, str)],
            },
            'validated_actions': checked['accepted'],
            'discarded_free_text': len(analysis.get('recommended_tests', [])) - len(proposals),
            'limitations': ['Ollama è chiamato solo in locale.',
                            'Le proposte richiedono sempre una successiva approvazione.',
                            'I suggerimenti AI non sono evidenze di vulnerabilità.']}
