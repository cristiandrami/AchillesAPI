"""Matrice di test API: ipotesi per OWASP API Security Top 10 (2023).

Questa fase è SOLO pianificazione: non produce vulnerabilità confermate.
Le categorie sono etichette per aiutare il tester a organizzare il lavoro.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from achillesapi.core.openapi import parse_openapi


_ID = re.compile(r'\{(?:[^{}]*(?:id|uuid|key|ref|number)[^{}]*)\}', re.I)
_SEARCH = re.compile(r'(?:search|filter|query|where|sort|orderby|limit|offset|page)', re.I)


def build_risk_matrix(spec: dict[str, Any]) -> dict[str, Any]:
    """Genera test candidati spiegando cosa manca per eseguirli davvero."""
    parsed = parse_openapi(spec)
    candidates: list[dict[str, Any]] = []
    categories: Counter[str] = Counter()
    for ep in parsed.endpoints[:2000]:
        operation = f'{ep.method.upper()} {ep.path}'
        method = ep.method.upper()
        param_names = [p.name for p in ep.parameters]
        cases: list[tuple[str, str, str]] = []
        if _ID.search(ep.path):
            cases.append(('API1:2023', 'BOLA / object ownership',
                          'Due identità autorizzate e due risorse appartenenti a proprietari diversi'))
        if method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            cases.append(('API5:2023', 'Broken Function Level Authorization',
                          'Policy di ruoli verificata, profili distinti e, per scritture, fixture usa-e-getta'))
        if method in {'POST', 'PUT', 'PATCH'} and ep.request_body:
            cases.append(('API3:2023', 'Broken Object Property Level Authorization',
                          'Schema delle proprietà, policy di scrittura e dati di test reversibili'))
        if any(_SEARCH.search(name) for name in param_names):
            cases.append(('API4:2023', 'Unrestricted Resource Consumption / input limits',
                          'Soglie concordate; test a basso traffico e senza carico aggressivo'))
        if re.search(r'/(?:transfer|payment|approve|checkout|withdraw|refund|purchase)(?:/|$)', ep.path, re.I):
            cases.append(('API6:2023', 'Sensitive Business Flows',
                          'Regole di business documentate e approvazione esplicita'))
        for category, label, needs in cases:
            categories[category] += 1
            candidates.append({
                'operation': operation, 'owasp_category': category, 'hypothesis': label,
                'preconditions': needs, 'status': 'candidate_not_tested',
                'confirmed_vulnerability': False, 'requests_sent': 0,
            })
    return {
        'engine': 'achilles-api-risk-matrix-v090', 'requests_sent': 0,
        'summary': {'operations': len(parsed.endpoints), 'candidate_tests': len(candidates),
                    'categories': dict(sorted(categories.items()))},
        'candidates': candidates[:4000],
        'limitations': [
            'Le categorie OWASP sono ipotesi statiche, non vulnerabilità dimostrate.',
            'Non si eseguono payload o richieste al target.',
            'Le regole di accesso e business devono essere fornite o confermate dal proprietario.',
        ],
    }
