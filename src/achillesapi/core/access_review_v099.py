"""v0.92: confronto autorizzazioni usando SOLO risposte HTTP gia registrate.

Appunti:
- La stessa operazione puo avere risposte diverse per utenti differenti.
- Una differenza non dimostra BOLA/BFLA: serve la regola di accesso attesa.
- Conserviamo soltanto codici HTTP, identita e nomi degli endpoint, mai token.
"""
from __future__ import annotations

from collections import defaultdict
import re
from typing import Any


def review_access_evidence(assessment: dict[str, Any]) -> dict[str, Any]:
    """Confronta identita per endpoint e segnala le anomalie da verificare."""
    if not isinstance(assessment, dict):
        raise ValueError('Il report deve essere un oggetto JSON.')
    execution = assessment.get('execution_report') or {}
    observations = execution.get('observations', []) if isinstance(execution, dict) else []
    if not isinstance(observations, list):
        raise ValueError('execution_report.observations deve essere una lista.')

    # La policy e' una dichiarazione dell'operatore, non un'inferenza da Swagger.
    expectations = assessment.get('access_expectations') or []
    if not isinstance(expectations, list):
        raise ValueError('access_expectations deve essere una lista.')
    expected: dict[tuple[str, str], str] = {}
    for entry in expectations[:500]:
        if not isinstance(entry, dict):
            continue
        operation, identity, access = (entry.get(k) for k in ('operation', 'identity', 'access'))
        if isinstance(operation, str) and isinstance(identity, str) and access in ('allow', 'deny'):
            expected[operation.split('?', 1)[0], identity[:64]] = access

    by_operation: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    total = 0
    for item in observations[:10000]:
        if not isinstance(item, dict):
            continue
        op, principal, status = item.get('operation'), item.get('identity'), item.get('status')
        if (not isinstance(op, str) or not isinstance(principal, str)
                or type(status) is not int or not 100 <= status <= 599):
            continue
        # Conserviamo solo path documentabili, non query string o URL con segreti.
        label = op.split('?', 1)[0].split('#', 1)[0][:180]
        if not re.fullmatch(r'[A-Z]{3,8} /[A-Za-z0-9_./{}-]*', label):
            continue
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', principal):
            continue
        by_operation[label][principal].add(status)
        total += 1

    differences = []
    policy_conflicts = []
    for operation, roles in sorted(by_operation.items())[:1500]:
        # Differenze per classe: 200 vs 201 non basta per indicare accesso diverso.
        classes = {name: sorted({status // 100 for status in statuses})
                   for name, statuses in roles.items()}
        if len(roles) >= 2 and len({tuple(k) for k in classes.values()}) > 1:
            differences.append({'operation': operation, 'status': 'difference_needs_review',
                                'identity_status_classes': classes})
        for name, statuses in roles.items():
            rule = expected.get((operation, name))
            if not rule:
                continue
            success = any(200 <= s < 300 for s in statuses)
            if (rule == 'deny' and success) or (rule == 'allow' and all(s in (401, 403) for s in statuses)):
                policy_conflicts.append({
                    'operation': operation, 'identity': name, 'expected': rule,
                    'observed_status_codes': sorted(statuses),
                    'status': 'policy_conflict_requires_confirmation',
                })

    return {
        'engine': 'achilles-access-evidence-v099', 'requests_sent': 0,
        'summary': {'recorded_responses': total, 'operations_compared': len(by_operation),
                    'response_differences': len(differences), 'policy_conflicts': len(policy_conflicts)},
        'differences': differences, 'policy_conflicts': policy_conflicts,
        'confirmed_vulnerabilities': 0,
        'limitations': [
            'Analisi offline: non crea nuovi test BOLA/BFLA.',
            'Una policy indicata dall’operatore va verificata prima di dichiarare una vulnerabilita.',
            'Codici 2xx/401/403 non dimostrano da soli ownership o accesso a dati riservati.',
        ],
    }
