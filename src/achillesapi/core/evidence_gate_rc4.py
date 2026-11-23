"""RC4 — Controllo dei livelli di prova prima di pubblicare finding.

Appunti:
- Non prendiamo per buona l'etichetta 'confirmed' ricevuta da un tool.
- Cerchiamo riferimento a policy, osservazione e riproduzione indipendente.
- Il risultato di questo modulo è sempre una *valutazione della prova*.
"""
from __future__ import annotations

import re
from typing import Any

_SAFE_ID = re.compile(r'^[A-Za-z0-9_.:/-]{1,100}$')


def review_proof_records(document: dict[str, Any]) -> dict[str, Any]:
    """Valuta le prove dichiarate dall'operatore senza contattare il target."""
    if not isinstance(document, dict) or not isinstance(document.get('records'), list):
        raise ValueError('Serve un documento con records: [...]')
    if len(document['records']) > 500:
        raise ValueError('Limite massimo: 500 record')
    reviewed = []
    for index, row in enumerate(document['records'], start=1):
        if not isinstance(row, dict):
            raise ValueError(f'Record {index}: formato non valido')
        finding_id = row.get('finding_id', '')
        if not isinstance(finding_id, str) or not _SAFE_ID.fullmatch(finding_id):
            raise ValueError(f'Record {index}: finding_id non valido')
        # Sono soltanto riferimenti a evidenze, non contenuti HTTP sensibili.
        refs = row.get('evidence_refs', [])
        if (not isinstance(refs, list) or len(refs) > 20 or
            any(not isinstance(ref, str) or not _SAFE_ID.fullmatch(ref) for ref in refs)):
            raise ValueError(f'Record {index}: evidence_refs non validi')
        policy = row.get('independent_policy_ref')
        reproducible = row.get('reproduced') is True
        has_policy = isinstance(policy, str) and bool(_SAFE_ID.fullmatch(policy))
        unique_refs = sorted(set(refs))
        # Per considerare le prove 'sufficienti per una revisione' occorrono
        # almeno due evidenze distinte, una policy e riproduzione dichiarata.
        substantiated = has_policy and reproducible and len(unique_refs) >= 2
        reviewed.append({'finding_id': finding_id,
                         'evidence_reference_count': len(unique_refs),
                         'policy_reference_present': has_policy,
                         'reproduced_by_operator': reproducible,
                         'evidence_status': 'ready_for_manual_confirmation' if substantiated
                         else 'insufficient_evidence',
                         'confirmed_automatically': False})
    return {'engine': 'achilles-proof-gate-rc4', 'network_requests_sent': 0,
            'records': reviewed,
            'summary': {'total': len(reviewed),
                        'ready_for_review': sum(r['evidence_status'] == 'ready_for_manual_confirmation'
                                                for r in reviewed)},
            'limitations': ['I riferimenti non sostituiscono le evidenze originali.',
                            'Nessuna vulnerabilità viene confermata automaticamente.',
                            'La conferma finale spetta al penetration tester.']}
