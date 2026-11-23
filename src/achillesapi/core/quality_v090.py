"""Controlli finali di qualità della campagna, senza inventare finding."""
from __future__ import annotations

from typing import Any


def assess_campaign_quality(report: dict[str, Any]) -> dict[str, Any]:
    """Rende espliciti blocchi, copertura e qualità delle evidenze.

    Se non esistono osservazioni HTTP, la campagna NON viene etichettata
    come assessment completo, anche se tutti i task offline sono riusciti.
    """
    steps = [x for x in report.get('steps', []) if isinstance(x, dict)]
    outcomes = {status: sum(s.get('status') == status for s in steps)
                for status in ('complete', 'failed', 'skipped')}
    coverage = report.get('preflight', {}).get('summary', {})
    verified = report.get('verification', {}).get('summary', {})
    observations = sum(max(0, int(s.get('http_observations') or 0)) for s in steps)
    checks = [
        {'id': 'execution', 'status': 'pass' if outcomes['failed'] == 0 else 'attention',
         'detail': f"{outcomes['failed']} task con errore"},
        {'id': 'skipped', 'status': 'pass' if outcomes['skipped'] == 0 else 'attention',
         'detail': f"{outcomes['skipped']} task non eseguiti"},
        {'id': 'http-evidence', 'status': 'pass' if observations else 'attention',
         'detail': f'{observations} osservazioni HTTP riportate dai job; non è il contatore di rete'},
        {'id': 'coverage', 'status': 'pass' if coverage.get('observed_operations') == coverage.get('operations')
         and coverage.get('operations', 0) > 0 else 'attention',
         'detail': f"{coverage.get('observed_operations', 0)}/{coverage.get('operations', 0)} operazioni osservate"},
        {'id': 'findings', 'status': 'review_required',
         'detail': f"{verified.get('requires_review', 0)} gruppi da verificare manualmente"},
    ]
    return {
        'engine': 'achilles-campaign-quality-v090', 'requests_sent': 0,
        'state': 'requires_review' if any(x['status'] != 'pass' for x in checks) else 'assessment_review_required',
        'metrics': {'total_steps': len(steps), **outcomes, 'reported_http_observations': observations,
                    'observed_operations': coverage.get('observed_operations', 0),
                    'total_openapi_operations': coverage.get('operations', 0),
                    'operator_confirmed_groups': verified.get('confirmed_by_operator', 0)},
        'checks': checks,
        'limitations': [
            'HTTP observations non è una misura affidabile di tutte le richieste inviate.',
            'Copertura endpoint non significa completezza dei test di vulnerabilità.',
            'La qualità finale richiede revisione del penetration tester.',
        ],
    }
