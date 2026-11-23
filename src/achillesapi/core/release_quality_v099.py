"""v0.91/v0.95/v0.99: diagnostica conservativa della suite.

Appunti: un task completato non equivale a vulnerabilita assente. Il gate
riconosce campagne incomplete e aiuta a capire cosa manca prima di un report.
"""
from __future__ import annotations

from typing import Any


def diagnose_campaign(report: dict[str, Any]) -> dict[str, Any]:
    """Rileva incoerenze negli esiti della suite senza inviare richieste."""
    if not isinstance(report, dict):
        raise ValueError('Il file deve contenere un report JSON.')
    steps = report.get('steps', [])
    if not isinstance(steps, list):
        raise ValueError('steps deve essere una lista.')
    counts = {state: sum(isinstance(s, dict) and s.get('status') == state for s in steps)
              for state in ('complete', 'failed', 'skipped')}
    unknown = len(steps) - sum(counts.values())
    reasons = []
    if not steps:
        reasons.append('Nessun task della campagna registrato.')
    if counts['failed']:
        reasons.append(f"{counts['failed']} task falliti da analizzare.")
    if counts['skipped']:
        reasons.append(f"{counts['skipped']} task saltati: verificare applicabilita e prerequisiti.")
    if unknown:
        reasons.append(f'{unknown} task senza stato conclusivo.')
    if report.get('status') in ('interrupted', 'stopped_by_operator'):
        reasons.append('Campagna interrotta prima del completamento.')
    observations = sum(max(0, int(s.get('http_observations') or 0))
                       for s in steps if isinstance(s, dict))
    if not observations:
        reasons.append('Nessuna risposta HTTP documentata: analisi solo offline o incompleta.')
    return {
        'engine': 'achilles-campaign-diagnostics-v099', 'requests_sent': 0,
        'status': 'needs_attention' if reasons else 'ready_for_operator_review',
        'summary': {'steps': len(steps), **counts, 'nonfinal': unknown,
                    'http_observations': observations},
        'issues': reasons,
        'limitations': ['Le osservazioni HTTP non rappresentano il numero di richieste tentate.',
                        'Il gate non certifica assenza di vulnerabilita o adeguatezza della copertura.'],
    }


def assess_release_readiness(report: dict[str, Any]) -> dict[str, Any]:
    """Valuta solo la completezza formale, senza dichiarare production-ready."""
    diagnostics = diagnose_campaign(report)
    findings = report.get('verification') or {}
    review = findings.get('summary') or {} if isinstance(findings, dict) else {}
    pending = int(review.get('requires_review') or 0) if isinstance(review, dict) else 0
    checks = [
        {'name': 'execution', 'pass': not diagnostics['summary']['failed'] and not diagnostics['summary']['nonfinal']},
        {'name': 'coverage_review', 'pass': diagnostics['summary']['http_observations'] > 0},
        {'name': 'task_blocks', 'pass': not diagnostics['summary']['skipped']},
        {'name': 'finding_review', 'pass': pending == 0},
        {'name': 'campaign_not_interrupted', 'pass': report.get('status') not in ('interrupted', 'stopped_by_operator')},
    ]
    return {
        'engine': 'achilles-release-gate-v099', 'requests_sent': 0,
        'state': 'requires_operator_review',
        'formal_checks_passed': sum(x['pass'] for x in checks),
        'formal_checks_total': len(checks),
        'checks': checks, 'diagnostics': diagnostics,
        'limitations': ['Il risultato non certifica la sicurezza del target.',
                        'La produzione richiede benchmark indipendenti, threat model e audit di sicurezza.'],
    }
