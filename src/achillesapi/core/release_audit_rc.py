"""Audit offline dei risultati della campagna prima del rilascio di un report.

Appunti: non assegniamo automaticamente l'etichetta 'confirmed'.
Un report deve distinguere l'esecuzione reale, i task saltati e le ipotesi.
"""
from __future__ import annotations

from typing import Any


def audit_campaign(report: dict[str, Any]) -> dict[str, Any]:
    """Applica regole semplici di qualità senza contattare alcun server."""
    if not isinstance(report, dict):
        raise ValueError('Il report deve contenere un oggetto JSON')
    steps = report.get('steps')
    if not isinstance(steps, list):
        raise ValueError('Il report non contiene la lista dei task eseguiti')
    errors = []
    warnings = []
    if not steps:
        errors.append('Nessun task registrato')
    incomplete = [s for s in steps if isinstance(s, dict) and s.get('status') in {'running','orchestrating'}]
    failed = [s for s in steps if isinstance(s, dict) and s.get('status') == 'failed']
    skipped = [s for s in steps if isinstance(s, dict) and s.get('status') == 'skipped']
    if incomplete:
        errors.append(f'{len(incomplete)} task non terminati')
    if failed:
        warnings.append(f'{len(failed)} task falliti')
    if skipped:
        warnings.append(f'{len(skipped)} task saltati: non equivalgono a test superati')
    telemetry = report.get('http_telemetry')
    if report.get('mode') == 'active':
        if not isinstance(telemetry, dict) or telemetry.get('scope') != 'campaign_all_processes':
            errors.append('Contabilità HTTP globale non disponibile')
        else:
            if telemetry.get('attempted', 0) > telemetry.get('limit', 0):
                errors.append('Superato il budget HTTP dichiarato')
            if telemetry.get('pending', 0):
                warnings.append('Tentativi HTTP senza esito contabilizzato')
    elif report.get('mode') != 'offline':
        warnings.append('Modalità della campagna non riconosciuta')
    return {'engine': 'achilles-release-audit-rc2', 'network_requests_sent': 0,
            'status': 'blocked' if errors else 'review_required' if warnings else 'ready_for_review',
            'errors': errors, 'warnings': warnings,
            'summary': {'tasks': len(steps), 'failed': len(failed),
                        'skipped': len(skipped), 'incomplete': len(incomplete)},
            'statement': 'La readiness riguarda la qualità del report, non garantisce che l’API sia sicura.'}
