"""v0.93: revisione Mass Assignment confrontando snapshot autorizzati.

Appunti: non scriviamo sull'API. Esaminiamo prima/dopo raccolti dal tester;
restituiamo nomi dei campi, non valori (che potrebbero essere sensibili).
"""
from __future__ import annotations

from typing import Any
import re


def review_mutations(report: dict[str, Any]) -> dict[str, Any]:
    """Segnala le modifiche ai campi protetti con riscontri prima/dopo."""
    if not isinstance(report, dict):
        raise ValueError('Serve un report JSON.')
    comparisons = report.get('state_comparisons') or []
    if not isinstance(comparisons, list):
        raise ValueError('state_comparisons deve essere un array.')
    findings = []
    for index, item in enumerate(comparisons[:300]):
        if not isinstance(item, dict):
            continue
        before, after = item.get('before'), item.get('after')
        protected = item.get('protected_fields') or []
        attempted = item.get('attempted_fields') or []
        if not (isinstance(before, dict) and isinstance(after, dict)
                and isinstance(protected, list) and isinstance(attempted, list)):
            continue
        # Consideriamo solo chiavi di primo livello, esplicitamente classificate.
        fields = sorted(set(x for x in protected if isinstance(x, str) and
                            re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,99}', x))
                        & set(x for x in attempted if isinstance(x, str) and
                              re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,99}', x)))[:100]
        changed = [name for name in fields if name in before and name in after
                   and before[name] != after[name]]
        missing = [name for name in fields if name not in before or name not in after]
        status = ('suspicious_change_requires_review' if changed else
                  'insufficient_snapshots' if missing else 'no_protected_change_observed')
        operation = str(item.get('operation', 'unknown')).split('?', 1)[0][:180]
        if not re.fullmatch(r'[A-Z]{3,8} /[A-Za-z0-9_./{}-]*', operation):
            operation = 'unknown'
        findings.append({'case': index + 1, 'operation': operation,
                         'status': status, 'changed_protected_fields': changed,
                         'unverifiable_fields': missing})
    return {
        'engine': 'achilles-mutation-review-v099', 'requests_sent': 0,
        'summary': {'cases_reviewed': len(findings),
                    'suspicious_changes': sum(x['status'] == 'suspicious_change_requires_review' for x in findings)},
        'cases': findings, 'confirmed_vulnerabilities': 0,
        'limitations': ['Non invia POST/PATCH/DELETE.',
                        'La differenza dei valori richiede conferma di policy, causalita e riproducibilita.',
                        'I valori delle risorse non vengono scritti nel report.'],
    }
