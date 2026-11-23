"""Conservative, offline findings triage; no invented proof or exploit claims."""
from __future__ import annotations

import hashlib
from typing import Any

from achillesapi.reporting.professional import summarize_assessment


def classify_findings(assessment: dict[str, Any]) -> dict[str, Any]:
    """Deduplicate indicators while preserving independent evidence limitations.

    Only explicitly trusted operator verdicts can produce 'confirmed'. The
    scanner/AI cannot self-certify a vulnerability from response status alone.
    """
    if not isinstance(assessment, dict):
        raise ValueError('Assessment must be an object')
    found = summarize_assessment(assessment).get('findings', [])
    if not found and isinstance(assessment.get('report_schema'), str) and isinstance(assessment.get('findings'), list):
        # Un report professionale espone finding al primo livello: li leggiamo
        # come evidenze già SANITIZZATE, senza trasformarli in conferme.
        normalized = {'plan': {'operations': []},
                      'execution_report': {'findings': assessment['findings'][:2000]}}
        found = summarize_assessment(normalized).get('findings', [])
    groups: dict[str, dict[str, Any]] = {}
    for f in found[:2000]:
        if not isinstance(f, dict):
            continue
        category = str(f.get('category') or 'unclassified')[:90]
        operation = str(f.get('operation') or 'unknown')[:180]
        key = category.lower() + '|' + operation.upper()
        fingerprint = hashlib.sha256(key.encode()).hexdigest()[:16]
        verdict = f.get('operator_verdict')
        if verdict not in ('confirmed', 'false_positive'):
            verdict = 'requires_review'
        group = groups.setdefault(fingerprint, {
            'fingerprint': fingerprint, 'category': category,
            'operation': operation, 'severity': f.get('severity', 'informational'),
            'status': verdict, 'occurrences': 0, 'indicators': [],
            'verification': 'operator_review_required' if verdict == 'requires_review' else 'operator_supplied',
        })
        group['occurrences'] += 1
        indicator = str(f.get('reason') or '')[:400]
        if indicator and indicator not in group['indicators']:
            group['indicators'].append(indicator)
    result = list(groups.values())
    return {
        'engine': 'achilles-evidence-triage-v080',
        'requests_sent': 0,
        'summary': {'raw_indicators': len(found), 'deduplicated_groups': len(result),
                    'requires_review': sum(x['status'] == 'requires_review' for x in result),
                    'confirmed_by_operator': sum(x['status'] == 'confirmed' for x in result)},
        'findings': result,
        'limitations': ['Deduplica per categoria ed endpoint; non dimostra sfruttabilità.',
                        'Anomalie HTTP e output AI non costituiscono conferma automatica.',
                        'Le conferme devono essere indipendenti e tracciabili.'],
    }
