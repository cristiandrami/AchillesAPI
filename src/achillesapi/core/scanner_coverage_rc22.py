"""RC22 scanner inventory and active-test prerequisites, from OpenAPI schemas.

The RC15 network engine remains authoritative: this file generates a precise
plan, including nested body locations and unsafe mutation requirements.
"""
from __future__ import annotations

from typing import Any

from achillesapi.core.rc15_security import DEFAULT_FAMILIES, discover, relevant
from achillesapi.core.diagnostics_rc20 import diagnose


def scanner_plan(spec: dict[str, Any], *, approved_http: bool = False,
                 approved_writes: bool = False, has_disposable_fixture: bool = False,
                 max_points: int = 250) -> dict[str, Any]:
    if not 1 <= max_points <= 250:
        raise ValueError('max_points must be 1..250')
    points = discover(spec, max_points=max_points)
    tests = []
    for point in points:
        families = [name for name in DEFAULT_FAMILIES if relevant(point,name)]
        if not families:continue
        mutation = point.method in {'POST','PUT','PATCH','DELETE'}
        codes = []
        if not approved_http: codes.append('HTTP_CONSENT_REQUIRED')
        if mutation:
            if not has_disposable_fixture:codes.append('WORKFLOW_REQUIRED')
            if not approved_writes:codes.append('WRITES_CONSENT_REQUIRED')
        if point.location=='xml_body':
            # XXE needs an explicitly approved collector, not inferred from schema.
            codes.append('CONFIG_REQUIRED')
        if point.location=='file_upload':
            codes.append('CONFIG_REQUIRED')
        tests.append({'operation':point.operation, 'location':point.location,
                      'field':point.name,'mime_type':point.mime,
                      'families':families,'state':'ready' if not codes else 'blocked',
                      'requires_write':mutation,
                      'issues':[diagnose(code,action='rc15-scan') for code in dict.fromkeys(codes)]})
    coverage = {family:{'candidate_fields':sum(family in t['families'] for t in tests),
                        'ready_fields':sum(family in t['families'] and t['state']=='ready' for t in tests)}
                for family in DEFAULT_FAMILIES}
    return {'engine':'achilles-scanner-coverage-rc22','network_requests_sent':0,
            'tests':tests,'coverage':coverage,'eligible_cases':len(tests),
            'ready_cases':sum(t['state']=='ready' for t in tests),
            'requires_disposable_fixture':sum(t['requires_write'] for t in tests),
            'limitations':['Il piano non invia payload né dimostra una vulnerabilità.',
                           'SSRF blind/XXE richiedono callback raggiungibile e consenso separato.',
                           'XSS riflesso non equivale a esecuzione browser.',
                           'I test su body usano solo fixture temporanee con cleanup.']}
