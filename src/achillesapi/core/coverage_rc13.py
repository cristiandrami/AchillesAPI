"""RC10: copertura verificabile, distinta dalla presenza di task nel registro."""
from __future__ import annotations

from collections import Counter
from typing import Any

from achillesapi.core.injection_planner_v2 import injection_surface_plan
from achillesapi.core.openapi import parse_openapi


def coverage_catalog(spec: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_openapi(spec)
    surfaces = injection_surface_plan(spec)
    by_method = Counter(endpoint.method for endpoint in parsed.endpoints)
    operations = sorted({f'{e.method} {e.path}' for e in parsed.endpoints})
    return {
        'api_name': parsed.title, 'operations_total': len(operations),
        'operations_by_method': dict(sorted(by_method.items())),
        'operations': operations, 'input_surfaces': surfaces,
        'principle': 'Le superfici documentate non equivalgono ai test realmente eseguiti.',
    }


def execution_coverage(catalog: dict[str, Any], stages: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Non calcolare falsi percentuali di sicurezza da task completati."""
    executed: set[str] = set()
    attempted: set[str] = set()
    for name, stage in stages.items():
        if not isinstance(stage, dict) or not stage.get('executed'):
            continue
        if name == 'injection':
            for case in stage.get('cases', []):
                if case.get('request_count', 0):
                    attempted.add(case['operation'])
                    if case.get('status') not in ('not_tested_auth', 'inconclusive'):
                        executed.add(case['operation'])
        elif name in {'advanced_get', 'bounded_get_security'}:
            for case in stage.get('cases', []):
                if case.get('requests_sent', 0):
                    attempted.add(case.get('operation', ''))
                    if case.get('status') not in ('inconclusive', 'not_executed', 'skipped_budget'):
                        executed.add(case.get('operation', ''))
        elif name == 'authorization':
            for rule in stage.get('rules', []):
                if rule.get('status') not in ('not_executed_budget_exhausted', 'not_executed'):
                    attempted.add(rule.get('operation', ''))
                    executed.add(rule.get('operation', ''))
        elif name == 'workflows':
            # Report del workflow non espone sempre operation per step:
            # NON attribuire automaticamente copertura endpoint per i suoi task.
            pass
    all_ops = set(catalog['operations'])
    return {
        'operations_documented': len(all_ops),
        'operations_with_http_attempts': len(attempted & all_ops),
        'operations_with_evaluable_http_results': len(executed & all_ops),
        'operations_not_verified': sorted(all_ops - executed),
        'coverage_not_a_security_score': True,
        'stages': {name: {'executed': bool(stage.get('executed')),
                          'requests_sent': stage.get('requests_sent', 0),
                          'finding_count': len(stage.get('findings', []))}
                   for name, stage in stages.items()},
    }
