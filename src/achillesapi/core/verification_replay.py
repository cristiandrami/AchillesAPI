"""Read-only, scoped replay of bounded injection indicators.

The replay is a second independent control/probe pair. Matching HTTP
characteristics strengthen evidence but NEVER confirm an exploit by themselves.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from achillesapi.core.http import SafeHTTPClient
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.workflows import get_read_side_effect_risk


def replay_readonly_indicators(spec: dict[str, Any], findings: list[dict[str, Any]], *,
                               base_url: str, allowed_hosts: set[str],
                               auth: Any = None, path_values: dict[str, str] | None = None,
                               max_requests: int = 4, rate: float = 2.) -> dict[str, Any]:
    """Replay up to two query-based GET findings using recorded fixed test inputs."""
    if not 1 <= max_requests <= 20:
        raise ValueError('Budget riproducibilità non valido')
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=max_requests,
                            requests_per_second=rate)
    endpoints = {f'{e.method} {e.path}': e for e in parse_openapi(spec).endpoints}
    tested = []
    for finding in findings:
        if len(tested) >= 2 or int(client.request_statistics['attempted']) + 2 > max_requests:
            break
        operation = finding.get('operation')
        ep = endpoints.get(operation)
        if ep is None or ep.method != 'GET' or get_read_side_effect_risk(ep):
            continue
        if finding.get('location') not in (None, 'query'):
            continue
        parameter = finding.get('parameter') or finding.get('field')
        if (not isinstance(parameter, str) or parameter.lower() in
            {'token', 'secret', 'password', 'authorization', 'cookie'} or
            not any(p.name == parameter and p.location == 'query' for p in ep.parameters)):
            continue
        payloads = finding.get('test_payloads', [])
        baseline = finding.get('test_baseline')
        if not (isinstance(baseline, str) and isinstance(payloads, list)
                and payloads and isinstance(payloads[0], str) and len(payloads[0]) <= 160):
            continue
        path = ep.path
        valid_path = True
        for param in re.findall(r'\{([^{}]+)\}', path):
            val = (path_values or {}).get(param, '')
            if not isinstance(val, str) or not val or any(x in val for x in '/\\?#%') or val in {'.', '..'}:
                valid_path = False
                break
            path = path.replace('{'+param+'}', quote(val, safe=''))
        if not valid_path:
            continue
        outcomes = []
        for value in (baseline, payloads[0]):
            material = auth
            res = client.request('GET', base_url.rstrip('/')+path,
                execute=True, headers=getattr(material, 'headers', None) or {},
                cookies=getattr(material, 'cookies', None) or {},
                params={**(getattr(material, 'params', None) or {}), parameter: value},
                sensitive_header_names=set(getattr(material, 'headers', None) or {}),
                sensitive_query_names=set(getattr(material, 'params', None) or {}))
            r = res.response
            outcomes.append({'status': r.status_code if r else None,
                             'length': len(r.body_preview) if r else None,
                             'truncated': bool(r.body_truncated) if r else None})
        original = finding.get('evidence') or {}
        expected_base = (original.get('baseline') or {}).get('status')
        expected_variant = ((original.get('variants') or [{}])[0] or {}).get('status')
        reproducible_status = (expected_base is not None and expected_variant is not None
                               and outcomes[0]['status'] == expected_base
                               and outcomes[1]['status'] == expected_variant and
                               not any(o['truncated'] for o in outcomes))
        tested.append({'operation': operation, 'parameter': parameter,
                       'finding_category': finding.get('category'),
                       'requests_sent': 2,
                       'status': 'indicator_reproduced_not_exploit_confirmed' if reproducible_status
                                 else 'inconclusive_or_not_reproduced',
                       'status_comparison': outcomes,
                       'payload': payloads[0], 'control': baseline})
    return {'engine': 'achilles-readonly-replay', 'executed': True,
            'requests_sent': client.request_statistics['attempted'],
            'results': tested, 'findings': [],
            'limitations': ['Riproducibilità HTTP non equivale a exploit confermato.',
                            'Non vengono registrati corpi di risposta o credenziali.']}
