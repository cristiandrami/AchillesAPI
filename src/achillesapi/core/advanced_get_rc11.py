"""RC11: verifiche GET conservative con payload espliciti e controlli negativi.

NON prova automaticamente XSS, SSRF o path traversal; i risultati sono osservazioni.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote
import re

from achillesapi.core.http import SafeHTTPClient
from achillesapi.core.openapi import parse_openapi

_MARKER = 'ACHILLES_REFLECTION_7183'
_PROBES = {'reflection': _MARKER + '<probe>', 'redirect': 'https://example.invalid/achilles-redirect'}
_SENSITIVE = re.compile(r'password|token|secret|auth|cookie|key|credential', re.I)


def advanced_get_scan(spec: dict[str, Any], *, base_url: str, allow_hosts: set[str],
                      execute: bool = False, allow_insecure_http: bool = False,
                      max_requests: int = 20, rate: float = 2.0,
                      path_values: dict[str, str] | None = None,
                      auth: Any = None) -> dict[str, Any]:
    """Solo GET autorizzate, nessun redirect seguito, nessuna enumerazione di ID."""
    from urllib.parse import urlsplit
    if execute and urlsplit(base_url).scheme == 'http' and auth and not allow_insecure_http:
        raise ValueError('HTTP con credenziali non autorizzato')
    if not 1 <= max_requests <= 150:
        raise ValueError('Budget fuori intervallo')
    client = SafeHTTPClient(allowed_hosts=allow_hosts, max_requests=max_requests, requests_per_second=rate)
    path_values = path_values or {}
    candidates: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for e in parse_openapi(spec).endpoints:
        if e.method != 'GET':
            continue
        path = e.path
        missing = False
        for key in re.findall(r'\{([^{}]+)\}', path):
            value = path_values.get(key)
            if not isinstance(value, str) or not value or any(x in value for x in '/\\?#%'):
                missing = True
                break
            path = path.replace('{' + key + '}', quote(value, safe=''))
        if missing:
            skipped.append({'operation': f'GET {e.path}', 'reason': 'Identificativo path non fornito'})
            continue
        for param in e.parameters:
            if param.location != 'query' or _SENSITIVE.search(param.name):
                continue
            candidates.append({'operation': f'GET {e.path}', 'path': path,
                               'parameter': param.name})
    cases = []
    for candidate in candidates:
        if execute and client.request_statistics['attempted'] + 2 > max_requests:
            skipped.append({'operation': candidate['operation'], 'reason': 'Budget insufficiente'})
            continue
        case = {k: v for k, v in candidate.items() if k != 'path'}
        case.update({'status': 'not_executed', 'requests_sent': 0})
        cases.append(case)
        if not execute:
            continue
        params = dict(getattr(auth, 'params', {}) or {})
        headers = dict(getattr(auth, 'headers', {}) or {})
        cookies = dict(getattr(auth, 'cookies', {}) or {})
        url = base_url.rstrip('/') + candidate['path']
        try:
            controls = []
            for payload in (_MARKER, _PROBES['reflection']):
                result = client.request('GET', url, execute=True, headers=headers, cookies=cookies,
                    params={**params, candidate['parameter']: payload},
                    sensitive_query_names=set(params), sensitive_header_names=set(headers))
                response = result.response
                controls.append((response.status_code if response else None,
                                 response.body_preview or '' if response else '',
                                 response.body_truncated if response else None))
            case['requests_sent'] = 2
            # Riflessione diversa da XSS. Non affermare esecuzione JS.
            reflected = all(_MARKER in item[1] for item in controls)
            marker_exposed = '<probe>' in controls[1][1] and '<probe>' not in controls[0][1]
            if reflected and marker_exposed and not any(item[2] for item in controls):
                case['status'] = 'manual_review'
                case['evidence'] = {'statuses': [item[0] for item in controls],
                                    'payloads': [_MARKER, _PROBES['reflection']],
                                    'reason': 'Input HTML-like riflesso senza escaping evidente; verificare contesto e CSP.'}
            else:
                case['status'] = 'no_indicator' if all(item[0] is not None for item in controls) else 'inconclusive'
        except Exception as exc:
            case['status'] = 'inconclusive'
            case['reason'] = type(exc).__name__
    return {'engine': 'achilles-advanced-get-rc11', 'executed': execute,
            'requests_sent': client.request_statistics['attempted'], 'cases': cases,
            'findings': [{'category': 'possible_reflected_input', 'operation': c['operation'],
                          'parameter': c['parameter'], 'severity': 'informational',
                          'verification_status': 'requires_manual_review',
                          'evidence': c['evidence'], 'test_payloads': c['evidence']['payloads']}
                         for c in cases if c['status'] == 'manual_review'],
            'skipped': skipped,
            'limitations': ['Riflessione non equivale a XSS confermata.',
                            'SSRF, XXE, file upload e race condition non vengono eseguiti automaticamente.']}
