"""Bounded GET safety checks for redirect, HTML reflection and traversal indicators.

No redirect is followed, no internal URL is fetched, no file contents are
requested, and this module NEVER produces confirmed exploit findings. Write
operations, OAST/SSRF and uploads require separate approved fixture workflows.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from achillesapi.core.http import SafeHTTPClient
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.workflows import get_read_side_effect_risk

_SENSITIVE = re.compile(r'(?:token|secret|password|key|session|cookie|auth)', re.I)
_URL = re.compile(r'(?:redirect|return_?to|next_?url|continue|callback_?url)', re.I)
_PATH = re.compile(r'(?:filename|filepath|file_?path|directory|file|document_?path)', re.I)
_MARKER = 'ACHILLES_CHECK_92317'


def _url(base: str, template: str, values: dict[str, str]) -> str | None:
    def substitute(m: re.Match[str]) -> str:
        v = values.get(m.group(1), '')
        if not v or len(v) > 128 or any(c in v for c in '/\\?#%\r\n') or v in ('.','..'):
            raise ValueError('Parametro path mancante/non sicuro')
        return quote(v, safe='')
    try:
        return base.rstrip('/') + re.sub(r'\{([^{}]+)\}', substitute, template)
    except ValueError:
        return None


def scan_bounded_get(spec: dict[str, Any], *, base_url: str, allowed_hosts: set[str],
                     auth: Any = None, path_values: dict[str, str] | None = None,
                     execute: bool = False, max_requests: int = 12,
                     rate: float = 2.0) -> dict[str, Any]:
    """Bounded read-only active tests, all requests subject to SafeHTTPClient scope."""
    if not 1 <= max_requests <= 100:
        raise ValueError('Budget scanner GET fuori intervallo')
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=max_requests,
                            requests_per_second=rate)
    cases: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for ep in parse_openapi(spec).endpoints:
        if ep.method != 'GET':
            continue
        if get_read_side_effect_risk(ep):
            skipped.append({'operation': f'GET {ep.path}', 'reason': 'GET potenzialmente con effetti collaterali'})
            continue
        address = _url(base_url, ep.path, path_values or {})
        if not address:
            skipped.append({'operation': f'GET {ep.path}', 'reason': 'ID path non disponibile'})
            continue
        for parm in ep.parameters:
            if parm.location != 'query' or _SENSITIVE.search(parm.name):
                continue
            kind = ('redirect' if _URL.search(parm.name) else
                    'traversal' if _PATH.search(parm.name) else 'reflection')
            if kind == 'redirect':
                values = ('achilles-check', 'https://example.invalid/achilles-check')
            elif kind == 'traversal':
                values = ('achilles-not-a-file.txt', '../achilles-not-a-file.txt')
            else:
                values = (_MARKER, '<achilles-'+_MARKER+'>')
            row: dict[str, Any] = {'operation': f'GET {ep.path}', 'parameter': parm.name,
                    'technique': kind, 'payloads': list(values), 'status': 'not_executed',
                    'requests_sent': 0}
            cases.append(row)
            if not execute:
                continue
            if int(client.request_statistics['attempted']) + 2 > max_requests:
                row['status'] = 'skipped_budget'
                continue
            observed = []
            for val in values:
                result = client.request('GET', address, execute=True,
                         params={**(getattr(auth, 'params', None) or {}), parm.name: val},
                         headers=getattr(auth, 'headers', None) or {},
                         cookies=getattr(auth, 'cookies', None) or {},
                         sensitive_query_names=set(getattr(auth, 'params', None) or {}),
                         sensitive_header_names=set(getattr(auth, 'headers', None) or {}))
                part = result.response
                observed.append({'status': part.status_code if part else None,
                                 'redirect_host': part.redirect_host if part else None,
                                 'body': part.body_preview if part else '',
                                 'truncated': part.body_truncated if part else False})
            row['requests_sent'] = 2
            status0, status1 = observed[0]['status'], observed[1]['status']
            if status0 is None or status1 is None or any(x['truncated'] for x in observed):
                row['status'] = 'inconclusive'
                continue
            signal = False
            description = ''
            if kind == 'redirect':
                signal = 300 <= status1 < 400 and observed[1]['redirect_host'] == 'example.invalid' and observed[0]['redirect_host'] != 'example.invalid'
                description = 'Redirect verso hostname di prova esterno; nessun redirect è stato seguito.'
            elif kind == 'reflection':
                signal = ('<achilles-'+_MARKER+'>' in observed[1]['body'] and
                          '<achilles-'+_MARKER+'>' not in observed[0]['body'])
                description = 'Input con tag HTML riflesso non codificato; non dimostra esecuzione JavaScript.'
            elif kind == 'traversal':
                signal = status0 != status1 and status1 >= 500
                description = 'Il percorso relativo fittizio causa errore server diverso dal controllo; non dimostra lettura file.'
            row['status'] = 'manual_review' if signal else 'no_indicator'
            if signal:
                findings.append({'category': {'redirect':'possible_open_redirect',
                                              'reflection':'possible_html_reflection',
                                              'traversal':'possible_path_handling_error'}[kind],
                    'severity': 'medium' if kind == 'redirect' else 'informational',
                    'operation': row['operation'], 'field': parm.name,
                    'test_payloads': list(values), 'verification_status': 'requires_manual_review',
                    'reason': description, 'evidence': {'baseline_status': status0,
                        'probe_status': status1, 'redirect_destination_host': observed[1]['redirect_host'],
                        'requests_compared': 2}})
            # Raw response text intentionally NEVER reaches JSON output.
    return {'engine': 'achilles-bounded-get-scanner', 'executed': execute,
        'requests_sent': client.request_statistics['attempted'], 'cases': cases,
        'findings': findings, 'skipped': skipped,
        'limitations': ['XSS, traversal e redirect sono indicatori, non exploit confermati.',
                         'SSRF non è verificabile senza callback controllato.',
                         'XXE e upload richiedono una fixture con scritture esplicitamente autorizzate.']}
