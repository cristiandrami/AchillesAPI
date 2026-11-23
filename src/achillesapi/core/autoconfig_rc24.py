"""Exhaustive, passive OpenAPI operation coverage plan.

The proposal is not proof of a security flaw and does not authorize HTTP,
object access, identity comparisons or writes. Every operation is retained,
even if a matching CRUD workflow cannot be discovered.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from achillesapi.core.openapi import parse_openapi
from achillesapi.core.workflow_automation_rc16 import discover_resource_workflows, draft_multi_resource_manifest
from achillesapi.core.workflows import get_read_side_effect_risk

_PARAM = re.compile(r'\{([^{}]+)\}')


def _url_suggestion(spec: dict[str, Any]) -> str | None:
    """Propose one unambiguous absolute origin, never approve its scope."""
    servers = spec.get('servers', [])
    if not isinstance(servers, list) or len(servers) != 1:
        return None
    raw = servers[0].get('url') if isinstance(servers[0], dict) else None
    if not isinstance(raw, str) or '{' in raw or '}' in raw or len(raw) > 250:
        return None
    url = urlsplit(raw)
    if url.scheme not in {'https', 'http'} or not url.hostname or url.username or url.password:
        return None
    if url.query or url.fragment or url.hostname not in {'localhost', '127.0.0.1'} and url.scheme != 'https':
        return None
    return raw.rstrip('/')


def build_autoconfiguration(spec: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_openapi(spec)
    discovered = discover_resource_workflows(spec, max_candidates=100)
    workflows = discovered['candidates']
    linked: dict[str, list[str]] = {}
    for candidate in workflows:
        for operation in [candidate['create'], candidate['read'],
                          candidate.get('cleanup'), *(candidate.get('mutations') or [])]:
            if operation:
                linked.setdefault(operation, []).append(candidate['resource'])
    rows: list[dict[str, Any]] = []
    for ep in parsed.endpoints:
        op = f'{ep.method} {ep.path}'
        path_ids = list(dict.fromkeys(_PARAM.findall(ep.path)))
        query = [p.name for p in ep.parameters if p.location == 'query' and p.required]
        body = ep.method in {'POST', 'PUT', 'PATCH', 'DELETE'}
        try:
            side_effect = ep.method == 'GET' and bool(get_read_side_effect_risk(ep))
        except (KeyError, TypeError, ValueError):
            side_effect = True
        is_read = ep.method == 'GET' and not side_effect
        blockers = []
        if is_read and path_ids:
            blockers.append('resource_ids')
        if is_read and query:
            blockers.append('required_query')
        if body:
            blockers.extend(['approved_fixture', 'write_consent'])
        if side_effect:
            blockers.append('get_side_effect_risk')
        if ep.method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}:
            blockers.append('dedicated_method_engine')
        categories = []
        if is_read:
            categories.append('read_scan')
            if path_ids:
                categories.append('bola_candidate')
        if body:
            categories.append('workflow_write')
            if ep.method in {'PATCH', 'PUT'}:
                categories.extend(['mass_assignment_candidate', 'bfla_candidate'])
            else:
                categories.append('bfla_candidate')
        rows.append({'operation': op, 'method': ep.method, 'path': ep.path,
                     'path_parameters': path_ids, 'required_query': query,
                     'workflow_resources': linked.get(op, []), 'categories': categories,
                     'automatic_selection': True, 'status': ('read_candidate' if is_read and not blockers else
                     'requires_input' if blockers else 'discovery_only'),
                     'missing_inputs': blockers, 'active_authorized': False})
    summary = {'total_operations': len(rows),
               'read_candidates': sum('read_scan' in x['categories'] for x in rows),
               'immediately_parameterizable_gets': sum(x['status'] == 'read_candidate' for x in rows),
               'object_access_candidates': sum('bola_candidate' in x['categories'] for x in rows),
               'write_candidates': sum('workflow_write' in x['categories'] for x in rows),
               'operations_requiring_input': sum(x['status'] == 'requires_input' for x in rows),
               'discovered_workflows': discovered['total_candidates'],
               'workflow_discovery_limited': discovered['total_candidates'] > len(workflows)}
    # Offline, intentionally NONEXECUTABLE multi-resource draft. Its placeholders
    # must be replaced and validated before any POST/PATCH/DELETE.
    try:
        draft = draft_multi_resource_manifest(spec, max_candidates=10)
    except (ValueError, TypeError, KeyError):
        draft = {'resources': []}
    return {'engine': 'achilles-autoconfig-rc24', 'requests_sent': 0,
            'workflow_draft': draft, 'workflow_draft_incomplete': True,
            'summary': summary, 'operations': rows,
            'suggested_base_url': _url_suggestion(spec),
            'workflow_candidates': workflows,
            'notes': ['Tutti i path sono inventariati, anche senza POST/DELETE.',
                      'Il piano non equivale all’esecuzione né alla copertura delle vulnerabilità.',
                      'Le policy business, credenziali e ID reali non sono deducibili in modo affidabile.',
                      'Le scritture richiedono sempre fixture validate e approvazione esplicita.']}
