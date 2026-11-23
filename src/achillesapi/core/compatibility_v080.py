"""Offline OpenAPI compatibility and coverage planning (no target traffic).

This module infers *possibility*, never authorization, test success, ownership,
or exploitability. Unknown business rules remain explicitly unknown.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from achillesapi.core.openapi import load_openapi, parse_openapi

_READ = {'GET', 'HEAD', 'OPTIONS'}
_WRITE = {'POST', 'PUT', 'PATCH', 'DELETE'}
_SLOT = re.compile(r'\{[^{}]+\}')


def _clean_path(path: str) -> str:
    return _SLOT.sub('{id}', path).rstrip('/') or '/'


def _operation_id(item: Any) -> str:
    return f'{item.method} {item.path}'


def match_observations(operation: str, observations: list[dict[str, Any]]) -> int:
    """Count real HTTP observations matching a templated OpenAPI operation."""
    method, _, template = operation.partition(' ')
    template = template.split('?', 1)[0]
    pattern = '^' + re.escape(template).replace(r'\{', '{').replace(r'\}', '}') + '$'
    pattern = re.sub(r'\{[^{}]+\}', r'[^/]+', pattern)
    try:
        matcher = re.compile(pattern)
    except re.error:
        return 0
    count = 0
    for obs in observations[:10000]:
        if not isinstance(obs, dict):
            continue
        recorded = obs.get('operation') or f"{obs.get('method','')} {obs.get('path','')}"
        if not isinstance(recorded, str):
            continue
        parts = recorded.split(' ', 1)
        if len(parts) != 2 or parts[0].upper() != method.upper():
            continue
        if matcher.fullmatch(parts[1].split('?', 1)[0]):
            count += 1
    return count


def _extract_observations(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    execution = document.get('execution_report')
    if isinstance(execution, dict) and isinstance(execution.get('observations'), list):
        return [v for v in execution['observations'] if isinstance(v, dict)]
    if isinstance(document.get('responses'), list):
        return [v for v in document['responses'] if isinstance(v, dict)]
    return []


def analyze_compatibility(spec: dict[str, Any], *, has_auth: bool = False,
                          active_allowed: bool = False, writes_approved: bool = False,
                          ai_enabled: bool = False,
                          assessment: dict[str, Any] | None = None) -> dict[str, Any]:
    """Produce an operation x check matrix and preflight tool gate reasons.

    Applicability is derived only from declarative OpenAPI surface. It does not
    assert that a credential works or that a potential test is exploitable.
    """
    parsed = parse_openapi(spec)
    observations = _extract_observations(assessment)
    entries = []
    methods = Counter()
    path_params = 0
    protected = 0
    for ep in parsed.endpoints[:2000]:
        method = ep.method.upper()
        methods[method] += 1
        required = [p.name for p in ep.parameters if p.required]
        security_names = sorted({key for requirement in ep.security for key in requirement.schemes})
        uses_security = bool(security_names)
        if uses_security:
            protected += 1
        is_read = method in _READ
        requires_body = method in _WRITE and bool(ep.request_body)
        missing = []
        if any(p.location == 'path' and p.required for p in ep.parameters):
            missing.append('Valori dei parametri path')
            path_params += 1
        if method in _WRITE:
            missing.append('Fixture e policy di cleanup approvate')
        if uses_security and not has_auth:
            missing.append('Profilo auth compatibile con lo schema OpenAPI')
        if method in _WRITE and requires_body:
            missing.append('Dati validi per il request body')
        if not active_allowed:
            state = 'offline_only'
        elif method in _WRITE and not writes_approved:
            state = 'requires_approval'
        elif missing:
            state = 'needs_configuration'
        elif is_read:
            state = 'candidate'
        else:
            state = 'needs_configuration'
        op = _operation_id(ep)
        seen = match_observations(op, observations)
        entries.append({
            'operation': op, 'method': method, 'path': ep.path,
            'operation_id': ep.operation_id, 'security_schemes': security_names,
            'required_parameters': required,
            'request_body_declared': requires_body,
            'applicability': state,
            'missing_inputs': missing,
            'http_observations': seen,
            'coverage': 'observed' if seen else 'not_observed',
            'suggested_checks': (["authorization-review", "response-analysis", "input-validation"]
                                 if is_read else ["workflow", "mass-assignment-review", "authorization-review"]
                                 if method in _WRITE else ["http-configuration"]),
        })
    total = len(entries)
    seen_total = sum(x['http_observations'] > 0 for x in entries)
    read_count = sum(x['method'] in _READ for x in entries)
    write_count = sum(x['method'] in _WRITE for x in entries)
    return {
        'engine': 'achilles-compatibility-v080',
        'source': 'OpenAPI specification and optional recorded HTTP metadata',
        'requests_sent': 0,
        'summary': {
            'operations': total, 'read_operations': read_count,
            'write_operations': write_count, 'protected_operations': protected,
            'operations_with_path_parameters': path_params,
            'observed_operations': seen_total,
            'not_observed_operations': total - seen_total,
            'http_coverage_percent': round(100 * seen_total / total, 1) if total else 0.0,
            'methods': dict(sorted(methods.items())),
            'coverage_is_measured': bool(observations),
        },
        'operations': entries,
        'limitations': [
            'Swagger descrive la superficie, non la logica di business o i permessi reali.',
            'Candidate non significa test eseguito. Not observed non equivale a non vulnerabile.',
            'La copertura HTTP conta operazioni osservate, non percentuali di vulnerabilità rilevate.',
            'Parametri, credenziali e payload validi possono richiedere conferma umana.',
        ],
    }


def from_file(path: str, **kwargs: Any) -> dict[str, Any]:
    return analyze_compatibility(load_openapi(path), **kwargs)


def known_unavailable_actions(coverage: dict[str, Any]) -> dict[str, str]:
    """Skip only *provably* inapplicable operations; no guessed missing business rules."""
    summary = coverage['summary']
    unavailable = {}
    if summary['write_operations'] == 0:
        for action in ('workflow-assess', 'multi-resource-assess'):
            unavailable[action] = 'OpenAPI non dichiara operazioni di scrittura.'
    if summary['read_operations'] == 0:
        unavailable['journey-assess'] = 'OpenAPI non dichiara operazioni di lettura.'
    if summary['operations'] == 0:
        for action in ('auto-assess', 'advanced-vuln-assess', 'autonomous-agent', 'agent-loop-v2'):
            unavailable[action] = 'OpenAPI non contiene operazioni HTTP.'
    return unavailable
