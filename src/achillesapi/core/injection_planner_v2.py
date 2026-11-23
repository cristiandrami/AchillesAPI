"""RC7 injection surface catalogue. Never executes mutating methods automatically.

OpenAPI metadata is an *input schema*, not permission to perform writes.
The catalogue maps parameter/query/body/XML entrypoints to bounded tests and
provides an honest execution prerequisite for each selected operation.
"""
from __future__ import annotations

from typing import Any

from achillesapi.core.openapi import parse_openapi
from achillesapi.core.testgen import _resolve_schema

FAMILIES = {
    'string': ('sql_error', 'sql_boolean', 'nosql', 'ssti', 'command', 'xpath', 'ldap', 'crlf',
               'xss_reflection', 'path_traversal', 'open_redirect', 'ssrf'),
    'number': ('sql_boolean', 'nosql'),
    'integer': ('sql_boolean', 'nosql'),
    'object': ('nosql', 'mass_assignment'),
    'array': ('nosql', 'input_validation'),
}
SKIP = ('password', 'token', 'secret', 'apikey', 'api_key', 'authorization', 'credential')


def _body_paths(spec: dict[str, Any], schema: dict[str, Any], prefix: str = '', depth: int = 0) -> list[tuple[str, str]]:
    if depth > 4:
        return []
    obj = _resolve_schema(spec, schema)
    if not isinstance(obj, dict):
        return []
    combinations: list[dict[str, Any]] = [obj]
    for key in ('allOf', 'oneOf', 'anyOf'):
        for branch in obj.get(key, [])[:5]:
            if isinstance(branch, dict):
                combinations.append(_resolve_schema(spec, branch))
    out = []
    for element in combinations:
        for name, node in list(element.get('properties', {}).items())[:50]:
            if not isinstance(node, dict) or any(word in name.lower() for word in SKIP):
                continue
            resolved = _resolve_schema(spec, node)
            if resolved.get('readOnly'):
                continue
            pointer = prefix + '/' + name.replace('~','~0').replace('/','~1')
            kind = resolved.get('type', 'string')
            if kind == 'object' and resolved.get('properties'):
                out.extend(_body_paths(spec, resolved, pointer, depth+1))
            else:
                out.append((pointer, kind))
    return list(dict.fromkeys(out))


def injection_surface_plan(spec: dict[str, Any], *, max_cases: int = 750) -> dict[str, Any]:
    """Bounded offline plan for every relevant OpenAPI input surface."""
    parsed = parse_openapi(spec)
    cases = []
    skipped = []
    for endpoint in parsed.endpoints:
        operation = endpoint.method + ' ' + endpoint.path
        if endpoint.method not in ('GET', 'POST', 'PATCH', 'PUT', 'DELETE'):
            continue
        available = []
        for p in endpoint.parameters:
            if p.location in ('path', 'query', 'header', 'cookie') and not any(x in p.name.lower() for x in SKIP):
                available.append((p.location, p.name, getattr(p, 'schema_', {}) or {}))
        body = endpoint.request_body or {}
        if isinstance(body, dict):
            body = _resolve_schema(spec, body)
            for media, entry in body.get('content', {}).items():
                if not isinstance(entry, dict):
                    continue
                content_type = media.lower().split(';')[0]
                schema = entry.get('schema', {})
                if 'json' in content_type:
                    for pointer, kind in _body_paths(spec, schema):
                        available.append(('json_body', pointer, {'type': kind}))
                elif 'xml' in content_type:
                    available.append(('xml_body', '/', {'type': 'xml'}))
                elif 'form' in content_type:
                    for pointer, kind in _body_paths(spec, schema):
                        available.append(('form_body', pointer, {'type': kind}))
                else:
                    skipped.append({'operation': operation, 'reason': 'Unsupported content type: ' + content_type})
        for location, name, schema in available:
            kind = schema.get('type', 'string') if isinstance(schema, dict) else 'string'
            families = ('xxe', 'xml_parser_hardening') if kind == 'xml' else FAMILIES.get(kind, ('input_validation',))
            for family in families:
                if len(cases) >= max_cases:
                    break
                is_write = endpoint.method != 'GET'
                cases.append({
                    'operation': operation, 'location': location, 'name': name, 'family': family,
                    'execution': 'requires_disposable_fixture_and_write_approval' if is_write
                                 else 'requires_authorized_scope_and_safe_path_values',
                    'status': 'planned_not_executed',
                    'manual_review_required': True,
                })
        if not available:
            skipped.append({'operation': operation, 'reason': 'No declared, non-sensitive input surface'})
    return {'engine':'achilles-injection-planner-rc7', 'executed':False, 'requests_sent':0,
            'planned_cases':len(cases), 'cases':cases, 'skipped':skipped,
            'by_method':{method:sum(c['operation'].startswith(method+' ') for c in cases)
                         for method in ('GET','POST','PATCH','PUT','DELETE')},
            'limitations':['A plan is not a vulnerability finding.',
                           'Mutating operations require separately approved disposable fixtures and verified cleanup.',
                           'XXE/XML and bodies are inventoried offline, not sent by the GET-only active scanner.']}
