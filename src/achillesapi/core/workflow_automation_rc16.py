"""RC16: cross-resource workflow discovery from arbitrary OpenAPI paths.

Generates dependency-aware proposals, not executable writes. The existing
multi-resource engine verifies markers and cleanup for approved manifests.
"""
from __future__ import annotations

import re
from typing import Any

from achillesapi.core.openapi import parse_openapi
from achillesapi.core.workflows import get_read_side_effect_risk

_SEG = re.compile(r'\{([^{}]+)\}')


def discover_resource_workflows(spec: dict[str, Any], *, max_candidates: int = 50) -> dict[str, Any]:
    if not 1 <= max_candidates <= 100:
        raise ValueError('Workflow discovery limit must be 1..100')
    endpoints = parse_openapi(spec).endpoints
    methods = {(ep.method, ep.path): ep for ep in endpoints}
    collections = sorted({path for method, path in methods if method == 'POST'})
    proposals = []
    for collection in collections:
        name = collection.rstrip('/').split('/')[-1]
        if not name or name.startswith('{'):
            continue
        # Exact item suffix, not similar-looking unrelated nested routes.
        candidates = [path for method, path in methods
                      if method == 'GET' and path.startswith(collection + '/{')
                      and path.count('/') == collection.count('/') + 1
                      and re.fullmatch(r'\{[A-Za-z_][\w-]*\}', path.rsplit('/', 1)[-1])]
        # OpenAPI systems often create nested resources but expose a flat item
        # route: POST /projects/{projectId}/tickets -> GET /tickets/{ticketId}.
        # Match only the final collection segment and mark the link as inferred.
        if not candidates:
            candidates = [path for method, path in methods if method == 'GET'
                          and re.fullmatch(r'/(?:api/[^/]+/)?' + re.escape(name) +
                          r'/\{[A-Za-z_][\w-]*\}', path)]
        for item in sorted(set(candidates)):
            read = methods['GET', item]
            if get_read_side_effect_risk(read):
                continue
            delete = f'DELETE {item}' if ('DELETE', item) in methods else None
            mutation = [f'{m} {item}' for m in ('PATCH', 'PUT') if (m, item) in methods]
            parent_ids = _SEG.findall(collection)
            child_id = _SEG.findall(item)[-1]
            parents = []
            for other in collections:
                if other == collection:
                    continue
                # Existing parent resource: /projects/{project_id}/tickets <- /projects
                if collection.startswith(other + '/{') and other.count('/') < collection.count('/'):
                    parents.append(other)
            proposals.append({
                'name': re.sub('[^A-Za-z0-9_]+', '_', collection.strip('/'))[:50],
                'resource': collection, 'create': f'POST {collection}',
                'read': f'GET {item}', 'cleanup': delete,
                'mutations': mutation, 'resource_id_parameter': child_id,
                'required_parent_identifiers': parent_ids,
                'depends_on_collections': sorted(parents, key=lambda p: (p.count('/'), p)),
                'status': 'requires_operator_fixture_and_approval' if delete else 'blocked_missing_cleanup',
                'operator_inputs': ['owner_profile', 'temporary_create_json', 'create_response_id_pointer',
                                    'read_response_id_pointer', 'unique_marker_field',
                                    'approved_parent_path_values', 'expected_cross_identity_policy'],
                'relationship': 'exact_item_path' if item.startswith(collection + '/') else 'inferred_resource_name',
                'safe_to_execute_automatically': False,
            })
    proposals = sorted(proposals, key=lambda p: (p['resource'].count('/'), p['resource']))
    return {'engine': 'achilles-resource-workflow-discovery-rc16',
            'candidates': proposals[:max_candidates],
            'total_candidates': len(proposals), 'requests_sent': 0,
            'supports_multiple_workflows': True,
            'limitations': ['Relazioni suggerite strutturalmente, non ownership verificata.',
                            'Nessuna modifica ai dati prima dell’approvazione di un manifest con cleanup.']}


def draft_multi_resource_manifest(spec: dict[str, Any], *, max_candidates: int = 10,
                                  owner_profile: str = 'REVIEW_OWNER') -> dict[str, Any]:
    """Produce editable, non-executable fixtures from multiple OpenAPI lifecycles.

    Never invent credentials, real IDs or mutation permission. The draft is
    deliberately blocked by placeholder values until edited and preflighted.
    """
    from achillesapi.core.workflows import _request_schema
    from achillesapi.core.testgen import _resolve_schema
    from achillesapi.core.openapi import parse_openapi

    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', owner_profile):
        raise ValueError('Invalid owner profile name')
    discovery = discover_resource_workflows(spec, max_candidates=max_candidates)
    endpoints = {(e.method + ' ' + e.path): e for e in parse_openapi(spec).endpoints}
    resources: list[dict[str, Any]] = []
    names_used: set[str] = set()
    # Only use parent linkage after a matching parent fixture has itself been
    # included in the draft. A missing or ambiguous parent stays REVIEW_.
    parents_by_collection: dict[str, list[tuple[str, str]]] = {}
    for candidate in discovery['candidates']:
        if not candidate['cleanup']:
            continue
        create = endpoints[candidate['create']]
        schema = _request_schema(spec, create)
        properties = schema.get('properties', {}) if isinstance(schema, dict) else {}
        if not isinstance(properties, dict):
            continue
        strings = [key for key, value in properties.items()
                   if isinstance(value, dict) and _resolve_schema(spec, value).get('type') == 'string'
                   and not _resolve_schema(spec, value).get('readOnly')]
        if not strings:
            continue
        marker = next((key for key in ('name', 'label', 'title', 'description') if key in strings), strings[0])
        name = candidate['name'][:40] or 'resource'
        if name[0].isdigit(): name = 'r_' + name[:38]
        if name in names_used:
            name = name[:30] + '_' + str(len(resources) + 1)
        names_used.add(name)
        body = {marker: 'REVIEW_TEMP_MARKER'}
        for key in schema.get('required', []):
            if key in body or key not in properties:
                continue
            definition = _resolve_schema(spec, properties[key])
            if definition.get('readOnly'):
                continue
            kind = definition.get('type')
            body[key] = 0 if kind in ('integer', 'number') else False if kind == 'boolean' else [] if kind == 'array' else {} if kind == 'object' else 'REVIEW_' + key.upper()
        child = candidate['resource_id_parameter']
        path_values = {p: 'REVIEW_' + p.upper() for p in candidate['required_parent_identifiers']}
        # A path parent can be connected to a previously drafted temporary
        # resource iff the exact collection path and path-parameter name agree
        # and there is exactly one fixture for that collection. Otherwise the
        # field remains REVIEW_ and requires an operator-provided identifier.
        for parent_collection in candidate['depends_on_collections']:
            parent_matches = parents_by_collection.get(parent_collection, [])
            if len(parent_matches) == 1:
                parent_name, parent_id_param = parent_matches[0]
                if parent_id_param in path_values:
                    path_values[parent_id_param] = '${' + parent_name + '.id}'
        path_values[child] = '${' + name + '.id}'
        resources.append({
            'name': name, 'identity': owner_profile,
            'create': candidate['create'], 'read': candidate['read'],
            'delete': candidate['cleanup'], 'body': body,
            'marker_field': marker, 'id_pointer': '/id',
            'read_id_pointer': '/' + child if child in ('id',) else '/id',
            'marker_pointer': '/' + marker, 'path_values': path_values,
            'access': [], 'mutations': [], 'write_checks': [],
        })
        parents_by_collection.setdefault(candidate['resource'], []).append((name, child))
    return {'resources': resources}
