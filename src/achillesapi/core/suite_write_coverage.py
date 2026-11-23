"""Explain the write-test coverage of a whole API campaign.

Never mistake an OpenAPI operation for an executed security check. A write
operation can only be executed through a validated, approved resource fixture.
This module does not generate credentials, test payloads, or HTTP requests.
"""
from __future__ import annotations

from typing import Any

WRITE_METHODS = frozenset({'POST', 'PUT', 'PATCH', 'DELETE'})


def _paths(spec: dict[str, Any]) -> dict[str, Any]:
    paths = spec.get('paths', {})
    return paths if isinstance(paths, dict) else {}


def write_inventory(spec: dict[str, Any], manifests: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Map every documented write to its explicitly approved test fixtures."""
    all_ops = sorted(
        f'{method.upper()} {path}'
        for path, raw in _paths(spec).items()
        if isinstance(raw, dict)
        for method in raw
        if method.upper() in WRITE_METHODS
    )
    assigned: dict[str, list[str]] = {op: [] for op in all_ops}
    for manifest_id, doc in manifests.items():
        for resource in doc.get('resources', []):
            if not isinstance(resource, dict):
                continue
            ops = [resource.get('create'), resource.get('delete')]
            ops += [x.get('operation') for x in resource.get('mutations', []) if isinstance(x, dict)]
            ops += [x.get('operation') for x in resource.get('write_checks', []) if isinstance(x, dict)]
            for op in ops:
                if isinstance(op, str) and op in assigned and manifest_id not in assigned[op]:
                    assigned[op].append(manifest_id)
    operations = []
    for op in all_ops:
        ids = assigned[op]
        operations.append({'operation': op, 'state': 'approved_fixture_not_yet_executed'
                          if ids else 'not_tested_no_approved_fixture',
                           'approved_workflow_count': len(ids),
                           'workflow_config_ids': ids})
    return {'documented_write_operations': len(all_ops),
            'with_approved_fixture': sum(bool(assigned[op]) for op in all_ops),
            'without_approved_fixture': sum(not assigned[op] for op in all_ops),
            'executed_write_operations': 0,
            'operations': operations,
            'explanation': ('La presenza nello Swagger non prova l’esecuzione. '
                            'Le scritture richiedono fixture con ownership e cleanup verificati.')}


def update_write_execution(coverage: dict[str, Any], steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Mark only operations belonging to a completed resource campaign as executed.

    A completed task does not itself prove that every write succeeded. This
    status says the relevant fixture campaign ran; request evidence remains in
    the child job. Failed/skipped campaigns are never promoted to executed.
    """
    completed = {
        step.get('workflow_config_id')
        for step in steps
        if step.get('action') == 'rc16-assess' and step.get('status') == 'complete'
        and isinstance(step.get('workflow_config_id'), str)
    }
    count = 0
    for op in coverage.get('operations', []):
        if op.get('state') == 'not_tested_no_approved_fixture':
            continue
        if any(manifest_id in completed for manifest_id in op.get('workflow_config_ids', [])):
            op['state'] = 'fixture_campaign_completed_review_child_evidence'
            count += 1
        else:
            op['state'] = 'approved_fixture_not_yet_executed'
    coverage['executed_write_operations'] = count
    return coverage
