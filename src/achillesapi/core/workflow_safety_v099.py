"""v0.94: suggerimenti di workflow senza operazioni distruttive.

Appunti: una POST sulla collection potrebbe produrre un ID, ma l'OpenAPI
non garantisce che esista una DELETE o che cancellare sia sicuro.
"""
from __future__ import annotations

from typing import Any

from achillesapi.core.workflow_dependencies_v090 import infer_dependencies
from achillesapi.core.openapi import parse_openapi


def review_workflow_safety(spec: dict[str, Any]) -> dict[str, Any]:
    """Classifica i workflow candidati indicando condizioni e rischi."""
    dependencies = infer_dependencies(spec)
    operations = {f'{ep.method.upper()} {ep.path}' for ep in parse_openapi(spec).endpoints}
    proposals = []
    for entry in dependencies['dependencies']:
        source = entry.get('from')
        target = entry.get('to')
        if not source or not target or not target.startswith('GET '):
            # DELETE serve per cleanup, non come fase di osservazione.
            continue
        # Non assumiamo che il path GET abbia lo stesso schema della DELETE.
        delete = 'DELETE ' + target.partition(' ')[2]
        cleanup_available = delete in operations
        proposals.append({
            'create': source, 'inspect': target,
            'cleanup_candidate': delete if cleanup_available else None,
            'status': 'requires_operator_manifest',
            'missing': ['Body valido', 'ID estratto dalla vera risposta POST',
                        'Identita e ownership verificata', 'Approvazione delle scritture']
                       + ([] if cleanup_available else ['Endpoint di cleanup non documentato']),
        })
    return {
        'engine': 'achilles-workflow-safety-v099', 'requests_sent': 0,
        'summary': {'candidate_workflows': len(proposals),
                    'with_documented_delete': sum(bool(x['cleanup_candidate']) for x in proposals)},
        'proposals': proposals[:400],
        'limitations': ['Le relazioni sono ipotesi di struttura, non workflow approvati.',
                        'DELETE documentata non garantisce cleanup sicuro o idempotente.',
                        'Serve un manifest autorizzato prima di inviare traffico attivo.'],
    }
