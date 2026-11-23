"""Inferenza offline di relazioni fra endpoint da percorsi dichiarati.

Una relazione di path NON prova una dipendenza di business. Non eseguiamo
POST/DELETE e non inventiamo identificativi o autorizzazioni.
"""
from __future__ import annotations

import re
from typing import Any

from achillesapi.core.openapi import parse_openapi

_PARAM = re.compile(r'\{([^{}]+)\}')


def infer_dependencies(spec: dict[str, Any]) -> dict[str, Any]:
    """Crea un grafo di risorse e suggerimenti di sequenza conservativi."""
    endpoints = parse_openapi(spec).endpoints[:2000]
    operations = {f'{ep.method.upper()} {ep.path}': ep for ep in endpoints}
    edges: list[dict[str, Any]] = []
    for name, ep in operations.items():
        slots = _PARAM.findall(ep.path)
        if not slots:
            continue
        prefix = ep.path.split('/{', 1)[0].rstrip('/') or '/'
        # Una POST sulla collection potrebbe generare l'ID della risorsa.
        candidate = 'POST ' + prefix
        if candidate in operations and candidate != name:
            edges.append({
                'from': candidate, 'to': name, 'relation': 'possible_created_identifier',
                'parameter_names': slots, 'status': 'hypothesis',
                'needs': ['Body valido', 'Risposta HTTP con ID reale', 'Prova di ownership'],
            })
        # Un segmento genitore con parametro può richiedere una risorsa già presente.
        if len(slots) > 1:
            edges.append({
                'from': None, 'to': name, 'relation': 'nested_resource_identifiers',
                'parameter_names': slots, 'status': 'requires_fixtures',
                'needs': ['Identificativi distinti per ciascun segmento', 'Controllo scope'],
            })
    return {
        'engine': 'achilles-workflow-dependencies-v090', 'requests_sent': 0,
        'summary': {'operations': len(operations), 'candidate_relations': len(edges)},
        'dependencies': edges[:400],
        'limitations': ['Le dipendenze inferite dai path devono essere verificate.',
                        'Non crea risorse o esegue workflow senza manifest e consenso esplicito.'],
    }
