"""Suggest API workflows offline using conservative REST structure heuristics."""
from __future__ import annotations

import re
from typing import Any
from achillesapi.core.openapi import parse_openapi


def infer_workflows(spec: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_openapi(spec)
    grouped: dict[str, dict[str, list[str]]] = {}
    for ep in parsed.endpoints:
        path = ep.path
        parent = re.sub(r'/\{[^{}]+\}$', '', path).rstrip('/') or '/'
        grouped.setdefault(parent, {}).setdefault(ep.method.upper(), []).append(path)
    proposals = []
    for root, methods in sorted(grouped.items()):
        creates = methods.get('POST', [])
        item = next((path for path in methods.get('GET', []) if re.search(r'/\{[^{}]+\}$', path)), None)
        deletes = next((path for path in methods.get('DELETE', []) if re.search(r'/\{[^{}]+\}$', path)), None)
        if not creates or not item:
            continue
        proposals.append({
            'resource': root, 'create': 'POST ' + creates[0], 'read': 'GET ' + item,
            'cleanup': 'DELETE ' + deletes if deletes else None,
            'status': 'candidate_review_required' if deletes else 'no_safe_cleanup_documented',
            'missing_inputs': ['Profilo proprietario', 'Body POST valido', 'JSON Pointer ID dalla risposta',
                               'Conferma fixture usa-e-getta',
                               *([] if deletes else ['Strategia cleanup documentata'])],
            'writes_executed': False,
        })
    return {'engine':'achilles-workflow-inference-v080', 'requests_sent':0,
            'candidates':proposals[:150], 'summary':{'candidates':len(proposals)},
            'limitations':['Heuristics are not proof of business dependencies.',
                           'A workflow must never run writes without disposable fixtures and explicit authorization.']}
