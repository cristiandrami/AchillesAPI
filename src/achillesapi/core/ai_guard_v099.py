"""v0.97: validazione di piani proposti da Ollama, prima di ogni esecuzione.

Appunti: il modello puo suggerire task ma non puo inventare comandi,
aggiungere host, disattivare scope o autorizzare richieste POST.
"""
from __future__ import annotations

from typing import Any

from achillesapi.core.ai_planner_v080 import ALLOWED
from achillesapi.core.openapi import parse_openapi


def validate_advisory_plan(spec: dict[str, Any], suggestion: Any) -> dict[str, Any]:
    """Accetta soltanto nomi di tool permessi ed endpoint dello Swagger."""
    valid_operations = {f'{ep.method.upper()} {ep.path}' for ep in parse_openapi(spec).endpoints}
    if not isinstance(suggestion, dict) or not isinstance(suggestion.get('actions'), list):
        raise ValueError('Il piano AI deve contenere un array actions.')
    accepted, rejected = [], []
    for entry in suggestion['actions'][:100]:
        if not isinstance(entry, dict):
            rejected.append('invalid_entry')
            continue
        action, operation = entry.get('action'), entry.get('operation')
        if not isinstance(action, str) or action not in ALLOWED:
            rejected.append('tool_not_allowed')
        elif operation is not None and operation not in valid_operations:
            rejected.append('operation_not_in_openapi')
        elif any(key in entry for key in ('url', 'payload', 'command', 'token', 'headers', 'execute', 'approve_writes')):
            rejected.append('unsafe_argument')
        else:
            accepted.append({'action': action, 'operation': operation,
                             'state': 'operator_approval_required'})
    return {
        'engine': 'achilles-ai-plan-guard-v099', 'requests_sent': 0,
        'accepted': accepted, 'rejected_reasons': rejected,
        'summary': {'accepted': len(accepted), 'rejected': len(rejected)},
        'auto_executed': False,
        'limitations': ['Un consiglio AI non autorizza traffico di rete.',
                        'Solo task e operazioni esplicitamente supportati sono accettati.'],
    }
