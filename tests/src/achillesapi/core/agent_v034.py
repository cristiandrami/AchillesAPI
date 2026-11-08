"""Bounded deterministic agent for choosing supported follow-up tests.

The local LLM may provide an advisory summary after execution, but cannot set
hosts, methods, identities, write payloads or change safety rules.
"""
from __future__ import annotations

from typing import Any
from achillesapi.models.api import ParsedAPI
from achillesapi.core.production_v031 import next_actions


def plan_agent_cycle(parsed: ParsedAPI, assessment: dict[str, Any], *, budget: int = 5) -> dict[str, Any]:
    """Select a finite action queue from observed coverage and existing OpenAPI GETs."""
    if not 0 <= budget <= 20:
        raise ValueError('Agent budget must be between 0 and 20')
    queue = next_actions(parsed, assessment, budget=budget)
    allowed = {f'GET {ep.path}' for ep in parsed.endpoints if ep.method == 'GET'}
    actions = []
    for entry in queue['proposed_actions']:
        if entry['kind'] == 'scoped_get_baseline' and entry['operation'] in allowed:
            actions.append({'action':'baseline_get_recommended', 'operation':entry['operation'],
                            'reason':'GET senza osservazioni: eseguire prima auto-assess attivo con scope e profili.',
                            'executable_by_agent':False, 'requires_execute':True,
                            'requires_scope':True, 'requires_known_parameters':True})
        else:
            actions.append({'action':'operator_prerequisite', 'operation':entry['operation'],
                            'reason':entry['instruction'], 'executable':False})
    return {'engine':'deterministic-agent-v0.34', 'budget':budget,'actions':actions,
            'executable_candidates':0,
            'operator_prerequisites':sum(a.get('action')=='operator_prerequisite' for a in actions),
            'requests_sent':0, 'model_can_authorize_requests':False,
            'loop':'observe -> rank approved candidates -> execute via existing bounded scanner -> review',
            'limitation':'This planner does not implement general autonomous exploitation.'}


def agent_cycle_review(parsed: ParsedAPI, assessment: dict[str, Any], *, budget: int = 5) -> dict[str, Any]:
    """Provide an action plan and stopping criteria from a completed scan."""
    plan = plan_agent_cycle(parsed, assessment, budget=budget)
    doable = 0  # Baseline GETs belong to auto-assess; agent only repeats observed anomalies.
    return {**plan,'stop_reason':('no_supported_actions' if not doable else
                                 'operator_scope_and_credentials_required'),
            'next_step':('Per le GET senza risposte esegui auto-assess ATTIVO con scope e identità approvati; '
                         'per le scritture configura manifest e cleanup. Non ci sono anomalie ripetibili '
                         'nella scansione precedente.'),
            'note':'Zero requests is expected for offline review or when no supported anomaly exists.'}
