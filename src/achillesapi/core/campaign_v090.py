"""Preflight della campagna: decide cosa può essere pianificato senza inviare HTTP.

La matrice distingue un controllo *possibile* da uno *eseguito*. Non deduce
permessi o dati applicativi non dichiarati nello Swagger.
"""
from __future__ import annotations

from typing import Any

from achillesapi.core.compatibility_v080 import analyze_compatibility, known_unavailable_actions

# I risultati precedenti possono essere prodotti da più task. Una dipendenza è
# un vincolo sui dati, non il permesso di eseguire richieste HTTP.
RESULT_DEPENDENT = frozenset({
    'verify-findings', 'vulnerability-triage', 'differential-review',
    'adaptive-review', 'coverage-report', 'next-actions', 'agent-review',
    'ai-prioritize', 'ai-correlate', 'autonomous-agent', 'agent-loop-v2',
    'verify-access-policy', 'benchmark-evaluate', 'access-evidence-review', 'mutation-review',
    'evidence-package', 'campaign-diagnostics', 'release-readiness', 'benchmark-review',
})
CONFIG_TYPES = {
    'journey-assess': 'journey',
    'workflow-assess': 'workflow',
    'multi-resource-assess': 'multi-resource',
    'verify-access-policy': 'context',
    'analyze-evidence': 'evidence',
    'benchmark-evaluate': 'benchmark',
    'benchmark-review': 'benchmark',
}
WRITE_TASKS = frozenset({'workflow-assess', 'multi-resource-assess'})


def campaign_preflight(
    spec: dict[str, Any], catalog: dict[str, dict[str, Any]], order: tuple[str, ...],
    *, has_auth: bool = False, has_config: bool = False, config_usage: str = '',
    active: bool = False, writes: bool = False, ai: bool = False,
    has_scope: bool = False, authorized: bool = False,
    include_optional: bool = True, max_total_requests: int = 300,
    per_task_limit: int = 40, agent_budget: int = 3, profile_count: int = 0,
) -> dict[str, Any]:
    """Descrive tutti i task, le dipendenze e i problemi correggibili.

    Non avvia processi, non legge token e non contatta il target. I controlli
    dipendenti da evidenze sono segnati *waiting_for_result*, non falliti.
    """
    coverage = analyze_compatibility(
        spec, has_auth=has_auth, active_allowed=active,
        writes_approved=writes, ai_enabled=ai,
    )
    unavailable = known_unavailable_actions(coverage)
    tasks: list[dict[str, Any]] = []
    for index, action in enumerate(order):
        tool = catalog[action]
        kind = tool['requirements']
        missing: list[str] = []
        state = 'ready'
        reason = ''
        expected_config = CONFIG_TYPES.get(action)
        if action in unavailable:
            state, reason = 'not_applicable', unavailable[action]
        elif action == 'access-probe' and (not has_auth or profile_count != 2):
            state, reason = 'blocked', 'Confronto GET: servono auth.yaml e due profili di test.'
            missing.extend(['auth', 'two_profiles'])
        elif tool.get('ai') and not ai:
            state, reason = 'disabled', 'AI locale non abilitata.'
        elif tool.get('active') and action != 'auto-assess' and not include_optional:
            state, reason = 'disabled', 'Test attivo facoltativo disabilitato.'
        elif action in WRITE_TASKS and not writes:
            state, reason = 'disabled', 'Scritture non abilitate per la campagna.'
        elif tool.get('active') and active and not (has_scope and authorized):
            state, reason = 'blocked', 'Mancano scope autorizzato e conferma per HTTP.'
            missing.append('scope')
        elif tool.get('active') and writes and tool.get('writes') and not has_auth:
            state, reason = 'blocked', 'Workflow di scrittura: carica un profilo auth.'
            missing.append('auth')
        elif expected_config and (not has_config or config_usage != expected_config):
            state, reason = 'blocked', f'Richiesto manifest di tipo {expected_config}.'
            missing.append(expected_config)
        elif kind == 'spec-config' and not has_config:
            state, reason = 'blocked', 'Richiesto un manifest valido.'
            missing.append('manifest')
        elif kind == 'auth-only' and not has_auth:
            state, reason = 'blocked', 'Carica auth.yaml.'
            missing.append('auth')
        elif kind == 'scope' and not has_scope:
            state, reason = 'blocked', 'Indica Base URL e host consentito.'
            missing.append('scope')
        elif kind in {'both', 'report', 'report-config', 'config-report'}:
            state, reason = 'waiting_for_result', 'Richiede un assessment precedente completato.'
        # Il budget calcolato è una riserva, non una misura esatta del traffico.
        max_requests = (min(agent_budget, 15) if action in {'autonomous-agent', 'agent-loop-v2'}
                        else per_task_limit) if tool.get('active') and active else 0
        tasks.append({
            'index': index, 'action': action, 'category': tool['category'],
            'state': state, 'reason': reason, 'missing_inputs': missing,
            'config_type': expected_config,
            'requires_result': action in RESULT_DEPENDENT,
            'network_mode': 'active' if tool.get('active') and active else 'offline',
            'writes_possible': bool(tool.get('writes')),
            'maximum_http_requests_reserved': max_requests,
            'result_provides': 'assessment' if action in {'assess', 'auto-assess'} else 'analysis',
        })
    counts = {status: sum(t['state'] == status for t in tasks) for status in
              ('ready', 'blocked', 'disabled', 'not_applicable', 'waiting_for_result')}
    return {
        'engine': 'achilles-campaign-preflight-v090', 'requests_sent': 0,
        'summary': {'total': len(tasks), **counts,
                    'maximum_suite_reservation': max_total_requests,
                    'note': 'Le richieste HTTP non vengono misurate in questa fase.'},
        'operations': coverage['summary'], 'tasks': tasks,
        'limitations': [
            'READY indica solo prerequisiti presenti, non test già effettuato.',
            'WAITING_FOR_RESULT verrà rivalutato dopo i task che producono evidenze.',
            'La mancanza di una policy aziendale non può essere risolta dallo Swagger.',
            'Il budget è un limite conservativo, non un contatore di traffico misurato.',
        ],
    }
