"""AI advisory -> deterministic, allowlisted follow-up decisions.

The model can select from pre-existing approved scanners; it cannot supply
URLs, HTTP methods, request bodies, credentials, or alter safety approvals.
"""
from __future__ import annotations

from typing import Any

_WHITELIST = {
    'injection': ('sql', 'injection', 'nosql', 'ssti', 'xpath', 'ldap'),
    'authorization': ('bola', 'bfla', 'accesso', 'permess', 'autorizz', 'role', 'tenant'),
    'bounded_get_security': ('xss', 'redirect', 'traversal', 'riflession'),
    'body_probes': ('json', 'patch', 'mass assignment'),
    'verification_replay': ('verifica', 'confirm', 'ripet', 'reproduce', 'evidence'),
}


def allowed_agent_decisions(analysis: dict[str, Any] | None, *,
                            available: dict[str, Any],
                            approved_writes: bool = False,
                            approved_body_probes: bool = False,
                            executed: dict[str, Any] | None = None) -> dict[str, Any]:
    """Map natural-language recommendations to existing approved tasks only.

    This function is pure. It cannot execute requests. A second layer makes
    all HTTP calls via the existing bounded campaign orchestrator.
    """
    suggestions = (analysis or {}).get('recommended_tests', [])
    if not isinstance(suggestions, list):
        suggestions = []
    suggestions = [s for s in suggestions[:20] if isinstance(s, str)]
    decisions = []
    selected: set[str] = set()
    for suggestion in suggestions:
        lower = suggestion.lower()
        matches = [name for name, tokens in _WHITELIST.items()
                   if any(token in lower for token in tokens)]
        for task in matches:
            if task in selected:
                continue
            selected.add(task)
            block = None
            if not available.get(task, {}).get('available', False):
                block = 'Prerequisiti del task non disponibili'
            elif task == 'body_probes' and not (approved_writes and approved_body_probes):
                block = 'Consenso scritture e consenso sonde mancanti'
            decisions.append({'task': task, 'mode': 'approved_engine_only',
                'reason': 'Suggerimento mappato su task preesistente, senza URL o payload generati dal modello',
                'status': 'blocked_prerequisite' if block else
                          'already_executed' if executed and task in executed and executed[task].get('executed') else
                          'operator_approval_required',
                'block_reason': block, 'proposed_by_ai': True})
    return {'engine': 'achilles-adaptive-agent-v3',
            'ai_requested_tests': len(suggestions), 'selected_tasks': decisions,
            'automatic_arbitrary_http': False,
            'limitations': ['Le raccomandazioni AI non autorizzano mai nuove destinazioni o scritture.',
                            'La riproducibilità delle sonde GET è gestita da un verificatore deterministico separato.']}
