"""Bounded deterministic next-step planner for local AI-assisted campaigns.

External LLM output may advise but is never allowed to become an arbitrary
command, URL, or permission. This module never performs HTTP requests.
"""
from __future__ import annotations

from typing import Any

ALLOWED = frozenset({
    'security-inventory','workflow-discover','journey-discover','coverage-report',
    'vulnerability-triage','ai-correlate','verify-access-policy', 'advanced-vuln-assess',
})


def deterministic_next_steps(coverage: dict[str, Any], *,
                             has_http_evidence: bool = False,
                             ai_available: bool = False) -> dict[str, Any]:
    """Suggest next actions from measured coverage and missing preconditions."""
    summary = coverage.get('summary', {})
    actions = []
    if summary.get('not_observed_operations', 0):
        actions.append({'action': 'coverage-report', 'reason': 'Esistono endpoint non osservati',
                        'state': 'requires_assessment', 'target_requests': 0})
    if summary.get('write_operations', 0):
        actions.append({'action': 'workflow-discover', 'reason': 'Operazioni di scrittura documentate',
                        'state': 'offline_candidate', 'target_requests': 0})
    if summary.get('protected_operations', 0):
        actions.append({'action': 'security-inventory', 'reason': 'Schemi di autorizzazione dichiarati',
                        'state': 'offline_candidate', 'target_requests': 0})
    if has_http_evidence:
        actions.append({'action': 'vulnerability-triage', 'reason': 'Metadati HTTP da revisionare',
                        'state': 'offline_candidate', 'target_requests': 0})
    if has_http_evidence and ai_available:
        actions.append({'action': 'ai-correlate', 'reason': 'Correlazione consultiva con Ollama locale',
                        'state': 'requires_local_ai', 'target_requests': 0})
    return {'engine': 'achilles-local-agent-planner-v080',
            'ai_mode': 'advisory_only', 'suggested_actions': actions,
            'commands_executed': 0, 'target_requests': 0,
            'limitations': ['Le proposte non sono automaticamente autorizzate.',
                            'Un modello linguistico non può modificare scope, budget o consentire scritture.',
                            'Questa funzione non genera né esegue richieste non previste dal registry.']}


def validate_model_suggestions(raw: Any) -> list[str]:
    """Allowlist for any future Ollama proposals; never trust arbitrary text."""
    if not isinstance(raw, list):
        return []
    result = []
    for name in raw[:20]:
        if type(name) is str and name in ALLOWED and name not in result:
            result.append(name)
    return result
