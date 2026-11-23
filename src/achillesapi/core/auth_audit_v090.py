"""Audit dichiarativo dei profili; non estrae né mostra alcun segreto."""
from __future__ import annotations

from typing import Any

from achillesapi.core.auth import load_authentication_manager
from achillesapi.core.auth_readiness_v080 import auth_readiness


def audit_auth(spec: dict[str, Any], auth_path: str | None = None) -> dict[str, Any]:
    """Verifica la compatibilità dichiarata e suggerisce interventi senza provare i token."""
    readiness = auth_readiness(spec, auth_path)
    problems: list[dict[str, str]] = []
    for scheme in readiness['schemes']:
        if scheme['status'] != 'configured_unverified':
            problems.append({'type': 'missing_scheme', 'name': scheme['scheme'],
                             'action': 'Aggiungi un profilo del tipo indicato dallo Swagger.'})
    if auth_path:
        # L'oggetto manager rende disponibili solo metadati, non i token.
        manager = load_authentication_manager(auth_path)
        if not manager.names:
            problems.append({'type': 'empty_profiles', 'name': 'auth.yaml',
                             'action': 'Configura almeno un profilo se sono richieste identità.'})
    return {
        'engine': 'achilles-auth-audit-v090', 'requests_sent': 0,
        'summary': {'profiles': readiness['profile_count'],
                    'schemes': len(readiness['schemes']), 'configuration_gaps': len(problems)},
        'readiness': readiness, 'gaps': problems,
        'limitations': ['Non verifica la validità o la scadenza del token.',
                        'Non espone credenziali, password o token nel risultato.',
                        'Le autorizzazioni reali richiedono identità di test differenti.'],
    }
