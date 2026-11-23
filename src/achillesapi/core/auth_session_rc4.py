"""RC4 — Audit offline delle sessioni di autenticazione.

Non facciamo il login durante l'audit: leggiamo solo la struttura dei profili.
Il report non deve mai includere token o password salvati nello YAML.
"""
from __future__ import annotations

from pathlib import Path

from achillesapi.core.auth import AuthenticationManager


def audit_session_profiles(auth_yaml: str | Path) -> dict:
    """Spiega quali sessioni possono essere rinnovate e quali vanno gestite manualmente."""
    manager = AuthenticationManager.from_file(auth_yaml)
    details = []
    for item in manager.describe():
        name, kind = str(item['name']), str(item['type'])
        dynamic = kind in {'oauth2_client_credentials', 'login_json'}
        notes = []
        if not dynamic:
            notes.append('Credenziale statica: rinnovo manuale se scade.')
        else:
            notes.append('Acquisizione dinamica supportata per i client che usano AuthenticationManager.')
            notes.append('Refresh 401 disponibile nei controlli che lo implementano esplicitamente.')
        details.append({'profile': name, 'type': kind,
                        'dynamic_token': dynamic, 'notes': notes})
    return {'engine': 'achilles-auth-session-rc4', 'network_requests_sent': 0,
            'profiles': details,
            'summary': {'total': len(details),
                        'dynamic': sum(bool(x['dynamic_token']) for x in details)},
            'limitations': ['Non verifica scadenza o privilegi reali dei token.',
                            'Il refresh automatico non è garantito su tutti i task.']}
