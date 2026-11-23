"""Prova GET con due identità, limitata a endpoint documentati in OpenAPI.

Appunti:
- Non inventiamo ID di clienti né regole aziendali: li fornisce l'operatore.
- Richieste solo GET, su host autorizzato, senza redirect e con budget.
- Restituiamo status e confronto in memoria; non salviamo token o corpi.
- Un 200 inatteso è un candidato da confermare, non una BOLA certa.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from achillesapi.core.auth import AuthenticationManager
from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.core.openapi import load_openapi, parse_openapi


class ProbeError(ValueError):
    """Input non completo o endpoint non utilizzabile per il confronto."""


def _choose_get(specification: dict[str, Any], operation: str | None,
                values: dict[str, str]) -> tuple[str, str]:
    """Sceglie una GET con parametri disponibili: mai una URL arbitraria."""
    parsed = parse_openapi(specification)
    candidates = []
    for endpoint in parsed.endpoints:
        label = endpoint.method + ' ' + endpoint.path
        if endpoint.method != 'GET' or (operation and operation != label):
            continue
        required = {p.name for p in endpoint.parameters if p.required and p.location == 'path'}
        # Le query richieste vengono rifiutate per non inventare dati applicativi.
        extra = [p.name for p in endpoint.parameters if p.required and p.location == 'query']
        if extra or not required.issubset(values):
            continue
        candidates.append((label, endpoint.path))
    if not candidates:
        raise ProbeError('Nessuna GET compatibile: seleziona operazione e ID espliciti')
    return candidates[0]


def _render_path(template: str, values: dict[str, str]) -> str:
    """Sostituisce i segnaposto evitando slash, query o traversal nei valori."""
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = values.get(name, '')
        if (not value or len(value) > 128 or value in ('.', '..') or
                any(character in value for character in ('/', '\\', '?', '#', '%', '\r', '\n'))):
            raise ProbeError(f'Valore path per {name} mancante o non consentito')
        return quote(value, safe='')
    path = re.sub(r'\{([^{}]+)\}', replace, template)
    if '{' in path or '}' in path:
        raise ProbeError('Path Swagger non completamente risolto')
    return path


def compare_identities(spec_path: str | Path, *, base_url: str,
                       allowed_hosts: set[str], auth_manager: AuthenticationManager,
                       owner: str, other: str, path_values: dict[str, str] | None = None,
                       operation: str | None = None, expected_other: str = 'unknown',
                       expected_owner: str = 'allow',
                       execute: bool = False, allow_insecure_http: bool = False,
                       max_requests: int = 2, rate: float = 1.0,
                       retry_401: bool = False) -> dict[str, Any]:
    """Esegue al massimo due GET, con verifica separata delle identità.

    Il risultato `requires_review` non equivale a vulnerabilità confermata.
    Per una conferma occorrono ownership, policy e analisi della risposta.
    """
    if owner == other or owner not in auth_manager.names or other not in auth_manager.names:
        raise ProbeError('Servono due profili differenti presenti in auth.yaml')
    if expected_owner not in {'deny', 'allow'}:
        raise ProbeError('expected_owner deve essere deny o allow')
    if expected_other not in {'unknown', 'deny', 'allow'}:
        raise ProbeError('expected_other deve essere unknown, deny o allow')
    if retry_401 and max_requests < 4:
        raise ProbeError('Il rinnovo token richiede un budget di almeno 4 GET')
    if max_requests < 2:
        raise ProbeError('Il confronto richiede un budget di almeno 2 richieste')
    if not base_url or not allowed_hosts:
        raise ProbeError('Indica Base URL e host autorizzato')
    if urlsplit(base_url).scheme == 'http' and not allow_insecure_http:
        raise ScopeError('Autenticazione su HTTP in chiaro non approvata')
    values = path_values or {}
    label, template = _choose_get(load_openapi(spec_path), operation, values)
    target = base_url.rstrip('/') + _render_path(template, values)
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=max_requests,
                            requests_per_second=rate)
    # Il dry-run non risolve i token: non contatta nemmeno OAuth/login.
    client._validate_target('GET', target)
    base = {'engine': 'achilles-active-authorization-rc2', 'operation': label,
            'owner': owner, 'other': other, 'expected_other': expected_other,
            'expected_owner': expected_owner,
            'executed': execute, 'requests_sent': 0, 'confirmed_vulnerabilities': 0}
    if not execute:
        return {**base, 'status': 'dry_run', 'observations': [],
                'limitations': ['Nessun test HTTP eseguito; verifica scope e parametri prima di procedere.']}
    results = []
    transient_bodies: list[str | None] = []
    for identity in (owner, other):
        material = auth_manager.resolve(identity, allowed_hosts=allowed_hosts,
                                        allow_insecure_http=allow_insecure_http)
        evidence = client.request('GET', target, execute=True,
                                  headers=material.headers, cookies=material.cookies,
                                  params=material.params,
                                  sensitive_query_names=set(material.params),
                                  sensitive_header_names=set(material.headers))
        response = evidence.response
        # Il retry è consentito SOLO per GET, SOLO su token dinamici e SOLO
        # quando l'operatore lo abilita: nessuna scrittura viene ripetuta.
        if (retry_401 and response and response.status_code == 401
                and auth_manager.is_dynamic(identity)):
            auth_manager.invalidate(identity)
            refreshed = auth_manager.resolve(identity, allowed_hosts=allowed_hosts,
                                             allow_insecure_http=allow_insecure_http)
            evidence = client.request('GET', target, execute=True,
                                      headers=refreshed.headers, params=refreshed.params,
                                      cookies=refreshed.cookies,
                                      sensitive_query_names=set(refreshed.params),
                                      sensitive_header_names=set(refreshed.headers))
            response = evidence.response
        transient_bodies.append(response.body_preview if response else None)
        results.append({'identity': identity,
                        'status_code': response.status_code if response else None,
                        'network_error': evidence.error if not response else None,
                        'body_truncated': response.body_truncated if response else None})
    owner_code, other_code = (r['status_code'] for r in results)
    other_allowed = other_code is not None and 200 <= other_code < 300
    owner_allowed = owner_code is not None and 200 <= owner_code < 300
    same_body = (all(value is not None for value in transient_bodies) and
                 transient_bodies[0] == transient_bodies[1] and
                 not any(r['body_truncated'] for r in results))
    if not owner_code or not other_code:
        verdict = 'inconclusive_network_failure'
    elif expected_owner == 'deny' and owner_allowed:
        verdict = 'owner_policy_conflict_requires_review'
    elif expected_owner == 'deny' and owner_code not in {401, 403}:
        verdict = 'inconclusive_owner_status'
    elif expected_other == 'deny' and other_allowed and (owner_allowed or expected_owner == 'deny'):
        verdict = 'policy_conflict_requires_review'
    elif expected_other == 'deny' and other_code in {401, 403}:
        verdict = 'expected_denial_observed'
    elif expected_other == 'allow' and other_code in {401, 403}:
        verdict = 'unexpected_denial_requires_review'
    else:
        verdict = 'inconclusive_or_expected'
    return {**base, 'status': verdict, 'requests_sent': client.request_statistics['attempted'],
            'observations': results, 'same_body_observed': bool(same_body),
            'limitations': ['La policy è dichiarata dall’operatore, non dedotta dallo Swagger.',
                            'Una risposta 2xx non prova da sola la lettura di dati non autorizzati.',
                            'I contenuti HTTP e le credenziali non sono inclusi nel report.']}
