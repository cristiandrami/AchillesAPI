"""RC4 — Matrice di autorizzazione GET basata su policy esplicite.

Appunti:
- Una regola descrive una GET, due identità e il risultato atteso.
- Validiamo TUTTE le regole prima di inviare la prima richiesta.
- Non indoviniamo ID, policy né credenziali: li fornisce il tester.
- Un 200 imprevisto è una violazione *sospetta*, non un finding confermato.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from achillesapi.core.access_probe_rc import (
    ProbeError, _choose_get, _render_path, compare_identities,
)
from achillesapi.core.auth import AuthenticationManager
from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.core.openapi import load_openapi


def read_rules(path: str | Path) -> dict[str, Any]:
    """Carica JSON/YAML senza interpretare comandi o fare richieste di rete."""
    source = Path(path)
    if source.stat().st_size > 128 * 1024:
        raise ProbeError('Il file delle policy supera 128 KiB')
    try:
        data = yaml.safe_load(source.read_text(encoding='utf-8'))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ProbeError('File delle policy JSON/YAML non valido') from exc
    if not isinstance(data, dict):
        raise ProbeError('Il file deve contenere un oggetto con rules')
    return data


def preflight_rules(spec_path: str | Path, policy: dict[str, Any], *,
                    profile_names: set[str], max_rules: int = 50) -> list[dict[str, Any]]:
    """Normalizza le regole senza risolvere token o eseguire test HTTP.

    In pratica: se anche la decima regola è errata, non eseguiamo le prime nove.
    """
    rules = policy.get('rules')
    if not isinstance(rules, list) or not 1 <= len(rules) <= max_rules:
        raise ProbeError(f'Indica da 1 a {max_rules} regole in rules')
    spec = load_openapi(spec_path)
    normalized: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for position, raw in enumerate(rules, start=1):
        if not isinstance(raw, dict):
            raise ProbeError(f'Regola {position}: serve un oggetto')
        allowed_keys = {'id', 'operation', 'path_values', 'owner', 'other', 'expected_other', 'expected_owner'}
        if set(raw) - allowed_keys:
            raise ProbeError(f'Regola {position}: campi non riconosciuti')
        rule_id = raw.get('id', f'rule-{position}')
        operation = raw.get('operation')
        owner, other = raw.get('owner'), raw.get('other')
        expected = raw.get('expected_other')
        expected_owner = raw.get('expected_owner', 'allow')
        values = raw.get('path_values', {})
        if not isinstance(rule_id, str) or not 1 <= len(rule_id) <= 64 or rule_id in identifiers:
            raise ProbeError(f'Regola {position}: ID mancante o duplicato')
        identifiers.add(rule_id)
        if not isinstance(operation, str) or not operation.startswith('GET '):
            raise ProbeError(f'Regola {position}: scegliere una GET dallo Swagger')
        if (not isinstance(owner, str) or not isinstance(other, str) or owner == other
                or owner not in profile_names or other not in profile_names):
            raise ProbeError(f'Regola {position}: servono due profili auth.yaml differenti')
        if expected_owner not in {'allow', 'deny'}:
            raise ProbeError(f'Regola {position}: expected_owner deve essere allow o deny')
        if expected not in {'allow', 'deny'}:
            raise ProbeError(f'Regola {position}: expected_other deve essere allow o deny')
        if not isinstance(values, dict) or len(values) > 15 or any(
            not isinstance(k, str) or not isinstance(v, (str, int)) or isinstance(v, bool)
            for k, v in values.items()
        ):
            raise ProbeError(f'Regola {position}: path_values non valido')
        string_values = {k: str(v) for k, v in values.items()}
        _, template = _choose_get(spec, operation, string_values)
        _render_path(template, string_values)  # Previene traversal e parametri incompleti.
        normalized.append({'id': rule_id, 'operation': operation, 'owner': owner,
                           'other': other, 'expected_other': expected,
                           'expected_owner': expected_owner, 'path_values': string_values})
    return normalized


def run_access_matrix(spec_path: str | Path, *, policy: dict[str, Any], base_url: str,
                      allowed_hosts: set[str], auth_manager: AuthenticationManager,
                      execute: bool = False, allow_insecure_http: bool = False,
                      max_requests: int = 40, rate: float = 1.0,
                      retry_401: bool = False) -> dict[str, Any]:
    """Confronta più endpoint/utenti con scope e budget; nessuna scrittura HTTP.

    Appunto: con OAuth2 possono esserci POST di autenticazione autorizzate,
    conteggiate nel ledger globale. Le chiamate applicative sono solo GET.
    """
    rules = preflight_rules(spec_path, policy, profile_names=set(auth_manager.names))
    if max_requests < len(rules) * (4 if retry_401 else 2):
        raise ProbeError('Budget insufficiente per le regole e gli eventuali retry')
    if not base_url or not allowed_hosts:
        raise ScopeError('Base URL e host esplicitamente autorizzati obbligatori')
    # Questo passaggio non fa rete: verifica host, metodo e protocollo.
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=max_requests,
                            requests_per_second=rate)
    from urllib.parse import urlsplit
    if urlsplit(base_url).scheme == 'http' and not allow_insecure_http:
        raise ScopeError('HTTP in chiaro non autorizzato')
    for rule in rules:
        target = base_url.rstrip('/') + _render_path(rule['operation'][4:], rule['path_values'])
        client._validate_target('GET', target)
    report: dict[str, Any] = {'engine': 'achilles-access-matrix-rc4', 'executed': execute,
        'confirmed_vulnerabilities': 0, 'requests_sent': 0, 'rules': [],
        'summary': {'total': len(rules), 'review_required': 0, 'expected': 0,
                    'inconclusive': 0},
        'limitations': ['Le regole di accesso sono fornite dall’operatore.',
                        'Le risposte 2xx non confermano da sole una vulnerabilità.',
                        'I corpi HTTP e le credenziali non sono esportati.']}
    if not execute:
        report['status'] = 'dry_run'
        report['rules'] = [{'id': r['id'], 'operation': r['operation'],
                            'expected_other': r['expected_other'],
                            'expected_owner': r['expected_owner'], 'owner': r['owner'], 'other': r['other'], 'state': 'ready'} for r in rules]
        return report
    remaining = max_requests
    for r in rules:
        if remaining < (4 if retry_401 else 2):
            report['rules'].append({'id': r['id'], 'status': 'not_executed_budget_exhausted'})
            report['summary']['inconclusive'] += 1
            continue
        try:
            result = compare_identities(spec_path, base_url=base_url,
                allowed_hosts=allowed_hosts, auth_manager=auth_manager,
                owner=r['owner'], other=r['other'], path_values=r['path_values'],
                operation=r['operation'], expected_other=r['expected_other'],
                expected_owner=r['expected_owner'], execute=True,
                allow_insecure_http=allow_insecure_http,
                max_requests=remaining, rate=rate, retry_401=retry_401)
            report['requests_sent'] += result['requests_sent']
            remaining -= result['requests_sent']
            status = result['status']
            if status.endswith('requires_review'):
                report['summary']['review_required'] += 1
            elif status.startswith('expected_') or status == 'inconclusive_or_expected':
                report['summary']['expected'] += 1
            else:
                report['summary']['inconclusive'] += 1
            report['rules'].append({'id': r['id'], 'operation': r['operation'],
                                    'expected_other': r['expected_other'],
                                    'expected_owner': r['expected_owner'], 'owner': r['owner'], 'other': r['other'], 'status': status,
                                    'observations': result['observations'],
                                    'same_body_observed': result.get('same_body_observed', False)})
        except (ProbeError, ScopeError, ValueError, RuntimeError) as exc:
            # Una singola regola fallita non diventa un finding confermato.
            # Interrompiamo, invece, se perdiamo la garanzia del budget.
            name = type(exc).__name__
            report['rules'].append({'id': r['id'], 'status': 'inconclusive_error',
                                    'error_type': name})
            report['summary']['inconclusive'] += 1
            if 'Budget' in name or 'Scope' in name:
                report['status'] = 'stopped_on_guardrail'
                break
    report.setdefault('status', 'completed_with_review' if report['summary']['review_required']
                      else 'completed')
    return report
