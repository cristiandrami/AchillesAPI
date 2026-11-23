"""Prove di injection GET entro scope: nessuna scrittura e nessuna shell locale.

Appunti importanti:
- Il motore non utilizza nomi degli endpoint scritti per un laboratorio.
- I casi di test partono dai parametri query dichiarati nello Swagger.
- Le risposte rimangono temporanee; nel report salviamo solo indicatori.
- Un confronto sospetto NON basta per dichiarare una vulnerabilità confermata.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from achillesapi.core.auth import AuthenticationManager
from achillesapi.core.http import SafeHTTPClient
from achillesapi.core.openapi import load_openapi, parse_openapi

FAMILIES = ('sql_error', 'sql_boolean', 'sql_time', 'nosql', 'ssti', 'command', 'xpath', 'ldap', 'crlf')
DEFAULT_FAMILIES = ('sql_error', 'sql_boolean', 'nosql', 'ssti', 'command', 'xpath', 'ldap', 'crlf')
SQL_ERRORS = re.compile(r'(sqlite|sql syntax|sqlstate|unterminated quoted|mysql|postgresql|ora-\d{4}|odbc|database error)', re.I)
COMMAND_MARKER = 'ACHILLES_RC5_CMD_MARKER'

# Payload brevi e non distruttivi. La famiglia time-based è opzionale.
PAIRS: dict[str, tuple[str, ...]] = {
    'sql_error': ("'",),
    'sql_boolean': ("z' OR '1'='1", "z' OR '1'='2"),
    'sql_time': ("z' OR IF(1=1,SLEEP(0.35),0)-- ", "z' OR IF(1=2,SLEEP(0.35),0)-- "),
    'nosql': ('{"$ne":null}', '{"$eq":"__achilles_nonexistent__"}'),
    'ssti': ('{{7*7}}', '{{7*8}}'),
    'command': ('127.0.0.1; echo ' + COMMAND_MARKER, '127.0.0.1'),
    'xpath': ("x' or '1'='1", "x' or '1'='2"),
    'ldap': ('*)(|(cn=*))', 'achilles-nonexistent-user'),
    'crlf': ('achilles\r\nX-Achilles-Probe: safe-marker', 'achilles'),
}


class InjectionConfigurationError(ValueError):
    """Il piano non è utilizzabile senza dati aggiuntivi."""


def _fingerprint(text: str | None) -> str:
    return hashlib.sha256((text or '').encode('utf-8', errors='replace')).hexdigest()[:16]


def _path(template: str, values: dict[str, str]) -> str:
    """Rende il path Swagger senza trasformare un valore in un nuovo segmento."""
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        value = values.get(key)
        if not isinstance(value, str) or not value or len(value) > 128 or any(c in value for c in '/\\?#%\r\n') or value in {'.', '..'}:
            raise InjectionConfigurationError('Valore path mancante/non valido: ' + key)
        return quote(value, safe='')
    return re.sub(r'\{([^{}]+)\}', replace, template)


def _select(specification: dict, values: dict[str, str]) -> tuple[list[dict], list[dict]]:
    """Select GET query, scoped path and declared non-sensitive custom headers."""
    parsed = parse_openapi(specification)
    results: list[dict] = []
    ignored: list[dict] = []
    excluded = ('password', 'token', 'secret', 'api_key', 'apikey', 'authorization',
                'cookie', 'host', 'proxy', 'forwarded')
    for endpoint in parsed.endpoints:
        label = f'{endpoint.method} {endpoint.path}'
        if endpoint.method != 'GET':
            ignored.append({'operation': label, 'reason':'Body or write tests require an approved disposable fixture.'})
            continue
        try:
            rendered = _path(endpoint.path, values)
        except InjectionConfigurationError as exc:
            ignored.append({'operation':label,'reason':str(exc)})
            continue
        for parameter in endpoint.parameters:
            if parameter.location not in ('query', 'path', 'header'):
                continue
            if any(x in parameter.name.lower() for x in excluded):
                ignored.append({'operation':label,'reason':'Sensitive or routing header/parameter omitted.'})
                continue
            if parameter.location == 'header' and not parameter.name.lower().startswith('x-'):
                ignored.append({'operation':label,'reason':'Only custom x- headers are eligible.'})
                continue
            if parameter.location == 'path' and parameter.name not in values:
                ignored.append({'operation':label,'reason':'Safe path ID missing.'})
                continue
            results.append({'operation':label,'path':rendered, 'template':endpoint.path,
                            'parameter':parameter.name,'location':parameter.location})
    return results, ignored


def _collect(response: Any) -> dict[str, Any]:
    """Nel report non entrano payload, token o corpi HTTP."""
    part = response.response
    body = part.body_preview if part else None
    return {
        'status': part.status_code if part else None,
        'length': len(body) if body is not None else None,
        'body_digest': _fingerprint(body) if body is not None else None,
        'elapsed_ms': part.elapsed_ms if part else None,
        'error': response.error if not part else None,
        'truncated': part.body_truncated if part else None,
        '_body': body,
        '_headers': part.headers if part else {},
    }


def _without_echo(text: str, payload: str) -> str:
    """Ignora le differenze dovute alla sola riflessione dell'input.

    Esempio: una ricerca che restituisce il termine digitato cambia output
    per due input diversi, ma questo NON significa SQLi o XPath injection.
    """
    try:
        parsed=json.loads(text)
        def strip(value):
            if isinstance(value,str):
                return value.replace(payload,'[QUERY_INPUT]')
            if isinstance(value,list):
                return [strip(v) for v in value]
            if isinstance(value,dict):
                return {k:strip(v) for k,v in value.items()}
            return value
        return json.dumps(strip(parsed),sort_keys=True,ensure_ascii=False)
    except (ValueError, TypeError):
        return text.replace(payload,'[QUERY_INPUT]')


def _review(family: str, base: dict, variants: list[dict], probes: tuple[str, ...]) -> tuple[str, list[str]]:
    """Sceglie indicatori prudenti, senza chiamarli exploit confermati."""
    if base.get('error') or not variants or any(x['error'] for x in variants):
        return 'inconclusive', ['Mancano risposte HTTP valide.']
    if base.get('truncated') or any(x['truncated'] for x in variants):
        return 'inconclusive', ['Corpo troncato: confronto non affidabile.']
    text = [x['_body'] or '' for x in variants]
    notes = []
    if family == 'sql_error':
        if SQL_ERRORS.search(text[0]) and not SQL_ERRORS.search(base['_body'] or ''):
            notes.append('Nuovo errore SQL dopo il carattere di prova.')
    elif family == 'ssti':
        if (len(text)>1 and re.search(r'(?<!\d)49(?!\d)', text[0]) and re.search(r'(?<!\d)56(?!\d)', text[1])
                and not re.search(r'(?<!\d)(?:49|56)(?!\d)', base.get('_body') or '')
                and '{{7*7}}' not in text[0] and '{{7*8}}' not in text[1]):
            notes.append('La risposta contiene due risultati aritmetici coerenti con una valutazione template.')
    elif family == 'command':
        if (COMMAND_MARKER in text[0] and COMMAND_MARKER not in text[1]
                and _without_echo(text[0],probes[0]) != _without_echo(text[1],probes[1])):
            # Un'eco del parametro senza esecuzione NON prova command injection.
            notes.append('Il marker compare nella risposta; può trattarsi anche di semplice riflessione.')
            return 'manual_review', notes
    elif family == 'crlf':
        if any(k.lower() == 'x-achilles-probe' and v == 'safe-marker' for k, v in variants[0]['_headers'].items()):
            notes.append('Header di prova presente nella risposta (verificare proxy e cache).')
    elif family == 'sql_time':
        a, b = variants[0].get('elapsed_ms'), variants[1].get('elapsed_ms')
        if a is not None and b is not None and a - b > 250:
            notes.append('Differenza temporale: necessarie ripetizioni per escludere jitter.')
    else:
        if (variants[0]['status'] == variants[1]['status'] == base.get('status') == 200
                and _without_echo(text[0],probes[0]) != _without_echo(text[1],probes[1])):
            notes.append('Differenza fra condizione di prova positiva e negativa: controllare la semantica.')
    return ('suspected' if notes else 'no_indicator'), notes


def _family_priority(item: dict[str, str], family: str) -> int:
    """Schedule relevant, cheap, read-only probes before brute family sweeps.

    Only generic OpenAPI operation and parameter hints influence ordering.
    They never constitute a finding and never expand the authorized scope.
    """
    name = (item['operation'] + ' ' + item['parameter']).lower()
    clues = {
        'sql_error': ('sql', 'search', 'query', 'report', 'term'),
        'sql_boolean': ('sql', 'search', 'query', 'report', 'term'),
        'nosql': ('selector', 'filter', 'mongo', 'nosql', 'criteria'),
        'ssti': ('template', 'render', 'expression', 'format'),
        'command': ('diagnostic', 'address', 'host', 'command', 'shell', 'ping'),
        'xpath': ('xpath', 'xml', 'document'),
        'ldap': ('ldap', 'directory', 'distinguished', 'filter'),
        'crlf': ('gateway', 'header', 'response', 'newline', 'redirect'),
        'sql_time': ('sql', 'query', 'search'),
    }
    return (20 if any(word in name for word in clues.get(family, ())) else 0) + (
        2 if family == 'sql_error' else 1 if family == 'sql_boolean' else 0
    )


def _schedule_probes(items: list[dict], families: tuple[str, ...]) -> list[tuple[dict, str]]:
    """Cover one family on each eligible surface before deeper testing.

    The old endpoint-major loop could exhaust a 40-request budget on the first
    two or three search parameters, never reaching later XML/template inputs.
    """
    ranked = [sorted(families, key=lambda f: -_family_priority(item, f)) for item in items]
    return [(item, ranked[i][round_index])
            for round_index in range(len(families))
            for i, item in enumerate(items) if round_index < len(ranked[i])]


def injection_assessment(spec_path: Path, *, base_url: str, allow_hosts: set[str],
                         path_values: dict[str, str] | None = None,
                         auth_manager: AuthenticationManager | None = None,
                         profile: str | None = None, execute: bool = False,
                         allow_insecure_http: bool = False,
                         max_requests: int = 40, rate: float = 2.0,
                         families: tuple[str, ...] = DEFAULT_FAMILIES) -> dict[str, Any]:
    """Esegue prove GET limitate; nessuna scrittura o conferma automatica."""
    if any(family not in FAMILIES for family in families) or not families:
        raise InjectionConfigurationError('Famiglia injection sconosciuta.')
    if max_requests < 1 or max_requests > 150:
        raise InjectionConfigurationError('Budget massimo consentito: 1–150 richieste.')
    if profile and (not auth_manager or profile not in auth_manager.names):
        raise InjectionConfigurationError('Il profilo richiesto non è in auth.yaml.')
    if execute and base_url.startswith('http://') and not allow_insecure_http:
        raise InjectionConfigurationError('HTTP con credenziali richiede approvazione esplicita.')
    if not base_url or not allow_hosts:
        raise InjectionConfigurationError('Indica Base URL e host autorizzato.')
    spec = load_openapi(spec_path)
    from achillesapi.core.injection_planner_v2 import injection_surface_plan
    surface_plan = injection_surface_plan(spec)
    selected, ignored = _select(spec, path_values or {})
    client = SafeHTTPClient(allowed_hosts=allow_hosts, max_requests=max_requests,
                            requests_per_second=rate, max_body_bytes=16384, timeout=5)
    cases: list[dict[str, Any]] = []
    remaining = max_requests
    schedule = _schedule_probes(selected[:120], families)
    for item, family in schedule:
        probes = PAIRS[family]
        needed = 1 + len(probes)
        if execute and remaining < needed:
            ignored.append({'operation': item['operation'], 'parameter': item['parameter'],
                            'family': family, 'reason': 'Budget HTTP insufficiente: prova non eseguita.'})
            continue
        case = {'operation': item['operation'], 'parameter': item['parameter'],
                'location': item['location'], 'family': family,
                'status': 'not_executed' if not execute else 'inconclusive', 'indicators': [],
                'request_count': 0}
        cases.append(case)
        if not execute:
            continue
        auth = auth_manager.resolve(profile, allowed_hosts=allow_hosts, allow_insecure_http=allow_insecure_http) if profile else None
        params = dict(auth.params) if auth else {}
        safe_headers = dict(auth.headers) if auth else {}
        safe_cookies = dict(auth.cookies) if auth else {}
        def fetch(value: str) -> dict:
            location = item['location']
            url = base_url.rstrip('/') + item['path']
            query = dict(params)
            headers = dict(safe_headers)
            if location == 'query':
                query[item['parameter']] = value
            elif location == 'header':
                headers[item['parameter']] = value
            else:
                # Preserve the approved original fixture ID while altering
                # this single path parameter. No ID enumeration or writes.
                original = (path_values or {}).get(item['parameter'], '')
                url = base_url.rstrip('/') + _path(item['template'],
                        {**(path_values or {}), item['parameter']:original + value})
            return _collect(client.request('GET', url, execute=True,
                params=query, headers=headers, cookies=safe_cookies,
                sensitive_query_names=set(query)|{item['parameter']},
                sensitive_header_names=set(headers)|{item['parameter']}))
        try:
            baseline = fetch('__achilles_normal_control__')
            outcomes = [fetch(payload) for payload in probes]
            case['request_count'] = needed
            case['status'], case['indicators'] = _review(family, baseline, outcomes, probes)
            if baseline['status'] in (401, 403) and all(x['status'] in (401, 403) for x in outcomes):
                case['status'] = 'not_tested_auth'
                case['indicators'] = ['Tutte le sonde sono state rifiutate (401/403): verificare identità e permessi prima di dedurre che l’input sia sicuro.']
            case['evidence'] = {'baseline': {k: v for k, v in baseline.items() if not k.startswith('_')},
                                'variants': [{k: v for k, v in x.items() if not k.startswith('_')} for x in outcomes]}
            remaining -= needed
        except Exception as exc:
            # Non scriviamo contenuti dell'eccezione: potrebbero contenere URL o credenziali.
            case['status'] = 'inconclusive'
            case['indicators'] = ['Prova non conclusa: ' + type(exc).__name__]
            remaining = max(0, max_requests - client.request_statistics['attempted'])
            if remaining < 3:
                break
    # Un payload XPath può funzionare anche in SQL: non attribuiamo il linguaggio
    # senza conoscere la tecnologia del backend. L'operatore dovrà verificare.
    sql_suspects={(c['operation'],c['parameter']) for c in cases
                  if c['family'] in {'sql_error','sql_boolean'} and c['status']=='suspected'}
    for case in cases:
        if (case['family']=='xpath' and case['status']=='suspected' and
                (case['operation'],case['parameter']) in sql_suspects):
            case['status']='manual_review'
            case['indicators']=['Sintassi condivisa con SQL: verificare il motore backend prima di classificare come XPath.']
    return {
        'engine': 'achilles-injection-assessment-rc5', 'mode': 'GET_query_active_plus_all_methods_offline_plan',
        'extended_injection_plan': surface_plan,
        'executed': execute, 'confirmed_vulnerabilities': 0,
        'requests_sent': client.request_statistics['attempted'],
        'summary': {'planned': len(schedule), 'executed_cases': len(cases) if execute else 0,
                    'covered_inputs': len({(c['operation'], c['parameter'], c['location']) for c in cases}) if execute else 0,
                    'suspicious': sum(c['status'] in ('suspected','manual_review') for c in cases),
                    'inconclusive': sum(c['status'] in ('inconclusive','not_tested_auth') for c in cases),
                    'auth_blocked_cases': sum(c['status'] == 'not_tested_auth' for c in cases),
                    'untested_operations': len(ignored)},
        'cases': cases,
        # Le segnalazioni sono candidate, non vulnerabilità confermate.
        'findings': [
            {'category':'possible_'+case['family']+'_injection',
             'operation':case['operation'], 'parameter':case['parameter'], 'location':case['location'],
             'severity':'medium' if case['status']=='suspected' else 'informational',
             'verification_status':'requires_manual_review',
             'reason':'; '.join(case['indicators']),
             # Exact fixed probes actually sent; never record authorization,
             # custom HTTP headers, cookies or response bodies.
             'test_payloads':list(PAIRS[case['family']]),
             'test_baseline':'__achilles_normal_control__',
             'evidence':case.get('evidence',{})}
            for case in cases if case['status'] in {'suspected','manual_review'}
        ],
        'skipped': ignored[:250],
        'limitations': [
            'Le sonde GET possono usare query, path fixture autorizzati e header X-; body JSON/XML, XXE e scritture restano pianificati offline.',
            'Il piano attraversa prima tutti gli input GET applicabili; la scelta iniziale delle famiglie è euristica e non prova una vulnerabilità.',
            'Se i controlli ricevono soltanto 401/403 senza profilo autorizzato, sono indicati come non verificati, non come esito negativo.',
            'Boolean, NoSQL, XPath, LDAP e template producono indizi, non exploit confermati.',
            'Il test time-based è opzionale e non sufficiente senza ripetizioni e statistiche.',
            'Il report salva soltanto i payload fissi del motore, mai credenziali, header autenticati o corpi di risposta.',
            'I test sono eseguiti soltanto sul target esplicitamente autorizzato.',
        ],
    }
