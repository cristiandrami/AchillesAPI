"""Explicitly approved, one-shot POST -> GET -> DELETE ID discovery.

Never called during OpenAPI import or preview. The UI must warn that a POST
may have persistent side effects when the response lacks an identifier.
Without positive read-back of a unique marker and ID, cleanup is blocked and
manual cleanup is reported. No raw request/response data leaves this module.
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import urlsplit
from typing import Any

from achillesapi.core.http import SafeHTTPClient
from achillesapi.core.workflows import _json_pointer, get_read_side_effect_risk
from achillesapi.dashboard.manifest_builder import (
    IDENTIFIER, build_guided_manifest,
)

_VALID_ID = re.compile(r'[A-Za-z0-9_.:~-]{1,128}\Z')
_SAFE_HOST = re.compile(r'[A-Za-z0-9.:-]{1,253}\Z')


def _candidate_values(data: Any, parent_values: dict[str,str], prefix: str = '', depth: int = 0) -> list[dict[str, str]]:
    """Collect bounded scalar JSON Pointer candidates, including opaque "id" keys."""
    if depth > 5 or len(prefix) > 120:
        return []
    result: list[dict[str, str]] = []
    if isinstance(data, dict):
        for key, value in list(data.items())[:60]:
            if not isinstance(key, str):
                continue
            pointer = prefix + '/' + key.replace('~','~0').replace('/','~1')
            if (IDENTIFIER.search(key) and isinstance(value, (str,int))
                and not isinstance(value, bool) and _VALID_ID.fullmatch(str(value))
                and not (key in parent_values and str(value) == parent_values[key])):
                result.append({'pointer': pointer, 'value': str(value), 'field': key})
            elif isinstance(value, (dict, list)):
                result += _candidate_values(value, parent_values, pointer, depth + 1)
    elif isinstance(data, list):
        for idx, value in enumerate(data[:3]):
            if isinstance(value, (dict,list)):
                result += _candidate_values(value, parent_values, prefix+'/'+str(idx), depth+1)
    return result[:35]


def _untyped_scalar_candidates(data: Any, parent_values: dict[str,str],
                               input_values: set[str], prefix: str = '', depth: int = 0) -> list[dict[str,str]]:
    """Fallback when an API uses an opaque ID field name (e.g. /receipt/code).

    A single candidate may be verified via GET; several ambiguous values are
    returned as hints and MUST NOT authorize DELETE. Avoid known secret names.
    """
    if depth>5:return []
    result=[]
    if isinstance(data,dict):
        for key,value in list(data.items())[:45]:
            if not isinstance(key,str) or re.search(r'(?:password|secret|token|authorization|credential|cookie|session|api.?key)',key,re.I):
                continue
            ptr=prefix+'/'+key.replace('~','~0').replace('/','~1')
            if isinstance(value,(str,int)) and not isinstance(value,bool) and _VALID_ID.fullmatch(str(value)):
                if str(value) not in input_values and not (key in parent_values and str(value)==parent_values[key]):
                    result.append({'pointer':ptr,'value':str(value),'field':key})
            elif isinstance(value,(dict,list)):
                result += _untyped_scalar_candidates(value,parent_values,input_values,ptr,depth+1)
    elif isinstance(data,list):
        for i,value in enumerate(data[:3]):
            if isinstance(value,(dict,list)):
                result += _untyped_scalar_candidates(value,parent_values,input_values,prefix+'/'+str(i),depth+1)
    return result[:40]


def _select_identifier(json_data: Any, candidate: dict[str, Any], parent_values: dict[str,str], input_values: set[str] | None = None) -> tuple[str | None, str | None, list[str]]:
    options = _candidate_values(json_data, parent_values)
    if not options:
        options = _untyped_scalar_candidates(json_data, parent_values,
                                              (input_values or set()) | set(parent_values.values()))
    if not options:
        return None, None, []
    declared = set(candidate.get('id_schema_pointers') or [])
    name = candidate.get('path_parameter') or ''
    def score(row: dict[str,str]) -> int:
        key = row['field'].lower()
        return (100 if row['pointer'] in declared else 0) + (80 if key == name.lower() else 0) + (70 if key == 'id' else 0) + (30 if key in ('uuid','uid','guid') else 0) - row['pointer'].count('/') * 3
    ranked = sorted(options, key=lambda row: (-score(row), row['pointer']))
    # Scores alone cannot prove which ID belongs to the newly created object.
    top = score(ranked[0])
    if len(ranked) > 1 and score(ranked[1]) == top:
        return None, None, [r['pointer'] for r in ranked]
    return ranked[0]['pointer'], ranked[0]['value'], [r['pointer'] for r in ranked]


def _response_json(evidence: Any) -> dict[str,Any] | list[Any] | None:
    response = evidence.response
    if response is None or response.body_truncated:
        return None
    try:
        obj = json.loads(response.body_preview)
        return obj if isinstance(obj,(dict,list)) else None
    except (ValueError, TypeError):
        return None


def _matches_marker(obj: Any, marker: str, pointer_hints: list[str]) -> bool:
    if any(_json_pointer(obj, ptr) == marker for ptr in pointer_hints):
        return True
    # A schema may omit the read response: still require an exact scalar match.
    def recursive(value: Any, depth: int = 0) -> bool:
        if depth > 5:return False
        if isinstance(value,dict):
            return any(v == marker if isinstance(v,str) else recursive(v,depth+1) if isinstance(v,(dict,list)) else False for v in list(value.values())[:60])
        if isinstance(value,list):
            return any(recursive(x,depth+1) for x in value[:5])
        return False
    return recursive(obj)


def _matches_id(obj: Any, identifier: str, pointer_hints: list[str]) -> bool:
    if any(str(_json_pointer(obj, ptr)) == identifier for ptr in pointer_hints):
        return True
    return (any(row['value'] == identifier for row in _candidate_values(obj, {}))
            or any(row['value'] == identifier for row in _untyped_scalar_candidates(obj, {}, set())))


def probe_created_identifier(
    *, candidate: dict[str, Any], spec: dict[str,Any], parsed: Any,
    base_url: str, allow_host: str, allow_insecure_http: bool,
    identity: str, auth_manager: Any, path_values: dict[str,str], body: dict[str,Any],
    marker_field: str, approve_writes: bool, approve_possible_orphan: bool,
    acknowledge_get_side_effect_risk: bool = False,
    client: SafeHTTPClient | None = None,
) -> dict[str,Any]:
    """Bounded, authorized 3-request probe; never silently create resources."""
    if not approve_writes or not approve_possible_orphan:
        raise ValueError('Conferma scritture e possibilità di cleanup manuale prima della POST di prova.')
    parsed_url = urlsplit(base_url)
    if (parsed_url.scheme not in ('http','https') or not parsed_url.hostname or
        not _SAFE_HOST.fullmatch(allow_host) or allow_host.lower().rstrip('.') != parsed_url.hostname.lower().rstrip('.') or
        parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment):
        raise ValueError('Base URL e hostname autorizzato devono coincidere e non contenere credenziali.')
    if parsed_url.scheme == 'http' and (not allow_insecure_http or parsed_url.hostname not in {'127.0.0.1','localhost','::1'}):
        raise ValueError('HTTP in chiaro per la prova è consentito solo su localhost con approvazione.')
    if not candidate.get('ready') or not candidate.get('read') or not candidate.get('delete'):
        raise ValueError('Creazione di prova richiede POST, GET, DELETE e un marcatore verificabile.')
    if candidate.get('read_get_risk') and not acknowledge_get_side_effect_risk:
        raise ValueError('La GET potrebbe modificare lo stato: conferma separatamente il rischio della GET.')
    if not isinstance(path_values,dict) or set(path_values) != set(candidate.get('required_path_params') or []):
        raise ValueError('Compila tutti gli ID parent richiesti dal path prima della prova.')
    if any(not isinstance(x,str) or not _VALID_ID.fullmatch(x) for x in path_values.values()):
        raise ValueError('Valore parent non valido per una risorsa di test.')
    if identity not in auth_manager.names:
        raise ValueError('Profilo di autenticazione non disponibile.')
    # Reuse the same schema, path and mutation validation as the actual workflow.
    build_guided_manifest(candidate, owner=identity, other=None,
                          marker=marker_field, identifier='id', body=body,
                          deny_other=False, path_values=path_values,
                          acknowledge_get_side_effect_risk=acknowledge_get_side_effect_risk)
    field = candidate['field_specs'].get(marker_field,{})
    max_length = field.get('maxLength')
    marker = 'achilles-' + secrets.token_hex(10)
    if isinstance(max_length,int) and len(marker) > max_length:
        raise ValueError('Il campo marker non permette una stringa di prova univoca.')
    probe_body = dict(body)
    probe_body[marker_field] = marker
    user = auth_manager.resolve(identity, allowed_hosts={allow_host}, allow_insecure_http=allow_insecure_http)
    client = client or SafeHTTPClient(allowed_hosts={allow_host}, allowed_methods={'POST','GET','DELETE'},
                                     max_requests=3, requests_per_second=1.0, max_body_bytes=65_536)
    result: dict[str,Any] = {'created':False,'verified':False,'cleanup_verified':False,
                 'manual_cleanup_required':False,'id_pointer':None,'id_value':None,
                 'candidate_pointers':[],'http_attempts':0,'steps':[],'marker_for_cleanup':None,
                 'notice':'La POST reale è stata autorizzata; nessun body/token di risposta viene salvato.'}
    def send(method: str, operation: str, *, identifier: str | None = None, json_body:dict[str,Any] | None=None):
        _, path = operation.split(' ', 1)
        values = dict(path_values)
        if identifier is not None:
            values[candidate['path_parameter']] = identifier
        for name in re.findall(r'\{([^{}]+)\}',path):
            if name not in values:
                raise ValueError('Manca ID parent per il path di ' + method + ': ' + name)
            path = path.replace('{'+name+'}',values[name])
        if len(path)>2000 or not path.startswith('/'):
            raise ValueError('Path di prova fuori dai limiti')
        evidence = client.request(method,base_url.rstrip('/')+path,execute=True,
                                  headers=user.headers,cookies=user.cookies,params=user.params,json_body=json_body)
        result['http_attempts']+=1
        status = evidence.response.status_code if evidence.response else None
        result['steps'].append({'method':method,'status':status,'network_error':bool(evidence.error)})
        return evidence
    # Before POST, ensure the required READ/DELETE variables can be substituted.
    for operation in (candidate['read'],candidate['delete']):
        missing = set(re.findall(r'\{([^{}]+)\}', operation)) - set(path_values) - {candidate['path_parameter']}
        if missing:
            raise ValueError('Il workflow richiede ulteriori parent ID: ' + ', '.join(sorted(missing)))
    created = send('POST',candidate['create'],json_body=probe_body)
    if created.response is None or not 200 <= created.response.status_code < 300:
        result['manual_cleanup_required'] = True
        result['notice'] = 'POST non confermata o risposta di rete incerta: verifica se una risorsa è stata creata prima di riprovare.'
        return result
    result['created'] = True
    result['marker_for_cleanup'] = marker
    # Once POST has succeeded the object may be orphaned: never claim cleanup
    # unless GET verifies a uniquely identified object with the exact marker.
    result['manual_cleanup_required'] = True
    pointer, identifier, candidates = _select_identifier(_response_json(created), candidate, path_values,
        {str(v) for v in probe_body.values() if isinstance(v, (str,int)) and not isinstance(v,bool)})
    result['candidate_pointers'] = candidates
    if pointer is None or identifier is None:
        result['notice'] = 'Risposta POST senza ID unico riconoscibile: risorsa eventualmente creata, cleanup manuale necessario. Controlla il report del server.'
        return result
    result['id_pointer'] = pointer
    result['id_value'] = identifier
    try:
        read = send('GET', candidate['read'],identifier=identifier)
    except (ValueError,RuntimeError) as exc:
        result['notice'] = 'GET non completata dopo la POST: possibili effetti persistenti, cleanup manuale necessario.'
        return result
    data = _response_json(read)
    if not read.response or read.response.status_code != 200 or data is None:
        result['notice'] = 'ID trovato ma GET di controllo fallita. Non eseguo DELETE: cleanup manuale necessario.'
        return result
    hints = (candidate.get('read_marker_pointers') or {}).get(marker_field) or ['/'+marker_field]
    id_hints = candidate.get('read_id_candidates') or [pointer, '/id', '/data/id']
    if not (_matches_marker(data, marker, hints) and _matches_id(data,identifier,id_hints)):
        result['notice'] = 'GET non conferma ID e marker della stessa risorsa: DELETE bloccata, cleanup manuale necessario.'
        return result
    result['verified'] = True
    try:
        deleted = send('DELETE', candidate['delete'],identifier=identifier)
    except (ValueError,RuntimeError):
        result['notice'] = 'DELETE non completata dopo la POST: verifica manualmente il cleanup.'
        return result
    result['cleanup_verified'] = bool(deleted.response and 200 <= deleted.response.status_code < 300)
    result['manual_cleanup_required'] = not result['cleanup_verified']
    result['notice'] = ('ID rilevato, oggetto verificato e DELETE riuscita. Puoi usare il JSON Pointer nel manifest.'
                        if result['cleanup_verified'] else
                        'ID rilevato ma DELETE non riuscita: verifica manualmente la risorsa prima di altri test.')
    return result


def resolve_parent_from_get(*, candidate: dict[str,Any], variable: str, source_operation: str,
                            pointer: str, base_url: str, allow_host: str, identity: str,
                            auth_manager: Any, approve_http: bool, allow_insecure_http: bool,
                            client: SafeHTTPClient | None = None) -> dict[str,Any]:
    """One GET approved by operator, selected from OpenAPI; no blind enumeration."""
    if not approve_http:
        raise ValueError('Conferma di autorizzazione HTTP necessaria per recuperare l’ID parent.')
    source = next((source for item in candidate.get('parent_guidance', [])
                   if item.get('parameter') == variable
                   for source in item.get('read_sources', [])
                   if source.get('operation') == source_operation),None)
    if not source:
        raise ValueError('GET non presente tra i suggerimenti autorizzati di questo Swagger.')
    if not re.fullmatch(r'/(?:[A-Za-z0-9_~.-]+/?){1,8}', pointer):
        raise ValueError('JSON Pointer non valido per recuperare ID parent.')
    target=urlsplit(base_url)
    if (target.scheme not in ('http','https') or not target.hostname or target.hostname.lower() != allow_host.lower() or
        target.username or target.password or target.query or target.fragment):
        raise ValueError('Host autorizzato e Base URL devono coincidere.')
    if target.scheme == 'http' and (not allow_insecure_http or target.hostname not in {'127.0.0.1','localhost','::1'}):
        raise ValueError('HTTP consentito solo su localhost con consenso specifico.')
    if identity not in auth_manager.names:
        raise ValueError('Profilo di autenticazione non valido.')
    user=auth_manager.resolve(identity,allowed_hosts={allow_host},allow_insecure_http=allow_insecure_http)
    client=client or SafeHTTPClient(allowed_hosts={allow_host},allowed_methods={'GET'},max_requests=1)
    _, path=source_operation.split(' ',1)
    observed=client.request('GET',base_url.rstrip('/')+path,execute=True,
                            headers=user.headers,cookies=user.cookies,params=user.params)
    data=_response_json(observed)
    if observed.response is None or observed.response.status_code != 200 or data is None:
        return {'found':False,'status':observed.response.status_code if observed.response else None,
                'message':'La GET non ha fornito JSON 200 leggibile; chiedi un ID parent autorizzato.'}
    value=_json_pointer(data,pointer)
    if not isinstance(value,(str,int)) or isinstance(value,bool) or not _VALID_ID.fullmatch(str(value)):
        return {'found':False,'status':200,'message':'La risposta non contiene un ID parent valido nel JSON Pointer selezionato.'}
    return {'found':True,'value':str(value),'source':source_operation,'pointer':pointer,
            'status':200,'message':'ID parent ottenuto con una GET autorizzata. Verifica che appartenga al profilo selezionato.'}
