"""Offline, target-independent disposable-resource manifest assistant.

Only OpenAPI metadata is read. A draft is NOT a permission to write: callers
must review fixture values, pointer semantics, account ownership and cleanup.
"""
from __future__ import annotations

import re
from typing import Any

import yaml

from achillesapi.core.openapi import load_openapi, parse_openapi
from achillesapi.core.workflows import _request_schema
from achillesapi.core.testgen import _resolve_schema

PATH_VAR = re.compile(r'\{([^{}]+)\}')
IDENTIFIER = re.compile(r'(?:^id$|_id$|Id$|ID$|uuid|guid|^uid$|_ref$|Ref$|reference$|^key$|_key$|Key$|identifier$|Identifier$)', re.I)
MARKER = re.compile(r'^(?:label|name|title|description|reference|tag)$', re.I)
SENSITIVE = re.compile(r'password|secret|token|credential|api.?key', re.I)


def _fields(spec: dict[str, Any], schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return a bounded writable JSON property map, resolving local references."""
    props = _resolve_schema(spec, schema).get('properties', {})
    if not isinstance(props, dict):
        return {}
    return {str(k): _resolve_schema(spec, v) for k,v in list(props.items())[:50]
            if isinstance(v, dict) and not _resolve_schema(spec,v).get('readOnly')}


def _sample_field(field: dict[str, Any]) -> Any:
    """Generate non-sensitive examples only; never pretend they are business-valid."""
    if field.get('enum') and isinstance(field['enum'], list):
        return field['enum'][0]
    typ=field.get('type')
    if typ=='boolean': return False
    if typ=='integer': return max(1,field.get('minimum',0))
    if typ=='number': return max(1.0,field.get('minimum',0.0))
    if typ=='array': return []
    if typ=='object': return {}
    if typ=='string':
        return 'REVIEW_VALUE'
    return 'REVIEW_VALUE'


def _response_schema(spec: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    """Resolve a response with JSON content, including local response $ref."""
    response = _resolve_schema(spec, response)
    for media, content in response.get('content', {}).items():
        if 'json' in media.lower() and isinstance(content, dict):
            return _resolve_schema(spec, content.get('schema', {}))
    return {}


def _object_schema(spec: dict[str, Any], schema: Any, depth: int = 0) -> dict[str, Any]:
    """Resolve local $ref/composition and common response envelopes (offline)."""
    if depth > 8 or not isinstance(schema, dict):
        return {}
    resolved = _resolve_schema(spec, schema)
    merged = dict(resolved)
    if isinstance(merged.get('properties'), dict):
        merged['properties'] = dict(merged['properties'])
    for branch in ('allOf', 'oneOf', 'anyOf'):
        options = resolved.get(branch, [])
        if isinstance(options, list):
            for part in options[:8]:
                sub = _object_schema(spec, part, depth + 1)
                merged.setdefault('properties', {}).update(sub.get('properties', {}))
                merged['required'] = list(dict.fromkeys(merged.get('required', []) + sub.get('required', [])))
    return merged


def _id_pointers(spec: dict[str, Any], schema: dict[str, Any], prefix: str = '', depth: int = 0) -> list[str]:
    if depth > 3:
        return []
    obj = _object_schema(spec, schema)
    candidates = []
    for name, raw in list(obj.get('properties', {}).items())[:60]:
        if not isinstance(raw, dict):
            continue
        field = _object_schema(spec, raw)
        pointer = prefix + '/' + name.replace('~', '~0').replace('/', '~1')
        if IDENTIFIER.search(name) and field.get('type') in ('integer', 'string', 'number', None):
            candidates.append(pointer)
        if field.get('type') == 'object' or field.get('properties'):
            candidates += _id_pointers(spec, raw, pointer, depth + 1)
    return list(dict.fromkeys(candidates))[:30]


def _json_example_paths(node: Any, keys: set[str] | None = None, prefix: str = '', depth: int = 0) -> list[str]:
    if depth > 4 or not isinstance(node, dict):
        return []
    paths = []
    for key, value in list(node.items())[:50]:
        pointer = prefix + '/' + str(key).replace('~','~0').replace('/','~1')
        if (keys is None and IDENTIFIER.search(key) or keys is not None and key in keys) and isinstance(value,(str,int)) and not isinstance(value,bool):
            paths.append(pointer)
        elif isinstance(value,dict):
            paths += _json_example_paths(value, keys, pointer, depth+1)
    return paths


def _response_examples(spec: dict[str, Any], endpoint: Any) -> list[dict[str, Any]]:
    result = []
    if endpoint is None:
        return []
    for status, response in endpoint.responses.items():
        if not str(status).startswith('2') or not isinstance(response,dict):
            continue
        response = _resolve_schema(spec,response)
        for media, entry in response.get('content',{}).items():
            if 'json' not in media.lower() or not isinstance(entry,dict):
                continue
            if isinstance(entry.get('example'),dict):result.append(entry['example'])
            schema = _resolve_schema(spec,entry.get('schema',{}))
            if isinstance(schema.get('example'),dict):result.append(schema['example'])
            for example in entry.get('examples',{}).values():
                example = _resolve_schema(spec,example) if isinstance(example,dict) else {}
                if isinstance(example.get('value'),dict):result.append(example['value'])
    return result[:10]


def _response_field_pointers(spec: dict[str, Any], endpoint: Any, name: str) -> list[str]:
    if endpoint is None:return []
    pointers = []
    def walk(schema: dict[str, Any], prefix: str = '', depth: int = 0) -> None:
        if depth > 4:return
        obj = _object_schema(spec,schema)
        for key, value in list(obj.get('properties',{}).items())[:50]:
            pointer = prefix + '/' + key.replace('~','~0').replace('/','~1')
            if key == name:pointers.append(pointer)
            if isinstance(value,dict):walk(value,pointer,depth+1)
    for status, response in endpoint.responses.items():
        if str(status).startswith('2') and isinstance(response,dict):
            walk(_response_schema(spec,response))
    for example in _response_examples(spec,endpoint):
        pointers.extend(_json_example_paths(example,{name}))
    return list(dict.fromkeys(pointers))[:15]


def _response_id_candidates(spec: dict[str, Any], endpoint: Any) -> list[str]:
    paths = []
    for status, response in endpoint.responses.items():
        if not str(status).startswith('2') or not isinstance(response, dict):
            continue
        paths.extend(_id_pointers(spec, _response_schema(spec, response)))
    for example in _response_examples(spec, endpoint):
        paths.extend(_json_example_paths(example))
    # Prefer true /id and /<resource>Id before generic references.
    return sorted(set(paths), key=lambda x: (x.count('/'), 0 if x.lower().endswith('/id') else 1, x))


def _resource_name(path: str) -> str:
    names = [s for s in path.lower().split('/') if s and not s.startswith('{')]
    if not names:
        return ''
    name = names[-1].replace('-', '').replace('_', '')
    return name[:-3] + 'y' if name.endswith('ies') else name[:-1] if name.endswith('s') else name


def _detail_score(create: Any, detail: Any) -> int:
    """Score unrelated and nested CRUD routes without assuming same URL prefix."""
    if detail.method != 'GET' or not PATH_VAR.search(detail.path):
        return -1
    segments = [x for x in detail.path.split('/') if x]
    if not segments or not re.fullmatch(r'\{[^{}]+\}', segments[-1]):
        return -1
    coll = create.path.rstrip('/')
    score = 0
    if detail.path.startswith(coll + '/{'):
        score += 90
    if _resource_name(coll) == _resource_name(detail.path.rsplit('/', 1)[0]):
        score += 65
    op = (create.operation_id or '').lower() + ' ' + (detail.operation_id or '').lower()
    if _resource_name(coll) and _resource_name(coll) in op:
        score += 10
    return score if score >= 60 else -1


def _parent_guidance(parsed: Any, spec: dict[str, Any], variable: str) -> dict[str, Any]:
    """Explain why an OpenAPI path argument has no actual runtime value.

    Candidate GET producers are HINTS only. A contract cannot prove the IDs
    existing in the database or their ownership, even with enum/example values.
    """
    sources = []
    for ep in parsed.endpoints:
        if ep.method != 'GET' or PATH_VAR.search(ep.path):
            continue
        from achillesapi.core.workflows import get_read_side_effect_risk
        if get_read_side_effect_risk(ep):
            continue
        paths = _response_field_pointers(spec, ep, variable)
        collection_match = False
        if not paths:
            # A collection GET may list existing parent objects even when the
            # response schema is omitted. Purely structural suggestion.
            stem = re.sub(r'(?:_?(?:id|uuid|key|ref|identifier))$', '', variable, flags=re.I).lower()
            segment = ep.path.rstrip('/').split('/')[-1].lower().replace('-','').replace('_','')
            stem = stem.replace('-','').replace('_','')
            collection_match = bool(stem and segment in {stem, stem+'s', stem+'es', stem[:-1]+'ies' if stem.endswith('y') else ''})
        if not paths:
            # A resource-context endpoint may return the current user's tenant,
            # org, account or project even if no response schema was specified.
            # Do not claim that any actual field is present.
            if not collection_match and not re.search(r'(?:/me|/whoami|/profile|/session|/context|/identity|/self)$', ep.path, re.I):
                continue
        sources.append({
            'operation': 'GET ' + ep.path,
            'pointer_suggestion': paths[0] if paths else ('/items/0/id' if collection_match else '/' + variable.replace('~','~0').replace('/','~1')),
            'evidence': 'response_schema' if paths else ('collection_route_heuristic' if collection_match else 'identity_route_heuristic'),
            'verified': False,
        })
    return {
        'parameter': variable,
        'reason': 'OpenAPI definisce il segnaposto {' + variable + '} e il suo tipo, non i valori realmente presenti sul server né la proprietà della risorsa.',
        'how_to_resolve': [
            'Usa una risorsa parent già esistente, autorizzata per il profilo selezionato.',
            'Verifica se un endpoint GET di identità, elenco o dettaglio restituisce il valore. I suggerimenti non sono garanzie.',
            'Se non esistono endpoint leggibili, chiedi al proprietario API un ID di test oppure configura prima la creazione del parent con cleanup.',
            'Conferma che il valore sia coerente con la stessa identità e lo stesso ambiente dell’operazione POST.',
        ],
        'read_sources': sources[:12],
        'value_known_from_spec': False,
    }


def discover_manifest_candidates(spec_path: str) -> list[dict[str, Any]]:
    """Enumerate ALL POST operations, including nested ones, with safe lifecycle status.

    Missing read/delete/schema/marker are reported and visible, never silently
    dropped. Only complete candidates may be rendered into executable fixtures.
    """
    spec = load_openapi(spec_path)
    parsed = parse_openapi(spec)
    methods = {(ep.method, ep.path): ep for ep in parsed.endpoints}
    results = []
    for endpoint in parsed.endpoints:
        if endpoint.method != 'POST':
            continue
        schema = _object_schema(spec, _request_schema(spec, endpoint))
        fields = _fields(spec, schema)
        markers = [name for name, prop in fields.items()
                   if MARKER.fullmatch(name) and prop.get('type') == 'string'
                   and (prop.get('maxLength') is None or prop['maxLength'] >= 32)]
        if not markers:
            markers = [name for name, prop in fields.items() if prop.get('type') == 'string'
                       and not SENSITIVE.search(name) and (prop.get('maxLength') is None or prop['maxLength'] >= 32)][:5]
        required = [x for x in schema.get('required', []) if isinstance(x, str) and x in fields]
        matched = sorted((( _detail_score(endpoint, ep), ep) for ep in parsed.endpoints if ep.method == 'GET'),
                         key=lambda pair: pair[0], reverse=True)
        reader = matched[0][1] if matched and matched[0][0] >= 0 else None
        from achillesapi.core.workflows import get_read_side_effect_risk
        read_risk = get_read_side_effect_risk(reader) if reader else None
        read = f'GET {reader.path}' if reader else None
        deleter = methods.get(('DELETE', reader.path)) if reader else None
        delete = f'DELETE {reader.path}' if deleter else None
        mutator_endpoint = next((methods[(method, reader.path)] for method in ('PATCH', 'PUT')
                                 if reader and (method, reader.path) in methods), None)
        mutator = f'{mutator_endpoint.method} {mutator_endpoint.path}' if mutator_endpoint else None
        mutation_schema = _object_schema(spec, _request_schema(spec, mutator_endpoint)) if mutator_endpoint else {}
        mutation_fields = _fields(spec, mutation_schema)
        mutation_required = [name for name in mutation_schema.get('required', [])
                             if isinstance(name, str) and name in mutation_fields]
        def _mutation_spec(value):
            return {'type':value.get('type', 'string'),
                    'enum':value.get('enum', [])[:15] if isinstance(value.get('enum'), list) else [],
                    'description':str(value.get('description',''))[:160],
                    'readOnly':bool(value.get('readOnly'))}

        # Show only declared actions anchored to the freshly-created object's
        # path; no existing resource or arbitrary operation is eligible.
        write_actions = [f'{ep.method} {ep.path}' for ep in parsed.endpoints
                         if reader and ep.method in {'POST', 'PATCH'}
                         and ep.path.startswith(reader.path + '/')
                         and set(re.findall(r'\{([^{}]+)\}', ep.path)) <=
                             set(re.findall(r'\{([^{}]+)\}', reader.path))][:12]
        path_param = re.findall(r'\{([^{}]+)\}', reader.path)[-1] if reader else None
        parent_params = re.findall(r'\{([^{}]+)\}', endpoint.path)
        id_pointers = _response_id_candidates(spec, endpoint)
        read_id_pointers = _response_id_candidates(spec, reader) if reader else []
        read_marker_paths = {marker:_response_field_pointers(spec,reader,marker) for marker in markers}
        # OpenAPI response schemas are often undocumented. A path placeholder
        # is an ID *hint*, not proof of a response JSON field.
        hints = []
        if path_param:
            hints = [path_param, 'id', _resource_name(endpoint.path) + 'Id']
        ids = list(dict.fromkeys([v[1:] if v.count('/') == 1 else v for v in id_pointers] + hints))
        status = 'ready_for_fixture_review'
        missing = []
        if not reader: missing.append('GET per ID non trovato')
        if not deleter: missing.append('DELETE per ID non trovato')
        if not markers: missing.append('Campo marker testuale scrivibile non rilevato')
        if not fields: missing.append('Body JSON con campi dichiarati non trovato')
        if parent_params: missing.append('Parametri del path POST da compilare: ' + ', '.join(parent_params))
        if missing: status = 'requires_configuration'
        results.append({
            'create': f'POST {endpoint.path}', 'read': read, 'delete': delete,
            'mutation': mutator,
            'mutation_field_specs': {name:_mutation_spec(value) for name,value in mutation_fields.items()},
            'mutation_required': mutation_required,
            'mutation_field_count': len(mutation_fields),
            'write_action_candidates': write_actions, 'path_parameter': path_param,
            'read_get_risk': read_risk,
            'required_path_params': parent_params,
            'parent_guidance': [_parent_guidance(parsed, spec, variable) for variable in parent_params],
            'status': status, 'needs': missing,
            'ready': bool(reader and deleter and markers and fields),
            'marker_candidates': markers, 'id_candidates': ids,
            'id_schema_pointers': id_pointers, 'read_id_candidates': read_id_pointers,
            'read_marker_pointers': read_marker_paths,
            'id_inferred_from': 'response_schema' if id_pointers else 'path_parameter_heuristic',
            'required': required, 'fields': list(fields),
            'field_specs': {key: {'type':value.get('type','string'),
                                'enum':value.get('enum', [])[:15] if isinstance(value.get('enum'), list) else [],
                                'description':str(value.get('description',''))[:160],
                                'minLength':value.get('minLength'), 'maxLength':value.get('maxLength'),
                                'minimum':value.get('minimum')}
                           for key, value in fields.items()},
            'body_example': {name: ('temporary-resource' if markers and name == markers[0]
                                    else _sample_field(fields[name]))
                             for name in dict.fromkeys(required + markers[:1]) if name in fields},
            'warnings': ['Conferma il JSON Pointer dell’ID POST e GET: un suggerimento dal path non è una prova.',
                         'Le scritture richiedono dati temporanei, autorizzazione e cleanup verificabile.'] + missing,
        })
    return results[:200]


def discover_write_operations(spec_path: str) -> list[dict[str, Any]]:
    """Unfiltered POST/PATCH/PUT/DELETE inventory for dashboard selection."""
    parsed = parse_openapi(load_openapi(spec_path))
    candidates = discover_manifest_candidates(spec_path)
    used = {part for c in candidates for part in (c['create'], c['read'], c['delete'], c['mutation']) if part}
    return [{'operation': f'{ep.method} {ep.path}', 'method': ep.method,
             'lifecycle_mapped': f'{ep.method} {ep.path}' in used}
            for ep in parsed.endpoints if ep.method in ('POST','PATCH','PUT','DELETE')]

def build_manifest_draft(candidate: dict[str,Any], profile: str='owner',
                         other_profile: str|None=None, marker: str|None=None,
                         identifier: str|None=None)->str:
    """Create an editable YAML proposal with explicit, non-executable TODO fields."""
    if not candidate.get('marker_candidates'):
        raise ValueError('Nessun campo marker utilizzabile nello schema.')
    marker=marker or candidate['marker_candidates'][0]
    if marker not in candidate['marker_candidates']:
        raise ValueError('Seleziona un marker proposto dalla specifica.')
    id_field=identifier or (candidate['id_schema_pointers'][0].lstrip('/') if len(candidate['id_schema_pointers']) == 1 else 'REVIEW_ID_FIELD')
    if identifier and (not isinstance(identifier, str) or not re.fullmatch(r'/?[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z_][A-Za-z0-9_]*){0,4}', identifier)):
        raise ValueError('Indica un campo ID o JSON Pointer valido.')
    if not candidate['ready']:
        raise ValueError('Workflow incompleto: ' + ', '.join(candidate['needs']))
    param=candidate['path_parameter']
    resource={
        'name':'resource', 'create':candidate['create'],'read':candidate['read'],
        'delete':candidate['delete'],'identity':profile,
        'body':dict(candidate['body_example']),
        'marker_field':marker,'marker_pointer':((candidate.get('read_marker_pointers',{}).get(marker) or ['/'+marker])[0]),
        'id_pointer':'/'+id_field.lstrip('/'),'read_id_pointer':(candidate.get('read_id_candidates') or ['/'+id_field.lstrip('/')])[0],
        'path_values':{**{key:'REVIEW_PARENT_ID' for key in candidate.get('required_path_params', [])}, param:'${resource.id}'},
        'access':([{'identity':other_profile,'expected':'deny'}] if other_profile and other_profile!=profile else [])
    }
    return '# BOZZA NON APPROVATA: verifica payload, marker, ID, ownership e cleanup.\n' + yaml.safe_dump({'resources':[resource]},sort_keys=False,allow_unicode=True)


def build_guided_manifest(candidate: dict[str, Any], *, owner: str, other: str | None,
                          marker: str, identifier: str, body: dict[str, Any],
                          deny_other: bool, path_values: dict[str, str] | None = None,
                          mutation_body: dict[str, Any] | None = None,
                          mutation_expected_deny: bool = False,
                          write_action: str | None = None, write_identity: str | None = None,
                          acknowledge_get_side_effect_risk: bool = False) -> str:
    """Produce a complete fixture from explicit browser form fields, not placeholders.

    OpenAPI can tell us field types, but not the real business rules or resource
    ownership. The operator supplies these values. No network traffic occurs.
    """
    if not candidate['ready']:
        raise ValueError('Non posso eseguire un ciclo senza GET/DELETE e marker: ' + ', '.join(candidate['needs']))
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', owner):
        raise ValueError('Scegli il profilo dell’utente che crea la risorsa.')
    if other and not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', other):
        raise ValueError('Seleziona un secondo profilo valido.')
    if marker not in candidate['marker_candidates']:
        raise ValueError('Scegli un campo testuale proposto per riconoscere la risorsa temporanea.')
    if not isinstance(identifier, str) or not re.fullmatch(r'/?[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z_][A-Za-z0-9_]*){0,4}', identifier):
        raise ValueError('Indica il campo ID o JSON Pointer della risposta POST, ad esempio /data/id.')
    if not isinstance(body,dict) or set(body)-set(candidate['fields']):
        raise ValueError('I campi del payload devono essere dichiarati nello Swagger.')
    if any(field not in body for field in candidate['required']):
        missing=[field for field in candidate['required'] if field not in body]
        raise ValueError('Compila i campi obbligatori della creazione: '+', '.join(missing))
    if marker not in body or not isinstance(body[marker],str) or not body[marker].strip():
        raise ValueError('Inserisci un testo nel campo che identifica la risorsa temporanea.')
    if len(str(body))>8192:
        raise ValueError('Dati di creazione troppo lunghi: massimo 8 KB.')
    if 'REVIEW_' in str(body) or 'TODO_' in str(body):
        raise ValueError('Rimuovi i testi provvisori dai dati di creazione.')
    schema=candidate['field_specs']
    for key,value in body.items():
        kind=schema[key]['type']
        good={'string':isinstance(value,str),'integer':type(value) is int,
              'number':type(value) in (int,float),'boolean':type(value) is bool,
              'object':isinstance(value,dict),'array':isinstance(value,list)}.get(kind, True)
        if not good:raise ValueError(f'Il campo «{key}» deve essere di tipo {kind}.')
        enum=schema[key].get('enum') or []
        if enum and value not in enum:raise ValueError(f'Il campo «{key}» deve essere uno dei valori ammessi dallo Swagger.')
        if kind=='string':
            lo=schema[key].get('minLength');hi=schema[key].get('maxLength')
            if isinstance(lo,int) and len(value)<lo:raise ValueError(f'«{key}» deve avere almeno {lo} caratteri.')
            if isinstance(hi,int) and len(value)>hi:raise ValueError(f'«{key}» può avere al massimo {hi} caratteri.')
    values = path_values or {}
    if not isinstance(values, dict) or set(values) != set(candidate.get('required_path_params', [])):
        raise ValueError('Compila tutti e soli i parametri path della POST: ' + ', '.join(candidate.get('required_path_params', [])))
    if any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9_.:~-]{1,128}', v) for v in values.values()):
        raise ValueError('Gli ID parent devono essere segmenti path sicuri e già autorizzati.')
    if type(acknowledge_get_side_effect_risk) is not bool:
        raise ValueError('La conferma GET deve essere booleana.')
    if candidate.get('read_get_risk') and not acknowledge_get_side_effect_risk:
        raise ValueError('La GET scelta è ambigua: verifica se modifica lo stato e confermala separatamente.')
    item={'name':'resource','create':candidate['create'],'read':candidate['read'],
          'delete':candidate['delete'],'identity':owner,'body':body,
          'marker_field':marker,'marker_pointer':((candidate.get('read_marker_pointers',{}).get(marker) or ['/'+marker])[0]),
          'id_pointer':'/'+identifier.lstrip('/'),'read_id_pointer':(candidate.get('read_id_candidates') or ['/'+identifier.lstrip('/')])[0],
          'path_values':{**values, candidate['path_parameter']:'${resource.id}'},
          'access':([{'identity':other,'expected':'deny'}] if deny_other and other and other!=owner else [])}
    if acknowledge_get_side_effect_risk and candidate.get('read_get_risk'):
        item['acknowledge_get_side_effect_risk'] = True
    if mutation_body:
        if not candidate.get('mutation'):
            raise ValueError('La risorsa selezionata non ha PATCH/PUT compatibile con la GET.')
        if not isinstance(mutation_body, dict) or len(str(mutation_body)) > 4096:
            raise ValueError('La modifica deve essere un oggetto JSON di test di massimo 4 KB.')
        if 'REVIEW_' in str(mutation_body) or 'TODO_' in str(mutation_body):
            raise ValueError('Sostituisci i segnaposto del PATCH con valori di test esplicitamente approvati.')
        if marker in mutation_body or 'id' in mutation_body:
            # The mutation body is separately validated below against PATCH/PUT schema by the core preflight.
            raise ValueError('La modifica non può alterare ID/marker e richiede campi autorizzati.')
        mutation = {'operation':candidate['mutation'], 'body':mutation_body}
        if mutation_expected_deny:
            # Only leaf fields supplied by the operator become verification
            # pointers. The runtime compares baseline and post-PATCH GET.
            def pointers(obj, path='', depth=0):
                if depth > 4:
                    raise ValueError('La verifica dei campi supporta fino a quattro livelli JSON.')
                for key, value in obj.items():
                    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', key):
                        raise ValueError('Nomi campo non compatibili con la verifica policy.')
                    pointer = path + '/' + key
                    if isinstance(value, dict):
                        yield from pointers(value, pointer, depth + 1)
                    elif type(value) in (str, int, float, bool):
                        yield pointer
                    else:
                        raise ValueError('Per il controllo policy usa campi JSON scalari.')
            selected = list(pointers(mutation_body))
            if not selected or len(selected) > 6:
                raise ValueError('Puoi verificare massimo sei campi PATCH scalari per workflow.')
            mutation['expected_policy'] = 'deny'
            mutation['verify_fields'] = selected
        item['mutations'] = [mutation]
    elif mutation_expected_deny:
        raise ValueError('Seleziona una PATCH e i campi da verificare.')
    if write_action:
        if write_action not in candidate.get('write_action_candidates', ()):
            raise ValueError('Operazione BFLA non prevista per questa risorsa nello Swagger.')
        if not write_identity or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', write_identity):
            raise ValueError('Seleziona il profilo con cui provare il permesso di scrittura.')
        item['write_checks'] = [{'operation': write_action, 'identity': write_identity,
                                 'expected': 'deny'}]
    return yaml.safe_dump({'resources':[item]},sort_keys=False,allow_unicode=True)
