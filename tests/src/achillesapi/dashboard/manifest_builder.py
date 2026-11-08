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
IDENTIFIER = re.compile(r'(?:^id$|_id$|Id$|ID$|uuid|ref$)', re.I)
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


def discover_manifest_candidates(spec_path: str) -> list[dict[str, Any]]:
    """Find POST/create, GET/detail, DELETE/detail trios in any OpenAPI 3.x file.

    This is an offline heuristic; it does not assume that every named resource is
    safe or disposable. Only the operator may approve a concrete write fixture.
    """
    spec=load_openapi(spec_path)
    parsed=parse_openapi(spec)
    methods={(ep.method,ep.path): ep for ep in parsed.endpoints}
    result=[]
    for endpoint in parsed.endpoints:
        if endpoint.method!='POST' or PATH_VAR.search(endpoint.path):
            # Nested resources are possible but may require IDs from a parent;
            # the operator can start with a root resource then extend the YAML.
            continue
        collection=endpoint.path.rstrip('/')
        for (method,detail), reader in methods.items():
            if method!='GET' or not detail.startswith(collection+'/'):
                continue
            suffix=detail[len(collection):]
            if not re.fullmatch(r'/\{[^{}]+\}',suffix):
                continue
            if ('DELETE',detail) not in methods:continue
            schema=_request_schema(spec,endpoint)
            fields=_fields(spec,schema)
            markers=[name for name,prop in fields.items() if MARKER.search(name)
                     and prop.get('type')=='string' and prop.get('maxLength',100)>=32]
            required=[x for x in schema.get('required',[]) if isinstance(x,str)]
            response_fields=[]
            for status,content in endpoint.responses.items():
                if not str(status).startswith('2') or not isinstance(content,dict): continue
                response_fields=list(_fields(spec, _response_schema(spec,content)))
                if response_fields: break
            ids=[x for x in response_fields if IDENTIFIER.search(x)]
            if not markers:continue
            result.append({'create':f'POST {endpoint.path}', 'read':f'GET {detail}',
                           'delete':f'DELETE {detail}', 'path_parameter':PATH_VAR.search(suffix).group(1),
                           'marker_candidates':markers,'id_candidates':ids,
                           'required':required,'fields':list(fields),
                           'field_specs':{key:{'type':value.get('type','string'),'enum':value.get('enum',[])[:15] if isinstance(value.get('enum'),list) else [],'description':str(value.get('description',''))[:160], 'minLength':value.get('minLength'), 'maxLength':value.get('maxLength'), 'minimum':value.get('minimum')} for key,value in fields.items()},
                           'body_example':{name: ('temporary-resource' if name==markers[0]
                                               else _sample_field(fields[name]))
                                           for name in dict.fromkeys(required+[markers[0]]) if name in fields},
                           'warnings': ['Verifica che il server restituisca id e marker nella GET.',
                                        'Conferma che DELETE elimini soltanto risorse di test.',
                                        'I valori del payload sono esempi, non dati validati.']})
            break
    return result[:20]


def _response_schema(spec:dict[str,Any], response:dict[str,Any])->dict[str,Any]:
    """Return a JSON schema from a response, supporting local $ref."""
    response=_resolve_schema(spec,response)
    for name,record in response.get('content',{}).items():
        if 'json' in name and isinstance(record,dict):
            return _resolve_schema(spec,record.get('schema',{}))
    return {}


def build_manifest_draft(candidate: dict[str,Any], profile: str='owner',
                         other_profile: str|None=None, marker: str|None=None,
                         identifier: str|None=None)->str:
    """Create an editable YAML proposal with explicit, non-executable TODO fields."""
    if not candidate.get('marker_candidates'):
        raise ValueError('Nessun campo marker utilizzabile nello schema.')
    marker=marker or candidate['marker_candidates'][0]
    if marker not in candidate['marker_candidates']:
        raise ValueError('Seleziona un marker proposto dalla specifica.')
    id_field=identifier or (candidate['id_candidates'][0] if candidate['id_candidates'] else 'REVIEW_ID_FIELD')
    if identifier and identifier not in candidate['id_candidates']:
        raise ValueError('Il campo ID indicato non compare fra quelli osservati in OpenAPI.')
    param=candidate['path_parameter']
    resource={
        'name':'resource', 'create':candidate['create'],'read':candidate['read'],
        'delete':candidate['delete'],'identity':profile,
        'body':dict(candidate['body_example']),
        'marker_field':marker,'marker_pointer':'/'+marker,
        'id_pointer':'/'+id_field,'read_id_pointer':'/'+id_field,
        'path_values':{param:'${resource.id}'},
        'access':([{'identity':other_profile,'expected':'deny'}] if other_profile and other_profile!=profile else [])
    }
    return '# BOZZA NON APPROVATA: verifica payload, marker, ID, ownership e cleanup.\n' + yaml.safe_dump({'resources':[resource]},sort_keys=False,allow_unicode=True)


def build_guided_manifest(candidate: dict[str, Any], *, owner: str, other: str | None,
                          marker: str, identifier: str, body: dict[str, Any],
                          deny_other: bool) -> str:
    """Produce a complete fixture from explicit browser form fields, not placeholders.

    OpenAPI can tell us field types, but not the real business rules or resource
    ownership. The operator supplies these values. No network traffic occurs.
    """
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', owner):
        raise ValueError('Scegli il profilo dell’utente che crea la risorsa.')
    if other and not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', other):
        raise ValueError('Seleziona un secondo profilo valido.')
    if marker not in candidate['marker_candidates']:
        raise ValueError('Scegli un campo testuale proposto per riconoscere la risorsa temporanea.')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', identifier):
        raise ValueError('Indica il nome del campo ID della risposta POST, ad esempio id. Non inserire / o JSON.')
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
    item={'name':'resource','create':candidate['create'],'read':candidate['read'],
          'delete':candidate['delete'],'identity':owner,'body':body,
          'marker_field':marker,'marker_pointer':'/'+marker,
          'id_pointer':'/'+identifier,'read_id_pointer':'/'+identifier,
          'path_values':{candidate['path_parameter']:'${resource.id}'},
          'access':([{'identity':other,'expected':'deny'}] if deny_other and other and other!=owner else [])}
    return yaml.safe_dump({'resources':[item]},sort_keys=False,allow_unicode=True)
