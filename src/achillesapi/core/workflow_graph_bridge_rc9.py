"""Convert approved disposable-workflow definitions into a read-only DAG document.

No payload, identity, token or HTTP request is involved. The generated graph is
submitted to the *existing* strict DAG validator against the imported OpenAPI.
"""
from __future__ import annotations
import re
from typing import Any

_REF = re.compile(r'\$\{([A-Za-z][A-Za-z0-9_-]{0,40})\.id\}')
_NAME = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{0,32}$')
_METHODS = {'create':'POST', 'read':'GET', 'modify':'PATCH', 'cleanup':'DELETE'}


def derive_disposable_graph(manifest: dict[str, Any]) -> dict[str, Any]:
    """Derive dependencies from `${resource.id}` references, not endpoint names."""
    if not isinstance(manifest, dict):
        raise ValueError('Il manifest workflow deve essere un oggetto YAML/JSON.')
    if set(manifest) == {'steps'}:
        return manifest
    if isinstance(manifest.get('resources'), list):
        rows = manifest['resources']
        origin = 'resources'
    elif isinstance(manifest.get('workflows'), list):
        rows = manifest['workflows']
        origin = 'workflows'
    else:
        raise ValueError('Serve un manifest con steps, resources o workflows.')
    if not 1 <= len(rows) <= 10:
        raise ValueError('Per la conversione sono supportati da 1 a 10 workflow.')
    definitions = {}
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError('Ogni workflow deve essere un oggetto.')
        name = row.get('name') or f'resource_{i}'
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in definitions:
            raise ValueError('Ogni workflow deve avere un nome univoco valido (1-33 caratteri).')
        definitions[name] = row

    # Resolve exact expressions that refer to another temporary resource.
    def references(obj: Any) -> set[str]:
        if isinstance(obj, str):
            return set(_REF.findall(obj))
        if isinstance(obj, dict):
            found=set()
            for child in obj.values(): found.update(references(child))
            return found
        if isinstance(obj, list):
            found=set()
            for child in obj: found.update(references(child))
            return found
        return set()

    dep_map={}
    for name, row in definitions.items():
        deps=references({key:value for key,value in row.items() if key not in {'name','read','cleanup','delete','mutations','access'}})
        # A resource's own `${name.id}` is normally used by its read/delete,
        # not as a prerequisite for its initial POST.
        deps.discard(name)
        if deps-set(definitions):
            raise ValueError('Riferimento parent non valido nel workflow ' + name)
        dep_map[name]=deps

    steps=[]
    child_last={}
    for name,row in definitions.items():
        create=row.get('create')
        read=row.get('read')
        cleanup=row.get('delete') if origin=='resources' else row.get('cleanup')
        identity=row.get('identity') if origin=='resources' else (create or {}).get('identity')
        def operation(raw: Any, method: str) -> str:
            value = raw.get('operation') if isinstance(raw,dict) else raw
            if not isinstance(value,str) or not value.startswith(method+' '):
                raise ValueError(name+': manca operazione '+method+' valida.')
            return value
        create_op=operation(create,'POST')
        read_op=operation(read,'GET')
        delete_op=operation(cleanup,'DELETE')
        create_id=name+'_create';read_id=name+'_read';delete_id=name+'_cleanup'
        deps=sorted(dep+'_create' for dep in dep_map[name])
        steps.append({'id':create_id, 'kind':'create', 'operation':create_op,
                      'cleanup_step':delete_id, 'depends_on':deps, 'identity':identity})
        steps.append({'id':read_id, 'kind':'read', 'operation':read_op,
                      'depends_on':[create_id], 'identity':identity})
        last=read_id
        for idx, mutation in enumerate(row.get('mutations') or []):
            raw=mutation.get('operation') if isinstance(mutation,dict) else None
            if not isinstance(raw,str) or raw.split(' ',1)[0] not in {'PATCH','PUT'}:
                raise ValueError(name+': modifica PATCH/PUT non valida')
            step_id=name+'_modify_'+str(idx+1)
            steps.append({'id':step_id,'kind':'modify','operation':raw,
                          'depends_on':[last], 'identity':identity})
            last=step_id
        child_last[name]=(delete_id,last,create_id)
        steps.append({'id':delete_id,'kind':'cleanup','operation':delete_op,
                      'depends_on':[create_id,last], 'identity':identity})
    for name in definitions:
        # Parent cleanup must happen after cleanup of every dependent child.
        parent_cleanup=child_last[name][0]
        item=next(x for x in steps if x['id']==parent_cleanup)
        item['depends_on'].extend(child_last[child][0] for child in definitions if name in dep_map[child])
        item['depends_on']=list(dict.fromkeys(item['depends_on']))
    if len(steps)>30:
        raise ValueError('Il DAG contiene più di 30 step, limite del validatore.')
    return {'steps':steps}
