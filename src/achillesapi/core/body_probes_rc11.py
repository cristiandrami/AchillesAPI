"""RC11: sonde JSON limitate a campi PATCH già approvati nel manifest.

Per ogni sonda crea una propria fixture, verifica ID/marker, legge e tenta
cleanup con il motore workflow preesistente. Non testa body arbitrari.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from achillesapi.core.workflows import workflow_plan, run_workflows

# Input brevi che non alterano in modo intenzionale strutture o comandi di sistema.
BODY_PROBES = ("'", '{{7*7}}')


def body_probe_plan(parsed: Any, spec: dict[str, Any], workflows: list[dict[str, Any]],
                    profile_names: set[str], *, max_cases: int = 4) -> dict[str, Any]:
    """Nessuna generazione senza un campo di mutazione nominato dall'operatore."""
    if not 1 <= max_cases <= 10:
        raise ValueError('Numero massimo di prove JSON: 1-10')
    cases: list[dict[str, Any]] = []
    for index, wf in enumerate(workflows):
        mutations = wf.get('mutations', [wf['mutation']] if 'mutation' in wf else [])
        if not mutations:
            continue
        for field, value in mutations[0].get('body', {}).items():
            if field in mutations[0].get('restricted_fields', ()) and isinstance(value, str) and len(value) <= 128:
                for payload in BODY_PROBES:
                    if len(cases) < max_cases:
                        cases.append({'workflow_index': index, 'name': wf['name'],
                                      'field': field, 'payload': payload})
    # Ricalcola budget con il motore che effettivamente eseguirà i test.
    per_case = []
    for case in cases:
        draft = deepcopy(workflows[case['workflow_index']])
        mutation = draft.get('mutations', [draft['mutation']] if 'mutation' in draft else [])[0]
        mutation['body'][case['field']] = case['payload']
        per_case.append(workflow_plan(parsed, spec, [draft], profile_names)['request_budget_required'])
    return {'engine': 'approved-json-body-probes-rc11', 'cases': cases,
            'request_budget_required': sum(per_case),
            'conditions': ['Solo campi stringa già indicati come restricted_fields nel manifest.',
                           'Una fixture distinta per payload, con verifica e cleanup.',
                           'Confronti di stato non confermano automaticamente injection.']}


def run_body_probes(parsed: Any, spec: dict[str, Any], workflows: list[dict[str, Any]], *,
                    identities: dict[str, Any], base_url: str, allowed_hosts: set[str],
                    execute: bool, approve_writes: bool, approve_body_probes: bool,
                    allow_insecure_http: bool, max_requests: int, rate: float = 1.) -> dict[str, Any]:
    plan = body_probe_plan(parsed, spec, workflows, set(identities))
    if not execute:
        return {**plan, 'executed': False, 'requests_sent': 0, 'results': [], 'findings': []}
    if not approve_writes or not approve_body_probes:
        raise ValueError('Sono richieste approvazioni separate per scritture e sonde JSON.')
    if max_requests < plan['request_budget_required']:
        raise ValueError('Budget insufficiente per creare e ripulire tutte le fixture di prova.')
    reports = []
    total = 0
    for case in plan['cases']:
        draft = deepcopy(workflows[case['workflow_index']])
        mutation = draft.get('mutations', [draft['mutation']] if 'mutation' in draft else [])[0]
        mutation['body'][case['field']] = case['payload']
        budget = workflow_plan(parsed, spec, [draft], set(identities))['request_budget_required']
        outcome = run_workflows(parsed, spec, [draft], base_url=base_url,
            allowed_hosts=allowed_hosts, identities=identities, execute=True,
            approve_writes=True, allow_insecure_http=allow_insecure_http,
            max_requests=budget, rate=rate)
        total += outcome['requests_sent']
        flow = outcome['workflows'][0]
        reports.append({'workflow': case['name'], 'field': case['field'],
                        'payload': case['payload'],
                        'created': flow.get('created'),
                        'cleanup_verified': flow.get('cleanup_verified'),
                        'manual_cleanup_required': flow.get('manual_cleanup_required'),
                        'response_evidence': flow.get('observations', []),
                        'errors': flow.get('errors', [])})
        if flow.get('manual_cleanup_required'):
            # Una fixture non ripulita è un errore operativo: fermare tutte le sonde.
            break
    return {**plan, 'executed': True, 'requests_sent': total, 'results': reports,
            'findings': [],
            'manual_cleanup_required': any(r['manual_cleanup_required'] for r in reports),
            'limitations': ['Risultati di input validation, non prova di SQLi/SSTI.',
                            'Il payload è presentato solo perché è un valore fisso privo di segreti.']}


_SECRET_FIELD = re.compile(r"password|passwd|secret|token|api.?key|credential|session|otp|pin|authorization", re.I)
_UNSAFE_AUTO_FIELD = re.compile(
    r"(?:password|passwd|secret|token|api.?key|credential|session|otp|pin|"
    r"authorization|role|permission|privilege|admin|owner|tenant|account|"
    r"approved|reimbursed|status|state|balance|price|amount|payment|"
    r"(?:^|[_-])(?:id|uid|uuid|guid)(?:$|[_-]))", re.I,
)


def _patch_properties(spec: dict[str, Any], schema: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Resolve local references and shallow object allOf without fetching remote schemas."""
    from achillesapi.core.testgen import _resolve_schema
    if depth > 6:
        return {}
    obj = _resolve_schema(spec, schema)
    props = dict(obj.get('properties', {})) if isinstance(obj.get('properties'), dict) else {}
    for branch in obj.get('allOf', []) if isinstance(obj.get('allOf'), list) else []:
        if isinstance(branch, dict):
            props.update(_patch_properties(spec, branch, depth + 1))
    return props


def _writable_string(spec: dict[str, Any], schema: dict[str, Any]) -> bool:
    """Accept OpenAPI 3.0 nullable strings and OpenAPI 3.1 string|null unions."""
    from achillesapi.core.testgen import _resolve_schema
    prop = _resolve_schema(spec, schema)
    if prop.get('readOnly') or prop.get('writeOnly') or prop.get('deprecated'):
        return False
    branches = prop.get('anyOf', prop.get('oneOf'))
    if isinstance(branches, list):
        candidates = [_resolve_schema(spec, b) for b in branches if isinstance(b, dict)]
        non_null = [b for b in candidates if b.get('type') != 'null']
        if len(non_null) != 1 or len(non_null) != len(candidates) - 1:
            return False  # only a strict union of one string and null is unambiguous
        prop = {**non_null[0], **{k: v for k, v in prop.items() if k not in ('anyOf', 'oneOf')}}
    typ = prop.get('type')
    if isinstance(typ, list):
        if set(typ) != {'string', 'null'}:
            return False
    elif typ != 'string':
        return False
    # Reject fields whose contract makes either of the bounded probes invalid.
    if prop.get('enum') is not None or prop.get('const') is not None or prop.get('pattern') or prop.get('format'):
        return False
    if isinstance(prop.get('minLength'), int) and prop['minLength'] > min(map(len, BODY_PROBES)):
        return False
    if isinstance(prop.get('maxLength'), int) and prop['maxLength'] < max(map(len, BODY_PROBES)):
        return False
    return True


def _string_leaf_paths(spec: dict[str, Any], properties: dict[str, Any], *,
                       prefix: str = '', depth: int = 0) -> list[tuple[str, dict[str, Any]]]:
    """Expose only explicitly typed, bounded nested object leaves (no arrays)."""
    from achillesapi.core.testgen import _resolve_schema
    if depth > 3:
        return []
    found: list[tuple[str, dict[str, Any]]] = []
    for field, raw in properties.items():
        if (not isinstance(field, str) or not isinstance(raw, dict) or
                not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,40}', field)):
            continue
        path = f'{prefix}.{field}' if prefix else field
        schema = _resolve_schema(spec, raw)
        if schema.get('readOnly') or schema.get('writeOnly'):
            continue
        if _writable_string(spec, raw):
            found.append((path, raw))
        elif schema.get('type') == 'object' and isinstance(schema.get('properties'), dict):
            found.extend(_string_leaf_paths(spec, schema['properties'], prefix=path, depth=depth+1))
    return found


def _set_nested(body: dict[str, Any], dotted: str, value: str) -> None:
    obj = body
    keys = dotted.split('.')
    for key in keys[:-1]:
        current = obj.setdefault(key, {})
        if not isinstance(current, dict):
            raise ValueError('Campo PATCH annidato non è un oggetto')
        obj = current
    obj[keys[-1]] = value

def resource_probe_options(parsed: Any, spec: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Discover bounded PATCH inputs from *both* approved mutations and OpenAPI.

    A workflow without a mutation is a valid candidate: selecting one of its
    schema fields explicitly authorizes a dedicated PATCH on a disposable
    fixture. Merely discovering candidates NEVER performs a write.
    """
    from achillesapi.core.workflows import _operation, _request_schema
    options: list[dict[str, Any]] = []
    for item in manifest.get('resources', []):
        if not isinstance(item, dict):
            continue
        marker = item.get('marker_field')
        read = item.get('read', '')
        if not isinstance(read, str) or not read.startswith('GET '):
            continue
        patch_operation = 'PATCH ' + read[4:]
        try:
            patch = _operation(parsed, patch_operation, {'PATCH'})
        except ValueError:
            continue
        properties = _patch_properties(spec, _request_schema(spec, patch))
        raw_patch = spec.get('paths', {}).get(patch.path, {}).get('patch', {})
        from achillesapi.core.testgen import _resolve_schema
        body_definition = _resolve_schema(spec, raw_patch.get('requestBody', {}))
        media = body_definition.get('content', {}) if isinstance(body_definition, dict) else {}
        if not isinstance(media, dict):
            media = {}
        form_schema = _resolve_schema(spec, media.get('application/x-www-form-urlencoded', {}).get('schema', {}))
        xml_schema = _resolve_schema(spec, media.get('application/xml', {}).get('schema', {}))
        if not properties and not form_schema and not xml_schema:
            continue
        mutations = item.get('mutations', [])
        if not isinstance(mutations, list):
            continue
        explicitly_configured: set[str] = set()
        for i, mutation in enumerate(mutations):
            if not isinstance(mutation, dict) or mutation.get('operation') != patch_operation:
                continue
            for field, original in mutation.get('body', {}).items():
                if (field == marker or field == 'id' or _SECRET_FIELD.search(field)):
                    continue
                if (not isinstance(original, str) or len(original) > 128
                        or not isinstance(properties.get(field), dict)
                        or not _writable_string(spec, properties[field])):
                    continue
                options.append({'key': f"{item['name']}:{i}:{field}",
                                'resource': item['name'], 'mutation_index': i,
                                'field': field, 'operation': patch_operation,
                                'source': 'manifest',
                                'reason': 'Campo PATCH già approvato nel workflow; richiede consenso separato alle sonde.'})
                explicitly_configured.add(field)
        # The existing wizard deliberately made mutation optional. Offer OpenAPI
        # fields without requiring another YAML or hand-written JSON. Avoid
        # privileged/security-control fields for all new, auto-discovered writes.
        if len(mutations) >= 4:
            continue
        for field, raw in _string_leaf_paths(spec, properties):
            if field in explicitly_configured or field == 'id' or _SECRET_FIELD.search(field):
                continue
            marker_field = field == marker
            if not marker_field and _UNSAFE_AUTO_FIELD.search(field):
                continue
            if marker_field:
                # Sometimes an API exposes only one text field and that field
                # is also the fixture marker. Allow it ONLY with an explicit
                # selection and a verified PATCH restoration before cleanup.
                options.append({'key': f"{item['name']}:marker:{field}",
                                'resource': item['name'], 'mutation_index': -1,
                                'field': field, 'operation': patch_operation,
                                'source': 'openapi_marker', 'restore_marker': True,
                                'reason': 'Campo usato come marker: PATCH di prova e ripristino verificato del marker PRIMA del cleanup. Se il ripristino fallisce, cleanup manuale.'})
                continue
            options.append({'key': f"{item['name']}:new:{field}",
                            'resource': item['name'], 'mutation_index': -1,
                            'field': field, 'operation': patch_operation,
                            'source': 'openapi',
                            'reason': 'PATCH disponibile nello Swagger: dopo la tua selezione sarà creata una modifica temporanea soltanto per questo campo.'})
        # Form and XML variants use the very same verified fixture life cycle.
        # No form/XML requests are sent until the operator selects these fields.
        for mime, schema in (('application/x-www-form-urlencoded', form_schema),
                             ('application/xml', xml_schema)):
            if not isinstance(schema, dict) or not isinstance(schema.get('properties'), dict):
                continue
            root_name = ((schema.get('xml') or {}).get('name') if isinstance(schema.get('xml'), dict) else None) or 'root'
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,40}', root_name):
                continue
            for field, raw in _string_leaf_paths(spec, schema['properties']):
                if ('.' in field or field == marker or _SECRET_FIELD.search(field)
                        or _UNSAFE_AUTO_FIELD.search(field)):
                    continue
                options.append({'key': f"{item['name']}:media:{mime}:{field}",
                    'resource': item['name'], 'mutation_index': -1,
                    'field': field, 'operation': patch_operation,
                    'content_type': mime, 'xml_root': root_name, 'source': 'openapi_media',
                    'reason': ('Campo di un body form/XML documentato nello Swagger. ' +
                               'La prova richiede la selezione e una fixture temporanea verificabile.')})
    return options[:40]


def resource_probe_diagnostics(parsed: Any, spec: dict[str, Any], manifest: dict[str, Any],
                               options: list[dict[str, Any]] | None = None) -> list[str]:
    """Specific reasons for zero candidates, without claiming the API is safe."""
    from achillesapi.core.workflows import _operation, _request_schema
    options = resource_probe_options(parsed, spec, manifest) if options is None else options
    if options:
        return []
    resources = manifest.get('resources', [])
    if not resources:
        return ['Non ci sono risorse temporanee nel manifest. Salva prima un workflow dal wizard.']
    reasons = []
    for resource in resources[:10]:
        name = str(resource.get('name', 'risorsa'))
        read = resource.get('read', '')
        if not isinstance(read, str) or not read.startswith('GET '):
            reasons.append(f'{name}: non è presente una GET di verifica per la risorsa.')
            continue
        path = read[4:]
        try:
            patch = _operation(parsed, 'PATCH '+path, {'PATCH'})
        except ValueError:
            reasons.append(f'{name}: nello Swagger manca PATCH {path}. Scegli una risorsa con PATCH sullo stesso path della GET.')
            continue
        props = _patch_properties(spec, _request_schema(spec, patch))
        if not props:
            reasons.append(f'{name}: lo Swagger non dichiara proprietà JSON del body PATCH. Il tool non può indovinare i campi.')
        elif len(resource.get('mutations', [])) >= 4:
            reasons.append(f'{name}: il manifest ha già quattro modifiche, limite massimo del motore.')
        else:
            reasons.append(f'{name}: nessun campo stringa JSON/form/XML sicuro per le sonde (es. numeri, ID, campi riservati o vincoli incompatibili).')
    return reasons


def _apply_resource_probe_case(manifest: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """Prepare an in-memory, expressly selected single-field PATCH for this fixture."""
    draft = deepcopy(manifest)
    target = next(r for r in draft['resources'] if r['name'] == case['resource'])
    if case['mutation_index'] == -1:
        mime = case.get('content_type', 'application/json')
        if mime == 'application/xml':
            from xml.etree.ElementTree import Element, SubElement, tostring
            root = Element(case.get('xml_root', 'root'))
            SubElement(root, case['field']).text = case['payload']
            payload_body = tostring(root, encoding='unicode')
        else:
            payload_body = {}
            _set_nested(payload_body, case['field'], case['payload'])
        change = {'operation': case['operation'], 'body': payload_body}
        if mime != 'application/json':
            change['content_type'] = mime
        if case.get('restore_marker'):
            change['restore_marker'] = True
        target.setdefault('mutations', []).append(change)
    else:
        _set_nested(target['mutations'][case['mutation_index']]['body'], case['field'], case['payload'])
    return draft


def resource_body_probe_plan(parsed: Any, spec: dict[str, Any], manifest: dict[str, Any],
                             profiles: set[str], selections: list[str]) -> dict[str, Any]:
    """Validate selected fields and reserve the entire lifecycle of every payload."""
    from achillesapi.core.multi_resource import plan_multi_resource
    if len(selections) > 4 or len(set(selections)) != len(selections):
        raise ValueError('Scegli al massimo quattro campi PATCH diversi.')
    candidates = resource_probe_options(parsed, spec, manifest)
    available = {o['key']: o for o in candidates}
    if any(key not in available for key in selections):
        raise ValueError('Un campo selezionato non appartiene ai PATCH documentati del workflow autorizzato.')
    cases = []
    budget = 0
    for key in selections:
        option = available[key]
        for payload in BODY_PROBES:
            case = {**option, 'payload': payload}
            draft = _apply_resource_probe_case(manifest, case)
            # Strict core preflight still validates all create/read/delete and
            # PATCH paths, identities, bodies, markers, and dependency graph.
            case_budget = plan_multi_resource(parsed, spec, draft, profiles)['request_budget_required']
            budget += case_budget
            cases.append({**case, 'request_budget_required': case_budget})
    return {'engine': 'approved-json-body-probes-rc13', 'cases': cases,
            'request_budget_required': budget, 'available_fields': candidates,
            'conditions': ['Campo approvato esplicitamente nel wizard, anche se manca una mutazione nel manifest.',
                           'Fixture indipendente e cleanup verificato per ogni payload.',
                           'Nessun payload inviato fuori dai workflow autorizzati.']}


def run_resource_body_probes(parsed: Any, spec: dict[str, Any], manifest: dict[str, Any], *,
                             selections: list[str], identities: dict[str, Any],
                             base_url: str, allowed_hosts: set[str], execute: bool,
                             approve_writes: bool, approve_body_probes: bool,
                             allow_insecure_http: bool, max_requests: int, rate: float = 1.) -> dict[str, Any]:
    from achillesapi.core.multi_resource import run_multi_resource, plan_multi_resource
    plan = resource_body_probe_plan(parsed, spec, manifest, set(identities), selections)
    if not execute:
        return {**plan, 'executed': False, 'requests_sent': 0, 'results': [], 'findings': []}
    if not approve_writes or not approve_body_probes:
        raise ValueError('Per le sonde JSON sono indispensabili due consensi espliciti.')
    if not plan['cases']:
        raise ValueError('Seleziona almeno un campo PATCH dal wizard.')
    if max_requests < plan['request_budget_required']:
        raise ValueError(f"Budget insufficiente: riserva almeno {plan['request_budget_required']} richieste per le sonde e il cleanup.")
    reports, total = [], 0
    for case in plan['cases']:
        draft = _apply_resource_probe_case(manifest, case)
        budget = case['request_budget_required']
        outcome = run_multi_resource(parsed, spec, draft, base_url=base_url,
            allowed_hosts=allowed_hosts, identities=identities, execute=True,
            approve_writes=True, allow_insecure_http=allow_insecure_http,
            max_requests=budget, rate=rate)
        total += outcome.get('requests_sent', 0)
        resource = next((r for r in outcome.get('resources_results', [])
                         if r.get('name') == case['resource']), {})
        reports.append({'workflow': case['resource'], 'field': case['field'],
                        'operation': case['operation'], 'payload': case['payload'],
                        'cleanup_verified': bool(resource.get('cleanup_verified')),
                        'manual_cleanup_required': outcome.get('manual_cleanup_required', False),
                        'response_evidence': resource.get('observations', []),
                        'errors': resource.get('errors', []),
                        'target_status': next((o.get('status') for o in resource.get('observations', [])
                                               if o.get('step') == 'mutation'), None)})
        if outcome.get('manual_cleanup_required'):
            break
    return {**plan, 'executed': True, 'requests_sent': total,
            'results': reports, 'findings': [],
            'manual_cleanup_required': any(r['manual_cleanup_required'] for r in reports),
            'limitations': ['Una sonda JSON non costituisce conferma automatica di injection.',
                            'Sono stati inviati solo payload predefiniti su fixture temporanee.']}
