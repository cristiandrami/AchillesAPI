"""Multi-resource disposable assessment, with independently verified cleanup.

The user, not OpenAPI or a language model, approves fixture bodies, identity,
resource ownership markers, paths, and rollback. Derived IDs live only in RAM.
No value from an API response can change the scheme, host, HTTP method, or path
structure declared by OpenAPI. A failed/uncertain create forces manual review.
"""
from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import yaml

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.http import SafeHTTPClient, ScopeError, RequestBudgetExceeded
from achillesapi.core.production_v031 import scope_audit
from achillesapi.core.workflows import _auth_ok, _capture_json, _json_pointer, _operation, _request_schema
from achillesapi.models.api import ParsedAPI


class MultiResourceError(ValueError):
    """Manifest violates preflight constraints; no traffic should be sent."""


_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$")
_REF = re.compile(r"^\$\{([A-Za-z][A-Za-z0-9_-]{0,40})\.id\}$")
_PATH = re.compile(r"\{([^{}]+)\}")
_ID = re.compile(r"^[A-Za-z0-9_.:~-]{1,128}$")


def load_multi_resource_config(path: Path | str) -> dict[str, Any]:
    """Read a YAML fixture manifest without resolving secrets or contacting a host."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise MultiResourceError("Cannot load multi-resource YAML") from exc
    if not isinstance(data, dict):
        raise MultiResourceError("Manifest must contain a YAML mapping")
    return data


def _template(text: str, ids: dict[str, str], *, path_segment: bool = False) -> str:
    """Interpolate only previously captured, validated fixture IDs."""
    if not isinstance(text, str):
        raise MultiResourceError("Template values must be strings")
    match = _REF.fullmatch(text)
    if match:
        if match.group(1) not in ids:
            raise MultiResourceError("Dependent fixture ID not yet available")
        return quote(ids[match.group(1)], safe="") if path_segment else ids[match.group(1)]
    if '${' in text:
        raise MultiResourceError("Only whole-value ${resource.id} references are permitted")
    return text


def _render(path: str, values: dict[str, str], ids: dict[str, str]) -> str:
    """Render an operation's placeholders as individual encoded path segments."""
    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise MultiResourceError(f"Unresolved path parameter {name}")
        value = _template(values[name], ids, path_segment=True)
        if value in ('', '.', '..') or '/' in value or '\\' in value or any(ord(ch) < 32 for ch in value):
            raise MultiResourceError("Unsafe path value")
        return quote(value, safe="") if not _REF.fullmatch(values[name]) else value
    return _PATH.sub(substitute, path)


def _body(data: Any, ids: dict[str, str]) -> Any:
    """Resolve approved, exact ID placeholders inside nested JSON fixtures."""
    if isinstance(data, str):
        return _template(data, ids)
    if isinstance(data, dict):
        return {k: _body(v, ids) for k, v in data.items()}
    if isinstance(data, list):
        return [_body(v, ids) for v in data]
    return data


def plan_multi_resource(parsed: ParsedAPI, spec: dict[str, Any], manifest: dict[str, Any],
                        profiles: set[str]) -> dict[str, Any]:
    """Validate entire fixture graph and calculate a safe worst-case request budget.

    All create operations require POST + 201, a unique marker property in JSON,
    exact read (GET) and delete (DELETE) of the created object. No writes occur.
    """
    if not isinstance(manifest, dict) or set(manifest) != {'resources'}:
        raise MultiResourceError("Manifest must contain only resources")
    resources = manifest['resources']
    if not isinstance(resources, list) or not 1 <= len(resources) <= 10:
        raise MultiResourceError("Provide 1..10 explicitly approved disposable resources")
    seen: set[str] = set()
    work: list[dict[str, Any]] = []
    for position, item in enumerate(resources):
        if not isinstance(item, dict) or set(item) - {'name', 'create', 'read', 'delete', 'identity', 'body',
                'marker_field', 'marker_pointer', 'id_pointer', 'read_id_pointer', 'path_values', 'access', 'mutations'}:
            raise MultiResourceError("Unknown or malformed resource fields")
        name = item.get('name')
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in seen:
            raise MultiResourceError("Resource names must be distinct simple identifiers")
        seen.add(name)
        identity = item.get('identity')
        if identity not in profiles:
            raise MultiResourceError(f"{name}: undefined identity")
        create = _operation(parsed, item.get('create'), {'POST'})
        read = _operation(parsed, item.get('read'), {'GET'})
        delete = _operation(parsed, item.get('delete'), {'DELETE'})
        if read.path != delete.path:
            raise MultiResourceError(f"{name}: DELETE must use the same resource path as GET")
        if not _request_schema(spec, create):
            raise MultiResourceError(f"{name}: creation must declare a JSON request body")
        body = item.get('body')
        if not isinstance(body, dict) or not body or len(json.dumps(body)) > 8192:
            raise MultiResourceError(f"{name}: a bounded approved JSON body is required")
        marker = item.get('marker_field')
        schema = _request_schema(spec, create)
        if not isinstance(marker, str) or marker not in body or not isinstance(body[marker], str):
            raise MultiResourceError(f"{name}: string marker_field must exist in create body")
        # Marker must be declared writable in the OpenAPI schema; no assumption
        # that an undocumented property can be safely persisted.
        from achillesapi.core.testgen import _resolve_schema
        field = _resolve_schema(spec, schema.get('properties', {}).get(marker, {}))
        if field.get('type') != 'string' or field.get('readOnly') or (isinstance(field.get('maxLength'), int) and field['maxLength'] < 32):
            raise MultiResourceError(f"{name}: marker must be writable string with length >=32")
        if any(not isinstance(item.get(k), str) or not item[k].startswith('/') or len(item[k]) > 128
               for k in ('id_pointer', 'read_id_pointer', 'marker_pointer')):
            raise MultiResourceError(f"{name}: id_pointer/read_id_pointer/marker_pointer required")
        values = item.get('path_values', {})
        if not isinstance(values, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k,v in values.items()):
            raise MultiResourceError("path_values must map parameter names to strings")
        dependencies: set[str] = set()
        # Own ID is valid in read/delete paths after creation, but may never
        # appear in the create URL or request body.
        for key, val in values.items():
            if '${' in val:
                match = _REF.fullmatch(val)
                if not match or match.group(1) not in seen:
                    raise MultiResourceError(f"{name}: invalid or future path reference")
                if match.group(1) != name:
                    dependencies.add(match.group(1))
        for val in re.findall(r'"([^"\\]*\$\{[^"\\]*\}[^"\\]*)"', json.dumps(body)):
            match = _REF.fullmatch(val)
            if not match or match.group(1) not in seen or match.group(1) == name:
                raise MultiResourceError(f"{name}: invalid or future body reference")
            dependencies.add(match.group(1))
        for placeholder in _PATH.findall(create.path):
            if _REF.fullmatch(values.get(placeholder,'')) and _REF.fullmatch(values[placeholder]).group(1) == name:
                raise MultiResourceError(f"{name}: create path cannot use its own future ID")
        for endpoint in (create, read, delete):
            missing = set(_PATH.findall(endpoint.path)) - set(values)
            if missing:
                raise MultiResourceError(f"{name}: missing path values {sorted(missing)}")
            for parameter in endpoint.parameters:
                if parameter.required and parameter.location in ('query', 'header') and parameter.name not in values:
                    raise MultiResourceError(f"{name}: required {parameter.location} parameter {parameter.name} missing")
        # A mutation targets ONLY this already-created disposable resource.
        # It is never inferred from OpenAPI or from an LLM response.
        mutations = item.get('mutations', [])
        if not isinstance(mutations, list) or len(mutations) > 4:
            raise MultiResourceError(f'{name}: mutations must be a list of at most four entries')
        for mutation in mutations:
            if (not isinstance(mutation, dict) or set(mutation) != {'operation', 'body'}
                or not isinstance(mutation['body'], dict) or not mutation['body']
                or len(json.dumps(mutation['body'])) > 4096):
                raise MultiResourceError(f'{name}: mutation needs operation and approved bounded JSON body')
            target = _operation(parsed, mutation['operation'], {'PATCH', 'PUT'})
            if target.path != read.path:
                raise MultiResourceError(f'{name}: mutation must target the same verified resource path')
            if not _request_schema(spec, target):
                raise MultiResourceError(f'{name}: mutation must declare a JSON request body')
            if marker in mutation['body'] or 'id' in mutation['body']:
                raise MultiResourceError(f'{name}: mutation may not change marker or ID')
            if '${' in json.dumps(mutation['body']):
                raise MultiResourceError(f'{name}: mutation body may not contain dynamic references')
        checks = item.get('access', [])
        if not isinstance(checks, list) or len(checks) > 6:
            raise MultiResourceError("access must be a bounded list")
        for check in checks:
            if not isinstance(check, dict) or set(check) != {'identity', 'expected'} or check['identity'] not in profiles or check['expected'] not in ('allow', 'deny'):
                raise MultiResourceError("access entries require identity and expected allow/deny")
        work.append({'name': name, 'depends_on': sorted(dependencies), 'create': create,
                     'read': read, 'delete': delete, 'config': item})
    # Create + verify GET + access GETs + reverify GET before DELETE + DELETE +
    # confirm-404 GET. Cleanup reserve is included even after early failures.
    budget = sum(5 + len(w['config'].get('access', [])) + 3*len(w['config'].get('mutations', [])) for w in work)
    return {'engine':'multi-resource-v0.32', 'executable_with_approval': True,
            'requests_sent':0, 'request_budget_required':budget,
            'resources':[{'name':w['name'],'depends_on':w['depends_on'],
                          'operations':[w['config'][x] for x in ('create','read','delete')],
                          'access_checks':len(w['config'].get('access',[])), 'mutation_checks':len(w['config'].get('mutations',[]))} for w in work],
            '_prepared':work}


def run_multi_resource(parsed: ParsedAPI, spec: dict[str, Any], manifest: dict[str, Any], *,
                       base_url: str, allowed_hosts: set[str],
                       identities: dict[str, AuthenticationMaterial], execute: bool = False,
                       approve_writes: bool = False, allow_insecure_http: bool = False,
                       max_requests: int = 80, rate: float = 1.0, timeout: float = 8.0) -> dict[str, Any]:
    """Run approved disposable resources, then reverse-order cleanup in finally.

    Each DELETE is preceded by a fresh GET and performed only if ID and random
    marker still match. Failures are recorded for human cleanup, never retried
    blindly. Response bodies, secrets and unredacted resource IDs never persist.
    """
    plan = plan_multi_resource(parsed, spec, manifest, set(identities))
    public = {k: v for k, v in plan.items() if k != '_prepared'}
    if not execute:
        return {**public, 'executed':False, 'message':'Dry run; zero network requests'}
    if not approve_writes:
        raise ScopeError('Use --approve-writes explicitly for disposable POST/DELETE')
    scope = scope_audit(base_url, list(allowed_hosts))
    if not scope['approved']:
        raise ScopeError('Base URL outside approved host scope')
    if urlsplit(base_url).scheme == 'http' and identities and not allow_insecure_http:
        raise ScopeError('Refusing credentials over plaintext HTTP')
    if max_requests < plan['request_budget_required'] or not 0.1 <= rate <= 10 or timeout <= 0:
        raise ScopeError('Request budget or rate/timeout invalid')
    # Verify every profile/scheme combination before any creation or login.
    schemes = {scheme.scheme_name: {'type': scheme.type, 'scheme': scheme.scheme,
                                   'location': scheme.in_, 'parameter_name': scheme.parameter_name}
               for scheme in parsed.security_schemes}
    for item in plan['_prepared']:
        cfg = item['config']
        for endpoint, identity_name in ((item['create'],cfg['identity']),
                                        (item['read'],cfg['identity']),
                                        (item['delete'],cfg['identity'])):
            if not _auth_ok(endpoint, identities[identity_name], schemes):
                raise ScopeError('Identity incompatible with endpoint OpenAPI security')
        for mutation in cfg.get('mutations', []):
            endpoint = _operation(parsed, mutation['operation'], {'PATCH', 'PUT'})
            if not _auth_ok(endpoint, identities[cfg['identity']], schemes):
                raise ScopeError('Mutation identity incompatible with OpenAPI security')
        for check in cfg.get('access', []):
            if not _auth_ok(item['read'], identities[check['identity']], schemes):
                raise ScopeError('Access identity incompatible with OpenAPI security')
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=max_requests,
                            requests_per_second=rate, timeout=timeout,
                            allowed_methods={'GET','POST','PUT','PATCH','DELETE'})
    identifiers: dict[str, str] = {}
    created: list[dict[str, Any]] = []
    report: dict[str, Any] = {**public,'executed':True,'resources_results':[],
                              'requests_sent':0,'findings':[], 'manual_cleanup_required':False,
                              'limitations':['Only explicitly approved disposable fixtures are written.',
                                             'Access 2xx mismatches are policy violations only when the expected policy is trustworthy.']}

    def send(step: Any, config: dict[str, Any], identity: str, label: str,
             body: dict[str, Any] | None = None) -> Any:
        """Send one request declared in OpenAPI and return transient evidence."""
        path = _render(step.path, config.get('path_values', {}), identifiers)
        material = identities[identity]
        values = config.get('path_values', {})
        params = {p.name: _template(values[p.name], identifiers) for p in step.parameters
                  if p.location == 'query' and p.name in values}
        headers = {p.name: _template(values[p.name], identifiers) for p in step.parameters
                   if p.location == 'header' and p.name in values}
        params.update(material.params)
        headers.update(material.headers)
        evidence = client.request(step.method, base_url.rstrip('/') + path, execute=True,
                                  headers=headers, params=params, cookies=material.cookies,
                                  json_body=body, sensitive_query_names=set(params),
                                  sensitive_header_names=set(headers))
        report['requests_sent'] += 1
        status = evidence.response.status_code if evidence.response else None
        return evidence, {'step':label, 'operation':f'{step.method} {step.path}',
                          'status':status, 'error_type':evidence.error and evidence.error.split(':')[0]}

    try:
        for resource in plan['_prepared']:
            cfg = resource['config']
            name = resource['name']
            row: dict[str, Any] = {'name':name,'created':False,'verified':False,
                                   'observations':[], 'cleanup_verified':False,'errors':[]}
            report['resources_results'].append(row)
            marker = 'achilles-' + secrets.token_hex(12)
            body = _body(cfg['body'], identifiers)
            body[cfg['marker_field']] = marker
            if len(json.dumps(body)) > 8192:
                raise MultiResourceError('Generated fixture body exceeds size cap')
            created_evidence, observation = send(resource['create'], cfg, cfg['identity'], 'create', body)
            row['observations'].append(observation)
            if not created_evidence.response or created_evidence.response.status_code != 201:
                row['errors'].append('creation_not_confirmed_manual_review')
                report['manual_cleanup_required'] = True
                break
            row['created'] = True
            entry = {'resource':resource,'marker':marker,'verified':False}
            created.append(entry)   # Register before parsing; cleanup could be uncertain.
            rid = _json_pointer(_capture_json(created_evidence), cfg['id_pointer'])
            if not isinstance(rid, (str,int)) or isinstance(rid,bool) or not _ID.fullmatch(str(rid)):
                row['errors'].append('created_id_missing_or_unsafe')
                report['manual_cleanup_required'] = True
                break
            identifiers[name] = str(rid)
            baseline, observation = send(resource['read'], cfg, cfg['identity'], 'baseline')
            row['observations'].append(observation)
            content = _capture_json(baseline)
            verified = (baseline.response is not None and baseline.response.status_code == 200
                        and str(_json_pointer(content, cfg['read_id_pointer'])) == str(rid)
                        and _json_pointer(content,cfg['marker_pointer']) == marker)
            row['verified'] = verified
            entry['verified'] = verified
            if not verified:
                row['errors'].append('ownership_marker_verification_failed')
                report['manual_cleanup_required'] = True
                break
            for mutation in cfg.get('mutations', []):
                # Re-read before *every* write. Prevent acting on a replaced resource.
                current, observation = send(resource['read'], cfg, cfg['identity'], 'pre_mutation_verify')
                row['observations'].append(observation)
                state = _capture_json(current)
                if (not current.response or current.response.status_code != 200
                    or str(_json_pointer(state, cfg['read_id_pointer'])) != str(rid)
                    or _json_pointer(state, cfg['marker_pointer']) != marker):
                    row['errors'].append('mutation_blocked_identity_mismatch')
                    report['manual_cleanup_required'] = True
                    entry['verified'] = False
                    break
                endpoint = _operation(parsed, mutation['operation'], {'PATCH','PUT'})
                changed, observation = send(endpoint, cfg, cfg['identity'], 'mutation', mutation['body'])
                row['observations'].append(observation)
                if not changed.response or not 200 <= changed.response.status_code < 300:
                    row['errors'].append('mutation_response_failed')
                    break
                check_state, observation = send(resource['read'], cfg, cfg['identity'], 'post_mutation_verify')
                row['observations'].append(observation)
                state = _capture_json(check_state)
                if (not check_state.response or check_state.response.status_code != 200
                    or str(_json_pointer(state, cfg['read_id_pointer'])) != str(rid)
                    or _json_pointer(state, cfg['marker_pointer']) != marker):
                    row['errors'].append('post_mutation_identity_mismatch')
                    report['manual_cleanup_required'] = True
                    entry['verified'] = False
                    break
            if row['errors']:
                break
            for check in cfg.get('access',[]):
                response, observation = send(resource['read'],cfg,check['identity'], 'access_check')
                observation['identity'] = check['identity']
                row['observations'].append(observation)
                status = response.response.status_code if response.response else None
                violation = (check['expected'] == 'deny' and isinstance(status,int) and 200 <= status < 300)
                violation |= (check['expected'] == 'allow' and isinstance(status,int) and status in (401,403))
                if violation:
                    report['findings'].append({'category':'AUTHORIZATION_POLICY_MISMATCH',
                        'resource':name,'operation':f"GET {resource['read'].path}",
                        'expected':check['expected'],'observed_status':status,
                        'confidence':'policy_based_requires_review',
                        'description':'The response contradicts the explicit operator access policy.'})
    except (MultiResourceError, ScopeError, ValueError, RequestBudgetExceeded) as exc:
        report['errors'] = [type(exc).__name__ + ': ' + str(exc)]
        report['manual_cleanup_required'] = bool(created)
    finally:
        # Safety over successful completion: clean children before parents.
        for entry in reversed(created):
            resource = entry['resource']
            cfg = resource['config']
            row = next(r for r in report['resources_results'] if r['name'] == resource['name'])
            if not entry['verified'] or resource['name'] not in identifiers:
                row['errors'].append('manual_cleanup_unverified_resource')
                report['manual_cleanup_required'] = True
                continue
            try:
                observation_result, observation = send(resource['read'], cfg, cfg['identity'], 'pre_cleanup_verify')
                row['observations'].append(observation)
                content = _capture_json(observation_result)
                valid = (observation_result.response is not None and observation_result.response.status_code == 200
                         and str(_json_pointer(content,cfg['read_id_pointer'])) == identifiers[resource['name']]
                         and _json_pointer(content,cfg['marker_pointer']) == entry['marker'])
                if not valid:
                    row['errors'].append('cleanup_suspended_marker_mismatch')
                    report['manual_cleanup_required'] = True
                    continue
                deleted, observation = send(resource['delete'],cfg,cfg['identity'],'delete')
                row['observations'].append(observation)
                if not deleted.response or deleted.response.status_code not in (200,202,204):
                    row['errors'].append('delete_failed')
                    report['manual_cleanup_required'] = True
                    continue
                gone, observation = send(resource['read'],cfg,cfg['identity'],'verify_deleted')
                row['observations'].append(observation)
                row['cleanup_verified'] = bool(gone.response and gone.response.status_code in (404,410))
                if not row['cleanup_verified']:
                    report['manual_cleanup_required'] = True
                    row['errors'].append('delete_not_verified')
            except (MultiResourceError, ScopeError, ValueError, RequestBudgetExceeded) as exc:
                row['errors'].append('cleanup_exception_' + type(exc).__name__)
                report['manual_cleanup_required'] = True
    return report
