"""RC15: bounded, OpenAPI-driven *active* API security checks.

All network traffic is opt-in and exact-host scoped. The report contains only
allowlisted probe strings and limited, redacted response metadata. Write probes
require explicitly described disposable fixtures and verified cleanup. OAST
requires an independent, operator-controlled callback collector.

A differential response is an *indicator*, not a confirmed exploit.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlsplit
from xml.sax.saxutils import escape

import httpx
import yaml

from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.testgen import _resolve_schema
from achillesapi.core.workflows import get_read_side_effect_risk
from achillesapi.core.injection_engine_rc5 import SQL_ERRORS, PAIRS as INJECTION_PAIRS, _review as review_injection

FAMILIES = (
    'sql_error', 'sql_boolean', 'sql_time', 'nosql', 'ssti', 'command',
    'xpath', 'ldap', 'crlf', 'xss', 'path_traversal', 'open_redirect', 'ssrf', 'xxe', 'file_upload',
)
DEFAULT_FAMILIES = (
    'sql_error', 'sql_boolean', 'nosql', 'ssti', 'command', 'xpath', 'ldap',
    'crlf', 'xss', 'path_traversal', 'open_redirect', 'ssrf', 'xxe', 'file_upload',
)
_URL = re.compile(r'(?:url|uri|callback|webhook|remote|fetch|proxy|endpoint|target|destination)', re.I)
_FILE = re.compile(r'(?:file|filename|path|template|directory|document)', re.I)
_REDIRECT = re.compile(r'(?:redirect|return[_-]?to|next[_-]?url|continue[_-]?url)', re.I)
_SECRET = re.compile(r'password|secret|token|cookie|credential|api.?key|auth|session|pin|otp', re.I)
_XSS_PROBE = '<achilles-rc15-probe data-check="safe">'
_CONTROL = 'achilles-rc15-control'
_SQL_CONTROL = '__achilles_normal_control__'
_MIME = {'application/json', 'application/x-www-form-urlencoded', 'application/xml', 'text/xml', 'multipart/form-data'}
_TOKEN = re.compile(r'^[0-9a-f]{32}$')
_FIELD = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]{0,63}$')


class RC15Error(ValueError):
    pass


@dataclass(frozen=True)
class Point:
    operation: str
    method: str
    path: str
    location: str
    name: str
    mime: str = ''
    datatype: str = 'string'


def _schema(spec: dict, node: Any) -> dict:
    try:
        result = _resolve_schema(spec, node or {})
        return result if isinstance(result, dict) else {}
    except (ValueError, KeyError, TypeError):
        return {}


def _body_fields(spec: dict, schema: dict, prefix: str = '', depth: int = 0) -> list[tuple[str, str]]:
    """Walk bounded objects and arrays; dots represent object properties, 0 array fixture element."""
    if depth > 5:
        return []
    root = _schema(spec, schema)
    out: list[tuple[str, str]] = []
    if root.get('type') == 'array' and isinstance(root.get('items'), dict):
        return _body_fields(spec, root['items'], prefix + '.0' if prefix else '0', depth + 1)
    for branch_key in ('allOf', 'oneOf', 'anyOf'):
        for branch in root.get(branch_key, [])[:3] if isinstance(root.get(branch_key), list) else []:
            out += _body_fields(spec, branch, prefix, depth + 1)
    props = root.get('properties', {})
    for name, raw in list(props.items())[:60] if isinstance(props, dict) else []:
        if not isinstance(name, str) or not _FIELD.fullmatch(name) or _SECRET.search(name):
            continue
        item = _schema(spec, raw)
        if item.get('readOnly') or item.get('writeOnly') or item.get('enum') or item.get('const') is not None:
            continue
        full = prefix + '.' + name if prefix else name
        if item.get('type') in ('object', 'array'):
            out += _body_fields(spec, item, full, depth + 1)
        elif item.get('type') in ('string', None) or item.get('type') == ['string', 'null']:
            out.append((full, 'string'))
    return list(dict.fromkeys(out))[:80]


def discover(spec: dict[str, Any], *, max_points: int = 250) -> list[Point]:
    """Only declared operations and input fields; no lab-specific endpoint names."""
    result: list[Point] = []
    parsed = parse_openapi(spec)
    for ep in parsed.endpoints:
        if ep.method not in ('GET', 'POST', 'PATCH', 'PUT'):
            continue
        if ep.method == 'GET' and get_read_side_effect_risk(ep):
            continue
        operation = f'{ep.method} {ep.path}'
        for p in ep.parameters:
            if p.location not in ('query', 'path', 'header') or _SECRET.search(p.name):
                continue
            if p.location == 'header' and not p.name.lower().startswith('x-'):
                continue
            result.append(Point(operation, ep.method, ep.path, p.location, p.name))
        content = (_schema(spec, ep.request_body) or {}).get('content', {})
        if not isinstance(content, dict):
            continue
        for ctype, entry in content.items():
            mime = ctype.lower().split(';')[0].strip()
            if (mime not in _MIME and not mime.endswith(('+json', '+xml'))) or not isinstance(entry, dict):
                continue
            root = _schema(spec, entry.get('schema', {}))
            if mime in ('application/xml', 'text/xml') or mime.endswith('+xml'):
                result.append(Point(operation, ep.method, ep.path, 'xml_body', '/', mime))
                for field, datatype in _body_fields(spec, root):
                    result.append(Point(operation, ep.method, ep.path, 'xml_field', field, mime, datatype))
            elif mime == 'multipart/form-data':
                for field, raw in list(root.get('properties', {}).items())[:25] if isinstance(root.get('properties'), dict) else []:
                    item = _schema(spec, raw)
                    if (isinstance(field, str) and _FIELD.fullmatch(field) and
                            (item.get('format') in ('binary', 'byte') or item.get('type') == 'string')):
                        result.append(Point(operation, ep.method, ep.path, 'file_upload', field, mime))
            else:
                for field, datatype in _body_fields(spec, root):
                    result.append(Point(operation, ep.method, ep.path,
                                        'json_body' if (mime == 'application/json' or mime.endswith('+json')) else 'form_body', field, mime, datatype))
        if len(result) >= max_points:
            break
    return result[:max_points]


def relevant(point: Point, family: str) -> bool:
    if family == 'xxe':
        return point.location == 'xml_body'
    if family == 'file_upload':
        return point.location == 'file_upload'
    if point.location == 'xml_body':
        return False  # XXE is the only whole-document XML probe
    if point.location == 'xml_field' and family in ('xxe', 'file_upload', 'open_redirect'):
        return False  # XML entity injection only belongs to the whole approved document
    if point.location == 'file_upload':
        return False
    if family == 'open_redirect':
        return bool(_REDIRECT.search(point.name))
    if family == 'ssrf':
        return bool(_URL.search(point.name))
    if family == 'path_traversal':
        return bool(_FILE.search(point.name))
    if family == 'xss':
        return point.datatype == 'string'
    return point.datatype == 'string'


def read_fixtures(path: Path | None, spec: dict) -> dict[str, dict]:
    """Approved operator-controlled body fixtures, not automatically inferred payloads.

    Every mutating operation must be declared stateless OR include cleanup and
    a read-back verification route; no successful write is silently forgotten.
    """
    if path is None:
        return {}
    if path.stat().st_size > 128 * 1024:
        raise RC15Error('Fixture exceeds 128 KiB')
    raw = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(raw, dict) or not isinstance(raw.get('operations'), list):
        raise RC15Error('Fixture needs an operations list')
    declared = {f'{e.method} {e.path}' for e in parse_openapi(spec).endpoints}
    result: dict[str, dict] = {}
    for item in raw['operations'][:35]:
        if not isinstance(item, dict) or not isinstance(item.get('operation'), str):
            raise RC15Error('Invalid fixture entry')
        name = item['operation']
        if name not in declared or name in result or not name.startswith(('POST ', 'PUT ', 'PATCH ')):
            raise RC15Error('Fixture operation missing, duplicated or unsupported: ' + name)
        if not isinstance(item.get('path_values', {}), dict):
            raise RC15Error('Invalid fixture path values')
        if not item.get('stateless') and not isinstance(item.get('cleanup'), dict):
            raise RC15Error('Write fixture requires explicit cleanup or stateless=true: ' + name)
        if item.get('cleanup'):
            cleanup = item['cleanup']
            op = cleanup.get('operation')
            if op not in declared or not op.startswith('DELETE '):
                raise RC15Error('Cleanup DELETE must be declared in OpenAPI: ' + name)
            if (not isinstance(cleanup.get('id_from'), str)
                    or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,70}', cleanup['id_from'])
                    or not isinstance(cleanup.get('read_operation'), str)
                    or cleanup['read_operation'] not in declared
                    or not cleanup['read_operation'].startswith('GET ')):
                raise RC15Error('Cleanup requires id_from and Swagger GET read_operation')
            if not isinstance(cleanup.get('path_parameter'), str) or not _FIELD.fullmatch(cleanup['path_parameter']):
                raise RC15Error('Cleanup requires path_parameter')
        result[name] = item
    return result


def _safe_path(base_url: str, path: str, values: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = values.get(name)
        if (not isinstance(value, str) or not value or len(value) > 128
                or value in ('.', '..') or any(ch in value for ch in '\\/?#%\r\n')):
            raise RC15Error('Safe path value required for {' + name + '}')
        return quote(value, safe='')
    rendered = re.sub(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', replace, path)
    if '{' in rendered or '}' in rendered:
        raise RC15Error('Invalid path template')
    return base_url.rstrip('/') + rendered


def _set_path(body: Any, dotpath: str, value: Any) -> None:
    steps = dotpath.split('.')
    dest = body
    for key in steps[:-1]:
        if key.isdecimal() and isinstance(dest, list):
            pos = int(key)
            if pos >= len(dest) or pos > 8:
                raise RC15Error('Array index absent from supplied fixture')
            dest = dest[pos]
        elif isinstance(dest, dict) and key in dest:
            dest = dest[key]
        else:
            raise RC15Error('Field absent from supplied baseline fixture')
    final = steps[-1]
    if isinstance(dest, list) and final.isdecimal() and int(final) < len(dest):
        dest[int(final)] = value
    elif isinstance(dest, dict) and final in dest:
        dest[final] = value
    else:
        raise RC15Error('Mutation field absent from supplied baseline')


def _callback_address(base: str, token: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(base)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or (parsed.scheme == 'http' and parsed.hostname not in {'localhost', '127.0.0.1', '::1'})):
        raise RC15Error('Callback base must be HTTPS, or local-only HTTP')
    return base.rstrip('/') + '/callback/' + token


def _seen(observer: str, token: str, *, timeout: float = 0.35) -> bool:
    """Poll only a loopback collector, never a target-supplied URL."""
    parts = urlsplit(observer)
    if (parts.scheme != 'http' or parts.hostname not in {'127.0.0.1', 'localhost', '::1'}
            or parts.username or parts.password or parts.path not in ('', '/')
            or parts.query or parts.fragment):
        raise RC15Error('Observer must be a local HTTP callback collector')
    with httpx.Client(follow_redirects=False, trust_env=False, timeout=timeout) as client:
        response = client.get(observer.rstrip('/') + '/observed/' + token)
        return response.status_code == 200 and response.text == 'true'


def _observation(result: Any) -> dict[str, Any]:
    part = result.response
    preview = part.body_preview if part else ''
    return {
        'status': part.status_code if part else None,
        'body_sha256': hashlib.sha256(preview.encode('utf8', 'replace')).hexdigest()[:16] if part else None,
        'body_length': len(preview) if part else None,
        'truncated': part.body_truncated if part else False,
        'elapsed_ms': part.elapsed_ms if part else None,
        'redirect_host': part.redirect_host if part else None,
        'content_type': (part.headers.get('content-type', '') if part else '')[:90],
        'error': result.error if not part else None,
    }


def _raw(result: Any) -> str:
    return result.response.body_preview if result.response else ''


def _result_from_family(family: str, baseline: Any, variants: list[Any], payloads: tuple[str, ...],
                        *, marker: str | None = None, callback_hit: bool = False) -> tuple[str, list[str]]:
    base = _observation(baseline)
    signals = [_observation(x) for x in variants]
    if not signals or any(v['error'] or v['truncated'] for v in [base, *signals]):
        return 'inconclusive', ['Incomplete/truncated HTTP evidence']
    if base['status'] in (401, 403) and all(x['status'] in (401, 403) for x in signals):
        return 'not_tested_auth', ['Identity has no permission to test this operation']
    if family == 'ssrf' or family == 'xxe':
        return ('observed_callback', ['Unique token received by approved callback collector']) if callback_hit else ('no_indicator', [])
    if family == 'open_redirect':
        host = urlsplit(payloads[-1]).hostname
        if host and signals[-1]['status'] in (301, 302, 303, 307, 308) and signals[-1]['redirect_host'] == host and base['redirect_host'] != host:
            return 'suspected', ['Server Location matches the external harmless probe URL; redirect was not followed']
        return 'no_indicator', []
    if family == 'xss':
        ct = signals[-1]['content_type'].lower().split(';')[0]
        if (ct in ('text/html', 'application/xhtml+xml') and payloads[-1] in _raw(variants[-1])
                and payloads[-1] not in _raw(baseline)):
            return 'manual_review', ['Unescaped HTML markup reflected in an HTML response; script execution not tested']
        return 'no_indicator', []
    if family == 'path_traversal':
        if marker and marker in _raw(variants[-1]) and marker not in _raw(baseline):
            return 'fixture_verified', ['Operator-created harmless file fixture marker was returned']
        return 'no_indicator', []
    if family == 'file_upload':
        if signals[-1]['status'] in (200, 201, 202, 204) and base['status'] in (200, 201, 202, 204):
            return 'manual_review', ['MIME/file validation acceptance needs policy review; no executable upload or RCE was tested']
        return 'no_indicator', []
    # Reuse the same conservative RC5 differential checks and echo normalization.
    comparison = [
        {**_observation(x), '_body': _raw(x), '_headers': x.response.headers if x.response else {}}
        for x in variants
    ]
    base_injection = {**base, '_body': _raw(baseline), '_headers': baseline.response.headers if baseline.response else {}}
    return review_injection(family, base_injection, comparison, payloads)


def _cleanup(client: SafeHTTPClient, base_url: str, config: dict, created: Any, *,
             params: dict, headers: dict, cookies: dict, path_values: dict[str, str]) -> dict:
    """Try delete then GET verification for every created resource, including failing probes."""
    cleanup = config['cleanup']
    text_body = _raw(created)
    try:
        data = json.loads(text_body)
        value = data
        for segment in cleanup['id_from'].split('.'):
            value = value[int(segment)] if isinstance(value, list) else value[segment]
        identifier = str(value)
        if (not identifier or len(identifier) > 128 or identifier in ('.', '..')
                or any(c in identifier for c in '/\\?#%\r\n')):
            raise ValueError('Unsafe cleanup ID')
    except (ValueError, TypeError, KeyError, IndexError):
        return {'verified': False, 'reason': 'create_response_id_missing', 'manual_cleanup_required': True, 'attempted': False}
    vals = {**path_values, cleanup['path_parameter']: identifier}
    delete_op = cleanup['operation'].split(' ', 1)[1]
    read_op = cleanup['read_operation'].split(' ', 1)[1]
    try:
        delete = client.request('DELETE', _safe_path(base_url, delete_op, vals), execute=True,
                                params=params, headers=headers, cookies=cookies,
                                sensitive_query_names=set(params), sensitive_header_names=set(headers))
        status = delete.response.status_code if delete.response else None
        if status not in (200, 202, 204, 404):
            return {'verified': False, 'delete_status': status, 'manual_cleanup_required': True, 'attempted': True}
        verify = client.request('GET', _safe_path(base_url, read_op, vals), execute=True,
                                params=params, headers=headers, cookies=cookies,
                                sensitive_query_names=set(params), sensitive_header_names=set(headers))
        check = verify.response.status_code if verify.response else None
        return {'verified': check in (404, 410), 'delete_status': status, 'read_status': check,
                'manual_cleanup_required': check not in (404, 410), 'attempted': True}
    except (ValueError, OSError, RuntimeError):
        return {'verified': False, 'manual_cleanup_required': True, 'reason': 'cleanup_http_failed', 'attempted': True}


def _run_request(client: SafeHTTPClient, point: Point, value: str | None, base_url: str,
                 path_values: dict[str, str], auth: Any, fixture: dict | None = None, *,
                 xml_oast_url: str | None = None, decode_json_payload: bool = False) -> tuple[Any, dict | None]:
    paths = {**(path_values or {}), **(fixture.get('path_values', {}) if fixture else {})}
    if point.location == 'path' and value is not None:
        # Path values remain bounded; never inject separators/encoded traversal.
        original = paths.get(point.name, '')
        paths[point.name] = str(original) + value
    url = _safe_path(base_url, point.path, paths)
    params = dict(getattr(auth, 'params', {}) or {})
    headers = dict(getattr(auth, 'headers', {}) or {})
    cookies = dict(getattr(auth, 'cookies', {}) or {})
    body: dict[str, Any] = {}
    if point.location == 'query' and value is not None:
        params[point.name] = value
    elif point.location == 'header' and value is not None:
        headers[point.name] = value
    elif point.location in ('json_body', 'form_body'):
        if fixture is None or not isinstance(fixture.get('body'), dict):
            raise RC15Error('Body tests need a complete operator-provided baseline body')
        content = copy.deepcopy(fixture['body'])
        if value is not None:
            injection = json.loads(value) if decode_json_payload and value.startswith('{') else value
            if point.location == 'form_body' and point.name in content:
                content[point.name] = injection
            else:
                _set_path(content, point.name, injection)
        if point.location == 'json_body':
            body['json_body'] = content
        else:
            if not all(isinstance(v, str) for v in content.values()):
                raise RC15Error('Form fields must be strings')
            body['form_body'] = content
    elif point.location in ('xml_body', 'xml_field'):
        if fixture is None or not isinstance(fixture.get('body'), str):
            raise RC15Error('XML requires an operator baseline XML string')
        if point.location == 'xml_field':
            from xml.etree import ElementTree
            if '<!DOCTYPE' in fixture['body'].upper() or '<!ENTITY' in fixture['body'].upper():
                raise RC15Error('XML fixture cannot contain user-supplied entities')
            root = ElementTree.fromstring(fixture['body'])
            if value is not None:
                target = root
                for segment in point.name.split('.'):
                    if segment.isdecimal():
                        children = list(target)
                        if int(segment) >= len(children):
                            raise RC15Error('XML array index absent in fixture')
                        target = children[int(segment)]
                    else:
                        found = next((child for child in target if child.tag == segment), None)
                        if found is None:
                            raise RC15Error('XML element absent from fixture')
                        target = found
                target.text = value
            body['xml_body'] = ElementTree.tostring(root, encoding='unicode')
        elif value is None:
            body['xml_body'] = fixture['body']
        elif xml_oast_url:
            root = re.search(r'^\s*<([A-Za-z][A-Za-z0-9_-]*)\b', fixture['body'])
            if not root or '<!DOCTYPE' in fixture['body'].upper() or '<!ENTITY' in fixture['body'].upper():
                raise RC15Error('XML fixture must have a simple root and no DTD')
            from xml.etree import ElementTree
            try:
                ElementTree.fromstring(fixture['body'])
            except ElementTree.ParseError as exc:
                raise RC15Error('Invalid baseline XML') from exc
            root_name = root.group(1)
            # A safe non-exfiltrating network indicator: no file:/// and no user-defined entity.
            payload = ('<!DOCTYPE ' + root_name + ' [<!ENTITY achilles SYSTEM "' + escape(xml_oast_url) + '">]>'
                       + fixture['body'].replace('>', '>&achilles;', 1))
            body['xml_body'] = payload
            body['approved_xml_oast_url'] = xml_oast_url
        else:
            raise RC15Error('XXE needs a controlled callback receiver')
    elif point.location == 'file_upload':
        # Only text-safe markers; mismatch MIME without executable extension.
        if fixture is None:
            raise RC15Error('Upload requires a disposable fixture')
        body['multipart_files'] = {point.name: (
            'achilles-rc15-probe.txt', b'ACHILLES_RC15_SAFE_UPLOAD\n',
            'image/png' if value else 'text/plain',
        )}
    result = client.request(point.method, url, execute=True,
                            headers=headers, params=params, cookies=cookies,
                            sensitive_query_names=set(params) | ({point.name} if point.location == 'query' else set()),
                            sensitive_header_names=set(headers) | ({point.name} if point.location == 'header' else set()),
                            **body)
    cleanup_state: dict | None = None
    if point.method != 'GET' and fixture is not None and not fixture.get('stateless'):
        cleanup_state = _cleanup(client, base_url, fixture, result, params=params, headers=headers,
                                 cookies=cookies, path_values=paths)
    return result, cleanup_state


def _safe_case(point: Point) -> dict:
    return {'operation': point.operation, 'location': point.location, 'parameter': point.name,
            'media_type': point.mime or None, 'request_count': 0}


def scan_rc15(spec: dict[str, Any], *, base_url: str, allowed_hosts: set[str],
              auth: Any = None, auth_profiles: dict[str, Any] | None = None,
              path_values: dict[str, str] | None = None, execute: bool = False,
              approve_writes: bool = False, fixtures: dict[str, dict] | None = None,
              approve_xml_oast: bool = False, callback_base: str | None = None,
              callback_observer: str | None = None, fixture_file: str | None = None,
              fixture_marker: str | None = None, max_requests: int = 40,
              rate: float = 2.0, families: tuple[str, ...] = DEFAULT_FAMILIES,
              max_cases: int = 150, callback_checker: Callable[[str], bool] | None = None) -> dict[str, Any]:
    """Plan or execute bounded, self-contained HTTP probes.

    callback_checker is an injected test hook; production uses local observer.
    """
    if not set(families) <= set(FAMILIES) or not families:
        raise RC15Error('Unknown RC15 probe family')
    if not 1 <= max_requests <= 500 or not .1 <= rate <= 5 or not 1 <= max_cases <= 500:
        raise RC15Error('Request/case/rate outside RC15 safe limits')
    if (callback_base is None) != (callback_observer is None) and callback_checker is None:
        raise RC15Error('Specify both callback base and local observer')
    if callback_base:
        _callback_address(callback_base, '0' * 32)
    if callback_observer and callback_checker is None:
        parts = urlsplit(callback_observer)
        if parts.scheme != 'http' or parts.hostname not in ('localhost', '127.0.0.1', '::1') or parts.path not in ('', '/'):
            raise RC15Error('Observer must be loopback')
    if fixture_file and (not re.fullmatch(r'[A-Za-z0-9_-]{1,64}\.txt', fixture_file) or not fixture_marker or
                         not re.fullmatch(r'ACHILLES_FIXTURE_[A-Za-z0-9_-]{4,100}', fixture_marker)):
        raise RC15Error('Traversal requires harmless *.txt name and ACHILLES_FIXTURE_* marker')
    # Enforce base host scope even for dry-run input validation.
    parts = urlsplit(base_url)
    if (parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or parts.hostname.lower().rstrip('.') not in
            {x.lower().rstrip('.') for x in allowed_hosts}):
        raise RC15Error('Base URL must use an explicitly approved hostname')
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=max_requests,
                            requests_per_second=rate, max_body_bytes=32768, timeout=5.0,
                            allowed_methods={'GET', 'POST', 'PUT', 'PATCH', 'DELETE'} if approve_writes else {'GET'})
    fixtures = fixtures or {}
    points = discover(spec)
    cases: list[dict] = []
    findings: list[dict] = []
    skipped: list[dict] = []
    remaining = max_requests
    pending: list[tuple[Point, str, tuple[str, ...], int, dict | None]] = []
    # Budget across all inputs and families (round-robin) rather than exhaust first endpoint.
    for family in families:
        for point in points:
            if not relevant(point, family):
                continue
            fixture = fixtures.get(point.operation)
            if point.method != 'GET':
                if not fixture:
                    skipped.append({**_safe_case(point), 'family': family,
                                    'reason': 'Write probe needs a disposable operator fixture'})
                    continue
                if not approve_writes:
                    skipped.append({**_safe_case(point), 'family': family, 'reason': 'Write approval required'})
                    continue
                if fixture.get('mime') and fixture['mime'] != point.mime:
                    continue
                if point.location not in ('json_body', 'form_body', 'xml_body', 'xml_field', 'file_upload'):
                    # Write endpoint parameter fuzzing can change business state unexpectedly.
                    continue
            else:
                if point.location in ('json_body', 'form_body', 'xml_body', 'xml_field', 'file_upload'):
                    continue
            if family in ('ssrf', 'xxe') and not callback_base:
                skipped.append({**_safe_case(point), 'family': family, 'reason': 'Operator callback collector required'})
                continue
            if family == 'xxe' and not approve_xml_oast:
                skipped.append({**_safe_case(point), 'family': family, 'reason': 'Explicit XML OAST consent required'})
                continue
            if family == 'file_upload' and not fixture:
                continue
            if family == 'path_traversal' and not fixture_file:
                skipped.append({**_safe_case(point), 'family': family, 'reason': 'Harmless traversal file fixture required'})
                continue
            if point.location == 'path' and family in ('path_traversal', 'crlf', 'xss', 'ssrf', 'open_redirect'):
                continue
            required_names = re.findall(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', point.path)
            available_values = {**(path_values or {}), **(fixture.get('path_values', {}) if fixture else {})}
            if any(not available_values.get(name) for name in required_names):
                skipped.append({**_safe_case(point), 'family': family, 'reason': 'Missing approved path parameter value'})
                continue
            if family == 'open_redirect':
                values = (_CONTROL, 'https://example.invalid/achilles-rc15-redirect')
            elif family == 'xss':
                values = (_CONTROL, _XSS_PROBE)
            elif family == 'path_traversal':
                values = (fixture_file, '../' + fixture_file)
            elif family in ('ssrf', 'xxe'):
                values = (_CONTROL, '__CALLBACK__')
            elif family == 'file_upload':
                values = ('', 'mime-mismatch')
            else:
                values = tuple(INJECTION_PAIRS[family])
            calls_per_probe = 3 if len(values) == 2 else 2
            if family == 'sql_time':
                calls_per_probe = 7  # 1 baseline + 3 repeated true/false pairs
            if family in ('ssrf', 'xxe', 'file_upload'):
                calls_per_probe = 2
            # Each mutating request must reserve DELETE plus GET verification.
            multiplier = 3 if point.method != 'GET' and not fixture.get('stateless', False) else 1
            budget = calls_per_probe * multiplier
            pending.append((point, family, values, budget, fixture))
            if len(pending) >= 500:
                break
        if len(pending) >= 500:
            break
    # Explicit round-robin across operations. The earlier sort was
    # operation-major: a small request budget could exhaust the first resource
    # without testing SSRF or redirect endpoints appearing later in the spec.
    # Prefer bounded OAST probes when the operator supplied an approved callback;
    # still run at most one probe per distinct operation before deeper sweeps.
    priorities = {'ssrf': 0 if callback_base else 9, 'xxe': 0 if callback_base else 9,
                  'open_redirect': 1, 'xss': 2, 'path_traversal': 3,
                  'file_upload': 4, 'sql_error': 5, 'sql_boolean': 6,
                  'nosql': 7, 'ssti': 8}
    grouped: dict[str, list[tuple[Point, str, tuple[str, ...], int, dict | None]]] = {}
    for candidate in pending:
        grouped.setdefault(candidate[0].operation, []).append(candidate)
    for group in grouped.values():
        group.sort(key=lambda x: (priorities.get(x[1], 10), x[0].name))
    # Preserve an explicitly approved write campaign as its own group. The
    # old interleaving could consume max_cases after a single POST probe,
    # making the remaining fixture fields impossible to test. Within the read
    # group, keep round-robin across distinct operations to prevent starvation.
    round_robin = []
    for is_write in (True, False):
        order = sorted((key for key, group in grouped.items()
                        if (group[0][0].method != 'GET') == is_write),
                       key=lambda key: (priorities.get(grouped[key][0][1], 10), key))
        for index in range(max((len(grouped[key]) for key in order), default=0)):
            for key in order:
                if index < len(grouped[key]):
                    round_robin.append(grouped[key][index])
    pending = round_robin[:max_cases]
    for point, family, values, budget, fixture in pending:
        row = {**_safe_case(point), 'family': family, 'status': 'planned_not_executed',
               'minimum_budget': budget, 'verification_status': 'not_tested'}
        cases.append(row)
        if not execute:
            continue
        if client.request_statistics['attempted'] + budget > max_requests:
            row['status'] = 'skipped_budget'
            continue
        material = (auth_profiles or {}).get(fixture.get('profile')) if fixture and fixture.get('profile') else auth
        if fixture and fixture.get('profile') and material is None:
            row['status'] = 'blocked_missing_profile'
            continue
        try:
            def send(value: str | None, oast_url: str | None = None) -> tuple[Any, dict | None]:
                return _run_request(client, point, value, base_url, path_values or {}, material,
                                    fixture, xml_oast_url=oast_url,
                                    decode_json_payload=(family == 'nosql' and point.location == 'json_body'))
            start_count = int(client.request_statistics['attempted'])
            if family == 'file_upload':
                control, control_cleanup = send(None)
                probe, probe_cleanup = send('mime-mismatch')
                variants = [probe]
                payloads = ('text/plain fixture', 'image/png mismatch fixture')
                cleanups = [control_cleanup, probe_cleanup]
            elif family in ('ssrf', 'xxe'):
                token = secrets.token_hex(16)
                callback_url = _callback_address(callback_base or '', token)
                control, control_cleanup = send(None if family == 'xxe' else _CONTROL)
                probe, probe_cleanup = send(callback_url, callback_url if family == 'xxe' else None)
                variants = [probe]
                payloads = (_CONTROL, '[CALLBACK_URL_REDACTED]')
                cleanups = [control_cleanup, probe_cleanup]
            else:
                control, control_cleanup = send(_SQL_CONTROL)
                variants_and_cleanup = [send(v) for v in (values * 3 if family == 'sql_time' else values)]
                variants = [x[0] for x in variants_and_cleanup]
                payloads = values
                cleanups = [control_cleanup] + [x[1] for x in variants_and_cleanup]
            row['request_count'] = int(client.request_statistics['attempted']) - start_count
            row['responses'] = {'control': _observation(control), 'variants': [_observation(x) for x in variants]}
            if any(c is not None and not c.get('verified') for c in cleanups):
                row['status'] = 'blocked_cleanup_failed'
                row['cleanup'] = cleanups
                skipped.append({**_safe_case(point), 'family': family, 'reason': 'Cleanup unverified; all subsequent writes blocked'})
                # Stop all further probes; do not accidentally leave additional resources.
                break
            row['cleanup_verified'] = all(c is None or c.get('verified') for c in cleanups)
            callback_hit = False
            if family in ('ssrf', 'xxe'):
                checker = callback_checker or (lambda value: _seen(callback_observer or '', value))
                for attempt in range(2):
                    callback_hit = checker(token)
                    if callback_hit:
                        break
                    if attempt == 0:
                        time.sleep(.15)
            if family == 'sql_time' and len(variants) == 6:
                true_ms = [v.response.elapsed_ms for v in variants[0::2] if v.response]
                false_ms = [v.response.elapsed_ms for v in variants[1::2] if v.response]
                base_status = _observation(control)['status']
                if (len(true_ms) == len(false_ms) == 3 and base_status is not None
                        and all(_observation(x)['status'] == base_status for x in variants)):
                    diff = statistics.median(true_ms) - statistics.median(false_ms)
                    jitter = max(statistics.pstdev(true_ms), statistics.pstdev(false_ms))
                    row['status'] = 'manual_review' if diff >= 250 and jitter < 180 else 'no_indicator'
                    row['indicators'] = ([f'Repeated true/false latency median difference: {round(diff)} ms; review for jitter']
                                         if row['status'] == 'manual_review' else [])
                else:
                    row['status'], row['indicators'] = 'inconclusive', ['Timing pairs incomplete or HTTP statuses differ']
            else:
                row['status'], row['indicators'] = _result_from_family(
                    family, control, variants, payloads, marker=fixture_marker,
                    callback_hit=callback_hit)
            if row['status'] in ('suspected', 'manual_review', 'fixture_verified', 'observed_callback'):
                # The observed callback/fixture is confirmed as *behaviour*, never
                # a universal confirmation of the vulnerability class.
                confidence = ('observed_behavior_requires_review'
                              if row['status'] in ('fixture_verified', 'observed_callback')
                              else 'requires_manual_review')
                findings.append({
                    'category': {'ssrf': 'ssrf_callback', 'xxe': 'xxe_callback', 'xss': 'possible_reflected_xss',
                                 'path_traversal': 'path_traversal_fixture', 'open_redirect': 'possible_open_redirect',
                                 'file_upload': 'possible_file_upload_validation_weakness'}.get(family, 'possible_' + family + '_injection'),
                    'family': family, 'operation': point.operation, 'field': point.name,
                    'location': point.location, 'severity': 'informational',
                    'verification_status': confidence, 'reason': '; '.join(row.get('indicators', [])),
                    'evidence': {'control': row['responses']['control'],
                                 'probe': row['responses']['variants'],
                                 'cleanup_verified': row['cleanup_verified'],
                                 'callback_received': callback_hit if family in ('ssrf', 'xxe') else None},
                    'test_payloads': ['[CALLBACK_URL_REDACTED]' if family in ('ssrf', 'xxe') else x for x in payloads],
                })
        except (ValueError, ScopeError, RuntimeError, OSError, KeyError, TypeError) as exc:
            row['status'] = 'blocked_or_inconclusive'
            row['reason'] = type(exc).__name__  # Never serialize exception text containing tokens / URL.
            if point.method != 'GET' and client.request_statistics['attempted']:
                # Failed write or cleanup is not safe to retry on another fixture.
                row['status'] = 'manual_cleanup_review_required'
                break
    return {'engine': 'achilles-rc15-active-security', 'version': '1.0.0rc15',
            'executed': execute, 'requests_sent': client.request_statistics['attempted'],
            'summary': {'planned': len(pending), 'covered': sum(x['status'] not in ('planned_not_executed','skipped_budget') for x in cases) if execute else 0,
                        'findings': len(findings), 'skipped': len(skipped)},
            'cases': cases, 'findings': findings, 'skipped': skipped[:250],
            'manual_cleanup_required': any(x['status'] in ('blocked_cleanup_failed', 'manual_cleanup_review_required') for x in cases),
            'limitations': [
                'No implicit exploitation, file exfiltration, or shell execution.',
                'XXE and SSRF require an independent callback; a missing callback is not proof of safety.',
                'XSS findings indicate HTML reflection, not confirmed browser execution.',
                'Write operations require operator-provided disposable fixtures with cleanup or an explicit stateless contract.',
                'Ambiguous injection differences never become confirmed vulnerabilities without proof.',
            ]}
