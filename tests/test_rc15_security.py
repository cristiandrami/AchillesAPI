"""RC15 network integration tests: real local HTTP, scope, cleanup and OAST."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.core.rc15_callback import RC15Collector
from achillesapi.core.rc15_security import discover, scan_rc15, read_fixtures, RC15Error

SPEC = {
    'openapi': '3.1.0',
    'info': {'title': 'RC15 independent test API', 'version': '1'},
    'paths': {},
}
SPEC['paths']['/search'] = {
    'get': {
        'parameters': [
            {'name': key, 'in': 'query', 'schema': {'type': 'string'}}
            for key in ('q', 'redirect_url', 'file_path', 'callback_url')
        ],
        'responses': {'200': {'description': 'ok'}},
    },
}
SPEC['paths']['/assets'] = {
    'post': {
        'requestBody': {'content': {'application/json': {'schema': {
            'type': 'object', 'properties': {'metadata': {
                'type': 'object', 'properties': {
                    'note': {'type': 'string'},
                    'items': {'type': 'array', 'items': {
                        'type': 'object', 'properties': {'description': {'type': 'string'}}}},
                }
            }}
        }}}},
        'responses': {'201': {'description': 'created'}},
    },
}
SPEC['paths']['/assets/{item_id}'] = {
    'parameters': [{'name': 'item_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}],
    'get': {'responses': {'200': {'description': 'ok'}}},
    'delete': {'responses': {'204': {'description': 'done'}}},
}
SPEC['paths']['/xml'] = {
    'post': {
        'requestBody': {'content': {'application/xml': {
            'schema': {'type': 'object', 'properties': {'value': {'type': 'string'}}},
        }}},
        'responses': {'200': {'description': 'ok'}},
    },
}
SPEC['paths']['/upload'] = {
    'post': {
        'requestBody': {'content': {'multipart/form-data': {
            'schema': {'type': 'object', 'properties': {'file': {'type': 'string', 'format': 'binary'}}},
        }}},
        'responses': {'201': {'description': 'created'}},
    },
}

@pytest.fixture
def api():
    state = {'items': {}, 'counter': 0, 'requests': 0, 'xml_payloads': [], 'redirects': []}
    class Handler(BaseHTTPRequestHandler):
        def response(self, status=200, body=b'', ctype='text/plain', location=None):
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            if location: self.send_header('Location', location)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            from urllib.parse import urlsplit, parse_qs
            path = urlsplit(self.path).path
            query = parse_qs(urlsplit(self.path).query)
            state['requests'] += 1
            if path == '/search':
                if query.get('callback_url', [''])[0].startswith('http://127.0.0.1:'):
                    import httpx
                    try: httpx.get(query['callback_url'][0], timeout=.5)
                    except httpx.HTTPError: pass
                if query.get('redirect_url', [''])[0].startswith('https://example.invalid/'):
                    self.response(302, location=query['redirect_url'][0]); return
                term = query.get('q', [''])[0]
                if term == '<achilles-rc15-probe data-check="safe">':
                    self.response(200, term.encode(), 'text/html'); return
                if query.get('file_path', [''])[0].startswith('../achilles-test-fixture.txt'):
                    self.response(200, b'ACHILLES_FIXTURE_SAFE12345'); return
                self.response(200, ('term=' + term).encode()); return
            ident = path.rsplit('/', 1)[-1]
            if ident in state['items']:
                self.response(200, json.dumps(state['items'][ident]).encode(), 'application/json')
            else: self.response(404)
        def do_POST(self):
            state['requests'] += 1
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            if self.path == '/xml':
                state['xml_payloads'].append(body.decode())
                self.response(200, b'<ok/>', 'application/xml'); return
            if self.path in ('/assets', '/upload'):
                state['counter'] += 1
                ident = str(state['counter'])
                state['items'][ident] = {'id': ident, 'raw': body.decode(errors='replace')}
                self.response(201, json.dumps({'id': ident}).encode(), 'application/json'); return
            self.response(404)
        def do_DELETE(self):
            state['requests'] += 1
            ident = self.path.rsplit('/', 1)[-1]
            state['items'].pop(ident, None)
            self.response(204)
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_address[1]), state
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)


def test_planner_discovers_nested_arrays_json_xml_and_upload():
    points = discover(SPEC)
    keys = {(x.operation, x.location, x.name) for x in points}
    assert ('POST /assets', 'json_body', 'metadata.note') in keys
    assert ('POST /assets', 'json_body', 'metadata.items.0.description') in keys
    assert ('POST /xml', 'xml_body', '/') in keys
    assert ('POST /upload', 'file_upload', 'file') in keys


def test_plan_sends_nothing(api):
    url, state = api
    report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'}, execute=False,
                       families=('sql_error', 'xss', 'open_redirect'))
    assert report['requests_sent'] == 0 and state['requests'] == 0
    assert report['cases']
    assert not report['findings']


def test_reflection_redirect_traversal_with_fixture(api):
    url, _ = api
    report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'}, execute=True,
        families=('xss', 'open_redirect', 'path_traversal'), fixture_file='achilles-test-fixture.txt',
        fixture_marker='ACHILLES_FIXTURE_SAFE12345', rate=5, max_requests=35)
    categories = {x['category'] for x in report['findings']}
    assert 'possible_reflected_xss' in categories
    assert 'possible_open_redirect' in categories
    assert 'path_traversal_fixture' in categories
    assert not report['manual_cleanup_required']
    assert all('response_body' not in str(x) for x in report['findings'])


def test_ssrf_callback_requires_receiver(api):
    url, state = api
    collector = RC15Collector(port=0) if False else RC15Collector(port=8789)
    thread = threading.Thread(target=collector.serve, daemon=True); thread.start()
    try:
        report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'}, execute=True,
            families=('ssrf',), callback_base='http://127.0.0.1:8789',
            callback_observer='http://127.0.0.1:8789', rate=5)
        assert any(f['category'] == 'ssrf_callback' for f in report['findings'])
    finally:
        collector.close(); thread.join(timeout=2)


def test_sql_not_false_positive_on_simple_echo(api):
    url, _ = api
    report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'}, execute=True,
        families=('sql_boolean',), max_requests=12, rate=5)
    assert not report['findings']


def test_write_blocked_without_fixture(api):
    url, state = api
    report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'}, execute=True,
                       families=('sql_error',), max_requests=9, rate=5)
    assert state['items'] == {}
    assert report['skipped']


def test_json_write_cleanup_for_each_probe(api):
    url, state = api
    fixtures = {'POST /assets': {'body': {'metadata': {'note': 'fixture', 'items': [{'description': 'test'}]}},
        'cleanup': {'operation': 'DELETE /assets/{item_id}', 'id_from': 'id',
                    'path_parameter': 'item_id', 'read_operation': 'GET /assets/{item_id}'}}}
    report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'}, execute=True,
        approve_writes=True, fixtures=fixtures, families=('sql_error',),
        max_cases=2, max_requests=12, rate=5)
    assert report['requests_sent'] == 12
    assert not report['manual_cleanup_required']
    assert not state['items']


def test_xml_oast_hardening(api):
    url, _ = api
    client = SafeHTTPClient(allowed_hosts={'127.0.0.1'}, allowed_methods={'POST'})
    payload = '<!DOCTYPE root [<!ENTITY achilles SYSTEM "http://127.0.0.1:8788/callback/0123456789abcdef0123456789abcdef">]><root>&achilles;</root>'
    with pytest.raises(ScopeError):
        client.request('POST', url+'/xml', xml_body=payload)
    with pytest.raises(ScopeError):
        client.request('POST', url+'/xml', xml_body='<!DOCTYPE root [<!ENTITY a SYSTEM "file:///etc/passwd">]><root>&a;</root>',
                       approved_xml_oast_url='http://127.0.0.1:8788/callback/0123456789abcdef0123456789abcdef')
    client.request('POST', url+'/xml', xml_body=payload,
                   approved_xml_oast_url='http://127.0.0.1:8788/callback/0123456789abcdef0123456789abcdef', execute=False)


def test_upload_stays_harmless_and_cleanup(api):
    url, state = api
    fixture = {'POST /upload': {'cleanup': {'operation': 'DELETE /assets/{item_id}',
        'read_operation': 'GET /assets/{item_id}', 'path_parameter': 'item_id', 'id_from': 'id'}}}
    report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'}, execute=True,
        approve_writes=True, fixtures=fixture, families=('file_upload',), max_requests=8, rate=5)
    assert not report['manual_cleanup_required']
    assert not state['items']
    assert any(x['family'] == 'file_upload' for x in report['cases'])


def test_scope_cannot_be_overridden_by_callback():
    with pytest.raises(RC15Error):
        scan_rc15(SPEC, base_url='https://unauthorized.example', allowed_hosts={'127.0.0.1'},
                  execute=True, families=('ssrf',))


def test_xml_probe_runs_only_with_approval(api):
    url, state = api
    fixture = {'POST /xml': {'body': '<root><value>sample</value></root>', 'stateless': True}}
    report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'}, execute=True,
        approve_writes=True, approve_xml_oast=True, fixtures=fixture,
        callback_base='http://127.0.0.1:8788', callback_observer='http://127.0.0.1:8788',
        callback_checker=lambda _: True, families=('xxe',), max_requests=8, rate=5)
    assert any(f['category'] == 'xxe_callback' for f in report['findings'])
    assert any('<!DOCTYPE' in x for x in state['xml_payloads'])


def test_xml_field_injection_uses_approved_stateless_fixture(api):
    url, state = api
    fixtures = {'POST /xml': {'mime': 'application/xml',
        'body': '<root><value>baseline</value></root>', 'stateless': True}}
    report = scan_rc15(SPEC, base_url=url, allowed_hosts={'127.0.0.1'},
        execute=True, approve_writes=True, fixtures=fixtures,
        families=('xpath',), max_cases=2, max_requests=10, rate=5)
    matches = [row for row in report['cases'] if row['location']=='xml_field']
    assert matches and matches[0]['request_count'] > 0
    assert state['xml_payloads'] and all('<root>' in p for p in state['xml_payloads'])
