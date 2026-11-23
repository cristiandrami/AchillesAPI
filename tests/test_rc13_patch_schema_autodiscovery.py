"""RC13: regression tests for PATCH fields absent from the wizard-generated manifest.

No real remote API is contacted. Local HTTP fixtures are test-owned and disposable.
"""
from __future__ import annotations

import json
import threading
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml
from fastapi.testclient import TestClient

from achillesapi.core.openapi import parse_openapi
from achillesapi.core.body_probes_rc11 import (
    resource_probe_options, resource_probe_diagnostics, resource_body_probe_plan,
)
from achillesapi.core.pipeline_rc13 import create_plan, execute_pipeline, PipelineError
from achillesapi.dashboard.server import create_app


SPEC = {
    'openapi': '3.1.0', 'info': {'title': 'Unrelated Enterprise API', 'version': '1'},
    'paths': {
        '/records': {'post': {'requestBody': {'content': {'application/json': {'schema': {
            'type': 'object', 'properties': {'label': {'type': 'string', 'minLength': 2, 'maxLength': 100}}}}}},
            'responses': {'201': {'description': 'created'}}}},
        '/records/{record_id}': {
            'parameters': [{'name': 'record_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}],
            'get': {'responses': {'200': {'description': 'ok'}, '404': {'description': 'missing'}}},
            'patch': {'requestBody': {'content': {'application/json': {'schema': {'$ref': '#/components/schemas/RecordPatch'}}}},
                      'responses': {'200': {'description': 'updated'}}},
            'delete': {'responses': {'204': {'description': 'deleted'}}},
        },
    },
    'components': {'schemas': {'RecordPatch': {'type': 'object', 'properties': {
        'label': {'anyOf': [{'type': 'string'}, {'type': 'null'}]},
        'quantity': {'type': 'number'},
        'access_token': {'type': 'string'},
    }}}}
}
MANIFEST = {'resources': [{
    'name': 'record', 'create': 'POST /records', 'read': 'GET /records/{record_id}',
    'delete': 'DELETE /records/{record_id}', 'identity': 'owner',
    'body': {'label': 'test-fixture'}, 'marker_field': 'label',
    'marker_pointer': '/label', 'id_pointer': '/id', 'read_id_pointer': '/id',
    'path_values': {'record_id': '${record.id}'},
    # Same as the dashboard wizard when optional PATCH is not configured.
}]}


def setup_files(tmp_path, spec=SPEC, manifest=MANIFEST):
    spec_path = tmp_path / 'api.json'; spec_path.write_text(json.dumps(spec))
    auth_path = tmp_path / 'auth.yaml'; auth_path.write_text(
        'profiles:\n  - name: owner\n    type: bearer\n    token: fixture-token\n'
    )
    manifest_path = tmp_path / 'resources.yaml'; manifest_path.write_text(yaml.safe_dump(manifest))
    return spec_path, auth_path, manifest_path


def test_discovers_nullable_string_marker_when_no_patch_body_was_entered(tmp_path):
    spec, auth, manifest = setup_files(tmp_path)
    plan = create_plan(spec, auth_config=auth, workflow_config=manifest)
    options = plan['body_probe_options']
    assert [x['key'] for x in options] == ['record:marker:label']
    assert options[0]['restore_marker'] is True
    assert options[0]['source'] == 'openapi_marker'
    assert plan['test_types']['body_injection']['available']
    assert not plan['test_types']['body_injection']['ready']
    selected = create_plan(spec, auth_config=auth, workflow_config=manifest,
                           body_probe_fields=['record:marker:label'])
    assert selected['test_types']['body_injection']['ready']
    assert len(selected['body_probe_plan']['cases']) == 2
    assert selected['body_probe_plan']['request_budget_required'] == 20
    assert resource_probe_diagnostics(parse_openapi(SPEC), SPEC, MANIFEST) == []


def test_rejects_unapproved_field_and_does_not_infer_sensitive_input(tmp_path):
    spec, auth, manifest = setup_files(tmp_path)
    with pytest.raises(ValueError, match='non appartiene'):
        create_plan(spec, auth_config=auth, workflow_config=manifest,
                    body_probe_fields=['record:new:access_token'])
    with pytest.raises(ValueError, match='non appartiene'):
        create_plan(spec, auth_config=auth, workflow_config=manifest,
                    body_probe_fields=['record:marker:quantity'])
    patchless = deepcopy(SPEC)
    del patchless['paths']['/records/{record_id}']['patch']
    options = resource_probe_options(parse_openapi(patchless), patchless, MANIFEST)
    assert options == []
    reasons = resource_probe_diagnostics(parse_openapi(patchless), patchless, MANIFEST)
    assert any('manca PATCH' in reason for reason in reasons)


def test_dashboard_api_shows_schema_candidate_without_extra_yaml(tmp_path):
    spec, auth, manifest = setup_files(tmp_path)
    with TestClient(create_app(tmp_path / 'dashboard'), base_url='http://127.0.0.1:8766') as c:
        header = {'x-achilles-token': c.get('/api/bootstrap').json()['csrf_token']}
        def upload(kind, filepath):
            resp = c.post('/api/import-text', headers=header, json={
                'kind': kind, 'name': filepath.name, 'content': filepath.read_text()})
            assert resp.status_code == 200, resp.text
            return resp.json()['id']
        config = {'action': 'auto-assess', 'specification_id': upload('openapi', spec),
                  'auth_config_id': upload('auth', auth), 'config_usage': 'multi-resource',
                  'config_id': upload('config', manifest)}
        result = c.post('/api/control/rc13/body-fields', headers=header, json=config)
        assert result.status_code == 200, result.text
        assert [x['key'] for x in result.json()['fields']] == ['record:marker:label']
        assert '1 campi PATCH disponibili' in result.json()['message']
        assert result.json()['diagnostics'] == []
        assert 'workflows.yaml' not in result.json()['message']


def test_no_http_without_two_explicit_approvals(tmp_path):
    spec, auth, manifest = setup_files(tmp_path)
    base = dict(base_url='http://127.0.0.1:1', allowed_hosts={'127.0.0.1'},
                auth_config=auth, profile='owner', workflow_config=manifest, execute=True,
                allow_insecure_http=True, max_requests=60, rate=5,
                body_probes=True, body_probe_fields=['record:marker:label'])
    with pytest.raises(PipelineError, match='approvazioni'):
        execute_pipeline(spec, approve_writes=False, approve_body_probes=False, **base)
    with pytest.raises(PipelineError, match='approvazioni'):
        execute_pipeline(spec, approve_writes=True, approve_body_probes=False, **base)


@pytest.mark.parametrize('fail_restore', [False, True])
def test_marker_restored_before_delete_or_cleanup_blocked(tmp_path, fail_restore):
    spec, auth, manifest = setup_files(tmp_path)
    records = {}
    events = []

    class Handler(BaseHTTPRequestHandler):
        def response(self, code, data=None):
            self.send_response(code)
            self.send_header('content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data or {}).encode())

        def body(self):
            return json.loads(self.rfile.read(int(self.headers.get('content-length', '0'))) or b'{}')

        def do_POST(self):
            assert self.path == '/records'
            identity = 'id-'+str(len(records)+len(events))
            records[identity] = {'id': identity, **self.body()}
            events.append(('POST', identity))
            self.response(201, {'id': identity})

        def do_GET(self):
            identity = self.path.split('/')[-1]
            self.response(200, records[identity]) if identity in records else self.response(404)

        def do_PATCH(self):
            identity = self.path.split('/')[-1]
            update = self.body()
            if fail_restore and update.get('label', '').startswith('achilles-'):
                events.append(('RESTORE_FAILED', identity))
                return self.response(409)
            records[identity].update(update)
            events.append(('PATCH', identity, update['label']))
            self.response(200, records[identity])

        def do_DELETE(self):
            identity = self.path.split('/')[-1]
            events.append(('DELETE', identity))
            records.pop(identity, None)
            self.response(204)

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        result = execute_pipeline(spec, base_url=f'http://127.0.0.1:{server.server_address[1]}',
                                  allowed_hosts={'127.0.0.1'}, auth_config=auth, profile='owner',
                                  workflow_config=manifest, execute=True, allow_insecure_http=True,
                                  max_requests=70, rate=5, approve_writes=True,
                                  body_probes=True, approve_body_probes=True,
                                  body_probe_fields=['record:marker:label'])
        result_probes = result['stages']['body_probes']
        assert result_probes['executed']
        if fail_restore:
            assert result['manual_cleanup_required']
            assert not any(e[0] == 'DELETE' for e in events if e[1] in records)
            assert result_probes['results'][0]['manual_cleanup_required']
        else:
            assert not result['manual_cleanup_required'], result
            assert all(x['cleanup_verified'] for x in result_probes['results'])
            assert not records
            assert len([e for e in events if e[0] == 'DELETE']) == 3
            assert len([e for e in events if e[0] == 'PATCH']) == 4
            assert len([e for e in events if e[0] == 'PATCH' and e[2].startswith('achilles-')]) == 2
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)
