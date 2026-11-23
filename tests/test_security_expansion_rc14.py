"""Safety, ground truth and integration tests for the new security-expansion paths."""
from __future__ import annotations

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

import pytest

from achillesapi.core.openapi import parse_openapi
from achillesapi.core.multi_resource import plan_multi_resource, run_multi_resource, MultiResourceError
from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.pipeline_rc13 import create_plan, execute_pipeline
from achillesapi.core.security_capability_rc14 import capability_inventory
from achillesapi.core.verification_rc14 import review_evidence
from achillesapi.dashboard.manifest_builder import discover_manifest_candidates, build_guided_manifest

SPEC = {
    'openapi': '3.1.0', 'info': {'title': 'Generic Accounting Fixture', 'version': '1'},
    'paths': {
        '/assets': {'post': {'requestBody': {'content': {'application/json': {
            'schema': {'type': 'object', 'properties': {'label': {'type': 'string', 'maxLength': 120},
                 'amount': {'type': 'number'}}}}}}, 'responses': {'201': {'description': 'created'}}}},
        '/assets/{asset_id}': {
            'parameters': [{'in': 'path', 'name': 'asset_id', 'required': True, 'schema': {'type': 'string'}}],
            'get': {'responses': {'200': {'description': 'OK'}, '404': {'description': 'missing'}}},
            'patch': {'requestBody': {'content': {'application/json': {
                'schema': {'type': 'object', 'properties': {
                    'approved': {'type': 'boolean'}, 'reimbursed': {'type': 'boolean'},
                    'amount': {'type': 'number'}, 'label': {'type': 'string'}}}}}},
                'responses': {'200': {'description': 'updated'}, '403': {'description': 'denied'}}},
            'delete': {'responses': {'204': {'description': 'removed'}}}},
        '/assets/{asset_id}/approve': {'post': {
            'parameters': [{'in': 'path', 'name': 'asset_id', 'required': True, 'schema': {'type': 'string'}}],
            'responses': {'200': {'description': 'approved'}, '403': {'description': 'denied'}}}},
        '/fetch': {'get': {'parameters': [{'in': 'query', 'name': 'callback_url',
                                         'schema': {'type': 'string'}}],
                           'responses': {'200': {'description': 'ok'}}}},
        '/xml/submit': {'post': {'requestBody': {'content': {'application/xml': {
            'schema': {'type': 'object', 'properties': {'entity': {'type': 'string'}}}}}},
            'responses': {'200': {'description': 'ok'}}}},
    }
}
MANIFEST = {'resources': [{'name': 'asset', 'create': 'POST /assets',
    'read': 'GET /assets/{asset_id}', 'delete': 'DELETE /assets/{asset_id}',
    'identity': 'owner', 'body': {'label': 'fixture'}, 'marker_field': 'label',
    'marker_pointer': '/label', 'id_pointer': '/id', 'read_id_pointer': '/id',
    'path_values': {'asset_id': '${asset.id}'},
    'mutations': [{'operation': 'PATCH /assets/{asset_id}',
                   'body': {'approved': True, 'amount': 43},
                   'expected_policy': 'deny', 'verify_fields': ['/approved', '/amount']}],
    'write_checks': [{'operation': 'POST /assets/{asset_id}/approve',
                      'identity': 'colleague', 'expected': 'deny'}]}]}


def identities():
    return {'owner': AuthenticationMaterial(headers={'Authorization': 'Bearer owner'}, params={}, cookies={}),
            'colleague': AuthenticationMaterial(headers={'Authorization': 'Bearer colleague'}, params={}, cookies={})}


@pytest.fixture
def server():
    items, events, config = {}, [], {'vulnerable': True}
    class Handler(BaseHTTPRequestHandler):
        def answer(self, status, data=None):
            self.send_response(status); self.send_header('Content-Type', 'application/json'); self.end_headers()
            self.wfile.write(json.dumps(data or {}).encode())
        def json_body(self):
            return json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or '{}')
        def do_POST(self):
            if self.path == '/assets':
                ident = 'id' + str(len(events))
                items[ident] = {'id': ident, 'approved': False, 'reimbursed': False,
                                'amount': 1, **self.json_body()}
                events.append(('create', ident))
                return self.answer(201, {'id': ident})
            ident = self.path.split('/')[-2]
            if self.path.endswith('/approve') and ident in items:
                if not config['vulnerable']:
                    return self.answer(403)
                items[ident]['approved'] = True
                events.append(('approve', ident))
                return self.answer(200)
            self.answer(404)
        def do_GET(self):
            ident = self.path.split('/')[-1]
            self.answer(200, items[ident]) if ident in items else self.answer(404)
        def do_PATCH(self):
            ident = self.path.split('/')[-1]
            if ident not in items:
                return self.answer(404)
            body = self.json_body()
            if not config['vulnerable'] and 'approved' in body:
                return self.answer(403)
            items[ident].update(body)
            events.append(('patch', ident))
            self.answer(200)
        def do_DELETE(self):
            ident = self.path.split('/')[-1]
            if ident not in items:
                return self.answer(404)
            del items[ident]
            events.append(('delete', ident))
            self.answer(204)
        def log_message(self, *args): pass
    srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
    try: yield f'http://127.0.0.1:{srv.server_address[1]}', items, events, config
    finally: srv.shutdown(); srv.server_close(); thread.join(timeout=2)


def test_runtime_bfla_and_boolean_numeric_mass_assignment_on_disposable_fixture(server):
    url, items, events, _ = server
    report = run_multi_resource(parse_openapi(SPEC), SPEC, MANIFEST,
        base_url=url, allowed_hosts={'127.0.0.1'}, identities=identities(),
        execute=True, approve_writes=True, allow_insecure_http=True,
        max_requests=35, rate=10)
    categories = {x['category'] for x in report['findings']}
    assert categories == {'bfla_write_policy_conflict', 'mass_assignment_policy_conflict'}
    assert [x['field'] for x in report['findings'] if x['category'] == 'mass_assignment_policy_conflict'] == ['/approved','/amount']
    assert not items
    assert report['resources_results'][0]['cleanup_verified']
    assert not report['manual_cleanup_required']
    assert len([x for x in events if x[0] == 'delete']) == 1
    assert report['requests_sent'] <= report['request_budget_required']


def test_protected_write_action_does_not_create_false_positive(server):
    url, items, events, settings = server
    settings['vulnerable'] = False
    manifest = deepcopy(MANIFEST)
    manifest['resources'][0].pop('mutations')
    result = run_multi_resource(parse_openapi(SPEC), SPEC, manifest,
        base_url=url, allowed_hosts={'127.0.0.1'}, identities=identities(), execute=True,
        approve_writes=True, allow_insecure_http=True, max_requests=25, rate=10)
    assert not result['findings']
    assert not items
    assert result['resources_results'][0]['cleanup_verified']


def test_write_checks_reject_arbitrary_route_and_missing_approval(server):
    url, items, _, _ = server
    fake = deepcopy(MANIFEST)
    fake['resources'][0]['write_checks'][0]['operation'] = 'POST /assets'
    with pytest.raises((MultiResourceError, ValueError)):
        plan_multi_resource(parse_openapi(SPEC), SPEC, fake, set(identities()))
    with pytest.raises(Exception, match='approve-writes'):
        run_multi_resource(parse_openapi(SPEC), SPEC, MANIFEST, base_url=url,
            allowed_hosts={'127.0.0.1'}, identities=identities(), execute=True,
            approve_writes=False, allow_insecure_http=True, max_requests=35)
    assert not items


def test_generic_wizard_discovers_write_actions_and_generates_policy_manifest(tmp_path):
    specfile = tmp_path / 'api.json'; specfile.write_text(json.dumps(SPEC))
    c = next(c for c in discover_manifest_candidates(str(specfile)) if c['create'] == 'POST /assets')
    assert 'POST /assets/{asset_id}/approve' in c['write_action_candidates']
    import yaml
    content = build_guided_manifest(c, owner='owner', other='colleague', marker='label', identifier='id',
        body={'label': 'fixture'}, deny_other=True, path_values={},
        mutation_body={'approved': True, 'amount': 43}, mutation_expected_deny=True,
        write_action='POST /assets/{asset_id}/approve', write_identity='colleague')
    generated = yaml.safe_load(content)
    assert generated['resources'][0]['mutations'][0]['verify_fields'] == ['/approved','/amount']
    assert plan_multi_resource(parse_openapi(SPEC), SPEC, generated, {'owner','colleague'})['request_budget_required'] >= 11


def test_capability_inventory_is_explicitly_offline_and_evidence_does_not_confirm():
    report = capability_inventory(SPEC)
    assert report['request_count'] == 0
    families = {c['family'] for c in report['candidates']}
    assert {'json_input', 'xml_input', 'ssrf', 'mass_assignment', 'bfla'} <= families
    assert all(c['status'] == 'candidate_not_executed' for c in report['candidates'])
    check = review_evidence([{'category': 'fake_injection', 'operation': 'GET /foo',
                              'verification_status': 'confirmed', 'evidence': {}},
                             {'category': 'fake_injection', 'operation': 'GET /foo',
                              'evidence': {'http_comparison': {'baseline': {'status': 200},
                                                            'variants': [{'status': 500}]}}}])
    assert check['unique_review_items'] == 1
    assert check['verified_exploits'] == 0
    assert check['observations'][0]['status'] == 'comparison_recorded_not_confirmed'


def test_pipeline_dry_run_contains_new_inventory_and_verification(tmp_path):
    filepath = tmp_path / 'spec.json'; filepath.write_text(json.dumps(SPEC))
    output = execute_pipeline(filepath, base_url='http://127.0.0.1:1',
                              allowed_hosts=set(), execute=False)
    assert output['security_capabilities']['candidates']
    assert output['verification']['verified_exploits'] == 0
    assert output['requests_sent'] == 0


def test_pipeline_surfaces_new_write_findings_in_dashboard_report(tmp_path, server):
    import yaml
    from achillesapi.dashboard.job_view import viewer_payload
    url, resources, events, _ = server
    spec_path = tmp_path/'openapi.json'; spec_path.write_text(json.dumps(SPEC))
    manifest_path = tmp_path/'resources.yaml'; manifest_path.write_text(yaml.safe_dump(MANIFEST))
    auth_path = tmp_path/'auth.yaml'
    auth_path.write_text('profiles:\n  - name: owner\n    type: bearer\n    token: owner\n  - name: colleague\n    type: bearer\n    token: colleague\n')
    result = execute_pipeline(spec_path, base_url=url, allowed_hosts={'127.0.0.1'},
        auth_config=auth_path, profile='owner', workflow_config=manifest_path,
        execute=True, approve_writes=True, allow_insecure_http=True,
        max_requests=95, rate=5)
    categories = [f['category'] for f in result['findings']]
    assert 'mass_assignment_policy_conflict' in categories
    assert 'bfla_write_policy_conflict' in categories
    assert result['verification']['unique_review_items'] >= 2
    assert resources == {}
    report = viewer_payload(result, action='rc13-assess', job_id='test-job')
    assert any(f['category'] == 'bfla_write_policy_conflict' for f in report['findings'])
    assert any(f['category'] == 'mass_assignment_policy_conflict' for f in report['findings'])
    assert 'security_capabilities' in report


def test_owner_and_cross_tenant_denial_conflicts_not_lost_from_aggregation():
    from achillesapi.core.pipeline_rc13 import authorization_findings
    rows = authorization_findings({'rules': [
        {'id': 'same-tenant', 'operation': 'GET /assets/{asset_id}',
         'status':'policy_conflict_requires_review', 'owner':'owner', 'expected_owner':'allow',
         'expected_other':'deny', 'observations':[{'identity':'owner','status_code':200},
                                                   {'identity':'colleague','status_code':200}]},
        {'id': 'cross-tenant', 'operation': 'GET /assets/{asset_id}',
         'status':'owner_policy_conflict_requires_review', 'owner':'owner',
         'expected_owner':'deny', 'expected_other':'deny',
         'observations':[{'identity':'owner','status_code':200},
                         {'identity':'colleague','status_code':403}]},
        {'id': 'safe', 'status':'policy_matched', 'operation':'GET /', 'observations':[]},
    ]})
    assert len(rows) == 2
    assert rows[1]['rule_id'] == 'cross-tenant'
    assert rows[1]['access_comparison'][0] == {'profile':'owner','status_code':200,'expected':'deny'}
    assert rows[1]['verification_status'] == 'requires_manual_review'


def test_mass_assignment_protected_patch_is_successful_negative_control(server):
    url, items, events, settings = server
    settings['vulnerable'] = False
    manifest = deepcopy(MANIFEST)
    manifest['resources'][0].pop('write_checks')
    result = run_multi_resource(parse_openapi(SPEC), SPEC, manifest,
        base_url=url, allowed_hosts={'127.0.0.1'}, identities=identities(), execute=True,
        approve_writes=True, allow_insecure_http=True, max_requests=35, rate=10)
    assert result['findings'] == []
    assert result['resources_results'][0]['errors'] == []
    assert any(row['step'] == 'negative_policy_verified'
               for row in result['resources_results'][0]['observations'])
    assert result['resources_results'][0]['cleanup_verified']
    assert not items


def test_nested_json_scalar_mass_assignment_persisted_and_cleaned(server):
    url, items, _, _ = server
    spec = deepcopy(SPEC)
    patch_schema = spec['paths']['/assets/{asset_id}']['patch']['requestBody']['content']['application/json']['schema']
    patch_schema['properties']['flags'] = {'type': 'object', 'properties': {
        'restricted': {'type': 'boolean'}}}
    manifest = deepcopy(MANIFEST)
    manifest['resources'][0].pop('write_checks')
    manifest['resources'][0]['mutations'] = [{
        'operation': 'PATCH /assets/{asset_id}', 'body': {'flags': {'restricted': True}},
        'expected_policy': 'deny', 'verify_fields': ['/flags/restricted']
    }]
    result = run_multi_resource(parse_openapi(spec), spec, manifest,
        base_url=url, allowed_hosts={'127.0.0.1'}, identities=identities(), execute=True,
        approve_writes=True, allow_insecure_http=True, max_requests=35, rate=10)
    assert [f['field'] for f in result['findings']] == ['/flags/restricted']
    assert result['resources_results'][0]['cleanup_verified']
    assert not items
