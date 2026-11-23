"""RC16 regression tests: real HTTP, cross-principal object match, topology, cleanup."""
from __future__ import annotations

from copy import deepcopy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.multi_resource import MultiResourceError, plan_multi_resource, order_disposable_resources
from achillesapi.core.rc16_orchestration import prepare_campaign, run_campaign
from achillesapi.core.workflow_automation_rc16 import discover_resource_workflows, draft_multi_resource_manifest
from achillesapi.core.authorization_auto_rc16 import generate_authorization_policy
from achillesapi.core.openapi import parse_openapi
from test_v034 import sample, manifest


def test_graph_orders_child_before_parent_and_rejects_cycle():
    backwards = {'resources': list(reversed(deepcopy(manifest()['resources'])))}
    ordered = order_disposable_resources(backwards['resources'])
    assert [x['name'] for x in ordered] == ['collection', 'document']
    plan = plan_multi_resource(parse_openapi(sample()), sample(), backwards, {'owner', 'other'})
    assert plan['execution_order'] == ['collection', 'document']
    wrong = deepcopy(backwards)
    wrong['resources'][1]['body']['parent'] = '${document.id}'
    with pytest.raises(MultiResourceError, match='Cyclic'):
        plan_multi_resource(parse_openapi(sample()), sample(), wrong, {'owner', 'other'})


def test_discovery_generates_multiple_independent_or_related_candidates():
    found = discover_resource_workflows(sample())
    assert len(found['candidates']) == 2
    assert {x['create'] for x in found['candidates']} == {'POST /collections', 'POST /collections/{collection_ref}/documents'}
    assert all(x['requests_sent'] == 0 for x in [found])
    draft = draft_multi_resource_manifest(sample(), owner_profile='owner')
    assert len(draft['resources']) == 2
    assert all(item['identity'] == 'owner' and item['delete'].startswith('DELETE ') for item in draft['resources'])
    assert any('REVIEW' in json.dumps(item) for item in draft['resources'])
    parent = next(item for item in draft['resources'] if item['create'] == 'POST /collections')
    child = next(item for item in draft['resources'] if item['create'].endswith('/documents'))
    assert child['path_values']['collection_ref'] == '${' + parent['name'] + '.id}'


def test_policy_creation_skips_missing_identifiers_and_keeps_explicit_role(tmp_path):
    spec = tmp_path / 'spec.json'; spec.write_text(json.dumps(sample()))
    ready = generate_authorization_policy(spec, owner='owner', others=['other'],
        path_values={'collection_ref':'fixture-1','document_ref':'fixture-2'})
    assert ready['rules_generated'] == 2
    assert all(x['expected_other']=='deny' for x in ready['rules'])
    missing = generate_authorization_policy(spec, owner='owner', others=['other'],
        path_values={'collection_ref':'fixture-1'})
    assert missing['rules_generated'] == 1
    assert any(x['reason']=='approved_identifier_missing' for x in missing['skipped'])
    with pytest.raises(ValueError):
        generate_authorization_policy(spec, owner='owner', others=['other'],
            path_values={'document_ref':'../../etc/passwd'})


@pytest.mark.parametrize('cross_access', [False, True])
def test_real_server_cross_identity_and_reverse_cleanup(cross_access):
    objects={'collections':{},'documents':{}}
    events=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def respond(self, status, data=None):
            raw=json.dumps(data or {}).encode()
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_POST(self):
            length=int(self.headers.get('Content-Length','0'))
            body=json.loads(self.rfile.read(length))
            if self.path == '/collections':
                objects['collections']['collection-1']={'id':'collection-1', **body}
                events.append('create_collection');return self.respond(201,{'id':'collection-1'})
            if self.path == '/collections/collection-1/documents':
                objects['documents']['document-1']={'id':'document-1',**body}
                events.append('create_document');return self.respond(201,{'id':'document-1'})
            return self.respond(404)
        def do_GET(self):
            ident=self.path.split('/')[-1]
            obj=objects['documents'].get(ident) or objects['collections'].get(ident)
            if obj is None:return self.respond(404)
            if self.headers.get('Authorization')=='Bearer other' and not cross_access:
                return self.respond(403)
            return self.respond(200,obj)
        def do_DELETE(self):
            ident=self.path.split('/')[-1]
            if self.headers.get('Authorization')!='Bearer owner':return self.respond(403)
            if objects['documents'].pop(ident, None):
                events.append('delete_document');return self.respond(204)
            if objects['collections'].pop(ident, None):
                events.append('delete_collection');return self.respond(204)
            return self.respond(404)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        cases=deepcopy(manifest())
        cases['resources']=list(reversed(cases['resources']))
        report=run_campaign(sample(),cases,identities={
            'owner':AuthenticationMaterial(headers={'Authorization':'Bearer owner'}),
            'other':AuthenticationMaterial(headers={'Authorization':'Bearer other'})},
            base_url=f'http://127.0.0.1:{server.server_port}',allowed_hosts={'127.0.0.1'},
            cross_identity=['other'],expected_other='deny',execute=True,
            approve_writes=True,allow_insecure_http=True,max_requests=35,rate=10)
        assert [r['name'] for r in report['resources_results']] == ['collection','document']
        assert report['added_cross_identity_checks'] == 1
        assert report['requests_sent'] <= report['request_budget_required']
        assert not report['manual_cleanup_required'],report
        assert all(x['cleanup_verified'] for x in report['resources_results'])
        assert events == ['create_collection','create_document','delete_document','delete_collection']
        assert not objects['collections'] and not objects['documents']
        found=report['findings']
        if cross_access:
            assert len(found)==2
            assert all(x['same_temporary_resource_verified'] is True for x in found)
            assert all(x['verification_status']=='same_disposable_object_policy_conflict_requires_review' for x in found)
        else:
            assert not found
        text=json.dumps(report)
        assert 'collection-1' not in text and 'document-1' not in text
        assert 'Bearer ' not in text
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)


def test_writes_fail_closed_before_http(monkeypatch):
    from achillesapi.core import multi_resource
    monkeypatch.setattr(multi_resource, 'SafeHTTPClient',
                        lambda *a,**kw: (_ for _ in ()).throw(AssertionError('unexpected HTTP')))
    creds={'owner':AuthenticationMaterial(),'other':AuthenticationMaterial()}
    dry=run_campaign(sample(),manifest(),identities=creds,base_url='',allowed_hosts=set(),cross_identity=['other'])
    assert dry['requests_sent']==0 and dry['executed'] is False
    with pytest.raises(Exception, match='approve-writes'):
        run_campaign(sample(),manifest(),identities=creds,base_url='http://127.0.0.1:8080',
                     allowed_hosts={'127.0.0.1'},cross_identity=['other'],execute=True)
