"""Generic parent-ID hints, explicitly approved live ID probing, and descriptive reports.

No tests here call a real external server; the live HTTP lifecycle uses a fake
client with response-only evidence and checks that unsafe deletion never happens.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json

import pytest
from fastapi.testclient import TestClient

from achillesapi.core.assessment import assessment_to_dict, assess_api
from achillesapi.core.openapi import load_openapi, parse_openapi
from achillesapi.dashboard.manifest_builder import discover_manifest_candidates
from achillesapi.dashboard.live_fixture_discovery import _select_identifier, probe_created_identifier
from achillesapi.dashboard.server import create_app
from achillesapi.reporting.professional import summarize_assessment
from test_rc9_independent_enterprise import SPEC


class FakeAuth:
    names = ['owner']
    def resolve(self, *args, **kwargs):
        return SimpleNamespace(headers={'Authorization':'Bearer SECRET'},cookies={},params={})


class FakeClient:
    def __init__(self, *, correct_marker=True):
        self.calls=[]
        self.marker=''
        self.correct_marker=correct_marker

    def request(self, method, url, *, execute, json_body=None, **kwargs):
        assert execute
        self.calls.append((method,url))
        if method == 'POST':
            self.marker=json_body['description']
            status,body=201,{'payload':{'documentRef':'temporary-DOC-9', 'tenantId':'test-tenant'}}
        elif method == 'GET':
            status,body=200,{'documentRef':'temporary-DOC-9',
                'description':self.marker if self.correct_marker else 'other-object'}
        else:
            status,body=204,{}
        return SimpleNamespace(response=SimpleNamespace(status_code=status,
            body_preview=json.dumps(body),body_truncated=False),error=None)


@pytest.fixture
def spec_path(tmp_path):
    spec=deepcopy(SPEC)
    # Undocumented POST response: ID must be learned only after approved POST.
    spec['paths']['/tenants/{tenantId}/documents']['post']['responses']={
        '201':{'description':'created'}}
    path=tmp_path/'corporate.json'
    path.write_text(json.dumps(spec))
    return path


def _document_candidate(path):
    spec=load_openapi(path)
    return spec,next(x for x in discover_manifest_candidates(str(path))
                     if x['create']=='POST /tenants/{tenantId}/documents')


def test_parent_guidance_is_generic_and_never_claims_real_values(spec_path):
    spec,candidate=_document_candidate(spec_path)
    guidance=candidate['parent_guidance'][0]
    assert guidance['parameter']=='tenantId'
    assert guidance['value_known_from_spec'] is False
    assert guidance['how_to_resolve']
    assert candidate['id_schema_pointers']==[]
    assert candidate['ready']


def test_response_id_inferred_without_schema_and_ambiguous_response_rejected(spec_path):
    _,candidate=_document_candidate(spec_path)
    pointer,value,choices=_select_identifier({'payload':{'documentRef':'DOC42','tenantId':'tenantA'}},candidate,{'tenantId':'tenantA'})
    assert pointer=='/payload/documentRef' and value=='DOC42'
    assert '/payload/tenantId' not in choices
    ambiguous=deepcopy(candidate)
    ambiguous['path_parameter']='resource'
    pointer,value,choices=_select_identifier({'idA':'abc','idB':'def'},ambiguous,{})
    assert pointer is None and value is None


def test_opaque_generated_identifier_name_can_be_inferred_as_last_resort(spec_path):
    _,candidate=_document_candidate(spec_path)
    pointer,value,_=_select_identifier({'result':{'code':'RECEIPT-77','description':'known-marker'}},
        candidate,{'tenantId':'test-tenant'},{'known-marker'})
    assert (pointer,value)==('/result/code','RECEIPT-77')


def test_disposable_probe_requires_both_consents_before_any_network(spec_path):
    spec,candidate=_document_candidate(spec_path)
    client=FakeClient()
    args=dict(candidate=candidate,spec=spec,parsed=parse_openapi(spec),
              base_url='http://127.0.0.1:8795',allow_host='127.0.0.1',allow_insecure_http=True,
              identity='owner',auth_manager=FakeAuth(),path_values={'tenantId':'test-tenant'},
              body={'description':'temporary-document'},marker_field='description',
              client=client,approve_writes=True,approve_possible_orphan=True)
    for key in ('approve_writes','approve_possible_orphan'):
        with pytest.raises(ValueError,match='Conferma scritture'):
            probe_created_identifier(**{**args,key:False})
    assert client.calls==[]
    with pytest.raises(ValueError,match='HTTP in chiaro'):
        probe_created_identifier(**{**args,'allow_host':'example.org','base_url':'http://example.org'})
    assert not client.calls
    result=probe_created_identifier(**args)
    assert result['created'] and result['verified'] and result['cleanup_verified']
    assert result['manual_cleanup_required'] is False
    assert result['id_pointer']=='/payload/documentRef'
    assert [step[0] for step in client.calls]==['POST','GET','DELETE']
    assert 'SECRET' not in json.dumps(result)


def test_never_deletes_when_get_does_not_match_unique_marker(spec_path):
    spec,candidate=_document_candidate(spec_path)
    client=FakeClient(correct_marker=False)
    result=probe_created_identifier(candidate=candidate,spec=spec,parsed=parse_openapi(spec),
              base_url='http://127.0.0.1:8795',allow_host='127.0.0.1',allow_insecure_http=True,
              identity='owner',auth_manager=FakeAuth(),path_values={'tenantId':'test-tenant'},
              body={'description':'temporary-document'},marker_field='description',client=client,
              approve_writes=True,approve_possible_orphan=True)
    assert result['created'] and not result['verified']
    assert result['manual_cleanup_required']
    assert [step[0] for step in client.calls]==['POST','GET']


def test_passive_auth_warnings_keep_endpoint_explanation_and_no_false_confirmations():
    parsed=parse_openapi(SPEC)
    original=assessment_to_dict(assess_api(parsed))
    report=summarize_assessment(original)
    assert report['findings']
    auth=[f for f in report['findings'] if f['category']=='AUTH-002']
    assert auth
    assert all(f['operation'].startswith(('GET ','POST ','DELETE ','PATCH ')) for f in auth)
    assert all(f['reason'] and f['reason']!='Review required' and f['reason']!='unknown' for f in auth)
    assert all(f['severity']=='informational' and f['status']=='requires_review' for f in auth)
    assert all(f['source_type']=='static_openapi' for f in auth)


def test_dashboard_probe_requires_csrf_and_explicit_writes(tmp_path,spec_path):
    with TestClient(create_app(tmp_path/'dashboard'),base_url='http://127.0.0.1:8766') as client:
        csrf={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        result=client.post('/api/import-text',headers=csrf,json={
            'kind':'openapi','content':spec_path.read_text(),'name':'corporate.json'})
        assert result.status_code==200
        sid=result.json()['id']
        auth=client.post('/api/import-text',headers=csrf,json={
            'kind':'auth','content':'profiles:\n  - name: owner\n    type: bearer\n    token: demo-only\n','name':'demo.yaml'})
        assert auth.status_code==200
        aid=auth.json()['id']
        candidates=client.get('/api/control/manifest/candidates/'+sid).json()['candidates']
        ix=next(i for i,x in enumerate(candidates) if x['create'].endswith('/documents'))
        payload={'specification_id':sid,'auth_config_id':aid,'candidate_index':ix,
                 'identity':'owner','base_url':'http://127.0.0.1:8795','allow_host':'127.0.0.1',
                 'allow_insecure_http':True,'approve_writes':False,'approve_possible_orphan':True,
                 'path_values':{'tenantId':'test-tenant'},
                 'body':{'description':'temporary'},'marker':'description'}
        assert client.post('/api/control/manifest/probe-id',json=payload).status_code==403
        assert client.post('/api/control/manifest/probe-id',headers=csrf,json=payload).status_code==422
        assert client.post('/api/control/manifest/parent-lookup',headers=csrf,json={
            **payload,'approve_http':False,'variable':'tenantId','source_operation':'GET /me',
            'pointer':'/tenantId'}).status_code==422
        page=client.get('/').text
        assert 'guidedProbeId' in page
        js=client.get('/assets/app.js').text
        assert '/api/control/manifest/probe-id' in js
        assert '/api/control/manifest/parent-lookup' in js
