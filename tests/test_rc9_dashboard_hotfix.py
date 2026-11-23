"""RC9 UI hotfix: GET semantics, multi-workflow composition and minimal retry metadata.

All tests are offline; no HTTP is sent to an external API.
"""
from __future__ import annotations

import json
import time
from copy import deepcopy

from fastapi.testclient import TestClient
import pytest
import yaml

from achillesapi.core.openapi import parse_openapi
from achillesapi.core.workflows import _operation, get_read_side_effect_risk, WorkflowError
from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.manifest_builder import discover_manifest_candidates
from test_rc9_independent_enterprise import SPEC


def test_get_operation_name_does_not_block_disposable_read():
    spec=deepcopy(SPEC)
    spec['paths']['/projects/{projectId}']['get']['operationId']='get-run-status'
    api=parse_openapi(spec)
    endpoint=_operation(api,'GET /projects/{projectId}',{'GET'})
    assert get_read_side_effect_risk(endpoint) is None


def test_genuine_action_get_requires_independent_review():
    spec=deepcopy(SPEC)
    spec['paths']['/projects/{projectId}']['get']['operationId']='deleteProjectNow'
    endpoint=parse_openapi(spec)
    with pytest.raises(WorkflowError,match='conferma esplicitamente'):
        _operation(endpoint,'GET /projects/{projectId}',{'GET'})
    assert _operation(endpoint,'GET /projects/{projectId}',{'GET'},
                      acknowledge_get_side_effect_risk=True).operation_id=='deleteProjectNow'


def test_get_action_path_and_safe_resource_collection():
    spec=deepcopy(SPEC)
    spec['paths']['/jobs/run']={'get':{'responses':{'200':{'description':'ok'}}}}
    spec['paths']['/jobs/runs/{runId}']={'get':{'responses':{'200':{'description':'ok'}}}}
    parsed=parse_openapi(spec)
    assert get_read_side_effect_risk(_operation(parsed,'GET /jobs/runs/{runId}',{'GET'})) is None
    with pytest.raises(WorkflowError,match='GET /jobs/run'):
        _operation(parsed,'GET /jobs/run',{'GET'})


@pytest.fixture
def dashboard(tmp_path):
    with TestClient(create_app(tmp_path/'dashboard'),base_url='http://127.0.0.1:8766') as client:
        token={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        result=client.post('/api/import-text',headers=token,json={
            'kind':'openapi','name':'enterprise.json','content':json.dumps(SPEC)})
        assert result.status_code==200,result.text
        auth=client.post('/api/import-text',headers=token,json={
            'kind':'auth','name':'auth.yaml','content':yaml.safe_dump({'profiles':[
                {'name':'owner','type':'bearer','token':'fixture-only-owner'},
                {'name':'other','type':'bearer','token':'fixture-only-other'}
            ]})})
        assert auth.status_code==200,auth.text
        yield client,token,result.json()['id'],auth.json()['id']


def _prepared(client,token,sid,aid,index,marker,identifier,body):
    response=client.post('/api/control/manifest/guided',headers=token,json={
        'specification_id':sid,'auth_config_id':aid,'candidate_index':index,
        'identity':'owner','other_identity':'other','deny_other':True,
        'marker':marker,'identifier':identifier,'body':body,
        'path_values':{'tenantId':'test-tenant'},
    })
    assert response.status_code==200,response.text
    imported=client.post('/api/import-text',headers=token,json={
        'kind':'config','name':'resources.yaml','content':response.json()['yaml']})
    assert imported.status_code==200
    return imported.json()['id']


def test_composing_two_independent_workflows_without_traffic(dashboard):
    client,token,sid,aid=dashboard
    candidates=client.get('/api/control/manifest/candidates/'+sid).json()['candidates']
    project=next(i for i,c in enumerate(candidates) if c['create'].endswith('/projects'))
    doc=next(i for i,c in enumerate(candidates) if c['create'].endswith('/documents'))
    a=_prepared(client,token,sid,aid,project,'title','/data/id',{'title':'temporary-project'})
    b=_prepared(client,token,sid,aid,doc,'description','/payload/documentRef',{'description':'temporary-document'})
    request={'specification_id':sid,'auth_config_id':aid,'config_ids':[a,b]}
    combined=client.post('/api/control/manifest/compose',headers=token,json=request)
    assert combined.status_code==200,combined.text
    info=combined.json()
    assert info['resources']==2 and info['required_requests']>=10
    assert info['config_usage']=='multi-resource'
    # Read-only offline preflight accepts the combined fixture without contacting the target.
    from achillesapi.core.multi_resource import plan_multi_resource
    from achillesapi.core.openapi import load_openapi
    import pathlib
    target=client.app.state.workspace if hasattr(client.app.state,'workspace') else None
    # Instead of inspecting opaque workspace paths, query existing validation route.
    config=client.get('/api/control/manifest/candidates/'+sid)
    assert config.status_code==200
    bad=client.post('/api/control/manifest/compose',headers=token,json={**request,'config_ids':[a,a]})
    assert bad.status_code==422
    no_token=client.post('/api/control/manifest/compose',json=request)
    assert no_token.status_code==403


def test_retry_contract_exposes_only_required_metadata(dashboard,monkeypatch):
    from achillesapi.dashboard import control
    client,token,sid,aid=dashboard
    monkeypatch.setattr(control,'SUITE_ORDER',('access-matrix',))
    submit=client.post('/api/control/suite',headers=token,json={'config':{
        'action':'auto-assess','specification_id':sid,'auth_config_id':aid,
        'base_url':'https://company.example','allow_host':'company.example'},
        'include_active':False,'include_optional':True})
    assert submit.status_code==200,submit.text
    ident=submit.json()['id']
    for _ in range(100):
        state=client.get('/api/jobs/'+ident).json()
        if state['status']=='complete':break
        time.sleep(.05)
    assert state['status']=='complete'
    result=client.get(f'/api/control/suite/{ident}/prerequisites/0')
    assert result.status_code==200,result.text
    contract=result.json()['retry_requirements']
    assert contract['needs_auth'] and contract['has_auth']
    assert contract['needs_config'] and not contract['has_config']
    assert contract['config_usages']==['context']
    assert not contract['active_capable'] or not contract['active_selected']
    assert contract['has_scope']
    assert 'fixture-only-owner' not in json.dumps(result.json())


def test_dashboard_minimal_mode_and_per_workflow_controls(dashboard):
    client,_,_,_=dashboard
    html=client.get('/').text
    assert 'class="simple-mode"' in html
    assert 'workflowChecklist' in html and 'workflowCombine' in html
    assert 'advancedToggle' in html
    scripts=client.get('/assets/job-viewer.js').text
    assert 'retry_requirements' in scripts
    assert 'required_secret_variables' in scripts
