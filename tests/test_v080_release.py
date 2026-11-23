"""v0.80 generic compatibility, safety invariants, durable campaign regression."""
from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from achillesapi.core.compatibility_v080 import analyze_compatibility, match_observations, known_unavailable_actions
from achillesapi.core.workflow_inference_v080 import infer_workflows
from achillesapi.core.security_surfaces_v080 import security_surfaces
from achillesapi.core.auth_readiness_v080 import auth_readiness
from achillesapi.core.ai_planner_v080 import deterministic_next_steps, validate_model_suggestions
from achillesapi.core.verification_v080 import classify_findings
from achillesapi.dashboard.persistence_v080 import CampaignStore
from achillesapi.dashboard.server import create_app
import achillesapi.dashboard.control as ctrl


SPEC = {
    'openapi':'3.0.3','info':{'title':'Unrelated sample API','version':'1'},
    'servers':[{'url':'https://api.example.test'}],
    'components':{'securitySchemes':{'bearerAuth':{'type':'http','scheme':'bearer'}}},
    'paths':{
        '/items':{'post':{'security':[{'bearerAuth':[]}], 'requestBody':{'content':{'application/json':{'schema':{'type':'object'}}}},'responses':{'201':{'description':'created'}}}},
        '/items/{item_id}':{
            'get':{'security':[{'bearerAuth':[]}],'parameters':[{'in':'path','name':'item_id','required':True,'schema':{'type':'string'}}], 'responses':{'200':{'description':'found'}}},
            'delete':{'security':[{'bearerAuth':[]}], 'parameters':[{'in':'path','name':'item_id','required':True,'schema':{'type':'string'}}], 'responses':{'204':{'description':'removed'}}}},
        '/ready':{'get':{'responses':{'200':{'description':'ok'}}}},
    }
}


def test_coverage_is_per_operation_and_factual():
    observation={'execution_report':{'observations':[{'operation':'GET /items/abc-42', 'status':200}]}}
    result=analyze_compatibility(SPEC,has_auth=True,active_allowed=True,assessment=observation)
    assert result['summary']['operations']==4
    assert result['summary']['observed_operations']==1
    assert result['summary']['http_coverage_percent']==25.0
    by_op={e['operation']:e for e in result['operations']}
    assert by_op['GET /items/{item_id}']['http_observations']==1
    assert by_op['DELETE /items/{item_id}']['http_observations']==0
    assert by_op['POST /items']['applicability']=='requires_approval'
    assert result['requests_sent']==0
    assert match_observations('GET /items/{item_id}', [{'operation':'POST /items/abc-42'}]) == 0


def test_provably_unavailable_writes_skipped_not_reported_as_test():
    read_only={'openapi':'3.0.3','info':{'title':'Read only','version':'1'},
               'paths':{'/catalog':{'get':{'responses':{'200':{'description':'ok'}}}}}}
    verdict=known_unavailable_actions(analyze_compatibility(read_only))
    assert 'workflow-assess' in verdict and 'multi-resource-assess' in verdict
    assert 'auto-assess' not in verdict


def test_workflow_inference_safe_candidate_and_no_run():
    found=infer_workflows(SPEC)
    assert found['summary']['candidates']==1
    candidate=found['candidates'][0]
    assert candidate['create']=='POST /items'
    assert candidate['cleanup']=='DELETE /items/{item_id}'
    assert candidate['status']=='candidate_review_required'
    assert found['requests_sent']==0


def test_auth_readiness_secret_never_emitted(tmp_path):
    auth=tmp_path/'auth.yaml'
    auth.write_text('profiles:\n  - name: alice\n    type: bearer\n    token: TOPSECRET-DO-NOT-EXPOSE\n')
    out=auth_readiness(SPEC,str(auth))
    assert out['schemes'][0]['status']=='configured_unverified'
    assert out['profile_count']==1
    assert 'TOPSECRET-DO-NOT-EXPOSE' not in json.dumps(out)
    assert 'bearer' in out['supported_runtime_types']


def test_inference_candidates_are_not_verified_vulns():
    found=security_surfaces(SPEC)
    assert found['requests_sent']==0
    assert found['summary']['candidates']>=2
    assert all(x['confirmed_vulnerability'] is False for x in found['candidates'])


def test_model_suggestions_always_allowlisted_and_never_run():
    output=deterministic_next_steps(analyze_compatibility(SPEC),ai_available=True)
    assert output['commands_executed']==0
    assert validate_model_suggestions(['security-inventory','curl -X DELETE http://evil','security-inventory','autonomous-agent'])==['security-inventory']


def test_indicators_never_self_confirm():
    result=classify_findings({'report_schema':'achillesapi.professional.2','findings':[
        {'category':'potential_bola','operation':'GET /items/{item_id}','severity':'high','reason':'Unexpected 200'},
        {'category':'potential_bola','operation':'GET /items/{item_id}','severity':'high','reason':'Repeated 200'},
    ]})
    assert result['requests_sent']==0
    assert result['summary']['confirmed_by_operator']==0
    assert all(f['status']=='requires_review' for f in result['findings'])


def test_dashboard_offline_preview_no_token_and_cannot_mutate(tmp_path):
    client=TestClient(create_app(tmp_path/'app'),base_url='http://127.0.0.1:8766')
    token=client.get('/api/bootstrap').json()['csrf_token']
    headers={'x-achilles-token':token}
    assert client.get('/api/bootstrap').json()['version']==__import__('achillesapi').__version__
    spec_id=client.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    secret='TOPSECRET-KEEP-PRIVATE'
    auth_id=client.post('/api/import-text',headers=headers,json={'kind':'auth',
        'content':'profiles:\n  - name: alice\n    type: bearer\n    token: '+secret+'\n'}).json()['id']
    r=client.get('/api/compatibility/'+spec_id,params={'auth_config_id':auth_id,'active':'true'})
    assert r.status_code==200,r.text
    assert r.json()['summary']['operations']==4
    assert secret not in r.text
    assert 'coverageRun' in client.get('/').text
    assert 'coverage' in client.get('/assets/job-viewer.js').text
    assert client.get('/api/campaigns').json()==[]
    assert secret not in (tmp_path/'app'/'campaigns.sqlite3').read_bytes().decode('latin1')


def test_campaign_persists_and_retry_after_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(ctrl,'SUITE_ORDER',('scope-audit',))
    root=tmp_path/'app'
    client=TestClient(create_app(root),base_url='http://127.0.0.1:8766')
    h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    spec_id=client.post('/api/import-text',headers=h,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    started=client.post('/api/control/suite',headers=h,json={'config':{'action':'auto-assess','specification_id':spec_id}})
    assert started.status_code==200,started.text
    parent=started.json()['id']
    for _ in range(160):
        if client.get('/api/jobs/'+parent).json()['status']=='complete':break
        time.sleep(.04)
    assert client.get('/api/jobs/'+parent).json()['status']=='complete'
    assert client.get('/api/results/'+parent).json()['steps'][0]['status']=='skipped'
    recovered=TestClient(create_app(root),base_url='http://127.0.0.1:8766')
    h2={'x-achilles-token':recovered.get('/api/bootstrap').json()['csrf_token']}
    assert recovered.get('/api/job-view/'+parent).status_code==200
    assert recovered.get('/api/campaigns').json()[0]['id']==parent
    rerun=recovered.post('/api/control/suite/'+parent+'/retry',headers=h2,json={
        'step_index':0,'base_url':'https://api.example.test','allow_host':'api.example.test'})
    assert rerun.status_code==200,rerun.text
    for _ in range(160):
        if recovered.get('/api/jobs/'+parent).json()['status']=='complete':break
        time.sleep(.04)
    assert recovered.get('/api/results/'+parent).json()['steps'][0]['status']=='complete'
    again=TestClient(create_app(root),base_url='http://127.0.0.1:8766')
    assert again.get('/api/job-view/'+parent).status_code==200


def test_persistence_does_not_restore_running_as_success(tmp_path):
    root=tmp_path/'work';root.mkdir()
    store=CampaignStore(root)
    ident='a'*32
    store.save_job({'id':ident,'status':'running','action':'auto-assess','token':'DONOTSTORE'})
    jobs=store.load_jobs()
    assert jobs[ident]['status']=='failed'
    assert 'interrotta' in jobs[ident]['error']
    assert b'DONOTSTORE' not in (root/'campaigns.sqlite3').read_bytes()


def test_new_offline_tools_execute_inside_suite(tmp_path, monkeypatch):
    """Real CLI subprocesses, without target HTTP or lab-specific routes."""
    order=('compatibility-report','workflow-infer','security-surfaces','auth-preflight',
           'adaptive-plan','auto-assess','verify-findings')
    monkeypatch.setattr(ctrl,'SUITE_ORDER',order)
    client=TestClient(create_app(tmp_path/'instance'),base_url='http://127.0.0.1:8766')
    headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    spec_id=client.post('/api/import-text',headers=headers,json={
        'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    response=client.post('/api/control/suite',headers=headers,json={
        'config':{'action':'auto-assess','specification_id':spec_id}})
    assert response.status_code==200,response.text
    parent=response.json()['id']
    for _ in range(450):
        if client.get('/api/jobs/'+parent).json()['status']=='complete':
            break
        time.sleep(.05)
    assert client.get('/api/jobs/'+parent).json()['status']=='complete'
    report=client.get('/api/results/'+parent).json()
    assert len(report['steps'])==len(order)
    assert all(step['status']=='complete' for step in report['steps']),report['steps']
    assert report['preflight']['summary']['operations']==4
    assert report['security_surfaces']['requests_sent']==0
    assert report['verification']['summary']['confirmed_by_operator']==0
    assert len(report['workflow_proposals']['candidates'])==1
    view=client.get('/api/job-view/'+parent)
    assert view.status_code==200,view.text
    assert len(view.json()['compatibility']['operations'])==4
