"""Form-generated prerequisites must be schema-validated, retryable and safe."""
import json
import time
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app
import achillesapi.dashboard.control as control

SPEC={'openapi':'3.0.3','info':{'title':'Prerequisite test','version':'1'},
      'servers':[{'url':'http://127.0.0.1:8795'}],
      'paths':{'/health':{'get':{'responses':{'200':{'description':'ok'}}}},
               '/objects/{obj_id}':{'get':{'parameters':[{'name':'obj_id','in':'path','required':True,'schema':{'type':'string'}}],
                              'responses':{'200':{'description':'ok'}}}}}}

def suite(tmp_path, monkeypatch, action):
    monkeypatch.setattr(control,'SUITE_ORDER',(action,))
    client=TestClient(create_app(tmp_path/'instance'),base_url='http://127.0.0.1:8766')
    header={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    sp=client.post('/api/import-text',headers=header,json={'kind':'openapi','content':json.dumps(SPEC)})
    assert sp.status_code==200,sp.text
    r=client.post('/api/control/suite',headers=header,json={'config':{'action':'auto-assess','specification_id':sp.json()['id']}})
    assert r.status_code==200,r.text
    sid=r.json()['id']
    for _ in range(180):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    assert client.get('/api/jobs/'+sid).json()['status']=='complete'
    return client,header,sid

def create(client,header,sid,payload):
    return client.post(f'/api/control/suite/{sid}/prerequisites/0/generate',headers=header,json=payload)

def test_journey_form_build_and_retry(tmp_path,monkeypatch):
    client,headers,sid=suite(tmp_path,monkeypatch,'journey-assess')
    options=client.get(f'/api/control/suite/{sid}/prerequisites/0')
    assert options.status_code==200
    assert any(x['operation']=='GET /objects/{obj_id}' for x in options.json()['operations'])
    bad=create(client,headers,sid,{'steps':[{'operation':'DELETE /objects/{obj_id}'}]})
    assert bad.status_code==422
    generated=create(client,headers,sid,{'steps':[{'operation':'GET /objects/{obj_id}', 'values':{'obj_id':'known-fixture'}}]})
    assert generated.status_code==200,generated.text
    assert generated.json()['config_usage']=='journey'
    retry=client.post(f'/api/control/suite/{sid}/retry',headers=headers,json={
        'step_index':0,'config_id':generated.json()['id'],'config_usage':'journey',
        'base_url':'http://127.0.0.1:8795'})
    assert retry.status_code==200,retry.text
    for _ in range(160):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    assert client.get('/api/results/'+sid).json()['steps'][0]['status']=='complete'

def test_policy_form_rejects_unsafe_and_accepts_rule(tmp_path,monkeypatch):
    client,headers,sid=suite(tmp_path,monkeypatch,'verify-access-policy')
    assert create(client,headers,sid,{'rules':[{'operation':'POST /objects','identity':'alice','expected':'deny'}]}).status_code==422
    created=create(client,headers,sid,{'rules':[{'operation':'GET /health','identity':'alice','expected':'deny'}]})
    assert created.status_code==200,created.text
    assert created.json()['config_usage']=='context'

def test_benchmark_requires_human_label_confirmation(tmp_path,monkeypatch):
    client,headers,sid=suite(tmp_path,monkeypatch,'benchmark-evaluate')
    labels={'positive_ids':['OBS-1'],'verified_positive_ids':['OBS-1']}
    assert create(client,headers,sid,labels).status_code==422
    labels['human_verified']=True
    result=create(client,headers,sid,labels)
    assert result.status_code==200,result.text
    assert result.json()['config_usage']=='benchmark'
    text=(tmp_path/'instance'/'uploads'/(result.json()['id']+'.config.yaml')).read_text()
    assert json.loads(text)['positive_ids']==['OBS-1']

def test_evidence_requires_actual_http_assessment(tmp_path,monkeypatch):
    client,headers,sid=suite(tmp_path,monkeypatch,'analyze-evidence')
    result=create(client,headers,sid,{})
    assert result.status_code==422
    assert 'auto-assess' in result.json()['detail']
    assert 'prerequisite-builder.js' in client.get('/job/'+sid).text
    assert client.post(f'/api/control/suite/{sid}/prerequisites/0/generate',json={}).status_code==403

def test_benchmark_guided_retry_uses_human_verified_ids(tmp_path,monkeypatch):
    monkeypatch.setattr(control,'SUITE_ORDER',('auto-assess','benchmark-evaluate'))
    client=TestClient(create_app(tmp_path/'instance'),base_url='http://127.0.0.1:8766')
    headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    sp=client.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(SPEC)})
    sid=client.post('/api/control/suite',headers=headers,json={'config':{'action':'auto-assess','specification_id':sp.json()['id']}}).json()['id']
    for _ in range(180):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    report=client.get('/api/results/'+sid).json()
    assert report['steps'][1]['status']=='skipped'
    labels={'human_verified':True,'positive_ids':['KNOWN-1'],'verified_positive_ids':['KNOWN-1']}
    generated=client.post(f'/api/control/suite/{sid}/prerequisites/1/generate',headers=headers,json=labels)
    assert generated.status_code==200,generated.text
    retry=client.post(f'/api/control/suite/{sid}/retry',headers=headers,json={
        'step_index':1,'config_id':generated.json()['id'],'config_usage':'benchmark'})
    assert retry.status_code==200,retry.text
    for _ in range(170):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    final=client.get('/api/results/'+sid).json()
    assert final['steps'][1]['status']=='complete',final['steps'][1]
    result=client.get('/api/results/'+final['steps'][1]['job_id']).json()
    assert result['true_positives']==1

def test_auth_profile_guided_builder(tmp_path,monkeypatch):
    client,headers,sid=suite(tmp_path,monkeypatch,'auth-profiles')
    generated=create(client,headers,sid,{'profiles':[{'name':'owner','type':'bearer','token_env':'ACHILLES_TOKEN_OWNER'}]})
    assert generated.status_code==200,generated.text
    auth_id=generated.json()['auth_config_id']
    assert (tmp_path/'instance'/'uploads'/(auth_id+'.auth.yaml')).is_file()
    retry=client.post(f'/api/control/suite/{sid}/retry',headers=headers,json={'step_index':0,'auth_config_id':auth_id})
    assert retry.status_code==200,retry.text
    for _ in range(120):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    assert client.get('/api/results/'+sid).json()['steps'][0]['status']=='complete'

def test_workflow_form_on_independent_lab(tmp_path,monkeypatch):
    from pathlib import Path
    lab=Path('/mnt/data/independent-api-lab/openapi.json')
    if not lab.is_file():return
    monkeypatch.setattr(control,'SUITE_ORDER',('workflow-assess',))
    client=TestClient(create_app(tmp_path/'instance'),base_url='http://127.0.0.1:8766')
    headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    spec=client.post('/api/import-text',headers=headers,json={'kind':'openapi','content':lab.read_text()})
    assert spec.status_code==200,spec.text
    sid=client.post('/api/control/suite',headers=headers,json={'config':{'action':'auto-assess','specification_id':spec.json()['id']}}).json()['id']
    for _ in range(120):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    opts=client.get(f'/api/control/suite/{sid}/prerequisites/0').json()
    assert len(opts['candidates'])>0
    result=create(client,headers,sid,{'candidate_index':0,'owner':'owner','other':'other',
        'marker_field':'label','marker_value':'temporary-v052-resource','id_pointer':'/id','body':{'label':'temporary-v052-resource'}})
    assert result.status_code==200,result.text
    assert result.json()['config_usage']=='workflow'

def test_multi_resource_guided_on_independent_lab(tmp_path,monkeypatch):
    from pathlib import Path
    lab=Path('/mnt/data/independent-api-lab/openapi.json')
    if not lab.is_file():return
    monkeypatch.setattr(control,'SUITE_ORDER',('multi-resource-assess',))
    client=TestClient(create_app(tmp_path/'instance'),base_url='http://127.0.0.1:8766')
    headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    spec=client.post('/api/import-text',headers=headers,json={'kind':'openapi','content':lab.read_text()})
    assert spec.status_code==200
    auth=client.post('/api/import-text',headers=headers,json={'kind':'auth','content':Path('/mnt/data/independent-api-lab/auth.yaml').read_text()})
    assert auth.status_code==200,auth.text
    sid=client.post('/api/control/suite',headers=headers,json={'config':{'action':'auto-assess','specification_id':spec.json()['id'],'auth_config_id':auth.json()['id']}}).json()['id']
    for _ in range(150):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    result=create(client,headers,sid,{'candidate_index':0,'owner':'owner','other':'other',
        'marker_field':'label','id_pointer':'id','body':{'label':'temporary-v052-resource'}})
    assert result.status_code==200,result.text
    assert result.json()['config_usage']=='multi-resource'

def test_analyze_evidence_generated_from_existing_http_observations(tmp_path,monkeypatch):
    monkeypatch.setattr(control,'SUITE_ORDER',('auto-assess','analyze-evidence'))
    client=TestClient(create_app(tmp_path/'instance'),base_url='http://127.0.0.1:8766')
    headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    spec=client.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    sid=client.post('/api/control/suite',headers=headers,json={'config':{'action':'auto-assess','specification_id':spec}}).json()['id']
    for _ in range(160):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    report=client.get('/api/results/'+sid).json()
    previous=report['source_assessment_id']
    assert previous
    path=tmp_path/'instance'/'reports'/(previous+'.json')
    # Synthetic prior network metadata for a deterministic offline regression test.
    path.write_text(json.dumps({'execution_report':{'observations':[
        {'operation':'GET /health','status':200,'identity':'owner'}]}}))
    gen=client.post(f'/api/control/suite/{sid}/prerequisites/1/generate',headers=headers,json={})
    assert gen.status_code==200,gen.text
    retry=client.post(f'/api/control/suite/{sid}/retry',headers=headers,json={'step_index':1,
         'config_id':gen.json()['id'],'config_usage':'evidence'})
    assert retry.status_code==200,retry.text
    for _ in range(150):
        if client.get('/api/jobs/'+sid).json()['status']=='complete':break
        time.sleep(.05)
    final=client.get('/api/results/'+sid).json()
    assert final['steps'][1]['status']=='complete', final['steps'][1]
