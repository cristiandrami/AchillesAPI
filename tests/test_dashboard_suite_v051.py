"""Suite grouped navigation, isolated retry, and actionable sanitized result tests."""
import json
import time
from pathlib import Path
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app
import achillesapi.dashboard.control as ctrl

SPEC={'openapi':'3.0.3','info':{'title':'Retry Lab','version':'1'},'servers':[{'url':'https://qa.example.test'}],
      'paths':{'/health':{'get':{'responses':{'200':{'description':'ok'}}}}}}


def launch(tmp_path, monkeypatch, order):
    monkeypatch.setattr(ctrl,'SUITE_ORDER',order)
    client=TestClient(create_app(tmp_path/'instance'),base_url='http://127.0.0.1:8766')
    headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    spec=client.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    out=client.post('/api/control/suite',headers=headers,json={'config':{'action':'auto-assess','specification_id':spec}})
    assert out.status_code==200,out.text
    parent=out.json()['id']
    for _ in range(150):
        if client.get('/api/jobs/'+parent).json()['status']=='complete':break
        time.sleep(.05)
    assert client.get('/api/jobs/'+parent).json()['status']=='complete'
    return client,headers,parent


def wait_complete(client,parent):
    for _ in range(150):
        obj=client.get('/api/jobs/'+parent).json()
        if obj['status']=='complete':return obj
        time.sleep(.07)
    raise AssertionError('retry timeout')


def test_retry_skipped_scope_with_missing_url(tmp_path,monkeypatch):
    client,headers,parent=launch(tmp_path,monkeypatch,('scope-audit',))
    before=client.get('/api/results/'+parent).json()
    assert before['steps'][0]['status']=='skipped'
    invalid=client.post('/api/control/suite/'+parent+'/retry',headers=headers,json={'step_index':0})
    assert invalid.status_code==422
    retry=client.post('/api/control/suite/'+parent+'/retry',headers=headers,json={
        'step_index':0,'base_url':'https://qa.example.test','allow_host':'qa.example.test'})
    assert retry.status_code==200,retry.text
    wait_complete(client,parent)
    final=client.get('/api/results/'+parent).json()
    assert final['steps'][0]['status']=='complete',final
    assert len(final['steps'][0]['attempts'])==2
    assert final['summary']=={'completed':1,'failed':0,'skipped':0,'total':1}
    job_id=final['steps'][0]['job_id']
    assert client.get('/api/job-view/'+job_id).status_code==200
    assert any(j.get('suite_id')==parent and j['id']==job_id for j in client.get('/api/jobs').json())
    suite=client.get('/api/job-view/'+parent).json()
    assert suite['suite_steps'][0]['status']=='complete'
    assert suite['suite_summary']['completed']==1
    again=client.post('/api/control/suite/'+parent+'/retry',headers=headers,json={'step_index':0})
    assert again.status_code==422


def test_retry_requires_token_and_no_arbitrary_step(tmp_path,monkeypatch):
    client,headers,parent=launch(tmp_path,monkeypatch,('scope-audit',))
    assert client.post('/api/control/suite/'+parent+'/retry',json={'step_index':0}).status_code==403
    assert client.post('/api/control/suite/'+parent+'/retry',headers=headers,json={'step_index':40}).status_code==422
    assert client.post('/api/control/suite/'+parent+'/retry',headers=headers,json={'step_index':0,'config_usage':'../../danger'}).status_code==422


def test_retry_missing_auth_config_remains_skipped_until_uploaded(tmp_path,monkeypatch):
    client,headers,parent=launch(tmp_path,monkeypatch,('auth-profiles',))
    invalid=client.post('/api/control/suite/'+parent+'/retry',headers=headers,json={'step_index':0})
    assert invalid.status_code==422
    assert 'auth.yaml' in invalid.json()['detail']
    auth='profiles:\n  - name: alice\n    type: bearer\n    token_env: ACHILLES_LAB_OWNER\n'
    upload=client.post('/api/import-text',headers=headers,json={'kind':'auth','content':auth})
    assert upload.status_code==200,upload.text
    retry=client.post('/api/control/suite/'+parent+'/retry',headers=headers,json={
        'step_index':0,'auth_config_id':upload.json()['id']})
    assert retry.status_code==200,retry.text
    wait_complete(client,parent)
    final=client.get('/api/results/'+parent).json()
    assert final['steps'][0]['status'] in {'complete','failed'}
    # The report never persists credentials.
    assert 'demo-secret-token' not in json.dumps(final)


def test_suite_view_includes_observation_drilldown_without_secrets(tmp_path,monkeypatch):
    client,headers,parent=launch(tmp_path,monkeypatch,('analyze-openapi',))
    report=client.get('/api/results/'+parent).json()
    child=report['steps'][0]['job_id']
    root=tmp_path/'instance'/'reports'
    (root/(child+'.json')).write_text(json.dumps({'report_schema':'achillesapi.professional.2','source_kind':'assessment','findings':[{
        'category':'cors_credentialed_origin_reflection','operation':'GET /cors','severity':'medium',
        'reason':'Origin reflection with credentials','evidence':{'allow_credentials':True,'token':'not-for-ui'}}]}))
    response=client.get('/api/job-view/'+parent)
    assert response.status_code==200,response.text
    data=response.json()
    assert len(data['suite_findings'])==1
    finding=data['suite_findings'][0]
    assert finding['category']=='cors_credentialed_origin_reflection'
    assert finding['source_job_id']==child
    assert 'not-for-ui' not in response.text
    html=client.get('/job/'+parent).text
    assert 'job-viewer.js' in html
    assert 'Suite' in (Path(__file__).parents[1]/'src/achillesapi/dashboard/static/job-viewer.js').read_text()
