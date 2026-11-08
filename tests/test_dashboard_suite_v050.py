"""Sequential suite regression and explicit skip reasons; no lab dependency."""
import json
import time
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app
import achillesapi.dashboard.control as control

SPEC={'openapi':'3.0.3','info':{'title':'Suite test','version':'1'},'servers':[{'url':'https://qa.example.test'}],'paths':{'/health':{'get':{'responses':{'200':{'description':'OK'}}}}}}

def client_with_spec(tmp_path):
    client=TestClient(create_app(tmp_path/'suite'),base_url='http://127.0.0.1:8766')
    h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    uploaded=client.post('/api/import-text',headers=h,json={'kind':'openapi','content':json.dumps(SPEC)})
    assert uploaded.status_code==200,uploaded.text
    return client,h,uploaded.json()['id']

def test_suite_run_and_viewer(tmp_path,monkeypatch):
    monkeypatch.setattr(control,'SUITE_ORDER',('analyze-openapi','auto-assess','ai-correlate'))
    client,h,spec=client_with_spec(tmp_path)
    launch=client.post('/api/control/suite',headers=h,json={'config':{'action':'auto-assess','specification_id':spec}})
    assert launch.status_code==200,launch.text
    suite_id=launch.json()['id']
    for _ in range(220):
        state=client.get('/api/jobs/'+suite_id).json()
        if state['status'] not in {'running','orchestrating'}:break
        time.sleep(.08)
    assert state['status']=='complete',state
    report=client.get('/api/results/'+suite_id).json()
    steps=report['steps']
    assert [i['action'] for i in steps]==list(control.SUITE_ORDER)
    assert steps[0]['status']=='complete',steps
    assert steps[1]['status']=='complete',steps
    assert steps[2]['status']=='skipped' and 'AI' in steps[2]['reason']
    assert report['summary']=={'completed':2,'failed':0,'skipped':1,'total':3}
    assert report['source_assessment_id']==steps[1]['job_id']
    assert all(client.get('/job/'+i['job_id']).status_code==200 for i in steps[:2])
    view=client.get('/api/job-view/'+suite_id)
    assert view.status_code==200,view.text
    assert any(sec['key']=='steps' for sec in view.json()['sections'])
    assert view.json()['summary']['tools_completed']==2
    assert 'id="suiteRun"' in client.get('/').text

def test_suite_requires_scope_and_write_approval(tmp_path):
    client,h,spec=client_with_spec(tmp_path)
    without_scope=client.post('/api/control/suite',headers=h,json={
        'include_active':True,'config':{'action':'auto-assess','specification_id':spec}})
    assert without_scope.status_code==422
    writes=client.post('/api/control/suite',headers=h,json={
        'include_writes':True,'config':{'action':'auto-assess','specification_id':spec}})
    assert writes.status_code==422
    unauthorized=client.post('/api/control/suite',json={'config':{'action':'auto-assess','specification_id':spec}})
    assert unauthorized.status_code==403

def test_suite_skip_matrix():
    cfg=control.ToolRequest(action='auto-assess',specification_id='a'*32)
    r=control.SuiteRequest(config=cfg)
    assert control.suite_skip_reason('ai-analyze',cfg,r,None)
    assert control.suite_skip_reason('ai-correlate',cfg,r,None)
    assert control.suite_skip_reason('workflow-assess',cfg,r,None)
    assert control.suite_skip_reason('scope-audit',cfg,r,None)
    assert control.suite_skip_reason('auto-assess',cfg,r,None) is None
    assert set(control.SUITE_ORDER)==set(control.TOOLS)
