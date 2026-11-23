"""Test di integrazione dashboard RC4: caricamento e job isolati."""
from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app

SPEC = {'openapi':'3.0.3','info':{'title':'New API','version':'1'},
        'paths':{'/items/{item_id}':{'get':{
            'parameters':[{'name':'item_id','in':'path','required':True,'schema':{'type':'string'}}],
            'responses':{'200':{'description':'ok'}}}}}}
AUTH = {'profiles':[{'name':'owner','type':'bearer','token':'private-owner'},
                    {'name':'other','type':'bearer','token':'private-other'}]}
RULES = {'rules':[{'operation':'GET /items/{item_id}','path_values':{'item_id':'10'},
                   'owner':'owner','other':'other','expected_other':'deny'}]}


def test_dashboard_runs_dry_matrix_and_retains_privacy(tmp_path):
    client = TestClient(create_app(tmp_path/'server'),base_url='http://127.0.0.1:8766')
    token = client.get('/api/bootstrap').json()['csrf_token']
    h={'x-achilles-token':token}

    def store(kind, data):
        response=client.post('/api/import-text', headers=h,json={'kind':kind,
            'content':json.dumps(data),'name':kind+'.json'})
        assert response.status_code==200,response.text
        return response.json()['id']

    specification=store('openapi',SPEC)
    authorization=store('auth',AUTH)
    rules=store('config',RULES)
    config={'action':'access-matrix','specification_id':specification,
            'auth_config_id':authorization,'config_id':rules,'config_usage':'context',
            'base_url':'https://test.example','allow_host':'test.example'}
    # Il dry-run non invia traffico al server di test.
    started=client.post('/api/control/jobs',headers=h,json=config)
    assert started.status_code==200,started.text
    job_id=started.json()['id']
    for _ in range(150):
        current=client.get('/api/jobs/'+job_id).json()
        if current['status']!='running':break
        time.sleep(.06)
    assert current['status']=='complete',current
    report=client.get('/api/results/'+job_id).json()
    assert report['status']=='dry_run'
    assert report['requests_sent']==0
    assert 'private-owner' not in json.dumps(report)
    assert 'private-other' not in json.dumps(report)
    assert 'id="matrixDrawer"' in client.get('/').text
    assert client.get('/api/bootstrap').json()['version']==__import__('achillesapi').__version__


def test_dashboard_rejects_unauthorized_matrix(tmp_path):
    client=TestClient(create_app(tmp_path/'server'),base_url='http://127.0.0.1:8766')
    assert client.post('/api/control/jobs',json={'action':'access-matrix'}).status_code==403


def test_matrix_suite_guided_generation_and_retry(tmp_path, monkeypatch):
    import achillesapi.dashboard.control as control
    monkeypatch.setattr(control, 'SUITE_ORDER', ('access-matrix',))
    client = TestClient(create_app(tmp_path/'server'),base_url='http://127.0.0.1:8766')
    h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    def upload(kind, data):
        response=client.post('/api/import-text',headers=h,json={'kind':kind,'content':json.dumps(data)})
        assert response.status_code == 200,response.text
        return response.json()['id']
    spec_id=upload('openapi',SPEC)
    auth_id=upload('auth',AUTH)
    launch=client.post('/api/control/suite',headers=h,json={'config':{
        'action':'access-matrix','specification_id':spec_id,
        'auth_config_id':auth_id,'base_url':'https://test.example',
        'allow_host':'test.example'}})
    assert launch.status_code==200,launch.text
    suite_id=launch.json()['id']
    for _ in range(120):
        state=client.get('/api/jobs/'+suite_id).json()
        if state['status']!='orchestrating':break
        time.sleep(.05)
    assert state['status']=='complete',state
    report=client.get('/api/results/'+suite_id).json()
    assert report['steps'][0]['status']=='skipped'
    opts=client.get(f'/api/control/suite/{suite_id}/prerequisites/0').json()
    assert opts['builder']=='access-matrix'
    assert sorted(opts['auth_profiles'])==['other','owner']
    generation=client.post(f'/api/control/suite/{suite_id}/prerequisites/0/generate',
        headers=h,json=RULES)
    assert generation.status_code==200,generation.text
    cfg_id=generation.json()['id']
    assert generation.json()['config_usage']=='context'
    retry=client.post(f'/api/control/suite/{suite_id}/retry',headers=h,json={
        'step_index':0,'config_id':cfg_id,'config_usage':'context',
        'base_url':'https://test.example','allow_host':'test.example'})
    assert retry.status_code==200,retry.text
    for _ in range(130):
        state=client.get('/api/jobs/'+suite_id).json()
        if state.get('current_step') is None and state['status']=='complete':
            results=client.get('/api/results/'+suite_id).json()
            if results['steps'][0].get('status')=='complete':break
        time.sleep(.06)
    assert results['steps'][0]['status']=='complete',results['steps']
    assert 'private-owner' not in json.dumps(results)
