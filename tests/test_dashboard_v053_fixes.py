"""Regressions: guided ID field conversion and invalid response evidence rejection."""
import json
import time
from pathlib import Path
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app
import achillesapi.dashboard.control as control


def ready(client,sid):
    for _ in range(200):
        if client.get('/api/jobs/'+sid).json()['status']=='complete': return
        time.sleep(.04)
    raise AssertionError('suite did not complete')


def test_guided_workflow_accepts_id_without_slash(tmp_path,monkeypatch):
    monkeypatch.setattr(control,'SUITE_ORDER',('workflow-assess',))
    client=TestClient(create_app(tmp_path/'app'),base_url='http://127.0.0.1:8766')
    header={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    lab=Path('/mnt/data/independent-api-lab/openapi.json')
    doc=client.post('/api/import-text',headers=header,json={'kind':'openapi','content':lab.read_text()}).json()
    suite=client.post('/api/control/suite',headers=header,json={'config':{'action':'auto-assess','specification_id':doc['id']}}).json()['id']
    ready(client,suite)
    r=client.post(f'/api/control/suite/{suite}/prerequisites/0/generate',headers=header,json={
        'candidate_index':0,'owner':'owner','other':'other','marker_field':'label',
        'marker_value':'temporary-v053-test','id_pointer':'id',
        'body':{'label':'temporary-v053-test'}})
    assert r.status_code==200,r.text
    import yaml
    config=yaml.safe_load((tmp_path/'app'/'uploads'/(r.json()['id']+'.config.yaml')).read_text())
    assert config['workflows'][0]['create']['id_pointer']=='/id'
    assert config['workflows'][0]['read']['id_pointer']=='/id'


def test_evidence_wrong_shape_rejected_before_job(tmp_path):
    client=TestClient(create_app(tmp_path/'app'),base_url='http://127.0.0.1:8766')
    header={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    bad=client.post('/api/import-text',headers=header,json={'kind':'config','content':json.dumps({'findings':[]})})
    assert bad.status_code==200,bad.text
    r=client.post('/api/control/jobs',headers=header,json={
        'action':'analyze-evidence','config_id':bad.json()['id'],'config_usage':'evidence'})
    assert r.status_code==422,r.text
    assert 'responses' in r.json()['detail']


def test_evidence_valid_yaml_accepted_and_executed(tmp_path):
    client=TestClient(create_app(tmp_path/'app'),base_url='http://127.0.0.1:8766')
    header={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    evidence='responses:\n - method: GET\n   path: /health\n   status_code: 200\n   headers: {}\n'
    upload=client.post('/api/import-text',headers=header,json={'kind':'config','content':evidence})
    assert upload.status_code==200,upload.text
    r=client.post('/api/control/jobs',headers=header,json={
        'action':'analyze-evidence','config_id':upload.json()['id'],'config_usage':'evidence'})
    assert r.status_code==200,r.text
    jid=r.json()['id']
    for _ in range(150):
        state=client.get('/api/jobs/'+jid).json()
        if state['status']!='running':break
        time.sleep(.05)
    assert state['status']=='complete',state
    assert client.get('/api/results/'+jid).json()['responses_analyzed']==1
