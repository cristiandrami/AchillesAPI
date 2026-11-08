"""Regression tests for the guided lab-independent browser experience."""
import json
import time
from pathlib import Path
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app

MINI={"openapi":"3.0.3","info":{"title":"External QA API","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}

def client(tmp_path):
    test=TestClient(create_app(tmp_path/'web'),base_url='http://127.0.0.1')
    token=test.get('/api/bootstrap').json()['csrf_token']
    return test,{'x-achilles-token':token}

def test_gui_has_a_single_guided_workflow(tmp_path):
    test,_=client(tmp_path)
    html=test.get('/').text
    for name in ['specFile','authFile','configFile','secretFields','toolSelect','jobsList']:
        assert 'id="'+name+'"' in html
    assert 'Avvia tutto il laboratorio' not in html
    assert 'Dashboard indipendente dal laboratorio' in html
    js=test.get('/assets/app.js').text
    assert 'specPasteBtn' in js and 'import-text' in js

def test_file_and_paste_imports_are_functional(tmp_path):
    test,headers=client(tmp_path)
    specfile=test.post('/api/upload',headers=headers,files={'file':('external.json',json.dumps(MINI).encode(),'application/json')})
    assert specfile.status_code==200,specfile.text
    assert specfile.json()['operations']==1
    pasted=test.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(MINI)})
    assert pasted.status_code==200,pasted.text
    auth='profiles:\n  - name: tester\n    type: bearer\n    token_env: ACHILLES_TESTER_TOKEN\n'
    upload=test.post('/api/auth-config',headers=headers,files={'file':('auth.yaml',auth.encode())})
    assert upload.status_code==200,upload.text
    assert upload.json()['descriptions'][0]['environment_variables']==['ACHILLES_TESTER_TOKEN']
    inline=test.post('/api/import-text',headers=headers,json={'kind':'auth','content':auth})
    assert inline.status_code==200,inline.text
    assert inline.json()['profiles'][0]['name']=='tester'
    assert test.get('/api/auth-template').status_code==200
    assert test.post('/api/import-text',headers=headers,json={'kind':'config','content':'resources: []'}).status_code==200

def test_secrets_not_persisted_or_reflected_and_are_restricted(tmp_path):
    test,headers=client(tmp_path)
    spec=test.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(MINI)}).json()['id']
    auth=test.post('/api/import-text',headers=headers,json={'kind':'auth','content':'profiles:\n  - name: tester\n    type: bearer\n    token_env: ACHILLES_TESTER_TOKEN\n'}).json()['id']
    bad=test.post('/api/control/jobs',headers=headers,json={'action':'auto-assess','specification_id':spec,'auth_config_id':auth,'secrets':{'OTHER_TOKEN':'not-allowed'}})
    assert bad.status_code==400,bad.text
    value='UNIQUE_SECRET_060705'
    good=test.post('/api/control/jobs',headers=headers,json={'action':'auto-assess','specification_id':spec,'auth_config_id':auth,'base_url':'http://127.0.0.1:8795','secrets':{'ACHILLES_TESTER_TOKEN':value}})
    assert good.status_code==200,good.text
    jid=good.json()['id']
    for _ in range(120):
        res=test.get('/api/jobs').json()
        if any(j['id']==jid and j['status']!='running' for j in res):break
        time.sleep(.05)
    assert any(j['id']==jid and j['status']=='complete' for j in res),res
    assert value not in json.dumps(test.get('/api/jobs').json())
    assert value not in json.dumps(test.get('/api/results/'+jid).json())
    for file in (tmp_path/'web').rglob('*'):
        if file.is_file():assert value.encode() not in file.read_bytes(),str(file)

def test_active_target_scope_cannot_be_bypassed(tmp_path):
    test,headers=client(tmp_path)
    spec=test.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(MINI)}).json()['id']
    result=test.post('/api/control/jobs',headers=headers,json={'action':'auto-assess','specification_id':spec,'execute':True,'acknowledgment':True,'base_url':'http://external.test','allow_host':'127.0.0.1'})
    assert result.status_code==400
