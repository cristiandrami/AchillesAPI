"""Guarantee the dashboard treats an API under test as an external system."""
from __future__ import annotations
import json
import time
from tempfile import TemporaryDirectory
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app

SPEC={"openapi":"3.0.3","info":{"title":"External API","version":"1.0"},
      "paths":{"/health":{"get":{"responses":{"200":{"description":"OK"}}}}}}

def client():
    temp=TemporaryDirectory()
    c=TestClient(create_app(temp.name),base_url='http://127.0.0.1:8766')
    headers={'x-achilles-token':c.get('/api/bootstrap').json()['csrf_token']}
    return temp,c,headers

def load_spec(c,h):
    response=c.post('/api/upload',headers=h,files={'file':('external.json',json.dumps(SPEC),'application/json')})
    assert response.status_code==200,response.text
    return response.json()['id']

def wait_for(c,ident):
    for _ in range(100):
        job=c.get('/api/jobs/'+ident).json()
        if job['status']!='running':return job
        time.sleep(.1)
    raise AssertionError('Task did not finish')

def test_no_lab_specific_endpoints_or_controls():
    tmp,c,h=client()
    with tmp:
        assert c.post('/api/control/demo/load',headers=h).status_code==404
        assert c.post('/api/control/services/lab/start',headers=h).status_code==404
        assert c.post('/api/control/services/lab/stop',headers=h).status_code==404
        page=c.get('/').text
        assert 'startAll' not in page and 'labStart' not in page and 'loadDemo' not in page
        assert 'http://127.0.0.1:8795/docs' not in page
        assert c.get('/api/control/tools').status_code==200
        state=c.get('/api/control/services').json()
        assert 'lab' not in state and 'ollama' in state

def test_generic_openapi_upload_and_cli_dry_runs():
    tmp,c,h=client()
    with tmp:
        spec_id=load_spec(c,h)
        assert c.get('/api/summary/'+spec_id).json()['operations']==1
        for action in ('analyze-openapi','auto-assess','workflow-map'):
            response=c.post('/api/control/jobs',headers=h,json={
                'action':action,'specification_id':spec_id,
                'base_url':'http://127.0.0.1:8795','allow_host':'127.0.0.1'})
            assert response.status_code==200,response.text
            item=wait_for(c,response.json()['id'])
            assert item['status']=='complete',item
            assert c.get('/api/results/'+item['id']).status_code==200

def test_scope_guards_unapproved_active_jobs():
    tmp,c,h=client()
    with tmp:
        spec_id=load_spec(c,h)
        base={'action':'auto-assess','specification_id':spec_id,
              'base_url':'https://example.org','allow_host':'example.org','execute':True}
        assert c.post('/api/control/jobs',headers=h,json=base).status_code==400
        base['acknowledgment']=True
        base['allow_host']='other.example'
        assert c.post('/api/control/jobs',headers=h,json=base).status_code==400
        base['allow_host']='example.org'
        base['action']='rm -rf /'
        assert c.post('/api/control/jobs',headers=h,json=base).status_code==400

def test_no_lab_credentials_injected_into_assessment_worker():
    from inspect import getsource
    from achillesapi.dashboard.control import register_control_routes
    code=getsource(register_control_routes)
    assert 'ACHILLES_LAB_OWNER' not in code
    assert 'labs.control_center_api' not in code
    assert '/api/control/demo/load' not in code
