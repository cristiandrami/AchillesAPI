"""RC25 regressions: per-CLI budgets, multi-fixture suite and retry identity wizard."""
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

import achillesapi.dashboard.control as control
from achillesapi.dashboard.control import cli_request_budget
from achillesapi.dashboard.server import create_app
from test_v034 import sample, manifest


def upload(client, headers, kind, content):
    res = client.post('/api/import-text', headers=headers, json={
        'kind':kind, 'content':json.dumps(content), 'name':kind+'.json'})
    assert res.status_code == 200, res.text
    return res.json()['id']


def test_cli_max_request_bounds_for_access_probe():
    assert cli_request_budget('access-probe', 125) == 100
    assert cli_request_budget('access-probe', 150) == 100
    assert cli_request_budget('access-probe', 2) == 2
    assert cli_request_budget('access-probe', 1) == 2
    assert cli_request_budget('rc16-access-auto', 125) == 125
    assert cli_request_budget('rc16-access-auto', 150) == 150


def test_rc16_retry_contract_exposes_auth_upload_and_profiles(tmp_path):
    with TestClient(create_app(tmp_path/'retry'), base_url='http://127.0.0.1:8766') as client:
        headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        spec=upload(client,headers,'openapi',sample())
        auth=upload(client,headers,'auth',{'profiles':[
            {'name':'owner','type':'bearer','token':'test-owner'},
            {'name':'other','type':'bearer','token':'test-other'}]})
        # An unconfigured suite still records RC16 GET as skipped, with a retry.
        import achillesapi.dashboard.control as module
        original=module.SUITE_ORDER
        module.SUITE_ORDER=('rc16-access-auto',)
        try:
            start=client.post('/api/control/suite',headers=headers,json={
                'config':{'action':'auto-assess','specification_id':spec,
                           'base_url':'http://127.0.0.1:8797','allow_host':'127.0.0.1'}})
            assert start.status_code==200,start.text
            identifier=start.json()['id']
            for _ in range(100):
                state=client.get('/api/jobs/'+identifier).json()
                if state['status']=='complete':break
                time.sleep(.05)
            assert state['status']=='complete',state
            res=client.get(f'/api/control/suite/{identifier}/prerequisites/0')
            assert res.status_code==200,res.text
            contract=res.json()['retry_requirements']
            assert contract['needs_auth'] is True
            assert contract['has_auth'] is False
            assert 'auth_profiles' not in res.json()
            selected=client.get(f'/api/control/suite/{identifier}/prerequisites/0',params={'auth_config_id':auth})
            assert selected.status_code==200,selected.text
            assert set(selected.json()['auth_profiles'])=={'owner','other'}
        finally:
            module.SUITE_ORDER=original


def test_suite_schedules_each_approved_resource_separately(tmp_path, monkeypatch):
    monkeypatch.setattr(control, 'SUITE_ORDER', ('rc16-assess',))
    with TestClient(create_app(tmp_path/'suite'),base_url='http://127.0.0.1:8766') as client:
        headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        spec=upload(client,headers,'openapi',sample())
        auth=upload(client,headers,'auth',{'profiles':[
            {'name':'owner','type':'bearer','token':'test-owner'},
            {'name':'other','type':'bearer','token':'test-other'}]})
        first=manifest()
        first['resources']=first['resources'][:1]
        second=json.loads(json.dumps(first))
        second['resources'][0]['name']='collection_second'
        second['resources'][0]['body']['label']='approved_second'
        second['resources'][0]['path_values']={'collection_ref':'${collection_second.id}'}
        config1=upload(client,headers,'config',first)
        config2=upload(client,headers,'config',second)
        resp=client.post('/api/control/suite',headers=headers,json={
            'workflow_config_ids':[config1,config2],
            'include_active':True,'include_writes':True,'include_ai':False,
            'max_total_requests':100,'max_runtime_seconds':180,
            'config':{'action':'auto-assess','specification_id':spec,'auth_config_id':auth,
                      'config_id':config1,'config_usage':'multi-resource',
                      'base_url':'http://127.0.0.1:9998','allow_host':'127.0.0.1',
                      'acknowledgment':True,'approve_writes':True,'allow_insecure_http':True,
                      'profiles':['other'],'expected_other':'deny','max_requests':30}})
        assert resp.status_code==200,resp.text
        job=resp.json()['id']
        for _ in range(300):
            state=client.get('/api/jobs/'+job).json()
            if state['status']=='complete':break
            time.sleep(.08)
        assert state['status']=='complete',state
        report=client.get('/api/results/'+job).json()
        steps=report['steps']
        assert report['workflow_campaign']['requested']==2
        assert report['summary']['total']==2
        assert [step['workflow_config_id'] for step in steps]==[config1,config2]
        assert all(step['action']=='rc16-assess' for step in steps)
        assert all(step['status'] in {'failed','complete','skipped'} for step in steps)
        assert all(step.get('job_id') or step.get('reason') for step in steps)
        # The serialized manifest (including cleanup) is not silently replaced
        # by a single combined fixture. Distinct child job IDs are recorded.
        child_ids=[x.get('job_id') for x in steps if x.get('job_id')]
        assert len(set(child_ids))==len(child_ids)
        assert report['summary']['total']==len(steps)


def test_rc25_browser_retry_and_multiflow_present():
    root=Path(__file__).resolve().parents[1]/'src/achillesapi/dashboard/static'
    app=(root/'app.js').read_text(encoding='utf-8')
    viewer=(root/'job-viewer.js').read_text(encoding='utf-8')
    assert "workflow_config_ids:ready.workflow_config_ids||[]" in app
    assert "savedWorkflows.filter(w=>w.specId===specId)" in app
    assert 'async function refreshRetryProfiles(authId)' in viewer
    assert "step.action==='rc16-access-auto'" in viewer
    assert "step.action==='rc16-assess'" in viewer
    assert 'Operazioni di scrittura senza cleanup sicuro' in app
    assert 'workflowExpectedPolicy=optionSelect(' in viewer
    assert "if(!['deny','allow'].includes(workflowExpectedPolicy?.value))" in viewer


def test_retry_rc16_get_after_uploading_auth_yaml(tmp_path, monkeypatch):
    monkeypatch.setattr(control,'SUITE_ORDER',('rc16-access-auto',))
    with TestClient(create_app(tmp_path/'retry-live'),base_url='http://127.0.0.1:8766') as client:
        h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        spec=upload(client,h,'openapi',sample())
        auth=upload(client,h,'auth',{'profiles':[
            {'name':'owner','type':'bearer','token':'test-owner'},
            {'name':'other','type':'bearer','token':'test-other'}]})
        response=client.post('/api/control/suite',headers=h,json={
            'config':{'action':'auto-assess','specification_id':spec,
                      'base_url':'http://127.0.0.1:8797','allow_host':'127.0.0.1'}})
        assert response.status_code==200,response.text
        job=response.json()['id']
        for _ in range(150):
            current=client.get('/api/jobs/'+job).json()
            if current['status']=='complete':break
            time.sleep(.04)
        assert current['status']=='complete'
        result=client.post(f'/api/control/suite/{job}/retry',headers=h,json={
            'step_index':0,'auth_config_id':auth,'profiles':['owner','other'],
            'expected_other':'deny','path_values':['collection_ref=approved-id'],
            'enable_active':False,'acknowledgment':False,'allow_insecure_http':True})
        assert result.status_code==200,result.text
        for _ in range(200):
            current=client.get('/api/jobs/'+job).json()
            if current['status']=='complete':break
            time.sleep(.05)
        assert current['status']=='complete',current
        report=client.get('/api/results/'+job).json()
        assert report['steps'][0]['status']=='complete',report['steps'][0]
        assert report['steps'][0]['job_id']
        assert report['summary']['completed']==1


def test_access_probe_max_requests_125_no_cli_parser_failure(tmp_path):
    with TestClient(create_app(tmp_path/'budget'),base_url='http://127.0.0.1:8766') as client:
        h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        spec=upload(client,h,'openapi',sample())
        auth=upload(client,h,'auth',{'profiles':[
            {'name':'owner','type':'bearer','token':'test-owner'},
            {'name':'other','type':'bearer','token':'test-other'}]})
        result=client.post('/api/control/jobs',headers=h,json={
            'action':'access-probe','specification_id':spec,'auth_config_id':auth,
            'base_url':'http://127.0.0.1:8797','allow_host':'127.0.0.1',
            'profiles':['owner','other'],'operation':'GET /collections/{collection_ref}',
            'expected_other':'deny','path_values':['collection_ref=approved-id'],
            'max_requests':125,'execute':False,'allow_insecure_http':True})
        assert result.status_code==200,result.text
        job=result.json()['id']
        for _ in range(200):
            state=client.get('/api/jobs/'+job).json()
            if state['status'] not in ('running','orchestrating'):break
            time.sleep(.04)
        assert state['status']=='complete',state
        assert 'not in the range' not in str(state)
