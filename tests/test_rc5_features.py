"""Test RC5: task help, retry due identità, piani AI e injection."""
from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from achillesapi.core.task_help_rc5 import task_help, PURPOSES
from achillesapi.core.registry_v090 import TOOLS, SUITE_ORDER
from achillesapi.core.injection_engine_rc5 import injection_assessment
from achillesapi.dashboard.server import create_app
import achillesapi.dashboard.control as control


SPEC = {
    'openapi':'3.0.3','info':{'title':'Indipendente','version':'1'},
    'paths':{
        '/organizations/{organization_id}/tickets/{ticket_id}':{'get':{
            'parameters':[
                {'name':'organization_id','in':'path','required':True,'schema':{'type':'string'}},
                {'name':'ticket_id','in':'path','required':True,'schema':{'type':'string'}}],
            'responses':{'200':{'description':'OK'}}}},
        '/search':{'get':{'parameters':[{'name':'term','in':'query','required':True,'schema':{'type':'string'}}],
                           'responses':{'200':{'description':'OK'}}}},
    },
}
AUTH={'profiles':[{'name':'owner','type':'bearer','token':'private-owner-token'},
                  {'name':'other','type':'bearer','token':'private-other-token'}]}


def build_suite(tmp_path, monkeypatch, action):
    monkeypatch.setattr(control, 'SUITE_ORDER', (action,))
    client=TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766')
    h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    def store(kind,obj):
        result=client.post('/api/import-text',headers=h,json={'kind':kind,'content':json.dumps(obj)})
        assert result.status_code==200,result.text
        return result.json()['id']
    spec=store('openapi',SPEC)
    auth=store('auth',AUTH)
    job=client.post('/api/control/suite',headers=h,json={
        'config':{'action':action,'specification_id':spec,'auth_config_id':auth,
                  'base_url':'https://training.example','allow_host':'training.example'}})
    assert job.status_code==200,job.text
    suite=job.json()['id']
    wait_suite(client,suite)
    return client,h,suite


def wait_suite(client,suite, timeout=18):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        data=client.get('/api/jobs/'+suite).json()
        if data['status']=='complete':return
        time.sleep(.08)
    raise AssertionError('Suite non terminata: '+str(data))


def test_explain_each_registered_tool():
    assert len(SUITE_ORDER)==65 and len(TOOLS)==67
    assert set(TOOLS)==set(PURPOSES)==set(SUITE_ORDER) | {'rc13-assess', 'rc15-scan'}
    assert 'due utenti' in task_help('access-probe')['purpose']
    for name in TOOLS:
        item=task_help(name)
        assert item['purpose'] and item['requires'] and item['interpretation']


def test_retry_access_probe_has_explicit_users_and_operation(tmp_path,monkeypatch):
    client,h,suite=build_suite(tmp_path,monkeypatch,'access-probe')
    report=client.get('/api/results/'+suite).json()
    assert report['steps'][0]['status']=='skipped'
    help_data=client.get('/api/job-view/'+suite).json()
    assert help_data['task_help_map']['access-probe']['requires']
    options=client.get(f'/api/control/suite/{suite}/prerequisites/0').json()
    assert options['builder']=='access-probe'
    assert sorted(options['auth_profiles'])==['other','owner']
    assert any(o['operation'].startswith('GET /organizations/') for o in options['operations'])
    invalid=client.post(f'/api/control/suite/{suite}/retry',headers=h,json={
        'step_index':0,'profiles':['owner','owner'], 'operation':'GET /organizations/{organization_id}/tickets/{ticket_id}',
        'path_values':['organization_id=acme','ticket_id=t100']})
    assert invalid.status_code in (422,400)
    launch=client.post(f'/api/control/suite/{suite}/retry',headers=h,json={
        'step_index':0,'profiles':['owner','other'], 'operation':'GET /organizations/{organization_id}/tickets/{ticket_id}',
        'path_values':['organization_id=acme','ticket_id=t100'], 'expected_other':'deny'})
    assert launch.status_code==200,launch.text
    wait_suite(client,suite)
    final=client.get('/api/results/'+suite).json()
    assert final['steps'][0]['status']=='complete',final['steps']
    child=final['steps'][0]['job_id']
    data=client.get('/api/results/'+child).json()
    assert data['owner']=='owner' and data['other']=='other'
    assert data['expected_other']=='deny' and data['status']=='dry_run'
    assert 'private-owner-token' not in json.dumps(data)


def test_ai_plan_guard_guided_generation_and_retry(tmp_path,monkeypatch):
    client,h,suite=build_suite(tmp_path,monkeypatch,'ai-plan-guard')
    opts=client.get(f'/api/control/suite/{suite}/prerequisites/0').json()
    assert opts['builder']=='ai-plan-guard' and 'security-inventory' in opts['allowed_actions']
    generation=client.post(f'/api/control/suite/{suite}/prerequisites/0/generate',headers=h,json={
        'actions':[{'action':'security-inventory'},{'action':'workflow-discover'}]})
    assert generation.status_code==200,generation.text
    document=generation.json()
    assert document['config_usage']=='proposals'
    launch=client.post(f'/api/control/suite/{suite}/retry',headers=h,json={
        'step_index':0,'config_id':document['id'],'config_usage':'proposals'})
    assert launch.status_code==200,launch.text
    wait_suite(client,suite)
    final=client.get('/api/results/'+suite).json()
    assert final['steps'][0]['status']=='complete',final
    result=client.get('/api/results/'+final['steps'][0]['job_id']).json()
    assert result['summary']['accepted']==2 and result['auto_executed'] is False


def test_injection_dry_run_no_network(tmp_path):
    path=tmp_path/'api.json';path.write_text(json.dumps(SPEC))
    result=injection_assessment(path,base_url='https://training.example',allow_hosts={'training.example'},
                                max_requests=6,execute=False)
    assert result['requests_sent']==0
    assert result['cases']
    assert result['confirmed_vulnerabilities']==0
    assert result['summary']['suspicious']==0


def test_injection_omits_sensitive_query(tmp_path):
    spec=json.loads(json.dumps(SPEC))
    spec['paths']['/secret']={'get':{'parameters':[{'name':'api_key','in':'query','schema':{'type':'string'}}],
                                   'responses':{'200':{'description':'ok'}}}}
    path=tmp_path/'api.json';path.write_text(json.dumps(spec))
    result=injection_assessment(path,base_url='https://training.example',allow_hosts={'training.example'},execute=False)
    assert not any(c['parameter']=='api_key' for c in result['cases'])


def test_token_not_shown_in_catalog_or_help(tmp_path):
    client=TestClient(create_app(tmp_path/'x'),base_url='http://127.0.0.1:8766')
    catalog=client.get('/api/control/tools').json()
    assert len(catalog)==67
    assert all(c['help']['purpose'] and c['help']['requires'] for c in catalog)
    assert 'private-owner-token' not in json.dumps(catalog)


def test_injection_dashboard_dry_run_is_real_cli_job(tmp_path):
    client=TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766')
    h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    spec=client.post('/api/import-text',headers=h,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    launch=client.post('/api/control/jobs',headers=h,json={
        'action':'injection-assess','specification_id':spec,
        'base_url':'https://training.example','allow_host':'training.example',
        'injection_families':['sql_error','sql_boolean'], 'max_requests':12})
    assert launch.status_code==200,launch.text
    child=launch.json()['id']
    end=time.monotonic()+15
    while time.monotonic()<end:
        job=client.get('/api/jobs/'+child).json()
        if job['status']!='running':break
        time.sleep(.08)
    assert job['status']=='complete',job
    result=client.get('/api/results/'+child).json()
    assert result['requests_sent']==0 and result['engine']=='achilles-injection-assessment-rc5'
    assert {c['family'] for c in result['cases']}=={'sql_error','sql_boolean'}
