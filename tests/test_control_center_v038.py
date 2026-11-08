"""Control-center regression: test real CLI jobs, safeguards and demo startup."""
from __future__ import annotations
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app


def dashboard():
    root=TemporaryDirectory()
    client=TestClient(create_app(root.name),base_url='http://127.0.0.1:8766')
    token=client.get('/api/bootstrap').json()['csrf_token']
    headers={'x-achilles-token':token}
    return root,client,headers


def poll(client,ident):
    for _ in range(120):
        job=client.get('/api/jobs/'+ident).json()
        if job['status']!='running':return job
        time.sleep(.1)
    raise AssertionError('Job did not complete')


def test_catalog_and_demo_import():
    tmp,c,h=dashboard()
    with tmp:
        tools=c.get('/api/control/tools').json()
        assert len(tools)>=25
        assert any(x['name']=='multi-resource-assess' for x in tools)
        demo=c.post('/api/control/demo/load',headers=h)
        assert demo.status_code==200
        assert c.get('/api/summary/'+demo.json()['specification_id']).json()['operations']>=12
        assert c.post('/api/control/demo/load').status_code==403


def test_offline_runner_uses_real_cli():
    tmp,c,h=dashboard()
    with tmp:
        demo=c.post('/api/control/demo/load',headers=h).json()
        for action in ('analyze-openapi','workflow-map','auto-assess'):
            config={'action':action,'specification_id':demo['specification_id'],
                    'base_url':demo['base_url'],'allow_host':demo['allow_host']}
            r=c.post('/api/control/jobs',headers=h,json=config)
            assert r.status_code==200,r.text
            job=poll(c,r.json()['id'])
            assert job['status']=='complete',job
            assert c.get('/api/results/'+job['id']).status_code==200


def test_block_unapproved_execution_and_writes():
    tmp,c,h=dashboard()
    with tmp:
        demo=c.post('/api/control/demo/load',headers=h).json()
        initial={'action':'multi-resource-assess','specification_id':demo['specification_id'],
              'config_id':demo['config_id'],'auth_config_id':demo['auth_id'],
              'base_url':'http://127.0.0.1:8795','allow_host':'127.0.0.1',
              'execute':True,'allow_insecure_http':True}
        assert c.post('/api/control/jobs',headers=h,json=initial).status_code==400
        initial['acknowledgment']=True
        assert c.post('/api/control/jobs',headers=h,json=initial).status_code==400
        initial['approve_writes']=True
        initial['base_url']='http://example.org'
        assert c.post('/api/control/jobs',headers=h,json=initial).status_code==400
        initial['base_url']='https://example.org'
        assert c.post('/api/control/jobs',headers=h,json=initial).status_code==400


def test_no_shell_and_untrusted_values():
    tmp,c,h=dashboard()
    with tmp:
        demo=c.post('/api/control/demo/load',headers=h).json()
        bad={'action':'bash -c malicious','specification_id':demo['specification_id']}
        assert c.post('/api/control/jobs',headers=h,json=bad).status_code==400
        bad={'action':'auto-assess','specification_id':demo['specification_id'],
             'path_values':['id=123\n--execute']}
        assert c.post('/api/control/jobs',headers=h,json=bad).status_code==400
        assert c.post('/api/control/services/lab/start',headers={'origin':'https://evil.test',**h}).status_code==403


def test_lab_start_and_live_multiresource_cleanup():
    tmp,c,h=dashboard()
    with tmp:
        demo=c.post('/api/control/demo/load',headers=h).json()
        start=c.post('/api/control/services/lab/start',headers=h)
        assert start.status_code==200,start.text
        try:
            for _ in range(60):
                status=c.get('/api/control/services').json()
                if status['lab']=='online':break
                time.sleep(.15)
            assert status['lab']=='online',status
            config={'action':'multi-resource-assess','specification_id':demo['specification_id'],
                    'auth_config_id':demo['auth_id'],'config_id':demo['config_id'],
                    'base_url':demo['base_url'],'allow_host':demo['allow_host'],
                    'execute':True,'approve_writes':True,'acknowledgment':True,
                    'max_requests':60,'rate':5,'allow_insecure_http':True}
            created=c.post('/api/control/jobs',headers=h,json=config)
            assert created.status_code==200,created.text
            task=poll(c,created.json()['id'])
            assert task['status']=='complete',task
            report=c.get('/api/results/'+task['id']).json()
            assert report['requests_sent']>=10
            assert report['manual_cleanup_required'] is False
            assert len(report['resources_results'])==2
        finally:
            c.post('/api/control/services/lab/stop',headers=h)
