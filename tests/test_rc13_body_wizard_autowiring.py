"""RC13 JSON PATCH uses the existing resources.yaml wizard, no extra YAML."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml
from fastapi.testclient import TestClient

from achillesapi.core.pipeline_rc13 import create_plan, execute_pipeline, PipelineError
from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.rc13_bridge import rc13_command
from achillesapi.dashboard.control import ToolRequest

SPEC = {
    'openapi': '3.0.3', 'info': {'title': 'Generic Test Resource API', 'version': '1'},
    'paths': {
      '/items': {'post': {'requestBody': {'content': {'application/json': {
        'schema': {'type':'object', 'properties': {'label': {'type':'string', 'maxLength':128}}}}}},
        'responses': {'201': {'description':'created'}}}},
      '/items/{item_id}': {'parameters':[{'name':'item_id', 'in':'path', 'required':True,
        'schema':{'type':'string'}}],
        'get': {'responses': {'200': {'description':'ok'},'404': {'description':'missing'}}},
        'patch': {'requestBody': {'content': {'application/json': {
          'schema': {'type':'object', 'properties': {'role':{'type':'string'}, 'counter':{'type':'integer'}}}}}},
          'responses': {'200': {'description':'patched'}}},
        'delete': {'responses': {'204': {'description':'deleted'}}}}}}
MANIFEST = {'resources':[{
    'name':'asset', 'create':'POST /items', 'read':'GET /items/{item_id}',
    'delete':'DELETE /items/{item_id}', 'identity':'owner',
    'body':{'label':'achilles-fixture'}, 'marker_field':'label',
    'marker_pointer':'/label', 'id_pointer':'/id', 'read_id_pointer':'/id',
    'path_values':{'item_id':'${asset.id}'},
    'mutations':[{'operation':'PATCH /items/{item_id}',
                  'body':{'role':'operator', 'counter':7}}]
}]}


def fixture_files(tmp_path):
    spec=tmp_path/'spec.json';spec.write_text(json.dumps(SPEC))
    auth=tmp_path/'auth.yaml';auth.write_text('profiles:\n  - name: owner\n    type: bearer\n    token: unit-test-only\n')
    manifest=tmp_path/'resource.yaml';manifest.write_text(yaml.safe_dump(MANIFEST))
    return spec, auth, manifest


def test_wizard_lists_approved_fields_without_network(tmp_path):
    spec,auth,manifest=fixture_files(tmp_path)
    plan=create_plan(spec,auth_config=auth,workflow_config=manifest)
    assert plan['test_types']['disposable_workflows']['available']
    assert [x['key'] for x in plan['body_probe_options']] == ['asset:0:role']
    assert plan['test_types']['body_injection']['available']
    assert plan['body_probe_plan']['cases']==[]
    selected=create_plan(spec,auth_config=auth,workflow_config=manifest,
                         body_probe_fields=['asset:0:role'])
    assert len(selected['body_probe_plan']['cases'])==2
    assert selected['body_probe_plan']['request_budget_required'] >= 16
    with pytest.raises(ValueError, match='non appartiene'):
        create_plan(spec,auth_config=auth,workflow_config=manifest,
                    body_probe_fields=['asset:0:counter'])


def test_dashboard_returns_choices_and_cli_uses_same_manifest(tmp_path):
    spec,auth,manifest=fixture_files(tmp_path)
    with TestClient(create_app(tmp_path/'dashboard'),base_url='http://127.0.0.1:8766') as client:
        token=client.get('/api/bootstrap').json()['csrf_token']
        head={'x-achilles-token':token}
        def upload(kind,content,name):
            response=client.post('/api/import-text',headers=head,json={
                'kind':kind,'content':content,'name':name})
            assert response.status_code==200,response.text
            return response.json()['id']
        sid=upload('openapi',spec.read_text(),'demo.json')
        aid=upload('auth',auth.read_text(),'auth.yaml')
        mid=upload('config',manifest.read_text(),'resources.yaml')
        cfg={'action':'auto-assess','specification_id':sid,
             'auth_config_id':aid,'config_id':mid,'config_usage':'multi-resource'}
        result=client.post('/api/control/rc13/body-fields',headers=head,json=cfg)
        assert result.status_code==200,result.text
        assert [x['key'] for x in result.json()['fields']]==['asset:0:role']
        result=client.post('/api/control/rc13/plan',headers=head,json=cfg)
        assert result.status_code==200,result.text
        assert result.json()['body_probe_options'][0]['field']=='role'
        cfg_obj=ToolRequest.model_validate(cfg)
        cmd=rc13_command(cfg_obj,lambda v,suffix: spec if v==sid else auth,
                         lambda x:manifest,active=True,writes=True,body_probes=True,
                         ai=False,max_requests=100,output=tmp_path/'out.json',
                         body_probe_fields=['asset:0:role'])
        assert cmd.count('--workflow-config')==1
        assert cmd[cmd.index('--body-probe-field')+1]=='asset:0:role'


def test_full_http_lifecycle_and_cleanup(tmp_path):
    spec,auth,manifest=fixture_files(tmp_path)
    records={};events=[]
    class Handler(BaseHTTPRequestHandler):
        def send(self,code,data=None):
            self.send_response(code)
            self.send_header('content-type','application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data or {}).encode())
        def read(self):
            n=int(self.headers.get('content-length','0'))
            return json.loads(self.rfile.read(n) or b'{}')
        def do_POST(self):
            assert self.path=='/items'
            item_id='unit-'+str(len(events))
            body=self.read()
            records[item_id]={'id':item_id,**body}
            events.append(('POST',item_id))
            self.send(201,{'id':item_id})
        def do_GET(self):
            item_id=self.path.split('/')[-1]
            if item_id in records:self.send(200,records[item_id])
            else:self.send(404,{'error':'missing'})
        def do_PATCH(self):
            item_id=self.path.split('/')[-1]
            if item_id not in records:return self.send(404)
            data=self.read()
            records[item_id].update(data)
            events.append(('PATCH',item_id,data['role']))
            self.send(200,records[item_id])
        def do_DELETE(self):
            item_id=self.path.split('/')[-1]
            if item_id in records:
                del records[item_id]
                events.append(('DELETE',item_id))
                self.send(204)
            else:self.send(404)
        def log_message(self,*args):pass
    service=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    worker=threading.Thread(target=service.serve_forever,daemon=True);worker.start()
    try:
        base_url=f'http://127.0.0.1:{service.server_address[1]}'
        kwargs={'base_url':base_url,'allowed_hosts':{'127.0.0.1'},
                'auth_config':auth,'profile':'owner','workflow_config':manifest,
                'execute':True,'allow_insecure_http':True,'max_requests':110,'rate':5,
                'approve_writes':True, 'body_probes':True,
                'body_probe_fields':['asset:0:role']}
        with pytest.raises(PipelineError,match='approvazioni'):
            execute_pipeline(spec,approve_body_probes=False,**kwargs)
        assert records=={} and events==[]
        report=execute_pipeline(spec,approve_body_probes=True,**kwargs)
        probes=report['stages']['body_probes']
        assert probes['executed'] and len(probes['results'])==2
        assert all(x['cleanup_verified'] for x in probes['results'])
        assert not report['manual_cleanup_required']
        assert records=={}
        assert len([e for e in events if e[0]=='POST'])==3
        assert len([e for e in events if e[0]=='DELETE'])==3
        assert {'\'', '{{7*7}}'}=={x['payload'] for x in probes['results']}
        assert report['requests_sent']<=110
    finally:
        service.shutdown();service.server_close();worker.join(timeout=2)


def test_rc13_ai_status_visible_without_hallucinated_analysis():
    from achillesapi.dashboard.job_view import viewer_payload, ai_dossier_entry
    raw={'engine':'achilles-rc13-campaign','findings':[],
         'ai':{'status':'failed','message':'Ollama non raggiungibile'},
         'coverage':{'coverage_not_a_security_score':True}}
    view=viewer_payload(raw,job_id='a'*32,action='rc13-assess')
    assert view['ai'][0]['data']['status']=='failed'
    entry=ai_dossier_entry(raw,action='rc13-assess',job_id='a'*32,ai_status='failed')
    assert any(s['name']=='rc13_ollama_status' for s in entry['sections'])
    assert not any(s['name']=='rc13_local_ollama_analysis' for s in entry['sections'])


def test_rc13_is_a_regular_selectable_dashboard_task(tmp_path):
    with TestClient(create_app(tmp_path/'app'),base_url='http://127.0.0.1:8766') as client:
        token=client.get('/api/bootstrap').json()['csrf_token']
        head={'x-achilles-token':token}
        registry=client.get('/api/control/tools').json()
        assert any(t['name']=='rc13-assess' for t in registry)
        resp=client.post('/api/import-text',headers=head,json={
            'kind':'openapi','name':'api.json','content':json.dumps(SPEC)})
        assert resp.status_code==200
        config={'action':'rc13-assess','specification_id':resp.json()['id']}
        result=client.post('/api/control/jobs',headers=head,json=config)
        assert result.status_code==200,result.text
        import time
        for _ in range(100):
            job=client.get('/api/jobs/'+result.json()['id']).json()
            if job['status'] not in {'running','orchestrating'}:break
            time.sleep(.1)
        assert job['status']=='complete',job
        raw=client.get('/api/results/'+result.json()['id']).json()
        assert raw['engine']=='achilles-rc13-campaign'
        assert raw['requests_sent']==0
        view=client.get('/api/job-view/'+result.json()['id']).json()
        assert view['ai'][0]['data']['status']=='not_invoked_offline'
