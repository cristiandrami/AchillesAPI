"""Regression tests for dashboard, safe mutations and Agent v2."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.multi_resource import plan_multi_resource, run_multi_resource, MultiResourceError
from achillesapi.core.verification_v037 import verify_access_policies
from achillesapi.core.agent_v037 import agent_v2_plan
from achillesapi.core.openapi import analyze_openapi_file
from achillesapi.dashboard.server import create_app
from test_v034 import sample,manifest


def prepared(tmp_path):
    spec=sample()
    spec['paths']['/collections/{collection_ref}']['patch']={
        'operationId':'changeParent','parameters':[{'in':'path','name':'collection_ref',
         'required':True,'schema':{'type':'string'}}],
        'requestBody':{'content':{'application/json':{'schema':{
            'type':'object','properties':{'note':{'type':'string'}}}}}},
        'responses':{'200':{'description':'updated'}}}
    f=tmp_path/'sample.json';f.write_text(json.dumps(spec))
    cfg=manifest();cfg['resources'][0]['mutations']=[{'operation':'PATCH /collections/{collection_ref}',
                                                       'body':{'note':'checked'}}]
    return spec,analyze_openapi_file(f),cfg


def test_mutation_budget_and_preflight(tmp_path):
    spec,api,cfg=prepared(tmp_path)
    planned=plan_multi_resource(api,spec,cfg,{'owner','other'})
    assert planned['request_budget_required']==14
    assert planned['resources'][0]['mutation_checks']==1
    unsafe=manifest();unsafe['resources'][0]['mutations']=[{'operation':'PATCH /collections/{collection_ref}',
        'body':{'label':'overwrite marker'}}]
    with pytest.raises(MultiResourceError):plan_multi_resource(api,spec,unsafe,{'owner','other'})
    unsafe=manifest();unsafe['resources'][0]['mutations']=[{'operation':'PATCH /collections/{collection_ref}',
        'body':{'note':'${document.id}'}}]
    with pytest.raises(MultiResourceError):plan_multi_resource(api,spec,unsafe,{'owner','other'})


def test_real_http_mutation_with_verified_cleanup(tmp_path):
    spec,api,cfg=prepared(tmp_path)
    cfg['resources']=cfg['resources'][:1]
    state={'record':None,'patches':0,'deletes':0}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def answer(self,status,data=None):
            encoded=json.dumps(data).encode() if data is not None else b''
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(encoded)));self.end_headers();self.wfile.write(encoded)
        def readbody(self):return json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        def do_POST(self):
            state['record']={'id':'col-1',**self.readbody()};self.answer(201,{'id':'col-1'})
        def do_GET(self):self.answer(200,state['record']) if state['record'] else self.answer(404)
        def do_PATCH(self):
            state['record'].update(self.readbody());state['patches']+=1;self.answer(200,state['record'])
        def do_DELETE(self):state['deletes']+=1;state['record']=None;self.answer(204)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        result=run_multi_resource(api,spec,cfg,base_url=f'http://127.0.0.1:{server.server_port}',
            allowed_hosts={'127.0.0.1'},identities={'owner':AuthenticationMaterial(),
            'other':AuthenticationMaterial()},execute=True,approve_writes=True,
            allow_insecure_http=True,max_requests=20,rate=10)
        assert result['requests_sent']==9  # 5 baseline+cleanup, one access, three mutation
        assert result['resources_results'][0]['cleanup_verified']
        assert state['patches']==1 and state['deletes']==1
    finally:
        server.shutdown();server.server_close();thread.join(2)


def test_access_policy_differentials():
    saved={'execution_report':{'observations':[{'operation':'GET /items/{id}',
        'identity':'bob','status':200}]}}
    rules=[{'operation':'GET /items/{id}','identity':'bob','expected':'deny'},
           {'operation':'GET /items/{id}','identity':'alice','expected':'allow'}]
    result=verify_access_policies(saved,rules)
    assert result['review_count']==1
    assert result['confirmed_vulnerabilities']==0
    assert result['results'][1]['classification'].startswith('inconclusive')


def test_agent_v2_does_not_invent_action(tmp_path):
    spec,api,cfg=prepared(tmp_path)
    result=agent_v2_plan(api,{'operations':[]},[{'operation':'POST /collections',
                                    'check':'baseline','status':503,'identity':'owner'}])
    assert result['actions']==[] and result['model_authorizes_requests'] is False


def test_dashboard_upload_plan_and_scope(tmp_path):
    app=create_app(tmp_path/'ui')
    client=TestClient(app,base_url="http://127.0.0.1")
    assert client.get('/').status_code==200
    token=client.get('/api/bootstrap').json()['csrf_token']
    assert client.post('/api/upload',files={'file':('api.yaml','nope')}).status_code==403
    spec=sample()
    response=client.post('/api/upload',headers={'x-achilles-token':token},
        files={'file':('api.json',json.dumps(spec).encode(),'application/json')})
    assert response.status_code==200,response.text
    sid=response.json()['id']
    assert client.get('/api/summary/'+sid).json()['operations']==6
    unauthorized=client.post('/api/jobs',headers={'x-achilles-token':token},json={
        'specification_id':sid,'execute':True,'base_url':'https://outside.test',
        'allow_host':'inside.test'})
    assert unauthorized.status_code==400
    with patch('achillesapi.dashboard.server.subprocess.run') as run:
        def execute_fake(args,**kwargs):
            out=Path(args[args.index('--output')+1]);out.write_text('{"plan":{"operations":[]}}')
            from subprocess import CompletedProcess
            return CompletedProcess(args,0,'','')
        run.side_effect=execute_fake
        started=client.post('/api/jobs',headers={'x-achilles-token':token},json={'specification_id':sid})
        assert started.status_code==200,started.text
        import time
        jid=started.json()['id']
        for _ in range(30):
            if client.get('/api/jobs/'+jid).json()['status']!='running':break
            time.sleep(.02)
        assert client.get('/api/jobs/'+jid).json()['status']=='complete'
        assert client.get('/api/results/'+jid).json()['plan']['operations']==[]


def test_dashboard_rejects_cross_origin_and_host_rebinding(tmp_path):
    client=TestClient(create_app(tmp_path/'ui'),base_url='http://127.0.0.1')
    token=client.get('/api/bootstrap').json()['csrf_token']
    denied=client.post('/api/upload',headers={'x-achilles-token':token,
            'Origin':'https://evil.example'},files={'file':('bad.yaml','test')})
    assert denied.status_code==403
    different_port=client.post('/api/upload',headers={'x-achilles-token':token,
            'Origin':'http://127.0.0.1:9999'},files={'file':('bad.yaml','test')})
    assert different_port.status_code==403
    rebound=client.get('/api/bootstrap',headers={'Host':'outside.example'})
    assert rebound.status_code==403


def test_dashboard_export_escapes_html(tmp_path):
    from achillesapi.reporting.professional import write_professional_report
    original=tmp_path/'scan.json'
    original.write_text(json.dumps({'plan':{'operations':[]},
        'execution_report':{'findings':[{'category':'CORS','operation':'GET /<script>alert(1)</script>',
        'explanation':'<script>alert(1)</script>'}]}}))
    paths=write_professional_report(original,tmp_path/'out',('html','json'))
    html=next(x for x in paths if x.suffix=='.html').read_text()
    assert '<script>alert(1)</script>' not in html
