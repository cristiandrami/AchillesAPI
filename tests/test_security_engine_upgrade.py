"""Regression and negative safety cases for the security engine upgrade."""
from __future__ import annotations

import json
import threading
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from achillesapi.core.active_scanners_rc15 import scan_bounded_get
from achillesapi.core.agent_adaptive_v3 import allowed_agent_decisions
from achillesapi.core.auth import AuthenticationFile, AuthenticationManager, AuthenticationConfigError
from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.core.multi_resource import MultiResourceError, plan_multi_resource
from achillesapi.core.openapi import load_openapi, parse_openapi, OpenAPIParseError
from achillesapi.core.verification_replay import replay_readonly_indicators


@pytest.fixture
def server():
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, data=b'ok', extra=None):
            self.send_response(status)
            for k,v in (extra or {}).items(): self.send_header(k,v)
            self.end_headers()
            self.wfile.write(data)
        def do_GET(self):
            query = parse_qs(urlsplit(self.path).query)
            requests.append(('GET',self.path,b''))
            if urlsplit(self.path).path == '/redirect':
                val = query.get('next_url',[''])[0]
                if val.startswith('https://'):
                    return self.respond(302, b'', {'Location': val})
                return self.respond(200)
            if urlsplit(self.path).path == '/reflect':
                return self.respond(200, query.get('q',[''])[0].encode())
            return self.respond(200)
        def do_POST(self):
            content = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            requests.append(('POST',self.path,content))
            self.respond(200)
        def log_message(self,*args): pass
    svc = ThreadingHTTPServer(('127.0.0.1',0), Handler)
    thread=threading.Thread(target=svc.serve_forever,daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{svc.server_address[1]}', requests
    finally:
        svc.shutdown();svc.server_close();thread.join(timeout=2)


def test_external_local_ref_resolved_without_network(tmp_path):
    (tmp_path/'schemas.yaml').write_text('components:\n  schemas:\n    Thing:\n      type: object\n      properties:\n        value:\n          type: string\n')
    source=tmp_path/'spec.yaml'
    source.write_text('''openapi: 3.0.3
info: {title: Example, version: "1"}
paths:
  /objects:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: 'schemas.yaml#/components/schemas/Thing'}
      responses:
        '200': {description: ok}
''')
    spec=load_openapi(source, validate=False)
    schema=spec['paths']['/objects']['post']['requestBody']['content']['application/json']['schema']
    assert schema['properties']['value']['type']=='string'
    assert parse_openapi(spec).title == 'Example'


def test_external_ref_rejects_network_traversal_and_cycle(tmp_path):
    base={'openapi':'3.0.3','info':{'title':'x','version':'1'},
          'paths':{'/x':{'get':{'responses':{'200':{'description':'ok',
             'content':{'application/json':{'schema':{'$ref':'https://host/s.yaml'}}}}}}}}}
    p=tmp_path/'openapi.json'
    for ref in ('https://host/s.yaml','../topsecret.yaml','loop.yaml#/schema'):
        base['paths']['/x']['get']['responses']['200']['content']['application/json']['schema']['$ref']=ref
        p.write_text(json.dumps(base))
        if ref.startswith('loop'):
            (tmp_path/'loop.yaml').write_text('schema: {$ref: "loop.yaml#/schema"}')
        with pytest.raises(OpenAPIParseError): load_openapi(p,validate=False)


def test_http_form_xml_and_binary_bounded(server):
    url, requests = server
    client=SafeHTTPClient(allowed_hosts={'127.0.0.1'},allowed_methods={'GET','POST'},
                          max_requests=5,requests_per_second=10)
    for kwargs in ({'form_body': {'item':'hello'}},
                   {'xml_body':'<probe><value>ok</value></probe>'},
                   {'binary_body':b'abc','binary_content_type':'application/octet-stream'}):
        output=client.request('POST',url+'/upload',execute=True,**kwargs)
        assert output.response.status_code==200
    assert len(requests)==3
    assert requests[0][2]==b'item=hello'
    assert b'<value>ok</value>' in requests[1][2]
    assert requests[2][2]==b'abc'
    with pytest.raises(ScopeError):
        client.request('POST',url,execute=False,xml_body='<!DOCTYPE x [<!ENTITY a "foo">]><x>&a;</x>')
    with pytest.raises(ScopeError):
        client.request('POST',url,execute=False,binary_body=b'x'*16385,binary_content_type='application/octet-stream')
    with pytest.raises(ScopeError):
        client.request('POST',url,execute=False,form_body={'a':'1'},json_body={'a':'1'})


def test_multipart_upload_transport_only_accepts_safe_test_files(server):
    url, requests = server
    client = SafeHTTPClient(allowed_hosts={'127.0.0.1'},allowed_methods={'POST'},
                            max_requests=2,requests_per_second=10)
    probe = {'upload': ('probe.txt',b'harmless test data','text/plain')}
    result = client.request('POST',url+'/upload',execute=True,multipart_files=probe)
    assert result.response.status_code == 200
    assert b'probe.txt' in requests[0][2]
    assert b'harmless test data' in requests[0][2]
    with pytest.raises(ScopeError):
        client.request('POST',url+'/upload',execute=False,
            multipart_files={'upload':('payload.exe',b'bytes','application/octet-stream')})
    with pytest.raises(ScopeError):
        client.request('POST',url+'/upload',execute=False,
            multipart_files={'upload':('test.txt',b'x'*16385,'text/plain')})


def test_readonly_scanner_detects_redirect_and_reflection_without_following(server):
    url, requests = server
    spec={'openapi':'3.0.3','info':{'title':'x','version':'1'},'paths':{
      '/redirect':{'get':{'parameters':[{'name':'next_url','in':'query','schema':{'type':'string'}}],
                         'responses':{'200':{'description':'ok'}}}},
      '/reflect':{'get':{'parameters':[{'name':'q','in':'query','schema':{'type':'string'}}],
                        'responses':{'200':{'description':'ok'}}}}}}
    outcome=scan_bounded_get(spec,base_url=url,allowed_hosts={'127.0.0.1'},
                             max_requests=4, rate=10,execute=True)
    assert outcome['requests_sent']==4
    assert {row['category'] for row in outcome['findings']} == {
        'possible_open_redirect','possible_html_reflection'}
    assert not any('example.invalid' in req[0] for req in requests)
    assert all(row['verification_status']=='requires_manual_review' for row in outcome['findings'])
    assert 'body_preview' not in json.dumps(outcome)


def test_readonly_replay_uses_fixed_case_only_and_no_exploit_confirmation(server):
    url,_=server
    spec={'openapi':'3.0.3','info':{'title':'x','version':'1'},'paths':{
      '/reflect':{'get':{'parameters':[{'name':'q','in':'query','schema':{'type':'string'}}],
                        'responses':{'200':{'description':'ok'}}}}}}
    findings=[{'category':'possible_sql_error_injection','operation':'GET /reflect',
               'parameter':'q','location':'query','test_baseline':'control',
               'test_payloads':["'"], 'evidence':{'baseline':{'status':200},
               'variants':[{'status':200}]}}]
    result=replay_readonly_indicators(spec,findings,base_url=url,allowed_hosts={'127.0.0.1'},max_requests=4,rate=10)
    assert result['requests_sent']==2
    assert result['results'][0]['status']=='indicator_reproduced_not_exploit_confirmed'
    assert result['findings']==[]


def test_agent_whitelist_and_write_approval():
    raw={'recommended_tests':['Verifica SQL injection', 'Test BFLA sul ruolo',
          'Mass assignment su JSON PATCH','Invia DELETE https://outside.invalid']}
    available={key:{'available':True} for key in ('injection','authorization','body_probes')}
    plan=allowed_agent_decisions(raw,available=available)
    assert {'injection','authorization','body_probes'} <= {x['task'] for x in plan['selected_tasks']}
    assert next(x for x in plan['selected_tasks'] if x['task']=='body_probes')['status']=='blocked_prerequisite'
    assert plan['automatic_arbitrary_http'] is False
    assert 'outside.invalid' not in json.dumps(plan)


def test_form_and_xml_manifest_preflight_with_schema_declaration():
    spec={'openapi':'3.0.3','info':{'title':'media test','version':'1'},'paths':{
        '/things':{'post':{'requestBody':{'content':{'application/json':{'schema':{
            'type':'object','properties':{'label':{'type':'string'}}}}}},
                            'responses':{'201':{'description':'ok'}}}},
        '/things/{thing_id}':{'parameters':[{'name':'thing_id','in':'path','required':True,
                        'schema':{'type':'string'}}],
            'get':{'responses':{'200':{'description':'ok'}}},
            'delete':{'responses':{'204':{'description':'ok'}}},
            'patch':{'requestBody':{'content':{
                'application/x-www-form-urlencoded':{'schema':{'type':'object','properties':{'name':{'type':'string'}}}},
                'application/xml':{'schema':{'type':'string'}}}},
                'responses':{'200':{'description':'ok'}}}}}}
    manifest={'resources':[{'name':'thing','create':'POST /things','read':'GET /things/{thing_id}',
        'delete':'DELETE /things/{thing_id}', 'identity':'owner','body':{'label':'temporary'},
        'marker_field':'label','marker_pointer':'/label','id_pointer':'/id','read_id_pointer':'/id',
        'path_values':{'thing_id':'${thing.id}'},
        'mutations':[{'operation':'PATCH /things/{thing_id}',
                      'body':{'name':'test'},'content_type':'application/x-www-form-urlencoded'},
                     {'operation':'PATCH /things/{thing_id}',
                      'body':'<thing><name>test</name></thing>','content_type':'application/xml'}]}]}
    plan=plan_multi_resource(parse_openapi(spec),spec,manifest,{'owner'})
    assert plan['request_budget_required'] >= 10
    bad=deepcopy(manifest)
    bad['resources'][0]['mutations'][1]['body']='<!DOCTYPE thing><thing/>'
    with pytest.raises(MultiResourceError): plan_multi_resource(parse_openapi(spec),spec,bad,{'owner'})


def test_oauth_refresh_grant_rotation_and_authorization_code_pkce(monkeypatch):
    from achillesapi.core.auth import AuthenticationFile, AuthenticationManager
    import httpx
    from achillesapi.core import auth_dynamic
    sent=[]
    class FakeResponse:
        status_code=200
        content=b'{"access_token":"demo-access","expires_in":45,"refresh_token":"rotated-demo"}'
        def json(self): return json.loads(self.content)
    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs['follow_redirects'] is False
            assert kwargs['trust_env'] is False
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def post(self, url, **kwargs):
            sent.append(kwargs['data'])
            return FakeResponse()
    monkeypatch.setattr(httpx,'Client',FakeClient)
    profiles=AuthenticationFile.model_validate({'profiles':[
        {'name':'refresh','type':'oauth2_refresh_token', 'token_url':'https://auth.example.com/token',
         'client_id':'client-1','refresh_token':'first-refresh'},
        {'name':'pkce','type':'oauth2_authorization_code','token_url':'https://auth.example.com/token',
         'client_id':'client-1','authorization_code_env':'TEST_OAUTH_CODE',
         'code_verifier_env':'TEST_OAUTH_VERIFIER','redirect_uri':'http://127.0.0.1/callback'}]})
    monkeypatch.setenv('TEST_OAUTH_CODE','one-use-code')
    monkeypatch.setenv('TEST_OAUTH_VERIFIER','pkce-verifier')
    manager=AuthenticationManager(profiles)
    material=manager.resolve('refresh',allowed_hosts={'auth.example.com'})
    assert material.headers['Authorization']=='Bearer demo-access'
    assert sent[-1]['grant_type']=='refresh_token'
    manager.invalidate('refresh')
    manager.resolve('refresh',allowed_hosts={'auth.example.com'})
    assert sent[-1]['refresh_token']=='rotated-demo'
    manager.resolve('pkce',allowed_hosts={'auth.example.com'})
    assert sent[-1]['grant_type']=='authorization_code'
    assert sent[-1]['code_verifier']=='pkce-verifier'
    manager.invalidate('pkce')
    manager.resolve('pkce',allowed_hosts={'auth.example.com'})
    assert sent[-1]['grant_type']=='refresh_token'  # rotated in process memory
    assert all('demo-access' not in repr(x) for x in sent)


def test_auth_code_without_refresh_cannot_be_reused(monkeypatch):
    import httpx
    from achillesapi.core.auth import AuthenticationFile, AuthenticationManager
    class Response:
        status_code=200
        content=b'{"access_token":"ok","expires_in":40}'
        def json(self): return json.loads(self.content)
    class Client:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args):pass
        def post(self,*args,**kwargs): return Response()
    monkeypatch.setattr(httpx,'Client',Client)
    monkeypatch.setenv('PKCE_CODE','once')
    monkeypatch.setenv('PKCE_VERIFIER','verifier')
    manager=AuthenticationManager(AuthenticationFile.model_validate({'profiles':[{
      'name':'one-use','type':'oauth2_authorization_code','token_url':'https://auth.example.com/token',
      'client_id':'client','authorization_code_env':'PKCE_CODE',
      'code_verifier_env':'PKCE_VERIFIER','redirect_uri':'http://127.0.0.1/callback'}]}))
    manager.resolve('one-use',allowed_hosts={'auth.example.com'})
    manager.invalidate('one-use')
    with pytest.raises(AuthenticationConfigError, match='già utilizzato'):
        manager.resolve('one-use',allowed_hosts={'auth.example.com'})


def test_nested_patch_fields_auto_discovered_without_custom_json():
    from achillesapi.core.body_probes_rc11 import resource_probe_options, resource_body_probe_plan
    spec={'openapi':'3.0.3','info':{'title':'nested','version':'1'},'paths':{
      '/things':{'post':{'requestBody':{'content':{'application/json':{'schema':{'type':'object',
        'properties':{'label':{'type':'string','maxLength':120}}}}}},
        'responses':{'201':{'description':'ok'}}}},
      '/things/{thing_id}':{'parameters':[{'in':'path','name':'thing_id','required':True,
        'schema':{'type':'string'}}],
        'get':{'responses':{'200':{'description':'ok'}}},
        'delete':{'responses':{'204':{'description':'ok'}}},
        'patch':{'requestBody':{'content':{'application/json':{'schema':{'type':'object',
          'properties':{'details':{'type':'object','properties':{'caption':{'type':'string'}}}}}}}},
          'responses':{'200':{'description':'ok'}}}}}}
    manifest={'resources':[{'name':'thing','identity':'owner','create':'POST /things',
      'read':'GET /things/{thing_id}', 'delete':'DELETE /things/{thing_id}',
      'body':{'label':'temporary'},'marker_field':'label','marker_pointer':'/label',
      'id_pointer':'/id','read_id_pointer':'/id','path_values':{'thing_id':'${thing.id}'}}]}
    parsed=parse_openapi(spec)
    options=resource_probe_options(parsed,spec,manifest)
    opt=next(x for x in options if x['field']=='details.caption')
    plan=resource_body_probe_plan(parsed,spec,manifest,{'owner'},[opt['key']])
    assert len(plan['cases'])==2
    assert plan['request_budget_required']>0


def test_bounded_get_finding_export_keeps_exact_probe_but_not_arbitrary_body():
    from achillesapi.reporting.professional import _normalize_observation
    item={'category':'possible_open_redirect','operation':'GET /redirect',
          'field':'next_url','test_payloads':['achilles-check','https://example.invalid/achilles-check'],
          'severity':'medium','reason':'Redirect verso host di prova',
          'evidence':{'baseline_status':200,'probe_status':302,'requests_compared':2,
                      'redirect_destination_host':'example.invalid',
                      'authorization':'Bearer do-not-log', 'body':'very-secret'}}
    report=_normalize_observation(item,0,passive=False)
    assert report['test_payloads']==item['test_payloads']
    assert report['test_input']['parameter']=='next_url'
    assert 'open redirect' in report['what_found'].lower()
    assert report['evidence']['probe_status']==302
    assert 'Bearer' not in json.dumps(report)
    assert 'very-secret' not in json.dumps(report)
    assert 'example.invalid' in json.dumps(report)
    item['test_payloads']=['Bearer evil', 'some-secret']
    assert _normalize_observation(item,1,passive=False)['test_payloads']==[]
