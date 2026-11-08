"""Cross-resource production engine checks, including a real local HTTP server."""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.multi_resource import (MultiResourceError, plan_multi_resource,
                                              run_multi_resource)
from achillesapi.core.vulnerability_engine import vulnerability_test_plan, vulnerability_evidence_review
from achillesapi.core.agent_v034 import agent_cycle_review
from achillesapi.core.openapi import analyze_openapi_file


def sample():
    spec={'openapi':'3.0.3','info':{'title':'Unrelated API','version':'1'},'paths':{}}
    for group, collection, single, ident in (
        ('parent','/collections','/collections/{collection_ref}','collection_ref'),
        ('child','/collections/{collection_ref}/documents','/documents/{document_ref}','document_ref')):
        schema={'type':'object','properties':{'label':{'type':'string','maxLength':80},
                                              'parent':{'type':'string'}}}
        spec['paths'].setdefault(collection,{})['post']={
            'operationId':'create'+group, 'responses':{'201':{'description':'created'}},
            'requestBody':{'content':{'application/json':{'schema':schema}}},
            'parameters':([{'in':'path','name':'collection_ref','required':True,'schema':{'type':'string'}}]
                          if group=='child' else [])}
        spec['paths'][single]={
            'get':{'operationId':'read'+group,'responses':{'200':{'description':'OK'}},
                   'parameters':[{'in':'path','name':ident,'required':True,'schema':{'type':'string'}}]},
            'delete':{'operationId':'delete'+group,'responses':{'204':{'description':'deleted'}},
                   'parameters':[{'in':'path','name':ident,'required':True,'schema':{'type':'string'}}]}}
    return spec


def parsed(tmp_path):
    path=tmp_path/'spec.json'
    path.write_text(json.dumps(sample()))
    return analyze_openapi_file(path)


def manifest():
    return {'resources':[
        {'name':'collection','create':'POST /collections',
         'read':'GET /collections/{collection_ref}',
         'delete':'DELETE /collections/{collection_ref}',
         'identity':'owner','body':{'label':'approved'},
         'marker_field':'label','marker_pointer':'/label',
         'id_pointer':'/id','read_id_pointer':'/id',
         'path_values':{'collection_ref':'${collection.id}'},
         'access':[{'identity':'other','expected':'deny'}]},
        {'name':'document','create':'POST /collections/{collection_ref}/documents',
         'read':'GET /documents/{document_ref}',
         'delete':'DELETE /documents/{document_ref}',
         'identity':'owner','body':{'label':'approved','parent':'${collection.id}'},
         'marker_field':'label','marker_pointer':'/label',
         'id_pointer':'/id','read_id_pointer':'/id',
         'path_values':{'collection_ref':'${collection.id}','document_ref':'${document.id}'}}
    ]}


def test_preflight_and_reference_rules(tmp_path):
    api=parsed(tmp_path)
    p=plan_multi_resource(api,sample(),manifest(),{'owner','other'})
    assert p['request_budget_required']==11
    assert p['resources'][1]['depends_on']==['collection']
    wrong=manifest(); wrong['resources'][1]['body']['parent']='${missing.id}'
    with pytest.raises(MultiResourceError):
        plan_multi_resource(api,sample(),wrong,{'owner','other'})


def test_no_network_without_write_approval(tmp_path,monkeypatch):
    from achillesapi.core import multi_resource as module
    api=parsed(tmp_path)
    def fail(*args,**kwargs): raise AssertionError('HTTP client must not be initialized')
    monkeypatch.setattr(module,'SafeHTTPClient',fail)
    credentials={'owner':AuthenticationMaterial(), 'other':AuthenticationMaterial()}
    dry=run_multi_resource(api,sample(),manifest(),base_url='http://127.0.0.1:9',
       allowed_hosts={'127.0.0.1'},identities=credentials)
    assert dry['requests_sent']==0
    with pytest.raises(Exception):
        run_multi_resource(api,sample(),manifest(),base_url='http://127.0.0.1:9',
          allowed_hosts={'127.0.0.1'},identities=credentials,execute=True)


def test_real_http_nested_resources(tmp_path):
    state={'collections':{},'documents':{},'deletions':[]}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def response(self,status,body=None):
            encoded=json.dumps(body).encode() if body is not None else b''
            self.send_response(status);self.send_header('content-type','application/json');
            self.send_header('content-length',str(len(encoded)));self.end_headers();self.wfile.write(encoded)
        def do_POST(self):
            length=int(self.headers.get('Content-Length',0)); data=json.loads(self.rfile.read(length))
            if self.path=='/collections':
                state['collections']['collection-1']={'id':'collection-1',**data};self.response(201,{'id':'collection-1'})
            elif self.path=='/collections/collection-1/documents':
                state['documents']['document-1']={'id':'document-1',**data};self.response(201,{'id':'document-1'})
            else:self.response(404)
        def do_GET(self):
            if self.path=='/collections/collection-1': self.response(200,state['collections']['collection-1']) if 'collection-1' in state['collections'] else self.response(404)
            elif self.path=='/documents/document-1': self.response(200,state['documents']['document-1']) if 'document-1' in state['documents'] else self.response(404)
            else:self.response(404)
        def do_DELETE(self):
            if self.path=='/documents/document-1':
                state['documents'].pop('document-1',None);state['deletions'].append('document');self.response(204)
            elif self.path=='/collections/collection-1':
                state['collections'].pop('collection-1',None);state['deletions'].append('collection');self.response(204)
            else:self.response(404)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        result=run_multi_resource(parsed(tmp_path),sample(),manifest(),
            base_url=f'http://127.0.0.1:{server.server_port}',allowed_hosts={'127.0.0.1'},
            identities={'owner':AuthenticationMaterial(),'other':AuthenticationMaterial()},
            execute=True,approve_writes=True,allow_insecure_http=True,max_requests=20,rate=10)
        assert result['requests_sent']==11
        assert result['manual_cleanup_required'] is False
        assert all(x['cleanup_verified'] for x in result['resources_results'])
        assert state['deletions']==['document','collection']
        assert result['findings'][0]['category']=='AUTHORIZATION_POLICY_MISMATCH'
        text=json.dumps(result)
        assert 'collection-1' not in text and 'document-1' not in text
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


def test_agent_and_vulnerability_triage(tmp_path):
    api=parsed(tmp_path)
    vulnerability=vulnerability_test_plan(api)
    assert len(vulnerability['operations'])==6
    assert not any(x['active_supported'] for x in vulnerability['operations'] if x['operation'].startswith('DELETE'))
    assessment={'execution_report':{'findings':[{'category':'authorization_policy_mismatch',
        'expected':'deny','observed_status':200,'operation':'GET /documents/{document_ref}'}]}}
    review=vulnerability_evidence_review(api,assessment)
    assert review['confirmed_vulnerabilities']==0
    assert review['candidate_count']==1
    agent=agent_cycle_review(api,{'plan':{'operations':[]}},budget=3)
    assert agent['requests_sent']==0
    assert agent['model_can_authorize_requests'] is False


def test_cross_resource_write_unsafe_templates_blocked(tmp_path):
    api=parsed(tmp_path)
    bad=manifest()
    bad['resources'][1]['path_values']['collection_ref']='${document.id}'
    with pytest.raises(MultiResourceError):
        plan_multi_resource(api,sample(),bad,{'owner','other'})
    bad=manifest()
    bad['resources'][0]['read']='GET /documents/{document_ref}'
    with pytest.raises(MultiResourceError):
        plan_multi_resource(api,sample(),bad,{'owner','other'})
    bad=manifest()
    bad['resources'][1]['body']['parent']='prefix-${collection.id}'
    with pytest.raises(MultiResourceError):
        plan_multi_resource(api,sample(),bad,{'owner','other'})


def test_scope_and_budget_fail_closed(tmp_path,monkeypatch):
    from achillesapi.core import multi_resource as module
    api=parsed(tmp_path)
    def must_not_send(*args,**kwargs): raise AssertionError('HTTP must never run')
    monkeypatch.setattr(module,'SafeHTTPClient',must_not_send)
    identities={'owner':AuthenticationMaterial(), 'other':AuthenticationMaterial()}
    with pytest.raises(Exception):
        run_multi_resource(api,sample(),manifest(),
            base_url='http://example.org',allowed_hosts={'127.0.0.1'},identities=identities,
            execute=True,approve_writes=True,allow_insecure_http=True)
    with pytest.raises(Exception):
        run_multi_resource(api,sample(),manifest(),
            base_url='http://127.0.0.1:1',allowed_hosts={'127.0.0.1'},identities=identities,
            execute=True,approve_writes=True,allow_insecure_http=True,max_requests=1)


def test_professional_reporting_includes_multi_resource_findings():
    from achillesapi.reporting.professional import summarize_assessment
    content={'plan':{'operations':[],'execution':{'requests_sent':12}},
             'multi_resource_execution':{'manual_cleanup_required':True,
                 'findings':[{'category':'AUTHORIZATION_POLICY_MISMATCH',
                              'operation':'GET /documents/{document_ref}',
                              'confidence':'policy_based_requires_review'}]}}
    result=summarize_assessment(content)
    assert len(result['findings'])==1
    assert result['findings'][0]['status']=='requires_review'
    assert result['summary']['manual_cleanup_required'] is True
