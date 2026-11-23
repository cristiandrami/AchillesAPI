"""RC9 regression: one saved access matrix powers all three suite tasks.

The private ephemeral HTTP server is read-only and never connects to a third-party target.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import time

import pytest
from fastapi.testclient import TestClient

from achillesapi.core.authorization_suite_bridge_rc9 import probe_from_rule
from achillesapi.core.verification_v037 import verify_access_policies
from achillesapi.dashboard.server import create_app
import achillesapi.dashboard.control as control


SPEC = {"openapi":"3.0.3", "info":{"title":"Independent API", "version":"1"},
        "paths":{"/resources/{resource_id}":{"get":{
          "parameters":[{"name":"resource_id","in":"path","required":True,"schema":{"type":"string"}}],
          "responses":{"200":{"description":"ok"}}}}}}
AUTH = {"profiles":[{"name":"alice","type":"bearer","token":"qa-alice"},
                    {"name":"bob","type":"bearer","token":"qa-bob"}]}
MATRIX = {"rules":[
 {"id":"A", "operation":"GET /resources/{resource_id}",
  "owner":"alice", "other":"bob", "expected_owner":"allow", "expected_other":"deny",
  "path_values":{"resource_id":"alpha"}},
 {"id":"B", "operation":"GET /resources/{resource_id}",
  "owner":"alice", "other":"bob", "expected_owner":"deny", "expected_other":"deny",
  "path_values":{"resource_id":"beta"}},
]}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        is_valid = self.headers.get('Authorization') in ('Bearer qa-alice','Bearer qa-bob')
        if self.path == '/resources/alpha':
            status=200 if self.headers.get('Authorization')=='Bearer qa-alice' else 403
        elif self.path == '/resources/beta':
            status=200 if is_valid else 401
        else:
            status=404
        self.send_response(status)
        self.end_headers()
        self.wfile.write(b'{}')

    def log_message(self,*args): pass


@pytest.fixture
def server():
    host=ThreadingHTTPServer(('127.0.0.1',0), Handler)
    thread=Thread(target=host.serve_forever,daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{host.server_address[1]}'
    host.shutdown(); host.server_close(); thread.join(timeout=2)


def upload(client,headers,kind,document):
    response=client.post('/api/import-text',headers=headers,json={
        'kind':kind, 'name':kind+'.json','content':json.dumps(document)})
    assert response.status_code==200,response.text
    return response.json()['id']


def test_adapter_preserves_denied_first_identity():
    result=probe_from_rule(MATRIX['rules'][1])
    assert result['expected_owner']=='deny'
    assert result['path_values']==['resource_id=beta']
    assert result['profiles']==['alice','bob']


def test_verifier_never_merges_same_operation_different_resource_ids():
    assessment={'engine':'achilles-access-matrix-rc4','executed':True, 'rules':[
       {'id':'A','operation':MATRIX['rules'][0]['operation'],'observations':[
          {'identity':'alice','status_code':200},{'identity':'bob','status_code':403}]},
       {'id':'B','operation':MATRIX['rules'][1]['operation'],'observations':[
          {'identity':'alice','status_code':200},{'identity':'bob','status_code':200}]},
    ]}
    out=verify_access_policies(assessment,MATRIX['rules'])
    assert len(out['results'])==4
    assert out['review_count']==2
    assert all(x['classification']=='consistent_with_policy_not_proven' for x in out['results'][:2])
    assert all(x['classification']=='policy_mismatch_requires_review' for x in out['results'][2:])
    assert out['confirmed_vulnerabilities']==0
    from achillesapi.reporting.professional import summarize_assessment
    observations=summarize_assessment(out)['findings']
    assert len(observations)==2
    assert all(x['severity']=='medium' for x in observations)
    assert all('policy' in x['reason'].lower() for x in observations)


def test_verifier_does_not_pretend_offline_matrix_is_verified():
    out=verify_access_policies({'engine':'achilles-access-matrix-rc4','executed':False,
                               'rules':[{'id':'A','operation':MATRIX['rules'][0]['operation']}]},MATRIX['rules'])
    assert out['review_count']==0
    assert all(x['classification']=='inconclusive_missing_observation' for x in out['results'])


def test_three_tasks_run_with_dedicated_matrix_even_if_workflow_config_selected(tmp_path,server,monkeypatch):
    monkeypatch.setattr(control,'SUITE_ORDER',('access-probe','access-matrix','verify-access-policy'))
    with TestClient(create_app(tmp_path/'app'),base_url='http://127.0.0.1:8766') as client:
        h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        spec=upload(client,h,'openapi',SPEC)
        auth=upload(client,h,'auth',AUTH)
        matrix=upload(client,h,'config',MATRIX)
        unrelated=upload(client,h,'config',{'workflows':[{'name':'independent-placeholder'}]})
        payload={'include_active':True,'include_optional':True,'max_total_requests':100,
                 'config':{'action':'auto-assess','specification_id':spec,'auth_config_id':auth,
                    'access_rules_id':matrix,'config_id':unrelated,'config_usage':'multi-resource',
                    'base_url':server,'allow_host':'127.0.0.1','acknowledgment':True,
                    'allow_insecure_http':True,'max_requests':12,'profiles':['alice','bob']}}
        started=client.post('/api/control/suite',headers=h,json=payload)
        assert started.status_code==200,started.text
        job=started.json()['id']
        for _ in range(250):
            state=client.get('/api/jobs/'+job).json()
            if state['status'] not in ('running','orchestrating'): break
            time.sleep(.10)
        assert state['status']=='complete',state
        report=client.get('/api/results/'+job).json()
        steps=report['steps']
        assert [x['action'] for x in steps]==list(control.SUITE_ORDER)
        assert [x['status'] for x in steps]==['complete']*3,steps
        assert report['summary']['skipped']==0,steps
        assert report['access_matrix']['rule_count']==2
        assert steps[0]['matrix_rule_id']=='A'
        assert steps[1]['matrix_rule_count']==2
        assert steps[2]['matrix_rule_count']==2
        matrix_report=client.get('/api/results/'+steps[1]['job_id']).json()
        assert matrix_report['requests_sent']==4
        verifier_report=client.get('/api/results/'+steps[2]['job_id']).json()
        assert verifier_report['requests_sent']==0
        assert verifier_report['review_count']==2
        assert len(verifier_report['results'])==4
        assert verifier_report['confirmed_vulnerabilities']==0


def test_preview_tracks_separate_access_rules_config(tmp_path):
    with TestClient(create_app(tmp_path/'preview'),base_url='http://127.0.0.1:8766') as client:
        h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        spec=upload(client,h,'openapi',SPEC)
        auth=upload(client,h,'auth',AUTH)
        matrix=upload(client,h,'config',MATRIX)
        args={'auth_config_id':auth,'access_rules_id':matrix,'config_usage':'multi-resource',
              'active':'true','base_url':'https://qa.example.test','allow_host':'qa.example.test',
              'authorized':'true'}
        result=client.get('/api/control/suite/preflight/'+spec,params=args)
        assert result.status_code==200,result.text
        tasks={x['action']:x for x in result.json()['tasks']}
        assert tasks['access-probe']['state']=='ready'
        assert tasks['access-matrix']['state']=='ready'
        assert tasks['verify-access-policy']['state']=='waiting_for_result'
