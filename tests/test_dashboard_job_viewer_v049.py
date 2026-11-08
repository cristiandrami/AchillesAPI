"""Standalone tab, all-tool view model, and redaction regression."""
import json
import time
from pathlib import Path
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.job_view import viewer_payload, safe_tree

SPEC={'openapi':'3.0.3','info':{'title':'Viewer smoke','version':'1'},'paths':{'/status':{'get':{'responses':{'200':{'description':'OK'}}}}}}

def test_viewer_preserves_correlated_observations_and_lists():
    data={'engine':'achillesapi-local-intelligence','evidence_analysis':{
        'scanner_observations':{'count':1,'findings':[{'category':'cors_credentialed_origin_reflection',
          'operation':'GET /misconfigured/cors','severity':'medium','evidence':{'allow_credentials':True,
          'authorization':'Bearer SECRET','property_paths':['secret.property']}}]}},
        'status_counts':{'200':37},'ai_correlation':{'executive_summary':'Verificare CORS',
        'next_steps':['Verifica con ambiente autorizzato']},'actions':[{'operation':'GET /a'}]}
    view=viewer_payload(data,action='ai-correlate',job_id='a'*32)
    assert len(view['findings'])==1
    assert view['findings'][0]['evidence']['allow_credentials'] is True
    assert view['ai'][0]['data']['next_steps'][0]=='Verifica con ambiente autorizzato'
    assert any(s['key']=='actions' for s in view['sections'])
    assert 'Bearer SECRET' not in json.dumps(view)
    assert 'secret.property' not in json.dumps(view)

def test_viewer_handles_many_tool_output_shapes():
    variants=[
      {'engine':'agent-v2','actions':[],'stop_reason':'no_supported_candidate','requests_sent':0},
      {'engine':'inventory','operations':[{'path':'/a','method':'GET'}],'nodes':[{'id':'a'}]},
      {'plan':{'operations':[{'method':'GET','path':'/a','status':'eligible_get'}]},
       'execution_report':{'findings':[{'category':'write_only_property_returned','operation':'GET /a',
       'severity':'medium','evidence':{'property_count':1}}]}},
      {'engine':'achillesapi-local-ai','ai_analysis':{'executive_summary':'Test','limitations':['offline']}},
      {'engine':'workflow','workflow_execution':{'workflows':[{'findings':[],'name':'A'}]}}
    ]
    for variant in variants:
        result=viewer_payload(variant,action='test',job_id='b'*32)
        assert isinstance(result['details'],dict)
        assert isinstance(result['sections'],list)
        assert isinstance(result['findings'],list)

def test_tree_redacts_secrets_and_malicious_markup_is_inert():
    obj={'token':'secret-abc','headers':{'Authorization':'Bearer abc'},'body_preview':'private',
      'allow_credentials':True,'description':'<img src=x onerror=alert(1)>'}
    sanitized=safe_tree(obj)
    assert sanitized['token'].startswith('[omesso')
    assert sanitized['headers'].startswith('[omesso')
    assert sanitized['allow_credentials'] is True
    # HTML can occur as untrusted text, never inserted into DOM as markup.
    js=Path('src/achillesapi/dashboard/static/job-viewer.js').read_text()
    assert 'innerHTML' not in js.replace('// No innerHTML with job data:','')
    assert 'textContent=' in js

def test_job_view_page_and_api_complete_job(tmp_path):
    client=TestClient(create_app(tmp_path/'dashboard'),base_url='http://127.0.0.1:8766')
    token=client.get('/api/bootstrap').json()['csrf_token']
    header={'x-achilles-token':token}
    spec=client.post('/api/import-text',headers=header,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    start=client.post('/api/control/jobs',headers=header,json={'action':'analyze-openapi','specification_id':spec})
    assert start.status_code==200,start.text
    jid=start.json()['id']
    for _ in range(100):
        job=client.get('/api/jobs/'+jid).json()
        if job['status']!='running':break
        time.sleep(.05)
    assert job['status']=='complete',job
    page=client.get('/job/'+jid)
    assert page.status_code==200
    assert 'job-viewer.js' in page.text
    assert "default-src 'self'" in page.headers['content-security-policy']
    response=client.get('/api/job-view/'+jid)
    assert response.status_code==200,response.text[:200]
    assert response.json()['id']==jid
    assert response.json()['action']=='analyze-openapi'
    assert client.get('/api/job-view/'+'c'*32).status_code==404
    assert client.get('/job/../../etc/passwd').status_code!=200
    assert 'Esplora in nuova scheda' in client.get('/assets/app.js').text
