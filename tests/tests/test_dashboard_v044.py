"""End-to-end regression for tab-preserving exports and AI evidence wiring."""
import json
import time
from pathlib import Path
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app
from achillesapi.core.evidence_bridge import evidence_from_assessment

SPEC={"openapi":"3.0.3","info":{"title":"Independent audit API","version":"1"},"servers":[{"url":"https://qa.example.com"}],
      "paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}

def _wait(c, jid):
    for _ in range(150):
        job=c.get('/api/jobs/'+jid).json()
        if job['status']!='running':return job
        time.sleep(.04)
    raise AssertionError('job timed out')

def test_assessment_bridge_uses_metadata_not_fake_body():
    report={'execution_report':{'observations':[
        {'method':'GET','path':'/health','status_code':200,'body_preview':'SECRET','headers':{'Authorization':'Bearer a'}},
        {'method':'GET','path':'/missing','status_code':503}]}}
    result=evidence_from_assessment(report)
    assert len(result['responses'])==2
    assert result['responses'][0]['body_preview']==''
    assert result['responses'][0]['headers']=={}
    assert 'SECRET' not in json.dumps(result)
    try:evidence_from_assessment({'plan':{'operations':[]}})
    except ValueError as exc: assert 'assessment attivo' in str(exc)
    else:raise AssertionError('accepted plan without observations')

def test_pdf_html_exports_and_ai_previous_result(tmp_path):
    test=TestClient(create_app(tmp_path/'ui'),base_url='http://127.0.0.1:8766')
    token=test.get('/api/bootstrap').json()['csrf_token']
    header={'x-achilles-token':token}
    spec=test.post('/api/import-text',headers=header,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    task=test.post('/api/control/jobs',headers=header,json={'action':'auto-assess','specification_id':spec})
    assert task.status_code==200,task.text
    job=_wait(test,task.json()['id'])
    assert job['status']=='complete',job
    html=test.get('/api/export/'+job['id']+'/html')
    pdf=test.get('/api/export/'+job['id']+'/pdf')
    assert html.status_code==200,html.text[:300]
    assert pdf.status_code==200,pdf.text[:300] if pdf.status_code!=200 else ''
    assert pdf.content[:4]==b'%PDF'
    assert 'inline' in pdf.headers.get('content-disposition','')
    assert 'inline' in html.headers.get('content-disposition','')
    bad=test.post('/api/control/jobs',headers=header,json={
        'action':'ai-correlate','specification_id':spec,'assessment_id':job['id'], 'model':'achilles-local'})
    assert bad.status_code==422 and 'assessment' in bad.text.lower(),bad.text
    js=test.get('/assets/app.js').text
    assert "window.open(path,'_blank'" in js
    assert 'id="previousJob"' in test.get('/').text
    assert "location.href='/api/export/" not in js
