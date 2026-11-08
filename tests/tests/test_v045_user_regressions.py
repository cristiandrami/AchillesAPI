"""User-reported dashboard failures: real CLI invocations and truthful agent semantics."""
import json
import time
from pathlib import Path
from typer.testing import CliRunner
from fastapi.testclient import TestClient
from achillesapi.cli import app
from achillesapi.dashboard.server import create_app

SPEC = {
    'openapi':'3.0.3','info':{'title':'Unrelated Service','version':'1'},
    'paths': {
        '/health':{'get':{'responses':{'200':{'description':'OK'}}}},
        '/records/{record_id}':{'get':{'parameters':[{'name':'record_id','in':'path','required':True,
              'schema':{'type':'string'}}],'responses':{'200':{'description':'OK'}}}},
        '/admin/audit':{'get':{'responses':{'200':{'description':'OK'}}}},
        '/records':{'post':{'responses':{'201':{'description':'Created'}}}},
    }
}

def wait(c,jid):
    for _ in range(140):
        job=c.get('/api/jobs/'+jid).json()
        if job['status']!='running':return job
        time.sleep(.04)
    raise AssertionError('job did not complete')

def test_prioritize_works_with_plain_json_report(tmp_path):
    spec=tmp_path/'service.json';spec.write_text(json.dumps(SPEC))
    report=tmp_path/'report.json';report.write_text(json.dumps({'operation_count':4,'notes':['saved metadata']}))
    output=tmp_path/'priorities.json'
    r=CliRunner().invoke(app,['ai-prioritize',str(spec),str(report),'--budget','3','--output',str(output)])
    assert r.exit_code==0,r.output
    result=json.loads(output.read_text())
    assert result['http_observations_available']==0
    assert result['source_note'].startswith('Piano ricostruito')
    assert result['coverage_next_steps']
    assert result.get('requests_sent',0)==0


def test_agent_distinguishes_write_prerequisite_from_safe_get(tmp_path):
    spec=tmp_path/'service.json';spec.write_text(json.dumps(SPEC))
    report=tmp_path/'assessment.json';report.write_text('{}')
    output=tmp_path/'agent.json'
    r=CliRunner().invoke(app,['autonomous-agent',str(spec),str(report),'--budget','5','--output',str(output)])
    assert r.exit_code==0,r.output
    data=json.loads(output.read_text())
    assert data['requests_sent']==0
    assert data['executable_candidates']==0
    assert data['operator_prerequisites']>=1
    assert any(a['operation']=='POST /records' for a in data['actions'])
    assert any(a['action']=='baseline_get_recommended' for a in data['actions'])


def test_ai_correlate_cli_accepts_real_assessment_without_ai_flag(tmp_path,monkeypatch):
    spec=tmp_path/'service.json';spec.write_text(json.dumps(SPEC))
    report=tmp_path/'assessment.json'
    report.write_text(json.dumps({'execution_report':{'observations':[
        {'operation':'GET /health','status':503,'identity':'anonymous','check':'baseline'}]}}))
    monkeypatch.setattr('achillesapi.cli.correlate_with_ollama',lambda parsed,evidence,**k:{
        'executive_summary':'Una risposta 503 osservata','cross_correlations':[],
        'false_positive_checks':[],'next_steps':['Verifica riproducibilità'],
        'limitations':['Non è prova di vulnerabilità'], 'model_assessment_is_not_a_finding':True})
    output=tmp_path/'ai-correlation.json'
    result=CliRunner().invoke(app,['ai-correlate',str(spec),str(report),'--output',str(output)])
    assert result.exit_code==0,result.output
    saved=json.loads(output.read_text())
    assert saved['target_requests_sent']==0
    assert saved['ai_correlation']['executive_summary']=='Una risposta 503 osservata'


def test_dashboard_ai_prioritize_end_to_end(tmp_path):
    client=TestClient(create_app(tmp_path/'web'),base_url='http://127.0.0.1:8766')
    h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    sid=client.post('/api/import-text',headers=h,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    original=client.post('/api/control/jobs',headers=h,json={'action':'analyze-openapi','specification_id':sid})
    assert original.status_code==200,original.text
    job=wait(client,original.json()['id']);assert job['status']=='complete',job
    second=client.post('/api/control/jobs',headers=h,json={'action':'ai-prioritize','specification_id':sid,
         'assessment_id':job['id'],'budget':3,'ai':False})
    assert second.status_code==200,second.text
    task=wait(client,second.json()['id']);assert task['status']=='complete',task
    result=client.get('/api/results/'+task['id']).json()
    assert result['coverage_next_steps']
    assert result['http_observations_available']==0
    assert result.get('requests_sent',0)==0


def test_dashboard_distinguishes_viewed_result_from_evidence_selection():
    js=Path(__file__).resolve().parents[1]/'src/achillesapi/dashboard/static/app.js'
    s=js.read_text()
    assert 'assessment_id:evidenceJob||null' in s
    assert "async function viewJob(id){selectedJob=id;" in s
    assert "$('previousJob').onchange=()=>{evidenceJob=" in s
    assert "const prev=previousJobs.find(x=>x.id===evidenceJob)" in s
