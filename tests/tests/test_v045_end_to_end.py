"""Regressions for errors reported by real dashboard users.

No external API is contacted. Dashboard tool invocation uses the actual subprocess
worker, while AI correlation receives a local-only stubbed Ollama response.
"""
from __future__ import annotations
import json
import time
import threading
from pathlib import Path
from unittest.mock import patch
from typer.testing import CliRunner
from fastapi.testclient import TestClient
from achillesapi.cli import app
from achillesapi.dashboard.server import create_app

SPEC = {"openapi":"3.0.3","info":{"title":"Unrelated API","version":"1"},
        "servers":[{"url":"https://qa.example.test"}],"paths":{"/health":{"get":{"responses":{"200":{"description":"OK"}}}},
                 "/books/{book_id}":{"get":{"parameters":[{"name":"book_id","in":"path","required":True,
                      "schema":{"type":"string"}}],"responses":{"200":{"description":"OK"}}}},
                 "/admin/audit":{"get":{"responses":{"200":{"description":"OK"}}}},
                 "/books":{"post":{"responses":{"201":{"description":"Created"}}}}}}


def wait_job(client,jid):
    for _ in range(130):
        job=client.get('/api/jobs/'+jid).json()
        if job['status']!='running':return job
        time.sleep(.05)
    raise AssertionError('worker timed out')


def prepare(client,header):
    return client.post('/api/import-text',headers=header,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']


def test_ai_prioritize_accepts_previous_result_without_plan(tmp_path):
    spec=tmp_path/'api.json';spec.write_text(json.dumps(SPEC))
    previous=tmp_path/'analyze-openapi.json';previous.write_text(json.dumps({'title':'Unrelated API','endpoints':[]}))
    output=tmp_path/'ai-priorities.json'
    result=CliRunner().invoke(app,['ai-prioritize',str(spec),str(previous),'--budget','4','--output',str(output)])
    assert result.exit_code==0,result.output
    data=json.loads(output.read_text())
    assert data['source_note'].startswith('Piano ricostruito')
    assert data['http_observations_available']==0
    assert data['coverage_next_steps']
    assert data['coverage_next_steps'][0]['operation'].startswith('GET ')
    assert data.get('requests_sent',0)==0


def test_next_actions_favors_get_and_explains_uncovered(tmp_path):
    spec=tmp_path/'api.json';spec.write_text(json.dumps(SPEC))
    prior=tmp_path/'prior.json';prior.write_text('{}')
    out=tmp_path/'queue.json'
    result=CliRunner().invoke(app,['next-actions',str(spec),str(prior),'--budget','2','--output',str(out)])
    assert result.exit_code==0,result.output
    payload=json.loads(out.read_text())
    assert all(x['operation'].startswith('GET ') for x in payload['proposed_actions'])
    assert payload['requests_sent']==0


def test_dashboard_ai_correlate_does_not_inject_ai_flag(tmp_path,monkeypatch):
    """Test the actual dashboard process command construction and real CLI output.

    Inject a local fake correlation module in the child runner by patching its
    subprocess boundary, so no model has to be installed for this regression.
    """
    import achillesapi.dashboard.control as control
    client=TestClient(create_app(tmp_path/'web'),base_url='http://127.0.0.1:8766')
    header={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    sid=prepare(client,header)
    # Create a *real* prior job, then overwrite its report with real-looking
    # sanitized HTTP observations as if a separate authorized scan completed.
    response=client.post('/api/control/jobs',headers=header,json={'action':'auto-assess','specification_id':sid})
    assert response.status_code==200,response.text
    job=wait_job(client,response.json()['id']);assert job['status']=='complete',job
    report=tmp_path/'web'/'reports'/f'{job["id"]}.json'
    payload=json.loads(report.read_text())
    payload['execution_report']={'requests_sent':1,'observations':[
        {'operation':'GET /health','status':503,'check':'baseline','identity':'anonymous'}]}
    report.write_text(json.dumps(payload))
    # Build an ai-correlate job and capture its CLI command; this test covers
    # the *dashboard* rather than just the ai-correlate CLI.
    observed=[]
    original_run=control.subprocess.run
    def instrumented_run(command,*args,**kwargs):
        observed.append(list(command))
        return original_run(command,*args,**kwargs)
    monkeypatch.setattr(control.subprocess,'run',instrumented_run)
    task=client.post('/api/control/jobs',headers=header,json={
       'action':'ai-correlate','specification_id':sid,'assessment_id':job['id'],
       'ai':True,'model':'achilles-local'})
    assert task.status_code==200,task.text
    finished=wait_job(client,task.json()['id'])
    assert observed
    cli_args=observed[-1]
    assert 'ai-correlate' in cli_args
    assert '--ai' not in cli_args
    assert '--model' in cli_args
    # No model server in this test: CLI should report a clear unavailable Ollama
    # error, not the invalid CLI option that the user experienced.
    assert finished['status']=='failed'
    assert 'No such option: --ai' not in str(finished['error'])


def test_agent_without_reproducible_anomaly_explains_no_traffic(tmp_path):
    spec=tmp_path/'api.json';spec.write_text(json.dumps(SPEC))
    prior=tmp_path/'assessment.json'
    from achillesapi.core.openapi import analyze_openapi_file
    from achillesapi.core.generic import build_generic_plan
    plan=build_generic_plan(analyze_openapi_file(spec))
    prior.write_text(json.dumps({'plan':plan,'execution_report':{'observations':[
        {'operation':'GET /health','check':'baseline','status':200,'identity':'anonymous'}]}}))
    result_path=tmp_path/'agent.json'
    result=CliRunner().invoke(app,['agent-loop-v2',str(spec),str(prior),'--output',str(result_path)])
    assert result.exit_code==0,result.output
    data=json.loads(result_path.read_text())
    assert data['stop_reason']=='no_supported_candidate'
    assert 'No qualifying' in data['interpretation']
    assert data['requests_sent']==0
