"""RC19 release QA: offline gate, explicit benchmark, dashboard CSRF and CLI."""
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.release_validation_rc19 import (
    RC19ValidationError, quality_gate, benchmark_findings
)
from achillesapi.dashboard.server import create_app

SPEC={'openapi':'3.0.3','info':{'title':'RC19 synthetic','version':'1'},'paths':{'/health':{'get':{'responses':{'200':{'description':'ok'}}}}}}


def test_quality_gate_is_conservative_and_redacted():
    source={'engine':'lab','executed':False,'requests_sent':0,
            'findings':[{'operation':'GET /health','category':'info','verification_status':'confirmed','authorization':'SENSITIVE_TOKEN'}]}
    result=quality_gate(source)
    assert result['release_gate']=='review_required'
    assert result['counts']['claims_of_confirmation']==1
    assert result['network_requests_sent']==0
    assert 'SENSITIVE_TOKEN' not in json.dumps(result)
    bad=dict(source,executed=False,requests_sent=4)
    assert quality_gate(bad)['release_gate']=='blocked'
    with pytest.raises(RC19ValidationError):quality_gate([])


def test_benchmark_never_claims_offline_true_negatives():
    truth={'cases':[{'id':'a','operation':'GET /health','category':'injection','expected':'negative'}]}
    source={'engine':'lab','executed':False,'requests_sent':0,'findings':[]}
    offline=benchmark_findings(source,truth)
    assert offline['status']=='not_evaluated_offline'
    assert offline['summary']['not_evaluated']==1
    assert offline['summary']['negative_controls_passed']==0
    active=dict(source,executed=True,requests_sent=2)
    checked=benchmark_findings(active,truth)
    assert checked['summary']['negative_controls_passed']==1
    with pytest.raises(RC19ValidationError):benchmark_findings(active,{'cases':[truth['cases'][0],truth['cases'][0]]})


def test_cli_rc19_quality_and_benchmark(tmp_path):
    assessment=tmp_path/'assessment.json'
    assessment.write_text(json.dumps({'engine':'test','executed':False,'requests_sent':0,'findings':[]}))
    expected=tmp_path/'expected.json'
    expected.write_text(json.dumps({'cases':[{'id':'x','operation':'GET /health','category':'auth','expected':'negative'}]}))
    output=tmp_path/'quality.json'
    cli=CliRunner()
    result=cli.invoke(app,['rc19-quality',str(assessment),'--output',str(output)])
    assert result.exit_code==0,result.output
    assert json.loads(output.read_text())['network_requests_sent']==0
    output=tmp_path/'bench.json'
    result=cli.invoke(app,['rc19-benchmark',str(assessment),str(expected),'--output',str(output)])
    assert result.exit_code==0,result.output
    assert json.loads(output.read_text())['status']=='not_evaluated_offline'


def test_dashboard_offline_qa_with_completed_job(tmp_path):
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8766') as client:
        token=client.get('/api/bootstrap').json()['csrf_token']
        headers={'x-achilles-token':token}
        spec=client.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(SPEC),'name':'sample.json'})
        assert spec.status_code==200,spec.text
        job=client.post('/api/control/rc13/run',headers=headers,json={
            'config':{'action':'auto-assess','specification_id':spec.json()['id']},
            'active':False,'max_requests':10})
        assert job.status_code==200,job.text
        ident=job.json()['id']
        for _ in range(150):
            status=client.get('/api/jobs/'+ident).json()['status']
            if status not in ('running','orchestrating'):break
            time.sleep(.02)
        assert status=='complete',status
        quality=client.post('/api/rc19/quality/'+ident,headers=headers)
        assert quality.status_code==200,quality.text
        assert quality.json()['network_requests_sent']==0
        assert client.post('/api/rc19/quality/'+ident).status_code==403
        assert client.post('/api/rc19/quality/'+'a'*32,headers=headers).status_code==404
        truth={'cases':[{'id':'no-false-claim','operation':'GET /health','category':'injection','expected':'negative'}]}
        benchmark=client.post('/api/rc19/benchmark/'+ident,headers=headers,json={'ground_truth':truth})
        assert benchmark.status_code==200,benchmark.text
        assert benchmark.json()['summary']['not_evaluated']==1
        bad=client.post('/api/rc19/benchmark/'+ident,headers=headers,json={'ground_truth':{'cases':[]}})
        assert bad.status_code==422
