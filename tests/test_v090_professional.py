"""Verifiche v0.90: genericità, autenticazione, preflight e sicurezza della suite."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from achillesapi.core.registry_v090 import TOOLS, SUITE_ORDER
from achillesapi.core.campaign_v090 import campaign_preflight
from achillesapi.core.workflow_dependencies_v090 import infer_dependencies
from achillesapi.core.risk_matrix_v090 import build_risk_matrix
from achillesapi.core.auth_audit_v090 import audit_auth
from achillesapi.core.quality_v090 import assess_campaign_quality
from achillesapi.core.verification_v090 import review_assessment
from achillesapi.dashboard.server import _safe_error, create_app
import achillesapi.dashboard.control as control


SPEC_A = {
    'openapi': '3.0.3', 'info': {'title': 'Inventory', 'version': '1'},
    'components': {'securitySchemes': {'bearerAuth': {'type': 'http', 'scheme': 'bearer'}}},
    'paths': {
        '/articles': {'post': {'requestBody': {'content': {'application/json': {'schema': {'type': 'object'}}}},
                               'responses': {'201': {'description': 'created'}}}},
        '/articles/{article_id}': {
            'get': {'parameters': [{'in': 'path', 'name': 'article_id', 'required': True,
                                    'schema': {'type': 'string'}}], 'responses': {'200': {'description': 'ok'}}},
            'delete': {'responses': {'204': {'description': 'deleted'}}}},
    },
}
SPEC_B = {
    'openapi': '3.1.0', 'info': {'title': 'Another service', 'version': '2'},
    'paths': {
        '/health': {'get': {'responses': {'200': {'description': 'healthy'}}}},
        '/search': {'get': {'parameters': [{'in': 'query', 'name': 'limit', 'schema': {'type': 'integer'}}],
                            'responses': {'200': {'description': 'ok'}}}},
    },
}


def test_registry_is_central_and_complete():
    assert set(TOOLS) == set(SUITE_ORDER) | {'rc13-assess', 'rc15-scan'}
    assert len(TOOLS) >= 45
    assert all(not TOOLS[cmd].get('active') for cmd in
               ('campaign-preflight', 'risk-matrix', 'campaign-quality',
                'workflow-dependencies', 'auth-audit', 'verification-review'))


@pytest.mark.parametrize('spec,expected_write', [(SPEC_A, True), (SPEC_B, False)])
def test_preflight_is_generic_and_does_not_claim_http(spec, expected_write):
    result = campaign_preflight(spec, TOOLS, SUITE_ORDER)
    assert result['requests_sent'] == 0
    assert len(result['tasks']) == len(SUITE_ORDER)
    by_name = {x['action']: x for x in result['tasks']}
    assert by_name['verify-findings']['state'] == 'waiting_for_result'
    assert by_name['campaign-quality']['state'] == 'waiting_for_result'
    if expected_write:
        assert by_name['workflow-assess']['state'] == 'disabled'
    else:
        assert by_name['workflow-assess']['state'] == 'not_applicable'
    assert all(t['state'] != 'tested' for t in result['tasks'])


def test_preflight_distinguishes_missing_configs_and_consent():
    report = campaign_preflight(SPEC_A, TOOLS, SUITE_ORDER,
                                active=True, writes=True, ai=True, has_scope=True,
                                authorized=True, has_auth=True, max_total_requests=100)
    tasks = {t['action']: t for t in report['tasks']}
    assert tasks['journey-assess']['state'] == 'blocked'
    assert tasks['workflow-assess']['config_type'] == 'workflow'
    assert tasks['auto-assess']['network_mode'] == 'active'
    assert tasks['auto-assess']['maximum_http_requests_reserved'] == 40
    assert report['summary']['maximum_suite_reservation'] == 100


def test_workflow_dependencies_do_not_execute_writes():
    report = infer_dependencies(SPEC_A)
    assert report['requests_sent'] == 0
    assert any(x['from'] == 'POST /articles' and x['to'] == 'GET /articles/{article_id}'
               for x in report['dependencies'])
    assert all(x['status'] != 'verified' for x in report['dependencies'])
    assert infer_dependencies(SPEC_B)['summary']['candidate_relations'] == 0


def test_risk_matrix_is_not_fake_vulnerabilities():
    report = build_risk_matrix(SPEC_A)
    assert report['requests_sent'] == 0
    assert all(x['status'] == 'candidate_not_tested' and not x['confirmed_vulnerability']
               for x in report['candidates'])
    assert any(x['owasp_category'] == 'API1:2023' for x in report['candidates'])
    assert build_risk_matrix(SPEC_B)['summary']['candidate_tests'] >= 1


def test_auth_audit_never_prints_inline_credentials(tmp_path):
    credential = 'EXPLICITLY-SECRET-THIS-MUST-NOT-APPEAR'
    auth = tmp_path / 'auth.yaml'
    auth.write_text('profiles:\n  - name: owner\n    type: bearer\n    token: '+credential+'\n')
    report = audit_auth(SPEC_A, str(auth))
    assert report['summary']['profiles'] == 1
    assert credential not in json.dumps(report)
    assert report['readiness']['schemes'][0]['status'] == 'configured_unverified'


def test_subprocess_error_redacts_inline_and_env_secrets(tmp_path):
    secret = 'VERY-SENSITIVE-OWN-TOKEN'
    auth = tmp_path / 'auth.yaml'
    auth.write_text('profiles:\n  - name: owner\n    type: bearer\n    token: '+secret+'\n')
    result = _safe_error('Error '+secret+' key SECRETVALUE', {'A':'SECRETVALUE'},auth)
    assert secret not in result and 'SECRETVALUE' not in result
    assert result.count('[REDACTED]') == 2


def test_quality_marks_offline_runs_incomplete():
    report = {'steps':[{'action':'analyze-openapi','status':'complete'},
                       {'action':'workflow-assess','status':'skipped'}],
              'preflight': {'summary': {'operations': 2, 'observed_operations': 0}},
              'verification': {'summary': {'requires_review': 1}}}
    quality = assess_campaign_quality(report)
    assert quality['metrics']['reported_http_observations'] == 0
    assert quality['metrics']['skipped'] == 1
    assert quality['state'] == 'requires_review'
    assert quality['requests_sent'] == 0


def test_verification_requires_operator_proof():
    assessment = {'report_schema':'achillesapi.professional.2', 'findings': [
        {'category':'potential_bola', 'operation':'GET /articles/{article_id}',
         'severity':'high', 'reason':'Unexpected 200'}]}
    verdict = review_assessment(assessment)
    assert verdict['summary']['confirmed_by_operator'] == 0
    assert verdict['findings'][0]['status'] == 'requires_review'
    assert verdict['findings'][0]['verified_automatically'] is False


def test_dashboard_preview_is_read_only_and_checks_scope(tmp_path):
    client = TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766')
    token = client.get('/api/bootstrap').json()['csrf_token']
    assert client.get('/api/bootstrap').json()['version']==__import__('achillesapi').__version__
    upload=client.post('/api/import-text',headers={'x-achilles-token':token},
                       json={'kind':'openapi','content':json.dumps(SPEC_A)})
    assert upload.status_code==200,upload.text
    ident=upload.json()['id']
    response=client.get('/api/control/suite/preflight/'+ident,params={
        'active':True,'authorized':True,'base_url':'https://blocked.example.org',
        'allow_host':'example.com'})
    assert response.status_code==200,response.text
    tasks={x['action']:x for x in response.json()['tasks']}
    assert tasks['auto-assess']['state']=='blocked'
    assert 'scope' in tasks['auto-assess']['missing_inputs']
    page=client.get('/').text
    assert 'suitePreview' in page and 'suiteStop' in page
    assert client.get('/assets/app.js').status_code==200


def test_cli_new_offline_commands_end_to_end(tmp_path):
    spec = tmp_path/'openapi.json'
    spec.write_text(json.dumps(SPEC_A))
    root=Path(__file__).resolve().parents[1]
    env={**os.environ, 'PYTHONPATH': str(root/'src')}
    for command in ('campaign-preflight','risk-matrix','workflow-dependencies','auth-audit'):
        target = tmp_path/(command+'.json')
        response=subprocess.run([sys.executable,'-m','achillesapi.cli',command,str(spec),
                                 '--output',str(target)],cwd=root,env=env,capture_output=True,
                                text=True,timeout=25)
        assert response.returncode==0,(command,response.stderr)
        assert json.loads(target.read_text())['requests_sent']==0


def test_cooperative_stop_only_between_tasks(tmp_path, monkeypatch):
    # Simuliamo un CLI che impiega del tempo: nessuna API viene contattata.
    monkeypatch.setattr(control,'SUITE_ORDER',('analyze-openapi','map-api','security-inventory'))
    started=[]
    def fake_subprocess(argv, **kwargs):
        started.append(argv[3])
        path=Path(argv[argv.index('--output')+1])
        time.sleep(.35)
        path.write_text(json.dumps({'engine':'simulated','requests_sent':0}))
        return SimpleNamespace(returncode=0,stderr='')
    monkeypatch.setattr(control.subprocess,'run',fake_subprocess)
    client=TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766')
    token=client.get('/api/bootstrap').json()['csrf_token']
    h={'x-achilles-token':token}
    spec_id=client.post('/api/import-text',headers=h,json={
        'kind':'openapi','content':json.dumps(SPEC_A)}).json()['id']
    initial=client.post('/api/control/suite',headers=h,json={
        'config':{'action':'auto-assess','specification_id':spec_id}})
    assert initial.status_code==200,initial.text
    parent=initial.json()['id']
    stop=client.post('/api/control/suite/'+parent+'/stop',headers=h)
    assert stop.status_code==200,stop.text
    for _ in range(150):
        if client.get('/api/jobs/'+parent).json()['status']=='complete':break
        time.sleep(.03)
    result=client.get('/api/results/'+parent)
    assert result.status_code==200,result.text
    report=result.json()
    assert report['status']=='stopped_by_operator'
    assert report['summary']['skipped']>=1
    assert not all(x['status']=='complete' for x in report['steps'])
    assert report['quality_gate']['state']=='requires_review'
    assert client.post('/api/control/suite/'+parent+'/stop',headers=h).status_code==409


def test_suite_quality_tool_uses_parent_report(tmp_path, monkeypatch):
    # Esecuzione reale della CLI per controllare la catena report -> quality.
    monkeypatch.setattr(control,'SUITE_ORDER',('assess','campaign-quality'))
    client=TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766')
    h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    spec_id=client.post('/api/import-text',headers=h,json={
        'kind':'openapi','content':json.dumps(SPEC_B)}).json()['id']
    started=client.post('/api/control/suite',headers=h,json={
        'config':{'action':'auto-assess','specification_id':spec_id}})
    assert started.status_code==200,started.text
    parent=started.json()['id']
    for _ in range(220):
        if client.get('/api/jobs/'+parent).json()['status']=='complete':break
        time.sleep(.05)
    result=client.get('/api/results/'+parent).json()
    assert [step['status'] for step in result['steps']]==['complete','complete'],result['steps']
    assert result['quality_gate']['metrics']['reported_http_observations']==0
    assert 'http_accounting_note' in result
