"""Regression: AI notes must be reviewable and policy-denied first identities work.

These tests use synthetic output; they never claim to have exercised Ollama itself.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from achillesapi.core.ai_observations_rc9 import extract_ai_observations
from achillesapi.core.access_matrix_rc4 import preflight_rules, run_access_matrix
from achillesapi.dashboard.job_view import viewer_payload
from achillesapi.reporting.professional import summarize_assessment

AI_OBSERVATIONS = [
    'Endpoint /api/v1/tenants/{tenant}/customers/{customer_id} non verifica il tenant (VULN BOLA)',
    'Endpoint /api/v1/tenants/{tenant}/purchase-orders/{order_id} espone ordini di altri tenant (VULN BOLA)',
    'Endpoint /api/v1/tenants/{tenant}/purchase-orders/{order_id}/approve consente approvazioni senza ruolo manager (VULN BFLA)',
]


def ai_job():
    return {
        'engine': 'achillesapi-local-ai', 'provider': 'ollama-local-only',
        'ai_analysis': {'executive_summary': 'Analisi di ipotesi',
                        'risk_observations': AI_OBSERVATIONS,
                        'recommended_tests': [], 'limitations': []},
    }


def test_ai_findings_visible_but_not_confirmed():
    job = ai_job()
    findings = summarize_assessment(job)['findings']
    assert len(findings) == 3
    assert [f['category'] for f in findings] == ['AI_BOLA', 'AI_BOLA', 'AI_BFLA']
    assert all(f['source_type'] == 'ai_hypothesis' for f in findings)
    assert all(f['status'] == 'ai_unverified' and f['confidence'] == 'unverified' for f in findings)
    assert all(f['ai_label'].startswith('AI - ') for f in findings)
    assert all(f['test_payloads'] == [] and f['test_request'] is None for f in findings)
    assert all(not f['evidence']['http_tested'] for f in findings)
    view = viewer_payload(job, action='ai-analyze', job_id='a' * 32)
    assert len(view['findings']) == 3
    assert len(view['ai']) == 1


def test_ai_findings_survive_suite_and_professional_roundtrip():
    orig = summarize_assessment(ai_job())['findings']
    parent = {'engine': 'achillesapi-bounded-suite', 'findings': orig}
    normalized = summarize_assessment(parent)['findings']
    assert len(normalized) == 3
    assert normalized[2]['category'] == 'AI_BFLA'
    assert normalized[0]['source_type'] == 'ai_hypothesis'
    assert normalized[0]['ai_label'] == 'AI - medium'
    professional = {'report_schema':'achillesapi.professional.2','source_kind':'tool_analysis',
                    'summary':{'operations_in_spec':0},'findings':normalized}
    reopened = viewer_payload(professional, action='report', job_id='b'*32)
    assert len(reopened['findings']) == 3
    assert reopened['findings'][0]['test_request'] is None


def test_ai_deduplicated_bounded_and_secret_redacted():
    job = ai_job()
    job['ai_analysis']['risk_observations'] = AI_OBSERVATIONS[:1]*3 + [
        'Endpoint /api/v1/data possibile accesso. Authorization: Bearer never-show-this',
        {'description': 'Token: abc123 Endpoint /api/v1/test BOLA'},
        13, None,
    ]
    result=extract_ai_observations(job)
    assert len(result) == 3
    assert 'never-show-this' not in json.dumps(result)
    assert 'abc123' not in json.dumps(result)
    assert not extract_ai_observations({'ai_analysis':{'risk_observations': 'a string'}})
    assert not extract_ai_observations({'engine': 'plain-plan', 'recommended_tests': ['BOLA']})


def test_matrix_accepts_denied_first_identity(tmp_path: Path):
    spec=tmp_path/'api.yaml'
    spec.write_text('''openapi: 3.0.3
info: {title: Test, version: '1'}
paths:
  /tenants/{tenant}/customers/{customer_id}:
    get:
      parameters:
        - {name: tenant, in: path, required: true, schema: {type: string}}
        - {name: customer_id, in: path, required: true, schema: {type: string}}
      responses: {'200': {description: OK}}
''')
    rules={'rules':[{'id':'cross-tenant','operation':'GET /tenants/{tenant}/customers/{customer_id}',
                     'owner':'owner','other':'colleague',
                     'expected_owner':'deny','expected_other':'deny',
                     'path_values':{'tenant':'acme','customer_id':'c201'}}]}
    normal=preflight_rules(spec,rules,profile_names={'owner','colleague'})
    assert normal[0]['expected_owner']=='deny'
    del rules['rules'][0]['expected_owner']
    assert preflight_rules(spec,rules,profile_names={'owner','colleague'})[0]['expected_owner']=='allow'
    rules['rules'][0]['expected_owner']='unsupported'
    with pytest.raises(ValueError,match='expected_owner'):
        preflight_rules(spec,rules,profile_names={'owner','colleague'})


def test_matrix_reports_first_identity_policy_conflict(monkeypatch,tmp_path):
    from achillesapi.core import access_matrix_rc4
    spec=tmp_path/'api.yaml'
    spec.write_text('''openapi: 3.0.3
info: {title: Test, version: '1'}
paths:
  /x/{id}:
    get:
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {'200': {description: OK}}
''')
    policy={'rules':[{'operation':'GET /x/{id}','id':'r1','owner':'a','other':'b',
                      'path_values':{'id':'abc'},'expected_owner':'deny','expected_other':'deny'}]}
    def fake_compare(*args,**kwargs):
        assert kwargs['expected_owner']=='deny'
        return {'requests_sent':2,'status':'owner_policy_conflict_requires_review',
                'observations':[{'identity':'a','status_code':200},{'identity':'b','status_code':200}],
                'same_body_observed':True}
    monkeypatch.setattr(access_matrix_rc4,'compare_identities',fake_compare)
    auth=Mock(names=['a','b'])
    result=run_access_matrix(spec,policy=policy,base_url='http://127.0.0.1:8795',
                             allowed_hosts={'127.0.0.1'},auth_manager=auth,
                             allow_insecure_http=True,execute=True)
    assert result['summary']['review_required']==1
    findings=viewer_payload(result,action='access-matrix',job_id='a'*32)['findings']
    assert len(findings)==1
    assert 'HTTP 200' in findings[0]['reason']
    assert findings[0]['test_request']=='GET /x/{id}'
    assert findings[0]['test_payloads']==[]


def test_access_matrix_html_has_first_identity_policy_and_ai_filter():
    root=Path(__file__).resolve().parents[1]/'src/achillesapi/dashboard/static'
    html=(root/'index.html').read_text()
    js=(root/'app.js').read_text()
    view=(root/'job-viewer.js').read_text()
    assert 'id="matrixOwnerExpected"' in html
    assert "expected_owner:$('matrixOwnerExpected').value" in js
    assert "['ai','Solo ipotesi AI']" in view
    assert 'Payload: nessuno. L’AI ha generato un’ipotesi' in view


def test_ai_observations_from_nested_advisory_and_correlations():
    # Other Ollama tasks may use different structured response containers.
    parsed = extract_ai_observations({
        'local_ai_advice': {'risk_observations': ['Endpoint /api/v1/items/{id} possible BOLA']},
        'ai_correlation': {'cross_correlations': [
            'Possible SSRF at /api/v1/url/fetch (requires manual verification)',
            'Nessuna evidenza di SQL injection in /api/v1/reports',
        ]},
    })
    assert [x['category'] for x in parsed] == ['AI_BOLA', 'AI_SSRF']
    assert all(x['source_type'] == 'ai_hypothesis' for x in parsed)


def test_suite_job_view_collects_ai_observations(tmp_path, monkeypatch):
    import time
    from fastapi.testclient import TestClient
    from achillesapi.dashboard.server import create_app
    import achillesapi.dashboard.control as ctrl
    monkeypatch.setattr(ctrl, 'SUITE_ORDER', ('analyze-openapi',))
    client = TestClient(create_app(tmp_path/'workspace'), base_url='http://127.0.0.1:8766')
    token = client.get('/api/bootstrap').json()['csrf_token']
    spec = {'openapi':'3.0.3','info':{'title':'Test','version':'1'},
            'paths':{'/ping':{'get':{'responses':{'200':{'description':'OK'}}}}}}
    upload=client.post('/api/import-text',headers={'x-achilles-token':token},
                       json={'kind':'openapi','content':json.dumps(spec)})
    assert upload.status_code==200,upload.text
    start=client.post('/api/control/suite',headers={'x-achilles-token':token},json={
        'config':{'action':'analyze-openapi','specification_id':upload.json()['id']}})
    assert start.status_code==200,start.text
    parent=start.json()['id']
    for _ in range(130):
        state=client.get('/api/jobs/'+parent).json()
        if state.get('status')=='complete':
            break
        time.sleep(.05)
    assert state['status']=='complete',state
    steps=client.get('/api/results/'+parent).json()['steps']
    child=steps[0]['job_id']
    (tmp_path/'workspace'/'reports'/(child+'.json')).write_text(json.dumps(ai_job()))
    view=client.get('/api/job-view/'+parent)
    assert view.status_code==200,view.text
    findings=view.json()['suite_findings']
    assert len(findings)==3,findings
    assert all(f['source_job_id']==child for f in findings)
    assert all(f['source_type']=='ai_hypothesis' for f in findings)
    assert not any(f.get('test_payloads') for f in findings)


def test_ai_report_export_keeps_explanation_and_no_fake_payloads(tmp_path):
    from achillesapi.reporting.professional import write_professional_report
    source=tmp_path/'input.json'
    source.write_text(json.dumps(ai_job()))
    outputs=write_professional_report(source,tmp_path/'export',formats=('json','html','md'))
    assert len(outputs)==3
    exported=json.loads((tmp_path/'export'/'achilles-report.json').read_text())
    assert len(exported['findings'])==3
    assert 'AI - medium' in (tmp_path/'export'/'achilles-report.md').read_text()
    assert 'Payload inviati' in (tmp_path/'export'/'achilles-report.html').read_text()
    # Reopening an already-exported normalized report must not drop the items.
    more=write_professional_report(tmp_path/'export'/'achilles-report.json',tmp_path/'second',formats=('json',))
    assert len(json.loads(more[0].read_text())['findings'])==3
