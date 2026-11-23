"""Ollama runtime truthfulness and reproducible sanitized injection findings."""
import json
import time
from urllib.error import URLError

from fastapi.testclient import TestClient

import achillesapi.dashboard.control as control
from achillesapi.dashboard.server import create_app
from achillesapi.reporting.professional import summarize_assessment

SPEC = {'openapi':'3.0.3', 'info':{'title':'Generic','version':'1'},
        'paths':{'/search':{'get':{'parameters':[{'name':'term','in':'query','schema':{'type':'string'}}],
                    'responses':{'200':{'description':'OK'}}}}}}


def finding():
    from achillesapi.core.injection_engine_rc5 import PAIRS
    return {'category':'possible_sql_boolean_injection','operation':'GET /search',
            'parameter':'term','location':'query','severity':'medium',
            'reason':'Differenza tra condizioni di prova positive e negative',
            'test_payloads':list(PAIRS['sql_boolean']),
            'evidence':{'baseline':{'status':200,'length':10,'body_digest':'a'*16},
                        'variants':[{'status':200,'length':20,'body_digest':'b'*16},
                                    {'status':200,'length':10,'body_digest':'a'*16}]}}


def test_injection_report_explains_and_lists_actual_probes():
    doc=summarize_assessment({'engine':'achilles-injection-assessment-rc5','findings':[finding()]})
    item=doc['findings'][0]
    assert 'SQL Injection' in item['what_found']
    assert item['verification_guidance']
    assert len(item['test_payloads'])==2
    assert item['test_input']=={'location':'query','parameter':'term','baseline':'__achilles_normal_control__'}
    assert item['evidence']['http_comparison']['baseline']['status']==200
    assert item['evidence']['http_comparison']['variants'][0]['length']==20
    assert 'body' not in item['evidence']


def test_suite_report_preserves_payloads_and_blocks_injected_secrets():
    normal=summarize_assessment({'engine':'achilles-injection-assessment-rc5','findings':[finding()]})['findings'][0]
    reconstructed=summarize_assessment({'engine':'achillesapi-bounded-suite','findings':[normal]})['findings'][0]
    assert reconstructed['test_payloads']==normal['test_payloads']
    assert reconstructed['evidence']['http_comparison']['variants'][0]['status']==200
    attack=finding()
    attack['test_payloads']=['Bearer very-secret-token']
    attack['evidence']['body']='sensitive content'
    out=summarize_assessment({'engine':'achilles-injection-assessment-rc5','findings':[attack]})['findings'][0]
    assert not out['test_payloads']
    assert 'body' not in out['evidence']


def test_ai_readiness_handles_model_name_and_unreachable_service(monkeypatch):
    monkeypatch.setattr(control, '_local_ollama_json', lambda *a, **kw:{'models':[{'name':'achilles-local:latest'}, {'name':'qwen3:8b'}]})
    assert control._ollama_readiness('achilles-local')['status']=='ready'
    assert control._ollama_readiness('qwen3:8b')['status']=='ready'
    assert control._ollama_readiness('does-not-exist')['status']=='unavailable'
    monkeypatch.setattr(control, '_local_ollama_json', lambda *a, **kw: (_ for _ in ()).throw(URLError('refused')))
    assert 'non raggiungibile' in control._ollama_readiness('achilles-local')['message']


def test_ai_result_must_really_contain_model_output():
    assert control._ai_output_present('ai-analyze', {'provider':'ollama-local-only','ai_analysis':{'executive_summary':'test'}})
    assert not control._ai_output_present('ai-analyze', {'provider':'ollama-local-only'})
    assert not control._ai_output_present('scan', {'ai_analysis':None})
    assert control._ai_output_present('scan', {'ai_analysis':{'executive_summary':'test'}})


def test_suite_skips_missing_ollama_but_continues_deterministic(monkeypatch,tmp_path):
    monkeypatch.setattr(control,'SUITE_ORDER',('analyze-openapi','ai-analyze','scan'))
    monkeypatch.setattr(control,'_ollama_readiness',lambda model:{'status':'unavailable','model':model,'message':'model offline'})
    client=TestClient(create_app(tmp_path/'repo'),base_url='http://127.0.0.1:8766')
    header={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    response=client.post('/api/import-text',headers=header,json={'kind':'openapi','content':json.dumps(SPEC)})
    assert response.status_code==200,response.text
    spec_id=response.json()['id']
    start=client.post('/api/control/suite',headers=header,json={
        'config':{'action':'analyze-openapi','specification_id':spec_id,'model':'qwen3:8b'},
        'include_ai':True})
    assert start.status_code==200,start.text
    job_id=start.json()['id']
    for _ in range(150):
        state=client.get('/api/jobs/'+job_id).json()
        if state['status'] not in {'orchestrating','running'}:break
        time.sleep(.06)
    assert state['status']=='complete',state
    report=client.get('/api/results/'+job_id).json()
    assert report['ai_readiness']['status']=='unavailable'
    assert [s['status'] for s in report['steps']]==['complete','skipped','complete'],report['steps']
    assert report['steps'][1]['ai_status']=='not_invoked'
    assert report['steps'][2]['ai_status']=='not_invoked'
    assert 'model offline' in report['steps'][2]['ai_note']
    view=client.get('/api/job-view/'+job_id).json()
    assert view['ai_readiness']['status']=='unavailable'


def test_generic_coverage_explanations_are_truthful():
    from achillesapi.core.coverage_explainer_rc9 import explain_suite_gaps
    gaps=explain_suite_gaps([
        {'action':'access-probe','status':'skipped','reason':'missing path ID'},
        {'action':'workflow-graph','status':'failed','reason':'invalid graph'},
        {'action':'injection-assess','status':'complete'},
    ])
    assert len(gaps)==2
    assert all('Non testato' in x['interpretation'] for x in gaps)
    assert all(x['next_step'] for x in gaps)


def test_generic_disposable_manifest_to_validated_dag():
    from pathlib import Path
    import yaml
    from achillesapi.core.workflow_graph_bridge_rc9 import derive_disposable_graph
    from achillesapi.core.production_v031 import workflow_graph
    from achillesapi.core.openapi import analyze_openapi_file
    folder=Path(__file__).resolve().parent/'fixtures'/'independent-api-lab'
    manifest=yaml.safe_load((folder/'resources.yaml').read_text())
    graph=derive_disposable_graph(manifest)
    result=workflow_graph(analyze_openapi_file(folder/'openapi.json'),graph)
    assert result['valid']
    assert result['execution_order'].index('ticket_cleanup') < result['execution_order'].index('project_cleanup')
    assert graph['steps'][0]['operation']=='POST /projects'
    assert all(not any(key in str(step) for key in ('body','token','password')) for step in graph['steps'])


def test_cannot_invent_dag_without_cleanup():
    import pytest
    from achillesapi.core.workflow_graph_bridge_rc9 import derive_disposable_graph
    with pytest.raises(ValueError,match='DELETE'):
        derive_disposable_graph({'resources':[{'name':'abc','create':'POST /x','read':'GET /x/{id}'}]})


def test_authorization_mismatch_explains_policy_without_tokens():
    raw={'engine':'achilles-multi-resource-assessment',
         'findings':[{'category':'AUTHORIZATION_POLICY_MISMATCH',
                      'operation':'GET /tenants/{tenant}/expenses/{expense_id}',
                      'resource':'expense', 'expected':'deny', 'observed_status':200,
                      'description':'The response contradicts the policy.',
                      'token':'Bearer private-hidden'}]}
    found=summarize_assessment(raw)['findings'][0]
    assert found['test_request']=='GET /tenants/{tenant}/expenses/{expense_id}'
    assert found['evidence']['expected_access']=='deny'
    assert found['evidence']['observed_http_status']==200
    assert found['test_payloads']==[]
    assert 'Bearer' not in json.dumps(found)

def test_dashboard_ai_checkbox_explicitly_describes_local_optin():
    from pathlib import Path
    page=Path(control.__file__).with_name('static').joinpath('index.html').read_text(encoding='utf-8')
    assert 'id="suiteAI"' in page
    assert 'Usa Ollama nei task che lo supportano' in page


def test_exact_payload_quotes_are_not_double_escaped_in_report():
    from achillesapi.core.injection_engine_rc5 import PAIRS
    candidate=finding()
    candidate['category']='possible_nosql_injection'
    candidate['test_payloads']=list(PAIRS['nosql'])
    clean=summarize_assessment({'engine':'achilles-injection-assessment-rc5', 'findings':[candidate]})['findings'][0]
    assert clean['test_payloads'][0]=='{"$ne":null}'
    twice=summarize_assessment({'engine':'achillesapi-bounded-suite','findings':[clean]})['findings'][0]
    assert twice['test_payloads']==clean['test_payloads']
