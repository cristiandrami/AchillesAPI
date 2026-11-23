"""Release candidate guardrails: per-workflow PATCH approvals, finite campaign budgets."""
import json
from pathlib import Path

from fastapi.testclient import TestClient
from achillesapi.core.campaign_ledger import CampaignLedger,CampaignBudgetError
from achillesapi.dashboard.server import create_app
from test_rc25_multiflow_retry_budget import upload
from test_v034 import sample, manifest


def test_explicit_budget_extension_keeps_spent_attempts(tmp_path):
    ledger=CampaignLedger.create(tmp_path/'campaign.db',limit=3,rate=10,runtime_seconds=120)
    ledger.finish(ledger.reserve(),status=200)
    ledger.finish(ledger.reserve(),status=403)
    assert ledger.snapshot()['remaining']==1
    assert ledger.extend_limit(6)['remaining']==4
    assert ledger.snapshot()['attempted']==2
    try:
        ledger.extend_limit(601)
        assert False,'Limit exceeded'
    except CampaignBudgetError:
        pass
    assert ledger.snapshot()['limit']==6


def test_multiworkflow_fields_require_approved_manifests(tmp_path):
    with TestClient(create_app(tmp_path/'app'),base_url='http://127.0.0.1:8766') as client:
        h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        spec=upload(client,h,'openapi',sample())
        config=upload(client,h,'config',manifest())
        data={
          'config':{'action':'auto-assess','specification_id':spec},
          'workflow_config_ids':[config],
          'include_rc13':True,'include_writes':True,'rc13_body_probes':True,
          'rc13_body_fields_by_workflow':{'f'*32:['PATCH /unknown::admin']}}
        r=client.post('/api/control/suite',headers=h,json=data)
        assert r.status_code==422,r.text
        data['rc13_body_fields_by_workflow']={config:['field1','field2','field3','field4','field5']}
        r=client.post('/api/control/suite',headers=h,json=data)
        assert r.status_code==422,r.text


def test_patch_approvals_persist_per_workflow_in_dashboard():
    root=Path(__file__).resolve().parents[1]/'src/achillesapi/dashboard/static'
    app=(root/'app.js').read_text(encoding='utf-8')
    html=(root/'index.html').read_text(encoding='utf-8')
    backend=(root.parent/'control.py').read_text(encoding='utf-8')
    assert 'const bodyProbeSelections=new Map()' in app
    assert 'bodyProbeSelections.set(key,bodyProbeFields.slice())' in app
    assert 'rc13_body_fields_by_workflow:ready.rc13_body_fields_by_workflow' in app
    assert 'id="bodyProbeDetectAll"' in html
    assert 'id="bodyProbeCoverage"' in html
    assert 'selected_targets = [(workflow, fields)' in backend
    assert "rc13_cfg.config_id = target_workflow" in backend
    assert '/assets/rc27-polish.css' in html
    assert '/assets/app.js?v=rc27-multiflow-1' in html


def test_budget_retry_contract_uses_actual_http_attempts():
    root=Path(__file__).resolve().parents[1]/'src/achillesapi/dashboard/static'
    js=(root/'job-viewer.js').read_text(encoding='utf-8')
    assert 'r.actual_remaining_requests' in js
    assert 'I tentativi già effettuati restano conteggiati' in js


def test_suite_reports_patch_step_for_each_approved_manifest(tmp_path, monkeypatch):
    import time
    import achillesapi.dashboard.control as control
    monkeypatch.setattr(control,'SUITE_ORDER',())
    with TestClient(create_app(tmp_path/'multi-patch'),base_url='http://127.0.0.1:8766') as client:
        h={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        spec=upload(client,h,'openapi',sample())
        first=manifest()
        first['resources']=first['resources'][:1]
        second=json.loads(json.dumps(first))
        second['resources'][0]['name']='second_collection'
        refs=[upload(client,h,'config',x) for x in (first,second)]
        auth=upload(client,h,'auth',{'profiles':[{'name':'owner','type':'bearer','token':'demo-owner'}]})
        result=client.post('/api/control/suite',headers=h,json={
          'config':{'action':'auto-assess','specification_id':spec,'auth_config_id':auth,
                    'base_url':'http://127.0.0.1:9998','allow_host':'127.0.0.1',
                    'acknowledgment':True,'approve_writes':True,'allow_insecure_http':True,
                    'max_requests':20},
          'include_active':True,'workflow_config_ids':refs,'include_rc13':True,
          'include_writes':True,'rc13_body_probes':True,
          'rc13_body_fields_by_workflow':{refs[0]:['field_a'],refs[1]:['field_b']},
          'max_total_requests':100})
        assert result.status_code==200,result.text
        job=result.json()['id']
        for _ in range(120):
            state=client.get('/api/jobs/'+job).json()
            if state['status']=='complete':break
            time.sleep(.04)
        assert state['status']=='complete',state
        report=client.get('/api/results/'+job).json()
        assert report['summary']['total']==2,report.get('steps')
        assert [entry['workflow_config_id'] for entry in report['steps']]==refs
        assert all(entry['action']=='rc13-assess' for entry in report['steps'])


def test_new_dashboard_assets_resolve_without_404(tmp_path):
    with TestClient(create_app(tmp_path/'assets'),base_url='http://127.0.0.1:8766') as client:
        home=client.get('/')
        assert home.status_code==200
        assert 'bodyProbeDetectAll' in home.text
        assert 'v1.0.0-rc.27' in home.text
        style=client.get('/assets/rc27-polish.css')
        assert style.status_code==200
        assert 'body-probe-coverage' in style.text
        script=client.get('/assets/app.js')
        assert script.status_code==200
        assert 'bodyProbeSelections' in script.text
