"""RC20–RC23 offline, API and UI integration checks. No unauthorized target traffic."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner
from bs4 import BeautifulSoup

from achillesapi.cli import app
from achillesapi.core.openapi import load_openapi
from achillesapi.core.autonomous_workspace_rc20 import build_workspace
from achillesapi.core.diagnostics_rc20 import diagnose, reason_code, enrich_steps
from achillesapi.core.authorization_planner_rc21 import (
    build_authorization_plan, allowlisted_agent_intentions)
from achillesapi.core.scanner_coverage_rc22 import scanner_plan
from achillesapi.core.evidence_verification_rc22 import verify_controlled_cases
from achillesapi.core.release_validation_rc23 import audit_campaign, readiness_check
from achillesapi.dashboard.server import create_app

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'tests/fixtures/independent-api-lab/openapi.json'


def test_workspace_does_not_infer_permission():
    plan=build_workspace(load_openapi(SPEC))
    assert plan['requests_sent']==0
    assert len(plan['workflow_candidates'])>=2
    assert plan['api']['operations']>=20
    groups={g['id']:g for g in plan['groups']}
    assert groups['openapi']['status']=='ready'
    assert groups['bola']['status']=='requires_input'
    assert groups['mass_assignment']['status']=='requires_input'
    assert any(x['code']=='POLICY_REQUIRED' for x in groups['bola']['issues'])
    assert all(g['status']!='ready' for g in plan['groups'] if g['id'] in {'bfla','mass_assignment'})


def test_autofill_does_not_grant_active_approval():
    data=build_workspace(load_openapi(SPEC),has_auth=True,has_policy=True,
        has_fixture=True,has_scope=True,http_approved=True,writes_approved=False)
    groups={g['id']:g for g in data['groups']}
    assert groups['read_only_http']['status']=='ready'
    assert 'WRITES_CONSENT_REQUIRED' in {issue['code'] for issue in groups['bfla']['issues']}


def test_diagnostics_codes_map_to_existing_dashboard_elements():
    html=BeautifulSoup((ROOT/'src/achillesapi/dashboard/static/index.html').read_text(),
                      'html.parser')
    for code in ['SPEC_REQUIRED','SCOPE_REQUIRED','AUTH_REQUIRED',
                 'PATCH_FIELDS_REQUIRED','CLEANUP_REQUIRED','AI_UNAVAILABLE']:
        issue=diagnose(code)
        assert html.find(id=issue['section']) is not None,code
        assert html.find(id=issue['field']) is not None,code
    assert diagnose('NOT_RECOGNIZED')['code']=='TASK_ERROR'
    assert reason_code('rc13-assess','Sonde JSON PATCH requires fixture')=='PATCH_FIELDS_REQUIRED'
    rows=enrich_steps([{'action':'rc13-assess','status':'skipped',
                        'reason':'Sonde JSON PATCH requires fixture'},
                       {'action':'assess','status':'complete'}])
    assert rows[0]['remediation']['section']=='massAssignmentPanel'
    assert 'remediation' not in rows[1]


def test_authorization_plan_cross_resources_with_no_invented_ids():
    result=build_authorization_plan(load_openapi(SPEC),owner='owner',others=['other'],
                                    expected_other='deny')
    assert result['counts']['BOLA']>=1
    assert result['counts']['BFLA']>=1
    assert result['counts']['BOPLA_MASS_ASSIGNMENT']>=1
    for case in result['test_cases']:
        assert case['scope']=='operator_approved_disposable_resource'
        if case['category']!='BOLA':
            assert any(e['code']=='WRITES_CONSENT_REQUIRED' for e in case['issues'])
    allowed=allowlisted_agent_intentions(result,approved_manifest=True,approve_writes=False)
    assert not any(item['category']!='BOLA' for item in allowed['approved_intentions'])
    assert len(allowed['blocked_intentions'])>=1
    with pytest.raises(ValueError,match='unsupported'):
        allowlisted_agent_intentions(result,requested_categories=['arbitrary_http'])


def test_scanner_plan_discovers_nested_surfaces_and_write_gates():
    spec=load_openapi(SPEC)
    plan=scanner_plan(spec)
    assert plan['network_requests_sent']==0
    assert plan['coverage']['sql_error']['candidate_fields']>=1
    assert all(t['state']=='blocked' for t in plan['tests'])
    planned=scanner_plan(spec,approved_http=True)
    assert any(t['state']=='ready' for t in planned['tests'] if not t['requires_write'])
    assert all(t['state']=='blocked' for t in planned['tests'] if t['requires_write'])
    with pytest.raises(ValueError): scanner_plan(spec,max_points=1000)


def test_controlled_verification_requires_independent_negative_control():
    evidence={'operation':'GET /orders/{id}','category':'BOLA','case_id':'a',
              'expected_other':'deny',
              'control':{'owner_status':200,'marker_verified':True},
              'attempt':{'other_status':200,'marker_verified':True},
              'replay':{'same_identity':True,'same_object_marker':True}}
    report=verify_controlled_cases([evidence,evidence])
    assert report['unique_cases']==1
    assert report['observations'][0]['status']=='probable_policy_violation'
    evidence['control']['negative_control_denied']=True
    assert verify_controlled_cases([evidence])['observations'][0]['status']=='confirmed_policy_violation'
    evidence['expected_other']=None
    assert verify_controlled_cases([evidence])['observations'][0]['status']=='inconclusive'
    evidence['expected_other']='deny';evidence['control']['marker_verified']=False
    assert verify_controlled_cases([evidence])['observations'][0]['status']=='inconclusive'


def test_report_gate_counts_skipped_not_success():
    report=audit_campaign({'status':'complete','steps':[
        {'action':'assess','status':'complete'},
        {'action':'rc13-assess','status':'skipped','reason':'Sonde JSON PATCH require fields'}],
        'limitations':['some methods not exercised']})
    assert report['coverage_ratio']==.5
    assert report['unresolved'][0]['issue']['code']=='PATCH_FIELDS_REQUIRED'
    assert report['quality']=='review_ready'
    assert readiness_check(regression_passed=10,regression_failed=0)['ready_for_stable'] is False


def test_real_dashboard_endpoints_and_csrf(tmp_path):
    client=TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766')
    csrf=client.get('/api/bootstrap').json()['csrf_token']
    with SPEC.open('rb') as file:
        response=client.post('/api/upload',files={'file':('openapi.json',file,'application/json')},
                             headers={'x-achilles-token':csrf})
    assert response.status_code==200,response.text
    sid=response.json()['id']
    result=client.get('/api/control/autopilot/'+sid)
    assert result.status_code==200,result.text
    assert result.json()['network_requests_sent']==0
    assert result.json()['workspace']['workflow_candidates']
    assert client.get('/assets/autopilot-rc23.js').status_code==200
    assert client.post('/api/control/autopilot/preflight',json={'specification_id':sid}).status_code==403
    p=client.post('/api/control/autopilot/preflight',json={'specification_id':sid},
                  headers={'x-achilles-token':csrf})
    assert p.status_code==200 and p.json()['workspace']['requests_sent']==0
    p=client.post('/api/control/autopilot/preflight',json={'specification_id':sid,'writes_approved':'yes'},
                  headers={'x-achilles-token':csrf})
    assert p.status_code==422
    assert client.post('/api/control/rc22/verify-controlled',json={'cases':[]}).status_code==403
    r=client.post('/api/control/rc22/verify-controlled',json={'cases':[]},
                  headers={'x-achilles-token':csrf})
    assert r.status_code==200 and r.json()['unique_cases']==0
    assert client.get('/api/control/rc23/audit/'+'a'*32).status_code==403


def test_cli_exposes_all_four_milestones(tmp_path):
    runner=CliRunner()
    for command,engine in [('rc20-plan','achilles-workspace-autopilot-rc20'),
                           ('rc21-plan','achilles-authorization-plan-rc21'),
                           ('rc22-coverage','achilles-scanner-coverage-rc22')]:
        output=tmp_path/(command+'.json')
        process=runner.invoke(app,[command,str(SPEC),'--output',str(output)])
        assert process.exit_code==0,process.output
        assert json.loads(output.read_text())['engine']==engine
    report=tmp_path/'suite.json'; report.write_text(json.dumps({'steps':[{'status':'skipped','action':'rc13-assess',
        'reason':'Sonde JSON PATCH'}],'limitations':['no active scope']}))
    output=tmp_path/'audit.json'
    process=runner.invoke(app,['rc23-report-audit',str(report),'--output',str(output)])
    assert process.exit_code==0,process.output
    assert json.loads(output.read_text())['task_counts']['skipped']==1


def test_dashboard_static_separates_workflows_and_optional_preflight():
    html=BeautifulSoup((ROOT/'src/achillesapi/dashboard/static/index.html').read_text(), 'html.parser')
    assert html.find(id='autopilotPanel')
    assert html.find(id='autopilotChecks')
    assert any('autopilot-rc23.js' in x.get('src','') for x in html.select('script[src]'))
    src=(ROOT/'src/achillesapi/dashboard/static/app.js').read_text()
    assert 'window.AchillesAutopilot?.refresh(specId)' in src
    assert not any(x in (ROOT/'src/achillesapi/dashboard/static/autopilot-rc23.js').read_text()
                   for x in ['innerHTML','approve_writes = true','fetch("https://'])
