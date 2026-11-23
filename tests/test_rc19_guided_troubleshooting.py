"""Regression for actionable dashboard errors and safe partial-suite startup."""
from pathlib import Path
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app

BASE = Path(__file__).resolve().parents[1]
STATIC = BASE / 'src' / 'achillesapi' / 'dashboard' / 'static'


def test_dashboard_serves_guided_remediation_and_nonblocking_suite():
    html = BeautifulSoup((STATIC/'index.html').read_text(encoding='utf-8'), 'html.parser')
    assert html.find(id='suiteExecutionNotice')
    assert any('issue-guide.js' in x.get('src','') for x in html.select('script[src]'))
    assert html.find(id='massAssignmentPanel').find(id='bodyProbeWizard')
    assert html.find(id='bodyProbeWizard').find(id='bodyProbeWorkflowSelect')
    src=(STATIC/'app.js').read_text(encoding='utf-8')
    assert 'async function prepareSuiteLaunch()' in src
    assert "if(!include_writes){params.config_id=null;params.approve_writes=false;}" in src
    assert "window.AchillesIssueGuide?.renderList(skipped,'suiteStatus')" in src
    assert "window.AchillesIssueGuide.report(text,at)" in src
    assert "if($('suiteRc13Body').checked){requireBodyProbeFields();" not in src[src.index('async function runSuite()'):src.index('function explainJobError')]
    assert "if(!specId)throw Error('Passaggio 1" in src


def test_guide_locations_are_real_dom_ids_and_never_autoconsent():
    script=(STATIC/'issue-guide.js').read_text(encoding='utf-8')
    html=BeautifulSoup((STATIC/'index.html').read_text(encoding='utf-8'), 'html.parser')
    for id in ['step1','step2','step3','workflowCreateSection','workflowManageSection',
               'massAssignmentPanel','bflaPanel','authMatrixSection','fullSuite',
               'rc13Panel','agentOptionsSection','loginConfigPanel','loginKeysPanel',
               'securityScannerOptionsSection','step5','advancedToolsGroup']:
        assert html.find(id=id) is not None, id
        assert id in script
    assert 'innerHTML' not in script
    assert 'fetch(' not in script
    assert 'approve_writes=' not in script
    assert "if(parent.matches('details'))parent.open=true" in script


def test_assets_load_and_server_still_rejects_missing_consent(tmp_path):
    with TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766') as client:
        assert client.get('/assets/issue-guide.js').status_code==200
        page=client.get('/')
        assert page.status_code==200
        assert 'issue-guide.js' in page.text
        # The backend guards must remain independent of any JS downgrade decisions.
        bootstrap=client.get('/api/bootstrap').json()
        resp=client.post('/api/control/suite',json={
            'config': {'action':'auto-assess', 'specification_id':None,
                      'execute':True,'acknowledgment':False,'approve_writes':True},
            'include_active':True,'include_writes':True,
        },headers={'x-achilles-token':bootstrap['csrf_token']})
        assert resp.status_code==422
        assert 'OpenAPI' in str(resp.json())


def test_job_viewer_links_to_exact_configuration_section():
    html=(STATIC/'job-viewer.html').read_text(encoding='utf-8')
    js=(STATIC/'job-viewer.js').read_text(encoding='utf-8')
    assert 'issue-guide.js' in html
    assert 'function fixFromDashboard(message)' in js
    assert "link.href='/#'+encodeURIComponent(guide.section)" in js
    assert 'fixFromDashboard(step.error||step.reason' in js
