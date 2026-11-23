"""RC9 UX: repeatable guided creation, selection after wizard, explicit launch consent."""
from __future__ import annotations

import json
from pathlib import Path

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / 'src' / 'achillesapi' / 'dashboard' / 'static'


def test_workflow_picker_is_after_guided_builder_and_before_manual_yaml(tmp_path):
    with TestClient(create_app(tmp_path/'dashboard'), base_url='http://127.0.0.1:8766') as client:
        response = client.get('/')
        assert response.status_code == 200
        html = BeautifulSoup(response.text, 'html.parser')
        drawer = html.find(id='guidedDrawer')
        library = html.find(id='workflowLibraryPanel')
        assert drawer and library
        # RC19 separates creation from launching existing workflows. The picker
        # remains usable even when the creation wizard is collapsed.
        assert drawer.find_parent(id='workflowCreateSection')
        assert library.find_parent(id='workflowManageSection')
        assert drawer.find(id='workflowLibraryPanel') is None
        assert response.text.index('id="guidedDrawer"') < response.text.index('id="workflowLibraryPanel"')
        assert html.find(id='guidedDrawer').name == 'details'
        assert html.find(id='workflowManageSection').name == 'section'
        assert html.find(id='workflowRunSingle') and html.find(id='workflowRunCombined')
        assert html.find(id='workflowRunHttpAck') and html.find(id='workflowRunWritesAck')
        assert html.find(id='fullSuite') and html.find(id='ollamaPanel')
        assert 'src="/assets/app.js?v=rc27-multiflow-1"' in response.text
        js = client.get('/assets/app.js').text
        assert 'Configura un altro workflow (torna allo Step 1)' in js
        assert 'Esegui il test con questo workflow' in js
        assert 'guideStartAnother' in js
        assert 'launchMultiWorkflow' in js
        assert 'resetWorkflowRunApprovals' in js


def test_no_target_requests_during_guided_backend_config(tmp_path):
    """Backend is still purely offline during manifest guided creation."""
    from test_rc9_independent_enterprise import SPEC
    import yaml
    from achillesapi.dashboard.manifest_builder import discover_manifest_candidates

    with TestClient(create_app(tmp_path/'dashboard'), base_url='http://127.0.0.1:8766') as client:
        csrf = client.get('/api/bootstrap').json()['csrf_token']
        headers = {'x-achilles-token': csrf}
        spec = client.post('/api/import-text', headers=headers, json={
            'kind':'openapi','name':'generic.json','content':json.dumps(SPEC)})
        assert spec.status_code == 200
        auth = client.post('/api/import-text', headers=headers, json={
            'kind':'auth','name':'auth.yaml','content':yaml.safe_dump({'profiles':[
                {'name':'owner','type':'bearer','token':'fake-owner'},
                {'name':'other','type':'bearer','token':'fake-other'}
            ]})})
        assert auth.status_code == 200
        sid,aid = spec.json()['id'],auth.json()['id']
        candidates = client.get(f'/api/control/manifest/candidates/{sid}').json()['candidates']
        configs = []
        for route, body, marker, identifier in [
            ('/projects',{'title':'temporary-project'},'title','/data/id'),
            ('/documents',{'description':'temporary-document'},'description','/payload/documentRef')
        ]:
            candidate_index = next(i for i,c in enumerate(candidates) if c['create'].endswith(route))
            created = client.post('/api/control/manifest/guided',headers=headers,json={
                'specification_id':sid,'auth_config_id':aid,'candidate_index':candidate_index,
                'identity':'owner','other_identity':'other','deny_other':True,'marker':marker,
                'identifier':identifier,'body':body,'path_values':{'tenantId':'test-tenant'}})
            assert created.status_code == 200,created.text
            imported = client.post('/api/import-text', headers=headers, json={
                'kind':'config','content':created.json()['yaml'],'name':'resources.yaml'})
            assert imported.status_code == 200, imported.text
            configs.append(imported.json()['id'])
        assembled = client.post('/api/control/manifest/compose',headers=headers,json={
            'specification_id':sid,'auth_config_id':aid,'config_ids':configs})
        assert assembled.status_code == 200, assembled.text
        assert assembled.json()['resources'] == 2


def test_workflow_ux_js_controls():
    import shutil
    import subprocess
    import pytest
    if shutil.which('node') is None:
        pytest.skip('Node.js missing')
    run = subprocess.run(['node', str(ROOT/'tests/js_rc9_workflow_ux.cjs')],
                         text=True, capture_output=True, timeout=12)
    assert run.returncode == 0, run.stdout + run.stderr
    assert '12 controller checks passed' in run.stdout
