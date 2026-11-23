"""Regression coverage: OpenAPI-driven workflow UX with independent sections."""
from pathlib import Path

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'src' / 'achillesapi' / 'dashboard' / 'static'
OPENAPI = ROOT / 'tests' / 'fixtures' / 'independent-api-lab' / 'openapi.json'


def test_each_security_area_has_an_independent_workflow_choice_and_visible_preview():
    html = BeautifulSoup((ASSETS / 'index.html').read_text(encoding='utf8'), 'html.parser')
    assert html.find(id='workflowOverview').find(id='workflowDetectedList')
    for panel, select, preview in [
        ('authMatrixSection', 'accessWorkflowSelect', 'accessWorkflowPreview'),
        ('massAssignmentPanel', 'massWorkflowSelect', 'massWorkflowPreview'),
        ('bflaPanel', 'bflaWorkflowSelect', 'bflaWorkflowPreview'),
        ('rc13Panel', 'rc13WorkflowSelectAuto', 'rc13WorkflowSelectPreview'),
        ('fullSuite', 'suiteWorkflowSelectAuto', 'suiteWorkflowSelectPreview'),
    ]:
        parent = html.find(id=panel)
        assert parent is not None
        assert parent.find(id=select) is not None, (panel, select)
        assert parent.find(id=preview) is not None, (panel, preview)
    assert html.find(id='bodyProbeWizard').find_parent(id='massAssignmentPanel')
    assert html.find(id='guidedMutationBody').find_parent(id='massAssignmentPanel')
    assert html.find(id='massAutoFields').find_parent(id='massAssignmentPanel')
    assert html.find(id='guidedBflaAction').find_parent(id='bflaPanel')
    ids = [tag['id'] for tag in html.select('[id]')]
    assert len(ids) == len(set(ids))


def test_discovery_is_triggered_on_spec_upload_without_manual_discovery_button():
    script = (ASSETS / 'app.js').read_text(encoding='utf8')
    visual = (ASSETS / 'workflow-autopilot.js').read_text(encoding='utf8')
    assert 'try{await guideDiscover()}' in script
    assert 'window.AchillesWorkflowUX?.refresh(manifestCandidates,savedWorkflows)' in script
    assert 'mutation_field_specs' in visual
    assert 'statusText(candidate)' in visual
    assert 'candidate.ready' in visual
    assert 'textContent' in visual
    assert 'innerHTML' not in visual
    assert 'window.fetch' not in visual and 'fetch(' not in visual
    assert 'approve_writes' not in visual
    assert 'saveLocalPanel' in visual
    assert 'queueMicrotask' in visual  # Prevent cross-workflow edits from leaking on change.


def test_candidate_indices_remain_backend_owned_and_incomplete_workflows_stay_read_only(tmp_path):
    app = create_app(tmp_path / 'workspace')
    with TestClient(app, base_url='http://127.0.0.1:8766') as client:
        assert client.get('/assets/workflow-autopilot.js').status_code == 200
        csrf = client.get('/api/bootstrap').json()['csrf_token']
        with OPENAPI.open('rb') as stream:
            response = client.post('/api/upload', files={'file': ('openapi.json', stream, 'application/json')},
                                   headers={'x-achilles-token': csrf})
        assert response.status_code == 200
        spec_id = response.json()['id']
        candidates = client.get(f'/api/control/manifest/candidates/{spec_id}').json()['candidates']
        assert candidates
        candidate = candidates[0]
        assert candidate['mutation'] == 'PATCH /projects/{project_ref}'
        assert candidate['mutation_field_specs']['note']['type'] == 'string'
        assert 'ready' in candidate
        assert client.get('/').status_code == 200
