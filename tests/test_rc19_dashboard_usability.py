"""RC19: single-purpose dashboard and visible Mass Assignment JSON editor."""
from pathlib import Path
import json
import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.manifest_builder import discover_manifest_candidates, build_guided_manifest

ROOT=Path(__file__).parents[1]
OPENAPI=ROOT/'tests/fixtures/independent-api-lab/openapi.json'
STATIC=ROOT/'src/achillesapi/dashboard/static'


def test_mass_assignment_is_a_visible_dedicated_section():
    html=BeautifulSoup((STATIC/'index.html').read_text(), 'html.parser')
    patch=html.find(id='guidedMutationBody')
    panel=html.find(id='massAssignmentPanel')
    assert panel is not None and patch is not None
    assert patch.find_parent(id='massAssignmentPanel') is not None
    assert patch.find_parent(id='guidedStage3') is None
    assert patch.find_parent(attrs={'hidden':True}) is None
    assert patch.find_parent('label').get('hidden') is None
    assert html.find(id='guidedMutationField').find_parent(id='massAssignmentPanel')
    assert html.find(id='guidedMutationExpectedDeny').find_parent(id='massAssignmentPanel')
    assert html.find(id='bflaPanel').find(id='guidedBflaAction')
    assert html.find(id='authMatrixSection').find(id='matrixDrawer')
    assert html.find(id='workflowCreateSection').find(id='guidedDrawer')
    assert html.find(id='loginConfigPanel').find(id='rc18OidcRun')
    assert html.find(id='loginKeysPanel').find(id='rc18JwksRun')
    assert 'RC18 ·' not in html.find(id='loginConfigPanel').find('h2').get_text()
    # Specialized OAuth/JWKS tools are now available via the advanced-options drawer.
    for ident in ['massAssignmentPanel','bflaPanel']:
        assert html.select_one(f'nav.sidebar a[href="#{ident}"]') is not None
    assert html.select_one('nav.sidebar a[href="#advancedToolsGroup"]') is not None
    assert html.find(id='simpleAdvancedToggle') is not None
    ids=[node['id'] for node in html.select('[id]')]
    assert len(ids)==len(set(ids))


def test_openapi_patch_fields_populate_mass_assignment_editor():
    candidate=discover_manifest_candidates(str(OPENAPI))[0]
    assert candidate['mutation']=='PATCH /projects/{project_ref}'
    assert candidate['mutation_field_specs']['note']['type']=='string'
    assert candidate['mutation_field_count']>=1
    assert 'label' in candidate['field_specs']


def test_placeholder_cannot_be_submitted_as_patch_value():
    candidate=discover_manifest_candidates(str(OPENAPI))[0]
    config=dict(owner='owner',other='other',marker='label',identifier='id',
                body={'label':'temporaneo autorizzato'},deny_other=True,path_values={},
                mutation_expected_deny=True)
    with pytest.raises(ValueError,match='segnaposto'):
        build_guided_manifest(candidate,**config,mutation_body={'note':'REVIEW_VALORE_PATCH'})
    yaml_text=build_guided_manifest(candidate,**config,mutation_body={'note':'nota-di-prova'})
    assert 'PATCH /projects/{project_ref}' in yaml_text
    assert 'expected_policy: deny' in yaml_text
    assert '/note' in yaml_text


def test_dashboard_serves_separated_panels(tmp_path):
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8766') as client:
        response=client.get('/')
        assert response.status_code==200
        assert 'Body JSON PATCH/PUT · sempre modificabile' in response.text
        token=client.get('/api/bootstrap').json()['csrf_token']
        with OPENAPI.open('rb') as stream:
            uploaded=client.post('/api/upload',files={'file':('openapi.json',stream,'application/json')},headers={'x-achilles-token':token})
        assert uploaded.status_code==200
        parsed=client.get('/api/control/manifest/candidates/'+uploaded.json()['id']).json()
        assert parsed['candidates'][0]['mutation_field_specs']['note']['type']=='string'
        assert 'REVIEW_' not in json.dumps(parsed['candidates'][0]['mutation_field_specs'])
