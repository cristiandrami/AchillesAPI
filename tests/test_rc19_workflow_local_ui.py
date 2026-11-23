"""Regression contract: workflow choices must be independent per section."""
from pathlib import Path
from bs4 import BeautifulSoup

ROOT=Path(__file__).parents[1]/'src/achillesapi/dashboard/static'


def test_independent_workflow_choosers_exist():
    soup=BeautifulSoup((ROOT/'index.html').read_text(encoding='utf8'),'html.parser')
    fields={
        'massWorkflowSelect':'massAssignmentPanel',
        'bflaWorkflowSelect':'bflaPanel',
        'workflowRunSelect':'workflowRunPanel',
        'bodyProbeWorkflowSelect':'massAssignmentPanel',
        'rc13WorkflowSelect':'rc13Panel',
        'suiteWorkflowSelect':'fullSuite',
    }
    for id,panel in fields.items():
        field=soup.find(id=id)
        assert field and field.name=='select'
        assert field.find_parent(id=panel) is not None
    assert len({x['id'] for x in soup.select('[id]')})==len(soup.select('[id]'))


def test_specialized_sections_are_progressive_disclosure():
    soup=BeautifulSoup((ROOT/'index.html').read_text(encoding='utf8'),'html.parser')
    assert soup.find(id='simpleAdvancedToggle')
    for id in ('step4','loginConfigPanel','loginKeysPanel','qualityGatePanel','benchmarkPanel','rc13Panel'):
        assert 'simple-advanced-hidden' in soup.find(id=id)['class']
    assert 'simple-advanced-hidden' not in soup.find(id='massAssignmentPanel')['class']


def test_no_global_wizard_dependency_for_mutation_and_bfla():
    js=(ROOT/'app.js').read_text(encoding='utf8')
    assert "const c=localCandidate('mass');" in js
    assert "localWorkflowState.mass.get(key)" in js
    assert "localWorkflowState.bfla.get(key)" in js
    assert "workflow_config_ids=[...new Set(" in js
    assert "workflow_config_ids:ready.workflow_config_ids||[]" in js
    assert "await scopedWorkflowConfig('rc13WorkflowSelect')" in js
    assert "await scopedWorkflowConfig('bodyProbeWorkflowSelect')" in js
