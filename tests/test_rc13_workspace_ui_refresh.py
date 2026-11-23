"""Dashboard visual-refresh regressions: UI labels and wiring only, no target requests."""
import json
from pathlib import Path

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app

STATIC=Path(__file__).resolve().parents[1]/'src'/'achillesapi'/'dashboard'/'static'


def _page():
    return BeautifulSoup((STATIC/'index.html').read_text(encoding='utf-8'),'html.parser')


def test_in_depth_assessment_is_named_for_users_but_ids_are_stable():
    doc=_page()
    assert doc.select_one('#rc13Heading').get_text(strip=True)=='Analisi approfondita API'
    assert doc.select_one('#rc13Run').get_text(strip=True)=='Avvia analisi approfondita'
    assert 'Motore integrato RC13' not in doc.get_text()
    assert doc.select_one('#suiteRc13')['type']=='checkbox'
    for ident in ('rc13Plan','rc13Run','rc13Active','rc13Writes','rc13Body',
                  'rc13AI','rc13Ack','rc13WriteAck','rc13BodyAck','suiteRun'):
        assert doc.select_one('#'+ident), ident
    js=(STATIC/'app.js').read_text(encoding='utf-8')
    assert "'rc13-assess'" in js
    assert "action:$('toolSelect').value" in js
    assert "'/api/control/rc13/run'" in js
    assert "'/api/control/suite'" in js
    assert "displayTaskName" in js


def test_navigation_and_guided_workflow_anchors_exist():
    doc=_page()
    ids={e['id'] for e in doc.select('[id]')}
    assert len(ids)==len(doc.select('[id]'))
    for link in doc.select('nav.sidebar a[href^="#"]'):
        assert link['href'][1:] in ids
    # RC19 groups links by purpose: wizard/picker are still present but
    # have their own dedicated section rather than sharing the same card.
    for anchor in ('step1','step2','step3','advancedToolsGroup','fullSuite','step5',
                   'workflowCreateSection','workflowManageSection','massAssignmentPanel',
                   'bflaPanel'):
        assert doc.select_one(f'nav.sidebar a[href="#{anchor}"]')
    assert doc.select_one('#step4') and doc.select_one('#rc13Panel')
    assert doc.select_one('#loginConfigPanel') and doc.select_one('#loginKeysPanel')
    assert doc.select_one('#guidedDrawer').name=='details'
    assert doc.select_one('#guidedDrawer').find_parent(id='workflowCreateSection')
    assert doc.select_one('#workflowLibraryPanel').find_parent(id='workflowManageSection')
    assert doc.select_one('#ollamaPanel')
    assert doc.select_one('link[href*="workspace-ui.css"]')


def test_safety_consent_and_previous_features_are_preserved():
    doc=_page()
    for ident in ('specFile','baseUrl','allowHost','authFile','matrixImportFile',
                  'workflowRunSingle','workflowRunCombined','bodyProbeDetect',
                  'bodyProbeOptions','suiteActive','suiteWrites','suiteAck',
                  'suiteWritesAck','suiteRc13Body','rc13BodyAck','ollamaStart',
                  'ollamaModelPicker','rc13OpenAI','jobsList'):
        assert doc.select_one('#'+ident), ident
    # The new navigation JS must not change consent and never call the target.
    nav=(STATIC/'ui-experience.js').read_text(encoding='utf-8')
    assert 'fetch(' not in nav
    assert 'window.open(' not in nav
    assert 'target.open=true' in nav


def test_all_languages_have_the_new_feature_names():
    source=(STATIC/'i18n-catalog.js').read_text(encoding='utf-8')
    catalog=json.loads(source.split('window.AchillesUILocales = ',1)[1].strip().removesuffix(';'))
    for language in ('en','es','fr'):
        for text in ('Analisi approfondita API','Avvia analisi approfondita',
                     'Sonde sui campi JSON (PATCH)','Analizza le tue API con un percorso chiaro.',
                     'Includi analisi approfondita (input, accessi, workflow, copertura e AI)'):
            assert catalog[language].get(text), (language,text)


def test_server_serves_new_style_and_existing_endpoints(tmp_path):
    with TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766') as client:
        assert client.get('/assets/workspace-ui.css').status_code==200
        assert client.get('/assets/ui-experience.js').status_code==200
        assert client.get('/').status_code==200
        assert client.get('/api/bootstrap').status_code==200
        assert client.get('/api/control/tools').status_code==200
        assert 'workspace-ui.css' in client.get('/').text
