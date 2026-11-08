"""Regression: offline selection, collapsible wizard, multiple saved CRUD workflows."""
import json
import time
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app

SPEC={'openapi':'3.0.3','info':{'title':'Unrelated external API','version':'1'},'paths':{'/alive':{'get':{'responses':{'200':{'description':'OK'}}}}}}

def test_offline_action_ignores_stale_active_flag(tmp_path):
    client=TestClient(create_app(tmp_path/'web'),base_url='http://127.0.0.1:8766')
    csrf=client.get('/api/bootstrap').json()['csrf_token']
    headers={'x-achilles-token':csrf}
    spec=client.post('/api/import-text',headers=headers,json={'kind':'openapi','content':json.dumps(SPEC)}).json()['id']
    r=client.post('/api/control/jobs',headers=headers,json={'action':'analyze-openapi','specification_id':spec,'execute':True,'approve_writes':True})
    assert r.status_code==200,r.text
    for _ in range(100):
        status=client.get('/api/jobs/'+r.json()['id']).json()
        if status['status']!='running':break
        time.sleep(.05)
    assert status['status']=='complete',status

def test_collapsible_wizard_and_workflow_library_are_generic(tmp_path):
    client=TestClient(create_app(tmp_path/'web'),base_url='http://127.0.0.1:8766')
    page=client.get('/').text
    assert '<details class="guided-drawer" id="guidedDrawer">' in page
    assert 'id="workflowSaved"' in page and 'id="workflowChoose"' in page
    assert 'id="modeExplanation"' in page
    js=client.get('/assets/app.js').text
    for name in ['renderSavedWorkflows','chooseSavedWorkflow','removeSavedWorkflow','savedWorkflows.push','execute=Boolean(execute&&obj.active)']:
        assert name in js
    assert '/api/control/services/lab/start' not in js
