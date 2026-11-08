"""Dashboard manifest wizard: independent API specs, safe failures and usability."""
from pathlib import Path
import json

import pytest
from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.manifest_builder import discover_manifest_candidates,build_manifest_draft

LAB=Path('/mnt/data/independent-api-lab')

@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path),base_url="http://127.0.0.1:8766") as t:
        token=t.get('/api/bootstrap').json()['csrf_token']
        yield t, {'x-achilles-token':token}


def setup_files(client):
    t,headers=client
    with (LAB/'openapi.json').open('rb') as f:
        r=t.post('/api/upload',files={'file':('openapi.json',f,'application/json')},headers=headers)
    assert r.status_code==200,r.text
    with (LAB/'auth.yaml').open('rb') as f:
        a=t.post('/api/auth-config',files={'file':('auth.yaml',f,'application/x-yaml')},headers=headers)
    assert a.status_code==200,a.text
    return r.json()['id'],a.json()['id']


def test_candidate_discovery_is_offline_and_generic():
    choices=discover_manifest_candidates(str(LAB/'openapi.json'))
    assert len(choices)>0
    assert choices[0]['create']=='POST /projects'
    assert choices[0]['read']=='GET /projects/{project_ref}'
    assert choices[0]['marker_candidates']==['label']
    assert 'lab-alice' not in json.dumps(choices)


def test_manifest_editor_routes(client):
    t,headers=client
    spec,auth=setup_files(client)
    options=t.get('/api/control/manifest/candidates/'+spec)
    assert options.status_code==200
    assert options.json()['candidates']
    draft=t.post('/api/control/manifest/draft',json={
        'specification_id':spec,'candidate_index':0,'identity':'owner',
        'other_identity':'other'},headers=headers)
    assert draft.status_code==200,draft.text
    text=draft.json()['yaml']
    assert 'REVIEW_ID_FIELD' in text
    invalid=t.post('/api/control/manifest/validate',json={
        'specification_id':spec,'auth_config_id':auth,'yaml':text},headers=headers)
    assert invalid.status_code==422
    assert 'segnaposto' in invalid.text
    corrected=text.replace('/REVIEW_ID_FIELD','/id')
    validated=t.post('/api/control/manifest/validate',json={
        'specification_id':spec,'auth_config_id':auth,'yaml':corrected},headers=headers)
    assert validated.status_code==200,validated.text
    assert validated.json()['valid']
    assert validated.json()['required_requests']>=6


def test_no_unapproved_writes(client):
    t,headers=client
    spec,auth=setup_files(client)
    draft=t.post('/api/control/manifest/draft',json={
        'specification_id':spec,'candidate_index':0,'identity':'owner'},headers=headers).json()['yaml']
    config=t.post('/api/import-text',json={'kind':'config','content':draft,'name':'resources.yaml'},headers=headers).json()['id']
    run=t.post('/api/control/jobs',json={
        'action':'auto-assess','specification_id':spec,'auth_config_id':auth,'config_id':config,
        'base_url':'http://127.0.0.1:8795','allow_host':'127.0.0.1',
        'config_usage':'multi-resource','approve_writes':True,'execute':True,
        'acknowledgment':True},headers=headers)
    assert run.status_code==422
    assert 'REVIEW_' in run.text


def test_readable_rate_error(client):
    t,headers=client
    spec,_=setup_files(client)
    bad=t.post('/api/control/jobs',json={'action':'auto-assess','specification_id':spec,'rate':40},headers=headers)
    assert bad.status_code==422
    msg=bad.json()['detail']
    assert 'Richieste al secondo' in msg and 'massimo consentito 5' in msg
    assert 'input' not in msg and 'ctx' not in msg


def test_unauthorized_manifest_generation(client):
    t,_=client
    assert t.post('/api/control/manifest/draft',json={}).status_code==403


def test_bad_profiles_and_index_are_explained(client):
    t,headers=client
    spec,_=setup_files(client)
    resp=t.post('/api/control/manifest/draft',json={'specification_id':spec,'candidate_index':99,'identity':'owner'},headers=headers)
    assert resp.status_code==422
    assert 'Seleziona un workflow' in resp.json()['detail']
