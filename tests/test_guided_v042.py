"""New human guided manifest builder: no placeholder and clear validation."""
import yaml
from pathlib import Path
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.manifest_builder import discover_manifest_candidates,build_guided_manifest

LAB=Path('/mnt/data/independent-api-lab')

def test_guided_manifest_without_placeholder():
    candidate=discover_manifest_candidates(str(LAB/'openapi.json'))[0]
    config=build_guided_manifest(candidate,owner='owner',other='other',
         marker='label',identifier='id',body={'label':'temporary-project'},deny_other=True)
    y=yaml.safe_load(config)
    assert 'REVIEW_' not in config and 'TODO_' not in config
    assert y['resources'][0]['id_pointer']=='/id'
    assert y['resources'][0]['access']==[{'identity':'other','expected':'deny'}]

def test_guided_fails_if_missing_id_or_fixture():
    c=discover_manifest_candidates(str(LAB/'openapi.json'))[0]
    import pytest
    with pytest.raises(ValueError,match='ID'):
        build_guided_manifest(c,owner='owner',other=None,marker='label',identifier='',body={'label':'ok'},deny_other=False)
    with pytest.raises(ValueError,match='label'):
        build_guided_manifest(c,owner='owner',other=None,marker='label',identifier='id',body={},deny_other=False)

def test_dashboard_guided_endpoint(tmp_path):
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8766') as t:
        headers={'x-achilles-token':t.get('/api/bootstrap').json()['csrf_token']}
        with (LAB/'openapi.json').open('rb') as f:spec=t.post('/api/upload',files={'file':('openapi.json',f,'application/json')},headers=headers).json()['id']
        with (LAB/'auth.yaml').open('rb') as f:auth=t.post('/api/auth-config',files={'file':('auth.yaml',f,'application/x-yaml')},headers=headers).json()['id']
        payload={'specification_id':spec,'auth_config_id':auth,'candidate_index':0,
            'identity':'owner','other_identity':'other','deny_other':True,'marker':'label',
            'identifier':'id','body':{'label':'my-safe-temporary'}}
        r=t.post('/api/control/manifest/guided',json=payload,headers=headers)
        assert r.status_code==200,r.text
        assert r.json()['valid'] and r.json()['required_requests']>=6
        assert 'REVIEW_' not in r.json()['yaml']
        payload['identifier']='';assert t.post('/api/control/manifest/guided',json=payload,headers=headers).status_code==422
        assert t.post('/api/control/manifest/guided',json=payload).status_code==403
