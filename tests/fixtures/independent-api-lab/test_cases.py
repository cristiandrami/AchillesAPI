"""Standalone training API verification; scanner implementation is not imported."""
from pathlib import Path
from fastapi.testclient import TestClient

def test_standalone_lab_positive_and_negative_controls():
    import importlib.util
    lab = Path(__file__).resolve().parent
    assert lab.is_dir()
    module_spec = importlib.util.spec_from_file_location('achilles_v046_external_fixture', lab / 'app.py')
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    app = module.app
    client = TestClient(app)
    h = {"Authorization": "Bearer demo-owner"}
    other = {"Authorization": "Bearer demo-other"}
    project = client.post('/projects', json={"label": "v046-test"}, headers=h).json()["id"]
    try:
        assert client.get(f'/projects/{project}', headers=other).status_code == 200
        assert client.get(f'/secure/projects/{project}', headers=other).status_code == 403
        assert client.get('/admin/audit', headers=other).status_code == 200
        assert client.get('/secure/admin/audit', headers=other).status_code == 403
        assert client.get('/misconfigured/auth').status_code == 200
        assert client.get('/secure/auth').status_code in (401,403)
        assert 'internal_token' in client.get('/profile/exposed',headers=h).json()
        assert 'internal_token' not in client.get('/profile/safe',headers=h).json()
        c = client.get('/misconfigured/cors',headers={'Origin':'https://evil.example'})
        assert c.headers['access-control-allow-origin'] == 'https://evil.example'
        assert c.headers['access-control-allow-credentials'] == 'true'
        c = client.get('/secure/cors',headers={'Origin':'https://evil.example'})
        assert 'access-control-allow-origin' not in c.headers
        assert client.get('/misconfigured/cache',headers=h).headers['cache-control'].startswith('public')
        assert client.get('/secure/cache',headers=h).headers['cache-control'].startswith('private')
        assert client.get('/unstable/repeatable').status_code == 503
        assert client.get('/unstable/healthy').status_code == 200
    finally:
        assert client.delete(f'/projects/{project}',headers=h).status_code == 204
