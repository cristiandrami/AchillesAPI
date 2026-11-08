"""Exercise deliberately vulnerable and protected routes in an unrelated API."""
from fastapi.testclient import TestClient
from labs.independent_api.app import app, records


def test_independent_lab_bola_and_protection():
    client = TestClient(app)
    headers = {"Authorization": "Bearer demo-alice"}
    assert client.get('/v2/inventory/inv-b', headers=headers).status_code == 200
    assert client.get('/v2/secure/inventory/inv-b', headers=headers).status_code == 403
    assert client.get('/v2/inventory/inv-b').status_code == 401


def test_independent_lab_bfla_and_validation():
    client = TestClient(app)
    headers = {"Authorization": "Bearer demo-alice"}
    assert client.get('/v2/admin/exports', headers=headers).status_code == 200
    assert client.get('/v2/secure/admin/exports', headers=headers).status_code == 403
    assert client.get('/v2/search', params={'term': ''}, headers=headers).status_code == 422
    assert client.get('/v2/search', params={'term': "'"}, headers=headers).status_code == 500


def test_independent_lab_disposable_lifecycle():
    client = TestClient(app)
    headers = {"Authorization": "Bearer demo-alice"}
    created = client.post('/v2/inventory', json={'label': 'temporary-test-asset', 'owner': 'alice'}, headers=headers)
    assert created.status_code == 201
    identifier = created.json()['id']
    try:
        assert client.get(f'/v2/inventory/{identifier}', headers={'Authorization': 'Bearer demo-bob'}).status_code == 200
        patch = client.patch(f'/v2/inventory/{identifier}', json={'is_approved': True}, headers=headers)
        assert patch.status_code == 200
        assert patch.json()['is_approved'] is True
    finally:
        assert client.delete(f'/v2/inventory/{identifier}', headers=headers).status_code == 204
    assert client.get(f'/v2/inventory/{identifier}', headers=headers).status_code == 404
    assert identifier not in records
