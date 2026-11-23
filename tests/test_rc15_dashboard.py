"""RC15 control plane: standalone catalog entry, fail-closed preflight and CLI job."""
from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app

SPEC = {'openapi': '3.0.3', 'info': {'title': 'RC15 Dashboard Fixture', 'version': '1'},
    'paths': {'/search': {'get': {'parameters': [
        {'in': 'query', 'name': 'search', 'schema': {'type': 'string'}}],
        'responses': {'200': {'description': 'ok'}}}},
        '/assets': {'post': {'requestBody': {'content': {'application/json': {
            'schema': {'type': 'object', 'properties': {'name': {'type': 'string'}}}}}},
            'responses': {'201': {'description': 'created'}}}}}}


def setup(client):
    header = {'x-achilles-token': client.get('/api/bootstrap').json()['csrf_token']}
    uploaded = client.post('/api/import-text', headers=header, json={
        'kind': 'openapi', 'content': json.dumps(SPEC), 'name': 'rc15-test.json'})
    assert uploaded.status_code == 200, uploaded.text
    return header, uploaded.json()['id']


def test_rc15_visible_and_dryrun_without_target_requests(tmp_path):
    with TestClient(create_app(tmp_path/'app'), base_url='http://127.0.0.1:8766') as client:
        head, sid = setup(client)
        entries = client.get('/api/control/tools').json()
        item = next(entry for entry in entries if entry['name'] == 'rc15-scan')
        assert 'callback' in item['help']['requires'].lower()
        res = client.post('/api/control/jobs', headers=head, json={
            'action': 'rc15-scan', 'specification_id': sid,
            'base_url': 'https://api.example.test', 'allow_host': 'api.example.test',
            'max_requests': 10})
        assert res.status_code == 200, res.text
        job_id = res.json()['id']
        for _ in range(150):
            status = client.get('/api/jobs/' + job_id).json()['status']
            if status not in {'running', 'orchestrating'}:
                break
            time.sleep(.1)
        assert status == 'complete', client.get('/api/jobs/' + job_id).json()
        result = client.get('/api/results/' + job_id).json()
        assert result['requests_sent'] == 0
        assert result['cases']


def test_rc15_dashboard_rejects_writes_or_callbacks_without_approval(tmp_path):
    with TestClient(create_app(tmp_path/'app'), base_url='http://127.0.0.1:8766') as client:
        head, sid = setup(client)
        cfg = {'action': 'rc15-scan', 'specification_id': sid,
            'base_url': 'http://127.0.0.1:8799', 'allow_host': '127.0.0.1',
            'allow_insecure_http': True, 'execute': True, 'acknowledgment': True,
            'approve_writes': True}
        res = client.post('/api/control/jobs', headers=head, json=cfg)
        assert res.status_code in (400, 422), res.text
        cfg['approve_writes'] = False
        cfg['rc15_callback_base'] = 'https://callback.example.test'
        cfg['rc15_callback_observer'] = 'http://127.0.0.1:8788'
        res = client.post('/api/control/jobs', headers=head, json=cfg)
        assert res.status_code in (400, 422), res.text
        cfg['rc15_callback_approved'] = True
        cfg['rc15_callback_observer'] = 'http://attacker.example:8788'
        res = client.post('/api/control/jobs', headers=head, json=cfg)
        assert res.status_code in (400, 422), res.text
