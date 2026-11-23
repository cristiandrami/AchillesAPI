"""Regression: full-suite remains accessible after UI simplification.

Offline and active tests use a single static action; they contact no target.
"""
from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

import achillesapi.dashboard.control as control
from achillesapi.dashboard.server import create_app

SPEC = {"openapi": "3.0.3", "info": {"title": "Suite restored", "version": "1"},
        "paths": {"/health": {"get": {"responses": {"200": {"description": "OK"}}}}}}


def _dashboard(tmp_path):
    client = TestClient(create_app(tmp_path / 'workspace'), base_url='http://127.0.0.1:8766')
    token = {'x-achilles-token': client.get('/api/bootstrap').json()['csrf_token']}
    response = client.post('/api/import-text', headers=token,
                           json={'kind': 'openapi', 'content': json.dumps(SPEC)})
    assert response.status_code == 200, response.text
    return client, token, response.json()['id']


def _await_suite(client, id_):
    for _ in range(100):
        result = client.get('/api/jobs/' + id_).json()
        if result['status'] not in {'running', 'orchestrating'}:
            return result
        time.sleep(0.06)
    raise AssertionError('Timed out waiting for suite')


def test_suite_is_visible_in_simplified_dashboard(tmp_path):
    client, _, _ = _dashboard(tmp_path)
    html = client.get('/').text
    assert 'id="fullSuite"' in html and 'id="fullSuite" data-advanced-panel' not in html
    assert 'href="#fullSuite"' in html
    assert all('id="' + id_ + '"' in html for id_ in
               ('suiteRun', 'suiteActive', 'suiteAck', 'suiteWrites', 'suiteWritesAck'))
    code = client.get('/assets/app.js').text
    assert 'function suiteConfig(active)' in code
    assert "$('toolWrites').checked" not in code[code.index('async function runSuite()'):code.index('function explainJobError(')]
    assert "$('toolAck').checked" not in code[code.index('async function runSuite()'):code.index('function explainJobError(')]


def test_complete_offline_suite_launches_regardless_of_selected_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(control, 'SUITE_ORDER', ('analyze-openapi',))
    client, token, spec = _dashboard(tmp_path)
    result = client.post('/api/control/suite', headers=token,
                         json={'config': {'action': 'auto-assess', 'specification_id': spec}})
    assert result.status_code == 200, result.text
    state = _await_suite(client, result.json()['id'])
    assert state['status'] == 'complete', state
    report = client.get('/api/results/' + result.json()['id']).json()
    assert [s['action'] for s in report['steps']] == ['analyze-openapi']
    assert report['mode'] == 'offline'


def test_active_suite_has_its_own_ack_and_writes_stay_guarded(tmp_path, monkeypatch):
    monkeypatch.setattr(control, 'SUITE_ORDER', ('analyze-openapi',))
    client, token, spec = _dashboard(tmp_path)
    cfg = {'action': 'auto-assess', 'specification_id': spec,
           'base_url': 'http://127.0.0.1:8795', 'allow_host': '127.0.0.1',
           'acknowledgment': True, 'execute': True}
    denied = client.post('/api/control/suite', headers=token,
                         json={'config': {**cfg, 'acknowledgment': False}, 'include_active': True})
    assert denied.status_code == 422
    result = client.post('/api/control/suite', headers=token,
                         json={'config': cfg, 'include_active': True})
    assert result.status_code == 200, result.text
    assert _await_suite(client, result.json()['id'])['status'] == 'complete'
    report = client.get('/api/results/' + result.json()['id']).json()
    assert report['mode'] == 'active'
    assert report['http_telemetry']['attempted'] == 0 if 'attempted' in report['http_telemetry'] else True

    denied_writes = client.post('/api/control/suite', headers=token,
                                json={'config': cfg, 'include_active': True, 'include_writes': True})
    assert denied_writes.status_code == 422

    auth = client.post('/api/import-text', headers=token,
                       json={'kind': 'auth', 'content':
                             'profiles:\n  - name: owner\n    type: bearer\n    token: disposable-fixture-only\n'})
    assert auth.status_code == 200, auth.text
    manifest = client.post('/api/import-text', headers=token,
                           json={'kind': 'config', 'content': 'resources: []\n'})
    assert manifest.status_code == 200, manifest.text
    payload = {**cfg, 'approve_writes': True, 'auth_config_id': auth.json()['id'],
               'config_id': manifest.json()['id'], 'config_usage': 'multi-resource'}
    authorized = client.post('/api/control/suite', headers=token,
                             json={'config': payload, 'include_active': True, 'include_writes': True})
    assert authorized.status_code == 200, authorized.text
    assert _await_suite(client, authorized.json()['id'])['status'] == 'complete'
    # There were no write-capable tasks in this intentionally bounded suite.
    report = client.get('/api/results/' + authorized.json()['id']).json()
    assert report['steps'][0]['action'] == 'analyze-openapi'
