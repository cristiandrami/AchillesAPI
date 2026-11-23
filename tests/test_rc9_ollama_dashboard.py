"""Regression tests for the always-visible local Ollama control plane (RC9)."""
from __future__ import annotations

import json
from pathlib import Path
from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app
import achillesapi.dashboard.control as control


def make_client(tmp_path):
    client = TestClient(create_app(tmp_path / 'dashboard'), base_url='http://127.0.0.1:8766')
    token = client.get('/api/bootstrap').json()['csrf_token']
    return client, {'x-achilles-token': token}


def test_ollama_visible_in_primary_dashboard(tmp_path):
    client, _ = make_client(tmp_path)
    page = client.get('/').text
    assert 'id="ollamaPanel"' in page
    assert 'href="#ollamaPanel"' in page
    assert 'id="ollamaModelPicker"' in page
    assert 'id="ollamaStart"' in page
    assert 'id="ollamaTest"' in page
    assert 'id="serviceRefresh"' in page
    assert 'id="ollamaStop"' in page
    assert 'id="suiteRun"' in page  # suite remains accessible
    assert 'data-advanced-panel' not in page.split('id="ollamaPanel"', 1)[1].split('</section>', 1)[0]
    assert page.count('id="ollamaStart"') == 1
    assert page.count('id="ollamaStatus"') == 1
    assert page.count('id="ollamaModel"') == 1
    script = client.get('/assets/app.js').text
    assert "'/api/control/ollama/test'" in script
    assert "'/api/control/services/ollama/start'" in script
    assert 'setInterval(statusAI,15000)' in script


def test_ollama_offline_message_and_missing_install(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path)
    monkeypatch.setattr(control, '_installed_ollama_executable', lambda: None)
    monkeypatch.setattr(control, '_local_ollama_json', lambda *a, **kw: (_ for _ in ()).throw(ConnectionError('not active')))
    state = client.get('/api/control/services').json()
    assert state['ollama'] == 'offline'
    assert state['ollama_installed'] is False
    assert state['ollama_models'] == []
    assert 'Installa' in state['ollama_message']


def test_running_ollama_and_models_are_reported(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path)
    monkeypatch.setattr(control, '_installed_ollama_executable', lambda: '/usr/bin/ollama')
    def fake(path, payload=None, **kwargs):
        if path == '/api/tags':
            return {'models': [{'name': 'qwen3:8b'}, {'name': 'achilles-local:latest'}]}
        if path == '/api/ps':
            return {'models': [{'name': 'qwen3:8b'}]}
        raise AssertionError('Unexpected path')
    monkeypatch.setattr(control, '_local_ollama_json', fake)
    state = client.get('/api/control/services').json()
    assert state['ollama'] == 'online'
    assert state['ollama_installed'] is True
    assert state['ollama_models'] == ['qwen3:8b', 'achilles-local:latest']
    assert state['ollama_loaded_models'] == ['qwen3:8b']


def test_start_detects_running_external_instance_without_spawning(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path)
    monkeypatch.setattr(control, '_local_ollama_json', lambda *a, **kw: {'models': []})
    monkeypatch.setattr(control.subprocess, 'Popen', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('Must not spawn')))
    assert client.post('/api/control/services/ollama/start').status_code == 403
    result = client.post('/api/control/services/ollama/start', headers=headers)
    assert result.status_code == 200
    assert result.json()['state'] == 'already-running'


def test_start_only_approved_local_binary_and_stop_managed(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path)
    def unavailable(*args, **kwargs):
        raise ConnectionError('offline')
    monkeypatch.setattr(control, '_local_ollama_json', unavailable)
    monkeypatch.setattr(control, '_installed_ollama_executable', lambda: '/opt/ollama/bin/ollama')
    spawned = []
    class Process:
        def __init__(self):
            self.stopped = False
        def poll(self):
            return 0 if self.stopped else None
        def terminate(self):
            self.stopped = True
        def wait(self, timeout=None):
            return 0
    def fake_popen(argv, **kwargs):
        spawned.append((argv, kwargs))
        return Process()
    monkeypatch.setattr(control.subprocess, 'Popen', fake_popen)
    a = client.post('/api/control/services/ollama/start', headers=headers)
    assert a.status_code == 200, a.text
    assert a.json()['state'] == 'starting'
    assert spawned[0][0] == ['/opt/ollama/bin/ollama', 'serve']
    assert spawned[0][1]['env']['OLLAMA_HOST'] == '127.0.0.1:11434'
    assert client.get('/api/control/services').json()['ollama_managed'] is True
    b = client.post('/api/control/services/ollama/start', headers=headers)
    assert b.json()['state'] == 'starting'
    assert len(spawned) == 1
    c = client.post('/api/control/services/ollama/stop', headers=headers)
    assert c.json()['state'] == 'stopped'
    assert client.get('/api/control/services').json()['ollama_managed'] is False


def test_start_missing_install_fails_informatively(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path)
    monkeypatch.setattr(control, '_installed_ollama_executable', lambda: None)
    monkeypatch.setattr(control, '_local_ollama_json', lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionError()))
    response = client.post('/api/control/services/ollama/start', headers=headers)
    assert response.status_code == 503
    assert 'Installa' in response.json()['detail']


def test_model_self_test_sends_fixed_prompt_and_validates_json(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path)
    requests = []
    def fake(path, payload=None, **kwargs):
        requests.append((path, payload))
        if path == '/api/tags': return {'models': [{'name': 'qwen3:8b'}]}
        assert path == '/api/generate'
        assert payload['stream'] is False
        assert payload['format'] == 'json'
        assert payload['model'] == 'qwen3:8b'
        assert 'password' not in json.dumps(payload).lower()
        return {'response': '{"status":"ok"}', 'done': True}
    monkeypatch.setattr(control, '_local_ollama_json', fake)
    assert client.post('/api/control/ollama/test', json={'model': 'qwen3:8b'}).status_code == 403
    response = client.post('/api/control/ollama/test', headers=headers, json={'model': 'qwen3:8b'})
    assert response.status_code == 200, response.text
    assert response.json()['ok'] is True
    assert [entry[0] for entry in requests] == ['/api/tags', '/api/generate']


def test_model_test_rejects_missing_model_bad_model_and_invalid_json(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path)
    monkeypatch.setattr(control, '_local_ollama_json', lambda path, **kw: (
        {'models': [{'name': 'qwen3:8b'}]} if path == '/api/tags' else {'response': 'invalid'}))
    missing = client.post('/api/control/ollama/test', headers=headers, json={'model': 'not-installed'})
    assert missing.status_code == 422
    unsafe = client.post('/api/control/ollama/test', headers=headers, json={'model': 'qwen3:8b;curl example.com'})
    assert unsafe.status_code == 422
    bad = client.post('/api/control/ollama/test', headers=headers, json={'model': 'qwen3:8b'})
    assert bad.status_code == 422
    assert 'JSON' in bad.json()['detail']
