"""RC2: test mirati senza collegarsi a un target esterno."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.access_probe_rc import compare_identities, ProbeError
from achillesapi.core.auth import AuthenticationManager, AuthenticationFile
from achillesapi.core.campaign_ledger import CampaignLedger, CampaignBudgetError
from achillesapi.core.evidence_integrity_rc import build_integrity_record, verify_integrity_record
from achillesapi.core.http import SafeHTTPClient, ScopeError, RequestBudgetExceeded
from achillesapi.core.release_audit_rc import audit_campaign
from achillesapi.models.evidence import ExecutionEvidence, RequestEvidence, ResponseEvidence

SPEC = {'openapi': '3.0.3', 'info': {'title': 'Independent API', 'version': '1'},
        'paths': {'/users/{userId}': {'get': {
            'parameters': [{'name': 'userId', 'in': 'path', 'required': True,
                            'schema': {'type': 'string'}}],
            'responses': {'200': {'description': 'ok'}, '403': {'description': 'denied'}}}}}}


def _spec(tmp_path: Path) -> Path:
    file = tmp_path / 'openapi.json'
    file.write_text(json.dumps(SPEC))
    return file


def _auth() -> AuthenticationManager:
    return AuthenticationManager(AuthenticationFile.model_validate({'profiles': [
        {'name': 'owner', 'type': 'bearer', 'token': 'owner-secret-token'},
        {'name': 'other', 'type': 'bearer', 'token': 'other-secret-token'},
    ]}))


def test_global_budget_atomic_when_many_workers(tmp_path):
    ledger = CampaignLedger.create(tmp_path / 'shared.sqlite', limit=7, rate=100, runtime_seconds=10)

    def book(_):
        try:
            return ledger.reserve()
        except CampaignBudgetError:
            return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(book, range(30)))
    valid = [ticket for ticket in results if ticket is not None]
    assert len(valid) == 7
    for i, ticket in enumerate(valid):
        ledger.finish(ticket, status=200 if i % 2 else None)
    ledger.finish(valid[0], status=500)  # un ticket non può contare due volte
    snapshot = ledger.snapshot()
    assert snapshot['attempted'] == 7
    assert snapshot['remaining'] == 0
    assert snapshot['responses_received'] + snapshot['network_errors'] == 7
    assert snapshot['pending'] == 0
    assert 'owner-secret-token' not in json.dumps(snapshot)


def test_global_budget_shared_by_separate_http_clients(tmp_path, monkeypatch):
    ledger = CampaignLedger.create(tmp_path / 'budget.sqlite', limit=1, rate=100, runtime_seconds=10)
    monkeypatch.setenv('ACHILLES_CAMPAIGN_LEDGER', str(ledger.path))

    class DummyResponse:
        status_code = 200
        headers = {}
        encoding = 'utf-8'
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def iter_bytes(self): yield b'ok'

    class DummyClient:
        def __init__(self, **_): pass
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def stream(self, *_args, **_kwargs): return DummyResponse()

    monkeypatch.setattr('achillesapi.core.http.httpx.Client', DummyClient)
    one = SafeHTTPClient(allowed_hosts={'test.example'}, max_requests=3)
    two = SafeHTTPClient(allowed_hosts={'test.example'}, max_requests=3)
    one.request('GET', 'https://test.example/read')  # dry-run: non consuma budget
    one.request('GET', 'https://test.example/read', execute=True)
    with pytest.raises(RequestBudgetExceeded):
        two.request('GET', 'https://test.example/read', execute=True)
    assert ledger.snapshot()['attempted'] == 1


def test_probe_dry_run_never_resolves_auth(tmp_path, monkeypatch):
    def no_auth(*args, **kwargs):
        raise AssertionError('Dry-run should not resolve credentials')
    manager = _auth()
    monkeypatch.setattr(manager, 'resolve', no_auth)
    result = compare_identities(_spec(tmp_path), base_url='https://test.example',
        allowed_hosts={'test.example'}, auth_manager=manager,
        owner='owner', other='other', path_values={'userId': '42'})
    assert result['status'] == 'dry_run' and result['requests_sent'] == 0


def test_probe_policy_conflict_is_not_auto_confirmed(tmp_path, monkeypatch):
    def mock_request(self, _method, url, *, headers=None, **_):
        status = 200 if 'owner-secret-token' in headers['Authorization'] else 200
        return ExecutionEvidence(executed=True,
            request=RequestEvidence(method='GET', url='https://test.example/users/{userId}'),
            response=ResponseEvidence(status_code=status, body_preview='same-resource',
                                      elapsed_ms=1.0))
    monkeypatch.setattr(SafeHTTPClient, 'request', mock_request)
    result = compare_identities(_spec(tmp_path), base_url='https://test.example',
        allowed_hosts={'test.example'}, auth_manager=_auth(),
        owner='owner', other='other', path_values={'userId': '42'},
        expected_other='deny', execute=True)
    assert result['status'] == 'policy_conflict_requires_review'
    assert result['same_body_observed']
    assert result['confirmed_vulnerabilities'] == 0
    assert 'secret-token' not in json.dumps(result)
    assert 'same-resource' not in json.dumps(result)


def test_probe_rejects_path_traversal_and_host_outside_scope(tmp_path):
    with pytest.raises(ProbeError):
        compare_identities(_spec(tmp_path), base_url='https://test.example',
            allowed_hosts={'test.example'}, auth_manager=_auth(),
            owner='owner', other='other', path_values={'userId': '../admin'})
    with pytest.raises(ScopeError):
        compare_identities(_spec(tmp_path), base_url='https://evil.example',
            allowed_hosts={'test.example'}, auth_manager=_auth(),
            owner='owner', other='other', path_values={'userId': '42'})


def test_integrity_record_detects_file_edit(tmp_path):
    path = tmp_path / 'report.json'
    path.write_text('{"steps": []}')
    expected = build_integrity_record(path)
    assert verify_integrity_record(path, expected)['verified']
    path.write_text('{"steps": [42]}')
    assert not verify_integrity_record(path, expected)['verified']


def test_release_gate_does_not_certify_security():
    offline = audit_campaign({'mode': 'offline', 'steps': [
        {'status': 'complete'}, {'status': 'skipped'}]})
    assert offline['status'] == 'review_required'
    active = audit_campaign({'mode': 'active', 'steps': [{'status': 'complete'}]})
    assert active['status'] == 'blocked'
    proper = audit_campaign({'mode': 'active', 'steps': [{'status': 'complete'}],
                             'http_telemetry': {'scope': 'campaign_all_processes',
                                                'attempted': 1, 'limit': 3, 'pending': 0}})
    assert proper['status'] == 'ready_for_review'


def test_rc2_cli_has_new_commands(tmp_path):
    runner = CliRunner()
    spec = _spec(tmp_path)
    config = tmp_path / 'auth.yaml'
    config.write_text('profiles:\n- name: owner\n  type: bearer\n  token: owner-secret-token\n'
                      '- name: other\n  type: bearer\n  token: other-secret-token\n')
    report = tmp_path / 'probe.json'
    result = runner.invoke(app, ['access-probe', str(spec), '--base-url',
        'https://test.example', '--allow-host', 'test.example',
        '--auth-config', str(config), '--profile', 'owner', '--profile', 'other',
        '--path-value', 'userId=123', '--output', str(report)])
    assert result.exit_code == 0, result.output
    assert json.loads(report.read_text())['executed'] is False
    source = tmp_path / 'campaign.json'
    source.write_text(json.dumps({'mode': 'offline', 'steps': [{'status': 'complete'}]}))
    for name in ('campaign-audit', 'evidence-integrity'):
        generated = tmp_path / (name + '.json')
        response = runner.invoke(app, [name, str(source), '--output', str(generated)])
        assert response.exit_code == 0, response.output
        assert generated.is_file()


def test_live_loopback_bola_get_and_global_budget(tmp_path, monkeypatch):
    """E2E locale: due utenti, una risorsa e zero richieste fuori scope."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    history = []

    class API(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            history.append((self.path, self.headers.get('Authorization')))
            if self.path != '/users/42':
                self.send_response(404)
                self.end_headers()
                return
            owner = self.headers.get('Authorization') == 'Bearer owner-secret-token'
            self.send_response(200 if owner else 403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"resource":"private"}' if owner else b'{"error":"denied"}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ledger = CampaignLedger.create(tmp_path/'live.sqlite', limit=2, rate=100, runtime_seconds=20)
        monkeypatch.setenv('ACHILLES_CAMPAIGN_LEDGER', str(ledger.path))
        report = compare_identities(_spec(tmp_path), base_url=f'http://127.0.0.1:{server.server_port}',
            allowed_hosts={'127.0.0.1'}, auth_manager=_auth(),
            owner='owner', other='other', path_values={'userId': '42'},
            expected_other='deny', execute=True, allow_insecure_http=True)
        assert report['status'] == 'expected_denial_observed'
        assert len(history) == 2
        assert ledger.snapshot()['attempted'] == 2
        assert ledger.snapshot()['remaining'] == 0
        assert 'owner-secret-token' not in json.dumps(report)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_live_dynamic_auth_in_global_budget(tmp_path, monkeypatch):
    """Una POST OAuth2 consuma budget prima della GET vera e propria."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class API(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            assert self.path == '/token'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"access_token":"issued-owner","expires_in":300}')
        def do_GET(self):
            owner = self.headers.get('Authorization') == 'Bearer issued-owner'
            self.send_response(200 if owner else 403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f'http://127.0.0.1:{server.server_port}'
        manager = AuthenticationManager(AuthenticationFile.model_validate({'profiles': [
            {'name': 'owner', 'type': 'oauth2_client_credentials', 'token_url': url + '/token',
             'client_id': 'client', 'client_secret': 'do-not-print'},
            {'name': 'other', 'type': 'bearer', 'token': 'not-owner'},
        ]}))
        ledger = CampaignLedger.create(tmp_path/'oauth.sqlite', limit=3, rate=100, runtime_seconds=20)
        monkeypatch.setenv('ACHILLES_CAMPAIGN_LEDGER', str(ledger.path))
        report = compare_identities(_spec(tmp_path), base_url=url,
            allowed_hosts={'127.0.0.1'}, auth_manager=manager,
            owner='owner', other='other', path_values={'userId': '42'},
            expected_other='deny', execute=True, allow_insecure_http=True)
        assert report['status'] == 'expected_denial_observed'
        assert ledger.snapshot()['attempted'] == 3
        assert ledger.snapshot()['responses_received'] == 3
        assert 'issued-owner' not in json.dumps(report)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_suite_runs_rc2_reporting_commands(tmp_path, monkeypatch):
    """Regressione completa del routing CLI per i nuovi task di reporting."""
    import time
    from fastapi.testclient import TestClient
    from achillesapi.dashboard.server import create_app
    import achillesapi.dashboard.control as control

    small_spec = {'openapi': '3.0.3', 'info': {'title': 'Smoke', 'version': '1'},
                  'servers': [{'url': 'https://target.example.test'}],
                  'paths': {'/health': {'get': {'responses': {'200': {'description': 'ok'}}}}}}
    monkeypatch.setattr(control, 'SUITE_ORDER',
                        ('analyze-openapi', 'auto-assess', 'campaign-audit', 'evidence-integrity'))
    client = TestClient(create_app(tmp_path/'workspace'), base_url='http://127.0.0.1:8766')
    csrf = client.get('/api/bootstrap').json()['csrf_token']
    headers = {'x-achilles-token': csrf}
    uploaded = client.post('/api/import-text', headers=headers,
        json={'kind': 'openapi', 'content': json.dumps(small_spec)})
    assert uploaded.status_code == 200, uploaded.text
    spec_id = uploaded.json()['id']
    launch = client.post('/api/control/suite', headers=headers,
        json={'config': {'action': 'auto-assess', 'specification_id': spec_id}})
    assert launch.status_code == 200, launch.text
    suite_id = launch.json()['id']
    for _ in range(230):
        state = client.get('/api/jobs/'+suite_id).json()
        if state['status'] not in {'running', 'orchestrating'}:
            break
        time.sleep(.08)
    assert state['status'] == 'complete', state
    report = client.get('/api/results/'+suite_id).json()
    assert report['summary']['completed'] == 4, report['steps']
    assert report['http_telemetry']['scope'] == 'no_active_traffic'
    assert all(s['status'] == 'complete' for s in report['steps'])
    preview = client.get('/api/job-view/'+suite_id).json()
    assert preview['summary']['tools_total'] == 4


def test_shared_budget_between_real_subprocesses(tmp_path):
    """Due CLI separate non possono prenotare entrambe l'ultimo credito."""
    import os
    import subprocess
    import sys

    ledger = CampaignLedger.create(tmp_path / 'two_processes.sqlite',
                                   limit=1, rate=100, runtime_seconds=20)
    source = Path(__file__).resolve().parents[1] / 'src'
    env = {**os.environ, 'PYTHONPATH': str(source) + os.pathsep + os.environ.get('PYTHONPATH', '')}
    code = ('from achillesapi.core.campaign_ledger import CampaignLedger, CampaignBudgetError\n'
            'import sys\n'
            'try:\n'
            '    CampaignLedger(sys.argv[1]).reserve()\n'
            '    print("allowed")\n'
            'except CampaignBudgetError:\n'
            '    print("blocked")\n')
    def launch(_):
        return subprocess.run([sys.executable, '-c', code, str(ledger.path)],
                              capture_output=True, text=True, env=env, timeout=15)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(launch, range(2)))
    assert all(item.returncode == 0 for item in results)
    assert sorted(item.stdout.strip() for item in results) == ['allowed', 'blocked']
    assert ledger.snapshot()['attempted'] == 1
