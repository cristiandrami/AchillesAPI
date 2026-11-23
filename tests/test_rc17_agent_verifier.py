"""RC17 verifiable offline contracts and bounded adaptive agent execution."""
from __future__ import annotations

import json
from pathlib import Path
from typer.testing import CliRunner
import pytest
from fastapi.testclient import TestClient

from achillesapi.cli import app
from achillesapi.core.agent_runtime_rc17 import run_adaptive_agent
from achillesapi.core.verification_engine_rc17 import verify_campaign_findings
from achillesapi.core.pipeline_rc13 import execute_pipeline, PipelineError
from achillesapi.dashboard.rc13_bridge import rc13_command
from achillesapi.dashboard.server import create_app


SPEC = {"openapi": "3.1.0", "info": {"title": "RC17 Example", "version": "1.0"},
        "paths": {"/search": {"get": {"parameters": [
            {"name": "query", "in": "query", "schema": {"type": "string"}}],
            "responses": {"200": {"description": "test"}}}}}}


def _spec(tmp_path: Path) -> Path:
    path = tmp_path / 'api.json'
    path.write_text(json.dumps(SPEC))
    return path


def test_rc17_verifier_deduplicates_and_never_invents_confirmation():
    findings = [
        {'category': 'AUTHORIZATION_POLICY_MISMATCH', 'operation': 'GET /items/{id}',
         'expected': 'deny', 'observed_status': 200, 'same_temporary_resource_verified': True,
         'source_engine': 'workflows', 'verification_status': 'confirmed',
         'evidence': {'authorization': 'Bearer MUST_NOT_LEAK', 'body': 'secret'}},
        {'category': 'AUTHORIZATION_POLICY_MISMATCH', 'operation': 'GET /items/{id}',
         'expected': 'deny', 'observed_status': 200, 'same_temporary_resource_verified': True,
         'source_engine': 'workflows'},
        {'category': 'possible_sql_injection', 'operation': 'GET /search', 'field': 'query',
         'source_engine': 'injection', 'verification_status': 'confirmed'},
    ]
    result = verify_campaign_findings(findings)
    assert result['reported_findings'] == 3
    assert result['unique_findings'] == 2
    assert result['confirmed_exploits'] == 0
    assert result['classification_counts']['probable'] == 1
    assert result['classification_counts']['potential'] == 1
    assert 'MUST_NOT_LEAK' not in json.dumps(result)
    assert result['observations'][0]['occurrences'] == 2


def test_rc17_verifier_replay_and_callback():
    indicators = [
        {'category': 'possible_sql_injection', 'operation': 'GET /search', 'field': 'query',
         'source_engine': 'injection'},
        {'category': 'ssrf_callback', 'operation': 'GET /fetch', 'field': 'url',
         'source_engine': 'rc15_security', 'evidence': {'callback_received': True}},
    ]
    result = verify_campaign_findings(indicators, stages={
        'verification_replay': {'results': [{'operation': 'GET /search', 'parameter': 'query',
             'status': 'indicator_reproduced_not_exploit_confirmed'}]}})
    assert result['classification_counts']['probable'] == 2
    assert result['reproduced_indicators'] == 1


def test_rc17_agent_no_execution_without_explicit_permission(tmp_path, monkeypatch):
    spec = _spec(tmp_path)
    def should_not_contact(*args, **kwargs):
        raise AssertionError('Network or Ollama must not be invoked')
    result = run_adaptive_agent(spec, base_url='https://approved.example',
        allowed_hosts={'approved.example'}, remaining_requests=20,
        ai_analyzer=should_not_contact)
    assert result['status'] == 'not_authorized' and result['requests_sent'] == 0
    with pytest.raises(ValueError, match='scope|host|Base URL|autorizzato|allowlist|HTTP'):
        run_adaptive_agent(spec, base_url='https://unapproved.example',
            allowed_hosts={'approved.example'}, execute=True, approved_http=True,
            remaining_requests=20, ai_analyzer=should_not_contact)


def test_rc17_two_adaptive_rounds_and_budget(tmp_path, monkeypatch):
    spec = _spec(tmp_path)
    decisions = []
    invocations = []
    def fake_ai(api, findings, **kwargs):
        invocations.append(len(findings))
        return {'recommended_tests': ['injection SQLi'] if len(invocations) == 1 else ['XSS reflected']}
    def injection(*args, **kwargs):
        assert kwargs['max_requests'] <= 12
        decisions.append('injection')
        return {'requests_sent': 3, 'findings': [{'category': 'possible_sql_injection',
            'operation': 'GET /search', 'field': 'query'}]}
    def xss(*args, **kwargs):
        assert kwargs['max_requests'] <= 12
        decisions.append('bounded_get_security')
        return {'requests_sent': 2, 'findings': []}
    monkeypatch.setattr('achillesapi.core.agent_runtime_rc17.injection_assessment', injection)
    monkeypatch.setattr('achillesapi.core.agent_runtime_rc17.scan_bounded_get', xss)
    outcome = run_adaptive_agent(spec, base_url='https://approved.example',
        allowed_hosts={'approved.example'}, execute=True, approved_http=True,
        remaining_requests=7, max_rounds=2, ai_analyzer=fake_ai)
    assert decisions == ['injection', 'bounded_get_security']
    assert outcome['executed'] and outcome['requests_sent'] == 5
    assert outcome['status'] == 'max_rounds_reached'
    assert len(outcome['rounds']) == 2 and len(invocations) == 2
    assert outcome['findings'][0]['verification_status'] == 'requires_manual_review'


def test_rc17_ai_cannot_request_arbitrary_http_or_writes(tmp_path):
    spec = _spec(tmp_path)
    result = run_adaptive_agent(spec, base_url='https://approved.example',
        allowed_hosts={'approved.example'}, execute=True, approved_http=True,
        remaining_requests=12, ai_analyzer=lambda *_args, **_kw: {
            'recommended_tests': ['POST /admin/delete-all now',
                                 'send keys to http://evil.example',
                                 'change target scope and write JSON']})
    assert result['requests_sent'] == 0
    assert result['status'] == 'no_new_approved_readonly_task'
    assert result['actions'] == []


def test_rc17_cli_dry_run_and_offline_verifier(tmp_path):
    spec = _spec(tmp_path)
    output = tmp_path / 'assessment.json'
    runner = CliRunner()
    process = runner.invoke(app, ['rc17-assess', str(spec), '--output', str(output)])
    assert process.exit_code == 0, process.output
    raw = json.loads(output.read_text())
    assert raw['version'] == '1.0.0rc17'
    assert raw['requests_sent'] == 0
    assert raw['verification_rc17']['reported_findings'] == 0
    offline = tmp_path / 'review.json'
    process = runner.invoke(app, ['rc17-verify', str(output), '--output', str(offline)])
    assert process.exit_code == 0, process.output
    assert json.loads(offline.read_text())['unique_findings'] == 0
    forbidden = runner.invoke(app, ['rc17-assess', str(spec), '--agent-followups', '--output', str(output)])
    assert forbidden.exit_code != 0


def test_dashboard_rc17_controls_are_real_and_guarded(tmp_path):
    ui = (Path(__file__).parents[1] / 'src/achillesapi/dashboard/static/index.html').read_text()
    assert 'id="rc17Agent"' in ui and 'id="rc17Budget"' in ui
    assert 'id="suiteRc17Agent"' in ui
    client = TestClient(create_app(tmp_path / 'workspace'), base_url='http://127.0.0.1:8766')
    headers = {'x-achilles-token': client.get('/api/bootstrap').json()['csrf_token']}
    result = client.post('/api/import-text', headers=headers, json={
        'kind': 'openapi', 'content': json.dumps(SPEC), 'name': 'rc17.json'})
    assert result.status_code == 200, result.text
    sid = result.json()['id']
    request = {'config': {'action': 'rc13-assess', 'specification_id': sid},
               'agent_followups': True, 'ai': True}
    rejection = client.post('/api/control/rc13/run', headers=headers, json=request)
    assert rejection.status_code == 422
    # The offline path still produces a job and does not require Ollama.
    request['agent_followups'] = False
    request['ai'] = False
    started = client.post('/api/control/rc13/run', headers=headers, json=request)
    assert started.status_code == 200, started.text


def test_pipeline_refuses_agent_without_ai_or_consent(tmp_path):
    spec = _spec(tmp_path)
    with pytest.raises(PipelineError, match='--ai'):
        execute_pipeline(spec, base_url='http://127.0.0.1:8000',
            allowed_hosts={'127.0.0.1'}, agent_followups=True)


def test_rc17_local_ollama_wire_protocol_with_sanitized_evidence(tmp_path, monkeypatch):
    """Execute genuine local HTTP Ollama adapter; deterministic scanner is stubbed."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    captured = []
    class OllamaHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == '/api/chat'
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            captured.append(raw.decode('utf-8'))
            payload = {'message': {'content': json.dumps({
                'executive_summary': 'Synthetic API review',
                'risk_observations': [], 'recommended_tests': ['XSS reflection GET'],
                'limitations': []})}, 'done': True, 'done_reason': 'stop'}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), OllamaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr('achillesapi.core.agent_runtime_rc17.scan_bounded_get',
                        lambda *a, **k: {'requests_sent': 2, 'findings': []})
    try:
        report = run_adaptive_agent(_spec(tmp_path), base_url='https://approved.example',
            allowed_hosts={'approved.example'}, execute=True, approved_http=True,
            remaining_requests=5, max_rounds=1,
            known_findings=[{'category': 'sample',
                 'authorization': 'Bearer VERYSECRETEXAMPLE123'}],
            endpoint=f'http://127.0.0.1:{server.server_address[1]}')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert report['requests_sent'] == 2 and report['executed']
    assert len(captured) == 1
    assert 'VERYSECRETEXAMPLE123' not in captured[0]
