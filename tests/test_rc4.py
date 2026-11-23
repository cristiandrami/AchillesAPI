"""RC4: prove riproducibili su Swagger indipendente e server HTTP locale."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.access_matrix_rc4 import preflight_rules, run_access_matrix
from achillesapi.core.access_probe_rc import ProbeError
from achillesapi.core.ai_followup_rc4 import local_followup_review
from achillesapi.core.auth import AuthenticationFile, AuthenticationManager
from achillesapi.core.auth_session_rc4 import audit_session_profiles
from achillesapi.core.evidence_gate_rc4 import review_proof_records


SPEC = {'openapi': '3.0.3', 'info': {'title': 'Independently tested', 'version': '1.0'},
        'paths': {'/items/{item_id}': {'get': {
            'parameters': [{'name': 'item_id', 'in': 'path', 'required': True,
                            'schema': {'type': 'string'}}],
            'responses': {'200': {'description': 'ok'}, '403': {'description': 'forbidden'}}}}}}


def files(tmp_path):
    spec = tmp_path / 'spec.json'
    spec.write_text(json.dumps(SPEC))
    auth = tmp_path / 'auth.yaml'
    auth.write_text('profiles:\n  - name: owner\n    type: bearer\n    token: secret-owner\n'
                    '  - name: other\n    type: bearer\n    token: secret-other\n')
    policy = {'rules': [{'id': 'item-read', 'operation': 'GET /items/{item_id}',
                         'path_values': {'item_id': '42'}, 'owner': 'owner',
                         'other': 'other', 'expected_other': 'deny'}]}
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(policy))
    return spec, auth, rules, policy


def test_preflight_rejects_invalid_rule_before_network(tmp_path, monkeypatch):
    spec, auth, _, policy = files(tmp_path)
    manager = AuthenticationManager.from_file(auth)
    policy['rules'].append({**policy['rules'][0], 'id': 'bad',
                            'operation': 'POST /items/{item_id}'})
    monkeypatch.setattr(manager, 'resolve', lambda *_a, **_k:
                        pytest.fail('Il preflight non deve chiamare auth'))
    with pytest.raises(ProbeError):
        run_access_matrix(spec, policy=policy, base_url='https://example.test',
                          allowed_hosts={'example.test'}, auth_manager=manager, execute=True)


def test_preflight_rejects_injection_or_unknown_operation(tmp_path):
    spec, auth, _, policy = files(tmp_path)
    policy['rules'][0]['path_values'] = {'item_id': '../secret'}
    with pytest.raises(ProbeError):
        preflight_rules(spec, policy, profile_names={'owner','other'})
    policy['rules'][0]['path_values'] = {'item_id': '42'}
    policy['rules'][0]['operation'] = 'GET /hidden/{item_id}'
    with pytest.raises(ProbeError):
        preflight_rules(spec, policy, profile_names={'owner','other'})


def test_dryrun_never_contacts_target_or_returns_secrets(tmp_path, monkeypatch):
    spec, auth, _, policy = files(tmp_path)
    manager = AuthenticationManager.from_file(auth)
    monkeypatch.setattr(manager, 'resolve', lambda *_a, **_k:
                        pytest.fail('Non risolvere credenziali in dry-run'))
    result = run_access_matrix(spec, policy=policy, base_url='https://example.test',
        allowed_hosts={'example.test'}, auth_manager=manager)
    assert result['status'] == 'dry_run' and result['requests_sent'] == 0
    assert 'secret-owner' not in json.dumps(result)


def test_access_matrix_live_local_server(tmp_path):
    spec, auth, _, policy = files(tmp_path)
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.path, self.headers.get('Authorization')))
            body = b'{"item_id":"42"}'
            if self.headers.get('Authorization') == 'Bearer secret-other':
                self.send_response(200)  # Questo e' il comportamento sospetto.
            else:
                self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_access_matrix(spec, policy=policy,
            base_url=f'http://127.0.0.1:{server.server_port}',
            allowed_hosts={'127.0.0.1'}, auth_manager=AuthenticationManager.from_file(auth),
            execute=True, allow_insecure_http=True, max_requests=2, rate=100)
        assert len(hits) == 2
        assert result['requests_sent'] == 2
        assert result['summary']['review_required'] == 1
        assert result['confirmed_vulnerabilities'] == 0
        assert 'secret-owner' not in json.dumps(result)
        assert 'secret-other' not in json.dumps(result)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_matrix_budget_preflight(tmp_path):
    spec, auth, _, policy = files(tmp_path)
    with pytest.raises(ProbeError, match='Budget'):
        run_access_matrix(spec, policy=policy, base_url='https://example.test',
            allowed_hosts={'example.test'}, auth_manager=AuthenticationManager.from_file(auth),
            max_requests=1, execute=True)


def test_sessions_audit_never_exports_inline_tokens(tmp_path):
    _, auth, _, _ = files(tmp_path)
    result = audit_session_profiles(auth)
    assert result['summary'] == {'total': 2, 'dynamic': 0}
    assert 'secret-' not in json.dumps(result)


def test_evidence_requires_independent_proof_and_never_auto_confirms():
    data = {'records': [{'finding_id': 'BOLA-1', 'evidence_refs': ['req-A', 'res-B'],
                         'independent_policy_ref': 'rule-access', 'reproduced': True},
                        {'finding_id': 'BOLA-2', 'evidence_refs': ['req-C'],
                         'reproduced': False, 'confirmed': True}]}
    result = review_proof_records(data)
    assert result['records'][0]['evidence_status'] == 'ready_for_manual_confirmation'
    assert result['records'][1]['evidence_status'] == 'insufficient_evidence'
    assert all(row['confirmed_automatically'] is False for row in result['records'])
    with pytest.raises(ValueError):
        review_proof_records({'records':[{'finding_id':'\nsecret'}]})


def test_ollama_proposals_restricted_even_if_model_suggests_shell(monkeypatch):
    def fake(*_, **__):
        return {'recommended_tests': ['security-inventory', 'rm -rf /',
                                      'GET https://evil.example', 'workflow-discover']}
    monkeypatch.setattr('achillesapi.core.ai_followup_rc4.analyze_with_ollama',fake)
    result = local_followup_review(SPEC, {'findings': []})
    assert result['auto_executed'] is False
    assert len(result['validated_actions']) == 2
    assert result['discarded_free_text'] == 2
    assert 'rm -rf' not in json.dumps(result)


def test_new_cli_commands_operational(tmp_path, monkeypatch):
    spec, auth, rules, _ = files(tmp_path)
    cli = CliRunner()
    for argv in [
        ['access-matrix',str(spec),'--rules',str(rules),'--base-url',
         'https://example.test','--allow-host','example.test','--auth-config',str(auth)],
        ['auth-session-audit','--config',str(auth)],
    ]:
        out = tmp_path / (argv[0] + '.json')
        response = cli.invoke(app, [*argv,'--output',str(out)])
        assert response.exit_code == 0, response.output
        assert out.exists()
    proof = tmp_path / 'proof.json'
    proof.write_text('{"records": []}')
    result = cli.invoke(app, ['proof-gate',str(proof),'--output',str(tmp_path/'proof-result.json')])
    assert result.exit_code == 0, result.output


def test_registry_and_version():
    from achillesapi.core.registry_v090 import TOOLS, SUITE_ORDER
    from achillesapi import __version__
    assert __version__ == '1.0.0rc27'  # Versione corrente del pacchetto
    assert set(TOOLS) == set(SUITE_ORDER) | {'rc13-assess', 'rc15-scan'} and len(SUITE_ORDER) == 65


def test_process_supervisor_completes_and_handles_timeout(tmp_path):
    import os
    import subprocess
    import sys
    from achillesapi.core.process_supervisor_rc4 import run_cli_bounded
    ok = run_cli_bounded([sys.executable, '-c', 'print("ok")'],
                         cwd=tmp_path, env=os.environ, timeout=5)
    assert ok.returncode == 0
    with pytest.raises(subprocess.TimeoutExpired):
        run_cli_bounded([sys.executable,'-c','import time;time.sleep(20)'],
                        cwd=tmp_path, env=os.environ, timeout=.15)


def test_process_supervisor_does_not_return_large_stdout(tmp_path):
    import os
    import sys
    from achillesapi.core.process_supervisor_rc4 import run_cli_bounded
    result=run_cli_bounded([sys.executable,'-c',
                'import sys;sys.stdout.write("S"*200000);sys.stderr.write("E"*20000)'],
                cwd=tmp_path,env=os.environ,timeout=5)
    assert result.returncode==0
    assert 'S' not in result.stderr and len(result.stderr)<=16384


def test_matrix_viewer_highlights_only_review_required():
    from achillesapi.dashboard.job_view import viewer_payload
    raw={'engine':'achilles-access-matrix-rc4',
         'rules':[{'id':'r1','operation':'GET /items/{item_id}',
                   'status':'policy_conflict_requires_review','observations':[]},
                  {'id':'r2','operation':'GET /health',
                   'status':'expected_denial_observed','observations':[]}]}
    view=viewer_payload(raw, action='access-matrix', job_id='a'*32)
    assert len(view['findings']) == 1
    assert view['findings'][0]['status']=='requires_review'
    assert any(section['key']=='rules' for section in view['sections'])
    assert view['findings'][0]['id']=='POLICY-001'
