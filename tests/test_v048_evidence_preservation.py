"""Regression: real HTTP observations must not erase original scanner findings."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner
from achillesapi.cli import app
from achillesapi.core.evidence_signals import scanner_findings
from achillesapi.reporting.professional import summarize_assessment


SPEC = '''openapi: 3.0.3
info:
  title: Regression API
  version: "1"
paths:
  /profile/exposed:
    get:
      responses:
        '200': {description: OK}
  /misconfigured/cors:
    get:
      responses:
        '200': {description: OK}
  /projects/{project_ref}:
    get:
      parameters:
        - name: project_ref
          in: path
          required: true
          schema: {type: string}
      responses:
        '200': {description: OK}
'''


def assessment():
    return {
        'version': '0.47.0',
        'plan': {'operations': [{'status': 'eligible_get'}] * 3,
                 'execution': {'requests_sent': 3}},
        'execution_report': {
            'observations': [
                {'operation': 'GET /profile/exposed', 'status': 200},
                {'operation': 'GET /misconfigured/cors', 'status': 200},
                {'operation': 'GET /projects/{project_ref}', 'status': 200},
            ],
            'findings': [
                {'id': 'OBS-0001', 'category': 'write_only_property_returned',
                 'operation': 'GET /profile/exposed', 'severity': 'medium',
                 'why_flagged': 'A writeOnly value was returned',
                 'evidence': {'property_paths': ['password', 'credential_private']}},
                {'id': 'OBS-0002', 'category': 'cors_credentialed_origin_reflection',
                 'operation': 'GET /misconfigured/cors', 'severity': 'medium',
                 'evidence': {'arbitrary_origin_reflected': True,
                              'allow_credentials': True,
                              'authorization': 'Bearer SUPERSECRET'}},
            ],
        },
        'multi_resource_execution': {'findings': [{
            'category': 'AUTHORIZATION_POLICY_MISMATCH',
            'operation': 'GET /projects/{project_ref}',
            'expected': 'deny', 'observed_status': 200,
            'description': 'Conflicts with test policy',
        }]},
    }


def test_scanner_finding_bridge_keeps_three_and_redacts():
    original = assessment()
    found = scanner_findings(original)
    assert len(found) == 3
    assert [x['category'] for x in found] == [
        'write_only_property_returned', 'cors_credentialed_origin_reflection',
        'AUTHORIZATION_POLICY_MISMATCH',
    ]
    assert found[0]['evidence']['property_count'] == 2
    assert found[1]['evidence']['allow_credentials'] is True
    assert found[2]['evidence']['expected_access'] == 'deny'
    assert found[2]['evidence']['observed_status'] == 200
    serialized = json.dumps(found)
    assert 'SUPERSECRET' not in serialized
    assert 'password' not in serialized
    assert 'credential_private' not in serialized
    assert all(x['verified'] is False for x in found)


def test_professional_export_preserves_cors_flags_and_no_raw_properties():
    report = summarize_assessment(assessment())
    assert report['summary']['findings_requiring_review'] == 3
    first, cors, policy = report['findings']
    assert first['evidence']['property_count'] == 2
    assert cors['evidence']['arbitrary_origin_reflected'] is True
    assert cors['evidence']['allow_credentials'] is True
    assert cors['reason'] != '[redacted: potentially sensitive]'
    assert policy['category'] == 'AUTHORIZATION_POLICY_MISMATCH'
    extracted = scanner_findings(report)
    assert len(extracted) == 3
    assert extracted[1]['evidence']['allow_credentials'] is True
    serialized = json.dumps(report)
    assert 'SUPERSECRET' not in serialized
    assert 'credential_private' not in serialized


def test_cli_ai_correlation_keeps_both_scanner_and_response_categories(tmp_path, monkeypatch):
    spec = tmp_path/'spec.yaml'
    spec.write_text(SPEC, encoding='utf-8')
    data = tmp_path/'assessment.json'
    data.write_text(json.dumps(assessment()), encoding='utf-8')
    output = tmp_path/'correlation.json'
    captured = {}

    def fake_ollama(_api, evidence, **_kwargs):
        captured['evidence'] = evidence
        return {'executive_summary': 'Controlli da verificare',
                'cross_correlations': [], 'false_positive_checks': [],
                'next_steps': [], 'limitations': [], 'execution_authorized': False}

    monkeypatch.setattr('achillesapi.cli.correlate_with_ollama', fake_ollama)
    result = CliRunner().invoke(app, ['ai-correlate', str(spec), str(data),
                                      '--output', str(output)])
    assert result.exit_code == 0, result.output
    saved = json.loads(output.read_text())
    assert saved['evidence_analysis']['responses_analyzed'] == 3
    # No raw headers -> detection engine reports zero *new* indicators, while
    # scanner observations MUST survive and be sent to Ollama.
    assert saved['evidence_analysis']['summary']['finding_count'] == 0
    assert saved['evidence_analysis']['scanner_observations']['count'] == 3
    assert captured['evidence']['scanner_observations']['count'] == 3
    assert saved['target_requests_sent'] == 0
    assert saved['ai_correlation']['execution_authorized'] is False


def test_forged_arbitrary_report_text_cannot_leak_to_model():
    raw = assessment()
    raw['execution_report']['findings'][0]['why_flagged'] = 'Bearer VERYPRIVATE'
    raw['execution_report']['findings'][0]['evidence']['body_preview'] = 'VERYPRIVATE'
    result = json.dumps(scanner_findings(raw))
    assert 'VERYPRIVATE' not in result


def test_ai_output_report_preserves_scanner_evidence_after_export():
    from achillesapi.ai.sanitizer import sanitize
    findings = scanner_findings(assessment())
    sanitized = sanitize({'scanner_observations': {'findings': findings}})
    assert sanitized['scanner_observations']['findings'][1]['evidence']['allow_credentials'] is True
    derived = {
        'engine': 'achillesapi-local-intelligence',
        'evidence_analysis': {'scanner_observations': {'count': 3, 'findings': findings}},
        'ai_correlation': {'executive_summary': 'No confirmed vulnerabilities'},
    }
    exported = summarize_assessment(derived)
    assert exported['summary']['findings_requiring_review'] == 3
    assert exported['summary']['findings_by_severity']['medium'] == 2
    assert exported['findings'][1]['evidence']['allow_credentials'] is True
    assert exported['findings'][0]['evidence']['property_count'] == 2


def test_ollama_receives_structured_scanner_signals_on_loopback():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from achillesapi.ai.intelligence import correlate_with_ollama
    from achillesapi.core.openapi import analyze_openapi_file
    from tempfile import TemporaryDirectory

    captured = {}
    class FakeOllama(BaseHTTPRequestHandler):
        def do_POST(self):
            content = json.loads(self.rfile.read(int(self.headers['content-length'])))
            captured['message'] = content['messages'][1]['content']
            response = {'message': {'content': json.dumps({
                'executive_summary': 'Tre osservazioni richiedono verifica',
                'cross_correlations': [], 'false_positive_checks': [],
                'next_steps': [], 'limitations': []})}}
            body = json.dumps(response).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            pass

    with TemporaryDirectory() as directory:
        spec = Path(directory)/'api.yaml'
        spec.write_text(SPEC)
        parsed = analyze_openapi_file(spec)
        server = ThreadingHTTPServer(('127.0.0.1', 0), FakeOllama)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            evidence = {'findings': [], 'scanner_observations': {
                'count': 3, 'findings': scanner_findings(assessment())}}
            correlate_with_ollama(parsed, evidence,
                                  endpoint=f'http://127.0.0.1:{server.server_port}')
            assert 'cors_credentialed_origin_reflection' in captured['message']
            assert '"allow_credentials": true' in captured['message']
            assert '"property_count": 2' in captured['message']
            assert 'SUPERSECRET' not in captured['message']
            assert 'credential_private' not in captured['message']
        finally:
            server.shutdown()
            server.server_close()
