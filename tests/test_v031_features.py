"""Version 0.31: generic offline engines and optional network scope guard."""
from __future__ import annotations

import json
import socket
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.core.openapi import analyze_openapi_file
from achillesapi.core.production_v031 import (
    AssessmentPolicyError, benchmark_evaluate, coverage_report, differential_review,
    scope_audit, workflow_graph,
)


SPEC = Path('labs/independent_api/openapi.json')


def test_scope_audit_explicit_host_and_cidr():
    assert scope_audit('https://staging.example.com/v1', ['staging.example.com'])['approved']
    assert not scope_audit('https://other.example.com', ['staging.example.com'])['approved']
    assert not scope_audit('http://127.0.0.1:8000', ['127.0.0.1'], allowed_cidrs=['10.0.0.0/8'])['approved']
    with pytest.raises(AssessmentPolicyError):
        scope_audit('https://staging.example.com', ['staging.example.com'], allowed_cidrs=['not-a-cidr'])


def test_scope_audit_credentials_and_traversal():
    assert not scope_audit('https://user:pass@target.test/', ['target.test'])['approved']
    assert not scope_audit('https://target.test/%2e%2e/secrets', ['target.test'])['approved']


def test_coverage_reports_missing_operations_not_assumed_tested():
    api = analyze_openapi_file(SPEC)
    operation = f'{api.endpoints[0].method} {api.endpoints[0].path}'
    assessment = {'plan': {'operations': [{'method': api.endpoints[0].method,
                                          'path': api.endpoints[0].path,
                                          'status': 'eligible_get'}]},
                  'execution_report': {'observations': [{'operation': operation, 'status': 200, 'check': 'baseline'}]}}
    report = coverage_report(api, assessment)
    assert report['observed_operations'] == 1
    assert report['declared_operations'] == len(api.endpoints)
    assert report['unobserved_operations'] == len(api.endpoints) - 1


def test_coverage_does_not_count_planned_only():
    api = analyze_openapi_file(SPEC)
    result = coverage_report(api, {'plan': {'operations': [{'method': 'GET', 'path': '/whatever', 'status': 'eligible_get'}]}})
    assert result['observed_operations'] == 0


def test_differential_only_prepares_manual_review():
    report = differential_review({'execution_report': {'observations': [
        {'operation': 'GET /things', 'identity': 'alice', 'check': 'baseline', 'status': 200},
        {'operation': 'GET /things', 'identity': 'alice', 'check': 'invalid', 'status': 400},
        {'operation': 'GET /things', 'identity': 'bob', 'check': 'baseline', 'status': 200},
    ]}})
    assert report['review_count'] == 1
    assert report['confirmed_vulnerabilities'] == 0


def _graph_manifest():
    return {'steps': [
        {'id': 'create', 'operation': 'POST /api/documents', 'kind': 'create', 'cleanup_step': 'cleanup'},
        {'id': 'read', 'operation': 'GET /api/documents/{document_ref}', 'depends_on': ['create']},
        {'id': 'cleanup', 'operation': 'DELETE /api/documents/{document_ref}', 'kind': 'cleanup', 'depends_on': ['create', 'read']},
    ]}


def _synthetic_api():
    from achillesapi.models.api import EndpointInfo, ParsedAPI
    return ParsedAPI(title='Unrelated', version='1.0', openapi_version='3.0.3', endpoints=[
        EndpointInfo(path='/api/documents', method='POST'),
        EndpointInfo(path='/api/documents/{document_ref}', method='GET'),
        EndpointInfo(path='/api/documents/{document_ref}', method='DELETE'),
    ])


def test_workflow_dag_is_offline_and_cleanup_required():
    result = workflow_graph(_synthetic_api(), _graph_manifest())
    assert result['execution_order'] == ['create', 'read', 'cleanup']
    assert not result['executable'] and result['requests_sent'] == 0


def test_workflow_graph_rejects_cycle_and_missing_cleanup():
    value = _graph_manifest()
    value['steps'][0]['depends_on'] = ['read']
    with pytest.raises(AssessmentPolicyError, match='cycle'):
        workflow_graph(_synthetic_api(), value)
    value = _graph_manifest()
    value['steps'][0].pop('cleanup_step')
    with pytest.raises(AssessmentPolicyError, match='cleanup'):
        workflow_graph(_synthetic_api(), value)


def test_benchmark_uses_verified_labels_only():
    result = benchmark_evaluate({'positive_ids': ['a', 'b']}, {'verified_positive_ids': ['a', 'c']})
    assert (result['true_positives'], result['false_positives'], result['false_negatives']) == (1, 1, 1)
    assert result['precision'] == 0.5 and result['recall'] == 0.5
    with pytest.raises(AssessmentPolicyError):
        benchmark_evaluate({'positive_ids': ['a']}, {'findings': [{'id': 'a'}]})


def test_http_scope_enforces_cidr_before_connection():
    client = SafeHTTPClient(allowed_hosts={'staging.example.test'}, allowed_cidrs={'10.10.0.0/16'})
    with patch('achillesapi.core.http.socket.getaddrinfo', return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.10.1.3', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443)),
    ]):
        with pytest.raises(ScopeError, match='outside approved'):
            client.request('GET', 'https://staging.example.test/test', execute=False)
    with patch('achillesapi.core.http.socket.getaddrinfo', return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.10.1.3', 443)),
    ]):
        result = client.request('GET', 'https://staging.example.test/test', execute=False)
    assert not result.executed


def test_http_does_not_log_redirect_location_or_raw_exception():
    sensitive = SafeHTTPClient._safe_headers({'Location': 'https://elsewhere/?token=abc',
                                              'WWW-Authenticate': 'Bearer token=sensitive', 'Server': 'nginx'})
    assert sensitive['Location'] == '[REDACTED]'
    assert sensitive['WWW-Authenticate'] == '[REDACTED]'
    assert sensitive['Server'] == 'nginx'


def test_cli_new_commands(tmp_path):
    runner = CliRunner()
    scope_file = tmp_path / 'scope.json'
    result = runner.invoke(app, ['scope-audit', 'https://example.test/v1', '--allow-host', 'example.test', '--output', str(scope_file)])
    assert result.exit_code == 0, result.output
    assert json.loads(scope_file.read_text())['approved'] is True
    result = runner.invoke(app, ['scope-audit', 'https://bad.example.test', '--allow-host', 'example.test'])
    assert result.exit_code == 2
    assessment = tmp_path / 'assessment.json'
    assessment.write_text(json.dumps({'plan': {'operations': []}, 'execution_report': {'observations': []}}))
    result = runner.invoke(app, ['coverage-report', str(SPEC), str(assessment), '--output', str(tmp_path / 'coverage.json')])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ['differential-review', str(assessment), '--output', str(tmp_path / 'review.json')])
    assert result.exit_code == 0, result.output
    expected = tmp_path / 'expected.json'
    verified = tmp_path / 'verified.json'
    expected.write_text('{"positive_ids":["case1"]}')
    verified.write_text('{"verified_positive_ids":["case1"]}')
    result = runner.invoke(app, ['benchmark-evaluate', str(expected), str(verified), '--output', str(tmp_path / 'bench.json')])
    assert result.exit_code == 0, result.output


def test_next_actions_offline_never_invents_operations():
    from achillesapi.core.production_v031 import next_actions
    api = analyze_openapi_file(SPEC)
    operation = api.endpoints[0]
    plan = {'plan': {'operations': [{'method': operation.method, 'path': operation.path, 'status': 'eligible_get'}]}}
    result = next_actions(api, plan, budget=4)
    known = {f'{ep.method} {ep.path}' for ep in api.endpoints}
    assert all(action['operation'] in known for action in result['proposed_actions'])
    assert result['requests_sent'] == 0 and not result['llm_may_execute']
    with pytest.raises(AssessmentPolicyError):
        next_actions(api, plan, budget=51)
