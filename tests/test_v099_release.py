"""Test v0.99: API diverse, privacy, CLI e controlli della release candidate."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.access_review_v099 import review_access_evidence
from achillesapi.core.ai_guard_v099 import validate_advisory_plan
from achillesapi.core.benchmark_review_v099 import compare_ground_truth
from achillesapi.core.evidence_package_v099 import build_evidence_package
from achillesapi.core.http import SafeHTTPClient, RequestBudgetExceeded
from achillesapi.core.mutation_review_v099 import review_mutations
from achillesapi.core.release_quality_v099 import assess_release_readiness, diagnose_campaign
from achillesapi.core.registry_v090 import TOOLS, SUITE_ORDER
from achillesapi.core.workflow_safety_v099 import review_workflow_safety


@pytest.fixture
def catalog_api():
    return {'openapi': '3.0.3', 'info': {'title': 'Catalog', 'version': '1'},
            'paths': {'/items': {'post': {'responses': {'201': {'description': 'created'}}}},
                      '/items/{id}': {
                          'get': {'parameters': [{'name': 'id', 'in': 'path', 'required': True,
                                                 'schema': {'type': 'string'}}],
                                  'responses': {'200': {'description': 'ok'}}},
                          'delete': {'responses': {'204': {'description': 'deleted'}}}}}}


@pytest.fixture
def read_only_api():
    return {'openapi': '3.1.0', 'info': {'title': 'Observability', 'version': '2'},
            'paths': {'/health': {'get': {'responses': {'200': {'description': 'ok'}}}},
                      '/metrics': {'get': {'responses': {'200': {'description': 'ok'}}}}}}


def test_registry_includes_v099_offline_features():
    assert len(TOOLS) == len(SUITE_ORDER) + 2 >= 53 and 'rc13-assess' in TOOLS
    for key in ('workflow-safety', 'access-evidence-review', 'mutation-review',
                'evidence-package', 'benchmark-review', 'release-readiness',
                'ai-plan-guard', 'campaign-diagnostics'):
        assert not TOOLS[key].get('active')


@pytest.mark.parametrize('valid', [False, True])
def test_access_differences_are_not_confirmed_without_policy(valid):
    report = {'execution_report': {'observations': [
        {'operation': 'GET /items/{id}', 'identity': 'alice', 'status': 200},
        {'operation': 'GET /items/{id}', 'identity': 'bob', 'status': 403} ]}}
    if valid:
        report['access_expectations'] = [
            {'operation': 'GET /items/{id}', 'identity': 'alice', 'access': 'deny'}]
    result = review_access_evidence(report)
    assert result['summary']['response_differences'] == 1
    assert result['summary']['policy_conflicts'] == (1 if valid else 0)
    assert result['confirmed_vulnerabilities'] == 0


def test_access_malformed_is_rejected():
    with pytest.raises(ValueError):
        review_access_evidence({'execution_report': {'observations': 'not a list'}})


def test_mass_assignment_review_never_outputs_private_values():
    raw = {'state_comparisons': [{'operation': 'PATCH /items/{id}',
           'before': {'role': 'REDACTME', 'name': 'Alice'},
           'after': {'role': 'admin', 'name': 'Alice'},
           'protected_fields': ['role'], 'attempted_fields': ['role']}]}
    result = review_mutations(raw)
    assert result['summary']['suspicious_changes'] == 1
    assert result['cases'][0]['changed_protected_fields'] == ['role']
    assert 'REDACTME' not in json.dumps(result)
    assert result['confirmed_vulnerabilities'] == 0


def test_workflow_safety_is_generic(catalog_api, read_only_api):
    result = review_workflow_safety(catalog_api)
    assert result['summary']['candidate_workflows'] == 1
    assert result['summary']['with_documented_delete'] == 1
    assert all(x['status'] == 'requires_operator_manifest' for x in result['proposals'])
    assert review_workflow_safety(read_only_api)['proposals'] == []


def test_independent_benchmark_calculates_f1():
    summary = compare_ground_truth({'positive_ids': ['A', 'B']},
                                   {'verified_positive_ids': ['A', 'C']})['summary']
    assert (summary['tp'], summary['fp'], summary['fn']) == (1, 1, 1)
    assert summary['precision'] == summary['recall'] == summary['f1'] == .5
    with pytest.raises(ValueError):
        compare_ground_truth({'positive_ids': 'A'}, {'verified_positive_ids': []})


def test_evidence_package_discards_values():
    raw = {'plan': {'operations': []}, 'execution_report': {'findings': [
        {'category': 'BOLA', 'operation': 'GET /users/SECRET', 'reason': 'Bearer secretToken',
         'severity': 'high'}]}}
    result = build_evidence_package(raw)
    assert 'SECRET' not in json.dumps(result)
    assert 'secretToken' not in json.dumps(result)
    assert result['requests_sent'] == 0


def test_campaign_gate_does_not_certify_security():
    report = {'steps': [{'action': 'assess', 'status': 'complete'},
                       {'action': 'workflow-assess', 'status': 'skipped'}],
              'verification': {'summary': {'requires_review': 2}}}
    assert diagnose_campaign(report)['status'] == 'needs_attention'
    result = assess_release_readiness(report)
    assert result['state'] == 'requires_operator_review'
    assert result['formal_checks_passed'] < result['formal_checks_total']


def test_ai_plan_guard_rejects_remote_urls_and_unknown_commands(read_only_api):
    proposal = {'actions': [
        {'action': 'security-inventory', 'operation': 'GET /health'},
        {'action': 'run-shell', 'operation': 'GET /health'},
        {'action': 'security-inventory', 'operation': 'GET /unknown'},
        {'action': 'security-inventory', 'operation': 'GET /health', 'url': 'https://evil.example'},
    ]}
    result = validate_advisory_plan(read_only_api, proposal)
    assert result['summary'] == {'accepted': 1, 'rejected': 3}
    assert not result['auto_executed']
    assert 'evil.example' not in json.dumps(result)


def test_http_client_counts_attempts_but_not_dry_runs(monkeypatch):
    original_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={'ok': True}))
    def fake_client(**kwargs):
        kwargs['transport'] = transport
        return original_client(**kwargs)
    monkeypatch.setattr(httpx, 'Client', fake_client)
    client = SafeHTTPClient(allowed_hosts={'127.0.0.1'}, max_requests=1,
                            requests_per_second=10000)
    client.request('GET','http://127.0.0.1:8000/test', execute=False)
    assert client.request_statistics['attempted'] == 0
    client.request('GET','http://127.0.0.1:8000/test', execute=True)
    assert client.request_statistics['attempted'] == 1
    assert client.request_statistics['responses_received'] == 1
    with pytest.raises(RequestBudgetExceeded):
        client.request('GET','http://127.0.0.1:8000/test',execute=True)
    assert client.request_statistics['attempted'] == 1


def test_cli_eight_new_commands_work_offline(tmp_path, catalog_api):
    runner = CliRunner()
    spec = tmp_path / 'openapi.json'
    source = tmp_path / 'assessment.json'
    truth = tmp_path / 'truth.json'
    verified = tmp_path / 'verified.json'
    proposals = tmp_path / 'proposals.json'
    spec.write_text(json.dumps(catalog_api))
    source.write_text(json.dumps({'steps': [{'action': 'assess', 'status': 'complete'}]}))
    truth.write_text(json.dumps({'positive_ids': ['A']}))
    verified.write_text(json.dumps({'verified_positive_ids': ['A']}))
    proposals.write_text(json.dumps({'actions': [{'action': 'security-inventory'}]}))
    for args in [
        ['workflow-safety', str(spec)],
        ['access-evidence-review', str(source)],
        ['mutation-review', str(source)],
        ['evidence-package', str(source)],
        ['campaign-diagnostics', str(source)],
        ['release-readiness', str(source)],
        ['benchmark-review', str(truth), str(verified)],
        ['ai-plan-guard', str(spec), '--proposals', str(proposals)],
    ]:
        output = tmp_path / (args[0] + '.json')
        result = runner.invoke(app, [*args, '--output', str(output)])
        assert result.exit_code == 0, (args, result.output, result.exception)
        assert json.loads(output.read_text())['requests_sent'] == 0


def test_independent_corpus_validates_five_different_openapi_documents(tmp_path):
    from achillesapi.core.independent_validation_v099 import validate_specification_corpus
    fixtures = Path(__file__).resolve().parent/'fixtures'/'benchmark_specs'
    audit = validate_specification_corpus(fixtures)
    assert audit['summary'] == {'total': 5, 'planned': 5, 'failed': 0}
    assert len({item['operations'] for item in audit['cases']}) >= 2
    assert audit['requests_sent'] == 0
    dest = tmp_path/'corpus.json'
    result = CliRunner().invoke(app, ['benchmark-corpus', str(fixtures), '--output', str(dest)])
    assert result.exit_code == 0, result.output
    assert json.loads(dest.read_text())['summary']['planned'] == 5
