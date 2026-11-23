"""RC13 contract tests: don't regress legacy workflows, auth and safe defaults."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.coverage_rc13 import coverage_catalog, execution_coverage
from achillesapi.core.pipeline_rc13 import create_plan, execute_pipeline, PipelineError
from achillesapi.core.advanced_get_rc11 import advanced_get_scan


@pytest.fixture
def spec(tmp_path):
    document = {'openapi': '3.0.3', 'info': {'title': 'Example Business', 'version': '1'},
                'paths': {'/search': {'get': {'parameters': [{'in': 'query', 'name': 'term',
                        'schema': {'type': 'string'}}], 'responses': {'200': {'description': 'OK'}}}},
                          '/items': {'post': {'requestBody': {'content': {'application/json': {
                              'schema': {'type': 'object', 'properties': {'name': {'type': 'string'}}}}}},
                              'responses': {'201': {'description': 'created'}}}}}}
    p = tmp_path / 'api.json'
    p.write_text(json.dumps(document))
    return p


def test_catalog(spec):
    plan = create_plan(spec)
    assert plan['api_name'] == 'Example Business'
    assert plan['test_types']['body_injection']['available'] is False
    assert plan['catalog']['operations_total'] == 2


def test_plan_does_not_contact_target(spec):
    report = execute_pipeline(spec, base_url='https://example.com', allowed_hosts=set(), execute=False)
    assert report['requests_sent'] == 0
    assert report['findings'] == []
    assert report['coverage']['operations_with_evaluable_http_results'] == 0


def test_refuses_writes_without_manifest(spec):
    with pytest.raises(PipelineError, match='manifest'):
        execute_pipeline(spec, base_url='https://example.com', allowed_hosts={'example.com'},
                         approve_writes=True)


def test_refuses_out_of_scope_before_network(spec):
    with pytest.raises(PipelineError, match='host'):
        execute_pipeline(spec, base_url='https://example.com', allowed_hosts={'other.com'},
                         execute=True)


def test_refuses_plain_http_without_approval(spec):
    with pytest.raises(PipelineError, match='HTTP'):
        execute_pipeline(spec, base_url='http://127.0.0.1:8000', allowed_hosts={'127.0.0.1'},
                         execute=True)


def test_dry_run_get_probe(spec):
    result = advanced_get_scan(json.loads(spec.read_text()), base_url='https://example.com',
                               allow_hosts={'example.com'})
    assert result['executed'] is False
    assert result['cases'][0]['parameter'] == 'term'


def test_coverage_is_not_a_security_score(spec):
    catalog = coverage_catalog(json.loads(spec.read_text()))
    result = execution_coverage(catalog, {'injection': {'executed': True,
        'cases': [{'operation': 'GET /search', 'request_count': 3, 'status': 'no_indicator'}],
        'requests_sent': 3}})
    assert result['operations_with_evaluable_http_results'] == 1
    assert 'POST /items' in result['operations_not_verified']
    assert result['coverage_not_a_security_score']


def test_cli_new_commands(spec, tmp_path):
    runner = CliRunner()
    out = tmp_path / 'plan.json'
    result = runner.invoke(app, ['rc13-coverage', str(spec), '-o', str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
    out2 = tmp_path / 'dry.json'
    result = runner.invoke(app, ['rc13-assess', str(spec), '-o', str(out2)])
    assert result.exit_code == 0, result.output
    assert json.loads(out2.read_text())['requests_sent'] == 0


def test_body_probe_plan_requires_approved_string_field():
    from achillesapi.core.body_probes_rc11 import body_probe_plan
    from achillesapi.core.openapi import parse_openapi
    document = {'openapi': '3.0.3', 'info': {'title':'Body Fixture','version':'1'},
      'paths': {'/items': {'post': {'requestBody': {'content': {'application/json': {'schema': {'type': 'object', 'properties': {'label': {'type': 'string', 'maxLength': 80}}}}}}, 'responses': {'201': {'description': 'ok'}}}},
       '/items/{item_id}': {'parameters': [{'name':'item_id','in':'path','required': True,
                          'schema':{'type':'string'}}],
                          'get': {'responses': {'200': {'description':'ok'}}},
                          'patch': {'requestBody': {'content': {'application/json': {
                              'schema': {'type': 'object', 'properties': {'role': {'type':'string'}}}}}},
                             'responses': {'200': {'description':'ok'}}},
                          'delete': {'responses': {'204': {'description':'ok'}}}}}}
    workflow = {'name': 'safe-asset',
      'create': {'operation': 'POST /items', 'identity': 'owner', 'body': {'label': 'unit-test'},
                 'id_pointer': '/id','marker_field': 'label'},
      'read': {'operation':'GET /items/{item_id}','identity':'owner',
               'id_parameter':'item_id','id_pointer':'/id'},
      'mutation': {'operation':'PATCH /items/{item_id}', 'identity':'owner',
                   'body': {'role':'employee'}, 'restricted_fields':['role']},
      'cleanup': {'operation':'DELETE /items/{item_id}', 'identity':'owner'}}
    plan = body_probe_plan(parse_openapi(document), document, [workflow], {'owner'})
    assert len(plan['cases']) == 2
    assert plan['request_budget_required'] >= 10
    from achillesapi.core.body_probes_rc11 import run_body_probes
    with pytest.raises(ValueError, match='approvazioni'):
        run_body_probes(parse_openapi(document), document, [workflow],
            identities={'owner': None}, base_url='http://127.0.0.1:1234',
            allowed_hosts={'127.0.0.1'}, execute=True,
            approve_writes=True, approve_body_probes=False,
            allow_insecure_http=True, max_requests=100)
