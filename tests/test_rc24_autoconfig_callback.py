"""rc24: exhaustive OpenAPI inventory and opt-in dashboard-managed OAST."""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from achillesapi.core.autoconfig_rc24 import build_autoconfiguration
from achillesapi.dashboard.local_callback_control import LocalCallbackControl
from achillesapi.dashboard.server import create_app

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'src/achillesapi/dashboard/static'
ASTERION = ROOT / 'tests/fixtures/asterion_lab_openapi.json'


def test_autoconfig_enumerates_all_operations_including_non_crud():
    sample = {
        'openapi': '3.0.3',
        'info': {'title': 'Fixture', 'version': '1.0'},
        'servers': [{'url': 'https://api.example.test'}],
        'paths': {
            '/health': {'get': {'responses': {'200': {'description': 'ok'}}}},
            '/orders/{order_id}': {
                'get': {'parameters': [{'name': 'order_id', 'in': 'path', 'required': True,
                                        'schema': {'type': 'string'}}],
                        'responses': {'200': {'description': 'ok'}}},
                'patch': {'parameters': [{'name': 'order_id', 'in': 'path', 'required': True,
                                          'schema': {'type': 'string'}}],
                          'responses': {'200': {'description': 'ok'}}},
            },
            '/lookup': {'get': {'parameters': [{'name': 'q', 'in': 'query', 'required': True,
                                               'schema': {'type': 'string'}}],
                                'responses': {'200': {'description': 'ok'}}}},
            '/service': {'options': {'responses': {'200': {'description': 'ok'}}}},
        },
    }
    plan = build_autoconfiguration(sample)
    assert plan['requests_sent'] == 0
    assert plan['summary']['total_operations'] == 5
    assert len(plan['operations']) == 5
    ops = {item['operation']: item for item in plan['operations']}
    assert ops['GET /health']['status'] == 'read_candidate'
    assert ops['GET /orders/{order_id}']['missing_inputs'] == ['resource_ids']
    assert 'write_consent' in ops['PATCH /orders/{order_id}']['missing_inputs']
    assert 'required_query' in ops['GET /lookup']['missing_inputs']
    assert ops['OPTIONS /service']['status'] == 'requires_input'
    assert not any(op['active_authorized'] for op in plan['operations'])
    assert plan['suggested_base_url'] == 'https://api.example.test'


@pytest.mark.skipif(not ASTERION.is_file(), reason='Asterion fixture not available')
def test_asterion_has_all_39_operations_and_offline_draft():
    plan = build_autoconfiguration(json.loads(ASTERION.read_text(encoding='utf8')))
    assert plan['summary']['total_operations'] == 39
    assert plan['summary']['object_access_candidates'] >= 7
    assert plan['summary']['discovered_workflows'] == 3
    assert len(plan['operations']) == 39
    assert plan['workflow_draft_incomplete'] is True
    assert plan['workflow_draft']['resources']
    assert plan['suggested_base_url'] == 'http://127.0.0.1:8797'


def test_local_callback_control_is_loopback_only_and_can_stop():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    manager = LocalCallbackControl(port=port)
    assert manager.status()['running'] is False
    try:
        status = manager.start()
        assert status['running'] is True and status['managed_here'] is True
        assert status['url'] == f'http://127.0.0.1:{port}'
        assert manager.start()['running'] is True
    finally:
        manager.stop()
    assert manager.status()['running'] is False
    with pytest.raises(RuntimeError, match='soltanto'):
        manager.stop()


def test_dashboard_callback_routes_require_csrf_and_workspace_is_visible(tmp_path, monkeypatch):
    import achillesapi.dashboard.local_callback_control as module
    cls = module.LocalCallbackControl
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    monkeypatch.setattr(module, 'LocalCallbackControl', lambda: cls(port=port))
    app = create_app(tmp_path/'workspace')
    with TestClient(app, base_url='http://127.0.0.1:8766') as client:
        html = BeautifulSoup(client.get('/').text, 'html.parser')
        panel = html.find(id='securityScannerOptionsSection')
        assert panel is not None and 'simple-advanced-hidden' not in panel.get('class', [])
        for ident in ('callbackStart', 'callbackStop', 'callbackRefresh', 'callbackApply',
                      'rc15CallbackBase', 'rc15CallbackObserver', 'rc15CallbackAck',
                      'autoconfigPanel', 'autoconfigRows', 'autoMatrixIds', 'autoMatrixOthers',
                      'autoMatrixGenerate', 'autoMatrixPolicyAck'):
            assert html.find(id=ident) is not None, ident
        ids = [x['id'] for x in html.select('[id]')]
        assert len(ids) == len(set(ids))
        csrf = client.get('/api/bootstrap').json()['csrf_token']
        assert client.get('/api/control/callback/status').json()['running'] is False
        assert client.post('/api/control/callback/start').status_code == 403
        response = client.post('/api/control/callback/start', headers={'x-achilles-token': csrf})
        assert response.status_code == 200
        assert response.json()['running'] is True
        assert response.json()['managed_here'] is True
        assert client.get('/api/control/callback/status').json()['running'] is True
        assert client.post('/api/control/callback/stop').status_code == 403
        assert client.post('/api/control/callback/stop',headers={'x-achilles-token':csrf}).status_code == 200


@pytest.mark.skipif(not ASTERION.is_file(), reason='Asterion fixture not available')
def test_dashboard_auto_config_route_is_offline_and_complete(tmp_path):
    app=create_app(tmp_path/'workspace')
    with TestClient(app,base_url='http://127.0.0.1:8766') as client:
        csrf=client.get('/api/bootstrap').json()['csrf_token']
        with ASTERION.open('rb') as source:
            upload=client.post('/api/upload',files={'file':('openapi.json',source,'application/json')},
                               headers={'x-achilles-token':csrf})
        assert upload.status_code==200,upload.text
        spec_id=upload.json()['id']
        plan=client.get('/api/control/autoconfig/'+spec_id)
        assert plan.status_code==200,plan.text
        assert plan.json()['summary']['total_operations']==39
        assert plan.json()['requests_sent']==0
        assert all(row['active_authorized'] is False for row in plan.json()['operations'])
        assert client.get('/api/control/autoconfig/'+'0'*32).status_code==404


def test_rc15_planning_reaches_later_ssrf_endpoint_with_small_case_budget():
    from achillesapi.core.rc15_security import scan_rc15
    operations = {
        '/search': {'get': {'parameters': [
            {'in': 'query', 'name': f'param_{index}', 'schema': {'type': 'string'}}
            for index in range(15)], 'responses': {'200': {'description': 'ok'}}}},
        '/external/fetch': {'get': {'parameters': [
            {'in': 'query', 'name': 'target_url', 'schema': {'type': 'string'}}],
            'responses': {'200': {'description': 'ok'}}}},
    }
    spec = {'openapi': '3.0.3', 'info': {'title': 'RoundRobin', 'version': '1'}, 'paths': operations}
    result = scan_rc15(spec, base_url='http://127.0.0.1:8797',
        allowed_hosts={'127.0.0.1'}, execute=False, max_cases=3,
        callback_base='http://127.0.0.1:8788', callback_observer='http://127.0.0.1:8788',
        families=('sql_error', 'ssrf'), max_requests=10)
    assert len(result['cases']) == 3
    assert any(case['operation'] == 'GET /external/fetch' and case['family'] == 'ssrf'
               for case in result['cases'])
    assert result['requests_sent'] == 0
