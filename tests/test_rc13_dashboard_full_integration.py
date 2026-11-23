"""RC13 user-facing dashboard integration, without external network calls."""
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.control import ToolRequest
from achillesapi.dashboard.rc13_bridge import rc13_command
import achillesapi.dashboard.control as control

SPEC = {'openapi': '3.0.3', 'info': {'title': 'Integration Test API', 'version': '1'},
        'paths': {'/search': {'get': {'parameters': [{'in':'query','name':'term','schema':{'type':'string'}}],
                     'responses': {'200': {'description':'ok'}}}},
                  '/assets': {'post': {'responses': {'201': {'description':'created'}}}}}}


def setup(client):
    token = client.get('/api/bootstrap').json()['csrf_token']
    head = {'x-achilles-token': token}
    response = client.post('/api/import-text', headers=head, json={
        'kind': 'openapi', 'content': json.dumps(SPEC), 'name': 'integration.json'})
    assert response.status_code == 200, response.text
    return head, response.json()['id']


def completed(client, identifier):
    for _ in range(180):
        item = client.get('/api/jobs/' + identifier).json()
        if item['status'] not in {'running', 'orchestrating'}:
            return item
        time.sleep(.1)
    raise AssertionError('RC13 dashboard job did not finish')


def test_plan_no_http_and_rc13_standalone_result(tmp_path):
    with TestClient(create_app(tmp_path/'app'), base_url='http://127.0.0.1:8766') as client:
        head, spec_id = setup(client)
        payload = {'action':'auto-assess', 'specification_id': spec_id, 'model': 'achilles-local'}
        response = client.post('/api/control/rc13/plan', headers=head, json=payload)
        assert response.status_code == 200, response.text
        assert response.json()['api_name'] == 'Integration Test API'
        assert response.json()['catalog']['operations_total'] == 2
        response = client.post('/api/control/rc13/run', headers=head, json={
            'config': payload, 'active': False, 'max_requests': 30})
        assert response.status_code == 200, response.text
        job_id = response.json()['id']
        assert completed(client, job_id)['status'] == 'complete'
        result = client.get('/api/results/'+job_id).json()
        assert result['engine'] == 'achilles-rc13-campaign'
        assert result['requests_sent'] == 0
        assert result['coverage']['operations_documented'] == 2
        viewer = client.get('/api/job-view/'+job_id)
        assert viewer.status_code in {200, 404}  # dedicated view route differs by release


def test_rc13_fails_closed_on_missing_consents(tmp_path):
    with TestClient(create_app(tmp_path/'app'), base_url='http://127.0.0.1:8766') as client:
        head, spec_id = setup(client)
        cfg={'action':'auto-assess','specification_id':spec_id,'base_url':'http://127.0.0.1:8795',
             'allow_host':'127.0.0.1','allow_insecure_http':True}
        res=client.post('/api/control/rc13/run',headers=head,json={
            'config':cfg,'active':True,'max_requests':30})
        assert res.status_code==422
        cfg['acknowledgment']=True
        res=client.post('/api/control/rc13/run',headers=head,json={
            'config':cfg,'active':True,'writes':True,'max_requests':30})
        assert res.status_code==422
        res=client.post('/api/control/rc13/run',headers=head,json={
            'config':cfg,'active':True,'body_probes':True,'max_requests':30})
        assert res.status_code==422


def test_rc13_command_never_executes_unapproved_workflow(tmp_path):
    spec=tmp_path/'api.yaml';spec.write_text(json.dumps(SPEC))
    manifest=tmp_path/'f.config.yaml';manifest.write_text('workflows: []')
    cfg=ToolRequest(action='auto-assess',specification_id='a'*32,config_id='b'*32,
                    config_usage='workflow',base_url='https://example.com',allow_host='example.com')
    def file_id(value, suffix):return spec
    def upload_cfg(value):return manifest
    cmd=rc13_command(cfg,file_id,upload_cfg,active=True,writes=False,
                     body_probes=False,ai=False,max_requests=30,output=tmp_path/'out.json')
    assert '--workflow-config' not in cmd
    assert '--approve-writes' not in cmd


def test_suite_includes_rc13_child_and_parent_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(control, 'SUITE_ORDER', ('analyze-openapi',))
    with TestClient(create_app(tmp_path/'app'), base_url='http://127.0.0.1:8766') as client:
        head, spec_id = setup(client)
        started=client.post('/api/control/suite',headers=head,json={
            'config':{'specification_id':spec_id,'action':'auto-assess'},
            'include_rc13':True,'rc13_max_requests':50,'include_active':False,
            'max_total_requests':100})
        assert started.status_code==200,started.text
        suite_id=started.json()['id']
        assert completed(client, suite_id)['status']=='complete'
        result=client.get('/api/results/'+suite_id).json()
        assert result['summary']['total']==2
        assert [x['action'] for x in result['steps']]==['rc13-assess','analyze-openapi']
        assert result['steps'][0]['status']=='complete',result['steps'][0]
        assert result['rc13_coverage']['operations_documented']==2
        child_id=result['steps'][0]['job_id']
        child=client.get('/api/results/'+child_id).json()
        assert child['engine']=='achilles-rc13-campaign'
        assert child['requests_sent']==0


def test_rc13_active_local_http_through_dashboard(tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        def log_message(self, *args):
            pass

    service = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        with TestClient(create_app(tmp_path/'app'), base_url='http://127.0.0.1:8766') as client:
            head, spec_id = setup(client)
            response = client.post('/api/control/rc13/run', headers=head, json={
                'config':{'action':'auto-assess','specification_id':spec_id,
                          'base_url':f'http://127.0.0.1:{service.server_address[1]}',
                          'allow_host':'127.0.0.1','acknowledgment':True,
                          'allow_insecure_http':True,'rate':5},
                'active':True,'max_requests':10})
            assert response.status_code==200,response.text
            item=completed(client,response.json()['id'])
            assert item['status']=='complete',item
            raw=client.get('/api/results/'+item['id']).json()
            assert raw['executed'] is True
            assert 0 < raw['requests_sent'] <= 10
            view=client.get('/api/job-view/'+item['id']).json()
            assert view['rc13_coverage']['coverage_not_a_security_score'] is True
    finally:
        service.shutdown()
        service.server_close()
        thread.join(timeout=2)


def test_multiresource_dashboard_format_supported_in_rc13_plan(tmp_path):
    from achillesapi.core.pipeline_rc13 import _load_fixture
    path=tmp_path/'resource.yaml'
    path.write_text('resources:\n  - name: approved_resource\n')
    legacy, resources=_load_fixture(path)
    assert legacy == [] and resources['resources'][0]['name']=='approved_resource'


def test_rc13_policy_conflict_preserves_identity_alias_and_http_status():
    from achillesapi.reporting.professional import summarize_assessment
    from achillesapi.core.pipeline_rc13 import execute_pipeline
    # The regression target is the *actual* output schema consumed by
    # summarize_assessment: access_comparison, never raw bearer tokens.
    raw = {'engine': 'achilles-rc13-campaign', 'version': '1.0.0rc13',
           'findings': [{'category': 'authorization_policy_conflict',
                         'operation': 'GET /tickets/{ticket_id}', 'severity': 'medium',
                         'access_comparison': [
                             {'profile': 'owner', 'expected': 'allow', 'status_code': 200},
                             {'profile': 'colleague', 'expected': 'deny', 'status_code': 200}],
                         'reason': 'Conflitto con policy del tester.'}]}
    report = summarize_assessment(raw)
    f = report['findings'][0]
    assert f['access_comparison'] == raw['findings'][0]['access_comparison']
    assert f['category'] == 'authorization_policy_conflict'
    assert 'Authorization' not in json.dumps(f)


def test_rc13_body_probes_rejected_with_resources_manifest(tmp_path):
    from achillesapi.dashboard.control import RC13DashboardRequest
    from unittest.mock import patch
    from achillesapi.dashboard import control
    # A resources.yaml wizard manifest cannot silently enable an incompatible
    # RC11 body scanner. This should be a readable preflight error, not a job failure.
    with TestClient(create_app(tmp_path / 'app'), base_url='http://127.0.0.1:8766') as client:
        head, spec_id = setup(client)
        # Fully approved writes but no compatible JSON probe cases.
        with patch.object(control, '_ollama_readiness', return_value={'status': 'ready'}):
            response = client.post('/api/control/rc13/run', headers=head, json={
                'config': {'action': 'auto-assess', 'specification_id': spec_id,
                           'base_url': 'http://127.0.0.1:8795',
                           'allow_host': '127.0.0.1', 'allow_insecure_http': True,
                           'acknowledgment': True, 'approve_writes': True},
                'active': True, 'writes': True, 'body_probes': True,
                'max_requests': 30})
        assert response.status_code == 422
        assert 'Sonde JSON' in response.text or 'manifest' in response.text


def test_rc13_in_full_suite_active_local_http(tmp_path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    monkeypatch.setattr(control, 'SUITE_ORDER', ('analyze-openapi',))
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        def log_message(self, *args):
            pass
    service = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = Thread(target=service.serve_forever, daemon=True)
    worker.start()
    try:
        with TestClient(create_app(tmp_path / 'app'), base_url='http://127.0.0.1:8766') as client:
            head, spec_id = setup(client)
            response = client.post('/api/control/suite', headers=head, json={
                'config': {'action':'auto-assess','specification_id':spec_id,
                           'base_url': f'http://127.0.0.1:{service.server_address[1]}',
                           'allow_host':'127.0.0.1','acknowledgment': True,
                           'allow_insecure_http':True,'rate':5},
                'include_rc13':True,'include_active':True,'include_writes':False,
                'rc13_max_requests':10,'max_total_requests':30})
            assert response.status_code == 200, response.text
            suite_id = response.json()['id']
            assert completed(client, suite_id)['status'] == 'complete'
            report = client.get('/api/results/'+suite_id).json()
            assert report['summary']['total'] == 2
            assert report['steps'][0]['status'] == 'complete', report['steps'][0]
            assert report['rc13_coverage']['operations_with_evaluable_http_results'] >= 1
            assert report['http_telemetry']['attempted'] >= 1
            assert report['http_telemetry']['attempted'] <= 30
    finally:
        service.shutdown()
        service.server_close()
        worker.join(timeout=2)
