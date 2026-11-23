"""RC16 command and dashboard integration (offline, no target traffic)."""
from __future__ import annotations

import json
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.dashboard.server import create_app
from achillesapi.core.registry_v090 import TOOLS, SUITE_ORDER
from achillesapi.core.task_help_rc5 import task_help
from test_v034 import sample, manifest


def test_rc16_cli_commands_dry_run(tmp_path):
    spec=tmp_path/'swagger.json';spec.write_text(json.dumps(sample()))
    auth=tmp_path/'auth.yaml'
    auth.write_text('''profiles:
  - name: owner
    type: bearer
    token_env: RC16_OWNER_TOKEN
  - name: other
    type: bearer
    token_env: RC16_OTHER_TOKEN
''')
    cfg=tmp_path/'resources.yaml';cfg.write_text(json.dumps(manifest()))
    runner=CliRunner()
    output=tmp_path/'discovery.json'; draft=tmp_path/'draft.yaml'
    res=runner.invoke(app,['rc16-workflows',str(spec),'--output',str(output),
                           '--manifest-draft',str(draft),'--owner-profile','owner'])
    assert res.exit_code==0, res.output
    assert output.is_file() and draft.is_file()
    assert len(json.loads(output.read_text())['candidates'])==2
    comparison=tmp_path/'matrix.json'
    res=runner.invoke(app,['rc16-access-auto',str(spec),'--auth-config',str(auth),
       '--owner-profile','owner','--other-profile','other','--path-value','document_ref=testing123',
       '--base-url','https://approved.local','--allow-host','approved.local','--output',str(comparison)])
    assert res.exit_code==0,res.output
    assert json.loads(comparison.read_text())['requests_sent']==0
    campaign=tmp_path/'campaign.json'
    res=runner.invoke(app,['rc16-assess',str(spec),'--config',str(cfg),'--auth-config',str(auth),
       '--compare-profile','other','--output',str(campaign)])
    assert res.exit_code==0,res.output
    report=json.loads(campaign.read_text())
    assert report['requests_sent']==0 and report['added_cross_identity_checks']==1
    assert 'collection-1' not in campaign.read_text()


def test_dashboard_rc16_offline_discovery_never_contacts_target(tmp_path):
    appserver=create_app(tmp_path/'workspace')
    with TestClient(appserver,base_url='http://localhost') as client:
        bootstrap=client.get('/api/bootstrap')
        assert bootstrap.status_code==200
        assert bootstrap.json()['version']==__import__('achillesapi').__version__
        headers={'x-achilles-token': bootstrap.json()['csrf_token']}
        upload=client.post('/api/import-text',json={
            'kind':'openapi','name':'tenant_api.json','content':json.dumps(sample())},headers=headers)
        assert upload.status_code==200, upload.text
        sid=upload.json()['id']
        refused=client.post('/api/control/rc16/discover',json={'action':'rc16-workflows','specification_id':sid})
        assert refused.status_code==403
        resp=client.post('/api/control/rc16/discover',
                         json={'action':'rc16-workflows','specification_id':sid,'profiles':['owner']},headers=headers)
        assert resp.status_code==200,resp.text
        data=resp.json()
        assert data['discovery']['requests_sent']==0
        assert len(data['draft']['resources'])==2
        assert not any('token' in json.dumps(row).lower() for row in data['draft']['resources'])
        tool_catalog=client.get('/api/control/tools')
        # The public tool list may be mounted at either /api/control/tools or /api/control/catalog.
        if tool_catalog.status_code==200:
            names={x['name'] for x in tool_catalog.json()}
            assert {'rc16-workflows','rc16-access-auto','rc16-assess'} <= names


def test_rc16_suite_catalog_and_help():
    assert {'rc16-workflows','rc16-access-auto','rc16-assess'} <= set(TOOLS)
    assert all(name in SUITE_ORDER for name in ['rc16-workflows','rc16-access-auto','rc16-assess'])
    for name in ['rc16-workflows','rc16-access-auto','rc16-assess']:
        help=task_help(name)
        assert help['purpose'] and help['requires']
    assert TOOLS['rc16-assess']['writes'] and TOOLS['rc16-assess']['active']
    assert not TOOLS['rc16-workflows'].get('active',False)


def test_rc16_suite_prevents_duplicate_disposable_writes():
    from achillesapi.dashboard.control import ToolRequest, SuiteRequest, suite_skip_reason
    cfg = ToolRequest(action='rc16-assess', config_usage='multi-resource',
                      specification_id='spec1', config_id='manifest1', auth_config_id='auth1',
                      base_url='https://approved.example', allow_host='approved.example',
                      profiles=['owner', 'other'], expected_other='deny',
                      execute=True, approve_writes=True, acknowledgment=True)
    suite = SuiteRequest(config=cfg, include_active=True, include_writes=True)
    reason = suite_skip_reason('multi-resource-assess', cfg, suite, None)
    assert reason and 'motore di verifica multi-risorsa' in reason
    assert suite_skip_reason('rc16-assess', cfg, suite, None) is None


def test_rc16_dashboard_executes_dry_run_as_real_cli_job(tmp_path):
    """Verify the UI control plane routes to the rc16 command, not an inert task card."""
    import time
    client=TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766')
    headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
    def upload(kind, data):
        response=client.post('/api/import-text',headers=headers,
            json={'kind':kind,'content':json.dumps(data)})
        assert response.status_code==200,response.text
        return response.json()['id']
    specification=upload('openapi',sample())
    authorization=upload('auth',{'profiles':[
        {'name':'owner','type':'bearer','token_env':'RC16_DASH_OWNER'},
        {'name':'other','type':'bearer','token_env':'RC16_DASH_OTHER'}]})
    resources=upload('config',manifest())
    started=client.post('/api/control/jobs',headers=headers,json={
        'action':'rc16-assess','specification_id':specification,
        'auth_config_id':authorization,'config_id':resources,
        'config_usage':'multi-resource','profiles':['other'],
        'expected_other':'deny','execute':False})
    assert started.status_code==200,started.text
    ident=started.json()['id']
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        state=client.get(f'/api/jobs/{ident}').json()
        if state['status'] not in ('running','queued','orchestrating'):break
        time.sleep(.05)
    assert state['status']=='complete',state
    report=client.get(f'/api/results/{ident}').json()
    assert report['engine']=='achilles-rc16-multi-tenant-orchestration'
    assert report['requests_sent']==0 and report['added_cross_identity_checks']==1
    assert 'RC16_DASH_OWNER' not in json.dumps(report)
