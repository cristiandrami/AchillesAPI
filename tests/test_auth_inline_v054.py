from __future__ import annotations
import base64
import json
from pathlib import Path

import pytest
from achillesapi.core.auth import AuthenticationManager, AuthenticationConfigError


def config(tmp_path, yaml_text):
    f = tmp_path / 'auth.yaml'
    f.write_text(yaml_text, encoding='utf-8')
    return AuthenticationManager.from_file(f)


def test_inline_bearer_without_env(tmp_path, monkeypatch):
    monkeypatch.delenv('ACHILLES_LAB_OTHER', raising=False)
    manager = config(tmp_path, 'profiles:\n - name: other\n   type: bearer\n   token: demo-other\n')
    assert manager.resolve('other').headers['Authorization'] == 'Bearer demo-other'
    assert 'demo-other' not in repr(manager)
    assert 'demo-other' not in repr(manager._profiles['other'])
    assert 'demo-other' not in json.dumps(manager.describe())
    assert manager.describe()[0]['environment_variables'] == []


def test_inline_basic(tmp_path):
    m=config(tmp_path,'profiles:\n - name: user\n   type: basic\n   username: sample\n   password: letmein\n')
    assert m.resolve('user').headers['Authorization']=='Basic '+base64.b64encode(b'sample:letmein').decode()


@pytest.mark.parametrize('location,material', [('header','headers'),('query','params'),('cookie','cookies')])
def test_inline_apikey(tmp_path, location, material):
    m=config(tmp_path,f'profiles:\n - name: api\n   type: api_key\n   location: {location}\n   parameter_name: X-API-Key\n   value: abc\n')
    assert getattr(m.resolve('api'),material)['X-API-Key']=='abc'


def test_both_sources_rejected_without_leaking_secret(tmp_path):
    with pytest.raises(AuthenticationConfigError) as exc:
        config(tmp_path, 'profiles:\n - name: other\n   type: bearer\n   token: SHHH_SUPER_SECRET\n   token_env: TOKEN_VAR\n')
    assert 'SHHH_SUPER_SECRET' not in str(exc.value)


def test_inline_login_json_config(tmp_path):
    m=config(tmp_path, 'profiles:\n - name: user\n   type: login_json\n   login_url: https://api.example.test/login\n   username: alice\n   password: pass123\n')
    p=m._profiles['user']
    assert p.username=='alice' and p.password=='pass123'
    assert 'pass123' not in repr(p)


def test_inline_oauth_config(tmp_path):
    m=config(tmp_path,'profiles:\n - name: machine\n   type: oauth2_client_credentials\n   token_url: https://api.example.test/oauth/token\n   client_id: demo-client\n   client_secret: demo-secret\n')
    assert m.names==['machine']
    assert 'demo-secret' not in json.dumps(m.describe())


def test_upload_does_not_echo_secret(tmp_path):
    from fastapi.testclient import TestClient
    from achillesapi.dashboard.server import create_app
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8766') as client:
        token=client.get('/api/bootstrap').json()['csrf_token']
        content='profiles:\n  - name: other\n    type: bearer\n    token: SUPERPRIVATE\n'
        resp=client.post('/api/auth-config',files={'file':('auth.yaml',content,'application/x-yaml')},headers={'x-achilles-token':token})
        assert resp.status_code==200,resp.text
        assert 'SUPERPRIVATE' not in resp.text
        assert resp.json()['descriptions'][0]['environment_variables']==[]
        bad=content.replace('type: bearer','type: nonexistent')
        resp=client.post('/api/import-text',json={'kind':'auth','content':bad},headers={'x-achilles-token':token})
        assert resp.status_code==422
        assert 'SUPERPRIVATE' not in resp.text
