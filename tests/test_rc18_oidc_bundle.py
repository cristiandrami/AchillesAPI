"""RC18: real offline JWT verification and safe multi-file dashboard imports."""
from __future__ import annotations
import io
import json
import os
import time
import zipfile
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.oidc_enterprise_rc18 import (
    OIDCSafetyError, audit_metadata, audit_jwks, fetch_approved_json, full_oidc_audit,
    verify_access_token,
)
from achillesapi.core.openapi_bundle_rc18 import import_zip_bundle, OpenAPIBundleError
from achillesapi.core.openapi import load_openapi
from achillesapi.dashboard.server import create_app
from achillesapi.core.registry_v090 import TOOLS, SUITE_ORDER

SPEC = {
    'openapi':'3.0.3', 'info':{'title':'rc18 lab','version':'1'},
    'paths':{'/private':{'get':{'security':[{'oidc':['orders.read']}],
                               'responses':{'200':{'description':'ok'}}}}},
    'components':{'securitySchemes':{'oidc':{'type':'oauth2','flows':{'authorizationCode':{
        'authorizationUrl':'https://idp.example.org/authorize',
        'tokenUrl':'https://idp.example.org/token', 'scopes':{'orders.read':'read'}}}}}},
}


def zip_bytes(entries: dict[str, str | bytes], symlink: str | None = None):
    buff = io.BytesIO()
    with zipfile.ZipFile(buff,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,data in entries.items():
            archive.writestr(name,data)
        if symlink:
            info=zipfile.ZipInfo(symlink)
            info.create_system=3
            info.external_attr=(0o120777<<16)
            archive.writestr(info,'target.yaml')
    return buff.getvalue()


def bundled_parts():
    return zip_bytes({
        'apis/main.yaml': '''openapi: 3.0.3\ninfo: {title: Bundle Demo, version: '1'}\npaths:\n  /items:\n    get:\n      parameters:\n        - $ref: ../common/params.yaml#/components/parameters/Tenant\n      responses: {'200': {description: OK}}\n''',
        'common/params.yaml': '''components:\n  parameters:\n    Tenant:\n      name: tenant\n      in: query\n      schema: {type: string}\n''',
    })


def test_multi_file_zip_resolves_references_without_network(tmp_path):
    dest=tmp_path/'bundled.yaml'
    details=import_zip_bundle(bundled_parts(),dest)
    assert details['root']=='apis/main.yaml'
    assert details['file_count']==2
    spec=load_openapi(dest)
    assert spec['paths']['/items']['get']['parameters'][0]['name']=='tenant'
    assert details['network_requests']==0


@pytest.mark.parametrize('name',["../outside.yaml",'/abs.yaml', 'a\\oops.yaml', 'a/../escape.yaml'])
def test_zip_traversal_rejected(tmp_path,name):
    archive=zip_bytes({'openapi.yaml':json.dumps(SPEC),name:'openapi: 3.0.3'})
    with pytest.raises(OpenAPIBundleError):
        import_zip_bundle(archive,tmp_path/'out.yaml')
    assert not (tmp_path/'out.yaml').exists()


def test_symlink_zip_rejected(tmp_path):
    with pytest.raises(OpenAPIBundleError):
        import_zip_bundle(zip_bytes({'openapi.yaml':json.dumps(SPEC)},symlink='bad.yaml'),tmp_path/'x.yaml')


def test_multiple_roots_require_explicit_selection(tmp_path):
    raw=zip_bytes({'one.yaml':json.dumps(SPEC),'two.yaml':json.dumps(SPEC)})
    with pytest.raises(OpenAPIBundleError, match='root_name'):
        import_zip_bundle(raw,tmp_path/'x.yaml')
    details=import_zip_bundle(raw,tmp_path/'chosen.yaml',root_name='one.yaml')
    assert details['root']=='one.yaml'


def test_jwks_duplicate_key_private_material_and_rotation():
    out=audit_jwks({'keys':[{'kid':'same','kty':'RSA','n':'nope','e':'AQAB'},
                              {'kid':'same','kty':'RSA','d':'PRIVATE'}]},
                   old_jwks={'keys':[{'kid':'old','kty':'RSA'}]})
    assert {f['code'] for f in out['findings']} >= {'JWKS_DUPLICATE_KID','JWKS_PRIVATE_MATERIAL'}
    assert out['rotation']=={'added_count':1,'removed_count':1}
    assert 'same' not in json.dumps(out)


def test_oidc_metadata_pin_pkce_and_unsigned():
    result=audit_metadata({'issuer':'https://attacker.example','id_token_signing_alg_values_supported':['none']},
                          expected_issuer='https://idp.example.org')
    assert {'OIDC_ISSUER_MISMATCH','OIDC_UNSIGNED_ID_TOKEN','OIDC_PKCE_S256_UNDECLARED'} <= {x['code'] for x in result['findings']}


def test_oauth_scope_and_implicit_audit():
    spec=json.loads(json.dumps(SPEC))
    spec['components']['securitySchemes']['oidc']['flows']['implicit']={
        'authorizationUrl':'http://example.org/a','scopes':{}}
    spec['paths']['/private']['get']['security']=[{'oidc':['not-declared']}]
    result=full_oidc_audit(spec)
    codes={x['code'] for x in result['oauth']['findings']}
    assert {'OAUTH_UNDECLARED_SCOPE','OAUTH_IMPLICIT_FLOW','OAUTH_ENDPOINT_HTTP'}<=codes


def rsa_jwt():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pub=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    pub['kid']='rotation-kid'
    pub['alg']='RS256'
    claims={'iss':'https://idp.example.org','aud':'achilles-test', 'exp':int(time.time())+180,'iat':int(time.time()),'sub':'PRIVATE_SUBJECT'}
    token=jwt.encode(claims,key,algorithm='RS256',headers={'kid':'rotation-kid'})
    return token, {'keys':[pub]}


def test_real_jwt_signature_audience_expiry_and_secret_redaction(monkeypatch):
    token,jwks=rsa_jwt()
    valid=verify_access_token(token,jwks,expected_issuer='https://idp.example.org',expected_audience='achilles-test')
    assert valid['status']=='verified'
    assert 'PRIVATE_SUBJECT' not in str(valid) and token not in str(valid)
    assert verify_access_token(token,jwks,expected_issuer='https://idp.example.org',expected_audience='wrong')['status']=='rejected'
    assert verify_access_token(token,jwks,expected_issuer='https://wrong.example',expected_audience='achilles-test')['status']=='rejected'
    tampered=token[:-3] + 'abc'
    assert verify_access_token(tampered,jwks,expected_issuer='https://idp.example.org',expected_audience='achilles-test')['status']=='rejected'
    monkeypatch.setenv('RC18_TEST_TOKEN',token)
    report=full_oidc_audit(SPEC, jwks=jwks, token_env='RC18_TEST_TOKEN',
                           expected_issuer='https://idp.example.org',expected_audience='achilles-test')
    assert report['jwt']['status']=='verified'
    assert token not in json.dumps(report)
    assert 'PRIVATE_SUBJECT' not in json.dumps(report)


def test_jwt_alg_none_rejected():
    token=jwt.encode({'iss':'https://idp.example.org','aud':'a','exp':int(time.time())+300},key='',algorithm='none',headers={'kid':'x'})
    assert verify_access_token(token,{'keys':[{'kid':'x','kty':'oct','k':'abc'}]},expected_issuer='https://idp.example.org',expected_audience='a')['status']=='rejected'


def test_discovery_fails_closed_before_network():
    for url, hosts in [('https://outside.invalid/.well-known/openid-configuration',{'inside.invalid'}),
                       ('http://inside.invalid/.well-known/openid-configuration',{'inside.invalid'}),
                       ('https://u:p@inside.invalid/x',{'inside.invalid'})]:
        with pytest.raises(OIDCSafetyError):
            fetch_approved_json(url,allowed_hosts=hosts)


def test_cli_offline_oidc_and_zip(tmp_path):
    source=tmp_path/'spec.yaml'
    source.write_text(json.dumps(SPEC))
    output=tmp_path/'report.json'
    runner=CliRunner()
    result=runner.invoke(app,['rc18-oidc-audit',str(source),'--output',str(output)])
    assert result.exit_code==0,result.output
    assert json.loads(output.read_text())['network_requests']==0
    bad=runner.invoke(app,['rc18-oidc-audit',str(source), '--discovery-url', 'https://evil.invalid/x'])
    assert bad.exit_code!=0
    zipped=tmp_path/'openapi.zip';zipped.write_bytes(bundled_parts())
    bundled=tmp_path/'bundled.yaml'
    result=runner.invoke(app,['rc18-openapi-bundle',str(zipped),'--output',str(bundled)])
    assert result.exit_code==0,result.output
    assert load_openapi(bundled)['info']['title']=='Bundle Demo'


def test_dashboard_zip_upload_oidc_panel_and_suite(tmp_path):
    client=TestClient(create_app(tmp_path), base_url='http://127.0.0.1:8000')
    bootstrap=client.get('/api/bootstrap').json()
    assert bootstrap['version']==__import__('achillesapi').__version__
    token=bootstrap['csrf_token']
    body=bundled_parts()
    resp=client.post('/api/upload', files={'file':('bundle.zip',body,'application/zip')},headers={'x-achilles-token':token})
    assert resp.status_code==200,resp.text
    data=resp.json()
    assert data['bundle'] is True and data['operations']==1
    source=client.get('/api/summary/'+data['id'])
    assert source.status_code==200
    audit=client.post('/api/rc18/oidc-audit',json={'specification_id':data['id']},headers={'x-achilles-token':token})
    assert audit.status_code==200
    assert audit.json()['network_requests']==0
    invalid=client.post('/api/rc18/oidc-audit',json={'specification_id':data['id'],'token':'secret'},headers={'x-achilles-token':token})
    assert invalid.status_code==400
    assert client.post('/api/rc18/oidc-audit',json={'specification_id':data['id']}).status_code==403
    assert 'rc18-oidc-audit' in SUITE_ORDER and 'rc18-oidc-audit' in TOOLS
    html=Path('src/achillesapi/dashboard/static/index.html').read_text()
    js=Path('src/achillesapi/dashboard/static/app.js').read_text()
    assert 'rc18OidcRun' in html and 'rc18OidcRun' in js and '.zip' in html


def test_auth_profile_local_jwks_enforces_real_token_signature(tmp_path):
    from achillesapi.core.auth import AuthenticationManager, AuthenticationConfigError
    token, jwks = rsa_jwt()
    config = tmp_path/'auth.yaml'
    jwks_path=tmp_path/'jwks.json'
    jwks_path.write_text(json.dumps(jwks))
    config.write_text('''profiles:\n  - name: owner\n    type: bearer\n    token_env: RC18_PROFILE_TOKEN\n    oidc_issuer: https://idp.example.org\n    oidc_audience: achilles-test\n    oidc_jwks_file: jwks.json\n''')
    os.environ['RC18_PROFILE_TOKEN']=token
    try:
        manager=AuthenticationManager.from_file(config)
        assert manager.resolve('owner').headers['Authorization'] == 'Bearer '+token
        config.write_text(config.read_text().replace('achilles-test','wrong-audience'))
        with pytest.raises(AuthenticationConfigError,match='validation failed'):
            AuthenticationManager.from_file(config).resolve('owner')
        config.write_text(config.read_text().replace('wrong-audience','achilles-test').replace('jwks.json','../outside.json'))
        with pytest.raises(AuthenticationConfigError, match='local'):
            AuthenticationManager.from_file(config).resolve('owner')
    finally:
        os.environ.pop('RC18_PROFILE_TOKEN',None)


def test_real_discovery_http_local_and_rejected_redirect(tmp_path):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=='/redirect':
                self.send_response(302)
                self.send_header('Location','https://evil.invalid')
                self.end_headers()
            else:
                payload=b'{"issuer":"http://127.0.0.1", "jwks_uri":"http://127.0.0.1/keys"}'
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.end_headers()
                self.wfile.write(payload)
        def log_message(self, *args):pass
    with ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
        port=server.server_address[1]
        worker=threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        try:
            result=fetch_approved_json(f'http://127.0.0.1:{port}/.well-known/openid-configuration',
                                       allowed_hosts={'127.0.0.1'},allow_insecure_http=True)
            assert result['issuer'].startswith('http://')
            with pytest.raises(OIDCSafetyError, match='HTTP 302'):
                fetch_approved_json(f'http://127.0.0.1:{port}/redirect',
                                    allowed_hosts={'127.0.0.1'},allow_insecure_http=True)
        finally:
            server.shutdown();worker.join(timeout=3)


def test_rc18_scopes_and_untrusted_jose_headers_are_rejected():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({'kid':'scope-key','alg':'RS256'})
    base={'iss':'https://idp.example.org','aud':'achilles-test','exp':int(time.time())+120,
          'scope':'orders.read billing.read'}
    token=jwt.encode(base,key,algorithm='RS256',headers={'kid':'scope-key'})
    assert verify_access_token(token,{'keys':[jwk]},expected_issuer='https://idp.example.org',
                               expected_audience='achilles-test',required_scopes=('orders.read',))['status']=='verified'
    assert verify_access_token(token,{'keys':[jwk]},expected_issuer='https://idp.example.org',
                               expected_audience='achilles-test',required_scopes=('admin',))['reason']=='scope_mismatch'
    bad=jwt.encode(base,key,algorithm='RS256',headers={'kid':'scope-key','jku':'https://evil.invalid/jwks'})
    assert verify_access_token(bad,{'keys':[jwk]},expected_issuer='https://idp.example.org',
                               expected_audience='achilles-test')['reason']=='untrusted_or_critical_header'


def test_weak_rsa_public_key_flagged_without_leaking_jwk():
    key=rsa.generate_private_key(public_exponent=65537,key_size=1024)
    public=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public['kid']='weak-public-key'
    out=audit_jwks({'keys':[public]})
    assert 'JWKS_WEAK_RSA' in {x['code'] for x in out['findings']}
    assert 'weak-public-key' not in json.dumps(out)
