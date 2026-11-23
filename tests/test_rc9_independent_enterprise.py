"""Independent enterprise-style OAS: no lab hardcoding, no target networking."""
from pathlib import Path
import json

import pytest
import yaml
from fastapi.testclient import TestClient

from achillesapi.core.openapi import load_openapi, parse_openapi
from achillesapi.core.multi_resource import plan_multi_resource
from achillesapi.core.injection_planner_v2 import injection_surface_plan
from achillesapi.core.campaign_rc9 import campaign_plan_rc9, verification_summary_rc9
from achillesapi.dashboard.manifest_builder import (
    discover_manifest_candidates, discover_write_operations, build_guided_manifest
)
from achillesapi.dashboard.server import create_app


def make_spec():
    success = {'200': {'description':'OK'}}
    removed = {'204': {'description':'removed'}}
    schema = lambda name: {'$ref':'#/components/schemas/'+name}
    response = lambda data: {'description':'OK','content':{'application/json':{'schema':data}}}
    body = lambda data: {'content':{'application/json':{'schema':data}}}
    string = {'type':'string'}
    tenant = [{'in':'path','name':'tenantId','required':True,'schema':string}]
    fields = lambda props: {'type':'object','properties':props}
    project_input = {**fields({'title':{'type':'string','maxLength':100},
                               'description':string, 'password':{'type':'string','writeOnly':True}}),
                     'required':['title']}
    project_create = fields({'data':fields({'id':string,'title':string})})
    project_read = fields({'data':fields({'projectId':string,'title':string})})
    document_input = {**fields({'description':string,'mimeType':string}),'required':['description']}
    return {
        'openapi':'3.0.3', 'info':{'title':'Helios Corporate API','version':'2026.11'},
        'servers':[{'url':'https://api.example.test/v1'}],
        'components':{'schemas':{
            'ProjectInput':project_input,'ProjectCreate':project_create,'ProjectRead':project_read}},
        'paths':{
            '/tenants/{tenantId}/projects':{
                'post':{'parameters':tenant, 'requestBody':body(schema('ProjectInput')),
                        'responses':{'201':response(schema('ProjectCreate'))}}},
            '/projects/{projectId}':{
                'get':{'responses':{'200':response(schema('ProjectRead'))}},
                'patch':{'requestBody':body(fields({'status':string})), 'responses':success},
                'delete':{'responses':removed}},
            '/tenants/{tenantId}/documents':{
                'post':{'parameters':tenant, 'requestBody':body(document_input),
                        'responses':{'201':{'description':'created','content':{'application/json':{
                            'schema':{},'example':{'payload':{'documentRef':'DOC-A'}}}}}}}},
            '/documents/{documentRef}':{
                'get':{'responses':{'200':response(fields({'documentRef':string,'description':string}))}},
                'delete':{'responses':removed}},
            '/batch/import':{'post':{'requestBody':body(fields({'name':string})),
                                     'responses':{'202':{'description':'accepted'}}}},
            '/reports/{reportId}':{'patch':{'responses':success},'delete':{'responses':removed}},
            '/search':{'get':{'parameters':[
                {'name':'q','in':'query','schema':string},
                {'name':'X-Search-Mode','in':'header','schema':string}], 'responses':success}},
        }
    }


SPEC = make_spec()


@pytest.fixture
def spec_path(tmp_path):
    path=tmp_path/'enterprise.json'
    path.write_text(json.dumps(SPEC),encoding='utf8')
    return path


def test_all_writes_are_listed_and_missing_cleanup_visible(spec_path):
    writes=discover_write_operations(str(spec_path))
    operations={x['operation'] for x in writes}
    assert len(operations)==8  # 3 POST, 2 PATCH, 3 DELETE
    assert 'POST /batch/import' in operations
    assert 'PATCH /reports/{reportId}' in operations
    cs=discover_manifest_candidates(str(spec_path))
    assert len(cs)==3
    assert {c['create'] for c in cs}=={'POST /tenants/{tenantId}/projects',
                                      'POST /tenants/{tenantId}/documents', 'POST /batch/import'}
    assert not next(x for x in cs if x['create']=='POST /batch/import')['ready']


def test_nested_id_schema_and_response_example_without_execution(spec_path):
    cs=discover_manifest_candidates(str(spec_path))
    proj=next(x for x in cs if x['create'].endswith('/projects'))
    assert proj['id_schema_pointers']==['/data/id']
    assert proj['read_id_candidates']==['/data/projectId']
    assert proj['read_marker_pointers']['title']==['/data/title']
    assert proj['required_path_params']==['tenantId']
    assert proj['mutation']=='PATCH /projects/{projectId}'
    doc=next(x for x in cs if x['create'].endswith('/documents'))
    assert doc['id_schema_pointers']==['/payload/documentRef']
    assert doc['ready']


def test_nested_guided_manifest_with_authorized_parent_and_mutation(spec_path):
    cs=discover_manifest_candidates(str(spec_path))
    proj=next(x for x in cs if x['create'].endswith('/projects'))
    manifest=build_guided_manifest(proj,owner='tenant_owner',other='auditor',
        marker='title',identifier='data/id',body={'title':'temporary-project'},
        deny_other=True,path_values={'tenantId':'test-tenant'},mutation_body={'status':'test'})
    obj=yaml.safe_load(manifest)
    item=obj['resources'][0]
    assert item['id_pointer']=='/data/id'
    assert item['read_id_pointer']=='/data/projectId'
    assert item['marker_pointer']=='/data/title'
    assert item['path_values']=={'tenantId':'test-tenant','projectId':'${resource.id}'}
    assert item['mutations']==[{'operation':'PATCH /projects/{projectId}','body':{'status':'test'}}]
    plan=plan_multi_resource(parse_openapi(load_openapi(spec_path)),load_openapi(spec_path),obj,
                             {'tenant_owner','auditor'})
    assert plan['request_budget_required']>=8
    with pytest.raises(ValueError, match='parametri path'):
        build_guided_manifest(proj,owner='tenant_owner',other=None,marker='title',
            identifier='data/id',body={'title':'hello'},deny_other=False,path_values={})


def test_plan_includes_json_xml_query_header_and_methods_without_http(spec_path):
    result=injection_surface_plan(load_openapi(spec_path))
    assert result['executed'] is False and result['requests_sent']==0
    methods=result['by_method']
    assert methods['GET']>0 and methods['POST']>0 and methods['PATCH']>0
    assert any(c['location']=='json_body' for c in result['cases'])
    assert any(c['location']=='header' for c in result['cases'])
    campaign=campaign_plan_rc9(load_openapi(spec_path))
    assert campaign['summary']['needs_prerequisites']>0
    assert campaign['summary']['injection_candidates']==result['planned_cases']
    assert verification_summary_rc9({'execution_report':{'findings':[
      {'category':'SQLI','operation':'GET /search'},
      {'category':'SQLI','operation':'GET /search'}]}})['deduplicated_groups']==1


def test_dashboard_discovery_returns_all_writes(spec_path,tmp_path):
    with TestClient(create_app(tmp_path/'dash'),base_url='http://127.0.0.1:8766') as client:
        token={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        with spec_path.open('rb') as file:
            r=client.post('/api/upload',files={'file':('helio.json',file,'application/json')},headers=token)
        assert r.status_code==200,r.text
        result=client.get('/api/control/manifest/candidates/'+r.json()['id'])
        assert result.status_code==200,result.text
        assert len(result.json()['write_operations'])==8
        assert len(result.json()['candidates'])==3


def test_guided_dashboard_nested_identifier_and_patch_end_to_end(spec_path,tmp_path):
    auth_yaml='profiles:\n  - name: tenant_owner\n    type: bearer\n    token_env: HELIOS_TEST_OWNER\n  - name: auditor\n    type: bearer\n    token_env: HELIOS_TEST_AUDITOR\n'
    with TestClient(create_app(tmp_path/'console'),base_url='http://127.0.0.1:8766') as client:
        headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        with spec_path.open('rb') as file:
            s=client.post('/api/upload',files={'file':('helios.json',file,'application/json')},headers=headers)
        assert s.status_code==200,s.text
        a=client.post('/api/import-text',json={'kind':'auth','name':'helios-auth.yaml','content':auth_yaml},headers=headers)
        assert a.status_code==200,a.text
        payload={
            'specification_id':s.json()['id'],'auth_config_id':a.json()['id'],
            'candidate_index':0,'identity':'tenant_owner','other_identity':'auditor',
            'deny_other':True,'marker':'title','identifier':'/data/id',
            'body':{'title':'temporary-project'},'path_values':{'tenantId':'tenant-test'},
            'mutation_body':{'status':'temporary'},
        }
        r=client.post('/api/control/manifest/guided',json=payload,headers=headers)
        assert r.status_code==200,r.text
        y=yaml.safe_load(r.json()['yaml'])
        assert y['resources'][0]['id_pointer']=='/data/id'
        assert y['resources'][0]['mutations'][0]['operation']=='PATCH /projects/{projectId}'
        payload['path_values']={}
        bad=client.post('/api/control/manifest/guided',json=payload,headers=headers)
        assert bad.status_code==422
        assert 'path' in bad.json()['detail']
