"""XML scalar coverage is derived from the Swagger, never from lab names."""
from achillesapi.core.rc15_security import discover, relevant
from achillesapi.core.scanner_coverage_rc22 import scanner_plan

SPEC={
 'openapi':'3.0.3','info':{'title':'XML test','version':'1'},
 'paths':{'/import':{'post':{'requestBody':{'content':{'application/xml':{'schema':{
  'type':'object','properties':{'callbackUrl':{'type':'string'},
    'filename':{'type':'string'},'value':{'type':'string'}}}}}},
  'responses':{'200':{'description':'ok'}}}}}}


def test_xml_scalar_ssrf_path_discovery_requires_fixture():
    points=discover(SPEC)
    assert any(p.location=='xml_field' and p.name=='callbackUrl' and relevant(p,'ssrf') for p in points)
    assert any(p.location=='xml_field' and p.name=='filename' and relevant(p,'path_traversal') for p in points)
    assert not any(p.location=='xml_field' and relevant(p,'xxe') for p in points)
    result=scanner_plan(SPEC, approved_http=True,approved_writes=False)
    assert any(x['location']=='xml_field' and 'ssrf' in x['families'] for x in result['tests'])
    assert all(x['state']=='blocked' for x in result['tests'])
