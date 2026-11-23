"""Semantic regressions for full-suite coverage transparency and human labels."""
from __future__ import annotations

import json
from pathlib import Path
from achillesapi.core.suite_write_coverage import write_inventory, update_write_execution


def test_inventory_distinguishes_documented_and_approved_and_executed():
    spec={'paths':{
       '/v1/items':{'post':{}},
       '/v1/items/{id}':{'get':{},'patch':{},'delete':{}},
       '/v1/admin/config':{'post':{}},
       '/v1/documents/xml-import':{'post':{}},
    }}
    approved={'manifest-A':{'resources':[
        {'name':'items','create':'POST /v1/items','read':'GET /v1/items/{id}',
         'delete':'DELETE /v1/items/{id}',
         'mutations':[{'operation':'PATCH /v1/items/{id}','body':{'status':'test'}}],
         'write_checks':[]}]}}
    result=write_inventory(spec,approved)
    assert result['documented_write_operations']==5
    assert result['with_approved_fixture']==3
    assert result['without_approved_fixture']==2
    assert result['executed_write_operations']==0
    assert {x['operation'] for x in result['operations'] if x['state']=='not_tested_no_approved_fixture'}=={
        'POST /v1/admin/config','POST /v1/documents/xml-import'}
    update_write_execution(result,[{'action':'rc16-assess','workflow_config_id':'manifest-A','status':'failed'}])
    assert result['executed_write_operations']==0
    update_write_execution(result,[{'action':'rc16-assess','workflow_config_id':'manifest-A','status':'complete'}])
    assert result['executed_write_operations']==3
    assert result['without_approved_fixture']==2


def test_pending_unreviewed_post_is_not_a_workflow_in_browser():
    root=Path(__file__).resolve().parents[1]/'src/achillesapi/dashboard/static'
    app=(root/'app.js').read_text()
    issue=(root/'issue-guide.js').read_text()
    html=(root/'index.html').read_text()
    assert 'candidate.ready && candidate.create && candidate.read && candidate.delete' in app
    assert "'Operazioni di scrittura senza cleanup sicuro'" in app
    assert "'autoconfigPanel','information'" in app
    assert "entry.kind==='information'?'LIMITAZIONE DEL TEST'" in issue
    assert 'friendly-names.js?v=rc26' in html
    assert 'RC17: follow-up' not in html
    assert 'Sonde PATCH RC13' not in app


def test_preexisting_report_actions_remain_machine_readable():
    root=Path(__file__).resolve().parents[1]/'src/achillesapi/dashboard/static'
    viewer=(root/'job-viewer.js').read_text()
    public=(root/'friendly-names.js').read_text()
    assert "'rc16-assess':'Test dei workflow e autorizzazioni'" in public
    assert "'rc13-assess':'Analisi approfondita API'" in public
    assert "const displayTaskName=name=>window.AchillesPublicNames?.action(name)" in viewer
    assert "step.action==='rc16-assess'" in viewer


def test_asterion_writes_reported_not_claimed_executed():
    import zipfile
    zip_file=Path('/mnt/data/AsterionLogistics-Enterprise-API-Lab-v1.0.zip')
    if not zip_file.exists():
        import pytest
        pytest.skip('Independent Asterion lab not installed')
    with zipfile.ZipFile(zip_file) as z:
        filename=next(n for n in z.namelist() if n.endswith('/openapi.json'))
        spec=json.loads(z.read(filename))
    report=write_inventory(spec,{})
    assert report['documented_write_operations']==14
    assert report['with_approved_fixture']==0
    assert report['without_approved_fixture']==14
    assert report['executed_write_operations']==0
    for op in ['POST /v1/admin/dispatch-rules','POST /v1/documents/xml-import', 'POST /v1/documents/uploads']:
        assert op in {item['operation'] for item in report['operations']}
