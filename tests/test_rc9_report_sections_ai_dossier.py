"""RC9 report UX regression: profile provenance, grouped categories and AI dossier.

All fixtures are synthetic and no external target or Ollama is contacted.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.job_view import ai_dossier_entry, viewer_payload
from achillesapi.reporting.professional import summarize_assessment


def test_access_probe_displays_both_profile_aliases_and_http_codes():
    raw = {
        'engine':'achilles-active-authorization-rc2',
        'executed':True,'status':'policy_conflict_requires_review',
        'operation':'GET /tickets/{ticket_id}',
        'owner':'owner','other':'colleague',
        'expected_owner':'allow','expected_other':'deny',
        'observations':[
            {'identity':'owner','status_code':200,'token':'super-secret'},
            {'identity':'colleague','status_code':200,'authorization':'Bearer secret'},
        ],
    }
    finding=summarize_assessment(raw)['findings'][0]
    assert finding['access_comparison']==[
        {'profile':'owner','expected':'allow','status_code':200},
        {'profile':'colleague','expected':'deny','status_code':200},
    ]
    assert 'super-secret' not in json.dumps(finding)
    assert 'Bearer secret' not in json.dumps(finding)
    reopened=summarize_assessment({'report_schema':'achillesapi.professional.2','findings':[finding]})
    assert reopened['findings'][0]['access_comparison']==finding['access_comparison']


def test_access_matrix_and_policy_verifier_show_specific_profiles_and_rule_ids():
    matrix={'engine':'achilles-access-matrix-rc4','executed':True,'rules':[
        {'id':'ticket-1', 'operation':'GET /tickets/{ticket_id}',
         'status':'policy_conflict_requires_review','expected_owner':'allow',
         'expected_other':'deny','owner':'owner','other':'colleague',
         'observations':[{'identity':'owner','status_code':200},{'identity':'colleague','status_code':200}]},
    ]}
    found=summarize_assessment(matrix)['findings'][0]
    assert found['rule_id']=='ticket-1'
    assert [p['profile'] for p in found['access_comparison']]==['owner','colleague']
    assert [p['expected'] for p in found['access_comparison']]==['allow','deny']
    assert [p['status_code'] for p in found['access_comparison']]==[200,200]

    offline={'engine':'access-policy-verifier-v0.36','results':[
        {'rule_id':'ticket-1','classification':'policy_mismatch_requires_review',
         'operation':'GET /tickets/{ticket_id}','identity':'colleague','expected':'deny',
         'observed_statuses':[200]},
    ]}
    check=summarize_assessment(offline)['findings'][0]
    assert check['rule_id']=='ticket-1'
    assert check['access_comparison']==[{'profile':'colleague','expected':'deny','status_code':200}]


def test_access_comparison_untrusted_labels_cannot_disclose_tokens():
    raw={'engine':'x','findings':[{'category':'authorization_policy_conflict',
        'operation':'GET /x','access_comparison':[
            {'profile':'Authorization: Bearer TOPSECRET','expected':'deny','status_code':200},
            {'profile':'colleague','expected':'deny','status_code':403},
        ]}]}
    item=summarize_assessment(raw)['findings'][0]
    assert item['access_comparison']==[{'profile':'colleague','expected':'deny','status_code':403}]
    assert 'TOPSECRET' not in json.dumps(item)


def test_ai_dossier_differentiates_ollama_and_deterministic_advice():
    raw={'provider':'ollama-local-only','ai_analysis':{
         'executive_summary':'Valutare permessi su /users',
         'risk_observations':['Possibile BOLA'],
         'recommended_tests':['Confrontare profili'],
         'limitations':['Non verificato con GET'],
         'token':'secret', 'notes':'<script>alert(1)</script>'}}
    result=ai_dossier_entry(raw,action='ai-analyze',job_id='a'*32,ai_status='completed_local')
    assert result['provenance']=='ollama_eseguito'
    assert result['sections'][0]['data']['token'].startswith('[omesso')
    assert result['sections'][0]['data']['risk_observations']==['Possibile BOLA']
    assert ai_dossier_entry({'engine':'plan'},action='intelligent-plan',job_id='b'*32) is None
    deterministic=ai_dossier_entry({'recommended_tests':['Rivedere GET /a']},action='ai-prioritize',job_id='b'*32)
    assert deterministic['provenance']=='analisi_deterministica'


def test_dossier_endpoint_and_static_assets_for_completed_job(tmp_path):
    home=tmp_path/'ui'
    spec={'openapi':'3.0.3','info':{'title':'Sample','version':'1'},
          'paths':{'/health':{'get':{'responses':{'200':{'description':'OK'}}}}}}
    with TestClient(create_app(home),base_url='http://127.0.0.1:8766') as client:
        headers={'x-achilles-token':client.get('/api/bootstrap').json()['csrf_token']}
        uploaded=client.post('/api/import-text',headers=headers,json={
            'kind':'openapi','content':json.dumps(spec),'name':'api.json'})
        assert uploaded.status_code==200,uploaded.text
        start=client.post('/api/control/jobs',headers=headers,json={
            'action':'analyze-openapi','specification_id':uploaded.json()['id']})
        assert start.status_code==200,start.text
        jid=start.json()['id']
        for _ in range(100):
            state=client.get('/api/jobs/'+jid).json()
            if state['status']!='running':break
            time.sleep(.05)
        assert state['status']=='complete'
        (home/'reports'/(jid+'.json')).write_text(json.dumps({
            'provider':'ollama-local-only',
            'ai_analysis':{'executive_summary':'Consigli','recommended_tests':['Test A','Test B'],
                           'limitations':['Non confermato']}}))
        response=client.get('/api/job-ai/'+jid)
        assert response.status_code==200,response.text
        dossier=response.json()
        assert dossier['total_ai_outputs']==1
        assert dossier['entries'][0]['sections'][0]['data']['recommended_tests']==['Test A','Test B']
        page=client.get('/job/'+jid+'/ai')
        assert page.status_code==200
        assert 'job-ai.js' in page.text
        assert "script-src 'self'" in page.headers['content-security-policy']
        assert client.get('/api/job-ai/'+'f'*32).status_code==404
        view=client.get('/job/'+jid).text
        assert 'id="aiDossier"' in view
        assert 'Read-only dossier' in client.get('/assets/job-ai.js').text


def test_new_report_has_group_sections_and_text_only_rendering():
    src=Path('src/achillesapi/dashboard/static/job-viewer.js').read_text()
    assert 'function groupedFindings(' in src
    assert 'function findingSection(' in src
    assert 'Identità utilizzate · profili auth.yaml' in src
    assert 'access_comparison' in src
    assert 'Dossier AI completo' in src
    assert 'innerHTML' not in src.replace('// No innerHTML with job data:','')
    assert 'innerHTML' not in Path('src/achillesapi/dashboard/static/job-ai.js').read_text()
