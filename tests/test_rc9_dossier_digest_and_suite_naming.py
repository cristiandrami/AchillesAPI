"""RC9 UI-only change: AI executive digest and suite names from OpenAPI info.title.

No target HTTP traffic or Ollama inference in these tests.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

import achillesapi.dashboard.control as control
from achillesapi.dashboard.ai_dossier_summary import build_ai_dossier_summary
from achillesapi.dashboard.server import create_app
from achillesapi.dashboard.suite_identity import api_name_from_spec, suite_identity

SPEC = {'openapi': '3.0.3', 'info': {'title': 'Northstar Enterprise API', 'version': '1'},
        'paths': {'/health': {'get': {'responses': {'200': {'description': 'OK'}}}}}}


def test_identity_uses_openapi_title_and_actual_immutable_id():
    key = 'abcdef09876543211234567890abcdef'
    values = suite_identity(SPEC, key)
    assert values == {'api_name': 'Northstar Enterprise API', 'suite_code': key[:12],
                      'display_name': 'Northstar Enterprise API · '+key[:12]}
    assert api_name_from_spec({'info': {'title': '  API  \n with    spaces\t'}}) == 'API with spaces'
    assert api_name_from_spec({'info': {}}) == 'API senza titolo'
    assert len(api_name_from_spec({'info': {'title': 'A'*300}})) <= 100
    assert '<script>' in api_name_from_spec({'info': {'title': '<script>'}})  # text, not HTML


def test_digest_only_reuses_source_text_deduplicated_and_sanitized():
    def entry(action, risk, actions, summary='Sintesi di prova'):
        return {'action': action, 'job_id': 'a'*32, 'provenance': 'ollama_eseguito',
                'sections': [{'name': 'ai_analysis', 'data': {
                    'executive_summary': summary, 'risk_observations': risk,
                    'recommended_tests': actions, 'limitations':['Non verificato con HTTP']}}]}
    result = build_ai_dossier_summary([
        entry('ai-analyze', ['Possibile BOLA su /customers'], ['Confrontare due tenant']),
        entry('ai-correlate', [' possibile  bola su /customers '],
              ['Confrontare due tenant','Esaminare la policy per utente'])])
    assert len(result['risks']) == 1
    assert [x['text'] for x in result['actions']] == [
        'Confrontare due tenant', 'Esaminare la policy per utente']
    assert len(result['limitations']) == 1
    assert result['risks'][0]['action'] == 'ai-analyze'
    assert 'non sono vulnerabilità confermate' in result['notice']
    assert build_ai_dossier_summary([])['risks'] == []


def test_suite_name_persisted_on_job_report_history_and_ai_dossier(tmp_path, monkeypatch):
    monkeypatch.setattr(control, 'SUITE_ORDER', ('analyze-openapi',))
    root = tmp_path / 'project'
    with TestClient(create_app(root), base_url='http://127.0.0.1:8766') as client:
        headers = {'x-achilles-token': client.get('/api/bootstrap').json()['csrf_token']}
        uploaded = client.post('/api/import-text', headers=headers,
                               json={'kind':'openapi', 'name':'test.json',
                                     'content':json.dumps(SPEC)})
        assert uploaded.status_code == 200, uploaded.text
        job = client.post('/api/control/suite', headers=headers,
                          json={'config': {'action':'auto-assess',
                                           'specification_id': uploaded.json()['id']}})
        assert job.status_code == 200, job.text
        started = job.json()
        sid = started['id']
        assert started['display_name'] == f"Northstar Enterprise API · {sid[:12]}"
        for _ in range(80):
            state = client.get('/api/jobs/'+sid).json()
            if state['status'] != 'orchestrating': break
            time.sleep(.1)
        assert state['status'] == 'complete', state
        assert state['display_name'] == started['display_name']
        report = client.get('/api/results/'+sid).json()
        assert report['display_name'] == started['display_name']
        view = client.get('/api/job-view/'+sid).json()
        assert view['display_name'] == started['display_name']
        assert client.get('/api/campaigns').json()[0]['display_name'] == started['display_name']
        dossier = client.get('/api/job-ai/'+sid).json()
        assert dossier['display_name'] == started['display_name']
        assert 'executive_digest' in dossier
        assert dossier['executive_digest']['risks'] == []
    with TestClient(create_app(root), base_url='http://127.0.0.1:8766') as client:
        historical = client.get('/api/jobs/'+sid).json()
        assert historical['display_name'] == started['display_name']


def test_new_dossier_has_visible_summary_and_sanitized_content_only():
    base = Path(__file__).resolve().parents[1] / 'src/achillesapi/dashboard/static'
    html = (base/'job-ai.html').read_text()
    js = (base/'job-ai.js').read_text()
    assert html.index('id="executiveDigest"') < html.index('id="aiItems"')
    assert 'function renderDigest(dossier)' in js
    assert 'dossier.executive_digest' in js
    assert 'innerHTML' not in js
    assert 'Fonte:' in js
    assert 'data-no-translate' in html
