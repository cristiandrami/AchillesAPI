"""Report grouping is deterministic, conservative, escaped and translated."""
import json
from pathlib import Path
import pytest
from achillesapi.reporting.professional import summarize_assessment, _html, _markdown
from achillesapi.reporting.cvss import score_cvss31
from achillesapi.dashboard.job_view import viewer_payload

BASE = Path(__file__).resolve().parents[1] / 'src' / 'achillesapi' / 'dashboard' / 'static'


def test_macro_severity_sorted_and_never_overrides_child():
    raw = {'engine': 'mock-authorized-test', 'findings': [
        {'category': 'possible_sql_error_injection', 'operation': 'GET /search', 'severity': 'low',
         'reason': 'Baseline differs'},
        {'category': 'bfla_write_policy_conflict', 'operation': 'POST /assets/{id}/approve',
         'severity': 'high', 'reason': 'Policy deny, HTTP 200',
         'access_comparison': [{'profile':'employee','expected':'deny','status_code':200}]},
        {'category': 'possible_ssti_injection', 'operation': 'GET /render', 'severity': 'critical',
         'reason': 'Review required'},
        {'category': 'mass_assignment_policy_conflict', 'operation': 'PATCH /assets/{id}',
         'field': '/approved', 'profile': 'employee', 'severity':'medium',
         'reason': 'state changed', 'evidence': {'baseline_changed': True, 'persisted': True}},
    ]}
    report = summarize_assessment(raw)
    assert [g['severity'] for g in report['finding_groups']] == ['critical','high']
    assert [g['category'] for g in report['finding_groups']] == ['injection','authorization']
    assert [x['severity'] for x in report['findings']] == ['low','high','critical','medium']
    assert all(x['status'] == 'requires_review' for x in report['findings'])
    finding = next(x for x in report['findings'] if x['category'] == 'mass_assignment_policy_conflict')
    assert finding['evidence']['json_field_pointer'] == '/approved'
    assert finding['evidence']['persisted_after_patch'] is True
    assert 'Mass Assignment' in finding['what_found']
    assert report['finding_groups'][0]['count'] == 2
    assert 'Severità' not in _markdown(report) or 'severità massima' in _markdown(report)
    assert _html(report).index('Injection e input') < _html(report).index('Autorizzazione e campi riservati')
    visible = viewer_payload(raw, action='rc13-assess', job_id='test')
    assert visible['finding_groups'][0]['severity'] == 'critical'


def test_cvss31_is_only_calculated_from_explicit_complete_vector():
    assert score_cvss31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') == 9.8
    assert score_cvss31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N') == 0.0
    with pytest.raises(ValueError):
        score_cvss31('CVSS:3.1/AV:N/AC:L')
    raw = {'engine':'offline', 'findings': [
        {'category':'test', 'severity':'medium','reason':'review', 'operation':'GET /',
         'cvss_vector':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'},
        {'category':'test2','severity':'medium','reason':'review','operation':'GET /',
         'cvss_vector':'9.9; bearer token=secret'}]}
    a,b = summarize_assessment(raw)['findings']
    assert a['cvss_base_score'] == 9.8
    assert b.get('cvss_base_score') is None
    assert 'cvss_vector' not in b


def test_new_suite_wizard_consent_label_and_four_translations():
    html = (BASE / 'index.html').read_text(encoding='utf-8')
    key = 'Sonde aggiuntive sui campi JSON (solo campi e risorse esplicitamente approvati)'
    assert key in html
    # HTML attribute serialization may add an XML-style self-closing slash.
    from bs4 import BeautifulSoup
    consent = BeautifulSoup(html, 'html.parser').find(id='suiteRc13Body')
    assert consent is not None and consent.name == 'input' and consent.get('type') == 'checkbox' 
    i18n = (BASE / 'i18n-catalog.js').read_text(encoding='utf-8')
    data = json.loads(i18n.split('window.AchillesUILocales = ',1)[1].rstrip().rstrip(';'))
    for language in ('en','es','fr'):
        assert data[language][key]


def test_report_never_places_untrusted_text_in_html():
    raw = {'engine': 'test', 'findings': [
        {'category':'example', 'operation':'GET /<script>alert(1)</script>',
         'severity':'informational', 'reason':'<script>evil()</script>'}]}
    html = _html(summarize_assessment(raw))
    assert '<script>alert(1)</script>' not in html
    assert '&lt;script&gt;' in html


def test_duplicate_observation_identifiers_preserved_in_all_renderers(tmp_path):
    # Child jobs can each emit POLICY-001; a report must never silently drop one.
    raw = {'engine': 'test', 'findings': [
        {'id': 'POLICY-001', 'category': 'bfla_write_policy_conflict',
         'operation': 'POST /first/approve', 'severity': 'high', 'reason': 'first profile'},
        {'id': 'POLICY-001', 'category': 'bfla_write_policy_conflict',
         'operation': 'POST /second/approve', 'severity': 'medium', 'reason': 'second profile'}]}
    report = summarize_assessment(raw)
    assert report['finding_groups'][0]['count'] == 2
    assert report['finding_groups'][0]['finding_indices'] == [0, 1]
    assert 'POST /first/approve' in _markdown(report)
    assert 'POST /second/approve' in _markdown(report)
    assert 'POST /first/approve' in _html(report)
    assert 'POST /second/approve' in _html(report)
