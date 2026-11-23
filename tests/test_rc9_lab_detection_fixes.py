"""Regressions for enterprise API detection: no lab-specific paths in the core."""
import json

from achillesapi.core.injection_engine_rc5 import _schedule_probes
from achillesapi.dashboard.job_view import viewer_payload
from achillesapi.reporting.professional import summarize_assessment


def test_direct_injection_results_survive_professional_and_dashboard_reports():
    sample = {
        'engine': 'achilles-injection-assessment-rc5',
        'requests_sent': 15,
        'confirmed_vulnerabilities': 0,
        'findings': [
            {'category': 'possible_sql_error_injection', 'operation': 'GET /report',
             'severity': 'medium', 'verification_status': 'requires_manual_review',
             'reason': 'New SQL error after a controlled probe.',
             'evidence': {'status': 500, 'token': 'super-secret'}},
            {'category': 'possible_nosql_injection', 'operation': 'GET /filter',
             'severity': 'informational', 'reason': 'Boolean differential indicator.'},
        ],
    }
    result = viewer_payload(sample, action='injection-assess', job_id='a' * 32)
    assert len(result['findings']) == 2
    assert result['summary']['findings_requiring_review'] == 2
    assert result['findings'][0]['severity'] == 'medium'
    assert result['findings'][0]['reason'] == sample['findings'][0]['reason']
    assert result['findings'][0]['status'] == 'requires_review'
    assert 'super-secret' not in json.dumps(result)


def test_authorization_conflict_is_visible_but_not_confirmed():
    sample = {'engine': 'achilles-active-authorization-rc2',
              'operation': 'GET /asset/{asset_id}', 'executed': True,
              'status': 'policy_conflict_requires_review', 'requests_sent': 2,
              'observations': [{'identity': 'owner', 'status_code': 200},
                               {'identity': 'other', 'status_code': 200}]}
    findings = summarize_assessment(sample)['findings']
    assert len(findings) == 1
    assert findings[0]['category'] == 'authorization_policy_conflict'
    assert findings[0]['status'] == 'requires_review'
    assert findings[0]['confidence'] == 'indicator'
    assert not summarize_assessment({**sample, 'executed': False})['findings']


def test_injection_budget_schedules_all_surfaces_before_deep_sweeps():
    items = [
        {'operation': 'GET /search', 'parameter': 'term', 'location': 'query'},
        {'operation': 'GET /filter', 'parameter': 'selector', 'location': 'query'},
        {'operation': 'GET /render', 'parameter': 'expression', 'location': 'query'},
        {'operation': 'GET /xml/lookup', 'parameter': 'xpath', 'location': 'query'},
    ]
    families = ('sql_error', 'sql_boolean', 'nosql', 'ssti', 'command', 'xpath')
    plan = _schedule_probes(items, families)
    assert len(plan) == len(items) * len(families)
    assert [case[0]['parameter'] for case in plan[:4]] == [x['parameter'] for x in items]
    assert [case[1] for case in plan[:4]] == ['sql_error', 'nosql', 'ssti', 'xpath']
    assert all(len([step for step in plan if step[0] is item]) == len(families) for item in items)


def test_suite_parent_can_export_sanitized_child_findings():
    suite = {'engine': 'achillesapi-bounded-suite', 'version': '1.0',
             'findings': [{'category': 'possible_ssti_injection',
                           'operation': 'GET /template', 'severity': 'medium',
                           'reason': 'Two arithmetic expressions evaluated',
                           'source_action': 'injection-assess',
                           'source_job_id': 'a' * 32}],
             'summary': {'completed': 1, 'failed': 0, 'skipped': 0, 'total': 1}}
    normalized = viewer_payload(suite, action='full-suite', job_id='b' * 32)
    assert normalized['summary']['findings_requiring_review'] == 1
    assert normalized['findings'][0]['category'] == 'possible_ssti_injection'
