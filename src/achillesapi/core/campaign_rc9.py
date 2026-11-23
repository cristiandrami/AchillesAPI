"""RC9 deterministic, offline campaign coverage, prerequisites and evidence policy.

Local AI proposals are advisory and never bypass the explicit scope, request
budget, mutation approval, resource ownership or cleanup checks.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from achillesapi.core.injection_planner_v2 import injection_surface_plan
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.testgen import _resolve_schema


def campaign_plan_rc9(spec: dict[str, Any], *, profiles: list[str] | None = None,
                      approved_fixture: bool = False,
                      authorized_scope: bool = False) -> dict[str, Any]:
    parsed = parse_openapi(spec)
    inject = injection_surface_plan(spec)
    operations = []
    for ep in parsed.endpoints:
        method = ep.method
        if method not in {'GET','POST','PATCH','PUT','DELETE'}:
            continue
        op = method + ' ' + ep.path
        required = [x.name for x in ep.parameters if x.required and x.location == 'path']
        body = _resolve_schema(spec, ep.request_body or {})
        content_types = list(body.get('content', {})) if isinstance(body, dict) else []
        action = 'active_get_allowed_after_approval' if method == 'GET' else 'requires_approved_disposable_fixture'
        tasks = ['authentication_baseline', 'schema_validation', 'error_handling']
        if required:
            tasks.append('known_test_path_values')
        if method == 'GET':
            tasks += ['object_level_authorization_when_policy_known','bounded_read_only_injection']
        else:
            tasks += ['business_logic_and_access_policy', 'verified_test_resource_lifecycle']
        operations.append({'operation':op, 'execution_mode':action,
                           'required_path_parameters':required,
                           'request_content_types':content_types,
                           'test_candidates':tasks,
                           'ready_for_http':bool(authorized_scope and
                                (method == 'GET' or approved_fixture)),
                           'finding_status':'not_tested'})
    counts = Counter(o['execution_mode'] for o in operations)
    blocked = [o['operation'] for o in operations if not o['ready_for_http']]
    result = {
        'engine':'achilles-rc9-campaign-planner', 'requests_sent':0,
        'summary':{'operations':len(operations), 'methods':dict(Counter(o['operation'].split(' ')[0] for o in operations)),
                   'http_ready':sum(o['ready_for_http'] for o in operations),
                   'needs_prerequisites':len(blocked), 'injection_candidates':inject['planned_cases'],
                   'profiles':len(profiles or []), 'authorization_rules_inferred':0},
        'execution_modes':dict(counts), 'operations':operations,
        'injection_surface':{'planned_cases':inject['planned_cases'], 'by_method':inject['by_method']},
        'prerequisites':{
            'authorization_scope':authorized_scope,
            'test_identities_available':bool(profiles),
            'cross_user_checks_possible':len(profiles or [])>=2,
            'disposable_fixture_available':approved_fixture,
            'blocked_operations':blocked[:100],
        },
        'verification_policy':{
            'confirmed_vulnerabilities_from_openapi_alone':0,
            'heuristic_response_difference_is_confirmation':False,
            'policy_violations_require_explicit_trusted_rule':True,
            'ambiguous_identifiers_require_review':True,
        },
        'next_steps':[
            {'priority':1, 'task':'approve_scope_and_identities',
             'requires':'base URL, allowlist e autorizzazione scritta'},
            {'priority':2, 'task':'configure_owned_test_resources',
             'requires':'POST, GET per ID, DELETE, marker verificabile e fixture approvata'},
            {'priority':3, 'task':'execute_bounded_get_tests',
             'requires':'scope, budget e parametri path di prova'},
            {'priority':4, 'task':'execute_approved_workflows',
             'requires':'policy di accesso, manifest verificato e cleanup'},
            {'priority':5, 'task':'correlate_and_verify',
             'requires':'evidenze ripetibili, confronto contro controlli negativi e policy'},
        ],
        'limitations':['Questa pianificazione non invia HTTP e non dichiara finding confermati.',
                       'L’analisi AI locale non può autorizzare nuove scritture o cambiare lo scope.'],
    }
    return result


def verification_summary_rc9(report: dict[str, Any]) -> dict[str, Any]:
    """Deduplicate observed findings without converting suspicions into proof."""
    raw = []
    if not isinstance(report, dict):
        raise ValueError('Report must be an object')
    for location in ('execution_report','multi_resource_execution','workflow_execution'):
        section = report.get(location)
        if not isinstance(section, dict):
            continue
        raw.extend(item for item in section.get('findings', []) if isinstance(item, dict))
        for workflow in section.get('workflows', []):
            if isinstance(workflow, dict):
                raw.extend(x for x in workflow.get('findings', []) if isinstance(x, dict))
    unique = {}
    for item in raw[:3000]:
        key = (str(item.get('category','unknown')),str(item.get('operation', '')),
               str(item.get('parameter', '')),str(item.get('resource', '')))
        if key not in unique:
            status = 'requires_manual_review'
            # Even explicit policy findings cannot be independently verified
            # without a positive ownership and response identity check.
            if item.get('verified') is True and item.get('policy_verified') is True:
                status = 'evidence_backed_requires_operator_signoff'
            unique[key] = {'category':key[0],'operation':key[1],
                           'parameter':key[2], 'resource':key[3],
                           'status':status, 'occurrences':0}
        unique[key]['occurrences'] += 1
    return {'engine':'achilles-rc9-verification-summary', 'raw_findings':len(raw),
            'deduplicated_groups':len(unique), 'verified_automatically':0,
            'groups':list(unique.values()),
            'message':'Le differenze HTTP non diventano vulnerabilità confermate senza una policy verificata.'}
