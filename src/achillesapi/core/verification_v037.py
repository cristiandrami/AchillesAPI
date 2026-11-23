"""Strict offline differential verification of operator-supplied access rules.

Only known, explicitly asserted access policies may support policy mismatch
findings. Raw statuses alone never establish exploitability or ownership.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Any


def verify_access_policies(assessment: dict[str, Any], rules: list[dict[str, str]]) -> dict[str, Any]:
    """Compare observed GET statuses to an explicit trusted allow/deny matrix.

    Rule schema: {operation: 'GET /object/{id}', identity: 'alice', expected: 'deny'}.
    Missing/malformed observations are inconclusive, not a 'pass'. Each rule
    requires a real baseline observation of the same operation and identity.
    """
    if not isinstance(assessment, dict) or not isinstance(rules, list) or len(rules) > 200:
        raise ValueError('Expected assessment object and <= 200 explicit access rules')
    # A real access-matrix report carries its evidence *per rule*. Never join
    # observations by operation/identity alone: two different path IDs may use
    # the same templated GET but have opposite expected permissions.
    if assessment.get('engine') == 'achilles-access-matrix-rc4':
        return _verify_matrix_report(assessment, rules)
    execution = assessment.get('execution_report', {})
    observations = execution.get('observations', []) if isinstance(execution, dict) else []
    known: dict[tuple[str,str],list[int]] = defaultdict(list)
    for obs in observations if isinstance(observations,list) else []:
        if (isinstance(obs,dict) and isinstance(obs.get('operation'),str)
            and isinstance(obs.get('identity'),str) and type(obs.get('status')) is int):
            known[(obs['operation'],obs['identity'])].append(obs['status'])
    results = []
    for rule in rules:
        if (not isinstance(rule,dict) or set(rule) != {'operation','identity','expected'}
            or not isinstance(rule['operation'],str) or not rule['operation'].startswith('GET /')
            or not isinstance(rule['identity'],str) or rule['expected'] not in ('allow','deny')):
            raise ValueError('Each rule requires GET operation, identity, allow/deny')
        statuses=known.get((rule['operation'],rule['identity']), [])
        if not statuses:
            classification='inconclusive_missing_observation'
        elif rule['expected']=='deny' and any(200 <= status < 300 for status in statuses):
            classification='policy_mismatch_requires_review'
        elif rule['expected']=='allow' and all(status in (401,403) for status in statuses):
            classification='policy_mismatch_requires_review'
        elif all(400 <= status < 500 for status in statuses) and rule['expected']=='deny':
            classification='consistent_with_policy_not_proven'
        elif all(200 <= status < 300 for status in statuses) and rule['expected']=='allow':
            classification='consistent_with_policy_not_proven'
        else:
            classification='inconclusive_mixed_responses'
        results.append({'operation':rule['operation'],'identity':rule['identity'],
                        'expected':rule['expected'],'observed_statuses':sorted(set(statuses)),
                        'classification':classification})
    return {'engine':'access-policy-verifier-v0.36','requests_sent':0,
            'review_count':sum(r['classification']=='policy_mismatch_requires_review' for r in results),
            'confirmed_vulnerabilities':0,'results':results,
            'limitations':['HTTP response status alone cannot prove resource ownership or data access.',
                           'Operator must confirm the policy, response body and negative controls.']}


def _verify_matrix_report(assessment: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Strict status-only review, keyed by the exact rule ID and GET operation.

    Refuse guessing: an incomplete/dry-run observation is INCONCLUSIVE.
    The policy is the operator's policy, not a model inference.
    """
    if not 1 <= len(rules) <= 20:
        raise ValueError('Matrix review requires 1–20 explicit operator rules')
    by_id = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get('id'), str) or rule['id'] in by_id:
            raise ValueError('Matrix policy IDs must be unique')
        if rule.get('expected_owner') not in ('allow', 'deny') or rule.get('expected_other') not in ('allow', 'deny'):
            raise ValueError('Matrix policy requires allow/deny for BOTH users')
        by_id[rule['id']] = rule
    observations = assessment.get('rules', [])
    if not isinstance(observations, list):
        raise ValueError('Matrix report has no list of rule observations')
    seen = set()
    results = []
    for entry in observations:
        if not isinstance(entry, dict) or not isinstance(entry.get('id'), str):
            continue
        policy = by_id.get(entry['id'])
        if not policy or entry['id'] in seen or entry.get('operation') != policy.get('operation'):
            continue
        seen.add(entry['id'])
        got = entry.get('observations', [])
        for field, user_field in (('expected_owner', 'owner'), ('expected_other', 'other')):
            identity = policy[user_field]
            statuses = [x['status_code'] for x in got if isinstance(x,dict)
                        and x.get('identity') == identity and type(x.get('status_code')) is int] if isinstance(got,list) else []
            classification = 'inconclusive_missing_observation'
            if len(statuses) == 1 and assessment.get('executed'):
                code = statuses[0]
                if policy[field] == 'deny':
                    if 200 <= code < 300: classification = 'policy_mismatch_requires_review'
                    elif code in (401,403): classification = 'consistent_with_policy_not_proven'
                    else: classification = 'inconclusive_status'
                elif 200 <= code < 300: classification = 'consistent_with_policy_not_proven'
                elif code in (401,403): classification = 'policy_mismatch_requires_review'
                else: classification = 'inconclusive_status'
            results.append({'rule_id':policy['id'], 'operation':policy['operation'],
                            'path_values':policy.get('path_values',{}), 'identity':identity,
                            'expected':policy[field], 'observed_statuses':statuses,
                            'classification':classification})
    # Every unmatched rule remains explicitly unverified rather than vanishing.
    for rule in rules:
        if rule['id'] not in seen:
            for field, user_field in (('expected_owner','owner'),('expected_other','other')):
                results.append({'rule_id':rule['id'], 'operation':rule['operation'],
                                'path_values':rule.get('path_values',{}), 'identity':rule[user_field],
                                'expected':rule[field], 'observed_statuses':[],
                                'classification':'inconclusive_missing_observation'})
    return {'engine':'access-policy-verifier-v0.36','source_engine':'achilles-access-matrix-rc4',
            'requests_sent':0, 'review_count':sum(x['classification']=='policy_mismatch_requires_review' for x in results),
            'confirmed_vulnerabilities':0, 'results':results,
            'limitations':['Matrix rules are operator-provided, not inferred from OpenAPI.',
                           'HTTP statuses require response-content and ownership verification.',
                           'Missing observations never count as a successful authorization test.']}
