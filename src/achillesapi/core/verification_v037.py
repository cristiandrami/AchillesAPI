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
