"""RC16: policy-driven, multi-endpoint authorization checks from one approved fixture map.

No resource ID is guessed. A second identity and the expected cross-identity
policy must be explicitly supplied. All traffic goes through access_matrix_rc4.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from achillesapi.core.access_matrix_rc4 import preflight_rules, run_access_matrix
from achillesapi.core.auth import AuthenticationManager
from achillesapi.core.openapi import load_openapi, parse_openapi
from achillesapi.core.workflows import get_read_side_effect_risk

_BAD_FIELD = re.compile(r"(?:secret|token|password|cookie|api_?key|authorization)", re.I)
_PATH_PARAMS = re.compile(r"\{([^{}]+)\}")


def generate_authorization_policy(
    specification: Path | str, *, owner: str, others: list[str],
    path_values: dict[str, str], expected_other: str = 'deny',
    expected_owner: str = 'allow', max_rules: int = 50,
) -> dict[str, Any]:
    """Produce a complete *candidate* policy for all safely addressable GET routes.

    The policy describes operator assumptions. `preflight_rules` is applied
    before network execution; missing values are reported instead of guessed.
    """
    if expected_other not in {'allow', 'deny'} or expected_owner not in {'allow', 'deny'}:
        raise ValueError('Expected policies must be allow or deny')
    if not re.fullmatch(r'[\w.-]{1,64}', owner) or not others or len(others) > 5:
        raise ValueError('Provide an owner and 1..5 other profiles')
    if len(set(others)) != len(others) or owner in others or any(
        not isinstance(o, str) or not re.fullmatch(r'[\w.-]{1,64}', o) for o in others
    ):
        raise ValueError('Owner and comparison profiles must be distinct, safe identifiers')
    if not 1 <= max_rules <= 50:
        raise ValueError('Maximum rules must be between 1 and 20')
    if not isinstance(path_values, dict) or len(path_values) > 30:
        raise ValueError('Fixture path-values mapping invalid')
    safe_values = {}
    for k, v in path_values.items():
        if (not isinstance(k, str) or not re.fullmatch(r'[\w.-]{1,64}', k)
            or not isinstance(v, (str, int)) or isinstance(v, bool) or not str(v)
            or len(str(v)) > 128 or any(c in str(v) for c in '/\\?&#%\r\n')
            or str(v) in {'.', '..'}):
            raise ValueError('Invalid approved path value')
        safe_values[k] = str(v)
    parsed = parse_openapi(load_openapi(specification))
    eligible = []
    skipped: list[dict[str, Any]] = []
    for ep in parsed.endpoints:
        if ep.method != 'GET':
            continue
        op = f'GET {ep.path}'
        keys = _PATH_PARAMS.findall(ep.path)
        required = [p.name for p in ep.parameters if p.required and p.location == 'query']
        missing = sorted(set(keys) - set(safe_values))
        if get_read_side_effect_risk(ep):
            skipped.append({'operation': op, 'reason': 'read_side_effect_risk'})
        elif not keys:
            # Collection reads do not prove BOLA over an owned object.
            skipped.append({'operation': op, 'reason': 'no_explicit_resource_id'})
        elif required:
            # Legacy access_probe requires exact read-only GETs without required query fields.
            skipped.append({'operation': op, 'reason': 'required_query_not_supported', 'fields': required})
        elif missing:
            skipped.append({'operation': op, 'reason': 'approved_identifier_missing', 'fields': missing})
        elif any(_BAD_FIELD.search(key) for key in keys):
            skipped.append({'operation': op, 'reason': 'potential_sensitive_field'})
        else:
            eligible.append((op, {key: safe_values[key] for key in set(keys)}))
    rules = []
    for op, values in sorted(eligible):
        for other in others:
            if len(rules) >= max_rules:
                break
            rules.append({'id': f'auto-{len(rules)+1}', 'operation': op,
                          'owner': owner, 'other': other, 'expected_owner': expected_owner,
                          'expected_other': expected_other, 'path_values': values})
    return {'engine': 'achilles-authorization-auto-rc16',
            'rules': rules, 'skipped': skipped,
            'identities_compared': [owner, *others], 'rules_generated': len(rules),
            'explicit_policy_required': True, 'requests_sent': 0,
            'limitations': ['L’operatore approva le risorse e la policy; nessuna ownership è inferita dallo Swagger.',
                            'I GET senza ID/fixture sono esclusi; BFLA scrittura richiede manifest.',
                            'Un conflitto HTTP non conferma automaticamente una vulnerabilità.']}


def execute_authorization_auto(specification: Path | str, *, base_url: str,
                               allowed_hosts: set[str], auth_manager: AuthenticationManager,
                               owner: str, others: list[str], path_values: dict[str, str],
                               expected_other: str, execute: bool,
                               allow_insecure_http: bool = False, rate: float = 1.,
                               max_requests: int = 40) -> dict[str, Any]:
    policy = generate_authorization_policy(specification, owner=owner, others=others,
                                           path_values=path_values, expected_other=expected_other,
                                           max_rules=min(50, max_requests // 2))
    if not policy['rules']:
        return {**policy, 'status': 'blocked_missing_approved_fixture', 'executed': False, 'findings': []}
    if not all(n in auth_manager.names for n in [owner, *others]):
        raise ValueError('An identity is not present in auth.yaml')
    preflight_rules(specification, policy, profile_names=set(auth_manager.names))
    outcome = run_access_matrix(specification, policy=policy, base_url=base_url,
        allowed_hosts=allowed_hosts, auth_manager=auth_manager, execute=execute,
        allow_insecure_http=allow_insecure_http, rate=rate, max_requests=max_requests)
    # Imports locally to avoid an import cycle in pipeline_rc13.
    from achillesapi.core.pipeline_rc13 import authorization_findings
    return {**policy, **outcome, 'engine': 'achilles-authorization-auto-rc16',
            'findings': authorization_findings(outcome),
            'rules_generated': len(policy['rules']), 'skipped': policy['skipped']}
