"""RC16: authorized multi-identity disposable-resource campaign orchestration.

Policy is operator supplied; writes never happen without an approved fixture
and a separate explicit flag. Detection does not invent business permissions.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from achillesapi.core.multi_resource import MultiResourceError, plan_multi_resource, run_multi_resource
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.auth import AuthenticationMaterial


def prepare_campaign(spec: dict[str, Any], manifest: dict[str, Any], *,
                     profiles: set[str], cross_identity: list[str] | None = None,
                     expected_other: str = 'deny', max_comparisons: int = 24) -> dict[str, Any]:
    """Combine approved fixture checks and cross-identity GET policy without network I/O.

    Each resource's own identity owns its disposable marker. The caller must
    *explicitly* name comparison identities and decide deny/allow: Swagger
    cannot determine resource ownership or the business authorization policy.
    """
    if expected_other not in {'allow', 'deny'}:
        raise MultiResourceError('Expected policy must be allow or deny')
    if not 0 <= max_comparisons <= 60:
        raise MultiResourceError('Comparison limit must be between 0 and 60')
    others = cross_identity or []
    if len(others) > 6 or len(set(others)) != len(others) or any(
        not isinstance(name, str) or name not in profiles for name in others
    ):
        raise MultiResourceError('Comparison identities must be distinct profiles from auth.yaml')
    if not isinstance(manifest, dict) or not isinstance(manifest.get('resources'), list):
        raise MultiResourceError('Approved resources manifest required')
    configured = deepcopy(manifest)
    injected = 0
    for resource in configured['resources']:
        if not isinstance(resource, dict):
            raise MultiResourceError('Invalid resource entry')
        owner = resource.get('identity')
        if owner not in profiles:
            raise MultiResourceError('Resource owner must appear in auth.yaml')
        access = resource.setdefault('access', [])
        if not isinstance(access, list):
            raise MultiResourceError('Access must be a list')
        for other in others:
            if other == owner or any(x.get('identity') == other for x in access if isinstance(x, dict)):
                continue
            if len(access) >= 6 or injected >= max_comparisons:
                raise MultiResourceError('Cross-identity checks exceed per-resource or global budget')
            access.append({'identity': other, 'expected': expected_other})
            injected += 1
    parsed = parse_openapi(spec)
    plan = plan_multi_resource(parsed, spec, configured, profiles)
    return {'engine': 'achilles-rc16-multi-tenant-orchestration',
            'manifest': configured, 'plan': plan,
            'added_cross_identity_checks': injected,
            'comparison_profiles': others, 'expected_other': expected_other,
            'dry_run_only': True,
            'limitations': ['Permission policy and disposable resource fixtures must be approved.',
                            'GET comparison confirms an object marker, not the correctness of business policy.']}


def run_campaign(spec: dict[str, Any], manifest: dict[str, Any], *,
                 identities: dict[str, AuthenticationMaterial], base_url: str,
                 allowed_hosts: set[str], cross_identity: list[str] | None = None,
                 expected_other: str = 'deny', execute: bool = False,
                 approve_writes: bool = False, allow_insecure_http: bool = False,
                 max_requests: int = 100, rate: float = 1.) -> dict[str, Any]:
    """Use the existing write-scope, marker and reverse-cleanup engine unmodified."""
    approved = prepare_campaign(spec, manifest, profiles=set(identities),
                                cross_identity=cross_identity, expected_other=expected_other)
    plan = approved['plan']
    if execute and max_requests < plan['request_budget_required']:
        raise MultiResourceError('Insufficient budget, including reserved cleanup')
    result = run_multi_resource(parse_openapi(spec), spec, approved['manifest'],
        base_url=base_url, allowed_hosts=allowed_hosts, identities=identities,
        execute=execute, approve_writes=approve_writes,
        allow_insecure_http=allow_insecure_http, max_requests=max_requests, rate=rate)
    return {**result, 'engine': 'achilles-rc16-multi-tenant-orchestration',
            'added_cross_identity_checks': approved['added_cross_identity_checks'],
            'comparison_profiles': approved['comparison_profiles'],
            'expected_other': expected_other,
            'verification_policy': 'explicit_operator_policy',
            'finding_confirmation': 'requires_manual_review'}
