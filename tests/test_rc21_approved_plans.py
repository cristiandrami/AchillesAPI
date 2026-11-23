"""Configured authorization plans become reviewable without silently executing requests."""
import pytest
from pathlib import Path

from achillesapi.core.openapi import load_openapi
from achillesapi.core.authorization_planner_rc21 import (
    build_authorization_plan,allowlisted_agent_intentions)

SPEC=Path(__file__).parent/'fixtures/independent-api-lab/openapi.json'


def test_approved_manifest_id_policy_and_fields_yield_reviewable_intentions():
    plan=build_authorization_plan(load_openapi(SPEC),
        owner='demo-owner',others=['demo-other'],expected_other='deny',
        fixture_ids={'project_ref':'approved-example-project',
                     'ticket_ref':'approved-example-ticket'},
        approved_manifest=True,writes_approved=True,
        forbidden_fields={'PATCH /projects/{project_ref}':['note']})
    patch=[c for c in plan['test_cases'] if c['operation']=='PATCH /projects/{project_ref}']
    assert {c['category'] for c in patch}=={'BFLA','BOPLA_MASS_ASSIGNMENT'}
    assert all(c['status']=='ready_to_review' for c in patch)
    intentions=allowlisted_agent_intentions(plan,
        approved_manifest=True, approve_writes=True)
    assert any(c['category']=='BOPLA_MASS_ASSIGNMENT' for c in intentions['approved_intentions'])
    assert intentions['executed'] is False and intentions['requests_sent']==0


def test_unapproved_writes_never_become_agent_intentions():
    plan=build_authorization_plan(load_openapi(SPEC),
        owner='demo-owner',others=['demo-other'],expected_other='deny',
        fixture_ids={'project_ref':'known','ticket_ref':'known'},
        approved_manifest=False,writes_approved=False)
    assert all(case['status']!='ready_to_review' for case in plan['test_cases']
               if case.get('effect')=='write')
    intentions=allowlisted_agent_intentions(plan,approved_manifest=True,approve_writes=True)
    assert not any(x['category']!='BOLA' for x in intentions['approved_intentions'])


def test_policy_fields_must_exist_and_flags_must_be_bool():
    spec=load_openapi(SPEC)
    with pytest.raises(ValueError,match='not present'):
        build_authorization_plan(spec,forbidden_fields={
            'PATCH /projects/{project_ref}':['made_up_sensitive_field']})
    with pytest.raises(ValueError,match='booleans'):
        build_authorization_plan(spec,writes_approved='yes')
