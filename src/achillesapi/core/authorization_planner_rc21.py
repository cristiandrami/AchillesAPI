"""RC21 automatic *planning* for BOLA/BFLA/BOPLA and multi-resource dependencies.

Discovery is not an access-control oracle. Owner/other identities, expected
policy, object IDs and write approval are required before any active test.
"""
from __future__ import annotations

import re
from typing import Any

from achillesapi.core.openapi import parse_openapi
from achillesapi.core.rc15_security import _body_fields
from achillesapi.core.workflows import _request_schema, get_read_side_effect_risk
from achillesapi.core.workflow_automation_rc16 import discover_resource_workflows
from achillesapi.core.diagnostics_rc20 import diagnose

_SENSITIVE = re.compile(r'(?:password|secret|token|api.?key|authorization|cookie|session)', re.I)
_OBJECT = re.compile(r'\{([^{}]+)\}')


def build_authorization_plan(spec: dict[str, Any], *,
                             owner: str | None = None, others: list[str] | None = None,
                             expected_other: str | None = None,
                             fixture_ids: dict[str, str] | None = None,
                             approved_manifest: bool = False, writes_approved: bool = False,
                             forbidden_fields: dict[str, list[str]] | None = None,
                             max_cases: int = 200) -> dict[str, Any]:
    """Generate an auditable offline test plan, never mutable HTTP payloads."""
    if not 1 <= max_cases <= 500:
        raise ValueError('max_cases must be 1..500')
    if expected_other not in (None, 'allow', 'deny'):
        raise ValueError('Expected policy must be explicitly allow or deny')
    names = [x for x in (others or []) if isinstance(x,str) and x != owner][:6]
    if len(names) != len(set(names)):
        raise ValueError('Comparison identities must be distinct')
    provided_ids = fixture_ids or {}
    forbidden_fields = forbidden_fields or {}
    if not isinstance(provided_ids, dict) or not isinstance(forbidden_fields, dict):
        raise ValueError('Fixture IDs and forbidden-field policy must be mappings')
    if type(approved_manifest) is not bool or type(writes_approved) is not bool:
        raise ValueError('Write flags must be explicit booleans')
    parsed = parse_openapi(spec)
    index = {(e.method,e.path):e for e in parsed.endpoints}
    workflows = discover_resource_workflows(spec,max_candidates=100)['candidates']
    cases: list[dict[str, Any]] = []
    for wf in workflows:
        resource = wf['resource']
        dependencies = wf['depends_on_collections']
        common = {'workflow':wf['name'], 'collection':resource,
                  'dependencies':dependencies,
                  'cleanup_operation':wf['cleanup'],
                  'scope': 'operator_approved_disposable_resource'}
        read_op = wf['read']
        read = index.get(('GET',read_op[4:]))
        identifiers = list(_OBJECT.findall(read.path)) if read else []
        qrequired = [p.name for p in read.parameters if p.location=='query' and p.required] if read else []
        missing = [name for name in identifiers + qrequired if not provided_ids.get(name)]
        issues = ([diagnose('IDENTITIES_REQUIRED')] if not owner or not names else []) + \
                 ([diagnose('POLICY_REQUIRED')] if not expected_other else []) + \
                 ([diagnose('CLEANUP_REQUIRED')] if not wf['cleanup'] else [])
        if missing: issues.append(diagnose('WORKFLOW_REQUIRED',detail='Parametri: '+', '.join(missing[:8])))
        if read and not get_read_side_effect_risk(read):
            cases.append({**common, 'category':'BOLA', 'operation':read_op,
                          'identity_pairs': [[owner,name] for name in names] if owner else [],
                          'required_identifiers':identifiers,
                          'required_query_parameters':qrequired,
                          'status':'ready_to_review' if not issues else 'needs_operator_inputs',
                          'issues':issues,'expected_other':expected_other,
                          'request_count_estimate':2*len(names) if names else 0})
        for operation in [wf['create'], *wf['mutations']]:
            method,path=operation.split(' ',1)
            ep=index.get((method,path))
            if not ep:continue
            # Body generation is delegated to the existing rc16 approved-fixture engine.
            # Planning alone does not create payloads or access resources.
            write_issues=list(issues)
            if not approved_manifest:write_issues.append(diagnose('WORKFLOW_REQUIRED'))
            if not writes_approved:write_issues.append(diagnose('WRITES_CONSENT_REQUIRED'))
            for key in _OBJECT.findall(path):
                if not provided_ids.get(key):
                    write_issues.append(diagnose('WORKFLOW_REQUIRED',detail='ID: '+key))
            write_issues=list({(item['code'],item.get('detail','')):item for item in write_issues}.values())
            cases.append({**common,'category':'BFLA','operation':operation,
                          'identity_pairs':[[owner,name] for name in names] if owner else [],
                          'status':'ready_to_review' if not write_issues else 'needs_operator_inputs',
                          'issues':write_issues,
                          'expected_other':expected_other,
                          'effect':'write','requires_explicit_policy':True})
            if method in {'PATCH','PUT'}:
                shape = _request_schema(spec,ep) or {}
                fields = [field for field,kind in _body_fields(spec,shape)
                          if not _SENSITIVE.search(field) and kind=='string']
                # The operator identifies which fields MUST NOT be modifiable;
                # no inference from a name like `isAdmin` is a business policy.
                requested=forbidden_fields.get(operation,[])
                if not isinstance(requested,list) or any(not isinstance(x,str) for x in requested):
                    raise ValueError('Forbidden-field policy must list field names')
                if set(requested)-set(fields):
                    raise ValueError('Operator field policy refers to fields not present in OpenAPI')
                bopla_issues=list(write_issues)
                if not requested:bopla_issues.append(diagnose('PATCH_FIELDS_REQUIRED'))
                cases.append({**common,'category':'BOPLA_MASS_ASSIGNMENT',
                              'operation':operation,'candidate_fields':fields[:40],
                              'forbidden_fields':requested[:40],
                              'status':'ready_to_review' if not bopla_issues else 'needs_operator_inputs',
                              'issues':bopla_issues,
                              'policy_not_inferred':True, 'effect':'write'})
        if len(cases)>=max_cases:break
    cases=cases[:max_cases]
    by_category = {name:sum(row['category']==name for row in cases)
                   for name in ('BOLA','BFLA','BOPLA_MASS_ASSIGNMENT')}
    return {'engine':'achilles-authorization-plan-rc21', 'network_requests_sent':0,
            'workflows_found':len(workflows),'test_cases':cases,'counts':by_category,
            'unresolved_count':sum(x['status']=='needs_operator_inputs' for x in cases),
            'limitations':['Identificatori e query richiesti sono elencati, mai inventati.',
                           'Operazioni di scrittura solo tramite motore rc16 e manifest verificato.',
                           'L’AI non può attribuire policy di business o autorizzazioni.']}


def allowlisted_agent_intentions(authorization_plan: dict[str, Any], *,
                                  approved_manifest: bool = False,
                                  approve_writes: bool = False,
                                  requested_categories: list[str] | None = None) -> dict[str, Any]:
    """Deterministic bound between AI recommendations and available engines.

    No arbitrary operation, URL, identity, request body or method may be added
    by an LLM. Even an approved intention is not permission to execute.
    """
    selected = set(requested_categories or ['BOLA','BFLA','BOPLA_MASS_ASSIGNMENT'])
    allowed = {'BOLA','BFLA','BOPLA_MASS_ASSIGNMENT'}
    if selected - allowed:raise ValueError('Agent requested an unsupported authorization category')
    approved = []
    blocked = []
    for item in authorization_plan.get('test_cases',[]):
        if item.get('category') not in selected:continue
        ready = item.get('category')=='BOLA' and item.get('status')=='ready_to_review'
        if item.get('effect')=='write':
            ready=bool(approved_manifest and approve_writes and
                       item.get('status')=='ready_to_review')
        row={'category':item['category'],'operation':item['operation'],'workflow':item['workflow']}
        (approved if ready else blocked).append(row)
    return {'engine':'achilles-agent-authorization-guard-rc21','approved_intentions':approved,
            'blocked_intentions':blocked,'executed':False,'requests_sent':0,
            'note':'Le intenzioni approvate devono comunque superare preflight, scope e budget degli engine esistenti.'}
