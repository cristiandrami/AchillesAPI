"""OpenAPI-driven workspace preflight, entirely offline, with typed readiness.

Only the server and an approved fixture can establish ownership or authorize
mutations. This planner never guesses business policy, credentials, or IDs.
"""
from __future__ import annotations

import re
from typing import Any

from achillesapi.core.diagnostics_rc20 import diagnose
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.workflow_automation_rc16 import discover_resource_workflows
from achillesapi.core.rc15_security import discover as scanner_points, relevant

_PARAMS = re.compile(r'\{([^{}]+)\}')


def build_workspace(spec: dict[str, Any], *, has_auth: bool = False,
                    has_policy: bool = False, has_fixture: bool = False,
                    has_scope: bool = False, http_approved: bool = False,
                    writes_approved: bool = False, ai_available: bool = False) -> dict[str, Any]:
    """Produce explicit, per-family actionable prerequisites from one Swagger."""
    parsed = parse_openapi(spec)
    operations = []
    for ep in parsed.endpoints:
        required_query = [p.name for p in ep.parameters if p.location == 'query' and p.required]
        required_path = _PARAMS.findall(ep.path)
        operations.append({'operation': f'{ep.method} {ep.path}', 'method': ep.method,
            'path': ep.path, 'required_path_parameters': required_path,
            'required_query_parameters': required_query,
            'security_declared': bool(ep.security),
            'requires_fixture': ep.method in {'POST','PATCH','PUT','DELETE'}})
    discovered = discover_resource_workflows(spec, max_candidates=100)
    eligible = discovered['candidates']
    points = scanner_points(spec, max_points=250)
    families = ('sql_error','sql_boolean','nosql','ssti','command','xpath','ldap',
                'crlf','xss','ssrf','xxe','path_traversal','open_redirect','file_upload')
    scanner_counts = {family: sum(relevant(point,family) for point in points)
                      for family in families}
    groups = []
    def add(name: str, available: bool, missing: list[str], total: int,
            reason: str = '') -> None:
        readiness = ('not_applicable' if not available else
                     'ready' if not missing else 'requires_input')
        groups.append({'id': name, 'status': readiness, 'candidate_count': total,
                       'issues': [diagnose(code,action=name) for code in dict.fromkeys(missing)],
                       'note': reason})
    add('openapi', True, [], len(operations))
    add('read_only_http', any(e['method']=='GET' for e in operations),
        ([] if has_scope and http_approved else
         (['SCOPE_REQUIRED'] if not has_scope else [])+
         (['HTTP_CONSENT_REQUIRED'] if not http_approved else [])),
        sum(e['method']=='GET' for e in operations))
    add('bola', any(e['method']=='GET' and e['required_path_parameters'] for e in operations),
        (['AUTH_REQUIRED'] if not has_auth else [])+
        (['POLICY_REQUIRED'] if not has_policy else [])+
        ([] if has_scope and http_approved else ['SCOPE_REQUIRED','HTTP_CONSENT_REQUIRED']),
        sum(e['method']=='GET' and bool(e['required_path_parameters']) for e in operations))
    has_mutable = bool(eligible)
    writes = ((['AUTH_REQUIRED'] if not has_auth else []) +
              (['WORKFLOW_REQUIRED'] if not has_fixture else []) +
              (['WRITES_CONSENT_REQUIRED'] if not writes_approved else []) +
              (['SCOPE_REQUIRED'] if not has_scope else []) +
              (['HTTP_CONSENT_REQUIRED'] if not http_approved else []))
    add('bfla',has_mutable,list(writes)+(['POLICY_REQUIRED'] if not has_policy else []),
        len(eligible))
    add('mass_assignment',any(x['mutations'] for x in eligible),
        list(writes)+(['PATCH_FIELDS_REQUIRED'] if not has_policy else []),
        sum(bool(x['mutations']) for x in eligible))
    add('disposable_workflows',has_mutable,writes,len(eligible))
    add('scanners',bool(points),
        ([] if has_scope and http_approved else ['SCOPE_REQUIRED','HTTP_CONSENT_REQUIRED']),
        len(points), 'Le sonde su body e upload richiedono fixture e cleanup separati.')
    add('local_ai',bool(points),(['AI_UNAVAILABLE'] if not ai_available else []),len(points))
    return {'engine':'achilles-workspace-autopilot-rc20', 'requests_sent':0,
            'api':{'title':parsed.title,'version':parsed.version,
                   'operations':len(operations)},
            'operations': operations,'workflow_candidates':eligible,
            'scanner_parameter_counts':scanner_counts,
            'groups':groups,'ready_groups':[g['id'] for g in groups if g['status']=='ready'],
            'requires_input_groups':[g['id'] for g in groups if g['status']=='requires_input'],
            'assumptions':['Lo Swagger non prova le autorizzazioni business.',
                           'La presenza di POST/DELETE non prova che sia sicuro creare e cancellare.',
                           'I check attivi richiedono consenso, target in scope e budget.']}
