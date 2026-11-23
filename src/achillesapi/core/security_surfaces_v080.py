"""Non-exploiting OpenAPI security surface discovery for triage."""
from __future__ import annotations

import re
from typing import Any
from achillesapi.core.openapi import parse_openapi


def security_surfaces(spec: dict[str, Any]) -> dict[str, Any]:
    parsed=parse_openapi(spec)
    candidates=[]
    for ep in parsed.endpoints[:2000]:
        method=ep.method.upper()
        path=ep.path
        params=[p.name for p in ep.parameters]
        checks=[]
        if re.search(r'\{(?:[^{}]*id|uuid|key|number|ref)[^{}]*\}',path,re.I):
            checks.append('Object-level authorization: confirm ownership with two authorized identities')
        if method in {'POST','PATCH','PUT'}:
            checks.append('Mass assignment / write-property constraints: requires disposable fixture')
        if any(re.search(r'(search|filter|sort|query|where|id)',param,re.I) for param in params):
            checks.append('Input validation and injection hypothesis: requires safe test values')
        if method in {'DELETE','POST','PATCH','PUT'}:
            checks.append('Function-level authorization: requires trusted role policy')
        if not ep.security and not ep.security_is_explicitly_disabled:
            checks.append('Authentication requirement unknown: confirm security baseline')
        if checks:
            candidates.append({'operation':method+' '+path, 'checks':checks,
                               'state':'requires_review', 'confirmed_vulnerability':False})
    return {'engine':'achilles-security-surface-v080','requests_sent':0,
            'summary':{'operations':len(parsed.endpoints),'candidates':len(candidates)},
            'candidates':candidates,
            'limitations':['Hypotheses from API structure only; no exploit requests sent.',
                           'Do not interpret a candidate as a verified finding.',
                           'All active checks remain controlled by approved scope and request limits.']}
