"""RC22 independent-control evaluation for authorization and anomaly evidence.

Accepts only a compact pre-redacted evidence schema. A match of HTTP status
or an LLM claim alone cannot prove exploitation. Repeated negative control,
owner readback and explicit business policy are required for confirmation.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_VALID = {'allow','deny'}


def verify_controlled_cases(cases: list[dict[str, Any]], *, max_cases: int = 500) -> dict[str, Any]:
    if not isinstance(cases,list) or len(cases)>max_cases or max_cases<1 or max_cases>1000:
        raise ValueError('Invalid controlled evidence array')
    observations = []
    seen: set[str] = set()
    for i,item in enumerate(cases):
        if not isinstance(item,dict):raise ValueError('Evidence entries must be objects')
        operation=str(item.get('operation',''))[:180]
        if not re.fullmatch(r'(?:GET|POST|PATCH|PUT|DELETE|HEAD|OPTIONS) /[^\s?#]{1,150}',operation):
            raise ValueError('Evidence operation must be an OpenAPI-style METHOD /path')
        category=str(item.get('category','authorization'))[:60]
        if not re.fullmatch(r'[A-Za-z0-9_. -]{1,60}',category):
            raise ValueError('Invalid evidence category')
        control=item.get('control',{})
        attempt=item.get('attempt',{})
        replay=item.get('replay',{})
        if not all(isinstance(x,dict) for x in (control,attempt,replay)):
            raise ValueError('Evidence controls must be objects')
        key=hashlib.sha256(json.dumps([operation,category,item.get('case_id')],
                            sort_keys=True,default=str).encode()).hexdigest()[:20]
        if key in seen:continue
        seen.add(key)
        expected=item.get('expected_other')
        owner_ok=control.get('owner_status') in (200,201,206) and control.get('marker_verified') is True
        other_access=attempt.get('other_status') in (200,201,206) and attempt.get('marker_verified') is True
        # An independent negative control ensures the marker was NOT merely a
        # static text or globally public response. Its proof must be supplied.
        negative_ok=control.get('negative_control_denied') is True
        repeat_ok=replay.get('same_identity') is True and replay.get('same_object_marker') is True
        if expected not in _VALID:
            status='inconclusive'; rationale='Business policy not supplied by operator'
        elif not owner_ok:
            status='inconclusive'; rationale='Owner read-back and object marker not established'
        elif expected=='allow':
            status='observed_expected' if other_access else 'potential_policy_mismatch'
            rationale='Expected shared access' if other_access else 'Expected shared access not observed'
        elif not other_access:
            status='observed_expected'; rationale='Access denied or owned marker not present'
        elif negative_ok and repeat_ok:
            status='confirmed_policy_violation'; rationale='Explicit deny policy, owner/other marker, replay and negative control'
        elif repeat_ok:
            status='probable_policy_violation'; rationale='Repeated unauthorized object marker; independent negative control missing'
        else:
            status='potential_policy_violation'; rationale='Single authorization indicator; replay and controls required'
        observations.append({'id':key,'case_index':i,'operation':operation,
                             'category':category,'status':status,'rationale':rationale,
                             'controls':{'owner_marker':owner_ok,'other_marker':other_access,
                                         'negative_control':negative_ok,'replay':repeat_ok}})
    statuses=sorted({row['status'] for row in observations})
    return {'engine':'achilles-controlled-verifier-rc22','network_requests_sent':0,
            'unique_cases':len(observations),
            'classification_counts':{s:sum(x['status']==s for x in observations) for s in statuses},
            'observations':observations,
            'limitations':['La conferma si riferisce soltanto alla policy esplicita e alle prove fornite.',
                           'Il verificatore non invia richieste e non verifica l’autenticità dei record esterni.',
                           'Servono evidenze HTTP acquisite da scanner autorizzati.']}
