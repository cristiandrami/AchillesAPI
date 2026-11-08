"""Version 2 adaptive decision policy: finite, auditable and scope-preserving.

This module consumes only redacted observations and never executes model text.
The optional LLM remains advisory; requests are delegated to the existing
scoped follow-up executor after all preflight checks.
"""
from __future__ import annotations
from typing import Any
from achillesapi.core.orchestrator import choose_followups, run_followups
from achillesapi.models.api import ParsedAPI
from achillesapi.core.auth import AuthenticationMaterial


def agent_v2_plan(parsed: ParsedAPI, plan: dict[str,Any], observations: list[dict[str,Any]],
                  *, budget:int=5) -> dict[str,Any]:
    """Select bounded existing GET follow-ups, explain each stopping condition."""
    if not isinstance(observations,list):
        raise ValueError('Expected observation list')
    choice=choose_followups(parsed,plan,observations,budget=budget)
    return {'engine':'agent-v2-v0.37', 'budget':budget,
            'actions':choice['actions'], 'requests_sent':0,
            'decision_policy':'Only pre-existing OpenAPI GET requests with known parameters; no model-authored targets.',
            'stop_reason':'no_supported_candidate' if not choice['actions'] else 'awaiting_operator_execute',
            'interpretation':('No qualifying 5xx or anonymous-access anomaly was present in the recorded HTTP observations. '
                              'No target request was sent; this is not a vulnerability scan.'
                              if not choice['actions'] else
                              'The listed GET follow-ups need explicit scope and execution authorization.'),
            'model_authorizes_requests':False}


def agent_v2_execute(parsed:ParsedAPI, plan:dict[str,Any], observations:list[dict[str,Any]], *,
                     base_url:str, allowed_hosts:set[str],
                     identities:dict[str,AuthenticationMaterial]|None=None,
                     path_values:dict[str,str]|None=None,
                     budget:int=5, rate:float=1., timeout:float=8.,
                     allow_insecure_http:bool=False,execute:bool=False)->dict[str,Any]:
    """Run up to two observe/verify cycles with a strict global request budget.

    Each action is revisited at most twice. A 5xx becoming 2xx stops immediately.
    A persistent 5xx is merely reproducible behavior, never called SQLi or RCE.
    """
    state=agent_v2_plan(parsed,plan,observations,budget=budget)
    if not execute or not state['actions'] or budget==0:
        return {**state,'executed':False,'rounds':[],'requests_sent':0}
    first=run_followups(parsed,plan,observations,base_url=base_url,allowed_hosts=allowed_hosts,
                        identities=identities,path_values=path_values,budget=budget,rate=rate,
                        timeout=timeout,allow_insecure_http=allow_insecure_http,execute=True)
    used=first['network_requests_sent']
    rounds=[{'round':1,'result':first}]
    # Recheck only still-unresolved 5xx, once more, using existing observations.
    unresolved=[{'operation':obs['operation'],'identity':obs['identity'],
                 'check':'baseline','status':obs['status']}
                for obs in first.get('observations',[])
                if obs.get('reason')=='recheck_server_error' and obs.get('repeated')
                and isinstance(obs.get('status'),int) and obs['status']>=500]
    if unresolved and used<budget:
        second=run_followups(parsed,plan,unresolved,base_url=base_url,
              allowed_hosts=allowed_hosts,identities=identities,path_values=path_values,
              budget=budget-used,rate=rate,timeout=timeout,
              allow_insecure_http=allow_insecure_http,execute=True)
        used+=second['network_requests_sent']
        rounds.append({'round':2,'result':second})
    return {**state,'executed':True,'requests_sent':used,'rounds':rounds,
            'stop_reason':'budget_or_two_round_limit',
            'confirmed_vulnerabilities':0}
