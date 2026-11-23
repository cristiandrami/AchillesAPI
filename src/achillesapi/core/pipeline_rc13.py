"""RC10–RC13: orchestrazione incrementale, non modifica i motori legacy.

Dry-run preflight di tutti i sottosistemi prima di inviare traffico;
nessuna scrittura senza manifest approvato; Ollama solo advisory.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from achillesapi.core.openapi import load_openapi, parse_openapi
from achillesapi.core.coverage_rc13 import coverage_catalog, execution_coverage
from achillesapi.core.injection_engine_rc5 import injection_assessment
from achillesapi.core.injection_planner_v2 import injection_surface_plan
from achillesapi.core.advanced_get_rc11 import advanced_get_scan
from achillesapi.core.active_scanners_rc15 import scan_bounded_get
from achillesapi.core.verification_replay import replay_readonly_indicators
from achillesapi.core.agent_adaptive_v3 import allowed_agent_decisions
from achillesapi.core.access_matrix_rc4 import read_rules, preflight_rules, run_access_matrix
from achillesapi.core.auth import load_authentication_manager
from achillesapi.core.workflows import read_workflows, workflow_plan, run_workflows
from achillesapi.core.body_probes_rc11 import (body_probe_plan, run_body_probes,
    resource_probe_options, resource_body_probe_plan, run_resource_body_probes)
from achillesapi.core.multi_resource import (load_multi_resource_config,
    plan_multi_resource, run_multi_resource)
from achillesapi.core.security_capability_rc14 import capability_inventory
from achillesapi.core.rc15_security import discover as rc15_discover, scan_rc15
from achillesapi.core.verification_rc14 import review_evidence
from achillesapi.core.verification_engine_rc17 import verify_campaign_findings
from achillesapi.core.agent_runtime_rc17 import run_adaptive_agent


class PipelineError(ValueError):
    pass


_AUTH_POLICY_CONFLICTS = frozenset({
    'policy_conflict_requires_review', 'authorization_policy_conflict',
    'owner_policy_conflict_requires_review', 'other_policy_conflict_requires_review',
    'both_policy_conflict_requires_review',
})


def authorization_findings(stage: dict[str, Any]) -> list[dict[str, Any]]:
    """Preserve all per-identity policy conflicts, including deny/deny.

    Only a recorded matrix mismatch is emitted. No severity upgrade or
    vulnerability confirmation is derived from a status code alone.
    """
    results: list[dict[str, Any]] = []
    for rule in stage.get('rules', []):
        if not isinstance(rule, dict) or rule.get('status') not in _AUTH_POLICY_CONFLICTS:
            continue
        participants = []
        for obs in rule.get('observations', []):
            if not isinstance(obs, dict):
                continue
            profile = obs.get('identity')
            participants.append({
                'profile': profile, 'status_code': obs.get('status_code'),
                'expected': rule.get('expected_owner') if profile == rule.get('owner')
                            else rule.get('expected_other'),
            })
        results.append({
            'category': 'authorization_policy_conflict',
            'source_engine': 'authorization', 'rule_id': rule.get('id'),
            'operation': rule.get('operation'), 'access_comparison': participants,
            'severity': 'medium', 'verification_status': 'requires_manual_review',
            'reason': 'La matrice ha registrato una risposta incompatibile con la policy allow/deny.',
            'test_payloads': [], 'evidence': {'same_body_observed': rule.get('same_body_observed')},
        })
    return results


def _load_fixture(path: Path | None) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Use the existing strict validators for both dashboard and RC13 CLI manifests."""
    if path is None:
        return [], None
    manifest = load_multi_resource_config(path)
    if set(manifest) == {'resources'}:
        return [], manifest
    if set(manifest) == {'workflows'}:
        return read_workflows(path), None
    raise PipelineError('Manifest RC13: usa resources.yaml del wizard o workflows.yaml della CLI.')


def _scope(base_url: str, hosts: set[str], allow_http: bool) -> None:
    u = urlsplit(base_url)
    if (u.scheme not in {'http', 'https'} or not u.hostname or u.username or u.password
            or u.query or u.fragment or u.hostname.lower().rstrip('.') not in
            {h.lower().rstrip('.') for h in hosts}):
        raise PipelineError('Base URL deve essere assoluto e incluso negli host autorizzati.')
    if u.scheme == 'http' and not allow_http:
        raise PipelineError('HTTP in chiaro richiede autorizzazione esplicita.')
    if any(x in {'.', '..'} for x in u.path.split('/')):
        raise PipelineError('Path base contenente traversal.')


def create_plan(spec_path: Path, *, auth_config: Path | None = None,
                rules_path: Path | None = None, workflow_config: Path | None = None,
                path_values: dict[str, str] | None = None,
                body_probe_fields: list[str] | None = None) -> dict[str, Any]:
    spec = load_openapi(spec_path)
    api = parse_openapi(spec)
    manager = load_authentication_manager(auth_config) if auth_config else None
    if rules_path and not manager:
        raise PipelineError('La matrice richiede auth.yaml.')
    rules = preflight_rules(spec_path, read_rules(rules_path), profile_names=set(manager.names)) if rules_path else []
    workflows, resources = _load_fixture(workflow_config)
    workflow = (workflow_plan(api, spec, workflows, set(manager.names) if manager else None)
                if workflows else plan_multi_resource(api, spec, resources, set(manager.names) if manager else set())
                if resources else None)
    # _prepared holds transient EndpointInfo objects and must never enter JSON reports.
    if workflow is not None:
        workflow = {k: v for k, v in workflow.items() if k != '_prepared'}
    body_options = resource_probe_options(api, spec, resources) if resources else []
    body_plan = (body_probe_plan(api, spec, workflows, set(manager.names) if manager else set())
                 if workflows else
                 resource_body_probe_plan(api, spec, resources, set(manager.names) if manager else set(),
                                          body_probe_fields or []) if resources else None)
    surfaces = injection_surface_plan(spec)
    catalog = coverage_catalog(spec)
    test_types = {
        'injection_get': {'available': True, 'writes': False},
        'advanced_get': {'available': True, 'writes': False},
        'bounded_get_security': {'available': True, 'writes': False, 'techniques': ['redirect', 'reflection', 'path_handling']},
        'authorization_get': {'available': bool(rules), 'rule_count': len(rules), 'writes': False},
        'disposable_workflows': {'available': bool(workflows or resources), 'writes': True,
                                 'reserved_requests': workflow['request_budget_required'] if workflow else 0},
        'body_injection': {'available': bool(body_options or (body_plan and body_plan['cases'])),
                           'ready': bool(body_plan and body_plan['cases']),
                           'requires_field_selection': bool(body_options and not (body_plan and body_plan['cases'])),
                           'cases': len(body_plan['cases']) if body_plan else 0,
                           'requires_extra_approval': True,
                           'reason': 'Solo JSON PATCH su campi stringa esplicitamente approvati; non scanner completo.'},
        'rc15_active_security': {'available': True, 'writes': False,
            'input_points': len(rc15_discover(spec)),
            'techniques': ['XSS reflection', 'open redirect', 'traversal fixture', 'SSRF callback (optional)'],
            'note': 'Write/XML/upload probes use separate RC15 CLI fixtures with explicit approval.'},
        'ai_advisory': {'available': True, 'network_to_target': False},
    }
    return {'engine': 'achilles-rc13-plan', 'api_name': api.title,
            'spec_sha256': hashlib.sha256(spec_path.read_bytes()).hexdigest(),
            'catalog': catalog, 'test_types': test_types,
            'body_injection_plan': surfaces,
            'workflows': workflow, 'body_probe_plan': body_plan, 'body_probe_options': body_options,
            'authorization_rule_count': len(rules),
            'operator_input_needed': [x for x, needed in (
                ('Matrice accessi', not rules), ('Fixture temporanee', not (workflows or resources))) if needed],
            'security_capabilities': capability_inventory(spec),
            'note': 'La pianificazione non produce evidenze di vulnerabilità.'}


def execute_pipeline(spec_path: Path, *, base_url: str, allowed_hosts: set[str],
                     auth_config: Path | None = None, profile: str | None = None,
                     rules_path: Path | None = None, workflow_config: Path | None = None,
                     path_values: dict[str, str] | None = None,
                     execute: bool = False, approve_writes: bool = False,
                     body_probes: bool = False, approve_body_probes: bool = False,
                     body_probe_fields: list[str] | None = None,
                     allow_insecure_http: bool = False, max_requests: int = 150,
                     rate: float = 2., use_ai: bool = False,
                     model: str = 'achilles-local', ollama_url: str = 'http://127.0.0.1:11434',
                     rc15_callback_base: str | None = None, rc15_callback_observer: str | None = None,
                     rc15_fixture_file: str | None = None, rc15_fixture_marker: str | None = None,
                     agent_followups: bool = False, agent_rounds: int = 2,
                     agent_budget: int = 24) -> dict[str, Any]:
    """Coordina motori con budget per stadio; output non confonde ipotesi e prove."""
    if agent_followups and not use_ai:
        raise PipelineError('Agente rc.17: abilita anche --ai per le decisioni Ollama locali.')
    if agent_followups and not execute:
        raise PipelineError('Agente rc.17: esecuzione richiede consenso HTTP --execute.')
    if not 1 <= agent_rounds <= 3 or not 2 <= agent_budget <= 60:
        raise PipelineError('Agente rc.17: round 1-3 e budget da 2 a 60 richieste.')
    if not 1 <= max_requests <= 1000 or not 0.1 <= rate <= 5:
        raise PipelineError('Budget massimo 1000; frequenza fra 0.1 e 5 req/s.')
    if body_probes and not workflow_config:
        raise PipelineError('Le sonde body richiedono un manifest di fixture.')
    if body_probes and execute and (not approve_writes or not approve_body_probes):
        raise PipelineError('Le sonde JSON richiedono due approvazioni esplicite.')
    if approve_writes and not workflow_config:
        raise PipelineError('Le scritture richiedono il manifest di fixture approvate.')
    if workflow_config and execute and not approve_writes:
        raise PipelineError('Manifest fornito ma scritture non approvate: usa --approve-writes.')
    if use_ai and not execute:
        # L'AI può leggere il piano offline, ma il comando lo rende esplicito.
        pass
    plan = create_plan(spec_path, auth_config=auth_config, rules_path=rules_path,
                       workflow_config=workflow_config, path_values=path_values,
                       body_probe_fields=body_probe_fields)
    if not execute:
        empty_stages = {'injection': {'executed': False, 'requests_sent': 0},
                        'advanced_get': {'executed': False, 'requests_sent': 0},
                        'bounded_get_security': {'executed': False, 'requests_sent': 0},
                        'rc15_security': {'executed': False, 'requests_sent': 0}}
        if rules_path:
            empty_stages['authorization'] = {'executed': False, 'requests_sent': 0}
        if workflow_config:
            empty_stages['workflows'] = {'executed': False, 'requests_sent': 0}
        return {'engine': 'achilles-rc13-campaign', 'version': '1.0.0rc17',
                'api_name': plan['api_name'], 'executed': False,
                'requests_sent': 0, 'request_budget': max_requests,
                'stages': empty_stages, 'findings': [],
                'security_capabilities': plan['security_capabilities'],
                'verification': review_evidence([]),
                'verification_rc17': verify_campaign_findings([]),
                'agent_rc17': {'status': 'not_invoked_offline', 'requests_sent': 0},
                'ai': {'status': 'not_invoked_offline'},
                'coverage': execution_coverage(plan['catalog'], empty_stages),
                'plan': plan,
                'limitations': ['Solo pianificazione offline: non sono state inviate richieste HTTP.']}
    _scope(base_url, allowed_hosts, allow_insecure_http)
    spec = load_openapi(spec_path)
    parsed = parse_openapi(spec)
    manager = load_authentication_manager(auth_config) if auth_config else None
    if profile and (not manager or profile not in manager.names):
        raise PipelineError('Profilo non disponibile in auth.yaml.')
    workflows, resources = _load_fixture(workflow_config)
    if body_probes and resources and not body_probe_fields:
        raise PipelineError('Seleziona i campi PATCH nel wizard sonde JSON: non serve caricare workflows.yaml.')
    wf_budget = (plan['workflows'] or {}).get('request_budget_required', 0)
    body_budget = (plan.get('body_probe_plan') or {}).get('request_budget_required', 0) if body_probes else 0
    matrix_budget = 2 * plan['authorization_rule_count']
    # Due sotto-motori di sola lettura ricevono quote isolate.
    # Reserve capacity before the first network call: the agent cannot borrow
    # requests promised to fixture cleanup or authorization comparisons.
    reserved_agent = agent_budget if agent_followups else 0
    if agent_followups and max_requests - wf_budget - body_budget - matrix_budget - reserved_agent < 5:
        raise PipelineError('Budget insufficiente: riserva almeno 5 GET oltre alle richieste AI e cleanup.')
    get_budget = max(0, max_requests - wf_budget - body_budget - matrix_budget - reserved_agent)
    if get_budget >= 30:
        # rc24 allocates enough capacity for independent GET scanners to reach
        # later operations, rather than limiting RC15 to 24 HTTP requests.
        # These are caps, not guarantees: every engine still enforces its own
        # request/rate scope, and skipped_budget remains visible in its report.
        injection_budget = min(90, max(10, round(get_budget * .35)))
        advanced_budget = min(40, max(5, round(get_budget * .1)))
        bounded_get_budget = min(30, max(2, round(get_budget * .1)))
        rc15_budget = max(0, get_budget - injection_budget - advanced_budget - bounded_get_budget)
    else:
        injection_budget = max(0, get_budget - min(20, get_budget // 4))
        advanced_budget = get_budget - injection_budget
        bounded_get_budget = min(12, max(0, advanced_budget // 2)) if advanced_budget >= 4 else 0
        advanced_budget -= bounded_get_budget
        rc15_budget = min(24, max(0, advanced_budget // 2)) if advanced_budget >= 6 else 0
        advanced_budget -= rc15_budget
    if execute and wf_budget + body_budget + matrix_budget + get_budget > max_requests:
        raise PipelineError('Budget totale insufficiente per fixture e matrice.')
    if execute and (injection_budget < 3 or advanced_budget < 2):
        raise PipelineError('Servono almeno cinque richieste disponibili dopo le riserve dei workflow e della matrice.')
    stages: dict[str, dict[str, Any]] = {}
    if execute or injection_budget >= 1:
        stages['injection'] = injection_assessment(spec_path, base_url=base_url,
            allow_hosts=allowed_hosts, path_values=path_values or {}, auth_manager=manager,
            profile=profile, execute=execute, allow_insecure_http=allow_insecure_http,
            max_requests=max(1, min(150, injection_budget)), rate=rate)
        # Include solo le GET, non POST/PATCH: limiti sempre espliciti.
    if advanced_budget >= 1:
        material = manager.resolve(profile, allowed_hosts=allowed_hosts,
                allow_insecure_http=allow_insecure_http) if execute and profile else None
        stages['advanced_get'] = advanced_get_scan(spec, base_url=base_url,
            allow_hosts=allowed_hosts, execute=execute,
            allow_insecure_http=allow_insecure_http,
            max_requests=max(1, advanced_budget), rate=rate,
            path_values=path_values, auth=material)
    if bounded_get_budget >= 2:
        material = manager.resolve(profile, allowed_hosts=allowed_hosts,
            allow_insecure_http=allow_insecure_http) if execute and profile else None
        stages['bounded_get_security'] = scan_bounded_get(spec, base_url=base_url,
            allowed_hosts=allowed_hosts, execute=execute,
            max_requests=bounded_get_budget, rate=rate,
            path_values=path_values, auth=material)
    if rc15_budget >= 2:
        material = manager.resolve(profile, allowed_hosts=allowed_hosts,
            allow_insecure_http=allow_insecure_http) if execute and profile else None
        stages['rc15_security'] = scan_rc15(spec, base_url=base_url,
            allowed_hosts=allowed_hosts, execute=execute,
            max_requests=rc15_budget, rate=rate, auth=material,
            path_values=path_values, callback_base=rc15_callback_base,
            callback_observer=rc15_callback_observer,
            fixture_file=rc15_fixture_file, fixture_marker=rc15_fixture_marker,
            families=('open_redirect', 'xss', 'path_traversal', 'ssrf'))
    if rules_path:
        stages['authorization'] = run_access_matrix(spec_path, policy=read_rules(rules_path),
            base_url=base_url, allowed_hosts=allowed_hosts,
            auth_manager=manager, execute=execute,
            allow_insecure_http=allow_insecure_http,
            max_requests=max(2, matrix_budget), rate=rate)
    if workflows or resources:
        identities = {name: None for name in manager.names} if manager else {}
        if execute:
            if not manager:
                raise PipelineError('Il workflow richiede auth.yaml.')
            selected = ({name for wf in workflows for name in
                ([wf['create']['identity'], wf['read']['identity'], wf['cleanup']['identity']]
                 + [a['identity'] for a in wf.get('access', [])]
                 + [m['identity'] for m in wf.get('mutations', [])]
                 + ([wf['mutation']['identity']] if wf.get('mutation') else []))}
                if workflows else {item['identity'] for item in resources['resources']}
                | {check['identity'] for item in resources['resources'] for check in item.get('access', [])}
                | {check['identity'] for item in resources['resources'] for check in item.get('write_checks', [])})
            identities = {name: manager.resolve(name, allowed_hosts=allowed_hosts,
                    allow_insecure_http=allow_insecure_http) for name in selected}
        if workflows:
            stages['workflows'] = run_workflows(parsed, spec, workflows,
                base_url=base_url, allowed_hosts=allowed_hosts, identities=identities,
                execute=execute, approve_writes=approve_writes,
                allow_insecure_http=allow_insecure_http,
                max_requests=max(1, wf_budget), rate=rate)
        else:
            stages['workflows'] = run_multi_resource(parsed, spec, resources,
                base_url=base_url, allowed_hosts=allowed_hosts, identities=identities,
                execute=execute, approve_writes=approve_writes,
                allow_insecure_http=allow_insecure_http,
                max_requests=max(1, wf_budget), rate=rate)
    if body_probes and (workflows or resources):
        if not execute:
            raise PipelineError('L’esecuzione body probes richiede --execute')
        if not identities:
            raise PipelineError('Le sonde JSON richiedono profili autorizzati.')
        if stages.get('workflows', {}).get('manual_cleanup_required'):
            stages['body_probes'] = {'executed': False, 'requests_sent': 0, 'results': [],
                                    'findings': [], 'status': 'blocked_cleanup_required',
                                    'reason': 'Il workflow iniziale richiede cleanup manuale: nessuna sonda aggiuntiva inviata.'}
        else:
            stages['body_probes'] = (run_body_probes(parsed, spec, workflows,

            identities=identities, base_url=base_url, allowed_hosts=allowed_hosts,
            execute=True, approve_writes=approve_writes,
            approve_body_probes=approve_body_probes,
            allow_insecure_http=allow_insecure_http,
            max_requests=body_budget, rate=rate) if workflows else
            run_resource_body_probes(parsed, spec, resources,
                selections=body_probe_fields or [], identities=identities,
                base_url=base_url, allowed_hosts=allowed_hosts, execute=True,
                approve_writes=approve_writes, approve_body_probes=approve_body_probes,
                allow_insecure_http=allow_insecure_http, max_requests=body_budget, rate=rate))
    if 'body_probes' in stages:
        # Both legacy workflows.yaml and dashboard resources.yaml expose the
        # control PATCH status, but under different result collections.
        baseline_rows = (stages.get('workflows', {}).get('workflows', []) +
                         stages.get('workflows', {}).get('resources_results', []))
        baselines = {w.get('name'): next((o.get('status') for o in w.get('observations', [])
                    if o.get('step') in {'restricted_field_mutation', 'mutation'}), None)
                    for w in baseline_rows}
        for record in stages['body_probes']['results']:
            baseline = baselines.get(record['workflow'])
            response = next((o.get('status') for o in record.get('response_evidence', [])
                            if o.get('step') in {'restricted_field_mutation', 'mutation'}), None)
            if (isinstance(baseline, int) and 200 <= baseline < 300 and
                    isinstance(response, int) and response >= 500 and
                    record.get('cleanup_verified')):
                stages['body_probes'].setdefault('findings', []).append({
                    'category': 'possible_json_input_processing_error',
                    'workflow': record['workflow'], 'field': record['field'],
                    'operation': record.get('operation'),
                    'test_payloads': [record['payload']], 'severity': 'informational',
                    'verification_status': 'requires_manual_review',
                    'evidence': {'control_status': baseline, 'probe_status': response,
                                 'cleanup_verified': True},
                    'reason': ('Il body PATCH modificato con il payload ha prodotto HTTP 5xx, ' +
                               'mentre il PATCH di controllo ha restituito 2xx. ' +
                               'Il cleanup è verificato; si tratta di un indicatore da approfondire, non di injection confermata.')})
    ai_state: dict[str, Any] = {'status': 'not_requested', 'network_to_target': False}
    if use_ai:
        try:
            from achillesapi.ai.local import analyze_with_ollama, LocalAIError
            # Only schema/metadata and sanitized findings, no auth objects or raw HTTP bodies.
            findings = [f for stage in stages.values() for f in stage.get('findings', [])]
            analysis = analyze_with_ollama(parsed, findings[:60], endpoint=ollama_url, model=model)
            ai_state = {'status': 'completed_local', 'model': model,
                        'analysis': analysis, 'verification_status': 'ai_hypothesis_only'}
        except (ValueError, OSError, LocalAIError) as exc:
            ai_state = {'status': 'failed', 'error_type': type(exc).__name__,
                        'message': 'Ollama locale non raggiungibile o output non valido.'}
    agent_advice = allowed_agent_decisions(
        ai_state.get('analysis') if ai_state.get('status') == 'completed_local' else None,
        available=plan['test_types'], approved_writes=approve_writes,
        approved_body_probes=approve_body_probes, executed=stages)
    if ai_state.get('status') == 'completed_local':
        ai_state['agent_plan'] = agent_advice
    findings = [{**f, 'source_engine': name,
                 'verification_status': f.get('verification_status', 'requires_manual_review')}
                for name, stage in stages.items() for f in stage.get('findings', [])]
    # Le osservazioni della matrice sono strutturate in rules, NON in findings.
    # Non perdere i conflitti, e non presentarli come vulnerabilità confermate.
    findings.extend(authorization_findings(stages.get('authorization', {})))
    # The resources.yaml engine records authorization and field-policy findings
    # at stage top-level, unlike workflows.yaml. Preserve both formats.
    for observation in stages.get('workflows', {}).get('findings', []):
        findings.append({**observation, 'source_engine': 'workflows',
                         'verification_status': observation.get('verification_status', 'requires_manual_review')})
    for flow in stages.get('workflows', {}).get('workflows', []):
        for observation in flow.get('findings', []):
            findings.append({**observation, 'source_engine': 'workflows',
                'workflow': flow.get('name'), 'verification_status': 'requires_manual_review'})
    # Reproduce selected GET indicators with a second independent comparison.
    # This consumes only otherwise-unallocated HTTP budget and NEVER confirms an exploit.
    already_used = sum(int(stage.get('requests_sent', 0)) for stage in stages.values())
    if execute and max_requests - already_used >= 4:
        repeatable = [f for f in findings if f.get('source_engine') == 'injection']
        if repeatable:
            material = manager.resolve(profile, allowed_hosts=allowed_hosts,
                allow_insecure_http=allow_insecure_http) if manager and profile else None
            stages['verification_replay'] = replay_readonly_indicators(spec,
                repeatable, base_url=base_url, allowed_hosts=allowed_hosts,
                auth=material, path_values=path_values,
                max_requests=min(4, max_requests-already_used), rate=rate)
    agent_report: dict[str, Any] = {'status': 'not_requested', 'requests_sent': 0}
    if agent_followups:
        if any(stage.get('manual_cleanup_required') for stage in stages.values()):
            agent_report = {'status': 'blocked_cleanup_required', 'requests_sent': 0}
        elif ai_state.get('status') != 'completed_local':
            agent_report = {'status': 'blocked_ai_unavailable', 'requests_sent': 0}
        else:
            material = manager.resolve(profile, allowed_hosts=allowed_hosts,
                allow_insecure_http=allow_insecure_http) if manager and profile else None
            already_used = sum(int(stage.get('requests_sent', 0)) for stage in stages.values())
            allocation = min(agent_budget, max_requests - already_used)
            agent_report = run_adaptive_agent(spec_path, base_url=base_url,
                allowed_hosts=allowed_hosts, auth=material,
                path_values=path_values, known_findings=findings, prior_stages=stages,
                approved_http=True, execute=True, remaining_requests=allocation,
                max_rounds=agent_rounds, rate=rate, allow_insecure_http=allow_insecure_http,
                endpoint=ollama_url, model=model)
            stages['agent_followups'] = agent_report
            findings.extend(agent_report['findings'])
    sent = sum(int(stage.get('requests_sent', 0)) for stage in stages.values())
    if sent > max_requests:
        raise PipelineError('Budget HTTP globale superato: risultato scartato')
    return {'engine': 'achilles-rc13-campaign', 'version': '1.0.0rc17',
            'api_name': parsed.title, 'executed': execute,
            'requests_sent': sent, 'request_budget': max_requests,
            'stages': stages, 'findings': findings, 'ai': ai_state, 'agent_advice': agent_advice,
            'security_capabilities': plan['security_capabilities'],
            'verification': review_evidence(findings),
            'verification_rc17': verify_campaign_findings(findings, stages=stages),
            'agent_rc17': agent_report,
            'coverage': execution_coverage(plan['catalog'], stages),
            'manual_cleanup_required': any(stage.get('manual_cleanup_required', False) for stage in stages.values()),
            'limitations': [
                'La copertura indica operazioni verificate, non la sicurezza complessiva.',
                'Le sonde JSON PATCH usano fixture approvate; body XML/form/POST richiedono manifest e verifiche aggiuntive.',
                'BFLA/Mass Assignment richiedono regole e manifest di scrittura espliciti.',
                'Redirect, riflessione HTML e gestione path: sonde GET conservative. SSRF, XXE, upload e race condition non sono confermati automaticamente.',
                'Le osservazioni del modello locale non sono vulnerabilità confermate.',
                'RC17: l’agente non esegue mai scritture e sceglie solo motori GET già registrati.',
            ], 'plan': {k: v for k,v in plan.items() if k not in ('catalog', 'body_injection_plan')}}
