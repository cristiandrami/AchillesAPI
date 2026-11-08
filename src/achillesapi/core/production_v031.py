"""Offline production readiness helpers introduced in v0.28–v0.31.

No function in this module contacts an API. Separate planning, scope validation,
coverage metrics and differential evidence checks from network execution.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
import json
import re

import yaml

from achillesapi.models.api import ParsedAPI


class AssessmentPolicyError(ValueError):
    """An assessment or workflow manifest is unsafe or structurally invalid."""


def scope_audit(base_url: str, allowed_hosts: list[str], *, allowed_cidrs: list[str] | None = None) -> dict[str, Any]:
    """Check URL and exact hostname allowlist without issuing network requests.

    CIDRs validate syntax and may be supplied to the network guard later. A
    hostname is NOT considered to be inside a CIDR until DNS has been checked.
    """
    parts = urlsplit(base_url)
    hosts = {str(h).strip().lower().rstrip('.') for h in allowed_hosts}
    reasons = []
    if parts.scheme not in {'http', 'https'} or not parts.hostname:
        reasons.append('Base URL must be absolute HTTP(S).')
    if parts.username or parts.password or parts.query or parts.fragment:
        reasons.append('Credentials, query and fragment are not permitted in base URL.')
    if parts.hostname and parts.hostname.lower().rstrip('.') not in hosts:
        reasons.append('Base hostname is absent from explicit allowlist.')
    if parts.path and any(segment in {'.', '..'} for segment in parts.path.split('/')):
        reasons.append('Base path contains traversal segments.')
    if '\\' in base_url or re.search(r'%(?:2e|2f|5c)', base_url, re.I):
        reasons.append('Base URL contains encoded ambiguous path characters.')
    if not hosts or any(not h or '/' in h or ':' in h and not h.startswith('[') for h in hosts):
        reasons.append('Host allowlist is invalid or empty.')
    cidrs = []
    for raw in allowed_cidrs or []:
        try:
            cidrs.append(str(ip_network(raw, strict=False)))
        except ValueError as exc:
            raise AssessmentPolicyError(f'Invalid approved CIDR {raw!r}') from exc
    literal_ip = None
    try:
        if parts.hostname:
            literal_ip = ip_address(parts.hostname)
    except ValueError:
        pass
    if literal_ip is not None and cidrs and not any(literal_ip in ip_network(net) for net in cidrs):
        reasons.append('Literal IP is outside all approved CIDR ranges.')
    return {'engine': 'scope-audit-v0.31', 'approved': not reasons,
            'base_url': urlunsplit((parts.scheme, (parts.hostname or '') + (f':{parts.port}' if parts.port else ''), parts.path, '', '')),
            'host': parts.hostname, 'approved_hosts': sorted(hosts),
            'approved_cidrs': cidrs, 'reasons': reasons, 'requests_sent': 0,
            'limitations': ['DNS is not resolved in offline audit; IP allowlisting must be enforced at execution time.',
                            'An allowlisted hostname is not an authorization to test all its paths.']}


def _normalize_operation(method: Any, path: Any) -> str | None:
    """Return canonical METHOD /path, rejecting malformed saved observations."""
    if not isinstance(method, str) or not isinstance(path, str):
        return None
    if not re.fullmatch(r'/?[a-zA-Z]+', method) or not path.startswith('/'):
        return None
    return f'{method.lstrip("/").upper()} {path}'


def coverage_report(parsed: ParsedAPI, assessment: dict[str, Any]) -> dict[str, Any]:
    """Report declared vs attempted operations and why coverage is incomplete.

    Never inflate endpoint coverage from a generated test plan or 2xx status:
    an operation counts as observed only when an execution observation exists.
    """
    declared = {f'{ep.method} {ep.path}' for ep in parsed.endpoints}
    plan = assessment.get('plan', {})
    plan_ops = plan.get('operations', []) if isinstance(plan, dict) else []
    plan_by_op = {f"{x.get('method')} {x.get('path')}": x for x in plan_ops if isinstance(x, dict)}
    sources = []
    for key in ('execution_report', 'workflow_execution', 'journey_execution'):
        entry = assessment.get(key)
        if isinstance(entry, dict):
            sources.append((key, entry))
    observed = defaultdict(list)
    for source_name, source in sources:
        for item in source.get('observations', []):
            if not isinstance(item, dict):
                continue
            op = item.get('operation')
            if isinstance(op, str) and op in declared:
                observed[op].append({'source': source_name, 'status': item.get('status'),
                                     'check': item.get('check', 'unknown')})
    entries = []
    for op in sorted(declared):
        planned = plan_by_op.get(op, {})
        checks = observed.get(op, [])
        entries.append({'operation': op, 'observed': bool(checks), 'observation_count': len(checks),
                        'checks': sorted({str(c['check']) for c in checks}),
                        'planning_status': planned.get('status', 'not_in_plan'),
                        'blockers': planned.get('missing', []) or planned.get('blockers', []) or [],
                        'note': ('HTTP observations do not establish full security test coverage.'
                                 if checks else 'No matching HTTP observation in saved assessment.')})
    total = len(entries)
    covered = sum(row['observed'] for row in entries)
    return {'engine': 'coverage-v0.31', 'declared_operations': total,
            'observed_operations': covered, 'unobserved_operations': total - covered,
            'observed_ratio': round(covered / total, 4) if total else 0.0,
            'operations': entries, 'requests_sent': 0,
            'limitations': ['Observation coverage is NOT vulnerability detection coverage.',
                            'Workflow requests that lack operation identifiers are not counted.',
                            'Planned actions without HTTP execution do not count as observed.']}


def differential_review(assessment: dict[str, Any]) -> dict[str, Any]:
    """Summarize reproducible differential patterns, without creating findings.

    Only status-class changes for the SAME operation and explicit identity are
    compared. The output is a human-review queue, not a vulnerability claim.
    """
    execution = assessment.get('execution_report')
    observations = execution.get('observations', []) if isinstance(execution, dict) else []
    grouped = defaultdict(list)
    for item in observations if isinstance(observations, list) else []:
        if isinstance(item, dict) and isinstance(item.get('operation'), str) and isinstance(item.get('status'), int):
            grouped[(item['operation'], str(item.get('identity', 'unknown')))].append(item)
    queue = []
    for (op, identity), items in sorted(grouped.items()):
        checks = defaultdict(set)
        for item in items:
            checks[str(item.get('check', 'unknown'))].add(item['status'] // 100)
        if len(items) < 2:
            continue
        statuses = sorted({item['status'] // 100 for item in items})
        if len(statuses) >= 2:
            queue.append({'operation': op, 'identity': identity, 'status_classes': statuses,
                          'checks': sorted(checks), 'result': 'manual_review_required',
                          'explanation': 'Different response classes require policy and negative-control verification.'})
    return {'engine': 'differential-review-v0.29', 'review_count': len(queue),
            'candidates': queue, 'confirmed_vulnerabilities': 0, 'requests_sent': 0}


def workflow_graph(parsed: ParsedAPI, manifest: dict[str, Any]) -> dict[str, Any]:
    """Statically validate a multi-resource workflow DAG, never execute writes.

    Operator supplies explicit operations and dependencies. This prevents an
    LLM or an endpoint-name heuristic from inventing mutation authority.
    Cleanup is required for every creating step before the plan is approved.
    """
    if not isinstance(manifest, dict) or set(manifest) != {'steps'}:
        raise AssessmentPolicyError("Workflow manifest needs only a 'steps' list.")
    steps = manifest['steps']
    if not isinstance(steps, list) or not 1 <= len(steps) <= 30:
        raise AssessmentPolicyError('Provide 1..30 explicit workflow steps.')
    operations = {f'{ep.method} {ep.path}' for ep in parsed.endpoints}
    allowed = {'id', 'operation', 'depends_on', 'kind', 'cleanup_step', 'identity'}
    nodes = {}
    for step in steps:
        if not isinstance(step, dict) or set(step) - allowed:
            raise AssessmentPolicyError('Workflow step has unsupported fields.')
        step_id = step.get('id')
        if not isinstance(step_id, str) or not re.fullmatch(r'[a-zA-Z][\w-]{0,49}', step_id) or step_id in nodes:
            raise AssessmentPolicyError('Step IDs must be unique and alphanumeric.')
        op = step.get('operation')
        if op not in operations:
            raise AssessmentPolicyError(f'{step_id}: operation is not declared by OpenAPI.')
        kind = step.get('kind', 'read')
        method = op.split(' ', 1)[0]
        if kind not in {'read', 'create', 'modify', 'cleanup'}:
            raise AssessmentPolicyError(f'{step_id}: invalid step kind.')
        if kind == 'read' and method != 'GET':
            raise AssessmentPolicyError(f'{step_id}: read step must use GET.')
        if kind == 'create' and method != 'POST':
            raise AssessmentPolicyError(f'{step_id}: create step must use POST.')
        if kind == 'modify' and method not in {'PATCH', 'PUT'}:
            raise AssessmentPolicyError(f'{step_id}: modify step must use PATCH or PUT.')
        if kind == 'cleanup' and method != 'DELETE':
            raise AssessmentPolicyError(f'{step_id}: cleanup step must use DELETE.')
        deps = step.get('depends_on', [])
        if not isinstance(deps, list) or any(not isinstance(x, str) for x in deps) or len(deps) != len(set(deps)):
            raise AssessmentPolicyError(f'{step_id}: invalid dependencies.')
        nodes[step_id] = {'id': step_id, 'operation': op, 'kind': kind,
                          'depends_on': deps, 'identity': step.get('identity'),
                          'cleanup_step': step.get('cleanup_step')}
    for node in nodes.values():
        if any(dep not in nodes or dep == node['id'] for dep in node['depends_on']):
            raise AssessmentPolicyError(f"{node['id']}: unknown/self dependency.")
        if node['kind'] == 'create':
            cleaner = node['cleanup_step']
            if cleaner not in nodes or nodes[cleaner]['kind'] != 'cleanup':
                raise AssessmentPolicyError(f"{node['id']}: create must declare a valid cleanup_step.")
            if node['id'] not in nodes[cleaner]['depends_on']:
                raise AssessmentPolicyError(f"{node['id']}: cleanup must depend on resource creation.")
    order, pending = [], {k: set(v['depends_on']) for k, v in nodes.items()}
    while pending:
        ready = sorted(k for k, deps in pending.items() if not deps)
        if not ready:
            raise AssessmentPolicyError('Workflow dependency cycle detected.')
        for key in ready:
            order.append(key)
            del pending[key]
        for deps in pending.values():
            deps.difference_update(ready)
    return {'engine': 'multi-resource-dag-v0.28', 'valid': True, 'execution_order': order,
            'steps': [nodes[x] for x in order], 'requests_sent': 0, 'executable': False,
            'blocked_reason': 'Static DAG only: write payloads, ownership and rollback require approved fixtures.'}


def load_workflow_graph(path: Path | str) -> dict[str, Any]:
    """Load a YAML/JSON dependency manifest without executing its operations."""
    try:
        obj = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    except (OSError, yaml.YAMLError) as exc:
        raise AssessmentPolicyError('Could not parse workflow graph manifest.') from exc
    return obj


def save_json(path: Path, report: dict[str, Any]) -> None:
    """Create report directories and serialize a JSON report safely."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')


def benchmark_evaluate(ground_truth: dict[str, Any], verified_results: dict[str, Any]) -> dict[str, Any]:
    """Measure precision/recall from **human-verified** result IDs only.

    This is a label comparator, NOT a detector. Unreviewed scanner observations
    are excluded; otherwise a scanner could inflate its own detection score.
    Both inputs use simple string identifiers, not raw HTTP data.
    """
    if not isinstance(ground_truth, dict) or not isinstance(verified_results, dict):
        raise AssessmentPolicyError('Benchmark documents must be objects.')
    expected = ground_truth.get('positive_ids')
    verified = verified_results.get('verified_positive_ids')
    if not isinstance(expected, list) or not isinstance(verified, list):
        raise AssessmentPolicyError('Provide positive_ids and verified_positive_ids lists.')
    for collection in (expected, verified):
        if len(collection) > 10000 or len(collection) != len(set(map(str, collection))):
            raise AssessmentPolicyError('Benchmark IDs must be distinct and bounded.')
        if any(not isinstance(x, str) or not re.fullmatch(r'[a-zA-Z0-9:_./-]{1,128}', x) for x in collection):
            raise AssessmentPolicyError('Benchmark IDs must be short non-sensitive strings.')
    expected_ids, found_ids = set(expected), set(verified)
    tp, fp, fn = len(expected_ids & found_ids), len(found_ids - expected_ids), len(expected_ids - found_ids)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {'engine': 'verified-benchmark-v0.31', 'true_positives': tp, 'false_positives': fp,
            'false_negatives': fn, 'precision': round(precision, 4) if precision is not None else None,
            'recall': round(recall, 4) if recall is not None else None,
            'false_positive_ids': sorted(found_ids - expected_ids),
            'missed_ids': sorted(expected_ids - found_ids), 'requests_sent': 0,
            'limitation': 'Metrics are meaningful only with independent, complete ground truth and human-verified findings.'}


def next_actions(parsed: ParsedAPI, assessment: dict[str, Any], *, budget: int = 5) -> dict[str, Any]:
    """Prioritize untested safe GETs and unresolved prerequisites from real coverage.

    This is the conservative v0.30 decision loop's *offline* planning stage.
    Only pre-existing OpenAPI operations can become candidates; no arbitrary
    model output can become an executable HTTP method, host, path or payload.
    """
    if not isinstance(budget, int) or not 0 <= budget <= 50:
        raise AssessmentPolicyError('Action budget must be between 0 and 50.')
    coverage = coverage_report(parsed, assessment)
    queue = []
    for op in coverage['operations']:
        if op['observed']:
            continue
        status = op['planning_status']
        if status == 'eligible_get':
            queue.append({'operation': op['operation'], 'kind': 'scoped_get_baseline', 'priority': 1,
                          'executable_by_auto_assess': True,
                          'instruction': 'Run auto-assess with --execute, approved --allow-host and adequate budget.'})
        elif status in {'blocked_missing_inputs', 'missing_inputs'} or op['blockers']:
            queue.append({'operation': op['operation'], 'kind': 'missing_fixture', 'priority': 2,
                          'executable_by_auto_assess': False,
                          'instruction': 'Provide operator-approved parameter examples and re-plan.'})
        else:
            is_get = op['operation'].startswith('GET ')
            queue.append({'operation': op['operation'],
                          'kind': 'get_preflight_review' if is_get else 'manual_workflow_review',
                          'priority': 2 if is_get else 3,
                          'executable_by_auto_assess': False,
                          'instruction': ('Check GET authorization, known parameters and authentication; then run an approved baseline.'
                                          if is_get else
                                          'Requires an approved disposable fixture, ownership policy and cleanup before write testing.')})
    queue.sort(key=lambda item: (item['priority'], item['operation']))
    return {'engine': 'bounded-coverage-policy-v0.30', 'budget': budget,
            'proposed_actions': queue[:budget], 'remaining_actions': max(0, len(queue) - budget),
            'requests_sent': 0, 'llm_may_execute': False,
            'limitations': ['A planned GET is not executed by this command.',
                            'An LLM may rank these candidates but cannot authorize requests.']}
