"""Local, read-only and bounded interactive views of completed AchillesAPI jobs.

The detailed tree is sanitized on the server. It is not a raw result download;
raw exports remain explicit user actions.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from achillesapi.reporting.professional import summarize_assessment

_REDACT_KEY = re.compile(r"(?i)(authorization|headers|cookie|password|passwd|secret|token|api.?key|credential(?!s_allowed)|private.?key|body|payload|raw_?|request_headers|response_headers|property_paths|response_preview|body_preview|environment_variables)")
_REDACT_VALUE = re.compile(r"(?i)(bearer\s+[\w.\-]+|(?:api[_-]?key|password|token|authorization|set-cookie)\s*[:=]\s*\S+)")
_SAFE_KEY = re.compile(r"^[a-zA-Z][\w.\-]{0,100}$")
_SKIP = object()


def safe_tree(value: Any, *, depth: int = 0) -> Any:
    """Sanitize before presentation, with depth and size bounds to avoid huge DOMs."""
    if depth > 7:
        return '[limite profondità]'
    if isinstance(value, dict):
        result = {}
        for key, child in list(value.items())[:120]:
            if not isinstance(key, str) or not _SAFE_KEY.fullmatch(key):
                continue
            if _REDACT_KEY.search(key) and not (key in {'allow_credentials', 'cors_credentials_allowed'} and type(child) is bool):
                result[key] = '[omesso: potenzialmente sensibile]'
            else:
                result[key] = safe_tree(child, depth=depth + 1)
        return result
    if isinstance(value, list):
        result = [safe_tree(child, depth=depth + 1) for child in value[:250]]
        if len(value) > 250:
            result.append(f'[{len(value) - 250} elementi ulteriori omessi]')
        return result
    if type(value) in (int, float, bool) or value is None:
        return value
    if isinstance(value, str):
        text = value[:700].replace('\x00', '')
        return '[omesso: potenzialmente sensibile]' if _REDACT_VALUE.search(text) else text
    return '[tipo non visualizzabile]'


def _lists(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Locate semantic arrays at any supported command's conventional locations."""
    labels = {
        'operations': 'Operazioni', 'endpoints': 'Endpoint', 'actions': 'Azioni agent',
        'proposed_actions': 'Azioni proposte', 'candidates': 'Candidati',
        'recommended_tests': 'Test raccomandati', 'next_steps': 'Prossimi passi',
        'cross_correlations': 'Correlazioni AI', 'false_positive_checks': 'Controlli falsi positivi',
        'risk_observations': 'Osservazioni AI', 'limitations': 'Limitazioni',
        'coverage_next_steps': 'Copertura restante', 'rounds': 'Cicli agente',
        'workflows': 'Workflow', 'nodes': 'Nodi', 'edges': 'Collegamenti',
        'responses': 'Risposte', 'observations': 'Osservazioni HTTP',
        'steps': 'Esiti della suite completa',
    }
    results = []
    def visit(node: Any, path: str, depth: int):
        if depth > 3 or not isinstance(node, dict):
            return
        for key, val in list(node.items())[:90]:
            if not isinstance(key, str) or _REDACT_KEY.search(key):
                continue
            if isinstance(val, list) and key in labels:
                results.append({'key': path + '.' + key if path else key,
                                'title': labels[key], 'count': len(val),
                                'items': safe_tree(val)})
            elif isinstance(val, dict):
                visit(val, (path + '.' if path else '') + key, depth + 1)
    visit(raw, '', 0)
    return results[:35]


def viewer_payload(raw: dict[str, Any], *, action: str, job_id: str) -> dict[str, Any]:
    """One safe common view for every JSON-producing tool, including AI and agents."""
    if not isinstance(raw, dict):
        raise ValueError('Risultato non supportato')
    professional = summarize_assessment(raw)
    if raw.get('engine') == 'achillesapi-bounded-suite':
        professional['summary'].update({
            'tools_total': raw.get('summary',{}).get('total',0),
            'tools_completed': raw.get('summary',{}).get('completed',0),
            'tools_failed': raw.get('summary',{}).get('failed',0),
            'tools_skipped': raw.get('summary',{}).get('skipped',0),
            'http_budget_reserved': raw.get('reserved_request_budget',0),
        })
    findings = professional['findings']
    # A user may also open a professional report as a result. Preserve its
    # already-sanitized findings rather than incorrectly showing zero.
    if not findings and isinstance(raw.get('report_schema'), str) and isinstance(raw.get('findings'), list):
        from achillesapi.reporting.professional import _safe_category, _safe_text, _safe_reason, _evidence_metadata
        findings = [{
            'id': _safe_text(f.get('id', f'OBS-{index:04d}'), 64),
            'category': _safe_category(f.get('category', 'unclassified')),
            'operation': _safe_text(f.get('operation', 'unknown'), 160),
            'severity': f.get('severity', 'informational') if f.get('severity') in {'critical','high','medium','low','informational','info'} else 'informational',
            'status': 'requires_review', 'confidence': 'indicator',
            'reason': _safe_reason(f), 'evidence': _evidence_metadata(f.get('evidence')),
        } for index, f in enumerate(raw['findings'][:300], 1) if isinstance(f, dict)]
    # In assessments, the professional report is the authoritative source.
    # For AI correlations findings are preserved separately by that same report.
    sections = _lists(raw)
    ai = []
    for key in ('ai_analysis', 'ai_correlation', 'ai_advisory', 'local_ai_advice'):
        value = raw.get(key)
        if isinstance(value, dict):
            ai.append({'title': key.replace('_', ' ').title(), 'data': safe_tree(value)})
    return {
        'id': job_id, 'action': action, 'source_kind': professional['source_kind'],
        'summary': safe_tree(professional['summary']),
        'highlights': professional.get('source_highlights', []),
        'findings': findings[:300],
        'sections': sections,
        'ai': ai,
        'details': safe_tree(raw),
        'limitations': professional.get('limitations', []),
        'notice': 'Vista sanitizzata e di sola lettura. I suggerimenti AI non confermano vulnerabilità né autorizzano test.'
    }
