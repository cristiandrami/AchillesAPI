"""Grounded, bounded executive digest of recorded AI analyses.

No model inference or target requests are made. Summaries only reuse sanitized
statements that are actually present in the AI dossier, never fabricate findings.
"""
from __future__ import annotations

import re
from typing import Any

_RISK = ('risk_observations', 'prioritized_findings')
_ACTION = ('recommended_tests', 'recommended_actions', 'recommendations',
           'next_steps', 'priority_actions')
_SUMMARY = ('executive_summary',)
_LIMITATIONS = ('limitations',)
_TERMS = ('description', 'summary', 'text', 'title', 'reason', 'recommendation',
          'action', 'test', 'finding', 'observation', 'risk', 'name')


def _visible_sentences(value: Any):
    """Read only explicitly named, already sanitized human-language fields."""
    if isinstance(value, str):
        item = re.sub(r'\s+', ' ', value).strip()
        if item and not item.startswith('[omesso:'):
            yield item[:700]
    elif isinstance(value, list):
        for part in value[:80]:
            yield from _visible_sentences(part)
    elif isinstance(value, dict):
        for key in _TERMS:
            if key in value:
                yield from _visible_sentences(value[key])


def _extract(entry: dict[str, Any], keys: tuple[str, ...]):
    for section in entry.get('sections', [])[:12]:
        data = section.get('data') if isinstance(section, dict) else None
        if isinstance(data, dict):
            for key in keys:
                if key in data:
                    yield from _visible_sentences(data[key])
        # Top level arrays are allowed in a few historical AI commands.
        elif isinstance(data, list) and section.get('name') in keys:
            yield from _visible_sentences(data)


def build_ai_dossier_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicated short-list with traceable job origins and explicit uncertainty."""
    limits = {'executive_summaries': 3, 'risks': 12, 'actions': 12, 'limitations': 6}
    lists = {key: [] for key in limits}
    seen = {key: set() for key in limits}
    categories = {'executive_summaries': _SUMMARY, 'risks': _RISK,
                  'actions': _ACTION, 'limitations': _LIMITATIONS}
    for entry in entries[:100]:
        if not isinstance(entry, dict):
            continue
        source = {'action': str(entry.get('action', ''))[:80],
                  'job_id': str(entry.get('job_id', ''))[:32],
                  'provenance': str(entry.get('provenance', ''))[:55]}
        for bucket, keys in categories.items():
            for text in _extract(entry, keys):
                normalized = re.sub(r'\s+', ' ', text).casefold()
                if normalized in seen[bucket]:
                    continue
                seen[bucket].add(normalized)
                if len(lists[bucket]) < limits[bucket]:
                    lists[bucket].append({'text': text, **source})
    return {**lists, 'ai_outputs_reviewed': len(entries),
            'notice': ('Riepilogo basato esclusivamente sugli output AI registrati. '
                       'I rischi sono ipotesi da verificare: non sono vulnerabilità confermate. '
                       'Le azioni sono suggerimenti, non test già eseguiti.')}
