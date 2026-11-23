"""v0.95: verifica che il planner lavori con Swagger differenti.

Appunti: questa NON e' una scansione HTTP. Controlliamo parser, discovery,
compatibilita e workflow su un corpus di specifiche indipendenti dal lab.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from achillesapi.core.compatibility_v080 import analyze_compatibility
from achillesapi.core.openapi import load_openapi
from achillesapi.core.workflow_safety_v099 import review_workflow_safety


def validate_specification_corpus(directory: Path) -> dict[str, Any]:
    """Prova ogni Swagger locale; riporta i fallimenti senza bloccare il corpus."""
    if not directory.is_dir():
        raise ValueError('Indica una directory di specifiche OpenAPI.')
    files = sorted([item for item in directory.iterdir()
                    if item.is_file() and item.suffix.lower() in ('.yaml', '.yml', '.json')])
    if not 1 <= len(files) <= 25:
        raise ValueError('Il corpus deve contenere da 1 a 25 specifiche.')
    cases = []
    for path in files:
        if path.stat().st_size > 2 * 1024 * 1024:
            cases.append({'file': path.name, 'state': 'invalid', 'reason': 'File oltre 2 MiB'})
            continue
        try:
            spec = load_openapi(path)
            coverage = analyze_compatibility(spec)
            workflows = review_workflow_safety(spec)
            cases.append({
                'file': path.name, 'state': 'parsed_and_planned',
                'operations': coverage['summary']['operations'],
                'http_observations': 0,
                'workflow_candidates': workflows['summary']['candidate_workflows'],
            })
        except (ValueError, TypeError, OSError, KeyError) as exc:
            # Evitiamo di copiare un messaggio che potrebbe contenere input riservato.
            cases.append({'file': path.name, 'state': 'invalid',
                          'reason': 'Swagger non valido o costrutto non supportato',
                          'exception_type': type(exc).__name__})
    passed = sum(item['state'] == 'parsed_and_planned' for item in cases)
    return {'engine': 'achilles-independent-corpus-v099', 'requests_sent': 0,
            'summary': {'total': len(cases), 'planned': passed, 'failed': len(cases)-passed},
            'cases': cases,
            'limitations': ['Valida parsing e pianificazione soltanto, non HTTP o vulnerabilita.',
                            'Per la release stabile servono benchmark con target attivi e ground truth.']}
