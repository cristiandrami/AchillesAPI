"""Normalize prior results before offline planning; never fabricate HTTP evidence.

Different tools save different report schemas.  The OpenAPI document, not an
untrusted report, is the authority for the operation inventory.  This module
repairs absent plan metadata without pretending any request was executed.
"""
from __future__ import annotations
from typing import Any
from achillesapi.core.generic import build_generic_plan
from achillesapi.models.api import ParsedAPI


def prepare_assessment(parsed: ParsedAPI, source: dict[str, Any]) -> dict[str, Any]:
    """Add a fresh OpenAPI plan if missing and retain real observations unchanged.

    Return a new object. Empty observations stay empty; we never infer a status
    code from the YAML contract or from AI recommendations.
    """
    if not isinstance(source, dict):
        raise ValueError('Il risultato precedente deve essere un oggetto JSON.')
    normalized = dict(source)
    plan = normalized.get('plan')
    if not isinstance(plan, dict) or not isinstance(plan.get('operations'), list):
        normalized['plan'] = build_generic_plan(parsed)
        normalized['plan_reconstructed_from_openapi'] = True
    report = normalized.get('execution_report')
    if report is None:
        normalized['execution_report'] = {'observations': [], 'requests_sent': 0}
    elif not isinstance(report, dict):
        raise ValueError('Il risultato precedente contiene execution_report non valido.')
    elif not isinstance(report.get('observations', []), list):
        raise ValueError('Il risultato precedente contiene osservazioni HTTP non valide.')
    return normalized


def observed_http_count(source: dict[str, Any]) -> int:
    """Count actual recorded HTTP observations, not planned operations."""
    execution = source.get('execution_report') or {}
    return sum(1 for item in execution.get('observations', [])
               if isinstance(item,dict) and isinstance(item.get('status'),int)
               and isinstance(item.get('operation'),str))
