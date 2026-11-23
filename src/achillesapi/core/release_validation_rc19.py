"""RC19 reproducible QA: offline release gate and benchmark with explicit ground truth.

This module never performs network IO. A benchmark compares *indicators* with
operator-provided expectations; a matching indicator does not prove exploitation.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
import re
from typing import Any


class RC19ValidationError(ValueError):
    """Invalid or unsafe benchmark/report input."""


_OPERATION = re.compile(r"^(GET|POST|PATCH|PUT|DELETE|HEAD|OPTIONS) /[A-Za-z0-9_./{}-]{0,200}$")
_CATEGORY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,99}$")
_ID = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_SECRET_KEY = re.compile(r"(?:password|authorization|set.cookie|access.token|refresh.token|api.key|client.secret|private.key|cookie)", re.I)


def _bounded_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get('findings')
    if findings is None:
        return []
    if not isinstance(findings, list) or len(findings) > 15000:
        raise RC19ValidationError('findings deve essere una lista di massimo 15000 elementi')
    return [x for x in findings if isinstance(x, dict)]


def quality_gate(report: dict[str, Any]) -> dict[str, Any]:
    """Conservative audit of a saved assessment, never a target security verdict."""
    if not isinstance(report, dict):
        raise RC19ValidationError('Il report deve essere un oggetto JSON')
    if 'engine' not in report:
        raise RC19ValidationError('Report senza identificatore engine')
    findings = _bounded_findings(report)
    warnings: list[str] = []
    blockers: list[str] = []
    active = report.get('executed') is True
    requests = report.get('requests_sent', 0)
    budget = report.get('request_budget', None)
    if isinstance(requests, bool) or not isinstance(requests, int) or requests < 0:
        blockers.append('Contatore richieste mancante o non valido')
    if isinstance(budget, int) and not isinstance(budget, bool) and isinstance(requests, int) and requests > budget:
        blockers.append('Budget HTTP superato')
    if not active:
        warnings.append('Valutazione offline: nessun comportamento del target verificato')
        if isinstance(requests, int) and requests > 0:
            blockers.append('Report incoerente: richieste inviate ma executed=false')
    elif not isinstance(requests, int) or requests <= 0:
        warnings.append('Scansione attiva senza richieste HTTP registrate')
    if 'findings' not in report:
        warnings.append('Nessuna lista findings: impossibile verificare la copertura dei risultati')
    if 'coverage' not in report:
        warnings.append('Copertura non disponibile: nessuna percentuale dedotta dal numero di findings')
    if 'limitations' not in report:
        warnings.append('Limitazioni assenti: specificarle nel report professionale')
    if report.get('status') in {'failed', 'interrupted'}:
        blockers.append('Campagna non completata')
    # A passive rule, a scanner indicator or a free-form "confirmed" string is
    # NEVER evidence sufficient for promotion to confirmed exploitation.
    declared = sum(str(f.get('verification_status','')).lower() in {'confirmed', 'verified'} for f in findings)
    if declared:
        warnings.append(f'{declared} finding auto-dichiarati confermati: richiedono verifica indipendente delle prove')
    suspicious = 0
    for finding in findings:
        if any(_SECRET_KEY.search(str(key)) for key in finding):
            suspicious += 1
    if suspicious:
        warnings.append(f'{suspicious} finding con nomi di proprietà potenzialmente riservate: verificare redazione prima di condividere')
    stages = report.get('stages', {})
    incomplete = 0
    if isinstance(stages, dict):
        incomplete = sum(1 for x in stages.values() if isinstance(x,dict) and x.get('status') in {'running','failed','interrupted'})
    if incomplete:
        blockers.append(f'{incomplete} fasi non completate')
    # No source evidence, tokens, body previews, or arbitrary input strings in output.
    return {
        'engine': 'achilles-rc19-quality', 'network_requests_sent': 0,
        'release_gate': 'blocked' if blockers else 'review_required' if warnings else 'ready_for_manual_review',
        'counts': {'findings': len(findings), 'claims_of_confirmation': declared,
                   'http_requests': requests if isinstance(requests,int) else None,
                   'incomplete_stages': incomplete},
        'checks': {'active_execution_declared': active, 'http_budget_not_exceeded': not any('Budget HTTP' in e for e in blockers),
                   'contains_findings_array': 'findings' in report, 'coverage_declared': 'coverage' in report},
        'blockers': blockers, 'warnings': warnings,
        'limitations': ['La readiness misura la qualità della documentazione e del processo, non la sicurezza del target.',
                        'Un finding rimane un indicatore finché una prova riproducibile non ne dimostra la vulnerabilità.'],
    }


def benchmark_findings(report: dict[str, Any], ground_truth: dict[str, Any]) -> dict[str, Any]:
    """Compare observations with separately verified expected indicators.

    A negative case passes only when an actual active scan occurred. Offline or
    incomplete assessments cannot claim true negatives.
    """
    if not isinstance(ground_truth, dict):
        raise RC19ValidationError('Ground truth deve essere un oggetto JSON')
    cases = ground_truth.get('cases')
    if not isinstance(cases, list) or not 1 <= len(cases) <= 200:
        raise RC19ValidationError('Ground truth: indica da 1 a 200 casi')
    findings = _bounded_findings(report)
    active = report.get('executed') is True and isinstance(report.get('requests_sent'),int) and report['requests_sent'] > 0
    valid_ids: set[str] = set()
    keys: set[tuple[str,str]] = set()
    predictions: Counter[tuple[str,str]] = Counter()
    for f in findings:
        operation, category = f.get('operation'), f.get('category')
        if isinstance(operation,str) and isinstance(category,str):
            predictions[(operation,category)] += 1
    output = []
    summary = Counter()
    for case in cases:
        if not isinstance(case,dict):
            raise RC19ValidationError('Caso ground truth non valido')
        ident, operation, category, expected = (case.get(k) for k in ('id','operation','category','expected'))
        if not isinstance(ident,str) or not _ID.fullmatch(ident) or ident in valid_ids:
            raise RC19ValidationError('Identificatori casi duplicati o non validi')
        if not isinstance(operation,str) or not _OPERATION.fullmatch(operation):
            raise RC19ValidationError('Operazione attesa non valida (es. GET /items/{id})')
        if not isinstance(category,str) or not _CATEGORY.fullmatch(category):
            raise RC19ValidationError('Categoria attesa non valida')
        if expected not in {'positive','negative'}:
            raise RC19ValidationError('expected deve essere positive o negative')
        if (operation,category) in keys:
            raise RC19ValidationError('Combinazione categoria/operazione duplicata')
        valid_ids.add(ident)
        keys.add((operation,category))
        observed = predictions[(operation,category)] > 0
        if not active:
            state = 'not_evaluated'
        elif observed and expected == 'positive':
            state = 'true_indicator'
        elif observed and expected == 'negative':
            state = 'false_positive_indicator'
        elif expected == 'positive':
            state = 'missed_indicator'
        else:
            state = 'negative_control_passed'
        summary[state] += 1
        output.append({'id':ident,'operation':operation,'category':category,'expected':expected,
                       'indicator_observed':observed,'duplicate_indicators':max(0,predictions[(operation,category)]-1),
                       'result':state})
    evaluated = sum(summary[key] for key in ('true_indicator','false_positive_indicator','missed_indicator','negative_control_passed'))
    positive = summary['true_indicator']+summary['missed_indicator']
    negative = summary['false_positive_indicator']+summary['negative_control_passed']
    return {
        'engine':'achilles-rc19-ground-truth-benchmark', 'network_requests_sent':0,
        'status':'evaluated' if active else 'not_evaluated_offline',
        'summary': {'total':len(cases), 'evaluated':evaluated,
                    'true_indicators':summary['true_indicator'],
                    'missed_indicators':summary['missed_indicator'],
                    'false_positive_indicators':summary['false_positive_indicator'],
                    'negative_controls_passed':summary['negative_control_passed'],
                    'not_evaluated':summary['not_evaluated'],
                    'indicator_recall': round(summary['true_indicator']/positive,4) if positive else None,
                    'negative_control_pass_rate':round(summary['negative_control_passed']/negative,4) if negative else None},
        'cases':output,
        'limitations':['Il benchmark valuta segnali scanner contro una ground truth esplicita; NON conferma exploit.',
                       'Casi negativi offline non equivalgono a veri negativi.',
                       'Solo le operazioni/categorie elencate nella ground truth sono conteggiate.'],
    }


def fingerprint_json(value: dict[str, Any]) -> str:
    """Hash stable test inputs without embedding their content in the report."""
    return sha256(json.dumps(value,sort_keys=True,default=str,ensure_ascii=False).encode()).hexdigest()
