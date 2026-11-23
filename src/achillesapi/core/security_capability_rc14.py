"""Purely offline, target-independent security-surface inventory.

This module NEVER generates active requests or assumes that a declared input is
vulnerable. It describes which checks require operator policy or a disposable
fixture, instead of calling unexecuted techniques 'passed'.
"""
from __future__ import annotations
from typing import Any
import re

_URL = re.compile(r'(?:url|uri|callback|webhook|endpoint|remote|fetch|proxy|redirect)', re.I)
_FILE = re.compile(r'(?:file|path|filename|attachment|upload|document|template)', re.I)
_REDIRECT = re.compile(r'(?:redirect|return[_-]?to|next[_-]?url|continue[_-]?url)', re.I)
_SECRET = re.compile(r'(?:approved|reimbursed|role|admin|permission|privilege|balance|is[_-]?paid|status)', re.I)


def _resolve(spec: dict[str, Any], obj: Any, seen: set[str] | None = None) -> dict[str, Any]:
    """Resolve only local references, with a cycle guard and a bounded walk."""
    seen = set() if seen is None else seen
    for _ in range(12):
        if not isinstance(obj, dict):
            return {}
        ref = obj.get('$ref')
        if not ref:
            return obj
        if not isinstance(ref, str) or not ref.startswith('#/') or ref in seen:
            return {}
        seen.add(ref)
        try:
            target: Any = spec
            for segment in ref[2:].split('/'):
                target = target[segment.replace('~1', '/').replace('~0', '~')]
            obj = {**target, **{k: v for k, v in obj.items() if k != '$ref'}}
        except (KeyError, TypeError):
            return {}
    return {}


def _properties(spec: dict[str, Any], schema: Any, prefix: str = '', depth: int = 0) -> list[tuple[str, dict[str, Any]]]:
    if depth >= 5:
        return []
    obj = _resolve(spec, schema)
    out: list[tuple[str, dict[str, Any]]] = []
    branches = []
    for key in ('allOf', 'oneOf', 'anyOf'):
        if isinstance(obj.get(key), list):
            branches.extend(obj[key][:10])
    for branch in branches:
        out.extend(_properties(spec, branch, prefix, depth + 1))
    for field, raw in list(obj.get('properties', {}).items())[:80] if isinstance(obj.get('properties'), dict) else []:
        if not isinstance(field, str):
            continue
        path = f'{prefix}/{field}'
        prop = _resolve(spec, raw)
        out.append((path, prop))
        out.extend(_properties(spec, prop, path, depth + 1))
    if obj.get('type') == 'array' and isinstance(obj.get('items'), dict):
        out.extend(_properties(spec, obj['items'], prefix + '/*', depth + 1))
    return out


def capability_inventory(spec: dict[str, Any], max_candidates: int = 160) -> dict[str, Any]:
    """List honest P0/P1 coverage opportunities; do not claim active checks."""
    paths = spec.get('paths') if isinstance(spec.get('paths'), dict) else {}
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    techniques = {
        'json_input': ('Input JSON e injection', 'richiede fixture temporanea e campi approvati'),
        'form_input': ('Input form/urlencoded', 'richiede motore form e consenso esplicito'),
        'xml_input': ('Input XML e XXE', 'richiede motore XML non distruttivo e consenso'),
        'file_upload': ('Caricamento file', 'richiede fixture con upload e cleanup approvati'),
        'ssrf': ('Possibile superficie SSRF', 'richiede callback controllato e autorizzato'),
        'open_redirect': ('Possibile open redirect', 'richiede verifica della Location con URL controllato'),
        'path_traversal': ('Possibile path traversal', 'richiede payload e fixture controllati'),
        'mass_assignment': ('Campi sensibili da verificare', 'richiede policy di scrittura e verifica dello stato'),
        'bfla': ('Possibili operazioni privilegiate', 'richiede matrice su metodi di scrittura e fixture'),
    }
    def append(method: str, path: str, category: str, field: str = '') -> None:
        key = (f'{method} {path}', category, field)
        if key in seen or len(findings) >= max_candidates:
            return
        seen.add(key)
        title, prerequisite = techniques[category]
        findings.append({'operation': f'{method} {path}', 'family': category,
                         'title': title, 'field': field or None, 'status': 'candidate_not_executed',
                         'severity': 'informational', 'prerequisite': prerequisite,
                         'evidence': 'Solo analisi OpenAPI: nessuna richiesta HTTP inviata.'})
    for path, pathitem in list(paths.items())[:400]:
        if not isinstance(path, str) or not isinstance(pathitem, dict):
            continue
        for method, operation in list(pathitem.items()):
            if method.lower() not in {'get','post','put','patch','delete'} or not isinstance(operation, dict):
                continue
            verb = method.upper()
            if verb in {'POST','PUT','PATCH','DELETE'} and re.search(r'(?:approve|pay|grant|publish|transfer|refund|cancel|delete|admin|reset)', path, re.I):
                append(verb, path, 'bfla')
            for parm in [*(pathitem.get('parameters') or []), *(operation.get('parameters') or [])]:
                p = _resolve(spec, parm)
                name = p.get('name')
                if not isinstance(name, str):
                    continue
                if _URL.search(name): append(verb, path, 'ssrf', name)
                if _REDIRECT.search(name): append(verb, path, 'open_redirect', name)
                if _FILE.search(name): append(verb, path, 'path_traversal', name)
            body = operation.get('requestBody') or {}
            body = _resolve(spec, body)
            contents = body.get('content') if isinstance(body.get('content'), dict) else {}
            for content_type, media in contents.items():
                if not isinstance(media, dict):
                    continue
                mime = content_type.lower().split(';')[0].strip()
                if mime in {'application/json','application/merge-patch+json','application/json-patch+json'} or mime.endswith('+json'):
                    append(verb, path, 'json_input')
                if mime in {'application/x-www-form-urlencoded','multipart/form-data'}:
                    append(verb, path, 'form_input')
                if mime == 'multipart/form-data': append(verb, path, 'file_upload')
                if 'xml' in mime: append(verb, path, 'xml_input')
                for field, schema in _properties(spec, media.get('schema', {})):
                    if _URL.search(field): append(verb, path, 'ssrf', field)
                    if _REDIRECT.search(field): append(verb, path, 'open_redirect', field)
                    if _FILE.search(field): append(verb, path, 'path_traversal', field)
                    if _SECRET.search(field) and verb in {'POST','PUT','PATCH'}:
                        append(verb, path, 'mass_assignment', field)
                    if schema.get('format') in {'binary', 'byte'} and mime.startswith('multipart'):
                        append(verb, path, 'file_upload', field)
    counts: dict[str, int] = {}
    for c in findings:
        counts[c['family']] = counts.get(c['family'], 0) + 1
    return {'engine': 'achilles-capability-inventory', 'mode': 'offline',
            'request_count': 0, 'candidates': findings, 'counts': counts,
            'warning': 'I candidati non sono vulnerabilità e non costituiscono copertura attiva.'}
