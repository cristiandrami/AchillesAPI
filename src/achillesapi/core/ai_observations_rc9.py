"""Convert local AI prose into *unverified* review observations.

Only the model's explicit risk_observations are promoted to the review queue.
No inferred exploit, payload, HTTP call, or confirmed status is fabricated.
"""
from __future__ import annotations

import re
from typing import Any

_SENSITIVE = re.compile(r'(?i)(authorization\s*[:=]\s*bearer\s+\S+|bearer\s+\S+|(?:authorization|api[_-]?key|password|secret|token|set-cookie)\s*[:=]\s*\S+)')
_ENDPOINT = re.compile(r'(?:(GET|POST|PATCH|PUT|DELETE)\s+)?(/(?:api/)?[A-Za-z0-9_{}./-]{1,175})', re.I)
_MARKERS = (
    ('BOLA', re.compile(r'\bBOLA\b|broken object level authorization|\bIDOR\b', re.I)),
    ('BFLA', re.compile(r'\bBFLA\b|broken function level authorization', re.I)),
    ('SSRF', re.compile(r'\bSSRF\b', re.I)),
    ('SQLI', re.compile(r'\bSQLi?\b|SQL injection', re.I)),
    ('NOSQL', re.compile(r'NoSQL', re.I)),
    ('MASS_ASSIGNMENT', re.compile(r'mass assignment', re.I)),
    ('XSS', re.compile(r'\bXSS\b', re.I)),
    ('XXE', re.compile(r'\bXXE\b', re.I)),
)


def _bounded(value: Any, limit: int = 700) -> str:
    if not isinstance(value, str):
        return ''
    value = re.sub(r'[\x00-\x08\x0e-\x1f]', ' ', value).strip()[:limit]
    return _SENSITIVE.sub('[credenziale omessa]', value)


def _risk_level(text: str, category: str) -> str:
    # A suggested TRIAGE level, not verified impact or CVSS severity.
    if re.search(r'(?i)\b(critical|critico|high|alto|alta)\b', text):
        return 'high'
    if re.search(r'(?i)\b(medium|medio|media|moderate)\b', text):
        return 'medium'
    if category in {'BOLA', 'BFLA', 'SQLI', 'SSRF', 'MASS_ASSIGNMENT', 'NOSQL'}:
        return 'medium'
    return 'informational'


def extract_ai_observations(raw: dict[str, Any], *, max_items: int = 30) -> list[dict[str, Any]]:
    """Read local model suggestions; keep no raw payloads or secrets."""
    # Only explicit model observations/correlations, not recommended actions or
    # free-form planning text. A correlation must mention a known risk category
    # and an API endpoint to be considered an interesting hypothesis.
    observations: list[Any] = []
    for source in ('ai_analysis', 'ai_advisory', 'local_ai_advice'):
        block = raw.get(source)
        if isinstance(block, dict) and isinstance(block.get('risk_observations'), list):
            observations.extend(block['risk_observations'][:max_items])
    correlations = raw.get('ai_correlation')
    if isinstance(correlations, dict) and isinstance(correlations.get('cross_correlations'), list):
        for item in correlations['cross_correlations'][:max_items]:
            if (isinstance(item, str) and _ENDPOINT.search(item) and
                    any(pattern.search(item) for _, pattern in _MARKERS) and
                    not re.search(r'(?i)(nessun(?:a)? evidenza|non ci sono prove|no evidence|non rilevat)', item)):
                observations.append(item)
    if not observations:
        return []
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in observations[:max_items * 4]:
        if isinstance(entry, str):
            description = _bounded(entry)
        elif isinstance(entry, dict):
            # Compatible with models returning structured observations.
            description = _bounded(entry.get('description') or entry.get('observation') or entry.get('reason') or entry.get('title'))
        else:
            continue
        if not description or description.casefold() in seen:
            continue
        seen.add(description.casefold())
        detected = next((name for name, pattern in _MARKERS if pattern.search(description)), 'UNCLASSIFIED')
        match = _ENDPOINT.search(description)
        operation = 'Endpoint non specificato dall’AI'
        if match:
            operation = (match.group(1).upper() + ' ' if match.group(1) else '') + match.group(2)
        level = _risk_level(description, detected)
        found.append({
            'id': f'AI-OBS-{len(found)+1:03d}',
            'category': 'AI_' + detected,
            'title': 'AI · ' + detected + ' · ipotesi da verificare',
            'severity': level,
            'ai_label': 'AI - ' + ('Info' if level == 'informational' else level),
            'status': 'ai_unverified',
            'confidence': 'unverified',
            'source_type': 'ai_hypothesis',
            'operation': operation,
            'reason': description,
            'what_found': 'Il modello locale ha suggerito una possibile criticità, senza eseguire né dimostrare questo test HTTP.',
            'verification_guidance': 'Controllare endpoint, policy, ruoli e dati autorizzati. Eseguire verifiche deterministiche prima di classificare una vulnerabilità.',
            'test_payloads': [],
            'test_request': None,
            'test_input': {},
            'evidence': {'source': 'ollama_local', 'http_tested': False, 'test_payload_recorded': False},
        })
        if len(found) >= max_items:
            break
    return found
