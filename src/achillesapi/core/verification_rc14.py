"""Evidence-only verification: never upgrade an indicator without a control."""
from __future__ import annotations
from typing import Any
import hashlib
import json


def review_evidence(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicate for review while retaining each source and its evidence.

    'supporting_comparison' only says a meaningful baseline/variant is present;
    it is not a security exploit confirmation.
    """
    groups: dict[str, dict[str, Any]] = {}
    for item in findings[:500]:
        if not isinstance(item, dict):
            continue
        category = str(item.get('category', 'unclassified'))[:100]
        operation = str(item.get('operation', 'unknown'))[:180]
        field = str(item.get('field') or (item.get('test_input') or {}).get('parameter') or item.get('rule_id') or '')[:80]
        fingerprint = hashlib.sha256(json.dumps([category, operation, field], ensure_ascii=False).encode()).hexdigest()[:16]
        entry = groups.setdefault(fingerprint, {'fingerprint': fingerprint, 'category': category,
            'operation': operation, 'field_or_rule': field, 'occurrences': 0,
            'sources': [], 'status': 'requires_review', 'explanation': ''})
        entry['occurrences'] += 1
        source = str(item.get('source_engine', 'unknown'))[:80]
        if source not in entry['sources']:
            entry['sources'].append(source)
        comparison = item.get('evidence', {})
        if not isinstance(comparison, dict):
            comparison = {}
        http = comparison.get('http_comparison', comparison)
        if isinstance(http, dict) and isinstance(http.get('baseline'), dict) and isinstance(http.get('variants'), list):
            entry['status'] = 'comparison_recorded_not_confirmed'
            entry['explanation'] = 'Presenti baseline e varianti HTTP. Verificare riproducibilità e un controllo negativo.'
        elif item.get('access_comparison'):
            entry['status'] = 'policy_comparison_recorded_not_confirmed'
            entry['explanation'] = 'Registrato confronto tra identità e policy dichiarata; verificare proprietà e contenuto.'
        elif item.get('verification_status') == 'confirmed':
            # Never trust an arbitrary string as proof.
            entry['explanation'] = 'Lo scanner segnala confirmed, ma non sono presenti controlli sufficienti a convalidarlo.'
        else:
            entry['explanation'] = 'Non sono presenti confronti completi utilizzabili per una conferma automatica.'
    return {'engine': 'achilles-evidence-verification', 'verified_exploits': 0,
            'unique_review_items': len(groups), 'observations': list(groups.values()),
            'limitations': ['La deduplicazione non conferma la vulnerabilità.',
                            'La severità è mantenuta dai motori originali; non è inventato un CVSS.']}
