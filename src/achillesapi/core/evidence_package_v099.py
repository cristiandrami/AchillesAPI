"""v0.98: esportazione di un indice di evidenze senza dati riservati.

Appunti: i report tecnici grezzi possono contenere dati aziendali. Qui
esportiamo soltanto metadati strettamente necessari alla revisione.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from achillesapi.core.verification_v080 import classify_findings

_SAFE_CATEGORY = re.compile(r'[^A-Za-z0-9_\-]')


def build_evidence_package(report: dict[str, Any]) -> dict[str, Any]:
    """Prepara un indice dei finding sanitizzato e riproducibile."""
    groups = classify_findings(report)
    findings = []
    for item in groups['findings'][:1000]:
        # Fingerprint e nomi categoria sono utili. URL, token e corpi NON servono.
        fingerprint = item['fingerprint']
        category = _SAFE_CATEGORY.sub('_', str(item['category']))[:64]
        findings.append({
            'fingerprint': fingerprint, 'category': category,
            'status': item['status'],
            'severity': item['severity'] if item['severity'] in
                        ('critical', 'high', 'medium', 'low', 'info', 'informational') else 'informational',
            'occurrences': item['occurrences'],
            'operation_fingerprint': hashlib.sha256(str(item['operation']).encode()).hexdigest()[:16],
            'requires_operator_review': item['status'] == 'requires_review',
        })
    return {
        'engine': 'achilles-evidence-package-v099', 'requests_sent': 0,
        'summary': {'groups': len(findings),
                    'unverified': sum(x['requires_operator_review'] for x in findings)},
        'findings': findings,
        'limitations': ['Indice privato dei metadati; non contiene HTTP bodies, credenziali o URL.',
                        'Per la riproduzione servono evidenze originali conservate in luogo protetto.'],
    }
