"""Offline CVSS v3.1 base score from an *explicitly supplied* vector.

The framework NEVER guesses a CVSS vector from an injection indicator or
LLM-generated prose. A valid vector is an analyst input, not exploit proof.
"""
from __future__ import annotations
import math

AV={'N': .85,'A': .62,'L': .55,'P': .2}
AC={'L': .77,'H': .44}
UI={'N': .85,'R': .62}
CIA={'N': 0,'L': .22,'H': .56}

def score_cvss31(vector: str) -> float:
    """Return official CVSS 3.1 base score, with ROUNDUP to one decimal."""
    if not isinstance(vector, str) or not vector.startswith('CVSS:3.1/') or len(vector) > 130:
        raise ValueError('Serve un vettore CVSS:3.1 completo e valido')
    pairs = vector.split('/')[1:]
    try:
        parts = dict(segment.split(':',1) for segment in pairs)
    except ValueError as exc:
        raise ValueError('Formato CVSS non valido') from exc
    required = {'AV','AC','PR','UI','S','C','I','A'}
    if len(pairs) != 8 or set(parts) != required or len(set(x.split(':')[0] for x in pairs)) != 8:
        raise ValueError('Vettore CVSS incompleto o con metriche ripetute')
    if (parts['AV'] not in AV or parts['AC'] not in AC or parts['UI'] not in UI
        or parts['S'] not in ('U','C') or parts['PR'] not in ('N','L','H')
        or any(parts[key] not in CIA for key in ('C','I','A'))):
        raise ValueError('Valori CVSS non riconosciuti')
    scope_changed = parts['S'] == 'C'
    pr={'N': .85, 'L': .68 if scope_changed else .62,
        'H': .50 if scope_changed else .27}[parts['PR']]
    exploitability = 8.22 * AV[parts['AV']] * AC[parts['AC']] * pr * UI[parts['UI']]
    isc = 1 - (1-CIA[parts['C']])*(1-CIA[parts['I']])*(1-CIA[parts['A']])
    impact = (7.52*(isc-.029)-3.25*(isc-.02)**15 if scope_changed else 6.42*isc)
    if impact <= 0:
        return 0.0
    number = min((impact + exploitability) * (1.08 if scope_changed else 1), 10)
    return math.ceil(number * 10 - 1e-9)/10
