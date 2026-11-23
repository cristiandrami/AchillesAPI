"""v0.95: metriche misurabili solo usando una ground truth indipendente.

Appunti: un finding dello scanner NON puo diventare ground truth. Le etichette
positive_ids devono provenire dal benchmark verificato da un operatore.
"""
from __future__ import annotations

from typing import Any


def compare_ground_truth(truth: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """Calcola TP/FP/FN, precision, recall e F1 con controlli di tipo."""
    def ids(source: dict[str, Any], field: str) -> set[str]:
        values = source.get(field)
        if not isinstance(values, list) or len(values) > 10000:
            raise ValueError(f'{field} deve essere una lista con massimo 10000 ID.')
        if any(not isinstance(value, str) or not value.strip() or len(value) > 160 for value in values):
            raise ValueError(f'{field} contiene un identificativo non valido.')
        return set(values)

    if not isinstance(truth, dict) or not isinstance(observed, dict):
        raise ValueError('Le due configurazioni devono essere oggetti JSON.')
    positives = ids(truth, 'positive_ids')
    predicted = ids(observed, 'verified_positive_ids')
    true_positive = len(positives & predicted)
    false_positive = len(predicted - positives)
    false_negative = len(positives - predicted)
    precision = true_positive / (true_positive + false_positive) if predicted else 0.0
    recall = true_positive / (true_positive + false_negative) if positives else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        'engine': 'achilles-independent-benchmark-v099', 'requests_sent': 0,
        'summary': {'ground_truth_positives': len(positives), 'predicted_positives': len(predicted),
                    'tp': true_positive, 'fp': false_positive, 'fn': false_negative,
                    'precision': round(precision, 4), 'recall': round(recall, 4), 'f1': round(f1, 4)},
        'quality': 'requires_independent_truth',
        'limitations': ['La ground truth deve essere indipendente dallo scanner.',
                        'Senza etichette per i veri negativi non calcoliamo specificita/accuracy.',
                        'Le metriche sono valide solo per il benchmark rappresentato dalle etichette.'],
    }
