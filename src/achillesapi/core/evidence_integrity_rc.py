"""Impronte di integrità per report di assessment già sanitizzati.

Appunti:
- Un hash rileva modifiche al file, NON certifica chi l'ha prodotto.
- Usiamo lo SHA-256 dei byte originali, ma non esportiamo il contenuto.
- Non seguiamo percorsi esterni: la CLI riceve un file locale esplicito.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def build_integrity_record(path: str | Path) -> dict[str, Any]:
    """Calcola l'impronta di un report, senza caricarlo in memoria o mostrarlo."""
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ValueError('Il report deve essere un file regolare e non un link simbolico')
    if source.stat().st_size > 50 * 1024 * 1024:
        raise ValueError('Report troppo grande: massimo 50 MB')
    digest = hashlib.sha256()
    with source.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return {'engine': 'achilles-evidence-integrity-rc2',
            'algorithm': 'sha256', 'size_bytes': source.stat().st_size,
            'sha256': digest.hexdigest(),
            'note': 'Hash del report locale: non è una firma digitale e non dimostra la vulnerabilità.'}


def verify_integrity_record(path: str | Path, record: dict[str, Any]) -> dict[str, Any]:
    """Confronta il file con l'impronta fornita, senza divulgare l'evidenza."""
    if not isinstance(record, dict) or record.get('algorithm') != 'sha256':
        raise ValueError('Manifest di integrità non valido')
    actual = build_integrity_record(path)
    match = actual['sha256'] == record.get('sha256') and actual['size_bytes'] == record.get('size_bytes')
    return {'engine': 'achilles-evidence-verify-rc2', 'verified': match,
            'algorithm': 'sha256', 'note': 'Controlla solo l’integrità dei byte del file.'}
