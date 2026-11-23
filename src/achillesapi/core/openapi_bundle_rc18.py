"""Bounded, ZIP-safe local OpenAPI bundle import. No network and no ZIP extractall."""
from __future__ import annotations

import io
import os
from pathlib import Path, PurePosixPath
import stat
from tempfile import TemporaryDirectory
from typing import Any
from zipfile import BadZipFile, ZipFile

import yaml

from achillesapi.core.openapi import load_openapi, parse_openapi

MAX_FILES = 32
MAX_ENTRY_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024


class OpenAPIBundleError(ValueError):
    pass


def _safe_entry(name: str) -> PurePosixPath:
    if ('\\' in name or '\x00' in name or ':' in name or name.startswith('/') or
            name.startswith('//') or not name or name.endswith('/') and name.strip('/') == ''):
        raise OpenAPIBundleError('Path ZIP assoluto, ambiguo o non autorizzato')
    p = PurePosixPath(name)
    if any(part in ('', '..', '.') for part in name.split('/')) or p.is_absolute():
        raise OpenAPIBundleError('Path ZIP contiene traversal o segmenti non consentiti')
    return p


def import_zip_bundle(raw: bytes, destination: Path, *, root_name: str | None = None) -> dict[str, Any]:
    """Validate ZIP entries, resolve relative refs offline and persist only bundled YAML.

    destination is a server-generated opaque filename; never takes an uploaded name.
    Any failure leaves no partial output.
    """
    if not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise OpenAPIBundleError('Archivio mancante o oltre il limite di 8 MB')
    destination = Path(destination)
    if destination.exists():
        raise OpenAPIBundleError('Il file destinazione esiste già')
    try:
        with ZipFile(io.BytesIO(raw)) as archive:
            entries = [info for info in archive.infolist() if not info.is_dir()]
            if not entries or len(entries) > MAX_FILES:
                raise OpenAPIBundleError('Lo ZIP deve contenere da 1 a 32 file JSON/YAML')
            seen: set[str] = set()
            size = 0
            with TemporaryDirectory(prefix='achilles-rc18-') as folder:
                scratch = Path(folder)
                for info in entries:
                    entry = _safe_entry(info.filename)
                    if entry.as_posix().lower() in seen:
                        raise OpenAPIBundleError('Nomi file duplicati o non univoci nello ZIP')
                    seen.add(entry.as_posix().lower())
                    if entry.suffix.lower() not in {'.json', '.yaml', '.yml'}:
                        raise OpenAPIBundleError('Solo file JSON/YAML nel bundle')
                    mode = info.external_attr >> 16
                    if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                        raise OpenAPIBundleError('Link o file speciali non ammessi nello ZIP')
                    size += info.file_size
                    if info.file_size > MAX_ENTRY_BYTES or size > MAX_TOTAL_BYTES:
                        raise OpenAPIBundleError('Bundle non compresso oltre i limiti consentiti')
                    data = archive.read(info)
                    if len(data) != info.file_size:
                        raise OpenAPIBundleError('Dimensione ZIP non valida')
                    dest = scratch.joinpath(*entry.parts)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(data)
                files = sorted(seen)
                if root_name:
                    root = _safe_entry(root_name).as_posix()
                    if root not in files:
                        raise OpenAPIBundleError('File OpenAPI principale non presente nel bundle')
                else:
                    candidates = []
                    for name in files:
                        node = scratch.joinpath(*PurePosixPath(name).parts)
                        try:
                            doc = yaml.safe_load(node.read_text(encoding='utf-8'))
                        except (UnicodeError, yaml.YAMLError) as exc:
                            raise OpenAPIBundleError('File YAML/JSON non leggibile') from exc
                        if isinstance(doc, dict) and 'openapi' in doc and 'paths' in doc:
                            candidates.append(name)
                    if len(candidates) != 1:
                        raise OpenAPIBundleError('Indica root_name: il bundle ha zero o più specifiche OpenAPI principali')
                    root = candidates[0]
                spec = load_openapi(scratch.joinpath(*PurePosixPath(root).parts), allowed_ref_root=scratch)
                parsed = parse_openapi(spec)
                normalized = yaml.safe_dump(spec, allow_unicode=True, sort_keys=False).encode('utf-8')
                if len(normalized) > MAX_TOTAL_BYTES:
                    raise OpenAPIBundleError('OpenAPI consolidato oltre 8 MB')
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with destination.open('xb') as output:
                        os.chmod(destination, 0o600)
                        output.write(normalized)
                except BaseException:
                    destination.unlink(missing_ok=True)
                    raise
                return {'root': root, 'files': files, 'file_count': len(files),
                        'title': parsed.title, 'operations': parsed.endpoint_count,
                        'bundle_bytes': len(normalized), 'network_requests': 0}
    except BadZipFile as exc:
        raise OpenAPIBundleError('Archivio ZIP non valido') from exc
