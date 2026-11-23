"""Deterministic offline resolution of local-file OpenAPI references.

No HTTP, absolute paths or traversal outside the Swagger directory. External
references are expanded only when necessary; same-document references from the
root are left to the existing OpenAPI parser. Recursive external cycles fail
closed with actionable diagnostics instead of fetching unbounded files.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml


class ExternalReferenceError(ValueError):
    pass


def _pointer(value: Any, fragment: str) -> Any:
    if not fragment:
        return value
    if not fragment.startswith('/'):
        raise ExternalReferenceError('Riferimento esterno: serve un JSON Pointer #/…')
    current = value
    for token in fragment[1:].split('/'):
        token = unquote(token).replace('~1', '/').replace('~0', '~')
        if isinstance(current, dict):
            current = current[token]
        elif isinstance(current, list) and token.isdigit():
            current = current[int(token)]
        else:
            raise ExternalReferenceError('Riferimento esterno non risolvibile')
    return current


def bundle_local_references(spec: dict[str, Any], source: Path, *, max_files: int = 32,
                            max_depth: int = 24, max_bytes: int = 2_000_000,
                            allowed_root: Path | None = None) -> dict[str, Any]:
    """Inline relative file references, limited to the source document's directory.

    The supplied spec is not mutated. HTTPS references are not silently
    downloaded; they require an explicitly predownloaded local file instead.
    """
    root = (allowed_root or source.resolve().parent).resolve()
    if not source.resolve().is_relative_to(root):
        raise ExternalReferenceError('Swagger root fuori dalla directory consentita')
    loaded: dict[Path, Any] = {source.resolve(): spec}

    def read_file(path: Path) -> Any:
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            raise ExternalReferenceError('File $ref fuori dalla directory autorizzata dello Swagger')
        if resolved.suffix.lower() not in {'.yaml', '.yml', '.json'}:
            raise ExternalReferenceError('File $ref: consentiti solo JSON e YAML')
        if resolved not in loaded:
            if len(loaded) >= max_files:
                raise ExternalReferenceError('Troppi file OpenAPI referenziati')
            if not resolved.is_file() or resolved.stat().st_size > max_bytes:
                raise ExternalReferenceError('File $ref mancante o troppo grande')
            try:
                raw = resolved.read_text(encoding='utf-8')
                value = json.loads(raw) if resolved.suffix.lower() == '.json' else yaml.safe_load(raw)
            except (UnicodeError, ValueError, yaml.YAMLError) as exc:
                raise ExternalReferenceError('Impossibile leggere il file $ref locale') from exc
            if not isinstance(value, (dict, list)):
                raise ExternalReferenceError('File $ref deve contenere un oggetto o un array')
            loaded[resolved] = value
        return loaded[resolved]

    def walk(obj: Any, current: Path, chain: frozenset[tuple[Path, str]], depth: int) -> Any:
        if depth > max_depth:
            raise ExternalReferenceError('Riferimenti OpenAPI troppo annidati')
        if isinstance(obj, list):
            return [walk(v, current, chain, depth+1) for v in obj]
        if not isinstance(obj, dict):
            return obj
        ref = obj.get('$ref')
        if isinstance(ref, str):
            target, sep, fragment = ref.partition('#')
            if not target and current == source.resolve():
                # Let the existing parser handle root-local refs, including recursion.
                return {k: walk(v, current, chain, depth+1) if k != '$ref' else v
                        for k, v in obj.items()}
            if not target and current != source.resolve():
                dest = current
            else:
                parts = urlsplit(target)
                if parts.scheme or parts.netloc or target.startswith('/') or '\\' in target or '?' in target:
                    raise ExternalReferenceError('Riferimento remoto o assoluto non autorizzato: ' + ref[:120])
                dest = (current.parent / unquote(target)).resolve()
            key = (dest, fragment)
            if key in chain:
                raise ExternalReferenceError('Riferimento esterno ricorsivo: fornisci uno schema locale consolidato')
            try:
                referenced = _pointer(read_file(dest), fragment if sep else '')
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise ExternalReferenceError('JSON Pointer esterno non trovato: ' + ref[:120]) from exc
            if not isinstance(referenced, dict):
                raise ExternalReferenceError('Il riferimento deve puntare a un oggetto OpenAPI')
            siblings = {k: v for k, v in obj.items() if k != '$ref'}
            combined = {**referenced, **siblings}
            return walk(combined, dest, chain | {key}, depth+1)
        return {k: walk(v, current, chain, depth+1) for k, v in obj.items()}

    return walk(spec, source.resolve(), frozenset(), 0)
