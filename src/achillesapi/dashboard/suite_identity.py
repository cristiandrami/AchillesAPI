"""Human-friendly suite naming from the imported OpenAPI contract.

Pure presentation metadata: executable job IDs, paths, manifests and scope remain unchanged.
"""
from __future__ import annotations

import re
from typing import Any


def api_name_from_spec(spec: dict[str, Any]) -> str:
    """Use info.title without trusting it as HTML, a filename or an identifier."""
    info = spec.get('info') if isinstance(spec, dict) else None
    title = info.get('title') if isinstance(info, dict) else None
    if not isinstance(title, str):
        return 'API senza titolo'
    # Only printable text; limit size to avoid huge UI labels or misleading multi-line names.
    cleaned = re.sub(r'\s+', ' ', ''.join(ch for ch in title if ch.isprintable())).strip()
    return cleaned[:100].rstrip() or 'API senza titolo'


def suite_identity(spec: dict[str, Any], job_id: str) -> dict[str, str]:
    """The short visual code is a prefix of the immutable 32-char suite ID."""
    name = api_name_from_spec(spec)
    code = job_id[:12]
    return {'api_name': name, 'suite_code': code,
            'display_name': f'{name} · {code}'}
