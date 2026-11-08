"""Non-destructive OpenAPI response-contract checks (metadata-only evidence).

These checks are not direct proof of a vulnerability. Incorrect or outdated
OpenAPI definitions can also cause mismatches. Values never enter the report.
"""
from __future__ import annotations

import json
from typing import Any

from achillesapi.core.testgen import _resolve_schema


def _type_ok(value: Any, kind: str) -> bool:
    """Match JSON primitive types while distinguishing booleans from integers."""
    return {
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
        "string": lambda: isinstance(value, str),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda: isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": lambda: isinstance(value, bool),
        "null": lambda: value is None,
    }.get(kind, lambda: True)()


def _inspect(spec: dict[str, Any], schema: Any, value: Any, *, prefix: str = "",
             depth: int = 0, limit: int = 40) -> list[dict[str, str]]:
    """Compare bounded JSON keys/types with a documented schema, not their values."""
    if depth >= 6 or limit <= 0:
        return []
    rule = _resolve_schema(spec, schema)
    kind = rule.get("type")
    if isinstance(kind, list):
        if any(_type_ok(value, entry) for entry in kind):
            kind = None
        else:
            kind = kind[0] if kind else None
    issues = []
    if isinstance(kind, str) and not _type_ok(value, kind):
        return [{"property_path": prefix or "$", "problem": "type_mismatch", "expected_type": kind}]
    if isinstance(value, dict):
        properties = rule.get("properties", {})
        if not isinstance(properties, dict):
            return issues
        required = rule.get("required", [])
        if isinstance(required, list):
            for key in required[:40]:
                if isinstance(key, str) and key not in value:
                    issues.append({"property_path": (prefix + "." if prefix else "") + key,
                                   "problem": "missing_required_property"})
        for key, child in list(value.items())[:40]:
            if key in properties:
                path = (prefix + "." if prefix else "") + key
                issues.extend(_inspect(spec, properties[key], child, prefix=path,
                                       depth=depth + 1, limit=limit - 1))
                if len(issues) >= 40:
                    break
    elif isinstance(value, list) and isinstance(rule.get("items"), dict):
        for child in value[:2]:
            issues.extend(_inspect(spec, rule["items"], child, prefix=prefix + "[]",
                                   depth=depth + 1, limit=limit - 1))
    return issues[:40]


def response_contract_issues(spec: dict[str, Any], endpoint: Any,
                             status: int, text: str, content_type: str,
                             truncated: bool) -> list[dict[str, str]]:
    """Return safe field-path mismatches for a complete JSON success response.

    Never run on truncated bodies, non-JSON responses, or statuses without a
    declared JSON schema. This reduces ambiguous false positives.
    """
    if status < 200 or status >= 300 or truncated or "json" not in content_type.lower():
        return []
    declared = endpoint.responses.get(str(status)) or endpoint.responses.get("2XX")
    if not isinstance(declared, dict):
        return []
    resolved = _resolve_schema(spec, declared)
    media = resolved.get("content", {})
    if not isinstance(media, dict):
        return []
    schema = next((item.get("schema") for name, item in media.items()
                   if "json" in name.lower() and isinstance(item, dict) and item.get("schema")), None)
    if not schema:
        return []
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return [{"property_path": "$", "problem": "invalid_json"}]
    return _inspect(spec, schema, payload)
