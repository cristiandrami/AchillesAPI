"""Optional engagement facts that OpenAPI cannot know.

This configuration does not contain secrets: authentication credentials stay
in environment-backed authentication profiles. It describes only approved test
identifiers and the expected access policy for known test accounts.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class ContextError(ValueError):
    """Raised when the operator context has invalid or unsupported fields."""


def read_context(path: str | Path | None) -> dict[str, Any]:
    """Validate an optional YAML file and return only known configuration keys.

    The file is fully offline. To avoid silent mistakes during professional
    testing, unknown fields cause an error instead of being ignored.
    """
    if path is None:
        return {"path_values": {}, "expected_access": {}}
    try:
        content = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ContextError("Cannot read or parse the engagement context YAML.") from exc
    if not isinstance(content, dict):
        raise ContextError("The context must be a YAML mapping.")
    if set(content) - {"path_values", "expected_access"}:
        raise ContextError("Unknown context field. Allowed: path_values, expected_access.")
    raw_values = content.get("path_values", {})
    raw_access = content.get("expected_access", {})
    if not isinstance(raw_values, dict) or not isinstance(raw_access, dict):
        raise ContextError("path_values and expected_access must be mappings.")
    values = {}
    for key, value in raw_values.items():
        if not isinstance(key, str) or not key or isinstance(value, (dict, list, bool)) or value is None:
            raise ContextError("Each path_values item needs a name and a scalar string/number value.")
        values[key] = str(value)
    access = {}
    for operation, identities in raw_access.items():
        if not isinstance(operation, str) or not operation.startswith("GET /"):
            raise ContextError("expected_access keys must look like GET /resource/{id}.")
        if not isinstance(identities, dict) or not identities:
            raise ContextError("Every expected_access operation needs identity rules.")
        rules = {}
        for identity, expected in identities.items():
            if not isinstance(identity, str) or expected not in ("allow", "deny"):
                raise ContextError("Expected access must be allow/deny for a named identity.")
            rules[identity] = expected
        access[operation] = rules
    return {"path_values": values, "expected_access": access}
