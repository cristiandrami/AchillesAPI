"""OpenAPI-independent intelligence layer: deterministic and entirely offline.

This module never calls the target. It generates schema-conformant *candidate*
values, infers possible producer/consumer dependencies, and ranks checks by
applicability. Candidates are not production fixtures or proof of authorization.
"""
from __future__ import annotations

from typing import Any
import re
from achillesapi.core.testgen import _resolve_schema
from achillesapi.models.api import ParsedAPI

_MAX_DEPTH = 6
_MAX_FIELDS = 40


def sample_value(spec: dict[str, Any], raw: Any, depth: int = 0) -> tuple[Any, list[str]]:
    """Build a bounded example using schema examples/defaults/enums and types.

    Return (value, warnings). Synthetic values such as 1 or 'example' are
    *placeholders*, never inferred IDs or authorization grants. Cycles stop at
    depth six, preventing malicious schemas from exhausting resources.
    """
    if depth >= _MAX_DEPTH:
        return None, ["schema_depth_limit"]
    schema = _resolve_schema(spec, raw)
    if not schema:
        return None, ["unknown_schema"]
    for field in ("const", "example", "default"):
        if field in schema:
            return schema[field], []
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0], []
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0], []
    if "allOf" in schema:
        merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
        for part in schema["allOf"][:10]:
            resolved = _resolve_schema(spec, part)
            merged["properties"].update(resolved.get("properties", {}))
            merged["required"].extend(resolved.get("required", []))
        return sample_value(spec, merged, depth + 1)
    for variant in ("oneOf", "anyOf"):
        if isinstance(schema.get(variant), list) and schema[variant]:
            value, warnings = sample_value(spec, schema[variant][0], depth + 1)
            return value, [f"{variant}_first_variant_only", *warnings]
    typ = schema.get("type")
    if isinstance(typ, list):
        typ = next((x for x in typ if x != "null"), "null")
    if typ == "object" or (typ is None and "properties" in schema):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return {}, ["invalid_properties"]
        result: dict[str, Any] = {}
        warnings: list[str] = []
        required = schema.get("required", [])
        for key in required[:_MAX_FIELDS] if isinstance(required, list) else []:
            if key not in properties:
                warnings.append(f"missing_schema_for:{key}")
                continue
            prop = _resolve_schema(spec, properties[key])
            if prop.get("readOnly"):
                continue
            value, issues = sample_value(spec, properties[key], depth + 1)
            result[key] = value
            warnings.extend(f"{key}:{issue}" for issue in issues)
        if isinstance(required, list) and len(required) > _MAX_FIELDS:
            warnings.append("field_limit")
        return result, warnings
    if typ == "array":
        item, warnings = sample_value(spec, schema.get("items", {}), depth + 1)
        return [item] * max(1, min(2, int(schema.get("minItems", 1) or 1))), warnings
    if typ in ("integer", "number"):
        minimum = schema.get("minimum", 1)
        try:
            return max(1, minimum), ["synthetic_numeric_placeholder"]
        except TypeError:
            return 1, ["synthetic_numeric_placeholder"]
    if typ == "boolean":
        return False, ["synthetic_boolean_placeholder"]
    if typ == "string":
        fmt = schema.get("format")
        if fmt == "uuid":
            return "00000000-0000-4000-8000-000000000001", ["synthetic_uuid_placeholder"]
        if fmt == "date":
            return "2026-01-01", ["synthetic_date_placeholder"]
        if fmt == "date-time":
            return "2026-01-01T00:00:00Z", ["synthetic_datetime_placeholder"]
        if fmt == "email":
            return "tester@example.invalid", ["synthetic_email_placeholder"]
        minimum = schema.get("minLength", 0)
        return "example".ljust(min(128, max(7, minimum if isinstance(minimum, int) else 7)), "x"), ["synthetic_string_placeholder"]
    return None, [f"unsupported_type:{typ}"]


def _response_fields(spec: dict[str, Any], endpoint: Any) -> set[str]:
    """Extract candidate JSON field names from successful response schemas."""
    names: set[str] = set()
    for status, response in endpoint.responses.items():
        if not str(status).startswith("2") or not isinstance(response, dict):
            continue
        body = _resolve_schema(spec, response)
        for media, entry in body.get("content", {}).items():
            if "json" not in media or not isinstance(entry, dict):
                continue
            schema = _resolve_schema(spec, entry.get("schema", {}))
            if schema.get("type") == "array":
                schema = _resolve_schema(spec, schema.get("items", {}))
            names.update(schema.get("properties", {}).keys())
    return names


def intelligent_plan(parsed: ParsedAPI, spec: dict[str, Any]) -> dict[str, Any]:
    """Rank checks and suggest response-to-path dependencies without lab names.

    Never execute a candidate relationship automatically: same-name fields can
    refer to unrelated resources, and a path ID may belong to another tenant.
    """
    operations: list[dict[str, Any]] = []
    producers = [(ep, _response_fields(spec, ep)) for ep in parsed.endpoints]
    edges: list[dict[str, Any]] = []
    for ep in parsed.endpoints:
        parameters = []
        for param in ep.parameters:
            if param.location not in {"path", "query"}:
                continue
            value, warnings = sample_value(spec, param.schema_)
            parameters.append({"name": param.name, "in": param.location, "required": param.required,
                               "candidate": value, "warnings": warnings})
            if param.location == "path":
                for producer, fields in producers:
                    if producer is ep:
                        continue
                    if (param.name in fields or
                        (re.search(r"(?:id|ref|uuid)$", param.name.lower()) and "id" in fields and
                         (producer.path.rstrip("/") == ep.path.split("/{")[0].rstrip("/") or
                          producer.path.rstrip("/") == ep.path.rsplit("/", 1)[0].rstrip("/")))):
                        edges.append({"producer": f"{producer.method} {producer.path}",
                                      "consumer": f"{ep.method} {ep.path}",
                                      "source_field": param.name if param.name in fields else "id",
                                      "target_parameter": param.name,
                                      "confidence": "heuristic", "requires_approval": True})
        body_candidates = []
        if ep.request_body:
            for media, content in ep.request_body.get("content", {}).items():
                if "json" in media and isinstance(content, dict):
                    value, warnings = sample_value(spec, content.get("schema", {}))
                    body_candidates.append({"content_type": media, "candidate": value,
                                            "warnings": warnings, "execute_automatically": False})
        checks = ["baseline", "response_schema", "error_disclosure"] if ep.method == "GET" else ["workflow_candidate"]
        if ep.security:
            checks.extend(["missing_auth", "role_comparison"])
        if ep.method == "GET" and ep.query_parameters:
            checks.append("bounded_input_validation")
        if ep.method in {"POST", "PUT", "PATCH"}:
            checks.extend(["property_authorization_candidate", "mass_assignment_candidate"])
        operations.append({"operation": f"{ep.method} {ep.path}", "checks": checks,
                           "parameters": parameters, "request_bodies": body_candidates,
                           "needs_fixture_approval": ep.method != "GET"})
    # Deduplicate while preserving stable order; avoid quadratic output growth.
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for edge in edges:
        key = (edge["producer"], edge["consumer"], edge["target_parameter"])
        if key not in seen:
            unique.append(edge)
            seen.add(key)
        if len(unique) >= 500:
            break
    return {"engine": "intelligent-planner-v0.16", "network_requests_sent": 0,
            "operations": operations, "candidate_dependencies": unique,
            "limitations": ["Synthetic values are not real fixtures.",
                            "Dependencies are heuristic and require confirmation.",
                            "Writes require explicit approved workflow configuration."]}


def adaptive_queue(plan: dict[str, Any], observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prioritize remaining checks from observed HTTP status, without making requests.

    401/403 suggest a missing or invalid identity; 5xx merits error review;
    2xx merits response schema review. No HTTP status proves vulnerability.
    """
    known = {str(x.get("operation")): x for x in plan.get("operations", [])}
    queue = []
    for observation in observations:
        op = str(observation.get("operation", ""))
        if op not in known:
            continue
        status = observation.get("status")
        if status in (401, 403):
            next_check, reason = "verify_auth_profile", "access_denied"
        elif isinstance(status, int) and status >= 500:
            next_check, reason = "review_error_disclosure", "server_error"
        elif isinstance(status, int) and 200 <= status < 300:
            next_check, reason = "compare_response_schema", "successful_response"
        else:
            next_check, reason = "review_observation", "inconclusive"
        queue.append({"operation": op, "suggested_check": next_check,
                      "reason": reason, "automatically_authorized": False})
    return queue
