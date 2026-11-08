"""Discover possible GET->GET data dependencies from response schemas.

This is structural inference only. It never calls the target, assumes object
ownership, or authorizes a workflow. Users review YAML before execution.
"""
from __future__ import annotations

import re
from typing import Any

from achillesapi.core.generic import _POSSIBLE_MUTATION
from achillesapi.core.testgen import _resolve_schema
from achillesapi.models.api import ParsedAPI

_SLOT = re.compile(r"\{([^{}]+)\}")


def _json_response_fields(spec: dict[str, Any], endpoint: Any) -> dict[str, str]:
    """Map response property names to JSON Pointers, including nested arrays."""
    result: dict[str, str] = {}
    def visit(schema: Any, pointer: str, depth: int) -> None:
        """Traverse bounded schema references; avoid cycles and huge documents."""
        if depth >= 6 or len(result) >= 100:
            return
        rule = _resolve_schema(spec, schema)
        if not rule:
            return
        if rule.get("type") == "array":
            visit(rule.get("items", {}), pointer + "/0", depth + 1)
        props = rule.get("properties")
        if isinstance(props, dict):
            for key, child in list(props.items())[:100]:
                escaped = str(key).replace("~", "~0").replace("/", "~1")
                next_ptr = pointer + "/" + escaped
                result.setdefault(str(key), next_ptr)
                visit(child, next_ptr, depth + 1)
    for code, raw in endpoint.responses.items():
        if not str(code).startswith("2"):
            continue
        response = _resolve_schema(spec, raw)
        for media, value in response.get("content", {}).items():
            if isinstance(media, str) and "json" in media.lower() and isinstance(value, dict):
                visit(value.get("schema", {}), "", 0)
    return result


def discover_read_journeys(parsed: ParsedAPI, spec: dict[str, Any]) -> dict[str, Any]:
    """Propose pairwise GET journeys when response fields match path variables."""
    producers = [(ep, _json_response_fields(spec, ep)) for ep in parsed.endpoints
                 if ep.method == "GET" and not _POSSIBLE_MUTATION.search(ep.path)]
    candidates = []
    seen = set()
    for destination in parsed.endpoints:
        if destination.method != "GET" or _POSSIBLE_MUTATION.search(destination.path):
            continue
        slots = _SLOT.findall(destination.path)
        if not slots:
            continue
        for source, fields in producers:
            if source is destination:
                continue
            for slot in slots:
                if slot not in fields:
                    continue
                pair = (source.path, destination.path, slot)
                if pair in seen:
                    continue
                seen.add(pair)
                # Prefer a collection URL that is the direct parent of the
                # item endpoint; this is a heuristic, never permission.
                collection = destination.path.split("/{", 1)[0].rstrip("/")
                relation = "collection_to_item" if source.path.rstrip("/") == collection else "field_name_match"
                candidates.append({
                    "producer": "GET " + source.path,
                    "consumer": "GET " + destination.path,
                    "source_pointer": fields[slot],
                    "target_parameter": slot,
                    "relationship": relation,
                    "confidence": "structural_guess",
                    "requires_review": True,
                })
                if len(candidates) >= 200:
                    break
    candidates.sort(key=lambda x: (x["relationship"] != "collection_to_item", x["producer"], x["consumer"]))
    return {"engine": "read-journey-discovery-v0.18", "network_requests_sent": 0,
            "candidates": candidates[:200], "count": len(candidates[:200]),
            "warning": "Structural links do not establish ownership, credentials, or safe execution"}


def journey_draft(parsed: ParsedAPI, candidate: dict[str, Any]) -> dict[str, Any]:
    """Create an intentionally incomplete two-GET YAML starter for human review."""
    first = next(e for e in parsed.endpoints if "GET " + e.path == candidate["producer"] and e.method == "GET")
    second = next(e for e in parsed.endpoints if "GET " + e.path == candidate["consumer"] and e.method == "GET")
    variable = "captured_" + re.sub(r"\W", "_", candidate["target_parameter"])
    start_values = {p.name: "REPLACE_WITH_APPROVED_TEST_VALUE" for p in first.parameters
                    if p.required and p.location in ("path", "query")}
    next_values = {p.name: ("$" + variable if p.name == candidate["target_parameter"]
                             else "REPLACE_WITH_APPROVED_TEST_VALUE")
                   for p in second.parameters if p.required and p.location in ("path", "query")}
    return {"steps": [
        {"operation": candidate["producer"], "identity": "REPLACE_WITH_AUTH_PROFILE",
         "values": start_values, "capture": {variable: candidate["source_pointer"]}},
        {"operation": candidate["consumer"], "identity": "REPLACE_WITH_AUTH_PROFILE",
         "values": next_values},
    ]}
