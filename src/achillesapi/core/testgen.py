"""Deterministic, offline generation of API security test plans from OpenAPI.

This module creates proposals only. It never sends HTTP requests, resolves
credentials, or treats inferred relationships as confirmed vulnerabilities.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from achillesapi.models.api import EndpointInfo, ParsedAPI

_ID_NAME = re.compile(r"(?:^|[_-])(?:id|uuid|key)$|(?:Id|ID|Uuid|UUID|Key)$|^(?:id|uuid|key)$")
_PRIVILEGED = re.compile(r"admin|manage|privileged|internal|moderator|staff", re.I)
_SENSITIVE = re.compile(
    r"password|passwd|secret|token|api.?key|authorization|ssn|tax.?id|"
    r"credit.?card|card.?number|private.?key|refresh.?token", re.I,
)
_WRITE_METHODS = {"POST", "PUT", "PATCH"}
_OBJECT_METHODS = {"GET", "PUT", "PATCH", "DELETE"}


def _resolve_schema(spec: dict[str, Any], schema: Any, depth: int = 0) -> dict[str, Any]:
    """In pratica: Trova lo schema effettivo quando compare un riferimento a un componente.

    Attenzione: Non contatta direttamente l'API target.
    """
    if depth > 20 or not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if not isinstance(ref, str):
        return schema
    if not ref.startswith("#/"):
        return {}
    current: Any = spec
    try:
        for token in ref[2:].split("/"):
            current = current[token.replace("~1", "/").replace("~0", "~")]
    except (KeyError, TypeError):
        return {}
    if not isinstance(current, dict):
        return {}
    return {**current, **{k: v for k, v in schema.items() if k != "$ref"}}


def _json_schemas(spec: dict[str, Any], body: Any) -> list[dict[str, Any]]:
    """In pratica: Individua gli schemi JSON presenti nei corpi di richiesta o risposta.

    Attenzione: Non contatta direttamente l'API target.
    """
    body = _resolve_schema(spec, body)
    content = body.get("content", {})
    result: list[dict[str, Any]] = []
    if isinstance(content, dict):
        for media_type, media in content.items():
            if isinstance(media_type, str) and ("json" in media_type.lower()) and isinstance(media, dict):
                schema = media.get("schema")
                if isinstance(schema, dict):
                    result.append(schema)
    return result


def _properties(spec: dict[str, Any], schema: Any, prefix: str = "", depth: int = 0) -> list[dict[str, Any]]:
    """In pratica: Esamina le proprietà di uno schema, comprese quelle annidate.

    Attenzione: Non contatta direttamente l'API target.
    """
    if depth > 10:
        return []
    resolved = _resolve_schema(spec, schema)
    found: list[dict[str, Any]] = []
    props = resolved.get("properties", {})
    if isinstance(props, dict):
        required = set(resolved.get("required", [])) if isinstance(resolved.get("required", []), list) else set()
        for name, raw in props.items():
            if not isinstance(name, str) or not isinstance(raw, dict):
                continue
            prop = _resolve_schema(spec, raw)
            path = f"{prefix}.{name}" if prefix else name
            found.append({
                "name": path, "type": prop.get("type", "unknown"),
                "format": prop.get("format"), "required": name in required,
                "read_only": bool(prop.get("readOnly")),
                "write_only": bool(prop.get("writeOnly")),
                "sensitive_name": bool(_SENSITIVE.search(name)),
                "enum": prop.get("enum") if isinstance(prop.get("enum"), list) else None,
            })
            found.extend(_properties(spec, prop, path, depth + 1))
    return found


def _case(case_id: str, category: str, endpoint: EndpointInfo, title: str,
          objective: str, steps: list[str], *, risk: str = "low",
          prerequisites: list[str] | None = None, evidence: list[str] | None = None) -> dict[str, Any]:
    """In pratica: Costruisce una scheda test con obiettivo, prerequisiti ed evidenze richieste.

    Attenzione: Non contatta direttamente l'API target.
    """
    return {
        "id": case_id, "category": category, "title": title,
        "endpoint": {"method": endpoint.method, "path": endpoint.path,
                     "operation_id": endpoint.operation_id},
        "objective": objective, "steps": steps,
        "prerequisites": prerequisites or [],
        "evidence_to_collect": evidence or ["HTTP status", "response metadata", "request correlation ID"],
        "risk": risk, "execution": "manual_review_required",
        "confidence": "candidate_requires_policy_validation",
        "generated_from": "openapi_metadata_and_heuristics",
    }


def generate_test_plan(parsed: ParsedAPI, spec: dict[str, Any]) -> dict[str, Any]:
    """Generate deterministic, non-executable security test proposals."""
    # IN PRATICA: Crea proposte di test leggendo lo Swagger: non invia richieste.
    # SICUREZZA: Non contatta direttamente l'API target.
    cases: list[dict[str, Any]] = []
    workflows: list[dict[str, Any]] = []
    warnings: list[str] = []
    seq = 1

    for endpoint in parsed.endpoints:
        method, path = endpoint.method, endpoint.path
        ids = [p for p in endpoint.path_parameters if _ID_NAME.search(p.name)]
        if method in _OBJECT_METHODS and ids:
            for parameter in ids:
                cases.append(_case(
                    f"AT-{seq:04d}", "BOLA", endpoint,
                    f"Object-level authorization for {parameter.name}",
                    "Verify that a principal cannot read or modify an object owned by another principal.",
                    [f"Prepare two distinct authorized principals (owner and non-owner).",
                     f"Obtain two valid values for path parameter '{parameter.name}' from the approved test dataset.",
                     "Request the same object as its owner and as the non-owner.",
                     "For write methods, use an isolated disposable object and an approved reset procedure."],
                    risk="medium" if method in {"PUT", "PATCH", "DELETE"} else "low",
                    prerequisites=["Two test identities", "Known ownership mapping", "In-scope test objects"],
                    evidence=["Owner/non-owner status comparison", "Response property-path comparison", "Object ownership oracle"],
                )); seq += 1

        if _PRIVILEGED.search(path) or any(_PRIVILEGED.search(tag) for tag in endpoint.tags):
            cases.append(_case(
                f"AT-{seq:04d}", "BFLA", endpoint, "Function-level authorization boundary",
                "Verify that a low-privilege identity cannot invoke a privileged function.",
                ["Identify the intended role policy with the API owner.",
                 "Call the operation with an authorized privileged test identity.",
                 "Repeat with a low-privilege identity and compare authorization outcomes."],
                prerequisites=["Documented role policy", "Privileged and low-privilege test identities"],
                evidence=["Expected versus observed authorization decision", "HTTP status", "Response metadata"],
            )); seq += 1

        if method == "GET":
            for response in endpoint.responses.values():
                for schema in _json_schemas(spec, response):
                    sensitive = [p for p in _properties(spec, schema)
                                 if p["sensitive_name"] or p["write_only"]]
                    if sensitive:
                        names = [p["name"] for p in sensitive]
                        cases.append(_case(
                            f"AT-{seq:04d}", "BOPLA", endpoint, "Sensitive property exposure review",
                            "Check whether the response exposes properties that should not be readable by this role.",
                            ["Review the intended response DTO and field-level access policy.",
                             "Call the endpoint with a least-privilege test identity.",
                             "Compare returned property paths with the approved allowlist."],
                            prerequisites=["Expected response-field policy", "Least-privilege test identity"],
                            evidence=["Returned JSON property paths", "Approved field allowlist", "Role context"],
                        )); cases[-1]["candidate_properties"] = names; seq += 1

        if method in _WRITE_METHODS:
            candidates: list[str] = []
            for schema in _json_schemas(spec, endpoint.request_body):
                for prop in _properties(spec, schema):
                    if prop["read_only"] or prop["sensitive_name"]:
                        candidates.append(prop["name"])
            if candidates:
                cases.append(_case(
                    f"AT-{seq:04d}", "MASS_ASSIGNMENT", endpoint,
                    "Writable-property allowlist validation",
                    "Verify that server-controlled or sensitive properties cannot be changed through client input.",
                    ["Use a disposable test object and snapshot its initial state.",
                     "Submit only documented writable fields and record the baseline.",
                     "In a separate isolated test, add one candidate restricted field at a time.",
                     "Verify persisted state and restore the fixture."],
                    risk="high", prerequisites=["Disposable test object", "Field-level write policy", "Reliable reset/teardown"],
                    evidence=["Before/after object state", "Accepted/rejected property paths", "Server-side validation result"],
                )); cases[-1]["candidate_properties"] = sorted(set(candidates)); seq += 1

        for parameter in endpoint.parameters:
            schema = parameter.schema_
            if any(key in schema for key in ("enum", "minimum", "maximum", "minLength", "maxLength", "pattern")):
                cases.append(_case(
                    f"AT-{seq:04d}", "PARAMETER_VALIDATION", endpoint,
                    f"Constraint validation for {parameter.location} parameter '{parameter.name}'",
                    "Check that documented parameter constraints are enforced consistently.",
                    ["Send one valid in-policy value.", "Test each documented boundary and one out-of-range value.",
                     "Confirm errors are controlled and do not disclose internals."],
                    prerequisites=["Approved non-destructive test values"],
                    evidence=["Constraint tested", "HTTP status", "Error response shape"],
                )); cases[-1]["constraint"] = {k: schema[k] for k in ("enum", "minimum", "maximum", "minLength", "maxLength", "pattern") if k in schema}; seq += 1

    # Suggest collection-to-item workflows from path-template relationships.
    by_path: dict[str, list[EndpointInfo]] = defaultdict(list)
    for endpoint in parsed.endpoints:
        by_path[endpoint.path].append(endpoint)
    for collection_path, collection_ops in by_path.items():
        if "{" in collection_path or not collection_path.rstrip("/"):
            continue
        item_prefix = collection_path.rstrip("/") + "/{"
        item_paths = sorted(p for p in by_path if p.startswith(item_prefix))
        creates = [e for e in collection_ops if e.method == "POST"]
        for item_path in item_paths:
            reads = [e for e in by_path[item_path] if e.method == "GET"]
            if creates and reads:
                workflows.append({
                    "id": f"WF-{len(workflows)+1:03d}",
                    "title": f"Create then access resource under {collection_path}",
                    "confidence": "inferred_path_relationship",
                    "steps": [
                        {"method": "POST", "path": collection_path, "purpose": "Create a disposable resource and capture its returned identifier."},
                        {"method": "GET", "path": item_path, "purpose": "Read the created resource using the captured identifier."},
                    ],
                    "security_checks": ["Ownership enforcement", "Role authorization", "Response field exposure"],
                    "requires_manual_fixture_and_policy_review": True,
                })

    if not workflows:
        warnings.append("No unambiguous POST collection-to-item GET workflow could be inferred from path templates.")
    if not cases:
        warnings.append("No security test candidates matched the available OpenAPI metadata; this is not evidence of security.")

    identifier_candidates = []
    parameter_inventory = []
    for endpoint in parsed.endpoints:
        for parameter in endpoint.parameters:
            schema = parameter.schema_
            is_identifier = parameter.location == "path" and bool(_ID_NAME.search(parameter.name))
            parameter_inventory.append({
                "endpoint": {"method": endpoint.method, "path": endpoint.path},
                "name": parameter.name, "location": parameter.location,
                "required": parameter.required,
                "type": schema.get("type", "unknown"),
                "format": schema.get("format"),
                "has_constraints": any(k in schema for k in ("enum", "minimum", "maximum", "minLength", "maxLength", "pattern")),
            })
            if is_identifier:
                identifier_candidates.append({
                    "endpoint": {"method": endpoint.method, "path": endpoint.path},
                    "parameter": parameter.name, "format": schema.get("format"),
                    "type": schema.get("type", "unknown"),
                    "confidence": "heuristic_name_match",
                    "note": "Candidate identifier only; verify against API semantics and ownership model.",
                })

    return {
        "tool": "AchillesAPI", "generator_version": "0.8.0",
        "specification": {"title": parsed.title, "version": parsed.version,
                          "openapi_version": parsed.openapi_version},
        "summary": {"endpoint_count": parsed.endpoint_count, "test_case_count": len(cases),
                    "workflow_count": len(workflows)},
        "execution_policy": {
            "executed": False,
            "network_requests_sent": 0,
            "requires_explicit_execution_approval": True,
            "ai_used": False,
            "secrets_resolved": False,
            "note": "Generated proposals only. Review scope, policy, fixtures and teardown before execution.",
        },
        "discovery": {
            "object_identifier_candidates": identifier_candidates,
            "parameters": parameter_inventory,
            "limitations": [
                "Identifier discovery uses parameter names and OpenAPI types; it does not query live data.",
                "No concrete object IDs, credentials, cookies or example values are harvested.",
                "Endpoint dependencies are inferred from path templates and require validation.",
            ],
        },
        "test_cases": cases, "workflows": workflows, "warnings": warnings,
    }
