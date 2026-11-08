"""Generic object-lifecycle testing for **authorized, disposable** API fixtures.

This engine is independent from the demo API. It finds CRUD patterns in OpenAPI
and can test a selected fixture end-to-end: create -> verify ownership ->
compare another identity -> optionally test a restricted property -> delete.

Automatic writes are NEVER inferred from Swagger. The operator must name the
methods, provide a disposable fixture body and a cleanup operation, and explicitly
approve execution. The tool reports cleanup failures rather than promising that
rollback always succeeds. Every function below has a plain-language docstring.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import yaml

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.generic import _matches_security_scheme, _POSSIBLE_MUTATION
from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.core.testgen import _resolve_schema
from achillesapi.models.api import EndpointInfo, ParsedAPI


class WorkflowError(ValueError):
    """The workflow is missing required safety information or is not in OpenAPI."""


_OPERATION = re.compile(r"^(GET|POST|PATCH|PUT|DELETE) (/[^?#]*)$")
_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
_MAX_BODY_BYTES = 16_384
_SENSITIVE_FIELDS = re.compile(r"password|secret|token|api.?key|credential", re.I)


def _op_parts(value: str) -> tuple[str, str]:
    """Split 'METHOD /path' and reject anything that could redirect traffic."""
    match = _OPERATION.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise WorkflowError("Operations must look like 'POST /resources' or 'GET /resources/{id}'.")
    method, path = match.groups()
    if path.startswith("//") or "\\" in path or re.search(r"%(?:2e|2f|5c)", path, re.I) or any(
        item in (".", "..") for item in path.split("/")
    ):
        raise WorkflowError("Operation paths cannot contain traversal or absolute redirects.")
    return method, path


def _operation(parsed: ParsedAPI, value: str, methods: set[str]) -> EndpointInfo:
    """Ensure the requested method and path exist in the supplied Swagger file."""
    method, path = _op_parts(value)
    if method not in methods:
        raise WorkflowError(f"Unsupported method for workflow step: {method}.")
    for endpoint in parsed.endpoints:
        if endpoint.method == method and endpoint.path == path:
            if method == "GET" and _POSSIBLE_MUTATION.search(
                " ".join([path, endpoint.operation_id or ""])
            ):
                raise WorkflowError("GET route may change state and is not safe for automatic testing.")
            return endpoint
    raise WorkflowError(f"Operation not declared in OpenAPI: {value}.")


def _validate_keys(value: Any, allowed: set[str], label: str) -> dict[str, Any]:
    """Reject unknown YAML fields; silent typos could run the wrong test."""
    if not isinstance(value, dict) or set(value) - allowed:
        raise WorkflowError(f"{label} must be a mapping with only: {', '.join(sorted(allowed))}.")
    return value


def read_workflows(path: Path | str) -> list[dict[str, Any]]:
    """Load operator-approved disposable fixtures. No network calls or secrets."""
    try:
        content = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise WorkflowError("Unable to read workflow YAML.") from exc
    top = _validate_keys(content, {"workflows"}, "Workflow file")
    workflows = top.get("workflows")
    if not isinstance(workflows, list) or not workflows:
        raise WorkflowError("'workflows' must contain at least one test scenario.")
    if len(workflows) > 20:
        raise WorkflowError("Maximum 20 explicitly approved workflows per execution.")
    for raw in workflows:
        # Drafts cannot run until the operator supplies real disposable values.
        if "REPLACE_ME" in json.dumps(raw):
            raise WorkflowError("Workflow still contains REPLACE_ME placeholders. Review and fill its values.")
        wf = _validate_keys(raw, {"name", "create", "read", "access", "mutation", "cleanup",
                                  "restricted_response_fields", "path_values", "mutations"}, "Workflow")
        if not isinstance(wf.get("name"), str) or not re.fullmatch(r"[\w.-]{1,64}", wf["name"]):
            raise WorkflowError("Each workflow needs a short alphanumeric name.")
        create = _validate_keys(wf.get("create"), {"operation", "identity", "body", "id_pointer", "marker_field"}, "create")
        if not isinstance(create.get("body"), dict) or not create["body"]:
            raise WorkflowError("Create requires an explicit nonempty disposable JSON body.")
        if len(json.dumps(create["body"])) > _MAX_BODY_BYTES:
            raise WorkflowError("Create JSON body exceeds the safe 16 KB limit.")
        read = _validate_keys(wf.get("read"), {"operation", "identity", "id_parameter", "id_pointer", "marker_pointer"}, "read")
        cleanup = _validate_keys(wf.get("cleanup"), {"operation", "identity"}, "cleanup")
        for section in (create, read, cleanup):
            if not isinstance(section.get("operation"), str) or not isinstance(section.get("identity"), str):
                raise WorkflowError("Each create/read/cleanup step needs an operation and identity.")
        for pointer in (create.get("id_pointer"), read.get("id_pointer")):
            if not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 128:
                raise WorkflowError("Provide explicit JSON Pointers (e.g. /data/id) for created/read IDs.")
        if not isinstance(read.get("id_parameter"), str) or not read["id_parameter"]:
            raise WorkflowError("read.id_parameter must identify the resource path placeholder.")
        marker = create.get("marker_field")
        if not isinstance(marker, str) or not marker or marker not in create["body"]:
            raise WorkflowError("create.marker_field must name a writable string field in the approved create body.")
        if not isinstance(create["body"][marker], str):
            raise WorkflowError("The disposable marker field must contain a string prefix.")
        marker_pointer = read.get("marker_pointer", "/" + marker)
        if not isinstance(marker_pointer, str) or not marker_pointer.startswith("/"):
            raise WorkflowError("read.marker_pointer must be a JSON Pointer such as /label.")
        access = wf.get("access", [])
        if not isinstance(access, list) or len(access) > 12:
            raise WorkflowError("access must be a list with at most twelve checks.")
        for item in access:
            item = _validate_keys(item, {"operation", "identity", "expected", "category"}, "access check")
            if item.get("expected") not in ("allow", "deny") or item.get("category") not in ("BOLA", "BFLA"):
                raise WorkflowError("Each access check needs expected allow/deny and category BOLA/BFLA.")
            if not isinstance(item.get("identity"), str) or not item["identity"]:
                raise WorkflowError("Access checks require an identity name.")
        # v0.21: accept an ordered list of approved, independent mutations.
        # The older singular 'mutation' form remains fully compatible.
        if "mutations" in wf and "mutation" in wf:
            raise WorkflowError("Use either mutation or mutations, never both.")
        mutations = wf.get("mutations", [wf["mutation"]] if "mutation" in wf else [])
        if not isinstance(mutations, list) or len(mutations) > 5:
            raise WorkflowError("mutations must be a list containing at most five approved steps.")
        for mutation in mutations:
            mutation = _validate_keys(mutation, {"operation", "identity", "body", "restricted_fields"}, "mutation")
            if not isinstance(mutation.get("body"), dict) or not mutation["body"]:
                raise WorkflowError("Mutation requires an explicitly approved nonempty JSON body.")
            if len(json.dumps(mutation["body"])) > _MAX_BODY_BYTES:
                raise WorkflowError("Mutation JSON body exceeds 16 KB.")
            restricted = mutation.get("restricted_fields")
            if not isinstance(restricted, list) or not restricted or not all(
                isinstance(x, str) and x in mutation["body"] for x in restricted
            ):
                raise WorkflowError("List the top-level body fields that policy forbids modifying.")
            if not isinstance(mutation.get("identity"), str):
                raise WorkflowError("Mutation requires a test identity.")
        fields = wf.get("restricted_response_fields", [])
        if not isinstance(fields, list) or not all(isinstance(f, str) and f for f in fields):
            raise WorkflowError("restricted_response_fields must be a list of field names.")
        values = wf.get("path_values", {})
        if not isinstance(values, dict) or not all(
            isinstance(k, str) and isinstance(v, (str, int)) and not isinstance(v, bool)
            for k, v in values.items()
        ):
            raise WorkflowError("path_values must map parameter names to approved scalar test values.")
    names = [item["name"] for item in workflows]
    if len(set(names)) != len(names):
        raise WorkflowError("Workflow names must be unique.")
    return workflows


def _request_schema(spec: dict[str, Any], endpoint: EndpointInfo) -> dict[str, Any]:
    """Find the JSON request schema (including local component references)."""
    body = _resolve_schema(spec, endpoint.request_body or {})
    content = body.get("content")
    if not isinstance(content, dict):
        return {}
    for media, entry in content.items():
        if "json" in media.lower() and isinstance(entry, dict):
            return _resolve_schema(spec, entry.get("schema", {}))
    return {}


def _schema_fields(spec: dict[str, Any], endpoint: EndpointInfo) -> list[dict[str, Any]]:
    """List required writable properties without inventing real business data."""
    schema = _request_schema(spec, endpoint)
    props = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(props, dict):
        return []
    result = []
    for name, value in props.items():
        resolved = _resolve_schema(spec, value)
        result.append({"name": name, "required": name in required,
                       "type": resolved.get("type", "unknown"),
                       "read_only": bool(resolved.get("readOnly")),
                       "manual_value_required": name in required and not bool(resolved.get("readOnly"))})
    return result


def discover_workflows(parsed: ParsedAPI, spec: dict[str, Any]) -> dict[str, Any]:
    """Suggest real API CRUD lifecycles using only paths, methods and schemas.

    This is **offline discovery**, not automatic authorization to create data.
    Inferred relationships need operator confirmation before any write.
    """
    by_path: dict[str, dict[str, EndpointInfo]] = {}
    for endpoint in parsed.endpoints:
        by_path.setdefault(endpoint.path, {})[endpoint.method] = endpoint
    candidates = []
    for collection, operations in sorted(by_path.items()):
        if "POST" not in operations or "{" in collection:
            continue
        prefix = collection.rstrip("/") + "/{"
        for item, methods in sorted(by_path.items()):
            if not item.startswith(prefix) or item.count("{") != 1 or not item.endswith("}"):
                continue
            if "GET" not in methods:
                continue
            param = _PLACEHOLDER.search(item)
            candidates.append({
                "collection": collection,
                "create": f"POST {collection}", "read": f"GET {item}",
                "id_parameter": param.group(1) if param else None,
                "delete": f"DELETE {item}" if "DELETE" in methods else None,
                "mutation": next((f"{m} {item}" for m in ("PATCH", "PUT") if m in methods), None),
                "required_create_properties": [p for p in _schema_fields(spec, operations["POST"]) if p["required"]],
                "property_candidates": _schema_fields(spec, methods.get("PATCH") or methods.get("PUT"))
                                       if "PATCH" in methods or "PUT" in methods else [],
                "status": "lifecycle_candidate_requires_review" if "DELETE" in methods
                          else "no_cleanup_operation_do_not_execute",
                "needs": ["two test identities for object-level checks", "approved disposable create body",
                          "confirmed response ID JSON pointers", "confirmed resource ownership policy",
                          "delete/cleanup permission and verification"],
            })
    return {"engine": "workflow-discovery", "network_requests_sent": 0,
            "candidates": candidates, "candidate_count": len(candidates),
            "warning": "These are structural guesses, NOT permission to create or delete resources."}


def draft_workflow_config(parsed: ParsedAPI, spec: dict[str, Any]) -> dict[str, Any]:
    """Create an *unexecutable* YAML starter for every complete CRUD chain.

    In pratica: suggerisce le operazioni, senza inventare account, dati o ID.
    Devi sostituire tutti i valori REPLACE_ME e confermare la policy prima
    di poter usare il file. Un draft NON autorizza test sul target.
    """
    candidates = discover_workflows(parsed, spec)["candidates"]
    workflows: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates, 1):
        if not candidate["delete"]:
            continue
        create_body = {
            field["name"]: "REPLACE_ME_APPROVED_TEST_VALUE"
            for field in candidate["required_create_properties"]
            if not field["read_only"]
        }
        if not create_body:
            # The schema does not tell us which fixture fields are safe.
            create_body = {"REPLACE_ME_FIXTURE_FIELD": "REPLACE_ME_VALUE"}
        workflows.append({
            "name": f"candidate_{index}",
            "create": {"operation": candidate["create"],
                       "identity": "REPLACE_ME_OWNER_PROFILE",
                       "body": create_body,
                       "marker_field": "REPLACE_ME_MARKER_FIELD",
                       "id_pointer": "/REPLACE_ME_RESPONSE_ID_FIELD"},
            "read": {"operation": candidate["read"],
                     "identity": "REPLACE_ME_OWNER_PROFILE",
                     "id_parameter": candidate["id_parameter"],
                     "id_pointer": "/REPLACE_ME_RESPONSE_ID_FIELD",
                     "marker_pointer": "/REPLACE_ME_MARKER_FIELD"},
            "access": [{"identity": "REPLACE_ME_OTHER_PROFILE", "expected": "deny", "category": "BOLA"}],
            "cleanup": {"operation": candidate["delete"],
                        "identity": "REPLACE_ME_OWNER_PROFILE"},
        })
    return {"workflows": workflows}


def _json_pointer(value: Any, pointer: str) -> Any:
    """Read a field from a JSON body by its standard /a/b JSON Pointer."""
    current = value
    for segment in pointer[1:].split("/"):
        part = segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
        if current is None:
            return None
    return current


def _capture_json(evidence: Any) -> Any:
    """Parse a bounded response in memory; never write its body into reports."""
    if not evidence.response or evidence.response.body_truncated:
        return None
    try:
        return json.loads(evidence.response.body_preview)
    except (ValueError, TypeError):
        return None


def _render_template(path: str, *, identifier_name: str, identifier: str | None,
                     values: dict[str, Any]) -> str:
    """Replace path placeholders only with captured IDs or approved test values."""
    def replace(match: re.Match[str]) -> str:
        """Encode one parameter so that its value cannot add a new URL segment."""
        name = match.group(1)
        val = identifier if name == identifier_name else values.get(name)
        if not isinstance(val, (str, int, float)) or isinstance(val, bool):
            raise WorkflowError(f"Missing approved test value for path parameter {name}.")
        item = str(val)
        if not item or item in {".", ".."} or any(ord(c) < 32 for c in item):
            raise WorkflowError("Unsafe or empty path parameter value.")
        return quote(item, safe="")
    return _PLACEHOLDER.sub(replace, path)


def _auth_ok(endpoint: EndpointInfo, material: AuthenticationMaterial,
             definitions: dict[str, dict[str, Any]]) -> bool:
    """Only use identities compatible with the operation's declared security."""
    if not endpoint.security or endpoint.security_is_explicitly_disabled:
        return True
    return any(all(
        name in definitions and _matches_security_scheme(material, definitions[name])
        for name in alternative.schemes
    ) for alternative in endpoint.security)


def _validate_workflows(parsed: ParsedAPI, spec: dict[str, Any], workflows: list[dict[str, Any]],
                        known_profiles: set[str] | None = None) -> list[dict[str, Any]]:
    """Preflight every operation and cleanup path *before* network activity."""
    validated = []
    for wf in workflows:
        create = _operation(parsed, wf["create"]["operation"], {"POST"})
        read = _operation(parsed, wf["read"]["operation"], {"GET"})
        cleanup = _operation(parsed, wf["cleanup"]["operation"], {"DELETE"})
        ident = wf["read"]["id_parameter"]
        if "{" + ident + "}" not in read.path or "{" + ident + "}" not in cleanup.path:
            raise WorkflowError("Read and DELETE must reference the same captured identifier name.")
        if read.path != cleanup.path:
            raise WorkflowError("Cleanup must DELETE the exact resource path being read.")
        if not isinstance(wf["create"].get("id_pointer"), str):
            raise WorkflowError("Explicit create.id_pointer required.")
        if not _request_schema(spec, create):
            raise WorkflowError("Create must declare a JSON request body in OpenAPI.")
        wf_values = wf.get("path_values", {})
        for endpoint in (create, read, cleanup):
            for match in _PLACEHOLDER.findall(endpoint.path):
                if match != ident and match not in wf_values:
                    raise WorkflowError(f"Missing approved path value for {match}.")
        if "{" + ident + "}" in create.path:
            raise WorkflowError("Create cannot require the newly generated resource ID.")
        # Required properties must be present in the explicit disposable body.
        fields = _schema_fields(spec, create)
        marker_field = wf["create"]["marker_field"]
        marker_schema = _resolve_schema(spec, _request_schema(spec, create).get("properties", {}).get(marker_field, {}))
        if marker_schema.get("type") != "string" or marker_schema.get("readOnly"):
            raise WorkflowError("Disposable marker must be a declared, writable string request property.")
        maximum = marker_schema.get("maxLength")
        if isinstance(maximum, int) and maximum < 27:
            raise WorkflowError("Marker field maxLength is too small for safe unique fixture tagging.")
        missing = [f["name"] for f in fields if f["required"] and not f["read_only"]
                   and f["name"] not in wf["create"]["body"]]
        if missing:
            raise WorkflowError("Create fixture misses required schema properties: " + ", ".join(missing))
        access_ops = []
        for entry in wf.get("access", []):
            endpoint = _operation(parsed, entry.get("operation", wf["read"]["operation"]), {"GET"})
            for key in _PLACEHOLDER.findall(endpoint.path):
                if key != ident and key not in wf_values:
                    raise WorkflowError(f"Missing path value for access check: {key}.")
            access_ops.append(endpoint)
        mutations = wf.get("mutations", [wf["mutation"]] if "mutation" in wf else [])
        mutation_steps = []
        for mutate in mutations:
            mutation_op = _operation(parsed, mutate.get("operation"), {"PATCH", "PUT"})
            if mutation_op.path != read.path:
                raise WorkflowError("Mutation must target the newly created disposable resource.")
            if wf["create"]["marker_field"] in mutate["body"]:
                raise WorkflowError("Mutation cannot change the unique disposable marker.")
            if not _request_schema(spec, mutation_op):
                raise WorkflowError("Mutation must declare an application/json request body.")
            mutation_steps.append((mutation_op, mutate))
        referenced = [wf["create"]["identity"], wf["read"]["identity"], wf["cleanup"]["identity"]]
        referenced += [a["identity"] for a in wf.get("access", [])]
        for _, mutate in mutation_steps:
            referenced.append(mutate["identity"])
        if known_profiles is not None and set(referenced) - known_profiles:
            raise WorkflowError("Workflow refers to undefined auth profiles: " +
                                ", ".join(sorted(set(referenced) - known_profiles)))
        planned = 1 + 1 + len(access_ops) + 2 * len(mutation_steps) + 1 + 1
        validated.append({"config": wf, "create": create, "read": read, "cleanup": cleanup,
                          "access_ops": access_ops, "mutation_steps": mutation_steps,
                          "max_requests": planned, "ident": ident})
    return validated


def workflow_plan(parsed: ParsedAPI, spec: dict[str, Any], workflows: list[dict[str, Any]],
                  known_profiles: set[str] | None = None) -> dict[str, Any]:
    """Summarize real requests without printing fixture data or secrets."""
    prepared = _validate_workflows(parsed, spec, workflows, known_profiles)
    return {"engine": "disposable-workflows", "executed": False, "requests_sent": 0,
            "request_budget_required": sum(item["max_requests"] for item in prepared),
            "workflows": [{
                "name": item["config"]["name"],
                "create": item["create"].method + " " + item["create"].path,
                "read": item["read"].method + " " + item["read"].path,
                "delete_cleanup": item["cleanup"].method + " " + item["cleanup"].path,
                "checks": [entry["category"] for entry in item["config"].get("access", [])]
                          + (["MASS_ASSIGNMENT"] if item["mutation_steps"] else [])
                          + (["BOPLA"] if item["config"].get("restricted_response_fields") else []),
                "mutation": (item["mutation_steps"][0][0].method + " " + item["mutation_steps"][0][0].path)
                            if item["mutation_steps"] else None,
                "mutations": [ep.method + " " + ep.path for ep, _ in item["mutation_steps"]],
                "requires_operator_permission": True,
            } for item in prepared],
            "policy": "Only explicitly named disposable fixture operations; cleanup is attempted in finally; cleanup failure requires manual action.",
            "warning": "The workflow requires an HTTP 201 and a unique marker verified by GET before mutation/deletion. Rollback is never guaranteed on server failure."}


def _resolve_body_secrets(value: Any, depth: int = 0) -> Any:
    """Read {$env: NAME} body fields only at execution time, never during planning.

    In pratica: il file YAML contiene il nome della variabile, non la password.
    Il valore viene usato nella richiesta e NON salvato nel report.
    """
    if depth > 12:
        raise WorkflowError("Nested body fields exceed the safe depth limit.")
    if isinstance(value, dict) and set(value) == {"$env"}:
        name = value["$env"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise WorkflowError("Body $env must contain a valid environment variable name.")
        if not os.environ.get(name):
            raise WorkflowError(f"Required secret variable {name} is missing.")
        return os.environ[name]
    if isinstance(value, dict):
        return {key: _resolve_body_secrets(part, depth + 1) for key, part in value.items()}
    if isinstance(value, list):
        return [_resolve_body_secrets(part, depth + 1) for part in value]
    return value


def _safe_response(evidence: Any) -> dict[str, Any]:
    """Export only status, timing and error class; never return response bodies."""
    return {"status": evidence.response.status_code if evidence.response else None,
            "duration_ms": evidence.response.elapsed_ms if evidence.response else None,
            "error_type": evidence.error.split(":", 1)[0] if evidence.error else None}


def _observation(label: str, result: Any) -> dict[str, Any]:
    """Give one request an operator-readable label without exposing object IDs."""
    return {"step": label, **_safe_response(result)}


def run_workflows(parsed: ParsedAPI, spec: dict[str, Any], workflows: list[dict[str, Any]], *,
                  base_url: str, allowed_hosts: set[str], identities: dict[str, AuthenticationMaterial],
                  execute: bool = False, approve_writes: bool = False,
                  allow_insecure_http: bool = False, max_requests: int = 40,
                  rate: float = 1.0, timeout: float = 8.0) -> dict[str, Any]:
    """Execute approved disposable tests; attempt resource cleanup even on failure.

    No request goes out in dry-run. The only objects modified are resources
    created successfully by this very workflow run. A cleanup failure is
    reported explicitly, never silently treated as a successful rollback.
    """
    prepared = _validate_workflows(parsed, spec, workflows, set(identities))
    plan = workflow_plan(parsed, spec, workflows, set(identities))
    if not execute:
        return {**plan, "note": "Dry run: no network requests sent."}
    if not approve_writes:
        raise ScopeError("--approve-writes is required before POST/PATCH/DELETE requests.")
    urlparts = urlsplit(base_url)
    if urlparts.scheme not in {"http", "https"} or not urlparts.hostname:
        raise ScopeError("Provide an absolute HTTP(S) base URL.")
    if urlparts.username or urlparts.password or urlparts.query or urlparts.fragment:
        raise ScopeError("Base URL cannot contain embedded credentials, query or fragment.")
    if any(part in (".", "..") for part in urlparts.path.split("/")):
        raise ScopeError("Base URL contains traversal segments.")
    if urlparts.hostname.lower().rstrip(".") not in {item.lower().rstrip(".") for item in allowed_hosts}:
        raise ScopeError("Base URL is not in the exact hostname allowlist.")
    if urlparts.scheme == "http" and identities and not allow_insecure_http:
        raise ScopeError("Refusing to send credentials over unencrypted HTTP.")
    if not 0.1 <= rate <= 10 or timeout <= 0 or max_requests < plan["request_budget_required"]:
        raise ScopeError("Invalid rate/timeout or request budget below the preflight maximum.")
    definitions = {s.scheme_name: {"type": s.type, "scheme": s.scheme, "location": s.in_,
                                   "parameter_name": s.parameter_name}
                   for s in parsed.security_schemes}
    for item in prepared:
        wf = item["config"]
        stages = [(item["create"], wf["create"]["identity"]),
                  (item["read"], wf["read"]["identity"]),
                  (item["cleanup"], wf["cleanup"]["identity"])]
        stages.extend(zip(item["access_ops"], [a["identity"] for a in wf.get("access", [])]))
        stages.extend((endpoint, mutation["identity"]) for endpoint, mutation in item["mutation_steps"])
        for endpoint, name in stages:
            if not _auth_ok(endpoint, identities[name], definitions):
                raise ScopeError(f"Profile {name!r} is incompatible with OpenAPI security for {endpoint.method} {endpoint.path}.")
            # OpenAPI may require a query/header value unrelated to the ID.
            # Refuse to create a fixture if a later step is missing required inputs.
            supplied = wf.get("path_values", {})
            material = identities[name]
            for parameter in endpoint.parameters:
                if parameter.required and parameter.location in ("query", "header"):
                    implicit = parameter.name == item["ident"]
                    existing = (parameter.name in material.params if parameter.location == "query"
                                else any(k.lower() == parameter.name.lower() for k in material.headers))
                    if not implicit and not existing and parameter.name not in supplied:
                        raise WorkflowError(f"Required {parameter.location} input {parameter.name} missing for {endpoint.method} {endpoint.path}.")
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, timeout=timeout,
                             max_requests=max_requests, requests_per_second=rate,
                             allowed_methods={"GET", "POST", "PATCH", "PUT", "DELETE"})
    reports: list[dict[str, Any]] = []
    fingerprint_key = secrets.token_bytes(32)
    for item in prepared:
        wf = item["config"]
        name, ident = wf["name"], item["ident"]
        values = wf.get("path_values", {})
        record: dict[str, Any] = {"name": name, "created": False,
                                  "cleanup_attempted": False, "cleanup_verified": False,
                                  "manual_cleanup_required": False, "observations": [], "findings": [],
                                  "errors": []}
        reports.append(record)
        created_id: str | None = None
        verified_marker = False
        marker_field = wf["create"]["marker_field"]
        marker = "ac-" + secrets.token_hex(12)
        # Honor OpenAPI maxLength to avoid creating invalid fixture data.
        schema = _resolve_schema(spec, _request_schema(spec, item["create"]).get("properties", {}).get(marker_field, {}))
        prefix = wf["create"]["body"][marker_field]
        limit = schema.get("maxLength")
        marker_value = (prefix + "-" + marker) if prefix else marker
        if isinstance(limit, int):
            room = max(0, limit - len(marker) - 1)
            shortened_prefix = prefix[:room]
            marker_value = (shortened_prefix + "-" + marker) if shortened_prefix else marker
        def send(endpoint: EndpointInfo, identity: str, label: str, body: dict[str, Any] | None = None) -> Any:
            """Run one exact OpenAPI operation and keep only transient response content."""
            rendered = _render_template(endpoint.path, identifier_name=ident, identifier=created_id,
                                        values=values)
            url = base_url.rstrip("/") + "/" + rendered.lstrip("/")
            material = identities[identity]
            # Only include query/header values that OpenAPI explicitly declares;
            # credentials always take precedence over ordinary test parameters.
            params = {param.name: str(created_id if param.name == ident else values[param.name])
                      for param in endpoint.parameters if param.location == "query"
                      and (param.name in values or (param.name == ident and created_id is not None))}
            params.update(material.params)
            headers = {param.name: str(created_id if param.name == ident else values[param.name])
                       for param in endpoint.parameters if param.location == "header"
                       and (param.name in values or (param.name == ident and created_id is not None))}
            headers.update(material.headers)
            result = client.request(endpoint.method, url, execute=True, headers=headers,
                                    params=params, cookies=material.cookies,
                                    json_body=body, sensitive_query_names=set(params),
                                    sensitive_header_names=set(headers))
            record["observations"].append(_observation(label, result))
            return result
        try:
            create_body = _resolve_body_secrets(wf["create"]["body"])
            create_body[marker_field] = marker_value
            if len(json.dumps(create_body)) > _MAX_BODY_BYTES:
                raise WorkflowError("Disposable request body exceeds the 16 KB limit after tagging.")
            created = send(item["create"], wf["create"]["identity"], "create_disposable", create_body)
            # 201 Created is required. A 200 might have updated an existing
            # record, which is never safe to delete automatically.
            if not created.response or created.response.status_code != 201:
                record["errors"].append("create_failed_or_unexpected_status")
                # Some APIs write successfully but return a timeout/500/202.
                # We cannot prove whether the resource exists; escalate instead
                # of presenting an unverified rollback as safe.
                record["manual_cleanup_required"] = True
                record["errors"].append("creation_state_uncertain_check_target")
                continue
            record["created"] = True
            created_json = _capture_json(created)
            captured = _json_pointer(created_json, wf["create"]["id_pointer"])
            if not isinstance(captured, (str, int)) or isinstance(captured, bool) or not str(captured):
                record["errors"].append("created_resource_id_missing_in_response")
                record["manual_cleanup_required"] = True
                continue
            created_id = str(captured)
            if not re.fullmatch(r"[A-Za-z0-9_~.:-]{1,128}", created_id) or created_id in (".", ".."):
                record["errors"].append("returned_id_not_safe_for_resource_path")
                record["manual_cleanup_required"] = True
                created_id = None
                continue
            # An HMAC token links observations while keeping real IDs off disk.
            record["resource_fingerprint"] = hmac.new(
                fingerprint_key, created_id.encode(), hashlib.sha256).hexdigest()[:20]
            baseline = send(item["read"], wf["read"]["identity"], "owner_read_baseline")
            before_json = _capture_json(baseline)
            baseline_id = _json_pointer(before_json, wf["read"]["id_pointer"])
            verified_baseline = bool(baseline.response and
                                     200 <= baseline.response.status_code < 300 and
                                     str(baseline_id) == created_id)
            marker_pointer = wf["read"].get("marker_pointer", "/" + marker_field)
            verified_marker = verified_baseline and _json_pointer(before_json, marker_pointer) == marker_value
            record["baseline_identity_verified"] = verified_baseline
            record["unique_fixture_marker_verified"] = verified_marker
            if not verified_baseline:
                record["errors"].append("owner_read_did_not_confirm_new_resource_id")
            if not verified_marker:
                record["manual_cleanup_required"] = True
                record["errors"].append("unique_fixture_marker_not_verified_no_automatic_delete")
            if verified_marker:
                for field in wf.get("restricted_response_fields", []):
                    if isinstance(before_json, dict) and field in before_json:
                        record["findings"].append({
                            "category": "BOPLA", "check": "restricted_field_exposure",
                            "field": field, "confidence": "high_if_field_policy_correct",
                            "status": "observed_policy_mismatch", "requires_review": True,
                        })
            for check, endpoint in zip(wf.get("access", []), item["access_ops"]):
                if not verified_marker:
                    break
                response = send(endpoint, check["identity"],
                                f"{check['category']}_access_{check['identity']}")
                status = response.response.status_code if response.response else None
                allowed = isinstance(status, int) and 200 <= status < 300
                # Only compare resource identity when the check targets the same read endpoint.
                same_object = False
                if endpoint.path == item["read"].path:
                    checked = _capture_json(response)
                    same_object = str(_json_pointer(checked, wf["read"]["id_pointer"])) == created_id
                violation = check["expected"] == "deny" and allowed or (
                    check["expected"] == "allow" and status in (401, 403))
                if violation:
                    record["findings"].append({
                        "category": check["category"], "identity": check["identity"],
                        "operation": endpoint.method + " " + endpoint.path,
                        "expected": check["expected"], "observed_status": status,
                        "matched_fixture_id": same_object,
                        "confidence": "high_if_policy_correct" if same_object and verified_baseline else "indicator",
                        "status": "observed_policy_mismatch", "requires_review": True,
                    })
            # Ordered mutation stages operate only on this run's verified fixture.
            # A loss of the immutable marker stops all further writes and prevents
            # automatic DELETE, rather than risking removal of an unrelated object.
            for mutation_op, mutation in item["mutation_steps"]:
                if not verified_marker or not isinstance(before_json, dict):
                    break
                submitted_body = _resolve_body_secrets(mutation["body"])
                attempt = send(mutation_op, mutation["identity"], "restricted_field_mutation",
                               submitted_body)
                if not attempt.response or not 200 <= attempt.response.status_code < 300:
                    record["errors"].append("mutation_failed_or_denied")
                    continue
                after = send(item["read"], wf["read"]["identity"], "read_after_mutation")
                after_json = _capture_json(after)
                retained_identity = (isinstance(after_json, dict)
                    and str(_json_pointer(after_json, wf["read"]["id_pointer"])) == created_id
                    and _json_pointer(after_json, marker_pointer) == marker_value)
                if not retained_identity:
                    verified_marker = False
                    record["manual_cleanup_required"] = True
                    record["errors"].append("mutation_lost_fixture_identity_no_automatic_cleanup")
                    break
                for field in mutation["restricted_fields"]:
                    old_value = before_json.get(field)
                    new_value = after_json.get(field)
                    if new_value == submitted_body.get(field) and new_value != old_value:
                        record["findings"].append({
                            "category": "MASS_ASSIGNMENT", "field": field,
                            "status": "observed_policy_mismatch",
                            "confidence": "high_if_field_policy_correct",
                            "requires_review": True,
                            "evidence": {"accepted_status": attempt.response.status_code,
                                         "field_changed_to_submitted_value": True},
                        })
                before_json = after_json
        except Exception as exc:
            # Unknown failures are treated as incomplete tests, never ignored.
            # Only exception type reaches the report, not URLs or credentials.
            record["errors"].append(type(exc).__name__)
        finally:
            if record["created"] and created_id is not None and verified_marker:
                record["cleanup_attempted"] = True
                try:
                    result = send(item["cleanup"], wf["cleanup"]["identity"], "cleanup_delete")
                    if result.response and 200 <= result.response.status_code < 300:
                        verify = send(item["read"], wf["read"]["identity"], "verify_resource_deleted")
                        record["cleanup_verified"] = bool(
                            verify.response and verify.response.status_code in (404, 410)
                        )
                except Exception as exc:
                    record["errors"].append("cleanup_exception_" + type(exc).__name__)
                if not record["cleanup_verified"]:
                    record["manual_cleanup_required"] = True
                    record["errors"].append("cleanup_unverified_manual_followup_required")
    return {"engine": "disposable-workflows", "executed": True,
            "requests_sent": client._requests_made, "workflows": reports,
            "manual_cleanup_required": any(w["manual_cleanup_required"] for w in reports),
            "warning": "Observations depend on operator-supplied policy. No response body, token, or raw object ID is saved."}
