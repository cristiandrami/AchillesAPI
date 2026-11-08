"""Read-only multi-step journeys with runtime JSON Pointer variable capture.

A journey can use an identifier returned by one GET in a later GET without
hardcoding the identifier. Swagger supplies the operation allowlist; YAML
specifies approved starting values and links. This module NEVER sends writes.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import yaml

from achillesapi.core.auth import AuthenticationManager
from achillesapi.core.generic import _POSSIBLE_MUTATION
from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.models.api import ParsedAPI

_OPERATION = re.compile(r"^GET (/[^?#]*)$")
_TOKEN = re.compile(r"\{([^{}]+)\}")
_SYMBOL = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")


class JourneyError(ValueError):
    """The declared read-only journey is invalid or has missing runtime data."""


def read_journey(path: Path) -> dict[str, Any]:
    """Load only a small, explicitly declared YAML plan (no YAML code execution)."""
    if path.stat().st_size > 65536:
        raise JourneyError("Journey configuration exceeds 64 KB")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("steps"), list):
        raise JourneyError("Journey YAML must contain a steps list")
    if not 1 <= len(data["steps"]) <= 40:
        raise JourneyError("Journey must have 1-40 steps")
    return data


def _select_operations(parsed: ParsedAPI, steps: list[dict[str, Any]]) -> list[Any]:
    """Verify each step is a read-only operation documented by OpenAPI."""
    lookup = {(e.method, e.path): e for e in parsed.endpoints}
    operations = []
    captured_so_far: set[str] = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise JourneyError(f"Step {index+1} must be a mapping")
        operation = step.get("operation", "")
        match = _OPERATION.fullmatch(operation) if isinstance(operation, str) else None
        if not match or ("GET", match.group(1)) not in lookup:
            raise JourneyError(f"Step {index+1} must be a documented GET operation")
        endpoint = lookup[("GET", match.group(1))]
        if _POSSIBLE_MUTATION.search(" ".join([endpoint.path, endpoint.operation_id or ""])):
            raise JourneyError("Potentially state-changing GET excluded from journeys")
        for label in ("values", "capture"):
            if not isinstance(step.get(label, {}), dict):
                raise JourneyError(f"Step {index+1}: {label} must be a mapping")
        if "identity" in step and (not isinstance(step["identity"], str) or not step["identity"]):
            raise JourneyError("Identity must be a nonempty profile name")
        for name, source in step.get("values", {}).items():
            if not isinstance(name, str) or not name or not isinstance(source, (str, int, float)):
                raise JourneyError("Journey values must be strings or numbers")
            if isinstance(source, str) and source.startswith("$") and source[1:] not in captured_so_far:
                raise JourneyError("Unknown previous capture referenced by journey value")
        for name, pointer in step.get("capture", {}).items():
            if not _SYMBOL.fullmatch(str(name)) or not isinstance(pointer, str) or not pointer.startswith("/"):
                raise JourneyError("Capture variables must be named and use JSON pointers")
            captured_so_far.add(name)
        operations.append(endpoint)
    return operations


def _extract(value: Any, pointer: str) -> Any:
    """Read one JSON Pointer; never serialize captured values into reports."""
    current = value
    for token in pointer[1:].split("/"):
        name = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and name in current:
            current = current[name]
        elif isinstance(current, list) and name.isdigit() and int(name) < len(current):
            current = current[int(name)]
        else:
            raise JourneyError("Captured JSON Pointer did not exist")
    return current


def run_journey(parsed: ParsedAPI, configuration: dict[str, Any], *, base_url: str,
                allowed_hosts: set[str], manager: AuthenticationManager | None = None,
                execute: bool = False, max_requests: int = 30, rate: float = 1.0,
                allow_insecure_http: bool = False) -> dict[str, Any]:
    """Execute bounded GET chain, using captured values only in declared parameters.

    A step can set values like ``customer_id: '$customer_id'`` and capture the
    earlier ``/id``. The output records capture names only; no raw response or
    identifier is saved. Missing variables fail closed, not guessed.
    """
    steps = configuration["steps"]
    operations = _select_operations(parsed, steps)
    if execute and (not allowed_hosts or not base_url):
        raise ScopeError("Active journey requires a base URL and explicit host allowlist")
    if execute:
        parts = urlsplit(base_url)
        # Fail before logging in, rather than authenticating and only later
        # discovering that the requested API target is out of scope.
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ScopeError("Invalid journey base URL")
        if parts.hostname.lower().rstrip(".") not in {host.lower().rstrip(".") for host in allowed_hosts}:
            raise ScopeError("Journey base URL is outside the approved scope")
        if any(part in (".", "..") for part in parts.path.split("/")):
            raise ScopeError("Base URL must not contain traversal segments")
    if execute and manager:
        missing_profiles = sorted({step["identity"] for step in steps if step.get("identity") and step["identity"] not in manager.names})
        if missing_profiles:
            raise JourneyError("Unknown journey identity profile(s): " + ", ".join(missing_profiles))
    if len(steps) > max_requests:
        raise JourneyError("Step count exceeds the request budget")
    if execute and base_url.startswith("http://") and manager and not allow_insecure_http:
        raise JourneyError("Credentials over HTTP require --allow-insecure-http")
    if not execute:
        return {"engine": "journey-v0.18", "executed": False, "requests_sent": 0,
                "steps": [{"operation": step["operation"], "status": "planned"} for step in steps]}
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=max_requests,
                            requests_per_second=rate)
    variables: dict[str, str] = {}
    report: list[dict[str, Any]] = []
    for step, endpoint in zip(steps, operations):
        values: dict[str, str] = {}
        for key, raw in step.get("values", {}).items():
            if isinstance(raw, str) and raw.startswith("$"):
                if raw[1:] not in variables:
                    raise JourneyError("Required value from previous step was not captured")
                values[key] = variables[raw[1:]]
            else:
                values[key] = str(raw)
        missing = [param.name for param in endpoint.parameters if param.required and
                   param.location in ("path", "query") and param.name not in values]
        if missing:
            raise JourneyError("Required OpenAPI parameter was not supplied: " + ", ".join(missing))
        def render(match: re.Match[str]) -> str:
            """Substitute only declared single path segment values."""
            key = match.group(1)
            if key not in values or values[key] in (".", "..", ""):
                raise JourneyError("Path parameter has no safe fixture value")
            return quote(values[key], safe="")
        path = _TOKEN.sub(render, endpoint.path)
        url = base_url.rstrip("/") + path
        identity = step.get("identity")
        if identity and not manager:
            raise JourneyError("Named journey identity requires --auth-config")
        material = manager.resolve(identity, allowed_hosts=allowed_hosts,
                                   allow_insecure_http=allow_insecure_http) if identity else None
        headers = dict(material.headers) if material else {}
        params = {p.name: values[p.name] for p in endpoint.parameters if
                  p.location == "query" and p.name in values}
        if material:
            params.update(material.params)
        evidence = client.request("GET", url, execute=True, headers=headers, params=params,
                                  cookies=material.cookies if material else {},
                                  sensitive_query_names=set(params))
        status = evidence.response.status_code if evidence.response else None
        item = {"operation": step["operation"], "status": status,
                "identity": identity or "anonymous", "capture_names": [],
                "error_type": evidence.error.split(":", 1)[0] if evidence.error else None}
        if evidence.response and 200 <= status < 300 and step.get("capture"):
            try:
                payload = json.loads(evidence.response.body_preview)
                for name, pointer in step["capture"].items():
                    captured = _extract(payload, pointer)
                    if not isinstance(captured, (str, int)) or isinstance(captured, bool):
                        raise JourneyError("Captured value must be a string or integer")
                    encoded = str(captured)
                    if not encoded or len(encoded) > 256 or encoded in (".", ".."):
                        raise JourneyError("Captured value is not a safe fixture identifier")
                    variables[name] = encoded
                    item["capture_names"].append(name)
            except (ValueError, JourneyError) as exc:
                item["capture_error"] = type(exc).__name__
                report.append(item)
                break
        report.append(item)
        if evidence.error or status is None or status >= 400:
            break
    return {"engine": "journey-v0.18", "executed": True, "requests_sent": len(report),
            "steps": report, "captured_variable_names": sorted(variables),
            "limitations": ["GET-only; write operations require separate approved disposable workflows.",
                            "No response bodies or captured values are persisted."]}
