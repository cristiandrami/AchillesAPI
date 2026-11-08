"""Bounded, deterministic follow-up executor for a previously completed scan.

Only repeatable GET 5xx baselines are eligible. The engine never takes direct
instructions or URLs from an LLM, response body, or untrusted observation.
Every URL is rebuilt from a previously approved OpenAPI plan and scoped again.
"""
from __future__ import annotations

from typing import Any

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.generic import _compatible_identities
from achillesapi.core.http import SafeHTTPClient
from achillesapi.models.api import ParsedAPI


def verify_server_errors(parsed: ParsedAPI, plan: dict[str, Any], observations: list[dict[str, Any]], *,
                         base_url: str, allowed_hosts: set[str],
                         identities: dict[str, AuthenticationMaterial] | None,
                         path_values: dict[str, str], budget: int = 3, rate: float = 1.0,
                         timeout: float = 8.0) -> dict[str, Any]:
    """Reproduce up to `budget` server errors with the same approved GET baseline.

    The HTTP 5xx alone is not a vulnerability. Repeated 5xx merits investigation
    as an availability/validation issue; no raw response is written to disk.
    """
    if budget < 0 or budget > 20:
        raise ValueError("Adaptive budget must be between 0 and 20")
    eligible = {"GET " + item["path"]: item for item in plan["operations"]
                if item["status"] == "eligible_get"}
    endpoints = {(e.method, e.path): e for e in parsed.endpoints}
    profiles = identities or {"anonymous": AuthenticationMaterial()}
    defs = plan.get("security_definitions", {})
    selected: list[tuple[str, str]] = []
    for observation in observations:
        operation = observation.get("operation")
        identity = observation.get("identity")
        if observation.get("check") != "baseline" or not isinstance(observation.get("status"), int):
            continue
        if observation["status"] < 500 or operation not in eligible:
            continue
        key = (operation, identity)
        if identity in profiles and key not in selected:
            selected.append(key)
        if len(selected) >= budget:
            break
    if not selected:
        return {"engine": "adaptive-verification-v0.20", "requests_sent": 0, "observations": [],
                "limitations": ["No server errors selected for verification"]}
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=len(selected),
                            timeout=timeout, requests_per_second=rate)
    outcomes: list[dict[str, Any]] = []
    for operation, identity in selected:
        entry = eligible[operation]
        endpoint = endpoints[("GET", entry["path"])]
        if identity not in _compatible_identities(entry, defs, profiles):
            continue
        material = profiles[identity]
        query_names = {p.name for p in endpoint.query_parameters}
        params = {k: v for k, v in path_values.items() if k in query_names}
        params.update(material.params)
        url = base_url.rstrip("/") + "/" + entry["rendered_path"].lstrip("/")
        ev = client.request("GET", url, execute=True, headers=material.headers,
                            params=params, cookies=material.cookies,
                            sensitive_query_names=set(params))
        status = ev.response.status_code if ev.response else None
        outcomes.append({"operation": operation, "identity": identity,
                         "initial_status_class": "5xx", "verification_status": status,
                         "reproducible_server_error": isinstance(status, int) and status >= 500,
                         "conclusion": "requires_review", "error_type": ev.error.split(":",1)[0] if ev.error else None})
    return {"engine": "adaptive-verification-v0.20", "requests_sent": len(outcomes),
            "observations": outcomes,
            "limitations": ["HTTP 5xx is not proof of injection or another security vulnerability"]}
