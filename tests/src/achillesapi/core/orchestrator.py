"""Bounded, auditable follow-up engine for real API assessment observations.

v0.23 makes the previous *advice-only* adaptive queue executable, but ONLY for
read-only checks that can be reconstructed from OpenAPI. No model output, HTTP
response body or free-form URL can ever become an executable instruction.

The functions explain selection, preflight, budget and evidence separately so
operators can review or extend the policy without modifying the HTTP client.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.generic import _compatible_identities
from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.models.api import ParsedAPI


def choose_followups(parsed: ParsedAPI, plan: dict[str, Any], observations: list[dict[str, Any]],
                     *, budget: int = 3) -> dict[str, Any]:
    """Select at most `budget` conservative GET repetitions from observed facts.

    - A 5xx baseline is repeated to determine if it is transient.
    - A successful unauthenticated read of a *documented protected* operation is
      repeated anonymously to verify a specification/behavior discrepancy.
    We do not infer permission or exploitability from status codes.
    """
    if not 0 <= budget <= 20:
        raise ValueError("Agent follow-up budget must be between 0 and 20")
    eligible = {("GET", op["path"]): op for op in plan.get("operations", [])
                if op.get("status") == "eligible_get" and op.get("method") == "GET"}
    mapped = {(ep.method, ep.path): ep for ep in parsed.endpoints}
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for observation in observations:
        if not isinstance(observation, dict):
            continue  # Untrusted saved assessment may contain malformed items.
        operation = observation.get("operation")
        if not isinstance(operation, str) or not operation.startswith("GET "):
            continue
        path = operation[4:]
        entry = eligible.get(("GET", path))
        ep = mapped.get(("GET", path))
        if not entry or not ep:
            continue
        check = observation.get("check")
        status = observation.get("status")
        identity = observation.get("identity")
        if check == "baseline" and isinstance(status, int) and 500 <= status <= 599:
            category, profile, priority = "recheck_server_error", identity, 2
        elif (check == "without_credentials" and isinstance(status, int)
              and 200 <= status < 300 and ep.security and not ep.security_is_explicitly_disabled):
            category, profile, priority = "recheck_anonymous_access", "anonymous", 1
        else:
            continue
        if not isinstance(profile, str) or not profile:
            continue
        key = (operation, profile, category)
        if key in seen:
            continue
        seen.add(key)
        candidates.append({"operation": operation, "identity": profile,
                           "reason": category, "priority": priority,
                           "initial_status_class": "5xx" if priority == 2 else "2xx"})
    # Sort deterministically, favor checking anonymous access discrepancies.
    candidates.sort(key=lambda c: (c["priority"], c["operation"], c["identity"]))
    return {"engine": "bounded-agent-v0.23", "network_requests_sent": 0,
            "budget": budget, "actions": candidates[:budget],
            "skipped_budget": max(0, len(candidates) - budget),
            "policy": "Repeat existing eligible GET only; AI never authorizes targets or HTTP methods."}


def run_followups(parsed: ParsedAPI, plan: dict[str, Any], observations: list[dict[str, Any]], *,
                  base_url: str, allowed_hosts: set[str],
                  identities: dict[str, AuthenticationMaterial] | None = None,
                  path_values: dict[str, str] | None = None, budget: int = 3,
                  rate: float = 1.0, timeout: float = 8.0,
                  allow_insecure_http: bool = False, execute: bool = False) -> dict[str, Any]:
    """Perform a fail-closed preflight, then repeat only planner-approved GETs.

    No data from a server response is placed into the request path. Each request
    URL is rebuilt from an eligible Swagger operation, with the same operator
    path values used during the baseline. Raw response content and credentials
    are omitted from the JSON report.
    """
    proposal = choose_followups(parsed, plan, observations, budget=budget)
    if not execute or not proposal["actions"]:
        return {**proposal, "executed": False, "observations": []}
    parts = urlsplit(base_url)
    hosts = {host.strip().lower().rstrip(".") for host in allowed_hosts}
    if (parts.scheme not in {"http", "https"} or not parts.hostname
        or parts.hostname.lower().rstrip(".") not in hosts
        or parts.username or parts.password or parts.query or parts.fragment
        or any(segment in (".", "..") for segment in parts.path.split("/"))):
        raise ScopeError("Agent target must be an explicitly authorized HTTP(S) base URL")
    if parts.scheme == "http" and identities and not allow_insecure_http:
        raise ScopeError("Agent refuses to send credentials via HTTP without explicit approval")
    if not (0.1 <= rate <= 10) or not (0.1 <= timeout <= 60):
        raise ValueError("Agent rate and timeout are outside permitted bounds")
    profiles = identities or {"anonymous": AuthenticationMaterial()}
    definitions = plan.get("security_definitions", {})
    lookup = {"GET " + item["path"]: item for item in plan["operations"]
              if item.get("status") == "eligible_get" and item.get("method") == "GET"}
    endpoints = {(ep.method, ep.path): ep for ep in parsed.endpoints}
    # All checks are validated before the first request, including profiles.
    prepared = []
    for action in proposal["actions"]:
        entry = lookup[action["operation"]]
        ep = endpoints[("GET", entry["path"])]
        name = action["identity"]
        if name != "anonymous" and name not in profiles:
            raise ValueError("An observation refers to an unavailable identity profile")
        if action["reason"] == "recheck_anonymous_access":
            material = AuthenticationMaterial()
        else:
            if name not in _compatible_identities(entry, definitions, profiles):
                raise ValueError("A follow-up identity is incompatible with OpenAPI security")
            material = profiles[name]
        qnames = {param.name for param in ep.query_parameters}
        query = {key: str(value) for key, value in (path_values or {}).items() if key in qnames}
        query.update(material.params)
        url = base_url.rstrip("/") + "/" + entry["rendered_path"].lstrip("/")
        prepared.append((action, material, query, url))
    client = SafeHTTPClient(allowed_hosts=allowed_hosts, max_requests=len(prepared),
                            timeout=timeout, requests_per_second=rate)
    outcomes = []
    for action, material, query, url in prepared:
        ev = client.request("GET", url, execute=True, headers=material.headers,
                            params=query, cookies=material.cookies,
                            sensitive_query_names=set(query),
                            sensitive_header_names=set(material.headers))
        status = ev.response.status_code if ev.response else None
        repeated = (isinstance(status, int) and (status >= 500 if action["reason"] == "recheck_server_error"
                    else 200 <= status < 300))
        outcomes.append({"operation": action["operation"], "identity": action["identity"],
                         "reason": action["reason"], "status": status,
                         "repeated": repeated, "result": "requires_human_review" if repeated else "not_reproduced",
                         "error_type": ev.error.split(":", 1)[0] if ev.error else None})
    return {**proposal, "executed": True, "network_requests_sent": client._requests_made,
            "observations": outcomes,
            "limitations": ["Reproduced HTTP behavior is not a confirmed security vulnerability."]}
