"""Generic, OpenAPI-driven assessment for real authorized APIs.

The planner is deliberately offline. Execution supports GET only, and only
after an operator explicitly approves the hostname and supplies --execute.
Write operations remain review-only because OpenAPI does not specify a safe
way to create, modify, or restore live business data.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote, urlsplit

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.http import SafeHTTPClient, ScopeError
from achillesapi.models.api import EndpointInfo, ParsedAPI

_PATH_TOKEN = re.compile(r"\{([^{}]+)\}")
# GET is supposed to be read-only, but some applications abuse it for actions.
# This conservative heuristic blocks suspicious routes until an analyst reviews
# them; it does not assume that an endpoint is safe merely because it is GET.
_POSSIBLE_MUTATION = re.compile(
    r"(?:^|[\/._-])(?:delete|remove|reset|logout|revoke|disable|enable|"
    r"execute|run|trigger|publish|transfer|purchase|submit|send)(?:$|[\/._-])",
    re.IGNORECASE,
)


def _documented_path_value(endpoint: EndpointInfo, name: str) -> str | None:
    """Read a concrete path value only when OpenAPI explicitly provides one.

    We do not guess real customer IDs or create random object identifiers.
    An example or a single enum value is usable; otherwise the caller must
    provide --path-value NAME=VALUE.
    """
    # LEGGI: prova example/enum documentati, ma non inventa ID reali.
    # SICUREZZA: Non contatta direttamente l'API target.
    for parameter in endpoint.path_parameters:
        if parameter.name != name:
            continue
        candidates = [
            getattr(parameter, "example", None),
            parameter.schema_.get("example"),
        ]
        # OpenAPI 3.1 and newer FastAPI releases commonly use `examples`
        # rather than `example`. A single literal example is safe to use
        # for a local dry-run; never invent a second value.
        examples = parameter.schema_.get("examples")
        if isinstance(examples, list) and len(examples) == 1:
            candidates.append(examples[0])
        enum = parameter.schema_.get("enum")
        if isinstance(enum, list) and len(enum) == 1:
            candidates.append(enum[0])
        for example in candidates:
            if isinstance(example, (str, int, float)) and not isinstance(example, bool):
                return str(example)
    return None


def _render_path(endpoint: EndpointInfo, values: dict[str, str]) -> tuple[str | None, list[str]]:
    """Fill placeholders safely; return missing names instead of inventing IDs.

    The path is URL-encoded one segment at a time, preventing a supplied
    identifier from introducing an unexpected slash or query parameter.
    """
    # IN PRATICA: Sostituisce i segnaposto del percorso con i valori di test forniti.
    # SICUREZZA: Non contatta direttamente l'API target.
    missing: list[str] = []

    def replacement(match: re.Match[str]) -> str:
        """Resolve one placeholder without changing the original path shape."""
        # IN PRATICA: Sostituisce un singolo segnaposto usando soltanto un valore consentito.
        # SICUREZZA: Non contatta direttamente l'API target.
        name = match.group(1)
        value = values.get(name)
        if value is None:
            value = _documented_path_value(endpoint, name)
        if value is None or not str(value) or str(value) in (".", ".."):
            missing.append(name)
            return match.group(0)
        return quote(str(value), safe="")

    rendered = _PATH_TOKEN.sub(replacement, endpoint.path)
    return (rendered if not missing else None), missing


def _metadata_for(endpoint: EndpointInfo) -> dict[str, Any]:
    """Explain the possible authentication and parameter needs of an operation."""
    # LEGGI: riassume autenticazione e query necessari per il singolo endpoint.
    # SICUREZZA: Non contatta direttamente l'API target.
    security = sorted({
        name for requirement in endpoint.security
        for name in requirement.schemes
    })
    return {
        "method": endpoint.method,
        "path": endpoint.path,
        "operation_id": endpoint.operation_id,
        "security_schemes": security,
        # OpenAPI list entries are OR alternatives. Names inside one entry are AND.
        "security_alternatives": [sorted(requirement.schemes) for requirement in endpoint.security],
        "security_explicitly_disabled": endpoint.security_is_explicitly_disabled,
        "query_parameters": [
            {"name": p.name, "required": p.required}
            for p in endpoint.query_parameters
        ],
    }


def build_generic_plan(
    parsed: ParsedAPI,
    *,
    base_url: str | None = None,
    path_values: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build an offline, human-readable execution plan for any OpenAPI 3.x API.

    All methods appear in the plan. GET requests are candidates for
    controlled execution; POST/PUT/PATCH/DELETE are manual-only.
    Nothing in this function contacts the target or loads credentials.
    """
    # LEGGI: classifica ogni operazione in eseguibile, bloccata o solo manuale.
    # SICUREZZA: Non contatta direttamente l'API target.
    values = path_values or {}
    operations: list[dict[str, Any]] = []
    for endpoint in parsed.endpoints:
        rendered, missing = _render_path(endpoint, values)
        can_get = endpoint.method == "GET"
        # A GET with a state-changing name is unsafe to run unattended.
        # Operator can inspect it manually and keep the read-only scan bounded.
        possible_side_effect = bool(_POSSIBLE_MUTATION.search(
            " ".join(filter(None, [endpoint.path, endpoint.operation_id or ""]))
        ))
        # Query parameters can be required: only a provided test value
        # can make the request executable; never fabricate one.
        unresolved_query = [
            p.name for p in endpoint.query_parameters
            if p.required and p.name not in values
        ]
        operation = _metadata_for(endpoint)
        operation.update({
            "status": (
                "manual_only_non_get" if not can_get else
                "manual_review_possible_side_effect" if possible_side_effect else
                "blocked_missing_inputs" if (missing or unresolved_query) else
                "eligible_get"
            ),
            "missing_path_values": missing,
            "missing_query_values": unresolved_query,
            "rendered_path": rendered,
            "explanation": (
                "This operation can change server state; only a manual test proposal is produced."
                if not can_get else
                "This GET appears to trigger a state change; it is excluded from unattended execution."
                if possible_side_effect else
                "Supply real test values for missing inputs before running a GET request."
                if missing or unresolved_query else
                "Read-only GET candidate. Execution still requires scope approval and --execute."
            ),
        })
        operations.append(operation)
    return {
        "engine": "generic-assessment",
        "base_url": base_url,
        "api": {"title": parsed.title, "version": parsed.version, "endpoints": len(operations)},
        "security_definitions": {
            scheme.scheme_name: {
                "type": scheme.type,
                "scheme": scheme.scheme,
                "location": scheme.in_,
                "parameter_name": scheme.parameter_name,
            }
            for scheme in parsed.security_schemes
        },
        "summary": {
            "get_candidates": sum(op["status"] == "eligible_get" for op in operations),
            "blocked_missing_inputs": sum(op["status"] == "blocked_missing_inputs" for op in operations),
            "manual_only": sum(op["status"] in {"manual_only_non_get", "manual_review_possible_side_effect"} for op in operations),
        },
        "execution": {
            "executed": False, "requests_sent": 0,
            "default": "dry_run",
            "policy": "GET only; no auto mutations; explicit hostname allowlist and execution flag",
        },
        "operations": operations,
        "limitations": [
            "OpenAPI alone does not provide actual business authorization rules.",
            "Path IDs and required query inputs must come from configuration or documented examples.",
            "GET may still have server-side side effects on a poorly implemented API; operator authorization is required.",
            "Authorization differences are indicators, never proof of BOLA/BFLA without an ownership/role oracle.",
            "Only the selected base URL is used; operation-level server overrides require explicit review.",
        ],
    }


def _sanitize_observation(evidence: Any) -> dict[str, Any]:
    """Keep safe response metadata and discard potentially sensitive body text.

    The underlying transport may capture a short response preview. This
    generic engine never writes that preview to disk or sends it to AI.
    """
    # LEGGI: conserva solo stato, tempi ed errori, mai il corpo della risposta.
    # SICUREZZA: Non contatta direttamente l'API target.
    response = evidence.response
    return {
        "executed": evidence.executed,
        "status_code": response.status_code if response else None,
        "elapsed_ms": response.elapsed_ms if response else None,
        "body_truncated": response.body_truncated if response else None,
        "error_type": (
            evidence.error.split(":", 1)[0] if evidence.error else None
        ),
    }


def _matches_security_scheme(material: AuthenticationMaterial, scheme: dict[str, Any]) -> bool:
    """Check whether supplied credentials match an OpenAPI security scheme.

    For example, a Bearer-only test account should not be sent to an API-key
    endpoint. Matching uses the authentication *type*, not a secret value.
    No network requests are made.
    """
    scheme_type = (scheme.get("type") or "").lower()
    if scheme_type == "http":
        expected = (scheme.get("scheme") or "").lower()
        authorization = material.headers.get("Authorization", "")
        return (expected == "bearer" and authorization.startswith("Bearer ")) or (
            expected == "basic" and authorization.startswith("Basic ")
        )
    if scheme_type == "apikey":
        name = scheme.get("parameter_name")
        location = scheme.get("location")
        if not isinstance(name, str) or not name:
            return False
        if location == "header":
            return any(key.lower() == name.lower() for key in material.headers)
        if location == "query":
            return name in material.params
        if location == "cookie":
            return name in material.cookies
    # An externally acquired Bearer token can be used against OAuth2/OIDC
    # endpoints. The tool does not acquire or validate scopes; the API decides
    # whether the supplied test identity is authorized.
    if scheme_type in {"oauth2", "openidconnect"}:
        return material.headers.get("Authorization", "").startswith("Bearer ")
    return False


def _compatible_identities(
    operation: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    identities: dict[str, AuthenticationMaterial],
) -> dict[str, AuthenticationMaterial]:
    """Select only identities that can satisfy an operation's declared auth.

    An empty security requirement means a public route. Send one anonymous
    GET in that case, instead of replaying a user's secrets unnecessarily.
    Unknown security schemes are skipped rather than guessed.
    """
    alternatives = operation.get("security_alternatives", [])
    if not alternatives or [] in alternatives:
        return {"anonymous": AuthenticationMaterial()}
    matching: dict[str, AuthenticationMaterial] = {}
    for name, material in identities.items():
        if any(
            all(
                isinstance(definitions.get(scheme), dict)
                and _matches_security_scheme(material, definitions[scheme])
                for scheme in requirement
            )
            for requirement in alternatives
        ):
            matching[name] = material
    return matching


def execute_generic_gets(
    plan: dict[str, Any],
    *,
    base_url: str,
    allowed_hosts: set[str],
    identities: dict[str, AuthenticationMaterial] | None = None,
    path_values: dict[str, str] | None = None,
    execute: bool = False,
    timeout: float = 8.0,
    max_requests: int = 20,
    requests_per_second: float = 1.0,
    allow_insecure_http: bool = False,
) -> dict[str, Any]:
    """Run explicitly permitted GET candidates under a shared request budget.

    The caller must supply --execute and an exact allowlisted hostname.
    Authentication profiles are optional; each provided identity is tested
    independently. Redirects, non-GET methods and out-of-scope hosts are
    blocked by SafeHTTPClient. No response bodies or tokens are saved.

    The return value is a metadata-only execution report.
    """
    # LEGGI: fa GET controllate con budget e scope; non prova a modificare dati.
    # SICUREZZA: Questa funzione puo inviare richieste: controlla scope, token e autorizzazione.
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ScopeError("Provide a valid absolute HTTP(S) --base-url.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ScopeError("Base URL cannot contain credentials, query parameters or fragments.")
    if parts.hostname.lower().rstrip(".") not in {host.lower().rstrip(".") for host in allowed_hosts}:
        raise ScopeError("Base URL hostname is not in --allow-host.")
    profiles = identities or {"anonymous": AuthenticationMaterial()}
    if parts.scheme == "http" and identities and not allow_insecure_http:
        raise ScopeError(
            "Refusing to transmit credentials over HTTP. "
            "Use HTTPS or explicitly enable --allow-insecure-http for an authorized test."
        )
    # Choose relevant profiles BEFORE opening any network connection. This
    # reduces unnecessary traffic and prevents leaking an API key to a Bearer
    # endpoint or a session cookie to an unrelated route.
    eligible = [op for op in plan["operations"] if op["status"] == "eligible_get"]
    definitions = plan.get("security_definitions", {})
    prepared = [
        (op, _compatible_identities(op, definitions, profiles))
        for op in eligible
    ]
    planned_count = sum(len(selected) for _, selected in prepared)
    if planned_count > max_requests and execute:
        raise ScopeError(
            "Planned requests exceed --max-requests. Increase the explicit budget "
            "or reduce selected identities/endpoints."
        )
    client = SafeHTTPClient(
        allowed_hosts=allowed_hosts,
        timeout=timeout,
        max_requests=max_requests,
        requests_per_second=requests_per_second,
    )
    results: list[dict[str, Any]] = []
    skipped = [
        {"path": op["path"], "reason": "No compatible identity for declared OpenAPI authentication"}
        for op, selected in prepared if not selected
    ]
    for op, selected in prepared:
        # base_url may contain a prefix such as /v1, which must be preserved.
        url = base_url.rstrip("/") + "/" + str(op["rendered_path"]).lstrip("/")
        # Query values must be supplied explicitly (no guessed sample data).
        query_names = {p["name"] for p in op["query_parameters"]}
        values = path_values or {}
        query = {key: value for key, value in values.items() if key in query_names}
        for identity_name, material in selected.items():
            # Auth material wins over ordinary query parameters with the same name.
            params = {**query, **material.params}
            ev = client.request(
                "GET", url, execute=execute,
                headers=material.headers,
                params=params,
                cookies=material.cookies,
                sensitive_query_names=set(params),
                sensitive_header_names=set(material.headers),
            )
            results.append({
                "method": "GET", "path": op["path"], "identity": identity_name,
                **_sanitize_observation(ev),
            })
    # No response-code comparison is classified as a confirmed issue here.
    return {
        "engine": "generic-assessment",
        "executed": execute,
        "requests_sent": sum(1 for item in results if item["executed"]),
        "observations": results,
        "skipped_auth_mismatch": skipped,
        "findings_confirmed": 0,
        "interpretation": (
            "Observations require authorization-policy and ownership review; "
            "a status-code difference is not proof of a vulnerability."
        ),
    }
