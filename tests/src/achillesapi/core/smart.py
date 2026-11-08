"""Schema-aware, bounded API assessment that works without laboratory assumptions.

This is an *assessment engine*, not a lab runner. It chooses checks from the
OpenAPI operations, available test identities, and optional operator policies.
Nothing is sent until execution is explicitly authorized. HTTP methods other
than GET are never executed by this engine.

The implementation is deliberately deterministic: the local AI can interpret
sanitized results, but may not decide which network requests are permitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import secrets
import json
import re
from typing import Any
from urllib.parse import urlsplit

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.generic import _compatible_identities
from achillesapi.core.http import RequestBudgetExceeded, SafeHTTPClient, ScopeError
from achillesapi.models.api import ParsedAPI
from achillesapi.core.testgen import _json_schemas, _properties
from achillesapi.core.contracts import response_contract_issues
from achillesapi.models.evidence import ExecutionEvidence

# Never include raw response content in a saved finding.
_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sql_error", re.compile(r"sql syntax|sqlite error|sqlstate|postgresql|mysql|ora-\d{4}|odbc", re.I)),
    ("stack_trace", re.compile(r"traceback \(most recent call last\)|stack trace|java\.lang\.[\w.]+exception", re.I)),
    ("framework_debug", re.compile(r"debug toolbar|werkzeug debugger|exception details", re.I)),
)
_TEST_ORIGIN = "https://untrusted-origin.invalid"
_ID_PATTERN = re.compile(r"\{[^}]+\}")


@dataclass(frozen=True)
class ScanSettings:
    """Define limits for the automatic scanner, never permissions inferred by AI.

    max_requests is a hard budget shared across all checks and identities.
    max_probes_per_endpoint limits parameter mutation on any one operation.
    """

    max_requests: int = 60
    rate: float = 1.0
    timeout: float = 8.0
    max_probes_per_endpoint: int = 3
    check_cors: bool = True
    check_input_validation: bool = True
    check_authentication: bool = True
    allow_insecure_http: bool = False


@dataclass
class ScanState:
    """Keep transient response observations in memory and only export safe fields."""

    observations: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    # Fresh per-run HMAC key prevents offline guessing of tiny response bodies.
    fingerprint_key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)


def _metadata(evidence: ExecutionEvidence, key: bytes) -> dict[str, Any]:
    """Extract non-sensitive facts from one response; keep body values private.

    The SHA-256 fingerprint lets us compare representations without writing
    PII, access tokens or response bodies into the JSON output. A hash match
    alone is NOT enough to prove broken access control.
    """
    if evidence.response is None:
        return {"status": None, "duration_ms": None, "body_fingerprint": None, "error_type": (
            evidence.error.split(":", 1)[0] if evidence.error else None
        )}
    response = evidence.response
    return {
        "status": response.status_code,
        "duration_ms": response.elapsed_ms,
        "body_fingerprint": hmac.new(key, response.body_preview.encode("utf-8"), hashlib.sha256).hexdigest(),
        "truncated": response.body_truncated,
        "content_type": response.headers.get("content-type", response.headers.get("Content-Type", ""))[:80],
    }


def _add_finding(
    state: ScanState,
    *,
    category: str,
    operation: str,
    explanation: str,
    evidence: dict[str, Any],
    confidence: str = "indicator",
    severity: str = "low",
) -> None:
    """Record a bounded, explainable observation; never claim proof from heuristics."""
    if any(f["category"] == category and f["operation"] == operation
           and f["evidence"] == evidence for f in state.findings):
        return  # Different identities should not duplicate the same observation.
    state.findings.append({
        "id": f"OBS-{len(state.findings) + 1:04d}",
        "category": category,
        "operation": operation,
        "severity": severity,
        "confidence": confidence,
        "status": "requires_review",
        "why_flagged": explanation,
        "evidence": evidence,
    })


def _error_labels(evidence: ExecutionEvidence) -> list[str]:
    """Look for known error formats without saving sensitive response text."""
    if evidence.response is None:
        return []
    body = evidence.response.body_preview[:65536]
    return [label for label, pattern in _ERROR_SIGNATURES if pattern.search(body)]


def _invalid_input(schema: dict[str, Any]) -> str | None:
    """Create one harmless out-of-schema query value from OpenAPI constraints.

    The chosen probe is bounded and deterministic. It is *not* an exploit or a
    full fuzzing corpus. A string quote may reveal a server error; numeric
    schemas are tested with a nonnumeric value instead.
    """
    type_name = schema.get("type")
    if type_name in ("integer", "number"):
        return "not_a_number"
    if type_name == "boolean":
        return "not_a_boolean"
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return "__ACHILLES_OUTSIDE_ENUM__"
    if type_name == "string":
        # v0.22: use the documented string contract when possible. An empty
        # required-length value or a malformed format is a small, harmless
        # validation probe; never substitute a large fuzzing payload.
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and min_length > 0:
            return ""
        if schema.get("format") in {"uuid", "date", "date-time", "email", "ipv4", "ipv6"}:
            return "not-a-valid-" + str(schema["format"])
        max_length = schema.get("maxLength")
        if isinstance(max_length, int) and 0 <= max_length < 256:
            return "X" * (max_length + 1)
        return "'"
    return None


def describe_smart_checks(parsed: ParsedAPI, plan: dict[str, Any]) -> dict[str, Any]:
    """Explain which checks the framework chose and why, before sending traffic.

    This is the same generic decision process for any OpenAPI document. Write
    operations are included in the manual queue because Swagger does not say
    whether their data can be safely restored after a test.
    """
    operations = {(op["method"], op["path"]): op for op in plan["operations"]}
    proposed: list[dict[str, Any]] = []
    for endpoint in parsed.endpoints:
        op = operations[(endpoint.method, endpoint.path)]
        if op["status"] != "eligible_get":
            proposed.append({"method": endpoint.method, "path": endpoint.path,
                             "checks": [], "status": op["status"],
                             "needs": op.get("missing_path_values", []) + op.get("missing_query_values", [])})
            continue
        checks = ["baseline_http", "response_headers", "error_disclosure"]
        if endpoint.security:
            checks += ["missing_authentication", "cross_identity_comparison"]
        checks.append("cors_origin_probe")
        for param in endpoint.query_parameters:
            if _invalid_input(param.schema_) is not None:
                checks.append(f"query_schema_validation:{param.name}")
        proposed.append({"method": endpoint.method, "path": endpoint.path,
                         "checks": checks, "status": "eligible", "needs": []})
    return {
        "engine": "schema-aware-active-assessment",
        "decision_source": "OpenAPI schema + configured identities + optional expected-access policy",
        "network_requests_sent": 0,
        "check_selection": proposed,
        "note": "Plans are not findings; write methods require explicit lifecycle and rollback policies.",
    }


def _observe(
    client: SafeHTTPClient,
    state: ScanState,
    *,
    url: str,
    operation: str,
    check: str,
    identity_name: str,
    material: AuthenticationMaterial,
    query: dict[str, str],
    extra_headers: dict[str, str] | None = None,
) -> ExecutionEvidence | None:
    """Send one allowlisted GET and store only safe metadata.

    A shared client enforces the global rate, timeout and request budget. If
    the budget is exhausted, the check is skipped instead of bypassing limits.
    """
    if client._requests_made >= client.max_requests:
        state.skipped.append({"operation": operation, "check": check, "reason": "request_budget_exhausted"})
        return None
    headers = {**material.headers, **(extra_headers or {})}
    params = {**query, **material.params}
    try:
        evidence = client.request(
            "GET", url, execute=True, headers=headers, cookies=material.cookies,
            params=params, sensitive_query_names=set(params),
            sensitive_header_names=set(headers),
        )
    except RequestBudgetExceeded:
        state.skipped.append({"operation": operation, "check": check, "reason": "request_budget_exhausted"})
        return None
    state.observations.append({
        "operation": operation, "check": check, "identity": identity_name,
        **_metadata(evidence, state.fingerprint_key),
    })
    return evidence


def _response_checks(state: ScanState, operation: str, evidence: ExecutionEvidence, *, authenticated: bool) -> None:
    """Use real response evidence to identify possible disclosure/configuration issues.

    A server banner or missing cache restriction is an indication to review,
    not automatically an exploitable vulnerability.
    """
    response = evidence.response
    if response is None:
        return
    lower = {name.lower(): value for name, value in response.headers.items()}
    signatures = _error_labels(evidence)
    if signatures:
        _add_finding(state, category="error_disclosure", operation=operation,
                     explanation="The response contains a recognizable internal error format.",
                     evidence={"status": response.status_code, "signatures": signatures},
                     severity="medium")
    exposed = [name for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version") if name in lower]
    if exposed:
        _add_finding(state, category="technology_disclosure", operation=operation,
                     explanation="Implementation details are disclosed in response headers.",
                     evidence={"headers_present": exposed}, severity="info")
    cache = lower.get("cache-control", "").lower()
    if authenticated and response.status_code == 200 and "public" in cache:
        _add_finding(state, category="authenticated_public_cache", operation=operation,
                     explanation="An authenticated response explicitly allows public caching.",
                     evidence={"cache_control_public": True}, severity="medium")


def _cors_checks(state: ScanState, operation: str, evidence: ExecutionEvidence) -> None:
    """Inspect CORS headers after a controlled untrusted-Origin request.

    Reflection alone is not a confirmed vulnerability. The stronger indicator
    is that arbitrary Origin reflection is combined with credential support.
    """
    if evidence.response is None:
        return
    headers = {name.lower(): value for name, value in evidence.response.headers.items()}
    allows_origin = headers.get("access-control-allow-origin", "").lower() == _TEST_ORIGIN
    allows_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    if allows_origin and allows_credentials:
        _add_finding(state, category="cors_credentialed_origin_reflection", operation=operation,
                     explanation="The response reflects an arbitrary Origin while allowing credentials.",
                     evidence={"arbitrary_origin_reflected": True, "allow_credentials": True},
                     severity="medium")



def _response_field_paths(value: Any, *, prefix: str = "", depth: int = 0) -> set[str]:
    """List JSON property paths without recording any values from the response.

    A small recursion limit keeps deliberately nested payloads from consuming
    excess resources. Array samples use their first two elements only.
    """
    if depth > 8:
        return set()
    result: set[str] = set()
    if isinstance(value, dict):
        for key, child in list(value.items())[:100]:
            path = f"{prefix}.{key}" if prefix else str(key)
            result.add(path)
            result.update(_response_field_paths(child, prefix=path, depth=depth + 1))
    elif isinstance(value, list):
        for child in value[:2]:
            result.update(_response_field_paths(child, prefix=prefix, depth=depth + 1))
    return result


def _property_disclosure_checks(
    state: ScanState,
    operation: str,
    evidence: ExecutionEvidence,
    endpoint: Any,
    specification: dict[str, Any] | None,
) -> None:
    """Compare JSON field names with the response schema's sensitivity hints.

    A declared writeOnly property should not appear in a JSON response.
    A sensitive-looking name is only a review candidate, because an actual
    field-level permission policy is not present in OpenAPI.
    """
    if evidence.response is None or evidence.response.status_code >= 400 or not specification:
        return
    if "json" not in evidence.response.headers.get("content-type", "").lower():
        return
    try:
        content = json.loads(evidence.response.body_preview)
    except (ValueError, TypeError):
        return
    present = _response_field_paths(content)
    candidate_write_only: set[str] = set()
    candidate_sensitive: set[str] = set()
    for response_spec in endpoint.responses.values():
        for schema in _json_schemas(specification, response_spec):
            for prop in _properties(specification, schema):
                if prop["write_only"]:
                    candidate_write_only.add(prop["name"])
                if prop["sensitive_name"]:
                    candidate_sensitive.add(prop["name"])
    write_only_present = sorted(present & candidate_write_only)
    if write_only_present:
        _add_finding(state, category="write_only_property_returned", operation=operation,
                     explanation="A property declared writeOnly in OpenAPI appears in a GET response.",
                     evidence={"property_paths": write_only_present}, severity="medium")
    sensitive_present = sorted((present & candidate_sensitive) - candidate_write_only)
    if sensitive_present:
        _add_finding(state, category="sensitive_property_review", operation=operation,
                     explanation="The response contains potentially sensitive fields. Confirm role-based visibility.",
                     evidence={"property_paths": sensitive_present}, severity="low")

def _apply_expected_access(
    state: ScanState,
    *,
    operation: str,
    identity: str,
    status: int | None,
    policy: dict[str, dict[str, str]],
) -> None:
    """Compare an actual response to an operator-provided access policy.

    OpenAPI does not establish who owns an object or which roles may access it.
    Only explicit expected-access facts can produce a high-confidence mismatch.
    """
    expected = policy.get(operation, {}).get(identity)
    if expected not in ("allow", "deny") or status is None:
        return
    observed_success = 200 <= status < 300
    mismatch = (expected == "deny" and observed_success) or (
        expected == "allow" and status in (401, 403)
    )
    if mismatch:
        _add_finding(state, category="authorization_policy_mismatch", operation=operation,
                     explanation="Observed access contradicts the explicit test-account access policy.",
                     evidence={"identity": identity, "expected": expected, "status": status},
                     confidence="high_if_policy_is_correct", severity="high" if expected == "deny" else "medium")


def run_smart_assessment(
    parsed: ParsedAPI,
    plan: dict[str, Any],
    *,
    base_url: str,
    allowed_hosts: set[str],
    identities: dict[str, AuthenticationMaterial] | None = None,
    path_values: dict[str, str] | None = None,
    expected_access: dict[str, dict[str, str]] | None = None,
    specification: dict[str, Any] | None = None,
    settings: ScanSettings | None = None,
) -> dict[str, Any]:
    """Autonomously run eligible read-only checks and collect reviewable evidence.

    Steps: validate scope, select matching identities from OpenAPI security,
    perform baseline GETs, then select relevant auth/CORS/parameter probes.
    No operation uses lab-specific paths or users. All HTTP calls share a
    fixed budget. Nothing sends request bodies or changes data intentionally.

    This function is *execution only*; the CLI must require user opt-in.
    """
    settings = settings or ScanSettings()
    if settings.max_requests < 1 or settings.max_probes_per_endpoint < 0:
        raise ValueError("Request and per-endpoint probe limits must be valid.")
    urlparts = urlsplit(base_url)
    if urlparts.scheme not in ("http", "https") or not urlparts.hostname:
        raise ScopeError("Supply an absolute HTTP(S) base URL.")
    if urlparts.username or urlparts.password or urlparts.query or urlparts.fragment:
        raise ScopeError("Base URL must not embed credentials, query or fragment.")
    if urlparts.hostname.lower().rstrip(".") not in {v.lower().rstrip(".") for v in allowed_hosts}:
        raise ScopeError("Base URL is outside the explicitly authorized host allowlist.")
    if any(segment in (".", "..") for segment in urlparts.path.split("/")):
        raise ScopeError("Base URL cannot contain path traversal segments.")
    if urlparts.scheme == "http" and identities and not settings.allow_insecure_http:
        raise ScopeError("Refusing authentication credentials over plaintext HTTP.")
    state = ScanState()
    client = SafeHTTPClient(
        allowed_hosts=allowed_hosts, timeout=settings.timeout,
        max_requests=settings.max_requests, requests_per_second=settings.rate,
    )
    profiles = identities or {"anonymous": AuthenticationMaterial()}
    defs = plan.get("security_definitions", {})
    mapped = {(ep.method, ep.path): ep for ep in parsed.endpoints}
    value_map = path_values or {}
    policies = expected_access or {}
    for op in plan["operations"]:
        if op["status"] != "eligible_get":
            continue
        endpoint = mapped.get((op["method"], op["path"]))
        if endpoint is None:
            continue
        operation = f"GET {op['path']}"
        url = base_url.rstrip("/") + "/" + str(op["rendered_path"]).lstrip("/")
        # Guard against path traversal or a protocol-changing operation path.
        if any(segment in ("..", ".") for segment in op["path"].split("/")):
            state.skipped.append({"operation": operation, "check": "baseline", "reason": "unsafe_path"})
            continue
        selected = _compatible_identities(op, defs, profiles)
        if not selected:
            state.skipped.append({"operation": operation, "check": "baseline", "reason": "missing_compatible_auth_profile"})
            continue
        valid_query = {p.name for p in endpoint.query_parameters}
        query = {k: v for k, v in value_map.items() if k in valid_query}
        first_success: tuple[str, AuthenticationMaterial, ExecutionEvidence] | None = None
        current_successes: list[tuple[str, str]] = []
        for name, material in selected.items():
            evidence = _observe(client, state, url=url, operation=operation,
                                check="baseline", identity_name=name, material=material, query=query)
            if evidence is None:
                break
            _response_checks(state, operation, evidence, authenticated=bool(
                material.headers or material.params or material.cookies
            ))
            _property_disclosure_checks(state, operation, evidence, endpoint, specification)
            # v0.19: validate successful JSON against the corresponding OpenAPI
            # response schema. The report contains field paths, never values.
            if specification and evidence.response:
                response = evidence.response
                mismatches = response_contract_issues(
                    specification, endpoint, response.status_code,
                    response.body_preview, response.headers.get("content-type", ""),
                    response.body_truncated)
                if mismatches:
                    _add_finding(state, category="response_contract_mismatch", operation=operation,
                                 explanation="The response differs from its documented OpenAPI schema; verify the specification.",
                                 evidence={"issues": mismatches[:15], "status": response.status_code},
                                 confidence="indicator", severity="low")
            status = evidence.response.status_code if evidence.response else None
            _apply_expected_access(state, operation=operation, identity=name,
                                   status=status, policy=policies)
            if evidence.response and 200 <= evidence.response.status_code < 300:
                fingerprint = _metadata(evidence, state.fingerprint_key)["body_fingerprint"]
                current_successes.append((name, fingerprint))
                if first_success is None:
                    first_success = (name, material, evidence)
        # Identical data across accounts warrants investigation ONLY for paths
        # containing a resource identifier; it is not automatically BOLA.
        if _ID_PATTERN.search(endpoint.path) and len(current_successes) > 1:
            digest_groups: dict[str, list[str]] = {}
            for identity_name, digest in current_successes:
                digest_groups.setdefault(digest, []).append(identity_name)
            for matching in digest_groups.values():
                if len(matching) > 1:
                    _add_finding(state, category="cross_identity_object_review", operation=operation,
                                 explanation="Multiple identities received the same resource representation. Verify ownership rules.",
                                 evidence={"identities": matching, "same_response_fingerprint": True},
                                 severity="info")
        if first_success is None:
            continue
        name, material, baseline = first_success
        if settings.check_authentication and endpoint.security:
            unauth = _observe(client, state, url=url, operation=operation,
                              check="without_credentials", identity_name="anonymous",
                              material=AuthenticationMaterial(), query=query)
            if (unauth is not None and unauth.response is not None
                    and 200 <= unauth.response.status_code < 300):
                _add_finding(state, category="unauthenticated_access_review", operation=operation,
                             explanation="An endpoint marked as authenticated in OpenAPI responds successfully without credentials.",
                             evidence={"anonymous_status": unauth.response.status_code}, severity="medium")
        if settings.check_cors:
            cors = _observe(client, state, url=url, operation=operation,
                            check="cors_origin", identity_name=name, material=material,
                            query=query, extra_headers={"Origin": _TEST_ORIGIN})
            if cors is not None:
                _cors_checks(state, operation, cors)
        if settings.check_input_validation:
            probes = 0
            for param in endpoint.query_parameters:
                if probes >= settings.max_probes_per_endpoint:
                    break
                invalid = _invalid_input(param.schema_)
                if invalid is None:
                    continue
                # Required query parameters need a known valid baseline value;
                # otherwise their rejection cannot be attributed to mutation.
                if param.required and param.name not in query:
                    continue
                probe_query = {**query, param.name: invalid}
                candidate = _observe(client, state, url=url, operation=operation,
                                     check=f"invalid_query:{param.name}", identity_name=name,
                                     material=material, query=probe_query)
                if candidate is None:
                    break
                probes += 1
                if candidate.response is None:
                    continue
                labels = _error_labels(candidate)
                if labels and candidate.response.status_code >= 500:
                    _add_finding(state, category="input_error_disclosure", operation=operation,
                                 explanation="An invalid schema-aware query input produced an internal error signature.",
                                 evidence={"parameter": param.name, "status": candidate.response.status_code,
                                           "signatures": labels}, severity="medium")
                elif candidate.response.status_code >= 500 and baseline.response is not None and baseline.response.status_code < 500:
                    _add_finding(state, category="unexpected_server_error", operation=operation,
                                 explanation="An invalid query input caused a server error compared with the working baseline.",
                                 evidence={"parameter": param.name, "status": candidate.response.status_code}, severity="low")
    return {
        "engine": "schema-aware-active-assessment",
        "executed": True,
        "requests_sent": client._requests_made,
        "request_budget": settings.max_requests,
        "observations": state.observations,
        "findings": state.findings,
        "findings_confirmed": 0,
        "skipped": state.skipped,
        "report_safety": "Response bodies, credentials, and raw query values are not persisted. Fingerprints are per-run keyed HMACs.",
        "limitations": [
            "No automatic mutations, deletion, password reset or state-changing method execution.",
            "Business logic and ownership cannot be inferred from OpenAPI alone.",
            "No result is considered a confirmed vulnerability without a trusted oracle and review.",
            "GET operations may be state-changing in an incorrectly implemented API; obtain approval for the scope.",
        ],
    }
