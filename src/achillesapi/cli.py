"""Command-line interface for AchillesAPI."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from achillesapi import __version__
from achillesapi.ai.analyzer import analyze_api_locally
from achillesapi.ai.local import LocalAIError
from achillesapi.ai.intelligence import correlate_with_ollama
from achillesapi.core.assessment import assess_api, assessment_to_dict
from achillesapi.core.advanced import (
    AdvancedCheckError, bola_sweep, bfla_sweep, mass_assignment_check,
    sqli_probe, fuzz_query_parameter, inspect_jwt,
)
from achillesapi.core.auth import AuthenticationConfigError, AuthenticationMaterial, load_authentication_manager
from achillesapi.core.authorization import authorization_matrix
from achillesapi.core.bola import BolaCheckError, check_bola
from achillesapi.core.graph import build_api_graph, graph_to_dict
from achillesapi.core.generic import build_generic_plan, execute_generic_gets
from achillesapi.core.smart import ScanSettings, describe_smart_checks, run_smart_assessment
from achillesapi.core.context import ContextError, read_context
from achillesapi.core.multi_resource import MultiResourceError
from achillesapi.core.workflows import (WorkflowError, read_workflows, discover_workflows, draft_workflow_config,
                                       workflow_plan, run_workflows)
from achillesapi.core.testgen import generate_test_plan
from achillesapi.core.detection import EvidenceAnalysisError, analyze_response_evidence
from achillesapi.core.http import RequestBudgetExceeded, SafeHTTPClient, ScopeError
from achillesapi.core.openapi import OpenAPIParseError, analyze_openapi_file, load_openapi, parse_openapi
from achillesapi.core.intelligence import intelligent_plan, adaptive_queue
from achillesapi.core.journeys import JourneyError, read_journey, run_journey
from achillesapi.core.adaptive import verify_server_errors
from achillesapi.core.journey_discovery import discover_read_journeys, journey_draft
from achillesapi.core.auth_discovery import draft_auth_profiles
from achillesapi.core.security_inventory import security_inventory
from achillesapi.core.orchestrator import choose_followups, run_followups
from achillesapi.core.roadmap_v027 import workflow_dependency_map, vulnerability_triage, policy_gated_agent
from achillesapi.reporting.professional import write_professional_report
from achillesapi.core.production_v031 import (
    AssessmentPolicyError, scope_audit, coverage_report, differential_review,
    workflow_graph, load_workflow_graph, save_json, benchmark_evaluate, next_actions,
)

app = typer.Typer(
    name="achillesapi",
    help="AI-assisted, context-aware API security assessment framework.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Display the installed AchillesAPI version."""
    # IN PRATICA: Espone il comando 'version' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.

    typer.echo(f"AchillesAPI {__version__}")


@app.command("analyze-openapi")
def analyze_openapi(
    specification: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write normalized JSON output to this file."
    ),
    skip_validation: bool = typer.Option(
        False, "--skip-validation", help="Skip OpenAPI specification validation."
    ),
) -> None:
    """Validate and summarize an OpenAPI specification."""
    # IN PRATICA: Espone il comando 'analyze openapi' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.

    try:
        parsed = analyze_openapi_file(specification, validate=not skip_validation)
    except (OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"{parsed.title} — {parsed.version}")
    typer.echo("METHOD  PATH                         OPERATION ID       PARAMS  SECURITY")
    for endpoint in parsed.endpoints:
        schemes = sorted(
            {scheme for requirement in endpoint.security for scheme in requirement.schemes}
        )
        security_label = ", ".join(schemes) if schemes else (
            "disabled" if endpoint.security_is_explicitly_disabled else "unspecified"
        )
        typer.echo(
            f"{endpoint.method:<7} {endpoint.path:<28} "
            f"{(endpoint.operation_id or '—'):<18} "
            f"{len(endpoint.parameters):<7} {security_label}"
        )
    typer.echo(
        f"{parsed.endpoint_count} endpoints | {len(parsed.security_schemes)} security schemes"
    )

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(parsed.model_dump_json(indent=2, by_alias=True), encoding="utf-8")
        typer.echo(f"Normalized output written to {output}")



@app.command("generate-tests")
def generate_tests(
    specification: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    output: Path = typer.Option(Path("reports/test-plan.json"), "--output", "-o"),
    skip_validation: bool = typer.Option(False, "--skip-validation"),
) -> None:
    """Generate a deterministic, offline security test plan; sends no requests."""
    # IN PRATICA: Espone il comando 'generate tests' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.
    try:
        parsed = analyze_openapi_file(specification, validate=not skip_validation)
        spec = load_openapi(specification, validate=not skip_validation)
        payload = generate_test_plan(parsed, spec)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except (OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    summary = payload["summary"]
    typer.echo(
        f"Generated {summary['test_case_count']} test cases and "
        f"{summary['workflow_count']} workflows. No network requests sent."
    )
    typer.echo(f"Test plan written to {output}")


@app.command("analyze-evidence")
def analyze_evidence(
    evidence_file: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, readable=True),
    output: Path = typer.Option(Path("reports/evidence-analysis.json"), "--output", "-o"),
) -> None:
    """Correlate captured HTTP responses offline; sends no requests and stores no body values."""
    # IN PRATICA: Espone il comando 'analyze evidence' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.
    try:
        bundle = json.loads(evidence_file.read_text(encoding="utf-8"))
        report = analyze_response_evidence(bundle)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except (OSError, json.JSONDecodeError, EvidenceAnalysisError) as exc:
        typer.echo(f"Evidence analysis error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    summary = report["summary"]
    typer.echo(f"Analyzed {report['responses_analyzed']} captured responses; "
               f"{summary['finding_count']} indicators identified. No requests sent.")
    typer.echo(f"Report written to {output}")


@app.command("map-api")
def map_api(
    specification: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    output: Path = typer.Option(Path("reports/api-graph.json"), "--output", "-o"),
) -> None:
    """Build a provenance-aware graph of endpoints, resources and schemas."""
    # IN PRATICA: Espone il comando 'map api' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.
    try:
        parsed = analyze_openapi_file(specification)
        spec = load_openapi(specification)
        graph = build_api_graph(parsed, spec)
        payload = graph_to_dict(graph)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except (OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"Relationship graph: {graph.number_of_nodes()} nodes, "
        f"{graph.number_of_edges()} edges. Written to {output}"
    )


@app.command("assess")
def assess(
    specification: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Run passive, specification-based security checks (no network traffic)."""
    # IN PRATICA: Espone il comando 'assess' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.
    try:
        parsed = analyze_openapi_file(specification)
        payload = assessment_to_dict(assess_api(parsed))
    except (OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"Assessment written to {output}")
    typer.echo(f"{len(payload['findings'])} passive hypotheses; 0 confirmed vulnerabilities.")
    for finding in payload["findings"]:
        typer.echo(
            f"[{finding['severity'].upper()}] {finding['category']} "
            f"{finding['endpoint']}: {finding['title']}"
        )


def _bearer_token_from_profile(manager, profile_name: str) -> str:
    """Resolve a named profile for legacy bearer-only authorization sweeps."""
    # IN PRATICA: Espone il comando ' bearer token from profile' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.
    material = manager.resolve(profile_name)
    authorization = material.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise AuthenticationConfigError(
            f"Profile {profile_name!r} must be a Bearer profile for BOLA/BFLA sweeps."
        )
    token = authorization.removeprefix("Bearer ")
    if not token:
        raise AuthenticationConfigError(f"Profile {profile_name!r} resolved an empty bearer token.")
    return token


@app.command("auth-profiles")
def auth_profiles(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", "-o", help="Optional JSON report for the dashboard."),
) -> None:
    """Validate and list authentication profiles without displaying secret values."""
    # IN PRATICA: Espone il comando 'auth profiles' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.
    try:
        manager = load_authentication_manager(config)
    except AuthenticationConfigError as exc:
        typer.echo(f"Authentication configuration error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    report = {"profiles": manager.describe()}
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    typer.echo(json.dumps(report, indent=2, ensure_ascii=False))


@app.command("http-get")
def http_get(
    url: str = typer.Argument(..., help="Absolute URL on an explicitly allowlisted host."),
    allow_host: list[str] = typer.Option(
        ..., "--allow-host", help="Exact authorized hostname; repeat for multiple hosts."
    ),
    execute: bool = typer.Option(
        False, "--execute", help="Actually send the GET request; otherwise perform a dry run."
    ),
    timeout: float = typer.Option(10.0, min=0.1, max=60.0),
    max_requests: int = typer.Option(1, min=1, max=10),
    auth_config: Path | None = typer.Option(None, "--auth-config", exists=True, dir_okay=False),
    auth_profile: str | None = typer.Option(None, "--auth-profile"),
) -> None:
    """Perform a scoped GET request; dry-run is the default and only GET is enabled."""
    # IN PRATICA: Espone il comando 'http get' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    if bool(auth_config) != bool(auth_profile):
        typer.echo("Both --auth-config and --auth-profile must be supplied together.", err=True)
        raise typer.Exit(code=1)
    try:
        auth = None
        if auth_config and auth_profile:
            auth = load_authentication_manager(auth_config).resolve(auth_profile)
        client = SafeHTTPClient(
            allowed_hosts=set(allow_host), timeout=timeout, max_requests=max_requests
        )
        evidence = client.request(
            "GET", url, execute=execute,
            headers=auth.headers if auth else None,
            params=auth.params if auth else None,
            cookies=auth.cookies if auth else None,
            sensitive_query_names=set(auth.params) if auth else None,
            sensitive_header_names=set(auth.headers) if auth else None,
        )
    except (AuthenticationConfigError, ScopeError, RequestBudgetExceeded, ValueError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(evidence.model_dump(mode="json"), indent=2))


@app.command("bola-check")
def bola_check(
    url: str = typer.Argument(..., help="Authorized localhost object URL for the legacy BOLA checker."),
    owner_token: str | None = typer.Option(None, "--owner-token", hide_input=True),
    other_token: str | None = typer.Option(None, "--other-token", hide_input=True),
    execute: bool = typer.Option(
        False, "--execute", help="Send two GET requests; without this flag, only show the plan."
    ),
    timeout: float = typer.Option(5.0, min=0.1, max=30.0),
) -> None:
    """Compare object access by its owner and a different principal (localhost only)."""
    # IN PRATICA: Espone il comando 'bola check' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    if not execute:
        typer.echo(json.dumps({
            "check": "BOLA",
            "executed": False,
            "target": url,
            "planned_requests": 2,
            "principals": ["owner", "other"],
            "note": "Dry run: no network requests sent. Add --execute to run the localhost check.",
        }, indent=2))
        return
    if owner_token is None:
        owner_token = typer.prompt("Owner bearer token", hide_input=True)
    if other_token is None:
        other_token = typer.prompt("Other principal bearer token", hide_input=True)
    try:
        result = check_bola(
            url, owner_token=owner_token, other_token=other_token, timeout=timeout
        )
    except (BolaCheckError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(result.model_dump_json(indent=2))


def _path_values(items: list[str]) -> dict[str, str]:
    """In pratica: Converte argomenti NAME=VALUE della CLI in un dizionario.

    Attenzione: Non contatta direttamente l'API target.
    """
    values: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise AdvancedCheckError(f"Invalid path value {item!r}; expected NAME=VALUE.")
        name, value = item.split("=", 1)
        if not name or not value:
            raise AdvancedCheckError(f"Invalid path value {item!r}; name and value are required.")
        values[name] = value
    return values


@app.command("bola-sweep")
def bola_sweep_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    base_url: str = typer.Option(..., "--base-url"),
    owner_token: str | None = typer.Option(None, "--owner-token", hide_input=True),
    other_token: str | None = typer.Option(None, "--other-token", hide_input=True),
    auth_config: Path | None = typer.Option(None, "--auth-config", exists=True, dir_okay=False),
    owner_profile: str | None = typer.Option(None, "--owner-profile"),
    other_profile: str | None = typer.Option(None, "--other-profile"),
    path_value: list[str] = typer.Option([], "--path-value", help="Path placeholder NAME=VALUE; repeat as needed."),
    timeout: float = typer.Option(5.0, min=0.1, max=15.0),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Compare two principals across all GET operations (loopback only)."""
    # IN PRATICA: Espone il comando 'bola sweep' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    try:
        using_profiles = bool(auth_config or owner_profile or other_profile)
        if using_profiles:
            if not (auth_config and owner_profile and other_profile):
                raise AuthenticationConfigError(
                    "--auth-config, --owner-profile and --other-profile must be supplied together."
                )
            if owner_token or other_token:
                raise AuthenticationConfigError("Use profile options or raw token options, not both.")
            manager = load_authentication_manager(auth_config)
            owner_token = _bearer_token_from_profile(manager, owner_profile)
            other_token = _bearer_token_from_profile(manager, other_profile)
        else:
            if owner_token is None:
                owner_token = typer.prompt("Owner bearer token", hide_input=True)
            if other_token is None:
                other_token = typer.prompt("Other principal bearer token", hide_input=True)
        spec = load_openapi(specification)
        result = bola_sweep(spec, base_url, owner_token, other_token, _path_values(path_value), timeout)
    except (AuthenticationConfigError, AdvancedCheckError, OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    rendered = json.dumps(result, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    typer.echo(rendered)


@app.command("bfla-sweep")
def bfla_sweep_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    base_url: str = typer.Option(..., "--base-url"),
    low_token: str | None = typer.Option(None, "--low-token", hide_input=True),
    high_token: str | None = typer.Option(None, "--high-token", hide_input=True),
    auth_config: Path | None = typer.Option(None, "--auth-config", exists=True, dir_okay=False),
    low_profile: str | None = typer.Option(None, "--low-profile"),
    high_profile: str | None = typer.Option(None, "--high-profile"),
    path_value: list[str] = typer.Option([], "--path-value"),
    timeout: float = typer.Option(5.0, min=0.1, max=15.0),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Compare low/high privilege responses across GET operations (loopback only)."""
    # IN PRATICA: Espone il comando 'bfla sweep' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    try:
        using_profiles = bool(auth_config or low_profile or high_profile)
        if using_profiles:
            if not (auth_config and low_profile and high_profile):
                raise AuthenticationConfigError(
                    "--auth-config, --low-profile and --high-profile must be supplied together."
                )
            if low_token or high_token:
                raise AuthenticationConfigError("Use profile options or raw token options, not both.")
            manager = load_authentication_manager(auth_config)
            low_token = _bearer_token_from_profile(manager, low_profile)
            high_token = _bearer_token_from_profile(manager, high_profile)
        else:
            if low_token is None:
                low_token = typer.prompt("Low-privilege bearer token", hide_input=True)
            if high_token is None:
                high_token = typer.prompt("High-privilege bearer token", hide_input=True)
        spec = load_openapi(specification)
        result = bfla_sweep(spec, base_url, low_token, high_token, _path_values(path_value), timeout)
    except (AuthenticationConfigError, AdvancedCheckError, OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    rendered = json.dumps(result, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    typer.echo(rendered)


@app.command("sqli-check")
def sqli_check_command(
    url: str = typer.Argument(...),
    parameter: str = typer.Option(..., "--parameter", "-p"),
    token: str | None = typer.Option(None, "--token", hide_input=True),
) -> None:
    """Send a non-destructive quote-only SQLi canary to a loopback GET endpoint."""
    # IN PRATICA: Espone il comando 'sqli check' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    try:
        result = sqli_probe(url, parameter, token)
    except (AdvancedCheckError, ValueError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, indent=2))


@app.command("fuzz-parameter")
def fuzz_parameter_command(
    url: str = typer.Argument(...),
    parameter: str = typer.Option(..., "--parameter", "-p"),
    token: str | None = typer.Option(None, "--token", hide_input=True),
) -> None:
    """Run nine benign GET-only boundary/format cases against loopback."""
    # IN PRATICA: Espone il comando 'fuzz parameter' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    try:
        result = fuzz_query_parameter(url, parameter, token)
    except (AdvancedCheckError, ValueError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, indent=2))


@app.command("mass-assignment-check")
def mass_assignment_command(
    url: str = typer.Argument(...),
    body_file: Path = typer.Option(..., "--body-file", exists=True, dir_okay=False),
    token: str | None = typer.Option(None, "--token", hide_input=True),
    execute: bool = typer.Option(False, "--execute", help="Send PATCH to loopback; may modify lab data."),
) -> None:
    """Plan or explicitly send a caller-supplied JSON PATCH to loopback."""
    # IN PRATICA: Espone il comando 'mass assignment' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    if execute and token is None:
        token = typer.prompt("Bearer token", hide_input=True)
    try:
        body = json.loads(body_file.read_text(encoding="utf-8"))
        result = mass_assignment_check(url, body, token, execute)
    except (AdvancedCheckError, ValueError, OSError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, indent=2))


@app.command("role-matrix")
def role_matrix_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    base_url: str = typer.Option(..., "--base-url"),
    auth_config: Path = typer.Option(..., "--auth-config", exists=True, dir_okay=False),
    profile: list[str] = typer.Option(..., "--profile", help="Profile to include; repeat for each identity (2-10)."),
    path_value: list[str] = typer.Option([], "--path-value", help="Path placeholder NAME=VALUE; repeat as needed."),
    timeout: float = typer.Option(5.0, min=0.1, max=15.0),
    output: Path | None = typer.Option(Path("reports/role-matrix.json"), "--output", "-o"),
) -> None:
    """Compare GET access and JSON property visibility across auth profiles (loopback only)."""
    # IN PRATICA: Espone il comando 'role matrix' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    try:
        if len(profile) < 2 or len(profile) > 10 or len(set(profile)) != len(profile):
            raise AdvancedCheckError("Supply 2-10 distinct --profile values.")
        manager = load_authentication_manager(auth_config)
        materials = {name: manager.resolve(name) for name in profile}
        spec = load_openapi(specification)
        result = authorization_matrix(spec, base_url, materials, _path_values(path_value), timeout)
    except (AuthenticationConfigError, AdvancedCheckError, OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        typer.echo(f"Role matrix written to {output}")
    typer.echo(rendered)


@app.command("jwt-inspect")
def jwt_inspect_command(
    token: str | None = typer.Argument(None, help="Compact JWT; omitted means secure prompt."),
) -> None:
    """Decode JWT header and claims offline; signature is never verified."""
    # IN PRATICA: Espone il comando 'jwt inspect' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Non contatta direttamente l'API target.
    value = token or typer.prompt("JWT", hide_input=True)
    try:
        result = inspect_jwt(value)
    except AdvancedCheckError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, indent=2))


@app.command("ai-analyze")
def ai_analyze_command(
    specification: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", "-o"),
    model: str = typer.Option("achilles-local", "--model", help="Model already installed in local Ollama."),
    endpoint: str = typer.Option("http://127.0.0.1:11434", "--endpoint", help="Loopback Ollama endpoint only."),
    timeout: float = typer.Option(120.0, min=1.0, max=300.0),
) -> None:
    """Analyze an OpenAPI specification with the local Ollama model only."""
    # IN PRATICA: Espone il comando 'ai analyze' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo contattare Ollama sul computer locale, ma non l'API target.
    try:
        parsed = analyze_openapi_file(specification)
        result = analyze_api_locally(parsed, endpoint=endpoint, model=model, timeout=timeout)
    except (OpenAPIParseError, LocalAIError, ValueError, OSError) as exc:
        typer.echo(f"Local AI analysis failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        typer.echo(f"Local AI report written to {output}")
    typer.echo(rendered)


@app.command("ai-correlate")
def ai_correlate_command(
    specification: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, readable=True),
    evidence_file: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, readable=True),
    output: Path = typer.Option(Path("reports/ai-correlation.json"), "--output", "-o"),
    model: str = typer.Option("achilles-local", "--model", help="Model already installed in local Ollama."),
    endpoint: str = typer.Option("http://127.0.0.1:11434", "--endpoint", help="Loopback Ollama endpoint only."),
    timeout: float = typer.Option(120.0, min=1.0, max=300.0),
) -> None:
    """Correlate OpenAPI and captured response evidence using local Ollama; sends no target traffic."""
    # IN PRATICA: Espone il comando 'ai correlate' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo contattare Ollama sul computer locale, ma non l'API target.
    try:
        from achillesapi.ai.local import _local_endpoint
        _local_endpoint(endpoint)  # Reject a remote model before reading evidence.
        parsed = analyze_openapi_file(specification)
        bundle = json.loads(evidence_file.read_text(encoding="utf-8"))
        from achillesapi.core.evidence_bridge import evidence_from_assessment
        evidence_report = analyze_response_evidence(evidence_from_assessment(bundle))
        from achillesapi.core.evidence_signals import scanner_findings
        original_findings = scanner_findings(bundle)
        evidence_report["scanner_observations"] = {
            "count": len(original_findings),
            "findings": original_findings,
            "source": "original_assessment_or_professional_report",
            "verification": "requires_review",
        }
        ai_report = correlate_with_ollama(
            parsed, evidence_report, endpoint=endpoint, model=model, timeout=timeout
        )
        result = {
            "engine": "achillesapi-local-intelligence",
            "version": __version__,
            "provider": "ollama-local-only",
            "target_requests_sent": 0,
            "evidence_analysis": evidence_report,
            "correlation_summary": {
                "original_scanner_observations": len(original_findings),
                "additional_offline_response_indicators": evidence_report["summary"]["finding_count"],
                "verified_vulnerabilities": 0,
                "original_findings_preserved": True,
            },
            "ai_correlation": ai_report,
            "note": "Correlazioni consultive: non sono vulnerabilità confermate e non autorizzano l'esecuzione.",
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OpenAPIParseError, LocalAIError, EvidenceAnalysisError, ValueError, OSError) as exc:
        typer.echo(f"AI correlation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Local correlation completed with {model}; target requests sent: 0.")
    typer.echo(f"Report written to {output}")


@app.command("scan")
def scan_command(
    specification: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, readable=True),
    output: Path = typer.Option(Path("reports/scan.json"), "--output", "-o"),
    with_ai: bool = typer.Option(False, "--ai", help="Add advisory analysis from local Ollama."),
    model: str = typer.Option("achilles-local", "--model", help="Local Ollama model name."),
    endpoint: str = typer.Option("http://127.0.0.1:11434", "--endpoint", help="Loopback Ollama endpoint only."),
    skip_validation: bool = typer.Option(False, "--skip-validation"),
) -> None:
    """Run passive OpenAPI assessment; optionally add local-only AI interpretation. No target traffic."""
    # IN PRATICA: Espone il comando 'scan' della CLI, controlla le opzioni e presenta il risultato all'operatore.
    # SICUREZZA: Puo contattare Ollama sul computer locale, ma non l'API target.
    try:
        parsed = analyze_openapi_file(specification, validate=not skip_validation)
        deterministic = assessment_to_dict(assess_api(parsed))
        result: dict[str, object] = {
            "project": "AchillesAPI",
            "version": __version__,
            "scan_type": "passive_openapi_only",
            "target_requests_sent": 0,
            "api": {"title": parsed.title, "version": parsed.version, "endpoint_count": parsed.endpoint_count},
            "assessment": deterministic,
            "ai_analysis": None,
            "note": "This command does not send requests to the target API. Active checks remain separate and scoped.",
        }
        if with_ai:
            ai_result = analyze_api_locally(parsed, endpoint=endpoint, model=model)
            result["ai_analysis"] = ai_result["ai_analysis"]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OpenAPIParseError, LocalAIError, ValueError, OSError) as exc:
        typer.echo(f"Scan failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Passive assessment completed: {parsed.endpoint_count} endpoints, "
               f"{len(deterministic['findings'])} hypotheses. Requests sent: 0.")
    if with_ai:
        typer.echo(f"Local AI analysis completed with {model}.")
    typer.echo(f"Report written to {output}")



@app.command("workflow-discover")
def workflow_discover_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/workflow-candidates.json"), "--output", "-o"),
    draft_config: Path | None = typer.Option(None, "--draft-config", help="Save an unexecutable YAML workflow template."),
) -> None:
    """Discover possible CRUD chains from OpenAPI without contacting the API.

    In pratica: trova possibili sequenze POST -> GET -> PATCH -> DELETE.
    Non conosce quali oggetti siano sacrificabili: ogni proposta e una ipotesi.
    """
    try:
        parsed = analyze_openapi_file(specification)
        spec = load_openapi(specification)
        report = discover_workflows(parsed, spec)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if draft_config:
            import yaml
            draft_config.parent.mkdir(parents=True, exist_ok=True)
            draft_config.write_text(
                "# DRAFT ONLY: replace every REPLACE_ME and confirm disposable fixtures.\n"
                + yaml.safe_dump(draft_workflow_config(parsed, spec), sort_keys=False), encoding="utf-8")
    except (OpenAPIParseError, WorkflowError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Suggested {report['candidate_count']} possible lifecycles. Requests: 0. Report: {output}")


@app.command("workflow-assess")
def workflow_assess_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    workflow_config: Path = typer.Option(..., "--workflow-config", exists=True, dir_okay=False),
    base_url: str | None = typer.Option(None, "--base-url"),
    auth_config: Path | None = typer.Option(None, "--auth-config", exists=True, dir_okay=False),
    allow_host: list[str] = typer.Option([], "--allow-host", help="Exact authorized hostname."),
    execute: bool = typer.Option(False, "--execute", help="Contact the explicitly approved target."),
    approve_writes: bool = typer.Option(False, "--approve-writes", help="Explicitly approve disposable POST/PATCH/DELETE."),
    allow_insecure_http: bool = typer.Option(False, "--allow-insecure-http"),
    max_requests: int = typer.Option(40, "--max-requests", min=1, max=500),
    rate: float = typer.Option(1.0, "--rate", min=0.1, max=10),
    timeout: float = typer.Option(8.0, "--timeout", min=0.1, max=60),
    output: Path = typer.Option(Path("reports/workflow-assessment.json"), "--output", "-o"),
) -> None:
    """Run a disposable API lifecycle using an explicit, reviewed YAML fixture.

    In pratica: pianifica creazione, accesso, confronto account, modifica e
    cancellazione. Senza --execute non invia richieste. Con --execute richiede
    --approve-writes e tenta sempre DELETE + verifica della cancellazione.
    """
    try:
        parsed = analyze_openapi_file(specification)
        spec = load_openapi(specification)
        wf = read_workflows(workflow_config)
        if base_url is None:
            candidates = [s.get("url") for s in parsed.servers if isinstance(s, dict)
                          and isinstance(s.get("url"), str) and s["url"].startswith(("http://", "https://"))
                          and "{" not in s["url"]]
            if len(candidates) != 1:
                raise WorkflowError("Supply --base-url: specification has no single concrete server.")
            base_url = candidates[0]
        if execute and (not auth_config or not allow_host):
            raise WorkflowError("Execution requires --auth-config and explicit --allow-host.")
        if execute and not approve_writes:
            raise WorkflowError("Executing workflows requires --approve-writes.")
        manager = load_authentication_manager(auth_config) if auth_config else None
        names = set(manager.names) if manager else None
        plan = workflow_plan(parsed, spec, wf, names)
        result = {"tool": "AchillesAPI", "version": __version__, "plan": plan, "execution": None}
        if execute:
            # Preflight scope/budget before a dynamic auth profile contacts an
            # OAuth token endpoint. Authorization is not inferred from Swagger.
            from urllib.parse import urlsplit
            target = urlsplit(base_url)
            if (target.scheme not in {"http", "https"} or not target.hostname or
                target.hostname.lower().rstrip(".") not in {h.lower().rstrip(".") for h in allow_host} or
                target.username or target.password or target.query or target.fragment or
                any(part in (".", "..") for part in target.path.split("/"))):
                raise ScopeError("Workflow target is outside the exact host allowlist or has unsafe URL components")
            if max_requests < plan["request_budget_required"]:
                raise WorkflowError("Request budget is smaller than the workflow + cleanup reservation")
            required_names = {
                name for scenario in wf
                for name in ([scenario["create"]["identity"], scenario["read"]["identity"],
                              scenario["cleanup"]["identity"]]
                             + [step["identity"] for step in scenario.get("access", [])]
                             + [step["identity"] for step in scenario.get("mutations", [])]
                             + ([scenario["mutation"]["identity"]] if scenario.get("mutation") else []))
            }
            identities = {name: manager.resolve(name, allowed_hosts=set(allow_host),
                       allow_insecure_http=allow_insecure_http) for name in sorted(required_names)}
            result["execution"] = run_workflows(
                parsed, spec, wf, base_url=base_url, allowed_hosts=set(allow_host),
                identities=identities, execute=True, approve_writes=True,
                allow_insecure_http=allow_insecure_http, max_requests=max_requests,
                rate=rate, timeout=timeout,
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (WorkflowError, AuthenticationConfigError, OpenAPIParseError,
            ScopeError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    count = result["execution"]["requests_sent"] if execute else 0
    typer.echo(f"Workflows: {len(wf)} | Requests: {count} | Output: {output}")
    if execute and result["execution"]["manual_cleanup_required"]:
        typer.echo("WARNING: Some disposable resources were not verified as deleted. Manual cleanup required.", err=True)
        raise typer.Exit(code=2)


@app.command("intelligent-plan")
def intelligent_plan_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/intelligent-plan.json"), "--output", "-o"),
) -> None:
    """Offline: generate schema-aware request examples, dependency hints and test priorities."""
    try:
        parsed = analyze_openapi_file(specification)
        result = intelligent_plan(parsed, load_openapi(specification))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Planned {len(result['operations'])} operations, {len(result['candidate_dependencies'])} possible dependencies -> {output}")


@app.command("adaptive-review")
def adaptive_review_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    observations: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/adaptive-review.json"), "--output", "-o"),
) -> None:
    """Offline: prioritize next manual checks from sanitized HTTP observations."""
    try:
        parsed = analyze_openapi_file(specification)
        plan = intelligent_plan(parsed, load_openapi(specification))
        data = json.loads(observations.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            data = data.get("observations", data.get("execution_report", {}).get("observations", []))
        if not isinstance(data, list):
            raise ValueError("Expected a list of sanitized observations")
        queue = adaptive_queue(plan, data)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"queue": queue}, indent=2) + "\n", encoding="utf-8")
    except (OpenAPIParseError, ValueError, OSError, json.JSONDecodeError, AttributeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Proposed {len(queue)} follow-up checks -> {output}")


@app.command("journey-discover")
def journey_discover_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/read-journey-candidates.json"), "--output", "-o"),
    draft_config: Path | None = typer.Option(None, "--draft-config", help="Optional starter YAML for the highest-ranked candidate."),
) -> None:
    """Offline: find read-only producer/consumer links and draft a YAML journey."""
    try:
        parsed = analyze_openapi_file(specification)
        discovered = discover_read_journeys(parsed, load_openapi(specification))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(discovered, indent=2) + "\n", encoding="utf-8")
        if draft_config:
            if not discovered["candidates"]:
                raise JourneyError("No GET dependency candidates: cannot create a YAML draft")
            import yaml
            draft_config.parent.mkdir(parents=True, exist_ok=True)
            starter = journey_draft(parsed, discovered["candidates"][0])
            draft_config.write_text(yaml.safe_dump(starter, sort_keys=False), encoding="utf-8")
    except (OpenAPIParseError, JourneyError, OSError, ValueError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Candidates: {discovered['count']}, network requests: 0 -> {output}")


@app.command("auth-draft")
def auth_draft_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("auth-profiles.draft.yaml"), "--output", "-o"),
) -> None:
    """Offline: create environment-variable-based auth profile templates."""
    try:
        import yaml
        parsed = analyze_openapi_file(specification)
        draft = draft_auth_profiles(parsed)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(yaml.safe_dump({"profiles": draft["profiles"]}, sort_keys=False), encoding="utf-8")
    except (OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Profiles: {len(draft['profiles'])}; manual schemes: {len(draft['manual_configuration_required'])}. Review {output}")


@app.command("journey-assess")
def journey_assess_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    journey_config: Path = typer.Option(..., "--journey-config", exists=True, dir_okay=False),
    base_url: str = typer.Option(..., "--base-url"),
    auth_config: Path | None = typer.Option(None, "--auth-config", exists=True, dir_okay=False),
    allow_host: list[str] = typer.Option([], "--allow-host"),
    execute: bool = typer.Option(False, "--execute"),
    allow_insecure_http: bool = typer.Option(False, "--allow-insecure-http"),
    max_requests: int = typer.Option(30, "--max-requests", min=1, max=100),
    rate: float = typer.Option(1.0, "--rate", min=0.1, max=10),
    output: Path = typer.Option(Path("reports/journey.json"), "--output", "-o"),
) -> None:
    """Run approved GET-only chains, capturing IDs transiently from responses.

    Does not send POST/PATCH/DELETE. The YAML declares operations and JSON
    Pointers, and every operation must occur in the supplied OpenAPI document.
    """
    try:
        parsed = analyze_openapi_file(specification)
        config = read_journey(journey_config)
        manager = load_authentication_manager(auth_config) if auth_config else None
        result = run_journey(parsed, config, base_url=base_url, allowed_hosts=set(allow_host),
                             manager=manager, execute=execute, max_requests=max_requests,
                             rate=rate, allow_insecure_http=allow_insecure_http)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OpenAPIParseError, JourneyError, ScopeError, AuthenticationConfigError, ValueError, OSError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Journey: {result['requests_sent']} GET requests -> {output}")


@app.command("security-inventory")
def security_inventory_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/security-inventory.json"), "--output", "-o"),
) -> None:
    """List OWASP API test opportunities from Swagger, without sending traffic.

    Useful before an engagement to see what can/cannot be tested and what
    identities, policies and fixtures will be required; not a vulnerability scan.
    """
    try:
        parsed = analyze_openapi_file(specification)
        inventory = security_inventory(parsed, load_openapi(specification))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OpenAPIParseError, OSError, ValueError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Indexed {len(inventory['operations'])} operations. Offline report: {output}")


@app.command("agent-review")
def agent_review_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    budget: int = typer.Option(3, "--budget", min=0, max=20),
    output: Path = typer.Option(Path("reports/agent-plan.json"), "--output", "-o"),
) -> None:
    """Create an auditable, non-executing agent plan from saved HTTP evidence.

    The report is treated as untrusted. Only known GET operations from the
    independently parsed Swagger can be candidates for future execution.
    """
    try:
        parsed = analyze_openapi_file(specification)
        data = json.loads(assessment.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("plan"), dict):
            raise ValueError("Assessment report has no OpenAPI plan")
        previous = data.get("execution_report") or {}
        if not isinstance(previous, dict) or not isinstance(previous.get("observations"), list):
            raise ValueError("Assessment report has no HTTP observations")
        # Only offline: using the original plan preserves operations that were
        # eligible with approved path values. choose_followups independently
        # rechecks every method/path against the freshly parsed OpenAPI.
        # No saved URL, token or body is ever executed by this command.
        plan = data["plan"]
        if not isinstance(plan.get("operations"), list):
            raise ValueError("Saved assessment has no operation inventory")
        result = choose_followups(parsed, plan, previous["observations"], budget=budget)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OpenAPIParseError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Agent candidates: {len(result['actions'])}. Offline report: {output}")


@app.command("report")
def report_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False, help="Previously saved auto-assess JSON."),
    output_dir: Path = typer.Option(Path("reports/professional"), "--output-dir"),
    format: list[str] = typer.Option([], "--format", help="Repeat json, md, html or pdf; default json/md/html."),
) -> None:
    """Export a sanitized professional report offline; does not send HTTP."""
    try:
        generated = write_professional_report(assessment, output_dir, tuple(format) if format else ("json", "md", "html"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    for file in generated:
        typer.echo(str(file))


@app.command("workflow-map")
def workflow_map_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/workflow-map.json"), "--output", "-o"),
) -> None:
    """Suggest offline producer/consumer links without running unsafe writes."""
    try:
        result = workflow_dependency_map(analyze_openapi_file(specification), load_openapi(specification))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError, OpenAPIParseError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Suggested {len(result['candidate_dependencies'])} unverified dependencies; no traffic sent. {output}")


@app.command("vulnerability-triage")
def vulnerability_triage_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/triage.json"), "--output", "-o"),
) -> None:
    """Identify review requirements from evidence already collected."""
    try:
        source = json.loads(assessment.read_text(encoding="utf-8"))
        result = vulnerability_triage(source)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Triage prepared for {result['candidate_count']} observations. {output}")


@app.command("ai-prioritize")
def ai_prioritize_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    budget: int = typer.Option(3, "--budget", min=0, max=20),
    with_ai: bool = typer.Option(False, "--ai", help="Optional Ollama advisory; never authorizes actions."),
    model: str = typer.Option("achilles-local", "--model"),
    output: Path = typer.Option(Path("reports/ai-priorities.json"), "--output", "-o"),
) -> None:
    """Prepare a strictly bounded follow-up queue and optional offline AI advice."""
    try:
        parsed = analyze_openapi_file(specification)
        source = json.loads(assessment.read_text(encoding="utf-8"))
        from achillesapi.core.assessment_context import prepare_assessment
        source = prepare_assessment(parsed, source)
        result = policy_gated_agent(parsed, source, budget=budget)
        result['source_note'] = ('Piano ricostruito offline dallo Swagger; nessuna risposta HTTP inventata.'
                                 if source.get('plan_reconstructed_from_openapi') else
                                 'Piano OpenAPI originale utilizzato.')
        result['http_observations_available'] = len(source['execution_report'].get('observations', []))
        # The adaptive agent selects only observed anomalies. A completed GET
        # with no anomalies correctly produces zero follow-up actions. For the
        # operator, also show a separate queue of untested GETs and prerequisites.
        from achillesapi.core.production_v031 import next_actions
        queue = next_actions(parsed, source, budget=budget)
        result['coverage_next_steps'] = queue['proposed_actions']
        result['coverage_next_steps_remaining'] = queue['remaining_actions']
        result['interpretation'] = (
            'Nessuna anomalia GET da ripetere: elenco separato delle verifiche non ancora coperte.'
            if not result.get('actions') else
            'Sono presenti anomalie GET da verificare con controlli mirati e autorizzati.'
        )
        if with_ai:
            from achillesapi.ai.intelligence import correlate_with_ollama
            execution = source.get("execution_report") or {}
            findings = execution.get("findings", []) if isinstance(execution, dict) else []
            result["local_ai_advice"] = correlate_with_ollama(parsed, {"findings": findings}, model=model)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError, TypeError, OpenAPIParseError, LocalAIError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Review queue: {len(result['actions'])} approved-type proposals; 0 target requests. {output}")


@app.command("scope-audit")
def scope_audit_command(
    base_url: str = typer.Argument(..., help="API base URL to verify offline."),
    allow_host: list[str] = typer.Option([], "--allow-host", help="Explicit hostname, repeatable."),
    allow_cidr: list[str] = typer.Option([], "--allow-cidr", help="Approved IP network, repeatable."),
    output: Path = typer.Option(Path("reports/scope-audit.json"), "--output", "-o"),
) -> None:
    """Check target URL and host scope offline; does not resolve DNS."""
    try:
        result = scope_audit(base_url, allow_host, allowed_cidrs=allow_cidr)
        save_json(output, result)
    except (AssessmentPolicyError, OSError, ValueError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Scope: {'APPROVED' if result['approved'] else 'BLOCKED'}; no requests sent. {output}")
    if not result["approved"]:
        raise typer.Exit(code=2)


@app.command("coverage-report")
def coverage_report_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/coverage.json"), "--output", "-o"),
) -> None:
    """Report which OpenAPI operations have real HTTP observations."""
    try:
        parsed = analyze_openapi_file(specification)
        source = json.loads(assessment.read_text(encoding="utf-8"))
        result = coverage_report(parsed, source)
        save_json(output, result)
    except (OSError, ValueError, TypeError, OpenAPIParseError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Observed operations: {result['observed_operations']}/{result['declared_operations']}; {output}")


@app.command("differential-review")
def differential_review_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/differential-review.json"), "--output", "-o"),
) -> None:
    """Prepare manual review of contradictory HTTP response classes, offline."""
    try:
        source = json.loads(assessment.read_text(encoding="utf-8"))
        result = differential_review(source)
        save_json(output, result)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Differential review candidates: {result['review_count']}; {output}")


@app.command("workflow-graph")
def workflow_graph_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/workflow-graph.json"), "--output", "-o"),
) -> None:
    """Validate a multi-resource dependency DAG without sending requests."""
    try:
        parsed = analyze_openapi_file(specification)
        result = workflow_graph(parsed, load_workflow_graph(config))
        save_json(output, result)
    except (OSError, ValueError, TypeError, AssessmentPolicyError, OpenAPIParseError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Validated {len(result['steps'])} workflow steps offline; writes not executed. {output}")


@app.command("benchmark-evaluate")
def benchmark_evaluate_command(
    ground_truth: Path = typer.Argument(..., exists=True, dir_okay=False),
    verified_results: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/benchmark.json"), "--output", "-o"),
) -> None:
    """Compute precision and recall against an independent labeled benchmark."""
    try:
        expected = json.loads(ground_truth.read_text(encoding="utf-8"))
        verified = json.loads(verified_results.read_text(encoding="utf-8"))
        result = benchmark_evaluate(expected, verified)
        save_json(output, result)
    except (AssessmentPolicyError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Verified benchmark TP={result['true_positives']} FP={result['false_positives']} FN={result['false_negatives']}; {output}")


@app.command("next-actions")
def next_actions_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    budget: int = typer.Option(5, "--budget", min=0, max=50),
    output: Path = typer.Option(Path("reports/next-actions.json"), "--output", "-o"),
) -> None:
    """Create a bounded offline queue of supported tests based on missing coverage."""
    try:
        parsed = analyze_openapi_file(specification)
        source = json.loads(assessment.read_text(encoding="utf-8"))
        from achillesapi.core.assessment_context import prepare_assessment
        source = prepare_assessment(parsed, source)
        result = next_actions(parsed, source, budget=budget)
        result['source_note'] = ('Inventario OpenAPI ricostruito; nessuna richiesta HTTP eseguita.'
                                 if source.get('plan_reconstructed_from_openapi') else
                                 'Usato il piano OpenAPI precedente.')
        save_json(output, result)
    except (OSError, ValueError, TypeError, OpenAPIParseError, AssessmentPolicyError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Candidate next actions: {len(result['proposed_actions'])}; 0 target requests. {output}")


@app.command("auto-assess")
def auto_assess_command(
    specification: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    base_url: str | None = typer.Option(None, "--base-url", help="Approved API origin or base path; inferred if one unambiguous server is in OpenAPI."),
    context: Path | None = typer.Option(None, "--context", exists=True, dir_okay=False, help="Optional real-API test IDs and access policy YAML."),
    workflow_config: Path | None = typer.Option(None, "--workflow-config", exists=True, dir_okay=False,
                                                help="Optional approved disposable object lifecycle YAML."),
    approve_writes: bool = typer.Option(False, "--approve-writes", help="Explicitly approve disposable POST/PATCH/DELETE in workflow mode."),
    multi_resource_config: Path | None = typer.Option(None, "--multi-resource-config", exists=True, dir_okay=False,
                    help="Operator-approved multi-resource fixture manifest; requires --approve-writes."),
    journey_config: Path | None = typer.Option(None, "--journey-config", exists=True, dir_okay=False,
                                              help="Optional read-only dataflow journey YAML."),
    adaptive_verify: bool = typer.Option(False, "--adaptive-verify", help="Repeat up to 3 observed 5xx GET baselines."),
    agent_budget: int = typer.Option(0, "--agent-budget", min=0, max=20,
                                     help="Bounded deterministic follow-ups for observed GET anomalies; 0 disables."),
    allow_host: list[str] = typer.Option(
        [], "--allow-host", help="Exact authorized hostname; required for execution."
    ),
    path_value: list[str] = typer.Option(
        [], "--path-value", help="Test path/query value NAME=VALUE; repeat as needed."
    ),
    auth_config: Path | None = typer.Option(None, "--auth-config", exists=True, dir_okay=False),
    profile: list[str] = typer.Option(
        [], "--profile", help="Identity profile name; repeat to compare accounts."
    ),
    execute: bool = typer.Option(
        False, "--execute", help="Perform eligible GET requests; default is offline dry-run."
    ),
    allow_insecure_http: bool = typer.Option(
        False, "--allow-insecure-http", help="Explicitly approve credential transfer over unencrypted HTTP."
    ),
    max_requests: int = typer.Option(20, "--max-requests", min=1, max=500),
    requests_per_second: float = typer.Option(1.0, "--rate", min=0.1, max=10.0),
    timeout: float = typer.Option(8.0, "--timeout", min=0.1, max=60.0),
    max_probes_per_endpoint: int = typer.Option(3, "--max-probes-per-endpoint", min=0, max=10),
    no_validation: bool = typer.Option(False, "--no-validation", help="Disable bounded query validation probes."),
    no_cors: bool = typer.Option(False, "--no-cors", help="Disable Origin reflection checks."),
    no_auth_checks: bool = typer.Option(False, "--no-auth-checks", help="Disable anonymous access checks."),
    with_ai: bool = typer.Option(False, "--ai", help="Ask local Ollama to review sanitized findings (advisory only)."),
    model: str = typer.Option("achilles-local", "--model", help="Locally installed Ollama model."),
    output: Path = typer.Option(Path("reports/auto-assessment.json"), "--output", "-o"),
) -> None:
    """Automatically select and run safe tests from a real API's OpenAPI spec.

    Without --execute: only creates the plan, no target traffic. With --execute:
    performs bounded GET baselines and appropriate authentication, input, CORS,
    header and error checks. Mutations are disabled unless a reviewed
    --workflow-config and explicit --approve-writes are also provided. An optional
    --context supplies test IDs and authorization expectations not in Swagger.
    """
    # LEGGI: un solo comando coordina Swagger, test, credenziali, scope e report.
    # SICUREZZA: Puo inviare richieste HTTP all'API; leggere le opzioni e autorizzare il target.
    try:
        if profile and not auth_config:
            raise AuthenticationConfigError("--profile requires --auth-config.")
        if len(set(profile)) != len(profile):
            raise AuthenticationConfigError("Profile names must be distinct.")
        details = read_context(context)
        values = {**details["path_values"], **_path_values(path_value)}
        parsed = analyze_openapi_file(specification)
        if not base_url:
            candidates = [server.get("url") for server in parsed.servers
                          if isinstance(server, dict) and isinstance(server.get("url"), str)
                          and server["url"].startswith(("http://", "https://"))
                          and "{" not in server["url"]]
            if len(candidates) != 1:
                raise ValueError("Provide --base-url: Swagger does not declare exactly one usable HTTP(S) server.")
            base_url = candidates[0]
        plan = build_generic_plan(parsed, base_url=base_url, path_values=values)
        if execute:
            from urllib.parse import urlsplit
            parts = urlsplit(base_url)
            approved = {host.lower().strip().rstrip(".") for host in allow_host}
            if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.hostname.lower().rstrip(".") not in approved
                or parts.username or parts.password or parts.query or parts.fragment):
                raise ScopeError("Base URL must be an in-scope HTTP(S) URL without credentials or query")
            if any(part in (".", "..") for part in parts.path.split("/")):
                raise ScopeError("Base URL must not contain traversal segments")
        identities = None
        if auth_config:
            manager = load_authentication_manager(auth_config)
            if not profile:
                profile = manager.names
            if not profile:
                raise AuthenticationConfigError("The authentication configuration has no profiles.")
            unknown = sorted(set(profile) - set(manager.names))
            if unknown:
                raise AuthenticationConfigError(f"Unknown profiles: {', '.join(unknown)}.")
        spec = load_openapi(specification)
        lifecycle = read_workflows(workflow_config) if workflow_config else []
        from achillesapi.core.multi_resource import load_multi_resource_config, plan_multi_resource, run_multi_resource
        multi_manifest = load_multi_resource_config(multi_resource_config) if multi_resource_config else None
        if multi_manifest and not auth_config:
            raise MultiResourceError('Multi-resource fixtures require --auth-config')
        multi_plan = plan_multi_resource(parsed,spec,multi_manifest,set(profile)) if multi_manifest else None
        lifecycle_plan = workflow_plan(parsed, spec, lifecycle, set(profile) if auth_config else None) if lifecycle else None
        journey = read_journey(journey_config) if journey_config else None
        journey_reserved = len(journey["steps"]) if journey else 0
        adaptive_reserved = 3 if adaptive_verify else 0
        agent_reserved = agent_budget
        reserved_requests = (lifecycle_plan["request_budget_required"] if lifecycle_plan else 0) + journey_reserved + adaptive_reserved + agent_reserved + (multi_plan['request_budget_required'] if multi_plan else 0)
        if multi_manifest and execute and not approve_writes:
            raise MultiResourceError('--approve-writes required for multi-resource fixtures')
        if lifecycle and execute and not approve_writes:
            raise WorkflowError("Use --approve-writes explicitly when --workflow-config and --execute are combined.")
        if lifecycle and execute and not auth_config:
            raise WorkflowError("Workflow execution requires --auth-config.")
        if execute and max_requests <= reserved_requests:
            raise WorkflowError("Increase --max-requests to cover read checks plus reserved workflow cleanup requests.")
        # Resolve real credentials only after offline workflow and budget
        # preflights pass, so blocked scans never contact the auth endpoint.
        if auth_config and execute:
            identities = {name: manager.resolve(name, allowed_hosts=set(allow_host),
                          allow_insecure_http=allow_insecure_http) for name in profile}
        test_plan = generate_test_plan(parsed, spec)
        passive_findings = assessment_to_dict(assess_api(parsed))
        from achillesapi.core.campaign_rc9 import campaign_plan_rc9, verification_summary_rc9
        result: dict[str, object] = {
            "rc9_campaign_plan": campaign_plan_rc9(spec, profiles=profile,
                approved_fixture=bool(multi_manifest or lifecycle), authorized_scope=execute),
            "tool": "AchillesAPI",
            "version": __version__,
            "plan": plan,
            "adaptive_check_plan": describe_smart_checks(parsed, plan),
            "intelligent_plan": intelligent_plan(parsed, spec),
            "security_inventory": security_inventory(parsed, spec),
            "workflow_dependency_map": workflow_dependency_map(parsed, spec),
            "agent_plan": None,
            "agent_execution": None,
            "suggested_security_tests": test_plan,
            "passive_assessment": passive_findings,
            "execution_report": None,
            "selected_profiles": list(profile),
            "workflow_plan": lifecycle_plan,
            "multi_resource_plan": ({k:v for k,v in multi_plan.items() if k != '_prepared'} if multi_plan else None),
            "multi_resource_execution": None,
            "workflow_execution": None,
            "journey_plan": run_journey(parsed, journey, base_url=base_url, allowed_hosts=set(allow_host),
                                        execute=False) if journey else None,
            "journey_execution": None,
            "adaptive_verification": None,
            "authentication_requests": manager.auth_requests_made if auth_config else 0,
        }
        if not execute and agent_budget:
            result["agent_plan"] = {"engine": "bounded-agent-v0.23", "budget": agent_budget,
                                    "actions": [], "note": "No HTTP observations in dry-run; no requests sent."}
        if execute:
            if not allow_host:
                raise ScopeError("Explicit --allow-host required with --execute.")
            result["execution_report"] = run_smart_assessment(
                parsed, plan,
                base_url=base_url,
                allowed_hosts=set(allow_host),
                identities=identities,
                path_values=values,
                expected_access=details["expected_access"],
                specification=spec,
                settings=ScanSettings(
                    max_requests=max_requests - reserved_requests,
                    rate=requests_per_second,
                    timeout=timeout,
                    max_probes_per_endpoint=max_probes_per_endpoint,
                    check_cors=not no_cors,
                    check_input_validation=not no_validation,
                    check_authentication=not no_auth_checks,
                    allow_insecure_http=allow_insecure_http,
                ),
            )
            if auth_config:
                result["authentication_requests"] = manager.auth_requests_made
            result["adaptive_followups"] = adaptive_queue(result["intelligent_plan"], result["execution_report"].get("observations", []))
            if agent_budget:
                result["agent_plan"] = choose_followups(
                    parsed, plan, result["execution_report"].get("observations", []), budget=agent_budget)
                result["agent_execution"] = run_followups(
                    parsed, plan, result["execution_report"].get("observations", []),
                    base_url=base_url, allowed_hosts=set(allow_host), identities=identities,
                    path_values=values, budget=agent_budget, rate=requests_per_second,
                    timeout=timeout, allow_insecure_http=allow_insecure_http, execute=True)
            if adaptive_verify:
                result["adaptive_verification"] = verify_server_errors(
                    parsed, plan, result["execution_report"].get("observations", []),
                    base_url=base_url, allowed_hosts=set(allow_host), identities=identities,
                    path_values=values, budget=adaptive_reserved,
                    rate=requests_per_second, timeout=timeout)
            result["plan"]["execution"]["executed"] = True
            result["plan"]["execution"]["requests_sent"] = result["execution_report"]["requests_sent"]
            if result["agent_execution"]:
                result["plan"]["execution"]["requests_sent"] += result["agent_execution"]["network_requests_sent"]
            if result["adaptive_verification"]:
                result["plan"]["execution"]["requests_sent"] += result["adaptive_verification"]["requests_sent"]
            if journey:
                result["journey_execution"] = run_journey(
                    parsed, journey, base_url=base_url, allowed_hosts=set(allow_host),
                    manager=manager if auth_config else None, execute=True,
                    max_requests=journey_reserved, rate=requests_per_second,
                    allow_insecure_http=allow_insecure_http)
                result["plan"]["execution"]["requests_sent"] += result["journey_execution"]["requests_sent"]
            if multi_manifest:
                result['multi_resource_execution'] = run_multi_resource(
                    parsed,spec,multi_manifest,base_url=base_url,
                    allowed_hosts=set(allow_host),identities=identities or {},
                    execute=True,approve_writes=True,allow_insecure_http=allow_insecure_http,
                    max_requests=multi_plan['request_budget_required'],rate=requests_per_second,timeout=timeout)
                result['plan']['execution']['requests_sent'] += result['multi_resource_execution']['requests_sent']
            if lifecycle:
                result["workflow_execution"] = run_workflows(
                    parsed, spec, lifecycle, base_url=base_url,
                    allowed_hosts=set(allow_host), identities=identities or {},
                    execute=True, approve_writes=True,
                    allow_insecure_http=allow_insecure_http,
                    max_requests=lifecycle_plan["request_budget_required"], rate=requests_per_second,
                    timeout=timeout,
                )
                result["plan"]["execution"]["requests_sent"] += result["workflow_execution"]["requests_sent"]
        if execute and auth_config:
            result["authentication_requests"] = manager.auth_requests_made
        result["vulnerability_triage"] = vulnerability_triage(result)
        result["rc9_verification_summary"] = verification_summary_rc9(result)
        if with_ai:
            # Only a sanitized advisory summary reaches local Ollama. AI does
            # not choose requests, authorize scope or confirm vulnerabilities.
            result["ai_advisory"] = correlate_with_ollama(
                parsed,
                {"findings": (
                    (result["execution_report"]["findings"] if execute else [])
                    + [finding for entry in ((result["workflow_execution"] or {}).get("workflows", []))
                       for finding in entry.get("findings", [])]
                )},
                model=model,
            )
        # The report deliberately omits tokens, cookies and response bodies.
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except (
        AuthenticationConfigError, AdvancedCheckError, OpenAPIParseError,
        ScopeError, RequestBudgetExceeded, ContextError, WorkflowError, MultiResourceError, JourneyError, LocalAIError, ValueError, OSError
    ) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    summary = plan["summary"]
    typer.echo(
        f"API operations: {parsed.endpoint_count} | eligible GET: {summary['get_candidates']} | "
        f"missing inputs: {summary['blocked_missing_inputs']} | "
        f"manual-only: {summary['manual_only']}"
    )
    typer.echo(
        f"Requests sent: {result['plan']['execution']['requests_sent'] if execute else 0}. "
        f"Report: {output}"
    )
    if execute and result["workflow_execution"] and result["workflow_execution"]["manual_cleanup_required"]:
        typer.echo("WARNING: Resource cleanup could not be verified; manual cleanup required.", err=True)
        raise typer.Exit(code=2)


@app.command('multi-resource-assess')
def multi_resource_assess_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    config: Path = typer.Option(..., '--config', exists=True, dir_okay=False),
    base_url: str = typer.Option(..., '--base-url'),
    auth_config: Path = typer.Option(..., '--auth-config', exists=True, dir_okay=False),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    execute: bool = typer.Option(False, '--execute'),
    approve_writes: bool = typer.Option(False, '--approve-writes'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http'),
    max_requests: int = typer.Option(80, '--max-requests', min=1, max=500),
    rate: float = typer.Option(1.0, '--rate', min=0.1, max=10.0),
    output: Path = typer.Option(Path('reports/multi-resource.json'), '--output', '-o'),
) -> None:
    """Execute an explicitly approved multi-resource fixture with reverse cleanup."""
    from achillesapi.core.multi_resource import (MultiResourceError, load_multi_resource_config,
                                                 run_multi_resource, plan_multi_resource)
    try:
        parsed = analyze_openapi_file(specification)
        spec = load_openapi(specification)
        manifest = load_multi_resource_config(config)
        manager = load_authentication_manager(auth_config)
        plan = plan_multi_resource(parsed, spec, manifest, set(manager.names))
        if execute:
            # Scope/authorization and request-budget preflight precede token resolution.
            from achillesapi.core.production_v031 import scope_audit
            if not approve_writes or not scope_audit(base_url,allow_host)['approved']:
                raise ScopeError('Write approval and valid scope are required')
            if max_requests < plan['request_budget_required']:
                raise ScopeError('Request budget too small for safe cleanup')
            if base_url.startswith('http://') and not allow_insecure_http:
                raise ScopeError('Refusing credentials over HTTP')
            profiles = {r['config']['identity'] for r in plan['_prepared']}
            for r in plan['_prepared']:
                profiles.update(a['identity'] for a in r['config'].get('access', []))
            identities = {name: manager.resolve(name,allowed_hosts=set(allow_host),
                           allow_insecure_http=allow_insecure_http) for name in profiles}
        else:
            identities = {name: AuthenticationMaterial() for name in manager.names}
        result = run_multi_resource(parsed,spec,manifest,base_url=base_url,
                                    allowed_hosts=set(allow_host),identities=identities,
                                    execute=execute,approve_writes=approve_writes,
                                    allow_insecure_http=allow_insecure_http,
                                    max_requests=max_requests,rate=rate)
        save_json(output, result)
    except (MultiResourceError, ScopeError, AuthenticationConfigError, OpenAPIParseError,
            ValueError, OSError) as exc:
        typer.echo(f'Blocked: {exc}',err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f'Multi-resource: {result["requests_sent"]} requests; {output}')


@app.command('advanced-vuln-assess')
def advanced_vuln_assess_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    assessment: Path | None = typer.Option(None, '--assessment',exists=True,dir_okay=False),
    base_url: str | None = typer.Option(None,'--base-url'),
    allow_host: list[str] = typer.Option([],'--allow-host'),
    auth_config: Path | None = typer.Option(None,'--auth-config',exists=True,dir_okay=False),
    profile: list[str] = typer.Option([],'--profile'),
    path_value: list[str] = typer.Option([],'--path-value'),
    max_requests: int = typer.Option(40,'--max-requests',min=1,max=200),
    rate: float = typer.Option(1.0,'--rate',min=0.1,max=10.0),
    execute: bool = typer.Option(False,'--execute'),
    allow_insecure_http: bool = typer.Option(False,'--allow-insecure-http'),
    output: Path = typer.Option(Path('reports/advanced-vulnerability.json'), '--output','-o'),
) -> None:
    """Run bounded GET security checks and evidence triage; no injection exploitation."""
    from achillesapi.core.vulnerability_engine import vulnerability_test_plan, vulnerability_evidence_review
    try:
        parsed = analyze_openapi_file(specification)
        result = {'plan':vulnerability_test_plan(parsed),'requests_sent':0}
        saved = json.loads(assessment.read_text(encoding='utf-8')) if assessment else None
        if execute:
            if not base_url or not scope_audit(base_url,allow_host)['approved']:
                raise ScopeError('Explicit in-scope --base-url and --allow-host required')
            if profile and not auth_config:
                raise AuthenticationConfigError('Profiles require --auth-config')
            if base_url.startswith('http://') and auth_config and not allow_insecure_http:
                raise ScopeError('Credentials over HTTP require explicit approval')
            manager = load_authentication_manager(auth_config) if auth_config else None
            selected = profile or (manager.names if manager else [])
            if manager and set(selected) - set(manager.names):
                raise AuthenticationConfigError('Unknown profile names')
            values = _path_values(path_value)
            generic_plan = build_generic_plan(parsed,base_url=base_url,path_values=values)
            identities = {name:manager.resolve(name,allowed_hosts=set(allow_host),
                          allow_insecure_http=allow_insecure_http) for name in selected} if manager else None
            raw = run_smart_assessment(parsed,generic_plan,base_url=base_url,
                        allowed_hosts=set(allow_host), identities=identities,path_values=values,
                        specification=load_openapi(specification),
                        settings=ScanSettings(max_requests=max_requests,rate=rate,
                                              allow_insecure_http=allow_insecure_http))
            saved = {'plan':generic_plan,'execution_report':raw}
            result['execution_report'] = raw
            result['requests_sent'] = raw['requests_sent']
        if saved is not None:
            result['evidence_review'] = vulnerability_evidence_review(parsed,saved)
        save_json(output,result)
    except (OSError, ValueError, ScopeError, AuthenticationConfigError, OpenAPIParseError) as exc:
        typer.echo(f'Blocked: {exc}',err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f'Advanced vulnerability checks: {result["requests_sent"]} requests; {output}')


@app.command('autonomous-agent')
def autonomous_agent_command(
    specification: Path = typer.Argument(...,exists=True,dir_okay=False),
    assessment: Path = typer.Argument(...,exists=True,dir_okay=False),
    budget: int = typer.Option(5,'--budget',min=0,max=20),
    base_url: str | None = typer.Option(None,'--base-url'),
    allow_host: list[str] = typer.Option([],'--allow-host'),
    auth_config: Path | None = typer.Option(None,'--auth-config',exists=True,dir_okay=False),
    profile: list[str] = typer.Option([],'--profile'),
    path_value: list[str] = typer.Option([],'--path-value'),
    execute: bool = typer.Option(False,'--execute'),
    allow_insecure_http: bool = typer.Option(False,'--allow-insecure-http'),
    with_ai: bool = typer.Option(False,'--ai'),
    model: str = typer.Option('achilles-local','--model'),
    output: Path = typer.Option(Path('reports/agent-cycle.json'),'--output','-o'),
) -> None:
    """Plan and optionally execute bounded GET follow-ups; Ollama is advisory."""
    from achillesapi.core.agent_v034 import agent_cycle_review
    try:
        parsed = analyze_openapi_file(specification)
        saved = json.loads(assessment.read_text(encoding='utf-8'))
        if not isinstance(saved,dict):
            raise ValueError('Assessment must be a JSON object')
        from achillesapi.core.assessment_context import prepare_assessment
        saved = prepare_assessment(parsed, saved)
        result = agent_cycle_review(parsed,saved,budget=budget)
        result['http_observations_available'] = len(saved['execution_report'].get('observations', []))
        result['source_note'] = ('Piano ricostruito dal contratto OpenAPI; nessun traffico simulato.'
                                 if saved.get('plan_reconstructed_from_openapi') else 'Piano precedente verificato.')
        if execute:
            if not base_url or not allow_host:
                raise ScopeError('Explicit --base-url and --allow-host required for agent traffic')
            if not scope_audit(base_url,allow_host)['approved']:
                raise ScopeError('Agent target outside approved scope')
            manager = load_authentication_manager(auth_config) if auth_config else None
            if profile and not manager:
                raise AuthenticationConfigError('Profiles require --auth-config')
            selected = profile or (manager.names if manager else [])
            if manager and set(selected) - set(manager.names):
                raise AuthenticationConfigError('Unknown auth profile')
            if base_url.startswith('http://') and manager and not allow_insecure_http:
                raise ScopeError('Credentials over HTTP require --allow-insecure-http')
            identities = {name:manager.resolve(name,allowed_hosts=set(allow_host),
                         allow_insecure_http=allow_insecure_http) for name in selected} if manager else None
            values = _path_values(path_value)
            plan = build_generic_plan(parsed,base_url=base_url,path_values=values)
            observations = (saved.get('execution_report') or {}).get('observations', [])
            if not isinstance(observations,list):
                raise ValueError('Missing valid saved execution observations')
            # The executor ignores model-supplied targets and reconstructs
            # every supported follow-up from this OpenAPI + approved scope.
            result['execution'] = run_followups(parsed,plan,observations,
                base_url=base_url,allowed_hosts=set(allow_host),identities=identities,
                path_values=values,budget=budget,allow_insecure_http=allow_insecure_http,
                execute=True)
            result['requests_sent'] = result['execution']['network_requests_sent']
        if with_ai:
            evidence = (saved.get('execution_report') or {}).get('findings', [])
            result['ai_advisory'] = correlate_with_ollama(parsed,{'findings':evidence},model=model)
        save_json(output,result)
    except (OSError,ValueError,ScopeError,AssessmentPolicyError,OpenAPIParseError,
            AuthenticationConfigError,LocalAIError) as exc:
        typer.echo(f'Blocked: {exc}',err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f'Agent cycle: {result["requests_sent"]} target requests; {output}')



@app.command('dashboard')
def dashboard_command(
    port: int = typer.Option(8766, '--port', min=1024, max=65535),
    workspace: Path = typer.Option(Path('dashboard-data'), '--workspace'),
) -> None:
    """Start the interactive local browser dashboard, bound only to 127.0.0.1.

    Authentication secrets are read from environment variables on this host;
    no network-exposed dashboard mode is provided.
    """
    try:
        from achillesapi.dashboard.server import launch_dashboard
    except ImportError as exc:
        typer.echo('Dashboard dependencies missing. Run: uv sync --extra dashboard',err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f'Local control center: http://127.0.0.1:{port}')
    launch_dashboard(workspace=str(workspace),port=port)


@app.command('verify-access-policy')
def verify_access_policy_command(
    assessment: Path = typer.Argument(...,exists=True,dir_okay=False),
    rules: Path = typer.Argument(...,exists=True,dir_okay=False),
    output: Path = typer.Option(Path('reports/access-verification.json'),'--output','-o'),
) -> None:
    """Evaluate documented access rules against observed statuses, entirely offline."""
    from achillesapi.core.verification_v037 import verify_access_policies
    import yaml
    try:
        assessment_data=json.loads(assessment.read_text(encoding='utf-8'))
        rules_data=yaml.safe_load(rules.read_text(encoding='utf-8'))
        if isinstance(rules_data,dict):rules_data=rules_data.get('rules')
        data=verify_access_policies(assessment_data,rules_data)
        save_json(output,data)
    except (OSError,ValueError) as exc:
        typer.echo(f'Blocked: {exc}',err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f'Policy review candidates: {data["review_count"]}; {output}')


@app.command('agent-loop-v2')
def agent_loop_v2_command(
    specification: Path = typer.Argument(...,exists=True,dir_okay=False),
    assessment: Path = typer.Argument(...,exists=True,dir_okay=False),
    base_url: str | None = typer.Option(None,'--base-url'),
    allow_host: list[str] = typer.Option([],'--allow-host'),
    auth_config: Path | None = typer.Option(None,'--auth-config',exists=True,dir_okay=False),
    profile: list[str] = typer.Option([],'--profile'),
    path_value: list[str] = typer.Option([],'--path-value'),
    budget: int = typer.Option(5,'--budget',min=0,max=20),
    rate: float = typer.Option(1.,'--rate',min=0.1,max=10.),
    execute: bool = typer.Option(False,'--execute'),
    allow_insecure_http: bool = typer.Option(False,'--allow-insecure-http'),
    with_ai: bool = typer.Option(False,'--ai',help='Optional Ollama local advisory; cannot authorize actions'),
    model: str = typer.Option('achilles-local','--model'),
    output: Path = typer.Option(Path('reports/agent-v2.json'),'--output','-o'),
) -> None:
    """Run at most two bounded GET follow-up rounds; no model-authored attacks."""
    from achillesapi.core.agent_v037 import agent_v2_execute
    try:
        parsed=analyze_openapi_file(specification)
        saved=json.loads(assessment.read_text(encoding='utf-8'))
        if not isinstance(saved,dict):raise ValueError('Assessment must be JSON object')
        observations=(saved.get('execution_report') or {}).get('observations',[])
        if not isinstance(observations,list):raise ValueError('Execution observations missing')
        values=_path_values(path_value)
        plan=build_generic_plan(parsed,base_url=base_url,path_values=values)
        identities=None
        if execute:
            if not base_url or not scope_audit(base_url,allow_host)['approved']:
                raise ScopeError('Exact target and approved host required')
            if profile and not auth_config:
                raise AuthenticationConfigError('Profiles require --auth-config')
            if base_url.startswith('http://') and auth_config and not allow_insecure_http:
                raise ScopeError('Credentialed HTTP not approved')
            manager=load_authentication_manager(auth_config) if auth_config else None
            selected=profile or (manager.names if manager else [])
            if manager and set(selected)-set(manager.names):
                raise AuthenticationConfigError('Unknown profile')
            identities={name:manager.resolve(name,allowed_hosts=set(allow_host),
                allow_insecure_http=allow_insecure_http) for name in selected} if manager else None
        result=agent_v2_execute(parsed,plan,observations,base_url=base_url or '',
            allowed_hosts=set(allow_host),identities=identities,path_values=values,
            budget=budget,rate=rate,execute=execute,allow_insecure_http=allow_insecure_http)
        if with_ai:
            # The model sees only action metadata, never credentials or raw responses.
            result['ai_advisory']=correlate_with_ollama(parsed,{'findings':[
                {'category':'bounded_get_followup','operation':a['operation'],
                 'reason':a['reason']} for a in result.get('actions',[])]},model=model)
        save_json(output,result)
    except (OSError,ValueError,ScopeError,OpenAPIParseError,AuthenticationConfigError,LocalAIError) as exc:
        typer.echo(f'Blocked: {exc}',err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f'Agent v2: {result["requests_sent"]} GET follow-ups; {output}')



@app.command("compatibility-report")
def compatibility_report_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/compatibility.json"), "--output", "-o"),
) -> None:
    """Offline operation-by-operation capability and evidence coverage preflight."""
    from achillesapi.core.compatibility_v080 import from_file
    result = from_file(str(specification))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    typer.echo(f"{result['summary']['operations']} operazioni analizzate, nessuna richiesta HTTP. {output}")


@app.command("workflow-infer")
def workflow_infer_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/workflow-proposals.json"), "--output", "-o"),
) -> None:
    """Infer non-executable CRUD candidates from an OpenAPI specification."""
    from achillesapi.core.workflow_inference_v080 import infer_workflows
    result = infer_workflows(load_openapi(specification))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    typer.echo(f"{result['summary']['candidates']} workflow candidati. Nessuna scrittura eseguita. {output}")


@app.command("verify-findings")
def verify_findings_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/verified-indicators.json"), "--output", "-o"),
) -> None:
    """Conservative, offline evidence grouping; findings remain unconfirmed."""
    from achillesapi.core.verification_v080 import classify_findings
    result = classify_findings(json.loads(assessment.read_text(encoding="utf-8")))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    typer.echo(f"{result['summary']['deduplicated_groups']} gruppi di indicatori da rivedere. {output}")


@app.command("adaptive-plan")
def adaptive_plan_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/adaptive-plan.json"), "--output", "-o"),
    ai: bool = typer.Option(False, "--ai", help="Optional *advisory only* local Ollama analysis."),
    model: str = typer.Option("achilles-local", "--model"),
) -> None:
    """Create allowlisted follow-up suggestions; never execute proposed actions."""
    from achillesapi.core.compatibility_v080 import from_file
    from achillesapi.core.ai_planner_v080 import deterministic_next_steps
    coverage = from_file(str(specification))
    result = deterministic_next_steps(coverage, ai_available=ai)
    if ai:
        from achillesapi.ai.local import analyze_with_ollama
        result['local_ai_advice'] = analyze_with_ollama(
            parse_openapi(load_openapi(specification)), [], model=model)
        from achillesapi.core.ai_planner_v080 import validate_model_suggestions
        result['allowlisted_ai_command_names'] = validate_model_suggestions(
            result['local_ai_advice'].get('recommended_tests', []))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    typer.echo(f"{len(result['suggested_actions'])} suggerimenti, nessun comando eseguito. {output}")


@app.command("auth-preflight")
def auth_preflight_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    auth_config: Path | None = typer.Option(None, "--auth-config", exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/auth-readiness.json"), "--output", "-o"),
) -> None:
    """Compare OpenAPI security schemes to configured profile types without leaking secrets."""
    from achillesapi.core.auth_readiness_v080 import auth_readiness
    result=auth_readiness(load_openapi(specification),str(auth_config) if auth_config else None)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False,indent=2),encoding='utf-8')
    typer.echo(f"{len(result['schemes'])} schemi auth rilevati. Nessun token restituito. {output}")


@app.command("security-surfaces")
def security_surfaces_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/security-surfaces.json"), "--output", "-o"),
) -> None:
    """Generate safe API security review candidates from OpenAPI structure."""
    from achillesapi.core.security_surfaces_v080 import security_surfaces
    result=security_surfaces(load_openapi(specification))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    typer.echo(f"{result['summary']['candidates']} superfici da rivedere. Nessun test attivo eseguito. {output}")



# v0.90: questi comandi sono analisi OFFLINE. Non aprono connessioni al target.
@app.command("campaign-preflight")
def campaign_preflight_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/campaign-preflight.json"), "--output", "-o"),
) -> None:
    """Controlla in anticipo quali task sono applicabili e cosa manca."""
    from achillesapi.core.campaign_v090 import campaign_preflight
    from achillesapi.core.registry_v090 import TOOLS, SUITE_ORDER
    result = campaign_preflight(load_openapi(specification), TOOLS, SUITE_ORDER)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    typer.echo(f"{result['summary']['total']} task valutati; nessuna richiesta HTTP. {output}")


@app.command("workflow-dependencies")
def workflow_dependencies_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/dependencies.json"), "--output", "-o"),
) -> None:
    """Ricava le possibili dipendenze fra endpoint senza creare risorse."""
    from achillesapi.core.workflow_dependencies_v090 import infer_dependencies
    result = infer_dependencies(load_openapi(specification))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    typer.echo(f"{result['summary']['candidate_relations']} relazioni ipotizzate. {output}")


@app.command("auth-audit")
def auth_audit_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    auth_config: Path | None = typer.Option(None, "--auth-config", exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/auth-audit.json"), "--output", "-o"),
) -> None:
    """Confronta profili e schemi OpenAPI senza stampare credenziali."""
    from achillesapi.core.auth_audit_v090 import audit_auth
    result = audit_auth(load_openapi(specification), str(auth_config) if auth_config else None)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    typer.echo(f"{result['summary']['configuration_gaps']} lacune di configurazione. {output}")


@app.command("verification-review")
def verification_review_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/verification-review.json"), "--output", "-o"),
) -> None:
    """Organizza le osservazioni senza dichiarare vulnerabilità confermate."""
    from achillesapi.core.verification_v090 import review_assessment
    result = review_assessment(json.loads(assessment.read_text(encoding="utf-8")))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    typer.echo(f"{result['summary']['deduplicated_groups']} gruppi da verificare. {output}")


@app.command("campaign-quality")
def campaign_quality_command(
    report: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/campaign-quality.json"), "--output", "-o"),
) -> None:
    """Valuta la qualità dell'esecuzione senza nascondere controlli saltati."""
    from achillesapi.core.quality_v090 import assess_campaign_quality
    result = assess_campaign_quality(json.loads(report.read_text(encoding="utf-8")))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    typer.echo(f"Stato qualità: {result['state']}. {output}")


@app.command("risk-matrix")
def risk_matrix_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports/risk-matrix.json"), "--output", "-o"),
) -> None:
    """Suggerisce controlli OWASP API, senza attribuire vulnerabilità confermate."""
    from achillesapi.core.risk_matrix_v090 import build_risk_matrix
    result = build_risk_matrix(load_openapi(specification))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    typer.echo(f"{result['summary']['candidate_tests']} controlli suggeriti. {output}")

# ---------------------------------------------------------------------------
# v0.91 - v0.99: comandi offline per controlli, evidenze e release readiness.
# Ogni comando legge un file locale e produce JSON; nessuno invia traffico.
# ---------------------------------------------------------------------------

def _write_v099(payload: dict, output: Path) -> None:
    """Scrive il risultato in modo coerente senza esporre dati in console."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    typer.echo(f"Report creato: {output}")


def _read_v099(source: Path) -> dict:
    """Legge un file JSON locale, limitando dimensione e tipo dell'input."""
    if source.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('File troppo grande: massimo 8 MiB.')
    text = source.read_text(encoding='utf-8')
    # Un file generato dalla dashboard puo avere estensione .yaml anche se contiene JSON.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        import yaml
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError('Il documento deve contenere un oggetto JSON.')
    return data


@app.command('access-evidence-review')
def access_evidence_review_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/access-evidence.json'), '--output', '-o'),
) -> None:
    """Confronta evidenze multiutente gia raccolte, senza richiedere rete."""
    from achillesapi.core.access_review_v099 import review_access_evidence
    try:
        _write_v099(review_access_evidence(_read_v099(assessment)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('mutation-review')
def mutation_review_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/mutation-review.json'), '--output', '-o'),
) -> None:
    """Confronta snapshot prima/dopo, senza inviare PATCH o POST."""
    from achillesapi.core.mutation_review_v099 import review_mutations
    try:
        _write_v099(review_mutations(_read_v099(assessment)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('workflow-safety')
def workflow_safety_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/workflow-safety.json'), '--output', '-o'),
) -> None:
    """Propone workflow e segnala la mancanza di cleanup prima di scritture."""
    from achillesapi.core.workflow_safety_v099 import review_workflow_safety
    try:
        _write_v099(review_workflow_safety(load_openapi(specification)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('evidence-package')
def evidence_package_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/evidence-index.json'), '--output', '-o'),
) -> None:
    """Esporta impronte e categorie, non valori HTTP o segreti."""
    from achillesapi.core.evidence_package_v099 import build_evidence_package
    try:
        _write_v099(build_evidence_package(_read_v099(assessment)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('campaign-diagnostics')
def campaign_diagnostics_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/campaign-diagnostics.json'), '--output', '-o'),
) -> None:
    """Mostra errori, task non eseguiti e limiti della campagna."""
    from achillesapi.core.release_quality_v099 import diagnose_campaign
    try:
        _write_v099(diagnose_campaign(_read_v099(assessment)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('release-readiness')
def release_readiness_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/release-readiness.json'), '--output', '-o'),
) -> None:
    """Controlla prerequisiti di qualita, senza certificare la sicurezza."""
    from achillesapi.core.release_quality_v099 import assess_release_readiness
    try:
        _write_v099(assess_release_readiness(_read_v099(assessment)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('benchmark-review')
def benchmark_review_command(
    truth: Path = typer.Argument(..., exists=True, dir_okay=False),
    observed: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/benchmark-review.json'), '--output', '-o'),
) -> None:
    """Calcola precision, recall e F1 usando etichette indipendenti."""
    from achillesapi.core.benchmark_review_v099 import compare_ground_truth
    try:
        _write_v099(compare_ground_truth(_read_v099(truth), _read_v099(observed)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('benchmark-corpus')
def benchmark_corpus_command(
    specifications: Path = typer.Argument(..., exists=True, file_okay=False),
    output: Path = typer.Option(Path('reports/benchmark-corpus.json'), '--output', '-o'),
) -> None:
    """Esegue il planner offline su un insieme di Swagger indipendenti."""
    from achillesapi.core.independent_validation_v099 import validate_specification_corpus
    try:
        _write_v099(validate_specification_corpus(specifications), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('ai-plan-guard')
def ai_plan_guard_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    proposals: Path = typer.Option(..., '--proposals', exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/ai-plan-guard.json'), '--output', '-o'),
) -> None:
    """Filtra proposte Ollama usando soltanto comandi e operazioni consentiti."""
    from achillesapi.core.ai_guard_v099 import validate_advisory_plan
    try:
        _write_v099(validate_advisory_plan(load_openapi(specification), _read_v099(proposals)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Input non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('injection-assess')
def injection_assess_rc5(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    base_url: str = typer.Option(..., '--base-url'),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    auth_config: Path | None = typer.Option(None, '--auth-config', exists=True, dir_okay=False),
    profile: list[str] = typer.Option([], '--profile'),
    path_value: list[str] = typer.Option([], '--path-value'),
    families: str = typer.Option('sql_error,sql_boolean,nosql,ssti,command,xpath,ldap,crlf', '--families'),
    execute: bool = typer.Option(False, '--execute'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http'),
    max_requests: int = typer.Option(40, '--max-requests', min=1, max=150),
    rate: float = typer.Option(1.0, '--rate', min=0.1, max=5.0),
    output: Path = typer.Option(Path('reports/injection-assess.json'), '--output', '-o'),
) -> None:
    """Sonda parametri GET: solo target autorizzati e nessuna scrittura."""
    from achillesapi.core.injection_engine_rc5 import injection_assessment, InjectionConfigurationError
    from achillesapi.core.production_v031 import scope_audit
    try:
        if execute and not scope_audit(base_url, allow_host)['approved']:
            raise ScopeError('Base URL non compreso nello scope autorizzato')
        values = {}
        for item in path_value:
            if '=' not in item:
                raise InjectionConfigurationError('I parametri path usano NOME=VALORE')
            key, value = item.split('=', 1)
            if not key or key in values:
                raise InjectionConfigurationError('Parametro path mancante o duplicato')
            values[key] = value
        if len(profile) > 1:
            raise InjectionConfigurationError('Injection-assess accepts one --profile per scan; choose one identity or launch separate scans.')
        manager = load_authentication_manager(auth_config) if auth_config else None
        report = injection_assessment(
            specification, base_url=base_url, allow_hosts=set(allow_host),
            path_values=values, auth_manager=manager, profile=profile[0] if profile else None,
            execute=execute, allow_insecure_http=allow_insecure_http,
            max_requests=max_requests, rate=rate,
            families=tuple(x.strip() for x in families.split(',') if x.strip()),
        )
        save_json(output, report)
    except (ScopeError, InjectionConfigurationError, AuthenticationConfigError,
            RequestBudgetExceeded, OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo('Injection assessment bloccato: '+str(exc)[:180], err=True)
        raise typer.Exit(1) from exc
    typer.echo('Injection assessment: '+str(report['summary'])+'; report: '+str(output))


@app.command('rc15-scan')
def rc15_scan_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    base_url: str = typer.Option(..., '--base-url'),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    auth_config: Path | None = typer.Option(None, '--auth-config', exists=True, dir_okay=False),
    profile: str | None = typer.Option(None, '--profile'),
    fixture_config: Path | None = typer.Option(None, '--fixture-config', exists=True, dir_okay=False),
    path_value: list[str] = typer.Option([], '--path-value'),
    families: str = typer.Option('sql_error,sql_boolean,nosql,ssti,command,xpath,ldap,crlf,xss,path_traversal,open_redirect,ssrf,xxe,file_upload', '--families'),
    execute: bool = typer.Option(False, '--execute'),
    approve_writes: bool = typer.Option(False, '--approve-writes'),
    approve_xml_oast: bool = typer.Option(False, '--approve-xml-oast'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http'),
    callback_base: str | None = typer.Option(None, '--callback-base'),
    callback_observer: str | None = typer.Option(None, '--callback-observer'),
    fixture_file: str | None = typer.Option(None, '--fixture-file'),
    fixture_marker: str | None = typer.Option(None, '--fixture-marker'),
    max_requests: int = typer.Option(45, '--max-requests', min=1, max=500),
    max_cases: int = typer.Option(150, '--max-cases', min=1, max=500),
    rate: float = typer.Option(2.0, '--rate', min=.1, max=5.),
    output: Path = typer.Option(Path('reports/rc15-security.json'), '--output', '-o'),
) -> None:
    """RC15: scanner active multi-context; writes only with approved disposable fixtures."""
    from achillesapi.core.rc15_security import scan_rc15, read_fixtures, RC15Error
    from achillesapi.core.production_v031 import scope_audit
    try:
        if execute and not scope_audit(base_url, allow_host)['approved']:
            raise RC15Error('Target outside the allowed scope')
        if execute and base_url.startswith('http://') and not allow_insecure_http:
            raise RC15Error('Plaintext HTTP requires --allow-insecure-http')
        if approve_writes and not execute:
            raise RC15Error('Write approval requires --execute')
        if execute and fixture_config and not approve_writes:
            raise RC15Error('Fixture provided but writes are not explicitly approved')
        if approve_writes and not fixture_config:
            raise RC15Error('Writes require --fixture-config and verified cleanup contracts')
        values = {}
        for item in path_value:
            if '=' not in item:
                raise RC15Error('Use --path-value field=value')
            k, v = item.split('=', 1)
            if not k or k in values:
                raise RC15Error('Path values must be unique')
            values[k] = v
        spec = load_openapi(specification)
        fixture = read_fixtures(fixture_config, spec)
        manager = load_authentication_manager(auth_config) if auth_config else None
        auth = manager.resolve(profile, allowed_hosts=set(allow_host), allow_insecure_http=allow_insecure_http) if manager and profile and execute else None
        if profile and not manager:
            raise RC15Error('Profile requires an auth.yaml file')
        profiles = {}
        if execute and manager:
            for item in fixture.values():
                name = item.get('profile')
                if name and name not in profiles:
                    profiles[name] = manager.resolve(name, allowed_hosts=set(allow_host), allow_insecure_http=allow_insecure_http)
        result = scan_rc15(spec, base_url=base_url, allowed_hosts=set(allow_host),
            auth=auth, auth_profiles=profiles, fixtures=fixture, path_values=values,
            execute=execute, approve_writes=approve_writes,
            approve_xml_oast=approve_xml_oast, callback_base=callback_base,
            callback_observer=callback_observer, fixture_file=fixture_file,
            fixture_marker=fixture_marker, max_requests=max_requests, max_cases=max_cases,
            rate=rate, families=tuple(x.strip() for x in families.split(',') if x.strip()))
        save_json(output, result)
    except (ValueError, OSError, ScopeError, RequestBudgetExceeded, AuthenticationConfigError) as exc:
        typer.echo('RC15 blocked: ' + str(exc)[:200], err=True)
        raise typer.Exit(1) from exc
    typer.echo('RC15: ' + str(result['requests_sent']) + ' HTTP; ' +
               str(len(result['findings'])) + ' findings requiring review; ' + str(output))


@app.command('rc15-callback-server')
def rc15_callback_server(
    port: int = typer.Option(8788, '--port', min=1024, max=65535),
) -> None:
    """Run a private loopback callback collector for authorized SSRF/XXE fixtures."""
    from achillesapi.core.rc15_callback import RC15Collector
    receiver = RC15Collector(port=port)
    typer.echo(f'RC15 callback collector on http://127.0.0.1:{port} (Ctrl-C to stop)')
    try:
        receiver.serve()
    except KeyboardInterrupt:
        pass
    finally:
        receiver.close()


@app.command('access-probe')
def access_probe_rc2(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    base_url: str = typer.Option(..., '--base-url'),
    auth_config: Path = typer.Option(..., '--auth-config', exists=True, dir_okay=False),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    profile: list[str] = typer.Option([], '--profile'),
    operation: str | None = typer.Option(None, '--operation'),
    path_value: list[str] = typer.Option([], '--path-value'),
    expected_other: str = typer.Option('unknown', '--expected-other'),
    expected_owner: str = typer.Option('allow', '--expected-owner'),
    retry_401: bool = typer.Option(False, '--retry-401'),
    execute: bool = typer.Option(False, '--execute'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http'),
    max_requests: int = typer.Option(2, '--max-requests', min=2, max=100),
    rate: float = typer.Option(1., '--rate', min=.1, max=10.),
    output: Path = typer.Option(Path('reports/access-probe.json'), '--output', '-o'),
) -> None:
    """Confronta una GET Swagger con due identita, senza esportare segreti."""
    from achillesapi.core.access_probe_rc import compare_identities, ProbeError
    from achillesapi.core.production_v031 import scope_audit
    try:
        if len(profile) != 2:
            raise ProbeError('Indica esattamente due --profile: owner e altro utente')
        if execute and not scope_audit(base_url, allow_host)['approved']:
            raise ScopeError('L’host non è nello scope autorizzato')
        values = {}
        for item in path_value:
            if '=' not in item:
                raise ProbeError('Ogni --path-value deve essere NOME=VALORE')
            name, value = item.split('=', 1)
            if not name or name in values:
                raise ProbeError('Parametro path duplicato o vuoto')
            values[name] = value
        result = compare_identities(
            specification, base_url=base_url, allowed_hosts=set(allow_host),
            auth_manager=load_authentication_manager(auth_config),
            owner=profile[0], other=profile[1], operation=operation,
            path_values=values, expected_other=expected_other, expected_owner=expected_owner,
            execute=execute, allow_insecure_http=allow_insecure_http,
            max_requests=max_requests, rate=rate, retry_401=retry_401)
        save_json(output, result)
    except (ProbeError, ScopeError, AuthenticationConfigError, RequestBudgetExceeded,
            OpenAPIParseError, ValueError, OSError) as exc:
        typer.echo(f'Bloccato: {exc}', err=True)
        raise typer.Exit(1) from exc
    typer.echo(f'Confronto HTTP: {result["status"]}; report: {output}')


@app.command('campaign-audit')
def campaign_audit_rc2(
    report: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/campaign-audit.json'), '--output', '-o'),
) -> None:
    """Controlla offline se il report della suite e completo e verificabile."""
    from achillesapi.core.release_audit_rc import audit_campaign
    try:
        _write_v099(audit_campaign(_read_v099(report)), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'Report non valido: {exc}', err=True)
        raise typer.Exit(1) from exc


@app.command('evidence-integrity')
def evidence_integrity_rc2(
    report: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/evidence-integrity.json'), '--output', '-o'),
) -> None:
    """Calcola offline SHA-256 e dimensione del report, senza esportarne i dati."""
    from achillesapi.core.evidence_integrity_rc import build_integrity_record
    try:
        _write_v099(build_integrity_record(report), output)
    except (OSError, ValueError) as exc:
        typer.echo(f'File non valido: {exc}', err=True)
        raise typer.Exit(1) from exc



@app.command('access-matrix')
def access_matrix_rc4(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    rules: Path = typer.Option(..., '--rules', exists=True, dir_okay=False),
    base_url: str = typer.Option(..., '--base-url'),
    auth_config: Path = typer.Option(..., '--auth-config', exists=True, dir_okay=False),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    execute: bool = typer.Option(False, '--execute'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http'),
    max_requests: int = typer.Option(40, '--max-requests', min=2, max=150),
    rate: float = typer.Option(1.0, '--rate', min=.1, max=5.),
    output: Path = typer.Option(Path('reports/access-matrix.json'), '--output', '-o'),
) -> None:
    """Verifica una matrice GET con due profili per ogni regola dichiarata."""
    from achillesapi.core.access_matrix_rc4 import read_rules, run_access_matrix
    from achillesapi.core.access_probe_rc import ProbeError
    from achillesapi.core.production_v031 import scope_audit
    try:
        if execute and not scope_audit(base_url, allow_host)['approved']:
            raise ScopeError('Host non autorizzato per la matrice')
        result = run_access_matrix(specification, policy=read_rules(rules),
            base_url=base_url, allowed_hosts=set(allow_host),
            auth_manager=load_authentication_manager(auth_config),
            execute=execute, allow_insecure_http=allow_insecure_http,
            max_requests=max_requests, rate=rate)
        save_json(output, result)
    except (OSError, ValueError, ScopeError, ProbeError, AuthenticationConfigError,
            RequestBudgetExceeded) as exc:
        typer.echo('Matrice non avviata: controlla file, scope e profili.', err=True)
        raise typer.Exit(1) from exc


@app.command('auth-session-audit')
def auth_session_audit_rc4(
    config: Path = typer.Option(..., '--config', exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/auth-session-audit.json'), '--output', '-o'),
) -> None:
    """Mostra la gestione delle sessioni senza risolvere le credenziali."""
    from achillesapi.core.auth_session_rc4 import audit_session_profiles
    try:
        save_json(output, audit_session_profiles(config))
    except (OSError, ValueError, AuthenticationConfigError) as exc:
        typer.echo('auth.yaml non valido; i segreti non vengono stampati.', err=True)
        raise typer.Exit(1) from exc


@app.command('proof-gate')
def proof_gate_rc4(
    report: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/proof-gate.json'), '--output', '-o'),
) -> None:
    """Controlla metadati delle prove: non dichiara finding confermati."""
    from achillesapi.core.evidence_gate_rc4 import review_proof_records
    try:
        document = _read_v099(report)
        if 'records' not in document:
            # Un assessment tradizionale non ha attestazioni indipendenti.
            # Deriviamo i riferimenti ai finding, ma nessuno diventa confirmed.
            from achillesapi.core.evidence_package_v099 import build_evidence_package
            evidence = build_evidence_package(document)
            document = {'records': [{'finding_id': str(item['fingerprint'])[:80],
                         'evidence_refs': [], 'reproduced': False}
                         for item in evidence['findings']]}
        save_json(output, review_proof_records(document))
    except (OSError, ValueError) as exc:
        typer.echo('Documento prove non valido.', err=True)
        raise typer.Exit(1) from exc


@app.command('ai-followup-safe')
def ai_followup_safe_rc4(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    model: str = typer.Option('achilles-local', '--model'),
    output: Path = typer.Option(Path('reports/ai-followup.json'), '--output', '-o'),
) -> None:
    """Consulta Ollama in locale; il risultato è sempre un piano non eseguito."""
    from achillesapi.ai.local import LocalAIError
    from achillesapi.core.ai_followup_rc4 import local_followup_review
    try:
        save_json(output, local_followup_review(load_openapi(specification),
                                                _read_v099(assessment), model=model))
    except (OSError, ValueError, LocalAIError) as exc:
        typer.echo('Ollama locale o assessment non disponibili; nessun test attivo avviato.', err=True)
        raise typer.Exit(1) from exc


@app.command('rc9-plan')
def rc9_plan_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/rc9-plan.json'), '--output', '-o'),
) -> None:
    """Assess all method, body and injection surfaces, offline, without HTTP."""
    from achillesapi.core.campaign_rc9 import campaign_plan_rc9
    try:
        result=campaign_plan_rc9(load_openapi(specification))
        save_json(output,result)
    except (OSError,ValueError,OpenAPIParseError) as exc:
        typer.echo('RC9 plan blocked: '+str(exc)[:200],err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"RC9: {result['summary']['operations']} operations, {result['summary']['injection_candidates']} input tests planned; zero HTTP requests. {output}")



@app.command('rc13-assess')
def rc13_assess(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    base_url: str = typer.Option('http://127.0.0.1:8000', '--base-url'),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    auth_config: Path | None = typer.Option(None, '--auth-config', exists=True, dir_okay=False),
    profile: str | None = typer.Option(None, '--profile'),
    rules: Path | None = typer.Option(None, '--rules', exists=True, dir_okay=False),
    workflow_config: Path | None = typer.Option(None, '--workflow-config', exists=True, dir_okay=False),
    path_value: list[str] = typer.Option([], '--path-value'),
    execute: bool = typer.Option(False, '--execute'),
    approve_writes: bool = typer.Option(False, '--approve-writes'),
    body_probes: bool = typer.Option(False, '--body-probes'),
    body_probe_field: list[str] = typer.Option([], '--body-probe-field'),
    approve_body_probes: bool = typer.Option(False, '--approve-body-probes'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http'),
    max_requests: int = typer.Option(150, '--max-requests', min=1, max=1000),
    rate: float = typer.Option(2., '--rate', min=.1, max=5.),
    ai: bool = typer.Option(False, '--ai'),
    model: str = typer.Option('achilles-local', '--model'),
    ollama_url: str = typer.Option('http://127.0.0.1:11434', '--ollama-url'),
    rc15_callback_base: str | None = typer.Option(None, '--rc15-callback-base'),
    rc15_callback_observer: str | None = typer.Option(None, '--rc15-callback-observer'),
    rc15_fixture_file: str | None = typer.Option(None, '--rc15-fixture-file'),
    rc15_fixture_marker: str | None = typer.Option(None, '--rc15-fixture-marker'),
    agent_followups: bool = typer.Option(False, '--agent-followups', help='Run bounded local AI follow-up GET tasks'),
    agent_rounds: int = typer.Option(2, '--agent-rounds', min=1, max=3),
    agent_budget: int = typer.Option(24, '--agent-budget', min=2, max=60),
    output: Path = typer.Option(Path('reports/rc13-assessment.json'), '--output', '-o'),
) -> None:
    """RC13: coverage + injection GET + matrice + fixture approvate + AI locale."""
    from achillesapi.core.pipeline_rc13 import execute_pipeline, PipelineError
    try:
        values = {}
        for entry in path_value:
            if '=' not in entry:
                raise PipelineError('Usa --path-value nome=valore')
            key, value = entry.split('=', 1)
            if not key or key in values:
                raise PipelineError('Nome path mancante o duplicato')
            values[key] = value
        report = execute_pipeline(specification, base_url=base_url,
            allowed_hosts=set(allow_host), auth_config=auth_config, profile=profile,
            rules_path=rules, workflow_config=workflow_config,
            path_values=values, execute=execute, approve_writes=approve_writes,
            body_probes=body_probes, approve_body_probes=approve_body_probes,
            body_probe_fields=body_probe_field,
            allow_insecure_http=allow_insecure_http, max_requests=max_requests,
            rate=rate, use_ai=ai, model=model, ollama_url=ollama_url,
            rc15_callback_base=rc15_callback_base, rc15_callback_observer=rc15_callback_observer,
            rc15_fixture_file=rc15_fixture_file, rc15_fixture_marker=rc15_fixture_marker,
            agent_followups=agent_followups, agent_rounds=agent_rounds,
            agent_budget=agent_budget)
        save_json(output, report)
        typer.echo('RC13: '+str(report['requests_sent'])+' HTTP; '+str(len(report['findings']))+
                   ' indicatori; '+str(output))
    except (ValueError, OSError, ScopeError, RequestBudgetExceeded,
            AuthenticationConfigError, WorkflowError) as exc:
        typer.echo('RC13 bloccata: '+str(exc)[:240], err=True)
        raise typer.Exit(1) from exc


@app.command('rc13-coverage')
def rc13_coverage(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    auth_config: Path | None = typer.Option(None, '--auth-config', exists=True, dir_okay=False),
    rules: Path | None = typer.Option(None, '--rules', exists=True, dir_okay=False),
    workflow_config: Path | None = typer.Option(None, '--workflow-config', exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/rc13-coverage.json'), '--output', '-o'),
) -> None:
    """Pianifica offline le verifiche RC13 e mostra le superfici ancora scoperte."""
    from achillesapi.core.pipeline_rc13 import create_plan, PipelineError
    try:
        save_json(output, create_plan(specification, auth_config=auth_config,
                  rules_path=rules, workflow_config=workflow_config))
        typer.echo('Piano offline RC13: '+str(output))
    except (ValueError, OSError, AuthenticationConfigError, WorkflowError) as exc:
        typer.echo('Piano non valido: '+str(exc)[:200], err=True)
        raise typer.Exit(1) from exc




@app.command('rc16-workflows')
def rc16_workflows_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    max_candidates: int = typer.Option(30, '--max-candidates', min=1, max=100),
    manifest_draft: Path | None = typer.Option(None, '--manifest-draft'),
    owner_profile: str = typer.Option('REVIEW_OWNER', '--owner-profile'),
    output: Path = typer.Option(Path('reports/rc16-workflows.json'), '--output', '-o'),
) -> None:
    """Offline: discover all candidate disposable lifecycles, optionally draft JSON/YAML fixtures."""
    from achillesapi.core.workflow_automation_rc16 import (
        discover_resource_workflows, draft_multi_resource_manifest)
    try:
        spec = load_openapi(specification)
        result = discover_resource_workflows(spec, max_candidates=max_candidates)
        if manifest_draft is not None:
            import yaml
            draft = draft_multi_resource_manifest(spec, max_candidates=min(10, max_candidates),
                                                   owner_profile=owner_profile)
            manifest_draft.parent.mkdir(parents=True, exist_ok=True)
            manifest_draft.write_text(yaml.safe_dump(draft, sort_keys=False, allow_unicode=True),
                                      encoding='utf-8')
            result['manifest_draft'] = str(manifest_draft)
            result['manifest_draft_executable'] = False
        save_json(output, result)
        typer.echo(f'RC16 workflows: {result["total_candidates"]} candidates; {output}')
    except (ValueError, OSError, OpenAPIParseError) as exc:
        typer.echo(f'Blocked: workflow discovery {type(exc).__name__}: {exc}', err=True)
        raise typer.Exit(code=1) from exc


@app.command('rc16-access-auto')
def rc16_access_auto_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    auth_config: Path = typer.Option(..., '--auth-config', exists=True, dir_okay=False),
    owner_profile: str = typer.Option(..., '--owner-profile'),
    other_profile: list[str] = typer.Option([], '--other-profile'),
    path_value: list[str] = typer.Option([], '--path-value'),
    expected_other: str = typer.Option('deny', '--expected-other'),
    base_url: str = typer.Option('', '--base-url'),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    execute: bool = typer.Option(False, '--execute'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http'),
    max_requests: int = typer.Option(60, '--max-requests', min=2, max=150),
    rate: float = typer.Option(1., '--rate', min=0.1, max=5.),
    output: Path = typer.Option(Path('reports/rc16-access.json'), '--output', '-o'),
) -> None:
    """Multi-endpoint GET authorization matrix from explicit owner, policy and approved IDs."""
    from achillesapi.core.authorization_auto_rc16 import execute_authorization_auto
    try:
        values = _path_values(path_value)
        if execute and not base_url:
            raise ValueError('Active test requires base URL')
        result = execute_authorization_auto(specification, base_url=base_url,
            allowed_hosts=set(allow_host), auth_manager=load_authentication_manager(auth_config),
            owner=owner_profile, others=other_profile, path_values=values,
            expected_other=expected_other, execute=execute,
            allow_insecure_http=allow_insecure_http, max_requests=max_requests, rate=rate)
        save_json(output, result)
        typer.echo(f'RC16 authorization: {result.get("rules_generated", 0)} rules; '
                   f'{result.get("requests_sent", 0)} requests; {output}')
    except (OSError, ValueError, AuthenticationConfigError, ScopeError, RequestBudgetExceeded) as exc:
        typer.echo(f'Blocked: rc16-access-auto: {type(exc).__name__}: {exc}', err=True)
        raise typer.Exit(code=1) from exc


@app.command('rc16-assess')
def rc16_assess_command(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False),
    config: Path = typer.Option(..., '--config', exists=True, dir_okay=False),
    auth_config: Path = typer.Option(..., '--auth-config', exists=True, dir_okay=False),
    base_url: str = typer.Option('', '--base-url'),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    compare_profile: list[str] = typer.Option([], '--compare-profile'),
    expected_other: str = typer.Option('deny', '--expected-other'),
    execute: bool = typer.Option(False, '--execute'),
    approve_writes: bool = typer.Option(False, '--approve-writes'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http'),
    max_requests: int = typer.Option(120, '--max-requests', min=1, max=500),
    rate: float = typer.Option(1., '--rate', min=0.1, max=5.),
    output: Path = typer.Option(Path('reports/rc16-assessment.json'), '--output', '-o'),
) -> None:
    """Orchestrate multiple disposable resources, cross-profile BOLA/BFLA/BOPLA and cleanup."""
    from achillesapi.core.rc16_orchestration import prepare_campaign, run_campaign
    from achillesapi.core.multi_resource import load_multi_resource_config, MultiResourceError
    from achillesapi.core.production_v031 import scope_audit
    try:
        spec = load_openapi(specification)
        manifest = load_multi_resource_config(config)
        manager = load_authentication_manager(auth_config)
        approved = prepare_campaign(spec, manifest, profiles=set(manager.names),
                                    cross_identity=compare_profile, expected_other=expected_other)
        plan = approved['plan']
        if execute:
            if not approve_writes:
                raise ScopeError('Approve all disposable writes explicitly with --approve-writes')
            if not base_url or not scope_audit(base_url, allow_host)['approved']:
                raise ScopeError('Base URL must match the exact allow-host scope')
            if base_url.startswith('http://') and not allow_insecure_http:
                raise ScopeError('Credentials over HTTP require separate permission')
            if max_requests < plan['request_budget_required']:
                raise ScopeError('Insufficient request budget, including cleanup reserves')
            names = set(compare_profile)
            for resource in plan['_prepared']:
                entry = resource['config']
                names.add(entry['identity'])
                names.update(check['identity'] for check in entry.get('access', []))
                names.update(check['identity'] for check in entry.get('write_checks', []))
            identities = {name: manager.resolve(name, allowed_hosts=set(allow_host),
                       allow_insecure_http=allow_insecure_http) for name in sorted(names)}
        else:
            identities = {name: AuthenticationMaterial() for name in manager.names}
        outcome = run_campaign(spec, manifest, identities=identities, base_url=base_url,
                              allowed_hosts=set(allow_host), cross_identity=compare_profile,
                              expected_other=expected_other, execute=execute,
                              approve_writes=approve_writes, allow_insecure_http=allow_insecure_http,
                              max_requests=max_requests, rate=rate)
        save_json(output, outcome)
        typer.echo(f'RC16 assessment: {outcome.get("requests_sent", 0)} requests; '
                   f'{len(outcome.get("findings", []))} findings to review; {output}')
        if outcome.get('manual_cleanup_required'):
            typer.echo('WARNING: manual cleanup may be necessary. Inspect the report.', err=True)
            raise typer.Exit(code=2)
    except (OSError, ValueError, MultiResourceError, AuthenticationConfigError,
            ScopeError, RequestBudgetExceeded) as exc:
        typer.echo(f'Blocked: rc16-assess: {type(exc).__name__}: {exc}', err=True)
        raise typer.Exit(code=1) from exc


@app.command('rc17-verify')
def rc17_verify_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path('reports/rc17-verification.json'), '--output', '-o'),
) -> None:
    """Verify and deduplicate recorded evidence offline; never sends HTTP."""
    from achillesapi.core.verification_engine_rc17 import verify_campaign_findings
    try:
        record = json.loads(assessment.read_text(encoding='utf-8'))
        if not isinstance(record, dict):
            raise ValueError('Assessment must contain one JSON object')
        result = verify_campaign_findings(record.get('findings', []),
                                           stages=record.get('stages', {}))
        save_json(output, result)
        typer.echo(f"RC17 offline verification: {result['unique_findings']} grouped; {output}")
    except (OSError, ValueError, TypeError) as exc:
        typer.echo('RC17 verifica bloccata: ' + str(exc)[:200], err=True)
        raise typer.Exit(1) from exc


# An explicit RC17 entrypoint preserving the well-tested RC13 API and flags.
app.command('rc17-assess')(rc13_assess)


@app.command('rc18-openapi-bundle')
def rc18_openapi_bundle(
    source: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(Path('reports/rc18-bundled-openapi.yaml'), '--output', '-o'),
    root: str = typer.Option('', '--root', help='Path relativo dello Swagger principale nello ZIP.'),
):
    """Consolida OpenAPI multi-file/ZIP offline; blocca traversal, link e file remoti."""
    import yaml
    from achillesapi.core.openapi_bundle_rc18 import import_zip_bundle
    try:
        if source.suffix.lower() == '.zip':
            details = import_zip_bundle(source.read_bytes(), output, root_name=root or None)
        else:
            spec = load_openapi(source)
            parsed = parse_openapi(spec)
            if output.resolve() == source.resolve():
                raise ValueError('Scegli un output diverso dallo Swagger originale')
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(yaml.safe_dump(spec, allow_unicode=True, sort_keys=False), encoding='utf-8')
            details = {'root': str(source), 'file_count': None, 'title': parsed.title,
                       'operations': parsed.endpoint_count, 'network_requests': 0}
        typer.echo(json.dumps({'status': 'complete', 'output': str(output), **details}, ensure_ascii=False))
    except (OSError, ValueError, OpenAPIParseError) as exc:
        typer.echo('Blocked: bundle OpenAPI non valido: ' + str(exc)[:220], err=True)
        raise typer.Exit(2) from exc


@app.command('rc18-oidc-audit')
def rc18_oidc_audit(
    specification: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    metadata: Path | None = typer.Option(None, '--metadata', help='Discovery JSON già scaricato.'),
    jwks: Path | None = typer.Option(None, '--jwks', help='JWKS JSON pubblico locale.'),
    previous_jwks: Path | None = typer.Option(None, '--previous-jwks', help='JWKS precedente per audit rotazione.'),
    expected_issuer: str = typer.Option('', '--expected-issuer'),
    expected_audience: str = typer.Option('', '--expected-audience'),
    token_env: str = typer.Option('', '--token-env', help='Nome variabile ambiente contenente il JWT: mai passato in CLI.'),
    required_scope: list[str] = typer.Option([], '--required-scope', help='Scope obbligatori nel JWT di test.'),
    discovery_url: str = typer.Option('', '--discovery-url'),
    execute: bool = typer.Option(False, '--execute', help='Autorizza esclusivamente la discovery OIDC in scope.'),
    allow_host: list[str] = typer.Option([], '--allow-host'),
    fetch_jwks: bool = typer.Option(False, '--fetch-jwks', help='Scarica anche JWKS via endpoint discovery approvato.'),
    allow_insecure_http: bool = typer.Option(False, '--allow-insecure-http', help='Solo per laboratorio HTTP autorizzato.'),
    output: Path = typer.Option(Path('reports/rc18-oidc.json'), '--output', '-o'),
):
    """Audit OAuth2/OIDC; JWT verificato solo con issuer/audience/JWKS fidati."""
    from achillesapi.core.oidc_enterprise_rc18 import full_oidc_audit, fetch_approved_json, OIDCSafetyError
    try:
        def _load(path: Path | None) -> dict | None:
            if path is None:
                return None
            if not path.is_file() or path.stat().st_size > 128 * 1024:
                raise OIDCSafetyError('File di metadati/JWKS non valido o troppo grande')
            value = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(value, dict):
                raise OIDCSafetyError('File di metadati/JWKS deve contenere un oggetto JSON')
            return value
        spec = load_openapi(specification)
        data = _load(metadata)
        keys = _load(jwks)
        old_keys = _load(previous_jwks)
        requests_made = 0
        if discovery_url:
            if not execute or not allow_host:
                raise OIDCSafetyError('--discovery-url richiede --execute e --allow-host espliciti')
            data = fetch_approved_json(discovery_url, allowed_hosts=set(allow_host),
                                       allow_insecure_http=allow_insecure_http)
            requests_made += 1
            if fetch_jwks:
                jwks_uri = data.get('jwks_uri')
                if not isinstance(jwks_uri, str):
                    raise OIDCSafetyError('Discovery non contiene jwks_uri valido')
                keys = fetch_approved_json(jwks_uri, allowed_hosts=set(allow_host),
                                           allow_insecure_http=allow_insecure_http)
                requests_made += 1
        elif execute or fetch_jwks:
            raise OIDCSafetyError('--execute richiede --discovery-url; --fetch-jwks richiede discovery')
        result = full_oidc_audit(spec, metadata=data, jwks=keys, old_jwks=old_keys,
                                 expected_issuer=expected_issuer or None,
                                 expected_audience=expected_audience or None,
                                 token_env=token_env or None,
                                 required_scopes=tuple(required_scope))
        result['network_requests'] = requests_made
        output.parent.mkdir(parents=True, exist_ok=True)
        save_json(output, result)
        typer.echo(f'Audit OIDC salvato: {output} (richieste di discovery: {requests_made})')
    except (OSError, ValueError, TypeError, json.JSONDecodeError, OpenAPIParseError) as exc:
        # Never echo JWT, raw source, decoder exception or inline secret material.
        typer.echo('Blocked: RC18 OIDC: input, scope o trust non validi; controlla issuer, JWKS e hostname.', err=True)
        raise typer.Exit(2) from exc


@app.command('rc19-quality')
def rc19_quality_command(
    assessment: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(Path('reports/rc19-quality.json'), '--output', '-o'),
):
    """Controlla offline la qualità del report, senza contattare il target."""
    from achillesapi.core.release_validation_rc19 import quality_gate, RC19ValidationError
    try:
        if assessment.stat().st_size > 20 * 1024 * 1024:
            raise RC19ValidationError('Report oltre il limite di 20 MB')
        report=json.loads(assessment.read_text(encoding='utf-8'))
        result=quality_gate(report)
        save_json(output,result)
        typer.echo('RC19 quality: '+result['release_gate']+' · '+str(output))
    except (ValueError,OSError,TypeError) as exc:
        typer.echo('RC19 quality bloccata: formato o struttura del report non validi.',err=True)
        raise typer.Exit(2) from exc


@app.command('rc19-benchmark')
def rc19_benchmark_command(
    assessment: Path = typer.Argument(...,exists=True,dir_okay=False,readable=True),
    ground_truth: Path = typer.Argument(...,exists=True,dir_okay=False,readable=True),
    output: Path = typer.Option(Path('reports/rc19-benchmark.json'),'--output','-o'),
):
    """Confronta indicatori osservati con casi attesi verificati dall'operatore, offline."""
    from achillesapi.core.release_validation_rc19 import benchmark_findings, RC19ValidationError
    try:
        if assessment.stat().st_size>20*1024*1024 or ground_truth.stat().st_size>256*1024:
            raise RC19ValidationError('Report o ground truth troppo grandi')
        report=json.loads(assessment.read_text(encoding='utf-8'))
        expected=json.loads(ground_truth.read_text(encoding='utf-8'))
        result=benchmark_findings(report,expected)
        save_json(output,result)
        typer.echo('RC19 benchmark: '+result['status']+' · '+str(output))
    except (ValueError,OSError,TypeError) as exc:
        typer.echo('RC19 benchmark bloccato: input, ID o categorie non validi.',err=True)
        raise typer.Exit(2) from exc




@app.command("rc20-plan")
def rc20_plan(specification: Path = typer.Argument(..., exists=True, dir_okay=False),
              output: Path | None = typer.Option(None, "--output", "-o")) -> None:
    """Offline dashboard readiness: operations, workflows and structured prerequisites."""
    from achillesapi.core.autonomous_workspace_rc20 import build_workspace
    data = build_workspace(load_openapi(specification))
    _print_rc23_json(data,output)


@app.command("rc21-plan")
def rc21_plan(specification: Path = typer.Argument(..., exists=True, dir_okay=False),
              output: Path | None = typer.Option(None, "--output", "-o")) -> None:
    """Offline multi-resource BOLA/BFLA/BOPLA candidates; no policy assumed."""
    from achillesapi.core.authorization_planner_rc21 import build_authorization_plan
    _print_rc23_json(build_authorization_plan(load_openapi(specification)),output)


@app.command("rc22-coverage")
def rc22_coverage(specification: Path = typer.Argument(..., exists=True, dir_okay=False),
                  output: Path | None = typer.Option(None, "--output", "-o")) -> None:
    """Offline scanner coverage across query, path, body, XML and upload."""
    from achillesapi.core.scanner_coverage_rc22 import scanner_plan
    _print_rc23_json(scanner_plan(load_openapi(specification)),output)


@app.command("rc22-verify-controls")
def rc22_verify_controls(evidence: Path = typer.Argument(..., exists=True, dir_okay=False),
                         output: Path | None = typer.Option(None, "--output", "-o")) -> None:
    """Evaluate explicitly supplied owner/replay/negative controls offline."""
    from achillesapi.core.evidence_verification_rc22 import verify_controlled_cases
    raw=json.loads(evidence.read_text(encoding='utf-8'))
    if not isinstance(raw,dict):raise typer.BadParameter('Expected JSON object with cases')
    _print_rc23_json(verify_controlled_cases(raw.get('cases',[])),output)


@app.command("rc23-report-audit")
def rc23_report_audit(report: Path = typer.Argument(..., exists=True, dir_okay=False),
                      output: Path | None = typer.Option(None, "--output", "-o")) -> None:
    """Show execution/skip coverage and typed remediations for a suite report."""
    from achillesapi.core.release_validation_rc23 import audit_campaign
    _print_rc23_json(audit_campaign(json.loads(report.read_text(encoding='utf-8'))),output)


def _print_rc23_json(value: dict, output: Path | None) -> None:
    serialized=json.dumps(value,ensure_ascii=False,indent=2)
    if output:
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(serialized,encoding='utf-8')
        typer.echo(str(output))
    else:
        typer.echo(serialized)


if __name__ == "__main__":
    app()
