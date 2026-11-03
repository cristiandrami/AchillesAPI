"""Command-line interface for AchillesAPI."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from achillesapi import __version__
from achillesapi.core.assessment import assess_api, assessment_to_dict
from achillesapi.core.advanced import (
    AdvancedCheckError, bola_sweep, bfla_sweep, mass_assignment_check,
    sqli_probe, fuzz_query_parameter, inspect_jwt,
)
from achillesapi.core.bola import BolaCheckError, check_bola
from achillesapi.core.graph import build_api_graph, graph_to_dict
from achillesapi.core.http import RequestBudgetExceeded, SafeHTTPClient, ScopeError
from achillesapi.core.openapi import OpenAPIParseError, analyze_openapi_file, load_openapi

app = typer.Typer(
    name="achillesapi",
    help="AI-assisted, context-aware API security assessment framework.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Display the installed AchillesAPI version."""

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



@app.command("map-api")
def map_api(
    specification: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    output: Path = typer.Option(Path("reports/api-graph.json"), "--output", "-o"),
) -> None:
    """Build a provenance-aware graph of endpoints, resources and schemas."""
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
) -> None:
    """Perform a scoped GET request; dry-run is the default and only GET is enabled."""
    try:
        client = SafeHTTPClient(
            allowed_hosts=set(allow_host), timeout=timeout, max_requests=max_requests
        )
        evidence = client.request("GET", url, execute=execute)
    except (ScopeError, RequestBudgetExceeded, ValueError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(evidence.model_dump(mode="json"), indent=2))


@app.command("bola-check")
def bola_check(
    url: str = typer.Argument(..., help="Object URL on localhost, e.g. http://127.0.0.1:8000/api/orders/order-bob"),
    owner_token: str | None = typer.Option(None, "--owner-token", hide_input=True),
    other_token: str | None = typer.Option(None, "--other-token", hide_input=True),
    execute: bool = typer.Option(
        False, "--execute", help="Send two GET requests; without this flag, only show the plan."
    ),
    timeout: float = typer.Option(5.0, min=0.1, max=30.0),
) -> None:
    """Compare object access by its owner and a different principal (localhost only)."""
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
    path_value: list[str] = typer.Option([], "--path-value", help="Path placeholder NAME=VALUE; repeat as needed."),
    timeout: float = typer.Option(5.0, min=0.1, max=15.0),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Compare two principals across all GET operations (loopback only)."""
    if owner_token is None:
        owner_token = typer.prompt("Owner bearer token", hide_input=True)
    if other_token is None:
        other_token = typer.prompt("Other principal bearer token", hide_input=True)
    try:
        spec = load_openapi(specification)
        result = bola_sweep(spec, base_url, owner_token, other_token, _path_values(path_value), timeout)
    except (AdvancedCheckError, OpenAPIParseError, ValueError, OSError) as exc:
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
    path_value: list[str] = typer.Option([], "--path-value"),
    timeout: float = typer.Option(5.0, min=0.1, max=15.0),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Compare low/high privilege responses across GET operations (loopback only)."""
    if low_token is None:
        low_token = typer.prompt("Low-privilege bearer token", hide_input=True)
    if high_token is None:
        high_token = typer.prompt("High-privilege bearer token", hide_input=True)
    try:
        spec = load_openapi(specification)
        result = bfla_sweep(spec, base_url, low_token, high_token, _path_values(path_value), timeout)
    except (AdvancedCheckError, OpenAPIParseError, ValueError, OSError) as exc:
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
    if execute and token is None:
        token = typer.prompt("Bearer token", hide_input=True)
    try:
        body = json.loads(body_file.read_text(encoding="utf-8"))
        result = mass_assignment_check(url, body, token, execute)
    except (AdvancedCheckError, ValueError, OSError, json.JSONDecodeError) as exc:
        typer.echo(f"Blocked: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, indent=2))


@app.command("jwt-inspect")
def jwt_inspect_command(
    token: str | None = typer.Argument(None, help="Compact JWT; omitted means secure prompt."),
) -> None:
    """Decode JWT header and claims offline; signature is never verified."""
    value = token or typer.prompt("JWT", hide_input=True)
    try:
        result = inspect_jwt(value)
    except AdvancedCheckError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
