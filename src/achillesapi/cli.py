"""Command-line interface for AchillesAPI."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from achillesapi import __version__
from achillesapi.core.openapi import OpenAPIParseError, analyze_openapi_file, load_openapi
from achillesapi.core.graph import build_api_graph, graph_to_dict
from achillesapi.core.assessment import assess_api, assessment_to_dict
from achillesapi.core.http import SafeHTTPClient, ScopeError, RequestBudgetExceeded

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


if __name__ == "__main__":
    app()
