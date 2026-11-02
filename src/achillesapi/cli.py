"""Command-line interface for AchillesAPI."""

from __future__ import annotations

from pathlib import Path

import typer

from achillesapi import __version__
from achillesapi.core.openapi import OpenAPIParseError, analyze_openapi_file

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


if __name__ == "__main__":
    app()
