"""Regression checks for generic behavior across unrelated API layouts."""

import json

import pytest
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.generic import build_generic_plan, execute_generic_gets
from achillesapi.core.http import ScopeError
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.auth import AuthenticationMaterial


def spec(paths):
    """Build a small but valid OpenAPI document for a distinct API layout."""
    return {
        "openapi": "3.0.3",
        "info": {"title": "Unrelated API", "version": "1"},
        "paths": paths,
    }


def endpoint(parameters=None):
    """Create an operation without assuming any laboratory resource name."""
    return {
        "parameters": parameters or [],
        "responses": {"200": {"description": "OK"}},
    }


def test_general_api_can_be_planned_without_lab_names():
    """Normal endpoints without IDs remain runnable as anonymous GET requests."""
    p = parse_openapi(spec({
        "/invoices": {"get": endpoint()},
        "/catalog/{sku}": {"get": endpoint([
            {"name": "sku", "in": "path", "required": True, "schema": {"type": "string"}}
        ])},
        "/invoices": {"get": endpoint(), "post": endpoint()},
    }))
    plan = build_generic_plan(p, base_url="https://api.example.org")
    assert plan["summary"] == {
        "get_candidates": 1, "blocked_missing_inputs": 1, "manual_only": 1,
    }
    assert next(o for o in plan["operations"] if o["path"] == "/catalog/{sku}")["missing_path_values"] == ["sku"]


def test_custom_values_make_nonconventional_ids_eligible():
    """Identifiers use caller-provided values even when names are not userId/orderId."""
    p = parse_openapi(spec({
        "/devices/{serial_number}": {"get": endpoint([
            {"name": "serial_number", "in": "path", "required": True,
             "schema": {"type": "string"}}
        ])}
    }))
    plan = build_generic_plan(p, path_values={"serial_number": "X/Y?42"})
    assert plan["operations"][0]["rendered_path"] == "/devices/X%2FY%3F42"
    assert plan["summary"]["get_candidates"] == 1


def test_required_query_has_to_be_supplied():
    """Do not generate arbitrary production request parameters."""
    p = parse_openapi(spec({
        "/find": {"get": endpoint([
            {"name": "filter", "in": "query", "required": True,
             "schema": {"type": "string"}}
        ])}
    }))
    assert build_generic_plan(p)["summary"]["blocked_missing_inputs"] == 1
    assert build_generic_plan(p, path_values={"filter": "demo"})["summary"]["get_candidates"] == 1


def test_execution_is_dry_run_by_default_and_no_network():
    """Building and dry-running an authorized plan must never contact the API."""
    plan = build_generic_plan(parse_openapi(spec({"/status": {"get": endpoint()}})))
    result = execute_generic_gets(
        plan, base_url="https://api.example.org", allowed_hosts={"api.example.org"}
    )
    assert result["requests_sent"] == 0
    assert result["observations"][0]["executed"] is False
    assert "body" not in result["observations"][0]


def test_scope_restrictions_and_insecure_credentials():
    """Refuse out-of-scope hosts and accidental plaintext credential transport."""
    plan = build_generic_plan(parse_openapi(spec({"/status": {"get": endpoint()}})))
    with pytest.raises(ScopeError):
        execute_generic_gets(
            plan, base_url="https://bad.example.org", allowed_hosts={"api.example.org"}
        )
    with pytest.raises(ScopeError):
        execute_generic_gets(
            plan, base_url="http://api.example.org",
            allowed_hosts={"api.example.org"},
            identities={"analyst": AuthenticationMaterial(headers={"Authorization": "Bearer secret"})},
        )


def test_budget_precheck_does_not_send_partial_scan():
    """Reject oversized scans before a single network request is sent."""
    p = parse_openapi(spec({"/a": {"get": endpoint()}, "/b": {"get": endpoint()}}))
    plan = build_generic_plan(p)
    with pytest.raises(ScopeError, match="exceed"):
        execute_generic_gets(
            plan, base_url="https://api.example.org",
            allowed_hosts={"api.example.org"},
            max_requests=1, execute=True,
        )


def test_cli_dry_run(tmp_path):
    """A user can plan an arbitrary OpenAPI file from the real CLI."""
    path = tmp_path / "api.json"
    report = tmp_path / "out.json"
    path.write_text(json.dumps(spec({"/health": {"get": endpoint()}})))
    result = CliRunner().invoke(app, [
        "auto-assess", str(path), "--base-url", "https://api.example.org",
        "--output", str(report),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(report.read_text())
    assert data["plan"]["summary"]["get_candidates"] == 1
    assert data["execution_report"] is None


def test_single_openapi_31_path_example_is_supported():
    """Use one documented OpenAPI 3.1 example instead of asking for a manual ID."""
    p = parse_openapi(spec({
        "/widgets/{part_number}": {"get": endpoint([
            {"name": "part_number", "in": "path", "required": True,
             "schema": {"type": "string", "examples": ["TEST-1"]}}
        ])}
    }))
    plan = build_generic_plan(p)
    assert plan["operations"][0]["rendered_path"] == "/widgets/TEST-1"
