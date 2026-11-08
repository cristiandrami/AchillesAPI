"""Integration tests using a separate mini HTTP server and unrelated OpenAPI data."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.context import ContextError, read_context
from achillesapi.core.generic import build_generic_plan
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.smart import ScanSettings, describe_smart_checks, run_smart_assessment
from achillesapi.core.http import ScopeError


class FixtureAPI(BaseHTTPRequestHandler):
    """Serve an unrelated API shape; the scanner must have no knowledge of it."""

    def log_message(self, *_args):
        """Suppress server logs so fixtures cannot leak credentials in tests."""

    def do_GET(self):
        """Return synthetic JSON and intentionally different security behaviors."""
        target = urlsplit(self.path)
        query = parse_qs(target.query)
        status = 200
        headers = {}
        if target.path == "/inventory":
            body = {"products": 3}
        elif target.path.startswith("/tickets/"):
            # This deliberately accepts an anonymous request so our scanner
            # should raise a candidate auth finding without claiming proof.
            body = {"ticket_ref": target.path.rsplit("/", 1)[-1], "owner": "test-team", "private": "sensitive fixture value", "password": "lab-only-not-to-be-saved"}
            if self.headers.get("Origin") == "https://untrusted-origin.invalid":
                headers = {"Access-Control-Allow-Origin": self.headers["Origin"],
                           "Access-Control-Allow-Credentials": "true"}
        elif target.path == "/search":
            if query.get("limit") == ["not_a_number"]:
                status = 500
                body = {"detail": "SQL syntax error in test fixture: private-password-example"}
            else:
                body = {"result": "ok"}
        else:
            status = 404
            body = {"error": "missing"}
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)


@contextmanager
def serve():
    """Start a temporary test server bound exclusively to local loopback."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureAPI)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def spec():
    """Build a real OpenAPI definition without relying on laboratory routes."""
    bearer = [{"TestToken": []}]
    return parse_openapi({
        "openapi": "3.0.3", "info": {"title": "Independent API", "version": "1"},
        "components": {"securitySchemes": {"TestToken": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/inventory": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/tickets/{ticket_ref}": {"get": {"security": bearer,
                "parameters": [{"name": "ticket_ref", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok", "content": {
                    "application/json": {"schema": {"type": "object", "properties": {
                        "password": {"type": "string", "writeOnly": True},
                        "ticket_ref": {"type": "string"}
                    }}}
                }}}}},
            "/search": {"get": {"security": bearer,
                "parameters": [{"name": "limit", "in": "query", "required": True,
                                "schema": {"type": "integer", "minimum": 1}}],
                "responses": {"200": {"description": "ok"}}}},
            "/inventory": {"get": {"responses": {"200": {"description": "ok"}}},
                            "post": {"responses": {"201": {"description": "created"}}}},
        },
    })


def test_planner_selects_independent_operations_without_network():
    """Planning should recognize auth and input checks without contacting a host."""
    parsed = spec()
    plan = build_generic_plan(parsed, path_values={"ticket_ref": "TICKET-X", "limit": "4"})
    checks = describe_smart_checks(parsed, plan)
    assert checks["network_requests_sent"] == 0
    assert any("query_schema_validation:limit" in entry["checks"] for entry in checks["check_selection"])
    assert next(op for op in checks["check_selection"] if op["method"] == "POST")["status"] == "manual_only_non_get"


def test_scanner_runs_relevant_checks_and_redacts_bodies():
    """The same engine should test auth, schema and CORS on an unrelated server."""
    parsed = spec()
    plan = build_generic_plan(parsed, path_values={"ticket_ref": "TICKET-X", "limit": "4"})
    profiles = {
        "first": AuthenticationMaterial(headers={"Authorization": "Bearer alpha-test"}),
        "second": AuthenticationMaterial(headers={"Authorization": "Bearer beta-test"}),
    }
    with serve() as base:
        result = run_smart_assessment(
            parsed, plan, base_url=base, allowed_hosts={"127.0.0.1"},
            identities=profiles, path_values={"ticket_ref": "TICKET-X", "limit": "4"},
            expected_access={"GET /tickets/{ticket_ref}": {"second": "deny"}},
            specification={
                "paths": {"/tickets/{ticket_ref}": {"get": {
                    "responses": {"200": {"content": {"application/json": {"schema": {
                        "type": "object", "properties": {"password": {"type": "string", "writeOnly": True}}
                    }}}}}
                }}}
            },
            settings=ScanSettings(max_requests=30, rate=1000, allow_insecure_http=True),
        )
    categories = {entry["category"] for entry in result["findings"]}
    assert "cors_credentialed_origin_reflection" in categories
    assert "unauthenticated_access_review" in categories
    assert "input_error_disclosure" in categories
    assert "authorization_policy_mismatch" in categories
    assert "cross_identity_object_review" in categories
    assert "write_only_property_returned" in categories
    assert 0 < result["requests_sent"] <= 30
    output = json.dumps(result)
    assert "alpha-test" not in output
    assert "beta-test" not in output
    assert "private-password-example" not in output
    assert "sensitive fixture value" not in output
    assert "lab-only-not-to-be-saved" not in output


def test_bounded_scan_and_no_credentials_over_plain_http():
    """The budget and plaintext-credential protection cannot be bypassed."""
    parsed = spec()
    plan = build_generic_plan(parsed, path_values={"ticket_ref": "X", "limit": "4"})
    profile = {"sample": AuthenticationMaterial(headers={"Authorization": "Bearer secret"})}
    with pytest.raises(ScopeError, match="plaintext"):
        run_smart_assessment(parsed, plan, base_url="http://127.0.0.1:10",
                             allowed_hosts={"127.0.0.1"}, identities=profile)
    with serve() as base:
        result = run_smart_assessment(
            parsed, plan, base_url=base, allowed_hosts={"127.0.0.1"},
            identities=profile, path_values={"ticket_ref": "X", "limit": "4"},
            settings=ScanSettings(max_requests=2, rate=1000, allow_insecure_http=True),
        )
    assert result["requests_sent"] == 2
    assert any(item["reason"] == "request_budget_exhausted" for item in result["skipped"])


def test_context_is_optional_and_strict(tmp_path):
    """A real engagement can supply IDs and access facts, without secrets."""
    assert read_context(None) == {"path_values": {}, "expected_access": {}}
    source = tmp_path / "context.yaml"
    source.write_text('''path_values:\n  ticket_ref: "TICKET-X"\nexpected_access:\n  "GET /tickets/{ticket_ref}":\n    first: allow\n    second: deny\n''')
    data = read_context(source)
    assert data["path_values"]["ticket_ref"] == "TICKET-X"
    source.write_text("run_shell_command: true\n")
    with pytest.raises(ContextError):
        read_context(source)


def test_cli_infers_single_openapi_server_and_uses_context(tmp_path):
    """A real user can supply one spec and one optional context without lab flags."""
    from typer.testing import CliRunner
    from achillesapi.cli import app

    data = {
        "openapi": "3.0.3",
        "info": {"title": "Independent Production API", "version": "1"},
        "servers": [{"url": "https://qa.example.org/api/v4"}],
        "paths": {"/tickets/{ticket_ref}": {"get": {
            "parameters": [{"name": "ticket_ref", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}
        }}}
    }
    path = tmp_path / "api.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    ctx = tmp_path / "engagement.yaml"
    ctx.write_text('path_values:\n  ticket_ref: "TEST-1"\n', encoding="utf-8")
    report = tmp_path / "out.json"
    result = CliRunner().invoke(app, ["auto-assess", str(path), "--context", str(ctx),
                                       "--output", str(report)])
    assert result.exit_code == 0, result.output
    saved = json.loads(report.read_text(encoding="utf-8"))
    assert saved["plan"]["base_url"] == "https://qa.example.org/api/v4"
    assert saved["plan"]["summary"]["get_candidates"] == 1
    assert saved["adaptive_check_plan"]["network_requests_sent"] == 0
    assert saved["execution_report"] is None


def test_oauth2_bearer_profile_is_eligible():
    """Static externally acquired OAuth2 test tokens should be usable generically."""
    from achillesapi.core.generic import _compatible_identities

    operation = {"security_alternatives": [["OAuth2Test"]]}
    definitions = {"OAuth2Test": {"type": "oauth2"}}
    credentials = {"tester": AuthenticationMaterial(headers={"Authorization": "Bearer test-token"})}
    assert "tester" in _compatible_identities(operation, definitions, credentials)
    assert not _compatible_identities(
        operation, definitions,
        {"wrong": AuthenticationMaterial(headers={"Authorization": "Basic Zm9vOmJhcg=="})},
    )


def test_cli_live_assessment_from_arbitrary_openapi(monkeypatch, tmp_path):
    """The real CLI must exercise a fresh API without touching demo-lab code."""
    from typer.testing import CliRunner
    from achillesapi.cli import app

    swagger = {
        "openapi": "3.0.3", "info": {"title": "Unrelated Service", "version": "1"},
        "components": {"securitySchemes": {"Bearer": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/tickets/{ticket_ref}": {"get": {
                "security": [{"Bearer": []}],
                "parameters": [{"name": "ticket_ref", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok"}},
            }},
        },
    }
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(swagger), encoding="utf-8")
    auth_file = tmp_path / "auth.yaml"
    auth_file.write_text('profiles:\n  - name: operator\n    type: bearer\n    token_env: INTEGRATION_TEST_TOKEN\n')
    context_file = tmp_path / "context.yaml"
    context_file.write_text('path_values:\n  ticket_ref: TICKET-X\n')
    monkeypatch.setenv("INTEGRATION_TEST_TOKEN", "super-test-secret")
    outfile = tmp_path / "scan.json"
    with serve() as base:
        result = CliRunner().invoke(app, [
            "auto-assess", str(spec_file), "--base-url", base,
            "--allow-host", "127.0.0.1", "--auth-config", str(auth_file),
            "--context", str(context_file), "--max-requests", "5",
            "--rate", "10", "--allow-insecure-http", "--execute",
            "--output", str(outfile),
        ])
    assert result.exit_code == 0, result.output
    report = json.loads(outfile.read_text(encoding="utf-8"))
    assert 1 <= report["execution_report"]["requests_sent"] <= 5
    assert report["execution_report"]["findings_confirmed"] == 0
    assert "super-test-secret" not in outfile.read_text(encoding="utf-8")


def test_suspicious_get_methods_need_manual_review():
    """Do not assume that GET /reset or GET /delete is safe just by method."""
    parsed = parse_openapi({
        "openapi": "3.0.3", "info": {"title": "Action API", "version": "1"},
        "paths": {
            "/session/logout": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/exports": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/tasks/trigger": {"get": {"responses": {"200": {"description": "ok"}}}},
        },
    })
    plan = build_generic_plan(parsed)
    statuses = {op["path"]: op["status"] for op in plan["operations"]}
    assert statuses["/session/logout"] == "manual_review_possible_side_effect"
    assert statuses["/tasks/trigger"] == "manual_review_possible_side_effect"
    assert statuses["/exports"] == "eligible_get"
