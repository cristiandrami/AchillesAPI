"""v0.22 inventory + v0.23 deterministic bounded agent, non-lab tests."""
from __future__ import annotations

import json
from pathlib import Path
from typer.testing import CliRunner
import pytest

from achillesapi.cli import app
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.generic import build_generic_plan
from achillesapi.core.orchestrator import choose_followups, run_followups
from achillesapi.core.security_inventory import security_inventory
from achillesapi.core.http import ScopeError


def spec():
    return {"openapi": "3.0.3", "info": {"title": "Independent Office API", "version": "1"},
            "components": {"securitySchemes": {"auth": {"type": "http", "scheme": "bearer"}}},
            "paths": {
                "/workspaces/{space_ref}": {"get": {
                    "parameters": [{"name": "space_ref", "in": "path", "required": True,
                                    "schema": {"type": "string"}}],
                    "security": [{"auth": []}], "responses": {"200": {"description": "ok"}}}},
                "/service/status": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/workspaces": {"post": {"requestBody": {"content": {
                    "application/json": {"schema": {"type": "object"}}}},
                    "responses": {"201": {"description": "created"}}}},
            }}


def observations():
    return [
        {"operation": "GET /service/status", "check": "baseline", "identity": "anonymous", "status": 503},
        {"operation": "GET /workspaces/{space_ref}", "check": "without_credentials",
         "identity": "anonymous", "status": 200},
        {"operation": "GET /service/status", "check": "cors_origin", "identity": "anonymous", "status": 500},
        {"operation": "GET /external", "check": "baseline", "identity": "anonymous", "status": 503},
    ]


def test_inventory_is_only_opportunities():
    parsed = parse_openapi(spec())
    report = security_inventory(parsed, spec())
    assert report["network_requests_sent"] == 0
    entry = next(x for x in report["operations"] if x["operation"] == "GET /workspaces/{space_ref}")
    assert any("Object Level" in x for x in entry["test_areas"])
    assert all(not x["finding"] for x in report["operations"])


def test_agent_selects_only_relevant_get_rechecks():
    parsed = parse_openapi(spec())
    plan = build_generic_plan(parsed, path_values={"space_ref": "approved-fixture"})
    result = choose_followups(parsed, plan, observations(), budget=2)
    assert [x["reason"] for x in result["actions"]] == [
        "recheck_anonymous_access", "recheck_server_error"]
    assert "GET /external" not in str(result)
    assert choose_followups(parsed, plan, observations(), budget=0)["actions"] == []
    with pytest.raises(ValueError):
        choose_followups(parsed, plan, observations(), budget=21)


def test_agent_never_requests_out_of_scope_and_stays_offline():
    parsed = parse_openapi(spec())
    plan = build_generic_plan(parsed, path_values={"space_ref": "approved-fixture"})
    offline = run_followups(parsed, plan, observations(), base_url="http://127.0.0.1:3",
                            allowed_hosts={"127.0.0.1"}, budget=2)
    assert offline["executed"] is False
    with pytest.raises(ScopeError):
        run_followups(parsed, plan, observations(), base_url="https://unapproved.invalid",
                      allowed_hosts={"127.0.0.1"}, budget=2, execute=True)


def test_agent_real_503_and_schema_anonymous_reproduction():
    """Live server returns the same statuses on repeat; no raw response data saved."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    class Handler(BaseHTTPRequestHandler):
        attempts = 0
        def log_message(self, *args):
            pass
        def do_GET(self):
            Handler.attempts += 1
            status = 503 if self.path == "/service/status" else 200
            body = b'{"secret":"never-in-report"}'
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        parsed = parse_openapi(spec())
        plan = build_generic_plan(parsed, path_values={"space_ref": "approved-fixture"})
        result = run_followups(parsed, plan, observations(),
                               base_url=f"http://127.0.0.1:{server.server_port}",
                               allowed_hosts={"127.0.0.1"}, budget=2, rate=10, execute=True)
        assert result["network_requests_sent"] == 2
        assert Handler.attempts == 2
        assert all(x["repeated"] for x in result["observations"])
        assert "never-in-report" not in json.dumps(result)
    finally:
        server.shutdown(); thread.join(timeout=2); server.server_close()


def test_agent_refuses_http_credentials_without_approval():
    from achillesapi.core.auth import AuthenticationMaterial
    parsed = parse_openapi(spec())
    plan = build_generic_plan(parsed, path_values={"space_ref": "approved-fixture"})
    obs = [{"operation": "GET /workspaces/{space_ref}", "check": "baseline",
            "identity": "staff", "status": 503}]
    with pytest.raises(ScopeError):
        run_followups(parsed, plan, obs, base_url="http://127.0.0.1:9000",
                      allowed_hosts={"127.0.0.1"}, identities={"staff": AuthenticationMaterial(
                          headers={"Authorization": "Bearer test"})}, budget=1, execute=True)


def test_inventory_and_agent_review_cli(tmp_path):
    src = tmp_path / "api.json"
    src.write_text(json.dumps(spec()))
    outcome = tmp_path / "inventory.json"
    run = CliRunner().invoke(app, ["security-inventory", str(src), "--output", str(outcome)])
    assert run.exit_code == 0, run.output
    assert len(json.loads(outcome.read_text())["operations"]) == 3
    previous = tmp_path / "assessment.json"
    previous.write_text(json.dumps({"plan": build_generic_plan(parse_openapi(spec()),
                                                       path_values={"space_ref": "approved-fixture"}),
                                    "execution_report": {"observations": observations()}}))
    output = tmp_path / "agent.json"
    run = CliRunner().invoke(app, ["agent-review", str(src), str(previous),
                                   "--budget", "2", "--output", str(output)])
    assert run.exit_code == 0, run.output
    assert json.loads(output.read_text())["network_requests_sent"] == 0


def test_auto_assess_agent_budget_executes_only_eligible_get(tmp_path):
    """The CLI dispatches the v0.23 agent under a reserved global request cap."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    class Handler(BaseHTTPRequestHandler):
        seen = 0
        def log_message(self, *args):
            pass
        def do_GET(self):
            Handler.seen += 1
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source = tmp_path / "api.json"
    source.write_text(json.dumps({"openapi": "3.0.3", "info": {"title": "Service", "version": "1"},
                                  "paths": {"/status": {"get": {"responses": {"200": {"description": "ok"}}}}}}))
    output = tmp_path / "scan.json"
    try:
        result = CliRunner().invoke(app, ["auto-assess", str(source),
            "--base-url", f"http://127.0.0.1:{server.server_port}",
            "--allow-host", "127.0.0.1", "--agent-budget", "2",
            "--max-requests", "3", "--rate", "10", "--no-cors", "--no-validation",
            "--no-auth-checks", "--execute", "--output", str(output)])
        assert result.exit_code == 0, result.output
        report = json.loads(output.read_text())
        assert report["agent_execution"]["network_requests_sent"] == 1
        assert report["agent_execution"]["observations"][0]["repeated"]
        assert report["plan"]["execution"]["requests_sent"] == 2
        assert Handler.seen == 2
    finally:
        server.shutdown(); thread.join(timeout=2); server.server_close()


def test_v022_bounded_schema_probe_handles_formats_and_min_length():
    """Use OpenAPI constraints instead of sending generic dangerous payloads."""
    from achillesapi.core.smart import _invalid_input
    assert _invalid_input({"type": "string", "minLength": 2}) == ""
    assert _invalid_input({"type": "string", "format": "uuid"}) == "not-a-valid-uuid"
    assert _invalid_input({"type": "integer"}) == "not_a_number"
    assert len(_invalid_input({"type": "string", "maxLength": 12})) == 13
