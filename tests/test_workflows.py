"""Integration tests against an unrelated, ephemeral API (no Achilles lab routes)."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

import pytest
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.auth import AuthenticationMaterial
from achillesapi.core.http import ScopeError
from achillesapi.core.openapi import parse_openapi
from achillesapi.core.workflows import (
    WorkflowError, discover_workflows, read_workflows,
    workflow_plan, run_workflows,
)


def specification():
    """Define a non-lab CRUD API whose identifier is called `widget_ref`."""
    security = [{"AccessToken": []}]
    paths = {
        "/api/permissions": {"get": {"security": security,
            "responses": {"200": {"description": "Permissions"}}}},
        "/api/widgets": {"post": {
            "security": security,
            "requestBody": {"required": True, "content": {"application/json": {
                "schema": {"type": "object", "required": ["label"],
                           "properties": {"label": {"type": "string"}}}}}},
            "responses": {"201": {"description": "Created", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"ref": {"type": "string"}}}}}}},
        }},
        "/api/widgets/{widget_ref}": {
            "parameters": [{"name": "widget_ref", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "get": {"security": security, "responses": {"200": {"description": "OK"}}},
            "patch": {"security": security,
                      "requestBody": {"content": {"application/json": {
                          "schema": {"type": "object", "properties": {"is_reviewer": {"type": "boolean"}}}}}},
                      "responses": {"200": {"description": "Updated"}}},
            "delete": {"security": security, "responses": {"204": {"description": "Deleted"}}},
        },
    }
    return {"openapi": "3.0.3", "info": {"title": "Temporary Widgets", "version": "1"},
            "components": {"securitySchemes": {"AccessToken": {"type": "http", "scheme": "bearer"}}},
            "paths": paths}


def scenarios():
    """Create, probe and delete a test object under explicit operator policy."""
    return [{
        "name": "sandbox_widget",
        "create": {"operation": "POST /api/widgets", "identity": "fixture_owner",
                   "body": {"label": "disposable-test"}, "id_pointer": "/ref", "marker_field": "label"},
        "read": {"operation": "GET /api/widgets/{widget_ref}", "identity": "fixture_owner",
                 "id_parameter": "widget_ref", "id_pointer": "/ref", "marker_pointer": "/label"},
        "access": [{"identity": "other_tester", "expected": "deny", "category": "BOLA"}],
        "mutation": {"operation": "PATCH /api/widgets/{widget_ref}", "identity": "fixture_owner",
                     "body": {"is_reviewer": True}, "restricted_fields": ["is_reviewer"]},
        "restricted_response_fields": ["private_value"],
        "cleanup": {"operation": "DELETE /api/widgets/{widget_ref}", "identity": "fixture_owner"},
    }]


class WidgetServer(BaseHTTPRequestHandler):
    """Provide a real HTTP server with configurable mistakes, never used by production code."""
    records = {}
    delete_fails = False
    no_id = False
    corrupt_marker = False
    actions = []

    def log_message(self, *_args):
        """Suppress fixture HTTP logs (they might contain test data)."""

    def respond(self, status, obj=None):
        """Reply with a JSON body and correct Content-Length."""
        data = json.dumps(obj or {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        """Create one disposable object with an identifier chosen by the server."""
        self.actions.append("POST")
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.records["W-0001"] = {"ref": "W-0001", "label": ("different-preexisting-value" if self.corrupt_marker else payload["label"]),
                                  "is_reviewer": False, "private_value": "do-not-log-me"}
        self.respond(201, {} if self.no_id else {"ref": "W-0001"})

    def do_GET(self):
        """Incorrectly give the resource to both accounts (BOLA simulation)."""
        self.actions.append("GET")
        if self.path == "/api/permissions":
            return self.respond(200, {"privileged": True})
        record = self.records.get(self.path.rsplit("/", 1)[-1])
        self.respond(200, record) if record else self.respond(404)

    def do_PATCH(self):
        """Incorrectly accept the restricted `is_reviewer` field."""
        self.actions.append("PATCH")
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        record = self.records.get(self.path.rsplit("/", 1)[-1])
        if not record:
            self.respond(404)
        else:
            record.update(payload)
            self.respond(200, {"ok": True})

    def do_DELETE(self):
        """Delete a fixture, unless the negative cleanup test asks us to fail."""
        self.actions.append("DELETE")
        if self.delete_fails:
            return self.respond(503)
        self.records.pop(self.path.rsplit("/", 1)[-1], None)
        return self.respond(204)


@contextmanager
def live_api(*, delete_fails=False, no_id=False, corrupt_marker=False):
    """Open a local server only for the duration of an integration test."""
    WidgetServer.records = {}
    WidgetServer.actions = []
    WidgetServer.delete_fails = delete_fails
    WidgetServer.no_id = no_id
    WidgetServer.corrupt_marker = corrupt_marker
    server = ThreadingHTTPServer(("127.0.0.1", 0), WidgetServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def accounts():
    """Supply synthetic identities without exporting the token strings."""
    return {
        "fixture_owner": AuthenticationMaterial(headers={"Authorization": "Bearer fixture-owner-secret"}),
        "other_tester": AuthenticationMaterial(headers={"Authorization": "Bearer second-secret"}),
    }


def test_discovery_uses_generic_crud_shapes():
    """Infer POST/GET/PATCH/DELETE relationships without a preprogrammed path."""
    from achillesapi.core.openapi import parse_openapi
    spec = specification()
    result = discover_workflows(parse_openapi(spec), spec)
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["id_parameter"] == "widget_ref"
    assert result["candidates"][0]["delete"] == "DELETE /api/widgets/{widget_ref}"
    assert result["network_requests_sent"] == 0


def test_dry_run_has_no_network_and_does_not_print_fixture_payload():
    """Planning is safe and omits raw request bodies."""
    spec = specification()
    plan = workflow_plan(parse_openapi(spec), spec, scenarios(), set(accounts()))
    assert plan["request_budget_required"] == 7
    assert plan["requests_sent"] == 0
    assert "disposable-test" not in json.dumps(plan)


def test_live_disposable_lifecycle_auth_mass_assignment_and_cleanup():
    """Find policy failures, clean up, and keep response secrets out of reports."""
    spec = specification()
    with live_api() as base:
        result = run_workflows(parse_openapi(spec), spec, scenarios(),
                               base_url=base, allowed_hosts={"127.0.0.1"}, identities=accounts(),
                               execute=True, approve_writes=True, allow_insecure_http=True,
                               max_requests=7, rate=10)
    assert result["requests_sent"] == 7
    record = result["workflows"][0]
    assert record["created"] and record["cleanup_attempted"] and record["cleanup_verified"]
    assert not record["manual_cleanup_required"]
    assert {f["category"] for f in record["findings"]} == {"BOLA", "BOPLA", "MASS_ASSIGNMENT"}
    assert WidgetServer.records == {}
    assert WidgetServer.actions == ["POST", "GET", "GET", "PATCH", "GET", "DELETE", "GET"]
    output = json.dumps(result)
    for secret in ["fixture-owner-secret", "second-secret", "do-not-log-me", "W-0001", "disposable-test"]:
        assert secret not in output


def test_missing_approval_prevents_any_request():
    """Missing explicit write approval prevents creating even a test resource."""
    spec = specification()
    with live_api() as base:
        with pytest.raises(ScopeError, match="approve-writes"):
            run_workflows(parse_openapi(spec), spec, scenarios(), base_url=base,
                          allowed_hosts={"127.0.0.1"}, identities=accounts(),
                          execute=True, allow_insecure_http=True)
        assert WidgetServer.actions == []


def test_missing_allowlist_and_budgets_prevent_any_request():
    """A failed scope/budget preflight must not leave half-created objects."""
    spec = specification()
    with live_api() as base:
        for kwargs in ({"allowed_hosts": {"not-local.test"}, "max_requests": 7},
                       {"allowed_hosts": {"127.0.0.1"}, "max_requests": 6}):
            with pytest.raises(ScopeError):
                run_workflows(parse_openapi(spec), spec, scenarios(), base_url=base,
                              identities=accounts(), execute=True, approve_writes=True,
                              allow_insecure_http=True, **kwargs)
        assert WidgetServer.actions == []


def test_cleanup_failure_is_reported_not_silently_ignored():
    """A DELETE failure must never be misreported as a successful rollback."""
    spec = specification()
    with live_api(delete_fails=True) as base:
        result = run_workflows(parse_openapi(spec), spec, scenarios(),
                               base_url=base, allowed_hosts={"127.0.0.1"}, identities=accounts(),
                               execute=True, approve_writes=True, allow_insecure_http=True,
                               max_requests=7, rate=10)
    assert result["manual_cleanup_required"]
    assert result["workflows"][0]["cleanup_attempted"]
    assert not result["workflows"][0]["cleanup_verified"]
    assert "W-0001" not in json.dumps(result)


def test_missing_created_identifier_reports_manual_cleanup_required():
    """Even a successful POST may be impossible to delete if it returns no ID."""
    spec = specification()
    with live_api(no_id=True) as base:
        result = run_workflows(parse_openapi(spec), spec, scenarios(),
                               base_url=base, allowed_hosts={"127.0.0.1"}, identities=accounts(),
                               execute=True, approve_writes=True, allow_insecure_http=True,
                               max_requests=7, rate=10)
    assert result["manual_cleanup_required"]
    assert result["workflows"][0]["created"]
    assert not result["workflows"][0]["cleanup_attempted"]


def test_unknown_operation_and_missing_required_payload_are_rejected():
    """OpenAPI must authorize each lifecycle step before any request."""
    spec = specification()
    original = scenarios()
    original[0]["cleanup"]["operation"] = "DELETE /unrelated/{widget_ref}"
    with pytest.raises(WorkflowError, match="not declared"):
        workflow_plan(parse_openapi(spec), spec, original)
    invalid = scenarios()
    invalid[0]["create"]["body"] = {"other": "value"}
    with pytest.raises(WorkflowError, match="required"):
        workflow_plan(parse_openapi(spec), spec, invalid)


def test_strict_yaml_validation(tmp_path):
    """Reject a misspelled configuration field instead of guessing an action."""
    path = tmp_path / "workflow.yaml"
    path.write_text("workflows:\n  - name: typo\n    execute_shell: true\n")
    with pytest.raises(WorkflowError):
        read_workflows(path)


def test_cli_discovers_workflows_without_network(tmp_path):
    """End users can discover candidates with the installed CLI."""
    file = tmp_path / "openapi.json"
    file.write_text(json.dumps(specification()))
    out = tmp_path / "candidates.json"
    result = CliRunner().invoke(app, ["workflow-discover", str(file), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["candidate_count"] == 1


def test_draft_workflow_requires_explicit_real_test_values(tmp_path):
    """The generated starter can help users but must never be executable as-is."""
    import yaml
    from achillesapi.core.workflows import draft_workflow_config
    spec = specification()
    draft = draft_workflow_config(parse_openapi(spec), spec)
    assert draft["workflows"]
    file = tmp_path / "draft.yaml"
    file.write_text(yaml.safe_dump(draft))
    with pytest.raises(WorkflowError, match="REPLACE_ME"):
        read_workflows(file)


def test_cli_workflow_dry_run_and_discovery_draft(tmp_path):
    """Both new CLI commands work without credentials, network or lab references."""
    import yaml
    source = tmp_path / "spec.json"
    source.write_text(json.dumps(specification()))
    workflow = tmp_path / "workflow.yaml"
    workflow.write_text(yaml.safe_dump({"workflows": scenarios()}))
    output = tmp_path / "workflow-plan.json"
    result = CliRunner().invoke(app, ["workflow-assess", str(source),
        "--workflow-config", str(workflow), "--base-url", "https://example.org",
        "--output", str(output)])
    assert result.exit_code == 0, result.output
    data = json.loads(output.read_text())
    assert data["execution"] is None
    assert "disposable-test" not in output.read_text()
    draft = tmp_path / "starter.yaml"
    result = CliRunner().invoke(app, ["workflow-discover", str(source),
        "--draft-config", str(draft), "--output", str(tmp_path / "list.json")])
    assert result.exit_code == 0, result.output
    assert "REPLACE_ME" in draft.read_text()


def test_auto_assess_combines_planning_but_never_writes_in_dry_run(tmp_path):
    """The main command includes lifecycle planning without starting mutations."""
    import yaml
    source = tmp_path / "spec.json"
    source.write_text(json.dumps(specification()))
    workflow = tmp_path / "workflow.yaml"
    workflow.write_text(yaml.safe_dump({"workflows": scenarios()}))
    output = tmp_path / "auto.json"
    result = CliRunner().invoke(app, ["auto-assess", str(source),
        "--workflow-config", str(workflow), "--base-url", "https://example.org",
        "--output", str(output)])
    assert result.exit_code == 0, result.output
    data = json.loads(output.read_text())
    assert data["workflow_plan"]["request_budget_required"] == 7
    assert data["workflow_execution"] is None
    assert data["execution_report"] is None
    assert "disposable-test" not in output.read_text()


def test_incompatible_auth_is_blocked_before_resource_creation():
    """Do not send an API key to a bearer-only protected operation."""
    spec = specification()
    wrong = {"fixture_owner": AuthenticationMaterial(headers={"X-API-Key": "key"}),
             "other_tester": AuthenticationMaterial(headers={"Authorization": "Bearer second"})}
    with live_api() as base:
        with pytest.raises(ScopeError, match="incompatible"):
            run_workflows(parse_openapi(spec), spec, scenarios(),
                          base_url=base, allowed_hosts={"127.0.0.1"}, identities=wrong,
                          execute=True, approve_writes=True, allow_insecure_http=True,
                          max_requests=7)
        assert WidgetServer.actions == []


def test_workflow_cli_reports_manual_cleanup_with_special_exit_code(tmp_path, monkeypatch):
    """A CLI run with a failed DELETE must exit nonzero after saving its report."""
    import yaml
    source = tmp_path / "spec.json"
    source.write_text(json.dumps(specification()))
    workflow = tmp_path / "workflow.yaml"
    workflow.write_text(yaml.safe_dump({"workflows": scenarios()}))
    auth = tmp_path / "auth.yaml"
    auth.write_text(yaml.safe_dump({"profiles": [
        {"name": "fixture_owner", "type": "bearer", "token_env": "TEST_OWNER_TOKEN"},
        {"name": "other_tester", "type": "bearer", "token_env": "TEST_OTHER_TOKEN"},
    ]}))
    monkeypatch.setenv("TEST_OWNER_TOKEN", "owner-secret-token")
    monkeypatch.setenv("TEST_OTHER_TOKEN", "guest-secret-token")
    output = tmp_path / "run.json"
    with live_api(delete_fails=True) as base:
        result = CliRunner().invoke(app, ["workflow-assess", str(source),
            "--workflow-config", str(workflow), "--base-url", base,
            "--auth-config", str(auth), "--allow-host", "127.0.0.1",
            "--execute", "--approve-writes", "--allow-insecure-http",
            "--rate", "10", "--max-requests", "7", "--output", str(output)])
    assert result.exit_code == 2, result.output
    assert json.loads(output.read_text())["execution"]["manual_cleanup_required"]
    assert "owner-secret-token" not in output.read_text()


def test_function_level_policy_check_for_unrelated_operation():
    """BFLA can examine an unrelated protected function, not only object paths."""
    spec = specification()
    wf = scenarios()
    wf[0]["access"].append({"identity": "other_tester", "expected": "deny",
                             "category": "BFLA", "operation": "GET /api/permissions"})
    with live_api() as base:
        result = run_workflows(parse_openapi(spec), spec, wf,
                               base_url=base, allowed_hosts={"127.0.0.1"}, identities=accounts(),
                               execute=True, approve_writes=True, allow_insecure_http=True,
                               max_requests=8, rate=10)
    assert result["requests_sent"] == 8
    record = result["workflows"][0]
    assert record["cleanup_verified"]
    assert any(f["category"] == "BFLA" for f in record["findings"])


def test_auto_assess_can_run_approved_workflow_under_one_budget(tmp_path, monkeypatch):
    """Combining normal GET analysis and explicitly approved writes respects the global cap."""
    import yaml
    source = tmp_path / "spec.json"
    source.write_text(json.dumps(specification()))
    workflow = tmp_path / "workflow.yaml"
    workflow.write_text(yaml.safe_dump({"workflows": scenarios()}))
    auth = tmp_path / "auth.yaml"
    auth.write_text(yaml.safe_dump({"profiles": [
        {"name": "fixture_owner", "type": "bearer", "token_env": "WORKFLOW_OWNER_TOKEN"},
        {"name": "other_tester", "type": "bearer", "token_env": "WORKFLOW_OTHER_TOKEN"},
    ]}))
    monkeypatch.setenv("WORKFLOW_OWNER_TOKEN", "owner-example-token")
    monkeypatch.setenv("WORKFLOW_OTHER_TOKEN", "other-example-token")
    result_file = tmp_path / "auto.json"
    with live_api() as base:
        result = CliRunner().invoke(app, [
            "auto-assess", str(source), "--workflow-config", str(workflow),
            "--base-url", base, "--auth-config", str(auth),
            "--allow-host", "127.0.0.1", "--execute", "--approve-writes",
            "--allow-insecure-http", "--max-requests", "8", "--rate", "10",
            "--no-auth-checks", "--no-cors", "--no-validation", "--output", str(result_file),
        ])
    assert result.exit_code == 0, result.output
    output = json.loads(result_file.read_text())
    assert output["workflow_execution"]["requests_sent"] == 7
    assert output["workflow_execution"]["workflows"][0]["cleanup_verified"]
    assert output["plan"]["execution"]["requests_sent"] <= 8
    assert WidgetServer.records == {}


def test_mismatched_unique_marker_prevents_deleting_unverified_object():
    """Never delete a resource if POST may have returned a preexisting object."""
    spec = specification()
    with live_api(corrupt_marker=True) as base:
        result = run_workflows(parse_openapi(spec), spec, scenarios(),
                               base_url=base, allowed_hosts={"127.0.0.1"}, identities=accounts(),
                               execute=True, approve_writes=True, allow_insecure_http=True,
                               max_requests=7, rate=10)
    entry = result["workflows"][0]
    assert entry["manual_cleanup_required"]
    assert entry["unique_fixture_marker_verified"] is False
    assert entry["cleanup_attempted"] is False
    assert WidgetServer.actions == ["POST", "GET"]


def test_very_short_marker_field_is_blocked_before_network():
    """Avoid creating a fixture if its field cannot hold a safe random marker."""
    spec = specification()
    spec["paths"]["/api/widgets"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["label"]["maxLength"] = 12
    with pytest.raises(WorkflowError, match="maxLength"):
        workflow_plan(parse_openapi(spec), spec, scenarios())


def test_v021_multiple_mutations_apply_in_order_and_cleanup():
    """v0.21 repeats approved write+verification stages without leaking fixture values."""
    spec = specification()
    config = scenarios()
    config[0]["mutations"] = [
        config[0].pop("mutation"),
        {"operation": "PATCH /api/widgets/{widget_ref}", "identity": "fixture_owner",
         "body": {"is_reviewer": False}, "restricted_fields": ["is_reviewer"]},
    ]
    plan = workflow_plan(parse_openapi(spec), spec, config, set(accounts()))
    assert plan["request_budget_required"] == 9
    assert len(plan["workflows"][0]["mutations"]) == 2
    with live_api() as base:
        report = run_workflows(parse_openapi(spec), spec, config, base_url=base,
                               allowed_hosts={"127.0.0.1"}, identities=accounts(),
                               execute=True, approve_writes=True, allow_insecure_http=True,
                               max_requests=9, rate=10)
    entry = report["workflows"][0]
    assert report["requests_sent"] == 9
    assert entry["cleanup_verified"] and not entry["manual_cleanup_required"]
    assert [f["category"] for f in entry["findings"]].count("MASS_ASSIGNMENT") == 2
    assert WidgetServer.records == {}
    assert WidgetServer.actions == ["POST", "GET", "GET", "PATCH", "GET", "PATCH", "GET", "DELETE", "GET"]
    assert "fixture-owner-secret" not in json.dumps(report)


def test_v021_mutations_reject_unapproved_configuration(tmp_path):
    """No mutating action is sent for invalid sequence or insufficient budget."""
    from yaml import safe_dump
    data = scenarios()
    data[0]["mutations"] = [data[0].pop("mutation")]
    invalid = [dict(data[0], mutation=data[0]["mutations"][0])]
    path = tmp_path / "bad.yaml"
    path.write_text(safe_dump({"workflows": invalid}))
    with pytest.raises(WorkflowError, match="either mutation or mutations"):
        read_workflows(path)
    spec = specification()
    with live_api() as base:
        with pytest.raises(ScopeError):
            run_workflows(parse_openapi(spec), spec, data, base_url=base,
                          allowed_hosts={"127.0.0.1"}, identities=accounts(),
                          execute=True, approve_writes=True, allow_insecure_http=True,
                          max_requests=6)
        assert WidgetServer.actions == []
