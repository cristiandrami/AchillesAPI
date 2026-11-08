"""Cross-API tests for v0.17-v0.20: live OAuth, GET dataflow, bounded adaptation."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from achillesapi.core.auth import AuthenticationConfigError, AuthenticationManager, AuthenticationFile
from achillesapi.core.journeys import JourneyError, read_journey, run_journey
from achillesapi.core.adaptive import verify_server_errors
from achillesapi.core.generic import build_generic_plan
from achillesapi.core.openapi import analyze_openapi_file


class Handler(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        Handler.requests.append(("POST", self.path))
        if self.path == "/oauth/token":
            result = {"access_token": "test-only-token", "expires_in": 3600}
        elif self.path == "/session":
            assert b'"username"' in body
            result = {"session": {"access_token": "test-only-session"}}
        else:
            self.send_response(404); self.end_headers(); return
        data = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        Handler.requests.append(("GET", self.path))
        if self.path == "/v1/items":
            result = {"items": [{"itemRef": "abc-781"}]}
        elif self.path == "/v1/items/abc-781":
            result = {"id": "abc-781", "ok": True}
        elif self.path == "/v1/failure":
            self.send_response(503); self.end_headers(); return
        else:
            self.send_response(404); self.end_headers(); return
        data = json.dumps(result).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)


@pytest.fixture
def server():
    Handler.requests = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)


@pytest.fixture
def spec(tmp_path):
    payload = {"openapi": "3.0.3", "info": {"title": "Unrelated service", "version": "1"},
        "paths": {
          "/v1/items": {"get": {"responses": {"200": {"description": "ok"}}}},
          "/v1/items/{itemRef}": {"get": {"parameters": [{"name": "itemRef", "in": "path", "required": True,
                "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}},
          "/v1/failure": {"get": {"responses": {"200": {"description": "ok"}}}}
        }}
    path = tmp_path / "unrelated.json"
    path.write_text(json.dumps(payload))
    return analyze_openapi_file(path)


def test_oauth_client_credentials_scope_and_cache(monkeypatch, server):
    monkeypatch.setenv("DEMO_ID", "client")
    monkeypatch.setenv("DEMO_SECRET", "secret")
    manager = AuthenticationManager(AuthenticationFile.model_validate({"profiles": [{
        "name": "svc", "type": "oauth2_client_credentials", "token_url": server + "/oauth/token",
        "client_id_env": "DEMO_ID", "client_secret_env": "DEMO_SECRET", "scopes": ["read:items"]}]}))
    with pytest.raises(AuthenticationConfigError):
        manager.resolve("svc")
    with pytest.raises(AuthenticationConfigError):
        manager.resolve("svc", allowed_hosts={"127.0.0.1"})
    with pytest.raises(AuthenticationConfigError):
        manager.resolve("svc", allowed_hosts={"evil.invalid"}, allow_insecure_http=True)
    assert Handler.requests == []
    result = manager.resolve("svc", allowed_hosts={"127.0.0.1"}, allow_insecure_http=True)
    assert result.headers == {"Authorization": "Bearer test-only-token"}
    assert manager.resolve("svc", allowed_hosts={"127.0.0.1"}, allow_insecure_http=True) is result
    assert Handler.requests == [("POST", "/oauth/token")]
    assert "test-only-token" not in repr(result)


def test_login_json_pointer(monkeypatch, server):
    monkeypatch.setenv("DEMO_USERNAME", "safe-account")
    monkeypatch.setenv("DEMO_PASSWORD", "safe-pass")
    manager = AuthenticationManager(AuthenticationFile.model_validate({"profiles": [{
        "name": "login", "type": "login_json", "login_url": server + "/session",
        "username_env": "DEMO_USERNAME", "password_env": "DEMO_PASSWORD",
        "token_pointer": "/session/access_token"}]}))
    material = manager.resolve("login", allowed_hosts={"127.0.0.1"}, allow_insecure_http=True)
    assert material.headers["Authorization"] == "Bearer test-only-session"


def test_get_journey_captures_id_without_persisting(server, spec):
    config = {"steps": [
        {"operation": "GET /v1/items", "capture": {"selected_id": "/items/0/itemRef"}},
        {"operation": "GET /v1/items/{itemRef}", "values": {"itemRef": "$selected_id"}},
    ]}
    dry = run_journey(spec, config, base_url=server, allowed_hosts=set())
    assert dry["requests_sent"] == 0
    assert Handler.requests == []
    report = run_journey(spec, config, base_url=server, allowed_hosts={"127.0.0.1"}, execute=True)
    assert report["requests_sent"] == 2
    assert report["steps"][1]["status"] == 200
    assert "abc-781" not in json.dumps(report)
    assert "selected_id" in report["captured_variable_names"]


def test_journey_never_approves_writes_and_requires_budget(server, spec):
    config = {"steps": [{"operation": "POST /v1/items"}]}
    with pytest.raises(JourneyError):
        run_journey(spec, config, base_url=server, allowed_hosts={"127.0.0.1"}, execute=True)
    assert Handler.requests == []
    config = {"steps": [{"operation": "GET /v1/items"}, {"operation": "GET /v1/items"}]}
    with pytest.raises(JourneyError):
        run_journey(spec, config, base_url=server, allowed_hosts={"127.0.0.1"}, execute=True,
                    max_requests=1)
    assert Handler.requests == []


def test_adaptive_verifies_only_documented_get_errors(server, spec):
    plan = build_generic_plan(spec, base_url=server)
    observations = [{"operation": "GET /v1/failure", "check": "baseline", "identity": "anonymous", "status": 503},
                    {"operation": "GET /not-in-spec", "check": "baseline", "identity": "anonymous", "status": 503}]
    result = verify_server_errors(spec, plan, observations, base_url=server,
                                  allowed_hosts={"127.0.0.1"}, identities=None, path_values={}, budget=1)
    assert result["requests_sent"] == 1
    assert result["observations"][0]["reproducible_server_error"] is True
    assert Handler.requests == [("GET", "/v1/failure")]


def test_journey_discovery_nested_response_and_draft(tmp_path):
    from achillesapi.core.journey_discovery import discover_read_journeys, journey_draft
    from achillesapi.core.openapi import load_openapi
    path = Path(__file__).resolve().parents[1] / "labs/v020_service/openapi.json"
    parsed = analyze_openapi_file(path)
    result = discover_read_journeys(parsed, load_openapi(path))
    first = next(x for x in result["candidates"] if x["relationship"] == "collection_to_item")
    assert first["source_pointer"] == "/organizations/0/organization_ref"
    draft = journey_draft(parsed, first)
    assert draft["steps"][0]["capture"]["captured_organization_ref"] == first["source_pointer"]
    assert draft["steps"][1]["values"]["organization_ref"] == "$captured_organization_ref"


def test_journey_invalid_dependency_is_blocked_before_any_request(server, spec):
    config = {"steps": [
        {"operation": "GET /v1/items"},
        {"operation": "GET /v1/items/{itemRef}", "values": {"itemRef": "$never_captured"}},
    ]}
    with pytest.raises(JourneyError):
        run_journey(spec, config, base_url=server, allowed_hosts={"127.0.0.1"}, execute=True)
    assert Handler.requests == []


def test_journey_out_of_scope_before_token_acquisition(monkeypatch, spec, server):
    monkeypatch.setenv("DEMO_ID", "client")
    monkeypatch.setenv("DEMO_SECRET", "secret")
    manager = AuthenticationManager(AuthenticationFile.model_validate({"profiles": [{
        "name": "svc", "type": "oauth2_client_credentials", "token_url": server + "/oauth/token",
        "client_id_env": "DEMO_ID", "client_secret_env": "DEMO_SECRET"}]}))
    config = {"steps": [{"operation": "GET /v1/items", "identity": "svc"}]}
    from achillesapi.core.http import ScopeError
    with pytest.raises(ScopeError):
        run_journey(spec, config, base_url="http://unapproved.invalid",
                    allowed_hosts={"127.0.0.1"}, execute=True, manager=manager,
                    allow_insecure_http=True)
    assert Handler.requests == []
    assert manager.auth_requests_made == 0


def test_response_contract_reports_only_field_paths():
    from achillesapi.core.contracts import response_contract_issues
    spec = {"components": {"schemas": {"Thing": {"type": "object", "required": ["id", "active"],
             "properties": {"id": {"type": "integer"}, "active": {"type": "boolean"}}}}}}
    from types import SimpleNamespace
    endpoint = SimpleNamespace(responses={"200": {"content": {"application/json": {"schema": {
        "$ref": "#/components/schemas/Thing"}}}}})
    issues = response_contract_issues(spec, endpoint, 200,
         '{"id":"SECRET-DO-NOT-PERSIST"}', "application/json", False)
    assert {e["problem"] for e in issues} == {"type_mismatch", "missing_required_property"}
    assert "SECRET-DO-NOT-PERSIST" not in json.dumps(issues)
    assert response_contract_issues(spec, endpoint, 200, "{}", "application/json", True) == []


def test_auth_draft_has_no_passwords():
    from achillesapi.core.auth_discovery import draft_auth_profiles
    from achillesapi.core.openapi import load_openapi
    path = Path(__file__).resolve().parents[1] / "labs/v020_service/openapi.json"
    result = draft_auth_profiles(analyze_openapi_file(path))
    assert result["profiles"][0]["type"] == "bearer"
    assert "token_env" in result["profiles"][0]
    assert "demo-workload-token" not in json.dumps(result)
